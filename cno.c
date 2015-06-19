#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cno.h"
#include "picohttpparser/picohttpparser.h"


static inline uint32_t read1(unsigned char *p) { return p[0]; }
static inline uint32_t read2(unsigned char *p) { return p[0] <<  8 | p[1]; }
static inline uint32_t read4(unsigned char *p) { return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }
static inline uint32_t read3(unsigned char *p) { return read4(p) >> 8; }

static inline void write1(unsigned char *p, uint32_t x) { p[0] = x; }
static inline void write2(unsigned char *p, uint32_t x) { p[0] = x >>  8; p[1] = x; }
static inline void write3(unsigned char *p, uint32_t x) { p[0] = x >> 16; p[1] = x >>  8; p[2] = x; }
static inline void write4(unsigned char *p, uint32_t x) { p[0] = x >> 24; p[1] = x >> 16; p[2] = x >> 8; p[3] = x; }

static inline char *write_vector(char *ptr, const cno_io_vector_t *vec) { return (char *) memcpy(ptr, vec->data, vec->size) + vec->size; }
static inline char *write_string(char *ptr, const char *data)           { return (char *) memcpy(ptr, data, strlen(data)) + strlen(data); }
#define write_format(ptr, ...) (ptr + sprintf(ptr, ##__VA_ARGS__))


static const cno_io_vector_t CNO_PREFACE = CNO_IO_VECTOR_CONST("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
static const cno_settings_t  CNO_SETTINGS_STANDARD = {{{ 4096, 1, -1,   65536, 16384, -1 }}};
static const cno_settings_t  CNO_SETTINGS_INITIAL  = {{{ 4096, 1, 1024, 65536, 65536, -1 }}};


#define CNO_ERROR_GOAWAY(conn, type, ...) (cno_frame_write_goaway(conn, type) ? CNO_PROPAGATE : CNO_ERROR_TRANSPORT(__VA_ARGS__))
const char  CNO_FRAME_FLOW_CONTROLLED [256] = { 1 };  // only DATA is
const char *CNO_FRAME_NAME            [256] = {
    "DATA",         "HEADERS", "PRIORITY", "RST_STREAM",    "SETTINGS",
    "PUSH_PROMISE", "PING",    "GOAWAY",   "WINDOW_UPDATE", "CONTINUATION",
};


inline size_t cno_stream_next_id(cno_connection_t *conn)
{
    size_t last = conn->last_stream[CNO_PEER_LOCAL];
    return cno_connection_is_http2(conn) && (last || !conn->client) ? last + 2 : 1;
}


static inline int cno_stream_is_local(cno_connection_t *conn, size_t id)
{
    return (int) (id % 2) == (conn->client);
}


static void cno_stream_destroy(cno_connection_t *conn, cno_stream_t *stream)
{
    conn->stream_count[cno_stream_is_local(conn, stream->id)]--;
    cno_io_vector_clear(&stream->cache);
    cno_set_remove(&conn->streams, stream);
    free(stream);
}


static int cno_stream_destroy_clean(cno_connection_t *conn, cno_stream_t *stream)
{
    size_t id = stream->id;
    cno_stream_destroy(conn, stream);
    return CNO_FIRE(conn, on_stream_end, id);
}


static int cno_stream_close(cno_connection_t *conn, cno_stream_t *stream)
{
    if (stream->state == CNO_STREAM_CLOSED_REMOTE) {
        return cno_stream_destroy_clean(conn, stream);
    }

    if (stream->state != CNO_STREAM_RESERVED_LOCAL && stream->state != CNO_STREAM_OPEN) {
        return CNO_ERROR_ASSERTION("invalid stream state %lu", stream->state);
    }

    stream->accept &= ~(CNO_ACCEPT_WRITE_HEADERS | CNO_ACCEPT_WRITE_DATA | CNO_ACCEPT_WRITE_PUSH);
    stream->state = CNO_STREAM_CLOSED_LOCAL;
    return CNO_OK;
}


static cno_stream_t * cno_stream_new(cno_connection_t *conn, size_t id, int local)
{
    if (cno_stream_is_local(conn, id) != local) {
        (void) CNO_ERROR_INVALID_STREAM("invalid stream ID (%lu != %d mod 2)", id, local);
        return NULL;
    }

    if (id <= conn->last_stream[local]) {
        (void) CNO_ERROR_INVALID_STREAM("invalid stream ID (%lu <= %lu)", id, conn->last_stream[local]);
        return NULL;
    }

    if (conn->stream_count[local] >= conn->settings[!local].max_concurrent_streams) {
        (void) (local ? CNO_ERROR_WOULD_BLOCK("initiated too many concurrent streams; wait for on_stream_end")
                      : CNO_ERROR_TRANSPORT("received too many concurrent streams"));
        return NULL;
    }

    cno_stream_t *stream = calloc(1, sizeof(cno_stream_t));

    if (!stream) {
        (void) CNO_ERROR_NO_MEMORY;
        return NULL;
    }

    stream->id = id;
    stream->window_recv = conn->settings[local].initial_window_size;
    stream->window_send = conn->settings[local].initial_window_size;
    cno_set_insert(&conn->streams, id, stream);
    conn->last_stream[local] = id;
    conn->stream_count[local]++;

    if (CNO_FIRE(conn, on_stream_start, id)) {
        cno_stream_destroy(conn, stream);
        return NULL;
    }

    return stream;
}


static inline cno_stream_t * cno_stream_find(cno_connection_t *conn, size_t id)
{
    return id ? cno_set_find(&conn->streams, id) : NULL;
}


static int cno_frame_write(cno_connection_t *conn, cno_frame_t *frame, cno_stream_t *stream)
{
    size_t length = frame->payload.size;
    size_t limit  = conn->settings[CNO_PEER_REMOTE].max_frame_size;

    if (CNO_FRAME_FLOW_CONTROLLED[frame->type]) {
        if (length > conn->window_send) {
            return CNO_ERROR_WOULD_BLOCK("frame exceeds connection flow window (%lu > %lu)",
                length, conn->window_send);
        }

        if (stream) {
            if (length > stream->window_send) {
                return CNO_ERROR_WOULD_BLOCK("frame exceeds stream flow window (%lu > %lu)",
                    length, stream->window_send);
            }

            stream->window_send -= length;
        }

        conn->window_send -= length;
    }

    if (length > limit) {
        cno_frame_t part = *frame;

        if (part.type != CNO_FRAME_DATA         && part.type != CNO_FRAME_HEADERS
         && part.type != CNO_FRAME_PUSH_PROMISE && part.type != CNO_FRAME_CONTINUATION) {
            return CNO_ERROR_ASSERTION("frame too big (%lu > %lu)", length, limit);
        }

        if (part.flags & CNO_FLAG_PADDED) {
            return CNO_ERROR_ASSERTION("don't know how to split padded frames");
        }

        size_t endflags = part.flags & (CNO_FLAG_END_STREAM | CNO_FLAG_END_HEADERS);

        part.flags &= ~endflags;
        part.payload.size = limit;

        for (; length > limit; length -= part.payload.size, part.payload.data += part.payload.size) {
            if (cno_frame_write(conn, &part, stream)) {
                return CNO_PROPAGATE;
            }

            if (part.type == CNO_FRAME_HEADERS || part.type == CNO_FRAME_PUSH_PROMISE) {
                part.type = CNO_FRAME_CONTINUATION;
            }

            part.flags &= ~CNO_FLAG_PRIORITY;
        }

        part.flags |= endflags;
        part.payload.size = length;
        return cno_frame_write(conn, &part, stream);
    }

    unsigned char header[9];
    write3(header,     length);
    write1(header + 3, frame->type);
    write1(header + 4, frame->flags);
    write4(header + 5, frame->stream);

    return CNO_FIRE(conn, on_frame_send, frame)
        || CNO_FIRE(conn, on_write, (char *) header, sizeof(header))
        || (length && CNO_FIRE(conn, on_write, frame->payload.data, length));
}


static int cno_frame_write_goaway(cno_connection_t *conn, size_t code)
{
    unsigned char descr[8];
    write4(descr,     conn->last_stream[CNO_PEER_REMOTE]);
    write4(descr + 4, code);
    cno_frame_t error = { CNO_FRAME_GOAWAY, 0, 0, CNO_IO_VECTOR_ARRAY(descr) };
    return cno_frame_write(conn, &error, NULL);
}


static int cno_frame_write_rst_stream(cno_connection_t *conn, size_t stream, size_t code)
{
    if (!stream) {
        return CNO_ERROR_GOAWAY(conn, code, "RST'd stream 0");
    }

    cno_stream_t *obj = cno_stream_find(conn, stream);

    if (!obj) {
        return CNO_OK;  // assume stream already ended naturally
    }

    unsigned char descr[4];
    write4(descr, code);
    cno_frame_t error = { CNO_FRAME_RST_STREAM, 0, stream, CNO_IO_VECTOR_ARRAY(descr) };

    if (cno_frame_write(conn, &error, obj)) {
        return CNO_PROPAGATE;
    }

    // a stream in closed state can still accept headers/data.
    // headers will be decompressed; other than that, everything is ignored.
    obj->state = CNO_STREAM_CLOSED;

    if (!(obj->accept & (CNO_ACCEPT_HEADERS | CNO_ACCEPT_HEADCNT))) {
        // since headers were already handled, this stream can be safely destroyed.
        return cno_stream_destroy_clean(conn, obj);
    }

    return CNO_OK;
}


static int cno_frame_handle(cno_connection_t *conn, cno_frame_t *frame)
{
    size_t sz = frame->payload.size;
    unsigned char *ptr = (unsigned char *) frame->payload.data;
    unsigned char *end = sz + ptr;
    unsigned char rstd = 0 < frame->stream && frame->stream <= conn->last_stream[cno_stream_is_local(conn, frame->stream)];
    cno_stream_t *stream = cno_stream_find(conn, frame->stream);

    if (CNO_FRAME_FLOW_CONTROLLED[frame->type] && sz) {
        unsigned char payload[4];
        write4(payload, sz);
        cno_frame_t update = { CNO_FRAME_WINDOW_UPDATE, 0, 0, CNO_IO_VECTOR_ARRAY(payload) };

        if (cno_frame_write(conn, &update, NULL)) {
            return CNO_PROPAGATE;
        }

        if (frame->stream) {
            update.stream = frame->stream;

            if (cno_frame_write(conn, &update, stream)) {
                return CNO_PROPAGATE;
            }
        }
    }

    if (frame->type == CNO_FRAME_CONTINUATION) {
        if (!stream) {
            return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "CONTINUATION on a non-existent stream");
        }

        if (!(stream->accept & CNO_ACCEPT_HEADCNT)) {
            return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "CONTINUATION not after HEADERS/PUSH_PROMISE");
        }

        frame->type = stream->last_frame;
    }

    if (frame->flags & CNO_FLAG_PADDED) {
        unsigned char pad = *ptr++;

        if (pad >= --sz) {
            return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "frame padding bigger than whole payload");
        }

        sz -= pad;
    }

    if (frame->flags & CNO_FLAG_PRIORITY) {
        // TODO do something with this info.
        ptr += 5;
        sz  -= 5;
    }

    switch (frame->type) {
        case CNO_FRAME_PING: {
            if (frame->stream) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "got stream %lu PING-ed", frame->stream);
            }

            if (sz != 8) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_FRAME_SIZE_ERROR, "bad PING frame (length = %lu)", sz);
            }

            if (frame->flags & CNO_FLAG_ACK) {
                return CNO_FIRE(conn, on_pong, frame->payload.data);
            }

            cno_frame_t response = { CNO_FRAME_PING, CNO_FLAG_ACK, 0, frame->payload };
            return cno_frame_write(conn, &response, NULL);
        }

        case CNO_FRAME_GOAWAY: {
            if (frame->stream) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "got GOAWAY on stream %lu", frame->stream);
            }

            if (cno_connection_lost(conn)) {
                return CNO_PROPAGATE;
            }

            // TODO parse error code.
            return CNO_OK;
        }

        case CNO_FRAME_RST_STREAM: {
            if (!stream) {
                if (rstd) {
                    return CNO_OK;
                }

                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "reset of a nonexistent stream");
            }

            if (cno_stream_destroy_clean(conn, stream)) {
                return CNO_PROPAGATE;
            }

            // TODO parse error code.
            return CNO_OK;
        }

        case CNO_FRAME_PRIORITY: {
            if (!frame->stream) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "PRIORITY on stream 0");
            }

            // TODO something.
            return CNO_OK;
        }

        case CNO_FRAME_SETTINGS: {
            if (frame->stream) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "got SETTINGS on stream %lu", frame->stream);
            }

            if (frame->flags & CNO_FLAG_ACK) {
                if (sz) {
                    return CNO_ERROR_GOAWAY(conn, CNO_STATE_FRAME_SIZE_ERROR, "bad SETTINGS (ack with length = %lu)", sz);
                }

                return CNO_OK;
            }

            if (sz % 6) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_FRAME_SIZE_ERROR, "bad SETTINGS (length = %lu)", sz);
            }

            for (; ptr != end; ptr += 6) {
                size_t setting = read2(ptr);
                size_t value   = read4(ptr + 2);

                if (setting && setting < CNO_SETTINGS_UNDEFINED) {
                    conn->settings[CNO_PEER_REMOTE].array[setting - 1] = value;
                }
            }

            conn->encoder.limit_upper = conn->settings[CNO_PEER_REMOTE].header_table_size;
            cno_hpack_setlimit(&conn->encoder, conn->encoder.limit_upper);
            // TODO update stream flow control windows.
            cno_frame_t ack = { CNO_FRAME_SETTINGS, CNO_FLAG_ACK };
            return cno_frame_write(conn, &ack, NULL);
        }

        case CNO_FRAME_WINDOW_UPDATE: {
            if (sz != 4) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_FRAME_SIZE_ERROR, "bad WINDOW_UPDATE (length = %lu)", sz);
            }

            size_t increment = read4(ptr);

            #ifdef CNO_HTTP2_STRICT
                // nghttp2 fails this check sometimes.
                if (increment == 0) {
                    return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "bad WINDOW_UPDATE (incr = %lu)", increment);
                }
            #endif

            if (!frame->stream) {
                conn->window_send += increment;

                if (conn->window_send >= 0x80000000u) {
                    return CNO_ERROR_GOAWAY(conn, CNO_STATE_FLOW_CONTROL_ERROR,
                        "flow control window got too big (total = %lu)", conn->window_send);
                }
            } else if (stream != NULL) {
                stream->window_send += increment;

                if (stream->window_send >= 0x80000000u) {
                    return cno_frame_write_rst_stream(conn, frame->stream, CNO_STATE_PROTOCOL_ERROR);
                }
            }

            return CNO_FIRE(conn, on_flow_increase, frame->stream);
        }

        case CNO_FRAME_HEADERS: {
            if (stream == NULL) {
                stream = cno_stream_new(conn, frame->stream, CNO_PEER_REMOTE);

                if (stream == NULL) {
                    return CNO_PROPAGATE;
                }

                stream->accept = CNO_ACCEPT_HEADERS | CNO_ACCEPT_WRITE_HEADERS | CNO_ACCEPT_WRITE_PUSH;
            }

            if (stream->accept & CNO_ACCEPT_HEADCNT) {
                // continuation; proceed normally, state has already changed.
            } else if (stream->accept & CNO_ACCEPT_HEADERS) {
                if (stream->state == CNO_STREAM_IDLE) {
                    stream->state = CNO_STREAM_OPEN;
                } else if (stream->state == CNO_STREAM_RESERVED_REMOTE) {
                    stream->state = CNO_STREAM_CLOSED_LOCAL;
                }
            } else {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "got HEADERS on a stream in wrong state");
            }

            stream->last_frame = CNO_FRAME_HEADERS;
            stream->accept &= ~CNO_ACCEPT_HEADERS;
            stream->accept |=  CNO_ACCEPT_HEADCNT;

            if (cno_io_vector_extend(&stream->cache, (char *) ptr, sz)) {
                // note that we could've created the stream, but we don't need to bother
                // destroying it. this error is non-recoverable; connection_destroy
                // will handle things.
                return CNO_PROPAGATE;
            }

            break;
        }

        case CNO_FRAME_PUSH_PROMISE: {
            if (!conn->client) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "clients can't push");
            }

            if (!conn->settings[CNO_PEER_LOCAL].enable_push) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "push disabled");
            }

            if (!(stream && (stream->accept & (CNO_ACCEPT_PUSH | CNO_ACCEPT_PUSHCNT)))) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "PUSH_PROMISE not on an open stream");
            }

            if (stream->accept & CNO_ACCEPT_PUSHCNT) {
                // continuation; proceed as with HEADERS.
            } else {
                size_t promised = read4(ptr);
                ptr += 4;
                sz  -= 4;

                cno_stream_t *prstream = cno_stream_new(conn, promised, CNO_PEER_REMOTE);

                if (prstream == NULL) {
                    return CNO_PROPAGATE;
                }

                prstream->state  = CNO_STREAM_RESERVED_REMOTE;
                prstream->accept = CNO_ACCEPT_HEADERS;
                stream->last_promise = promised;
            }

            stream->last_frame = CNO_FRAME_PUSH_PROMISE;

            if (cno_io_vector_extend(&stream->cache, (char *) ptr, sz)) {
                return CNO_PROPAGATE;
            }

            break;
        }

        case CNO_FRAME_DATA: {
            if (!stream) {
                if (rstd) {
                    return CNO_OK;  // ignore data on reset stream
                }

                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "DATA on nonexistent stream");
            }

            if (!(stream->accept & CNO_ACCEPT_DATA)) {
                return cno_frame_write_rst_stream(conn, frame->stream, CNO_STATE_STREAM_CLOSED);
            }

            if (CNO_FIRE(conn, on_message_data, frame->stream, (const char *) ptr, sz)) {
                return CNO_PROPAGATE;
            }

            break;
        }

        default: return CNO_OK;  // ignore unrecognized frames
    }

    if (frame->flags & CNO_FLAG_END_HEADERS) {
        if (frame->type != CNO_FRAME_HEADERS && frame->type != CNO_FRAME_PUSH_PROMISE) {
            return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "END_HEADERS not on HEADERS");
        }

        size_t limit = CNO_MAX_HEADERS;
        cno_header_t  headers[CNO_MAX_HEADERS];
        cno_header_t *it;

        if (cno_hpack_decode(&conn->decoder, &stream->cache, headers, &limit)) {
            cno_frame_write_goaway(conn, CNO_STATE_COMPRESSION_ERROR);
            cno_io_vector_clear(&stream->cache);
            return CNO_PROPAGATE;
        }

        cno_io_vector_clear(&stream->cache);
        cno_message_t msg = { 0, CNO_IO_VECTOR_EMPTY, CNO_IO_VECTOR_EMPTY, headers, limit };

        for (it = headers; it != headers + limit; ++it) {
            if (strncmp(it->name.data, ":status", it->name.size) == 0) {
                char *ptr = it->value.data;
                char *end = it->value.data + it->value.size;

                for (; ptr != end; ++ptr) {
                    msg.code *= 10;

                    if ('0' <= *ptr && *ptr <= '9') {
                        msg.code += *ptr - '0';
                    } else {
                        break;
                    }
                }
            } else

            if (strncmp(it->name.data, ":path", it->name.size) == 0) {
                msg.path.data = it->value.data;
                msg.path.size = it->value.size;
            } else

            if (strncmp(it->name.data, ":method", it->name.size) == 0) {
                msg.method.data = it->value.data;
                msg.method.size = it->value.size;
            }
        }

        int failed;

        if (stream->state == CNO_STREAM_CLOSED) {
            failed = 0;  // ignore headers on reset stream
        } else if (frame->type == CNO_FRAME_HEADERS) {
            if (stream->state == CNO_STREAM_CLOSED) {
                // can finally destroy the thing.
                failed = cno_stream_destroy_clean(conn, stream);
            } else {
                failed = CNO_FIRE(conn, on_message_start, frame->stream, &msg);
                stream->accept &= ~(CNO_ACCEPT_HEADERS | CNO_ACCEPT_HEADCNT);
                stream->accept |=   CNO_ACCEPT_DATA;
            }
        } else {
            failed = CNO_FIRE(conn, on_message_push, stream->last_promise, &msg, frame->stream);
            stream->accept &= ~CNO_ACCEPT_PUSHCNT;
        }

        for (it = headers; it != headers + limit; ++it) {
            cno_io_vector_clear(&it->name);
            cno_io_vector_clear(&it->value);
        }

        if (failed) {
            return CNO_PROPAGATE;
        }
    }

    if (stream && frame->flags & CNO_FLAG_END_STREAM) {
        stream->accept &= ~CNO_ACCEPT_DATA;

        if (stream->state == CNO_STREAM_CLOSED_LOCAL) {
            if (cno_stream_destroy_clean(conn, stream)) {
                return CNO_PROPAGATE;
            }
        } else

        if (stream->state != CNO_STREAM_CLOSED) {
            stream->state = CNO_STREAM_CLOSED_REMOTE;
        }

        if (CNO_FIRE(conn, on_message_end, frame->stream)) {
            return CNO_PROPAGATE;
        }
    }

    return CNO_OK;
}


static int cno_settings_diff(cno_connection_t *conn, const cno_settings_t *old, const cno_settings_t *updated)
{
    size_t i = 0;
    // no. of configurable parameters * (2 byte id + 4 byte value)
    unsigned char payload[(CNO_SETTINGS_UNDEFINED - 1) * 6];
    unsigned char *ptr = payload;
    size_t *current = (size_t *) old;
    size_t *replace = (size_t *) updated;

    for (; ++i < CNO_SETTINGS_UNDEFINED; ++current, ++replace) {
        if (*current != *replace) {
            write2(ptr, i);
            write4(ptr + 2, *replace);
            ptr += 6;
        }
    }

    cno_frame_t frame = { CNO_FRAME_SETTINGS };
    frame.payload.data = (char *) payload;
    frame.payload.size = ptr - payload;
    return cno_frame_write(conn, &frame, NULL);
}


void cno_settings_copy(cno_connection_t *conn, cno_settings_t *target)
{
    memcpy(target, conn->settings + CNO_PEER_LOCAL, sizeof(cno_settings_t));
}


int cno_settings_apply(cno_connection_t *conn, const cno_settings_t *new_settings)
{
    if (new_settings->enable_push != 0 && new_settings->enable_push != 1) {
        return CNO_ERROR_ASSERTION("enable_push neither 0 nor 1");
    }

    if (new_settings->max_frame_size < 16384 || new_settings->max_frame_size > 16777215) {
        return CNO_ERROR_ASSERTION("maximum frame size out of bounds (2^14..2^24-1)");
    }

    if (conn->state != CNO_CONNECTION_INIT && cno_connection_is_http2(conn)) {
        // If not yet in HTTP2 mode, `cno_connection_upgrade` will send the SETTINGS frame.
        if (cno_settings_diff(conn, conn->settings + CNO_PEER_LOCAL, new_settings)) {
            return CNO_PROPAGATE;
        }
    }

    memcpy(conn->settings + CNO_PEER_LOCAL, new_settings, sizeof(cno_settings_t));
    conn->decoder.limit_upper = new_settings->header_table_size;
    // TODO the difference in initial flow control window size should be subtracted
    //      from the flow control window size of all active streams.
    return CNO_OK;
}


cno_connection_t * cno_connection_new(enum CNO_CONNECTION_KIND kind)
{
    cno_connection_t *conn = calloc(1, sizeof(cno_connection_t));

    if (conn == NULL) {
        (void) CNO_ERROR_NO_MEMORY;
        return NULL;
    }

    conn->kind  = kind;
    conn->state = kind == CNO_HTTP2_CLIENT ? CNO_CONNECTION_INIT : CNO_CONNECTION_HTTP1_INIT;
    memcpy(conn->settings,     &CNO_SETTINGS_STANDARD, sizeof(cno_settings_t));
    memcpy(conn->settings + 1, &CNO_SETTINGS_INITIAL,  sizeof(cno_settings_t));
    conn->window_recv = CNO_SETTINGS_INITIAL .initial_window_size;
    conn->window_send = CNO_SETTINGS_STANDARD.initial_window_size;
    cno_hpack_init(&conn->decoder, CNO_SETTINGS_INITIAL .header_table_size);
    cno_hpack_init(&conn->encoder, CNO_SETTINGS_STANDARD.header_table_size);
    cno_set_init(&conn->streams);
    return conn;
}


void cno_connection_destroy(cno_connection_t *conn)
{
    cno_io_vector_reset(&conn->buffer);
    cno_io_vector_clear((cno_io_vector_t *) &conn->buffer);
    cno_hpack_clear(&conn->encoder);
    cno_hpack_clear(&conn->decoder);
    cno_set_iterate(&conn->streams, cno_stream_t *, stream, cno_stream_destroy(conn, stream));
    free(conn);
}


int cno_connection_is_http2(cno_connection_t *conn)
{
    return conn->state != CNO_CONNECTION_HTTP1_INIT &&
           conn->state != CNO_CONNECTION_HTTP1_READY &&
           conn->state != CNO_CONNECTION_HTTP1_READING;
}


static int cno_connection_upgrade(cno_connection_t *conn)
{
    if (conn->client && CNO_FIRE(conn, on_write, CNO_PREFACE.data, CNO_PREFACE.size)) {
        return CNO_PROPAGATE;
    }

    return cno_settings_diff(conn, &CNO_SETTINGS_STANDARD, conn->settings + CNO_PEER_LOCAL);
}


int cno_connection_made(cno_connection_t *conn)
{
    int __retcode = CNO_OK;
    #define STOP(code) do              { __retcode = code;   goto done; } while (0)
    #define WAIT(cond) do if (!(cond)) { __retcode = CNO_OK; goto done; } while (0)

    while (!conn->closed) switch (conn->state) {
        case CNO_CONNECTION_HTTP1_INIT: {
            if (cno_stream_new(conn, 1, conn->client == CNO_PEER_LOCAL) == NULL) {
                STOP(CNO_PROPAGATE);
            }

            conn->state = CNO_CONNECTION_HTTP1_READY;
            break;
        }

        case CNO_CONNECTION_HTTP1_READY: {
            // Ignore leading CR/LFs.
            {
                char *buf = conn->buffer.data;
                char *end = conn->buffer.size + buf;
                while (buf != end && (*buf == '\r' || *buf == '\n')) ++buf;
                cno_io_vector_shift(&conn->buffer, buf - conn->buffer.data);
            }

            // Should be exactly one stream right now.
            cno_stream_t *stream = cno_stream_find(conn, 1);
            conn->http1_remaining = 0;
            WAIT(conn->buffer.size);

            // The HTTP 2 client preface starts with pseudo-broken HTTP/1.x.
            // PicoHTTPParser will reject it, but we want to know if the client speaks HTTP 2.
            if (!conn->client) {
                int may_be_http2 = strncmp(conn->buffer.data, CNO_PREFACE.data, conn->buffer.size) == 0;
                WAIT(conn->buffer.size >= CNO_PREFACE.size || !may_be_http2);
                if  (conn->buffer.size >= CNO_PREFACE.size &&  may_be_http2) {
                    // Definitely HTTP2. Stream 1 should be recycled, though.
                    cno_stream_destroy(conn, stream);
                    conn->last_stream[0] = 0;
                    conn->last_stream[1] = 0;
                    conn->state = CNO_CONNECTION_INIT;
                    break;
                }
            }

            size_t header_num = CNO_MAX_HEADERS;
            struct phr_header headers[CNO_MAX_HEADERS], *it = headers, *end;

            int minor;
            int ok = conn->client
              ? phr_parse_response(conn->buffer.data, conn->buffer.size, &minor,
                                    &stream->msg.code,
                    (const char **) &stream->msg.method.data,
                                    &stream->msg.method.size,
                                    headers, &header_num, 1)
              : phr_parse_request(conn->buffer.data, conn->buffer.size,
                    (const char **) &stream->msg.method.data,
                                    &stream->msg.method.size,
                    (const char **) &stream->msg.path.data,
                                    &stream->msg.path.size,
                                    &minor, headers, &header_num, 1);

            WAIT(ok != -2);

            if (ok == -1) {
                STOP(CNO_ERROR_TRANSPORT("bad HTTP/1.x request"));
            }

            if (minor != 1) {
                STOP(CNO_ERROR_TRANSPORT("bad HTTP/1.x request: HTTP/1.%d not supported", minor));
            }

            for (end = it + header_num; it != end; ++it) {
                char * name  = (char *) it->name;
                size_t size  = (size_t) it->name_len;
                char * value = (char *) it->value;
                size_t vsize = (size_t) it->value_len;

                {
                    char *it  = name;
                    char *end = name + size;
                    for (; it != end; ++it) *it = tolower(*it);
                }

                if (strncmp(name, "http2-settings", size) == 0) {
                    // TODO decode & emit on_frame
                } else

                if (strncmp(name, "upgrade", size) == 0 && strncmp(value, "h2c", vsize) == 0) {
                    cno_header_t upgrade_headers[] = {
                        { CNO_IO_VECTOR_CONST("connection"), CNO_IO_VECTOR_CONST("upgrade") },
                        { CNO_IO_VECTOR_CONST("upgrade"),    CNO_IO_VECTOR_CONST("h2c")     },
                    };

                    cno_message_t upgrade_msg = { 101, CNO_IO_VECTOR_EMPTY, CNO_IO_VECTOR_EMPTY, upgrade_headers, 2 };

                    if (cno_write_message(conn, stream->id, &upgrade_msg, 1)) {
                        STOP(CNO_PROPAGATE);
                    }

                    // If we send the preface now, we'll be able to send HTTP 2 frames
                    // while in the HTTP1_READING_UPGRADE state.
                    if (cno_connection_upgrade(conn)) {
                        STOP(CNO_PROPAGATE);
                    }
                    // Technically, server should refuse if HTTP2-Settings are not present.
                    // We'll let this slide.
                    conn->state = CNO_CONNECTION_HTTP1_READING_UPGRADE;
                } else

                if (strncmp(name, "content-length", size) == 0) {
                    if (conn->http1_remaining) {
                        STOP(CNO_ERROR_TRANSPORT("bad HTTP/1.x request: multiple content-lengths"));
                    }

                    conn->http1_remaining = (size_t) atoi(value);
                } else

                if (strncmp(name, "transfer-encoding", size) == 0) {
                    if (strncmp(value, "chunked", vsize) != 0) {
                        STOP(CNO_ERROR_TRANSPORT("bad HTTP/1.x request: unknown transfer-encoding"));
                    }

                    if (conn->http1_remaining) {
                        STOP(CNO_ERROR_TRANSPORT("bad HTTP/1.x request: chunked encoding w/ fixed length"));
                    }

                    conn->http1_remaining = (size_t) -1;
                }
            }

            // `phr_header` and `cno_header_t` have same contents.
            stream->msg.headers     = (cno_header_t *) &headers;
            stream->msg.headers_len = header_num;
            stream->state = CNO_STREAM_OPEN;

            if (conn->state == CNO_CONNECTION_HTTP1_READY) {
                conn->state = CNO_CONNECTION_HTTP1_READING;
            }

            cno_io_vector_shift(&conn->buffer, (size_t) ok);

            if (CNO_FIRE(conn, on_message_start, stream->id, &stream->msg)) {
                STOP(CNO_PROPAGATE);
            }

            break;
        }

        case CNO_CONNECTION_HTTP1_READING:
        case CNO_CONNECTION_HTTP1_READING_UPGRADE: {
            cno_stream_t *stream = cno_stream_find(conn, 1);

            WAIT(conn->buffer.size || !conn->http1_remaining);

            if (conn->http1_remaining == (size_t) -1) {
                char *it  = conn->buffer.data;
                char *end = conn->buffer.size + it;
                char *eol = it; while (eol != end && *eol++ != '\n');
                char *lim = it; while (lim != eol && *lim++ != ';');
                WAIT(eol != end);

                size_t data_len = 0;
                size_t head_len = (eol - it) + 2;  // + \r\n

                for (; it != lim; ++it) data_len =
                    '0' <= *it && *it <= '9' ? (data_len << 4) | (*it - '0'     ) :
                    'A' <= *it && *it <= 'F' ? (data_len << 4) | (*it - 'A' + 10) :
                    'a' <= *it && *it <= 'f' ? (data_len << 4) | (*it - 'a' + 10) : data_len;

                WAIT(conn->buffer.size >= data_len + head_len);

                if (data_len) {
                    if (CNO_FIRE(conn, on_message_data, stream->id, eol, data_len)) {
                        STOP(CNO_PROPAGATE);
                    }
                } else {
                    // That was the last chunk.
                    conn->http1_remaining = 0;
                }

                cno_io_vector_shift(&conn->buffer, data_len + head_len);
                break;
            }

            if (conn->http1_remaining) {
                size_t data_len = conn->http1_remaining;
                char * data_buf = conn->buffer.data;

                if (data_len > conn->buffer.size) {
                    data_len = conn->buffer.size;
                }

                if (CNO_FIRE(conn, on_message_data, stream->id, data_buf, data_len)) {
                    STOP(CNO_PROPAGATE);
                }

                conn->http1_remaining -= data_len;
                cno_io_vector_shift(&conn->buffer, data_len);
                break;
            }

            if (conn->state == CNO_CONNECTION_HTTP1_READING_UPGRADE) {
                conn->state = CNO_CONNECTION_PREFACE;
                stream->state = CNO_STREAM_CLOSED_REMOTE;
            } else {
                conn->state = CNO_CONNECTION_HTTP1_READY;
                stream->state = CNO_STREAM_IDLE;
            }

            if (CNO_FIRE(conn, on_message_end, stream->id)) {
                STOP(CNO_PROPAGATE);
            }

            break;
        }

        case CNO_CONNECTION_INIT: {
            conn->state = CNO_CONNECTION_PREFACE;

            if (cno_connection_upgrade(conn)) {
                STOP(CNO_PROPAGATE);
            }

            break;
        }

        case CNO_CONNECTION_PREFACE: {
            if (!conn->client) {
                WAIT(conn->buffer.size >= CNO_PREFACE.size);

                if (strncmp(conn->buffer.data, CNO_PREFACE.data, CNO_PREFACE.size)) {
                    STOP(CNO_ERROR_TRANSPORT("invalid HTTP 2 client preface"));
                }

                cno_io_vector_shift(&conn->buffer, CNO_PREFACE.size);
            }

            conn->state = CNO_CONNECTION_READY_NO_SETTINGS;
        }  // fallthrough

        case CNO_CONNECTION_READY_NO_SETTINGS:
        case CNO_CONNECTION_READY: {
            WAIT(conn->buffer.size >= 3);

            unsigned char *base = (unsigned char *) conn->buffer.data;
            size_t m = read3(base);

            if (m > conn->settings[CNO_PEER_LOCAL].max_frame_size) {
                STOP(CNO_ERROR_GOAWAY(conn, CNO_STATE_FRAME_SIZE_ERROR, "recv'd a frame that is too big"));
            }

            WAIT(conn->buffer.size >= 9 + m);

            conn->frame.payload.size = m;
            conn->frame.type         = read1(base + 3);
            conn->frame.flags        = read1(base + 4);
            conn->frame.stream       = read4(base + 5);
            conn->frame.payload.data = (char *) base + 9;

            if (conn->state == CNO_CONNECTION_READY_NO_SETTINGS && conn->frame.type != CNO_FRAME_SETTINGS) {
                STOP(CNO_ERROR_TRANSPORT("invalid HTTP 2 preface: no initial SETTINGS"));
            }

            conn->state = CNO_CONNECTION_READY;
            cno_io_vector_shift(&conn->buffer, 9 + conn->frame.payload.size);

            if (CNO_FIRE(conn, on_frame, &conn->frame)) {
                STOP(CNO_PROPAGATE);
            }

            if (cno_frame_handle(conn, &conn->frame)) {
                STOP(CNO_PROPAGATE);
            }

            break;
        }

        default: STOP(CNO_ERROR_INVALID_STATE("fell to the bottom of the DFA"));
    }

    #undef STOP
    #undef WAIT

    // Since previous `data_received` had finished, the data in the buffer
    // is incomplete (and useless).
    cno_io_vector_reset(&conn->buffer);
    cno_io_vector_clear((cno_io_vector_t *) &conn->buffer);

    cno_set_iterate(&conn->streams, cno_stream_t *, stream, {
        if (cno_stream_destroy_clean(conn, stream)) {
            return CNO_PROPAGATE;
        }
    });

    return CNO_OK;

done:

    if (cno_io_vector_strip(&conn->buffer)) {
        return CNO_PROPAGATE;
    }

    return __retcode;
}


int cno_connection_data_received(cno_connection_t *conn, const char *data, size_t length)
{
    if (conn->closed) {
        return CNO_ERROR_INVALID_STATE("already closed");
    }

    if (cno_io_vector_extend_tmp(&conn->buffer, data, length)) {
        return CNO_PROPAGATE;
    }

    return cno_connection_made(conn);
}


int cno_connection_stop(cno_connection_t *conn)
{
    if (cno_connection_is_http2(conn)) {
        return cno_frame_write_goaway(conn, CNO_STATE_NO_ERROR);
    }

    return CNO_OK;
}


int cno_connection_lost(cno_connection_t *conn)
{
    if (!conn->closed) {
        conn->closed = 1;

        if (cno_connection_made(conn)) {
            conn->closed = 0;
            return CNO_PROPAGATE;
        }
    }

    return CNO_OK;
}


static inline const char *cno_message_literal(const struct cno_st_message_t *msg)
{
    switch (msg->code) {
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 305: return "Use Proxy";
        case 306: return "(Unused)";
        case 307: return "Temporary Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 402: return "Payment Required";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Request Entity Too Large";
        case 414: return "Request-URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Requested Range Not Satisfiable";
        case 417: return "Expectation Failed";
        case 428: return "Precondition Required";
        case 429: return "Too Many Requests";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
        case 511: return "Network Authentication Required";
        default:  return "Unknown";
    }
}


int cno_write_reset(cno_connection_t *conn, size_t stream)
{
    return cno_frame_write_rst_stream(conn, stream, CNO_STATE_NO_ERROR);
}


int cno_write_push(cno_connection_t *conn, size_t stream, const cno_message_t *msg)
{
    if (conn->client) {
        return CNO_ERROR_ASSERTION("clients can't push");
    }

    if (!cno_connection_is_http2(conn) || !conn->settings[CNO_PEER_REMOTE].enable_push) {
        return CNO_OK;  // non-critical error
    }

    if (cno_stream_is_local(conn, stream)) {
        return CNO_OK;  // don't push in response to our own push
    }

    cno_stream_t *streamobj = cno_stream_find(conn, stream);

    if (streamobj == NULL || !(streamobj->accept & CNO_ACCEPT_WRITE_PUSH)) {
        return CNO_ERROR_INVALID_STREAM("stream %lu is not a response stream", stream);
    }

    size_t child = cno_stream_next_id(conn);
    cno_stream_t *childobj = cno_stream_new(conn, child, CNO_PEER_LOCAL);

    if (childobj == NULL) {
        return NULL;
    }

    childobj->state  = CNO_STREAM_RESERVED_LOCAL;
    childobj->accept = CNO_ACCEPT_WRITE_HEADERS;

    unsigned char childid[4];
    write4(childid, child);

    cno_frame_t frame = { CNO_FRAME_PUSH_PROMISE, CNO_FLAG_END_HEADERS, stream, CNO_IO_VECTOR_EMPTY };
    cno_header_t head[2] = {
        { CNO_IO_VECTOR_CONST(":method"), msg->method },
        { CNO_IO_VECTOR_CONST(":path"),   msg->path   },
    };

    if (cno_io_vector_extend(&frame.payload, (char *) childid, 4)
     || cno_hpack_encode(&conn->encoder, &frame.payload, head, 2)
     || cno_hpack_encode(&conn->encoder, &frame.payload, msg->headers, msg->headers_len)
     || cno_frame_write(conn, &frame, streamobj))
    {
        cno_stream_destroy_clean(conn, childobj);
        cno_io_vector_clear(&frame.payload);
        return CNO_PROPAGATE;
    }

    cno_io_vector_clear(&frame.payload);
    return CNO_FIRE(conn, on_message_start, child, msg)
        || CNO_FIRE(conn, on_message_end,   child);
}


int cno_write_message(cno_connection_t *conn, size_t stream, const cno_message_t *msg, int final)
{
    if (conn->closed) {
        return CNO_ERROR_INVALID_STATE("connection closed");
    }

    if (!cno_connection_is_http2(conn)) {
        if (stream != 1) {
            return CNO_ERROR_INVALID_STREAM("can only write to stream 1 in HTTP 1 mode, not %lu", stream);
        }

        char head[CNO_MAX_HTTP1_HEADER_SIZE], *ptr = head;
        cno_header_t *it  = msg->headers;
        cno_header_t *end = msg->headers_len + it;

        if (conn->client) {
            if (msg->method.size + msg->path.size >= CNO_MAX_HTTP1_HEADER_SIZE - sizeof(" HTTP/1.1\r\n")) {
                return CNO_ERROR_ASSERTION("path + method too long");
            }

            ptr = write_vector(ptr, &msg->method);
            ptr = write_string(ptr, " ");
            ptr = write_vector(ptr, &msg->path);
            ptr = write_string(ptr, " HTTP/1.1\r\n");
        } else {
            ptr = write_format(ptr, "HTTP/1.1 %d %s\r\n", msg->code, cno_message_literal(msg));
        }

        for (; it != end; ++it) {
            if (CNO_FIRE(conn, on_write, head, ptr - head)) {
                return CNO_PROPAGATE;
            }

            ptr = head;

            if (it->name.size + it->value.size + 4 >= CNO_MAX_HTTP1_HEADER_SIZE) {
                return CNO_ERROR_TRANSPORT("header too long");
            }

            if (strncmp(it->name.data, ":authority", it->name.size) == 0) {
                ptr = write_string(ptr, "host: ");
            } else if (strncmp(it->name.data, ":status", it->name.size) == 0) {
                return CNO_ERROR_ASSERTION("set `message.code` instead of sending :status");
            } else if (it->name.data[0] == ':') {
                continue;
            } else {
                ptr = write_vector(ptr, &it->name);
                ptr = write_string(ptr, ": ");
            }

            ptr = write_vector(ptr, &it->value);
            ptr = write_string(ptr, "\r\n");
        }

        ptr = write_string(ptr, "\r\n");
        return CNO_FIRE(conn, on_write, head, ptr - head);
    }

    cno_stream_t *streamobj = cno_stream_find(conn, stream);

    if (streamobj == NULL) {
        if (!conn->client) {
            return CNO_ERROR_INVALID_STREAM("responding to invalid stream %lu", stream);
        }

        streamobj = cno_stream_new(conn, stream, CNO_PEER_LOCAL);

        if (streamobj == NULL) {
            return CNO_PROPAGATE;
        }

        streamobj->accept = CNO_ACCEPT_HEADERS | CNO_ACCEPT_PUSH | CNO_ACCEPT_WRITE_HEADERS;
    }

    if (!(streamobj->accept & CNO_ACCEPT_WRITE_HEADERS)) {
        return CNO_ERROR_INVALID_STREAM("stream %lu not writable", stream);
    }

    cno_frame_t frame = { CNO_FRAME_HEADERS, CNO_FLAG_END_HEADERS, stream, CNO_IO_VECTOR_EMPTY };

    if (final) {
        frame.flags |= CNO_FLAG_END_STREAM;
    }

    if (conn->client) {
        cno_header_t head[] = {
            { CNO_IO_VECTOR_CONST(":method"), msg->method },
            { CNO_IO_VECTOR_CONST(":path"),   msg->path   },
        };

        if (cno_hpack_encode(&conn->encoder, &frame.payload, head, 2)) {
            if (streamobj->state == CNO_STREAM_IDLE) {
                // this time the error is (maybe) recoverable so we should clean up.
                cno_stream_destroy_clean(conn, streamobj);
            }

            return CNO_PROPAGATE;
        }
    } else {
        char code[10] = { 0 };
        snprintf(code, 10, "%d", msg->code);

        cno_header_t head[] = {
            { CNO_IO_VECTOR_CONST(":status"), CNO_IO_VECTOR_STRING(code) }
        };

        if (cno_hpack_encode(&conn->encoder, &frame.payload, head, 1)) {
            // stream initiated by client, we 100% did not create the object.
            return CNO_PROPAGATE;
        }
    }

    if (cno_hpack_encode(&conn->encoder, &frame.payload, msg->headers, msg->headers_len)
     || cno_frame_write(conn, &frame, streamobj))
    {
        if (streamobj->state == CNO_STREAM_IDLE) {
            cno_stream_destroy_clean(conn, streamobj);
        }

        cno_io_vector_clear(&frame.payload);
        return CNO_PROPAGATE;
    }

    cno_io_vector_clear(&frame.payload);

    if (streamobj->state == CNO_STREAM_IDLE) {
        streamobj->state = CNO_STREAM_OPEN;
    } else if (streamobj->state == CNO_STREAM_RESERVED_LOCAL) {
        streamobj->state = CNO_STREAM_CLOSED_REMOTE;
    }

    if (final) {
        return cno_stream_close(conn, streamobj);
    }

    streamobj->accept &= ~CNO_ACCEPT_WRITE_HEADERS;
    streamobj->accept |=  CNO_ACCEPT_WRITE_DATA;
    return CNO_OK;
}


int cno_write_data(cno_connection_t *conn, size_t stream, const char *data, size_t length, int final)
{
    if (conn->closed) {
        return CNO_ERROR_INVALID_STATE("connection closed");
    }

    if (!cno_connection_is_http2(conn)) {
        if (stream != 1) {
            return CNO_ERROR_INVALID_STREAM("can only write to stream 1 in HTTP 1 mode, not %lu", stream);
        }

        return length && CNO_FIRE(conn, on_write, data, length) ? CNO_PROPAGATE : CNO_OK;
    }

    cno_stream_t *streamobj = cno_stream_find(conn, stream);

    if (streamobj == NULL) {
        return CNO_ERROR_INVALID_STREAM("stream %lu does not exist", stream);
    }

    if (!(streamobj->accept & CNO_ACCEPT_WRITE_DATA)) {
        return CNO_ERROR_INVALID_STREAM("can't carry data over stream %lu", stream);
    }

    cno_frame_t frame = { CNO_FRAME_DATA, final ? CNO_FLAG_END_STREAM : 0, stream };
    frame.payload.data = (char *) data;
    frame.payload.size = length;

    if (cno_frame_write(conn, &frame, streamobj)) {
        return CNO_PROPAGATE;
    }

    return final ? cno_stream_close(conn, streamobj) : CNO_OK;
}
