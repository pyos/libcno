#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cno.h"
#include "picohttpparser/picohttpparser.h"


static inline uint8_t  read1(uint8_t *p) { return p[0]; }
static inline uint16_t read2(uint8_t *p) { return p[0] <<  8 | p[1]; }
static inline uint32_t read4(uint8_t *p) { return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }
static inline uint32_t read3(uint8_t *p) { return read4(p) >> 8; }

#define I8(x)  x
#define I16(x) x >> 8, x
#define I24(x) x >> 16, x >> 8, x
#define I32(x) x >> 24, x >> 16, x >> 8, x
#define PACK(...) (char *) (uint8_t []) { __VA_ARGS__ }, sizeof((uint8_t []) { __VA_ARGS__ })

static inline char *write_vector(char *ptr, const cno_io_vector_t *vec) { return (char *) memcpy(ptr, vec->data, vec->size) + vec->size; }
static inline char *write_string(char *ptr, const char *data)           { return (char *) memcpy(ptr, data, strlen(data)) + strlen(data); }
#define write_format(ptr, ...) (ptr + sprintf(ptr, ##__VA_ARGS__))
#define WRITE_GOAWAY(conn, type, ...) (cno_frame_write_goaway(conn, CNO_STATE_##type) ? CNO_PROPAGATE : CNO_ERROR(TRANSPORT, __VA_ARGS__))


static const cno_io_vector_t CNO_PREFACE = CNO_IO_VECTOR_CONST("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
static const cno_settings_t  CNO_SETTINGS_STANDARD = {{{ 4096, 1, -1,   65536, 16384, -1 }}};
static const cno_settings_t  CNO_SETTINGS_INITIAL  = {{{ 4096, 1, 1024, 65536, 65536, -1 }}};
const char *CNO_FRAME_NAME[256] = {
    "DATA",         "HEADERS", "PRIORITY", "RST_STREAM",    "SETTINGS",
    "PUSH_PROMISE", "PING",    "GOAWAY",   "WINDOW_UPDATE", "CONTINUATION",
};


inline uint32_t cno_stream_next_id(cno_connection_t *conn)
{
    uint32_t last = conn->last_stream[CNO_PEER_LOCAL];
    return cno_connection_is_http2(conn) && (last || !conn->client) ? last + 2 : 1;
}


static inline int cno_stream_is_local(cno_connection_t *conn, uint32_t id)
{
    return (int) (id % 2) == !!conn->client;
}


static void cno_stream_destroy(cno_connection_t *conn, cno_stream_t *stream)
{
    conn->stream_count[cno_stream_is_local(conn, stream->id)]--;
    cno_io_vector_clear(&stream->buffer);
    cno_set_remove(&conn->streams, stream);
    free(stream);
}


static int cno_stream_destroy_clean(cno_connection_t *conn, cno_stream_t *stream)
{
    uint32_t id = stream->id;
    cno_stream_destroy(conn, stream);
    return CNO_FIRE(conn, on_stream_end, id);
}


static int cno_stream_close(cno_connection_t *conn, cno_stream_t *stream)
{
    if (!(stream->accept & CNO_ACCEPT_INBOUND)) {
        return cno_stream_destroy_clean(conn, stream);
    }

    stream->accept &= ~CNO_ACCEPT_OUTBOUND;
    return CNO_OK;
}


static cno_stream_t * cno_stream_new(cno_connection_t *conn, uint32_t id, int local)
{
    if (cno_stream_is_local(conn, id) != local) {
        (void) CNO_ERROR(INVALID_STREAM, "invalid stream ID (%u != %d mod 2)", id, local + !conn->client);
        return NULL;
    }

    if (id <= conn->last_stream[local]) {
        (void) CNO_ERROR(INVALID_STREAM, "invalid stream ID (%u <= %u)", id, conn->last_stream[local]);
        return NULL;
    }

    if (conn->stream_count[local] >= conn->settings[!local].max_concurrent_streams) {
        (void) (local ? CNO_ERROR(WOULD_BLOCK, "initiated too many concurrent streams; wait for on_stream_end")
                      : CNO_ERROR(TRANSPORT, "received too many concurrent streams"));
        return NULL;
    }

    cno_stream_t *stream = calloc(1, sizeof(cno_stream_t));

    if (!stream) {
        (void) CNO_ERROR(NO_MEMORY, "--");
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


static inline cno_stream_t * cno_stream_find(cno_connection_t *conn, uint32_t id)
{
    return id ? cno_set_find(&conn->streams, id) : NULL;
}


static int cno_frame_write(cno_connection_t *conn, cno_frame_t *frame, cno_stream_t *stream)
{
    size_t length = frame->payload.size;
    size_t limit  = conn->settings[CNO_PEER_REMOTE].max_frame_size;

    if (frame->type == CNO_FRAME_DATA) {
        if (length > conn->window_send) {
            return CNO_ERROR(WOULD_BLOCK, "frame exceeds connection flow window (%zu > %u)",
                length, conn->window_send);
        }

        if (stream) {
            if (length > stream->window_send) {
                return CNO_ERROR(WOULD_BLOCK, "frame exceeds stream flow window (%zu > %u)",
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
            return CNO_ERROR(ASSERTION, "frame too big (%zu > %zu)", length, limit);
        }

        if (part.flags & CNO_FLAG_PADDED) {
            return CNO_ERROR(ASSERTION, "don't know how to split padded frames");
        }

        uint8_t endflags = part.flags & (part.type == CNO_FRAME_DATA ? CNO_FLAG_END_STREAM : CNO_FLAG_END_HEADERS);

        part.flags &= ~endflags;
        part.payload.size = limit;

        for (; length > limit; length -= part.payload.size, part.payload.data += part.payload.size) {
            if (cno_frame_write(conn, &part, stream)) {
                return CNO_PROPAGATE;
            }

            if (part.type == CNO_FRAME_HEADERS || part.type == CNO_FRAME_PUSH_PROMISE) {
                part.type = CNO_FRAME_CONTINUATION;
            }

            part.flags &= ~(CNO_FLAG_PRIORITY | CNO_FLAG_END_STREAM);
        }

        part.flags |= endflags;
        part.payload.size = length;
        return cno_frame_write(conn, &part, stream);
    }

    return CNO_FIRE(conn, on_frame_send, frame)
        || CNO_FIRE(conn, on_write, PACK(I24(length), I8(frame->type), I8(frame->flags), I32(frame->stream)))
        || (length && CNO_FIRE(conn, on_write, frame->payload.data, length));
}


static int cno_frame_write_goaway(cno_connection_t *conn, uint32_t /* enum CNO_STATE_CODE */ code)
{
    cno_frame_t error = { CNO_FRAME_GOAWAY, 0, 0, { PACK(I32(conn->last_stream[CNO_PEER_REMOTE]), I32(code)) } };
    return cno_frame_write(conn, &error, NULL);
}


static int cno_frame_write_rst_stream(cno_connection_t *conn, uint32_t stream, uint32_t /* enum CNO_STATE_CODE */ code)
{
    if (!stream) {
        return CNO_ERROR(ASSERTION, "RST'd stream 0");
    }

    cno_stream_t *obj = cno_stream_find(conn, stream);

    if (!obj) {
        return CNO_OK;  // assume stream already ended naturally
    }

    cno_frame_t error = { CNO_FRAME_RST_STREAM, 0, stream, { PACK(I32(code)) } };

    if (cno_frame_write(conn, &error, obj)) {
        return CNO_PROPAGATE;
    }

    // a stream in closed state can still accept headers/data.
    // headers will be decompressed; other than that, everything is ignored.
    obj->closed = 1;

    if (!(obj->accept & (CNO_ACCEPT_HEADERS | CNO_ACCEPT_HEADCNT))) {
        // since headers were already handled, this stream can be safely destroyed.
        return cno_stream_destroy_clean(conn, obj);
    }

    return CNO_OK;
}


static int cno_frame_handle_flow(cno_connection_t *conn, cno_stream_t *stream, cno_frame_t *frame)
{
    if (frame->payload.size) {
        cno_frame_t update = { CNO_FRAME_WINDOW_UPDATE, 0, 0, { PACK(I32(frame->payload.size)) } };

        if (cno_frame_write(conn, &update, NULL)) {
            return CNO_PROPAGATE;
        }

        if (stream) {
            update.stream = frame->stream;

            if (cno_frame_write(conn, &update, stream)) {
                return CNO_PROPAGATE;
            }
        }
    }

    return CNO_OK;
}


static int cno_frame_handle_end_headers(cno_connection_t *conn, cno_stream_t *stream, cno_frame_t *frame)
{
    cno_header_t  headers[CNO_MAX_HEADERS];
    cno_header_t *it;
    cno_message_t msg = { 0, CNO_IO_VECTOR_EMPTY, CNO_IO_VECTOR_EMPTY, headers, CNO_MAX_HEADERS };

    if (cno_hpack_decode(&conn->decoder, &stream->buffer, headers, &msg.headers_len)) {
        cno_io_vector_clear(&stream->buffer);
        cno_frame_write_goaway(conn, CNO_STATE_COMPRESSION_ERROR);
        return CNO_PROPAGATE;
    }

    cno_io_vector_clear(&stream->buffer);

    #if CNO_HTTP2_ENFORCE_MESSAGING_RULES
        int seen_normal = 0;
    #endif

    for (it = headers; it != headers + msg.headers_len; ++it) {
        #if CNO_HTTP2_ENFORCE_MESSAGING_RULES
            if (it->name.size && it->name.data[0] == ':') {
                if (seen_normal) {
                    return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "pseudo-header after normal header");
                }
            } else {
                seen_normal = 1;
            }
        #endif

        if (strncmp(it->name.data, ":status", it->name.size) == 0) {
            #if CNO_HTTP2_ENFORCE_MESSAGING_RULES
                if (!conn->client) {
                    return WRITE_GOAWAY(conn, PROTOCOL_ERROR, ":status in a request");
                }

                if (msg.code) {
                    return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "two :status-es");
                }
            #endif

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
            #if CNO_HTTP2_ENFORCE_MESSAGING_RULES
                if (conn->client && frame->type == CNO_FRAME_HEADERS) {
                    return WRITE_GOAWAY(conn, PROTOCOL_ERROR, ":path in a response");
                }

                if (msg.path.data) {
                    return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "two :path-s");
                }
            #endif

            msg.path.data = it->value.data;
            msg.path.size = it->value.size;
        } else

        if (strncmp(it->name.data, ":method", it->name.size) == 0) {
            #if CNO_HTTP2_ENFORCE_MESSAGING_RULES
                if (conn->client && frame->type == CNO_FRAME_HEADERS) {
                    return WRITE_GOAWAY(conn, PROTOCOL_ERROR, ":method in a response");
                }

                if (msg.method.data) {
                    return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "two :method-s");
                }
            #endif

            msg.method.data = it->value.data;
            msg.method.size = it->value.size;
        }

        #if CNO_HTTP2_ENFORCE_MESSAGING_RULES
            else if (it->name.size && it->name.data[0] == ':'
              && strncmp(it->name.data, ":authority", it->name.size)
              && strncmp(it->name.data, ":scheme",    it->name.size))
            {
                return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "invalid pseudo-header");
            } else {
                char *p = it->name.data;
                char *e = it->name.size + p;

                while (p != e) {
                    if (isupper(*p++)) {
                        return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "non-lowercase header name");
                    }
                }
            }
        #endif
    }

    #if CNO_HTTP2_ENFORCE_MESSAGING_RULES
        if (conn->client && frame->type == CNO_FRAME_HEADERS) {
            if (msg.code == 0) {
                return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "no :status in a response");
            }
        } else {
            if (msg.method.data == NULL) {
                return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "no :method in a request");
            }

            if (msg.path.data == NULL) {
                return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "no :path in a request");
            }
        }
    #endif

    int failed;

    if (frame->type != CNO_FRAME_HEADERS) {
        // accept pushes even on reset streams.
        stream->accept &= ~CNO_ACCEPT_PUSHCNT;
        failed = CNO_FIRE(conn, on_message_push, stream->last_promise, &msg, frame->stream);
    } else if (stream->closed) {
        // can finally destroy the thing.
        failed = cno_stream_destroy_clean(conn, stream);
    } else {
        stream->accept &= ~(CNO_ACCEPT_HEADERS | CNO_ACCEPT_HEADCNT);
        stream->accept |=   CNO_ACCEPT_DATA;
        failed = CNO_FIRE(conn, on_message_start, frame->stream, &msg);
    }

    for (it = headers; it != headers + msg.headers_len; ++it) {
        cno_io_vector_clear(&it->name);
        cno_io_vector_clear(&it->value);
    }

    return failed;
}


static int cno_frame_handle_end_stream(cno_connection_t *conn, cno_stream_t *stream, cno_frame_t *frame)
{
    stream->accept &= ~CNO_ACCEPT_INBOUND;

    if (!(stream->accept & CNO_ACCEPT_OUTBOUND)) {
        if (cno_stream_destroy_clean(conn, stream)) {
            return CNO_PROPAGATE;
        }
    }

    return CNO_FIRE(conn, on_message_end, frame->stream);
}


static int cno_frame_handle_headers(cno_connection_t *conn, cno_stream_t *stream, cno_frame_t *frame, int rstd)
{
    if (stream == NULL) {
        stream = cno_stream_new(conn, frame->stream, CNO_PEER_REMOTE);

        if (stream == NULL) {
            return CNO_PROPAGATE;
        }

        stream->accept = CNO_ACCEPT_HEADERS | CNO_ACCEPT_WRITE_HEADERS | CNO_ACCEPT_WRITE_PUSH;
    }

    if (!(stream->accept & (CNO_ACCEPT_HEADERS | CNO_ACCEPT_HEADCNT))) {
        return CNO_ERROR(TRANSPORT, "got HEADERS on a stream in wrong state");
    }

    stream->last_flags = CNO_FLAG_END_STREAM & frame->flags;
    stream->accept &= ~CNO_ACCEPT_HEADERS;
    stream->accept |=  CNO_ACCEPT_HEADCNT;

    if (cno_io_vector_extend(&stream->buffer, frame->payload.data, frame->payload.size)) {
        // note that we could've created the stream, but we don't need to bother
        // destroying it. this error is non-recoverable; connection_destroy
        // will handle things.
        return CNO_PROPAGATE;
    }

    if (frame->flags & CNO_FLAG_END_HEADERS) {
        if (cno_frame_handle_end_headers(conn, stream, frame)) {
            return CNO_PROPAGATE;
        }

        if (frame->flags & CNO_FLAG_END_STREAM) {
            return cno_frame_handle_end_stream(conn, stream, frame);
        }
    }

    return CNO_OK;
}


static int cno_frame_handle_push_promise(cno_connection_t *conn, cno_stream_t *stream, cno_frame_t *frame, int rstd)
{
    if (!conn->client) {
        return CNO_ERROR(TRANSPORT, "clients can't push");
    }

    if (!conn->settings[CNO_PEER_LOCAL].enable_push) {
        return CNO_ERROR(TRANSPORT, "push disabled");
    }

    if (!(stream && (stream->accept & (CNO_ACCEPT_PUSH | CNO_ACCEPT_PUSHCNT)))) {
        return CNO_ERROR(TRANSPORT, "PUSH_PROMISE not on an open stream");
    }

    if (frame->type != CNO_FRAME_CONTINUATION) {
        uint32_t promised = read4((uint8_t *) frame->payload.data);
        frame->payload.data += 4;
        frame->payload.size -= 4;

        cno_stream_t *prstream = cno_stream_new(conn, promised, CNO_PEER_REMOTE);

        if (prstream == NULL) {
            return CNO_PROPAGATE;
        }

        prstream->accept = CNO_ACCEPT_HEADERS;
        stream->last_promise = promised;
    }

    stream->last_flags = 0;  // PUSH_PROMISE cannot have END_STREAM

    if (cno_io_vector_extend(&stream->buffer, frame->payload.data, frame->payload.size)) {
        return CNO_PROPAGATE;
    }

    if (frame->flags & CNO_FLAG_END_HEADERS) {
        return cno_frame_handle_end_headers(conn, stream, frame);
    }

    return CNO_OK;
}


static int cno_frame_handle_continuation(cno_connection_t *conn, cno_stream_t *stream, cno_frame_t *frame, int rstd)
{
    if (!stream) {
        return CNO_ERROR(TRANSPORT, "CONTINUATION on a non-existent stream");
    }

    frame->flags |= stream->last_flags;

    if (stream->accept & CNO_ACCEPT_PUSHCNT) {
        return cno_frame_handle_push_promise(conn, stream, frame, rstd);
    }

    if (stream->accept & CNO_ACCEPT_HEADCNT) {
        return cno_frame_handle_headers(conn, stream, frame, rstd);
    }

    return CNO_ERROR(TRANSPORT, "CONTINUATION not after HEADERS/PUSH_PROMISE");
}


static int cno_frame_handle_data(cno_connection_t *conn, cno_stream_t *stream, cno_frame_t *frame, int rstd)
{
    if (!stream) {
        return rstd ? CNO_OK : CNO_ERROR(TRANSPORT, "DATA on nonexistent stream");
    }

    if (stream->accept & CNO_ACCEPT_DATA) {
        if (CNO_FIRE(conn, on_message_data, frame->stream, frame->payload.data, frame->payload.size)) {
            return CNO_PROPAGATE;
        }
    } else {
        if (cno_frame_write_rst_stream(conn, frame->stream, CNO_STATE_STREAM_CLOSED)) {
            return CNO_PROPAGATE;
        }
    }

    if (frame->flags & CNO_FLAG_END_STREAM) {
        return cno_frame_handle_end_stream(conn, stream, frame)
            || cno_frame_handle_flow(conn, NULL, frame);
    }

    return cno_frame_handle_flow(conn, stream, frame);
}


static int cno_frame_handle_ping(cno_connection_t *conn, cno_stream_t *steram, cno_frame_t *frame, int rstd)
{
    if (frame->stream) {
        return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "got stream %u PING-ed", frame->stream);
    }

    if (frame->payload.size != 8) {
        return WRITE_GOAWAY(conn, FRAME_SIZE_ERROR, "bad PING frame (length = %zu)", frame->payload.size);
    }

    if (frame->flags & CNO_FLAG_ACK) {
        return CNO_FIRE(conn, on_pong, frame->payload.data);
    }

    cno_frame_t response = { CNO_FRAME_PING, CNO_FLAG_ACK, 0, frame->payload };
    return cno_frame_write(conn, &response, NULL);
}


static int cno_frame_handle_goaway(cno_connection_t *conn, cno_stream_t *stream, cno_frame_t *frame, int rstd)
{
    if (frame->stream) {
        return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "got GOAWAY on stream %u", frame->stream);
    }

    if (cno_connection_lost(conn)) {
        return CNO_PROPAGATE;
    }

    // TODO parse error code.
    return CNO_OK;
}


static int cno_frame_handle_rst_stream(cno_connection_t *conn, cno_stream_t *stream, cno_frame_t *frame, int rstd)
{
    if (frame->payload.size != 4) {
        return WRITE_GOAWAY(conn, FRAME_SIZE_ERROR, "RST_STREAM of invalid length (%zu != 4)", frame->payload.size);
    }

    if (!stream) {
        return rstd ? CNO_OK : CNO_ERROR(TRANSPORT, "reset of a nonexistent stream");
    }

    if (cno_stream_destroy_clean(conn, stream)) {
        return CNO_PROPAGATE;
    }

    // TODO parse error code.
    return CNO_OK;
}


static int cno_frame_handle_priority(cno_connection_t *conn, cno_stream_t *stream, cno_frame_t *frame, int rstd)
{
    if (!frame->stream) {
        return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "PRIORITY on stream 0");
    }

    if (frame->payload.size != 5) {
        return WRITE_GOAWAY(conn, FRAME_SIZE_ERROR, "PRIORITY of invalid length (%zu != 5)", frame->payload.size);
    }

    // TODO something.
    return CNO_OK;
}


static int cno_frame_handle_settings(cno_connection_t *conn, cno_stream_t *stream, cno_frame_t *frame, int rstd)
{
    if (frame->stream) {
        return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "got SETTINGS on stream %u", frame->stream);
    }

    if (frame->flags & CNO_FLAG_ACK) {
        return frame->payload.size
             ? WRITE_GOAWAY(conn, FRAME_SIZE_ERROR, "bad SETTINGS (ack with length = %zu)", frame->payload.size)
             : CNO_OK;
    }

    if (frame->payload.size % 6) {
        return WRITE_GOAWAY(conn, FRAME_SIZE_ERROR, "bad SETTINGS (length = %zu)", frame->payload.size);
    }

    cno_settings_t *cfg = &conn->settings[CNO_PEER_REMOTE];
    uint8_t *ptr = (uint8_t *) frame->payload.data;
    uint8_t *end = ptr + frame->payload.size;

    for (; ptr != end; ptr += 6) {
        uint16_t setting = read2(ptr);
        uint32_t value   = read4(ptr + 2);

        if (setting && setting < CNO_SETTINGS_UNDEFINED) {
            cfg->array[setting - 1] = value;
        }
    }

    if (cfg->enable_push != 0 && cfg->enable_push != 1) {
        return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "invalid enable_push value (%u != 0, 1)", cfg->enable_push);
    }

    if (cfg->initial_window_size >= 0x80000000u) {
        return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "initial flow window %u out of bounds", cfg->initial_window_size);
    }

    if (cfg->max_frame_size < 16384 || cfg->max_frame_size > 16777215) {
        return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "maximum frame size out of bounds (2^14..2^24-1)");
    }

    conn->encoder.limit_upper = cfg->header_table_size;
    cno_hpack_setlimit(&conn->encoder, conn->encoder.limit_upper);
    // TODO update stream flow control windows.
    cno_frame_t ack = { CNO_FRAME_SETTINGS, CNO_FLAG_ACK, 0, CNO_IO_VECTOR_EMPTY };
    return cno_frame_write(conn, &ack, NULL);
}


static int cno_frame_handle_window_update(cno_connection_t *conn, cno_stream_t *stream, cno_frame_t *frame, int rstd)
{
    if (frame->payload.size != 4) {
        return WRITE_GOAWAY(conn, FRAME_SIZE_ERROR, "bad WINDOW_UPDATE (length = %zu)", frame->payload.size);
    }

    uint32_t increment = read4((uint8_t *) frame->payload.data);

    if (increment == 0 || increment >= 0x80000000u) {
        return CNO_ERROR(TRANSPORT, "bad WINDOW_UPDATE (incr = %u)", increment);
    }

    if (!frame->stream) {
        conn->window_send += increment;

        if (conn->window_send >= 0x80000000u) {
            return WRITE_GOAWAY(conn, FLOW_CONTROL_ERROR, "flow control window got too big (total = %u)", conn->window_send);
        }
    } else if (stream != NULL) {
        stream->window_send += increment;

        if (stream->window_send >= 0x80000000u) {
            return cno_frame_write_rst_stream(conn, frame->stream, CNO_STATE_FLOW_CONTROL_ERROR);
        }
    } else {
        return CNO_ERROR(TRANSPORT, "bad WINDOW_UPDATE (invalid stream)");
    }

    return CNO_FIRE(conn, on_flow_increase, frame->stream);
}


static int cno_frame_handle(cno_connection_t *conn, cno_frame_t *frame)
{
    int rstd = 0 < frame->stream && frame->stream <= conn->last_stream[cno_stream_is_local(conn, frame->stream)];
    cno_stream_t *stream = cno_stream_find(conn, frame->stream);

    if (frame->flags & CNO_FLAG_PADDED) {
        uint16_t pad = 1 + *(uint8_t *) frame->payload.data;

        if (pad >= frame->payload.size) {
            return WRITE_GOAWAY(conn, PROTOCOL_ERROR, "frame padding bigger than whole payload");
        }

        frame->payload.data += pad;
        frame->payload.size -= pad;
    }

    if (frame->flags & CNO_FLAG_PRIORITY) {
        // TODO do something with this info.
        frame->payload.data += 5;
        frame->payload.size -= 5;
    }

    switch (frame->type) {
        case CNO_FRAME_PING:          return cno_frame_handle_ping          (conn, stream, frame, rstd);
        case CNO_FRAME_GOAWAY:        return cno_frame_handle_goaway        (conn, stream, frame, rstd);
        case CNO_FRAME_RST_STREAM:    return cno_frame_handle_rst_stream    (conn, stream, frame, rstd);
        case CNO_FRAME_PRIORITY:      return cno_frame_handle_priority      (conn, stream, frame, rstd);
        case CNO_FRAME_SETTINGS:      return cno_frame_handle_settings      (conn, stream, frame, rstd);
        case CNO_FRAME_WINDOW_UPDATE: return cno_frame_handle_window_update (conn, stream, frame, rstd);
        case CNO_FRAME_HEADERS:       return cno_frame_handle_headers       (conn, stream, frame, rstd);
        case CNO_FRAME_PUSH_PROMISE:  return cno_frame_handle_push_promise  (conn, stream, frame, rstd);
        case CNO_FRAME_CONTINUATION:  return cno_frame_handle_continuation  (conn, stream, frame, rstd);
        case CNO_FRAME_DATA:          return cno_frame_handle_data          (conn, stream, frame, rstd);
        default: return CNO_OK;  // ignore unrecognized frames
    }
}


static int cno_settings_diff(cno_connection_t *conn, const cno_settings_t *old, const cno_settings_t *updated)
{
    size_t i = 0;
    uint8_t payload[CNO_SETTINGS_UNDEFINED - 1][6], (*ptr)[6] = payload;
    const uint32_t *current = old->array;
    const uint32_t *replace = updated->array;

    for (; ++i < CNO_SETTINGS_UNDEFINED; ++current, ++replace) {
        if (*current != *replace) {
            memcpy(ptr++, PACK(I16(i), I32(*replace)));
        }
    }

    cno_frame_t frame = { CNO_FRAME_SETTINGS, 0, 0, { (char *) payload, (ptr - payload) * sizeof(*ptr) } };
    return cno_frame_write(conn, &frame, NULL);
}


void cno_settings_copy(cno_connection_t *conn, cno_settings_t *target)
{
    memcpy(target, conn->settings + CNO_PEER_LOCAL, sizeof(cno_settings_t));
}


int cno_settings_apply(cno_connection_t *conn, const cno_settings_t *new_settings)
{
    if (new_settings->enable_push != 0 && new_settings->enable_push != 1) {
        return CNO_ERROR(ASSERTION, "enable_push neither 0 nor 1");
    }

    if (new_settings->max_frame_size < 16384 || new_settings->max_frame_size > 16777215) {
        return CNO_ERROR(ASSERTION, "maximum frame size out of bounds (2^14..2^24-1)");
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
        (void) CNO_ERROR(NO_MEMORY, "--");
        return NULL;
    }

    conn->kind  = kind;
    conn->state = CNO_CONNECTION_UNDEFINED;
    memcpy(conn->settings,     &CNO_SETTINGS_STANDARD, sizeof(cno_settings_t));
    memcpy(conn->settings + 1, &CNO_SETTINGS_INITIAL,  sizeof(cno_settings_t));
    conn->window_recv = CNO_SETTINGS_STANDARD.initial_window_size;
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


static int cno_connection_fire(cno_connection_t *conn)
{
    int __retcode = CNO_OK;
    #define STOP(code) do              { __retcode = code;   goto done; } while (0)
    #define WAIT(cond) do if (!(cond)) { __retcode = CNO_OK; goto done; } while (0)

    while (!conn->closed) switch (conn->state) {
        case CNO_CONNECTION_UNDEFINED: {
            WAIT(0);  // wait until connection_made before processing data
        }

        case CNO_CONNECTION_HTTP1_INIT: {
            if (cno_stream_new(conn, 1, !!conn->client) == NULL) {
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
                    if (cno_stream_destroy_clean(conn, stream)) {
                        return CNO_PROPAGATE;
                    }

                    conn->last_stream[0] = 0;
                    conn->last_stream[1] = 0;
                    conn->state = CNO_CONNECTION_INIT;
                    break;
                }
            }

            // `phr_header` and `cno_header_t` have same contents.
            cno_header_t headers[CNO_MAX_HEADERS], *it = headers, *end;
            cno_message_t msg = { 0, CNO_IO_VECTOR_EMPTY, CNO_IO_VECTOR_EMPTY, headers, CNO_MAX_HEADERS };

            int minor;
            int ok = conn->client
              ? phr_parse_response(conn->buffer.data, conn->buffer.size, &minor, &msg.code,
                    (const char **) &msg.method.data, &msg.method.size,
                    (struct phr_header *) headers, &msg.headers_len, 0)

              : phr_parse_request(conn->buffer.data, conn->buffer.size,
                    (const char **) &msg.method.data, &msg.method.size,
                    (const char **) &msg.path.data, &msg.path.size,
                    &minor, (struct phr_header *) headers, &msg.headers_len, 0);

            WAIT(ok != -2);

            if (ok == -1) {
                STOP(CNO_ERROR(TRANSPORT, "bad HTTP/1.x message"));
            }

            if (minor != 1) {
                STOP(CNO_ERROR(TRANSPORT, "bad HTTP/1.x message: HTTP/1.%d not supported", minor));
            }

            for (end = it + msg.headers_len; it != end; ++it) {
                char * name  = it->name.data;
                size_t size  = it->name.size;
                char * value = it->value.data;
                size_t vsize = it->value.size;

                {
                    char *it  = name;
                    char *end = name + size;
                    for (; it != end; ++it) *it = tolower(*it);
                }

                if (strncmp(name, "http2-settings", size) == 0) {
                    // TODO decode & emit on_frame
                } else

                if (!conn->client && strncmp(name, "upgrade", size) == 0 && strncmp(value, "h2c", vsize) == 0) {
                    if (conn->state != CNO_CONNECTION_HTTP1_READY) {
                        STOP(CNO_ERROR(TRANSPORT, "bad HTTP/1.x message: multiple upgrade headers"));
                    }

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
                        STOP(CNO_ERROR(TRANSPORT, "bad HTTP/1.x message: multiple content-lengths"));
                    }

                    conn->http1_remaining = (size_t) atoi(value);
                } else

                if (strncmp(name, "transfer-encoding", size) == 0) {
                    if (strncmp(value, "chunked", vsize) != 0) {
                        STOP(CNO_ERROR(TRANSPORT, "bad HTTP/1.x message: unknown transfer-encoding"));
                    }

                    if (conn->http1_remaining) {
                        STOP(CNO_ERROR(TRANSPORT, "bad HTTP/1.x message: chunked encoding w/ fixed length"));
                    }

                    conn->http1_remaining = (size_t) -1;
                }
            }

            stream->accept |= CNO_ACCEPT_WRITE_HEADERS;

            if (conn->state == CNO_CONNECTION_HTTP1_READY) {
                conn->state = CNO_CONNECTION_HTTP1_READING;
            }

            cno_io_vector_shift(&conn->buffer, (size_t) ok);

            if (CNO_FIRE(conn, on_message_start, stream->id, &msg)) {
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
            } else {
                conn->state = CNO_CONNECTION_HTTP1_READY;
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
                    STOP(CNO_ERROR(TRANSPORT, "invalid HTTP 2 client preface"));
                }

                cno_io_vector_shift(&conn->buffer, CNO_PREFACE.size);
            }

            conn->state = CNO_CONNECTION_READY_NO_SETTINGS;
        }  // fallthrough

        case CNO_CONNECTION_READY_NO_SETTINGS:
        case CNO_CONNECTION_READY: {
            WAIT(conn->buffer.size >= 3);

            uint8_t *base = (uint8_t *) conn->buffer.data;
            size_t m = read3(base);

            if (m > conn->settings[CNO_PEER_LOCAL].max_frame_size) {
                STOP(CNO_ERROR(TRANSPORT, "recv'd a frame that is too big"));
            }

            WAIT(conn->buffer.size >= 9 + m);

            cno_frame_t frame = { read1(base + 3), read1(base + 4), read4(base + 5), { (char *) base + 9, m } };

            if (conn->state == CNO_CONNECTION_READY_NO_SETTINGS && frame.type != CNO_FRAME_SETTINGS) {
                STOP(CNO_ERROR(TRANSPORT, "invalid HTTP 2 preface: no initial SETTINGS"));
            }

            conn->state = CNO_CONNECTION_READY;
            cno_io_vector_shift(&conn->buffer, 9 + m);

            if (CNO_FIRE(conn, on_frame, &frame)) {
                STOP(CNO_PROPAGATE);
            }

            if (cno_frame_handle(conn, &frame)) {
                STOP(CNO_PROPAGATE);
            }

            break;
        }

        default: STOP(CNO_ERROR(INVALID_STATE, "fell to the bottom of the DFA"));
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


int cno_connection_made(cno_connection_t *conn, enum CNO_HTTP_VERSION version)
{
    if (conn->state != CNO_CONNECTION_UNDEFINED) {
        return CNO_ERROR(ASSERTION, "called connection_made twice");
    }

    conn->state = version == CNO_HTTP2 ? CNO_CONNECTION_INIT : CNO_CONNECTION_HTTP1_INIT;
    return cno_connection_fire(conn);
}


int cno_connection_data_received(cno_connection_t *conn, const char *data, size_t length)
{
    if (conn->closed) {
        return CNO_ERROR(INVALID_STATE, "already closed");
    }

    if (cno_io_vector_extend_tmp(&conn->buffer, data, length)) {
        return CNO_PROPAGATE;
    }

    return cno_connection_fire(conn);
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

        if (cno_connection_fire(conn)) {
            conn->closed = 0;
            return CNO_PROPAGATE;
        }
    }

    return CNO_OK;
}


int cno_write_reset(cno_connection_t *conn, size_t stream)
{
    return cno_frame_write_rst_stream(conn, stream, CNO_STATE_NO_ERROR);
}


int cno_write_push(cno_connection_t *conn, size_t stream, const cno_message_t *msg)
{
    if (conn->client) {
        return CNO_ERROR(ASSERTION, "clients can't push");
    }

    if (!cno_connection_is_http2(conn) || !conn->settings[CNO_PEER_REMOTE].enable_push) {
        return CNO_OK;  // non-critical error
    }

    if (cno_stream_is_local(conn, stream)) {
        return CNO_OK;  // don't push in response to our own push
    }

    cno_stream_t *streamobj = cno_stream_find(conn, stream);

    if (streamobj == NULL || !(streamobj->accept & CNO_ACCEPT_WRITE_PUSH)) {
        return CNO_ERROR(INVALID_STREAM, "stream %zu is not a response stream", stream);
    }

    uint32_t child = cno_stream_next_id(conn);
    cno_stream_t *childobj = cno_stream_new(conn, child, CNO_PEER_LOCAL);

    if (childobj == NULL) {
        return NULL;
    }

    childobj->accept = CNO_ACCEPT_WRITE_HEADERS;

    cno_frame_t frame = { CNO_FRAME_PUSH_PROMISE, CNO_FLAG_END_HEADERS, stream, CNO_IO_VECTOR_EMPTY };
    cno_header_t head[2] = {
        { CNO_IO_VECTOR_CONST(":method"), msg->method },
        { CNO_IO_VECTOR_CONST(":path"),   msg->path   },
    };

    if (cno_io_vector_extend(&frame.payload, PACK(I32(child)))
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
        return CNO_ERROR(INVALID_STATE, "connection closed");
    }

    if (!cno_connection_is_http2(conn)) {
        if (stream != 1) {
            return CNO_ERROR(INVALID_STREAM, "can only write to stream 1 in HTTP 1 mode, not %zu", stream);
        }

        char head[CNO_MAX_HTTP1_HEADER_SIZE], *ptr = head;
        cno_header_t *it  = msg->headers;
        cno_header_t *end = msg->headers_len + it;

        if (conn->client) {
            if (msg->method.size + msg->path.size >= CNO_MAX_HTTP1_HEADER_SIZE - sizeof(" HTTP/1.1\r\n")) {
                return CNO_ERROR(ASSERTION, "path + method too long");
            }

            ptr = write_vector(ptr, &msg->method);
            ptr = write_string(ptr, " ");
            ptr = write_vector(ptr, &msg->path);
            ptr = write_string(ptr, " HTTP/1.1\r\n");
        } else {
            ptr = write_format(ptr, "HTTP/1.1 %d No Reason\r\n", msg->code);
        }

        ptr = write_string(ptr, "connection: keep-alive\r\n");

        for (; it != end; ++it) {
            if (CNO_FIRE(conn, on_write, head, ptr - head)) {
                return CNO_PROPAGATE;
            }

            ptr = head;

            if (it->name.size + it->value.size + 4 >= CNO_MAX_HTTP1_HEADER_SIZE) {
                return CNO_ERROR(TRANSPORT, "header too long");
            }

            if (strncmp(it->name.data, ":authority", it->name.size) == 0) {
                ptr = write_string(ptr, "host: ");
            } else if (strncmp(it->name.data, ":status", it->name.size) == 0) {
                return CNO_ERROR(ASSERTION, "set `message.code` instead of sending :status");
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
            return CNO_ERROR(INVALID_STREAM, "responding to invalid stream %zu", stream);
        }

        streamobj = cno_stream_new(conn, stream, CNO_PEER_LOCAL);

        if (streamobj == NULL) {
            return CNO_PROPAGATE;
        }

        streamobj->accept = CNO_ACCEPT_HEADERS | CNO_ACCEPT_PUSH | CNO_ACCEPT_WRITE_HEADERS;
    }

    if (!(streamobj->accept & CNO_ACCEPT_WRITE_HEADERS)) {
        return CNO_ERROR(INVALID_STREAM, "stream %zu not writable", stream);
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
            // non-recoverable error, so no point in destroying the stream
            // even if we just created it.
            return CNO_PROPAGATE;
        }
    } else {
        char code[10] = { 0 };
        snprintf(code, 10, "%d", msg->code);

        cno_header_t head[] = {
            { CNO_IO_VECTOR_CONST(":status"), CNO_IO_VECTOR_STRING(code) }
        };

        if (cno_hpack_encode(&conn->encoder, &frame.payload, head, 1)) {
            return CNO_PROPAGATE;
        }
    }

    if (cno_hpack_encode(&conn->encoder, &frame.payload, msg->headers, msg->headers_len)
     || cno_frame_write(conn, &frame, streamobj))
    {
        // no point in cleaning up the stream, the encoder is probably in invalid state.
        cno_io_vector_clear(&frame.payload);
        return CNO_PROPAGATE;
    }

    cno_io_vector_clear(&frame.payload);

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
        return CNO_ERROR(INVALID_STATE, "connection closed");
    }

    if (!cno_connection_is_http2(conn)) {
        if (stream != 1) {
            return CNO_ERROR(INVALID_STREAM, "can only write to stream 1 in HTTP 1 mode, not %zu", stream);
        }

        return length && CNO_FIRE(conn, on_write, data, length) ? CNO_PROPAGATE : CNO_OK;
    }

    cno_stream_t *streamobj = cno_stream_find(conn, stream);

    if (streamobj == NULL) {
        return CNO_ERROR(INVALID_STREAM, "stream %zu does not exist", stream);
    }

    if (!(streamobj->accept & CNO_ACCEPT_WRITE_DATA)) {
        return CNO_ERROR(INVALID_STREAM, "can't carry data over stream %zu", stream);
    }

    cno_frame_t frame = { CNO_FRAME_DATA, final ? CNO_FLAG_END_STREAM : 0, stream, { (char *) data, length } };

    if (cno_frame_write(conn, &frame, streamobj)) {
        return CNO_PROPAGATE;
    }

    return final ? cno_stream_close(conn, streamobj) : CNO_OK;
}
