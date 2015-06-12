#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cno.h"
#include "picohttpparser/picohttpparser.h"


#define CNO_READ_1BYTE(tg, ptr) tg = *ptr++
#define CNO_READ_2BYTE(tg, ptr) do { tg = ptr[0] <<  8 | ptr[1]; ptr += 2; } while (0)
#define CNO_READ_3BYTE(tg, ptr) do { tg = ptr[0] << 16 | ptr[1] <<  8 | ptr[2]; ptr += 3; } while (0)
#define CNO_READ_4BYTE(tg, ptr) do { tg = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3]; ptr += 4; } while (0)

#define CNO_WRITE_1BYTE(ptr, src) *ptr++ = src
#define CNO_WRITE_2BYTE(ptr, src) do { ptr[0] = src >>  8; ptr[1] = src; ptr += 2; } while (0)
#define CNO_WRITE_3BYTE(ptr, src) do { ptr[0] = src >> 16; ptr[1] = src >>  8; ptr[2] = src; ptr += 3; } while (0)
#define CNO_WRITE_4BYTE(ptr, src) do { ptr[0] = src >> 24; ptr[1] = src >> 16; ptr[2] = src >> 8; ptr[3] = src; ptr += 4; } while (0)

#define CNO_WRITE_VECTOR(ptr, vec) do { memcpy((ptr), (vec).data, (vec).size); (ptr) += (vec).size; } while (0)
#define CNO_WRITE_CONSTC(ptr, str) do { memcpy((ptr), (str), sizeof(str) - 1); (ptr) += sizeof(str) - 1; } while (0);
#define CNO_WRITE_FORMAT(ptr, ...) do { (ptr) += sprintf(ptr, ##__VA_ARGS__); } while (0)


static const struct cno_st_io_vector_t CNO_PREFACE = CNO_IO_VECTOR_CONST("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
static const struct cno_st_settings_t  CNO_SETTINGS_INITIAL = { { { 4096, 1, -1, 65536, 16384, -1 } } };


const char  CNO_FRAME_FLOW_CONTROLLED[256] = { 1, 0 };
const char *CNO_FRAME_NAME[256] = {
    "DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE",
    "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION", NULL
};


size_t cno_stream_next_id(cno_connection_t *conn)
{
    size_t last = conn->last_stream[CNO_PEER_LOCAL];
    return last == 0 ? 1 + !conn->client : cno_connection_is_http2(conn) ? last + 2 : last;
}


static int cno_stream_is_local(cno_connection_t *conn, size_t id)
{
    return (int) (id % 2) == (conn->client);
}


static cno_stream_t * cno_stream_new(cno_connection_t *conn, size_t id, int local)
{
    int i = cno_stream_is_local(conn, id);

    if (i != local) {
        (void) CNO_ERROR_INVALID_STREAM("invalid stream ID (mod 2: %d != %d)", i, local);
        return NULL;
    }

    if (id <= conn->last_stream[i]) {
        (void) CNO_ERROR_INVALID_STREAM("invalid stream ID (%lu <= %lu)", id, conn->last_stream[i]);
        return NULL;
    }

    if (conn->stream_count[i] >= conn->settings[!i].max_concurrent_streams) {
        if (i == CNO_PEER_LOCAL) {
            (void) CNO_ERROR_WOULD_BLOCK("initiated too many concurrent streams; wait for on_stream_end");
        } else {
            (void) CNO_ERROR_TRANSPORT("received too many concurrent streams");
        }
        return NULL;
    }

    cno_stream_t *stream = calloc(1, sizeof(cno_stream_t));

    if (!stream) {
        (void) CNO_ERROR_NO_MEMORY;
        return NULL;
    }

    conn->last_stream[i] = id;
    conn->stream_count[i]++;
    stream->id = id;
    stream->last_frame = CNO_FRAME_RST_STREAM;
    stream->state = CNO_STREAM_IDLE;
    stream->window_recv = conn->settings[i].initial_window_size;
    stream->window_send = conn->settings[i].initial_window_size;
    stream->cache.data = NULL;
    stream->cache.size = 0;
    cno_list_insert_after(&conn->streams, stream);

    if (CNO_FIRE(conn, on_stream_start, id)) {
        cno_list_remove(stream);
        free(stream);
        (void) CNO_PROPAGATE;
        return NULL;
    }

    return stream;
}


static void cno_stream_destroy(cno_connection_t *conn, cno_stream_t *stream)
{
    conn->stream_count[cno_stream_is_local(conn, stream->id)]--;
    cno_io_vector_clear(&stream->cache);
    cno_list_remove(stream);
    free(stream);
}


static int cno_stream_destroy_clean(cno_connection_t *conn, cno_stream_t *stream)
{
    size_t  state = stream->state;
    stream->state = CNO_STREAM_CLOSED;

    if (state == CNO_STREAM_OPEN || state == CNO_STREAM_CLOSED_LOCAL) {
        // Note that second argument is `1`. Callback should know that the stream
        // is dead, but shouldn't try to actually do anything with the message.
        if (CNO_FIRE(conn, on_message_end, stream->id, 1)) {
            return CNO_PROPAGATE;
        }
    }

    if (CNO_FIRE(conn, on_stream_end, stream->id)) {
        return CNO_PROPAGATE;
    }

    cno_stream_destroy(conn, stream);
    return CNO_OK;
}


static cno_stream_t * cno_stream_find(cno_connection_t *conn, size_t id)
{
    cno_stream_t *current = (cno_stream_t *) conn;

    if (id) while ((current = current->next) != (cno_stream_t *) conn) {
        if (current->id == id) {
            return current;
        }
    }
    // Technically not an error.
    return NULL;
}


#define CNO_ERROR_GOAWAY(conn, type, ...) (cno_frame_write_goaway(conn, type) ? CNO_PROPAGATE : CNO_ERROR_TRANSPORT(__VA_ARGS__))


static int cno_frame_write(cno_connection_t *conn, cno_frame_t *frame)
{
    char  header[9];
    char *headptr = header;
    size_t length = frame->payload.size;
    size_t stream = frame->stream_id;
    size_t limit  = conn->settings[CNO_PEER_REMOTE].max_frame_size;

    if (frame->stream == NULL) {
        frame->stream = cno_stream_find(conn, stream);
    }

    if (CNO_FRAME_FLOW_CONTROLLED[frame->type]) {
        if (length > conn->window_send) {
            return CNO_ERROR_WOULD_BLOCK("frame exceeds connection flow window (%lu > %lu)",
                length, conn->window_send);
        }

        if (frame->stream) {
            if (length > frame->stream->window_send) {
                return CNO_ERROR_WOULD_BLOCK("frame exceeds stream flow window (%lu > %lu)",
                    length, frame->stream->window_send);
            }

            frame->stream->window_send -= length;
        }

        conn->window_send -= length;
    }

    if (length > limit) {
        if (frame->type != CNO_FRAME_DATA && frame->type != CNO_FRAME_HEADERS) {
            return CNO_ERROR_ASSERTION("frame too big (%lu > %lu)", length, limit);
        }

        if (frame->flags & (CNO_FLAG_PADDED | CNO_FLAG_PRIORITY)) {
            return CNO_ERROR_NOT_IMPLEMENTED("don't know how to split padded frames");
        }

        char * restore_data = frame->payload.data;
        size_t restore_size = frame->payload.size;
        size_t erased_flags = frame->flags & (CNO_FLAG_END_STREAM | CNO_FLAG_END_HEADERS);
        frame->flags &= ~erased_flags;
        frame->payload.size = limit;

        for (; length; length -= frame->payload.size, frame->payload.data += frame->payload.size) {
            if (length <= limit) {
                frame->flags |= erased_flags;
                frame->payload.size = length;
            }

            if (cno_frame_write(conn, frame)) {
                frame->payload.data = restore_data;
                frame->payload.size = restore_size;
                frame->flags |= erased_flags;
                return CNO_PROPAGATE;
            }
        }

        frame->payload.data = restore_data;
        frame->payload.size = restore_size;
        return CNO_OK;
    }

    CNO_WRITE_3BYTE(headptr, length);
    CNO_WRITE_1BYTE(headptr, frame->type);
    CNO_WRITE_1BYTE(headptr, frame->flags);
    CNO_WRITE_4BYTE(headptr, stream);

    if (CNO_FIRE(conn, on_frame_send, frame)) {
        return CNO_PROPAGATE;
    }

    if (CNO_FIRE(conn, on_write, header, 9)) {
        return CNO_PROPAGATE;
    }

    if (length && CNO_FIRE(conn, on_write, frame->payload.data, length)) {
        return CNO_PROPAGATE;
    }

    return CNO_OK;
}


static int cno_frame_write_goaway(cno_connection_t *conn, size_t code)
{
    char descr[8];
    char *ptr = descr;
    size_t last_stream = code == CNO_STATE_NO_ERROR && !conn->client ? (1UL << 31) - !conn->client : conn->last_stream[CNO_PEER_REMOTE];

    CNO_WRITE_4BYTE(ptr, last_stream);
    CNO_WRITE_4BYTE(ptr, code);
    cno_frame_t error = { CNO_FRAME_GOAWAY };
    error.payload.data = descr;
    error.payload.size = sizeof(descr);

    return cno_frame_write(conn, &error);
}


static int cno_frame_write_rst_stream(cno_connection_t *conn, size_t stream, size_t code)
{
    if (stream == 0) {
        return CNO_ERROR_GOAWAY(conn, code, "RST'd stream 0");
    }

    cno_stream_t *obj = cno_stream_find(conn, stream);

    if (obj) {
        if (cno_stream_destroy_clean(conn, obj)) {
            return CNO_PROPAGATE;
        }
    }

    char descr[4];
    char *ptr = descr;
    CNO_WRITE_4BYTE(ptr, code);
    cno_frame_t error = { CNO_FRAME_RST_STREAM };
    error.payload.data = descr;
    error.payload.size = 4;
    return cno_frame_write(conn, &error);
}


static int cno_frame_handle(cno_connection_t *conn, cno_frame_t *frame)
{
    size_t sz = frame->payload.size;
    unsigned char *ptr = (unsigned char *) frame->payload.data;
    unsigned char *end = sz + ptr;
    cno_stream_t *stream = frame->stream = cno_stream_find(conn, frame->stream_id);
    int stream_may_be_reset = frame->stream_id && frame->stream_id <= conn->last_stream[CNO_PEER_REMOTE];

    if (CNO_FRAME_FLOW_CONTROLLED[frame->type] && sz) {
        if (conn->window_recv < sz) {
            // Accept the frame anyway.
            conn->window_recv = sz;
        }

        conn->window_recv -= sz;

        if (stream) {
            if (stream->window_recv < sz) {
                stream->window_recv = sz;
            }

            stream->window_recv -= sz;
        }

        unsigned char payload[4];
        unsigned char *ptr = payload;
        CNO_WRITE_4BYTE(ptr, sz);
        cno_frame_t update = { CNO_FRAME_WINDOW_UPDATE };
        update.payload.data = (char *) payload;
        update.payload.size = ptr - payload;

        if (cno_frame_write(conn, &update)) {
            return CNO_PROPAGATE;
        }

        if (frame->stream_id) {
            update.stream_id = frame->stream_id;

            if (cno_frame_write(conn, &update)) {
                return CNO_PROPAGATE;
            }
        }
    }

    if (frame->type == CNO_FRAME_CONTINUATION) {
        if (!stream) {
            if (stream_may_be_reset) {
                return CNO_OK;
            }

            return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "CONTINUATION on a non-existent stream");
        }

        frame->type = stream->last_frame;

        if (frame->type != CNO_FRAME_HEADERS && frame->type != CNO_FRAME_CONTINUATION) {
            return cno_frame_write_rst_stream(conn, frame->stream_id, CNO_STATE_PROTOCOL_ERROR);
        }
    }

    if (frame->flags & CNO_FLAG_PADDED) {
        size_t pad = *ptr++;

        if (pad >= sz - 1) {
            return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "DATA with padding bigger than whole frame");
        }

        sz -= pad + 1;
    }

    if (frame->flags & CNO_FLAG_PRIORITY) {
        // TODO do something with this info.
        ptr += 5;
        sz  -= 5;
    }

    if (stream) {
        stream->last_frame = 0;
    }

    switch (frame->type) {
        case CNO_FRAME_PING: {
            if (frame->stream_id) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "got stream %lu PING-ed", frame->stream_id);
            }

            if (sz != 8) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_FRAME_SIZE_ERROR, "bad PING frame (length = %lu)", sz);
            }

            if (frame->flags & CNO_FLAG_ACK) {
                return CNO_FIRE(conn, on_pong, frame->payload.data);
            }

            cno_frame_t response = { CNO_FRAME_PING, CNO_FLAG_ACK };
            response.payload.data = frame->payload.data;
            response.payload.size = frame->payload.size;
            return cno_frame_write(conn, &response);
        }

        case CNO_FRAME_GOAWAY: {
            if (frame->stream_id) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "got GOAWAY on stream %lu", frame->stream_id);
            }

            if (cno_connection_lost(conn)) {
                return CNO_PROPAGATE;
            }

            // TODO parse error code.
            return CNO_OK;
        }

        case CNO_FRAME_RST_STREAM: {
            if (!stream) {
                if (stream_may_be_reset) {
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
            if (frame->stream_id == 0) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "PRIORITY on stream 0");
            }

            // TODO something.
            return CNO_OK;
        }

        case CNO_FRAME_SETTINGS: {
            if (frame->stream_id) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "got SETTINGS on stream %lu", frame->stream_id);
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

            while (ptr != end) {
                size_t setting = 0; CNO_READ_2BYTE(setting, ptr);
                size_t value   = 0; CNO_READ_4BYTE(value,   ptr);

                if (setting && setting < CNO_SETTINGS_UNDEFINED) {
                    conn->settings[CNO_PEER_REMOTE].array[setting - 1] = value;
                }
            }

            conn->encoder.limit_upper = conn->settings[CNO_PEER_REMOTE].header_table_size;
            cno_hpack_setlimit(&conn->encoder, conn->encoder.limit_upper);

            cno_frame_t ack = { CNO_FRAME_SETTINGS, CNO_FLAG_ACK };

            if (cno_frame_write(conn, &ack)) {
                return CNO_PROPAGATE;
            }

            return CNO_OK;
        }

        case CNO_FRAME_WINDOW_UPDATE: {
            if (sz != 4) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_FRAME_SIZE_ERROR, "bad WINDOW_UPDATE (length = %lu)", sz);
            }

            size_t increment = 0;
            CNO_READ_4BYTE(increment, ptr);

            #ifdef CNO_HTTP2_STRICT
                if (increment == 0) {
                    return cno_frame_write_rst_stream(conn, frame->stream_id, CNO_STATE_PROTOCOL_ERROR)
                        ? CNO_PROPAGATE
                        : CNO_ERROR_TRANSPORT("bad WINDOW_UPDATE (incr = %lu)", increment);
                }
            #endif

            if (frame->stream_id == 0) {
                conn->window_send += increment;

                if (conn->window_send >= 0x80000000u) {
                    return CNO_ERROR_GOAWAY(conn, CNO_STATE_FLOW_CONTROL_ERROR,
                        "flow control window got too big (res = %lu)", conn->window_send);
                }
            } else if (stream != NULL) {
                stream->window_send += increment;

                if (stream->window_send >= 0x80000000u) {
                    return cno_frame_write_rst_stream(conn, frame->stream_id, CNO_STATE_PROTOCOL_ERROR);
                }
            }

            return CNO_FIRE(conn, on_flow_increase, frame->stream_id);
        }

        case CNO_FRAME_HEADERS: {
            if (stream == NULL) {
                stream = cno_stream_new(conn, frame->stream_id, CNO_PEER_REMOTE);

                if (stream == NULL) {
                    return CNO_PROPAGATE;
                }
            }

            if (stream->state != CNO_STREAM_IDLE &&
                stream->state != CNO_STREAM_OPEN &&
                stream->state != CNO_STREAM_CLOSED_LOCAL &&
                stream->state != CNO_STREAM_RESERVED_REMOTE) {
                    return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR,
                        "got HEADERS while stream is in state %lu", stream->state);
            }

            stream->last_frame = CNO_FRAME_HEADERS;
            stream->state = stream->state == CNO_STREAM_IDLE
                ? CNO_STREAM_OPEN
                : CNO_STREAM_CLOSED_LOCAL;

            if (cno_io_vector_extend(&stream->cache, (char *) ptr, sz)) {
                return CNO_PROPAGATE;
            }

            break;
        }

        case CNO_FRAME_PUSH_PROMISE: {
            return CNO_ERROR_GOAWAY(conn, CNO_STATE_INTERNAL_ERROR, "PUSH_PROMISE not implemented");
        }

        case CNO_FRAME_DATA: {
            if (frame->stream == 0) {
                return CNO_ERROR_GOAWAY(conn, CNO_STATE_PROTOCOL_ERROR, "DATA on stream 0");
            }

            if (!stream || (stream->state != CNO_STREAM_OPEN && stream->state != CNO_STREAM_CLOSED_LOCAL)) {
                if (stream_may_be_reset) {
                    return CNO_OK;
                }

                return cno_frame_write_rst_stream(conn, frame->stream_id, CNO_STATE_STREAM_CLOSED);
            }

            if (CNO_FIRE(conn, on_message_data, frame->stream_id, (const char *) ptr, sz)) {
                return CNO_PROPAGATE;
            }

            break;
        }

        default: {
            // Ignore unrecognized frames.
        }
    }

    if (stream && frame->flags & CNO_FLAG_END_HEADERS) {
        stream->last_frame = 0;

        size_t limit = 256;
        cno_header_t *headers = malloc(sizeof(cno_header_t) * limit);
        cno_header_t *it;

        if (headers == NULL) {
            return CNO_ERROR_NO_MEMORY;
        }

        if (cno_hpack_decode(&conn->decoder, &stream->cache, headers, &limit)) {
            (void) cno_frame_write_goaway(conn, CNO_STATE_COMPRESSION_ERROR);
            cno_io_vector_clear(&stream->cache);
            free(headers);
            return CNO_PROPAGATE;
        }

        cno_io_vector_clear(&stream->cache);
        cno_message_t msg = { 0 };
        msg.headers_len = limit;
        msg.headers = headers;

        for (it = headers ; it != headers + limit; ++it) {
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

        int failed = CNO_FIRE(conn, on_message_start, frame->stream_id, &msg);

        for (it = headers; it != headers + limit; ++it) {
            cno_io_vector_clear(&it->name);
            cno_io_vector_clear(&it->value);
        }

        free(headers);

        if (failed) {
            return CNO_PROPAGATE;
        }
    }

    if (stream && frame->flags & CNO_FLAG_END_STREAM) {
        if (stream->state == CNO_STREAM_CLOSED_LOCAL) {
            // This will also fire on_message_end:
            if (cno_stream_destroy_clean(conn, stream)) {
                return CNO_PROPAGATE;
            }
        } else

        if (stream->state != CNO_STREAM_CLOSED) {
            stream->state = CNO_STREAM_CLOSED_REMOTE;

            if (CNO_FIRE(conn, on_message_end, frame->stream_id, 0)) {
                return CNO_PROPAGATE;
            }
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
            CNO_WRITE_2BYTE(ptr, i);
            CNO_WRITE_4BYTE(ptr, *replace);
        }
    }

    cno_frame_t frame = { CNO_FRAME_SETTINGS };
    frame.payload.data = (char *) payload;
    frame.payload.size = ptr - payload;
    return cno_frame_write(conn, &frame);
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
    memcpy(conn->settings,     &CNO_SETTINGS_INITIAL, sizeof(cno_settings_t));
    memcpy(conn->settings + 1, &CNO_SETTINGS_INITIAL, sizeof(cno_settings_t));
    conn->window_recv = CNO_SETTINGS_INITIAL.initial_window_size;
    conn->window_send = CNO_SETTINGS_INITIAL.initial_window_size;
    cno_hpack_init(&conn->decoder, CNO_SETTINGS_INITIAL.header_table_size);
    cno_hpack_init(&conn->encoder, CNO_SETTINGS_INITIAL.header_table_size);
    cno_list_init(&conn->streams);
    return conn;
}


void cno_connection_destroy(cno_connection_t *conn)
{
    cno_io_vector_reset(&conn->buffer);
    cno_io_vector_clear((cno_io_vector_t *) &conn->buffer);
    cno_hpack_clear(&conn->encoder);
    cno_hpack_clear(&conn->decoder);

    while (conn->streams.first != (cno_stream_t *) conn) {
        cno_stream_destroy(conn, conn->streams.first);
    }

    free(conn);
}


int cno_connection_is_http2(cno_connection_t *conn)
{
    return conn->state != CNO_CONNECTION_HTTP1_INIT &&
           conn->state != CNO_CONNECTION_HTTP1_READY &&
           conn->state != CNO_CONNECTION_HTTP1_READING;
}


int cno_connection_upgrade(cno_connection_t *conn)
{
    if (conn->client && CNO_FIRE(conn, on_write, CNO_PREFACE.data, CNO_PREFACE.size)) {
        return CNO_PROPAGATE;
    }

    return cno_settings_diff(conn, &CNO_SETTINGS_INITIAL, conn->settings + CNO_PEER_LOCAL);
}


int cno_connection_made(cno_connection_t *conn)
{
    int __retcode = CNO_OK;
    #define STOP(code) do              { __retcode = code;   goto done; } while (0)
    #define WAIT(cond) do if (!(cond)) { __retcode = CNO_OK; goto done; } while (0)

    while (!conn->closed) switch (conn->state) {
        case CNO_CONNECTION_HTTP1_INIT: {
            if (cno_stream_new(conn, 1, conn->client) == NULL) {
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
            cno_stream_t *stream = conn->streams.first;
            stream->http1_remaining = 0;
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
                    conn->last_stream[0] = 0;
                    conn->state = CNO_CONNECTION_INIT;
                    break;
                }
            }

            size_t header_num = CNO_MAX_HTTP1_HEADERS;
            struct phr_header headers[CNO_MAX_HTTP1_HEADERS], *it = headers, *end;

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
                STOP(CNO_ERROR_TRANSPORT("HTTP/1.%d not supported", minor));
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
                    if (stream->http1_remaining) {
                        STOP(CNO_ERROR_TRANSPORT("bad HTTP/1.x request: multiple content-lengths"));
                    }

                    stream->http1_remaining = (size_t) atoi(value);
                } else

                if (strncmp(name, "transfer-encoding", size) == 0) {
                    if (strncmp(value, "chunked", vsize) != 0) {
                        STOP(CNO_ERROR_TRANSPORT("bad HTTP/1.x request: unknown transfer-encoding"));
                    }

                    if (stream->http1_remaining) {
                        STOP(CNO_ERROR_TRANSPORT("bad HTTP/1.x request: chunked encoding w/ fixed length"));
                    }

                    stream->http1_remaining = (size_t) -1;
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
            cno_stream_t *stream = conn->streams.first;

            WAIT(conn->buffer.size || !stream->http1_remaining);

            if (stream->http1_remaining == (size_t) -1) {
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
                    stream->http1_remaining = 0;
                }

                cno_io_vector_shift(&conn->buffer, data_len + head_len);
                break;
            }

            if (stream->http1_remaining) {
                size_t data_len = stream->http1_remaining;
                char * data_buf = conn->buffer.data;

                if (data_len > conn->buffer.size) {
                    data_len = conn->buffer.size;
                }

                if (CNO_FIRE(conn, on_message_data, stream->id, data_buf, data_len)) {
                    STOP(CNO_PROPAGATE);
                }

                stream->http1_remaining -= data_len;
                cno_io_vector_shift(&conn->buffer, data_len);
                break;
            }

            if (conn->state == CNO_CONNECTION_HTTP1_READING_UPGRADE) {
                conn->state = CNO_CONNECTION_PREFACE;
                conn->streams.first->state = CNO_STREAM_CLOSED_REMOTE;
            } else {
                conn->state = CNO_CONNECTION_HTTP1_READY;
                conn->streams.first->state = CNO_STREAM_IDLE;
            }

            if (CNO_FIRE(conn, on_message_end, stream->id, 0)) {
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

            size_t m;
            unsigned char *base = (unsigned char *) conn->buffer.data;
            CNO_READ_3BYTE(m, base);

            if (m > conn->settings[CNO_PEER_LOCAL].max_frame_size) {
                STOP(CNO_ERROR_GOAWAY(conn, CNO_STATE_FRAME_SIZE_ERROR, "recv'd a frame that is too big"));
            }

            WAIT(conn->buffer.size >= 9 + m);

            conn->frame.stream = NULL;
            conn->frame.payload.size = m;
            CNO_READ_1BYTE(m, base); conn->frame.type         = m;
            CNO_READ_1BYTE(m, base); conn->frame.flags        = m;
            CNO_READ_4BYTE(m, base); conn->frame.stream_id    = m;
            conn->frame.payload.data = (char *) base;

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

    while (conn->streams.first != (cno_stream_t *) conn) {
        if (cno_stream_destroy_clean(conn, conn->streams.first)) {
            return CNO_PROPAGATE;
        }
    }

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


static inline int cno_finalize_http2(cno_connection_t *conn, cno_stream_t *streamobj)
{
    if (streamobj->state == CNO_STREAM_CLOSED_REMOTE) {
        if (cno_stream_destroy_clean(conn, streamobj)) {
            cno_stream_destroy(conn, streamobj);
            return CNO_PROPAGATE;
        }
    } else {
        streamobj->state = CNO_STREAM_CLOSED_LOCAL;
    }

    return CNO_OK;
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

            CNO_WRITE_VECTOR(ptr, msg->method);
            CNO_WRITE_CONSTC(ptr, " ");
            CNO_WRITE_VECTOR(ptr, msg->path);
            CNO_WRITE_CONSTC(ptr, " HTTP/1.1\r\n");
        } else {
            CNO_WRITE_FORMAT(ptr, "HTTP/1.1 %d %s\r\n", msg->code, cno_message_literal(msg));
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
                CNO_WRITE_CONSTC(ptr, "host: ")
            } else if (strncmp(it->name.data, ":status", it->name.size) == 0) {
                return CNO_ERROR_ASSERTION("set `message.code` instead of sending :status");
            } else if (it->name.data[0] == ':') {
                continue;
            } else {
                CNO_WRITE_VECTOR(ptr, it->name);
                CNO_WRITE_CONSTC(ptr, ": ");
            }
            CNO_WRITE_VECTOR(ptr, it->value);
            CNO_WRITE_CONSTC(ptr, "\r\n");
        }

        CNO_WRITE_CONSTC(ptr, "\r\n");
        return CNO_FIRE(conn, on_write, head, ptr - head);
    }

    cno_stream_t *streamobj = cno_stream_find(conn, stream);

    if (streamobj == NULL) {
        streamobj = cno_stream_new(conn, stream, CNO_PEER_LOCAL);

        if (streamobj == NULL) {
            return CNO_PROPAGATE;
        }
    }

    cno_frame_t frame = { CNO_FRAME_HEADERS, CNO_FLAG_END_HEADERS, stream };

    if (final) {
        frame.flags |= CNO_FLAG_END_STREAM;
    }

    if (conn->client) {
        if (streamobj->state != CNO_STREAM_IDLE && streamobj->state != CNO_STREAM_OPEN) {
            return CNO_ERROR_INVALID_STREAM("stream %lu not idle or open", stream);
        }

        cno_header_t head[2] = {
            { CNO_IO_VECTOR_CONST(":method"), CNO_IO_VECTOR_REFER(msg->method) },
            { CNO_IO_VECTOR_CONST(":path"),   CNO_IO_VECTOR_REFER(msg->path)   },
        };

        if (cno_hpack_encode(&conn->encoder, &frame.payload, head, 2)) {
            return CNO_PROPAGATE;
        }
    } else {
        // TODO if stream is idle, this can only be a push promise,
        //      in which case client-type headers should be sent.
        if (streamobj->state != CNO_STREAM_IDLE          && streamobj->state != CNO_STREAM_OPEN
         && streamobj->state != CNO_STREAM_CLOSED_REMOTE && streamobj->state != CNO_STREAM_RESERVED_LOCAL) {
            return CNO_ERROR_INVALID_STREAM("stream %lu not idle, open, or reserved", stream);
        }

        char code[10] = { 0 };
        snprintf(code, 10, "%d", msg->code);

        cno_header_t head = { CNO_IO_VECTOR_CONST(":status"), { code, strlen(code) } };

        if (cno_hpack_encode(&conn->encoder, &frame.payload, &head, 1)) {
            return CNO_PROPAGATE;
        }
    }

    if (cno_hpack_encode(&conn->encoder, &frame.payload, msg->headers, msg->headers_len)) {
        cno_io_vector_clear(&frame.payload);
        return CNO_PROPAGATE;
    }

    if (cno_frame_write(conn, &frame)) {
        cno_io_vector_clear(&frame.payload);
        return CNO_PROPAGATE;
    }

    cno_io_vector_clear(&frame.payload);

    if (streamobj->state == CNO_STREAM_IDLE) {
        streamobj->state = CNO_STREAM_OPEN;
    } else if (streamobj->state == CNO_STREAM_RESERVED_LOCAL) {
        streamobj->state = CNO_STREAM_CLOSED_REMOTE;
    }

    return final ? cno_finalize_http2(conn, streamobj) : CNO_OK;
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

    if (streamobj->state != CNO_STREAM_OPEN && streamobj->state != CNO_STREAM_CLOSED_REMOTE) {
        return CNO_ERROR_INVALID_STREAM("can't carry data over stream %lu", stream);
    }

    cno_frame_t frame = { CNO_FRAME_DATA, final ? CNO_FLAG_END_STREAM : 0, stream };
    frame.payload.data = (char *) data;
    frame.payload.size = length;

    if (cno_frame_write(conn, &frame)) {
        return CNO_PROPAGATE;
    }

    return final ? cno_finalize_http2(conn, streamobj) : CNO_OK;
}
