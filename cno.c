#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cno.h"
#include "picohttpparser/picohttpparser.h"


size_t cno_stream_next_id(cno_connection_t *conn)
{
    size_t last = conn->last_stream[CNO_CFG_LOCAL];
    return last == 0 ? 1 + !conn->client : cno_connection_is_http2(conn) ? last + 2 : last;
}


static int cno_stream_is_local(cno_connection_t *conn, size_t id)
{
    return (id % 2) == (conn->client);
}


static cno_stream_t * cno_stream_new(cno_connection_t *conn, size_t id)
{
    int i = cno_stream_is_local(conn, id);

    if (id <= conn->last_stream[i]) {
        (void) CNO_ERROR_TRANSPORT("invalid stream ID (%lu <= %lu)", id, conn->last_stream[i]);
        return NULL;
    }
    // The peer enforces a limit on how many streams we create and vice versa.
    if (conn->stream_count[i] >= conn->settings[!i].max_concurrent_streams) {
        (void) CNO_ERROR_TRANSPORT("reached the limit on streams");
        return NULL;
    }

    cno_stream_t *stream = malloc(sizeof(cno_stream_t));

    if (!stream) {
        (void) CNO_ERROR_NO_MEMORY;
        return NULL;
    }

    CNO_ZERO(stream);
    conn->last_stream[i] = id;
    conn->stream_count[i]++;
    stream->id = id;
    stream->last_frame = CNO_FRAME_RST_STREAM;
    stream->state = CNO_STREAM_IDLE;
    stream->window_recv = conn->settings[i].initial_window_size;
    stream->window_send = conn->settings[i].initial_window_size;
    stream->cache.data = NULL;
    stream->cache.size = 0;
    cno_list_insert_after(conn, stream);

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


cno_connection_t * cno_connection_new(enum CNO_CONNECTION_KIND kind)
{
    cno_connection_t *conn = malloc(sizeof(cno_connection_t));

    if (conn == NULL) {
        (void) CNO_ERROR_NO_MEMORY;
        return NULL;
    }

    CNO_ZERO(conn);
    conn->kind  = kind;
    conn->state = kind == CNO_HTTP2_CLIENT ? CNO_CONNECTION_INIT : CNO_CONNECTION_HTTP1_INIT;
    memcpy(conn->settings,     &cno_settings_initial, sizeof(cno_settings_initial));
    memcpy(conn->settings + 1, &cno_settings_initial, sizeof(cno_settings_initial));
    conn->window_recv = conn->settings[CNO_CFG_LOCAL].initial_window_size;
    conn->window_send = conn->settings[CNO_CFG_LOCAL].initial_window_size;
    cno_hpack_setlimit(&conn->decoder, conn->settings[CNO_CFG_LOCAL].header_table_size, 1);
    cno_hpack_setlimit(&conn->encoder, conn->settings[CNO_CFG_LOCAL].header_table_size, 0);
    cno_list_init(&conn->decoder);
    cno_list_init(&conn->encoder);
    cno_list_init(conn);
    return conn;
}


void cno_connection_destroy(cno_connection_t *conn)
{
    cno_io_vector_reset(&conn->buffer);
    cno_io_vector_clear((cno_io_vector_t *) &conn->buffer);
    cno_io_vector_clear((cno_io_vector_t *) &conn->frame.payload);
    cno_hpack_clear(&conn->encoder);
    cno_hpack_clear(&conn->decoder);

    while (conn->streams.first != (cno_stream_t *) conn) {
        cno_stream_destroy(conn, conn->streams.first);
    }

    free(conn);
}


int cno_connection_made(cno_connection_t *conn)
{
    return cno_connection_fire(conn);
}


int cno_connection_data_received(cno_connection_t *conn, const char *data, size_t length)
{
    if (conn->closed) {
        return CNO_ERROR_INVALID_STATE("already closed");
    }

    if (cno_io_vector_extend_tmp(&conn->buffer, data, length)) {
        return CNO_PROPAGATE;
    }

    return cno_connection_fire(conn);
}


int cno_connection_lost(cno_connection_t *conn)
{
    if (conn->closed) {
        return CNO_OK;
    }

    conn->closed = 1;

    if (cno_connection_fire(conn)) {
        conn->closed = 0;
        return CNO_PROPAGATE;
    }

    return CNO_OK;
}


#define CNO_WRITE_1BYTE(ptr, src) *ptr++ = src
#define CNO_WRITE_2BYTE(ptr, src) do { ptr[0] = src >>  8; ptr[1] = src; ptr += 2; } while (0)
#define CNO_WRITE_3BYTE(ptr, src) do { ptr[0] = src >> 16; ptr[1] = src >>  8; ptr[2] = src; ptr += 3; } while (0)
#define CNO_WRITE_4BYTE(ptr, src) do { ptr[0] = src >> 24; ptr[1] = src >> 16; ptr[2] = src >> 8; ptr[3] = src; ptr += 4; } while (0)
#define CNO_READ_1BYTE(tg, ptr) tg = *ptr++
#define CNO_READ_2BYTE(tg, ptr) do { tg = ptr[0] <<  8 | ptr[1]; ptr += 2; } while (0)
#define CNO_READ_3BYTE(tg, ptr) do { tg = ptr[0] << 16 | ptr[1] <<  8 | ptr[2]; ptr += 3; } while (0)
#define CNO_READ_4BYTE(tg, ptr) do { tg = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3]; ptr += 4; } while (0)


static int cno_frame_write(cno_connection_t *conn, cno_frame_t *frame)
{
    char  header[9];
    char *ptr = header;
    size_t length = frame->payload.size;
    size_t stream = frame->stream_id;

    if (frame->stream == NULL) {
        frame->stream = cno_stream_find(conn, stream);
    }

    if (length > conn->settings[CNO_CFG_REMOTE].max_frame_size) {
        return CNO_ERROR_ASSERTION("frame too big (%lu > %lu)", length, conn->settings[CNO_CFG_REMOTE].max_frame_size);
    }

    if (cno_frame_is_flow_controlled(frame)) {
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

    CNO_WRITE_3BYTE(ptr, length);
    CNO_WRITE_1BYTE(ptr, frame->type);
    CNO_WRITE_1BYTE(ptr, frame->flags);
    CNO_WRITE_4BYTE(ptr, stream);

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
    size_t last_stream = code == CNO_STATE_NO_ERROR && !conn->client ? (1UL << 31) - !conn->client : conn->last_stream[CNO_CFG_REMOTE];

    CNO_WRITE_4BYTE(ptr, last_stream);
    CNO_WRITE_4BYTE(ptr, code);
    cno_frame_t error = { CNO_FRAME_GOAWAY };
    error.payload.data = descr;
    error.payload.size = sizeof(descr);

    return cno_frame_write(conn, &error);
}


int cno_connection_stop(cno_connection_t *conn)
{
    if (cno_connection_is_http2(conn)) {
        return cno_frame_write_goaway(conn, CNO_STATE_NO_ERROR);
    }

    return CNO_OK;
}


static int cno_frame_write_rst_stream(cno_connection_t *conn, size_t stream, size_t code)
{
    if (stream == 0) {
        if (cno_frame_write_goaway(conn, code)) {
            return CNO_PROPAGATE;
        }

        return CNO_ERROR_TRANSPORT("RST'd stream 0");
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


static int cno_connection_handle_frame(cno_connection_t *conn, cno_frame_t *frame)
{
    size_t sz = frame->payload.size;
    unsigned char *ptr = (unsigned char *) frame->payload.data;
    unsigned char *end = sz + ptr;
    cno_stream_t *stream = frame->stream = cno_stream_find(conn, frame->stream_id);

    if (cno_frame_is_flow_controlled(frame) && sz) {
        conn->window_recv -= sz;

        if (stream) {
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

    if (stream && frame->type != CNO_FRAME_CONTINUATION) {
        stream->last_frame = frame->type;
    }

    if (frame->flags & CNO_FLAG_PADDED) {
        size_t pad = *ptr++;

        if (pad >= sz - 1) {
            return cno_frame_write_goaway(conn, CNO_STATE_PROTOCOL_ERROR)
                ? CNO_PROPAGATE
                : CNO_ERROR_TRANSPORT("DATA with padding bigger than whole frame");
        }

        sz -= pad + 1;
    }

    if (frame->flags & CNO_FLAG_PRIORITY) {
        // TODO do something with this info.
        ptr += 5;
        sz  -= 5;
    }

    switch (frame->type) {
        case CNO_FRAME_PING: {
            if (frame->stream_id) {
                return cno_frame_write_goaway(conn, CNO_STATE_PROTOCOL_ERROR)
                    ? CNO_PROPAGATE
                    : CNO_ERROR_TRANSPORT("got stream %lu PING-ed", frame->stream_id);
            }

            if (sz != 8) {
                return cno_frame_write_goaway(conn, CNO_STATE_FRAME_SIZE_ERROR)
                    ? CNO_PROPAGATE
                    : CNO_ERROR_TRANSPORT("bad PING frame (length = %lu)", sz);
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
            if (cno_connection_lost(conn)) {
                return CNO_PROPAGATE;
            }

            // TODO parse error code.
            return CNO_OK;
        }

        case CNO_FRAME_RST_STREAM: {
            if (!stream) {
                return cno_frame_write_goaway(conn, CNO_STATE_PROTOCOL_ERROR)
                    ? CNO_PROPAGATE
                    : CNO_ERROR_TRANSPORT("reset of a nonexistent stream");
            }

            if (cno_stream_destroy_clean(conn, stream)) {
                return CNO_PROPAGATE;
            }

            // TODO parse error code.
            return CNO_OK;
        }

        case CNO_FRAME_PRIORITY: {
            if (frame->stream_id == 0) {
                return cno_frame_write_goaway(conn, CNO_STATE_PROTOCOL_ERROR)
                    ? CNO_PROPAGATE
                    : CNO_ERROR_TRANSPORT("PRIORITY on stream 0");
            }

            // TODO something.
            return CNO_OK;
        }

        case CNO_FRAME_SETTINGS: {
            if (frame->flags & CNO_FLAG_ACK) {
                if (sz) {
                    return cno_frame_write_goaway(conn, CNO_STATE_FRAME_SIZE_ERROR)
                        ? CNO_PROPAGATE
                        : CNO_ERROR_TRANSPORT("bad SETTINGS (ack with length = %lu)", sz);
                }

                return CNO_OK;
            }

            if (sz % 6) {
                return cno_frame_write_goaway(conn, CNO_STATE_FRAME_SIZE_ERROR)
                    ? CNO_PROPAGATE
                    : CNO_ERROR_TRANSPORT("bad SETTINGS (length = %lu)", sz);
            }

            while (ptr != end) {
                size_t setting = 0; CNO_READ_2BYTE(setting, ptr);
                size_t value   = 0; CNO_READ_4BYTE(value,   ptr);

                if (setting && setting < CNO_SETTINGS_UNDEFINED) {
                    conn->settings[CNO_CFG_REMOTE].array[setting] = value;
                }
            }

            conn->encoder.limit_upper = conn->settings[CNO_CFG_REMOTE].header_table_size;
            conn->decoder.limit_upper = conn->settings[CNO_CFG_REMOTE].header_table_size;
            cno_hpack_setlimit(&conn->encoder, conn->encoder.limit_upper, 0);

            cno_frame_t ack = { CNO_FRAME_SETTINGS, CNO_FLAG_ACK };

            if (cno_frame_write(conn, &ack)) {
                return CNO_PROPAGATE;
            }

            return CNO_OK;
        }

        case CNO_FRAME_WINDOW_UPDATE: {
            if (sz != 4) {
                return cno_frame_write_goaway(conn, CNO_STATE_FRAME_SIZE_ERROR)
                    ? CNO_PROPAGATE
                    : CNO_ERROR_TRANSPORT("bad WINDOW_UPDATE (length = %lu)", sz);
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
                    return cno_frame_write_goaway(conn, CNO_STATE_FLOW_CONTROL_ERROR)
                        ? CNO_PROPAGATE
                        : CNO_ERROR_TRANSPORT("flow control window got too big (res = %lu)", conn->window_send);
                }
            } else if (stream != NULL) {
                stream->window_send += increment;

                if (stream->window_send >= 0x80000000u) {
                    return cno_frame_write_rst_stream(conn, frame->stream_id, CNO_STATE_PROTOCOL_ERROR);
                }
            }

            return CNO_FIRE(conn, on_flow_control_update, frame->stream_id);
        }

        case CNO_FRAME_HEADERS: { recv_headers:
            if (stream == NULL) {
                stream = cno_stream_new(conn, frame->stream_id);

                if (stream == NULL) {
                    return CNO_PROPAGATE;
                }
            }

            if (stream->state != CNO_STREAM_IDLE &&
                stream->state != CNO_STREAM_CLOSED_LOCAL &&
                stream->state != CNO_STREAM_RESERVED_REMOTE) {
                    return cno_frame_write_goaway(conn, CNO_STATE_PROTOCOL_ERROR)
                        ? CNO_PROPAGATE
                        : CNO_ERROR_TRANSPORT("got HEADERS while stream is in state %lu", stream->state);
            }

            stream->state = stream->state == CNO_STREAM_IDLE
                ? CNO_STREAM_OPEN
                : CNO_STREAM_CLOSED_LOCAL;

            if (cno_io_vector_extend(&stream->cache, (char *) ptr, sz)) {
                return CNO_PROPAGATE;
            }

            if (frame->flags & CNO_FLAG_END_HEADERS) {
                size_t limit = conn->settings[CNO_CFG_LOCAL].max_header_list_size;

                if (limit > 255) {
                    limit = 255;
                }

                cno_header_t *headers = malloc(sizeof(cno_header_t) * limit);

                if (headers == NULL) {
                    return CNO_ERROR_NO_MEMORY;
                }

                if (cno_hpack_decode(&conn->decoder, &stream->cache, headers, &limit)) {
                    (void) cno_frame_write_goaway(conn, CNO_STATE_COMPRESSION_ERROR);
                    free(headers);
                    return CNO_PROPAGATE;
                }

                cno_message_t msg = { 0 };
                msg.major = 2;
                msg.headers_len = limit;
                msg.headers = headers;
                int state = CNO_OK;
                size_t k;

                for (k = 0; k < limit; ++k) {
                    char * name  = (char *) headers[k].name.data;
                    size_t size  = (size_t) headers[k].name.size;
                    char * value = (char *) headers[k].value.data;
                    size_t vsize = (size_t) headers[k].value.size;

                    if (strncmp(name, ":status", size) == 0) {
                        char *ptr = value;
                        char *end = value + vsize;

                        for (; ptr != end; ++ptr) {
                            msg.code *= 10;

                            if ('0' <= *ptr && *ptr <= '9') {
                                msg.code += *ptr - '0';
                            } else {
                                if (cno_frame_write_rst_stream(conn, frame->stream_id, CNO_STATE_PROTOCOL_ERROR)) {
                                    state = CNO_PROPAGATE;
                                    goto headers_stop;
                                }

                                state = CNO_OK;
                                goto headers_stop;
                            }
                        }
                    } else

                    if (strncmp(name, ":path", size) == 0) {
                        msg.path.data = value;
                        msg.path.size = vsize;
                    } else

                    if (strncmp(name, ":method", size) == 0) {
                        msg.method.data = value;
                        msg.method.size = vsize;
                    }
                }

                if (CNO_FIRE(conn, on_message_start, frame->stream_id, &msg)) {
                    state = CNO_PROPAGATE;
                    goto headers_stop;
                }

            headers_stop:
                for (k = 0; k < limit; ++k) {
                    cno_io_vector_clear(&headers[k].name);
                    cno_io_vector_clear(&headers[k].value);
                }

                free(headers);

                if (state != CNO_OK) {
                    return state;
                }
            }

        end_stream:
            if (frame->flags & CNO_FLAG_END_STREAM) {
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

        case CNO_FRAME_DATA: {
            if (frame->stream == 0) {
                return cno_frame_write_goaway(conn, CNO_STATE_PROTOCOL_ERROR)
                    ? CNO_PROPAGATE
                    : CNO_ERROR_TRANSPORT("DATA on stream 0");
            }

            if (!stream || (stream->state != CNO_STREAM_OPEN && stream->state != CNO_STREAM_CLOSED_LOCAL)) {
                return cno_frame_write_rst_stream(conn, frame->stream_id, CNO_STATE_STREAM_CLOSED);
            }

            if (CNO_FIRE(conn, on_message_data, frame->stream_id, (const char *) ptr, sz)) {
                return CNO_PROPAGATE;
            }

            if (frame->flags & CNO_FLAG_END_STREAM) {
                goto end_stream;  // in case CNO_FRAME_HEADERS
            }

            return CNO_OK;
        }

        case CNO_FRAME_PUSH_PROMISE: {
            return cno_frame_write_goaway(conn, CNO_STATE_INTERNAL_ERROR)
                ? CNO_PROPAGATE
                : CNO_ERROR_NOT_IMPLEMENTED("frame type %d (%s)", frame->type, cno_frame_get_name(frame));
        }

        case CNO_FRAME_CONTINUATION: {
            if (!stream) {
                return cno_frame_write_goaway(conn, CNO_STATE_PROTOCOL_ERROR)
                    ? CNO_PROPAGATE
                    : CNO_ERROR_TRANSPORT("CONTINUATION on a non-existent stream");
            }

            switch (stream->last_frame) {
                case CNO_FRAME_HEADERS: goto recv_headers;
              //case CNO_FRAME_PUSH_PROMISE:
                default: return cno_frame_write_rst_stream(conn, frame->stream_id, CNO_STATE_PROTOCOL_ERROR);
            }
        }

        default: {
            return cno_frame_write_goaway(conn, CNO_STATE_PROTOCOL_ERROR)
                ? CNO_PROPAGATE
                : CNO_ERROR_TRANSPORT("unknown frame type %d", frame->type);
        }
    }

    return CNO_OK;
}


static int cno_connection_send_preface(cno_connection_t *conn)
{
    if (conn->client && CNO_FIRE(conn, on_write, CNO_PREFACE.data, CNO_PREFACE.size)) {
        return CNO_PROPAGATE;
    }

    // TODO send actual settings

    cno_frame_t settings = { CNO_FRAME_SETTINGS };

    if (cno_frame_write(conn, &settings)) {
        return CNO_PROPAGATE;
    }

    return CNO_OK;
}


int cno_connection_is_http2(cno_connection_t *conn)
{
    return conn->state != CNO_CONNECTION_HTTP1_INIT &&
           conn->state != CNO_CONNECTION_HTTP1_READY &&
           conn->state != CNO_CONNECTION_HTTP1_READING;
}


int cno_connection_fire(cno_connection_t *conn)
{
    int __retcode = CNO_OK;
    #define STOP(code) do              { __retcode = code;   goto done; } while (0)
    #define WAIT(cond) do if (!(cond)) { __retcode = CNO_OK; goto done; } while (0)

    while (!conn->closed) switch (conn->state) {
        case CNO_CONNECTION_HTTP1_INIT: {
            if (cno_stream_new(conn, 1) == NULL) {
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
            CNO_ZERO(&stream->msg);
            stream->msg.major = 1;
            stream->msg.minor = 1;
            WAIT(conn->buffer.size);

            // The HTTP 2 preface starts with pseudo-broken HTTP/1.x.
            // PicoHTTPParser will reject it, but we want to know if the client
            // speaks HTTP 2.
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

            struct phr_header headers[100];
            size_t header_num = 100;
            size_t it;

            int ok = conn->client
              ? phr_parse_response(conn->buffer.data, conn->buffer.size,
                                    &stream->msg.minor, &stream->msg.code,
                    (const char **) &stream->msg.method.data,
                                    &stream->msg.method.size,
                                    headers, &header_num, 1)
              : phr_parse_request(conn->buffer.data, conn->buffer.size,
                    (const char **) &stream->msg.method.data,
                                    &stream->msg.method.size,
                    (const char **) &stream->msg.path.data,
                                    &stream->msg.path.size,
                                    &stream->msg.minor,
                                    headers, &header_num, 1);

            WAIT(ok != -2);

            if (ok == -1) {
                STOP(CNO_ERROR_TRANSPORT("bad HTTP/1.x request"));
            }

            if (stream->msg.minor != 1) {
                STOP(CNO_ERROR_TRANSPORT("HTTP/1.%d not supported", stream->msg.minor));
            }

            for (it = 0; it < header_num; ++it) {
                char * name  = (char *) headers[it].name;
                size_t size  = (size_t) headers[it].name_len;
                char * value = (char *) headers[it].value;
                size_t vsize = (size_t) headers[it].value_len;

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
                        { { "connection", 10 }, { "upgrade", 7 } },
                        { { "upgrade",     7 }, { "h2c",     3 } },
                    };

                    cno_message_t upgrade_msg = {
                        101, /* chunked */  0, /* method */ {0}, /* path */ {0},
                        /* headers_len */ 2, upgrade_headers
                    };

                    if (cno_write_message(conn, stream->id, &upgrade_msg, 1)) {
                        STOP(CNO_PROPAGATE);
                    }

                    // If we send the preface now, we'll be able to send HTTP 2 frames
                    // while in the HTTP1_READING_UPGRADE state.
                    if (cno_connection_send_preface(conn)) {
                        STOP(CNO_PROPAGATE);
                    }
                    // Technically, server should refuse if HTTP2-Settings are not present.
                    // We'll let this slide.
                    conn->state = CNO_CONNECTION_HTTP1_READING_UPGRADE;
                } else

                if (strncmp(name, "content-length", size) == 0) {
                    if (stream->msg.remaining) {
                        STOP(CNO_ERROR_TRANSPORT("bad HTTP/1.x request: multiple content-lengths"));
                    }

                    stream->msg.remaining = (size_t) atoi(headers[it].value);
                } else

                if (strncmp(name, "transfer-encoding", size) == 0) {
                    if (strncmp(headers[it].value, "chunked", headers[it].value_len) != 0) {
                        STOP(CNO_ERROR_TRANSPORT("bad HTTP/1.x request: unknown transfer-encoding"));
                    }

                    if (stream->msg.remaining) {
                        STOP(CNO_ERROR_TRANSPORT("bad HTTP/1.x request: chunked encoding w/ fixed length"));
                    }

                    stream->msg.chunked   = 1;
                    stream->msg.remaining = 1;
                }
            }

            stream->msg.headers_len = header_num;
            stream->msg.headers     = malloc(sizeof(headers));
            if (!stream->msg.headers) STOP(CNO_ERROR_NO_MEMORY);

            memcpy(stream->msg.headers, headers, sizeof(headers));

            if (CNO_FIRE(conn, on_message_start, stream->id, &stream->msg)) {
                free(stream->msg.headers);
                STOP(CNO_PROPAGATE);
            }

            stream->state = CNO_STREAM_OPEN;

            if (conn->state == CNO_CONNECTION_HTTP1_READY) {
                conn->state = CNO_CONNECTION_HTTP1_READING;
            }

            cno_io_vector_shift(&conn->buffer, (size_t) ok);
            free(stream->msg.headers);
            break;
        }

        case CNO_CONNECTION_HTTP1_READING:
        case CNO_CONNECTION_HTTP1_READING_UPGRADE: {
            cno_stream_t *stream = conn->streams.first;

            WAIT(conn->buffer.size || !stream->msg.remaining);

            if (stream->msg.chunked) {
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
                    stream->msg.remaining = stream->msg.chunked = 0;
                }

                cno_io_vector_shift(&conn->buffer, data_len + head_len);
                break;
            }

            if (stream->msg.remaining) {
                size_t data_len = stream->msg.remaining;
                char * data_buf = conn->buffer.data;

                if (data_len > conn->buffer.size) {
                    data_len = conn->buffer.size;
                }

                if (CNO_FIRE(conn, on_message_data, stream->id, data_buf, data_len)) {
                    STOP(CNO_PROPAGATE);
                }

                stream->msg.remaining -= data_len;
                cno_io_vector_shift(&conn->buffer, data_len);
                break;
            }

            if (CNO_FIRE(conn, on_message_end, stream->id, 0)) {
                STOP(CNO_PROPAGATE);
            }

            if (conn->state == CNO_CONNECTION_HTTP1_READING_UPGRADE) {
                conn->state = CNO_CONNECTION_PREFACE;
                conn->streams.first->state = CNO_STREAM_CLOSED_REMOTE;
            } else {
                conn->state = CNO_CONNECTION_HTTP1_READY;
                conn->streams.first->state = CNO_STREAM_IDLE;
            }

            break;
        }

        case CNO_CONNECTION_INIT: {
            conn->state = CNO_CONNECTION_PREFACE;

            if (cno_connection_send_preface(conn)) {
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
            WAIT(conn->buffer.size >= 9);

            size_t m;
            unsigned char *base = (unsigned char *) conn->buffer.data;
            CNO_ZERO(&conn->frame);
            CNO_READ_3BYTE(m, base); conn->frame.payload.size = m;
            CNO_READ_1BYTE(m, base); conn->frame.type         = m;
            CNO_READ_1BYTE(m, base); conn->frame.flags        = m;
            CNO_READ_4BYTE(m, base); conn->frame.stream_id    = m;

            if (conn->frame.payload.size > conn->settings[CNO_CFG_LOCAL].max_frame_size) {
                // TODO send FRAME_SIZE_ERROR
                //      if HEADERS, PUSH_PROMISE, CONTINUATION, SETTINGS, or stream is 0
                //      => CONNECTION_ERROR
            }

            if (conn->state == CNO_CONNECTION_READY_NO_SETTINGS && conn->frame.type != CNO_FRAME_SETTINGS) {
                STOP(CNO_ERROR_TRANSPORT("invalid HTTP 2 preface: got %s, not SETTINGS", cno_frame_get_name(&conn->frame)));
            }

            cno_io_vector_shift(&conn->buffer, 9);
            conn->state = CNO_CONNECTION_READING;
            break;
        }

        case CNO_CONNECTION_READING: {
            WAIT(conn->buffer.size >= conn->frame.payload.size);

            conn->frame.payload.data = cno_io_vector_slice(&conn->buffer, conn->frame.payload.size);
            conn->state = CNO_CONNECTION_READY;

            if (CNO_FIRE(conn, on_frame, &conn->frame)) {
                cno_io_vector_clear(&conn->frame.payload);
                STOP(CNO_PROPAGATE);
            }

            if (cno_connection_handle_frame(conn, &conn->frame)) {
                cno_io_vector_clear(&conn->frame.payload);
                STOP(CNO_PROPAGATE);
            }

            cno_io_vector_clear(&conn->frame.payload);
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
    cno_io_vector_clear((cno_io_vector_t *) &conn->frame.payload);

    while (conn->streams.first != (cno_stream_t *) conn) {
        if (cno_stream_destroy_clean(conn, conn->streams.first)) {
            return CNO_PROPAGATE;
        }
    }

    conn->state = CNO_CONNECTION_CLOSED;
    CNO_ZERO(&conn->buffer);
    return CNO_OK;

done:

    if (cno_io_vector_strip(&conn->buffer)) {
        return CNO_PROPAGATE;
    }

    return __retcode;
}


static int cno_write_get_mode(cno_connection_t *conn, size_t id, cno_stream_t **stream)
{
    switch (conn->state) {
        case CNO_CONNECTION_CLOSED:
            return CNO_ERROR_INVALID_STATE("connection already closed");

        case CNO_CONNECTION_INIT:
        case CNO_CONNECTION_HTTP1_INIT:
            return CNO_ERROR_INVALID_STATE("connection not yet initialized");

        case CNO_CONNECTION_HTTP1_READY:
        case CNO_CONNECTION_HTTP1_READING:
        // HTTP1_READING_UPGRADE is treated as HTTP 2 for writing
            if (id != conn->streams.first->id) {
                return CNO_ERROR_INVALID_STREAM(id);
            }

            *stream = conn->streams.first;
            return 1;

        default:
            *stream = cno_stream_find(conn, id);

            if (*stream == NULL) {
                // Clients can create streams with odd ids, while
                // servers reserve the even ids.
                if (conn->client ^ (id & 1)) {
                    return CNO_ERROR_INVALID_STREAM(id);
                }

                *stream = cno_stream_new(conn, id);

                if (*stream == NULL) {
                    return CNO_PROPAGATE;
                }
            }

            if (conn->client) {
                if ((*stream)->state != CNO_STREAM_IDLE && (*stream)->state != CNO_STREAM_OPEN) {
                    return CNO_ERROR_INVALID_STREAM(id);
                }
            } else {
                if ((*stream)->state != CNO_STREAM_IDLE          && (*stream)->state != CNO_STREAM_OPEN
                 && (*stream)->state != CNO_STREAM_CLOSED_REMOTE && (*stream)->state != CNO_STREAM_RESERVED_LOCAL) {
                    return CNO_ERROR_INVALID_STREAM(id);
                }
            }

            return 0;
    }
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


int cno_write_message(cno_connection_t *conn, size_t stream, cno_message_t *msg, int final)
{
    cno_stream_t *streamobj;

    switch (cno_write_get_mode(conn, stream, &streamobj)) {
        case -1: return CNO_PROPAGATE;
        case  1: {
            size_t i;
            char head[4096];
            char *tg = head;
            msg->major = 1;
            msg->minor = 1;

            if (conn->client) {
                if (msg->method.size + msg->path.size >= 4084) {
                    return CNO_ERROR_TRANSPORT("path too long (>= 4096 total)");
                }

                memcpy(tg, msg->method.data, msg->method.size); tg += msg->method.size; *tg++ = ' ';
                memcpy(tg, msg->path.data,   msg->path.size);   tg += msg->path.size;
                sprintf(tg, " HTTP/1.1\r\n");
                tg += strlen(tg);
            } else {
                sprintf(head, "HTTP/1.1 %d %s\r\n", msg->code, cno_message_literal(msg));
                tg += strlen(head);
            }

            for (i = 0; i < msg->headers_len; ++i) {
                if (CNO_FIRE(conn, on_write, head, tg - head)) {
                    return CNO_PROPAGATE;
                }

                cno_io_vector_t *name  = &msg->headers[i].name;
                cno_io_vector_t *value = &msg->headers[i].value;

                if (name->size + value->size >= 4090) {
                    return CNO_ERROR_TRANSPORT("header too long (>= 4096 total)");
                }

                tg = head;

                if (strncmp(name->data, ":authority", name->size) == 0) {
                    memcpy(tg, "Host: ", 6);
                    tg += 6;
                } else if (strncmp(name->data, ":status", name->size) == 0) {
                    return CNO_ERROR_ASSERTION("set `message.code` instead of sending :status");
                } else if (name->data[0] == ':') {
                    continue;
                } else {
                    memcpy(tg, name->data, name->size); tg += name->size;  *tg++ = ':';  *tg++ = ' ';
                }
                memcpy(tg, value->data, value->size); tg += value->size; *tg++ = '\r'; *tg++ = '\n';
            }

            *tg++ = '\r';
            *tg++ = '\n';

            if (CNO_FIRE(conn, on_write, head, tg - head)) {
                return CNO_PROPAGATE;
            }

            if (!final) {
                streamobj->state = CNO_STREAM_OPEN;
            }

            return CNO_OK;;
        }
    }

    cno_frame_t frame = { CNO_FRAME_HEADERS, CNO_FLAG_END_HEADERS, stream };
    msg->major = 2;
    msg->minor = 0;

    if (final) {
        frame.flags |= CNO_FLAG_END_STREAM;
    }

    if (conn->client) {
        cno_header_t head[2] = {
            { { ":method", 7 }, { msg->method.data, msg->method.size } },
            { { ":path",   5 }, { msg->path.data, msg->path.size } },
        };

        if (cno_hpack_encode(&conn->encoder, &frame.payload, head, 2)) {
            return CNO_PROPAGATE;
        }
    } else {
        char code[10] = { 0 };
        snprintf(code, 10, "%d", msg->code);

        cno_header_t head[1] = {
            { { ":status", 7 }, { code, strlen(code) } },
        };

        if (cno_hpack_encode(&conn->encoder, &frame.payload, head, 1)) {
            return CNO_PROPAGATE;
        }
    }

    if (cno_hpack_encode(&conn->encoder, &frame.payload, msg->headers, msg->headers_len)) {
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
    cno_stream_t *streamobj;

    switch (cno_write_get_mode(conn, stream, &streamobj)) {
        case -1: return CNO_PROPAGATE;
        case  1: {
            if (!length) {
                // Nothing to do.
            } /* else if (chunked) {
                size_t enc;
                char  encd[sizeof(size_t) + 2];
                char *it = encd + sizeof(size_t) + 2;
                *--it = '\n';
                *--it = '\r';

                for (enc = length; enc; enc >>= 4) {
                    *--it = (enc & 0xF) < 10
                          ? (enc & 0xF) + '0'
                          : (enc & 0xF) + 'A' - 10;
                }

                if (CNO_FIRE(conn, on_write, it, sizeof(size_t) + 2 - (it - encd))
                 || CNO_FIRE(conn, on_write, data, length)
                 || CNO_FIRE(conn, on_write, "\r\n", 2)) return CNO_PROPAGATE;
            } */ else {
                if (CNO_FIRE(conn, on_write, data, length)) {
                    return CNO_PROPAGATE;
                }
            }
            if (final) {
                streamobj->state = CNO_STREAM_IDLE;
            }
            return CNO_OK;
        }
    }

    cno_frame_t frame = { CNO_FRAME_DATA, final ? CNO_FLAG_END_STREAM : 0, stream };
    frame.payload.data = (char *) data;
    frame.payload.size = length;

    if (cno_frame_write(conn, &frame)) {
        return CNO_PROPAGATE;
    }

    return final ? cno_finalize_http2(conn, streamobj) : CNO_OK;
}
