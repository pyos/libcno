#include "core.h"
#include "list.h"
#include "error.h"
#include "write.h"
#include "picohttpparser/picohttpparser.h"
#include <stdlib.h>
#include <string.h>


static cno_stream_t * cno_stream_new(cno_connection_t *conn, size_t id)
{
    cno_stream_t *stream = malloc(sizeof(cno_stream_t));

    if (!stream) {
        (void) CNO_ERROR_NO_MEMORY;
        return NULL;
    }

    CNO_ZERO(stream);
    stream->id     = id;
    stream->state  = CNO_STREAM_IDLE;
    stream->window = conn->settings.initial_window_size;
    cno_list_insert_after(conn, stream);

    if (CNO_FIRE(conn, on_stream_start, id)) {
        free(stream);
        (void) CNO_PROPAGATE;
        return NULL;
    }

    return stream;
}

static int cno_stream_destroy(cno_connection_t *conn, cno_stream_t *stream)
{
    if (stream->state == CNO_STREAM_OPEN) {
        // Note that second argument is `1`. Callback should know that the stream
        // is dead, but shouldn't try to actually do anything with the message.
        if (CNO_FIRE(conn, on_message_end, stream->id, 1)) {
            return CNO_PROPAGATE;
        }
    }

    if (CNO_FIRE(conn, on_stream_end, stream->id)) {
        return CNO_PROPAGATE;
    }

    cno_list_remove(stream);
    free(stream);
    return CNO_OK;
}

#if 0
static cno_stream_t * cno_stream_find(cno_connection_t *conn, size_t id)
{
    cno_stream_t *current = (cno_stream_t *) conn;

    while ((current = current->next) != (cno_stream_t *) conn) {
        if (current->id == id) {
            return current;
        }
    }

    (void) CNO_ERROR_INVALID_STREAM(id);
    return NULL;
}
#endif

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
    conn->streams.first = (cno_stream_t *) conn;
    conn->streams.last  = (cno_stream_t *) conn;
    conn->settings.header_table_size = 4096;
    conn->settings.enable_push = 1;
    conn->settings.max_concurrent_streams = -1;
    conn->settings.initial_window_size = 65536;
    conn->settings.max_frame_size = 16384;
    conn->settings.max_header_list_size = -1;
    conn->window = 65536;
    return conn;
}


int cno_connection_destroy(cno_connection_t *conn)
{
    int ok = conn->closed ? CNO_OK : cno_connection_lost(conn);
    free(conn);
    return ok;
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


int cno_connection_made(cno_connection_t *conn)
{
    return cno_connection_fire(conn);
}


int cno_connection_lost(cno_connection_t *conn)
{
    if (conn->closed) {
        return CNO_ERROR_INVALID_STATE("already closed");
    }

    conn->closed = 1;
    return cno_connection_fire(conn);
}


#define _CNO_WRITE_1BYTE(ptr, src) *ptr++ = src
#define _CNO_WRITE_2BYTE(ptr, src) do { *ptr++ = src >>  8; _CNO_WRITE_1BYTE(ptr, src); } while (0)
#define _CNO_WRITE_3BYTE(ptr, src) do { *ptr++ = src >> 16; _CNO_WRITE_2BYTE(ptr, src); } while (0)
#define _CNO_WRITE_4BYTE(ptr, src) do { *ptr++ = src >> 24; _CNO_WRITE_3BYTE(ptr, src); } while (0)
#define _CNO_READ_1BYTE(tg, ptr) tg = *ptr++
#define _CNO_READ_2BYTE(tg, ptr) do { tg = *ptr++ <<  8; _CNO_READ_1BYTE(tg, ptr); } while (0)
#define _CNO_READ_3BYTE(tg, ptr) do { tg = *ptr++ << 16; _CNO_READ_2BYTE(tg, ptr); } while (0)
#define _CNO_READ_4BYTE(tg, ptr) do { tg = *ptr++ << 24; _CNO_READ_3BYTE(tg, ptr); } while (0)


static int cno_connection_send_frame(cno_connection_t *conn, cno_frame_t *frame)
{
    char  header[9];
    char *ptr = header;
    size_t length = frame->payload.size;
    size_t stream = frame->stream;

    if (length > conn->settings.max_frame_size) {
        return CNO_ERROR_ASSERTION("frame too big (%lu; limit = %lu)", length, conn->settings.max_frame_size);
    }

    _CNO_WRITE_3BYTE(ptr, length);
    _CNO_WRITE_1BYTE(ptr, frame->type);
    _CNO_WRITE_1BYTE(ptr, frame->flags);
    _CNO_WRITE_4BYTE(ptr, stream);

    if (CNO_FIRE(conn, on_write, header, 9)) {
        return CNO_PROPAGATE;
    }

    if (length && CNO_FIRE(conn, on_write, frame->payload.data, length)) {
        return CNO_PROPAGATE;
    }

    if (CNO_FIRE(conn, on_frame_send, frame)) {
        return CNO_PROPAGATE;
    }

    return CNO_OK;
}


static int cno_connection_send_goaway(cno_connection_t *conn, size_t code, const char *data, size_t length)
{
    size_t stream = conn->streams.last == (cno_stream_t *) conn ? 0 : conn->streams.last->id;

    char descr[8];
    char *ptr = descr;
    _CNO_WRITE_4BYTE(ptr, stream);
    _CNO_WRITE_4BYTE(ptr, code);

    cno_frame_t error = { CNO_FRAME_GOAWAY };

    if (!length) {
        error.payload.data = descr;
        error.payload.size = sizeof(descr);
    } else {
        if (cno_io_vector_extend(&error.payload, data, length)
         || cno_io_vector_extend(&error.payload, descr, sizeof(descr))) {
            return CNO_PROPAGATE;
        }
    }

    int ok = cno_connection_send_frame(conn, &error);

    if (length) {
        cno_io_vector_clear(&error.payload);
    }

    return ok;
}


static int cno_connection_handle_frame(cno_connection_t *conn, cno_frame_t *frame)
{
    char *ptr = frame->payload.data;
    char *end = frame->payload.size + ptr;
    size_t sz = frame->payload.size;

    switch (frame->type) {
        case CNO_FRAME_SETTINGS: {
            if (sz % 6) {
                if (cno_connection_send_goaway(conn, CNO_STATE_FRAME_SIZE_ERROR, NULL, 0)) {
                    return CNO_PROPAGATE;
                }

                return CNO_ERROR_TRANSPORT("bad SETTINGS (length = %lu)", sz);
            }

            while (ptr != end) {
                size_t setting; _CNO_READ_2BYTE(setting, ptr);
                size_t value;   _CNO_READ_4BYTE(value,   ptr);

                switch (setting) {
                    case CNO_SETTINGS_HEADER_TABLE_SIZE:      conn->settings.header_table_size      = value; break;
                    case CNO_SETTINGS_ENABLE_PUSH:            conn->settings.enable_push            = value; break;
                    case CNO_SETTINGS_MAX_CONCURRENT_STREAMS: conn->settings.max_concurrent_streams = value; break;
                    case CNO_SETTINGS_INITIAL_WINDOW_SIZE:    conn->settings.initial_window_size    = value; break;
                    case CNO_SETTINGS_MAX_FRAME_SIZE:         conn->settings.max_frame_size         = value; break;
                    case CNO_SETTINGS_MAX_HEADER_LIST_SIZE:   conn->settings.max_header_list_size   = value; break;
                }
            }

            cno_frame_t ack = { CNO_FRAME_SETTINGS, CNO_FLAG_ACK };

            if (cno_connection_send_frame(conn, &ack)) {
                return CNO_PROPAGATE;
            }

            return CNO_OK;
        }

        case CNO_FRAME_WINDOW_UPDATE: {
            if (sz != 4) {
                if (cno_connection_send_goaway(conn, CNO_STATE_FRAME_SIZE_ERROR, NULL, 0)) {
                    return CNO_PROPAGATE;
                }

                return CNO_ERROR_TRANSPORT("bad WINDOW_UPDATE (length = %lu)", sz);
            }

            size_t increment;
            _CNO_READ_4BYTE(increment, ptr);

            if (frame->stream == 0) {
                if (increment == 0) {
                    if (cno_connection_send_goaway(conn, CNO_STATE_PROTOCOL_ERROR, NULL, 0)) {
                        return CNO_PROPAGATE;
                    }

                    return CNO_ERROR_TRANSPORT("bad WINDOW_UPDATE (incr = %lu)", increment);
                }

                conn->window += increment;

                if (conn->window >= 0x80000000u) {
                    if (cno_connection_send_goaway(conn, CNO_STATE_FLOW_CONTROL_ERROR, NULL, 0)) {
                        return CNO_PROPAGATE;
                    }

                    return CNO_ERROR_TRANSPORT("flow control window got too big (incr = %lu)", increment);
                }
            } else {
                // TODO check that increment is nonzero
                // TODO increment stream's flow control window (stream->window)
                // TODO check that it is < (1 << 31); otherwise, return FLOW_CONTROL_ERROR.
            }

            return CNO_OK;
        }

        case CNO_FRAME_DATA:
        case CNO_FRAME_HEADERS:
        case CNO_FRAME_PRIORITY:
        case CNO_FRAME_RST_STREAM:
        case CNO_FRAME_PUSH_PROMISE:
        case CNO_FRAME_PING:
        case CNO_FRAME_GOAWAY:
        case CNO_FRAME_CONTINUATION: {
            (void) CNO_ERROR_NOT_IMPLEMENTED("frame type %d (%s)", frame->type, cno_frame_get_name(frame));
            (void) cno_connection_send_goaway(conn, CNO_STATE_INTERNAL_ERROR, NULL, 0);
            return CNO_PROPAGATE;
        }

        default: {
            if (cno_connection_send_goaway(conn, CNO_STATE_PROTOCOL_ERROR, NULL, 0)) {
                return CNO_PROPAGATE;
            }

            return CNO_ERROR_TRANSPORT("unknown frame type %d", frame->type);
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

    if (cno_connection_send_frame(conn, &settings)) {
        return CNO_PROPAGATE;
    }

    return CNO_OK;
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

            if (CNO_FIRE(conn, on_ready)) {
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

            // The HTTP 2 preface starts with pseudo-broken HTTP/1.x.
            // PicoHTTPParser will reject it, but we want to know if the client
            // speaks HTTP 2. (This also waits for a non-empty buffer, which
            // is a good thing because PicoHTTPParser breaks if length == 0.)
            if (!conn->client) {
                int may_be_http2 = strncmp(conn->buffer.data, CNO_PREFACE.data, conn->buffer.size) == 0;
                WAIT(conn->buffer.size >= CNO_PREFACE.size || !may_be_http2);
                if  (conn->buffer.size >= CNO_PREFACE.size &&  may_be_http2) {
                    // Definitely HTTP2. Stream 1 should be recycled, though.
                    cno_stream_destroy(conn, stream);

                    if (cno_connection_send_preface(conn)) {
                        STOP(CNO_PROPAGATE);
                    }

                    // NOTE transition to HTTP 2 will be seamless because the buffer
                    //      is already full. Thus we don't emit `on_ready` again.
                    conn->state = CNO_CONNECTION_INIT_UPGRADE;
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

            for (it = 0; it < header_num; ++it) {
                char * name  = (char *) headers[it].name;
                size_t size  = (size_t) headers[it].name_len;
                char * value = (char *) headers[it].value;
                size_t vsize = (size_t) headers[it].value_len;
                // TODO convert name to lowercase

                if (strncmp(name, "http2-settings", size) == 0) {
                    // TODO decode & emit on_frame
                } else

                if (strncmp(name, "upgrade", size) == 0 && strncmp(value, "h2c", vsize) == 0) {
                    cno_header_t upgrade_headers[] = {
                        { { "connection", 10 }, { "upgrade", 7 } },
                        { { "upgrade",     7 }, { "h2c",     3 } },
                    };

                    cno_message_t upgrade_msg = {
                        stream->msg.major, stream->msg.minor, 101,
                        /* chunked */  0, /* method */ {0}, /* path */ {0},
                        /* headers_len */ 2, upgrade_headers
                    };

                    if (cno_write_message(conn, stream->id, &upgrade_msg)) {
                        STOP(CNO_PROPAGATE);
                    }

                    // Technically, server should refuse if HTTP2-Settings are not present.
                    // We'll let this slide.
                    conn->state = CNO_CONNECTION_HTTP1_READING_UPGRADE;
                    // If we send the preface now, we'll be able to send HTTP 2 frames
                    // while in the HTTP1_READING_UPGRADE state.
                    if (cno_connection_send_preface(conn)) {
                        STOP(CNO_PROPAGATE);
                    }
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

            conn->streams.first->state = CNO_STREAM_OPEN;
            conn->state = CNO_CONNECTION_HTTP1_READING;
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
                    stream->msg.remaining = 0;
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
                conn->state = CNO_CONNECTION_INIT_UPGRADE;
                conn->streams.first->state = CNO_STREAM_CLOSED_REMOTE;
            } else {
                conn->state = CNO_CONNECTION_HTTP1_READY;
                conn->streams.first->state = CNO_STREAM_IDLE;
            }

            break;
        }

        case CNO_CONNECTION_INIT: {
            if (cno_connection_send_preface(conn)) {
                STOP(CNO_PROPAGATE);
            }

            if (CNO_FIRE(conn, on_ready)) {
                STOP(CNO_PROPAGATE);
            }
        }  // fallthrough

        case CNO_CONNECTION_INIT_UPGRADE: {
            if (!conn->client) {
                WAIT(conn->buffer.size >= CNO_PREFACE.size);

                if (strncmp(conn->buffer.data, CNO_PREFACE.data, CNO_PREFACE.size)) {
                    STOP(CNO_ERROR_TRANSPORT("invalid HTTP 2 preface: no client preface"));
                }

                cno_io_vector_shift(&conn->buffer, CNO_PREFACE.size);
            }

            conn->state = CNO_CONNECTION_PREFACE;
        }  // fallthrough (no closed-ness check)

        case CNO_CONNECTION_READY:
        case CNO_CONNECTION_PREFACE: {
            WAIT(conn->buffer.size >= 9);

            char *base = conn->buffer.data;
            _CNO_READ_3BYTE(conn->frame.payload.size, base);
            _CNO_READ_1BYTE(conn->frame.type,         base);
            _CNO_READ_1BYTE(conn->frame.flags,        base);
            _CNO_READ_4BYTE(conn->frame.stream,       base);

            if (conn->frame.payload.size > conn->settings.max_frame_size) {
                // TODO send FRAME_SIZE_ERROR
                //      if HEADERS, PUSH_PROMISE, CONTINUATION, SETTINGS, or stream sis 0
                //      => CONNECTION_ERROR
            }

            if (conn->state == CNO_CONNECTION_PREFACE && conn->frame.type != CNO_FRAME_SETTINGS) {
                STOP(CNO_ERROR_TRANSPORT("invalid HTTP 2 preface: no SETTINGS frame"));
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
        if (cno_stream_destroy(conn, conn->streams.first)) {
            return CNO_PROPAGATE;
        }
    }

    conn->state = CNO_CONNECTION_CLOSED;
    CNO_ZERO(&conn->buffer);
    return CNO_FIRE(conn, on_close);

done:

    if (cno_io_vector_strip(&conn->buffer)) {
        return CNO_PROPAGATE;
    }

    return __retcode;
}
