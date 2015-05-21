#include "core.h"
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
    stream->id    = id;
    stream->next  = conn->streams;
    stream->state = CNO_STREAM_IDLE;
    conn->streams = stream;

    if (CNO_FIRE(conn, on_stream_start, id)) {
        free(stream);
        (void) CNO_PROPAGATE;
        return NULL;
    }

    return stream;
}


static cno_stream_t * cno_stream_find(cno_connection_t *conn, size_t id)
{
    cno_stream_t *current = conn->streams;

    while (current->id != id) if (!(current = current->next)) {
        // XXX Maybe a hashmap? Definitely not an array - stream ids are sparse
        //     because they can be closed in different order.
        (void) CNO_ERROR_INVALID_STREAM(id);
        return NULL;
    }

    return current;
}


static int cno_stream_destroy(cno_connection_t *conn, size_t id)
{
    cno_stream_t *stream = cno_stream_find(conn, id);

    if (!stream) {
        return CNO_PROPAGATE;
    }

    if (stream->state == CNO_STREAM_OPEN) {
        // Note that second argument is `1`. Callback should know that the stream
        // is dead, but shouldn't try to actually do anything with the message.
        if (CNO_FIRE(conn, on_message_end, stream->id, 1)) {
            return CNO_PROPAGATE;
        }
    }

    if (CNO_FIRE(conn, on_stream_end, id)) {
        return CNO_PROPAGATE;
    }

    if (stream->next) stream->next->prev = stream->prev;
    if (stream->prev) stream->prev->next = stream->next;
    else conn->streams = stream->next;

    if (stream->msg.headers) {
        free(stream->msg.headers);
    }

    free(stream);
    return CNO_OK;
}


cno_connection_t * cno_connection_new(int server, int upgrade)
{
    cno_connection_t *conn = malloc(sizeof(cno_connection_t));

    if (conn == NULL) {
        (void) CNO_ERROR_NO_MEMORY;
        return NULL;
    }

    CNO_ZERO(conn);
    conn->state  = upgrade ? CNO_CONNECTION_INIT : CNO_CONNECTION_HTTP1_INIT;
    conn->server = server;
    conn->settings.max_frame_size = 1 << 14;
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


static int cno_connection_send_preface(cno_connection_t *conn) {
    if (!conn->server && CNO_FIRE(conn, on_write, CNO_PREFACE.data, CNO_PREFACE.size)) {
        return CNO_PROPAGATE;
    }

    // TODO send a SETTINGS frame
    return CNO_OK;
}


int cno_connection_fire(cno_connection_t *conn)
{
    int __retcode = CNO_OK;
    #define STOP(code) do              { __retcode = code;   goto done; } while (0)
    #define WAIT(cond) do if (!(cond)) { __retcode = CNO_OK; goto done; } while (0)

    while (1) {
        if (conn->closed) {
            // Since previous `data_received` had finished, the data in the buffer
            // is incomplete (and useless).
            cno_io_vector_reset(&conn->buffer);
            cno_io_vector_clear((cno_io_vector_t *) &conn->buffer);
            cno_io_vector_clear((cno_io_vector_t *) &conn->frame.payload);

            while (conn->streams) {
                // Guaranteed to succeed. This stream definitely exists.
                cno_stream_destroy(conn, conn->streams->id);
            }

            conn->state = CNO_CONNECTION_CLOSED;
            CNO_ZERO(&conn->buffer);
            return CNO_FIRE(conn, on_close);
        }

        switch (conn->state) {
            case CNO_CONNECTION_HTTP1_INIT: {
                if (cno_stream_new(conn, 1) == NULL) {
                    STOP(CNO_PROPAGATE);
                }

                conn->state = CNO_CONNECTION_HTTP1_READY;

                if (CNO_FIRE(conn, on_ready)) {
                    STOP(CNO_PROPAGATE);
                }

                break;
            }

            case CNO_CONNECTION_HTTP1_READY: {
                // Ignore leading CR/LFs.
                const char *ign = conn->buffer.data;
                const char *end = conn->buffer.size + ign;
                while (ign != end && (*ign == '\r' || *ign == '\n')) ++ign;
                cno_io_vector_shift(&conn->buffer, ign - conn->buffer.data);

                // Should be exactly one stream right now.
                cno_stream_t *stream = conn->streams;

                if (stream->msg.headers) {
                    free(stream->msg.headers);
                }

                CNO_ZERO(&stream->msg);
                stream->msg.major = 1;

                int may_be_http2 = strncmp(conn->buffer.data, CNO_PREFACE.data, conn->buffer.size) == 0;
                // The HTTP 2 preface starts with pseudo-broken HTTP/1.x.
                // PicoHTTPParser will reject it, but we want to know if the client
                // speaks HTTP 2. (This also waits for a non-empty buffer, which
                // is a good thing because PicoHTTPParser breaks if length == 0.)
                WAIT(conn->buffer.size >= CNO_PREFACE.size || !may_be_http2);
                if  (conn->buffer.size >= CNO_PREFACE.size &&  may_be_http2) {
                    // Definitely HTTP2. Stream 1 should be recycled, though.
                    cno_stream_destroy(conn, stream->id);

                    if (cno_connection_send_preface(conn)) {
                        STOP(CNO_PROPAGATE);
                    }

                    // NOTE transition to HTTP 2 will be seamless because the buffer
                    //      is already full. Thus we don't emit `on_ready` again.
                    conn->state = CNO_CONNECTION_INIT_UPGRADE;
                    break;
                }

                struct phr_header headers[100];
                size_t header_num = 100;
                size_t it;

                int ok = conn->server
                  ? phr_parse_request(conn->buffer.data, conn->buffer.size,
                        (const char **) &stream->msg.method.data,
                                        &stream->msg.method.size,
                        (const char **) &stream->msg.path.data,
                                        &stream->msg.path.size,
                                        &stream->msg.minor,
                                        headers, &header_num, 1)
                  : phr_parse_response(conn->buffer.data, conn->buffer.size,
                                        &stream->msg.minor, &stream->msg.code,
                        (const char **) &stream->msg.method.data,
                                        &stream->msg.method.size,
                                        headers, &header_num, 1);

                WAIT(ok != -2);

                if (ok == -1) {
                    STOP(CNO_ERROR_TRANSPORT("bad HTTP/1.x request"));
                }

                stream->msg.headers_len = header_num;
                stream->msg.headers     = calloc(sizeof(cno_header_t), header_num);
                if (!stream->msg.headers) STOP(CNO_ERROR_NO_MEMORY);

                conn->streams->state = CNO_STREAM_OPEN;
                conn->state = CNO_CONNECTION_HTTP1_READING;

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

                memcpy(stream->msg.headers, headers, sizeof(cno_header_t) * header_num);

                if (CNO_FIRE(conn, on_message_start, stream->id, &stream->msg)) {
                    STOP(CNO_PROPAGATE);
                }

                CNO_ZERO(&stream->msg.method);
                CNO_ZERO(&stream->msg.path);
                cno_io_vector_shift(&conn->buffer, (size_t) ok);
                continue;
            }

            case CNO_CONNECTION_HTTP1_READING:
            case CNO_CONNECTION_HTTP1_READING_UPGRADE: {
                cno_stream_t *stream = conn->streams;

                WAIT(conn->buffer.size || !stream->msg.remaining);

                if (stream->msg.chunked) {
                    char *it  = conn->buffer.data;
                    char *lim = conn->buffer.size + it;
                    char *eol = it; while (eol != lim && *eol != '\n') ++eol;
                    char *end = it; while (end != eol && *end != ';')  ++end;
                    WAIT(eol != lim);

                    size_t data_len = 0;
                    size_t head_len = (eol - it) + 3;  // + \r\n

                    for (; it != end; ++it) {
                        data_len = '0' <= *it && *it <= '9' ? (data_len << 4) | (*it - '0'     ) :
                                   'A' <= *it && *it <= 'F' ? (data_len << 4) | (*it - 'A' + 10) :
                                   'a' <= *it && *it <= 'f' ? (data_len << 4) | (*it - 'a'     ) : data_len;
                    }

                    WAIT(conn->buffer.size >= data_len + head_len);
                    cno_io_vector_shift(&conn->buffer, data_len + head_len);

                    if (data_len) {
                        if (CNO_FIRE(conn, on_message_data, stream->id, eol + 1, data_len)) {
                            STOP(CNO_PROPAGATE);
                        }
                    } else {
                        // That was the last chunk.
                        stream->msg.remaining = 0;
                    }
                } else if (stream->msg.remaining) {
                    size_t data_len = stream->msg.remaining;
                    char * data_buf = conn->buffer.data;

                    if (data_len > conn->buffer.size) {
                        data_len = conn->buffer.size;
                    }

                    stream->msg.remaining -= data_len;

                    cno_io_vector_shift(&conn->buffer, data_len);

                    if (CNO_FIRE(conn, on_message_data, stream->id, data_buf, data_len)) {
                        STOP(CNO_PROPAGATE);
                    }
                }

                if (!stream->msg.remaining) {
                    conn->state = conn->state == CNO_CONNECTION_HTTP1_READING_UPGRADE
                        ? CNO_CONNECTION_INIT_UPGRADE  // preface already sent in HTTP1_READY
                        : CNO_CONNECTION_HTTP1_READY;
                    // In HTTP/1.x, RST_STREAM is implied.
                    conn->streams->state = CNO_STREAM_IDLE;

                    if (CNO_FIRE(conn, on_message_end, stream->id, 0)) {
                        STOP(CNO_PROPAGATE);
                    }
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
                WAIT(conn->buffer.size >= CNO_PREFACE.size);

                if (strncmp(conn->buffer.data, CNO_PREFACE.data, CNO_PREFACE.size)) {
                    STOP(CNO_ERROR_TRANSPORT("HTTP 2 did not start with valid preface"));
                }

                conn->state = CNO_CONNECTION_PREFACE;
                cno_io_vector_shift(&conn->buffer, CNO_PREFACE.size);
                break;
            }

            case CNO_CONNECTION_READY:
            case CNO_CONNECTION_PREFACE: {
                WAIT(conn->buffer.size >= 9);

                char *base = conn->buffer.data;
                conn->frame.payload.size = base[0] << 16 | base[1] << 8 | base[2];
                conn->frame.type         = base[3];
                conn->frame.flags        = base[4];
                conn->frame.stream       = base[5] << 24 | base[6] << 16 | base[7] << 8 | base[8];

                if (conn->frame.payload.size > conn->settings.max_frame_size) {
                    // TODO send FRAME_SIZE_ERROR
                    //      if HEADERS, PUSH_PROMISE, CONTINUATION, SETTINGS, or stream sis 0
                    //      => CONNECTION_ERROR
                }

                if (conn->state == CNO_CONNECTION_PREFACE) {
                    // TODO check that we got a SETTINGS frame
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
                    STOP(CNO_PROPAGATE);
                }

                cno_io_vector_clear(&conn->frame.payload);
                break;
            }

            default: {
                STOP(CNO_ERROR_INVALID_STATE("fell to the bottom of the DFA"));
            }
        }
    }

    #undef STOP
    #undef WAIT

done:

    if (cno_io_vector_strip(&conn->buffer)) {
        return CNO_PROPAGATE;
    }

    return __retcode;
}
