#include "core.h"
#include "error.h"
#include "picohttpparser/picohttpparser.h"
#include <stdlib.h>
#include <string.h>


cno_connection_t * cno_connection_new (int server, int upgrade)
{
    cno_connection_t *conn = malloc(sizeof(cno_connection_t));

    if (conn == NULL) {
        (void) CNO_ERROR_NOMEMORY;
        return NULL;
    }

    memset(conn, 0, sizeof(cno_connection_t));

    conn->state  = upgrade ? CNO_CONNECTION_INIT : CNO_CONNECTION_HTTP1_INIT;
    conn->server = server;
    return conn;
}


static int cno_connection_stream_new (cno_connection_t *conn, size_t id)
{
    cno_stream_t *stream = malloc(sizeof(cno_stream_t));

    if (!stream) {
        return CNO_ERROR_NOMEMORY;
    }

    memset(stream, 0, sizeof(cno_stream_t));
    stream->id        = id;
    stream->next      = conn->streams;
    stream->msg.major = conn->state == CNO_CONNECTION_HTTP1_READY ? 1 : 2;
    stream->msg.code  = 0;
    stream->open      = 1;
    conn->streams = stream;
    CNO_FIRE(conn, on_stream_start, id);
    return CNO_OK;
}


static int cno_connection_stream_find (cno_connection_t *conn, size_t id, cno_stream_t **it, cno_stream_t **p)
{
    cno_stream_t *parent  = NULL;
    cno_stream_t *current = conn->streams;

    while (current->id != id) {
        parent  = current;
        current = current->next;

        if (!current) {
            return CNO_ERROR_NOSTREAM(id);
        }
    }

    if (it) *it = current;
    if (p)  *p  = parent;
    return CNO_OK;
}


static int cno_connection_stream_close (cno_connection_t *conn, size_t id) {
    cno_stream_t *parent;
    cno_stream_t *stream;

    if (cno_connection_stream_find(conn, id, &stream, &parent)) {
        return CNO_PROPAGATE;
    }

    if (!stream->open) {
        return CNO_ERROR_CLOSED;
    }

    stream->open = 0;

    if (stream->active) {
        CNO_FIRE(conn, on_message_end, id, 0);
        stream->active = 0;
    }

    return CNO_OK;
}


static int cno_connection_stream_destroy (cno_connection_t *conn, size_t id) {
    cno_stream_t *parent;
    cno_stream_t *stream;

    if (cno_connection_stream_find(conn, id, &stream, &parent)) {
        return CNO_PROPAGATE;
    }

    if (stream->active) {
        CNO_FIRE(conn, on_message_end, stream->id, 1);
    }

    CNO_FIRE(conn, on_stream_end, id);

    if (!parent) {
        conn->streams = stream->next;
    } else {
        parent->next = stream->next;
    }

    free(stream);
    return CNO_OK;
}


void cno_connection_destroy (cno_connection_t *conn)
{
    if (!conn->closed) {
        cno_connection_lost(conn);
    }

    free(conn);
}


int cno_connection_data_received (cno_connection_t *conn, const char *data, size_t length)
{
    if (conn->closed) {
        return CNO_ERROR_CLOSED;
    }

    if (cno_io_vector_extend_tmp(&conn->buffer, data, length)) {
        return CNO_PROPAGATE;
    }

    return cno_connection_fire(conn);
}


int cno_connection_lost (cno_connection_t *conn)
{
    if (conn->closed) {
        return CNO_ERROR_CLOSED;
    }

    conn->closed = 1;
    return cno_connection_fire(conn);
}


int cno_connection_fire (cno_connection_t *conn)
{
    int retcode = -1;

    #define STOP(code) do { retcode = code; goto done; } while (0)

    while (1) {
        if (conn->closed) {
            cno_io_vector_clear_tmp(&conn->buffer);

            if (conn->frame.payload) {
                free(conn->frame.payload);
            }

            while (conn->streams) {
                cno_connection_stream_destroy(conn, conn->streams->id);
            }

            conn->state = CNO_CONNECTION_CLOSED;
            conn->buffer.data   = NULL;
            conn->buffer.size   = 0;
            conn->buffer.offset = 0;
            CNO_FIRE(conn, on_close);
            return CNO_OK;
        }

        switch (conn->state) {
            case CNO_CONNECTION_HTTP1_INIT: {
                conn->state = CNO_CONNECTION_HTTP1_READY;

                if (cno_connection_stream_new(conn, 0)) {
                    STOP(CNO_PROPAGATE);
                }

                break;
            }

            case CNO_CONNECTION_HTTP1_READY: {
                // Ignore leading CRLFs.
                const char *ign = conn->buffer.data;
                const char *end = conn->buffer.size + ign;
                while (ign != end && (*ign == '\r' || *ign == '\n')) ++ign;
                cno_io_vector_shift(&conn->buffer, ign - conn->buffer.data);

                if (!conn->buffer.size) {
                    STOP(CNO_OK);
                }

                int ok;
                // Should be exactly one stream right now.
                cno_stream_t *stream = conn->streams;
                struct phr_header headers[100];
                size_t header_num = 100;
                size_t it;

                stream->msg.remaining = 0;

                if (conn->server) {
                    ok = phr_parse_request(conn->buffer.data, conn->buffer.size,
                      (const char **) &stream->msg.method.data,
                                      &stream->msg.method.size,
                      (const char **) &stream->msg.path.data,
                                      &stream->msg.path.size,
                      &stream->msg.minor,
                      headers, &header_num, stream->msg.read);
                } else {
                    ok = phr_parse_response(conn->buffer.data, conn->buffer.size,
                      &stream->msg.minor,
                      &stream->msg.code,
                      &ign, &it,  // the status message is redundant => ignored
                      headers, &header_num, stream->msg.read);
                }

                if (ok == -2) {
                    // Not enough data.
                    stream->msg.read = conn->buffer.size;
                    STOP(CNO_OK);
                }

                if (ok == -1) {
                    // Bad request/response.
                    STOP(CNO_ERROR_BAD_REQ);
                }

                conn->state = CNO_CONNECTION_HTTP1_READING;
                stream->msg.headers_len = header_num;
                stream->msg.headers = malloc(sizeof(cno_header_t) * header_num);
                stream->msg.chunked = 0;

                if (!stream->msg.headers) {
                    STOP(CNO_ERROR_NOMEMORY);
                }

                for (it = 0; it < header_num; ++it) {
                    char * name = (char *) headers[it].name;
                    size_t size = headers[it].name_len;
                    // TODO lowercase

                    if (strncmp(name, "content-length", size) == 0) {
                        if (stream->msg.remaining || stream->msg.chunked) {
                            // Cannot have both length and chunked TE/multiple content-lengths.
                            STOP(CNO_ERROR_BAD_REQ);
                        }

                        stream->msg.remaining = (size_t) atoi(headers[it].value);
                    } else

                    if (strncmp(name, "transfer-encoding", size) == 0) {
                        if (strncmp(headers[it].value, "chunked", headers[it].value_len) != 0) {
                            // Unsupported TE.
                            STOP(CNO_ERROR_BAD_REQ);
                        }

                        if (stream->msg.remaining) {
                            // Cannot have both length and chunked TE.
                            STOP(CNO_ERROR_BAD_REQ);
                        }

                        stream->msg.chunked = 1;
                    }
                }

                memcpy(stream->msg.headers, headers, sizeof(cno_header_t) * header_num);

                CNO_FIRE(conn, on_message_start, stream->id, &stream->msg);
                stream->active = 1;
                cno_io_vector_clear_nofree(&stream->msg.method);
                cno_io_vector_clear_nofree(&stream->msg.path);
                cno_io_vector_shift(&conn->buffer, (size_t) ok);
                continue;
            }

            case CNO_CONNECTION_HTTP1_READING: {
                if (!conn->buffer.size) {
                    STOP(CNO_OK);
                }

                cno_stream_t *stream = conn->streams;
                size_t limit  = stream->msg.remaining;
                char * buffer = conn->buffer.data;

                if (stream->msg.chunked) {
                    char *it  = conn->buffer.data;
                    char *lim = conn->buffer.size + it;
                    char *eol = it; while (eol != lim && *eol != '\n') ++eol;
                    char *end = it; while (end != eol && *end != ';')  ++end;

                    if (eol == lim) {
                        // Wait for a chunk header.
                        STOP(CNO_OK);
                    }

                    limit = 0;

                    size_t chunk_len = (eol - it) + 3;  // + \r\n

                    for (; it != end; ++it) {
                        limit = '0' <= *it && *it <= '9' ? (limit << 4) | (*it - '0') :
                                'A' <= *it && *it <= 'F' ? (limit << 4) | (*it - 'A') :
                                'a' <= *it && *it <= 'f' ? (limit << 4) | (*it - 'a') : limit;
                    }

                    chunk_len += limit;

                    if (conn->buffer.size < chunk_len) {
                        // Wait for a complete chunk, with a line break.
                        STOP(CNO_OK);
                    }

                    buffer = eol + 1;

                    cno_io_vector_shift(&conn->buffer, chunk_len);

                    if (limit == 0) {
                        // That was the last chunk.
                        stream->msg.chunked = 0;
                    }
                } else {
                    if (limit > conn->buffer.size) {
                        limit = conn->buffer.size;
                        stream->msg.remaining -= limit;
                    } else {
                        stream->msg.remaining = 0;
                    }

                    cno_io_vector_shift(&conn->buffer, limit);
                }

                if (limit) {
                    CNO_FIRE(conn, on_message_data, stream->id, buffer, limit);
                }

                if (!stream->msg.remaining && !stream->msg.chunked) {
                    // TODO switch to HTTP 2 if request ended and was an upgrade request
                    conn->state = CNO_CONNECTION_HTTP1_READY;
                    stream->active = 0;
                    CNO_FIRE(conn, on_message_end, stream->id, 0);
                }

                continue;
            }

            case CNO_CONNECTION_INIT: {
                if (conn->buffer.size < CNO_PREFACE.size) {
                    // Wait until preface is available
                    STOP(CNO_OK);
                }

                if (strncmp(conn->buffer.data, CNO_PREFACE.data, CNO_PREFACE.size)) {
                    // Bad request
                    STOP(CNO_ERROR_BAD_REQ);
                }

                conn->state = CNO_CONNECTION_PREFACE;
                cno_io_vector_shift(&conn->buffer, CNO_PREFACE.size);
                break;
            }

            case CNO_CONNECTION_READY:
            case CNO_CONNECTION_PREFACE: {
                if (conn->buffer.size < 9) {
                    // Wait for a frame header.
                    STOP(CNO_OK);
                }

                char *base = conn->buffer.data;
                conn->frame.length = base[0] << 16
                                   | base[1] << 8
                                   | base[2];
                conn->frame.type   = base[3];
                conn->frame.flags  = base[4];
                conn->frame.stream = base[5] << 24
                                   | base[6] << 16
                                   | base[7] << 8
                                   | base[8];
                // TODO if state is CONNECTION_PREFACE, check that this is a SETTINGS frame.

                cno_io_vector_shift(&conn->buffer, 9);
                conn->state = CNO_CONNECTION_READING;
                break;
            }

            case CNO_CONNECTION_READING: {
                if (conn->buffer.size < conn->frame.length) {
                    // Wait for a full frame.
                    STOP(CNO_OK);
                }

                conn->frame.payload = cno_io_vector_slice(&conn->buffer, conn->frame.length);
                conn->state = CNO_CONNECTION_READY;
                CNO_FIRE(conn, on_frame, &conn->frame);
                break;
            }

            default: STOP(CNO_ERROR_GENERIC);
        }
    }

    #undef STOP

done:

    if (cno_io_vector_strip(&conn->buffer)) {
        return CNO_PROPAGATE;
    }

    return retcode;
}
