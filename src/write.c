#include "write.h"
#include "error.h"
#include <string.h>
#include <stdio.h>


static const char *cno_response_literal(int status)
{
    switch (status) {
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


static int cno_is_http1(cno_connection_t *conn, size_t id, cno_stream_t **stream)
{
    switch (conn->state) {
        case CNO_CONNECTION_CLOSED:
            return CNO_ERROR_INVALID_STATE("connection already closed");

        case CNO_CONNECTION_INIT:
        case CNO_CONNECTION_INIT_UPGRADE:  // shouldn't have time to call this while in that state
        case CNO_CONNECTION_PREFACE:
        case CNO_CONNECTION_HTTP1_INIT:
            return CNO_ERROR_INVALID_STATE("connection not yet initialized");

        case CNO_CONNECTION_HTTP1_READY:
        case CNO_CONNECTION_HTTP1_READING:
        // HTTP1_READING_UPGRADE is treated as HTTP 2 for writing
            if (id != conn->streams->id) {
                return CNO_ERROR_INVALID_STREAM(id);
            }

            if (stream) {
                *stream = conn->streams;
            }

            return 1;

        default:
            return 0;
    }
}


int cno_write_message(cno_connection_t *conn, size_t stream, cno_message_t *msg)
{
    cno_stream_t *streamobj;

    switch (cno_is_http1(conn, stream, &streamobj)) {
        case -1: return CNO_PROPAGATE;
        case  1: {
            size_t i;
            char head[4096];
            char *tg = head;

            if (conn->server) {
                sprintf(head, "HTTP/1.%d %d %s\r\n", msg->minor, msg->code, cno_response_literal(msg->code));
                tg += strlen(head);
            } else {
                if (msg->method.size + msg->path.size >= 4084) {
                    return CNO_ERROR_TRANSPORT("path too long (>= 4096 total)");
                }

                memcpy(tg, msg->method.data, msg->method.size); tg += msg->method.size; *tg++ = ' ';
                memcpy(tg, msg->path.data,   msg->path.size);   tg += msg->path.size;
                sprintf(tg, " HTTP/1.%d\r\n", msg->minor);
                tg += strlen(tg);
            }

            for (i = 0; i < msg->headers_len; ++i) {
                CNO_FIRE(conn, on_write, head, tg - head);
                cno_io_vector_t *name  = &msg->headers[i].name;
                cno_io_vector_t *value = &msg->headers[i].value;

                if (name->size + value->size >= 4090) {
                    return CNO_ERROR_TRANSPORT("header too long (>= 4096 total)");
                }

                tg = head;
                memcpy(tg, name->data,  name->size);  tg += name->size;  *tg++ = ':';  *tg++ = ' ';
                memcpy(tg, value->data, value->size); tg += value->size; *tg++ = '\r'; *tg++ = '\n';
            }

            *tg++ = '\r';
            *tg++ = '\n';
            CNO_FIRE(conn, on_write, head, tg - head);
            return 0;
        }
    }

    return CNO_ERROR_NOT_IMPLEMENTED("HTTP 2 protocol");
}


int cno_write_data(cno_connection_t *conn, size_t stream, const char *data, size_t length, int chunked)
{
    cno_stream_t *streamobj;

    switch (cno_is_http1(conn, stream, &streamobj)) {
        case -1: return CNO_PROPAGATE;
        case  1: {
            if (!length) {
                // Nothing to do.
            } else if (chunked) {
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

                CNO_FIRE(conn, on_write, it, sizeof(size_t) + 2 - (it - encd));
                CNO_FIRE(conn, on_write, data, length);
                CNO_FIRE(conn, on_write, "\r\n", 2);
            } else {
                CNO_FIRE(conn, on_write, data, length);
            }
            return 0;
        }
    }

    return CNO_ERROR_NOT_IMPLEMENTED("HTTP 2 protocol");
}


int cno_write_end(cno_connection_t *conn, size_t stream, int chunked)
{
    cno_stream_t *streamobj;

    switch (cno_is_http1(conn, stream, &streamobj)) {
        case -1: return CNO_PROPAGATE;
        case  1: {
            if (chunked) {
                CNO_FIRE(conn, on_write, "0\r\n\r\n", 5);
            }

            return 0;
        }
    }

    return CNO_ERROR_NOT_IMPLEMENTED("HTTP 2 protocol");
}
