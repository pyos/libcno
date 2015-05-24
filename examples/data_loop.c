/*
 *  A simple client-server pair that is connected without actually using sockets.
 *  The client makes some requests, the server responds with a "Hello, World!",
 *  the client logs that.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "cno.h"


int write_cb(cno_connection_t *conn, cno_connection_t *other, const char *data, size_t length)
{
    return cno_connection_data_received(other, data, length);
}


int on_message_start(cno_connection_t *conn, cno_connection_t *other, size_t stream, cno_message_t *msg)
{
    printf("recv message: HTTP/%d.%d %d\n", msg->major, msg->minor, msg->code);
    return CNO_OK;
}


int on_message_data(cno_connection_t *conn, cno_connection_t *other, size_t stream, const char *data, size_t length)
{
    if (length) {
        printf("recv data: ");
        fwrite(data, length, 1, stdout);
        printf("\n");
    }
    return CNO_OK;
}


int on_message_end(cno_connection_t *conn, cno_connection_t *other, size_t stream)
{
    printf("recv message end\n");
    return CNO_OK;
}


int respond(cno_connection_t *conn, cno_connection_t *other, size_t stream, int disconnect)
{
    if (disconnect) return CNO_OK;

    cno_message_t message;
    CNO_ZERO(&message);
    message.code = 200;
    message.headers_len = 3;

    cno_header_t headers[3] = {
        { { "server", 6 }, { "echo-chamber/1.0", 16 } },
        { { "content-length", 14 }, { "14", 2 } },
        { { "cache-control", 13 }, { "no-cache", 8 } },
    };

    message.headers = headers;

    if (
        cno_write_message(conn, stream, &message)
     || cno_write_data(conn, stream, "Hello, World!\n", 14, 0)
     || cno_write_end(conn, stream, 0)
    ) return CNO_PROPAGATE;

    return CNO_OK;
}


int main(int argc, char *argv[])
{
    cno_connection_t *client = cno_connection_new(CNO_HTTP2_CLIENT);
    cno_connection_t *server = cno_connection_new(CNO_HTTP2_SERVER);

    if (client == NULL || server == NULL) {
        goto error;
    }

    client->cb_data          = server;
    client->on_write         = &write_cb;
    client->on_message_start = &on_message_start;
    client->on_message_data  = &on_message_data;
    client->on_message_end   = &on_message_end;

    server->cb_data          = client;
    server->on_write         = &write_cb;
    server->on_message_end   = &respond;

    cno_message_t message;
    CNO_ZERO(&message);
    message.path.data = "/";
    message.path.size = 1;
    message.method.data = "GET";
    message.method.size = 3;
    message.headers_len = 1;

    cno_header_t headers[1] = {
        { { "host", 4 }, { "localhost", 9 } },
    };

    message.headers = headers;

    if (
        cno_connection_made(client)
     || cno_connection_made(server)
     || cno_write_message(client, 1, &message)
     || cno_write_data(client, 1, "Hello, World!\n", 14, 0)
     || cno_write_end(client, 1, 0)
     || cno_connection_lost(client)
     || cno_connection_lost(server)
    ) goto error;

    cno_connection_destroy(client);
    cno_connection_destroy(server);
    return 0;

error:
    fprintf(stderr, "%s: %s at line %d in %s\n",
        cno_error_name(), cno_error_text(),
        cno_error_line(), cno_error_file());

    if (client) cno_connection_destroy(client);
    if (server) cno_connection_destroy(server);
    return 1;
}
