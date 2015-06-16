#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "cno.h"
#include "simple_common.h"


static int pass(cno_connection_t *conn, void *other, const char *data, size_t length)
{
    return cno_connection_data_received(other, data, length);
}


static int respond(cno_connection_t *conn, void *_, size_t stream)
{
    cno_header_t headers[3] = {
        // io vector = { char *, size_t }
        { CNO_IO_VECTOR_CONST("server"),         CNO_IO_VECTOR_CONST("echo-chamber/1.0") },
        { CNO_IO_VECTOR_CONST("content-length"), CNO_IO_VECTOR_CONST("14") },
        { CNO_IO_VECTOR_CONST("cache-control"),  CNO_IO_VECTOR_CONST("no-cache") },
    };

    cno_message_t message = { 200, CNO_IO_VECTOR_EMPTY, CNO_IO_VECTOR_EMPTY, headers, 3 };

    return cno_write_message(conn, stream, &message, 0)
        || cno_write_data(conn, stream, "Hello, World!\n", 14, 1);
}


int main(int argc, char *argv[])
{
    cno_connection_t *client = cno_connection_new(CNO_HTTP2_CLIENT);
    cno_connection_t *server = cno_connection_new(CNO_HTTP2_SERVER);

    if (client == NULL || server == NULL) {
        goto error;
    }

    client->cb_data          = server;
    client->on_write         = &pass;
    client->on_message_start = &log_recv_message;
    client->on_message_data  = &log_recv_message_data;
    client->on_message_end   = &log_recv_message_end;
    client->on_frame         = &log_recv_frame;
    client->on_frame_send    = &log_sent_frame;

    server->cb_data          = client;
    server->on_write         = &pass;
    server->on_message_end   = &respond;

    cno_header_t headers[1] = {
        { CNO_IO_VECTOR_CONST(":authority"), CNO_IO_VECTOR_CONST("localhost") },
    };

    cno_message_t message = { 0, CNO_IO_VECTOR_CONST("GET"), CNO_IO_VECTOR_CONST("/"), headers, 1};

    if (cno_connection_made(client)
     || cno_connection_made(server)
     || cno_write_message(client, cno_stream_next_id(client), &message, 1)
     || cno_connection_stop(client)
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
