/* An HTTP 2 request-response loop: it sets up a client and a server and connects
 * them to each other without using sockets.
 *
 * Usage:
 *
 *     ./data_loop
 *
 * (The output log is from the point of view of the client.)
 *
 */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "examples/simple_common.h"


struct conn_pair_t
{
    int pad;
    struct cno_connection_t  a;
    struct cno_connection_t *b;
};


static int pass(void *data, const char *buf, size_t length)
{
    return cno_connection_data_received(((struct conn_pair_t *) data)->b, buf, length);
}


static int respond(void *data, size_t stream)
{
    struct cno_header_t headers[3] = {
        { CNO_BUFFER_CONST("server"),         CNO_BUFFER_CONST("echo-chamber/1.0") },
        { CNO_BUFFER_CONST("content-length"), CNO_BUFFER_CONST("14") },
        { CNO_BUFFER_CONST("cache-control"),  CNO_BUFFER_CONST("no-cache") },
    };

    struct cno_message_t message = { 200, CNO_BUFFER_EMPTY, CNO_BUFFER_EMPTY, headers, 3 };
    struct cno_connection_t *conn = &((struct conn_pair_t *) data)->a;

    return cno_write_message(conn, stream, &message, 0)
        || cno_write_data(conn, stream, "Hello, World!\n", 14, 1) < 0;
}


int main(int argc, char *argv[])
{
    struct conn_pair_t server;
    struct conn_pair_t client;
    cno_connection_init(&server.a, CNO_SERVER);
    cno_connection_init(&client.a, CNO_CLIENT);
    server.pad = client.pad = 0;
    server.b = &client.a;
    client.b = &server.a;

    server.a.cb_data          = &server;
    server.a.on_write         = &pass;
    server.a.on_message_end   = &respond;

    client.a.cb_data          = &client;
    client.a.on_write         = &pass;
    client.a.on_message_start = &log_recv_message;
    client.a.on_message_data  = &log_recv_message_data;
    client.a.on_message_end   = &log_recv_message_end;
    client.a.on_frame         = &log_recv_frame;
    client.a.on_frame_send    = &log_sent_frame;

    struct cno_header_t headers[1] = {
        { CNO_BUFFER_CONST(":authority"), CNO_BUFFER_CONST("localhost") },
    };

    struct cno_message_t message = { 0, CNO_BUFFER_CONST("GET"), CNO_BUFFER_CONST("/"), headers, 1};

    if (cno_connection_made(&client.a, CNO_HTTP2)
     || cno_connection_made(&server.a, CNO_HTTP2)
     || cno_write_message(&client.a, cno_stream_next_id(&client.a), &message, 1)
     || cno_connection_stop(&client.a)
     || cno_connection_lost(&client.a)
     || cno_connection_lost(&server.a))
            goto error;

    cno_connection_reset(&client.a);
    cno_connection_reset(&server.a);
    return 0;

error:
    print_traceback();
    cno_connection_reset(&client.a);
    cno_connection_reset(&server.a);
    return 1;
}
