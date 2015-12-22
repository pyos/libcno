/* A basic POSIX multithreaded plaintext server.
 *
 * Usage:
 *
 *     ./server 8000
 *
 * (Serves both HTTP/1.x and h2c, aka plain-text HTTP 2. Clients can upgrade to HTTP 2
 *  either through prior knowledge or an HTTP/1.x `Upgrade: h2c` request. Try pointing
 *  the client [simple_client.c] to http://127.0.0.1:8000/. Also, if you have nghttp2
 *  or nghttp2-enabled curl, try using these, too.)
 *
 */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// See this file for callbacks:
#include "examples/simple_common.h"


static const int ONE = 1;  // Heh. See `setsockopt` below.


static int respond_with_hello_world(void *data, size_t stream)
{
    log_recv_message_end(data, stream);

    struct cno_connection_t *conn = &((struct cbdata_t *) data)->conn;
    struct cno_header_t headers[3] = {
        { CNO_BUFFER_CONST("server"),         CNO_BUFFER_CONST("hello-world/1.0") },
        { CNO_BUFFER_CONST("content-length"), CNO_BUFFER_CONST("14") },
        { CNO_BUFFER_CONST("cache-control"),  CNO_BUFFER_CONST("no-cache") },
    };

    struct cno_message_t message = { 200, CNO_BUFFER_EMPTY, CNO_BUFFER_EMPTY, headers, 3 };

    if (cno_write_message(conn, stream, &message, 0)
    ||  cno_write_data(conn, stream, "Hello, World!\n", 14, 1) < 0)
        // cno_write_data may return less than 14, in which case we should
        // wait for on_flow_increase and resend the rest of the data. but that's hard.
        return CNO_ERROR_UP();

    log_sent_message(data, stream, &message);
    return CNO_OK;
}


static void *handle(fd) ssize_t fd;
{
    ssize_t read;
    char message[8192];

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &ONE, sizeof(ONE)) < 0) {
        fprintf(stderr, "error: could not set TCP_NODELAY");
        return NULL;
    }

    struct cbdata_t data;
    struct cno_connection_t *conn = &data.conn;
    cno_connection_init(conn, CNO_SERVER);
    data.fd = fd;

    struct cno_settings_t settings;
    cno_settings_copy(conn, &settings);
    settings.enable_push = 0;
    settings.max_concurrent_streams = 1024;
    cno_settings_apply(conn, &settings);

    conn->cb_data          = &data;
    conn->on_write         = &write_to_fd;
    conn->on_frame         = &log_recv_frame;
    conn->on_frame_send    = &log_sent_frame;
    conn->on_message_start = &log_recv_message;
    conn->on_message_data  = &log_recv_message_data;
    conn->on_message_end   = &respond_with_hello_world;

    if (cno_connection_made(conn, CNO_HTTP1))
        goto error;

    while ((read = recv(fd, message, 8192, 0)) > 0)
        if (cno_connection_data_received(conn, message, read))
            goto error;

    if (cno_connection_lost(conn))
        goto error;

    cno_connection_reset(conn);
    close(fd);
    return NULL;

error:
    close(fd);
    print_traceback();
    cno_connection_lost(conn);
    cno_connection_reset(conn);
    return NULL;
}


int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return 2;
    }

    int port = atoi(argv[1]);
    ssize_t fd   = socket(AF_INET, SOCK_STREAM, 0);
    ssize_t conn;

    if (fd == -1) {
        fprintf(stderr, "error: could not create server socket\n");
        return 1;
    }

    struct sockaddr_in addr;
    struct sockaddr_in accepted;
    socklen_t structsz = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *) &addr, structsz) < 0) {
        fprintf(stderr, "error: could not bind on port %d\n", port);
        return 1;
    }

    listen(fd, 128);

    while (( conn = accept(fd, (struct sockaddr *) &accepted, &structsz) ) > 0) {
        pthread_t thread;

        if (pthread_create(&thread, NULL, handle, (void *) conn) < 0 || pthread_detach(thread) < 0) {
            fprintf(stderr, "error: failed to create thread\n");
            return 1;
        }
    }

    if (conn < 0) {
        fprintf(stderr, "error: accept failed\n");
        return 1;
    }

    close(fd);
    return 0;
}
