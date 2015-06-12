#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <unistd.h>

#include "cno.h"
// See this file for callbacks:
#include "simple_common.h"


static const int ONE = 1;  // Heh. See `setsockopt` below.


static int respond_with_hello_world(cno_connection_t *conn, void *fd, size_t stream, int disconnect)
{
    log_recv_message_end(conn, fd, stream, disconnect);

    if (disconnect) return CNO_OK;

    cno_header_t headers[3] = {
        // io vector = { char *, size_t }
        { CNO_IO_VECTOR_CONST("server"),         CNO_IO_VECTOR_CONST("hello-world/1.0") },
        { CNO_IO_VECTOR_CONST("content-length"), CNO_IO_VECTOR_CONST("14") },
        { CNO_IO_VECTOR_CONST("cache-control"),  CNO_IO_VECTOR_CONST("no-cache") },
    };

    cno_message_t message = { 200, CNO_IO_VECTOR_EMPTY, CNO_IO_VECTOR_EMPTY, headers, 3 };

    if (cno_write_message(conn, stream, &message, 0)
     || cno_write_data(conn, stream, "Hello, World!\n", 14, 1)) {
        // CNO_ERRNO_WOULD_BLOCK in cno_write_data can be handled by waiting for
        // a flow control update and retrying, but we don't have an event loop so we'll abort.
        return CNO_PROPAGATE;
    }

    log_message(*(int *) fd, &message, 0);
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

    cno_connection_t *conn = cno_connection_new(CNO_HTTP2_SERVER);

    if (conn == NULL) {
        goto error;
    }

    cno_settings_t settings;
    cno_settings_copy(conn, &settings);
    settings.enable_push = 0;
    settings.max_concurrent_streams = 1024;
    cno_settings_apply(conn, &settings);

    conn->cb_data          = &fd;
    conn->on_write         = &write_to_fd;
    conn->on_frame         = &log_recv_frame;
    conn->on_frame_send    = &log_sent_frame;
    conn->on_message_start = &log_recv_message;
    conn->on_message_data  = &log_recv_message_data;
    conn->on_message_end   = &respond_with_hello_world;

    if (cno_connection_made(conn)) {
        goto error;
    }

    while ((read = recv(fd, message, 8192, 0)) > 0) {
        if (cno_connection_data_received(conn, message, read)) {
            goto error;
        }
    }

    if (cno_connection_lost(conn)) {
        goto error;
    }

    cno_connection_destroy(conn);
    close(fd);
    return NULL;

error:
    cno_connection_lost(conn);

    fprintf(stderr, "%lu: %s: %s at line %d in %s\n", fd,
        cno_error_name(), cno_error_text(),
        cno_error_line(), cno_error_file());

    close(fd);
    cno_connection_destroy(conn);
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
