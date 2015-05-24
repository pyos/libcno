#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <unistd.h>

#include "cno.h"


void log_frame(int fd, cno_frame_t *frame, int recv)
{
    const char *e = recv ? "recv" : "sent";
    fprintf(stdout, "%d: %s frame %x (%s; flags: %x) on stream %lu\n", fd, e,
        frame->type, cno_frame_get_name(frame), frame->flags, frame->stream_id);
}


void log_message(int fd, cno_message_t *msg, int recv)
{
    const char *e = recv ? "recv" : "sent";
    fprintf(stdout, "%d: %s message HTTP/%d.%d %d, method = ", fd, e, msg->major, msg->minor, msg->code);
    fwrite(msg->method.data, msg->method.size, 1, stdout);
    fprintf(stdout, ", path = ");
    fwrite(msg->path.data, msg->path.size, 1, stdout);
    fprintf(stdout, ", headers:\n");

    size_t k = 0;

    for (; k < msg->headers_len; ++k) {
        printf("    (%lu) ", msg->headers[k].name.size);
        fwrite(msg->headers[k].name.data, msg->headers[k].name.size, 1, stdout);
        printf(" = (%lu) ", msg->headers[k].value.size);
        fwrite(msg->headers[k].value.data, msg->headers[k].value.size, 1, stdout);
        printf("\n");
    }
}


int frame_cb(cno_connection_t *conn, int *fd, cno_frame_t *frame)
{
    log_frame(*fd, frame, 1);
    return CNO_OK;
}


int frame_send_cb(cno_connection_t *conn, int *fd, cno_frame_t *frame)
{
    log_frame(*fd, frame, 0);
    return CNO_OK;
}


int write_cb(cno_connection_t *conn, int *fd, const char *data, size_t length)
{
    size_t wrote = 0;

    do {
        wrote += write(*fd, data + wrote, length - wrote);
    } while (wrote < length);

    return CNO_OK;
}


int message_start_cb(cno_connection_t *conn, int *fd, size_t stream, cno_message_t *msg)
{
    log_message(*fd, msg, 1);
    return CNO_OK;
}


int message_end_cb(cno_connection_t *conn, int *fd, size_t stream, int disconnect)
{
    if (disconnect) return CNO_OK;

    cno_message_t message;
    CNO_ZERO(&message);
    message.major = 1;
    message.minor = 1;
    message.code = 200;
    message.headers_len = 3;

    cno_header_t headers[3] = {
        { { "server", 6 }, { "unix-frame-dump-server/1.0", 26 } },
        { { "content-length", 14 }, { "14", 2 } },
        { { "cache-control", 13 }, { "no-cache", 8 } },
    };

    message.headers = headers;

    if (
        cno_write_message(conn, stream, &message)
     || cno_write_data(conn, stream, "Hello, World!\n", 14, 0)
     || cno_write_end(conn, stream, 0)
    ) return CNO_PROPAGATE;

    log_message(*fd, &message, 0);
    return CNO_OK;
}


void *handle(void *sockptr)
{
    int fd = (int) (size_t) sockptr;
    ssize_t read;
    char message[2048];

    cno_connection_t *conn = cno_connection_new(CNO_HTTP2_SERVER);

    if (conn == NULL) {
        goto error;
    }

    conn->cb_data          = &fd;
    conn->on_frame         = &frame_cb;
    conn->on_frame_send    = &frame_send_cb;
    conn->on_write         = &write_cb;
    conn->on_message_start = &message_start_cb;
    conn->on_message_end   = &message_end_cb;
    printf("started %d\n", fd);

    if (cno_connection_made(conn)) {
        goto error;
    }

    while ((read = recv(fd, message, 2048, 0)) > 0) {
        if (cno_connection_data_received(conn, message, read)) {
            goto error;
        }
    }

    if (recv < 0) {
        (void) CNO_ERROR_TRANSPORT("recv() failed");
        goto error;
    }

    if (cno_connection_lost(conn)) {
        goto error;
    }

    cno_connection_destroy(conn);
    close(fd);
    return NULL;

error:
    cno_connection_lost(conn);

    fprintf(stderr, "%d: %s: %s at line %d in %s\n", fd,
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
    int fd   = socket(AF_INET, SOCK_STREAM, 0);
    int conn;

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

        if (pthread_create(&thread, NULL, handle, (void *) (size_t) conn) < 0 || pthread_detach(thread) < 0) {
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
