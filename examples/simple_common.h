#ifndef _SIMPLE_COMMON_H_
#define _SIMPLE_COMMON_H_
#include "cno.h"


void log_frame(int fd, cno_frame_t *frame, int recv)
{
    const char *e = recv ? "recv" : "sent";
    fprintf(stdout, "%d: %s frame %x (%s; length=%lu; flags=%x) on stream %lu\n", fd, e,
        frame->type, CNO_FRAME_NAME[frame->type], frame->payload.size, frame->flags, frame->stream);
}


void log_message(int fd, cno_message_t *msg, int recv)
{
    const char *e = recv ? "recv" : "sent";
    fprintf(stdout, "%d: %s message [code = %d, method = ", fd, e, msg->code);
    fwrite(msg->method.data, msg->method.size, 1, stdout);
    fprintf(stdout, ", path = ");
    fwrite(msg->path.data, msg->path.size, 1, stdout);
    fprintf(stdout, "]\n");

    size_t k = 0;

    for (; k < msg->headers_len; ++k) {
        fprintf(stdout, "    "); fwrite(msg->headers[k].name.data,  msg->headers[k].name.size,  1, stdout);
        fprintf(stdout, ": ");   fwrite(msg->headers[k].value.data, msg->headers[k].value.size, 1, stdout);
        fprintf(stdout, "\n");
    }
}


int log_recv_frame(cno_connection_t *conn, void *fd, cno_frame_t *frame)
{
    log_frame(*(int *) fd, frame, 1);
    return CNO_OK;
}


int log_sent_frame(cno_connection_t *conn, void *fd, cno_frame_t *frame)
{
    log_frame(*(int *) fd, frame, 0);
    return CNO_OK;
}


int write_to_fd(cno_connection_t *conn, void *fd, const char *data, size_t length)
{
    size_t wrote = 0;

    do {
        wrote += write(*(int *) fd, data + wrote, length - wrote);
    } while (wrote < length);

    return CNO_OK;
}


int log_recv_message(cno_connection_t *conn, void *fd, size_t stream, cno_message_t *msg)
{
    log_message(*(int *) fd, msg, 1);
    return CNO_OK;
}


int log_recv_message_data(cno_connection_t *conn, void *fd, size_t stream, const char *data, size_t length)
{
    if (length) {
        fprintf(stdout, "%d: recv data: ", *(int *) fd);
        fwrite(data, length, 1, stdout);

        if (data[length - 1] != '\n') {
            fprintf(stdout, "\n");
        }
    }
    return CNO_OK;
}


int log_recv_message_end(cno_connection_t *conn, void *fd, size_t stream)
{
    fprintf(stdout, "%d: recv end of message; stream %lu closed\n", *(int *) fd, stream);
    return CNO_OK;
}

#endif
