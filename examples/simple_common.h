#ifndef _SIMPLE_COMMON_H_
#define _SIMPLE_COMMON_H_
#include <cno/core.h>


static const char *CNO_FRAME_NAME[256] = {
    "DATA",         "HEADERS", "PRIORITY", "RST_STREAM",    "SETTINGS",
    "PUSH_PROMISE", "PING",    "GOAWAY",   "WINDOW_UPDATE", "CONTINUATION",
};


struct cbdata_t
{
    int fd;
    struct cno_connection_t conn;
};


void log_frame(int fd, const struct cno_frame_t *frame, int recv)
{
    const char *e = recv ? "recv" : "sent";
    fprintf(stdout, "%d: %s frame %x (%s; length=%zu; flags=%x) on stream %u\n", fd, e,
        frame->type, CNO_FRAME_NAME[frame->type], frame->payload.size, frame->flags, frame->stream);
}


void log_message(int fd, const struct cno_message_t *msg, int recv)
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


int log_recv_frame(void *data, const struct cno_frame_t *frame)
{
    log_frame(((struct cbdata_t *) data)->fd, frame, 1);
    return CNO_OK;
}


int log_sent_frame(void *data, const struct cno_frame_t *frame)
{
    log_frame(((struct cbdata_t *) data)->fd, frame, 0);
    return CNO_OK;
}


int write_to_fd(void *data, const char *buf, size_t length)
{
    size_t wrote = 0;
    int fd = ((struct cbdata_t *) data)->fd;

    do
        wrote += write(fd, buf + wrote, length - wrote);
    while (wrote < length);

    return CNO_OK;
}


int log_sent_message(void *data, size_t stream, const struct cno_message_t *msg)
{
    log_message(((struct cbdata_t *) data)->fd, msg, 0);
    return CNO_OK;
}


int log_recv_message(void *data, size_t stream, const struct cno_message_t *msg)
{
    log_message(((struct cbdata_t *) data)->fd, msg, 1);
    return CNO_OK;
}


int log_recv_message_data(void *data, size_t stream, const char *buf, size_t length)
{
    if (length) {
        fprintf(stdout, "%d: recv data: ", ((struct cbdata_t *) data)->fd);
        fwrite(buf, length, 1, stdout);

        if (buf[length - 1] != '\n')
            fprintf(stdout, "\n");
    }
    return CNO_OK;
}


int log_recv_message_end(void *data, size_t stream)
{
    fprintf(stdout, "%d: recv end of message; stream %zu closed\n", ((struct cbdata_t *) data)->fd, stream);
    return CNO_OK;
}


void print_traceback(void)
{
    const struct cno_error_t *e = cno_error();
    const struct cno_traceback_t *it;

    fprintf(stderr, "[errno %d] %s\n", e->code, e->text);

    for (it = e->traceback; it != e->traceback_end; it++)
        fprintf(stderr, "  | line %d @ %s [%s]\n", it->line, it->file, it->func);
}

#endif
