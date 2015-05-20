#ifndef _CNO_CORE_H_
#define _CNO_CORE_H_
#include <stddef.h>
#include "iovec.h"

#define CNO_STRUCT_EXPORT(name) typedef struct cno_st_ ## name ## _t cno_ ## name ## _t
#define CNO_PAYLOAD_UNLIMITED ((size_t) -1)
#define CNO_PAYLOAD_CHUNKED   ((size_t) -2)
#define CNO_FIRE(ob, cb, ...) do if (ob->cb) ((cno_cb_ ## cb ## _t) ob->cb)(ob, ob->cb_data, ## __VA_ARGS__); while (0)


enum CNO_CONNECTION_STATE {
    CNO_CONNECTION_CLOSED,
    CNO_CONNECTION_INIT,
    CNO_CONNECTION_PREFACE,
    CNO_CONNECTION_READY,
    CNO_CONNECTION_READING,
    CNO_CONNECTION_HTTP1_INIT,
    CNO_CONNECTION_HTTP1_READY,
    CNO_CONNECTION_HTTP1_READING,
};


struct cno_st_frame_t {
    size_t length;
    size_t stream;
    char type;
    char flags;
    char * payload;
};


struct cno_st_header_t {
    struct cno_st_io_vector_t name;
    struct cno_st_io_vector_t value;
};


struct cno_st_message_t {
    int major;
    int minor;
    int code;
    size_t read;
    size_t remaining;
    size_t headers_len;
    struct cno_st_io_vector_t method;
    struct cno_st_io_vector_t path;
    struct cno_st_header_t *headers;
};


//struct cno_st_stream_t;
struct cno_st_stream_t {
    int open;
    int active;
    size_t id;
    struct cno_st_message_t msg;
    struct cno_st_stream_t *next;
};


struct cno_st_connection_t {
    int state;
    int closed;
    int server;
    struct cno_st_io_vector_tmp_t buffer;
    struct cno_st_frame_t frame;
    struct cno_st_stream_t *streams;
    void * cb_data;
    void * on_error;
    void * on_close;
    void * on_frame;
    void * on_write;
    void * on_stream_start;
    void * on_stream_end;
    void * on_message_start;
    void * on_message_data;
    void * on_message_end;
};


CNO_STRUCT_EXPORT(io_vector);
CNO_STRUCT_EXPORT(connection);
CNO_STRUCT_EXPORT(frame);
CNO_STRUCT_EXPORT(stream);
CNO_STRUCT_EXPORT(header);
CNO_STRUCT_EXPORT(message);


typedef void (* cno_cb_on_error_t)         (cno_connection_t *, void *, int, char *, char *, int, void *);
typedef void (* cno_cb_on_close_t)         (cno_connection_t *, void *);
typedef void (* cno_cb_on_frame_t)         (cno_connection_t *, void *, cno_frame_t *);
typedef void (* cno_cb_on_write_t)         (cno_connection_t *, void *, const char *, size_t);
typedef void (* cno_cb_on_stream_start_t)  (cno_connection_t *, void *, size_t);
typedef void (* cno_cb_on_stream_end_t)    (cno_connection_t *, void *, size_t);
typedef void (* cno_cb_on_message_start_t) (cno_connection_t *, void *, size_t, cno_message_t *);
typedef void (* cno_cb_on_message_data_t)  (cno_connection_t *, void *, size_t, const char *, size_t);
typedef void (* cno_cb_on_message_end_t)   (cno_connection_t *, void *, size_t, int disconnect);


static const struct cno_st_io_vector_t CNO_PREFACE = {
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24
};


cno_connection_t * cno_connection_new           (int server, int upgrade);
void               cno_connection_destroy       (cno_connection_t *conn);
int                cno_connection_data_received (cno_connection_t *conn, const char *data, size_t length);
int                cno_connection_lost          (cno_connection_t *conn);
int                cno_connection_fire          (cno_connection_t *conn);


#endif
