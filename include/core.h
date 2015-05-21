#ifndef _CNO_CORE_H_
#define _CNO_CORE_H_
#include <stddef.h>
#include <string.h>
#include "iovec.h"
#include "list.h"

#define CNO_STRUCT_EXPORT(name) typedef struct cno_st_ ## name ## _t cno_ ## name ## _t
#define CNO_DEF_CALLBACK(ob, cb, ...) typedef int (* cno_cb_ ## cb ## _t)(ob *, void *, ## __VA_ARGS__)
#define CNO_FIRE(ob, cb, ...) (ob->cb && ((cno_cb_ ## cb ## _t) ob->cb)(ob, ob->cb_data, ## __VA_ARGS__))
#define CNO_ZERO(ob) memset(ob, 0, sizeof(*ob))


enum CNO_CONNECTION_KIND {
    CNO_HTTP2_SERVER = 0,
    CNO_HTTP2_CLIENT = 1,
    CNO_HTTP1_CLIENT = 2,
};


enum CNO_CONNECTION_STATE {
    CNO_CONNECTION_CLOSED,
    CNO_CONNECTION_INIT,
    CNO_CONNECTION_INIT_UPGRADE,  // same as INIT, but does not emit `on_ready`.
    CNO_CONNECTION_PREFACE,
    CNO_CONNECTION_READY,
    CNO_CONNECTION_READING,
    CNO_CONNECTION_HTTP1_INIT,
    CNO_CONNECTION_HTTP1_READY,
    CNO_CONNECTION_HTTP1_READING,
    CNO_CONNECTION_HTTP1_READING_UPGRADE,  // reading HTTP/1.x request, writing HTTP 2 responses
};


enum CNO_STREAM_STATE {
    CNO_STREAM_IDLE,  // initial state
    CNO_STREAM_OPEN,  // recv HEADERS / sent HEADERS
    CNO_STREAM_CLOSED_LOCAL,  // sent END_STREAM
    CNO_STREAM_CLOSED_REMOTE, // recv END_STREAM
    CNO_STREAM_RESERVED_LOCAL,  // sent PUSH_PROMISE
    CNO_STREAM_RESERVED_REMOTE, // recv PUSH_PROMISE
    CNO_STREAM_CLOSED,  // recv RST_STREAM / sent RST_STREAM / both END_STREAM
};


enum CNO_FRAME_TYPE {
    CNO_FRAME_DATA,
    CNO_FRAME_HEADERS,
    CNO_FRAME_PRIORITY,
    CNO_FRAME_RST_STREAM,
    CNO_FRAME_SETTINGS,
    CNO_FRAME_PUSH_PROMISE,
    CNO_FRAME_PING,
    CNO_FRAME_GOAWAY,
    CNO_FRAME_WINDOW_UPDATE,
    CNO_FRAME_CONTINUATION,
};


enum CNO_STATE_CODE {
    CNO_STATE_NO_ERROR,
    CNO_STATE_PROTOCOL_ERROR,
    CNO_STATE_INTERNAL_ERROR,
    CNO_STATE_FLOW_CONTROL_ERROR,
    CNO_STATE_SETTINGS_TIMEOUT,
    CNO_STATE_STREAM_CLOSED,
    CNO_STATE_FRAME_SIZE_ERROR,
    CNO_STATE_REFUSED_STREAM,
    CNO_STATE_CANCEL,
    CNO_STATE_COMPRESSION_ERROR,
    CNO_STATE_CONNECT_ERROR,
    CNO_STATE_ENHANCE_YOUR_CALM,
    CNO_STATE_INADEQUATE_SECURITY,
    CNO_STATE_HTTP_1_1_REQUIRED,
};


enum CNO_FRAME_FLAGS {
    CNO_FLAG_ACK         = 0x1,
    CNO_FLAG_END_STREAM  = 0x1,
    CNO_FLAG_END_HEADERS = 0x4,
    CNO_FLAG_PADDED      = 0x8,
    CNO_FLAG_PRIORITY    = 0x20,
};


enum CNO_CONNECTION_SETTINGS {
    CNO_SETTINGS_HEADER_TABLE_SIZE      = 0x1,
    CNO_SETTINGS_ENABLE_PUSH            = 0x2,
    CNO_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
    CNO_SETTINGS_INITIAL_WINDOW_SIZE    = 0x4,
    CNO_SETTINGS_MAX_FRAME_SIZE         = 0x5,
    CNO_SETTINGS_MAX_HEADER_LIST_SIZE   = 0x6,
};


struct cno_st_frame_t {
    enum CNO_FRAME_TYPE  type;
    enum CNO_FRAME_FLAGS flags;
    size_t stream;
    struct cno_st_io_vector_t payload;
};


static inline const char *cno_frame_get_name(struct cno_st_frame_t *frame)
{
    switch (frame->type) {
        case CNO_FRAME_DATA:          return "DATA";
        case CNO_FRAME_HEADERS:       return "HEADERS";
        case CNO_FRAME_PRIORITY:      return "PRIORITY";
        case CNO_FRAME_RST_STREAM:    return "RST_STREAM";
        case CNO_FRAME_SETTINGS:      return "SETTINGS";
        case CNO_FRAME_PUSH_PROMISE:  return "PUSH_PROMISE";
        case CNO_FRAME_PING:          return "PING";
        case CNO_FRAME_GOAWAY:        return "GOAWAY";
        case CNO_FRAME_WINDOW_UPDATE: return "WINDOW_UPDATE";
        case CNO_FRAME_CONTINUATION:  return "CONTINUATION";
        default: return "UNKNOWN";
    }
};


struct cno_st_header_t {
    struct cno_st_io_vector_t name;
    struct cno_st_io_vector_t value;
};


struct cno_st_message_t {
    int major;
    int minor;
    int code;
    int chunked;
    struct cno_st_io_vector_t method;
    struct cno_st_io_vector_t path;
    size_t headers_len;
    struct cno_st_header_t *headers;
    size_t remaining;
};


struct cno_st_stream_t {
    CNO_LIST_LINK(struct cno_st_stream_t);
    size_t id;
    size_t window;
    enum CNO_STREAM_STATE state;
    struct cno_st_message_t msg;
};


struct cno_st_settings_t {
    size_t header_table_size;
    size_t enable_push;
    size_t max_concurrent_streams;
    size_t initial_window_size;
    size_t max_frame_size;
    size_t max_header_list_size;
};


struct cno_st_connection_t {
    struct { CNO_LIST_ROOT(struct cno_st_stream_t); } streams;
    union { int kind; int client; };
    enum CNO_CONNECTION_STATE state;
    int closed;
    size_t window;
    struct cno_st_io_vector_tmp_t buffer;
    struct cno_st_frame_t frame;
    struct cno_st_settings_t settings;
    void * cb_data;
    void * on_ready;
    void * on_close;
    void * on_frame;
    void * on_frame_send;
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


CNO_DEF_CALLBACK(cno_connection_t, on_ready);
CNO_DEF_CALLBACK(cno_connection_t, on_close);
CNO_DEF_CALLBACK(cno_connection_t, on_frame, cno_frame_t *);
CNO_DEF_CALLBACK(cno_connection_t, on_frame_send, cno_frame_t *);
CNO_DEF_CALLBACK(cno_connection_t, on_write, const char *, size_t);
CNO_DEF_CALLBACK(cno_connection_t, on_stream_start,  size_t);
CNO_DEF_CALLBACK(cno_connection_t, on_stream_end,    size_t);
CNO_DEF_CALLBACK(cno_connection_t, on_message_start, size_t, cno_message_t *);
CNO_DEF_CALLBACK(cno_connection_t, on_message_data,  size_t, const char *, size_t);
CNO_DEF_CALLBACK(cno_connection_t, on_message_end,   size_t, int disconnect);


static const struct cno_st_io_vector_t CNO_PREFACE = { "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24 };


cno_connection_t * cno_connection_new           (enum CNO_CONNECTION_KIND kind);
int                cno_connection_destroy       (cno_connection_t *conn);
int                cno_connection_made          (cno_connection_t *conn);
int                cno_connection_data_received (cno_connection_t *conn, const char *data, size_t length);
int                cno_connection_fire          (cno_connection_t *conn);
int                cno_connection_lost          (cno_connection_t *conn);

#endif
