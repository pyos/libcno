#ifndef _CNO_CORE_H_
#define _CNO_CORE_H_
#include <stddef.h>
#include <string.h>

#include "cno-common.h"
#include "cno-hpack.h"


#ifndef CNO_MAX_HTTP1_HEADER_SIZE
/* Max. length of a header, i.e. length of the name + length of the value + 4 bytes
 * (the ": " separator and the CRLF.) If a header longer than this is passed
 * to `cno_write_message`, it will return an assertion error.
 */
#define CNO_MAX_HTTP1_HEADER_SIZE 4096
#endif


#ifndef CNO_MAX_HEADERS
/* Max. number of entries in the header table of inbound messages. Applies to both HTTP 1
 * and HTTP 2. Since there's no way to know in advance how many headers a message has,
 * this option limits the stack space consumed. Does not affect outbound messages.
 */
#define CNO_MAX_HEADERS 128
#endif


enum CNO_PEER_KIND {
    CNO_PEER_REMOTE = 0,
    CNO_PEER_LOCAL  = 1,
    CNO_PEER_UNDEF  = 2,  // http 1 mode
};


enum CNO_CONNECTION_KIND {
    CNO_HTTP2_SERVER = 0,
    CNO_HTTP2_CLIENT = 1,
    CNO_HTTP1_CLIENT = 2,
};


enum CNO_CONNECTION_STATE {
    CNO_CONNECTION_INIT,
    CNO_CONNECTION_PREFACE,
    CNO_CONNECTION_READY,
    CNO_CONNECTION_READY_NO_SETTINGS,
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
    CNO_FRAME_DATA          = 0x0,
    CNO_FRAME_HEADERS       = 0x1,
    CNO_FRAME_PRIORITY      = 0x2,
    CNO_FRAME_RST_STREAM    = 0x3,
    CNO_FRAME_SETTINGS      = 0x4,
    CNO_FRAME_PUSH_PROMISE  = 0x5,
    CNO_FRAME_PING          = 0x6,
    CNO_FRAME_GOAWAY        = 0x7,
    CNO_FRAME_WINDOW_UPDATE = 0x8,
    CNO_FRAME_CONTINUATION  = 0x9,
};


enum CNO_STATE_CODE {
    CNO_STATE_NO_ERROR            = 0x0,
    CNO_STATE_PROTOCOL_ERROR      = 0x1,
    CNO_STATE_INTERNAL_ERROR      = 0x2,
    CNO_STATE_FLOW_CONTROL_ERROR  = 0x3,
    CNO_STATE_SETTINGS_TIMEOUT    = 0x4,
    CNO_STATE_STREAM_CLOSED       = 0x5,
    CNO_STATE_FRAME_SIZE_ERROR    = 0x6,
    CNO_STATE_REFUSED_STREAM      = 0x7,
    CNO_STATE_CANCEL              = 0x8,
    CNO_STATE_COMPRESSION_ERROR   = 0x9,
    CNO_STATE_CONNECT_ERROR       = 0xa,
    CNO_STATE_ENHANCE_YOUR_CALM   = 0xb,
    CNO_STATE_INADEQUATE_SECURITY = 0xc,
    CNO_STATE_HTTP_1_1_REQUIRED   = 0xd,
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
    CNO_SETTINGS_UNDEFINED              = 0x7,
};


struct cno_st_frame_t {
    enum CNO_FRAME_TYPE  type;
    enum CNO_FRAME_FLAGS flags;
    size_t stream;
    struct cno_st_io_vector_t payload;
};


struct cno_st_message_t {
    int code;
    struct cno_st_io_vector_t method;
    struct cno_st_io_vector_t path;
    struct cno_st_header_t *headers;
    size_t headers_len;
};


struct cno_st_stream_t {
    CNO_SET_VALUE;
    size_t id;
    size_t window_recv;
    size_t window_send;
    size_t last_promise;
    enum CNO_FRAME_TYPE last_frame;  // can be set to HEADERS/PUSH_PROMISE, used for CONTINUATION
    enum CNO_STREAM_STATE state;
    struct cno_st_message_t msg;
    struct cno_st_io_vector_t cache;  // frames that can have CONTINUATIONs are buffered here
};


struct cno_st_settings_t {
    union {  // TODO find a better way to implement this to avoid alignment bullshit
        struct {
            size_t header_table_size;
            size_t enable_push;
            size_t max_concurrent_streams;
            size_t initial_window_size;
            size_t max_frame_size;
            size_t max_header_list_size;
        };
        size_t array[CNO_SETTINGS_UNDEFINED - 1];
    };
};


struct cno_st_connection_t {
    union {
        enum CNO_CONNECTION_KIND kind;
        enum CNO_PEER_KIND client;  // == CNO_PEER_LOCAL iff we are the client
    };
    enum CNO_CONNECTION_STATE state;
    int closed;
    size_t window_recv;
    size_t window_send;
    size_t last_stream[2];  // dereferencable with CNO_PEER_REMOTE/CNO_PEER_LOCAL
    size_t stream_count[2];
    size_t http1_remaining;  // how many bytes to read before the next message; `-1` for chunked TE
    struct cno_st_settings_t settings[2];
    struct cno_st_io_vector_tmp_t buffer;
    struct cno_st_frame_t frame;
    struct cno_st_hpack_t decoder;
    struct cno_st_hpack_t encoder;
    CNO_SET(64) streams;
    void *cb_data;
    int (*on_write         )(struct cno_st_connection_t *, void *, const char * /* data */, size_t /* length */);
    int (*on_stream_start  )(struct cno_st_connection_t *, void *, size_t /* id */);
    int (*on_stream_end    )(struct cno_st_connection_t *, void *, size_t /* id */);
    int (*on_flow_increase )(struct cno_st_connection_t *, void *, size_t /* stream */);
    int (*on_message_start )(struct cno_st_connection_t *, void *, size_t /* stream */, struct cno_st_message_t * /* msg */);
    int (*on_message_push  )(struct cno_st_connection_t *, void *, size_t /* stream */, struct cno_st_message_t * /* msg */, size_t /* parent */);
    int (*on_message_data  )(struct cno_st_connection_t *, void *, size_t /* stream */, const char * /* data */, size_t /* length */);
    int (*on_message_end   )(struct cno_st_connection_t *, void *, size_t /* stream */);
    int (*on_frame         )(struct cno_st_connection_t *, void *, struct cno_st_frame_t * /* frame */);
    int (*on_frame_send    )(struct cno_st_connection_t *, void *, struct cno_st_frame_t * /* frame */);
    int (*on_pong          )(struct cno_st_connection_t *, void *, const char [8] /* payload */);
};


CNO_STRUCT_EXPORT(connection);
CNO_STRUCT_EXPORT(settings);
CNO_STRUCT_EXPORT(frame);
CNO_STRUCT_EXPORT(stream);
CNO_STRUCT_EXPORT(message);


extern const char  CNO_FRAME_FLOW_CONTROLLED[256];
extern const char *CNO_FRAME_NAME[256];


cno_connection_t * cno_connection_new           (enum CNO_CONNECTION_KIND kind);
void               cno_connection_destroy       (cno_connection_t *conn);
int                cno_connection_made          (cno_connection_t *conn);
int                cno_connection_data_received (cno_connection_t *conn, const char *data, size_t length);
int                cno_connection_lost          (cno_connection_t *conn);
int                cno_connection_stop          (cno_connection_t *conn);
int                cno_connection_is_http2      (cno_connection_t *conn);
void               cno_settings_copy            (cno_connection_t *conn, cno_settings_t *target);
int                cno_settings_apply           (cno_connection_t *conn, const cno_settings_t *new_settings);
size_t             cno_stream_next_id           (cno_connection_t *conn);

int cno_write_message (cno_connection_t *conn, size_t stream, const cno_message_t *msg, int final);
int cno_write_data    (cno_connection_t *conn, size_t stream, const char *data, size_t length, int final);

#endif
