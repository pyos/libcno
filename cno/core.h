#ifndef _CNO_CORE_H_
#define _CNO_CORE_H_
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cno/common.h>
#include <cno/hpack.h>


#ifndef CNO_HTTP2_ENFORCE_MESSAGING_RULES
/* Enable additional checks, which include ensuring only standard-defined pseudo-headers
 * appear in the message, responses contain a status code, requests have a path and
 * a method, etc. */
#define CNO_HTTP2_ENFORCE_MESSAGING_RULES 0
#endif


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
};


enum CNO_CONNECTION_KIND {
    CNO_SERVER = 0,
    CNO_CLIENT = 1,
};


enum CNO_HTTP_VERSION {
    CNO_HTTP1 = 0,
    CNO_HTTP2 = 1,
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
    CNO_CONNECTION_UNDEFINED,
};


enum CNO_STREAM_ACCEPT {
    CNO_ACCEPT_NOTHING       = 0x00,  // bitwise fields marking acceptable input on said stream.
    CNO_ACCEPT_HEADERS       = 0x01,  // stream can receive a HEADERS frame.
    CNO_ACCEPT_HEADCNT       = 0x02,  // stream can receive a CONTINUATION to HEADERS.
    CNO_ACCEPT_DATA          = 0x04,  // stream can receive a DATA frame.
    CNO_ACCEPT_PUSH          = 0x08,  // stream can receive a PUSH_PROMISE frame.
    CNO_ACCEPT_PUSHCNT       = 0x10,  // stream can receive a CONTINUATION to a PUSH_PROMISE.
    CNO_ACCEPT_INBOUND       = 0x1f,
    CNO_ACCEPT_WRITE_PUSH    = 0x20,
    CNO_ACCEPT_WRITE_HEADERS = 0x40,  // this time continuations are handled automatically
    CNO_ACCEPT_WRITE_DATA    = 0x80,
    CNO_ACCEPT_OUTBOUND      = 0xe0,
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
    uint8_t /* enum CNO_FRAME_TYPE  */ type;
    uint8_t /* enum CNO_FRAME_FLAGS */ flags;
    uint32_t stream;
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
    uint32_t id;
    uint32_t window_recv;
    uint32_t window_send;
    uint32_t last_promise;
    uint8_t closed;
    uint8_t /* enum CNO_STREAM_ACCEPT */ accept;
    // carry END_HEADERS from HEADERS/PUSH_PROMISE to CONTINUATION
    uint8_t /* enum CNO_FRAME_FLAGS   */ last_flags;
    struct cno_st_io_vector_t buffer;  // frames that can have CONTINUATIONs are buffered here
};


struct cno_st_settings_t {
    union {  // TODO find a better way to implement this to avoid alignment bullshit
        struct {
            uint32_t header_table_size;
            uint32_t enable_push;
            uint32_t max_concurrent_streams;
            uint32_t initial_window_size;
            uint32_t max_frame_size;
            uint32_t max_header_list_size;
        };
        uint32_t array[CNO_SETTINGS_UNDEFINED - 1];
    };
};


struct cno_st_connection_t {
    union {
        uint8_t /*enum CNO_CONNECTION_KIND */ kind;
        uint8_t /*enum CNO_PEER_KIND       */ client;  // == CNO_PEER_LOCAL iff we are the client
    };
    uint8_t /* enum CNO_CONNECTION_STATE */ state;
    uint8_t closed;
    uint32_t window_recv;
    uint32_t window_send;
    uint32_t last_stream[2];  // dereferencable with CNO_PEER_REMOTE/CNO_PEER_LOCAL
    uint32_t stream_count[2];
    size_t http1_remaining;  // how many bytes to read before the next message; `-1` for chunked TE
    struct cno_st_settings_t settings[2];
    struct cno_st_io_vector_tmp_t buffer;
    struct cno_st_hpack_t decoder;
    struct cno_st_hpack_t encoder;
    CNO_SET(64) streams;
    void *cb_data;
    int (*on_write         )(struct cno_st_connection_t *, void *, const char * /* data */, size_t /* length */);
    int (*on_stream_start  )(struct cno_st_connection_t *, void *, size_t /* id */);
    int (*on_stream_end    )(struct cno_st_connection_t *, void *, size_t /* id */);
    int (*on_flow_increase )(struct cno_st_connection_t *, void *, size_t /* stream */);
    int (*on_message_start )(struct cno_st_connection_t *, void *, size_t /* stream */, const struct cno_st_message_t * /* msg */);
    int (*on_message_push  )(struct cno_st_connection_t *, void *, size_t /* stream */, const struct cno_st_message_t * /* msg */, size_t /* parent */);
    int (*on_message_data  )(struct cno_st_connection_t *, void *, size_t /* stream */, const char * /* data */, size_t /* length */);
    int (*on_message_end   )(struct cno_st_connection_t *, void *, size_t /* stream */);
    int (*on_frame         )(struct cno_st_connection_t *, void *, const struct cno_st_frame_t * /* frame */);
    int (*on_frame_send    )(struct cno_st_connection_t *, void *, const struct cno_st_frame_t * /* frame */);
    int (*on_pong          )(struct cno_st_connection_t *, void *, const char * /* payload */);
};


CNO_STRUCT_EXPORT(connection);
CNO_STRUCT_EXPORT(settings);
CNO_STRUCT_EXPORT(frame);
CNO_STRUCT_EXPORT(stream);
CNO_STRUCT_EXPORT(message);
extern const char *CNO_FRAME_NAME[256];


cno_connection_t * cno_connection_new           (enum CNO_CONNECTION_KIND kind);
void               cno_connection_destroy       (cno_connection_t *conn);
int                cno_connection_made          (cno_connection_t *conn, enum CNO_HTTP_VERSION version);
int                cno_connection_data_received (cno_connection_t *conn, const char *data, size_t length);
int                cno_connection_lost          (cno_connection_t *conn);
int                cno_connection_stop          (cno_connection_t *conn);
int                cno_connection_is_http2      (cno_connection_t *conn);
void               cno_settings_copy            (cno_connection_t *conn, cno_settings_t *target);
int                cno_settings_apply           (cno_connection_t *conn, const cno_settings_t *new_settings);
uint32_t           cno_stream_next_id           (cno_connection_t *conn);

int cno_write_reset   (cno_connection_t *conn, size_t stream);
int cno_write_push    (cno_connection_t *conn, size_t stream, const cno_message_t *msg);
int cno_write_message (cno_connection_t *conn, size_t stream, const cno_message_t *msg, int final);
int cno_write_data    (cno_connection_t *conn, size_t stream, const char *data, size_t length, int final);

#endif
