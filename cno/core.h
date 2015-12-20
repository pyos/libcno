// required includes:
// #include <stddef.h>
// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
#include <cno/common.h>
#include <cno/hpack.h>
// skip to struct cno_connection_t for useful stuff.
#ifndef CNO_CORE_H
#define CNO_CORE_H


#ifndef CNO_HTTP2_ENFORCE_MESSAGING_RULES
/* Enable additional checks, which include ensuring only standard-defined pseudo-headers
 * appear in the message, responses contain a status code, requests have a path and
 * a method, etc. */
#define CNO_HTTP2_ENFORCE_MESSAGING_RULES 0
#endif


#ifndef CNO_MAX_HTTP1_HEADER_SIZE
/* Max. length of a header, i.e. length of the name + length of the value + 4 bytes
 * (the ": " separator and the CRLF.) If a header longer than this is passed
 * to `cno_write_message`, it will return an assertion error. */
#define CNO_MAX_HTTP1_HEADER_SIZE 4096
#endif


#ifndef CNO_MAX_HEADERS
/* Max. number of entries in the header table of inbound messages. Applies to both HTTP 1
 * and HTTP 2. Since there's no way to know in advance how many headers a message has,
 * this option limits the stack space consumed. Does not affect outbound messages. */
#define CNO_MAX_HEADERS 128
#endif


enum CNO_PEER_KIND
{
    CNO_PEER_REMOTE = 0,
    CNO_PEER_LOCAL  = 1,
};


enum CNO_CONNECTION_KIND
{
    CNO_SERVER = 0,
    CNO_CLIENT = 1,
};


enum CNO_HTTP_VERSION
{
    CNO_HTTP1 = 0,
    CNO_HTTP2 = 1,
};


enum CNO_CONNECTION_STATE
{
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


enum CNO_STREAM_ACCEPT
{
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


enum CNO_FRAME_TYPE
{
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
    CNO_FRAME_UNKNOWN       = 0xa,
};


enum CNO_STATE_CODE
{
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


enum CNO_FRAME_FLAGS
{
    CNO_FLAG_ACK         = 0x1,
    CNO_FLAG_END_STREAM  = 0x1,
    CNO_FLAG_END_HEADERS = 0x4,
    CNO_FLAG_PADDED      = 0x8,
    CNO_FLAG_PRIORITY    = 0x20,
};


enum CNO_CONNECTION_SETTINGS
{
    CNO_SETTINGS_HEADER_TABLE_SIZE      = 0x1,
    CNO_SETTINGS_ENABLE_PUSH            = 0x2,
    CNO_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
    CNO_SETTINGS_INITIAL_WINDOW_SIZE    = 0x4,
    CNO_SETTINGS_MAX_FRAME_SIZE         = 0x5,
    CNO_SETTINGS_MAX_HEADER_LIST_SIZE   = 0x6,
    CNO_SETTINGS_UNDEFINED              = 0x7,
};


struct cno_frame_t
{
    uint8_t /* enum CNO_FRAME_TYPE  */ type;
    uint8_t /* enum CNO_FRAME_FLAGS */ flags;
    uint16_t padding;
    uint32_t stream;
    struct cno_buffer_t payload;
};


struct cno_message_t
{
    int code;
    struct cno_buffer_t method;
    struct cno_buffer_t path;
    struct cno_header_t *headers;
    size_t headers_len;
};


struct cno_stream_t
{
    struct cno_hmap_value;
    uint32_t id;
    uint32_t window_recv;
    uint32_t window_send;
    uint32_t continued_promise;
    uint8_t closed;
    uint8_t /* enum CNO_STREAM_ACCEPT */ accept;
    uint8_t /* enum CNO_FRAME_FLAGS   */ continued_flags;
    struct cno_buffer_t continued;
};


struct cno_settings_t
{
    union {  // TODO implement this in a way not dependent on alignment
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


struct cno_connection_t
{
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
    struct cno_settings_t settings[2];
    struct cno_buffer_off_t buffer;
    struct cno_hpack_t decoder;
    struct cno_hpack_t encoder;
    struct cno_hmap(64) streams;

    /* Events, yay!
     *
     *   cb_data
     *     -- passed as the first argument to all callbacks.
     *   on_write
     *     -- called when there is something to send to the other side,
     *        such as a request or a response or a flow control window update.
     *        transport level is not within the scope of this library.
     *   on_stream_start
     *     -- called when either side initiates a stream.
     *        a request should arrive (or be sent) on that stream shortly.
     *   on_stream_end
     *     -- called when a stream is terminated. if the response was not
     *        sent/received on that stream yet, this means the request was aborted.
     *   on_flow_increase
     *     -- called when the other side is ready to accept some more payload.
     *        there is a global limit and one for each stream; when the global one
     *        is updated, this function is called with stream id = 0.
     *   on_message_start
     *     -- called when a real request/response is received on a stream
     *        (depending on whether this is a server connection or not).
     *        each stream carries exactly one request-response pair.
     *   on_message_data
     *     -- called each time a new chunk of payload for a previously received message
     *        arrives.
     *   on_message_end
     *     -- called after all chunks of the payload have arrived.
     *   on_message_push
     *     -- called on client side when the server wants to push some data.
     *        the basic idea is, it sends an "imaginary" request; the client receives
     *        it, and then everyone just sort of assumes that the client has actually
     *        sent that request, not the server. so expect an on_message_start
     *        on this stream shortly.
     *
     */
    void *cb_data;
    #define CNO_FIRE(ob, cb, ...) (ob->cb && ob->cb(ob->cb_data, ## __VA_ARGS__))
    int (*on_write         )(void *, const char * /* data */, size_t /* length */);
    int (*on_stream_start  )(void *, size_t /* stream id */);
    int (*on_stream_end    )(void *, size_t);
    int (*on_flow_increase )(void *, size_t);
    int (*on_message_start )(void *, size_t, const struct cno_message_t * /* msg */);
    int (*on_message_push  )(void *, size_t, const struct cno_message_t *, size_t /* parent stream */);
    int (*on_message_data  )(void *, size_t, const char * /* data */, size_t /* length */);
    int (*on_message_end   )(void *, size_t);
    int (*on_frame         )(void *, const struct cno_frame_t *);
    int (*on_frame_send    )(void *, const struct cno_frame_t *);
    int (*on_pong          )(void *, const char * /* payload, 8 bytes */);
} cno_connection_t;


/* Lifetime of a connection:
 *
 *  1. open a socket
 *  2. allocate a connection object
 *  3. --- cno_connection_init
 *  4. set callbacks, most importantly on_write and on_message_*
 *  5. optinally:
 *       --- cno_settings_copy, then modify them
 *       --- cno_settings_apply
 *  6. --- cno_connection_made
 *  7. --- cno_connection_data_received while socket is open
 *  8. --- cno_connection_lost
 *  9. --- cno_connection_reset
 *  10. deallocate the object
 *  11. close the socket
 *
 * If any of the steps 3-8 returns an error, call cno_connection_reset and abort.
 * To cleanly shut a connection down, call cno_connection_stop.
 *
 */
void     cno_connection_init          (struct cno_connection_t *conn, enum CNO_CONNECTION_KIND kind);
int      cno_connection_made          (struct cno_connection_t *conn, enum CNO_HTTP_VERSION version);
int      cno_connection_data_received (struct cno_connection_t *conn, const char *data, size_t length);
int      cno_connection_lost          (struct cno_connection_t *conn);
void     cno_connection_reset         (struct cno_connection_t *conn);
int      cno_connection_stop          (struct cno_connection_t *conn);
int      cno_connection_is_http2      (struct cno_connection_t *conn);
void     cno_settings_copy            (struct cno_connection_t *conn,       struct cno_settings_t *);
int      cno_settings_apply           (struct cno_connection_t *conn, const struct cno_settings_t *);

/* (As a client) sending requests:
 *
 *  1. construct a cno_message_t with cno_header_t-s and everything
 *  2. --- cno_stream_next_id
 *  3. --- cno_write_message (with final = 1 iff the request has no payload, 0 otherwise)
 *  4. --- cno_write_data any number of times, the last should have final = 1.
 *
 * (As a server) sending responses:
 *
 *  1. same, except the stream is the one on which the request has arrived,
 *     so no need to call cno_stream_next_id.
 *
 * (Also as a server) pushing resources:
 *
 *  1. same as sending a response, only with cno_write_push, and you're sending
 *     an "imaginary" request with no payload. this request will be dispatched
 *     through the callbacks as a normal one would. (pushing resources in response
 *     to such an imaginary request is a no-op, so don't worry about recursion.)
 *
 * (Either side can do this) aborting a stream:
 *
 *  1. call cno_write_reset if you do not wish to receive a pushed resource,
 *     or decide against sending a request/response in between calls to cno_write_data.
 *
 */
uint32_t cno_stream_next_id (struct cno_connection_t *conn);
int      cno_write_reset    (struct cno_connection_t *conn, size_t stream);
int      cno_write_push     (struct cno_connection_t *conn, size_t stream, const struct cno_message_t *msg);
int      cno_write_message  (struct cno_connection_t *conn, size_t stream, const struct cno_message_t *msg, int final);
int      cno_write_data     (struct cno_connection_t *conn, size_t stream, const char *data, size_t length, int final);

#endif
