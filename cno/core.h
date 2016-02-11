// required includes:
// #include <stddef.h>
// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
#ifndef CNO_CORE_H
#define CNO_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

// skip to struct cno_connection_t for useful stuff.
#include "config.h"
#include "common.h"
#include "hpack.h"


enum CNO_PEER_KIND
{
    CNO_REMOTE = 0,
    CNO_LOCAL  = 1,
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


enum CNO_CONNECTION_FLAGS
{
    CNO_CONN_FLAG_WRITING_CHUNKED = 0x01,  // Transfer-Encoding, that is
};


enum CNO_STREAM_ACCEPT
{
    CNO_ACCEPT_NOTHING       = 0x00,
    CNO_ACCEPT_HEADERS       = 0x01,
    CNO_ACCEPT_DATA          = 0x02,
    CNO_ACCEPT_PUSH          = 0x04,
    CNO_ACCEPT_TRAILERS      = 0x08,
    CNO_ACCEPT_INBOUND       = 0x0F,
    CNO_ACCEPT_WRITE_PUSH    = 0x20,
    CNO_ACCEPT_WRITE_HEADERS = 0x40,
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


enum CNO_RST_STREAM_CODE
{
    CNO_RST_NO_ERROR            = 0x0,
    CNO_RST_PROTOCOL_ERROR      = 0x1,
    CNO_RST_INTERNAL_ERROR      = 0x2,
    CNO_RST_FLOW_CONTROL_ERROR  = 0x3,
    CNO_RST_SETTINGS_TIMEOUT    = 0x4,
    CNO_RST_STREAM_CLOSED       = 0x5,
    CNO_RST_FRAME_SIZE_ERROR    = 0x6,
    CNO_RST_REFUSED_STREAM      = 0x7,
    CNO_RST_CANCEL              = 0x8,
    CNO_RST_COMPRESSION_ERROR   = 0x9,
    CNO_RST_CONNECT_ERROR       = 0xa,
    CNO_RST_ENHANCE_YOUR_CALM   = 0xb,
    CNO_RST_INADEQUATE_SECURITY = 0xc,
    CNO_RST_HTTP_1_1_REQUIRED   = 0xd,
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
    struct cno_stream_t *next;  // in hashmap bucket
    uint32_t id;
     int32_t window_recv;
     int32_t window_send;
    uint8_t closed;
    uint8_t /* enum CNO_STREAM_ACCEPT */ accept;
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
        uint32_t array[6];
    };
};


struct cno_connection_t
{
    uint8_t /* enum CNO_PEER_KIND        */ client;
    uint8_t /* enum CNO_CONNECTION_STATE */ state;
    uint8_t /* enum CNO_CONNECTION_FLAGS */ flags;
    uint8_t  continued_flags;  // OR the flags of the next CONTINUATION with this.
    uint32_t continued_stream;  // if nonzero, expect a CONTINUATION on that stream.
    uint32_t continued_promise;  // if prev. frame was a PUSH_PROMISE, this is the stream it created.
    uint32_t http1_remaining;  // how many bytes to read before the next message; `-1` for chunked TE
     int32_t window_recv;
     int32_t window_send;
    uint32_t last_stream  [2];  // dereferencable with CNO_REMOTE/CNO_LOCAL
    uint32_t stream_count [2];
    struct cno_settings_t settings[2];
    struct cno_buffer_dyn_t buffer;
    struct cno_buffer_dyn_t continued;  // concat CONTINUATIONs with this
    struct cno_hpack_t decoder;
    struct cno_hpack_t encoder;
    struct cno_stream_t *streams[CNO_STREAM_BUCKETS];

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
     *        sent/received on that stream yet, the request was aborted.
     *   on_flow_increase
     *     -- called when the other side is ready to accept some more payload.
     *        there is a global limit and one for each stream; when the global one
     *        is updated, this function is called with stream id = 0.
     *   on_message_start
     *     -- called when a real request/response is received on a stream
     *        (depending on whether this is a server connection or not).
     *        each stream carries exactly one request-response pair.
     *   on_message_trail
     *     -- called before on_message_end if the message contains trailers.
     *   on_message_data
     *     -- called each time a new chunk of payload for a previously received message
     *        arrives.
     *   on_message_end
     *     -- called after all chunks of the payload (and possibly the trailers) have arrived.
     *   on_message_push
     *     -- called on client side when the server wants to push some data.
     *        its argument is a fake request the client has been assumed to send;
     *        a response to that request should arrive soon on the same stream.
     */
    void *cb_data;
    #define CNO_FIRE(ob, cb, ...) (ob->cb && ob->cb(ob->cb_data, __VA_ARGS__))
    int (*on_write         )(void *, const char * /* data */, size_t /* length */);
    int (*on_stream_start  )(void *, uint32_t /* stream id */);
    int (*on_stream_end    )(void *, uint32_t);
    int (*on_flow_increase )(void *, uint32_t);
    int (*on_message_start )(void *, uint32_t, const struct cno_message_t * /* msg */);
    int (*on_message_trail )(void *, uint32_t, const struct cno_message_t * /* msg */);
    int (*on_message_push  )(void *, uint32_t, const struct cno_message_t *, uint32_t /* parent stream */);
    int (*on_message_data  )(void *, uint32_t, const char * /* data */, size_t /* length */);
    int (*on_message_end   )(void *, uint32_t);
    int (*on_frame         )(void *, const struct cno_frame_t *);
    int (*on_frame_send    )(void *, const struct cno_frame_t *);
    int (*on_pong          )(void *, const char[8]);
} cno_connection_t;


/* Lifetime of a connection:
 *
 *  connection = new cno_connection_t
 *  try {
 *      cno_connection_init(client ? CNO_CLIENT : CNO_SERVER)
 *      connection.on_write = ...
 *      connection.on_message_start = ...
 *      ...
 *      cno_connection_made(negotiated http2 ? CNO_HTTP2 : CNO_HTTP1)
 *      while (i/o is open) {
 *          cno_connection_data_received
 *      }
 *      cno_connection_lost
 *  } finally {
 *      cno_connection_reset
 *      delete connection
 *  }
 *
 */
void cno_connection_init          (struct cno_connection_t *, enum CNO_CONNECTION_KIND);
int  cno_connection_made          (struct cno_connection_t *, enum CNO_HTTP_VERSION);
int  cno_connection_data_received (struct cno_connection_t *, const char *, size_t);
int  cno_connection_lost          (struct cno_connection_t *);
void cno_connection_reset         (struct cno_connection_t *);
int  cno_connection_stop          (struct cno_connection_t *);
/* Returns whether the next message will be sent in HTTP 2 mode.
 * `cno_write_push` does nothing if this returns false. On the other hand,
 * you can't switch protocols (e.g. to websockets) if this returns true. */
int  cno_connection_is_http2      (struct cno_connection_t *);
/* cno_settings_copy loads a struct with current values, cno_settings_apply
 * either sends updated values to the peer or schedules them to be sent
 * when the connection enters HTTP 2 mode. */
void cno_settings_copy            (struct cno_connection_t *,       struct cno_settings_t *);
int  cno_settings_apply           (struct cno_connection_t *, const struct cno_settings_t *);

/* (As a client) sending requests:
 *
 *  headers = new cno_header_t[] { {name, value}, ... }
 *  message = new cno_message_t { 0, method, path, headers, length(headers) }
 *  stream  = cno_stream_next_id
 *  cno_write_message where final = 1 if there is no payload
 *  for (chunk in payload) {
 *      while (length(chunk) != 0) {
 *          sent = cno_write_data
 *          if (sent == 0)
 *              await on_flow_increase(0) or on_flow_increase(stream)
 *          chunk = drop(chunk, sent)
 *      }
 *  }
 *
 * (As a server) sending responses:
 *
 *  Same as sending a request, but specify the status code instead of `0`, leave
 *  method/path empty, and use the stream id provided by the on_message_{start,data,end}
 *  events.
 *
 * (Also as a server) pushing resources:
 *
 *  Same as sending a request, but use cno_write_push instead of cno_write_message
 *  and get the stream id from an event, not from cno_stream_next_id.
 *
 * (As a client again) aborting a push:
 *
 *  Call cno_write_reset with a stream id provided by on_message_push and code CNO_RST_CANCEL.
 *
 */
uint32_t cno_stream_next_id (struct cno_connection_t *);
int      cno_write_reset    (struct cno_connection_t *, uint32_t /* stream */, enum CNO_RST_STREAM_CODE);
int      cno_write_push     (struct cno_connection_t *, uint32_t, const struct cno_message_t *);
int      cno_write_message  (struct cno_connection_t *, uint32_t, const struct cno_message_t *, int final);
int      cno_write_data     (struct cno_connection_t *, uint32_t, const char *, size_t, int final);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
