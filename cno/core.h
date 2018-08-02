#pragma once

#include "config.h"
#include "common.h"
#include "hpack.h"

#ifdef __cplusplus
extern "C" {
#endif

// Skip to struct cno_connection_t for useful stuff.
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
    CNO_STATE_CLOSED,
    CNO_STATE_H2_INIT,
    CNO_STATE_H2_PREFACE,
    CNO_STATE_H2_SETTINGS,
    CNO_STATE_H2_FRAME,
    CNO_STATE_H1_HEAD,
    CNO_STATE_H1_BODY,
    CNO_STATE_H1_TAIL,
    CNO_STATE_H1_CHUNK,
    CNO_STATE_H1_CHUNK_BODY,
    CNO_STATE_H1_CHUNK_TAIL,
    CNO_STATE_H1_TRAILERS,
};


enum CNO_CONNECTION_FLAGS
{
    // Disable automatic sending of stream WINDOW_UPDATEs after receiving DATA;
    // application must call `cno_increase_flow_window` after processing a chunk from `on_message_data`.
    CNO_CONN_FLAG_MANUAL_FLOW_CONTROL = 0x01,
    // Disable special handling of the "Upgrade: h2c" header in HTTP/1.x mode.
    CNO_CONN_FLAG_DISALLOW_H2_UPGRADE = 0x02,
    // Disable special handling of the HTTP2 preface in HTTP/1.x mode.
    CNO_CONN_FLAG_DISALLOW_H2_PRIOR_KNOWLEDGE = 0x04,
};


enum CNO_STREAM_FLAGS
{
    CNO_STREAM_H1_WRITING_CHUNKED = 0x01,
    CNO_STREAM_HX_READING_HEAD_RESPONSE = 0x02,
};


enum CNO_STREAM_ACCEPT
{
    CNO_ACCEPT_HEADERS       = 0x01,
    CNO_ACCEPT_DATA          = 0x02,
    CNO_ACCEPT_PUSH          = 0x04,
    CNO_ACCEPT_INBOUND       = 0x07,
    CNO_ACCEPT_WRITE_HEADERS = 0x10,
    CNO_ACCEPT_WRITE_DATA    = 0x20,
    CNO_ACCEPT_WRITE_PUSH    = 0x40,
    CNO_ACCEPT_OUTBOUND      = 0x70,
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
    struct cno_stream_t *next; // in hashmap bucket
    uint32_t id;
    uint8_t /* enum CNO_STREAM_ACCEPT */ accept;
    uint8_t /* enum CNO_STREAM_FLAGS  */ flags;
     int32_t window_recv;
     int32_t window_send;
    uint64_t remaining_payload;
};


struct cno_settings_t
{
    union {
        // TODO implement this in a way not dependent on alignment
        // TODO extensions
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
    uint8_t /* enum CNO_PEER_KIND        */ client : 1;
    uint8_t /* enum CNO_HTTP_VERSION     */ mode : 1;
    uint8_t /* enum CNO_CONNECTION_STATE */ state;
    uint8_t /* enum CNO_CONNECTION_FLAGS */ flags;
    uint8_t  continued_flags;
    uint32_t continued_stream;
    uint32_t continued_promise;
     int32_t window_recv;
     int32_t window_send;
    uint32_t last_stream[2]; // dereferencable with CNO_REMOTE/CNO_LOCAL
    uint32_t stream_count[2];
    uint32_t goaway_sent;
    uint8_t  recently_reset_next;
    uint32_t recently_reset[CNO_STREAM_RESET_HISTORY];
    uint64_t remaining_h1_payload; // can't be monitored in cno_stream_t because the stream might get reset
    struct cno_settings_t settings[2];
    struct cno_buffer_dyn_t buffer;
    struct cno_buffer_dyn_t continued;
    struct cno_hpack_t decoder;
    struct cno_hpack_t encoder;
    struct cno_stream_t *streams[CNO_STREAM_BUCKETS];

    // Passed as the first argument to all callbacks.
    void *cb_data;
    // There is something to send to the other side. Transport level is outside
    // the scope of this library.
    int (*on_writev)(void *, const struct cno_buffer_t *, size_t count);
    // A new stream has been created due to sending/receiving a request or sending
    // a push promise. In the latter two cases, `on_message_head` will be called
    // shortly afterwards.
    int (*on_stream_start)(void *, uint32_t id);
    // Either a response has been sent/received fully, or the stream has been reset.
    // For HTTP 2, all stream ids are only used once; for 1.1, stream id 1 can be reused,
    // but multiple request/response pairs do not overlap.
    int (*on_stream_end)(void *, uint32_t id);
    // The other side has signaled that it is willing to accept more data.
    // There is a global limit (shared between all streams) and one for each stream;
    // `cno_write_data` will send as much data as the lowest of the two allows.
    // When the global limit is updated, this function is called with stream id = 0.
    int (*on_flow_increase)(void *, uint32_t id);
    // A request/response has been received (depending on whether this is a server
    // connection or not). Each stream carries exactly one request/response pair.
    int (*on_message_head)(void *, uint32_t id, const struct cno_message_t *);
    // Client only: server is intending to push a response to a request that
    // it anticipates in advance.
    int (*on_message_push)(void *, uint32_t id, const struct cno_message_t *, uint32_t parent);
    // A chunk of the payload has arrived.
    int (*on_message_data)(void *, uint32_t id, const char *, size_t);
    // All chunks of the payload (and possibly trailers) have arrived.
    // Trailers (like headers, but come after the payload) have been received.
    int (*on_message_tail)(void *, uint32_t id, const struct cno_message_t * /* nullable */ trailers);
    // An HTTP 2 frame has been received.
    int (*on_frame)(void *, const struct cno_frame_t *);
    // An HTTP 2 frame will be sent with `on_data` soon.
    int (*on_frame_send)(void *, const struct cno_frame_t *);
    // An acknowledgment of one of the previously sent pings has arrived.
    int (*on_pong)(void *, const char[8]);
    // New connection-wide settings have been chosen by the peer.
    int (*on_settings)(void *);
    // HTTP 1 server only: the previous request (see on_message_head) has requested
    // an update to a different protocol. If `cno_write_message` is called with code 101
    // before the next call to `cno_connection_data_received`, all further data will
    // be forwarded as payload to stream 1. Otherwise, the upgrade is ignored.
    int (*on_upgrade)(void *);
};


// Lifetime of a connection:
//
//  connection = new cno_connection_t
//  try {
//      cno_connection_init(client ? CNO_CLIENT : CNO_SERVER)
//      connection.on_writev = ...
//      connection.on_message_head = ...
//      ...
//      cno_connection_made(negotiated http2 ? CNO_HTTP2 : CNO_HTTP1)
//      while (i/o is open) {
//          cno_connection_data_received
//      }
//      cno_connection_lost
//  } finally {
//      cno_connection_reset
//      delete connection
//  }
//
void cno_connection_init          (struct cno_connection_t *, enum CNO_CONNECTION_KIND);
int  cno_connection_made          (struct cno_connection_t *, enum CNO_HTTP_VERSION);
int  cno_connection_data_received (struct cno_connection_t *, const char *, size_t);
int  cno_connection_lost          (struct cno_connection_t *);
void cno_connection_reset         (struct cno_connection_t *);
int  cno_connection_stop          (struct cno_connection_t *);
// Returns whether the next message will be sent in HTTP 2 mode.
// `cno_write_push` does nothing if this returns false. On the other hand,
// you can't switch protocols (e.g. to websockets) if this returns true.
int  cno_connection_is_http2(struct cno_connection_t *);
// Send a new configuration/schedule it to be sent when upgrading to HTTP 2.
// The current configuration can be read through `conn->settings[CNO_LOCAL]`.
// DO NOT modify `conn->settings` directly -- it is used to compute the delta.
int  cno_connection_set_config(struct cno_connection_t *, const struct cno_settings_t *);

// (As a client) sending requests:
//
//  headers = new cno_header_t[] { {name, value}, ... }
//  message = new cno_message_t { 0, method, path, headers, length(headers) }
//  stream  = cno_connection_next_stream
//  cno_write_message where final = 1 if there is no payload
//  for (chunk in payload) {
//      while (length(chunk) != 0) {
//          sent = cno_write_data
//          if (sent == 0)
//              await on_flow_increase(0) or on_flow_increase(stream)
//          chunk = drop(chunk, sent)
//      }
//  }
//
// (As a server) sending responses:
//
//  Same as sending a request, but specify the status code instead of `0`, leave
//  method/path empty, and use the stream id provided by the on_message_{start,data,end}
//  events.
//
// (Also as a server) pushing resources:
//
//  Same as sending a request, but use cno_write_push instead of cno_write_message
//  and get the stream id from an event, not from cno_connection_next_stream.
//
// (As a client again) aborting a push:
//
//  Call cno_write_reset with a stream id provided by on_message_push and code CNO_RST_CANCEL.
//
uint32_t cno_connection_next_stream (struct cno_connection_t *);
int cno_write_reset    (struct cno_connection_t *, uint32_t stream, enum CNO_RST_STREAM_CODE);
int cno_write_push     (struct cno_connection_t *, uint32_t stream, const struct cno_message_t *);
int cno_write_message  (struct cno_connection_t *, uint32_t stream, const struct cno_message_t *, int final);
int cno_write_data     (struct cno_connection_t *, uint32_t stream, const char *, size_t, int final);
int cno_write_ping     (struct cno_connection_t *, const char[8]);
int cno_write_frame    (struct cno_connection_t *, const struct cno_frame_t *);

// By default, cno assumes that `on_message_data` does not retain the data after returning.
// If it does copy the data somewhere, you should enable manual stream-level flow control,
// then ask to increase the window once the copy is deallocated.
int cno_increase_flow_window(struct cno_connection_t *, uint32_t stream, uint32_t bytes);

#ifdef __cplusplus
}  // extern "C"
#endif
