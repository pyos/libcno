#include <ctype.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "../picohttpparser/picohttpparser.h"


static inline uint8_t  read1(const uint8_t *p) { return p[0]; }
static inline uint16_t read2(const uint8_t *p) { return p[0] <<  8 | p[1]; }
static inline uint32_t read4(const uint8_t *p) { return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }
static inline uint32_t read3(const uint8_t *p) { return read4(p) >> 8; }


/* construct a stack-allocated array of bytes in place. expands to (pointer, length) */
#define PACK(...) (char *) (uint8_t []) { __VA_ARGS__ }, sizeof((uint8_t []) { __VA_ARGS__ })
#define I8(x)  x
#define I16(x) x >> 8, x
#define I24(x) x >> 16, x >> 8, x
#define I32(x) x >> 24, x >> 16, x >> 8, x


/* fake http "request" sent by the client at the beginning of a connection */
static const struct cno_buffer_t CNO_PREFACE = { "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24 };

/* standard-defined pre-initial-SETTINGS values */
static const struct cno_settings_t CNO_SETTINGS_STANDARD = {{{ 4096, 1, -1,   65535, 16384, -1 }}};

/* a somewhat more conservative version assumed to be used by the remote side at first */
static const struct cno_settings_t CNO_SETTINGS_CONSERVATIVE = {{{ 4096, 1, 100, 65535, 16384, -1 }}};

/* actual values to send in the first SETTINGS frame */
static const struct cno_settings_t CNO_SETTINGS_INITIAL = {{{ 4096, 1, 1024, 65535, 65536, -1 }}};


static int cno_stream_is_local(const struct cno_connection_t *conn, uint32_t id)
{
    return id % 2 == conn->client;
}


/* each stream carries a single request-response pair, plus push promises.
 *
 * local:: 1 (== CNO_LOCAL) if this side is initiating the stream.
 *
 * throws::
 *
 *     INVALID_STREAM if stream id is unacceptable.
 *     WOULD_BLOCK    if this side has initiated too many streams.
 *     TRANSPORT      if the other side has initiated too many streams.
 *     NO_MEMORY      streams are heap-allocated
 *
 */
static struct cno_stream_t * cno_stream_new(struct cno_connection_t *conn, uint32_t id, int local)
{
    if (cno_stream_is_local(conn, id) != local)
        return CNO_ERROR_NULL(INVALID_STREAM, "incorrect parity");

    if (id <= conn->last_stream[local])
        return CNO_ERROR_NULL(INVALID_STREAM, "nonmonotonic");

    if (conn->stream_count[local] >= conn->settings[!local].max_concurrent_streams)
        return local ? CNO_ERROR_NULL(WOULD_BLOCK, "wait for on_stream_end")
                     : CNO_ERROR_NULL(TRANSPORT,   "peer exceeded stream limit");

    struct cno_stream_t *stream = malloc(sizeof(struct cno_stream_t));
    if (!stream)
        return CNO_ERROR_NULL(NO_MEMORY, "%zu bytes", sizeof(struct cno_stream_t));

    *stream = (struct cno_stream_t) {
        .id          = conn->last_stream[local] = id,
        .next        = conn->streams[id % CNO_STREAM_BUCKETS],
        .window_recv = conn->settings[CNO_LOCAL] .initial_window_size,
        .window_send = conn->settings[CNO_REMOTE].initial_window_size,
    };

    conn->streams[id % CNO_STREAM_BUCKETS] = stream;
    conn->stream_count[local]++;

    if (CNO_FIRE(conn, on_stream_start, id)) {
        conn->streams[id % CNO_STREAM_BUCKETS] = stream->next;
        conn->stream_count[local]--;
        free(stream);
        return CNO_ERROR_UP_NULL();
    }

    return stream;
}


static struct cno_stream_t * cno_stream_find(const struct cno_connection_t *conn, uint32_t id)
{
    struct cno_stream_t *s = conn->streams[id % CNO_STREAM_BUCKETS];
    while (s && s->id != id) s = s->next;
    return s;
}


static void cno_stream_free(struct cno_connection_t *conn, struct cno_stream_t *stream)
{
    conn->stream_count[cno_stream_is_local(conn, stream->id)]--;

    struct cno_stream_t **s = &conn->streams[stream->id % CNO_STREAM_BUCKETS];
    while (*s != stream) s = &(*s)->next;
    *s = stream->next;

    free(stream);
}


static int cno_stream_rst(struct cno_connection_t *conn, struct cno_stream_t *stream)
{
    uint32_t id = stream->id;
    cno_stream_free(conn, stream);
    return CNO_FIRE(conn, on_stream_end, id);
}


/* send a single non-flow-controlled frame, splitting DATA/HEADERS if they are too big.
 *
 * throws::
 *
 *     ASSERTION   if a non-DATA frame exceeds the size limit (how)
 *     ASSERTION   if a padded frame exceeds the size limit (FIXME)
 *
 */
static int cno_frame_write(const struct cno_connection_t *conn,
                           const struct cno_frame_t      *frame)
{
    size_t length = frame->payload.size;
    size_t limit  = conn->settings[CNO_REMOTE].max_frame_size;

    if (length <= limit) {
        if (CNO_FIRE(conn, on_frame_send, frame))
            return CNO_ERROR_UP();

        if (CNO_FIRE(conn, on_write, PACK(I24(length), I8(frame->type), I8(frame->flags), I32(frame->stream))))
            return CNO_ERROR_UP();

        if (length)
            return CNO_FIRE(conn, on_write, frame->payload.data, length);

        return CNO_OK;
    }

    int carry_on_last = CNO_FLAG_END_HEADERS;

    if (frame->flags & CNO_FLAG_PADDED)
        return CNO_ERROR(ASSERTION, "don't know how to split padded frames");
    else if (frame->type == CNO_FRAME_DATA)
        carry_on_last = CNO_FLAG_END_STREAM;
    else if (frame->type != CNO_FRAME_HEADERS && frame->type != CNO_FRAME_PUSH_PROMISE)
        return CNO_ERROR(ASSERTION, "control frame too big");

    struct cno_frame_t part = *frame;
    part.flags &= ~carry_on_last;
    part.payload.size = limit;

    while (length > limit) {
        if (cno_frame_write(conn, &part))
            return CNO_ERROR_UP();

        length -= limit;
        part.flags &= ~(CNO_FLAG_PRIORITY | CNO_FLAG_END_STREAM);
        part.payload.data += limit;

        if (part.type != CNO_FRAME_DATA)
            part.type = CNO_FRAME_CONTINUATION;
    }

    part.flags |= frame->flags & carry_on_last;
    part.payload.size = length;
    return cno_frame_write(conn, &part);
}


static int cno_frame_write_settings(const struct cno_connection_t *conn,
                                    const struct cno_settings_t *previous,
                                    const struct cno_settings_t *current)
{
    size_t i = 0;
    uint8_t payload[CNO_SETTINGS_UNDEFINED - 1][6], (*ptr)[6] = payload;
    const uint32_t *ax = previous->array;
    const uint32_t *bx = current->array;

    for (; ++i < CNO_SETTINGS_UNDEFINED; ++ax, ++bx) {
        if (*ax != *bx) {
            struct cno_buffer_t buf = { PACK(I16(i), I32(*bx)) };
            memcpy(ptr++, buf.data, buf.size);
        }
    }

    struct cno_frame_t frame = { CNO_FRAME_SETTINGS, 0, 0, { (char *) payload, (ptr - payload) * 6 } };
    return cno_frame_write(conn, &frame);
}


static int cno_frame_write_rst_stream(struct cno_connection_t *conn,
                                      struct cno_stream_t     *stream,
                                      uint32_t /* enum CNO_RST_STREAM_CODE */ code)
{
    struct cno_frame_t error = { CNO_FRAME_RST_STREAM, 0, stream->id, { PACK(I32(code)) } };

    if (cno_frame_write(conn, &error))
        return CNO_ERROR_UP();

    if (!(stream->accept & CNO_ACCEPT_HEADERS))
        // since headers were already handled, this stream can be safely destroyed.
        // i sure hope there are no trailers, though.
        return cno_stream_rst(conn, stream);

    // still have to decompress headers to maintain shared compression state.
    // FIXME headers may never arrive if the peer receives RST_STREAM before sending them.
    stream->accept &= ~CNO_ACCEPT_OUTBOUND;
    stream->accept |=  CNO_ACCEPT_NOP_HEADERS;
    return CNO_OK;
}


static int cno_frame_write_goaway(struct cno_connection_t *conn,
                                  uint32_t /* enum CNO_RST_STREAM_CODE */ code)
{
    uint32_t last = conn->last_stream[CNO_REMOTE];
    struct cno_frame_t error = { CNO_FRAME_GOAWAY, 0, 0, { PACK(I32(last), I32(code)) } };
    return cno_frame_write(conn, &error);
}


/* shut down a connection and *then* throw a TRANSPORT error. */
#define cno_frame_write_error(conn, type, ...) \
    (cno_frame_write_goaway(conn, type) ? CNO_ERROR_UP() : CNO_ERROR(TRANSPORT, __VA_ARGS__))


static int cno_frame_handle_end_stream(struct cno_connection_t *conn,
                                       struct cno_stream_t     *stream)
{
    // don't move below the event. it may call write_{message,data} and destroy the stream.
    int half_open = (stream->accept &= ~CNO_ACCEPT_INBOUND) != 0;

    if (CNO_FIRE(conn, on_message_end, stream->id))
        return CNO_ERROR_UP();

    if (half_open)
        return CNO_OK;

    return cno_stream_rst(conn, stream);
}


static int cno_frame_handle_message(struct cno_connection_t *conn,
                                    struct cno_stream_t     *stream,
                                    struct cno_frame_t      *frame,
                                    struct cno_message_t    *msg)
{
    const struct cno_header_t *it  = msg->headers;
    const struct cno_header_t *end = msg->headers + msg->headers_len;

    int has_scheme = 0;
    // >HTTP/2 uses special pseudo-header fields beginning with ':' character
    // >(ASCII 0x3a) [to convey the target URI, ...]
    for (; it != end && cno_buffer_startswith(it->name, CNO_BUFFER_STRING(":")); ++it) {
        if (stream->accept & CNO_ACCEPT_TRAILERS)
            // >Pseudo-header fields MUST NOT appear in trailers.
            goto invalid_message;

        if (conn->client && !conn->continued_promise) {
            if (cno_buffer_eq(it->name, CNO_BUFFER_STRING(":status"))) {
                if (msg->code)
                    goto invalid_message;

                for (const char *p = it->value.data; p != it->value.data + it->value.size; p++) {
                    if (*p < '0' || '9' < *p)
                        goto invalid_message;

                    msg->code = msg->code * 10 + (*p - '0');
                }

                continue;
            }

            // >Endpoints MUST NOT generate pseudo-header fields
            // >other than those defined in this document.
            goto invalid_message;
        }

        if (cno_buffer_eq(it->name, CNO_BUFFER_STRING(":path"))) {
            if (msg->path.data)
                goto invalid_message;

            msg->path = it->value;
            continue;
        }


        if (cno_buffer_eq(it->name, CNO_BUFFER_STRING(":method"))) {
            if (msg->method.data)
                goto invalid_message;

            msg->method = it->value;
            continue;
        }

        if (cno_buffer_eq(it->name, CNO_BUFFER_STRING(":authority"))) continue;

        if (cno_buffer_eq(it->name, CNO_BUFFER_STRING(":scheme"))) {
            if (has_scheme)
                goto invalid_message;

            has_scheme = 1;
            continue;
        }

        goto invalid_message;
    }

    if (!conn->client && !cno_buffer_eq(msg->method, CNO_BUFFER_STRING("CONNECT"))
     && (!has_scheme || cno_buffer_eq(msg->path, CNO_BUFFER_EMPTY)))
        // >All HTTP/2 requests MUST include exactly one valid value for the :method, :scheme,
        // >and :path pseudo-header fields, unless it is a CONNECT request (Section 8.3).
        goto invalid_message;

    for (; it != end; ++it) {
        // >All pseudo-header fields MUST appear in the header block
        // >before regular header fields.
        if (cno_buffer_startswith(it->name, CNO_BUFFER_STRING(":")))
            goto invalid_message;

        // >However, header field names MUST be converted to lowercase
        // >prior to their encoding in HTTP/2.
        for (const char *p = it->name.data; p != it->name.data + it->name.size; p++)
            if ('A' <= *p && *p <= 'Z')
                goto invalid_message;

        // TODO
        // >HTTP/2 does not use the Connection header field to indicate
        // >connection-specific header fields.
    }

    if (stream->accept & CNO_ACCEPT_TRAILERS) {
        if (!(frame->flags & CNO_FLAG_END_STREAM))
            // there is no data after trailers.
            goto invalid_message;

        stream->accept &= ~CNO_ACCEPT_INBOUND;

        if (CNO_FIRE(conn, on_message_trail, stream->id, msg))
            return CNO_ERROR_UP();

        return cno_frame_handle_end_stream(conn, stream);
    }

    if (conn->client && !conn->continued_promise ? !msg->code : !msg->path.data || !msg->method.data)
        goto invalid_message;

    if (conn->continued_promise)
        // accept pushes even on reset streams.
        return CNO_FIRE(conn, on_message_push, stream->id, msg, conn->continued_stream);

    stream->accept &= ~CNO_ACCEPT_HEADERS;
    stream->accept |=  CNO_ACCEPT_TRAILERS | CNO_ACCEPT_DATA;

    if (stream->accept & CNO_ACCEPT_NOP_HEADERS)
        // hpack compression is now in sync, there's no use for this stream anymore.
        return cno_stream_rst(conn, stream);

    if (CNO_FIRE(conn, on_message_start, stream->id, msg))
        return CNO_ERROR_UP();

    if (frame->flags & CNO_FLAG_END_STREAM)
        return cno_frame_handle_end_stream(conn, stream);

    return CNO_OK;

invalid_message:
    return cno_frame_write_rst_stream(conn, stream, CNO_RST_PROTOCOL_ERROR);
}


static int cno_frame_handle_end_headers(struct cno_connection_t *conn,
                                        struct cno_stream_t     *stream,
                                        struct cno_frame_t      *frame)
{
    struct cno_header_t  headers[CNO_MAX_HEADERS];
    struct cno_message_t msg = { 0, CNO_BUFFER_EMPTY, CNO_BUFFER_EMPTY, headers, CNO_MAX_HEADERS };

    if (cno_hpack_decode(&conn->decoder, conn->continued.as_static, headers, &msg.headers_len)) {
        cno_buffer_dyn_clear(&conn->continued);
        cno_frame_write_goaway(conn, CNO_RST_COMPRESSION_ERROR);
        return CNO_ERROR_UP();
    }

    int failed = cno_frame_handle_message(conn, stream, frame, &msg);

    for (unsigned i = 0; i < msg.headers_len; i++)
        cno_hpack_free_header(&headers[i]);

    cno_buffer_dyn_clear(&conn->continued);
    conn->continued = CNO_BUFFER_DYN_EMPTY;
    conn->continued_stream  = 0;
    conn->continued_promise = 0;
    return failed;
}


static int cno_frame_handle_padding(struct cno_connection_t *conn, struct cno_frame_t *frame)
{
    if (frame->flags & CNO_FLAG_PADDED) {
        if (frame->payload.size == 0)
            return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "no padding found");

        size_t padding = read1((const uint8_t *) frame->payload.data) + 1;

        if (padding > frame->payload.size)
            return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "more padding than data");

        frame->payload.data += 1;
        frame->payload.size -= padding;
    }

    return CNO_OK;
}


static int cno_frame_handle_headers(struct cno_connection_t *conn,
                                    struct cno_stream_t     *stream,
                                    struct cno_frame_t      *frame)
{
    if (cno_frame_handle_padding(conn, frame))
        return CNO_ERROR_UP();

    if (stream == NULL) {
        if (conn->client)
            // servers cannot initiate streams.
            return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "unexpected HEADERS");

        stream = cno_stream_new(conn, frame->stream, CNO_REMOTE);
        if (stream == NULL)
            return CNO_ERROR_UP();

        stream->accept = CNO_ACCEPT_HEADERS | CNO_ACCEPT_WRITE_HEADERS | CNO_ACCEPT_WRITE_PUSH;
    }

    if (stream->accept & CNO_ACCEPT_TRAILERS) {
        stream->accept &= ~CNO_ACCEPT_DATA;

        if (!(frame->flags & CNO_FLAG_END_STREAM))
            return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "trailers without END_STREAM");
    }
    else if (!(stream->accept & CNO_ACCEPT_HEADERS))
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "unexpected HEADERS");

    if (frame->flags & CNO_FLAG_PRIORITY) {
        if (frame->payload.size < 5)
            return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "no priority spec");

        // TODO implement stream prioritization
        frame->payload.data += 5;
        frame->payload.size -= 5;
    }

    conn->continued_flags = frame->flags & CNO_FLAG_END_STREAM;
    conn->continued_stream = stream->id;

    if (cno_buffer_dyn_concat(&conn->continued, frame->payload))
        // no need to cleanup -- compression errors are non-recoverable,
        // everything will be destroyed along with the connection.
        return CNO_ERROR_UP();

    if (frame->flags & CNO_FLAG_END_HEADERS)
        return cno_frame_handle_end_headers(conn, stream, frame);

    return CNO_OK;
}


static int cno_frame_handle_push_promise(struct cno_connection_t *conn,
                                         struct cno_stream_t     *stream,
                                         struct cno_frame_t      *frame)
{
    if (cno_frame_handle_padding(conn, frame))
        return CNO_ERROR_UP();

    if (!conn->settings[CNO_LOCAL].enable_push || !stream || !(stream->accept & CNO_ACCEPT_PUSH))
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "unexpected PUSH_PROMISE");

    if (frame->payload.size < 4)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "PUSH_PROMISE too short");

    uint32_t promised = read4((const uint8_t *) frame->payload.data);

    struct cno_stream_t *child = cno_stream_new(conn, promised, CNO_REMOTE);
    if (child == NULL)
        return CNO_ERROR_UP();

    child->accept = CNO_ACCEPT_HEADERS;
    conn->continued_flags = 0;  // PUSH_PROMISE cannot have END_STREAM
    conn->continued_stream = stream->id;
    conn->continued_promise = promised;

    if (cno_buffer_dyn_concat(&conn->continued, (struct cno_buffer_t) { frame->payload.data + 4,
                                                                        frame->payload.size - 4 }))
        // a compression error. unrecoverable.
        return CNO_ERROR_UP();

    if (frame->flags & CNO_FLAG_END_HEADERS)
        return cno_frame_handle_end_headers(conn, child, frame);
    return CNO_OK;
}


static int cno_frame_handle_continuation(struct cno_connection_t *conn,
                                         struct cno_stream_t     *stream,
                                         struct cno_frame_t      *frame)
{
    if (!stream || !conn->continued_stream)
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "unexpected CONTINUATION");

    // we don't actually count CONTINUATIONs, but this is an ok estimate.
    size_t max_buf_size = (CNO_MAX_CONTINUATIONS + 1) * conn->settings[CNO_LOCAL].max_frame_size;
    if (frame->payload.size + conn->continued.size > max_buf_size)
        // finally a chance to use that error code.
        return cno_frame_write_error(conn, CNO_RST_ENHANCE_YOUR_CALM, "too many HEADERS");

    if (cno_buffer_dyn_concat(&conn->continued, frame->payload))
        return CNO_ERROR_UP();

    frame->flags |= conn->continued_flags;
    if (frame->flags & CNO_FLAG_END_HEADERS)
        return cno_frame_handle_end_headers(conn, stream, frame);
    return CNO_OK;
}


/* ignore non-HEADERS frames on reset streams, as the spec requires. unfortunately,
   these are indistinguishable from streams that were never opened, but hey, what
   can i do, keep a set of uint32_t-s? memory doesn't grow on trees, you know. */
static int cno_frame_handle_invalid_stream(struct cno_connection_t *conn,
                                           struct cno_frame_t *frame)
{
    if (!frame->stream || frame->stream > conn->last_stream[cno_stream_is_local(conn, frame->stream)])
        // definitely idle
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "invalid stream");
    return CNO_OK;
}


static int cno_frame_handle_data(struct cno_connection_t *conn,
                                 struct cno_stream_t     *stream,
                                 struct cno_frame_t      *frame)
{
    uint32_t length = frame->payload.size;

    if (cno_frame_handle_padding(conn, frame))
        return CNO_ERROR_UP();

    if (length) {
        // TODO allow manual flow control
        struct cno_frame_t update = { CNO_FRAME_WINDOW_UPDATE, 0, 0, { PACK(I32(length)) } };

        if (cno_frame_write(conn, &update))
            return CNO_ERROR_UP();
    }

    if (!stream)
        return cno_frame_handle_invalid_stream(conn, frame);

    if (!(stream->accept & CNO_ACCEPT_DATA))
        return cno_frame_write_rst_stream(conn, stream, CNO_RST_STREAM_CLOSED);

    if (CNO_FIRE(conn, on_message_data, frame->stream, frame->payload.data, frame->payload.size))
        return CNO_ERROR_UP();

    if (frame->flags & CNO_FLAG_END_STREAM)
        return cno_frame_handle_end_stream(conn, stream);

    if (!length)
        return CNO_OK;

    struct cno_frame_t update = { CNO_FRAME_WINDOW_UPDATE, 0, stream->id, { PACK(I32(length)) } };
    return cno_frame_write(conn, &update);
}


static int cno_frame_handle_ping(struct cno_connection_t *conn,
                                 struct cno_stream_t     *stream __attribute__((unused)),
                                 struct cno_frame_t      *frame)
{
    if (frame->stream)
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "PING on a stream");

    if (frame->payload.size != 8)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad PING frame");

    if (frame->flags & CNO_FLAG_ACK)
        return CNO_FIRE(conn, on_pong, frame->payload.data);

    struct cno_frame_t response = { CNO_FRAME_PING, CNO_FLAG_ACK, 0, frame->payload };
    return cno_frame_write(conn, &response);
}


static int cno_frame_handle_goaway(struct cno_connection_t *conn,
                                   struct cno_stream_t     *stream __attribute__((unused)),
                                   struct cno_frame_t      *frame)
{
    if (frame->stream)
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "GOAWAY on a stream");

    if (frame->payload.size < 8)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad GOAWAY");

    const uint32_t error = read4((const uint8_t *) frame->payload.data + 4);
    if (error != CNO_RST_NO_ERROR)
        return CNO_ERROR(TRANSPORT, "disconnected with error %u", error);
    return CNO_ERROR(DISCONNECT, "disconnected");
}


static int cno_frame_handle_rst_stream(struct cno_connection_t *conn,
                                       struct cno_stream_t     *stream,
                                       struct cno_frame_t      *frame)
{
    if (!stream)
        return cno_frame_handle_invalid_stream(conn, frame);

    if (frame->payload.size != 4)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad RST_STREAM");

    // TODO parse the error code and do something with it.
    return cno_stream_rst(conn, stream);
}


static int cno_frame_handle_priority(struct cno_connection_t *conn,
                                     struct cno_stream_t     *stream __attribute__((unused)),
                                     struct cno_frame_t      *frame)
{
    if (!frame->stream)
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "PRIORITY on stream 0");

    if (frame->payload.size != 5)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad PRIORITY");

    // TODO implement prioritization
    return CNO_OK;
}


static int cno_frame_handle_settings(struct cno_connection_t *conn,
                                     struct cno_stream_t     *stream __attribute__((unused)),
                                     struct cno_frame_t      *frame)
{
    if (frame->stream)
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "SETTINGS on a stream");

    if (frame->flags & CNO_FLAG_ACK) {
        if (frame->payload.size)
            return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad SETTINGS ack");
        return CNO_OK;
    }

    if (frame->payload.size % 6)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad SETTINGS");

    struct cno_settings_t *cfg = &conn->settings[CNO_REMOTE];
    const uint8_t *ptr = (const uint8_t *) frame->payload.data;
    const uint8_t *end = (const uint8_t *) frame->payload.data + frame->payload.size;

    for (; ptr != end; ptr += 6) {
        uint16_t setting = read2(ptr);
        uint32_t value   = read4(ptr + 2);

        if (setting && setting < CNO_SETTINGS_UNDEFINED)
            cfg->array[setting - 1] = value;
    }

    if (cfg->enable_push > 1)
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "enable_push out of bounds");

    if (cfg->initial_window_size > 0x7fffffff)
        return cno_frame_write_error(conn, CNO_RST_FLOW_CONTROL_ERROR,
                                     "initial_window_size out of bounds");

    if (cfg->max_frame_size < 16384 || cfg->max_frame_size > 16777215)
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "max_frame_size out of bounds");

    conn->encoder.limit_upper = cfg->header_table_size;
    cno_hpack_setlimit(&conn->encoder, conn->encoder.limit_upper);
    // TODO update stream flow control windows.

    struct cno_frame_t ack = { CNO_FRAME_SETTINGS, CNO_FLAG_ACK, 0, CNO_BUFFER_EMPTY };
    if (cno_frame_write(conn, &ack))
        return CNO_ERROR_UP();
    return CNO_FIRE(conn, on_settings);
}


static int cno_frame_handle_window_update(struct cno_connection_t *conn,
                                          struct cno_stream_t     *stream,
                                          struct cno_frame_t      *frame)
{
    if (frame->payload.size != 4)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad WINDOW_UPDATE");

    uint32_t increment = read4((const uint8_t *) frame->payload.data);

    if (increment == 0 || increment > 0x7fffffff)
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "window increment out of bounds");

    if (!frame->stream) {
        if (conn->window_send > 0x7fffffff - (int32_t) increment)
            return cno_frame_write_error(conn, CNO_RST_FLOW_CONTROL_ERROR, "window increment too big");

        conn->window_send += increment;
        // TODO maybe emit an event for each stream with nonzero window instead?
    } else {
        if (stream == NULL)
            return cno_frame_handle_invalid_stream(conn, frame);

        if (stream->window_send > 0x7fffffff - (int32_t) increment)
            return cno_frame_write_rst_stream(conn, stream, CNO_RST_FLOW_CONTROL_ERROR);

        stream->window_send += increment;
        // TODO maybe only emit an event if connection-wide window is nonzero?
    }

    return CNO_FIRE(conn, on_flow_increase, frame->stream);
}


typedef int cno_frame_handler_t(struct cno_connection_t *,
                                struct cno_stream_t     *,
                                struct cno_frame_t      *);


static cno_frame_handler_t *CNO_FRAME_HANDLERS[] = {
    // should be synced to enum CNO_FRAME_TYPE.
    &cno_frame_handle_data,
    &cno_frame_handle_headers,
    &cno_frame_handle_priority,
    &cno_frame_handle_rst_stream,
    &cno_frame_handle_settings,
    &cno_frame_handle_push_promise,
    &cno_frame_handle_ping,
    &cno_frame_handle_goaway,
    &cno_frame_handle_window_update,
    &cno_frame_handle_continuation,
};


static int cno_frame_handle(struct cno_connection_t *conn, struct cno_frame_t *frame)
{
    if (conn->continued_stream)
        if (frame->type != CNO_FRAME_CONTINUATION || frame->stream != conn->continued_stream)
            return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "expected a CONTINUATION");

    if (frame->type >= CNO_FRAME_UNKNOWN)
        return CNO_OK;

    struct cno_stream_t *stream = cno_stream_find(conn, frame->stream);
    return CNO_FRAME_HANDLERS[frame->type](conn, stream, frame);
}


int cno_connection_set_config(struct cno_connection_t *conn, const struct cno_settings_t *settings)
{
    if (settings->enable_push != 0 && settings->enable_push != 1)
        return CNO_ERROR(ASSERTION, "enable_push neither 0 nor 1");

    if (settings->max_frame_size < 16384 || settings->max_frame_size > 16777215)
        return CNO_ERROR(ASSERTION, "maximum frame size out of bounds (2^14..2^24-1)");

    if (conn->state != CNO_CONNECTION_INIT && cno_connection_is_http2(conn))
        // If not yet in HTTP2 mode, `cno_connection_upgrade` will send the SETTINGS frame.
        if (cno_frame_write_settings(conn, &conn->settings[CNO_LOCAL], settings))
            return CNO_ERROR_UP();

    memcpy(&conn->settings[CNO_LOCAL], settings, sizeof(*settings));
    conn->decoder.limit_upper = settings->header_table_size;
    // TODO the difference in initial flow control window size should be subtracted
    //      from the flow control window size of all active streams.
    return CNO_OK;
}


void cno_connection_init(struct cno_connection_t *conn, enum CNO_CONNECTION_KIND kind)
{
    *conn = (struct cno_connection_t) {
        .client      = CNO_CLIENT == kind,
        .state       = CNO_CONNECTION_UNDEFINED,
        .window_recv = CNO_SETTINGS_STANDARD.initial_window_size,
        .window_send = CNO_SETTINGS_STANDARD.initial_window_size,
        .settings    = { /* remote = */ CNO_SETTINGS_CONSERVATIVE,
                         /* local  = */ CNO_SETTINGS_INITIAL, },
    };

    cno_hpack_init(&conn->decoder, CNO_SETTINGS_INITIAL .header_table_size);
    cno_hpack_init(&conn->encoder, CNO_SETTINGS_STANDARD.header_table_size);
}


void cno_connection_reset(struct cno_connection_t *conn)
{
    cno_buffer_dyn_clear(&conn->buffer);
    cno_buffer_dyn_clear(&conn->continued);
    cno_hpack_clear(&conn->encoder);
    cno_hpack_clear(&conn->decoder);

    for (int i = 0; i < CNO_STREAM_BUCKETS; i++)
        while (conn->streams[i])
            cno_stream_free(conn, conn->streams[i]);
}


int cno_connection_is_http2(struct cno_connection_t *conn)
{
    return conn->state != CNO_CONNECTION_HTTP1_INIT &&
           conn->state != CNO_CONNECTION_HTTP1_READY &&
           conn->state != CNO_CONNECTION_HTTP1_READING &&
           conn->state != CNO_CONNECTION_UNDEFINED;
}


static int cno_connection_upgrade(struct cno_connection_t *conn)
{
    if (conn->client && CNO_FIRE(conn, on_write, CNO_PREFACE.data, CNO_PREFACE.size))
        return CNO_ERROR_UP();

    return cno_frame_write_settings(conn, &CNO_SETTINGS_STANDARD, &conn->settings[CNO_LOCAL]);
}


static int cno_connection_proceed(struct cno_connection_t *conn)
{
    while (1) switch (conn->state) {
        case CNO_CONNECTION_UNDEFINED:
            return CNO_OK;  // wait until connection_made before processing data

        case CNO_CONNECTION_HTTP1_INIT:
            conn->state = CNO_CONNECTION_HTTP1_READY;

            struct cno_stream_t *stream = cno_stream_new(conn, 1, conn->client);
            if (stream == NULL)
                return CNO_ERROR_UP();
            stream->accept = conn->client ? CNO_ACCEPT_WRITE_HEADERS : CNO_ACCEPT_HEADERS;

            break;

        case CNO_CONNECTION_HTTP1_READY: {
            {   // ignore leading crlf-s.
                char *buf = conn->buffer.data;
                char *end = conn->buffer.size + buf;
                while (buf != end && (*buf == '\r' || *buf == '\n')) ++buf;
                cno_buffer_dyn_shift(&conn->buffer, buf - conn->buffer.data);
            }

            if (!conn->buffer.size)
                return CNO_OK;

            struct cno_stream_t *stream = cno_stream_find(conn, 1);
            if (stream == NULL)
                return CNO_ERROR(ASSERTION, "connection is HTTP/1.x but stream 1 does not exist");
            if (!(stream->accept & CNO_ACCEPT_HEADERS))
                return CNO_ERROR(TRANSPORT, "server sent an HTTP/1.x response, but there was no request");

            // the http 2 client preface looks like an http 1 request, but is not.
            // picohttpparser will reject it. (note: CNO_PREFACE is null-terminated.)
            if (!conn->client && !strncmp(conn->buffer.data, CNO_PREFACE.data, conn->buffer.size)) {
                if (conn->buffer.size < CNO_PREFACE.size)
                    return CNO_OK;

                conn->state = CNO_CONNECTION_INIT;
                conn->last_stream[CNO_REMOTE] = 0;
                conn->last_stream[CNO_LOCAL]  = 0;

                if (cno_stream_rst(conn, stream))
                    return CNO_ERROR_UP();
                break;
            }

            struct cno_message_t msg = { 0, CNO_BUFFER_EMPTY, CNO_BUFFER_EMPTY, NULL, CNO_MAX_HEADERS };
            struct phr_header headers_phr[CNO_MAX_HEADERS];

            int minor;
            int ok = conn->client
              ? phr_parse_response(conn->buffer.data, conn->buffer.size, &minor, &msg.code,
                    &msg.method.data, &msg.method.size,
                    headers_phr, &msg.headers_len, 1)

              : phr_parse_request(conn->buffer.data, conn->buffer.size,
                    &msg.method.data, &msg.method.size,
                    &msg.path.data, &msg.path.size,
                    &minor, headers_phr, &msg.headers_len, 1);

            if (ok == -2) {
                if (conn->buffer.size > CNO_MAX_CONTINUATIONS * conn->settings[CNO_LOCAL].max_frame_size)
                    return CNO_ERROR(TRANSPORT, "HTTP/1.x message too big");
                return CNO_OK;
            }

            if (ok == -1)
                return CNO_ERROR(TRANSPORT, "bad HTTP/1.x message");

            if (minor != 0 && minor != 1)
                return CNO_ERROR(TRANSPORT, "HTTP/1.%d not supported", minor);

            struct cno_header_t headers[msg.headers_len];
            struct cno_header_t *it = msg.headers = headers;

            conn->http1_remaining = 0;

            for (size_t i = 0; i < msg.headers_len; i++, it++) {
                *it = (struct cno_header_t) {
                    { headers_phr[i].name,  headers_phr[i].name_len  },
                    { headers_phr[i].value, headers_phr[i].value_len },
                    0
                };

                {
                    char * ptr = (char *) it->name.data;
                    char * end = (char *) it->name.data + it->name.size;
                    for (; ptr != end; ptr++) *ptr = tolower(*ptr);
                }

                if (cno_buffer_eq(it->name, CNO_BUFFER_STRING("http2-settings"))) {
                    // TODO decode & emit on_frame
                } else

                if (!conn->client && cno_buffer_eq(it->name,  CNO_BUFFER_STRING("upgrade"))
                                  && cno_buffer_eq(it->value, CNO_BUFFER_STRING("h2c"))) {
                    if (conn->state != CNO_CONNECTION_HTTP1_READY)
                        return CNO_ERROR(TRANSPORT, "bad HTTP/1.x message: multiple upgrade headers");

                    struct cno_header_t upgrade_headers[] = {
                        { CNO_BUFFER_STRING("connection"), CNO_BUFFER_STRING("upgrade"), 0 },
                        { CNO_BUFFER_STRING("upgrade"),    CNO_BUFFER_STRING("h2c"),     0 },
                    };

                    struct cno_message_t upgrade_msg = { 101, CNO_BUFFER_EMPTY, CNO_BUFFER_EMPTY, upgrade_headers, 2 };

                    if (cno_write_message(conn, 1, &upgrade_msg, 1))
                        return CNO_ERROR_UP();

                    // if we send the preface now, we'll be able to send HTTP 2 frames
                    // while in the HTTP1_READING_UPGRADE state.
                    if (cno_connection_upgrade(conn))
                        return CNO_ERROR_UP();

                    // technically, server should refuse if HTTP2-Settings are not present.
                    // we'll let this slide.
                    conn->state = CNO_CONNECTION_HTTP1_READING_UPGRADE;
                } else

                if (cno_buffer_eq(it->name, CNO_BUFFER_STRING("content-length"))) {
                    if (conn->http1_remaining)
                        return CNO_ERROR(TRANSPORT, "bad HTTP/1.x message: multiple content-lengths");

                    const char *ptr = it->value.data;
                    const char *end = it->value.data + it->value.size;

                    while (ptr != end)
                        if ('0' <= *ptr && *ptr <= '9')
                            conn->http1_remaining = conn->http1_remaining * 10 + (*ptr++ - '0');
                        else
                            return CNO_ERROR(TRANSPORT, "bad HTTP/1.x message: non-int length");
                } else

                if (cno_buffer_eq(it->name, CNO_BUFFER_STRING("transfer-encoding"))) {
                    if (!cno_buffer_eq(it->value, CNO_BUFFER_STRING("identity")))
                        conn->http1_remaining = (uint32_t) -1;
                }
            }

            stream->accept &= ~CNO_ACCEPT_HEADERS;
            stream->accept |= CNO_ACCEPT_WRITE_HEADERS | CNO_ACCEPT_DATA;

            if (conn->state == CNO_CONNECTION_HTTP1_READY)
                conn->state = CNO_CONNECTION_HTTP1_READING;

            cno_buffer_dyn_shift(&conn->buffer, (size_t) ok);

            if (CNO_FIRE(conn, on_message_start, stream->id, &msg))
                return CNO_ERROR_UP();

            break;
        }

        case CNO_CONNECTION_HTTP1_READING:
        case CNO_CONNECTION_HTTP1_READING_UPGRADE: {
            struct cno_stream_t *stream = cno_stream_find(conn, 1);
            if (!stream)
                return CNO_ERROR(ASSERTION, "connection in HTTP/1.x mode but stream 1 does not exist");
            if (!(stream->accept & CNO_ACCEPT_DATA))
                return CNO_ERROR(ASSERTION, "connection expects HTTP/1.x message body, but stream 1 does not");

            if (!conn->http1_remaining) {
                if (conn->state != CNO_CONNECTION_HTTP1_READING_UPGRADE)
                    stream->accept |= CNO_ACCEPT_HEADERS; // TODO: trailers?
                const int destroy = !(stream->accept &= ~CNO_ACCEPT_DATA);

                conn->state = conn->state == CNO_CONNECTION_HTTP1_READING_UPGRADE
                    ? CNO_CONNECTION_PREFACE
                    : CNO_CONNECTION_HTTP1_READY;

                if (CNO_FIRE(conn, on_message_end, stream->id))
                    return CNO_ERROR_UP();
                if (destroy && cno_stream_rst(conn, stream))
                    return CNO_ERROR_UP();
                break;
            }

            if (!conn->buffer.size)
                return CNO_OK;

            if (conn->http1_remaining == (uint32_t) -1) {
                char *eol = memchr(conn->buffer.data, '\n', conn->buffer.size);

                if (eol++ == NULL)
                    return CNO_OK;

                size_t length = strtoul(conn->buffer.data, NULL, 16);
                size_t total  = length + (eol - conn->buffer.data) + 2;  // + crlf after data

                if (conn->buffer.size < total)
                    return CNO_OK;

                cno_buffer_dyn_shift(&conn->buffer, total);

                if (!length)
                    conn->http1_remaining = 0;
                else if (CNO_FIRE(conn, on_message_data, stream->id, eol, length))
                    return CNO_ERROR_UP();

                break;
            }

            struct cno_buffer_t b = { conn->buffer.data, conn->buffer.size };

            if (b.size > conn->http1_remaining)
                b.size = conn->http1_remaining;

            conn->http1_remaining -= b.size;
            cno_buffer_dyn_shift(&conn->buffer, b.size);

            if (CNO_FIRE(conn, on_message_data, stream->id, b.data, b.size))
                return CNO_ERROR_UP();
            break;
        }

        case CNO_CONNECTION_INIT:
            conn->state = CNO_CONNECTION_PREFACE;

            if (cno_connection_upgrade(conn))
                return CNO_ERROR_UP();

            break;

        case CNO_CONNECTION_PREFACE:
            if (!conn->client) {
                if (conn->buffer.size < CNO_PREFACE.size)
                    return CNO_OK;

                if (strncmp(conn->buffer.data, CNO_PREFACE.data, CNO_PREFACE.size))
                    return CNO_ERROR(TRANSPORT, "invalid HTTP 2 client preface");

                cno_buffer_dyn_shift(&conn->buffer, CNO_PREFACE.size);
            }

            conn->state = CNO_CONNECTION_READY_NO_SETTINGS;
            break;

        case CNO_CONNECTION_READY_NO_SETTINGS:
        case CNO_CONNECTION_READY: {
            if (conn->buffer.size < 9)
                return CNO_OK;

            const uint8_t *base = (const uint8_t *) conn->buffer.data;
            const size_t m = read3(base);

            if (m > conn->settings[CNO_LOCAL].max_frame_size)
                return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "frame too big");

            if (conn->buffer.size < 9 + m)
                return CNO_OK;

            struct cno_frame_t frame = { read1(&base[3]), read1(&base[4]), read4(&base[5]), { (const char *) &base[9], m } };

            if (conn->state == CNO_CONNECTION_READY_NO_SETTINGS && frame.type != CNO_FRAME_SETTINGS)
                return CNO_ERROR(TRANSPORT, "invalid HTTP 2 preface: no initial SETTINGS");

            conn->state = CNO_CONNECTION_READY;
            cno_buffer_dyn_shift(&conn->buffer, 9 + m);

            if (CNO_FIRE(conn, on_frame, &frame))
                return CNO_ERROR_UP();

            if (cno_frame_handle(conn, &frame))
                return CNO_ERROR_UP();

            break;
        }
    }
}


int cno_connection_made(struct cno_connection_t *conn, enum CNO_HTTP_VERSION version)
{
    if (conn->state != CNO_CONNECTION_UNDEFINED)
        return CNO_ERROR(ASSERTION, "called connection_made twice");

    conn->state = version == CNO_HTTP2 ? CNO_CONNECTION_INIT : CNO_CONNECTION_HTTP1_INIT;
    return cno_connection_proceed(conn);
}


int cno_connection_data_received(struct cno_connection_t *conn, const char *data, size_t length)
{
    if (conn->state == CNO_CONNECTION_UNDEFINED)
        return CNO_ERROR(DISCONNECT, "connection closed");

    if (cno_buffer_dyn_concat(&conn->buffer, (struct cno_buffer_t) { data, length }))
        return CNO_ERROR_UP();

    return cno_connection_proceed(conn);
}


int cno_connection_stop(struct cno_connection_t *conn)
{
    if (cno_connection_is_http2(conn))
        return cno_frame_write_goaway(conn, CNO_RST_NO_ERROR);

    return CNO_OK;
}


int cno_connection_lost(struct cno_connection_t *conn)
{
    conn->state = CNO_CONNECTION_UNDEFINED;

    struct cno_stream_t **s;

    for (s = &conn->streams[0]; s != &conn->streams[CNO_STREAM_BUCKETS]; s++)
        while (*s)
            if (cno_stream_rst(conn, *s))
                return CNO_ERROR_UP();

    cno_buffer_dyn_clear(&conn->buffer);
    cno_buffer_dyn_clear(&conn->continued);
    cno_hpack_clear(&conn->encoder);
    cno_hpack_clear(&conn->decoder);
    return CNO_OK;
}


uint32_t cno_connection_next_stream(struct cno_connection_t *conn)
{
    if (!cno_connection_is_http2(conn))
        return 1;

    uint32_t last = conn->last_stream[CNO_LOCAL];
    return conn->client && !last ? 1 : last + 2;
}


int cno_write_reset(struct cno_connection_t *conn, uint32_t stream, enum CNO_RST_STREAM_CODE code)
{
    if (!cno_connection_is_http2(conn))
        return CNO_ERROR(DISCONNECT, "HTTP/1.x connection rejected");

    struct cno_stream_t *obj = cno_stream_find(conn, stream);
    if (!obj)
        return CNO_OK;  // assume it has already been reset
    return cno_frame_write_rst_stream(conn, obj, code);
}


int cno_write_push(struct cno_connection_t *conn, uint32_t stream, const struct cno_message_t *msg)
{
    if (conn->state == CNO_CONNECTION_UNDEFINED)
        return CNO_ERROR(DISCONNECT, "connection closed");

    if (conn->client)
        return CNO_ERROR(ASSERTION, "clients can't push");

    if (!cno_connection_is_http2(conn) || !conn->settings[CNO_REMOTE].enable_push)
        return CNO_OK;

    struct cno_stream_t *streamobj = cno_stream_find(conn, stream);

    if (streamobj == NULL)
        return CNO_ERROR(INVALID_STREAM, "push to a nonexistent stream");

    if (!(streamobj->accept & CNO_ACCEPT_WRITE_PUSH))
        return CNO_OK;  // pushed requests are safe, so whether we send one doesn't matter

    uint32_t child = cno_connection_next_stream(conn);

    struct cno_stream_t *childobj = cno_stream_new(conn, child, CNO_LOCAL);

    if (childobj == NULL)
        return CNO_ERROR_UP();

    childobj->accept = CNO_ACCEPT_WRITE_HEADERS;

    struct cno_buffer_dyn_t payload = CNO_BUFFER_DYN_EMPTY;
    struct cno_frame_t frame = { CNO_FRAME_PUSH_PROMISE, CNO_FLAG_END_HEADERS, stream, CNO_BUFFER_EMPTY };
    struct cno_header_t head[2] = {
        { CNO_BUFFER_STRING(":method"), msg->method, 0 },
        { CNO_BUFFER_STRING(":path"),   msg->path,   0 },
    };

    if (cno_buffer_dyn_concat(&payload, (struct cno_buffer_t) { PACK(I32(child)) })
    ||  cno_hpack_encode(&conn->encoder, &payload, head, 2)
    ||  cno_hpack_encode(&conn->encoder, &payload, msg->headers, msg->headers_len))
        goto payload_generation_error;

    frame.payload = payload.as_static;

    if (cno_frame_write(conn, &frame))
        goto payload_generation_error;

    cno_buffer_dyn_clear(&payload);

    return CNO_FIRE(conn, on_message_start, child, msg)
        || CNO_FIRE(conn, on_message_end,   child);

payload_generation_error:
    cno_buffer_dyn_clear(&payload);
    return CNO_ERROR_UP();
}


int cno_write_message(struct cno_connection_t *conn, uint32_t stream, const struct cno_message_t *msg, int final)
{
    if (conn->state == CNO_CONNECTION_UNDEFINED)
        return CNO_ERROR(DISCONNECT, "connection closed");

    if (!cno_connection_is_http2(conn)) {
        if (stream != 1)
            return CNO_ERROR(INVALID_STREAM, "can only write to stream 1 in HTTP 1 mode");

        char buffer[CNO_MAX_HTTP1_HEADER_SIZE + 3];
        int size;

        if (conn->client)
            size = snprintf(buffer, sizeof(buffer), "%.*s %.*s HTTP/1.1\r\n",
                (int) msg->method.size, msg->method.data,
                (int) msg->path.size,   msg->path.data);
        else
            size = snprintf(buffer, sizeof(buffer), "HTTP/1.1 %d Something\r\n", msg->code);

        if (size > CNO_MAX_HTTP1_HEADER_SIZE)
            return CNO_ERROR(ASSERTION, "method/path too big");

        struct cno_header_t *it  = msg->headers;
        struct cno_header_t *end = msg->headers_len + it;
        int had_connection_header = 0;

        if (final)
            conn->flags &= ~CNO_CONN_FLAG_WRITING_CHUNKED;
        else
            conn->flags |= CNO_CONN_FLAG_WRITING_CHUNKED;

        for (; it != end; ++it) {
            if (size && CNO_FIRE(conn, on_write, buffer, size))
                return CNO_ERROR_UP();

            if (cno_buffer_eq(it->name, CNO_BUFFER_STRING(":authority")))
                size = snprintf(buffer, sizeof(buffer), "host: %.*s\r\n",
                    (int) it->value.size, it->value.data);

            else if (cno_buffer_startswith(it->name, CNO_BUFFER_STRING(":")))
                size = 0;

            else {
                size = snprintf(buffer, sizeof(buffer), "%.*s: %.*s\r\n",
                    (int) it->name.size,  it->name.data,
                    (int) it->value.size, it->value.data);

                if (cno_buffer_eq(it->name, CNO_BUFFER_STRING("connection")))
                    had_connection_header = 1;

                else if (cno_buffer_eq(it->name, CNO_BUFFER_STRING("content-length"))
                     ||  cno_buffer_eq(it->name, CNO_BUFFER_STRING("transfer-encoding")))
                    conn->flags &= ~CNO_CONN_FLAG_WRITING_CHUNKED;
            }

            if (size > CNO_MAX_HTTP1_HEADER_SIZE)
                return CNO_ERROR(ASSERTION, "header too big\r\n");
        }

        if (conn->flags & CNO_CONN_FLAG_WRITING_CHUNKED) {
            if (size && CNO_FIRE(conn, on_write, buffer, size))
                return CNO_ERROR_UP();

            size = snprintf(buffer, sizeof(buffer), "transfer-encoding: chunked\r\n");
        }

        if (!had_connection_header) {
            if (size && CNO_FIRE(conn, on_write, buffer, size))
                return CNO_ERROR_UP();

            size = snprintf(buffer, sizeof(buffer), "connection: keep-alive\r\n");
        }

        buffer[size + 0] = '\r';
        buffer[size + 1] = '\n';
        if (final && conn->client)
            cno_stream_find(conn, 1)->accept |= CNO_ACCEPT_HEADERS;
        return CNO_FIRE(conn, on_write, buffer, size + 2);
    }

    struct cno_stream_t *streamobj = cno_stream_find(conn, stream);

    if (streamobj == NULL) {
        if (!conn->client)
            return CNO_ERROR(INVALID_STREAM, "cannot respond to an idle stream");

        streamobj = cno_stream_new(conn, stream, CNO_LOCAL);

        if (streamobj == NULL)
            return CNO_ERROR_UP();

        streamobj->accept = CNO_ACCEPT_HEADERS | CNO_ACCEPT_PUSH | CNO_ACCEPT_WRITE_HEADERS;
    }

    if (!(streamobj->accept & CNO_ACCEPT_WRITE_HEADERS))
        return CNO_ERROR(INVALID_STREAM, "this stream is not writable");

    struct cno_buffer_dyn_t payload = CNO_BUFFER_DYN_EMPTY;
    struct cno_frame_t frame = { CNO_FRAME_HEADERS, CNO_FLAG_END_HEADERS, stream, CNO_BUFFER_EMPTY };

    if (final)
        frame.flags |= CNO_FLAG_END_STREAM;

    if (conn->client) {
        struct cno_header_t head[] = {
            { CNO_BUFFER_STRING(":method"), msg->method, 0 },
            { CNO_BUFFER_STRING(":path"),   msg->path,   0 },
        };

        if (cno_hpack_encode(&conn->encoder, &payload, head, 2))
            goto payload_generation_error;
    } else {
        char code[8];
        snprintf(code, sizeof(code), "%d", msg->code);

        struct cno_header_t head[] = {
            { CNO_BUFFER_STRING(":status"), CNO_BUFFER_STRING(code), 0 }
        };

        if (cno_hpack_encode(&conn->encoder, &payload, head, 1))
            goto payload_generation_error;
    }


    if (cno_hpack_encode(&conn->encoder, &payload, msg->headers, msg->headers_len))
        goto payload_generation_error;

    frame.payload = payload.as_static;

    if (cno_frame_write(conn, &frame))
        goto payload_generation_error;

    cno_buffer_dyn_clear(&payload);

    if (!final) {
        streamobj->accept &= ~CNO_ACCEPT_WRITE_HEADERS;
        streamobj->accept |=  CNO_ACCEPT_WRITE_DATA;
        return CNO_OK;
    }

    if (!(streamobj->accept &= ~CNO_ACCEPT_OUTBOUND))
        return cno_stream_rst(conn, streamobj);

    return CNO_OK;

payload_generation_error:
    cno_buffer_dyn_clear(&payload);
    return CNO_ERROR_UP();
}


int cno_write_data(struct cno_connection_t *conn, uint32_t stream, const char *data, size_t length, int final)
{
    if (conn->state == CNO_CONNECTION_UNDEFINED)
        return CNO_ERROR(DISCONNECT, "connection closed");

    if (!cno_connection_is_http2(conn)) {
        int chunked = conn->flags & CNO_CONN_FLAG_WRITING_CHUNKED;

        if (stream != 1)
            return CNO_ERROR(INVALID_STREAM, "can only write to stream 1 in HTTP 1 mode");

        if (length) {
            if (chunked) {
                char lenbuf[16];

                if (CNO_FIRE(conn, on_write, lenbuf, snprintf(lenbuf, sizeof(lenbuf), "%zX\r\n", length)))
                    return CNO_ERROR_UP();
            }

            if (CNO_FIRE(conn, on_write, data, length))
                return CNO_ERROR_UP();

            if (chunked && CNO_FIRE(conn, on_write, "\r\n", 2))
                return CNO_ERROR_UP();
        }

        if (final && chunked) {
            if (CNO_FIRE(conn, on_write, "0\r\n\r\n", 5))
                return CNO_ERROR_UP();
        }

        return length;
    }

    struct cno_stream_t *streamobj = cno_stream_find(conn, stream);

    if (streamobj == NULL)
        return CNO_ERROR(INVALID_STREAM, "stream does not exist");

    if (!(streamobj->accept & CNO_ACCEPT_WRITE_DATA))
        return CNO_ERROR(INVALID_STREAM, "this stream is not writable");

    if (conn->window_send < 0 || streamobj->window_send < 0)
        return 0;

    if (length > (uint32_t) conn->window_send) {
        length = (uint32_t) conn->window_send;
        final  = 0;
    }

    if (length > (uint32_t) streamobj->window_send) {
        length = (uint32_t) streamobj->window_send;
        final  = 0;
    }

    if (!length && !final)
        return 0;

    struct cno_frame_t frame = { CNO_FRAME_DATA, final ? CNO_FLAG_END_STREAM : 0, stream, { data, length } };

    if (cno_frame_write(conn, &frame))
        return CNO_ERROR_UP();

    conn->window_send -= length;
    streamobj->window_send -= length;

    if (final)
        if (!(streamobj->accept &= ~CNO_ACCEPT_OUTBOUND))
            if (cno_stream_rst(conn, streamobj))
                return CNO_ERROR_UP();

    return length;
}

// (the difference is that `conn` is non-const.)
int cno_write_frame(struct cno_connection_t *conn, const struct cno_frame_t *frame) {
    return cno_frame_write(conn, frame);
}
