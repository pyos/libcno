#include <ctype.h>
#include <stdio.h>

#include "core.h"
#include "../picohttpparser/picohttpparser.h"

// Endian-independent fixed-size reads. (These actually compile to efficient code.)
// `read3` is kind of unsafe because it reads 4, but it's only used in one place where there
// is at least 9 bytes available, so whatever.
static inline uint8_t  read1(const uint8_t *p) { return p[0]; }
static inline uint16_t read2(const uint8_t *p) { return p[0] <<  8 | p[1]; }
static inline uint32_t read4(const uint8_t *p) { return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }
static inline uint32_t read3(const uint8_t *p) { return read4(p) >> 8; }

// Construct a stack-allocated array of bytes in place.
#define PACK(...) ((struct cno_buffer_t) { (char *) (uint8_t []) { __VA_ARGS__ }, sizeof((uint8_t []) { __VA_ARGS__ }) })
#define I8(x)  (x)
#define I16(x) (x) >> 8,  (x)
#define I24(x) (x) >> 16, (x) >> 8,  (x)
#define I32(x) (x) >> 24, (x) >> 16, (x) >> 8, (x)

#define CNO_FIRE(ob, cb, ...) (ob->cb && ob->cb(ob->cb_data, ##__VA_ARGS__))

// Fake http "request" sent by the client at the beginning of a connection.
static const struct cno_buffer_t CNO_PREFACE = { "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24 };

// Standard-defined pre-initial-SETTINGS values
static const struct cno_settings_t CNO_SETTINGS_STANDARD = {{{
    .header_table_size      = 4096,
    .enable_push            = 1,
    .max_concurrent_streams = -1,
    .initial_window_size    = 65535,
    .max_frame_size         = 16384,
    .max_header_list_size   = -1,
}}};

// A somewhat more conservative version assumed to be used by the remote side at first.
// (In case we want to send some frames before ACK-ing the remote settings, but don't want to get told.)
static const struct cno_settings_t CNO_SETTINGS_CONSERVATIVE = {{{
    .header_table_size      = 4096,
    .enable_push            = 0,
    .max_concurrent_streams = 100,
    .initial_window_size    = 65535,
    .max_frame_size         = 16384,
    .max_header_list_size   = -1,
}}};

// Actual values to send in the first SETTINGS frame.
static const struct cno_settings_t CNO_SETTINGS_INITIAL = {{{
    .header_table_size      = 4096,
    .enable_push            = 1,
    .max_concurrent_streams = 1024,
    .initial_window_size    = 65535,
    .max_frame_size         = 16384,
    .max_header_list_size   = -1, // actually (CNO_MAX_CONTINUATIONS * max_frame_size - 32 * CNO_MAX_HEADERS)
}}};

// Even streams are initiated by the server, odd streams by the client.
static int cno_stream_is_local(const struct cno_connection_t *conn, uint32_t id)
{
    return id % 2 == conn->client;
}

static struct cno_stream_t * cno_stream_new(struct cno_connection_t *conn, uint32_t id, int local)
{
    if (cno_stream_is_local(conn, id) != local)
        return (local ? CNO_ERROR(INVALID_STREAM, "incorrect stream id parity")
                      : CNO_ERROR(PROTOCOL, "incorrect stream id parity")), NULL;

    if (cno_connection_is_http2(conn)) {
        if (id <= conn->last_stream[local])
            return (local ? CNO_ERROR(INVALID_STREAM, "nonmonotonic stream id")
                          : CNO_ERROR(PROTOCOL, "nonmonotonic stream id")), NULL;
    } else if (id != 1) {
        return CNO_ERROR(INVALID_STREAM, "HTTP/1.x has only one stream"), NULL;
    }

    if (conn->stream_count[local] >= conn->settings[!local].max_concurrent_streams)
        return (local ? CNO_ERROR(WOULD_BLOCK, "wait for on_stream_end")
                      : CNO_ERROR(PROTOCOL, "peer exceeded stream limit")), NULL;

    struct cno_stream_t *stream = malloc(sizeof(struct cno_stream_t));
    if (!stream)
        return CNO_ERROR(NO_MEMORY, "%zu bytes", sizeof(struct cno_stream_t)), NULL;

    *stream = (struct cno_stream_t) {
        .id          = conn->last_stream[local] = id,
        .next        = conn->streams[id % CNO_STREAM_BUCKETS],
        .window_recv = conn->settings[CNO_LOCAL] .initial_window_size,
        .window_send = conn->settings[CNO_REMOTE].initial_window_size,
    };

    // Gotta love C for not having any standard library to speak of.
    conn->streams[id % CNO_STREAM_BUCKETS] = stream;
    conn->stream_count[local]++;

    if (CNO_FIRE(conn, on_stream_start, id)) {
        conn->streams[id % CNO_STREAM_BUCKETS] = stream->next;
        conn->stream_count[local]--;
        free(stream);
        return CNO_ERROR_UP(), NULL;
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
    struct cno_stream_t **s = &conn->streams[stream->id % CNO_STREAM_BUCKETS];
    while (*s != stream) s = &(*s)->next;
    *s = stream->next;

    conn->stream_count[cno_stream_is_local(conn, stream->id)]--;
    free(stream);
}

static int cno_stream_end(struct cno_connection_t *conn, struct cno_stream_t *stream)
{
    uint32_t id = stream->id;
    cno_stream_free(conn, stream);
    return CNO_FIRE(conn, on_stream_end, id);
}

static int cno_stream_end_by_local(struct cno_connection_t *conn, struct cno_stream_t *stream)
{
    // HEADERS, DATA, WINDOW_UPDATE, and RST_STREAM may arrive on streams we have already reset
    // simply because the other side sent the frames before receiving ours. This is not
    // a protocol error according to the standard. (FIXME kinda broken with trailers...)
    if (stream->accept & (CNO_ACCEPT_HEADERS | CNO_ACCEPT_DATA)) {
        // Very convenient that this bit is reserved. (For what, we shall never know.)
        uint32_t is_headers = !!(stream->accept & CNO_ACCEPT_HEADERS);
        conn->recently_reset[conn->recently_reset_next++] = stream->id | is_headers << 31;
        conn->recently_reset_next %= CNO_STREAM_RESET_HISTORY;
    }
    return cno_stream_end(conn, stream);
}

static int cno_writev(const struct cno_connection_t *conn, const struct cno_buffer_t *iov, size_t iovcnt)
{
    if (conn->on_writev)
        return conn->on_writev(conn->cb_data, iov, iovcnt);
    if (conn->on_write)
        for (; iovcnt--; iov++)
            if (iov->size && conn->on_write(conn->cb_data, iov->data, iov->size))
                return CNO_ERROR_UP();
    return CNO_OK;
}

#define CNO_WRITEV(conn, ...) cno_writev(conn, (struct cno_buffer_t[]){__VA_ARGS__}, \
    sizeof((struct cno_buffer_t[]){__VA_ARGS__}) / sizeof(struct cno_buffer_t))

// Send a single non-flow-controlled* frame, splitting DATA/HEADERS if they are too big.
// (*meaning that it isn't counted; in case of DATA, this must be done by the caller.)
static int cno_frame_write(const struct cno_connection_t *conn,
                           const struct cno_frame_t      *frame)
{
    size_t length = frame->payload.size;
    size_t limit  = conn->settings[CNO_REMOTE].max_frame_size;

    if (length <= limit)
        return CNO_WRITEV(conn, PACK(I24(length), I8(frame->type), I8(frame->flags), I32(frame->stream)), frame->payload);

    if (frame->type != CNO_FRAME_HEADERS && frame->type != CNO_FRAME_PUSH_PROMISE && frame->type != CNO_FRAME_DATA)
        // A really unexpected outcome, considering that the *lowest possible* limit is 16 KiB.
        return CNO_ERROR(ASSERTION, "control frame too big");

    if (frame->flags & CNO_FLAG_PADDED)
        // TODO split padded frames.
        return CNO_ERROR(NOT_IMPLEMENTED, "don't know how to split padded frames");

    struct cno_frame_t part = *frame;
    part.payload.size = limit;
    // When splitting HEADERS/PUSH_PROMISE, the last CONTINUATION must carry the END_HEADERS flag,
    // but the HEADERS frame itself retains END_STREAM if set. When splitting DATA,
    // END_STREAM must be moved to the last frame in the sequence.
    uint8_t carry = frame->flags & (frame->type == CNO_FRAME_DATA ? CNO_FLAG_END_STREAM : CNO_FLAG_END_HEADERS);
    part.flags &= ~carry;

    for (; length > limit; length -= limit, part.payload.data += limit) {
        if (cno_frame_write(conn, &part))
            return CNO_ERROR_UP();
        if (part.type != CNO_FRAME_DATA)
            part.type = CNO_FRAME_CONTINUATION;
        part.flags &= ~(CNO_FLAG_PRIORITY | CNO_FLAG_END_STREAM);
    }

    part.flags |= carry;
    part.payload.size = length;
    return cno_frame_write(conn, &part);
}

static int cno_frame_write_goaway(struct cno_connection_t *conn,
                                  uint32_t /* enum CNO_RST_STREAM_CODE */ code)
{
    if (!conn->goaway_sent)
        conn->goaway_sent = conn->last_stream[CNO_REMOTE];
    struct cno_frame_t error = { CNO_FRAME_GOAWAY, 0, 0, PACK(I32(conn->goaway_sent), I32(code)) };
    return cno_frame_write(conn, &error);
}

// Shut down a connection and *then* throw a PROTOCOL error.
#define cno_frame_write_error(conn, type, ...) \
    (cno_frame_write_goaway(conn, type) ? CNO_ERROR_UP() : CNO_ERROR(PROTOCOL, __VA_ARGS__))

// Ignore frames on reset streams, as the spec requires. See `cno_stream_end_by_local`.
static int cno_frame_handle_invalid_stream(struct cno_connection_t *conn,
                                           struct cno_frame_t      *frame)
{
    if (frame->stream && frame->stream <= conn->last_stream[cno_stream_is_local(conn, frame->stream)])
        for (uint8_t i = 0; i < CNO_STREAM_RESET_HISTORY; i++)
            if ((frame->type != CNO_FRAME_HEADERS && conn->recently_reset[i] == frame->stream)
             || (frame->type != CNO_FRAME_DATA && conn->recently_reset[i] == (frame->stream | (1ul << 31))))
                return CNO_OK;
    return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "invalid stream");
}

// Send a delta between two configs as a SETTINGS frame.
static int cno_frame_write_settings(const struct cno_connection_t *conn,
                                    const struct cno_settings_t   *previous,
                                    const struct cno_settings_t   *current)
{
    uint8_t payload[CNO_SETTINGS_UNDEFINED - 1][6];
    uint8_t (*ptr)[6] = payload;
    for (size_t i = 0; i + 1 < CNO_SETTINGS_UNDEFINED; i++) {
        if (previous->array[i] == current->array[i])
            continue;
        struct cno_buffer_t buf = PACK(I16(i + 1), I32(current->array[i]));
        memcpy(ptr++, buf.data, buf.size);
    }
    struct cno_frame_t frame = { CNO_FRAME_SETTINGS, 0, 0, { (char *) payload, (ptr - payload) * 6 } };
    return cno_frame_write(conn, &frame);
}

static int cno_frame_write_rst_stream_by_id(struct cno_connection_t *conn, uint32_t id, uint32_t code)
{
    struct cno_frame_t error = { CNO_FRAME_RST_STREAM, 0, id, PACK(I32(code)) };
    return cno_frame_write(conn, &error);
}

static int cno_frame_write_rst_stream(struct cno_connection_t *conn,
                                      struct cno_stream_t     *stream,
                                      uint32_t /* enum CNO_RST_STREAM_CODE */ code)
{
    // Note that if HEADERS have not yet arrived, they may still do, in which case not decoding them
    // would break compression state. Setting CNO_RESET_STREAM_HISTORY is recommended.
    return cno_frame_write_rst_stream_by_id(conn, stream->id, code) ? CNO_ERROR_UP() : cno_stream_end_by_local(conn, stream);
}

static int cno_frame_handle_end_stream(struct cno_connection_t *conn,
                                       struct cno_stream_t     *stream,
                                       struct cno_message_t    *trailers)
{
    if (stream->remaining_payload && stream->remaining_payload != (uint64_t) -1)
        return cno_frame_write_rst_stream(conn, stream, CNO_RST_PROTOCOL_ERROR);
    if (CNO_FIRE(conn, on_message_tail, stream->id, trailers))
        return CNO_ERROR_UP();
    return !(stream->accept &= ~CNO_ACCEPT_INBOUND) && cno_stream_end(conn, stream);
}

static int cno_parse_content_length(struct cno_buffer_t value, uint64_t *cl)
{
    uint64_t prev = *cl = 0;
    for (const char *ptr = value.data, *end = ptr + value.size; ptr != end; ptr++, prev = *cl)
        if (*ptr < '0' || '9' < *ptr || (*cl = prev * 10 + (*ptr - '0')) < prev)
            return CNO_ERROR(PROTOCOL, "invalid content-length");
    return CNO_OK;
}

static int cno_frame_handle_message(struct cno_connection_t *conn,
                                    struct cno_stream_t     *stream,
                                    struct cno_frame_t      *frame,
                                    struct cno_message_t    *msg)
{
    int is_push = !!conn->continued_promise;
    int is_response = conn->client && !is_push;

    struct cno_header_t *it  = msg->headers;
    struct cno_header_t *end = msg->headers + msg->headers_len;

    // >HTTP/2 uses special pseudo-header fields beginning with ':' character
    // >(ASCII 0x3a) [to convey the target URI, ...]
    for (; it != end && cno_buffer_startswith(it->name, CNO_BUFFER_STRING(":")); it++)
        // >Pseudo-header fields MUST NOT appear in trailers.
        if (stream->accept & CNO_ACCEPT_TRAILERS)
            goto invalid_message;

    struct cno_header_t *first_non_pseudo = it;
    // Pseudo-headers are checked in reverse order because those that are used to fill fields
    // of `cno_message_t` are then erased, and shifting the two remaining headers up is cheaper
    // than moving all the normal headers down.
    int has_scheme = 0;
    int has_authority = 0;
    for (struct cno_header_t *h = it; h-- != msg->headers;) {
        if (is_response) {
            if (cno_buffer_eq(h->name, CNO_BUFFER_STRING(":status"))) {
                if (msg->code)
                    goto invalid_message;
                for (const char *p = h->value.data, *e = h->value.data + h->value.size; p != e; p++) {
                    if (*p < '0' || '9' < *p)
                        goto invalid_message;
                    if ((msg->code = msg->code * 10 + (*p - '0')) > 1000000)
                        goto invalid_message; // kind of an arbitrary limit, really
                }
                cno_hpack_free_header(h);
                continue;
            }
        } else {
            if (cno_buffer_eq(h->name, CNO_BUFFER_STRING(":path"))) {
                if (msg->path.data)
                    goto invalid_message;
                msg->path = h->value;
                cno_hpack_free_header(h);
                continue;
            }

            if (cno_buffer_eq(h->name, CNO_BUFFER_STRING(":method"))) {
                if (msg->method.data)
                    goto invalid_message;
                msg->method = h->value;
                cno_hpack_free_header(h);
                continue;
            }

            if (cno_buffer_eq(h->name, CNO_BUFFER_STRING(":authority"))) {
                if (has_authority)
                    goto invalid_message;
                has_authority = 1;
                *--it = *h;
                continue;
            }

            if (cno_buffer_eq(h->name, CNO_BUFFER_STRING(":scheme"))) {
                if (has_scheme)
                    goto invalid_message;
                has_scheme = 1;
                *--it = *h;
                continue;
            }
        }

        // >Endpoints MUST NOT generate pseudo-header fields other than those defined in this document.
        goto invalid_message;
    }

    msg->headers = it;
    msg->headers_len = end - it;

    stream->remaining_payload = (uint64_t) -1;
    for (it = first_non_pseudo; it != end; ++it) {
        // >All pseudo-header fields MUST appear in the header block
        // >before regular header fields.
        if (cno_buffer_startswith(it->name, CNO_BUFFER_STRING(":")))
            goto invalid_message;

        // >However, header field names MUST be converted to lowercase
        // >prior to their encoding in HTTP/2.
        for (const char *p = it->name.data; p != it->name.data + it->name.size; p++)
            if (isupper(*p))
                goto invalid_message;

        // >HTTP/2 does not use the Connection header field to indicate
        // >connection-specific header fields.
        if (cno_buffer_eq(it->name, CNO_BUFFER_STRING("connection")))
            goto invalid_message;

        // >The only exception to this is the TE header field, which MAY be present
        // > in an HTTP/2 request; when it is, it MUST NOT contain any value other than "trailers".
        if (cno_buffer_eq(it->name, CNO_BUFFER_STRING("te"))
        && !cno_buffer_eq(it->value, CNO_BUFFER_STRING("trailers")))
            goto invalid_message;

        if (cno_buffer_eq(it->name, CNO_BUFFER_STRING("content-length"))
         && cno_parse_content_length(it->value, &stream->remaining_payload))
            goto invalid_message;
    }

    if (stream->accept & CNO_ACCEPT_TRAILERS) {
        // There is no data after trailers.
        stream->accept &= ~CNO_ACCEPT_INBOUND;
        if (!(frame->flags & CNO_FLAG_END_STREAM))
            goto invalid_message;
        return cno_frame_handle_end_stream(conn, stream, msg);
    }

    // >All HTTP/2 requests MUST include exactly one valid value for the :method, :scheme,
    // >and :path pseudo-header fields, unless it is a CONNECT request (Section 8.3).
    if (is_response ? !msg->code : !cno_buffer_eq(msg->method, CNO_BUFFER_STRING("CONNECT")) &&
            (!msg->path.data || !msg->path.size || !msg->method.data || !msg->method.size || !has_scheme))
        goto invalid_message;

    if (is_push)
        return CNO_FIRE(conn, on_message_push, stream->id, msg, conn->continued_stream);

    stream->accept &= ~CNO_ACCEPT_HEADERS;
    stream->accept |=  CNO_ACCEPT_TRAILERS | CNO_ACCEPT_DATA;

    if (CNO_FIRE(conn, on_message_head, stream->id, msg))
        return CNO_ERROR_UP();

    if (frame->flags & CNO_FLAG_END_STREAM)
        return cno_frame_handle_end_stream(conn, stream, NULL);

    return CNO_OK;

invalid_message:
    return cno_frame_write_rst_stream(conn, stream, CNO_RST_PROTOCOL_ERROR);
}

static int cno_frame_handle_end_headers(struct cno_connection_t *conn,
                                        struct cno_stream_t     *stream,
                                        struct cno_frame_t      *frame)
{
    struct cno_header_t headers[CNO_MAX_HEADERS];
    struct cno_message_t msg = { 0, {}, {}, headers, CNO_MAX_HEADERS };
    if (cno_hpack_decode(&conn->decoder, CNO_BUFFER_VIEW(conn->continued), headers, &msg.headers_len)) {
        cno_buffer_dyn_clear(&conn->continued);
        cno_frame_write_goaway(conn, CNO_RST_COMPRESSION_ERROR);
        return CNO_ERROR_UP();
    }

    // Just ignore the message if the stream has already been reset.
    int failed = stream ? cno_frame_handle_message(conn, stream, frame, &msg) : CNO_OK;

    for (size_t i = 0; i < msg.headers_len; i++)
        cno_hpack_free_header(&msg.headers[i]);
    cno_buffer_dyn_clear(&conn->continued);
    conn->continued_stream = 0;
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

static int cno_frame_handle_priority(struct cno_connection_t *conn,
                                     struct cno_stream_t     *stream,
                                     struct cno_frame_t      *frame)
{
    if ((frame->flags & CNO_FLAG_PRIORITY) || frame->type == CNO_FRAME_PRIORITY) {
        if (frame->payload.size < 5 || (frame->type == CNO_FRAME_PRIORITY && frame->payload.size != 5))
            return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "PRIORITY of invalid size");

        if (!frame->stream)
            return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "PRIORITY on stream 0");

        if (frame->stream == (read4((const uint8_t *) frame->payload.data) & 0x7FFFFFFFUL))
            return stream ? cno_frame_write_rst_stream(conn, stream, CNO_RST_PROTOCOL_ERROR)
                          : cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "PRIORITY depends on itself");

        // TODO implement prioritization
        frame->payload.data += 5;
        frame->payload.size -= 5;
    }
    return CNO_OK;
}

static int cno_frame_handle_headers(struct cno_connection_t *conn,
                                    struct cno_stream_t     *stream,
                                    struct cno_frame_t      *frame)
{
    if (cno_frame_handle_padding(conn, frame))
        return CNO_ERROR_UP();

    if (cno_frame_handle_priority(conn, stream, frame))
        return CNO_ERROR_UP();

    if (stream == NULL) {
        if (conn->client || frame->stream <= conn->last_stream[CNO_REMOTE]) {
            if (cno_frame_handle_invalid_stream(conn, frame))
                return CNO_ERROR_UP();
            // else this frame must be decompressed, but ignored.
        } else if (conn->goaway_sent || conn->stream_count[CNO_REMOTE] >= conn->settings[CNO_LOCAL].max_concurrent_streams) {
            if (cno_frame_write_rst_stream_by_id(conn, frame->stream, CNO_RST_REFUSED_STREAM))
                return CNO_ERROR_UP();
        } else {
            stream = cno_stream_new(conn, frame->stream, CNO_REMOTE);
            if (stream == NULL)
                return CNO_ERROR_UP();
            stream->accept = CNO_ACCEPT_HEADERS | CNO_ACCEPT_WRITE_HEADERS | CNO_ACCEPT_WRITE_PUSH;
        }
    } else if (stream->accept & CNO_ACCEPT_TRAILERS) {
        stream->accept &= ~CNO_ACCEPT_DATA;
        if (!(frame->flags & CNO_FLAG_END_STREAM))
            return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "trailers without END_STREAM");
    } else if (!(stream->accept & CNO_ACCEPT_HEADERS)) {
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "unexpected HEADERS");
    }

    conn->continued_flags = frame->flags & CNO_FLAG_END_STREAM;
    conn->continued_stream = frame->stream;
    if (cno_buffer_dyn_concat(&conn->continued, frame->payload))
        // HPACK compression is now out of sync, this error is unrecoverable; don't bother cleaning up.
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

    if (frame->payload.size < 4)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "PUSH_PROMISE too short");

    // XXX stream may have been reset by us, in which case do what?
    if (!conn->settings[CNO_LOCAL].enable_push || !stream || !(stream->accept & CNO_ACCEPT_PUSH))
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "unexpected PUSH_PROMISE");

    uint32_t promised = read4((const uint8_t *) frame->payload.data);

    struct cno_stream_t *child = cno_stream_new(conn, promised, CNO_REMOTE);
    if (child == NULL)
        return CNO_ERROR_UP();
    child->accept = CNO_ACCEPT_HEADERS;

    conn->continued_flags = CNO_FLAG_END_STREAM; // pushed requests cannot have payload
    conn->continued_stream = frame->stream;
    conn->continued_promise = promised;
    struct cno_buffer_t tail = { frame->payload.data + 4, frame->payload.size - 4 };
    if (cno_buffer_dyn_concat(&conn->continued, tail))
        // Also a HPACK-desynchronizing error.
        return CNO_ERROR_UP();

    if (frame->flags & CNO_FLAG_END_HEADERS)
        return cno_frame_handle_end_headers(conn, child, frame);
    return CNO_OK;
}


static int cno_frame_handle_continuation(struct cno_connection_t *conn,
                                         struct cno_stream_t     *stream,
                                         struct cno_frame_t      *frame)
{
    if (!conn->continued_stream)
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "unexpected CONTINUATION");

    if (conn->continued_promise)
        stream = cno_stream_find(conn, conn->continued_promise);

    if ((conn->continued_flags += 2) > CNO_MAX_CONTINUATIONS * 2)
        // Finally, a chance to use that error code.
        return cno_frame_write_error(conn, CNO_RST_ENHANCE_YOUR_CALM, "too many CONTINUATIONs");

    if (cno_buffer_dyn_concat(&conn->continued, frame->payload))
        return CNO_ERROR_UP();

    frame->flags |= (conn->continued_flags & CNO_FLAG_END_STREAM);
    if (frame->flags & CNO_FLAG_END_HEADERS)
        return cno_frame_handle_end_headers(conn, stream, frame);
    return CNO_OK;
}


static int cno_frame_handle_data(struct cno_connection_t *conn,
                                 struct cno_stream_t     *stream,
                                 struct cno_frame_t      *frame)
{
    // For purposes of flow control, padding counts.
    int32_t length = frame->payload.size;
    if (cno_frame_handle_padding(conn, frame))
        return CNO_ERROR_UP();

    // Frames on invalid streams still count against the connection-wide flow control window.
    // TODO allow manual connection flow control?
    if (length && cno_frame_write(conn, &(struct cno_frame_t) { CNO_FRAME_WINDOW_UPDATE, 0, 0, PACK(I32(length)) }))
        return CNO_ERROR_UP();

    if (!stream)
        return cno_frame_handle_invalid_stream(conn, frame);

    if (!(stream->accept & CNO_ACCEPT_DATA))
        return cno_frame_write_rst_stream(conn, stream, CNO_RST_STREAM_CLOSED);

    if (length && length > stream->window_recv)
        return cno_frame_write_rst_stream(conn, stream, CNO_RST_FLOW_CONTROL_ERROR);

    if (stream->remaining_payload != (uint64_t) -1)
        stream->remaining_payload -= frame->payload.size;

    if (frame->payload.size && CNO_FIRE(conn, on_message_data, frame->stream, frame->payload.data, frame->payload.size))
        return CNO_ERROR_UP();

    if (frame->flags & CNO_FLAG_END_STREAM)
        return cno_frame_handle_end_stream(conn, stream, NULL);

    if (conn->flags & CNO_CONN_FLAG_MANUAL_FLOW_CONTROL) {
        // Forwarding padding to the application is kind of silly, so that part
        // of the frame will be flow-controlled automatically anyway.
        stream->window_recv -= frame->payload.size;
        length -= frame->payload.size;
    }

    if (!length)
        return CNO_OK;
    struct cno_frame_t update = { CNO_FRAME_WINDOW_UPDATE, 0, stream->id, PACK(I32(length)) };
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
        return CNO_ERROR(PROTOCOL, "disconnected with error %u", error);
    // TODO: clean shutdown: reject all streams higher than indicated in the frame
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
    return cno_stream_end(conn, stream);
}

static int cno_frame_handle_settings(struct cno_connection_t *conn,
                                     struct cno_stream_t     *stream __attribute__((unused)),
                                     struct cno_frame_t      *frame)
{
    if (frame->stream)
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "SETTINGS on a stream");

    if (frame->flags & CNO_FLAG_ACK) {
        // XXX maybe use the previous SETTINGS before receiving this?
        if (frame->payload.size)
            return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad SETTINGS ack");
        return CNO_OK;
    }

    if (frame->payload.size % 6)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad SETTINGS");

    struct cno_settings_t *cfg = &conn->settings[CNO_REMOTE];
    const uint8_t *ptr = (const uint8_t *) frame->payload.data;
    const uint8_t *end = (const uint8_t *) frame->payload.data + frame->payload.size;
    const int32_t old_window = cfg->initial_window_size;

    for (; ptr != end; ptr += 6) {
        uint16_t setting = read2(ptr);
        uint32_t value   = read4(ptr + 2);

        if (setting && setting < CNO_SETTINGS_UNDEFINED)
            cfg->array[setting - 1] = value;
    }

    if (cfg->enable_push > 1)
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "enable_push out of bounds");

    if (cfg->initial_window_size > 0x7FFFFFFFL)
        return cno_frame_write_error(conn, CNO_RST_FLOW_CONTROL_ERROR, "initial_window_size too big");

    if (cfg->max_frame_size < 16384 || cfg->max_frame_size > 16777215)
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "max_frame_size out of bounds");

    const int32_t window_diff = (int32_t)cfg->initial_window_size - old_window;
    if (window_diff != 0) {
        for (int i = 0; i < CNO_STREAM_BUCKETS; i++) {
            for (struct cno_stream_t *s = conn->streams[i], *n; s; s = n) {
                if (window_diff > 0 ? s->window_send > 0x7FFFFFFFL - window_diff : -s->window_send > 0x7FFFFFFFL + window_diff)
                    return cno_frame_write_error(conn, CNO_RST_FLOW_CONTROL_ERROR, "initial_window_size overflow");

                n = s->next; // on_flow_increase may destroy this stream. Assume it doesn't destroy anything else.
                s->window_send += window_diff;
                if (window_diff > 0 && CNO_FIRE(conn, on_flow_increase, s->id))
                    return CNO_ERROR_UP();
            }
        }
    }

    size_t limit = conn->encoder.limit_upper = cfg->header_table_size;
    if (limit > conn->settings[CNO_LOCAL].header_table_size)
        limit = conn->settings[CNO_LOCAL].header_table_size;
    if (cno_hpack_setlimit(&conn->encoder, limit))
        return CNO_ERROR_UP();

    struct cno_frame_t ack = { CNO_FRAME_SETTINGS, CNO_FLAG_ACK, 0, {} };
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

    if (increment == 0 || increment > 0x7FFFFFFFL)
        return cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, "window increment out of bounds");

    if (!frame->stream) {
        if (conn->window_send > 0x7FFFFFFFL - increment)
            return cno_frame_write_error(conn, CNO_RST_FLOW_CONTROL_ERROR, "window increment too big");

        conn->window_send += increment;
    } else {
        if (stream == NULL)
            return cno_frame_handle_invalid_stream(conn, frame);

        if (stream->window_send > 0x7FFFFFFFL - increment)
            return cno_frame_write_rst_stream(conn, stream, CNO_RST_FLOW_CONTROL_ERROR);

        stream->window_send += increment;
    }

    return CNO_FIRE(conn, on_flow_increase, frame->stream);
}

typedef int cno_frame_handler_t(struct cno_connection_t *,
                                struct cno_stream_t     *,
                                struct cno_frame_t      *);

static cno_frame_handler_t * const CNO_FRAME_HANDLERS[] = {
    // Should be synced to enum CNO_FRAME_TYPE.
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

    // >Implementations MUST ignore and discard any frame that has a type that is unknown.
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

    const int64_t window_diff = (int64_t)settings->initial_window_size - conn->settings[CNO_LOCAL].initial_window_size;
    if (window_diff != 0) {
        for (int i = 0; i < CNO_STREAM_BUCKETS; i++)
            for (struct cno_stream_t *s = conn->streams[i]; s; s = s->next)
                s->window_recv += window_diff;
    }
    conn->decoder.limit_upper = settings->header_table_size;
    memcpy(&conn->settings[CNO_LOCAL], settings, sizeof(*settings));
    return CNO_OK;
}

void cno_connection_init(struct cno_connection_t *conn, enum CNO_CONNECTION_KIND kind)
{
    *conn = (struct cno_connection_t) {
        .client      = CNO_CLIENT == kind,
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
    return conn->state == CNO_CONNECTION_INIT ||
           conn->state == CNO_CONNECTION_PREFACE ||
           conn->state == CNO_CONNECTION_SETTINGS ||
           conn->state == CNO_CONNECTION_READY ||
           conn->state == CNO_CONNECTION_HTTP1_READING_UPGRADE;
}

static int cno_connection_upgrade(struct cno_connection_t *conn)
{
    if (conn->client && CNO_WRITEV(conn, CNO_PREFACE))
        return CNO_ERROR_UP();
    return cno_frame_write_settings(conn, &CNO_SETTINGS_STANDARD, &conn->settings[CNO_LOCAL]);
}

static size_t cno_remove_chunked_te(struct cno_buffer_t *buf)
{
    // assuming the request is valid, chunked can only be the last transfer-encoding
    if (cno_buffer_endswith(*buf, CNO_BUFFER_STRING("chunked"))) {
        buf->size -= 7;
        while (buf->size && buf->data[buf->size - 1] == ' ')
            buf->size--;
        if (buf->size && buf->data[buf->size - 1] == ',')
            buf->size--;
    }
    return buf->size;
}

// NOTE these functions have tri-state returns now: negative for errors, 0 (CNO_OK)
//      to wait for more data, and positive (CNO_CONNECTION_STATE) to switch to another state.
static int cno_when_undefined(struct cno_connection_t *conn __attribute__((unused)))
{
    return CNO_OK; // Wait until connection_made before processing data.
}

static int cno_when_init(struct cno_connection_t *conn)
{
    if (cno_connection_upgrade(conn))
        return CNO_ERROR_UP();
    return CNO_CONNECTION_PREFACE;
}

static int cno_when_preface(struct cno_connection_t *conn)
{
    if (!conn->client) {
        if (strncmp(conn->buffer.data, CNO_PREFACE.data, conn->buffer.size))
            return CNO_ERROR(PROTOCOL, "invalid HTTP 2 client preface");
        if (conn->buffer.size < CNO_PREFACE.size)
            return CNO_OK;
        cno_buffer_dyn_shift(&conn->buffer, CNO_PREFACE.size);
    }
    return CNO_CONNECTION_SETTINGS;
}

static int cno_when_settings(struct cno_connection_t *conn)
{
    if (conn->buffer.size < 5)
        return CNO_OK;
    if (conn->buffer.data[3] != CNO_FRAME_SETTINGS || conn->buffer.data[4] != 0)
        return CNO_ERROR(PROTOCOL, "invalid HTTP 2 preface: no initial SETTINGS");
    return CNO_CONNECTION_READY;
}

static int cno_when_ready(struct cno_connection_t *conn)
{
    if (conn->buffer.size < 9)
        return CNO_OK;

    const uint8_t *base = (const uint8_t *) conn->buffer.data;
    const size_t len = read3(base);

    if (len > conn->settings[CNO_LOCAL].max_frame_size)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "frame too big");

    if (conn->buffer.size < 9 + len)
        return CNO_OK;

    struct cno_buffer_t payload = { conn->buffer.data + 9, len };
    struct cno_frame_t frame = { read1(&base[3]), read1(&base[4]), read4(&base[5]) & 0x7FFFFFFFUL, payload };
    if (CNO_FIRE(conn, on_frame, &frame) || cno_frame_handle(conn, &frame))
        return CNO_ERROR_UP();

    cno_buffer_dyn_shift(&conn->buffer, 9 + len);
    return CNO_CONNECTION_READY;
}

static int cno_when_http1_ready(struct cno_connection_t *conn)
{
    {   // Ignore leading CRLF.
        char *buf = conn->buffer.data;
        char *end = conn->buffer.size + buf;
        while (buf != end && (*buf == '\r' || *buf == '\n')) ++buf;
        cno_buffer_dyn_shift(&conn->buffer, buf - conn->buffer.data);
    }

    if (!conn->buffer.size)
        return CNO_OK;

    struct cno_stream_t *stream = cno_stream_find(conn, 1);
    if (conn->client) {
        if (!stream || !(stream->accept & CNO_ACCEPT_HEADERS))
            return CNO_ERROR(PROTOCOL, "server sent an HTTP/1.x response, but there was no request");
    } else {
        // Only allow upgrading with prior knowledge if no h1 requests have yet been sent.
        if (conn->last_stream[CNO_REMOTE] == 0 && !(conn->flags & CNO_CONN_FLAG_DISALLOW_H2_PRIOR_KNOWLEDGE)) {
            // The h2 preface almost looks like a h1 request, but is not. picohttpparser will reject it.
            if (!strncmp(conn->buffer.data, CNO_PREFACE.data, conn->buffer.size)) {
                if (conn->buffer.size < CNO_PREFACE.size)
                    return CNO_OK;
                return CNO_CONNECTION_INIT;
            }
        }

        if (!stream) {
            stream = cno_stream_new(conn, 1, CNO_REMOTE);
            if (!stream)
                return CNO_ERROR_UP();
            stream->accept = CNO_ACCEPT_HEADERS;
        }
        if (!(stream->accept & CNO_ACCEPT_HEADERS))
            return CNO_ERROR(WOULD_BLOCK, "already handling an HTTP/1.x message");
    }

    // Reserve one for :scheme. (Even on clients, just in case.)
    struct cno_message_t msg = { 0, {}, {}, NULL, CNO_MAX_HEADERS - 1 };
    struct phr_header headers_phr[CNO_MAX_HEADERS];

    int minor = 0;
    int ok = conn->client
        ? phr_parse_response(conn->buffer.data, conn->buffer.size,
            &minor, &msg.code, &msg.method.data, &msg.method.size,
            headers_phr, &msg.headers_len, 1)
        : phr_parse_request(conn->buffer.data, conn->buffer.size,
            &msg.method.data, &msg.method.size, &msg.path.data, &msg.path.size, &minor,
            headers_phr, &msg.headers_len, 1);

    if (ok == -2) {
        if (conn->buffer.size > CNO_MAX_CONTINUATIONS * conn->settings[CNO_LOCAL].max_frame_size)
            return CNO_ERROR(PROTOCOL, "HTTP/1.x message too big");
        return CNO_OK;
    }

    if (ok == -1)
        return CNO_ERROR(PROTOCOL, "bad HTTP/1.x message");

    if (minor != 0 && minor != 1)
        // HTTP/1.0 is probably not really supported either tbh.
        return CNO_ERROR(PROTOCOL, "HTTP/1.%d not supported", minor);

    // Have to switch the state before calling on_message_head; if it decides
    // to respond right away and there is a h2c upgrade in progress, response must be sent as h2.
    conn->state = CNO_CONNECTION_HTTP1_READING;
    // Even if there's no payload, the automaton will (almost) instantly switch back:
    stream->accept &= ~CNO_ACCEPT_HEADERS;
    stream->accept |=  CNO_ACCEPT_DATA;
    if (!conn->client)
        stream->accept |= CNO_ACCEPT_WRITE_HEADERS;

    struct cno_header_t headers[CNO_MAX_HEADERS];
    struct cno_header_t *it = msg.headers = headers;

    for (size_t i = 0; i < msg.headers_len; i++, it++) {
        *it = (struct cno_header_t) {
            .name  = { headers_phr[i].name,  headers_phr[i].name_len  },
            .value = { headers_phr[i].value, headers_phr[i].value_len },
        };

        {
            // Going to convert this h1 message to an h2-like form.
            char * ptr = (char *) it->name.data;
            char * end = (char *) it->name.data + it->name.size;
            for (; ptr != end; ptr++) *ptr = tolower(*ptr);
        }

        if (cno_buffer_eq(it->name, CNO_BUFFER_STRING("http2-settings"))) {
            // TODO decode & emit on_frame
            it--;
            continue;
        }

        if (cno_buffer_eq(it->name, CNO_BUFFER_STRING("upgrade"))) {
            if (cno_buffer_eq(it->value, CNO_BUFFER_STRING("h2c"))) {
                it--;
                // TODO: client-side h2 upgrade
                if (conn->client || conn->state != CNO_CONNECTION_HTTP1_READING
                 || conn->flags & CNO_CONN_FLAG_DISALLOW_H2_UPGRADE)
                    continue;

                struct cno_header_t upgrade_headers[] = {
                    { CNO_BUFFER_STRING("connection"), CNO_BUFFER_STRING("upgrade"), 0 },
                    { CNO_BUFFER_STRING("upgrade"),    CNO_BUFFER_STRING("h2c"),     0 },
                };
                struct cno_message_t upgrade_msg = { 101, {}, {}, upgrade_headers, 2 };
                // If we send the SETTINGS now, we'll be able to send HTTP 2 frames
                // while in the HTTP1_READING_UPGRADE state.
                if (cno_write_message(conn, 1, &upgrade_msg, 0) || cno_connection_upgrade(conn))
                    return CNO_ERROR_UP();

                // Technically, server should refuse if HTTP2-Settings are not present. We'll let this slide.
                conn->state = CNO_CONNECTION_HTTP1_READING_UPGRADE;
            } else if (conn->state != CNO_CONNECTION_HTTP1_READING) {
                if (conn->state == CNO_CONNECTION_HTTP1_READING_UPGRADE)
                    it--; // If upgrading to h2c, don't notify application of any upgrades.
            } else if (conn->client) {
                if (msg.code == 101)
                    conn->state = CNO_CONNECTION_UNKNOWN_PROTOCOL;
            } else {
                conn->state = CNO_CONNECTION_UNKNOWN_PROTOCOL_UPGRADE;
            }
            continue;
        }

        if (cno_buffer_eq(it->name, CNO_BUFFER_STRING("content-length"))) {
            if (stream->remaining_payload == (uint64_t) -1)
                continue; // ignore content-length with chunked transfer-encoding
            if (stream->remaining_payload)
                return CNO_ERROR(PROTOCOL, "multiple content-lengths");
            if (cno_parse_content_length(it->value, &stream->remaining_payload))
                return CNO_ERROR_UP();
            continue;
        }

        if (cno_buffer_eq(it->name, CNO_BUFFER_STRING("transfer-encoding"))) {
            // XXX this value is probably not actually allowed, but just in case:
            if (cno_buffer_eq(it->value, CNO_BUFFER_STRING("identity"))) {
                it--;
                continue;
            }
            // Any non-identity transfer-encoding requires chunked (which should also be listed).
            // (This part is a bit non-compatible with h2. Proxies should probably decode TEs.)
            if (!cno_remove_chunked_te(&it->value))
                it--;
            stream->remaining_payload = (uint64_t) -1;
            continue;
        }

        if (cno_buffer_eq(it->name, CNO_BUFFER_STRING("host"))) {
            it->name = CNO_BUFFER_STRING(":authority");
            continue;
        }
    }
    if (!conn->client)
        *it++ = (struct cno_header_t) { CNO_BUFFER_STRING(":scheme"), CNO_BUFFER_STRING("unknown"), 0 };
    msg.headers_len = it - msg.headers;

    cno_buffer_dyn_shift(&conn->buffer, (size_t) ok);

    if (CNO_FIRE(conn, on_message_head, stream->id, &msg))
        return CNO_ERROR_UP();

    return conn->state;
}

// TODO make this function more readable
static int cno_when_http1_reading(struct cno_connection_t *conn)
{
    struct cno_stream_t *stream = cno_stream_find(conn, 1);
    if (!stream || !(stream->accept & CNO_ACCEPT_DATA))
        return CNO_ERROR(ASSERTION, "connection expects HTTP/1.x message body, but stream 1 does not");

    if (!stream->remaining_payload || (stream->flags & CNO_STREAM_H1_READING_HEAD_RESPONSE)) {
        // TODO: trailers.
        if (CNO_FIRE(conn, on_message_tail, stream->id, NULL))
            return CNO_ERROR_UP();
        // if still writable, `cno_write_message`/`cno_write_data` will reset it.
        if (!(stream->accept &= ~CNO_ACCEPT_INBOUND) && cno_stream_end(conn, stream))
            return CNO_ERROR_UP();
        return conn->state == CNO_CONNECTION_HTTP1_READING_UPGRADE
            ? CNO_CONNECTION_PREFACE
            : CNO_CONNECTION_HTTP1_READY;
    }

    if (!conn->buffer.size)
        return CNO_OK;

    if (stream->remaining_payload == (uint64_t) -1) {
        char *eol = memchr(conn->buffer.data, '\n', conn->buffer.size);
        if (eol++ == NULL)
            return CNO_OK;

        char *end_of_length;
        size_t length = strtoul(conn->buffer.data, &end_of_length, 16);
        if (end_of_length == conn->buffer.data || end_of_length + 2 != eol)
            return CNO_ERROR(PROTOCOL, "HTTP/1.x chunked encoding parse error");

        size_t total = length + (eol - conn->buffer.data) + 2;  // + crlf after data
        if (conn->buffer.size < total)
            return CNO_OK;
        if (conn->buffer.data[total - 2] != '\r' || conn->buffer.data[total - 1] != '\n')
            return CNO_ERROR(PROTOCOL, "HTTP/1.x chunked encoding parse error");

        if (!length)
            stream->remaining_payload = 0;
        else if (CNO_FIRE(conn, on_message_data, stream->id, eol, length))
            return CNO_ERROR_UP();
        cno_buffer_dyn_shift(&conn->buffer, total);
    } else {
        struct cno_buffer_t b = CNO_BUFFER_VIEW(conn->buffer);
        if (b.size > stream->remaining_payload)
            b.size = stream->remaining_payload;
        stream->remaining_payload -= b.size;
        cno_buffer_dyn_shift(&conn->buffer, b.size);
        if (CNO_FIRE(conn, on_message_data, stream->id, b.data, b.size))
            return CNO_ERROR_UP();
    }
    return conn->state;
}

static int cno_when_unknown_protocol_upgrade(struct cno_connection_t *conn)
{
    if (CNO_FIRE(conn, on_upgrade))
        return CNO_ERROR_UP();
    // might've sent 101 and switched to the next state as a result
    if (conn->state == CNO_CONNECTION_UNKNOWN_PROTOCOL_UPGRADE)
        return CNO_CONNECTION_HTTP1_READING;
    return conn->state;
}

static int cno_when_unknown_protocol(struct cno_connection_t *conn)
{
    if (!conn->buffer.size)
        return CNO_OK;
    struct cno_buffer_t b = CNO_BUFFER_VIEW(conn->buffer);
    cno_buffer_dyn_shift(&conn->buffer, b.size);
    if (CNO_FIRE(conn, on_message_data, 1, b.data, b.size))
        return CNO_ERROR_UP();
    return CNO_CONNECTION_UNKNOWN_PROTOCOL;
}

typedef int cno_state_handler_t(struct cno_connection_t *);

static cno_state_handler_t * const CNO_STATE_MACHINE[] = {
    // Should be synced to enum CNO_CONNECTION_STATE.
    &cno_when_undefined,
    &cno_when_init,
    &cno_when_preface,
    &cno_when_settings,
    &cno_when_ready,
    &cno_when_http1_ready,
    &cno_when_http1_reading,
    &cno_when_http1_reading,//_upgrade,
    &cno_when_unknown_protocol_upgrade,
    &cno_when_unknown_protocol,
};

int cno_connection_made(struct cno_connection_t *conn, enum CNO_HTTP_VERSION version)
{
    if (conn->state != CNO_CONNECTION_UNDEFINED)
        return CNO_ERROR(ASSERTION, "called connection_made twice");

    conn->state = version == CNO_HTTP2 ? CNO_CONNECTION_INIT : CNO_CONNECTION_HTTP1_READY;
    return cno_connection_data_received(conn, NULL, 0);
}

int cno_connection_data_received(struct cno_connection_t *conn, const char *data, size_t length)
{
    if (conn->state == CNO_CONNECTION_UNDEFINED)
        return CNO_ERROR(DISCONNECT, "connection closed");

    if (length && cno_buffer_dyn_concat(&conn->buffer, (struct cno_buffer_t) { data, length }))
        return CNO_ERROR_UP();

    while (1) {
        int r = CNO_STATE_MACHINE[conn->state](conn);
        if (r <= 0)
            return r;
        conn->state = r;
    }
}

int cno_connection_stop(struct cno_connection_t *conn)
{
    return cno_write_reset(conn, 0, CNO_RST_NO_ERROR);
}

int cno_connection_lost(struct cno_connection_t *conn)
{
    if (!cno_connection_is_http2(conn)) {
        struct cno_stream_t * stream = cno_stream_find(conn, 1);
        if (stream) {
            if (conn->state == CNO_CONNECTION_UNKNOWN_PROTOCOL) {
                if (CNO_FIRE(conn, on_message_tail, 1, NULL))
                    return CNO_ERROR_UP();
            } else if (stream->accept & CNO_ACCEPT_DATA) {
                return CNO_ERROR(PROTOCOL, "unclean http/1.x termination");
            }
            // If still writable, `cno_write_message`/`cno_write_data` will reset the stream.
            if (!(stream->accept &= ~CNO_ACCEPT_INBOUND) && cno_stream_end(conn, stream))
                return CNO_ERROR_UP();
        }
        return CNO_OK;
    }

    // h2 won't work over half-closed connections.
    conn->state = CNO_CONNECTION_UNDEFINED;
    for (struct cno_stream_t **s = &conn->streams[0]; s != &conn->streams[CNO_STREAM_BUCKETS]; s++)
        while (*s)
            if (cno_stream_end(conn, *s))
                return CNO_ERROR_UP();
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
    if (!cno_connection_is_http2(conn)) {
        if (!stream && code == CNO_RST_NO_ERROR)
            return CNO_OK;
        struct cno_stream_t *obj = cno_stream_find(conn, 1);
        if (obj && cno_stream_end(conn, obj))
            return CNO_ERROR_UP();
        return CNO_ERROR(DISCONNECT, "HTTP/1.x connection rejected");
    }

    if (!stream)
        return cno_frame_write_goaway(conn, code);

    struct cno_stream_t *obj = cno_stream_find(conn, stream);
    return obj ? cno_frame_write_rst_stream(conn, obj, code) : CNO_OK; // assume idle streams have already been reset
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
    if (!streamobj || !(streamobj->accept & CNO_ACCEPT_WRITE_PUSH))
        return CNO_OK;  // pushed requests are safe, so whether we send one doesn't matter

    uint32_t child = cno_connection_next_stream(conn);

    struct cno_stream_t *childobj = cno_stream_new(conn, child, CNO_LOCAL);
    if (childobj == NULL)
        return CNO_ERROR_UP();
    childobj->accept = CNO_ACCEPT_WRITE_HEADERS;

    struct cno_buffer_dyn_t payload = {};
    struct cno_header_t head[2] = {
        { CNO_BUFFER_STRING(":method"), msg->method, 0 },
        { CNO_BUFFER_STRING(":path"),   msg->path,   0 },
    };

    if (cno_buffer_dyn_concat(&payload, PACK(I32(child)))
     || cno_hpack_encode(&conn->encoder, &payload, head, 2)
     || cno_hpack_encode(&conn->encoder, &payload, msg->headers, msg->headers_len))
        return cno_buffer_dyn_clear(&payload), CNO_ERROR_UP();

    struct cno_frame_t frame = { CNO_FRAME_PUSH_PROMISE, CNO_FLAG_END_HEADERS, stream, CNO_BUFFER_VIEW(payload) };
    if (cno_frame_write(conn, &frame))
        return cno_buffer_dyn_clear(&payload), CNO_ERROR_UP();

    cno_buffer_dyn_clear(&payload);
    return CNO_FIRE(conn, on_message_head, child, msg) || CNO_FIRE(conn, on_message_tail, child, NULL);
}

static int cno_discard_remaining_payload(struct cno_connection_t *conn, struct cno_stream_t *streamobj)
{
    if (!(streamobj->accept &= ~CNO_ACCEPT_OUTBOUND))
        return cno_stream_end_by_local(conn, streamobj);
    if (!conn->client && cno_connection_is_http2(conn) && cno_frame_write_rst_stream(conn, streamobj, CNO_RST_NO_ERROR))
        return CNO_ERROR_UP();
    return CNO_OK;
}

int cno_write_message(struct cno_connection_t *conn, uint32_t stream, const struct cno_message_t *msg, int final)
{
    if (conn->state == CNO_CONNECTION_UNDEFINED)
        return CNO_ERROR(DISCONNECT, "connection closed");

    int is_informational = 100 <= msg->code && msg->code < 200;
    if (is_informational && final)
        return CNO_ERROR(ASSERTION, "1xx codes cannot end the stream");

    for (const struct cno_header_t *it = msg->headers, *e = it + msg->headers_len; it != e; it++)
        for (const char *p = it->name.data; p != it->name.data + it->name.size; p++)
            if (isupper(*p))
                return CNO_ERROR(ASSERTION, "header names should be lowercase");

    struct cno_stream_t *streamobj = cno_stream_find(conn, stream);
    if (conn->client) {
        if (streamobj == NULL) {
            streamobj = cno_stream_new(conn, stream, CNO_LOCAL);
            if (streamobj == NULL)
                return CNO_ERROR_UP();
            streamobj->accept = CNO_ACCEPT_HEADERS | CNO_ACCEPT_PUSH | CNO_ACCEPT_WRITE_HEADERS;
        }
        if (!cno_connection_is_http2(conn) && !(streamobj->accept & CNO_ACCEPT_WRITE_HEADERS))
            return CNO_ERROR(WOULD_BLOCK, "HTTP/1.x request already in progress");
    } else {
        if (!streamobj || !(streamobj->accept & CNO_ACCEPT_WRITE_HEADERS))
            return CNO_ERROR(INVALID_STREAM, "this stream is not writable");
    }

    if (!cno_connection_is_http2(conn)) {
        if (conn->client) {
            if (cno_buffer_eq(msg->method, CNO_BUFFER_STRING("HEAD")))
                streamobj->flags |= CNO_STREAM_H1_READING_HEAD_RESPONSE;
            else
                streamobj->flags &= CNO_STREAM_H1_READING_HEAD_RESPONSE;

            if (CNO_WRITEV(conn, msg->method, CNO_BUFFER_STRING(" "), msg->path, CNO_BUFFER_STRING(" HTTP/1.1\r\n")))
                return CNO_ERROR_UP();
        } else {
            char codebuf[48];
            if (CNO_WRITEV(conn, {codebuf, snprintf(codebuf, sizeof(codebuf), "HTTP/1.1 %d No Reason\r\n", msg->code)}))
                return CNO_ERROR_UP();
        }

        struct cno_header_t *it  = msg->headers;
        struct cno_header_t *end = msg->headers_len + it;

        if (is_informational || final)
            streamobj->flags &= ~CNO_STREAM_H1_WRITING_CHUNKED;
        else
            streamobj->flags |= CNO_STREAM_H1_WRITING_CHUNKED;

        for (; it != end; ++it) {
            struct cno_buffer_t name = it->name;
            struct cno_buffer_t value = it->value;

            if (cno_buffer_eq(name, CNO_BUFFER_STRING(":authority")))
                name = CNO_BUFFER_STRING("host");

            else if (cno_buffer_startswith(name, CNO_BUFFER_STRING(":"))) // :scheme, probably
                continue;

            else if (cno_buffer_eq(name, CNO_BUFFER_STRING("content-length"))
                  || cno_buffer_eq(name, CNO_BUFFER_STRING("upgrade")))
                streamobj->flags &= ~CNO_STREAM_H1_WRITING_CHUNKED;

            else if (cno_buffer_eq(name, CNO_BUFFER_STRING("transfer-encoding"))) {
                // either CNO_STREAM_H1_WRITING_CHUNKED is set, there's no body at all, or message
                // is invalid because it contains both content-length and transfer-encoding.
                if (!cno_remove_chunked_te(&value))
                    continue;
            }

            if (CNO_WRITEV(conn, name, CNO_BUFFER_STRING(": "), value, CNO_BUFFER_STRING("\r\n")))
                return CNO_ERROR_UP();
        }

        if (streamobj->flags & CNO_STREAM_H1_WRITING_CHUNKED
          ? CNO_WRITEV(conn, CNO_BUFFER_STRING("transfer-encoding: chunked\r\n\r\n"))
          : CNO_WRITEV(conn, CNO_BUFFER_STRING("\r\n")))
            return CNO_ERROR_UP();

        if (msg->code == 101 && conn->state == CNO_CONNECTION_UNKNOWN_PROTOCOL_UPGRADE) {
            conn->state = CNO_CONNECTION_UNKNOWN_PROTOCOL;
            is_informational = 0;
        }
    } else {
        struct cno_buffer_dyn_t payload = {};

        if (conn->client) {
            struct cno_header_t head[] = {
                { CNO_BUFFER_STRING(":method"), msg->method, 0 },
                { CNO_BUFFER_STRING(":path"),   msg->path,   0 },
            };

            if (cno_hpack_encode(&conn->encoder, &payload, head, 2))
                return cno_buffer_dyn_clear(&payload), CNO_ERROR_UP();
        } else {
            char code[8];
            struct cno_header_t head[] = {
                { CNO_BUFFER_STRING(":status"), {code, snprintf(code, sizeof(code), "%d", msg->code)}, 0 }
            };

            if (cno_hpack_encode(&conn->encoder, &payload, head, 1))
                return cno_buffer_dyn_clear(&payload), CNO_ERROR_UP();
        }

        if (cno_hpack_encode(&conn->encoder, &payload, msg->headers, msg->headers_len))
            return cno_buffer_dyn_clear(&payload), CNO_ERROR_UP();

        struct cno_frame_t frame = { CNO_FRAME_HEADERS, CNO_FLAG_END_HEADERS, stream, CNO_BUFFER_VIEW(payload) };
        if (final)
            frame.flags |= CNO_FLAG_END_STREAM;
        if (cno_frame_write(conn, &frame))
            return cno_buffer_dyn_clear(&payload), CNO_ERROR_UP();

        cno_buffer_dyn_clear(&payload);
    }

    if (final)
        return cno_discard_remaining_payload(conn, streamobj);

    if (!is_informational) {
        streamobj->accept &= ~CNO_ACCEPT_WRITE_HEADERS;
        streamobj->accept |=  CNO_ACCEPT_WRITE_DATA;
    }

    return CNO_OK;
}

int cno_write_data(struct cno_connection_t *conn, uint32_t stream, const char *data, size_t length, int final)
{
    if (conn->state == CNO_CONNECTION_UNDEFINED)
        return CNO_ERROR(DISCONNECT, "connection closed");

    struct cno_stream_t *streamobj = cno_stream_find(conn, stream);
    if (!streamobj || !(streamobj->accept & CNO_ACCEPT_WRITE_DATA))
        return CNO_ERROR(INVALID_STREAM, "this stream is not writable");

    if (!cno_connection_is_http2(conn)) {
        if (streamobj->flags & CNO_STREAM_H1_WRITING_CHUNKED) {
            char lenbuf[16];
            struct cno_buffer_t len = { lenbuf, snprintf(lenbuf, sizeof(lenbuf), "%zX\r\n", length) };
            if (length && final ? CNO_WRITEV(conn, len, { data, length }, CNO_BUFFER_STRING("\r\n0\r\n\r\n"))
              : length          ? CNO_WRITEV(conn, len, { data, length }, CNO_BUFFER_STRING("\r\n"))
              : final           ? CNO_WRITEV(conn, CNO_BUFFER_STRING("0\r\n\r\n"))
              : CNO_OK)
                return CNO_ERROR_UP();
        } else if (length && CNO_WRITEV(conn, {data, length})) {
            return CNO_ERROR_UP();
        }
    } else {
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
    }

    return final && cno_discard_remaining_payload(conn, streamobj) ? CNO_ERROR_UP() : (int)length;
}

int cno_write_ping(struct cno_connection_t *conn, const char data[8])
{
    if (!cno_connection_is_http2(conn))
        return CNO_ERROR(ASSERTION, "cannot ping HTTP/1.x endpoints");
    struct cno_frame_t ping = { CNO_FRAME_PING, 0, 0, { data, 8 } };
    return cno_frame_write(conn, &ping);
}

int cno_write_frame(struct cno_connection_t *conn, const struct cno_frame_t *frame)
{
    if (!cno_connection_is_http2(conn))
        return CNO_ERROR(ASSERTION, "cannot send HTTP2 frames to HTTP/1.x endpoints");
    return cno_frame_write(conn, frame);
}

int cno_increase_flow_window(struct cno_connection_t *conn, uint32_t stream, uint32_t bytes)
{
    if (!bytes || !stream || !cno_connection_is_http2(conn))
        return CNO_OK;
    struct cno_stream_t *streamobj = cno_stream_find(conn, stream);
    if (!streamobj)
        return CNO_OK;
    streamobj->window_recv += bytes;
    struct cno_frame_t update = { CNO_FRAME_WINDOW_UPDATE, 0, stream, PACK(I32(bytes)) };
    return cno_frame_write(conn, &update);
}
