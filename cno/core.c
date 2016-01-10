#include <ctype.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cno/core.h>
#include <picohttpparser/picohttpparser.h>


static inline uint8_t  read1(const uint8_t *p) { return p[0]; }
static inline uint16_t read2(const uint8_t *p) { return p[0] <<  8 | p[1]; }
static inline uint32_t read4(const uint8_t *p) { return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }
static inline uint32_t read3(const uint8_t *p) { return read4(p) >> 8; }


// pack several bytes into an array, return it and its length.
#define PACK(...) (char *) (uint8_t []) { __VA_ARGS__ }, sizeof((uint8_t []) { __VA_ARGS__ })
#define I8(x)  x
#define I16(x) x >> 8, x
#define I24(x) x >> 16, x >> 8, x
#define I32(x) x >> 24, x >> 16, x >> 8, x


// PRI SM. heh.
static const struct cno_buffer_t CNO_PREFACE = CNO_BUFFER_CONST("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
static const struct cno_settings_t CNO_SETTINGS_STANDARD = {{{ 4096, 1, -1,   65536, 16384, -1 }}};
static const struct cno_settings_t CNO_SETTINGS_INITIAL  = {{{ 4096, 1, 1024, 65536, 65536, -1 }}};


/* check whether a stream is initiated by us, not our peer.
 *
 * even-numbered streams are initiated by the server.
 */
static int cno_stream_is_local(struct cno_connection_t *conn, uint32_t id)
{
    return id % 2 == !!conn->client;
}


/* deallocate a stream object *without firing a callback*.
 *
 * this is a fallback routine. since creating a stream always fires on_stream_start,
 * it should only be used if the state doesn't matter anymore.
 */
static void cno_stream_destroy(struct cno_connection_t *conn, struct cno_stream_t *stream)
{
    conn->stream_count[cno_stream_is_local(conn, stream->id)]--;

    struct cno_stream_t **s = &conn->streams[stream->id % CNO_STREAM_BUCKETS];
    while (*s != stream) s = &(*s)->next;
    *s = stream->next;

    free(stream);
}


/* deallocate a stream object.
 *
 * fires: on_stream_end.
 */
static int cno_stream_destroy_clean(struct cno_connection_t *conn, struct cno_stream_t *stream)
{
    uint32_t id = stream->id;
    cno_stream_destroy(conn, stream);
    return CNO_FIRE(conn, on_stream_end, id);
}


/* allocate resources for a new stream.
 *
 * third argument should be 1 (== CNO_PEER_LOCAL) iff we're initiating this stream.
 *
 * fires: on_stream_start.
 * throws:
 *   INVALID_STREAM if third argument is invalid.
 *   INVALID_STREAM if stream id is lower than that of some existing stream.
 *   WOULD_BLOCK    if we've already initiated too many streams.
 *   TRANSPORT      if the peer has gone over our limit on concurrent streams.
 *   NO_MEMORY
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

    struct cno_stream_t *stream = calloc(1, sizeof(struct cno_stream_t));

    if (!stream)
        return CNO_ERROR_NULL(NO_MEMORY, "%zu bytes", sizeof(struct cno_stream_t));

    stream->id = id;
    stream->window_recv = conn->settings[CNO_PEER_LOCAL].initial_window_size;
    stream->window_send = conn->settings[CNO_PEER_REMOTE].initial_window_size;
    stream->next = conn->streams[id % CNO_STREAM_BUCKETS];

    conn->streams[id % CNO_STREAM_BUCKETS] = stream;
    conn->last_stream[local] = id;
    conn->stream_count[local]++;

    if (CNO_FIRE(conn, on_stream_start, id)) {
        cno_stream_destroy(conn, stream);
        return CNO_ERROR_UP_NULL();
    }

    return stream;
}


/* retrieve a stream object by id, or NULL if not found.
 *
 * (that's a simple closed-hash prime-order map with integer keys.)
 */
static struct cno_stream_t * cno_stream_find(struct cno_connection_t *conn, uint32_t id)
{
    struct cno_stream_t *s = conn->streams[id % CNO_STREAM_BUCKETS];
    while (s && s->id != id) s = s->next;
    return s;
}


/* forbid sending any more data over this stream.
 *
 * inbound data will still be accepted. abort the stream (see cno_write_reset)
 * if that data is undesired.
 *
 * fires: on_stream_end if the stream is closed in the other direction as well.
 */
static int cno_stream_close(struct cno_connection_t *conn, struct cno_stream_t *stream)
{
    if (!(stream->accept & CNO_ACCEPT_INBOUND))
        return cno_stream_destroy_clean(conn, stream);

    stream->accept &= ~CNO_ACCEPT_OUTBOUND;
    return CNO_OK;
}


/* send a single frame. it should fit in the flow control window, though!
 *
 * fires: on_write, on_frame_send.
 * throws:
 *   ASSERTION   if a non-DATA frame exceeds the size limit (how)
 *   ASSERTION   if a padded frame exceeds the size limit (FIXME)
 */
static int cno_frame_write(struct cno_connection_t *conn,
                           struct cno_stream_t     *stream,
                           struct cno_frame_t      *frame)
{
    size_t length = frame->payload.size;
    size_t limit  = conn->settings[CNO_PEER_REMOTE].max_frame_size;

    if (length <= limit) {
        if (frame->type == CNO_FRAME_DATA) {
            if (stream)
                stream->window_send -= length;
            conn->window_send -= length;
        }

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
        if (cno_frame_write(conn, stream, &part))
            return CNO_ERROR_UP();

        length -= limit;
        part.flags &= ~(CNO_FLAG_PRIORITY | CNO_FLAG_END_STREAM);
        part.payload.data += limit;

        if (part.type != CNO_FRAME_DATA)
            part.type = CNO_FRAME_CONTINUATION;
    }

    part.flags |= frame->flags & carry_on_last;
    part.payload.size = length;
    return cno_frame_write(conn, stream, &part);
}


/* send an RST_STREAM frame (and close the stream for both input and output.)
 *
 * fires: on_write, on_frame_send, maybe on_stream_end.
 * throws: ASSERTION if attempted to reset stream 0
 */
static int cno_frame_write_rst_stream(struct cno_connection_t *conn,
                                      uint32_t stream,
                                      uint32_t /* enum CNO_RST_STREAM_CODE */ code)
{
    if (!stream)
        return CNO_ERROR(ASSERTION, "RST'd stream 0");

    struct cno_stream_t *obj = cno_stream_find(conn, stream);

    if (!obj)
        return CNO_OK;  // assume stream already ended naturally

    struct cno_frame_t error = { CNO_FRAME_RST_STREAM, 0, 0, stream, { PACK(I32(code)) } };

    if (cno_frame_write(conn, obj, &error))
        return CNO_ERROR_UP();

    // a stream in closed state can still accept headers/data.
    // headers will be decompressed; other than that, everything is ignored.
    obj->closed  = 1;
    obj->accept &= ~CNO_ACCEPT_OUTBOUND;

    if (!(obj->accept & CNO_ACCEPT_HEADERS))
        // since headers were already handled, this stream can be safely destroyed.
        return cno_stream_destroy_clean(conn, obj);

    return CNO_OK;
}


/* send a GOAWAY frame.
 *
 * fires: on_write, on_frame_send.
 */
static int cno_frame_write_goaway(struct cno_connection_t *conn, uint32_t /* enum CNO_RST_STREAM_CODE */ code)
{
    uint32_t last = conn->last_stream[CNO_PEER_REMOTE];
    struct cno_frame_t error = { CNO_FRAME_GOAWAY, 0, 0, 0, { PACK(I32(last), I32(code)) } };
    return cno_frame_write(conn, NULL, &error);
}


/* close a connection due to an error.
 *
 * fires: on_write, on_frame_send.
 * throws: TRANSPORT, always.
 */
#define cno_frame_write_error(conn, type, ...)           \
    (cno_frame_write_goaway(conn, type) ? CNO_ERROR_UP() \
                                        : CNO_ERROR(TRANSPORT, __VA_ARGS__))


/* close a connection due to a generic protocol error.
 *
 * fires: on_write, on_frame_send.
 * throws: TRANSPORT.
 */
#define cno_protocol_error(conn, ...) \
    cno_frame_write_error(conn, CNO_RST_PROTOCOL_ERROR, __VA_ARGS__)


static int cno_frame_parse_headers(struct cno_connection_t *conn,
                                   struct cno_stream_t     *stream,
                                   struct cno_message_t    *msg, int is_response)
{
    const char *p;
    const struct cno_header_t *it = msg->headers;
    int seen_normal = 0;

    for (; it != msg->headers + msg->headers_len; ++it)
        if (!cno_buffer_startswith(it->name, CNO_BUFFER_CONST(":"))) {
            seen_normal = 1;

            // TODO reject connection-specific headers
            for (p = it->name.data; p != it->name.data + it->name.size; p++)
                if ('A' <= *p && *p <= 'Z')
                    goto invalid_message;
        }
        else if (seen_normal)
            goto invalid_message;

        else if (!is_response && cno_buffer_eq(it->name, CNO_BUFFER_CONST(":path"))) {
            if (msg->path.data)
                goto invalid_message;

            msg->path.data = it->value.data;
            msg->path.size = it->value.size;
        }
        else if (!is_response && cno_buffer_eq(it->name, CNO_BUFFER_CONST(":method"))) {
            if (msg->method.data)
                goto invalid_message;

            msg->method.data = it->value.data;
            msg->method.size = it->value.size;
        }
        else if (!is_response && cno_buffer_eq(it->name, CNO_BUFFER_CONST(":authority")))
            {}  // nop
        else if (!is_response && cno_buffer_eq(it->name, CNO_BUFFER_CONST(":scheme")))
            {}  // nop

        else if (is_response && cno_buffer_eq(it->name, CNO_BUFFER_CONST(":status"))) {
            if (msg->code)
                goto invalid_message;

            for (p = it->value.data; p != it->value.data + it->value.size; p++) {
                if (*p < '0' || '9' < *p)
                    goto invalid_message;

                msg->code = msg->code * 10 + (*p - '0');
            }
        }
        else invalid_message: {
            msg->code = -1;
            return cno_frame_write_rst_stream(conn, stream->id, CNO_RST_PROTOCOL_ERROR);
        }

    if (is_response ? !msg->code
                    : !msg->path.data || !msg->method.data)
        goto invalid_message;

    return CNO_OK;
}


/* handle a frame that carries an END_STREAM flag.
 *
 * fires:
 *   on_message_end
 *   on_stream_end   if the stream is now closed in both directions.
 */
static int cno_frame_handle_end_stream(struct cno_connection_t *conn,
                                       struct cno_stream_t     *stream)
{
    int dont_close = stream->accept &= ~CNO_ACCEPT_INBOUND;

    if (CNO_FIRE(conn, on_message_end, stream->id))
        return CNO_ERROR_UP();

    if (dont_close)
        return CNO_OK;

    return cno_stream_destroy_clean(conn, stream);
}


/* handle a frame that carries an END_HEADERS flag.
 *
 * fires:
 *   on_message_push   if the frame is PUSH_PROMISE.
 *   on_message_start  if the frame is HEADERS and the stream was not reset.
 *
 * throws: TRANSPORT if header block is corrupt.
 */
static int cno_frame_handle_end_headers(struct cno_connection_t *conn,
                                        struct cno_stream_t     *stream,
                                        struct cno_frame_t      *frame, uint32_t promise)
{
    struct cno_header_t  headers[CNO_MAX_HEADERS];
    struct cno_message_t msg = { 0, CNO_BUFFER_EMPTY, CNO_BUFFER_EMPTY, headers, CNO_MAX_HEADERS };

    if (cno_hpack_decode(&conn->decoder, conn->continued.as_static, headers, &msg.headers_len)) {
        cno_buffer_dyn_clear(&conn->continued);
        cno_frame_write_goaway(conn, CNO_RST_COMPRESSION_ERROR);
        return CNO_ERROR_UP();
    }

    cno_buffer_dyn_clear(&conn->continued);
    conn->continued_stream  = 0;
    conn->continued_promise = 0;

    int failed = cno_frame_parse_headers(conn, stream, &msg, conn->client && promise == 0);

    if (!failed && msg.code != -1) {
        if (promise)
            // accept pushes even on reset streams.
            failed = CNO_FIRE(conn, on_message_push, promise, &msg, stream->id);
        else {
            stream->accept &= ~CNO_ACCEPT_HEADERS;
            stream->accept |=  CNO_ACCEPT_DATA;

            if (stream->closed)
                failed = cno_stream_destroy_clean(conn, stream);
            else if (CNO_FIRE(conn, on_message_start, stream->id, &msg))
                failed = -1;
            else if (frame->flags & CNO_FLAG_END_STREAM)
                failed = cno_frame_handle_end_stream(conn, stream);
        }
    }

    for (; msg.headers_len; msg.headers++, msg.headers_len--) {
        cno_buffer_clear(&msg.headers->name);
        cno_buffer_clear(&msg.headers->value);
    }

    return failed;
}


/* handle a HEADERS frame.
 *
 * fires:
 *   on_message_start  if the frame has END_HEADERS set.
 *   on_message_end    if the frame has END_STREAM set.
 *   on_stream_end     if the frame has END_STREAM and the stream was unidirectional.
 */
static int cno_frame_handle_headers(struct cno_connection_t *conn,
                                    struct cno_stream_t     *stream,
                                    struct cno_frame_t      *frame)
{
    if (stream == NULL) {
        stream = cno_stream_new(conn, frame->stream, CNO_PEER_REMOTE);

        if (stream == NULL)
            return CNO_ERROR_UP();

        stream->accept = CNO_ACCEPT_HEADERS | CNO_ACCEPT_WRITE_HEADERS | CNO_ACCEPT_WRITE_PUSH;
    }

    if (!(stream->accept & CNO_ACCEPT_HEADERS))
        return CNO_ERROR(TRANSPORT, "got HEADERS when expected none");

    if (frame->flags & CNO_FLAG_PRIORITY) {
        if (frame->payload.size < 5)
            return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "no priority spec");

        // can do nothing with this data without access to the transport layer :((
        frame->payload.data += 5;
        frame->payload.size -= 5;
    }

    conn->continued_flags = frame->flags & CNO_FLAG_END_STREAM;
    conn->continued_stream = stream->id;

    if (cno_buffer_dyn_concat(&conn->continued, frame->payload))
        // note that we could've created the stream, but we don't need to bother
        // destroying it. this error is non-recoverable; cno_connection_destroy
        // will handle things.
        return CNO_ERROR_UP();

    if (frame->flags & CNO_FLAG_END_HEADERS)
        return cno_frame_handle_end_headers(conn, stream, frame, 0);

    return CNO_OK;
}


/* handle a PUSH_PROMISE frame.
 *
 * fires: on_message_push if the frame has END_HEADERS set.
 */
static int cno_frame_handle_push_promise(struct cno_connection_t *conn,
                                         struct cno_stream_t     *stream,
                                         struct cno_frame_t      *frame)
{
    if (!stream || !(stream->accept & CNO_ACCEPT_PUSH))
        // also triggers if the other side is not a server
        return CNO_ERROR(TRANSPORT, "unexpected PUSH_PROMISE");

    if (!conn->settings[CNO_PEER_LOCAL].enable_push)
        return CNO_ERROR(TRANSPORT, "forbidden PUSH_PROMISE");

    if (frame->payload.size < 4)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "PUSH_PROMISE too short");

    uint32_t promised = read4((uint8_t *) frame->payload.data);
    frame->payload.data += 4;
    frame->payload.size -= 4;

    struct cno_stream_t *pushed = cno_stream_new(conn, promised, CNO_PEER_REMOTE);

    if (pushed == NULL)
        return CNO_ERROR_UP();

    pushed->accept = CNO_ACCEPT_HEADERS;
    conn->continued_flags = 0;  // PUSH_PROMISE cannot have END_STREAM
    conn->continued_stream = stream->id;
    conn->continued_promise = promised;

    if (cno_buffer_dyn_concat(&conn->continued, frame->payload))
        // same as headers -- this error affects the state of the decoder and will
        // completely screw the connection. no need to destroy the stream.
        return CNO_ERROR_UP();

    if (frame->flags & CNO_FLAG_END_HEADERS)
        return cno_frame_handle_end_headers(conn, stream, frame, promised);

    return CNO_OK;
}


/* handle a CONTINUATION.
 *
 * fires: same as *_headers or *_push_promise, depending on what is continued.
 */
static int cno_frame_handle_continuation(struct cno_connection_t *conn,
                                         struct cno_stream_t     *stream,
                                         struct cno_frame_t      *frame)
{
    if (!stream)
        return CNO_ERROR(TRANSPORT, "CONTINUATION on a non-existent stream");

    if (!conn->continued_stream)
        return CNO_ERROR(TRANSPORT, "CONTINUATION not after HEADERS/PUSH_PROMISE");

    frame->flags |= conn->continued_flags;

    // we don't actually count CONTINUATIONs, but this is a good estimate. especially
    // if the other side decides to send the message as a bunch of small frames
    // for some reason.
    size_t max_buf_size = (CNO_MAX_CONTINUATIONS + 1) * conn->settings[CNO_PEER_LOCAL].max_frame_size;

    if (frame->payload.size + conn->continued.size > max_buf_size)
        // finally a chance to use that error code.
        return cno_frame_write_error(conn, CNO_RST_ENHANCE_YOUR_CALM, "too many HEADERS");

    if (cno_buffer_dyn_concat(&conn->continued, frame->payload))
        return CNO_ERROR_UP();

    if (frame->flags & CNO_FLAG_END_HEADERS)
        return cno_frame_handle_end_headers(conn, stream, frame, conn->continued_promise);

    return CNO_OK;
}


/* ignore non-HEADERS frames on reset streams, as the spec requires. unfortunately,
 * these are indistinguishable from streams that were never opened, but hey, what
 * can i do, keep a set of uint32_t-s? memory doesn't grow on trees, you know. */
static int cno_frame_invalid_stream(struct cno_connection_t *conn, struct cno_frame_t *frame)
{
    return 0 < frame->stream && frame->stream <= conn->last_stream[cno_stream_is_local(conn, frame->stream)]
        ? CNO_OK
        : CNO_ERROR(TRANSPORT, "invalid stream");
}


/* handle a DATA frame. this includes sending a WINDOW_UPDATE to compensate for its size.
 *
 * fires:
 *   on_message_data
 *   on_message_end   if carries END_STREAM
 *   on_stream_end    if carries END_STREAM and the stream is (was) unidirectional
 */
static int cno_frame_handle_data(struct cno_connection_t *conn,
                                 struct cno_stream_t     *stream,
                                 struct cno_frame_t      *frame)
{
    uint32_t length = frame->payload.size + frame->padding;

    if (length) {
        // XXX do frames sent to closed streams count against flow control?
        //     what if the stream never even existed?
        struct cno_frame_t update = { CNO_FRAME_WINDOW_UPDATE, 0, 0, 0, { PACK(I32(length)) } };

        if (cno_frame_write(conn, NULL, &update))
            return CNO_ERROR_UP();

        // TODO update window_recv, should it ever become used.
    }

    if (!stream)
        return cno_frame_invalid_stream(conn, frame);

    if (!(stream->accept & CNO_ACCEPT_DATA))
        return cno_frame_write_rst_stream(conn, frame->stream, CNO_RST_STREAM_CLOSED);

    if (CNO_FIRE(conn, on_message_data, frame->stream, frame->payload.data, frame->payload.size))
        return CNO_ERROR_UP();

    if (frame->flags & CNO_FLAG_END_STREAM)
        return cno_frame_handle_end_stream(conn, stream);

    if (!length)
        return CNO_OK;

    struct cno_frame_t update = { CNO_FRAME_WINDOW_UPDATE, 0, 0, stream->id, { PACK(I32(length)) } };
    return cno_frame_write(conn, stream, &update);
}


/* handle a PING frame, maybe by sending a pong.
 *
 * fires: on_pong technically, never, as there is no way to send a ping for now.
 */
static int cno_frame_handle_ping(struct cno_connection_t *conn,
                                 struct cno_stream_t     *stream __attribute__((unused)),
                                 struct cno_frame_t      *frame)
{
    if (frame->stream)
        return cno_protocol_error(conn, "PING on nonzero stream");

    if (frame->payload.size != 8)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad PING frame");

    if (frame->flags & CNO_FLAG_ACK)
        return CNO_FIRE(conn, on_pong, frame->payload.data);

    struct cno_frame_t response = { CNO_FRAME_PING, CNO_FLAG_ACK, 0, 0, frame->payload };
    return cno_frame_write(conn, NULL, &response);
}


/* handle a GOAWAY frame, at least when the error code is nonzero.
 * when it is, i have no idea what to do.
 *
 * fires: nothing.
 * throws: TRANSPORT if this frame is due to an error on our part.
 */
static int cno_frame_handle_goaway(struct cno_connection_t *conn,
                                   struct cno_stream_t     *stream __attribute__((unused)),
                                   struct cno_frame_t      *frame)
{
    if (frame->stream)
        return cno_protocol_error(conn, "got GOAWAY on stream %u", frame->stream);

    if (frame->payload.size < 8)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad GOAWAY");

    uint32_t error = read4((uint8_t *) &frame->payload.data[4]);

    if (error != CNO_RST_NO_ERROR)
        return CNO_ERROR(TRANSPORT, "disconnected with error %u", error);

    return CNO_OK;
}


/* handle an RST_STREAM frame by destroying an appropriate object.
 *
 * fires: on_stream_end.
 */
static int cno_frame_handle_rst_stream(struct cno_connection_t *conn,
                                       struct cno_stream_t     *stream,
                                       struct cno_frame_t      *frame)
{
    if (!stream)
        return cno_frame_invalid_stream(conn, frame);

    if (frame->payload.size != 4)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad RST_STREAM");

    // TODO parse the error code and do something with it.
    return cno_stream_destroy_clean(conn, stream);
}


/* do not handle a PRIORITY frame. prioritizing streams requires knowledge about
 * the transport layer (essentially, a normal write buffer should be transformed into
 * a priority queue of frames to send), which we do not have. we simply assume that
 * everything sent through on_write is transmitted instantly, so there's no contention.
 *
 * fires: also nothing.
 */
static int cno_frame_handle_priority(struct cno_connection_t *conn,
                                     struct cno_stream_t     *stream __attribute__((unused)),
                                     struct cno_frame_t      *frame)
{
    if (!frame->stream)
        return cno_protocol_error(conn, "PRIORITY on stream 0");

    if (frame->payload.size != 5)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad PRIORITY");

    return CNO_OK;
}


/* handle a SETTINGS frame and apply everything it says to our connection.
 *
 * fires: on_flow_increase if the frame carries a new flow control window size.
 */
static int cno_frame_handle_settings(struct cno_connection_t *conn,
                                     struct cno_stream_t     *stream __attribute__((unused)),
                                     struct cno_frame_t      *frame)
{
    if (frame->stream)
        return cno_protocol_error(conn, "SETTINGS not on stream 0");

    if (frame->flags & CNO_FLAG_ACK)
        return frame->payload.size == 0
             ? CNO_OK
             : cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad SETTINGS ack");

    if (frame->payload.size % 6)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad SETTINGS");

    struct cno_settings_t *cfg = &conn->settings[CNO_PEER_REMOTE];
    uint8_t *ptr = (uint8_t *) frame->payload.data;
    uint8_t *end = ptr + frame->payload.size;

    for (; ptr != end; ptr += 6) {
        uint16_t setting = read2(ptr);
        uint32_t value   = read4(ptr + 2);

        if (setting && setting < CNO_SETTINGS_UNDEFINED)
            cfg->array[setting - 1] = value;
    }

    if (cfg->enable_push != 0 && cfg->enable_push != 1)
        return cno_protocol_error(conn, "invalid enable_push value %u", cfg->enable_push);

    if (cfg->initial_window_size >= 0x80000000u)
        return cno_frame_write_error(conn, CNO_RST_FLOW_CONTROL_ERROR,
                                     "initial flow window out of bounds [0..2^31)");

    if (cfg->max_frame_size < 16384 || cfg->max_frame_size > 16777215)
        return cno_protocol_error(conn, "maximum frame size out of bounds (2^14..2^24)");

    conn->encoder.limit_upper = cfg->header_table_size;
    cno_hpack_setlimit(&conn->encoder, conn->encoder.limit_upper);
    // TODO update stream flow control windows.

    struct cno_frame_t ack = { CNO_FRAME_SETTINGS, CNO_FLAG_ACK, 0, 0, CNO_BUFFER_EMPTY };
    return cno_frame_write(conn, NULL, &ack);
}


/* handle a WINDOW_UPDATE frame.
 *
 * fires: on_flow_increase.
 */
static int cno_frame_handle_window_update(struct cno_connection_t *conn,
                                          struct cno_stream_t     *stream,
                                          struct cno_frame_t      *frame)
{
    if (frame->payload.size != 4)
        return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "bad WINDOW_UPDATE");

    uint32_t increment = read4((uint8_t *) frame->payload.data);

    if (increment == 0 || increment >= 0x80000000u)
        return CNO_ERROR(TRANSPORT, "window increment out of bounds (0..2^31)");

    if (!frame->stream) {
        conn->window_send += increment;

        if (conn->window_send >= 0x80000000u)
            return cno_frame_write_error(conn, CNO_RST_FLOW_CONTROL_ERROR, "flow control window got too big");
    } else if (stream != NULL) {
        stream->window_send += increment;

        if (stream->window_send >= 0x80000000u)
            return cno_frame_write_rst_stream(conn, frame->stream, CNO_RST_FLOW_CONTROL_ERROR);
    } else
        return cno_frame_invalid_stream(conn, frame);

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
            return cno_protocol_error(conn, "expected a CONTINUATION");

    if (frame->flags & CNO_FLAG_PADDED) {
        if (frame->payload.size == 0)
            return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "no padding");

        frame->padding = read1((uint8_t *) frame->payload.data) + 1;

        if (frame->padding > frame->payload.size)
            return cno_protocol_error(conn, "truncated frame with padding");

        frame->payload.data += 1;  // padding follows the data.
        frame->payload.size -= frame->padding;
    }

    if (frame->type >= CNO_FRAME_UNKNOWN)
        return CNO_OK;

    struct cno_stream_t *stream = cno_stream_find(conn, frame->stream);
    return CNO_FRAME_HANDLERS[frame->type](conn, stream, frame);
}


/* send a SETTINGS frame containing the delta from one configuration to the other.
 *
 * fires:
 *   on_write
 *   on_frame_send
 */
static int cno_settings_diff(struct cno_connection_t *conn,
                       const struct cno_settings_t *a,
                       const struct cno_settings_t *b)
{
    size_t i = 0;
    uint8_t payload[CNO_SETTINGS_UNDEFINED - 1][6], (*ptr)[6] = payload;
    const uint32_t *ax = a->array;
    const uint32_t *bx = b->array;

    for (; ++i < CNO_SETTINGS_UNDEFINED; ++ax, ++bx)
        if (*ax != *bx)
            memcpy(ptr++, PACK(I16(i), I32(*bx)));

    struct cno_frame_t frame = { CNO_FRAME_SETTINGS, 0, 0, 0, { (char *) payload, (ptr - payload) * 6 } };
    return cno_frame_write(conn, NULL, &frame);
}


/* copy the current local settings into a provided struct. modify that struct
 * then call cno_settings_apply to change the configuration. */
void cno_settings_copy(struct cno_connection_t *conn, struct cno_settings_t *target)
{
    memcpy(target, &conn->settings[CNO_PEER_LOCAL], sizeof(*target));
}


/* check the new config and apply it to the local end of the connection.
 * (there's also the remote version of the configuration which we can't affect. each
 * side has to conform to the other's config, e.g. a server should only send push
 * promises if the client allows it even if the server itself has set enable_push to 0.)
 *
 * throws: ASSERTION if one of the parameters was set incorrectly.
 */
int cno_settings_apply(struct cno_connection_t *conn, const struct cno_settings_t *settings)
{
    if (settings->enable_push != 0 && settings->enable_push != 1)
        return CNO_ERROR(ASSERTION, "enable_push neither 0 nor 1");

    if (settings->max_frame_size < 16384 || settings->max_frame_size > 16777215)
        return CNO_ERROR(ASSERTION, "maximum frame size out of bounds (2^14..2^24-1)");

    if (conn->state != CNO_CONNECTION_INIT && cno_connection_is_http2(conn))
        // If not yet in HTTP2 mode, `cno_connection_upgrade` will send the SETTINGS frame.
        if (cno_settings_diff(conn, conn->settings + CNO_PEER_LOCAL, settings))
            return CNO_ERROR_UP();

    memcpy(&conn->settings[CNO_PEER_LOCAL], settings, sizeof(*settings));
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
        .settings    = { /* remote = */ CNO_SETTINGS_STANDARD,
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

    struct cno_stream_t **s;

    for (s = &conn->streams[0]; s != &conn->streams[CNO_STREAM_BUCKETS]; s++)
        while (*s)
            cno_stream_destroy(conn, *s);
}


/* return 1 iff the requests/responses will be sent as http 2. note that there
 * may still be an http 1 request in the buffer. */
int cno_connection_is_http2(struct cno_connection_t *conn)
{
    return conn->state != CNO_CONNECTION_HTTP1_INIT &&
           conn->state != CNO_CONNECTION_HTTP1_READY &&
           conn->state != CNO_CONNECTION_HTTP1_READING;
}


/* switch the outbound communication to http 2 mode. */
static int cno_connection_upgrade(struct cno_connection_t *conn)
{
    if (conn->client && CNO_FIRE(conn, on_write, CNO_PREFACE.data, CNO_PREFACE.size))
        return CNO_ERROR_UP();

    return cno_settings_diff(conn, &CNO_SETTINGS_STANDARD, &conn->settings[CNO_PEER_LOCAL]);
}


/* consume as much of the buffered data as possible. yep, this is a dfa!
 *
 * fires: EVERYTHING.
 */
static int cno_connection_proceed(struct cno_connection_t *conn)
{
    while (1) switch (conn->state) {
        case CNO_CONNECTION_UNDEFINED:
            return CNO_OK;  // wait until connection_made before processing data

        case CNO_CONNECTION_HTTP1_INIT:
            conn->state = CNO_CONNECTION_HTTP1_READY;

            if (cno_stream_new(conn, 1, !!conn->client) == NULL)
                return CNO_ERROR_UP();

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

            // should be exactly one stream right now.
            struct cno_stream_t *stream = cno_stream_find(conn, 1);

            // the http 2 client preface looks like an http 1 request, but is not.
            // picohttpparser will reject it. (note: CNO_PREFACE is null-terminated.)
            if (!conn->client && !strncmp(conn->buffer.data, CNO_PREFACE.data, conn->buffer.size)) {
                if (conn->buffer.size < CNO_PREFACE.size)
                    return CNO_OK;

                conn->state = CNO_CONNECTION_INIT;
                conn->last_stream[CNO_PEER_REMOTE] = 0;
                conn->last_stream[CNO_PEER_LOCAL]  = 0;

                if (cno_stream_destroy_clean(conn, stream))
                    return CNO_ERROR_UP();
                break;
            }

            // `phr_header` and `cno_header_t` have same contents.
            struct cno_header_t headers[CNO_MAX_HEADERS];
            struct cno_header_t *it = headers;
            struct cno_header_t *end;
            struct cno_message_t msg = { 0, CNO_BUFFER_EMPTY, CNO_BUFFER_EMPTY, headers, CNO_MAX_HEADERS };

            int minor;
            int ok = conn->client
              ? phr_parse_response(conn->buffer.data, conn->buffer.size, &minor, &msg.code,
                    (const char **) &msg.method.data, &msg.method.size,
                    (struct phr_header *) headers, &msg.headers_len, 0)

              : phr_parse_request(conn->buffer.data, conn->buffer.size,
                    (const char **) &msg.method.data, &msg.method.size,
                    (const char **) &msg.path.data, &msg.path.size,
                    &minor, (struct phr_header *) headers, &msg.headers_len, 0);

            if (ok == -2)
                return CNO_OK;
            if (ok == -1)
                return CNO_ERROR(TRANSPORT, "bad HTTP/1.x message");
            if (minor != 1)
                return CNO_ERROR(TRANSPORT, "HTTP/1.%d not supported", minor);

            conn->http1_remaining = 0;

            for (end = it + msg.headers_len; it != end; ++it) {
                {   // header names are case-insensitive
                    char * n = it->name.data;
                    size_t s = it->name.size;
                    for (; s--; n++) *n = tolower(*n);
                }

                if (cno_buffer_eq(it->name, CNO_BUFFER_CONST("http2-settings"))) {
                    // TODO decode & emit on_frame
                } else

                if (!conn->client && cno_buffer_eq(it->name,  CNO_BUFFER_CONST("upgrade"))
                                  && cno_buffer_eq(it->value, CNO_BUFFER_CONST("h2c"))) {
                    if (conn->state != CNO_CONNECTION_HTTP1_READY)
                        return CNO_ERROR(TRANSPORT, "bad HTTP/1.x message: multiple upgrade headers");

                    struct cno_header_t upgrade_headers[] = {
                        { CNO_BUFFER_CONST("connection"), CNO_BUFFER_CONST("upgrade") },
                        { CNO_BUFFER_CONST("upgrade"),    CNO_BUFFER_CONST("h2c")     },
                    };

                    struct cno_message_t upgrade_msg = { 101, CNO_BUFFER_EMPTY, CNO_BUFFER_EMPTY, upgrade_headers, 2 };

                    if (cno_write_message(conn, stream->id, &upgrade_msg, 1))
                        return CNO_ERROR_UP();

                    // if we send the preface now, we'll be able to send HTTP 2 frames
                    // while in the HTTP1_READING_UPGRADE state.
                    if (cno_connection_upgrade(conn))
                        return CNO_ERROR_UP();

                    // technically, server should refuse if HTTP2-Settings are not present.
                    // we'll let this slide.
                    conn->state = CNO_CONNECTION_HTTP1_READING_UPGRADE;
                } else

                if (cno_buffer_eq(it->name, CNO_BUFFER_CONST("content-length"))) {
                    if (conn->http1_remaining)
                        return CNO_ERROR(TRANSPORT, "bad HTTP/1.x message: multiple content-lengths");

                    char *ptr = it->value.data;
                    char *end = it->value.data + it->value.size;

                    while (ptr != end)
                        if ('0' <= *ptr && *ptr <= '9')
                            conn->http1_remaining = conn->http1_remaining * 10 + (*ptr++ - '0');
                        else
                            return CNO_ERROR(TRANSPORT, "bad HTTP/1.x message: non-int length");
                } else

                if (cno_buffer_eq(it->name, CNO_BUFFER_CONST("transfer-encoding"))) {
                    if (!cno_buffer_eq(it->value, CNO_BUFFER_CONST("chunked")))
                        return CNO_ERROR(TRANSPORT, "bad HTTP/1.x message: unknown transfer-encoding");

                    if (conn->http1_remaining)
                        return CNO_ERROR(TRANSPORT, "bad HTTP/1.x message: chunked encoding w/ fixed length");

                    conn->http1_remaining = (uint32_t) -1;
                }
            }

            stream->accept |= CNO_ACCEPT_WRITE_HEADERS;

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

            if (!conn->http1_remaining) {
                conn->state = conn->state == CNO_CONNECTION_HTTP1_READING_UPGRADE
                    ? CNO_CONNECTION_PREFACE
                    : CNO_CONNECTION_HTTP1_READY;

                if (CNO_FIRE(conn, on_message_end, stream->id))
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

                if (total > conn->settings[CNO_PEER_LOCAL].max_frame_size)
                    return CNO_ERROR(TRANSPORT, "HTTP/1.x chunk too big");

                if (conn->buffer.size < total)
                    return CNO_OK;

                cno_buffer_dyn_shift(&conn->buffer, total);

                if (!total)
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

            uint8_t *base = (uint8_t *) conn->buffer.data;
            size_t m = read3(base);

            if (m > conn->settings[CNO_PEER_LOCAL].max_frame_size)
                return cno_frame_write_error(conn, CNO_RST_FRAME_SIZE_ERROR, "frame too big");

            if (conn->buffer.size < 9 + m)
                return CNO_OK;

            struct cno_frame_t frame = { read1(&base[3]), read1(&base[4]), 0, read4(&base[5]), { (char *) &base[9], m } };

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
        return CNO_ERROR(INVALID_STATE, "connection closed");

    if (cno_buffer_dyn_concat(&conn->buffer, (struct cno_buffer_t) { (char *) data, length }))
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
            if (cno_stream_destroy_clean(conn, *s))
                return CNO_ERROR_UP();

    cno_buffer_dyn_clear(&conn->buffer);
    return CNO_OK;
}


uint32_t cno_stream_next_id(struct cno_connection_t *conn)
{
    if (!cno_connection_is_http2(conn))
        return 1;

    uint32_t last = conn->last_stream[CNO_PEER_LOCAL];

    if (last || !conn->client)
        return last + 2;

    // client-initiated streams are odd-numbered, but right now, `last` is 0.
    return 1;
}


int cno_write_reset(struct cno_connection_t *conn, size_t stream)
{
    if (!cno_connection_is_http2(conn))
        return CNO_ERROR(DISCONNECT, "HTTP/1.x connection rejected");

    return cno_frame_write_rst_stream(conn, stream, CNO_RST_CANCEL);
}


int cno_write_push(struct cno_connection_t *conn, size_t stream, const struct cno_message_t *msg)
{
    if (conn->state == CNO_CONNECTION_UNDEFINED)
        return CNO_ERROR(INVALID_STATE, "connection closed");

    if (conn->client)
        return CNO_ERROR(ASSERTION, "clients can't push");

    if (!cno_connection_is_http2(conn) || !conn->settings[CNO_PEER_REMOTE].enable_push)
        return CNO_OK;

    if (cno_stream_is_local(conn, stream))
        return CNO_OK;  // don't push in response to our own push

    struct cno_stream_t *streamobj = cno_stream_find(conn, stream);

    if (streamobj == NULL || !(streamobj->accept & CNO_ACCEPT_WRITE_PUSH))
        return CNO_ERROR(INVALID_STREAM, "stream %zu is not a response stream", stream);

    struct cno_buffer_dyn_t payload = CNO_BUFFER_DYN_ALIAS(CNO_BUFFER_EMPTY);
    struct cno_frame_t frame = { CNO_FRAME_PUSH_PROMISE, CNO_FLAG_END_HEADERS, 0, stream, CNO_BUFFER_EMPTY };
    struct cno_header_t head[2] = {
        { CNO_BUFFER_CONST(":method"), msg->method },
        { CNO_BUFFER_CONST(":path"),   msg->path   },
    };

    uint32_t child = cno_stream_next_id(conn);

    if (cno_buffer_dyn_concat(&payload, (struct cno_buffer_t) { PACK(I32(child)) })
    ||  cno_hpack_encode(&conn->encoder, &payload, head, 2)
    ||  cno_hpack_encode(&conn->encoder, &payload, msg->headers, msg->headers_len))
        goto payload_generation_error;

    frame.payload = payload.as_static;

    if (cno_frame_write(conn, streamobj, &frame))
        goto payload_generation_error;

    cno_buffer_dyn_clear(&payload);

    struct cno_stream_t *childobj = cno_stream_new(conn, child, CNO_PEER_LOCAL);

    if (childobj == NULL)
        return CNO_ERROR_UP();

    childobj->accept = CNO_ACCEPT_WRITE_HEADERS;

    return CNO_FIRE(conn, on_message_start, child, msg)
        || CNO_FIRE(conn, on_message_end,   child);

payload_generation_error:
    cno_buffer_dyn_clear(&payload);
    return CNO_ERROR_UP();
}


int cno_write_message(struct cno_connection_t *conn, size_t stream, const struct cno_message_t *msg, int final)
{
    if (conn->state == CNO_CONNECTION_UNDEFINED)
        return CNO_ERROR(INVALID_STATE, "connection closed");

    if (!cno_connection_is_http2(conn)) {
        if (stream != 1)
            return CNO_ERROR(INVALID_STREAM, "can only write to stream 1 in HTTP 1 mode, not %zu", stream);

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

        for (; it != end; ++it) {
            if (size && CNO_FIRE(conn, on_write, buffer, size))
                return CNO_ERROR_UP();

            if (cno_buffer_eq(it->name, CNO_BUFFER_CONST(":authority")))
                size = snprintf(buffer, sizeof(buffer), "host: %.*s\r\n",
                    (int) it->value.size, it->value.data);

            else if (cno_buffer_startswith(it->name, CNO_BUFFER_CONST(":")))
                size = 0;

            else {
                size = snprintf(buffer, sizeof(buffer), "%.*s: %.*s\r\n",
                    (int) it->name.size,  it->name.data,
                    (int) it->value.size, it->value.data);

                if (cno_buffer_eq(it->name, CNO_BUFFER_CONST("connection")))
                    had_connection_header = 1;
            }

            if (size > CNO_MAX_HTTP1_HEADER_SIZE)
                return CNO_ERROR(ASSERTION, "header too big\r\n");
        }

        if (!had_connection_header) {
            struct cno_buffer_t conn_header = CNO_BUFFER_CONST("connection: keep-alive\r\n");

            if (CNO_FIRE(conn, on_write, conn_header.data, conn_header.size))
                return CNO_ERROR_UP();
        }

        buffer[size + 0] = '\r';
        buffer[size + 1] = '\n';
        return CNO_FIRE(conn, on_write, buffer, size + 2);
    }

    struct cno_stream_t *streamobj = cno_stream_find(conn, stream);

    if (streamobj == NULL) {
        if (!conn->client)
            return CNO_ERROR(INVALID_STREAM, "responding to invalid stream %zu", stream);

        streamobj = cno_stream_new(conn, stream, CNO_PEER_LOCAL);

        if (streamobj == NULL)
            return CNO_ERROR_UP();

        streamobj->accept = CNO_ACCEPT_HEADERS | CNO_ACCEPT_PUSH | CNO_ACCEPT_WRITE_HEADERS;
    }

    if (!(streamobj->accept & CNO_ACCEPT_WRITE_HEADERS))
        return CNO_ERROR(INVALID_STREAM, "stream %zu not writable", stream);

    struct cno_buffer_dyn_t payload = CNO_BUFFER_DYN_ALIAS(CNO_BUFFER_EMPTY);
    struct cno_frame_t frame = { CNO_FRAME_HEADERS, CNO_FLAG_END_HEADERS, 0, stream, CNO_BUFFER_EMPTY };

    if (final)
        frame.flags |= CNO_FLAG_END_STREAM;

    if (conn->client) {
        struct cno_header_t head[] = {
            { CNO_BUFFER_CONST(":method"), msg->method },
            { CNO_BUFFER_CONST(":path"),   msg->path   },
        };

        if (cno_hpack_encode(&conn->encoder, &payload, head, 2))
            goto payload_generation_error;
    } else {
        char code[10] = { 0 };
        snprintf(code, 10, "%d", msg->code);

        struct cno_header_t head[] = {
            { CNO_BUFFER_CONST(":status"), CNO_BUFFER_STRING(code) }
        };

        if (cno_hpack_encode(&conn->encoder, &payload, head, 1))
            goto payload_generation_error;
    }


    if (cno_hpack_encode(&conn->encoder, &payload, msg->headers, msg->headers_len))
        goto payload_generation_error;

    frame.payload = payload.as_static;

    if (cno_frame_write(conn, streamobj, &frame))
        goto payload_generation_error;

    cno_buffer_dyn_clear(&payload);

    if (final)
        return cno_stream_close(conn, streamobj);

    streamobj->accept &= ~CNO_ACCEPT_WRITE_HEADERS;
    streamobj->accept |=  CNO_ACCEPT_WRITE_DATA;
    return CNO_OK;

payload_generation_error:
    cno_buffer_dyn_clear(&payload);
    return CNO_ERROR_UP();
}


int32_t cno_write_data(struct cno_connection_t *conn, size_t stream, const char *data, size_t length, int final)
{
    if (conn->state == CNO_CONNECTION_UNDEFINED)
        return CNO_ERROR(INVALID_STATE, "connection closed");

    if (!cno_connection_is_http2(conn)) {
        if (stream != 1)
            return CNO_ERROR(INVALID_STREAM, "can only write to stream 1 in HTTP 1 mode, not %zu", stream);

        if (length && CNO_FIRE(conn, on_write, data, length))
            return CNO_ERROR_UP();

        return length;
    }

    struct cno_stream_t *streamobj = cno_stream_find(conn, stream);

    if (streamobj == NULL)
        return CNO_ERROR(INVALID_STREAM, "stream %zu does not exist", stream);

    if (!(streamobj->accept & CNO_ACCEPT_WRITE_DATA))
        return CNO_ERROR(INVALID_STREAM, "can't carry data over stream %zu", stream);

    if (length > conn->window_send) {
        length = conn->window_send;
        final  = 0;
    }

    if (length > streamobj->window_send) {
        length = streamobj->window_send;
        final  = 0;
    }

    if (!length && !final)
        return 0;

    struct cno_frame_t frame = { CNO_FRAME_DATA, final ? CNO_FLAG_END_STREAM : 0, 0, stream, { (char *) data, length } };

    if (cno_frame_write(conn, streamobj, &frame))
        return CNO_ERROR_UP();

    if (final && cno_stream_close(conn, streamobj))
        return CNO_ERROR_UP();

    return length;
}
