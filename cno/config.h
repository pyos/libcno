#ifndef CNO_ERROR_TRACEBACKS
/* Max. depth of a stack trace to store on a cno_error_t should an error occur.
 * Controls thread-local storage space consumption in `common.c`. Must be at least 1
 * to store the original location of the error. */
#define CNO_ERROR_TRACEBACK 64
#endif

#ifndef CNO_BUFFER_ALLOC_INCR
/* The increment (in bytes) in which dynamically allocated buffers grow.
 * Controls the number of heap allocations & amount of wasted heap space. */
#define CNO_BUFFER_ALLOC_INCR 512
#endif

#ifndef CNO_MAX_HTTP1_HEADER_SIZE
/* Max. length of an outbound header in HTTP/1.1 mode. If a header longer than this is
 * passed to `cno_write_message`, it will return an assertion error. Does not affect
 * inbound messages and HTTP 2. Controls stack space usage. */
#define CNO_MAX_HTTP1_HEADER_SIZE 4096
#endif

#ifndef CNO_MAX_HEADERS
/* Max. number of entries in the header table of inbound messages. Applies to both HTTP 1
 * and HTTP 2. Does not affect outbound messages. Controls stack space usage. */
#define CNO_MAX_HEADERS 128
#endif

#ifndef CNO_MAX_CONTINUATIONS
/* Maximum number of CONTINUATION frames that can follow HEADERS/PUSH_PROMISE.
 * We can't start processing these frames until we've concatenated them all into
 * a single buffer. Controls peak memory consumption. */
#define CNO_MAX_CONTINUATIONS 5
#endif

#ifndef CNO_STREAM_BUCKETS
/* Number of buckets in the "stream id -> stream object" hash map. Must be prime to
 * ensure an even distribution. Controls stack/heap usage, depeding on where connection
 * objects are allocated. */
#define CNO_STREAM_BUCKETS 61
#endif
