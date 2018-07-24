#pragma once

#include "common.h"

#if __cplusplus
extern "C" {
#endif

enum CNO_HEADER_FLAGS
{
    CNO_HEADER_OWNS_NAME   = 0x01,  // owned strings should be free-d
    CNO_HEADER_OWNS_VALUE  = 0x02,
    CNO_HEADER_NOT_INDEXED = 0x04,
};


struct cno_header_t
{
    struct cno_buffer_t name;
    struct cno_buffer_t value;
    uint8_t /* enum CNO_HEADER_FLAGS */ flags;
};


struct cno_header_table_t
{
    struct cno_header_table_t *prev;
    struct cno_header_table_t *next;
    size_t k_size;
    size_t v_size;
    char data[];
};


struct cno_hpack_t
{
    struct cno_header_table_t *last;
    struct cno_header_table_t *first;
    uint32_t size;
    uint32_t limit;
    uint32_t limit_upper;
    uint32_t limit_update_min;  // only used by an encoder
    uint32_t limit_update_end;
};


// Initial value for an uninitialized `cno_header_t`.
static const struct cno_header_t CNO_HEADER_EMPTY = { { NULL, 0 }, { NULL, 0 }, 0 };

// Construct an empty dynamic table with a given default size limit.
void cno_hpack_init(struct cno_hpack_t *, uint32_t limit);

// Destroy the dynamic table.
void cno_hpack_clear(struct cno_hpack_t *);

// Set an encoder's dynamic table size limit. It must not be higher than `limit_upper`,
// which is set by the peer. (For a decoder, set `limit_upper`; `cno_hpack_decode` will
// update the actual limit according to what the peer selects.)
int cno_hpack_setlimit(struct cno_hpack_t *, uint32_t limit);

// Decode at most `*n` headers from a buffer into a provided array. `*n` is set to
// the actual number of headers decoded afterwards. The buffer must outlive the headers.
int cno_hpack_decode(struct cno_hpack_t *, struct cno_buffer_t, struct cno_header_t *, size_t *n);

// Encode exactly `n` headers into a dynamic buffer. If it errors, the buffer may contain
// partially encoded data. Clear it yourself.
int cno_hpack_encode(struct cno_hpack_t *, struct cno_buffer_dyn_t *, const struct cno_header_t *, size_t n);

#if !CFFI_CDEF_MODE

// Carefully deallocate buffers used to construct a header. (Some of them may be shared.)
static inline void cno_hpack_free_header(struct cno_header_t *h)
{
    if (h->flags & CNO_HEADER_OWNS_NAME)
        free((void *) h->name.data);
    if (h->flags & CNO_HEADER_OWNS_VALUE)
        free((void *) h->value.data);
    *h = CNO_HEADER_EMPTY;
}

#endif

#if __cplusplus
}
#endif
