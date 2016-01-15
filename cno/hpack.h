// #include "common.h"
#ifndef CNO_HPACK_H
#define CNO_HPACK_H


struct cno_header_t
{
    struct cno_buffer_t name;
    struct cno_buffer_t value;
};


struct cno_header_table_t
{
    struct cno_list_link_t(struct cno_header_table_t);
    size_t k_size;
    size_t v_size;
    char data[];
};


struct cno_hpack_t
{
    struct cno_list_root_t(struct cno_header_table_t);
    uint32_t size;
    uint32_t limit;
    uint32_t limit_upper;
    uint32_t limit_update_min;
    uint32_t limit_update_end;
};


void cno_hpack_init     (struct cno_hpack_t *, uint32_t limit);
void cno_hpack_setlimit (struct cno_hpack_t *, uint32_t limit);
void cno_hpack_clear    (struct cno_hpack_t *);

/* Decode at most `*n` headers from a buffer into a provided array.
 * `*n` is set to the actual number of headers decoded afterwards. */
int cno_hpack_decode(struct cno_hpack_t *, struct cno_buffer_t, struct cno_header_t *, size_t *n);

/* Encode exactly `n` headers into a dynamic buffer. Note: if it errors,
 * the buffer may contain partially encoded data. Clear it yourself. */
int cno_hpack_encode(struct cno_hpack_t *, struct cno_buffer_dyn_t *, const struct cno_header_t *, size_t n);


#endif
