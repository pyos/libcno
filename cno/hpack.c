#include "config.h"
#include "hpack.h"
#include "hpack-data.h"


void cno_hpack_init(struct cno_hpack_t *state, uint32_t limit)
{
    cno_list_init(state);
    state->size = 0;
    state->limit            = \
    state->limit_upper      = \
    state->limit_update_min = \
    state->limit_update_end = limit;
}


static void cno_hpack_evict(struct cno_hpack_t *state, uint32_t limit)
{
    while (state->size > limit) {
        struct cno_header_table_t *entry = state->last;
        state->size -= entry->k_size + entry->v_size + 32;
        cno_list_remove(entry);
        free(entry);
    }
}


void cno_hpack_clear(struct cno_hpack_t *state)
{
    cno_hpack_evict(state, 0);
}


void cno_hpack_setlimit(struct cno_hpack_t *state, uint32_t limit)
{
    if (state->limit_update_min > limit)
        cno_hpack_evict(state, state->limit_update_min = limit);

    // the update will be encoded the next time we send a header block.
    state->limit_update_end = limit;
}


static struct cno_buffer_t cno_header_table_k(const struct cno_header_table_t *t)
{
    return (struct cno_buffer_t) { &t->data[0], t->k_size };
}


static struct cno_buffer_t cno_header_table_v(const struct cno_header_table_t *t)
{
    return (struct cno_buffer_t) { &t->data[t->k_size], t->v_size };
}


/* Insert a header into the index table. */
static int cno_hpack_index(struct cno_hpack_t *state, const struct cno_header_t *h)
{
    size_t recorded = h->name.size + h->value.size + 32;
    size_t actual   = h->name.size + h->value.size + sizeof(struct cno_header_table_t);

    if (recorded > state->limit)
        cno_hpack_evict(state, 0);
    else {
        cno_hpack_evict(state, state->limit - recorded);

        struct cno_header_table_t *entry = malloc(actual);

        if (entry == NULL)
            return CNO_ERROR(NO_MEMORY, "%zu bytes", actual);

        state->size += recorded;
        memcpy(&entry->data[0],            h->name.data,  entry->k_size = h->name.size);
        memcpy(&entry->data[h->name.size], h->value.data, entry->v_size = h->value.size);
        cno_list_append(state, entry);
    }

    return CNO_OK;
}


/* Find a header given its index in the table. */
static int cno_hpack_lookup(struct cno_hpack_t *state, size_t index, struct cno_header_t *out)
{
    if (index == 0)
        return CNO_ERROR(COMPRESSION, "header index 0 is reserved");

    if (index <= CNO_HPACK_STATIC_TABLE_SIZE) {
        out->name  = CNO_HPACK_STATIC_TABLE[index - 1].name;
        out->value = CNO_HPACK_STATIC_TABLE[index - 1].value;
        return CNO_OK;
    }

    const struct cno_header_table_t *hdr = cno_list_end(state);

    for (index -= CNO_HPACK_STATIC_TABLE_SIZE; index; --index) {
        hdr = hdr->next;

        if (hdr == cno_list_end(state))
            return CNO_ERROR(COMPRESSION, "dynamic table index out of bounds");
    }

    char *buf = malloc(hdr->k_size + hdr->v_size);
    if (!buf)
        return CNO_ERROR(NO_MEMORY, "%zu bytes", hdr->k_size + hdr->v_size);
    memcpy(buf, hdr->data, hdr->k_size + hdr->v_size);
    out->name  = (struct cno_buffer_t){buf, hdr->k_size};
    out->value = (struct cno_buffer_t){buf + hdr->k_size, hdr->v_size};
    out->flags |= CNO_HEADER_OWNS_NAME;
    return CNO_OK;
}


/* Calculate the index of a header in the table. Return value is the index,
   0 if not found, negative if both name and value match. */
static int cno_hpack_index_of(struct cno_hpack_t *state, const struct cno_header_t *needle)
{
    size_t i = 1, possible = 0;
    const struct cno_header_t       *h = CNO_HPACK_STATIC_TABLE;
    const struct cno_header_table_t *t = state->first;

    #define TRY(k, v)                            \
        if (cno_buffer_eq(needle->name, k)) {    \
            if (cno_buffer_eq(needle->value, v)) \
                return -i;                       \
            if (possible == 0)                   \
                possible = i;                    \
        }
    for (; i <= CNO_HPACK_STATIC_TABLE_SIZE; ++h, ++i) TRY(h->name, h->value);
    for (; t != cno_list_end(state); t = t->next, ++i) TRY(cno_header_table_k(t),
                                                           cno_header_table_v(t));
    #undef TRY
    return possible;
}


static int cno_hpack_decode_uint(struct cno_buffer_dyn_t *source, uint8_t mask, size_t *out)
{
    if (!source->size)
        return CNO_ERROR(COMPRESSION, "expected uint, got EOF");

    const uint8_t *src = (const uint8_t *) source->data;
    const uint8_t head = *out = *src++ & mask;
    uint8_t size = 1;

    if (head == mask)
        do {
            if (size == source->size)
                return CNO_ERROR(COMPRESSION, "truncated multi-byte uint");

            if (size == sizeof(size_t))
                return CNO_ERROR(COMPRESSION, "uint literal too large");

            *out += (*src & 0x7Ful) << (7 * size++ - 7);
        } while (*src++ & 0x80);

    cno_buffer_dyn_shift(source, size);
    return CNO_OK;
}


static int cno_hpack_decode_string(struct cno_buffer_dyn_t *source, struct cno_buffer_t *out, int *borrow)
{
    if (!source->size)
        return CNO_ERROR(COMPRESSION, "expected string, got EOF");

    int    huffman = *source->data & 0x80;
    size_t length  = 0;

    if (cno_hpack_decode_uint(source, 0x7F, &length))
        return CNO_ERROR_UP();

    if (length > source->size)
        return CNO_ERROR(COMPRESSION, "expected %zu octets, got %zu", length, source->size);

    if (length && huffman) {
        const uint8_t *src = (const uint8_t *) source->data;
        const uint8_t *end = length + src;
        // min. length of a Huffman code = 5 bits => max length after decoding = x * 8 / 5.
        uint8_t *buf = malloc(length * 2);
        uint8_t *ptr = buf;

        if (!buf)
            return CNO_ERROR(NO_MEMORY, "%zu bytes", length * 2);

        struct cno_huffman_leaf_t state = { 0, 0, CNO_HUFFMAN_ACCEPT };

        do {
            uint8_t chr = *src++;

            for (int i = 0; i < 8 / CNO_HUFFMAN_INPUT_BITS; i++, chr <<= CNO_HUFFMAN_INPUT_BITS) {
                state = CNO_HUFFMAN_TREES[state.next | (chr >> (8 - CNO_HUFFMAN_INPUT_BITS))];

                if (state.flags & CNO_HUFFMAN_APPEND)
                    *ptr++ = state.byte;
            }
        } while (src != end);

        if (!(state.flags & CNO_HUFFMAN_ACCEPT)) {
            free(buf);
            return CNO_ERROR(COMPRESSION, "invalid or truncated Huffman code");
        }

        out->data = (char *) buf;
        out->size = ptr - buf;
    } else {
        out->data = source->data;
        out->size = length;
        *borrow = 1;
    }

    cno_buffer_dyn_shift(source, length);
    return CNO_OK;
}


static int cno_hpack_decode_one(struct cno_hpack_t      *state,
                                struct cno_buffer_dyn_t *source,
                                struct cno_header_t     *target)
{
    *target = CNO_HEADER_EMPTY;

    if (!source->size)
        return CNO_ERROR(COMPRESSION, "expected header, got EOF");

    size_t index = 0;

    if (*source->data & 0x80) {
        // 1....... -- name & value taken from the table
        return cno_hpack_decode_uint(source, 0x7F, &index)
            || cno_hpack_lookup(state, index, target);
    } else if ((*source->data & 0xC0) == 0x40) {
        // 01...... -- name taken from the table, value included as a literal
        if (cno_hpack_decode_uint(source, 0x3F, &index))
            return CNO_ERROR_UP();
    } else if ((*source->data & 0xE0) == 0x20) {
        // 001..... -- table size limit update; see cno_hpack_decode
        return CNO_ERROR(COMPRESSION, "unexpected table size limit update");
    } else {
        // 0000.... -- same as 0x40, but we shouldn't insert this header into the table.
        // 0001.... -- same as 0x00, but proxies must not encode differently.
        target->flags |= CNO_HEADER_NOT_INDEXED;
        if (cno_hpack_decode_uint(source, 0x0F, &index))
            return CNO_ERROR_UP();
    }

    if (index == 0) {
        int borrow = 0;
        if (cno_hpack_decode_string(source, &target->name, &borrow))
            return CNO_ERROR_UP();
        if (!borrow)
            target->flags |= CNO_HEADER_OWNS_NAME;
    } else {
        if (cno_hpack_lookup(state, index, target))
            return CNO_ERROR_UP();
    }

    int borrow = 0;
    if (cno_hpack_decode_string(source, &target->value, &borrow)) {
        cno_hpack_free_header(target);
        return CNO_ERROR_UP();
    }
    if (!borrow)
        target->flags |= CNO_HEADER_OWNS_VALUE;

    if (!(target->flags & CNO_HEADER_NOT_INDEXED) && cno_hpack_index(state, target)) {
        cno_hpack_free_header(target);
        return CNO_ERROR_UP();
    }

    return CNO_OK;
}


int cno_hpack_decode(struct cno_hpack_t *state, struct cno_buffer_t s,
                     struct cno_header_t *rs, size_t *n)
{
    struct cno_buffer_dyn_t buf = {{s}, 0, 0};
    struct cno_header_t *ptr =  rs;
    struct cno_header_t *end = &rs[*n];

    while (buf.size && (*buf.data & 0xE0) == 0x20) {
        // 001..... -- a new size limit for the table
        size_t limit = 0;

        if (cno_hpack_decode_uint(&buf, 0x1F, &limit))
            return CNO_ERROR_UP();

        if (limit > state->limit_upper)
            return CNO_ERROR(COMPRESSION, "requested table size is too big");

        cno_hpack_evict(state, state->limit = limit);
    }

    for (; buf.size; ptr++) {
        if (ptr == end) {
            while (ptr > rs)
                cno_hpack_free_header(--ptr);
            return CNO_ERROR(COMPRESSION, "header list too long");
        }

        if (cno_hpack_decode_one(state, &buf, ptr)) {
            while (ptr > rs)
                cno_hpack_free_header(--ptr);
            return CNO_ERROR_UP();
        }
    }

    *n = ptr - rs;
    return CNO_OK;
}


static int cno_hpack_encode_uint(struct cno_buffer_dyn_t *buf, uint8_t prefix, uint8_t mask, size_t num)
{
    if (num < mask) {
        prefix |= num;
        return cno_buffer_dyn_concat(buf, (struct cno_buffer_t) { (char *) &prefix, 1 });
    }

    uint8_t tmp[sizeof(num) * 2], *ptr = tmp;

    *ptr++ = prefix | mask;
    for (num -= mask; num > 0x7F; num >>= 7)
        *ptr++ = num | 0x80;
    *ptr++ = num;

    return cno_buffer_dyn_concat(buf, (struct cno_buffer_t) { (char *) tmp, ptr - tmp });
}


static int cno_hpack_encode_string(struct cno_buffer_dyn_t *buf, const struct cno_buffer_t s)
{
    if (!s.size)
        goto huffman_inefficient;

    uint8_t *out = malloc(s.size);
    uint8_t *ptr = out;

    if (out == NULL)
        return CNO_ERROR(NO_MEMORY, "%zu bytes", s.size);

    const uint8_t *src = (const uint8_t *) s.data;
    const uint8_t *end = src + s.size;

    uint64_t bits = 0;
    uint8_t  used = 0;

    while (src != end) {
        const struct cno_huffman_item_t it = CNO_HUFFMAN_TABLE[*src++];

        bits  = it.code | bits << it.bits;
        used += it.bits;

        while (used >= 8) {
            *ptr++ = bits >> (used -= 8);

            if (ptr == out + s.size) {
                free(out);
                goto huffman_inefficient;
            }
        }
    }

    if (used)
        *ptr++ = (0xff | bits << 8) >> used;

    int err = cno_hpack_encode_uint(buf, 0x80, 0x7F, ptr - out)
           || cno_buffer_dyn_concat(buf, (struct cno_buffer_t) { (char *) out, ptr - out });

    free(out);
    return err;

huffman_inefficient:
    return cno_hpack_encode_uint(buf, 0, 0x7F, s.size)
        || cno_buffer_dyn_concat(buf, s);
}


static int cno_hpack_encode_one(struct cno_hpack_t *state, struct cno_buffer_dyn_t *buf, const struct cno_header_t *h)
{
    int index = cno_hpack_index_of(state, h);
    if (index < 0)
        return cno_hpack_encode_uint(buf, 0x80, 0x7F, -index);

    if (h->flags & CNO_HEADER_NOT_INDEXED
        ? cno_hpack_encode_uint(buf, 0x10, 0x0F, index)
        : cno_hpack_encode_uint(buf, 0x40, 0x3F, index) || cno_hpack_index(state, h))
            return CNO_ERROR_UP();

    if (!index)
        if (cno_hpack_encode_string(buf, h->name))
            return CNO_ERROR_UP();

    return cno_hpack_encode_string(buf, h->value);
}


int cno_hpack_encode(struct cno_hpack_t *state, struct cno_buffer_dyn_t *buf,
               const struct cno_header_t *headers, size_t n)
{
    // force the other side to evict the same number of entries first
    if (state->limit != state->limit_update_min)
        if (cno_hpack_encode_uint(buf, 0x20, 0x1F, state->limit_update_min))
            return CNO_ERROR_UP();

    // only then set the limit to its actual value
    if (state->limit != state->limit_update_end)
        if (cno_hpack_encode_uint(buf, 0x20, 0x1F, state->limit_update_end))
            return CNO_ERROR_UP();

    state->limit_update_min = state->limit = state->limit_update_end;

    while (n--)
        if (cno_hpack_encode_one(state, buf, headers++))
            return CNO_ERROR_UP();

    return CNO_OK;
}
