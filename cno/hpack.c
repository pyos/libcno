#include <stdint.h>

#include <stddef.h>  // for common.h
#include <stdlib.h>
#include <string.h>

#include <cno/common.h>  // for hpack.h

#include <cno/hpack.h>
#include <cno/hpack-data.h>


void cno_hpack_init(struct cno_hpack_t *state, size_t limit)
{
    cno_list_init(state);
    state->size = 0;
    state->limit            = \
    state->limit_upper      = \
    state->limit_update_min = \
    state->limit_update_end = limit;
}


void cno_hpack_setlimit(struct cno_hpack_t *state, size_t limit)
{
    if (state->limit_update_min > limit)
        state->limit_update_min = limit;

    // the update will be applied (and encoded for the other side) the next time
    // we send a header block.
    state->limit_update_end = limit;
}


/* Calculate the size of a header in the index table. */
static size_t cno_header_size(const struct cno_header_t *h)
{
    return 32 + h->name.size + h->value.size;
}


/* Determine whether a header should be indexed. Certain headers containing
 * sensitive information should not be indexed to avoid attacks like CRIME. */
static int cno_header_is_indexed(const struct cno_header_t *h)
{
    return !(h->name.size == 6  && 0 == memcmp(h->name.data, "cookie", 6))
        && !(h->name.size == 10 && 0 == memcmp(h->name.data, "set-cookie", 10));
}


/* Remove headers until the remaining ones fit in available memory. */
static void cno_hpack_evict(struct cno_hpack_t *state, size_t limit)
{
    while (state->size > limit) {
        struct cno_header_table_t *entry = state->last;
        state->size -= cno_header_size(&entry->data);
        cno_list_remove(entry);
        cno_buffer_clear(&entry->data.name);
        cno_buffer_clear(&entry->data.value);
        free(entry);
    }
}


/* Remove all headers from the index table. */
void cno_hpack_clear(struct cno_hpack_t *state)
{
    cno_hpack_evict(state, 0);
}


/* Insert a header into the index table. */
static int cno_hpack_index(struct cno_hpack_t *state, const struct cno_header_t *source)
{
    struct cno_header_table_t *entry = calloc(1, sizeof(struct cno_header_table_t));

    if (entry == NULL)
        return CNO_ERROR(NO_MEMORY, "%zu bytes", sizeof(struct cno_header_table_t));

    if (cno_buffer_concat(&entry->data.name,  &source->name)) {
        free(entry);
        return CNO_ERROR_UP();
    }

    if (cno_buffer_concat(&entry->data.value, &source->value)) {
        cno_buffer_clear(&entry->data.name);
        free(entry);
        return CNO_ERROR_UP();
    }

    state->size += cno_header_size(source);
    cno_list_append(state, entry);
    cno_hpack_evict(state, state->limit);
    return CNO_OK;
}


/* Find a header given its index in the table. */
static const struct cno_header_t * cno_hpack_lookup(struct cno_hpack_t *state, size_t index)
{
    if (index == 0)
        return CNO_ERROR_NULL(COMPRESSION, "header index 0 is reserved");

    if (index <= CNO_HPACK_STATIC_TABLE_SIZE)
        return &CNO_HPACK_STATIC_TABLE[index - 1];

    struct cno_header_table_t *hdr = cno_list_end(state);

    for (index -= CNO_HPACK_STATIC_TABLE_SIZE; index; --index) {
        hdr = hdr->next;

        if (hdr == cno_list_end(state))
            return CNO_ERROR_NULL(COMPRESSION, "dynamic table index out of bounds");
    }

    return &hdr->data;
}


/* Calculate the index of a header in the table. Return value is the index,
 * 0 if not found. 1 is written at `r` if both the name and the value match. */
static size_t cno_hpack_index_of(struct cno_hpack_t *state, const struct cno_header_t *needle, int *r)
{
    size_t i = 1, possible = 0;
    const struct cno_header_t       *h = CNO_HPACK_STATIC_TABLE;
    const struct cno_header_table_t *t = state->first;

    #define TRY(x)                                                    \
        do {                                                          \
            if (cno_buffer_equals(&needle->name, &(x)->name)) {       \
                if (cno_buffer_equals(&needle->value, &(x)->value)) { \
                    *r = 1;                                           \
                    return i;                                         \
                }                                                     \
                if (possible == 0)                                    \
                    possible = i;                                     \
            }                                                         \
        } while (0)
    for (; i <= CNO_HPACK_STATIC_TABLE_SIZE; ++h, ++i) TRY(h);
    for (; t != cno_list_end(state); t = t->next, ++i) TRY(&t->data);
    #undef TRY

    return possible;
}


static int cno_hpack_decode_uint(struct cno_buffer_off_t *source, uint8_t mask, size_t *out)
{
    if (!source->size)
        return CNO_ERROR(COMPRESSION, "expected uint, got EOF");

    uint8_t *src = (uint8_t *) source->data;
    uint8_t head = *out = *src++ & mask;
    uint8_t size = 1;

    if (head == mask)
        do {
            if (size == source->size)
                return CNO_ERROR(COMPRESSION, "truncated multi-byte uint");

            if (size == sizeof(size_t))
                return CNO_ERROR(COMPRESSION, "uint literal too large");

            *out += (*src & 0x7F) << (7 * size++ - 7);
        } while (*src++ & 0x80);

    cno_buffer_off_shift(source, size);
    return CNO_OK;
}


static int cno_hpack_decode_string(struct cno_buffer_off_t *source, struct cno_buffer_t *out)
{
    if (!source->size)
        return CNO_ERROR(COMPRESSION, "expected string, got EOF");

    int    huffman = *source->data & 0x80;
    size_t length  = 0;

    if (cno_hpack_decode_uint(source, 0x7F, &length))
        return CNO_ERROR_UP();

    if (length > source->size)
        return CNO_ERROR(COMPRESSION, "expected %zu octets, got %zu", length, source->size);

    if (huffman) {
        uint8_t *src = (uint8_t *) source->data;
        uint8_t *end = length + src;
        // min. length of a Huffman code = 5 bits => max length after decoding = x * 8 / 5.
        uint8_t *buf = malloc(length * 2);
        uint8_t *ptr = buf;

        if (!buf)
            return CNO_ERROR(NO_MEMORY, "%zu bytes", length * 2);

        struct cno_huffman_leaf_t state = { CNO_HUFFMAN_LEAF_OK, 0, 0 };

        for (; src != end; src++) {
            uint8_t chr = *src;

            int i; for (i = 0; i < 2; i++, chr <<= 4) {
                state = CNO_HUFFMAN_TREES[state.tree | (chr >> 4)];

                if (state.type & CNO_HUFFMAN_LEAF_CHAR)
                    *ptr++ = state.data;
            }
        }

        if (!(state.type & CNO_HUFFMAN_LEAF_OK)) {
            free(buf);
            return CNO_ERROR(COMPRESSION, "invalid or truncated Huffman code");
        }

        out->data = (char *) buf;
        out->size = ptr - buf;
    } else {
        out->data = NULL;
        out->size = 0;

        if (cno_buffer_append(out, source->data, length))
            return CNO_ERROR_UP();
    }

    cno_buffer_off_shift(source, length);
    return CNO_OK;
}


static int cno_hpack_decode_one(struct cno_hpack_t *state,
                                struct cno_buffer_off_t *source,
                                struct cno_header_t *target)
{
    if (!source->size)
        return CNO_ERROR(COMPRESSION, "expected header, got EOF");

    const struct cno_header_t *header;
    uint8_t head = *source->data;
    uint8_t mask = 0;
    size_t index;

    if (head & 0x80 /* indexed header field */) {
        if (cno_hpack_decode_uint(source, 0x7F, &index))
            return CNO_ERROR_UP();

        if ((header = cno_hpack_lookup(state, index)) == NULL)
            return CNO_ERROR_UP();

        if (cno_buffer_copy(&target->name, &header->name))
            return CNO_ERROR_UP();

        if (cno_buffer_copy(&target->value, &header->value))
        {
            cno_buffer_clear(&target->name);
            return CNO_ERROR_UP();
        }

        return CNO_OK;
    }

    else if (head & 0x40 /* literal with incremental indexing */)
        mask = 0x30;

    else if (head & 0x20 /* dynamic table size update */) {
        if (cno_hpack_decode_uint(source, 0x1F, &index))
            return CNO_ERROR_UP();

        if (index > state->limit_upper)
            return CNO_ERROR(COMPRESSION, "requested table size is too big");

        cno_hpack_evict(state, state->limit = index);
        return CNO_OK;
    }

    // both other options decoded the same way.
    // head & 0x10 -- literal never indexed
    // otherwise   -- literal without indexing

    if (cno_hpack_decode_uint(source, 0x0F | mask, &index))
        return CNO_ERROR_UP();

    if (index) {
        if ((header = cno_hpack_lookup(state, index)) == NULL)
            return CNO_ERROR_UP();
        if (cno_buffer_copy(&target->name, &header->name))
            return CNO_ERROR_UP();
    } else
        if (cno_hpack_decode_string(source, &target->name))
            return CNO_ERROR_UP();

    if (cno_hpack_decode_string(source, &target->value)) {
        cno_buffer_clear(&target->name);
        return CNO_ERROR_UP();
    }

    if (mask) {  // the header should be added to the index table
        if (cno_hpack_index(state, target)) {
            cno_buffer_clear(&target->name);
            cno_buffer_clear(&target->value);
            return CNO_ERROR_UP();
        }
    }

    return CNO_OK;
}


int cno_hpack_decode(struct cno_hpack_t *state, const struct cno_buffer_t *s,
                     struct cno_header_t *rs, size_t *n)
{
    struct cno_buffer_off_t buf = { s->data, s->size, 0 };
    struct cno_header_t *ptr =  rs;
    struct cno_header_t *end = &rs[*n];

    while (ptr != end && buf.size) {
        if (cno_hpack_decode_one(state, &buf, ptr)) {
            while (ptr-- != rs) {
                cno_buffer_clear(&ptr->name);
                cno_buffer_clear(&ptr->value);
            }

            return CNO_ERROR_UP();
        }

        // ignore empty headers, including those generated by
        // dynamic table size update events.
        if (ptr->name.data != NULL || ptr->value.data != NULL) ++ptr;
    }

    *n = ptr - rs;
    return CNO_OK;
}


static int cno_hpack_encode_uint(struct cno_buffer_t *buf, uint8_t prefix, uint8_t mask, size_t num)
{
    if (num < mask) {
        prefix |= num;
        return cno_buffer_append(buf, (char *) &prefix, 1);
    }

    uint8_t  tmp[sizeof(num) * 2] = { prefix | mask };
    uint8_t *ptr = tmp;

    for (num -= mask; num; num >>= 7)
        *++ptr = (num & 0x7F) | 0x80;

    *ptr &= 0x7F;
    return cno_buffer_append(buf, (char *) tmp, ptr - tmp + 1);
}


static int cno_hpack_encode_string(struct cno_buffer_t *buf, const struct cno_buffer_t *s)
{
    if (s->size) {
        uint8_t *data = malloc(s->size);
        uint8_t *end  = data + s->size;
        uint8_t *ptr  = data;

        if (data == NULL)
            return CNO_ERROR(NO_MEMORY, "%zu bytes", s->size);

        uint8_t *src  = (uint8_t *) s->data;
        uint8_t *stop = src + s->size;

        uint64_t bits = 0;
        uint8_t  used = 0;

        while (src != stop) {
            const struct cno_huffman_item_t it = CNO_HUFFMAN_TABLE[*src++];

            bits  = (bits << it.bits) | it.code;
            used += it.bits;

            while (used >= 8) {
                *ptr++ = bits >> (used -= 8);

                if (ptr == end)
                    goto huffman_inefficient;
            }
        }

        if (used) {
            *ptr++ = (bits << (8 - used)) | (0xff >> used);

            if (ptr == end)
                goto huffman_inefficient;
        }

        int err = cno_hpack_encode_uint(buf, 0x80, 0x7F, ptr - data)
               || cno_buffer_append(buf, (char *) data, ptr - data);

        free(data);
        return err;

    huffman_inefficient:
        free(data);
    }

    return cno_hpack_encode_uint(buf, 0, 0x7F, s->size)
        || cno_buffer_append(buf, s->data, s->size);
}


static int cno_hpack_encode_size_update(struct cno_hpack_t *state, struct cno_buffer_t *buf, size_t size)
{
    return cno_hpack_encode_uint(buf, 0x20, 0x1F, state->limit = size);
}


static int cno_hpack_encode_one(struct cno_hpack_t *state, struct cno_buffer_t *buf, const struct cno_header_t *h)
{
    int full = 0;
    size_t index = cno_hpack_index_of(state, h, &full);

    if (cno_header_is_indexed(h)) {
        if (full)
            return cno_hpack_encode_uint(buf, 0x80, 0x7F, index);

        if (cno_hpack_encode_uint(buf, 0x40, 0x3F, index) || cno_hpack_index(state, h))
            return CNO_ERROR_UP();
    } else
        // "not indexed" means not added to the dynamic table. if there's already a header
        // with the same name there, we should still use its index for compression.
        if (cno_hpack_encode_uint(buf, 0x10, 0xF, index))
            return CNO_ERROR_UP();

    if (!index)
        if (cno_hpack_encode_string(buf, &h->name))
            return CNO_ERROR_UP();

    return cno_hpack_encode_string(buf, &h->value);
}


int cno_hpack_encode(struct cno_hpack_t *state, struct cno_buffer_t *buf,
               const struct cno_header_t *headers, size_t n)
{
    // if the size limit was updated, should encode two values:
    // the minimum value and the end value. the former may force the other side
    // to evict more entries from the table than the latter.
    if (state->limit != state->limit_update_min)
        if (cno_hpack_encode_size_update(state, buf, state->limit_update_min))
            return CNO_ERROR_UP();

    if (state->limit != state->limit_update_end)
        if (cno_hpack_encode_size_update(state, buf, state->limit_update_end))
            return CNO_ERROR_UP();

    while (n--)
        if (cno_hpack_encode_one(state, buf, headers++))
            return CNO_ERROR_UP();

    state->limit_update_min = state->limit;
    return CNO_OK;
}
