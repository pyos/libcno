#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "cno-hpack.h"
#include "cno-hpack-data.h"


void cno_hpack_init(cno_hpack_t *state, size_t limit)
{
    cno_list_init(state);
    state->limit            = \
    state->limit_upper      = \
    state->limit_update_min = \
    state->limit_update_end = limit;
}


static void cno_hpack_evict(cno_hpack_t *state, size_t limit)
{
    while (state->size > limit) {
        cno_header_table_t *evicting = state->last;
        state->size -= 32 + evicting->data.name.size + evicting->data.value.size;
        cno_list_remove(evicting);
        cno_io_vector_clear(&evicting->data.name);
        cno_io_vector_clear(&evicting->data.value);
        free(evicting);
    }
}


void cno_hpack_clear(cno_hpack_t *state)
{
    cno_hpack_evict(state, 0);
}


static inline int cno_hpack_indexed(cno_header_t *hdr)
{
    return (hdr->name.size != 6  || memcmp(hdr->name.data, "cookie", 6))
        && (hdr->name.size != 10 || memcmp(hdr->name.data, "set-cookie", 10));
}


static int cno_hpack_index(cno_hpack_t *state, cno_header_t *source)
{
    cno_header_table_t *entry = calloc(1, sizeof(cno_header_table_t));

    if (entry == NULL) {
        return CNO_PROPAGATE;
    }

    if (cno_io_vector_copy(&entry->data.name,  &source->name)
     || cno_io_vector_copy(&entry->data.value, &source->value))
    {
        cno_io_vector_clear(&entry->data.name);
        return CNO_PROPAGATE;
    }

    state->size += 32 + source->name.size + source->value.size;
    cno_list_prepend(state, entry);
    cno_hpack_evict(state, state->limit);
    return CNO_OK;
}


static int cno_hpack_lookup(cno_hpack_t *state, size_t index, const cno_header_t **out)
{
    if (index == 0) {
        return CNO_ERROR(COMPRESSION, "header index 0 is reserved");
    }

    if (index < CNO_HPACK_STATIC_TABLE_SIZE) {
        *out = CNO_HPACK_STATIC_TABLE + index - 1;
        return CNO_OK;
    }

    cno_header_table_t *hdr = cno_list_end(state);

    for (index -= CNO_HPACK_STATIC_TABLE_SIZE; index; --index) {
        hdr = hdr->next;

        if (hdr == cno_list_end(state)) {
            return CNO_ERROR(COMPRESSION, "dynamic table index out of bounds");
        }
    }

    *out = &hdr->data;
    return CNO_OK;
}


static int cno_hpack_index_of(cno_hpack_t *state, const cno_header_t *src, size_t *out)
{
    // Returns 1 if both name and value match, 0 if only name does. (*out = 0 if neither.)
    size_t i = 1, r = 0;
    const cno_header_t       *hp = CNO_HPACK_STATIC_TABLE;
    const cno_header_table_t *tp = state->first;
    #define MATCH(a, b) (a).size == (b).size && !memcmp((a).data, (b).data, (b).size)
    #define CHECK(a, b) do {                                         \
        if (MATCH((a).name, (b).name)) {                             \
            if (MATCH((a).value, (b).value)) { *out = i; return 1; } \
            if (!r) r = i;                                           \
        }                                                            \
    } while (0)

    for (; i <= CNO_HPACK_STATIC_TABLE_SIZE; ++hp, ++i) CHECK(*src, *hp);
    for (; tp != cno_list_end(state); tp = tp->next, ++i) CHECK(*src, tp->data);

    #undef MATCH
    #undef CHECK
    *out = r;
    return 0;
}


static int cno_hpack_decode_uint(cno_io_vector_tmp_t *source, uint8_t mask, size_t *out)
{
    if (!source->size) {
        return CNO_ERROR(COMPRESSION, "expected uint, got EOF");
    }

    uint8_t *src = (uint8_t *) source->data;
    uint8_t head = *out = *src++ & mask;
    uint8_t size = 1;

    if (head != mask) {
        return cno_io_vector_shift(source, 1);
    }

    do {
        if (size == source->size) {
            return CNO_ERROR(COMPRESSION, "truncated multi-byte uint");
        }

        if (size == sizeof(size_t)) {
            return CNO_ERROR(COMPRESSION, "uint literal too large");
        }

        *out += (*src & 0x7F) << (7 * size++ - 7);
    } while (*src++ & 0x80);

    return cno_io_vector_shift(source, size);
}


static int cno_hpack_decode_string(cno_io_vector_tmp_t *source, cno_io_vector_t *out)
{
    if (!source->size) {
        return CNO_ERROR(COMPRESSION, "expected string, got EOF");
    }

    int8_t huffman = *source->data & 0x80;
    size_t length = 0;

    if (cno_hpack_decode_uint(source, 0x7F, &length)) {
        return CNO_PROPAGATE;
    }

    if (length > source->size) {
        return CNO_ERROR(COMPRESSION, "expected %lu octets, got %lu", length, source->size);
    }

    if (huffman) {
        uint8_t *src = (uint8_t *) source->data;
        uint8_t *end = length + src;
        // Min. length of a Huffman code = 5 bits => max length after decoding = x * 8 / 5.
        uint8_t *buf = malloc(length * 2);
        uint8_t *ptr = buf;

        if (!buf) {
            return CNO_ERROR(NO_MEMORY);
        }

        cno_huffman_leaf_t ref = { CNO_HUFFMAN_LEAF_EOS, 0, 0 };

        while (src != end) {
            uint8_t part = *src++;
            uint8_t iter = 3;

            while (--iter) {
                ref = CNO_HUFFMAN_TREES[ref.tree | (part >> 4)];

                if (ref.type & CNO_HUFFMAN_LEAF_ERROR) {
                    free(buf);
                    return CNO_ERROR(COMPRESSION, "invalid Huffman code");
                }

                if (ref.type & CNO_HUFFMAN_LEAF_CHAR) {
                    *ptr++ = ref.data;
                }

                part <<= 4;
            }
        }

        if (!(ref.type & CNO_HUFFMAN_LEAF_EOS)) {
            free(buf);
            return CNO_ERROR(COMPRESSION, "truncated Huffman code");
        }

        out->data = (char *) buf;
        out->size = ptr - buf;
        return cno_io_vector_shift(source, length);
    }

    out->data = NULL;
    out->size = 0;
    return cno_io_vector_extend(out, source->data, length)
        || cno_io_vector_shift(source, length);
}


static int cno_hpack_decode_one(cno_hpack_t *state, cno_io_vector_tmp_t *source, cno_header_t *target)
{
    if (!source->size) {
        return CNO_ERROR(COMPRESSION, "expected header, got EOF");
    }

    const cno_header_t *header = NULL;
    uint8_t head    = *source->data;
    uint8_t indexed = 0;
    size_t  index   = 0;

    if (head & 0x80) {
        // Indexed header field.
        if (cno_hpack_decode_uint(source, 0x7F, &index)
         || cno_hpack_lookup(state, index, &header)
         || cno_io_vector_copy(&target->name,  &header->name))
        {
            return CNO_PROPAGATE;
        }

        if (cno_io_vector_copy(&target->value, &header->value))
        {
            cno_io_vector_clear(&target->name);
            return CNO_PROPAGATE;
        }

        return CNO_OK;
    }

    if (head & 0x40) {
        // Literal with incremental indexing.
        indexed = 0x30;
    }

    else if (head & 0x20) {
        // Dynamic table size update.
        if (cno_hpack_decode_uint(source, 0x1F, &index)) {
            return CNO_PROPAGATE;
        }

        if (index > state->limit_upper) {
            return CNO_ERROR(COMPRESSION, "requested table size is too big");
        }

        cno_hpack_evict(state, state->limit = index);
        return CNO_OK;
    }
    // else if (head & 0x10) -- literal never indexed
    // else                  -- literal without indexing

    if (cno_hpack_decode_uint(source, 0x0F | indexed, &index)) {
        return CNO_PROPAGATE;
    }

    if (index == 0) {
        if (cno_hpack_decode_string(source, &target->name)) {
            return CNO_PROPAGATE;
        }
    } else {
        if (cno_hpack_lookup(state, index, &header)
         || cno_io_vector_copy(&target->name, &header->name))
        {
            return CNO_PROPAGATE;
        }
    }

    if (cno_hpack_decode_string(source, &target->value)) {
        cno_io_vector_clear(&target->name);
        return CNO_PROPAGATE;
    }

    if (indexed) {
        if (cno_hpack_index(state, target)) {
            cno_io_vector_clear(&target->name);
            cno_io_vector_clear(&target->value);
            return CNO_PROPAGATE;
        }
    }

    return CNO_OK;
}


int cno_hpack_decode(cno_hpack_t *state, cno_io_vector_t *source, cno_header_t *array, size_t *limit)
{
    cno_io_vector_tmp_t sourcetmp = { source->data, source->size, 0 };
    cno_header_t *ptr = array;
    cno_header_t *end = array + *limit;

    while (ptr != end && sourcetmp.size) {
        if (cno_hpack_decode_one(state, &sourcetmp, ptr)) {
            while (ptr-- != array) {
                cno_io_vector_clear(&ptr->name);
                cno_io_vector_clear(&ptr->value);
            }

            return CNO_PROPAGATE;
        }

        // Ignore empty headers, including those generated by
        // dynamic table size update events.
        if (ptr->name.data != NULL || ptr->value.data != NULL) ++ptr;
    }

    *limit = ptr - array;
    return CNO_OK;
}


static int cno_hpack_encode_uint(cno_io_vector_t *target, uint8_t prefix, uint8_t mask, size_t num)
{
    if (num < mask) {
        prefix |= num;
        return cno_io_vector_extend(target, (char *) &prefix, 1);
    }

    uint8_t  buf[sizeof(num) * 2] = { prefix | mask };
    uint8_t *ptr = buf;
    num -= mask;

    while (num) {
        *++ptr = (num & 0x7F) | 0x80;
        num >>= 7;
    }

    *ptr &= 0x7F;
    return cno_io_vector_extend(target, (char *) buf, ptr - buf + 1);
}


static int cno_hpack_encode_string(cno_io_vector_t *target, cno_io_vector_t *source)
{
    if (source->size) {
        uint8_t *data = malloc(source->size);
        uint8_t *end  = data + source->size;
        uint8_t *ptr  = data;

        if (data == NULL) {
            return CNO_ERROR(NO_MEMORY);
        }

        uint8_t *src  = (uint8_t *) source->data;
        uint8_t *stop = src + source->size;

        uint64_t bits = 0;
        uint8_t  used = 0;

        while (src != stop) {
            const cno_huffman_item_t it = CNO_HUFFMAN_TABLE[*src++];

            bits  = (bits << it.bits) | it.code;
            used += it.bits;

            while (used >= 8) {
                *ptr++ = bits >> (used -= 8);

                if (ptr == end) {
                    goto huffman_inefficient;
                }
            }
        }

        if (used) {
            *ptr++ = (bits << (8 - used)) | (0xff >> used);

            if (ptr == end) {
                goto huffman_inefficient;
            }
        }

        if (cno_hpack_encode_uint(target, 0x80, 0x7F, ptr - data)
         || cno_io_vector_extend(target, (char *) data, ptr - data))
        {
            free(data);
            return CNO_PROPAGATE;
        }

        free(data);
        return CNO_OK;

    huffman_inefficient:
        free(data);
    }

    return cno_hpack_encode_uint(target, 0, 0x7F, source->size)
        || cno_io_vector_extend(target, source->data, source->size);
}


static int cno_hpack_encode_size_update(cno_hpack_t *state, cno_io_vector_t *target, size_t size)
{
    return cno_hpack_encode_uint(target, 0x20, 0x1F, state->limit = size);
}


static int cno_hpack_encode_one(cno_hpack_t *state, cno_io_vector_t *target, cno_header_t *source)
{
    size_t index = 0;
    int    full  = cno_hpack_index_of(state, source, &index);

    if (cno_hpack_indexed(source)) {
        if (full) {
            return cno_hpack_encode_uint(target, 0x80, 0x7F, index);
        }

        if (cno_hpack_encode_uint(target, 0x40, 0x3F, index) || cno_hpack_index(state, source)) {
            return CNO_PROPAGATE;
        }
    } else {
        if (cno_hpack_encode_uint(target, 0x10, 0xF, index)) {
            return CNO_PROPAGATE;
        }
    }

    if (!index) {
        if (cno_hpack_encode_string(target, &source->name)) {
            return CNO_PROPAGATE;
        }
    }

    return cno_hpack_encode_string(target, &source->value);
}


void cno_hpack_setlimit(cno_hpack_t *state, size_t limit)
{
    if (state->limit_update_min > limit)
        state->limit_update_min = limit;

    state->limit_update_end = limit;
}


int cno_hpack_encode(cno_hpack_t *state, cno_io_vector_t *target, cno_header_t *array, size_t amount)
{
    if (state->limit != state->limit_update_min) {
        if (cno_hpack_encode_size_update(state, target, state->limit_update_min)) {
            return CNO_PROPAGATE;
        }
    }

    if (state->limit != state->limit_update_end) {
        if (cno_hpack_encode_size_update(state, target, state->limit_update_end)) {
            return CNO_PROPAGATE;
        }
    }

    while (amount--) {
        if (cno_hpack_encode_one(state, target, array++)) {
            cno_io_vector_clear(target);
            return CNO_PROPAGATE;
        }
    }

    state->limit_update_min = state->limit;
    return CNO_OK;
}
