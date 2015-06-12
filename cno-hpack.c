#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "cno-hpack.h"
#include "cno-hpack-static.h"
#include "cno-hpack-huffman.h"


void cno_hpack_init(cno_hpack_t *state, size_t limit)
{
    cno_list_init(state);
    state->limit            = \
    state->limit_upper      = \
    state->limit_update_min = \
    state->limit_update_end = limit;
}


void cno_hpack_clear(cno_hpack_t *state)
{
    cno_header_table_t *clear = state->first;
    cno_header_table_t *next;

    while (clear != (cno_header_table_t *) state) {
        next = clear->next;
        cno_io_vector_clear(&clear->data.name);
        cno_io_vector_clear(&clear->data.value);
        free(clear);
        clear = next;
    }
}


static void cno_hpack_evict(cno_hpack_t *state)
{
    while (state->size > state->limit) {
        cno_header_table_t *evicting = state->last;
        state->size -= 32 + evicting->data.name.size + evicting->data.value.size;
        cno_list_remove(evicting);
        cno_io_vector_clear(&evicting->data.name);
        cno_io_vector_clear(&evicting->data.value);
        free(evicting);
    }
}


static int cno_hpack_index(cno_hpack_t *state, cno_header_t *source)
{
    cno_header_table_t *entry = calloc(1, sizeof(cno_header_table_t));

    if (entry == NULL) {
        return CNO_PROPAGATE;
    }

    if (cno_io_vector_extend(&entry->data.name, source->name.data, source->name.size)) {
        return CNO_PROPAGATE;
    }

    if (cno_io_vector_extend(&entry->data.value, source->value.data, source->value.size)) {
        cno_io_vector_clear(&entry->data.name);
        return CNO_PROPAGATE;
    }

    state->size += 32 + source->name.size + source->value.size;
    cno_list_insert_after(state, entry);
    cno_hpack_evict(state);
    return CNO_OK;
}


static int cno_hpack_find_index(cno_hpack_t *state, size_t index, const cno_header_t **out)
{
    if (index == 0) {
        return CNO_ERROR_TRANSPORT("hpack: header index 0 is reserved");
    }

    if (index <= CNO_HPACK_STATIC_TABLE_SIZE) {
        *out = CNO_HPACK_STATIC_TABLE + (index - 1);
        return CNO_OK;
    }

    cno_header_table_t *hdr = (cno_header_table_t *) state;

    for (index -= CNO_HPACK_STATIC_TABLE_SIZE; index; --index) {
        hdr = hdr->next;

        if (hdr == (cno_header_table_t *) state) {
            return CNO_ERROR_TRANSPORT("hpack: dynamic table index out of bounds");
        }
    }

    *out = &hdr->data;
    return CNO_OK;
}


static int cno_hpack_compare_index(cno_hpack_t *state, const cno_header_t *src, size_t *out, int *match)
{
    *out = 0;
    *match = 0;

    size_t i = 1;
    const cno_header_t *it  = CNO_HPACK_STATIC_TABLE;
    const cno_header_t *end = CNO_HPACK_STATIC_TABLE + CNO_HPACK_STATIC_TABLE_SIZE;
    #define __MATCH(a, b) (a).size == (b).size && strncmp((a).data, (b).data, (b).size) == 0

    for (; it != end; ++it, ++i) {
        if (__MATCH(it->name, src->name)) {
            if (__MATCH(it->value, src->value)) {
                *out = i;
                *match = 2;
                return CNO_OK;
            }

            *out = i;
            *match = 1;
        }
    }

    const cno_header_table_t *table = (const cno_header_table_t *) state;

    while ((table = table->next) != (const cno_header_table_t *) state) {
        if (__MATCH(table->data.name, src->name)) {
            if (__MATCH(table->data.value, src->value)) {
                *out = i;
                *match = 2;
                return CNO_OK;
            }

            if (!*match) {
                *out = i;
                *match = 1;
            }
        }

        ++i;
    }

    #undef __MATCH
    return CNO_OK;
}


static int cno_hpack_decode_uint(cno_io_vector_tmp_t *source, int prefix, size_t *result)
{
    if (!source->size) {
        return CNO_ERROR_TRANSPORT("hpack: expected uint, got EOF");
    }

    unsigned char *src = (unsigned char *) source->data;
    unsigned char *end = source->size + src;
    unsigned char mask = ~(0xFF << prefix);
    unsigned char head = *src++ & mask;
    unsigned char size = 0;

    if (head != mask) {
        // /--\------- prefix
        // xxxx....
        *result = (size_t) head;
        return cno_io_vector_shift(source, 1);
    }

    *result = 0;

    do {
        // xxxx1111
        // 1.......
        // 1... any amount of lines starting with 1
        // 0.......
        if (src == end) {
            return CNO_ERROR_TRANSPORT("hpack: truncated multi-byte uint");
        }

        if (++size > sizeof(size_t)) {
            return CNO_ERROR_TRANSPORT("hpack: uint literal too large");
        }

        *result <<= 7;
        *result  |= *src & 0x7F;
    } while (*src++ & 0x80);

    *result += (1 << prefix) - 1;
    return cno_io_vector_shift(source, size + 1);
}


static int cno_hpack_decode_string(cno_io_vector_tmp_t *source, cno_io_vector_t *out)
{
    if (!source->size) {
        return CNO_ERROR_TRANSPORT("hpack: expected string, got EOF");
    }

    char huffman = *source->data >> 7;
    size_t length = 0;

    if (cno_hpack_decode_uint(source, 7, &length)) {
        return CNO_PROPAGATE;
    }

    if (length > source->size) {
        return CNO_ERROR_TRANSPORT("hpack: truncated string literal (%lu out of %lu octets)", source->size, length);
    }

    if (huffman) {
        unsigned char *src = (unsigned char *) source->data;
        unsigned char *end = length + src;
        // Min. length of a Huffman code = 5 bits => max length after decoding = x * 8 / 5.
        unsigned char *buf = malloc(length * 2);
        unsigned char *ptr = buf;

        if (!buf) {
            return CNO_ERROR_NO_MEMORY;
        }

        unsigned short tree = 0;
        unsigned char  eos  = 1;

        while (src != end) {
            unsigned char next = *src++;
            unsigned char part = next >> 4;
            unsigned char iter;

            for (iter = 0; iter < 2; ++iter) {
                const cno_huffman_leaf_t a = CNO_HUFFMAN_TREES[tree | part];

                if (a.type & CNO_HUFFMAN_LEAF_ERROR) {
                    free(buf);
                    return CNO_ERROR_TRANSPORT("hpack: invalid Huffman code");
                }

                if (a.type & CNO_HUFFMAN_LEAF_CHAR) {
                    *ptr++ = a.data;
                }

                tree = a.tree;
                eos  = a.type & CNO_HUFFMAN_LEAF_EOS;
                part = next & 0xF;
            }
        }

        if (!eos) {
            free(buf);
            return CNO_ERROR_TRANSPORT("hpack: truncated Huffman code");
        }

        out->data = (char *) buf;
        out->size = ptr - buf;

        cno_io_vector_shift(source, length);
        return CNO_OK;
    }

    out->data = cno_io_vector_slice(source, length);
    out->size = length;
    return out->data ? CNO_OK : CNO_PROPAGATE;
}


static int cno_hpack_decode_one(cno_hpack_t *state, cno_io_vector_tmp_t *source, cno_header_t *target)
{
    if (!source->size) {
        return CNO_ERROR_TRANSPORT("hpack: expected header, got EOF");
    }

    target->name.data = target->value.data = NULL;
    target->name.size = target->value.size = 0;

    unsigned char head = (unsigned char) *source->data;
    unsigned char indexed;
    const cno_header_t *header = NULL;
    size_t index;

    // Indexed header field.
    if (head >> 7) {
        if (cno_hpack_decode_uint(source, 7, &index) ||
            cno_hpack_find_index(state, index, &header) ||
            cno_io_vector_extend(&target->name,  header->name.data,  header->name.size))
                return CNO_PROPAGATE;

        if (cno_io_vector_extend(&target->value, header->value.data, header->value.size)) {
            cno_io_vector_clear(&target->name);
            return CNO_PROPAGATE;
        }

        return CNO_OK;
    }

    if ((head >> 6) == 1) indexed = 1; else  // Literal with incremental indexing.
    if ((head >> 4) == 0) indexed = 0; else  // Literal without indexing.
    if ((head >> 4) == 1) indexed = 0; else  // Literal never indexed.
    if ((head >> 5) == 1) {  // Dynamic table size update.
        size_t new_size = 0;

        if (cno_hpack_decode_uint(source, 5, &new_size)) {
            return CNO_PROPAGATE;
        }

        if (new_size > state->limit_upper) {
            return CNO_ERROR_TRANSPORT("hpack: dynamic table size too big (%lu > %lu)",
                new_size, state->limit_upper);
        }

        state->limit = new_size;
        cno_hpack_evict(state);
        return CNO_OK;
    } else {
        return CNO_ERROR_TRANSPORT("hpack: invalid header field representation");
    }

    if (cno_hpack_decode_uint(source, 4 + 2 * indexed, &index)) {
        return CNO_PROPAGATE;
    }

    if (index == 0) {
        if (cno_hpack_decode_string(source, &target->name)) {
            return CNO_PROPAGATE;
        }
    } else {
        if (cno_hpack_find_index(state, index, &header) ||
            cno_io_vector_extend(&target->name, header->name.data, header->name.size))
                return CNO_PROPAGATE;
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

    size_t decoded = 0;
    size_t maximum = *limit;

    while (decoded < maximum && sourcetmp.size) {
        if (cno_hpack_decode_one(state, &sourcetmp, ptr)) {
            cno_header_t *clear = array;

            for (; clear != ptr; ++clear) {
                cno_io_vector_clear(&clear->name);
                cno_io_vector_clear(&clear->value);
            }

            return CNO_PROPAGATE;
        }

        // Ignore empty headers, including those generated by
        // dynamic table size update events.
        if (ptr->name.data != NULL || ptr->value.data != NULL) ++ptr, ++decoded;
    }

    *limit = decoded;
    return CNO_OK;
}


static int cno_hpack_encode_uint(cno_io_vector_t *target, int prefix, size_t num, unsigned char mark)
{
    unsigned char mask = ~(0xFF << prefix);

    if ((num >> prefix) == 0 && num != mask) {
        mark |= (unsigned char) num;
        return cno_io_vector_extend(target, (char *) &mark, 1);
    }

    unsigned char  buf[sizeof(num) * 2];
    unsigned char *end = buf + sizeof(num) * 2;
    unsigned char *ptr = end - 1; *ptr = 0;
    num -= (1 << prefix) - 1;

    while (num) {
        *ptr-- |= (num & 0x7F);
        *ptr = 0x80;
        num >>= 7;
    }

    *ptr = mark | mask;

    return cno_io_vector_extend(target, (char *) ptr, end - ptr);
}


static int cno_hpack_encode_string(cno_io_vector_t *target, cno_io_vector_t *source)
{
    if (source->size) {
        // Try Huffman first.
        unsigned char *data = malloc(source->size);
        unsigned char *end  = data + source->size;
        unsigned char *ptr  = data;

        if (data == NULL) {
            return CNO_ERROR_NO_MEMORY;
        }

        unsigned char *src  = (unsigned char *) source->data;
        unsigned char *stop = src + source->size;

        uint64_t bits = 0;
        uint8_t  used = 0;

        while (src != stop) {
            const cno_huffman_item_t it = CNO_HUFFMAN_TABLE[*src++];

            bits  = (bits << it.bits) | it.code;
            used += it.bits;

            while (used >= 8) {
                *ptr = bits >> (used -= 8);

                if (++ptr == end) {
                    goto huffman_inefficient;
                }
            }
        }

        if (used) {
            *ptr++ = (bits << (8 - used)) | (0xff >> used);
        }

        if (ptr == end) {
            goto huffman_inefficient;  // at least save the decoder some time
        }

        if (cno_hpack_encode_uint(target, 7, ptr - data, 0x80) ||
            cno_io_vector_extend(target, (char *) data, ptr - data)) {
                free(data);
                return CNO_PROPAGATE;
        }

        free(data);
        return CNO_OK;

    huffman_inefficient:
        free(data);
    }

    if (cno_hpack_encode_uint(target, 7, source->size, 0)) {
        return CNO_PROPAGATE;
    }

    return cno_io_vector_extend(target, source->data, source->size);
}


static int cno_hpack_encode_size_update(cno_hpack_t *state, cno_io_vector_t *target, size_t size)
{
    return cno_hpack_encode_uint(target, 5, state->limit = size, 0x20);
}


static int cno_hpack_encode_one(cno_hpack_t *state, cno_io_vector_t *target, cno_header_t *source, int indexed)
{
    int    match = 0;
    size_t index = 0;

    if (cno_hpack_compare_index(state, source, &index, &match)) {
        return CNO_PROPAGATE;
    }

    if (!indexed) {
        if (cno_hpack_encode_uint(target, 4, index, 0x10)) {
            return CNO_PROPAGATE;
        }
    } else if (match == 2) {
        // Matched the whole header. Note that non-indexed headers cannot be full matches.
        return cno_hpack_encode_uint(target, 7, index, 0x80);
    } else {
        if (cno_hpack_encode_uint(target, 6, index, 0x40)) {
            return CNO_PROPAGATE;
        }

        if (cno_hpack_index(state, source)) {
            return CNO_PROPAGATE;
        }
    }

    if (!match) {
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
        state->limit_update_min = state->limit;
    }

    for (; amount; --amount) {
        if (cno_hpack_encode_one(state, target, array++, 1)) {
            cno_io_vector_clear(target);
            return CNO_PROPAGATE;
        }
    }

    return CNO_OK;
}
