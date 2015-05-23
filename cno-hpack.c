#include <stdlib.h>
#include <string.h>

#include "cno-hpack.h"
#include "cno-hpack-huffman.h"


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

    return cno_io_vector_shift(source, size + 1);
}


static int cno_hpack_decode_string(cno_io_vector_tmp_t *source, cno_io_vector_t *out)
{
    if (!source->size) {
        return CNO_ERROR_TRANSPORT("hpack: expected string, got EOF");
    }

    char huffman = *source->data >> 7;
    size_t length;

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


static int cno_hpack_decode_one(cno_hpack_t *state, cno_io_vector_tmp_t *source, cno_header_t *target)
{
    if (!source->size) {
        return CNO_ERROR_TRANSPORT("hpack: expected header, got EOF");
    }

    target->name.data = target->value.data = NULL;
    target->name.size = target->value.size = 0;

    unsigned char head = (unsigned char) *source->data;
    unsigned char indexed;
    const cno_header_t *header;
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
        goto dyntable_evict;
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
        cno_header_table_t *entry = malloc(sizeof(cno_header_table_t));

        if (entry == NULL ||
            cno_io_vector_extend(&entry->data.name, target->name.data, target->name.size)) {
                cno_io_vector_clear(&target->name);
                cno_io_vector_clear(&target->value);
                return CNO_PROPAGATE;
        }

        if (cno_io_vector_extend(&entry->data.value, target->value.data, target->value.size)) {
            cno_io_vector_clear(&entry->data.name);
            cno_io_vector_clear(&target->name);
            cno_io_vector_clear(&target->value);
            return CNO_PROPAGATE;
        }

        cno_list_insert_after(state, entry);
        state->size += 32 + target->name.size + target->value.size;

        dyntable_evict: while (state->size > state->limit) {
            cno_header_table_t *evicting = state->last;
            state->size -= 32 + evicting->data.name.size + evicting->data.value.size;
            cno_list_remove(evicting);
            cno_io_vector_clear(&evicting->data.name);
            cno_io_vector_clear(&evicting->data.value);
            free(evicting);
        }
    }

    return CNO_OK;
}


static int cno_hpack_encode_one(cno_hpack_t *state, cno_io_vector_t *target, cno_header_t *source)
{
    return CNO_ERROR_NOT_IMPLEMENTED("hpack");
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


int cno_hpack_encode(cno_hpack_t *state, cno_io_vector_t *target, cno_header_t *array, size_t amount)
{
    if (target->size || target->data) {
        return CNO_ERROR_ASSERTION("non-empty io vector passed to hpack_encode");
    }

    for (; amount; --amount) {
        if (cno_hpack_encode_one(state, target, array++)) {
            cno_io_vector_clear(target);
            return CNO_PROPAGATE;
        }
    }

    return CNO_OK;
}
