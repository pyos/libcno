#include <stdlib.h>
#include <string.h>

#include "cno-hpack.h"
#include "cno-hpack-huffman.h"


static int cno_hpack_decode_uint(cno_hpack_t *state, cno_io_vector_tmp_t *source, int prefix, size_t *result)
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


static int cno_hpack_decode_string(cno_hpack_t *state, cno_io_vector_tmp_t *source, cno_io_vector_t *out)
{
    if (!source->size) {
        return CNO_ERROR_TRANSPORT("hpack: expected string, got EOF");
    }

    char huffman = *source->data >> 7;
    size_t length;

    if (cno_hpack_decode_uint(state, source, 7, &length)) {
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
    return CNO_ERROR_NOT_IMPLEMENTED("hpack");
}


static int cno_hpack_encode_one(cno_hpack_t *state, cno_io_vector_t *target, cno_header_t *source)
{
    return CNO_ERROR_NOT_IMPLEMENTED("hpack");
}


int cno_hpack_decode(cno_hpack_t *state, cno_io_vector_t *source, cno_header_t *array, size_t *limit)
{
    cno_io_vector_tmp_t sourcetmp = { source->data, source->size, 0 };

    size_t decoded = 0;
    size_t maximum = *limit;

    for (; decoded < maximum && sourcetmp.size; ++decoded) {
        if (cno_hpack_decode_one(state, &sourcetmp, array++)) {
            return CNO_PROPAGATE;
        }
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