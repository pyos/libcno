#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

    int huffman = *source->data >> 7;
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

        // Has to be at least 37 bits, since we can only read 8-bit chars and
        // if we happen to have 29 bits at some point, that will not be enough
        // for some Huffman codes.
        uint64_t bits = 0;
        uint64_t mask = 0;
        const cno_huffman_node_t *tree;

        next_char:
            while (src != end && mask < 1 << 30) {
                mask = mask << 8;
                bits = bits << 8 | *src++;
                if (!mask) mask = 0x80;
            }

            tree = CNO_HUFFMAN_TREE;

            while (mask) {
                tree = bits & mask ? tree->right : tree->left;
                mask >>= 1;

                if (tree == NULL) {
                    free(buf);
                    return CNO_ERROR_TRANSPORT("hpack: invalid Huffman code");
                }

                if (!tree->left && !tree->right) {
                    if (tree->data >= 256) {
                        free(buf);
                        return CNO_ERROR_TRANSPORT("hpack: EOS in Huffman-encoded string");
                    }

                    *ptr++ = (unsigned char) tree->data;
                    goto next_char;
                }
            }

            // Truncated Huffman code; the EOS character should be reachable
            // by hanging right (it has code 0b11111...11).
            while (tree->right) tree = tree->right;

            if (tree->data != 256) {
                free(buf);
                return CNO_ERROR_TRANSPORT("hpack: truncated non-EOS Huffman code");
            }

        out->data = buf;
        out->size = ptr - buf;

        cno_io_vector_shift(source, length);
        return CNO_OK;
    }

    out->data = cno_io_vector_slice(source, length);
    out->size = length;

    if (!out->data) {
        return CNO_PROPAGATE;
    }

    return CNO_OK;
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
