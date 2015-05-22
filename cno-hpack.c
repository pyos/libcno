#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "cno-hpack.h"
#include "cno-hpack-huffman.h"


cno_hpack_t *cno_hpack_start(cno_hpack_dynamic_t *dyntable, char *buf, size_t length)
{
    cno_hpack_t *state = malloc(sizeof(cno_hpack_t));

    if (state == NULL) {
        (void) CNO_ERROR_NO_MEMORY;
        return NULL;
    }

    CNO_ZERO(state);
    state->table = dyntable;
    state->buf.data = buf;
    state->buf.size = length;

    if (!length) {
        state->writing = 1;
    }

    return state;
}


void cno_hpack_destroy(cno_hpack_t *state)
{
    if (state->writing) {
        cno_io_vector_reset(&state->buf);
        cno_io_vector_clear((cno_io_vector_t *) &state->buf);
    }

    free(state);
}


static int cno_hpack_decode_uint(cno_hpack_t *state, int prefix, size_t *result)
{
    if (!state->buf.size) {
        return CNO_ERROR_TRANSPORT("hpack: expected uint, got EOF");
    }

    unsigned char *src = (unsigned char *) state->buf.data;
    unsigned char *end = state->buf.size + src;
    unsigned char mask = ~(0xFF << prefix);
    unsigned char head = *src++ & mask;
    unsigned char size = 0;

    if (head != mask) {
        // /--\------- prefix
        // xxxx....
        *result = (size_t) head;
        return cno_io_vector_shift(&state->buf, 1);
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

    return cno_io_vector_shift(&state->buf, size + 1);
}


static int cno_hpack_decode_string(cno_hpack_t *state, cno_io_vector_t *out)
{
    if (!state->buf.size) {
        return CNO_ERROR_TRANSPORT("hpack: expected string, got EOF");
    }

    int huffman = *state->buf.data >> 7;
    size_t length;

    if (cno_hpack_decode_uint(state, 7, &length)) {
        return CNO_PROPAGATE;
    }

    if (huffman) {
        unsigned char *src = (unsigned char *) state->buf.data;
        unsigned char *end = state->buf.size + src;

        char chunk[64];
        char *chunk_ptr = chunk;
        char *chunk_end = chunk + sizeof(chunk);
        out->data = NULL;
        out->size = 0;

        // Has to be at least 37 bits, since we can only read 8-bit chars and
        // if we happen to have 29 bits at some point, that will not be enough
        // for some Huffman codes.
        uint64_t buf  = (uint64_t) *src++;
        uint64_t mask = 1 << 7;

        while (mask) { next_char:
            if (chunk_ptr == chunk_end) {
                if (cno_io_vector_extend(out, chunk, sizeof(chunk))) {
                    cno_io_vector_clear(out);
                    return CNO_PROPAGATE;
                }

                chunk_ptr = chunk;
            }

            while (src != end && mask < 1 << 30) {
                mask <<= 8;
                buf  <<= 8;
                buf   |= *src++;
            }

            const cno_huffman_node_t *tree = CNO_HUFFMAN_TREE;

            while (mask) {
                tree = buf & mask ? tree->right : tree->left;
                mask >>= 1;

                if (tree == NULL) {
                    cno_io_vector_clear(out);
                    return CNO_ERROR_TRANSPORT("hpack: invalid Huffman code");
                }

                if (!tree->left && !tree->right) {
                    if (tree->data >= 256) {
                        cno_io_vector_clear(out);
                        return CNO_ERROR_TRANSPORT("hpack: EOS in Huffman-encoded string");
                    }

                    *chunk_ptr++ = (unsigned char) tree->data;
                    goto next_char;
                }
            }

            // Truncated Huffman code; the EOS character should be reachable
            // by hanging right (it has code 0b11111...11).
            while (tree->right) tree = tree->right;

            if (tree->data != 256) {
                cno_io_vector_clear(out);
                return CNO_ERROR_TRANSPORT("hpack: truncated non-EOS Huffman code");
            }
        }

        if (cno_io_vector_extend(out, chunk, chunk_ptr - chunk)) {
            cno_io_vector_clear(out);
            return CNO_PROPAGATE;
        }

        cno_io_vector_shift(&state->buf, length);
    } else {
        out->data = cno_io_vector_slice(&state->buf, length);
        out->size = length;
    }

    if (!out->data) {
        return CNO_PROPAGATE;
    }

    return CNO_OK;
}


static int cno_hpack_decode_one(cno_hpack_t *state, cno_header_t *target)
{
    return CNO_ERROR_NOT_IMPLEMENTED("hpack");
}


static int cno_hpack_encode_one(cno_hpack_t *state, cno_header_t *source)
{
    return CNO_ERROR_NOT_IMPLEMENTED("hpack");
}


int cno_hpack_decode(cno_hpack_t *state, cno_header_t *array, size_t *limit)
{
    size_t decoded = 0;
    size_t maximum = *limit;

    for (; decoded < maximum && state->buf.size; ++decoded) {
        if (cno_hpack_decode_one(state, array++)) {
            return CNO_PROPAGATE;
        }
    }

    *limit = decoded;
    return CNO_OK;
}


int cno_hpack_encode(cno_hpack_t *state, cno_header_t *array, size_t amount)
{
    if (!state->writing) {
        return CNO_ERROR_ASSERTION("hpack: expected a hpack_decode call");
    }

    for (; amount; --amount) {
        if (cno_hpack_encode_one(state, array++)) {
            return CNO_PROPAGATE;
        }
    }

    return CNO_OK;
}
