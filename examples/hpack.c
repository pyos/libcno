#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cno-hpack.h"


inline int from_hex(char x)
{
    if ('0' <= x && x <= '9') return x - '0';
    if ('A' <= x && x <= 'F') return x - 'A' + 10;
    if ('a' <= x && x <= 'f') return x - 'a' + 10;
    return -1;
}


inline char to_hex(int i)
{
    return i < 10 ? i + '0' : i - 10 + 'a';
}


int hex_to_bytes(cno_io_vector_t *source, cno_io_vector_t *target)
{
    if (source->size % 2) {
        return CNO_ERROR_ASSERTION("2 hex digits = 1 byte; 1 hex digit = nothing");
    }

    target->size = source->size / 2;
    target->data = malloc(source->size / 2);

    if (target->data == NULL) {
        return CNO_ERROR_NO_MEMORY;
    }

    unsigned char *out = (unsigned char *) target->data;
    char *ptr = source->data;
    char *end = source->size + ptr;

    while (ptr != end) {
        int ah = from_hex(*ptr++);
        int al = from_hex(*ptr++);

        if (ah == -1 || al == -1) {
            free(target->data);
            return CNO_ERROR_ASSERTION("hex digits are [0-9a-fA-F]");
        }

        *out++ = (ah << 4) | al;
    }

    return CNO_OK;
}


int bytes_to_hex(cno_io_vector_t *source, cno_io_vector_t *target)
{
    target->size = source->size * 2;
    target->data = malloc(target->size);

    if (target->data == NULL) {
        return CNO_ERROR_NO_MEMORY;
    }

    unsigned char *out = (unsigned char *) target->data;
    unsigned char *ptr = (unsigned char *) source->data;
    unsigned char *end = ptr + source->size;

    while (ptr != end) {
        *out++ = to_hex(*ptr >> 4);
        *out++ = to_hex(*ptr & 0xF);
        ++ptr;
    }

    return CNO_OK;
}


void clear_headers(cno_header_t *h, cno_header_t *end)
{
    for (; h != end; ++h) {
        cno_io_vector_clear(&h->name);
        cno_io_vector_clear(&h->value);
    }
}


void print_header(cno_header_t *h)
{
    printf("    "); fwrite(h->name.data,  h->name.size,  1, stdout);
    printf(": ");   fwrite(h->value.data, h->value.size, 1, stdout);
    printf("\n");
}


void print_table(cno_hpack_t *state)
{
    printf("dynamic table =\n");
    cno_header_table_t *table = state->first;

    while (table != (cno_header_table_t *) state) {
        print_header(&table->data);
        table = table->next;
    }
    printf(" -- [size: %lu, limit: %lu]\n\n", state->size, state->limit);
}


int main(int argc, char *argv[])
{
    if (argc <= 2) {
        fprintf(stderr, "usage: %s <dynamic table size> <header as hex> ...\n", argv[0]);
        return 2;
    }

    int size = atoi(argv[1]);

    if (size < 0 || size > 0x7fffffff) {
        fprintf(stderr, "error: invalid dynamic table size\n");
        return 2;
    }

    cno_hpack_t decoder = { 0 };
    cno_hpack_t encoder = { 0 };
    cno_hpack_init(&encoder, size);
    cno_hpack_init(&decoder, size);

    cno_header_t result[20];
    size_t i;

    for (i = 0; i < argc - 2; ++i) {
        size_t k;
        size_t limit = sizeof(result) / sizeof(result[0]);

        cno_io_vector_t source;
        cno_io_vector_t hexdata = { argv[i + 2], strlen(argv[i + 2]) };

        if (hex_to_bytes(&hexdata, &source)) {
            goto error;
        }

        if (cno_hpack_decode(&decoder, &source, result, &limit)) {
            cno_io_vector_clear(&source);
            goto error;
        }

        printf("decode(#%lu) =\n", i + 1);

        for (k = 0; k < limit; ++k) {
            print_header(result + k);
        }

        printf(" -- with ");
        print_table(&decoder);

        cno_io_vector_clear(&source);

        if (cno_hpack_encode(&encoder, &source, result, limit)) {
            clear_headers(result, result + limit);
            goto error;
        }

        clear_headers(result, result + limit);

        printf("input (#%lu) = ", i + 1); fwrite(hexdata.data, hexdata.size, 1, stdout);
        printf("\n");

        if (bytes_to_hex(&source, &hexdata)) {
            cno_io_vector_clear(&source);
            goto error;
        }

        printf("encode(#%lu) = ", i + 1); fwrite(hexdata.data, hexdata.size, 1, stdout);
        printf(" with ");
        cno_io_vector_clear(&source);
        cno_io_vector_clear(&hexdata);
        print_table(&encoder);
    }

    cno_hpack_clear(&encoder);
    cno_hpack_clear(&decoder);
    return 0;

error:
    fprintf(stderr, "error: %s: %s (%s:%d)\n", cno_error_name(), cno_error_text(), cno_error_file(), cno_error_line());
    cno_hpack_clear(&encoder);
    cno_hpack_clear(&decoder);
    return 1;
}
