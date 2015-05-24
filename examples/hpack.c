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
    if (i < 10) return i + '0';
    return i - 10 + 'a';
}


int hex_to_iovec(char *data, size_t size, cno_io_vector_t *target)
{
    if (size % 2) {
        return CNO_ERROR_ASSERTION("2 hex digits = 1 byte; 1 hex digit = nothing");
    }

    size /= 2;
    target->size = size;
    target->data = malloc(size);

    if (target->data == NULL) {
        return CNO_ERROR_NO_MEMORY;
    }

    size_t i;
    unsigned char *tg = (unsigned char *) target->data;

    for (i = 0; i < size; ++i) {
        int ah = from_hex(*data++);
        int al = from_hex(*data++);

        if (ah == -1 || al == -1) {
            free(target->data);
            return CNO_ERROR_ASSERTION("hex digits are [0-9a-fA-F]");
        }

        *tg++ = (ah << 4) | al;
    }

    return CNO_OK;
}


void print_hex(cno_io_vector_t *vec)
{
    unsigned char *ptr = (unsigned char *) vec->data;
    unsigned char *end = ptr + vec->size;

    while (ptr != end) {
        putchar(to_hex(*ptr >> 4));
        putchar(to_hex(*ptr & 0xF));
        ++ptr;
    }

    putchar('\n');
}


void print_header(cno_header_t *h)
{
    printf("    (%lu) ", h->name.size);
    fwrite(h->name.data, h->name.size, 1, stdout);
    printf(" = (%lu) ", h->value.size);
    fwrite(h->value.data, h->value.size, 1, stdout);
    printf("\n");
}


void print_table(cno_hpack_t *state)
{
    cno_header_table_t *table = state->first;

    while (table != (cno_header_table_t *) state) {
        print_header(&table->data);
        table = table->next;
    }
}


int main(int argc, char *argv[])
{
    if (argc == 1) {
        fprintf(stderr, "usage: %s <header as hex> ...\n", argv[0]);
        return 2;
    }

    cno_hpack_t decoder = { .limit = 170, .limit_upper = 0xffffffff, .limit_update_min = 170, .limit_update_end = 170 };
    cno_hpack_t encoder = { .limit = 170, .limit_upper = 0xffffffff, .limit_update_min = 170, .limit_update_end = 170 };
    cno_list_init(&encoder);
    cno_list_init(&decoder);

    cno_header_t result[20];
    size_t i;

    for (i = 0; i < argc - 1; ++i) {
        size_t k;
        size_t limit = sizeof(result) / sizeof(result[0]);

        cno_io_vector_t source;

        if (hex_to_iovec(argv[i + 1], strlen(argv[i + 1]), &source)) {
            goto error;
        }

        printf("-- input %lu:\n", i + 1);

        if (cno_hpack_decode(&decoder, &source, result, &limit)) {
            cno_io_vector_clear(&source);
            goto error;
        }

        cno_io_vector_clear(&source);

        if (cno_hpack_encode(&encoder, &source, result, limit)) {
            for (k = 0; k < limit; ++k) {
                cno_io_vector_clear(&result[k].name);
                cno_io_vector_clear(&result[k].value);
            }

            goto error;
        }

        for (k = 0; k < limit; ++k) {
            print_header(result + k);
            cno_io_vector_clear(&result[k].name);
            cno_io_vector_clear(&result[k].value);
        }

        printf("-- reencoded: ");
        print_hex(&source);
        cno_io_vector_clear(&source);

        printf("-- dynamic table after decoding (size = %lu <= %lu):\n", decoder.size, decoder.limit);
        print_table(&decoder);
        printf("-- dynamic table after encoding (size = %lu <= %lu):\n", encoder.size, encoder.limit);
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
