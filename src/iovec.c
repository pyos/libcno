#include "iovec.h"
#include "error.h"
#include <stdlib.h>
#include <string.h>


int cno_io_vector_shift (struct cno_st_io_vector_tmp_t *vec, size_t offset)
{
    if (offset > vec->size) {
        return CNO_ERROR_GENERIC;
    }

    vec->data   += offset;
    vec->size   -= offset;
    vec->offset += offset;
    return CNO_OK;
}


void cno_io_vector_reset (struct cno_st_io_vector_tmp_t *vec)
{
    vec->data   -= vec->offset;
    vec->size   += vec->offset;
    vec->offset  = 0;
}


void cno_io_vector_clear (struct cno_st_io_vector_t *vec)
{
    free(vec->data);
    cno_io_vector_clear_nofree(vec);
}


void cno_io_vector_clear_nofree (struct cno_st_io_vector_t *vec)
{
    vec->data = NULL;
    vec->size = 0;
}


void cno_io_vector_clear_tmp (struct cno_st_io_vector_tmp_t *vec)
{
    cno_io_vector_reset(vec);
    cno_io_vector_clear((struct cno_st_io_vector_t *) vec);
}


char * cno_io_vector_slice (struct cno_st_io_vector_tmp_t *vec, size_t size)
{
    if (size > vec->size) {
        (void) CNO_ERROR_GENERIC;
        return NULL;
    }

    char * mem = malloc(size);

    if (mem) {
        memcpy(mem, vec->data, size);
    } else {
        (void) CNO_ERROR_NOMEMORY;
    }

    cno_io_vector_shift(vec, size);
    return mem;
}


int cno_io_vector_strip (struct cno_st_io_vector_tmp_t *vec)
{
    char *ptr = malloc(vec->size);

    if (ptr == NULL) {
        return CNO_ERROR_NOMEMORY;
    }

    memcpy(ptr, vec->data, vec->size);
    free(vec->data - vec->offset);
    vec->data   = ptr;
    vec->offset = 0;
    return CNO_OK;
}


int cno_io_vector_extend (struct cno_st_io_vector_t *vec, const char *data, size_t length)
{
    size_t offset = vec->size;
    char * region = realloc(vec->data, offset + length);

    if (region == NULL) {
        return CNO_ERROR_NOMEMORY;
    }

    vec->size += length;
    vec->data  = region;
    memcpy(region + offset, data, length);
    return CNO_OK;
}


int cno_io_vector_extend_tmp (struct cno_st_io_vector_tmp_t *vec, const char *data, size_t length)
{
    size_t offset = vec->offset;
    cno_io_vector_reset(vec);
    int ok = cno_io_vector_extend((struct cno_st_io_vector_t *) vec, data, length);
    cno_io_vector_shift(vec, offset);
    return ok;
}
