#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "cno-common.h"


static struct {
    int          code;
    int          line;
    const char * file;
    char text[512];
} _cno_error;


int cno_error_set(int code, const char *file, int line, const char *fmt, ...)
{
    _cno_error.code = code;
    _cno_error.line = line;
    _cno_error.file = file;

    va_list vl;
    va_start(vl, fmt);
    vsnprintf(_cno_error.text, sizeof(_cno_error.text), fmt, vl);
    va_end(vl);
    return CNO_PROPAGATE;
}


int          cno_error      (void) { return _cno_error.code; }
int          cno_error_line (void) { return _cno_error.line; }
const char * cno_error_file (void) { return _cno_error.file; }
const char * cno_error_text (void) { return _cno_error.text; }
const char * cno_error_name (void)
{
    switch (cno_error()) {
        case CNO_ERRNO_UNKNOWN:         return "generic error";
        case CNO_ERRNO_ASSERTION:       return "assertion failed";
        case CNO_ERRNO_NO_MEMORY:       return "out of memory";
        case CNO_ERRNO_NOT_IMPLEMENTED: return "not implemented";
        case CNO_ERRNO_TRANSPORT:       return "transport error";
        case CNO_ERRNO_INVALID_STATE:   return "invalid state";
        case CNO_ERRNO_INVALID_STREAM:  return "stream does not exist";
        default: return "unknown error";
    }
}


void cno_list_insert_after(void *node, void *next)
{
    struct cno_st_list_link_t *node_ = (struct cno_st_list_link_t *) node;
    struct cno_st_list_link_t *next_ = (struct cno_st_list_link_t *) next;

    next_->next = node_->next;
    next_->prev = node_;
    node_->next = next_->next->prev = next_;
}


void cno_list_remove(void *node)
{
    struct cno_st_list_link_t *node_ = (struct cno_st_list_link_t *) node;
    node_->next->prev = node_->prev;
    node_->prev->next = node_->next;
}


void cno_io_vector_clear (struct cno_st_io_vector_t *vec)
{
    free(vec->data);
    vec->data = NULL;
    vec->size = 0;
}


void cno_io_vector_reset (struct cno_st_io_vector_tmp_t *vec)
{
    vec->data   -= vec->offset;
    vec->size   += vec->offset;
    vec->offset  = 0;
}


char * cno_io_vector_slice (struct cno_st_io_vector_tmp_t *vec, size_t size)
{
    if (size > vec->size) {
        (void) CNO_ERROR_ASSERTION("out of bounds (%lu > %lu)", size, vec->size);
        return NULL;
    }

    char *mem = malloc(size);

    if (mem) {
        memcpy(mem, vec->data, size);
    } else {
        (void) CNO_ERROR_NO_MEMORY;
    }

    cno_io_vector_shift(vec, size);
    return mem;
}


int cno_io_vector_shift (struct cno_st_io_vector_tmp_t *vec, size_t offset)
{
    if (offset > vec->size) {
        return CNO_ERROR_ASSERTION("out of bounds (%lu > %lu)", offset, vec->size);
    }

    vec->data   += offset;
    vec->size   -= offset;
    vec->offset += offset;
    return CNO_OK;
}


int cno_io_vector_strip (struct cno_st_io_vector_tmp_t *vec)
{
    char *ptr = malloc(vec->size);

    if (ptr == NULL) {
        return CNO_ERROR_NO_MEMORY;
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
        return CNO_ERROR_NO_MEMORY;
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
