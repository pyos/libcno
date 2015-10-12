#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <cno/common.h>


static _Thread_local struct {
    int  code;
    char text[512];
    cno_traceback_t  tb_head[128];
    cno_traceback_t *tb_last;
} cno_error_st;


int cno_error_set(const char *file, int line, const char *func, int code, const char *fmt, ...)
{
    cno_error_st.code = code;
    cno_error_st.tb_last = cno_error_st.tb_head;

    va_list vl;
    va_start(vl, fmt);
    vsnprintf(cno_error_st.text, sizeof(cno_error_st.text), fmt, vl);
    va_end(vl);

    return cno_error_upd(file, line, func);
}


const cno_traceback_t *cno_error_tb_head(void) { return cno_error_st.tb_head; }
const cno_traceback_t *cno_error_tb_next(const cno_traceback_t *trace)
{
    if (++trace == cno_error_st.tb_last) {
        return NULL;
    }

    return trace;
}

int cno_error_upd(const char *file, int line, const char *func)
{
    if (cno_error_st.tb_last == (cno_traceback_t *) &cno_error_st.tb_last) {
        cno_error_st.tb_last[-1].file = "...";
        cno_error_st.tb_last[-1].func = "...";
        cno_error_st.tb_last[-1].line = 0;
    } else {
        cno_error_st.tb_last->file = file;
        cno_error_st.tb_last->func = func;
        cno_error_st.tb_last->line = line;
        cno_error_st.tb_last++;
    }
    return -1;
}


int          cno_error      (void) { return cno_error_st.code; }
const char * cno_error_text (void) { return cno_error_st.text; }
const char * cno_error_name (void)
{
    switch (cno_error()) {
        case CNO_ERRNO_GENERIC:         return "fatal error";
        case CNO_ERRNO_ASSERTION:       return "assertion failed";
        case CNO_ERRNO_NO_MEMORY:       return "out of memory";
        case CNO_ERRNO_NOT_IMPLEMENTED: return "not implemented";
        case CNO_ERRNO_TRANSPORT:       return "transport error";
        case CNO_ERRNO_INVALID_STATE:   return "invalid state";
        case CNO_ERRNO_INVALID_STREAM:  return "invalid stream";
        case CNO_ERRNO_WOULD_BLOCK:     return "too much data";
        case CNO_ERRNO_COMPRESSION:     return "compression error";
        default: return "unknown error";
    }
}


void cno_io_vector_clear(cno_io_vector_t *vec)
{
    free(vec->data);
    vec->data = NULL;
    vec->size = 0;
}


void cno_io_vector_reset(cno_io_vector_tmp_t *vec)
{
    vec->data   -= vec->offset;
    vec->size   += vec->offset;
    vec->offset  = 0;
}


int cno_io_vector_shift(cno_io_vector_tmp_t *vec, size_t offset)
{
    vec->data   += offset;
    vec->size   -= offset;
    vec->offset += offset;
    return CNO_OK;
}


int cno_io_vector_strip(cno_io_vector_tmp_t *vec)
{
    char *ptr = malloc(vec->size);

    if (ptr == NULL) {
        return CNO_ERROR(NO_MEMORY, "--");
    }

    memcpy(ptr, vec->data, vec->size);
    free(vec->data - vec->offset);
    vec->data   = ptr;
    vec->offset = 0;
    return CNO_OK;
}


int cno_io_vector_copy(cno_io_vector_t *vec, const cno_io_vector_t *src)
{
    char *mem = malloc(src->size);

    if (mem == NULL) {
        return CNO_ERROR(NO_MEMORY, "--");
    }

    memcpy(mem, src->data, src->size);
    vec->data = mem;
    vec->size = src->size;
    return CNO_OK;
}


int cno_io_vector_extend(cno_io_vector_t *vec, const char *data, size_t length)
{
    size_t offset = vec->size;
    char * region = realloc(vec->data, offset + length);

    if (region == NULL) {
        return CNO_ERROR(NO_MEMORY, "--");
    }

    vec->size += length;
    vec->data  = region;
    memcpy(region + offset, data, length);
    return CNO_OK;
}


int cno_io_vector_extend_tmp(cno_io_vector_tmp_t *vec, const char *data, size_t length)
{
    size_t offset = vec->offset;
    cno_io_vector_reset(vec);
    int ok = cno_io_vector_extend((struct cno_st_io_vector_t *) vec, data, length);
    cno_io_vector_shift(vec, offset);
    return ok;
}
