#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>  // req @ common.h
#include <stdlib.h>
#include <string.h>

#include <cno/common.h>


static _Thread_local struct cno_error_t LAST_ERROR;


const struct cno_error_t * cno_error(void)
{
    return &LAST_ERROR;
}


int cno_error_set(const char *file, int line, const char *func, int code, const char *fmt, ...)
{
    LAST_ERROR.code = code;
    LAST_ERROR.traceback_end = &LAST_ERROR.traceback[0];

    va_list vl;
    va_start(vl, fmt);
    vsnprintf(LAST_ERROR.text, sizeof(LAST_ERROR.text), fmt, vl);
    va_end(vl);

    return cno_error_upd(file, line, func);
}


int cno_error_upd(const char *file, int line, const char *func)
{
    if (LAST_ERROR.traceback_end == &LAST_ERROR.traceback[CNO_ERROR_TRACEBACK_DEPTH]) {
        file = "...";
        func = "...";
        line = 0;
    }

    struct cno_traceback_t *tb = LAST_ERROR.traceback_end++;
    tb->file = file;
    tb->func = func;
    tb->line = line;
    return -1;
}
