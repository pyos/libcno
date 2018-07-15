#include <stdio.h>
#include <stdarg.h>

#include "config.h"
#include "common.h"


_Thread_local static struct cno_error_t E;


const struct cno_error_t * cno_error(void)
{
    return &E;
}


int cno_error_set(const char *file, int line, int code, const char *fmt, ...)
{
    E.code = code;
    E.traceback_end = &E.traceback[0];

    va_list vl;
    va_start(vl, fmt);
    vsnprintf(E.text, sizeof(E.text), fmt, vl);
    va_end(vl);

    return cno_error_upd(file, line);
}


int cno_error_upd(const char *file, int line)
{
    if (E.traceback_end != &E.traceback[sizeof(E.traceback) / sizeof(*E.traceback)])
        *E.traceback_end++ = (struct cno_traceback_t) { file, line };

    return -1;
}
