#include "error.h"
#include <stdio.h>
#include <stdarg.h>


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
