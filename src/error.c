#include "error.h"
#include <stdio.h>


static struct {
    int          code;
    int          line;
    const char * file;
    const char * text;
    void *       arg;
} _cno_error;


int cno_error_set(int code, const char *text, const char *file, int line, void *arg)
{
    _cno_error.code = code;
    _cno_error.line = line;
    _cno_error.file = file;
    _cno_error.text = text;
    _cno_error.arg  = arg;
    return CNO_PROPAGATE;
}


int          cno_error      (void) { return _cno_error.code; }
int          cno_error_line (void) { return _cno_error.line; }
const char * cno_error_file (void) { return _cno_error.file; }
const char * cno_error_text (void) { return _cno_error.text; }
void *       cno_error_arg  (void) { return _cno_error.arg; }
