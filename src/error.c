#include "error.h"
#include <stdio.h>


static struct {
    int _code;
    int _line;
    const char *_file;
    const char *_text;
    void *_arg;
} _cno_error;


int cno_error_set(int code, const char *text, const char *file, int line, void *arg)
{
    _cno_error._code = code;
    _cno_error._line = line;
    _cno_error._file = file;
    _cno_error._text = text;
    _cno_error._arg  = arg;
    return CNO_PROPAGATE;
}


int cno_error(void)
{
    return _cno_error._code;
}


int cno_error_line(void)
{
    return _cno_error._line;
}


const char *cno_error_file(void)
{
    return _cno_error._file;
}


const char *cno_error_text(void)
{
    return _cno_error._text;
}


void *cno_error_arg(void)
{
    return _cno_error._arg;
}
