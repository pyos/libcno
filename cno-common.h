#ifndef _CNO_COMMON_H_
#define _CNO_COMMON_H_
#include <stddef.h>
#include <string.h>


#define CNO_ERROR_SET(code, ...) cno_error_set(code, __FILE__, __LINE__, ##__VA_ARGS__)
#define CNO_ERROR_UNKNOWN(...)         CNO_ERROR_SET(CNO_ERRNO_UNKNOWN,         ##__VA_ARGS__)
#define CNO_ERROR_ASSERTION(...)       CNO_ERROR_SET(CNO_ERRNO_ASSERTION,       ##__VA_ARGS__)
#define CNO_ERROR_NO_MEMORY            CNO_ERROR_SET(CNO_ERRNO_NO_MEMORY,       "")
#define CNO_ERROR_NOT_IMPLEMENTED(...) CNO_ERROR_SET(CNO_ERRNO_NOT_IMPLEMENTED, ##__VA_ARGS__)
#define CNO_ERROR_TRANSPORT(...)       CNO_ERROR_SET(CNO_ERRNO_TRANSPORT,       ##__VA_ARGS__)
#define CNO_ERROR_INVALID_STATE(...)   CNO_ERROR_SET(CNO_ERRNO_INVALID_STATE,   ##__VA_ARGS__)
#define CNO_ERROR_INVALID_STREAM(...)  CNO_ERROR_SET(CNO_ERRNO_INVALID_STREAM,  ##__VA_ARGS__)
#define CNO_ERROR_WOULD_BLOCK(...)     CNO_ERROR_SET(CNO_ERRNO_WOULD_BLOCK,     ##__VA_ARGS__)

#define CNO_FIRE(ob, cb, ...) (ob->cb && ob->cb(ob, ob->cb_data, ## __VA_ARGS__))
#define CNO_STRUCT_EXPORT(name) typedef struct cno_st_ ## name ## _t cno_ ## name ## _t


enum CNO_RETCODE {
    CNO_OK        =  0,
    CNO_PROPAGATE = -1,
};


enum CNO_ERRNO {
    CNO_ERRNO_UNKNOWN,
    CNO_ERRNO_ASSERTION,
    CNO_ERRNO_NO_MEMORY,
    CNO_ERRNO_NOT_IMPLEMENTED,
    CNO_ERRNO_TRANSPORT,        // Transport-level syntax error. Stream-level errors simply close the stream.
    CNO_ERRNO_INVALID_STATE,    // Connection cannot do that while in the current state.
    CNO_ERRNO_INVALID_STREAM,   // Stream with given ID was not found.
    CNO_ERRNO_WOULD_BLOCK,      // Frame too big to send with current flow control window
};


int          cno_error_set  (int code, const char *file, int line, const char *fmt, ...);
int          cno_error      (void);
int          cno_error_line (void);
const char * cno_error_file (void);
const char * cno_error_text (void);
const char * cno_error_name (void);


struct cno_st_io_vector_t {
    char  *data;
    size_t size;
};


struct cno_st_io_vector_tmp_t {
    char  *data;
    size_t size;
    size_t offset;
};


CNO_STRUCT_EXPORT(io_vector);
CNO_STRUCT_EXPORT(io_vector_tmp);

#define CNO_IO_VECTOR_STRING(str) { str, strlen(str) }
#define CNO_IO_VECTOR_CONST(str)  { str, sizeof(str) - 1 }
#define CNO_IO_VECTOR_REFER(vec)  { (vec).data, (vec).size }
#define CNO_IO_VECTOR_EMPTY       { NULL, 0 }
void   cno_io_vector_clear      (struct cno_st_io_vector_t *vec);
void   cno_io_vector_reset      (struct cno_st_io_vector_tmp_t *vec);
char * cno_io_vector_slice      (struct cno_st_io_vector_tmp_t *vec, size_t size);
int    cno_io_vector_shift      (struct cno_st_io_vector_tmp_t *vec, size_t offset);
int    cno_io_vector_strip      (struct cno_st_io_vector_tmp_t *vec);
int    cno_io_vector_extend     (struct cno_st_io_vector_t *vec, const char *data, size_t length);
int    cno_io_vector_extend_tmp (struct cno_st_io_vector_tmp_t *vec, const char *data, size_t length);


#include "cno-common-list.h"
#include "cno-common-map.h"
#endif
