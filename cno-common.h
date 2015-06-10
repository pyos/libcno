#ifndef _CNO_COMMON_H_
#define _CNO_COMMON_H_
#include <stddef.h>

#define CNO_ZERO(ob) memset(ob, 0, sizeof(*ob))
#define CNO_STRUCT_EXPORT(name) typedef struct cno_st_ ## name ## _t cno_ ## name ## _t


#define CNO_OK         0
#define CNO_PROPAGATE -1
#define CNO_ERROR_SET(code, msg, ...) cno_error_set(code, __FILE__, __LINE__, msg, ##__VA_ARGS__)
#define CNO_ERROR_UNKNOWN(m, ...)         CNO_ERROR_SET(CNO_ERRNO_UNKNOWN,         m,  ##__VA_ARGS__)
#define CNO_ERROR_ASSERTION(m, ...)       CNO_ERROR_SET(CNO_ERRNO_ASSERTION,       m,  ##__VA_ARGS__)
#define CNO_ERROR_NO_MEMORY               CNO_ERROR_SET(CNO_ERRNO_NO_MEMORY,       "")
#define CNO_ERROR_NOT_IMPLEMENTED(m, ...) CNO_ERROR_SET(CNO_ERRNO_NOT_IMPLEMENTED, m,  ##__VA_ARGS__)
#define CNO_ERROR_TRANSPORT(m, ...)       CNO_ERROR_SET(CNO_ERRNO_TRANSPORT,       m,  ##__VA_ARGS__)
#define CNO_ERROR_INVALID_STATE(m, ...)   CNO_ERROR_SET(CNO_ERRNO_INVALID_STATE,   m,  ##__VA_ARGS__)
#define CNO_ERROR_INVALID_STREAM(m, ...)  CNO_ERROR_SET(CNO_ERRNO_INVALID_STREAM,  m,  ##__VA_ARGS__)
#define CNO_ERROR_WOULD_BLOCK(m, ...)     CNO_ERROR_SET(CNO_ERRNO_WOULD_BLOCK,     m,  ##__VA_ARGS__)


#define CNO_LIST_LINK(T) T *prev; T *next
#define CNO_LIST_ROOT(T) T *last; T *first


#define CNO_IO_VECTOR_CONST(str) { str, sizeof(str) - 1 }
#define CNO_IO_VECTOR_REFER(vec) { (vec).data, (vec).size }


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


struct cno_st_list_link_t {
    CNO_LIST_LINK(struct cno_st_list_link_t);
};


struct cno_st_io_vector_t {
    char  *data;
    size_t size;
};


struct cno_st_io_vector_tmp_t {
    char  *data;
    size_t size;
    size_t offset;
};


CNO_STRUCT_EXPORT(io_vector_tmp);
CNO_STRUCT_EXPORT(io_vector);
CNO_STRUCT_EXPORT(list_link);


int          cno_error_set  (int code, const char *file, int line, const char *fmt, ...);
int          cno_error      (void);
int          cno_error_line (void);
const char * cno_error_file (void);
const char * cno_error_text (void);
const char * cno_error_name (void);

void cno_list_init         (void *node);
void cno_list_insert_after (void *node, void *next);
void cno_list_remove       (void *node);

void   cno_io_vector_clear      (struct cno_st_io_vector_t *vec);
void   cno_io_vector_reset      (struct cno_st_io_vector_tmp_t *vec);
char * cno_io_vector_slice      (struct cno_st_io_vector_tmp_t *vec, size_t size);
int    cno_io_vector_shift      (struct cno_st_io_vector_tmp_t *vec, size_t offset);
int    cno_io_vector_strip      (struct cno_st_io_vector_tmp_t *vec);
int    cno_io_vector_extend     (struct cno_st_io_vector_t *vec, const char *data, size_t length);
int    cno_io_vector_extend_tmp (struct cno_st_io_vector_tmp_t *vec, const char *data, size_t length);


#endif
