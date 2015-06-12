#ifndef _CNO_COMMON_H_
#define _CNO_COMMON_H_
#include <stddef.h>
#include <string.h>


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

#define CNO_FIRE(ob, cb, ...) (ob->cb && ob->cb(ob, ob->cb_data, ## __VA_ARGS__))
#define CNO_STRUCT_EXPORT(name) typedef struct cno_st_ ## name ## _t cno_ ## name ## _t


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
    struct cno_st_list_link_t *prev;
    struct cno_st_list_link_t *next;
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

#define CNO_LIST_LINK(T) union { struct { T *prev; T *next;  }; cno_list_link_t __list_link_ref[1]; }
#define CNO_LIST_ROOT(T) union { struct { T *last; T *first; }; cno_list_link_t __list_link_ref[1]; }
#define cno_list_end(x) (void *) (x)->__list_link_ref
#define cno_list_init(x)            __cno_list_init((x)->__list_link_ref)
#define cno_list_insert_after(x, y) __cno_list_insert_after((x)->__list_link_ref, (y)->__list_link_ref)
#define cno_list_remove(x)          __cno_list_remove((x)->__list_link_ref)
void __cno_list_init         (cno_list_link_t *node);
void __cno_list_insert_after (cno_list_link_t *node, cno_list_link_t *next);
void __cno_list_remove       (cno_list_link_t *node);

#define CNO_IO_VECTOR_STRING(str) { str, strlen(str) }
#define CNO_IO_VECTOR_CONST(str) { str, sizeof(str) - 1 }
#define CNO_IO_VECTOR_REFER(vec) { (vec).data, (vec).size }
#define CNO_IO_VECTOR_EMPTY      { NULL, 0 }
void   cno_io_vector_clear      (struct cno_st_io_vector_t *vec);
void   cno_io_vector_reset      (struct cno_st_io_vector_tmp_t *vec);
char * cno_io_vector_slice      (struct cno_st_io_vector_tmp_t *vec, size_t size);
int    cno_io_vector_shift      (struct cno_st_io_vector_tmp_t *vec, size_t offset);
int    cno_io_vector_strip      (struct cno_st_io_vector_tmp_t *vec);
int    cno_io_vector_extend     (struct cno_st_io_vector_t *vec, const char *data, size_t length);
int    cno_io_vector_extend_tmp (struct cno_st_io_vector_tmp_t *vec, const char *data, size_t length);


#endif
