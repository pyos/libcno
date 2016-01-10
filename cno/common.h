// #include <stddef.h>
// #include <stdlib.h>
// #include <string.h>
#ifndef CNO_COMMON_H
#define CNO_COMMON_H


/* ----- Error handling -----
 *
 * A function that can return an error must return either an int or a pointer.
 * 0 or a non-NULL pointer means OK; -1 or a NULL pointer means there's an error.
 *
 * Call CNO_ERROR with the name of an error (there should be an appropriate CNO_ERRNO_*
 * constant) and the error message (printf-formatted) to signal a new error. CNO_ERROR
 * always returns -1, so that's all you need to do in int-returning functions.
 * CNO_ERROR_NULL is like CNO_ERROR but returns NULL.
 *
 * Call CNO_ERROR_UP to add a line to the traceback when exiting due to an error
 * in a nested function. CNO_ERROR_UP returns -1, just like CNO_ERROR.
 * CNO_ERROR_UP_NULL returns NULL instead, duh. */

#define CNO_OK 0

#define CNO_ERROR_SET(...)   cno_error_set(__FILE__, __LINE__, __func__, __VA_ARGS__)
#define CNO_ERROR(...)       CNO_ERROR_SET(CNO_ERRNO_ ## __VA_ARGS__)
#define CNO_ERROR_NULL(...) (CNO_ERROR(__VA_ARGS__), NULL)

#if CNO_ERROR_DISABLE_TRACEBACKS
    #define CNO_ERROR_UP()      -1
    #define CNO_ERROR_UP_NULL() NULL
#else
    #define CNO_ERROR_UP()       cno_error_upd(__FILE__, __LINE__, __func__)
    #define CNO_ERROR_UP_NULL() (CNO_ERROR_UP(), NULL)
#endif

/* Maximum number of lines in a traceback. Note that the space to hold them
 * is statically allocated. (Do not redefine this in different compilation units!) */
#define CNO_ERROR_TRACEBACK_DEPTH 128


enum CNO_ERRNO
{
    CNO_ERRNO_GENERIC,
    CNO_ERRNO_ASSERTION,
    CNO_ERRNO_NO_MEMORY,
    CNO_ERRNO_NOT_IMPLEMENTED,
    CNO_ERRNO_TRANSPORT,
    CNO_ERRNO_INVALID_STATE,
    CNO_ERRNO_INVALID_STREAM,
    CNO_ERRNO_WOULD_BLOCK,
    CNO_ERRNO_COMPRESSION,
    CNO_ERRNO_DISCONNECT,
};


struct cno_traceback_t
{
    const char * file;
    const char * func;
    int line;
};


struct cno_error_t
{
    int  code;
    char text[512];
    struct cno_traceback_t  traceback[CNO_ERROR_TRACEBACK_DEPTH];
    struct cno_traceback_t *traceback_end;
};


/* Return some information about the last error in the current thread. */
const struct cno_error_t * cno_error(void);


/* Reset the error information and construct a new traceback starting at a given point.
 * Should not be called directly; use CNO_ERROR instead. */
int cno_error_set (const char *file, int line,
                   const char *func, int code,
                   const char *fmt, ...) __attribute__ ((format(printf, 5, 6)));


/* Append a line to the traceback, if there is space left. */
int cno_error_upd (const char *file, int line,
                   const char *func);


/* ----- String views ----- */

struct cno_buffer_t
{
    // depending on where this thing is used, it may hold either binary octets
    // or human-readable data (http headers). casting the buffer to uint8_t
    // where necessary is easy, converting all string literals to uint8_t is not.
    char  *data;
    size_t size;
};


/* Initialize an empty static buffer. */
#define CNO_BUFFER_EMPTY ((struct cno_buffer_t) { NULL, 0 })

/* Initialize a static buffer from an array. */
#define CNO_BUFFER_ARRAY(arr) ((struct cno_buffer_t) { (char *) arr, sizeof(arr) })

/* Initialize a static buffer from a string constant. */
#define CNO_BUFFER_CONST(str) ((struct cno_buffer_t) { (char *) str, sizeof(str) - 1 })

/* Initialize a static buffer from a null-terminated string. */
#define CNO_BUFFER_STRING(str) ((struct cno_buffer_t) { (char *) str, strlen(str) })


static inline void cno_buffer_clear(struct cno_buffer_t *x)
{
    free(x->data);
    x->data = NULL;
    x->size = 0;
}


static inline int cno_buffer_eq(const struct cno_buffer_t a, const struct cno_buffer_t b)
{
    return a.size == b.size && 0 == memcmp(a.data, b.data, b.size);
}


static inline int cno_buffer_startswith(const struct cno_buffer_t a, const struct cno_buffer_t b)
{
    return a.size >= b.size && 0 == memcmp(a.data, b.data, b.size);
}


static inline int cno_buffer_copy(struct cno_buffer_t *a, const struct cno_buffer_t b)
{
    char *m = (char *) malloc(b.size);

    if (m == NULL)
        return CNO_ERROR(NO_MEMORY, "%zu bytes", b.size);

    memcpy(m, b.data, b.size);
    a->data = m;
    a->size = b.size;
    return CNO_OK;
}


/* ----- Shiftable string views ----- */

struct cno_buffer_dyn_t
{
    union {
        struct cno_buffer_t as_static;
        struct {
            char  *data;
            size_t size;
        };
    };
    size_t offset;
    size_t reserve;
};


/* Construct a shiftable view sharing a buffer with a static one. */
#define CNO_BUFFER_DYN_ALIAS(buf) (struct cno_buffer_dyn_t) { {buf}, 0, 0 }


static inline void cno_buffer_dyn_clear(struct cno_buffer_dyn_t *x)
{
    free(x->data - x->offset);
    x->data    = NULL;
    x->size    = 0;
    x->offset  = 0;
    x->reserve = 0;
}


/* Consume first few bytes of a buffer. */
static inline void cno_buffer_dyn_shift(struct cno_buffer_dyn_t *x, size_t off)
{
    x->data   += off;
    x->size   -= off;
    x->offset += off;
}


static inline int cno_buffer_dyn_concat(struct cno_buffer_dyn_t *a, const struct cno_buffer_t b)
{
    if (a->offset) {
        memmove(a->data - a->offset, a->data, a->size);
        a->data    -= a->offset;
        a->reserve += a->offset;
        a->offset   = 0;
    }

    if (b.size <= a->reserve) {
        memcpy(a->data + a->size, b.data, b.size);
        a->size    += b.size;
        a->reserve -= b.size;
        return CNO_OK;
    }

    // round up to a multiple of 512 bytes
    size_t new_size = (a->size + b.size + 511) & ~511;

    char *m = (char *) malloc(new_size);

    if (m == NULL)
        return CNO_ERROR(NO_MEMORY, "%zu bytes", new_size);

    memcpy(m, a->data, a->size);
    memcpy(m + a->size, b.data, b.size);
    free(a->data);
    a->data    = m;
    a->size   += b.size;
    a->reserve = new_size - a->size;
    return CNO_OK;
}


/* ----- Generic intrusive doubly-linked circular list ----- */


struct cno_list_t
{
    struct cno_list_t *prev;
    struct cno_list_t *next;
};


#define cno_list_link_t(T)               \
  { union {                              \
      struct cno_list_t cno_list_handle; \
      struct { T *prev, *next; };        \
  }; }


#define cno_list_root_t(T)               \
  { union {                              \
      struct cno_list_t cno_list_handle; \
      struct { T *last, *first; };       \
  }; }


#define cno_list_end(x)       ((void *) &(x)->cno_list_handle)
#define cno_list_init(x)      cno_list_gen_init(&(x)->cno_list_handle)
#define cno_list_append(x, y) cno_list_gen_append(&(x)->cno_list_handle, &(y)->cno_list_handle)
#define cno_list_remove(x)    cno_list_gen_remove(&(x)->cno_list_handle)


static inline void cno_list_gen_init(struct cno_list_t *x)
{
    x->next = x;
    x->prev = x;
}


static inline void cno_list_gen_append(struct cno_list_t *x, struct cno_list_t *y)
{
    y->prev = x;
    y->next = x->next;
    x->next = y->next->prev = y;
}


static inline void cno_list_gen_remove(struct cno_list_t *x)
{
    x->next->prev = x->prev;
    x->prev->next = x->next;
}

#endif
