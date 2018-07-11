#pragma once
// #include <stddef.h>
// #include <stdlib.h>
// #include <string.h>


enum CNO_ERRNO
{
    CNO_OK                    = 0,
    CNO_ERRNO_ASSERTION       = 1,
    CNO_ERRNO_NO_MEMORY       = 2,
    CNO_ERRNO_NOT_IMPLEMENTED = 3,
    CNO_ERRNO_TRANSPORT       = 4,  // (irrecoverable) protocol error
    CNO_ERRNO_INVALID_STREAM  = 6,  // (irrecoverable) cno_write_* with wrong arguments
    CNO_ERRNO_WOULD_BLOCK     = 7,  // cno_write_message would go above the limit on concurrent messages - wait for a request to complete
    CNO_ERRNO_COMPRESSION     = 8,  // (irrecoverable) hpack error, compression now in inconsistent state
    CNO_ERRNO_DISCONNECT      = 9,  // connection has already been closed
    CNO_ERRNO_SHUTDOWN_READ   = 10, // cno_write_reset terminated the HTTP/1.x connection - close the read side, handle pending events, close the write side
};


struct cno_traceback_t
{
    const char * file;
    int line;
};


struct cno_error_t
{
    int  code;
    char text[256];
    struct cno_traceback_t *traceback_end;
    struct cno_traceback_t  traceback[16];
};


struct cno_buffer_t
{
    // depending on where this thing is used, it may hold either binary octets
    // or human-readable data (http headers). casting the buffer to uint8_t
    // where necessary is easy, converting all string literals to uint8_t is not.
    const char *data;
    size_t size;
};


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
    size_t cap;
};


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


/* Return some information about the last error in the current thread. */
const struct cno_error_t * cno_error(void);

/* Fail with a specified error code and message. */
int cno_error_set(const char *file, int line, int code,
                  const char *fmt, ...) __attribute__ ((format(printf, 4, 5)));

/* Fail with the same code and message as the previous call to `cno_error_set`. */
int cno_error_upd(const char *file, int line);


#define CNO_ERROR(...)       cno_error_set(__FILE__, __LINE__, CNO_ERRNO_ ## __VA_ARGS__)
#define CNO_ERROR_UP()       cno_error_upd(__FILE__, __LINE__)
#define CNO_ERROR_NULL(...) (CNO_ERROR(__VA_ARGS__), NULL)
#define CNO_ERROR_UP_NULL() (CNO_ERROR_UP(), NULL)


#define cno_list_end(x)       ((void *) &(x)->cno_list_handle)
#define cno_list_init(x)      cno_list_gen_init(&(x)->cno_list_handle)
#define cno_list_append(x, y) cno_list_gen_append(&(x)->cno_list_handle, &(y)->cno_list_handle)
#define cno_list_remove(x)    cno_list_gen_remove(&(x)->cno_list_handle)


static const struct cno_buffer_t     CNO_BUFFER_EMPTY     = { NULL, 0 };
static const struct cno_buffer_dyn_t CNO_BUFFER_DYN_EMPTY = {{{NULL, 0}}, 0, 0};

// cffi does not compile inline functions
#if !CFFI_CDEF_MODE

static inline struct cno_buffer_t CNO_BUFFER_STRING(const char *s)
{
    return (struct cno_buffer_t) { s, strlen(s) };
}


static inline int cno_buffer_eq(const struct cno_buffer_t a, const struct cno_buffer_t b)
{
    return a.size == b.size && 0 == memcmp(a.data, b.data, b.size);
}


static inline int cno_buffer_startswith(const struct cno_buffer_t a, const struct cno_buffer_t b)
{
    return a.size >= b.size && 0 == memcmp(a.data, b.data, b.size);
}


static inline int cno_buffer_endswith(const struct cno_buffer_t a, const struct cno_buffer_t b)
{
    return a.size >= b.size && 0 == memcmp(a.data + a.size - b.size, b.data, b.size);
}


static inline void cno_buffer_dyn_clear(struct cno_buffer_dyn_t *x)
{
    free(x->data - x->offset);
    *x = CNO_BUFFER_DYN_EMPTY;
}


static inline void cno_buffer_dyn_shift(struct cno_buffer_dyn_t *x, size_t off)
{
    x->data   += off;
    x->size   -= off;
    x->cap    -= off;
    x->offset += off;
}


static inline int cno_buffer_dyn_reserve(struct cno_buffer_dyn_t *x, size_t n)
{
    if (n <= x->cap)
        return CNO_OK;

    if (x->offset) {
        memmove(x->data - x->offset, x->data, x->size);
        x->data  -= x->offset;
        x->cap   += x->offset;
        x->offset = 0;
    }

    if (n <= x->cap)
        return CNO_OK;

    if (n < x->cap + CNO_BUFFER_ALLOC_MIN)
        n = x->cap + CNO_BUFFER_ALLOC_MIN;
    if (n < x->cap * CNO_BUFFER_ALLOC_MIN_EXP)
        n = x->cap * CNO_BUFFER_ALLOC_MIN_EXP;

    char *m = (char *) malloc(n);
    if (m == NULL)
        return CNO_ERROR(NO_MEMORY, "%zu bytes", n);

    if (x->data != NULL)
        memcpy(m, x->data, x->size);
    free(x->data);
    x->data = m;
    x->cap  = n;
    return CNO_OK;
}


static inline int cno_buffer_dyn_concat(struct cno_buffer_dyn_t *a, const struct cno_buffer_t b)
{
    if (b.data == NULL)
        return CNO_OK;

    if (cno_buffer_dyn_reserve(a, a->size + b.size))
        return CNO_ERROR_UP();

    memcpy(a->data + a->size, b.data, b.size);
    a->size += b.size;
    return CNO_OK;
}


static inline void cno_list_gen_init(struct cno_list_t *x)
{
    *x = (struct cno_list_t) { x, x };
}


static inline void cno_list_gen_append(struct cno_list_t *x, struct cno_list_t *y)
{
    *y = (struct cno_list_t) { x, x->next };
    x->next->prev = y;
    x->next       = y;
}


static inline void cno_list_gen_remove(struct cno_list_t *x)
{
    x->next->prev = x->prev;
    x->prev->next = x->next;
}

#endif
