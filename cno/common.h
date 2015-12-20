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

#define CNO_ERROR_SET(...)   cno_error_set(__FILE__, __LINE__, __func__, ##__VA_ARGS__)
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
struct cno_error_t const * cno_error(void);


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


/* Initialize an empty dynamic buffer. */
#define CNO_BUFFER_EMPTY { NULL, 0 }

/* Initialize a static buffer from an array. None of the below functions work
 * with static buffers! Do not write to them either. */
#define CNO_BUFFER_ARRAY(arr)  { (char *) arr, sizeof(arr) }

/* Initialize a static buffer from a string constant. */
#define CNO_BUFFER_CONST(str)  { (char *) str, sizeof(str) - 1 }

/* Initialize a static buffer from a null-terminated string. */
#define CNO_BUFFER_STRING(str) { (char *) str, strlen(str) }


/* Release the contents of a dynamic buffer. */
static inline void cno_buffer_clear(struct cno_buffer_t * x)
{
    free(x->data);
    x->data = NULL;
    x->size = 0;
}


/* Check whether two buffers are equal. */
static inline int cno_buffer_equals(const struct cno_buffer_t *a, const struct cno_buffer_t *b)
{
    return a->size == b->size && 0 == memcmp(a->data, b->data, b->size);
}


/* Append new data to the end of a dynamic buffer. */
static inline int cno_buffer_append(struct cno_buffer_t *a, const char *b, size_t b_size)
{
    char *m = realloc(a->data, a->size + b_size);

    if (m == NULL)
        return CNO_ERROR(NO_MEMORY, "%zu bytes", a->size + b_size);

    memcpy(m + a->size, b, b_size);
    a->data  = m;
    a->size += b_size;
    return CNO_OK;
}


/* Append the contents of one buffer to another. */
static inline int cno_buffer_concat(struct cno_buffer_t *a, const struct cno_buffer_t *b)
{
    return cno_buffer_append(a, b->data, b->size);
}


/* Construct a buffer from an existing one. */
static inline int cno_buffer_copy(struct cno_buffer_t *a, const struct cno_buffer_t *b)
{
    a->data = NULL;
    a->size = 0;
    return cno_buffer_concat(a, b);
}


/* ----- Shiftable string views ----- */

struct cno_buffer_off_t
{
    char  *data;
    size_t size;
    size_t offset;
};


/* Release the contents of a shifted dynamic buffer. */
static inline void cno_buffer_off_clear(struct cno_buffer_off_t *x)
{
    free(x->data - x->offset);
    x->data   = NULL;
    x->size   = 0;
    x->offset = 0;
}


/* Consume first few bytes of a buffer. */
static inline void cno_buffer_off_shift(struct cno_buffer_off_t *x, size_t off)
{
    x->data   += off;
    x->size   -= off;
    x->offset += off;
}


/* Move back to the beginning of a buffer. */
static inline void cno_buffer_off_reset(struct cno_buffer_off_t *x)
{
    x->data  -= x->offset;
    x->size  += x->offset;
    x->offset = 0;
}


/* Append the contents of a buffer to a shifted buffer. */
static inline int cno_buffer_off_append(struct cno_buffer_off_t *a, const char *b, size_t b_size)
{
    char *m = realloc(a->data - a->offset, a->size + a->offset + b_size);

    if (m == NULL)
        return CNO_ERROR(NO_MEMORY, "%zu bytes", a->size + a->offset + b_size);

    memcpy(m + a->size + a->offset, b, b_size);
    a->data  = m + a->offset;
    a->size += b_size;
    return CNO_OK;
}


/* Release the consumed part of a buffer. */
static inline void cno_buffer_off_trim(struct cno_buffer_off_t *x)
{
    char *m = malloc(x->size);

    if (m == NULL)
        // ok, maybe later.
        return;

    memcpy(m, x->data, x->size);
    free(x->data - x->offset);
    x->data   = m;
    x->offset = 0;
}


/* ----- Generic intrusive doubly-linked circular list ----- */


struct cno_list_t
{
    struct cno_list_t *prev;
    struct cno_list_t *next;
};


#define cno_list_link_t(T)                  \
  {                                         \
      struct cno_list_t cno_list_handle[0]; \
      T *prev;                              \
      T *next;                              \
  }


#define cno_list_root_t(T)                  \
  {                                         \
      struct cno_list_t cno_list_handle[0]; \
      T *last;                              \
      T *first;                             \
  }


#define cno_list_end(x)       ((void *) (x)->cno_list_handle)
#define cno_list_init(x)      cno_list_gen_init((x)->cno_list_handle)
#define cno_list_append(x, y) cno_list_gen_append((x)->cno_list_handle, (y)->cno_list_handle)
#define cno_list_remove(x)    cno_list_gen_remove((x)->cno_list_handle)


static inline void cno_list_gen_init(struct cno_list_t *x)
{
    x->next = x;
    x->prev = x;
}


static inline void cno_list_gen_append(struct cno_list_t *x, struct cno_list_t *y)
{
    y->next = x->next;
    y->prev = x;
    x->next = y->next->prev = y;
}


static inline void cno_list_gen_remove(struct cno_list_t *x)
{
    x->next->prev = x->prev;
    x->prev->next = x->next;
}


/* ----- size_t-keyed intrusive hashmap (with closed hashing.) ----- */


struct cno_hmap_handle_t
{
    struct cno_list_link_t(struct cno_hmap_handle_t);
    size_t key;
};


struct cno_hmap_bucket_t
{
    struct cno_list_root_t(struct cno_hmap_handle_t);
};


#define cno_hmap(size) { struct cno_hmap_bucket_t cno_hmap_buckets[size]; }
#define cno_hmap_value { struct cno_hmap_handle_t cno_hmap_handle[1];     }


/* Yay, pointer magic! */
#define cno_hmap_size(m) sizeof((m)->cno_hmap_buckets) / sizeof(struct cno_hmap_bucket_t)
#define cno_hmap_init(m)            cno_hmap_gen_init(  cno_hmap_size(m), (m)->cno_hmap_buckets)
#define cno_hmap_insert(m, k, x)    cno_hmap_gen_insert(cno_hmap_size(m), (m)->cno_hmap_buckets, k, (x)->cno_hmap_handle)
#define cno_hmap_find(m, k)         cno_hmap_gen_find(  cno_hmap_size(m), (m)->cno_hmap_buckets, k)
#define cno_hmap_key(x)             (x)->cno_hmap_handle->key;
/* Buckets are circular doubly linked lists, so this works fine.
   The map should still be passed as the first argument just in case. */
#define cno_hmap_remove(m, x)       cno_list_remove((x)->cno_hmap_handle)
#define cno_hmap_clear(m)           cno_hmap_iterate(m, i, struct cno_st_set_handle_t *, x, cno_list_remove(x))

/* Iterate over all values in a map, assuming they are of same type T:
 *
 *    struct cno_hmap(256) set;
 *    ...
 *    cno_hmap_iterate(&set, something_t *, value, {
 *        printf("%zu -> %s\n", cno_hmap_key(value), value->some_field_of_something_t);
 *    });
 */
#define cno_hmap_iterate(m, T, value, block) do {                                                 \
    T value;                                                                                      \
    size_t __s = cno_hmap_size(m);                                                                \
    struct cno_hmap_bucket_t *__m;                                                                \
    struct cno_hmap_handle_t *__n, *__i;                                                          \
    for (__m = &(m)->cno_hmap_buckets[0]; __s--; ++__m)                                           \
    for (__i = __m->first, __n = __i->next; __i != cno_list_end(__m); __i = __n, __n = __i->next) \
    { value = (T) __i; block; }                                                                   \
} while (0)


static inline void cno_hmap_gen_init(size_t size, struct cno_hmap_bucket_t *buckets)
{
    while (size--) cno_list_init(buckets++);
}


static inline size_t cno_hmap_gen_hash(size_t key, size_t size)
{
    key ^= (key >> 20) ^ (key >> 12);  // not sure where I got this weird hash function...
    key ^= (key >>  7) ^ (key >>  4);
    return key & (size - 1);
}


static inline void cno_hmap_gen_insert(size_t size, struct cno_hmap_bucket_t *set,
                                       size_t key,  struct cno_hmap_handle_t *ob)
{
    cno_list_append(&set[cno_hmap_gen_hash(ob->key = key, size)], ob);
}


static inline void *cno_hmap_gen_find(size_t size, struct cno_hmap_bucket_t *set, size_t key)
{
    struct cno_hmap_bucket_t *root = &set[cno_hmap_gen_hash(key, size)];
    struct cno_hmap_handle_t *it   = root->first;

    for (; it != cno_list_end(root); it = it->next)
        if (key == it->key)
            return it;
    return NULL;
}


#endif
