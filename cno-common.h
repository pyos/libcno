#ifndef _CNO_COMMON_H_
#define _CNO_COMMON_H_
#include <stddef.h>  // size_t
#include <string.h>  // strlen


/* Emit an event on a given object. The object must have an "event data" field (cb_data).
 * No-op if nothing handles the event.
 */
#define CNO_FIRE(ob, cb, ...) (ob->cb && ob->cb(ob, ob->cb_data, ## __VA_ARGS__))

/* Mark a structure as public by typedef-ing it. Structures should be named
 * `struct cno_st_something_t`; the typedef-ed name will be `cno_something_t`.
 */
#define CNO_STRUCT_EXPORT(name) typedef struct cno_st_ ## name ## _t cno_ ## name ## _t


/* Error signaling.
 *
 * Functions that can fail should return either an int or a pointer; obviously, a NULL
 * pointer means an error. In int-returning functions, `CNO_OK` (0) is returned
 * when all is good, and `CNO_PROPAGATE` (-1) otherwise.
 *
 * If an error has occurred, some debug information may be obtained by calling various
 * `cno_error_*` functions (see below).
 *
 */
#define CNO_ERROR_SET(code, ...) cno_error_set(code, __FILE__, __LINE__, ##__VA_ARGS__)
#define CNO_ERROR_UNKNOWN(...)         CNO_ERROR_SET(CNO_ERRNO_UNKNOWN,         ##__VA_ARGS__)
#define CNO_ERROR_ASSERTION(...)       CNO_ERROR_SET(CNO_ERRNO_ASSERTION,       ##__VA_ARGS__)
#define CNO_ERROR_NO_MEMORY            CNO_ERROR_SET(CNO_ERRNO_NO_MEMORY,       "")
#define CNO_ERROR_NOT_IMPLEMENTED(...) CNO_ERROR_SET(CNO_ERRNO_NOT_IMPLEMENTED, ##__VA_ARGS__)
#define CNO_ERROR_TRANSPORT(...)       CNO_ERROR_SET(CNO_ERRNO_TRANSPORT,       ##__VA_ARGS__)
#define CNO_ERROR_INVALID_STATE(...)   CNO_ERROR_SET(CNO_ERRNO_INVALID_STATE,   ##__VA_ARGS__)
#define CNO_ERROR_INVALID_STREAM(...)  CNO_ERROR_SET(CNO_ERRNO_INVALID_STREAM,  ##__VA_ARGS__)
#define CNO_ERROR_WOULD_BLOCK(...)     CNO_ERROR_SET(CNO_ERRNO_WOULD_BLOCK,     ##__VA_ARGS__)


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


/* String ops.
 *
 * The basic transmission unit is an "io vector", which is a string tagged with its length.
 * A "temporary io vector" can additionally move the pointer over the string to mask
 * a part of the buffer that has already been handled.
 *
 */
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
#define CNO_IO_VECTOR_ARRAY(arr)  { (char *) arr, sizeof(arr) }
#define CNO_IO_VECTOR_EMPTY       { NULL, 0 }
void   cno_io_vector_clear      (struct cno_st_io_vector_t *vec);
int    cno_io_vector_extend     (struct cno_st_io_vector_t *vec, const char *data, size_t length);

void   cno_io_vector_reset      (struct cno_st_io_vector_tmp_t *vec);
int    cno_io_vector_shift      (struct cno_st_io_vector_tmp_t *vec, size_t offset);
int    cno_io_vector_strip      (struct cno_st_io_vector_tmp_t *vec);
int    cno_io_vector_extend_tmp (struct cno_st_io_vector_tmp_t *vec, const char *data, size_t length);


/* Generic circular doubly-linked list.
 *
 * A `struct T` that contains a `CNO_LIST_LINK(struct T)` can form a doubly linked list
 * with other objects of same type. The `CNO_LIST_LINK` is not required to have a name;
 * if it does not, `struct T` is extended with members `next` and `prev`.
 *
 * Optionally, another `struct R` may start with `CNO_LIST_ROOT(struct T)`.
 * The `struct R` is then also a part of the cycle; it's basically the beginning,
 * and also the end, of the list. If `struct R` is the root, `first` and `last`
 * point into the list proper; compare them to `cno_list_end(root)` to determine
 * whether they point to valid `struct T`s or you have gone full circle to the root.
 *
 * NOTE: `first`/`last`/`next`/`prev` point to `CNO_LIST_LINK`/`CNO_LIST_ROOT` of
 *       another element, not to the beginning. Either put `CNO_LIST_LINK` as
 *       the first member of the struct, or do some pointer arithmetic manually.
 *
 */
struct cno_st_list_link_t { struct cno_st_list_link_t *prev, *next; };


#define CNO_LIST_LINK(T) union { struct { T *prev, *next;  }; struct cno_st_list_link_t __list_handle[1]; }
#define CNO_LIST_ROOT(T) union { struct { T *last, *first; }; struct cno_st_list_link_t __list_handle[1]; }


#define cno_list_end(x)  (void *) (x)->__list_handle
#define cno_list_init(x)            __cno_list_init((x)->__list_handle)
#define cno_list_insert_after(x, y) __cno_list_insert_after((x)->__list_handle, (y)->__list_handle)
#define cno_list_remove(x)          __cno_list_remove((x)->__list_handle)


static inline void __cno_list_init(struct cno_st_list_link_t *node)
{
    node->next = node;
    node->prev = node;
}


static inline void __cno_list_insert_after(struct cno_st_list_link_t *node, struct cno_st_list_link_t *next)
{
    next->next = node->next;
    next->prev = node;
    node->next = next->next->prev = next;
}


static inline void __cno_list_remove(struct cno_st_list_link_t *node)
{
    node->next->prev = node->prev;
    node->prev->next = node->next;
    __cno_list_init(node);
}


/* A generic hash map-based set.
 *
 * A set is simply something of a type `CNO_SET(s)` where `s` is the number of buckets.
 * Yes, it's constant. If you want to change it, reallocate and repopulate the whole map.
 * It's not like there's a better way to do that anyway.
 *
 * A `struct T` can only be used as a value in a set if it has an unnamed `CNO_SET_VALUE`
 * as the first member:
 *
 *     struct something {
 *         CNO_SET_VALUE;
 *     }
 *
 * Note that even though this is a set, meaning all values can only appear once,
 * the insertion function requires a size_t key; that key should be some sort of a hash
 * computed from the object. Meaning, one object should have its key constant.
 * Don't insert a single copy of an object with different keys. Don't insert a single
 * object into many different sets, either, as metadata is stored on the object itself.
 *
 */
struct cno_st_set_handle_t { CNO_LIST_LINK(struct cno_st_set_handle_t); size_t key; };
struct cno_st_set_bucket_t { CNO_LIST_ROOT(struct cno_st_set_handle_t); };


#define CNO_SET(size) struct { struct cno_st_set_bucket_t __set_bucket[size]; }
#define CNO_SET_VALUE struct { struct cno_st_set_handle_t __set_handle[1]; }


/* Yay, pointer magic! */
#define cno_set_size(m) sizeof((m)->__set_bucket) / sizeof((m)->__set_bucket[0])
#define cno_set_init(m)            __cno_set_init(  cno_set_size(m), (m)->__set_bucket)
#define cno_set_insert(m, k, x)    __cno_set_insert(cno_set_size(m), (m)->__set_bucket, k, (x)->__set_handle)
#define cno_set_find(m, k)         __cno_set_find(  cno_set_size(m), (m)->__set_bucket, k)
#define cno_set_key(x)             (x)->__set_handle->key;
/* Buckets are circular doubly linked lists, so this works fine.
   The set should still be passed as the first argument just in case. */
#define cno_set_remove(m, x)       cno_list_remove((x)->__set_handle)
#define cno_set_clear(m)           cno_set_iterate(m, i, struct cno_st_set_handle_t *, x, cno_list_remove(x))

/* Iterate over all values in a set, assuming they are of same type T:
 *
 *    CNO_SET(256) set;
 *    ...
 *    cno_set_iterate(&set, something_t *, value, {
 *        printf("%lu -> %s\n", cno_set_key(value), value->some_field_of_something_t);
 *    });
 */
#define cno_set_iterate(m, T, value, block) do {                                                  \
    T value;                                                                                      \
    size_t __s = cno_set_size(m);                                                                 \
    struct cno_st_set_bucket_t *__m;                                                              \
    struct cno_st_set_handle_t *__n, *__i;                                                        \
    for (__m = (m)->__set_bucket; __s--; ++__m)                                                   \
    for (__i = __m->first, __n = __i->next; __i != cno_list_end(__m); __i = __n, __n = __i->next) \
    { value = (T) __i; block; }                                                                   \
} while (0)


static inline void __cno_set_init(size_t size, struct cno_st_set_bucket_t *buckets)
{
    while (size--) cno_list_init(buckets++);
}


static inline size_t __cno_set_hash(size_t key, size_t size)
{
    key ^= (key >> 20) ^ (key >> 12);
    key ^= (key >>  7) ^ (key >>  4);
    return key & (size - 1);
}


static inline void __cno_set_insert(size_t size, struct cno_st_set_bucket_t *set,
                                    size_t key,  struct cno_st_set_handle_t *ob)
{
    cno_list_insert_after(set + __cno_set_hash(ob->key = key, size), ob);
}


static inline void *__cno_set_find(size_t size, struct cno_st_set_bucket_t *set, size_t key)
{
    struct cno_st_set_bucket_t *root = set + __cno_set_hash(key, size);
    struct cno_st_set_handle_t *it   = root->first;

    for (; it != cno_list_end(root); it = it->next) if (key == it->key) {
        return it;
    }

    return NULL;
}


#endif
