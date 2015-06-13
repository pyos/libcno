struct cno_st_map_bucket_t { CNO_LIST_LINK(struct cno_st_map_bucket_t); size_t key; };


#define CNO_MAP(size) struct { struct cno_st_map_bucket_t __map_root_handle[size]; }
#define CNO_MAP_VALUE struct { struct cno_st_map_bucket_t __map_item_handle[1]; }


#define cno_map_size(m) sizeof((m)->__map_root_handle) / sizeof((m)->__map_root_handle[0])
#define cno_map_init(m)            __cno_map_init(   cno_map_size(m), (m)->__map_root_handle)
#define cno_map_insert(m, k, x)    __cno_map_insert( cno_map_size(m), (m)->__map_root_handle, k, (x)->__map_item_handle)
#define cno_map_find(m, k)         __cno_map_find(   cno_map_size(m), (m)->__map_root_handle, k)
#define cno_map_remove(m, x)       cno_list_remove((x)->__map_item_handle)
#define cno_map_clear(m)           cno_map_iterate(m, struct cno_st_map_bucket_t, __x, cno_list_remove(__x))


#define cno_map_iterate(m, T, var, block) do {                                        \
    T *var;                                                                           \
    size_t s = cno_map_size(m);                                                       \
    struct cno_st_map_bucket_t *__n, *__m, *__i;                                      \
    for (__m = (m)->__map_root_handle; s--; ++__m)                                    \
    for (__i = __m->next, __n = __i->next; __i != __m; __i = __n, __n = __i->next)    \
    { var = (T *) __i; block; }                                                       \
} while (0)


static inline void __cno_map_init(size_t size, struct cno_st_map_bucket_t *buckets)
{
    while (size--) cno_list_init(buckets++);
}


static inline size_t __cno_map_hash(size_t key, size_t size)
{
    return key & (size - 1);  // TODO
}


static inline void __cno_map_insert(size_t size, struct cno_st_map_bucket_t *map, size_t key, struct cno_st_map_bucket_t *ob)
{
    cno_list_insert_after(map + __cno_map_hash(ob->key = key, size), ob);
}


static void *__cno_map_find(size_t size, struct cno_st_map_bucket_t *map, size_t key)
{
    struct cno_st_map_bucket_t *root = map + __cno_map_hash(key, size);
    struct cno_st_map_bucket_t *it   = root->next;

    for (; it != root; it = it->next) {
        if (key == it->key) {
            return it;
        }
    }

    return NULL;
}
