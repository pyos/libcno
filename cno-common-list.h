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
}
