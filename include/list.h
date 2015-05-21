#ifndef _CNO_LIST_H_
#define _CNO_LIST_H_


#define CNO_LIST_LINK(T) T *prev;  T *next
#define CNO_LIST_ROOT(T) T *first; T *last


struct cno_st_list_link_t {
    CNO_LIST_LINK(struct cno_st_list_link_t);
};


static inline void cno_list_insert_after(void *node, void *next)
{
    struct cno_st_list_link_t *node_ = (struct cno_st_list_link_t *) node;
    struct cno_st_list_link_t *next_ = (struct cno_st_list_link_t *) next;

    next_->next = node_->next;
    next_->prev = node_;
    node_->next = next_->next->prev = next_;
}


static inline void cno_list_remove(void *node)
{
    struct cno_st_list_link_t *node_ = (struct cno_st_list_link_t *) node;
    node_->next->prev = node_->prev;
    node_->prev->next = node_->next;
}


#endif
