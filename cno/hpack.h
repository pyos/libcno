#ifndef _CNO_HPACK_H_
#define _CNO_HPACK_H_

#include <cno/common.h>


struct cno_st_header_t {
    struct cno_st_io_vector_t name;
    struct cno_st_io_vector_t value;
};


struct cno_st_header_table_t {
    CNO_LIST_LINK(struct cno_st_header_table_t);
    struct cno_st_header_t data;
};


struct cno_st_hpack_t {
    CNO_LIST_ROOT(struct cno_st_header_table_t);
    size_t size;
    size_t limit;
    size_t limit_upper;
    size_t limit_update_min;
    size_t limit_update_end;
};


CNO_STRUCT_EXPORT(header_table);
CNO_STRUCT_EXPORT(header);
CNO_STRUCT_EXPORT(hpack);


void cno_hpack_init     (cno_hpack_t *state, size_t limit);
void cno_hpack_clear    (cno_hpack_t *state);
void cno_hpack_setlimit (cno_hpack_t *state, size_t limit);
int  cno_hpack_decode   (cno_hpack_t *state, cno_io_vector_t *source, cno_header_t *array, size_t *limit);
int  cno_hpack_encode   (cno_hpack_t *state, cno_io_vector_t *target, cno_header_t *array, size_t amount);


#endif
