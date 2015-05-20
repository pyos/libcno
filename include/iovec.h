#ifndef _CNO_IOVEC_H_
#define _CNO_IOVEC_H_
#include <stddef.h>


struct cno_st_io_vector_t {
    char  *data;
    size_t size;
};


struct cno_st_io_vector_tmp_t {
    char  *data;
    size_t size;
    size_t offset;
};


void   cno_io_vector_clear      (struct cno_st_io_vector_t     *vec);
void   cno_io_vector_reset      (struct cno_st_io_vector_tmp_t *vec);
char * cno_io_vector_slice      (struct cno_st_io_vector_tmp_t *vec, size_t size);
int    cno_io_vector_shift      (struct cno_st_io_vector_tmp_t *vec, size_t offset);
int    cno_io_vector_strip      (struct cno_st_io_vector_tmp_t *vec);
int    cno_io_vector_extend     (struct cno_st_io_vector_t     *vec, const char *data, size_t length);
int    cno_io_vector_extend_tmp (struct cno_st_io_vector_tmp_t *vec, const char *data, size_t length);


#endif
