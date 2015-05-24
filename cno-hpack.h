#ifndef _CNO_HPACK_H_
#define _CNO_HPACK_H_

#include "cno-common.h"


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


void cno_hpack_clear    (cno_hpack_t *state);
void cno_hpack_setlimit (cno_hpack_t *state, size_t limit, int immediate);
int  cno_hpack_decode   (cno_hpack_t *state, cno_io_vector_t *source, cno_header_t *array, size_t *limit);
int  cno_hpack_encode   (cno_hpack_t *state, cno_io_vector_t *target, cno_header_t *array, size_t amount);

static const struct cno_st_header_t CNO_HPACK_STATIC_TABLE [] = {
    { { ":authority",                  10 }, { 0 } },
    { { ":method",                      7 }, { "GET",            3 } },
    { { ":method",                      7 }, { "POST",           4 } },
    { { ":path",                        5 }, { "/",              1 } },
    { { ":path",                        5 }, { "/index.html",   11 } },
    { { ":scheme",                      7 }, { "http",           4 } },
    { { ":scheme",                      7 }, { "https",          5 } },
    { { ":status",                      7 }, { "200",            3 } },
    { { ":status",                      7 }, { "204",            3 } },
    { { ":status",                      7 }, { "206",            3 } },
    { { ":status",                      7 }, { "304",            3 } },
    { { ":status",                      7 }, { "400",            3 } },
    { { ":status",                      7 }, { "404",            3 } },
    { { ":status",                      7 }, { "500",            3 } },
    { { "accept-charset",              14 }, { 0 } },
    { { "accept-encoding",             15 }, { "gzip, deflate", 13 } },
    { { "accept-language",             15 }, { 0 } },
    { { "accept-ranges",               13 }, { 0 } },
    { { "accept",                       6 }, { 0 } },
    { { "access-control-allow-origin", 27 }, { 0 } },
    { { "age",                          3 }, { 0 } },
    { { "allow",                        5 }, { 0 } },
    { { "authorization",               13 }, { 0 } },
    { { "cache-control",               13 }, { 0 } },
    { { "content-disposition",         19 }, { 0 } },
    { { "content-encoding",            16 }, { 0 } },
    { { "content-language",            16 }, { 0 } },
    { { "content-length",              14 }, { 0 } },
    { { "content-location",            16 }, { 0 } },
    { { "content-range",               13 }, { 0 } },
    { { "content-type",                12 }, { 0 } },
    { { "cookie",                       6 }, { 0 } },
    { { "date",                         4 }, { 0 } },
    { { "etag",                         4 }, { 0 } },
    { { "expect",                       6 }, { 0 } },
    { { "expires",                      7 }, { 0 } },
    { { "from",                         4 }, { 0 } },
    { { "host",                         4 }, { 0 } },
    { { "if-match",                     8 }, { 0 } },
    { { "if-modified-since",           17 }, { 0 } },
    { { "if-none-match",               13 }, { 0 } },
    { { "if-range",                     8 }, { 0 } },
    { { "if-unmodified-since",         19 }, { 0 } },
    { { "last-modified",               13 }, { 0 } },
    { { "link",                         4 }, { 0 } },
    { { "location",                     8 }, { 0 } },
    { { "max-forwards",                12 }, { 0 } },
    { { "proxy-authenticate",          18 }, { 0 } },
    { { "proxy-authorization",         19 }, { 0 } },
    { { "range",                        5 }, { 0 } },
    { { "referer",                      7 }, { 0 } },
    { { "refresh",                      7 }, { 0 } },
    { { "retry-after",                 11 }, { 0 } },
    { { "server",                       6 }, { 0 } },
    { { "set-cookie",                  10 }, { 0 } },
    { { "strict-transport-security",   25 }, { 0 } },
    { { "transfer-encoding",           17 }, { 0 } },
    { { "user-agent",                  10 }, { 0 } },
    { { "vary",                         4 }, { 0 } },
    { { "via",                          3 }, { 0 } },
    { { "www-authenticate",            16 }, { 0 } },
};


static const size_t CNO_HPACK_STATIC_TABLE_SIZE = sizeof(CNO_HPACK_STATIC_TABLE) / sizeof(struct cno_st_header_t);

#endif
