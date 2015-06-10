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


void cno_hpack_init     (cno_hpack_t *state, size_t limit);
void cno_hpack_clear    (cno_hpack_t *state);
void cno_hpack_setlimit (cno_hpack_t *state, size_t limit);
int  cno_hpack_decode   (cno_hpack_t *state, cno_io_vector_t *source, cno_header_t *array, size_t *limit);
int  cno_hpack_encode   (cno_hpack_t *state, cno_io_vector_t *target, cno_header_t *array, size_t amount);

static const struct cno_st_header_t CNO_HPACK_STATIC_TABLE [] = {
    { CNO_IO_VECTOR_CONST(":authority"),                   CNO_IO_VECTOR_CONST("")            },
    { CNO_IO_VECTOR_CONST(":method"),                      CNO_IO_VECTOR_CONST("GET")         },
    { CNO_IO_VECTOR_CONST(":method"),                      CNO_IO_VECTOR_CONST("POST")        },
    { CNO_IO_VECTOR_CONST(":path"),                        CNO_IO_VECTOR_CONST("/")           },
    { CNO_IO_VECTOR_CONST(":path"),                        CNO_IO_VECTOR_CONST("/index.html") },
    { CNO_IO_VECTOR_CONST(":scheme"),                      CNO_IO_VECTOR_CONST("http")        },
    { CNO_IO_VECTOR_CONST(":scheme"),                      CNO_IO_VECTOR_CONST("https")       },
    { CNO_IO_VECTOR_CONST(":status"),                      CNO_IO_VECTOR_CONST("200")         },
    { CNO_IO_VECTOR_CONST(":status"),                      CNO_IO_VECTOR_CONST("204")         },
    { CNO_IO_VECTOR_CONST(":status"),                      CNO_IO_VECTOR_CONST("206")         },
    { CNO_IO_VECTOR_CONST(":status"),                      CNO_IO_VECTOR_CONST("304")         },
    { CNO_IO_VECTOR_CONST(":status"),                      CNO_IO_VECTOR_CONST("400")         },
    { CNO_IO_VECTOR_CONST(":status"),                      CNO_IO_VECTOR_CONST("404")         },
    { CNO_IO_VECTOR_CONST(":status"),                      CNO_IO_VECTOR_CONST("500")         },
    { CNO_IO_VECTOR_CONST("accept-charset"),               CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("accept-encoding"),              CNO_IO_VECTOR_CONST("gzip, deflate") },
    { CNO_IO_VECTOR_CONST("accept-language"),              CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("accept-ranges"),                CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("accept"),                       CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("access-control-allow-origin"),  CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("age"),                          CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("allow"),                        CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("authorization"),                CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("cache-control"),                CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("content-disposition"),          CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("content-encoding"),             CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("content-language"),             CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("content-length"),               CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("content-location"),             CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("content-range"),                CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("content-type"),                 CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("cookie"),                       CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("date"),                         CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("etag"),                         CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("expect"),                       CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("expires"),                      CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("from"),                         CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("host"),                         CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("if-match"),                     CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("if-modified-since"),            CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("if-none-match"),                CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("if-range"),                     CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("if-unmodified-since"),          CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("last-modified"),                CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("link"),                         CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("location"),                     CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("max-forwards"),                 CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("proxy-authenticate"),           CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("proxy-authorization"),          CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("range"),                        CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("referer"),                      CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("refresh"),                      CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("retry-after"),                  CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("server"),                       CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("set-cookie"),                   CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("strict-transport-security"),    CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("transfer-encoding"),            CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("user-agent"),                   CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("vary"),                         CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("via"),                          CNO_IO_VECTOR_CONST("") },
    { CNO_IO_VECTOR_CONST("www-authenticate"),             CNO_IO_VECTOR_CONST("") },
};


static const size_t CNO_HPACK_STATIC_TABLE_SIZE = sizeof(CNO_HPACK_STATIC_TABLE) / sizeof(struct cno_st_header_t);

#endif
