#ifndef _CNO_WRITE_H_
#define _CNO_WRITE_H_
#include "core.h"


int cno_write_message (cno_connection_t *conn, size_t stream, cno_message_t *msg);
int cno_write_data    (cno_connection_t *conn, size_t stream, const char *data, size_t length, int chunked);
int cno_write_end     (cno_connection_t *conn, size_t stream, int chunked);


#endif
