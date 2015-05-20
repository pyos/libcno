#ifndef _CNO_ERROR_H_
#define _CNO_ERROR_H_


int cno_error_set(int code, const char *text, const char *file, int line, void *arg);
int cno_error(void);
int cno_error_line(void);
const char *cno_error_file(void);
const char *cno_error_text(void);
void *cno_error_arg(void);


#define CNO_OK 0
#define CNO_PROPAGATE -1
#define CNO_SET_ERROR(code, msg, arg) cno_error_set(code, msg, __FILE__, __LINE__, (void*) arg)
#define CNO_ERRNO_GENERIC     0
#define CNO_ERROR_GENERIC(m)  CNO_SET_ERROR(CNO_ERRNO_GENERIC, m, 0)
#define CNO_ERRNO_NOMEMORY    1
#define CNO_ERROR_NOMEMORY    CNO_SET_ERROR(CNO_ERRNO_NOMEMORY, "out of memory", 0)
#define CNO_ERRNO_NOSTREAM    2
#define CNO_ERROR_NOSTREAM(a) CNO_SET_ERROR(CNO_ERRNO_NOSTREAM, "stream not found", a)
#define CNO_ERRNO_CLOSED      3
#define CNO_ERROR_CLOSED      CNO_SET_ERROR(CNO_ERRNO_CLOSED, "connection closed", 0)
#define CNO_ERRNO_BAD_REQ     4
#define CNO_ERROR_BAD_REQ     CNO_SET_ERROR(CNO_ERRNO_BAD_REQ, "bad request", 0)
#define CNO_ERRNO_INVSTATE    5
#define CNO_ERROR_INVSTATE(m) CNO_SET_ERROR(CNO_ERRNO_INVSTATE, m, 0)


#endif
