#ifndef _CNO_ERROR_H_
#define _CNO_ERROR_H_
#define CNO_ERROR_SET(code, msg, arg) cno_error_set(code, msg, __FILE__, __LINE__, (void*) arg)
#define CNO_ERROR_UNKNOWN(m)         CNO_ERROR_SET(CNO_ERRNO_UNKNOWN,         m, 0)
#define CNO_ERROR_ASSERTION(m, a)    CNO_ERROR_SET(CNO_ERRNO_ASSERTION,       m, a)
#define CNO_ERROR_NO_MEMORY          CNO_ERROR_SET(CNO_ERRNO_NO_MEMORY,       "out of memory", 0)
#define CNO_ERROR_NOT_IMPLEMENTED(m) CNO_ERROR_SET(CNO_ERRNO_NOT_IMPLEMENTED, m, 0)
#define CNO_ERROR_TRANSPORT(m)       CNO_ERROR_SET(CNO_ERRNO_TRANSPORT,       m, 0)
#define CNO_ERROR_INVALID_STATE(m)   CNO_ERROR_SET(CNO_ERRNO_INVALID_STATE,   m, 0)
#define CNO_ERROR_INVALID_STREAM(a)  CNO_ERROR_SET(CNO_ERRNO_INVALID_STREAM,  "stream not found", a)


enum CNO_ERRNO {
    CNO_ERRNO_UNKNOWN,
    CNO_ERRNO_ASSERTION,
    CNO_ERRNO_NO_MEMORY,
    CNO_ERRNO_NOT_IMPLEMENTED,
    CNO_ERRNO_TRANSPORT,        // Transport-level syntax error. Stream-level errors simply close the stream.
    CNO_ERRNO_INVALID_STATE,    // Connection cannot do that while in the current state.
    CNO_ERRNO_INVALID_STREAM,   // Stream with given ID was not found.
};


#define CNO_OK         0
#define CNO_PROPAGATE -1


int          cno_error_set  (int code, const char *text, const char *file, int line, void *arg);
int          cno_error      (void);
int          cno_error_line (void);
const char * cno_error_file (void);
const char * cno_error_text (void);
void *       cno_error_arg  (void);


#endif
