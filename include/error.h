#ifndef _CNO_ERROR_H_
#define _CNO_ERROR_H_
#define CNO_ERROR_SET(code, msg, ...) cno_error_set(code, __FILE__, __LINE__, msg, ##__VA_ARGS__)
#define CNO_ERROR_UNKNOWN(m, ...)         CNO_ERROR_SET(CNO_ERRNO_UNKNOWN,         m,  ##__VA_ARGS__)
#define CNO_ERROR_ASSERTION(m, ...)       CNO_ERROR_SET(CNO_ERRNO_ASSERTION,       m,  ##__VA_ARGS__)
#define CNO_ERROR_NO_MEMORY               CNO_ERROR_SET(CNO_ERRNO_NO_MEMORY,       "")
#define CNO_ERROR_NOT_IMPLEMENTED(m, ...) CNO_ERROR_SET(CNO_ERRNO_NOT_IMPLEMENTED, m,  ##__VA_ARGS__)
#define CNO_ERROR_TRANSPORT(m, ...)       CNO_ERROR_SET(CNO_ERRNO_TRANSPORT,       m,  ##__VA_ARGS__)
#define CNO_ERROR_INVALID_STATE(m, ...)   CNO_ERROR_SET(CNO_ERRNO_INVALID_STATE,   m,  ##__VA_ARGS__)
#define CNO_ERROR_INVALID_STREAM(id)      CNO_ERROR_SET(CNO_ERRNO_INVALID_STREAM,  "%d", id)
#define CNO_ERROR_WOULD_BLOCK(m, ...)     CNO_ERROR_SET(CNO_ERRNO_WOULD_BLOCK,     m,  ##__VA_ARGS__)


enum CNO_ERRNO {
    CNO_ERRNO_UNKNOWN,
    CNO_ERRNO_ASSERTION,
    CNO_ERRNO_NO_MEMORY,
    CNO_ERRNO_NOT_IMPLEMENTED,
    CNO_ERRNO_TRANSPORT,        // Transport-level syntax error. Stream-level errors simply close the stream.
    CNO_ERRNO_INVALID_STATE,    // Connection cannot do that while in the current state.
    CNO_ERRNO_INVALID_STREAM,   // Stream with given ID was not found.
    CNO_ERRNO_WOULD_BLOCK,      // Frame too big to send with current flow control window
};


#define CNO_OK         0
#define CNO_PROPAGATE -1


int          cno_error_set  (int code, const char *file, int line, const char *fmt, ...);
int          cno_error      (void);
int          cno_error_line (void);
const char * cno_error_file (void);
const char * cno_error_text (void);


static inline const char * cno_error_name(void)
{
    switch (cno_error()) {
        case CNO_ERRNO_UNKNOWN:         return "generic error";
        case CNO_ERRNO_ASSERTION:       return "assertion failed";
        case CNO_ERRNO_NO_MEMORY:       return "out of memory";
        case CNO_ERRNO_NOT_IMPLEMENTED: return "not implemented";
        case CNO_ERRNO_TRANSPORT:       return "transport error";
        case CNO_ERRNO_INVALID_STATE:   return "invalid state";
        case CNO_ERRNO_INVALID_STREAM:  return "stream does not exist";
        default: return "unknown error";
    }
}


#endif
