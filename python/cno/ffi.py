import cffi
import subprocess


def create(root):
    ffi = cffi.FFI()
    ffi.set_source('cno._ffi', '#include <cno/core.h>', libraries=['cno'],
        include_dirs=[root],
        library_dirs=[root + '/obj']
    )
    ffi.cdef(
        subprocess.check_output(['cpp', '-I' + root, '-std=c11', '-P'], input=b'''
            #define CFFI_CDEF_MODE 1
            #define __attribute__(...)
            #include <cno/core.h>

            extern "Python" {
                int on_write         (void *, const char *, size_t);
                int on_stream_start  (void *, uint32_t);
                int on_stream_end    (void *, uint32_t);
                int on_flow_increase (void *, uint32_t);
                int on_message_start (void *, uint32_t, const struct cno_message_t *);
                int on_message_trail (void *, uint32_t, const struct cno_message_t *);
                int on_message_push  (void *, uint32_t, const struct cno_message_t *, uint32_t);
                int on_message_data  (void *, uint32_t, const char *, size_t);
                int on_message_end   (void *, uint32_t);
                int on_frame         (void *, const struct cno_frame_t *);
                int on_frame_send    (void *, const struct cno_frame_t *);
                int on_pong          (void *, const char[8]);
            }
        ''').decode('utf-8')
    )
    return ffi
