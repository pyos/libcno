import cffi
import subprocess


CALLBACKS = {
    'on_write':         'void *, const char *, size_t',
    'on_stream_start':  'void *, uint32_t',
    'on_stream_end':    'void *, uint32_t',
    'on_flow_increase': 'void *, uint32_t',
    'on_message_start': 'void *, uint32_t, const struct cno_message_t *',
    'on_message_trail': 'void *, uint32_t, const struct cno_message_t *',
    'on_message_push':  'void *, uint32_t, const struct cno_message_t *, uint32_t',
    'on_message_data':  'void *, uint32_t, const char *, size_t',
    'on_message_end':   'void *, uint32_t',
    'on_frame':         'void *, const struct cno_frame_t *',
    'on_frame_send':    'void *, const struct cno_frame_t *',
    'on_pong':          'void *, const char[8]',
}


def cpp(root, text):
    out = subprocess.check_output(['cpp', '-I' + root], input=text.encode('utf-8'))
    return b'\n'.join(x for x in out.split(b'\n') if not x.startswith(b'#')).decode('utf-8')


def create(root):
    ffi = cffi.FFI()
    ffi.set_source('cno._ffi', '#include <cno/core.h>', libraries=['cno'],
        include_dirs=[root],
        library_dirs=[root + '/obj']
    )
    ffi.cdef(cpp(root,
        '''
            #define CFFI_CDEF_MODE 1
            #define __attribute__(...)
            #include <cno/core.h>
        ''' + '\n'.join('extern "Python" int %s(%s);' % cb for cb in CALLBACKS.items())
    ))
    return ffi
