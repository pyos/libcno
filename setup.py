#!/usr/bin/env python3
import os
import sys
import cffi
import subprocess

from distutils.core import setup
from distutils.command.build_ext import build_ext as BuildExtCommand


def make_ffi(root):
    ffi = cffi.FFI()
    ffi.set_source('cno.ffi', '#include <cno/core.h>', libraries=['cno'],
        include_dirs=[root],
        library_dirs=[root + '/obj']
    )
    ffi.cdef(
        subprocess.check_output(['gcc', '-I' + root, '-std=c11', '-E', '-'], input=b'''
            #define CFFI_CDEF_MODE 1
            #define __attribute__(...)
            #include <cno/core.h>

            extern "Python" {
                int on_writev        (void *, const struct cno_buffer_t *, size_t);
                int on_close         (void *);
                int on_stream_start  (void *, uint32_t);
                int on_stream_end    (void *, uint32_t);
                int on_flow_increase (void *, uint32_t);
                int on_message_head  (void *, uint32_t, const struct cno_message_t *);
                int on_message_tail  (void *, uint32_t, const struct cno_message_t *);
                int on_message_push  (void *, uint32_t, const struct cno_message_t *, uint32_t);
                int on_message_data  (void *, uint32_t, const char *, size_t);
                int on_frame         (void *, const struct cno_frame_t *);
                int on_frame_send    (void *, const struct cno_frame_t *);
                int on_pong          (void *, const char[8]);
                int on_settings      (void *);
                int on_upgrade       (void *, uint32_t);
            }
        ''').decode('utf-8')
    )
    return ffi


class MakeBuildExtCommand (BuildExtCommand):
    def run(self):
        subprocess.check_call(['make'])
        super().run()


setup(
    name='cno',
    version='0.1.1',
    author='pyos',
    author_email='pyos100500@gmail.com',
    packages=['cno'],
    package_dir={'cno': 'python/cno'},
    ext_modules=[make_ffi('.').distutils_extension()],
    requires=['cffi (>=1.0.1)'],
    cmdclass={'build_ext': MakeBuildExtCommand},
)
