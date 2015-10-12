#!/usr/bin/env python3
from distutils.core import setup, Extension

setup(
    name='cno',
    version='0.1.0',
    author='pyos',
    author_email='pyos100500@gmail.com',
    packages=['cno'],
    package_dir={'cno': 'python/cno'},
    ext_modules=[
        Extension('cno.raw', [
            'cno/core.c', 'cno/hpack.c', 'cno/common.c',
            'python/cno/raw.c', 'picohttpparser/picohttpparser.c'
        ], include_dirs=['.'])
    ]
)
