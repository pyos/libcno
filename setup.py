#!/usr/bin/env python3
import subprocess
from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext as BuildExtCommand


class MakeBuildExtCommand (BuildExtCommand):
    def run(self):
        print('make python-pre-build-ext')
        subprocess.check_call(['make', 'python-pre-build-ext'])
        super().run()


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
    ],
    cmdclass={'build_ext': MakeBuildExtCommand},
)
