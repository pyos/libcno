#!/usr/bin/env python3
import os
import sys
import subprocess
from distutils.core import setup
from distutils.command.build_ext import build_ext as BuildExtCommand


sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python', 'cno'))
import ffi


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
    ext_modules=[ffi.create('.').distutils_extension()],
    requires=['cffi (>=1.0.1)'],
    cmdclass={'build_ext': MakeBuildExtCommand},
)
