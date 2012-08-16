from distutils.core import setup
from distutils.extension import Extension

spdylay_dir = '../'

setup(
    ext_modules = [Extension("spdylay",
                             ["spdylay.c"],
                             include_dirs=[spdylay_dir + 'lib/includes'],
                             library_dirs=[spdylay_dir + 'lib/.libs'],
                             libraries=['spdylay'])]
    )
