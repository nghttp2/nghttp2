from distutils.core import setup
from distutils.extension import Extension

setup(
    name = 'python-spdylay',
    # Also update __version__ in spdylay.pyx
    version = '0.1.0',
    description = 'SPDY library',
    author = 'Tatsuhiro Tsujikawa',
    author_email = 'tatsuhiro.t@gmail.com',
    url = 'http://spdylay.sourceforge.net/',
    keywords = [],
    ext_modules = [Extension("spdylay",
                             ["spdylay.c"],
                             libraries=['spdylay'])],
    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules'
        ]
    )
