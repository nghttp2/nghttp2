from distutils.core import setup
from distutils.extension import Extension

setup(
    name = 'python-spdylay',
    # Also update __version__ in spdylay.pyx
    version = '0.1.0',
    description = 'Python SPDY library on top of Spdylay C library',
    author = 'Tatsuhiro Tsujikawa',
    author_email = 'tatsuhiro.t@gmail.com',
    url = 'http://spdylay.sourceforge.net/',
    keywords = [],
    ext_modules = [Extension("spdylay",
                             ["spdylay.c"],
                             libraries=['spdylay'])],
    long_description="""\
Python-spdylay is a Python SPDY library on top of Spdylay C
library. It supports SPDY/2 and SPDY/3 protocol.

It does not perform any I/O operations. When the library needs them,
it calls the callback functions provided by the application. It also
does not include any event polling mechanism, so the application can
freely choose the way of handling events.

It provides almost all API Spdylay provides with Pythonic fashion.

The core library API works with Python 2 and 3.  But
``ThreadedSPDYServer`` requires Python 3.3 because it uses TLS NPN
extension.

Installation
============

First install Spdylay library. You can grab a source distribution from
`sf.net download page
<http://sourceforge.net/projects/spdylay/files/stable/>`_
or `clone git repository <https://github.com/tatsuhiro-t/spdylay>`_.

See `Spdylay documentation
<http://spdylay.sourceforge.net/package_README.html>`_ for the
required packages and how to build Spdylay from git repository.

After Spdylay is installed, run ``build_ext`` command to build
extension module::

    $ python setup.py build_ext

If you installed Spdylay library in other than standard location, use
``--include-dirs`` and ``--library-dirs`` to specify header file and
library locations respectively.

Documentation
=============

See `python-spdylay documentation
<http://spdylay.sourceforge.net/python.html>`_.

Samples
=======

Here is a simple SPDY server::

    #!/usr/bin/env python

    # The example SPDY server. Python 3.3 or later is required because TLS
    # NPN is used in spdylay.ThreadedSPDYServer. Put private key and
    # certificate file in the current working directory.

    import spdylay

    # private key file
    KEY_FILE='server.key'
    # certificate file
    CERT_FILE='server.crt'

    class MySPDYRequestHandler(spdylay.BaseSPDYRequestHandler):

        def do_GET(self):
            self.send_response(200)
            self.send_header('content-type', 'text/html; charset=UTF-8')

            content = '''\
    <html>
    <head><title>SPDY FTW</title></head>
    <body>
    <h1>SPDY FTW</h1>
    <p>The age of HTTP/1.1 is over. The time of SPDY has come.</p>
    </body>
    </html>'''.encode('UTF-8')

            self.wfile.write(content)

    if __name__ == "__main__":
        HOST, PORT = "localhost", 3000

        server = spdylay.ThreadedSPDYServer((HOST, PORT),
                                            MySPDYRequestHandler,
                                            cert_file=CERT_FILE,
                                            key_file=KEY_FILE)
        server.start()
""",
    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Cython',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules'
        ]
    )
