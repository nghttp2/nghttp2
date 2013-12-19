nghttp2 Python C extension module
=================================

This directory contains nghttp2 Python C extension module.  Currently,
header compressor and decompressor are implemented in extension using
cython.

This is experimental and adds some dependencies which is a bit hard to
check, so this extension module does not built with usual ``make`` in
the top directory. Instead, a user has to run ``make build_ext`` in
this directory.

The build extension module is called ``nghttp2``.

The module refers to the libnghttp2.so. If nghttp2 is installed using
``make install``, then importing nghttp2 module should work.  If a
user does not want to install nghttp2, then use ``LD_LIBRARY_PATH``
pointing to the location of libnghttp2.so, which is usually in
``lib/.libs``. If a user also does not want to install nghttp2 module,
use PYTHONPATH to point the location of extension module. This depends
on the architecture and Python version. For example, x86_64
architecture and Python 2.7 series, a module will be located at
``build/lib.linux-x86_64-2.7``.

Header compression
------------------

The following example code illustrates basic usage of compressor and
decompressor::

    import binascii
    import nghttp2

    deflater = nghttp2.HDDeflater(nghttp2.HD_SIDE_REQUEST)
    inflater = nghttp2.HDInflater(nghttp2.HD_SIDE_REQUEST)

    data = deflater.deflate([(b'foo', b'bar'),
			     (b'baz', b'buz')])
    print(binascii.b2a_hex(data))

    hdrs = inflater.inflate(data)
    print(hdrs)
