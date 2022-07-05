Python API Reference
====================

.. warning::

    Python bindings have been deprecated due to maintenance issue.  It
    will not get any updates.  It will be removed at the end of 2022.

.. py:module:: nghttp2

nghttp2 offers some high level Python API to C library.  The bindings
currently provide HPACK compressor and decompressor classes and HTTP/2
server class.

The extension module is called ``nghttp2``.

``make`` will build the bindings.  The target Python version is
determined by configure script.  If the detected Python version is not
what you expect, specify a path to Python executable in ``PYTHON``
variable as an argument to configure script (e.g., ``./configure
PYTHON=/usr/bin/python3.8``).

HPACK API
---------

.. py:class:: HDDeflater(hd_table_bufsize_max=DEFLATE_MAX_HEADER_TABLE_SIZE)

   This class is used to perform header compression.  The
   *hd_table_bufsize_max* limits the usage of header table in the
   given amount of bytes.  The default value is
   :py:data:`DEFLATE_MAX_HEADER_TABLE_SIZE`.  This is necessary
   because the deflater and inflater share the same amount of header
   table and the inflater decides that number.  The deflater may not
   want to use all header table size because of limited memory
   availability.  In that case, *hd_table_bufsize_max* can be used to
   cap the upper limit of table size whatever the header table size is
   chosen by the inflater.

   .. py:method:: deflate(headers)

      Deflates the *headers*. The *headers* must be sequence of tuple
      of name/value pair, which are byte strings (not unicode string).

      This method returns the deflated header block in byte string.
      Raises the exception if any error occurs.

   .. py:method:: set_no_refset(no_refset)

      Tells the deflater not to use reference set if *no_refset* is
      evaluated to ``True``.  If that happens, on each subsequent
      invocation of :py:meth:`deflate()`, deflater will clear up
      refersent set.

   .. py:method:: change_table_size(hd_table_bufsize_max)

      Changes header table size to *hd_table_bufsize_max* byte.  if
      *hd_table_bufsize_max* is strictly larger than
      ``hd_table_bufsize_max`` given in constructor,
      ``hd_table_bufsize_max`` is used as header table size instead.

      Raises the exception if any error occurs.

   .. py:method:: get_hd_table()

      Returns copy of current dynamic header table.

The following example shows how to deflate header name/value pairs:

.. code-block:: python

   import binascii, nghttp2

   deflater = nghttp2.HDDeflater()

   res = deflater.deflate([(b'foo', b'bar'),
                           (b'baz', b'buz')])

   print(binascii.b2a_hex(res))


.. py:class:: HDInflater()

   This class is used to perform header decompression.

   .. py:method:: inflate(data)

      Inflates the deflated header block *data*. The *data* must be
      byte string.

      Raises the exception if any error occurs.

   .. py:method:: change_table_size(hd_table_bufsize_max)

      Changes header table size to *hd_table_bufsize_max* byte.

      Raises the exception if any error occurs.

   .. py:method:: get_hd_table()

      Returns copy of current dynamic header table.

The following example shows how to inflate deflated header block:

.. code-block:: python

   deflater = nghttp2.HDDeflater()

   data = deflater.deflate([(b'foo', b'bar'),
                            (b'baz', b'buz')])

   inflater = nghttp2.HDInflater()

   hdrs = inflater.inflate(data)

   print(hdrs)


.. py:function:: print_hd_table(hdtable)

   Convenient function to print *hdtable* to the standard output.  The
   *hdtable* is the one retrieved by
   :py:meth:`HDDeflater.get_hd_table()` or
   :py:meth:`HDInflater.get_hd_table()`.  This function does not work
   if header name/value cannot be decoded using UTF-8 encoding.

   In output, ``s=N`` means the entry occupies ``N`` bytes in header
   table.  If ``r=y``, then the entry is in the reference set.

.. py:data:: DEFAULT_HEADER_TABLE_SIZE

   The default header table size, which is 4096 as per HTTP/2
   specification.

.. py:data:: DEFLATE_MAX_HEADER_TABLE_SIZE

   The default header table size for deflater.  The initial value
   is 4096.

HTTP/2 servers
--------------

.. note::

   We use :py:mod:`asyncio` for HTTP/2 server classes, and ALPN.
   Therefore, Python 3.8 or later is required to use these objects.
   To explicitly configure nghttp2 build to use Python 3.8, specify
   the ``PYTHON`` variable to the path to Python 3.8 executable when
   invoking configure script like this:

   .. code-block:: text

       $ ./configure PYTHON=/usr/bin/python3.8

.. py:class:: HTTP2Server(address, RequestHandlerClass, ssl=None)

   This class builds on top of the :py:mod:`asyncio` event loop.  On
   construction, *RequestHandlerClass* must be given, which must be a
   subclass of :py:class:`BaseRequestHandler` class.

   The *address* must be a tuple of hostname/IP address and port to
   bind.  If hostname/IP address is ``None``, all interfaces are
   assumed.

   To enable SSL/TLS, specify instance of :py:class:`ssl.SSLContext`
   in *ssl*.  Before passing *ssl* to
   :py:func:`BaseEventLoop.create_server`, ALPN protocol identifiers
   are set using :py:meth:`ssl.SSLContext.set_npn_protocols`.

   To disable SSL/TLS, omit *ssl* or specify ``None``.

   .. py:method:: serve_forever()

      Runs server and processes incoming requests forever.

.. py:class:: BaseRequestHandler(http2, stream_id)

   The class is used to handle the single HTTP/2 stream.  By default,
   it does not nothing.  It must be subclassed to handle each event
   callback method.

   The first callback method invoked is :py:meth:`on_headers()`. It is
   called when HEADERS frame, which includes request header fields, is
   arrived.

   If request has request body, :py:meth:`on_data()` is invoked for
   each chunk of received data chunk.

   When whole request is received, :py:meth:`on_request_done()` is
   invoked.

   When stream is closed, :py:meth:`on_close()` is called.

   The application can send response using :py:meth:`send_response()`
   method.  It can be used in :py:meth:`on_headers()`,
   :py:meth:`on_data()` or :py:meth:`on_request_done()`.

   The application can push resource using :py:meth:`push()` method.
   It must be used before :py:meth:`send_response()` call.

   A :py:class:`BaseRequestHandler` has the following instance
   variables:

   .. py:attribute:: client_address

      Contains a tuple of the form ``(host, port)`` referring to the
      client's address.

   .. py:attribute:: stream_id

      Stream ID of this stream

   .. py:attribute:: scheme

      Scheme of the request URI.  This is a value of ``:scheme``
      header field.

   .. py:attribute:: method

      Method of this stream.  This is a value of ``:method`` header
      field.

   .. py:attribute:: host

      This is a value of ``:authority`` or ``host`` header field.

   .. py:attribute:: path

      This is a value of ``:path`` header field.

   .. py:attribute:: headers

      Request header fields.

   A :py:class:`BaseRequestHandler` has the following methods:

   .. py:method:: on_headers()

      Called when request HEADERS is arrived.  By default, this method
      does nothing.

   .. py:method:: on_data(data)

      Called when a chunk of request body *data* is arrived.  This
      method will be called multiple times until all data are
      received.  By default, this method does nothing.

   .. py:method:: on_request_done()

      Called when whole request was received.  By default, this method
      does nothing.

   .. py:method:: on_close(error_code)

      Called when stream is about to close.  The *error_code*
      indicates the reason of closure.  If it is ``0``, the stream is
      going to close without error.

   .. py:method:: send_response(status=200, headers=None, body=None)

      Send response.  The *status* is HTTP status code.  The *headers*
      is additional response headers.  The *:status* header field will
      be appended by the library.  The *body* is the response body.
      It could be ``None`` if response body is empty.  Or it must be
      instance of either ``str``, ``bytes``, :py:class:`io.IOBase` or
      callable, called body generator, which takes one parameter,
      size.  The body generator generates response body.  It can pause
      generation of response so that it can wait for slow backend data
      generation.  When invoked, it should return tuple, byte string
      at most size length and flag.  The flag is either
      :py:data:`DATA_OK`, :py:data:`DATA_EOF` or
      :py:data:`DATA_DEFERRED`.  For non-empty byte string and it is
      not the last chunk of response, :py:data:`DATA_OK` must be
      returned as flag.  If this is the last chunk of the response
      (byte string could be ``None``), :py:data:`DATA_EOF` must be
      returned as flag.  If there is no data available right now, but
      additional data are anticipated, return tuple (``None``,
      :py:data:`DATA_DEFERRED`).  When data arrived, call
      :py:meth:`resume()` and restart response body transmission.

      Only the body generator can pause response body generation;
      instance of :py:class:`io.IOBase` must not block.

      If instance of ``str`` is specified as *body*, it will be
      encoded using UTF-8.

      The *headers* is a list of tuple of the form ``(name,
      value)``. The ``name`` and ``value`` can be either byte string
      or unicode string.  In the latter case, they will be encoded
      using UTF-8.

      Raises the exception if any error occurs.

   .. py:method:: push(path, method='GET', request_headers=None, status=200, headers=None, body=None)

      Push a specified resource.  The *path* is a path portion of
      request URI for this resource.  The *method* is a method to
      access this resource.  The *request_headers* is additional
      request headers to access this resource.  The ``:scheme``,
      ``:method``, ``:authority`` and ``:path`` are appended by the
      library.  The ``:scheme`` and ``:authority`` are inherited from
      request header fields of the associated stream.

      The *status* is HTTP status code.  The *headers* is additional
      response headers.  The ``:status`` header field is appended by
      the library.  The *body* is the response body.  It has the same
      semantics of *body* parameter of :py:meth:`send_response()`.

      The headers and request_headers are a list of tuple of the form
      ``(name, value)``. The ``name`` and ``value`` can be either byte
      string or unicode string.  In the latter case, they will be
      encoded using UTF-8.

      Returns an instance of ``RequestHandlerClass`` specified in
      :py:class:`HTTP2Server` constructor for the pushed resource.

      Raises the exception if any error occurs.

   .. py:method:: resume()

      Signals the restarting of response body transmission paused by
      ``DATA_DEFERRED`` from the body generator (see
      :py:meth:`send_response()` about the body generator).  It is not
      an error calling this method while response body transmission is
      not paused.

.. py:data:: DATA_OK

   ``DATA_OK`` indicates non empty data is generated from body generator.

.. py:data:: DATA_EOF

   ``DATA_EOF`` indicates the end of response body.

.. py:data:: DATA_DEFERRED

   ``DATA_DEFERRED`` indicates that data are not available right now
   and response should be paused.

The following example illustrates :py:class:`HTTP2Server` and
:py:class:`BaseRequestHandler` usage:

.. code-block:: python

    #!/usr/bin/env python3

    import io, ssl

    import nghttp2

    class Handler(nghttp2.BaseRequestHandler):

        def on_headers(self):
            self.push(path='/css/style.css',
                      request_headers = [('content-type', 'text/css')],
                      status=200,
                      body='body{margin:0;}')

            self.send_response(status=200,
                               headers = [('content-type', 'text/plain')],
                               body=io.BytesIO(b'nghttp2-python FTW'))

    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ctx.options = ssl.OP_ALL | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    ctx.load_cert_chain('server.crt', 'server.key')

    # give None to ssl to make the server non-SSL/TLS
    server = nghttp2.HTTP2Server(('127.0.0.1', 8443), Handler, ssl=ctx)
    server.serve_forever()

The following example illustrates HTTP/2 server using asynchronous
response body generation.  This is simplified reverse proxy:

.. code-block:: python

    #!/usr/bin/env python3

    import ssl
    import os
    import urllib
    import asyncio
    import io

    import nghttp2

    @asyncio.coroutine
    def get_http_header(handler, url):
        url = urllib.parse.urlsplit(url)
        ssl = url.scheme == 'https'
        if url.port == None:
            if url.scheme == 'https':
                port = 443
            else:
                port = 80
        else:
            port = url.port

        connect = asyncio.open_connection(url.hostname, port, ssl=ssl)
        reader, writer = yield from connect
        req = 'GET {path} HTTP/1.0\r\n\r\n'.format(path=url.path or '/')
        writer.write(req.encode('utf-8'))
        # skip response header fields
        while True:
            line = yield from reader.readline()
            line = line.rstrip()
            if not line:
                break
        # read body
        while True:
            b = yield from reader.read(4096)
            if not b:
                break
            handler.buf.write(b)
        writer.close()
        handler.buf.seek(0)
        handler.eof = True
        handler.resume()

    class Body:
        def __init__(self, handler):
            self.handler = handler
            self.handler.eof = False
            self.handler.buf = io.BytesIO()

        def generate(self, n):
            buf = self.handler.buf
            data = buf.read1(n)
            if not data and not self.handler.eof:
                return None, nghttp2.DATA_DEFERRED
            return data, nghttp2.DATA_EOF if self.handler.eof else nghttp2.DATA_OK

    class Handler(nghttp2.BaseRequestHandler):

        def on_headers(self):
            body = Body(self)
            asyncio.async(get_http_header(
                self, 'http://localhost' + self.path.decode('utf-8')))
            self.send_response(status=200, body=body.generate)

    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ctx.options = ssl.OP_ALL | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    ctx.load_cert_chain('server.crt', 'server.key')

    server = nghttp2.HTTP2Server(('127.0.0.1', 8443), Handler, ssl=ctx)
    server.serve_forever()
