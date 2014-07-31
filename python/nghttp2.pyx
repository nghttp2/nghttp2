# nghttp2 - HTTP/2 C Library

# Copyright (c) 2013 Tatsuhiro Tsujikawa

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
cimport cnghttp2

from libc.stdlib cimport malloc, free
from libc.string cimport memcpy, memset
from libc.stdint cimport uint8_t, uint16_t, uint32_t, int32_t

DEFAULT_HEADER_TABLE_SIZE = cnghttp2.NGHTTP2_DEFAULT_HEADER_TABLE_SIZE
DEFLATE_MAX_HEADER_TABLE_SIZE = 4096

HD_ENTRY_OVERHEAD = cnghttp2.NGHTTP2_HD_ENTRY_OVERHEAD

class HDTableEntry:

    def __init__(self, name, namelen, value, valuelen):
        self.name = name
        self.namelen = namelen
        self.value = value
        self.valuelen = valuelen

    def space(self):
        return self.namelen + self.valuelen + HD_ENTRY_OVERHEAD

cdef _get_hd_table(cnghttp2.nghttp2_hd_context *ctx):
    cdef int length = ctx.hd_table.len
    cdef cnghttp2.nghttp2_hd_entry *entry
    res = []
    for i in range(length):
        entry = cnghttp2.nghttp2_hd_table_get(ctx, i)
        k = _get_pybytes(entry.nv.name, entry.nv.namelen)
        v = _get_pybytes(entry.nv.value, entry.nv.valuelen)
        res.append(HDTableEntry(k, entry.nv.namelen,
                                v, entry.nv.valuelen))
    return res

cdef _get_pybytes(uint8_t *b, uint16_t blen):
    return b[:blen]

cdef class HDDeflater:
    '''Performs header compression. The constructor takes
    |hd_table_bufsize_max| parameter, which limits the usage of header
    table in the given amount of bytes. This is necessary because the
    header compressor and decompressor share the same amount of
    header table and the decompressor decides that number. The
    compressor may not want to use all header table size because of
    limited memory availability. In that case, the
    |hd_table_bufsize_max| can be used to cap the upper limit of table
    size whatever the header table size is chosen by the decompressor.
    The default value of |hd_table_bufsize_max| is 4096 bytes.

    The following example shows how to compress request header sets:

        import binascii, nghttp2

        deflater = nghttp2.HDDeflater()
        res = deflater.deflate([(b'foo', b'bar'),
                              (b'baz', b'buz')])
        print(binascii.b2a_hex(res))

    '''

    cdef cnghttp2.nghttp2_hd_deflater *_deflater

    def __cinit__(self, hd_table_bufsize_max = DEFLATE_MAX_HEADER_TABLE_SIZE):
        rv = cnghttp2.nghttp2_hd_deflate_new(&self._deflater,
                                             hd_table_bufsize_max)
        if rv != 0:
            raise Exception(_strerror(rv))

    def __dealloc__(self):
        cnghttp2.nghttp2_hd_deflate_del(self._deflater)

    def deflate(self, headers):
        '''Compresses the |headers|. The |headers| must be sequence of tuple
        of name/value pair, which are sequence of bytes (not unicode
        string).

        This function returns the encoded header block in byte string.
        An exception will be raised on error.

        '''
        cdef cnghttp2.nghttp2_nv *nva = <cnghttp2.nghttp2_nv*>\
                                        malloc(sizeof(cnghttp2.nghttp2_nv)*\
                                        len(headers))
        cdef cnghttp2.nghttp2_nv *nvap = nva

        for k, v in headers:
            nvap[0].name = k
            nvap[0].namelen = len(k)
            nvap[0].value = v
            nvap[0].valuelen = len(v)
            nvap[0].flags = cnghttp2.NGHTTP2_NV_FLAG_NONE
            nvap += 1

        cdef size_t outcap = 0
        cdef ssize_t rv
        cdef uint8_t *out
        cdef size_t outlen

        outlen = cnghttp2.nghttp2_hd_deflate_bound(self._deflater,
                                                   nva, len(headers))

        out = <uint8_t*>malloc(outlen)

        rv = cnghttp2.nghttp2_hd_deflate_hd(self._deflater, out, outlen,
                                            nva, len(headers))
        free(nva)

        if rv < 0:
            free(out)

            raise Exception(_strerror(rv))

        cdef bytes res

        try:
            res = out[:rv]
        finally:
            free(out)

        return res

    def change_table_size(self, hd_table_bufsize_max):
        '''Changes header table size to |hd_table_bufsize_max| byte.

        An exception will be raised on error.

        '''
        cdef int rv
        rv = cnghttp2.nghttp2_hd_deflate_change_table_size(self._deflater,
                                                           hd_table_bufsize_max)
        if rv != 0:
            raise Exception(_strerror(rv))

    def get_hd_table(self):
        '''Returns copy of current dynamic header table.'''
        return _get_hd_table(&self._deflater.ctx)

cdef class HDInflater:
    '''Performs header decompression.

    The following example shows how to compress request header sets:

        data = b'0082c5ad82bd0f000362617a0362757a'
        inflater = nghttp2.HDInflater()
        hdrs = inflater.inflate(data)
        print(hdrs)

    '''

    cdef cnghttp2.nghttp2_hd_inflater *_inflater

    def __cinit__(self):
        rv = cnghttp2.nghttp2_hd_inflate_new(&self._inflater)
        if rv != 0:
            raise Exception(_strerror(rv))

    def __dealloc__(self):
        cnghttp2.nghttp2_hd_inflate_del(self._inflater)

    def inflate(self, data):
        '''Decompresses the compressed header block |data|. The |data| must be
        byte string (not unicode string).

        '''
        cdef cnghttp2.nghttp2_nv nv
        cdef int inflate_flags
        cdef ssize_t rv
        cdef uint8_t *buf = data
        cdef size_t buflen = len(data)
        res = []
        while True:
            inflate_flags = 0
            rv = cnghttp2.nghttp2_hd_inflate_hd(self._inflater, &nv,
                                                &inflate_flags,
                                                buf, buflen, 1)
            if rv < 0:
                raise Exception(_strerror(rv))
            buf += rv
            buflen -= rv
            if inflate_flags & cnghttp2.NGHTTP2_HD_INFLATE_EMIT:
                # may throw
                res.append((nv.name[:nv.namelen], nv.value[:nv.valuelen]))
            if inflate_flags & cnghttp2.NGHTTP2_HD_INFLATE_FINAL:
                break

        cnghttp2.nghttp2_hd_inflate_end_headers(self._inflater)
        return res

    def change_table_size(self, hd_table_bufsize_max):
        '''Changes header table size to |hd_table_bufsize_max| byte.

        An exception will be raised on error.

        '''
        cdef int rv
        rv = cnghttp2.nghttp2_hd_inflate_change_table_size(self._inflater,
                                                           hd_table_bufsize_max)
        if rv != 0:
            raise Exception(_strerror(rv))

    def get_hd_table(self):
        '''Returns copy of current dynamic header table.'''
        return _get_hd_table(&self._inflater.ctx)

cdef _strerror(int liberror_code):
    return cnghttp2.nghttp2_strerror(liberror_code).decode('utf-8')

def print_hd_table(hdtable):
    '''Convenient function to print |hdtable| to the standard output. This
    function does not work if header name/value cannot be decoded using
    UTF-8 encoding.

    s=N means the entry occupies N bytes in header table.

    '''
    idx = 0
    for entry in hdtable:
        idx += 1
        print('[{}] (s={}) {}: {}'\
              .format(idx, entry.space(),
                      entry.name.decode('utf-8'),
                      entry.value.decode('utf-8')))

try:
    import socket
    import io
    import asyncio
    import traceback
    import sys
    import email.utils
    import datetime
    import time
except ImportError:
    asyncio = None

cdef _get_stream_user_data(cnghttp2.nghttp2_session *session,
                           int32_t stream_id):
    cdef void *stream_user_data

    stream_user_data = cnghttp2.nghttp2_session_get_stream_user_data\
                       (session, stream_id)
    if stream_user_data == NULL:
        return None

    return <object>stream_user_data

cdef size_t _make_nva(cnghttp2.nghttp2_nv **nva_ptr, headers):
    cdef cnghttp2.nghttp2_nv *nva
    cdef size_t nvlen

    nvlen = len(headers)
    nva = <cnghttp2.nghttp2_nv*>malloc(sizeof(cnghttp2.nghttp2_nv) * nvlen)
    for i, (k, v) in enumerate(headers):
        nva[i].name = k
        nva[i].namelen = len(k)
        nva[i].value = v
        nva[i].valuelen = len(v)
        nva[i].flags = cnghttp2.NGHTTP2_NV_FLAG_NONE

    nva_ptr[0] = nva

    return nvlen

cdef int server_on_header(cnghttp2.nghttp2_session *session,
                          const cnghttp2.nghttp2_frame *frame,
                          const uint8_t *name, size_t namelen,
                          const uint8_t *value, size_t valuelen,
                          uint8_t flags,
                          void *user_data):
    cdef http2 = <_HTTP2SessionCore>user_data

    handler = _get_stream_user_data(session, frame.hd.stream_id)
    if not handler:
        return 0

    key = name[:namelen]
    values = value[:valuelen].split(b'\x00')
    if key == b':scheme':
        handler.scheme = values[0]
    elif key == b':method':
        handler.method = values[0]
    elif key == b':authority' or key == b'host':
        handler.host = values[0]
    elif key == b':path':
        handler.path = values[0]

    if key == b'cookie':
        handler.cookies.extend(values)
    else:
        for v in values:
            handler.headers.append((key, v))

    return 0

cdef int server_on_begin_request_headers(cnghttp2.nghttp2_session *session,
                                         const cnghttp2.nghttp2_frame *frame,
                                         void *user_data):
    cdef http2 = <_HTTP2SessionCore>user_data

    handler = http2._make_handler(frame.hd.stream_id)
    cnghttp2.nghttp2_session_set_stream_user_data(session, frame.hd.stream_id,
                                                  <void*>handler)

    return 0

cdef int server_on_begin_headers(cnghttp2.nghttp2_session *session,
                                 const cnghttp2.nghttp2_frame *frame,
                                 void *user_data):
    if frame.hd.type == cnghttp2.NGHTTP2_HEADERS:
        if frame.headers.cat == cnghttp2.NGHTTP2_HCAT_REQUEST:
            return server_on_begin_request_headers(session, frame, user_data)

    return 0

cdef int server_on_frame_recv(cnghttp2.nghttp2_session *session,
                              const cnghttp2.nghttp2_frame *frame,
                              void *user_data):
    cdef http2 = <_HTTP2SessionCore>user_data

    if frame.hd.type == cnghttp2.NGHTTP2_DATA:
        if frame.hd.flags & cnghttp2.NGHTTP2_FLAG_END_STREAM:
            handler = _get_stream_user_data(session, frame.hd.stream_id)
            if not handler:
                return 0
            try:
                handler.on_request_done()
            except:
                sys.stderr.write(traceback.format_exc())
                return http2._rst_stream(frame.hd.stream_id)
    elif frame.hd.type == cnghttp2.NGHTTP2_HEADERS:
        if frame.headers.cat == cnghttp2.NGHTTP2_HCAT_REQUEST:
            handler = _get_stream_user_data(session, frame.hd.stream_id)
            if not handler:
                return 0
            # Check required header fields. We expect that :authority
            # or host header field.
            if handler.scheme is None or handler.method is None or\
               handler.host is None or handler.path is None:
                return http2._rst_stream(frame.hd.stream_id,
                                         cnghttp2.NGHTTP2_PROTOCOL_ERROR)
            if handler.cookies:
                handler.headers.append((b'cookie',
                                        b'; '.join(handler.cookies)))
                handler.cookies = None
            try:
                handler.on_headers()
                if frame.hd.flags & cnghttp2.NGHTTP2_FLAG_END_STREAM:
                    handler.on_request_done()
            except:
                sys.stderr.write(traceback.format_exc())
                return http2._rst_stream(frame.hd.stream_id)
    elif frame.hd.type == cnghttp2.NGHTTP2_SETTINGS:
        if (frame.hd.flags & cnghttp2.NGHTTP2_FLAG_ACK):
            http2._stop_settings_timer()

    return 0

cdef int server_on_data_chunk_recv(cnghttp2.nghttp2_session *session,
                                   uint8_t flags,
                                   int32_t stream_id, const uint8_t *data,
                                   size_t length, void *user_data):
    cdef http2 = <_HTTP2SessionCore>user_data

    handler = _get_stream_user_data(session, stream_id)
    if not handler:
        return 0

    try:
        handler.on_data(data[:length])
    except:
        sys.stderr.write(traceback.format_exc())
        return http2._rst_stream(stream_id)

    return 0

cdef int server_on_frame_send(cnghttp2.nghttp2_session *session,
                              const cnghttp2.nghttp2_frame *frame,
                              void *user_data):
    cdef http2 = <_HTTP2SessionCore>user_data

    if frame.hd.type == cnghttp2.NGHTTP2_PUSH_PROMISE:
        # For PUSH_PROMISE, send push response immediately
        handler = _get_stream_user_data\
                  (session, frame.push_promise.promised_stream_id)
        if not handler:
            return 0

        http2.send_response(handler)
    elif frame.hd.type == cnghttp2.NGHTTP2_SETTINGS:
        if (frame.hd.flags & cnghttp2.NGHTTP2_FLAG_ACK) == 0:
            return 0
        http2._start_settings_timer()

cdef int server_on_frame_not_send(cnghttp2.nghttp2_session *session,
                                  const cnghttp2.nghttp2_frame *frame,
                                  int lib_error_code,
                                  void *user_data):
    cdef http2 = <_HTTP2SessionCore>user_data

    if frame.hd.type == cnghttp2.NGHTTP2_PUSH_PROMISE:
        # We have to remove handler here. Without this, it is not
        # removed until session is terminated.
        handler = _get_stream_user_data\
                  (session, frame.push_promise.promised_stream_id)
        if not handler:
            return 0
        http2._remove_handler(handler)

cdef int server_on_stream_close(cnghttp2.nghttp2_session *session,
                                int32_t stream_id,
                                cnghttp2.nghttp2_error_code error_code,
                                void *user_data):
    cdef http2 = <_HTTP2SessionCore>user_data

    handler = _get_stream_user_data(session, stream_id)
    if not handler:
        return 0

    try:
        handler.on_close(error_code)
    except:
        sys.stderr.write(traceback.format_exc())

    http2._remove_handler(handler)

    return 0

cdef ssize_t server_data_source_read(cnghttp2.nghttp2_session *session,
                                     int32_t stream_id,
                                     uint8_t *buf, size_t length,
                                     uint32_t *data_flags,
                                     cnghttp2.nghttp2_data_source *source,
                                     void *user_data):
    cdef http2 = <_HTTP2SessionCore>user_data
    handler = <object>source.ptr

    try:
        data = handler.response_body.read(length)
    except:
        sys.stderr.write(traceback.format_exc())
        return cnghttp2.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

    if data:
        nread = len(data)
        memcpy(buf, <uint8_t*>data, nread)
        return nread

    data_flags[0] = cnghttp2.NGHTTP2_DATA_FLAG_EOF

    return 0

cdef class _HTTP2SessionCore:
    cdef cnghttp2.nghttp2_session *session
    cdef transport
    cdef handler_class
    cdef handlers
    cdef settings_timer

    def __cinit__(self, transport, handler_class):
        cdef cnghttp2.nghttp2_session_callbacks callbacks
        cdef cnghttp2.nghttp2_settings_entry iv[2]
        cdef int rv

        self.session = NULL

        self.transport = transport
        self.handler_class = handler_class
        self.handlers = set()
        self.settings_timer = None

        memset(&callbacks, 0, sizeof(callbacks))
        callbacks.on_header_callback = server_on_header
        callbacks.on_begin_headers_callback = server_on_begin_headers
        callbacks.on_frame_recv_callback = server_on_frame_recv
        callbacks.on_stream_close_callback = server_on_stream_close
        callbacks.on_frame_send_callback = server_on_frame_send
        callbacks.on_frame_not_send_callback = server_on_frame_not_send
        callbacks.on_data_chunk_recv_callback = server_on_data_chunk_recv

        rv = cnghttp2.nghttp2_session_server_new(&self.session, &callbacks,
                                                 <void*>self)
        if rv != 0:
            raise Exception('nghttp2_session_server_new failed: {}'.format\
                            (_strerror(rv)))

        iv[0].settings_id = cnghttp2.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS
        iv[0].value = 100
        iv[1].settings_id = cnghttp2.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE
        iv[1].value = cnghttp2.NGHTTP2_INITIAL_WINDOW_SIZE

        rv = cnghttp2.nghttp2_submit_settings(self.session,
                                              cnghttp2.NGHTTP2_FLAG_NONE,
                                              iv, sizeof(iv) / sizeof(iv[0]))

        if rv != 0:
            raise Exception('nghttp2_submit_settings failed: {}'.format\
                            (_strerror(rv)))

    def __dealloc__(self):
        cnghttp2.nghttp2_session_del(self.session)

    def data_received(self, data):
        cdef ssize_t rv

        rv = cnghttp2.nghttp2_session_mem_recv(self.session, data, len(data))
        if rv < 0:
            raise Exception('nghttp2_session_mem_recv failed: {}'.format\
                            (_strerror(rv)))
        self.send_data()

    OUTBUF_MAX = 65535
    SETTINGS_TIMEOUT = 5.0

    def send_data(self):
        cdef ssize_t outbuflen
        cdef const uint8_t *outbuf

        while True:
            if self.transport.get_write_buffer_size() > self.OUTBUF_MAX:
                break
            outbuflen = cnghttp2.nghttp2_session_mem_send(self.session, &outbuf)
            if outbuflen == 0:
                break
            if outbuflen < 0:
                raise Exception('nghttp2_session_mem_send faild: {}'.format\
                                (_strerror(outbuflen)))
            self.transport.write(outbuf[:outbuflen])

        if self.transport.get_write_buffer_size() == 0 and \
           cnghttp2.nghttp2_session_want_read(self.session) == 0 and \
           cnghttp2.nghttp2_session_want_write(self.session) == 0:
            self.transport.close()

    def _make_handler(self, stream_id):
        handler = self.handler_class(self, stream_id)
        self.handlers.add(handler)
        return handler

    def _remove_handler(self, handler):
        self.handlers.remove(handler)

    def send_response(self, handler):
        cdef cnghttp2.nghttp2_data_provider prd
        cdef cnghttp2.nghttp2_data_provider *prd_ptr
        cdef cnghttp2.nghttp2_nv *nva
        cdef size_t nvlen
        cdef int rv

        nva = NULL
        nvlen = _make_nva(&nva, handler.response_headers)

        if handler.response_body:
            prd.source.ptr = <void*>handler
            prd.read_callback = server_data_source_read
            prd_ptr = &prd
        else:
            prd_ptr = NULL

        rv = cnghttp2.nghttp2_submit_response(self.session, handler.stream_id,
                                              nva, nvlen, prd_ptr)

        free(nva)

        if rv != 0:
            # TODO Ignore return value
            self._rst_stream(handler.stream_id)
            raise Exception('nghttp2_submit_response failed: {}'.format\
                            (_strerror(rv)))

        self._log_request(handler)

    def push(self, handler, promised_handler):
        cdef cnghttp2.nghttp2_nv *nva
        cdef size_t nvlen
        cdef int32_t promised_stream_id

        self.handlers.add(promised_handler)

        nva = NULL
        nvlen = _make_nva(&nva, promised_handler.headers)

        promised_stream_id = cnghttp2.nghttp2_submit_push_promise\
                             (self.session,
                              cnghttp2.NGHTTP2_FLAG_NONE,
                              handler.stream_id,
                              nva, nvlen,
                              <void*>promised_handler)
        if promised_stream_id < 0:
            raise Exception('nghttp2_submit_push_promise failed: {}'.format\
                            (_strerror(promised_stream_id)))

        promised_handler.stream_id = promised_stream_id

        return promised_handler

    def _rst_stream(self, stream_id,
                   error_code=cnghttp2.NGHTTP2_INTERNAL_ERROR):
        cdef int rv

        rv = cnghttp2.nghttp2_submit_rst_stream\
             (self.session, cnghttp2.NGHTTP2_FLAG_NONE,
              stream_id, error_code)

        return rv

    def _start_settings_timer(self):
        loop = asyncio.get_event_loop()
        self.settings_timer = loop.call_later(self.SETTINGS_TIMEOUT,
                                              self._settings_timeout)

    def _stop_settings_timer(self):
        if self.settings_timer:
            self.settings_timer.cancel()
            self.settings_timer = None

    def _settings_timeout(self):
        cdef int rv

        self.settings_timer = None

        rv = cnghttp2.nghttp2_session_terminate_session\
             (self.session, cnghttp2.NGHTTP2_SETTINGS_TIMEOUT)
        try:
            self.send_data()
        except Exception as err:
            sys.stderr.write(traceback.format_exc())
            self.transport.close()
            return

    def _get_client_address(self):
        return self.transport.get_extra_info('peername')

    def _log_request(self, handler):
        now = datetime.datetime.now()
        tv = time.mktime(now.timetuple())
        datestr = email.utils.formatdate(timeval=tv, localtime=False,
                                        usegmt=True)
        try:
            method = handler.method.decode('utf-8')
        except:
            method = handler.method
        try:
            path = handler.path.decode('utf-8')
        except:
            path = handler.path
        sys.stderr.write('{} - - [{}] "{} {} HTTP/2" {} - {}\n'.format\
                         (handler.client_address[0],
                          datestr, method, path, handler.status,
                          'P' if handler.pushed else '-'))

if asyncio:

    class BaseRequestHandler:

        """HTTP/2 request (stream) handler base class.

        The class is used to handle the HTTP/2 stream. By default, it does
        not nothing. It must be subclassed to handle each event callback
        method.

        The first callback method invoked is on_headers(). It is called
        when HEADERS frame, which includes request header fields, is
        arrived.

        If request has request body, on_data(data) is invoked for each
        chunk of received data.

        When whole request is received, on_request_done() is invoked.

        When stream is closed, on_close(error_code) is called.

        The application can send response using send_response() method. It
        can be used in on_headers(), on_data() or on_request_done().

        The application can push resource using push() method. It must be
        used before send_response() call.

        The following instance variables are available:

        client_address
          Contains a tuple of the form (host, port) referring to the client's
          address.

        stream_id
          Stream ID of this stream

        scheme
          Scheme of the request URI. This is a value of :scheme header field.

        method
          Method of this stream. This is a value of :method header field.

        host
          This is a value of :authority or host header field.

        path
          This is a value of :path header field.

        """

        def __init__(self, http2, stream_id):
            self.headers = []
            self.cookies = []
            # Stream ID. For promised stream, it is initially -1.
            self.stream_id = stream_id
            self.http2 = http2
            # address of the client
            self.client_address = self.http2._get_client_address()
            # :scheme header field in request
            self.scheme = None
            # :method header field in request
            self.method = None
            # :authority or host header field in request
            self.host = None
            # :path header field in request
            self.path = None
            # HTTP status
            self.status = None
            # True if this is a handler for pushed resource
            self.pushed = False

        def on_headers(self):

            '''Called when request HEADERS is arrived.

            '''
            pass

        def on_data(self, data):

            '''Called when a chunk of request body is arrived. This method
            will be called multiple times until all data are received.

            '''
            pass

        def on_request_done(self):

            '''Called when whole request was received

            '''
            pass

        def on_close(self, error_code):

            '''Called when stream is about to close.

            '''
            pass

        def send_response(self, status=200, headers=None, body=None):

            '''Send response. The status is HTTP status code. The headers is
            additional response headers. The :status header field is
            appended by the library. The body is the response body. It
            could be None if response body is empty. Or it must be
            instance of either str, bytes or io.IOBase. If instance of str
            is specified, it is encoded using UTF-8.

            The headers is a list of tuple of the form (name,
            value). The name and value can be either unicode string or
            byte string.

            On error, exception will be thrown.

            '''
            if self.status is not None:
                raise Exception('response has already been sent')

            if not status:
                raise Exception('status must not be empty')

            body = self._wrap_body(body)

            self._set_response_prop(status, headers, body)
            self.http2.send_response(self)

        def push(self, path, method='GET', request_headers=None,
                 status=200, headers=None, body=None):

            '''Push a resource. The path is a path portion of request URI
            for this
            resource. The method is a method to access this
            resource. The request_headers is additional request
            headers to access this resource. The :scheme, :method,
            :authority and :path are appended by the library. The
            :scheme and :authority are inherited from the request (not
            request_headers parameter).

            The status is HTTP status code. The headers is additional
            response headers. The :status header field is appended by the
            library. The body is the response body. It could be None if
            response body is empty. Or it must be instance of either str,
            bytes or io.IOBase. If instance of str is specified, it is
            encoded using UTF-8.

            The headers and request_headers are a list of tuple of the
            form (name, value). The name and value can be either
            unicode string or byte string.

            On error, exception will be thrown.

            '''
            if not status:
                raise Exception('status must not be empty')

            if not method:
                raise Exception('method must not be empty')

            if not path:
                raise Exception('path must not be empty')

            body = self._wrap_body(body)

            promised_handler = self.http2._make_handler(-1)
            promised_handler.pushed = True
            promised_handler.scheme = self.scheme
            promised_handler.method = method.encode('utf-8')
            promised_handler.host = self.host
            promised_handler.path = path.encode('utf-8')
            promised_handler._set_response_prop(status, headers, body)

            if request_headers is None:
                request_headers = []

            request_headers = _encode_headers(request_headers)
            request_headers.append((b':scheme', promised_handler.scheme))
            request_headers.append((b':method', promised_handler.method))
            request_headers.append((b':authority', promised_handler.host))
            request_headers.append((b':path', promised_handler.path))

            promised_handler.headers = request_headers

            return self.http2.push(self, promised_handler)

        def _set_response_prop(self, status, headers, body):
            self.status = status

            if headers is None:
                headers = []

            self.response_headers = _encode_headers(headers)
            self.response_headers.append((b':status', str(status)\
                                          .encode('utf-8')))

            self.response_body = body

        def _wrap_body(self, body):
            if body is None:
                return body
            elif isinstance(body, str):
                return io.BytesIO(body.encode('utf-8'))
            elif isinstance(body, bytes):
                return io.BytesIO(body)
            elif isinstance(body, io.IOBase):
                return body
            else:
                raise Exception(('body must be None or instance of str or '
                                 'bytes or io.IOBase'))

    def _encode_headers(headers):
        return [(k if isinstance(k, bytes) else k.encode('utf-8'),
                 v if isinstance(v, bytes) else v.encode('utf-8')) \
                for k, v in headers]

    class _HTTP2Session(asyncio.Protocol):

        def __init__(self, RequestHandlerClass):
            asyncio.Protocol.__init__(self)
            self.RequestHandlerClass = RequestHandlerClass
            self.http2 = None

        def connection_made(self, transport):
            self.transport = transport
            self.connection_header = cnghttp2.NGHTTP2_CLIENT_CONNECTION_PREFACE
            sock = self.transport.get_extra_info('socket')
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ssl_ctx = self.transport.get_extra_info('sslcontext')
            if ssl_ctx:
                if sock.selected_npn_protocol().encode('utf-8') != \
                   cnghttp2.NGHTTP2_PROTO_VERSION_ID:
                    self.transport.abort()

        def connection_lost(self, exc):
            if self.http2:
                self.http2 = None

        def data_received(self, data):
            nread = min(len(data), len(self.connection_header))

            if self.connection_header.startswith(data[:nread]):
                data = data[nread:]
                self.connection_header = self.connection_header[nread:]
                if len(self.connection_header) == 0:
                    try:
                        self.http2 = _HTTP2SessionCore\
                                     (self.transport,
                                      self.RequestHandlerClass)
                    except Exception as err:
                        sys.stderr.write(traceback.format_exc())
                        self.transport.abort()
                        return

                    self.data_received = self.data_received2
                    self.resume_writing = self.resume_writing2
                    self.data_received(data)
            else:
                self.transport.abort()

        def data_received2(self, data):
            try:
                self.http2.data_received(data)
            except Exception as err:
                sys.stderr.write(traceback.format_exc())
                self.transport.close()
                return

        def resume_writing2(self):
            try:
                self.http2.send_data()
            except Exception as err:
                sys.stderr.write(traceback.format_exc())
                self.transport.close()
                return

    class HTTP2Server:

        '''HTTP/2 server.

        This class builds on top of the asyncio event loop. On
        construction, RequestHandlerClass must be given, which must be a
        subclass of BaseRequestHandler class.

        '''
        def __init__(self, address, RequestHandlerClass, ssl=None):

            '''address is a tuple of the listening address and port (e.g.,
            ('127.0.0.1', 8080)). RequestHandlerClass must be a subclass
            of BaseRequestHandler class to handle a HTTP/2 stream.  The
            ssl can be ssl.SSLContext instance. If it is not None, the
            resulting server is SSL/TLS capable.

            '''
            def session_factory():
                return _HTTP2Session(RequestHandlerClass)

            self.loop = asyncio.get_event_loop()

            if ssl:
                ssl.set_npn_protocols([cnghttp2.NGHTTP2_PROTO_VERSION_ID\
                                       .decode('utf-8')])

            coro = self.loop.create_server(session_factory,
                                           host=address[0], port=address[1],
                                           ssl=ssl)
            self.server = self.loop.run_until_complete(coro)

        def serve_forever(self):
            try:
                self.loop.run_forever()
            finally:
                self.server.close()
                self.loop.close()
