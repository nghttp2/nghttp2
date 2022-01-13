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
import logging


DEFAULT_HEADER_TABLE_SIZE = cnghttp2.NGHTTP2_DEFAULT_HEADER_TABLE_SIZE
DEFLATE_MAX_HEADER_TABLE_SIZE = 4096

HD_ENTRY_OVERHEAD = 32

class HDTableEntry:

    def __init__(self, name, namelen, value, valuelen):
        self.name = name
        self.namelen = namelen
        self.value = value
        self.valuelen = valuelen

    def space(self):
        return self.namelen + self.valuelen + HD_ENTRY_OVERHEAD

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
        cdef size_t length = cnghttp2.nghttp2_hd_deflate_get_num_table_entries(
            self._deflater)
        cdef const cnghttp2.nghttp2_nv *nv
        res = []
        for i in range(62, length + 1):
            nv = cnghttp2.nghttp2_hd_deflate_get_table_entry(self._deflater, i)
            k = _get_pybytes(nv.name, nv.namelen)
            v = _get_pybytes(nv.value, nv.valuelen)
            res.append(HDTableEntry(k, nv.namelen, v, nv.valuelen))
        return res

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
            rv = cnghttp2.nghttp2_hd_inflate_hd2(self._inflater, &nv,
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
        cdef size_t length = cnghttp2.nghttp2_hd_inflate_get_num_table_entries(
            self._inflater)
        cdef const cnghttp2.nghttp2_nv *nv
        res = []
        for i in range(62, length + 1):
            nv = cnghttp2.nghttp2_hd_inflate_get_table_entry(self._inflater, i)
            k = _get_pybytes(nv.name, nv.namelen)
            v = _get_pybytes(nv.value, nv.valuelen)
            res.append(HDTableEntry(k, nv.namelen, v, nv.valuelen))
        return res

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
    import ssl as tls
    from urllib.parse import urlparse
except ImportError:
    asyncio = None

# body generator flags
DATA_OK = 0
DATA_EOF = 1
DATA_DEFERRED = 2

class _ByteIOWrapper:

    def __init__(self, b):
        self.b = b

    def generate(self, n):
        data = self.b.read1(n)
        if not data:
            return None, DATA_EOF
        return data, DATA_OK

def wrap_body(body):
    if body is None:
        return body
    elif isinstance(body, str):
        return _ByteIOWrapper(io.BytesIO(body.encode('utf-8'))).generate
    elif isinstance(body, bytes):
        return _ByteIOWrapper(io.BytesIO(body)).generate
    elif isinstance(body, io.IOBase):
        return _ByteIOWrapper(body).generate
    else:
        # assume that callable in the form f(n) returning tuple byte
        # string and flag.
        return body

def negotiated_protocol(ssl_obj):
    protocol = ssl_obj.selected_alpn_protocol()
    if protocol:
        logging.info('alpn, protocol:%s', protocol)
        return protocol

    protocol = ssl_obj.selected_npn_protocol()
    if protocol:
        logging.info('npn, protocol:%s', protocol)
        return protocol

    return None

def set_application_protocol(ssl_ctx):
    app_protos = [cnghttp2.NGHTTP2_PROTO_VERSION_ID.decode('utf-8')]
    ssl_ctx.set_npn_protocols(app_protos)
    if tls.HAS_ALPN:
        ssl_ctx.set_alpn_protocols(app_protos)

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
    cdef http2 = <_HTTP2SessionCoreBase>user_data
    logging.debug('server_on_header, type:%s, stream_id:%s', frame.hd.type, frame.hd.stream_id)

    handler = _get_stream_user_data(session, frame.hd.stream_id)
    return on_header(name, namelen, value, valuelen, flags, handler)

cdef int client_on_header(cnghttp2.nghttp2_session *session,
                          const cnghttp2.nghttp2_frame *frame,
                          const uint8_t *name, size_t namelen,
                          const uint8_t *value, size_t valuelen,
                          uint8_t flags,
                          void *user_data):
    cdef http2 = <_HTTP2SessionCoreBase>user_data
    logging.debug('client_on_header, type:%s, stream_id:%s', frame.hd.type, frame.hd.stream_id)

    if frame.hd.type == cnghttp2.NGHTTP2_HEADERS:
        handler = _get_stream_user_data(session, frame.hd.stream_id)
    elif frame.hd.type == cnghttp2.NGHTTP2_PUSH_PROMISE:
        handler = _get_stream_user_data(session, frame.push_promise.promised_stream_id)

    return on_header(name, namelen, value, valuelen, flags, handler)


cdef int on_header(const uint8_t *name, size_t namelen,
                          const uint8_t *value, size_t valuelen,
                          uint8_t flags,
                          object handler):
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
    elif key == b':status':
        handler.status = values[0]

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
    logging.debug('server_on_frame_recv, type:%s, stream_id:%s', frame.hd.type, frame.hd.stream_id)

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

cdef int on_data_chunk_recv(cnghttp2.nghttp2_session *session,
                                   uint8_t flags,
                                   int32_t stream_id, const uint8_t *data,
                                   size_t length, void *user_data):
    cdef http2 = <_HTTP2SessionCoreBase>user_data

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
    logging.debug('server_on_frame_send, type:%s, stream_id:%s', frame.hd.type, frame.hd.stream_id)

    if frame.hd.type == cnghttp2.NGHTTP2_PUSH_PROMISE:
        # For PUSH_PROMISE, send push response immediately
        handler = _get_stream_user_data\
                  (session, frame.push_promise.promised_stream_id)
        if not handler:
            return 0

        http2.send_response(handler)
    elif frame.hd.type == cnghttp2.NGHTTP2_SETTINGS:
        if (frame.hd.flags & cnghttp2.NGHTTP2_FLAG_ACK) != 0:
            return 0
        http2._start_settings_timer()
    elif frame.hd.type == cnghttp2.NGHTTP2_HEADERS:
        if (frame.hd.flags & cnghttp2.NGHTTP2_FLAG_END_STREAM) and \
           cnghttp2.nghttp2_session_check_server_session(session):
            # Send RST_STREAM if remote is not closed yet
            if cnghttp2.nghttp2_session_get_stream_remote_close(
                    session, frame.hd.stream_id) == 0:
                http2._rst_stream(frame.hd.stream_id, cnghttp2.NGHTTP2_NO_ERROR)

cdef int server_on_frame_not_send(cnghttp2.nghttp2_session *session,
                                  const cnghttp2.nghttp2_frame *frame,
                                  int lib_error_code,
                                  void *user_data):
    cdef http2 = <_HTTP2SessionCore>user_data
    logging.debug('server_on_frame_not_send, type:%s, stream_id:%s', frame.hd.type, frame.hd.stream_id)

    if frame.hd.type == cnghttp2.NGHTTP2_PUSH_PROMISE:
        # We have to remove handler here. Without this, it is not
        # removed until session is terminated.
        handler = _get_stream_user_data\
                  (session, frame.push_promise.promised_stream_id)
        if not handler:
            return 0
        http2._remove_handler(handler)

cdef int on_stream_close(cnghttp2.nghttp2_session *session,
                                int32_t stream_id,
                                uint32_t error_code,
                                void *user_data):
    cdef http2 = <_HTTP2SessionCoreBase>user_data
    logging.debug('on_stream_close, stream_id:%s', stream_id)

    handler = _get_stream_user_data(session, stream_id)
    if not handler:
        return 0

    try:
        handler.on_close(error_code)
    except:
        sys.stderr.write(traceback.format_exc())

    http2._remove_handler(handler)

    return 0

cdef ssize_t data_source_read(cnghttp2.nghttp2_session *session,
                              int32_t stream_id,
                              uint8_t *buf, size_t length,
                              uint32_t *data_flags,
                              cnghttp2.nghttp2_data_source *source,
                              void *user_data):
    cdef http2 = <_HTTP2SessionCoreBase>user_data
    generator = <object>source.ptr

    http2.enter_callback()
    try:
        data, flag = generator(length)
    except:
        sys.stderr.write(traceback.format_exc())
        return cnghttp2.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    finally:
        http2.leave_callback()

    if flag == DATA_DEFERRED:
        return cnghttp2.NGHTTP2_ERR_DEFERRED

    if data:
        nread = len(data)
        memcpy(buf, <uint8_t*>data, nread)
    else:
        nread = 0

    if flag == DATA_EOF:
        data_flags[0] = cnghttp2.NGHTTP2_DATA_FLAG_EOF
        if cnghttp2.nghttp2_session_check_server_session(session):
            # Send RST_STREAM if remote is not closed yet
            if cnghttp2.nghttp2_session_get_stream_remote_close(
                    session, stream_id) == 0:
                http2._rst_stream(stream_id, cnghttp2.NGHTTP2_NO_ERROR)
    elif flag != DATA_OK:
        return cnghttp2.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE

    return nread

cdef int client_on_begin_headers(cnghttp2.nghttp2_session *session,
                                 const cnghttp2.nghttp2_frame *frame,
                                 void *user_data):
    cdef http2 = <_HTTP2ClientSessionCore>user_data

    if frame.hd.type == cnghttp2.NGHTTP2_PUSH_PROMISE:
        # Generate a temporary handler until the headers are all received
        push_handler = BaseResponseHandler()
        http2._add_handler(push_handler, frame.push_promise.promised_stream_id)
        cnghttp2.nghttp2_session_set_stream_user_data(session, frame.push_promise.promised_stream_id,
                                                      <void*>push_handler)

    return 0

cdef int client_on_frame_recv(cnghttp2.nghttp2_session *session,
                              const cnghttp2.nghttp2_frame *frame,
                              void *user_data):
    cdef http2 = <_HTTP2ClientSessionCore>user_data
    logging.debug('client_on_frame_recv, type:%s, stream_id:%s', frame.hd.type, frame.hd.stream_id)

    if frame.hd.type == cnghttp2.NGHTTP2_DATA:
        if frame.hd.flags & cnghttp2.NGHTTP2_FLAG_END_STREAM:
            handler = _get_stream_user_data(session, frame.hd.stream_id)
            if not handler:
                return 0
            try:
                handler.on_response_done()
            except:
                sys.stderr.write(traceback.format_exc())
                return http2._rst_stream(frame.hd.stream_id)
    elif frame.hd.type == cnghttp2.NGHTTP2_HEADERS:
        if frame.headers.cat == cnghttp2.NGHTTP2_HCAT_RESPONSE or frame.headers.cat == cnghttp2.NGHTTP2_HCAT_PUSH_RESPONSE:
            handler = _get_stream_user_data(session, frame.hd.stream_id)

            if not handler:
                return 0
            # TODO handle 1xx non-final response
            if handler.cookies:
                handler.headers.append((b'cookie',
                                        b'; '.join(handler.cookies)))
                handler.cookies = None
            try:
                handler.on_headers()
                if frame.hd.flags & cnghttp2.NGHTTP2_FLAG_END_STREAM:
                    handler.on_response_done()
            except:
                sys.stderr.write(traceback.format_exc())
                return http2._rst_stream(frame.hd.stream_id)
    elif frame.hd.type == cnghttp2.NGHTTP2_SETTINGS:
        if (frame.hd.flags & cnghttp2.NGHTTP2_FLAG_ACK):
            http2._stop_settings_timer()
    elif frame.hd.type == cnghttp2.NGHTTP2_PUSH_PROMISE:
        handler = _get_stream_user_data(session, frame.hd.stream_id)
        if not handler:
            return 0
        # Get the temporary push_handler which now should have all of the header data
        push_handler = _get_stream_user_data(session, frame.push_promise.promised_stream_id)
        if not push_handler:
            return 0
        # Remove the temporary handler
        http2._remove_handler(push_handler)
        cnghttp2.nghttp2_session_set_stream_user_data(session, frame.push_promise.promised_stream_id,
                                                      <void*>NULL)

        try:
            handler.on_push_promise(push_handler)
        except:
            sys.stderr.write(traceback.format_exc())
            return http2._rst_stream(frame.hd.stream_id)

    return 0

cdef int client_on_frame_send(cnghttp2.nghttp2_session *session,
                              const cnghttp2.nghttp2_frame *frame,
                              void *user_data):
    cdef http2 = <_HTTP2ClientSessionCore>user_data
    logging.debug('client_on_frame_send, type:%s, stream_id:%s', frame.hd.type, frame.hd.stream_id)

    if frame.hd.type == cnghttp2.NGHTTP2_SETTINGS:
        if (frame.hd.flags & cnghttp2.NGHTTP2_FLAG_ACK) != 0:
            return 0
        http2._start_settings_timer()

cdef class _HTTP2SessionCoreBase:
    cdef cnghttp2.nghttp2_session *session
    cdef transport
    cdef handler_class
    cdef handlers
    cdef settings_timer
    cdef inside_callback

    def __cinit__(self, transport, handler_class=None):
        self.session = NULL
        self.transport = transport
        self.handler_class = handler_class
        self.handlers = set()
        self.settings_timer = None
        self.inside_callback = False

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
                raise Exception('nghttp2_session_mem_send failed: {}'.format\
                                (_strerror(outbuflen)))
            self.transport.write(outbuf[:outbuflen])

        if self.transport.get_write_buffer_size() == 0 and \
           cnghttp2.nghttp2_session_want_read(self.session) == 0 and \
           cnghttp2.nghttp2_session_want_write(self.session) == 0:
            self.transport.close()

    def resume(self, stream_id):
        cnghttp2.nghttp2_session_resume_data(self.session, stream_id)
        if not self.inside_callback:
            self.send_data()

    def enter_callback(self):
        self.inside_callback = True

    def leave_callback(self):
        self.inside_callback = False

    def _make_handler(self, stream_id):
        logging.debug('_make_handler, stream_id:%s', stream_id)
        handler = self.handler_class(self, stream_id)
        self.handlers.add(handler)
        return handler

    def _remove_handler(self, handler):
        logging.debug('_remove_handler, stream_id:%s', handler.stream_id)
        self.handlers.remove(handler)

    def _add_handler(self, handler, stream_id):
        logging.debug('_add_handler, stream_id:%s', stream_id)
        handler.stream_id = stream_id
        handler.http2 = self
        handler.remote_address = self._get_remote_address()
        handler.client_certificate = self._get_client_certificate()
        self.handlers.add(handler)

    def _rst_stream(self, stream_id,
                   error_code=cnghttp2.NGHTTP2_INTERNAL_ERROR):
        cdef int rv

        rv = cnghttp2.nghttp2_submit_rst_stream\
             (self.session, cnghttp2.NGHTTP2_FLAG_NONE,
              stream_id, error_code)

        return rv

    def _get_remote_address(self):
        return self.transport.get_extra_info('peername')

    def _get_client_certificate(self):
        sock = self.transport.get_extra_info('socket')
        try:
            return sock.getpeercert()
        except AttributeError:
            return None

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

        logging.debug('_settings_timeout')

        self.settings_timer = None

        rv = cnghttp2.nghttp2_session_terminate_session\
             (self.session, cnghttp2.NGHTTP2_SETTINGS_TIMEOUT)
        try:
            self.send_data()
        except Exception as err:
            sys.stderr.write(traceback.format_exc())
            self.transport.close()
            return

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
        logging.info('%s - - [%s] "%s %s HTTP/2" %s - %s', handler.remote_address[0],
                          datestr, method, path, handler.status,
                          'P' if handler.pushed else '-')

    def close(self):
        rv = cnghttp2.nghttp2_session_terminate_session\
             (self.session, cnghttp2.NGHTTP2_NO_ERROR)
        try:
            self.send_data()
        except Exception as err:
            sys.stderr.write(traceback.format_exc())
            self.transport.close()
            return

cdef class _HTTP2SessionCore(_HTTP2SessionCoreBase):
    def __cinit__(self, *args, **kwargs):
        cdef cnghttp2.nghttp2_session_callbacks *callbacks
        cdef cnghttp2.nghttp2_settings_entry iv[2]
        cdef int rv

        super(_HTTP2SessionCore, self).__init__(*args, **kwargs)

        rv = cnghttp2.nghttp2_session_callbacks_new(&callbacks)

        if rv != 0:
            raise Exception('nghttp2_session_callbacks_new failed: {}'.format\
                            (_strerror(rv)))

        cnghttp2.nghttp2_session_callbacks_set_on_header_callback(
            callbacks, server_on_header)
        cnghttp2.nghttp2_session_callbacks_set_on_begin_headers_callback(
            callbacks, server_on_begin_headers)
        cnghttp2.nghttp2_session_callbacks_set_on_frame_recv_callback(
            callbacks, server_on_frame_recv)
        cnghttp2.nghttp2_session_callbacks_set_on_stream_close_callback(
            callbacks, on_stream_close)
        cnghttp2.nghttp2_session_callbacks_set_on_frame_send_callback(
            callbacks, server_on_frame_send)
        cnghttp2.nghttp2_session_callbacks_set_on_frame_not_send_callback(
            callbacks, server_on_frame_not_send)
        cnghttp2.nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
            callbacks, on_data_chunk_recv)

        rv = cnghttp2.nghttp2_session_server_new(&self.session, callbacks,
                                                 <void*>self)

        cnghttp2.nghttp2_session_callbacks_del(callbacks)

        if rv != 0:
            raise Exception('nghttp2_session_server_new failed: {}'.format\
                            (_strerror(rv)))

        iv[0].settings_id = cnghttp2.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS
        iv[0].value = 100
        iv[1].settings_id = cnghttp2.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE
        iv[1].value = cnghttp2.NGHTTP2_INITIAL_WINDOW_SIZE

        rv = cnghttp2.nghttp2_submit_settings(self.session,
                                              cnghttp2.NGHTTP2_FLAG_NONE,
                                              iv, sizeof(iv) // sizeof(iv[0]))

        if rv != 0:
            raise Exception('nghttp2_submit_settings failed: {}'.format\
                            (_strerror(rv)))

    def send_response(self, handler):
        cdef cnghttp2.nghttp2_data_provider prd
        cdef cnghttp2.nghttp2_data_provider *prd_ptr
        cdef cnghttp2.nghttp2_nv *nva
        cdef size_t nvlen
        cdef int rv

        logging.debug('send_response, stream_id:%s', handler.stream_id)

        nva = NULL
        nvlen = _make_nva(&nva, handler.response_headers)

        if handler.response_body:
            prd.source.ptr = <void*>handler.response_body
            prd.read_callback = data_source_read
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

        logging.debug('push, stream_id:%s', promised_stream_id)

        return promised_handler

    def connection_lost(self):
        self._stop_settings_timer()

        for handler in self.handlers:
            handler.on_close(cnghttp2.NGHTTP2_INTERNAL_ERROR)
        self.handlers = set()

cdef class _HTTP2ClientSessionCore(_HTTP2SessionCoreBase):
    def __cinit__(self, *args, **kwargs):
        cdef cnghttp2.nghttp2_session_callbacks *callbacks
        cdef cnghttp2.nghttp2_settings_entry iv[2]
        cdef int rv

        super(_HTTP2ClientSessionCore, self).__init__(*args, **kwargs)

        rv = cnghttp2.nghttp2_session_callbacks_new(&callbacks)

        if rv != 0:
            raise Exception('nghttp2_session_callbacks_new failed: {}'.format\
                            (_strerror(rv)))

        cnghttp2.nghttp2_session_callbacks_set_on_header_callback(
            callbacks, client_on_header)
        cnghttp2.nghttp2_session_callbacks_set_on_begin_headers_callback(
            callbacks, client_on_begin_headers)
        cnghttp2.nghttp2_session_callbacks_set_on_frame_recv_callback(
            callbacks, client_on_frame_recv)
        cnghttp2.nghttp2_session_callbacks_set_on_stream_close_callback(
            callbacks, on_stream_close)
        cnghttp2.nghttp2_session_callbacks_set_on_frame_send_callback(
            callbacks, client_on_frame_send)
        cnghttp2.nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
            callbacks, on_data_chunk_recv)

        rv = cnghttp2.nghttp2_session_client_new(&self.session, callbacks,
                                                 <void*>self)

        cnghttp2.nghttp2_session_callbacks_del(callbacks)

        if rv != 0:
            raise Exception('nghttp2_session_client_new failed: {}'.format\
                            (_strerror(rv)))

        iv[0].settings_id = cnghttp2.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS
        iv[0].value = 100
        iv[1].settings_id = cnghttp2.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE
        iv[1].value = cnghttp2.NGHTTP2_INITIAL_WINDOW_SIZE

        rv = cnghttp2.nghttp2_submit_settings(self.session,
                                              cnghttp2.NGHTTP2_FLAG_NONE,
                                              iv, sizeof(iv) // sizeof(iv[0]))

        if rv != 0:
            raise Exception('nghttp2_submit_settings failed: {}'.format\
                            (_strerror(rv)))

    def send_request(self, method, scheme, host, path, headers, body, handler):
        cdef cnghttp2.nghttp2_data_provider prd
        cdef cnghttp2.nghttp2_data_provider *prd_ptr
        cdef cnghttp2.nghttp2_priority_spec *pri_ptr
        cdef cnghttp2.nghttp2_nv *nva
        cdef size_t nvlen
        cdef int32_t stream_id

        body = wrap_body(body)

        custom_headers = _encode_headers(headers)
        headers = [
            (b':method', method.encode('utf-8')),
            (b':scheme', scheme.encode('utf-8')),
            (b':authority', host.encode('utf-8')),
            (b':path', path.encode('utf-8'))
        ]
        headers.extend(custom_headers)

        nva = NULL
        nvlen = _make_nva(&nva, headers)

        if body:
            prd.source.ptr = <void*>body
            prd.read_callback = data_source_read
            prd_ptr = &prd
        else:
            prd_ptr = NULL

        # TODO: Enable priorities
        pri_ptr = NULL

        stream_id = cnghttp2.nghttp2_submit_request\
                             (self.session, pri_ptr,
                              nva, nvlen, prd_ptr,
                              <void*>handler)
        free(nva)

        if stream_id < 0:
            raise Exception('nghttp2_submit_request failed: {}'.format\
                            (_strerror(stream_id)))

        logging.debug('request, stream_id:%s', stream_id)

        self._add_handler(handler, stream_id)
        cnghttp2.nghttp2_session_set_stream_user_data(self.session, stream_id,
                                                  <void*>handler)

        return handler

    def push(self, push_promise, handler):
        if handler:
            # push_promise accepted, fill in the handler with the stored
            # headers from the push_promise
            handler.status = push_promise.status
            handler.scheme = push_promise.scheme
            handler.method = push_promise.method
            handler.host = push_promise.host
            handler.path = push_promise.path
            handler.cookies = push_promise.cookies
            handler.stream_id = push_promise.stream_id
            handler.http2 = self
            handler.pushed = True

            self._add_handler(handler, handler.stream_id)

            cnghttp2.nghttp2_session_set_stream_user_data(self.session, handler.stream_id,
                                                      <void*>handler)
        else:
            # push_promise rejected, reset the stream
            self._rst_stream(push_promise.stream_id,
                              error_code=cnghttp2.NGHTTP2_NO_ERROR)

if asyncio:

    class BaseRequestHandler:

        """HTTP/2 request (stream) handler base class.

        The class is used to handle the HTTP/2 stream. By default, it does
        nothing. It must be subclassed to handle each event callback method.

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

        client_certificate
          May contain the client certificate in its non-binary form

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

        headers
          Request header fields

        """

        def __init__(self, http2, stream_id):
            self.headers = []
            self.cookies = []
            # Stream ID. For promised stream, it is initially -1.
            self.stream_id = stream_id
            self.http2 = http2
            # address of the client
            self.remote_address = self.http2._get_remote_address()
            # certificate of the client
            self._client_certificate = self.http2._get_client_certificate()
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

        @property
        def client_address(self):
            return self.remote_address

        @property
        def client_certificate(self):
            return self._client_certificate

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
            instance of either str, bytes, io.IOBase or callable,
            called body generator, which takes one parameter,
            size. The body generator generates response body. It can
            pause generation of response so that it can wait for slow
            backend data generation. When invoked, it should return
            tuple, byte string and flag. The flag is either DATA_OK,
            DATA_EOF and DATA_DEFERRED. For non-empty byte string and
            it is not the last chunk of response, DATA_OK is returned
            as flag.  If this is the last chunk of the response (byte
            string is possibly None), DATA_EOF must be returned as
            flag.  If there is no data available right now, but
            additional data are anticipated, return tuple (None,
            DATA_DEFERRD).  When data arrived, call resume() and
            restart response body transmission.

            Only the body generator can pause response body
            generation; instance of io.IOBase must not block.

            If instance of str is specified as body, it is encoded
            using UTF-8.

            The headers is a list of tuple of the form (name,
            value). The name and value can be either unicode string or
            byte string.

            On error, exception will be thrown.

            '''
            if self.status is not None:
                raise Exception('response has already been sent')

            if not status:
                raise Exception('status must not be empty')

            body = wrap_body(body)

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
            response headers. The :status header field is appended by
            the library. The body is the response body. It has the
            same semantics of body parameter of send_response().

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

            body = wrap_body(body)

            promised_handler = self.http2._make_handler(-1)
            promised_handler.pushed = True
            promised_handler.scheme = self.scheme
            promised_handler.method = method.encode('utf-8')
            promised_handler.host = self.host
            promised_handler.path = path.encode('utf-8')
            promised_handler._set_response_prop(status, headers, body)

            headers = [
                (b':method', promised_handler.method),
                (b':scheme', promised_handler.scheme),
                (b':authority', promised_handler.host),
                (b':path', promised_handler.path)
            ]
            headers.extend(_encode_headers(request_headers))

            promised_handler.headers = headers

            return self.http2.push(self, promised_handler)

        def _set_response_prop(self, status, headers, body):
            self.status = status

            if headers is None:
                headers = []

            self.response_headers = [(b':status', str(status).encode('utf-8'))]
            self.response_headers.extend(_encode_headers(headers))

            self.response_body = body

        def resume(self):
            self.http2.resume(self.stream_id)

    def _encode_headers(headers):
        if not headers:
            return []
        return [(k if isinstance(k, bytes) else k.encode('utf-8'),
                 v if isinstance(v, bytes) else v.encode('utf-8')) \
                for k, v in headers]

    class _HTTP2Session(asyncio.Protocol):

        def __init__(self, RequestHandlerClass):
            asyncio.Protocol.__init__(self)
            self.RequestHandlerClass = RequestHandlerClass
            self.http2 = None

        def connection_made(self, transport):
            address = transport.get_extra_info('peername')
            logging.info('connection_made, address:%s, port:%s', address[0], address[1])

            self.transport = transport
            sock = self.transport.get_extra_info('socket')
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError as e:
                logging.info('failed to set tcp-nodelay: %s', str(e))
            ssl_ctx = self.transport.get_extra_info('sslcontext')
            if ssl_ctx:
                ssl_obj = self.transport.get_extra_info('ssl_object')
                protocol = negotiated_protocol(ssl_obj)
                if protocol is None or protocol.encode('utf-8') != \
                   cnghttp2.NGHTTP2_PROTO_VERSION_ID:
                    self.transport.abort()
                    return
            try:
                self.http2 = _HTTP2SessionCore\
                             (self.transport,
                              self.RequestHandlerClass)
            except Exception as err:
                sys.stderr.write(traceback.format_exc())
                self.transport.abort()
                return


        def connection_lost(self, exc):
            logging.info('connection_lost')
            if self.http2:
                self.http2.connection_lost()
                self.http2 = None

        def data_received(self, data):
            try:
                self.http2.data_received(data)
            except Exception as err:
                sys.stderr.write(traceback.format_exc())
                self.transport.close()
                return

        def resume_writing(self):
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
                set_application_protocol(ssl)

            coro = self.loop.create_server(session_factory,
                                           host=address[0], port=address[1],
                                           ssl=ssl)
            self.server = self.loop.run_until_complete(coro)
            logging.info('listen, address:%s, port:%s', address[0], address[1])

        def serve_forever(self):
            try:
                self.loop.run_forever()
            finally:
                self.server.close()
                self.loop.close()



    class BaseResponseHandler:

        """HTTP/2 response (stream) handler base class.

        The class is used to handle the HTTP/2 stream. By default, it does
        not nothing. It must be subclassed to handle each event callback
        method.

        The first callback method invoked is on_headers(). It is called
        when HEADERS frame, which includes response header fields, is
        arrived.

        If response has a body, on_data(data) is invoked for each
        chunk of received data.

        When whole response is received, on_response_done() is invoked.

        When stream is closed or underlying connection is lost,
        on_close(error_code) is called.

        The application can send follow up requests using HTTP2Client.send_request() method.

        The application can handle push resource using on_push_promise() method.

        The following instance variables are available:

        server_address
          Contains a tuple of the form (host, port) referring to the server's
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

        headers
          Response header fields.  There is a special exception.  If this
          object is passed to push_promise(), this instance variable contains
          pushed request header fields.

        """

        def __init__(self, http2=None, stream_id=-1):
            self.headers = []
            self.cookies = []
            # Stream ID. For promised stream, it is initially -1.
            self.stream_id = stream_id
            self.http2 = http2
            # address of the server
            self.remote_address = None
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

        @property
        def server_address(self):
            return self.remote_address

        def on_headers(self):

            '''Called when response HEADERS is arrived.

            '''
            pass

        def on_data(self, data):

            '''Called when a chunk of response body is arrived. This method
            will be called multiple times until all data are received.

            '''
            pass

        def on_response_done(self):

            '''Called when whole response was received

            '''
            pass

        def on_close(self, error_code):

            '''Called when stream is about to close.

            '''
            pass

        def on_push_promise(self, push_promise):

            '''Called when a push is promised. Default behavior is to
            cancel the push. If application overrides this method,
            it should call either accept_push or reject_push.

            '''
            self.reject_push(push_promise)

        def reject_push(self, push_promise):

            '''Convenience method equivalent to calling accept_push
            with a falsy value.

            '''
            self.http2.push(push_promise, None)

        def accept_push(self, push_promise, handler=None):

            '''Accept a push_promise and provider a handler for the
            new stream. If a falsy value is supplied for the handler,
            the push is rejected.

            '''
            self.http2.push(push_promise, handler)

        def resume(self):
            self.http2.resume(self.stream_id)

    class _HTTP2ClientSession(asyncio.Protocol):

        def __init__(self, client):
            asyncio.Protocol.__init__(self)
            self.http2 = None
            self.pending = []
            self.client = client

        def connection_made(self, transport):
            address = transport.get_extra_info('peername')
            logging.info('connection_made, address:%s, port:%s', address[0], address[1])

            self.transport = transport
            sock = self.transport.get_extra_info('socket')
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ssl_ctx = self.transport.get_extra_info('sslcontext')
            if ssl_ctx:
                ssl_obj = self.transport.get_extra_info('ssl_object')
                protocol = negotiated_protocol(ssl_obj)
                if protocol is None or protocol.encode('utf-8') != \
                   cnghttp2.NGHTTP2_PROTO_VERSION_ID:
                    self.transport.abort()

            self.http2 = _HTTP2ClientSessionCore(self.transport)

	    # Clear pending requests
            send_pending = self.pending
            self.pending = []
            for method,scheme,host,path,headers,body,handler in send_pending:
                self.send_request(method=method, scheme=scheme, host=host, path=path,\
                                  headers=headers, body=body, handler=handler)
            self.http2.send_data()

        def connection_lost(self, exc):
            logging.info('connection_lost')
            if self.http2:
                self.http2 = None
            self.client.close()

        def data_received(self, data):
            try:
                self.http2.data_received(data)
            except Exception as err:
                sys.stderr.write(traceback.format_exc())
                self.transport.close()
                return

        def resume_writing(self):
            try:
                self.http2.send_data()
            except Exception as err:
                sys.stderr.write(traceback.format_exc())
                self.transport.close()
                return

        def send_request(self, method, scheme, host, path, headers, body, handler):
            try:
		# Waiting until connection established
                if not self.http2:
                    self.pending.append([method, scheme, host, path, headers, body, handler])
                    return

                self.http2.send_request(method=method, scheme=scheme, host=host, path=path,\
                                        headers=headers, body=body, handler=handler)
                self.http2.send_data()
            except Exception as err:
                sys.stderr.write(traceback.format_exc())
                self.transport.close()
                return

        def close(self):
            if self.http2:
                self.http2.close()


    class HTTP2Client:

        '''HTTP/2 client.

        This class builds on top of the asyncio event loop.

        '''
        def __init__(self, address, loop=None, ssl=None):

            '''address is a tuple of the connect address and port (e.g.,
            ('127.0.0.1', 8080)). The ssl can be ssl.SSLContext instance.
            If it is not None, the resulting client is SSL/TLS capable.
            '''

            self.address = address
            self.session = _HTTP2ClientSession(self)
            def session_factory():
                return self.session

            if ssl:
                set_application_protocol(ssl)

            self.loop = loop
            if not self.loop:
                self.loop = asyncio.get_event_loop()

            coro = self.loop.create_connection(session_factory,
                                           host=address[0], port=address[1],
                                           ssl=ssl)

            if ssl:
                self.scheme = 'https'
            else:
                self.scheme = 'http'

            self.transport,_ = self.loop.run_until_complete(coro)
            logging.info('connect, address:%s, port:%s', self.address[0], self.address[1])

        @property
        def io_loop(self):
            return self.loop

        def close(self):
            self.session.close()

        def send_request(self, method='GET', url='/', headers=None, body=None, handler=None):
            url = urlparse(url)
            scheme = url.scheme if url.scheme else self.scheme
            host = url.netloc if url.netloc else self.address[0]+':'+str(self.address[1])
            path = url.path
            if url.params:
                path += ';'+url.params
            if url.query:
                path += '?'+url.query
            if url.fragment:
                path += '#'+url.fragment

            self.session.send_request(method=method, scheme=scheme, host=host, path=path,\
                                      headers=headers, body=body, handler=handler)
