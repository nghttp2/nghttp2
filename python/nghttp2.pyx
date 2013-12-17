# nghttp2 - HTTP/2.0 C Library

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

HD_SIDE_REQUEST = cnghttp2.NGHTTP2_HD_SIDE_REQUEST
HD_SIDE_RESPONSE = cnghttp2.NGHTTP2_HD_SIDE_RESPONSE

HD_DEFLATE_HD_TABLE_BUFSIZE_MAX = 4096

cdef class _HDContextBase:

    cdef cnghttp2.nghttp2_hd_context _ctx

    def __init__(self):
        pass

    def change_table_size(self, hd_table_bufsize_max):
        '''Changes header table size to |hd_table_bufsize_max| byte.

        An exception will be raised on error.

        '''
        cdef int rv
        rv = cnghttp2.nghttp2_hd_change_table_size(&self._ctx,
                                                   hd_table_bufsize_max)
        if rv != 0:
            raise Exception(_strerror(rv))

cdef class HDDeflater(_HDContextBase):
    '''Performs header compression. The header compression algorithm has
    to know the header set to be compressed is request headers or
    response headers. It is indicated by |side| parameter in the
    constructor. The constructor also takes |hd_table_bufsize_max|
    parameter, which limits the usage of header table in the given
    amount of bytes. This is necessary because the header compressor
    and decompressor has to share the same amount of header table and
    the decompressor decides that number. The compressor may not want
    to use all header table size because of limited memory
    availability. In that case, the |hd_table_bufsize_max| can be used
    to cap the upper limit of talbe size whatever the header table
    size is chosen. The default value of |hd_table_bufsize_max| is
    4096 bytes.

    The following example shows how to compress request header sets:

        import binascii, nghttp2

        deflater = nghttp2.HDDeflater(nghttp2.HD_SIDE_REQUEST)
        res = deflater.deflate([(b'foo', b'bar'),
                              (b'baz', b'buz')])
        print(binascii.b2a_hex(res))

    '''

    def __cinit__(self, side,
                  hd_table_bufsize_max = HD_DEFLATE_HD_TABLE_BUFSIZE_MAX):
        rv = cnghttp2.nghttp2_hd_deflate_init2(&self._ctx, side,
                                               hd_table_bufsize_max)
        if rv != 0:
            raise Exception(_strerror(rv))

    def __init__(self, side,
                 hd_table_bufsize_max = HD_DEFLATE_HD_TABLE_BUFSIZE_MAX):
        super(HDDeflater, self).__init__()

    def __dealloc__(self):
        cnghttp2.nghttp2_hd_deflate_free(&self._ctx)

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
            nvap += 1
        cdef uint8_t *out = NULL
        cdef size_t outcap = 0
        cdef ssize_t rv
        rv = cnghttp2.nghttp2_hd_deflate_hd(&self._ctx, &out, &outcap,
                                            0, nva, len(headers))
        free(nva)
        if rv < 0:
            raise Exception(_strerror(rv))
        cdef bytes res
        try:
            res = out[:rv]
        finally:
            cnghttp2.nghttp2_free(out)
        return res

    def set_no_refset(self, no_refset):
        '''Tells the compressor not to use reference set if |no_refset| is
        nonzero. If |no_refset| is nonzero, on each invocation of
        deflate(), compressor first emits index=0 to clear up
        reference set.

        '''
        cnghttp2.nghttp2_hd_deflate_set_no_refset(&self._ctx, no_refset)

cdef class HDInflater(_HDContextBase):
    '''Performs header decompression.

    The following example shows how to compress request header sets:

        data = b'0082c5ad82bd0f000362617a0362757a'
        inflater = nghttp2.HDInflater(nghttp2.HD_SIDE_REQUEST)
        hdrs = inflater.inflate(data)
        print(hdrs)

    '''

    def __cinit__(self, side):
        rv = cnghttp2.nghttp2_hd_inflate_init(&self._ctx, side)
        if rv != 0:
            raise Exception(_strerror(rv))

    def __init__(self, side):
        super(HDInflater, self).__init__()

    def __dealloc__(self):
        cnghttp2.nghttp2_hd_inflate_free(&self._ctx)

    def inflate(self, data):
        '''Decompresses the compressed header block |data|. The |data| must be
        byte string (not unicode string).

        '''
        cdef cnghttp2.nghttp2_nv *nva
        cdef ssize_t rv

        rv = cnghttp2.nghttp2_hd_inflate_hd(&self._ctx, &nva,
                                            data, len(data))
        if rv < 0:
            raise Exception(_strerror(rv))
        try:
            res = [(nva[i].name[:nva[i].namelen],
                    nva[i].value[:nva[i].valuelen]) for i in range(rv)]
        finally:
            cnghttp2.nghttp2_nv_array_del(nva)
            cnghttp2.nghttp2_hd_end_headers(&self._ctx)
        return res

cdef _strerror(int liberror_code):
    return cnghttp2.nghttp2_strerror(liberror_code).decode('utf-8')
