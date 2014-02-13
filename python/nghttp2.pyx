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

HD_DEFLATE_HD_TABLE_BUFSIZE_MAX = 4096

HD_ENTRY_OVERHEAD = cnghttp2.NGHTTP2_HD_ENTRY_OVERHEAD

class HDTableEntry:

    def __init__(self, name, namelen, value, valuelen, ref):
        self.name = name
        self.namelen = namelen
        self.value = value
        self.valuelen = valuelen
        self.ref = ref

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
                                v, entry.nv.valuelen,
                                (entry.flags & cnghttp2.NGHTTP2_HD_FLAG_REFSET) != 0))
    return res

cdef _get_pybytes(uint8_t *b, uint16_t blen):
    return b[:blen]

cdef class HDDeflater:
    '''Performs header compression. The constructor takes
    |hd_table_bufsize_max| parameter, which limits the usage of header
    table in the given amount of bytes. This is necessary because the
    header compressor and decompressor has to share the same amount of
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

    cdef cnghttp2.nghttp2_hd_deflater _deflater

    def __cinit__(self,
                  hd_table_bufsize_max = HD_DEFLATE_HD_TABLE_BUFSIZE_MAX):
        rv = cnghttp2.nghttp2_hd_deflate_init2(&self._deflater,
                                               hd_table_bufsize_max)
        if rv != 0:
            raise Exception(_strerror(rv))

    def __dealloc__(self):
        cnghttp2.nghttp2_hd_deflate_free(&self._deflater)

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
        rv = cnghttp2.nghttp2_hd_deflate_hd(&self._deflater, &out, &outcap,
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
        cnghttp2.nghttp2_hd_deflate_set_no_refset(&self._deflater, no_refset)

    def change_table_size(self, hd_table_bufsize_max):
        '''Changes header table size to |hd_table_bufsize_max| byte.

        An exception will be raised on error.

        '''
        cdef int rv
        rv = cnghttp2.nghttp2_hd_deflate_change_table_size(&self._deflater,
                                                           hd_table_bufsize_max)
        if rv != 0:
            raise Exception(_strerror(rv))

    def get_hd_table(self,):
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

    cdef cnghttp2.nghttp2_hd_inflater _inflater

    def __cinit__(self):
        rv = cnghttp2.nghttp2_hd_inflate_init(&self._inflater)
        if rv != 0:
            raise Exception(_strerror(rv))

    def __dealloc__(self):
        cnghttp2.nghttp2_hd_inflate_free(&self._inflater)

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
            rv = cnghttp2.nghttp2_hd_inflate_hd(&self._inflater, &nv,
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

        cnghttp2.nghttp2_hd_inflate_end_headers(&self._inflater)
        return res

    def change_table_size(self, hd_table_bufsize_max):
        '''Changes header table size to |hd_table_bufsize_max| byte.

        An exception will be raised on error.

        '''
        cdef int rv
        rv = cnghttp2.nghttp2_hd_inflate_change_table_size(&self._inflater,
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

    s=N means the entry occupies N bytes in header table. if r=y, then
    the entry is in the reference set.

    '''
    idx = 0
    for entry in hdtable:
        idx += 1
        print('[{}] (s={}) (r={}) {}: {}'\
              .format(idx, entry.space(),
                      'y' if entry.ref else 'n',
                      entry.name.decode('utf-8'),
                      entry.value.decode('utf-8')))
