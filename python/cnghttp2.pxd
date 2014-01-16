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
from libc.stdint cimport uint8_t, uint16_t, uint32_t, int32_t

cdef extern from 'nghttp2/nghttp2.h':

    ctypedef struct nghttp2_nv:
          uint8_t *name
          uint8_t *value
          uint16_t namelen
          uint16_t valuelen

    const char* nghttp2_strerror(int lib_error_code)

cdef extern from 'nghttp2_helper.h':

    void nghttp2_free(void *ptr)

cdef extern from 'nghttp2_frame.h':

    void nghttp2_nv_array_del(nghttp2_nv *nva)

cdef extern from 'nghttp2_hd.h':

    # This is macro
    int NGHTTP2_HD_ENTRY_OVERHEAD

    ctypedef enum nghttp2_hd_side:
        NGHTTP2_HD_SIDE_REQUEST
        NGHTTP2_HD_SIDE_RESPONSE

    ctypedef enum nghttp2_hd_flags:
        NGHTTP2_HD_FLAG_REFSET

    ctypedef struct nghttp2_hd_entry:
        nghttp2_nv nv
        uint8_t flags

    ctypedef struct nghttp2_hd_ringbuf:
        size_t len

    ctypedef struct nghttp2_hd_context:
        nghttp2_hd_ringbuf hd_table

    int nghttp2_hd_deflate_init2(nghttp2_hd_context *deflater,
                                 nghttp2_hd_side side,
                                 size_t deflate_hd_table_bufsize_max)

    int nghttp2_hd_inflate_init(nghttp2_hd_context *inflater,
                                nghttp2_hd_side side)


    void nghttp2_hd_deflate_free(nghttp2_hd_context *deflater)

    void nghttp2_hd_inflate_free(nghttp2_hd_context *inflater)

    void nghttp2_hd_deflate_set_no_refset(nghttp2_hd_context *deflater,
                                          uint8_t no_refset)

    int nghttp2_hd_change_table_size(nghttp2_hd_context *context,
                                     size_t hd_table_bufsize_max)

    ssize_t nghttp2_hd_deflate_hd(nghttp2_hd_context *deflater,
                                  uint8_t **buf_ptr, size_t *buflen_ptr,
                                  size_t nv_offset,
                                  nghttp2_nv *nva, size_t nvlen)

    ssize_t nghttp2_hd_inflate_hd(nghttp2_hd_context *inflater,
                                  nghttp2_nv *nv_out, int *final,
                                  uint8_t *input, size_t inlen)

    int nghttp2_hd_inflate_end_headers(nghttp2_hd_context *inflater)

    nghttp2_hd_entry* nghttp2_hd_table_get(nghttp2_hd_context *context,
                                           size_t index)
