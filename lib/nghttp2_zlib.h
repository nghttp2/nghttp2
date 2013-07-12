/*
 * nghttp2 - HTTP/2.0 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef NGHTTP2_ZLIB_H
#define NGHTTP2_ZLIB_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */
#include <zlib.h>

#include "nghttp2_buffer.h"

/* This structure is used for both deflater and inflater. */
typedef struct {
  z_stream zst;
  /* The protocol version to select the dictionary later. */
  uint16_t version;
} nghttp2_zlib;

/*
 * Initializes |deflater| for deflating name/values pairs in the frame
 * of the protocol version |version|. If the |comp| is zero,
 * compression level becomes 0, which means no compression.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_ZLIB
 *     The z_stream initialization failed.
 * NGHTTP2_ERR_UNSUPPORTED_VERSION
 *     The version is not supported.
 */
int nghttp2_zlib_deflate_hd_init(nghttp2_zlib *deflater, int comp,
                                 uint16_t version);

/*
 * Initializes |inflater| for inflating name/values pairs in the
 * frame of the protocol version |version|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_ZLIB
 *     The z_stream initialization failed.
 * NGHTTP2_ERR_UNSUPPORTED_VERSION
 *     The version is not supported.
 */
int nghttp2_zlib_inflate_hd_init(nghttp2_zlib *inflater, uint16_t version);

/*
 * Deallocates any resources allocated for |deflater|.
 */
void nghttp2_zlib_deflate_free(nghttp2_zlib *deflater);

/*
 * Deallocates any resources allocated for |inflater|.
 */
void nghttp2_zlib_inflate_free(nghttp2_zlib *inflater);

/*
 * Returns the maximum length when |len| bytes of data are deflated by
 * |deflater|.
 */
size_t nghttp2_zlib_deflate_hd_bound(nghttp2_zlib *deflater, size_t len);

/*
 * Deflates data stored in |in| with length |inlen|. The output is
 * written to |out| with length |outlen|. This is not a strict
 * requirement but |outlen| should have at least
 * nghttp2_zlib_deflate_hd_bound(|inlen|) bytes for successful
 * operation.
 *
 * This function returns the number of bytes outputted if it succeeds,
 * or one of the following negative error codes:
 *
 * NGHTTP2_ERR_ZLIB
 *     The deflate operation failed.
 */
ssize_t nghttp2_zlib_deflate_hd(nghttp2_zlib *deflater,
                                uint8_t *out, size_t outlen,
                                const uint8_t *in, size_t inlen);

/*
 * Inflates data stored in |in| with length |inlen|.  The output is
 * added to |buf|.
 *
 * This function returns the number of bytes outputted if it succeeds,
 * or one of the following negative error codes:
 *
 * NGHTTP2_ERR_ZLIB
 *     The inflate operation failed.
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
ssize_t nghttp2_zlib_inflate_hd(nghttp2_zlib *inflater,
                                nghttp2_buffer* buf,
                                const uint8_t *in, size_t inlen);

#endif /* NGHTTP2_ZLIB_H */
