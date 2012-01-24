/*
 * Spdylay - SPDY Library
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
#ifndef SPDYLAY_ZLIB_H
#define SPDYLAY_ZLIB_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */
#include <zlib.h>

#include "spdylay_buffer.h"

typedef struct {
  z_stream zst;
} spdylay_zlib;

int spdylay_zlib_deflate_hd_init(spdylay_zlib *deflater);

int spdylay_zlib_inflate_hd_init(spdylay_zlib *inflater);

void spdylay_zlib_deflate_free(spdylay_zlib *zlib);

void spdylay_zlib_inflate_free(spdylay_zlib *zlib);

size_t spdylay_zlib_deflate_hd_bound(spdylay_zlib *deflater, size_t len);

ssize_t spdylay_zlib_deflate_hd(spdylay_zlib *deflater,
                                uint8_t *out, size_t outlen,
                                const uint8_t *in, size_t inlen);

ssize_t spdylay_zlib_inflate_hd(spdylay_zlib *inflater,
                                spdylay_buffer* buf,
                                const uint8_t *in, size_t inlen);

#endif /* SPDYLAY_ZLIB_H */
