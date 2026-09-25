/*
 * nghttp2
 *
 * Copyright (c) 2026 nghttp2 contributors
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
#ifndef NGHTTP2_BUF_H
#define NGHTTP2_BUF_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <nghttp2v2/nghttp2.h>

#include "nghttp2_mem.h"

void nghttp2_buf_wrap_init(nghttp2_buf *buf, uint8_t *src, size_t len);

/*
 * nghttp2_buf_cap returns the capacity of the buffer.  In other
 * words, it returns buf->end - buf->begin.
 */
size_t nghttp2_buf_cap(const nghttp2_buf *buf);

/*
 * nghttp2_buf_offset returns the distance from tbuf->begin to
 * tbuf->pos.  In other words, it returns buf->pos - buf->begin.
 */
size_t nghttp2_buf_offset(const nghttp2_buf *buf);

int nghttp2_buf_reserve(nghttp2_buf *buf, size_t size, const nghttp2_mem *mem);

/*
 * nghttp2_buf_swap swaps |a| and |b|.
 */
void nghttp2_buf_swap(nghttp2_buf *a, nghttp2_buf *b);

#endif /* !defined(NGHTTP2_BUF_H) */
