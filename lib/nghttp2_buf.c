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
#include "nghttp2_buf.h"

void nghttp2_buf_init(nghttp2_buf *buf) {
  buf->begin = buf->end = buf->pos = buf->last = NULL;
}

void nghttp2_buf_wrap_init(nghttp2_buf *buf, uint8_t *src, size_t len) {
  buf->begin = buf->pos = buf->last = src;
  buf->end = buf->begin + len;
}

void nghttp2_buf_free(nghttp2_buf *buf, const nghttp2_mem *mem) {
  nghttp2_mem_free(mem, buf->begin);
}

size_t nghttp2_buf_left(const nghttp2_buf *buf) {
  return (size_t)(buf->end - buf->last);
}

size_t nghttp2_buf_len(const nghttp2_buf *buf) {
  return (size_t)(buf->last - buf->pos);
}

size_t nghttp2_buf_cap(const nghttp2_buf *buf) {
  return (size_t)(buf->end - buf->begin);
}

size_t nghttp2_buf_offset(const nghttp2_buf *buf) {
  return (size_t)(buf->pos - buf->begin);
}

void nghttp2_buf_reset(nghttp2_buf *buf) { buf->pos = buf->last = buf->begin; }

int nghttp2_buf_reserve(nghttp2_buf *buf, size_t size, const nghttp2_mem *mem) {
  uint8_t *p;
  nghttp2_ssize pos_offset, last_offset;

  if ((size_t)(buf->end - buf->begin) >= size) {
    return 0;
  }

  pos_offset = buf->pos - buf->begin;
  last_offset = buf->last - buf->begin;

  p = nghttp2_mem_realloc(mem, buf->begin, size);
  if (p == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  *buf = (nghttp2_buf){
    .begin = p,
    .end = p + size,
    .pos = p + pos_offset,
    .last = p + last_offset,
  };

  return 0;
}

void nghttp2_buf_swap(nghttp2_buf *a, nghttp2_buf *b) {
  nghttp2_buf c = *a;

  *a = *b;
  *b = c;
}
