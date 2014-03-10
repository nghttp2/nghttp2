/*
 * nghttp2 - HTTP/2.0 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
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

#include "nghttp2_helper.h"

void nghttp2_buf_init(nghttp2_buf *buf)
{
  buf->begin = NULL;
  buf->end = NULL;
  buf->pos = NULL;
  buf->last = NULL;
  buf->mark = NULL;
}

int nghttp2_buf_init2(nghttp2_buf *buf, size_t initial)
{
  nghttp2_buf_init(buf);
  return nghttp2_buf_reserve(buf, initial);
}

void nghttp2_buf_free(nghttp2_buf *buf)
{
  free(buf->begin);
}

int nghttp2_buf_reserve(nghttp2_buf *buf, size_t new_cap)
{
  uint8_t *ptr;
  size_t cap;

  cap = nghttp2_buf_cap(buf);

  if(cap >= new_cap) {
    return 0;
  }

  new_cap = nghttp2_max(new_cap, cap * 2);

  ptr = realloc(buf->begin, new_cap);
  if(ptr == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  buf->pos = ptr + (buf->pos - buf->begin);
  buf->last = ptr + (buf->last - buf->begin);
  buf->mark = ptr + (buf->mark - buf->begin);
  buf->begin = ptr;
  buf->end = ptr + new_cap;

  return 0;
}

int nghttp2_buf_pos_reserve(nghttp2_buf *buf, size_t new_rel_cap)
{
  return nghttp2_buf_reserve(buf, nghttp2_buf_pos_offset(buf) + new_rel_cap);
}

int nghttp2_buf_last_reserve(nghttp2_buf *buf, size_t new_rel_cap)
{
  return nghttp2_buf_reserve(buf, nghttp2_buf_last_offset(buf) + new_rel_cap);
}

void nghttp2_buf_reset(nghttp2_buf *buf)
{
  buf->pos = buf->last = buf->mark = buf->begin;
}

void nghttp2_buf_wrap_init(nghttp2_buf *buf, uint8_t *begin, size_t len)
{
  buf->begin = buf->pos = buf->last = buf->mark = begin;
  buf->end = begin + len;
}
