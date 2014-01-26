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
#include "nghttp2_buffer.h"

#include <assert.h>
#include <string.h>

#include "nghttp2_helper.h"

void nghttp2_buffer_init(nghttp2_buffer *buffer, size_t max_capacity)
{
  buffer->buf = NULL;
  buffer->len = 0;
  buffer->capacity = 0;
  buffer->max_capacity = max_capacity;
}

void nghttp2_buffer_free(nghttp2_buffer *buffer)
{
  free(buffer->buf);
}

int nghttp2_buffer_reserve(nghttp2_buffer *buffer, size_t len)
{
  if(len > buffer->max_capacity) {
    return NGHTTP2_ERR_BUFFER_ERROR;
  }
  if(buffer->capacity < len) {
    uint8_t *new_buf;
    size_t new_cap = buffer->capacity == 0 ? 8 : buffer->capacity * 3 / 2;
    new_cap = nghttp2_min(buffer->max_capacity, nghttp2_max(new_cap, len));
    new_buf = realloc(buffer->buf, new_cap);
    if(new_buf == NULL) {
      return NGHTTP2_ERR_NOMEM;
    }
    buffer->buf = new_buf;
    buffer->capacity = new_cap;
  }
  return 0;
}

int nghttp2_buffer_add(nghttp2_buffer *buffer,
                       const uint8_t *data, size_t len)
{
  int rv;
  rv = nghttp2_buffer_reserve(buffer, buffer->len + len);
  if(rv != 0) {
    return rv;
  }
  memcpy(buffer->buf + buffer->len, data, len);
  buffer->len += len;
  return 0;
}

int nghttp2_buffer_add_byte(nghttp2_buffer *buffer, uint8_t b)
{
  int rv;
  rv = nghttp2_buffer_reserve(buffer, buffer->len + 1);
  if(rv != 0) {
    return rv;
  }
  buffer->buf[buffer->len] = b;
  ++buffer->len;
  return 0;
}

void nghttp2_buffer_release(nghttp2_buffer *buffer)
{
  buffer->buf = NULL;
  buffer->len = 0;
  buffer->capacity = 0;
}
