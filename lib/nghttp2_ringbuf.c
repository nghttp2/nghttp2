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
#include "nghttp2_ringbuf.h"

#include <assert.h>
#ifdef WIN32
#  include <intrin.h>
#endif /* defined(WIN32) */

#include <string.h>

#include "nghttp2_macro.h"

#ifndef NDEBUG
/* Power-of-two test; simple portable bit trick. */
static int ispow2(size_t n) { return n && !(n & (n - 1)); }
#endif /* !defined(NDEBUG) */

int nghttp2_ringbuf_init(nghttp2_ringbuf *rb, size_t nmemb, size_t size,
                         const nghttp2_mem *mem) {
  uint8_t *buf;

  if (nmemb) {
    assert(ispow2(nmemb));

    buf = nghttp2_mem_malloc(mem, nmemb * size);
    if (buf == NULL) {
      return NGHTTP2_ERR_NOMEM;
    }
  } else {
    buf = NULL;
  }

  nghttp2_ringbuf_buf_init(rb, nmemb, size, buf, mem);

  return 0;
}

void nghttp2_ringbuf_buf_init(nghttp2_ringbuf *rb, size_t nmemb, size_t size,
                              uint8_t *buf, const nghttp2_mem *mem) {
  rb->buf = buf;
  rb->mem = mem;
  rb->mask = nmemb - 1;
  rb->size = size;
  rb->first = 0;
  rb->len = 0;
}

void nghttp2_ringbuf_free(nghttp2_ringbuf *rb) {
  if (rb == NULL) {
    return;
  }

  nghttp2_mem_free(rb->mem, rb->buf);
}

void *nghttp2_ringbuf_push_front(nghttp2_ringbuf *rb) {
  rb->first = (rb->first - 1) & rb->mask;
  if (rb->len < rb->mask + 1) {
    ++rb->len;
  }

  return (void *)&rb->buf[rb->first * rb->size];
}

void *nghttp2_ringbuf_push_back(nghttp2_ringbuf *rb) {
  size_t offset = (rb->first + rb->len) & rb->mask;

  if (rb->len == rb->mask + 1) {
    rb->first = (rb->first + 1) & rb->mask;
  } else {
    ++rb->len;
  }

  return (void *)&rb->buf[offset * rb->size];
}

void nghttp2_ringbuf_pop_front(nghttp2_ringbuf *rb) {
  rb->first = (rb->first + 1) & rb->mask;
  --rb->len;
}

void nghttp2_ringbuf_pop_back(nghttp2_ringbuf *rb) {
  assert(rb->len);
  --rb->len;
}

void nghttp2_ringbuf_resize(nghttp2_ringbuf *rb, size_t len) {
  assert(len <= rb->mask + 1);
  rb->len = len;
}

void *nghttp2_ringbuf_get(const nghttp2_ringbuf *rb, size_t offset) {
  assert(offset < rb->len);
  offset = (rb->first + offset) & rb->mask;

  return &rb->buf[offset * rb->size];
}

int nghttp2_ringbuf_full(const nghttp2_ringbuf *rb) {
  return rb->len == rb->mask + 1;
}

int nghttp2_ringbuf_reserve(nghttp2_ringbuf *rb, size_t nmemb) {
  uint8_t *buf;
  size_t current_nmemb = rb->mask + 1;

  if (current_nmemb >= nmemb) {
    return 0;
  }

  assert(ispow2(nmemb));

  buf = nghttp2_mem_malloc(rb->mem, nmemb * rb->size);
  if (buf == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  if (rb->buf != NULL) {
    if (rb->first + rb->len <= current_nmemb) {
      memcpy(buf, rb->buf + rb->first * rb->size, rb->len * rb->size);
      rb->first = 0;
    } else {
      memcpy(buf, rb->buf + rb->first * rb->size,
             (current_nmemb - rb->first) * rb->size);
      memcpy(buf + (current_nmemb - rb->first) * rb->size, rb->buf,
             (rb->len - (current_nmemb - rb->first)) * rb->size);
      rb->first = 0;
    }

    nghttp2_mem_free(rb->mem, rb->buf);
  }

  rb->buf = buf;
  rb->mask = nmemb - 1;

  return 0;
}
