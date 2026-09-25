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
#ifndef NGHTTP2_RINGBUF_H
#define NGHTTP2_RINGBUF_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <nghttp2v2/nghttp2.h>

#include "nghttp2_mem.h"

typedef struct nghttp2_ringbuf {
  /* buf points to the underlying buffer. */
  uint8_t *buf;
  const nghttp2_mem *mem;
  /* mask is the bit mask to cover all bits for the maximum number of
     elements.  The maximum number of elements is mask + 1. */
  size_t mask;
  /* size is the size of each element. */
  size_t size;
  /* first is the offset to the first element. */
  size_t first;
  /* len is the number of elements actually stored. */
  size_t len;
} nghttp2_ringbuf;

/*
 * nghttp2_ringbuf_init initializes |rb|.  |nmemb| is the number of
 * elements that can be stored in this buffer.  |size| is the size of
 * each element.  |nmemb| must be power of 2.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_ringbuf_init(nghttp2_ringbuf *rb, size_t nmemb, size_t size,
                         const nghttp2_mem *mem);

/*
 * nghttp2_ringbuf_buf_init initializes |rb| with given buffer and
 * size.  Same restrictions are applied as nghttp2_ringbuf_init.
 */
void nghttp2_ringbuf_buf_init(nghttp2_ringbuf *rb, size_t nmemb, size_t size,
                              uint8_t *buf, const nghttp2_mem *mem);

/*
 * nghttp2_ringbuf_free frees resources allocated for |rb|.  This
 * function does not free the memory pointed by |rb|.
 */
void nghttp2_ringbuf_free(nghttp2_ringbuf *rb);

/* nghttp2_ringbuf_push_front moves the offset to the first element in
   the buffer backward, and returns the pointer to the element.
   Caller can store data to the buffer pointed by the returned
   pointer.  If this action exceeds the capacity of the ring buffer,
   this function returns the pointer to the last element, and rb->len
   remains unchanged. */
void *nghttp2_ringbuf_push_front(nghttp2_ringbuf *rb);

/* nghttp2_ringbuf_push_back moves the offset to the last element in
   the buffer forward, and returns the pointer to the element.  Caller
   can store data to the buffer pointed by the returned pointer.  If
   this action exceeds the capacity of the ring buffer, this function
   returns the pointer to the first element, and rb->len remains
   unchanged. */
void *nghttp2_ringbuf_push_back(nghttp2_ringbuf *rb);

/*
 * nghttp2_ringbuf_pop_front removes first element in |rb|.
 */
void nghttp2_ringbuf_pop_front(nghttp2_ringbuf *rb);

/*
 * nghttp2_ringbuf_pop_back removes the last element in |rb|.
 */
void nghttp2_ringbuf_pop_back(nghttp2_ringbuf *rb);

/* nghttp2_ringbuf_resize changes the number of elements stored.  This
   does not change the capacity of the underlying buffer. */
void nghttp2_ringbuf_resize(nghttp2_ringbuf *rb, size_t len);

/* nghttp2_ringbuf_get returns the pointer to the element at
   |offset|. */
void *nghttp2_ringbuf_get(const nghttp2_ringbuf *rb, size_t offset);

/* nghttp2_ringbuf_len returns the number of elements stored. */
static inline size_t nghttp2_ringbuf_len(const nghttp2_ringbuf *rb) {
  return rb->len;
}

/* nghttp2_ringbuf_full returns nonzero if |rb| is full. */
int nghttp2_ringbuf_full(const nghttp2_ringbuf *rb);

int nghttp2_ringbuf_reserve(nghttp2_ringbuf *rb, size_t nmemb);

/* nghttp2_static_ringbuf_def defines nghttp2_ringbuf struct wrapper
   which uses a statically allocated buffer.  nghttp2_ringbuf_free
   should never be called for rb field. */
#define nghttp2_static_ringbuf_def(NAME, NMEMB, SIZE)                          \
  typedef struct nghttp2_static_ringbuf_##NAME {                               \
    nghttp2_ringbuf rb;                                                        \
    uint8_t buf[(NMEMB) * (SIZE)];                                             \
  } nghttp2_static_ringbuf_##NAME;                                             \
                                                                               \
  static inline void nghttp2_static_ringbuf_##NAME##_init(                     \
    nghttp2_static_ringbuf_##NAME *srb) {                                      \
    nghttp2_ringbuf_buf_init(&srb->rb, (NMEMB), (SIZE), srb->buf, NULL);       \
  }

#endif /* !defined(NGHTTP2_RINGBUF_H) */
