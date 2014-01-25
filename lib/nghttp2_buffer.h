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
#ifndef NGHTTP2_BUFFER_H
#define NGHTTP2_BUFFER_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <nghttp2/nghttp2.h>

#include "nghttp2_int.h"

/*
 * Byte array buffer
 */
typedef struct {
  uint8_t *buf;
  /* Capacity of this buffer */
  size_t capacity;
  /* How many bytes are written to buf. len <= capacity must hold. */
  size_t len;
  /* Maximum capacity this buffer can grow up */
  size_t max_capacity;
} nghttp2_buffer;

void nghttp2_buffer_init(nghttp2_buffer *buffer, size_t max_capacity);

void nghttp2_buffer_free(nghttp2_buffer *buffer);

/*
 * Expands capacity so that it can contain at least |len| bytes of
 * data. If buffer->capacity >= len, no action is taken. If len >
 * buffer->max_capacity, NGHTTP2_ERR_BUFFER_ERROR is returned.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_BUFFER_ERROR
 *   The |len| is strictly larger than buffer->max_capacity
 * NGHTTP2_ERR_NOMEM
 *   Out of memory
 */
int nghttp2_buffer_reserve(nghttp2_buffer *buffer, size_t len);

/*
 * Appends the |data| with |len| bytes to the buffer. The data is
 * copied. The |buffer| will be expanded as needed.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_BUFFER_ERROR
 *   The |len| is strictly larger than buffer->max_capacity
 * NGHTTP2_ERR_NOMEM
 *   Out of memory
 */
int nghttp2_buffer_add(nghttp2_buffer *buffer,
                       const uint8_t *data, size_t len);

/*
 * Appends the a single byte|b| to the buffer. The data is copied. The
 * |buffer| will be expanded as needed.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_BUFFER_ERROR
 *   The |len| is strictly larger than buffer->max_capacity
 * NGHTTP2_ERR_NOMEM
 *   Out of memory
 */
int nghttp2_buffer_add_byte(nghttp2_buffer *buffer, uint8_t b);

/*
 * Releases the buffer without freeing it. The data members in buffer
 * is initialized.
 */
void nghttp2_buffer_release(nghttp2_buffer *buffer);

#endif /* NGHTTP2_BUFFER_H */
