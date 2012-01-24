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
#include "spdylay_buffer.h"

#include <assert.h>
#include <string.h>

void spdylay_buffer_init(spdylay_buffer *buffer, size_t chunk_capacity)
{
  spdylay_queue_init(&buffer->q);
  buffer->capacity = chunk_capacity;
  buffer->len = 0;
  /*
   * Set last_offset to maximum so that first append adds new buffer
   * buffer.
   */
  buffer->last_offset = buffer->capacity;
}

void spdylay_buffer_free(spdylay_buffer *buffer)
{
  while(!spdylay_queue_empty(&buffer->q)) {
    free(spdylay_queue_front(&buffer->q));
    spdylay_queue_pop(&buffer->q);
  }
}

int spdylay_buffer_alloc(spdylay_buffer *buffer)
{
  int r;
  uint8_t *buf = (uint8_t*)malloc(buffer->capacity);
  if(buf == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  if((r = spdylay_queue_push(&buffer->q, buf)) != 0) {
    free(buf);
    return r;
  }
  buffer->len += buffer->capacity-buffer->last_offset;
  buffer->last_offset = 0;
  return 0;
}

uint8_t* spdylay_buffer_get(spdylay_buffer *buffer)
{
  if(spdylay_queue_empty(&buffer->q)) {
    return NULL;
  } else {
    return spdylay_queue_back(&buffer->q)+buffer->last_offset;
  }
}

size_t spdylay_buffer_avail(spdylay_buffer *buffer)
{
  return buffer->capacity-buffer->last_offset;
}

void spdylay_buffer_advance(spdylay_buffer *buffer, size_t amount)
{
  buffer->last_offset += amount;
  buffer->len += amount;
  assert(buffer->last_offset <= buffer->capacity);
}

size_t spdylay_buffer_length(spdylay_buffer *buffer)
{
  return buffer->len;
}

size_t spdylay_buffer_front_length(spdylay_buffer *buffer)
{
  if(spdylay_queue_empty(&buffer->q)) {
    return 0;
  } else if(buffer->len >= buffer->capacity) {
    return buffer->capacity;
  } else {
    return buffer->len;
  }
}

uint8_t* spdylay_buffer_front_data(spdylay_buffer *buffer)
{
  if(spdylay_queue_empty(&buffer->q)) {
    return NULL;
  } else {
    return spdylay_queue_front(&buffer->q);
  }
}

void spdylay_buffer_pop(spdylay_buffer *buffer)
{
  if(!spdylay_queue_empty(&buffer->q)) {
    if(buffer->len >= buffer->capacity) {
      buffer->len -= buffer->capacity;
    } else {
      buffer->len = 0;
      buffer->last_offset = buffer->capacity;
    }
    free(spdylay_queue_front(&buffer->q));
    spdylay_queue_pop(&buffer->q);
  }
}

size_t spdylay_buffer_capacity(spdylay_buffer *buffer)
{
  return buffer->capacity;
}

void spdylay_buffer_serialize(spdylay_buffer *buffer, uint8_t *buf)
{
  while(spdylay_buffer_length(buffer)) {
    size_t len = spdylay_buffer_front_length(buffer);
    memcpy(buf, spdylay_buffer_front_data(buffer), len);
    buf += len;
    spdylay_buffer_pop(buffer);
  }
}
