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
  buffer->root.data = NULL;
  buffer->root.next = NULL;
  buffer->current = &buffer->root;
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
  spdylay_buffer_chunk *p = buffer->root.next;
  while(p) {
    spdylay_buffer_chunk *next = p->next;
    free(p->data);
    free(p);
    p = next;
  }
}

int spdylay_buffer_alloc(spdylay_buffer *buffer)
{
  if(buffer->current->next == NULL) {
    spdylay_buffer_chunk *chunk;
    uint8_t *buf;
    chunk = malloc(sizeof(spdylay_buffer_chunk));
    if(chunk == NULL) {
      return SPDYLAY_ERR_NOMEM;
    }
    buf = malloc(buffer->capacity);
    if(buf == NULL) {
      free(chunk);
      return SPDYLAY_ERR_NOMEM;
    }
    chunk->data = buf;
    chunk->next = NULL;
    buffer->current->next = chunk;
    buffer->current = chunk;
  } else {
    buffer->current = buffer->current->next;
  }
  buffer->len += buffer->capacity-buffer->last_offset;
  buffer->last_offset = 0;
  return 0;
}

uint8_t* spdylay_buffer_get(spdylay_buffer *buffer)
{
  if(buffer->current->data == NULL) {
    return NULL;
  } else {
    return buffer->current->data+buffer->last_offset;
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

size_t spdylay_buffer_capacity(spdylay_buffer *buffer)
{
  return buffer->capacity;
}

void spdylay_buffer_serialize(spdylay_buffer *buffer, uint8_t *buf)
{
  spdylay_buffer_chunk *p = buffer->root.next;
  for(; p; p = p->next) {
    size_t len;
    if(p == buffer->current) {
      len = buffer->last_offset;
    } else {
      len = buffer->capacity;
    }
    memcpy(buf, p->data, len);
    buf += len;
  }
}

void spdylay_buffer_reset(spdylay_buffer *buffer)
{
  buffer->current = &buffer->root;
  buffer->len = 0;
  buffer->last_offset = buffer->capacity;
}
