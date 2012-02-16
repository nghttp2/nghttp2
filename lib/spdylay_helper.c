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
#include "spdylay_helper.h"

#include <string.h>
#include <arpa/inet.h>

void spdylay_put_uint16be(uint8_t *buf, uint16_t n)
{
  uint16_t x = htons(n);
  memcpy(buf, &x, sizeof(uint16_t));
}

void spdylay_put_uint32be(uint8_t *buf, uint32_t n)
{
  uint32_t x = htonl(n);
  memcpy(buf, &x, sizeof(uint32_t));
}

uint16_t spdylay_get_uint16(const uint8_t *data)
{
  uint16_t n;
  memcpy(&n, data, sizeof(uint16_t));
  return ntohs(n);
}

uint32_t spdylay_get_uint32(const uint8_t *data)
{
  uint32_t n;
  memcpy(&n, data, sizeof(uint32_t));
  return ntohl(n);
}

int spdylay_reserve_buffer(uint8_t **buf_ptr, size_t *buflen_ptr,
                           size_t min_length)
{
  if(min_length > *buflen_ptr) {
    min_length = (min_length+4095)/4096*4096;
    uint8_t *temp = malloc(min_length);
    if(temp == NULL) {
      return SPDYLAY_ERR_NOMEM;
    } else {
      free(*buf_ptr);
      *buf_ptr = temp;
      *buflen_ptr = min_length;
    }
  }
  return 0;
}
