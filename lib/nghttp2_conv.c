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
#include "nghttp2_conv.h"

#include <string.h>

#include "nghttp2_net.h"
#include "nghttp2_str.h"

const uint8_t *nghttp2_get_uint32be(uint32_t *dest, const uint8_t *p) {
  memcpy(dest, p, sizeof(*dest));
  *dest = nghttp2_ntohl(*dest);
  return p + sizeof(*dest);
}

const uint8_t *nghttp2_get_uint24be(uint32_t *dest, const uint8_t *p) {
  *dest = 0;
  memcpy(((uint8_t *)dest) + 1, p, 3);
  *dest = nghttp2_ntohl(*dest);
  return p + 3;
}

const uint8_t *nghttp2_get_uint16be(uint16_t *dest, const uint8_t *p) {
  memcpy(dest, p, sizeof(*dest));
  *dest = nghttp2_ntohs(*dest);
  return p + sizeof(*dest);
}

uint8_t *nghttp2_put_uint32be(uint8_t *p, uint32_t n) {
  n = nghttp2_htonl(n);
  return nghttp2_cpymem(p, (const uint8_t *)&n, sizeof(n));
}

uint8_t *nghttp2_put_uint24be(uint8_t *p, uint32_t n) {
  n = nghttp2_htonl(n);
  return nghttp2_cpymem(p, ((const uint8_t *)&n) + 1, 3);
}

uint8_t *nghttp2_put_uint16be(uint8_t *p, uint16_t n) {
  n = nghttp2_htons(n);
  return nghttp2_cpymem(p, (const uint8_t *)&n, sizeof(n));
}
