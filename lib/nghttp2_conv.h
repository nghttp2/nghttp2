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
#ifndef NGHTTP2_CONV_H
#define NGHTTP2_CONV_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <nghttp2v2/nghttp2.h>

/*
 * nghttp2_get_uint32be reads 4 bytes from |p| as 32 bits unsigned
 * integer encoded as network byte order, and stores it in the buffer
 * pointed by |dest| in host byte order.  It returns |p| + 4.
 */
const uint8_t *nghttp2_get_uint32be(uint32_t *dest, const uint8_t *p);

/*
 * nghttp2_get_uint31be reads 4 bytes from |p| as 31 bits unsigned
 * integer encoded as network byte order, and stores it in the buffer
 * pointed by |dest| in host byte order.  It returns |p| + 4.
 */
static inline const uint8_t *nghttp2_get_uint31be(uint32_t *dest,
                                                  const uint8_t *p) {
  p = nghttp2_get_uint32be(dest, p);
  *dest &= INT32_MAX;

  return p;
}

/*
 * nghttp2_get_uint24be reads 3 bytes from |p| as 24 bits unsigned
 * integer encoded as network byte order, and stores it in the buffer
 * pointed by |dest| in host byte order.  It returns |p| + 3.
 */
const uint8_t *nghttp2_get_uint24be(uint32_t *dest, const uint8_t *p);

/*
 * nghttp2_get_uint16be reads 2 bytes from |p| as 16 bits unsigned
 * integer encoded as network byte order, and stores it in the buffer
 * pointed by |dest| in host byte order.  It returns |p| + 2.
 */
const uint8_t *nghttp2_get_uint16be(uint16_t *dest, const uint8_t *p);

/*
 * nghttp2_put_uint32be writes |n| in host byte order in |p| in
 * network byte order.  It returns the one beyond of the last written
 * position.
 */
uint8_t *nghttp2_put_uint32be(uint8_t *p, uint32_t n);

/*
 * nghttp2_put_uint24be writes |n| in host byte order in |p| in
 * network byte order.  It writes only least significant 24 bits.  It
 * returns the one beyond of the last written position.
 */
uint8_t *nghttp2_put_uint24be(uint8_t *p, uint32_t n);

/*
 * nghttp2_put_uint16be writes |n| in host byte order in |p| in
 * network byte order.  It returns the one beyond of the last written
 * position.
 */
uint8_t *nghttp2_put_uint16be(uint8_t *p, uint16_t n);

#endif /* !defined(NGHTTP2_CONV_H) */
