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
#ifndef NGHTTP2_STR_H
#define NGHTTP2_STR_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <nghttp2v2/nghttp2.h>

void *nghttp2_cpymem(void *dest, const void *src, size_t n);

/*
 * nghttp2_setmem writes a string of length |n| consisting only |b| to
 * the buffer pointed by |dest|.  It returns dest + n;
 */
uint8_t *nghttp2_setmem(uint8_t *dest, uint8_t b, size_t n);

/*
 * nghttp2_encode_hex encodes |data| of length |len| in hex string.
 * The buffer pointed by |dest| must have at least |len| * 2 bytes
 * space.  This function returns |dest| + |len| * 2.
 */
uint8_t *nghttp2_encode_hex(uint8_t *dest, const uint8_t *data, size_t len);

/*
 * nghttp2_encode_uint_hexlen returns the number of bytes
 * nghttp2_encode_uint_hex produces when |n| is given.
 */
size_t nghttp2_encode_uint_hexlen(uint64_t n);

/*
 * nghttp2_encode_uint_hex encodes |n| in hex string.  It omits the
 * leading zeros (e.g., 1fb).  The buffer pointed by |dest| must have
 * at least nghttp2_encode_uint_hexlen(|n|) bytes.  This function
 * returns |dest| + the number of bytes written.
 */
uint8_t *nghttp2_encode_uint_hex(uint8_t *dest, uint64_t n);

/*
 * nghttp2_encode_uintlen returns the number of bytes
 * nghttp2_encode_uint produces when |n| is given.
 */
size_t nghttp2_encode_uintlen(uint64_t n);

/*
 * nghttp2_encode_uint encodes |n| as a decimal integer to the buffer
 * pointed by |dest|.  This function assumes that the buffer contains
 * the sufficient capacity to write the number.  This function returns
 * the pointer to the buffer past the last byte written.
 */
uint8_t *nghttp2_encode_uint(uint8_t *dest, uint64_t n);

/*
 * nghttp2_encode_printable_ascii encodes |data| of length |len| in
 * |dest| in the following manner: printable ascii characters are
 * copied as is.  The other characters are converted to ".".  |dest|
 * must have at least |len|.  This function returns |dest| + the
 * number of bytes written.
 */
uint8_t *nghttp2_encode_printable_ascii(uint8_t *dest, const uint8_t *data,
                                        size_t len);

void nghttp2_downcase(uint8_t *s, size_t len);

extern const uint8_t nghttp2_downcase_tbl[];

/*
 * nghttp2_downcase_byte returns the lower case version of |c| if 'A'
 * <= |c| && |c| <= 'Z'.  Otherwise, it returns |c|.
 */
static inline uint8_t nghttp2_downcase_byte(uint8_t c) {
  return nghttp2_downcase_tbl[c];
}

#endif /* !defined(NGHTTP2_STR_H) */
