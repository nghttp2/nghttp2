/*
 * nghttp2 - HTTP/2.0 C Library
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
#ifndef NGHTTP2_TEST_HELPER_H
#define NGHTTP2_TEST_HELPER_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include "nghttp2_frame.h"
#include "nghttp2_hd.h"

#define MAKE_NV(NAME, VALUE)                                            \
  { (uint8_t*)NAME, (uint8_t*)VALUE, strlen(NAME), strlen(VALUE) }
#define ARRLEN(ARR) (sizeof(ARR)/sizeof(ARR[0]))

#define assert_nv_equal(A, B, len)                          \
  do {                                                      \
    size_t alloclen = sizeof(nghttp2_nv) * len;             \
    nghttp2_nv *sa = A, *sb = B;                            \
    nghttp2_nv *a = malloc(alloclen);                       \
    nghttp2_nv *b = malloc(alloclen);                       \
    ssize_t i_;                                             \
    memcpy(a, sa, alloclen);                                \
    memcpy(b, sb, alloclen);                                \
    nghttp2_nv_array_sort(a, len);                          \
    nghttp2_nv_array_sort(b, len);                          \
    for(i_ = 0; i_ < (ssize_t)len; ++i_) {                  \
      CU_ASSERT(nghttp2_nv_equal(&a[i_], &b[i_]));          \
    }                                                       \
    free(b);                                                \
    free(a);                                                \
  } while(0);

int unpack_frame(nghttp2_frame *frame, const uint8_t *in, size_t len);

int strmemeq(const char *a, const uint8_t *b, size_t bn);

int nvnameeq(const char *a, nghttp2_nv *nv);

int nvvalueeq(const char *a, nghttp2_nv *nv);

typedef struct {
  nghttp2_nv nva[256];
  size_t nvlen;
} nva_out;

void nva_out_init(nva_out *out);
void nva_out_reset(nva_out *out);

void add_out(nva_out *out, nghttp2_nv *nv);

ssize_t inflate_hd(nghttp2_hd_inflater *inflater, nva_out *out,
                   uint8_t *buf, size_t buflen);

#endif /* NGHTTP2_TEST_HELPER_H */
