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
#include "nghttp2_vec.h"
#include "nghttp2_macro.h"

uint64_t nghttp2_vec_len(const nghttp2_vec *vec, size_t n) {
  size_t i;
  uint64_t res = 0;

  for (i = 0; i < n; ++i) {
    res += vec[i].len;
  }

  return res;
}

int nghttp2_vec_len_max_int(uint64_t *dest, const nghttp2_vec *vec, size_t n) {
  uint64_t res = 0;
  size_t len;
  size_t i;

  for (i = 0; i < n; ++i) {
    len = vec[i].len;
    if (len > NGHTTP2_MAX_INT - res) {
      return -1;
    }

    res += len;
  }

  *dest = res;

  return 0;
}
