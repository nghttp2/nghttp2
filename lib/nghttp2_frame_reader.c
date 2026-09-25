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
#include "nghttp2_frame_reader.h"
#include "nghttp2_macro.h"

void nghttp2_frame_reader_server_init(nghttp2_frame_reader *frrd) {
  frrd->state = NGHTTP2_FRAME_READ_STATE_PREFACE;
  frrd->left = nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE);
}

void nghttp2_frame_reader_reset(nghttp2_frame_reader *frrd) {
  frrd->state = NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH;
}

void nghttp2_int_reader_reset(nghttp2_int_reader *ird) {
  *ird = (nghttp2_int_reader){0};
}

uint32_t nghttp2_int_reader_final(nghttp2_int_reader *ird) {
  uint32_t value = ird->value;

  nghttp2_int_reader_reset(ird);

  return value;
}

size_t nghttp2_int_reader_read(nghttp2_int_reader *ird, const uint8_t *src,
                               size_t srclen, size_t fieldlen) {
  const uint8_t *p;
  size_t n;
  size_t i;

  if (ird->left == 0) {
    ird->left = fieldlen;
  }

  n = nghttp2_min(ird->left, srclen);
  p = src;

  for (i = 0; i < n; ++i) {
    ird->value <<= 8;
    ird->value += *p++;
  }

  ird->left -= n;

  return n;
}

int nghttp2_int_reader_done(const nghttp2_int_reader *ird) {
  return ird->left == 0;
}
