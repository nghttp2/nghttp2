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
#ifndef NGHTTP2_TEST_HELPER_H
#define NGHTTP2_TEST_HELPER_H

#define MUNIT_ENABLE_ASSERT_ALIASES

#include "munit.h"

#include "nghttp2_macro.h"
#include "nghttp2_frame.h"
#include "nghttp2_buf.h"

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    .name = (uint8_t *)(NAME),                                                 \
    .value = (uint8_t *)(VALUE),                                               \
    .namelen = nghttp2_strlen_lit((NAME)),                                     \
    .valuelen = nghttp2_strlen_lit((VALUE)),                                   \
  }

#define MAKE_NV_NEVER_INDEX(NAME, VALUE)                                       \
  {                                                                            \
    .name = (uint8_t *)(NAME),                                                 \
    .value = (uint8_t *)(VALUE),                                               \
    .namelen = nghttp2_strlen_lit((NAME)),                                     \
    .valuelen = nghttp2_strlen_lit((VALUE)),                                   \
    .flags = NGHTTP2_NV_FLAG_NEVER_INDEX,                                      \
  }

void write_settings(nghttp2_buf *dest, const nghttp2_settings_entry *iv,
                    size_t ivlen);

void write_frame(nghttp2_buf *dest, const nghttp2_frame *fr);

void check_http2_preface(nghttp2_buf *data);

#endif /* !defined(NGHTTP2_TEST_HELPER_H) */
