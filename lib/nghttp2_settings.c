/*
 * nghttp2 - HTTP/2 C Library
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
#include "nghttp2_settings.h"

void nghttp2_settings_default(nghttp2_settings *settings) {
  *settings = (nghttp2_settings){
    .hpack_max_dtable_capacity = NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY,
    .hpack_encoder_max_dtable_capacity = NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY,
    .max_concurrent_streams_local = 100,
    .initial_max_stream_data = NGHTTP2_INITIAL_WINDOW_SIZE,
    .initial_max_data = NGHTTP2_INITIAL_WINDOW_SIZE,
    .settings_timeout = 10 * NGHTTP2_SECONDS,
    .glitch_ratelim_burst = 10000,
    .glitch_ratelim_rate = 330,
  };
}
