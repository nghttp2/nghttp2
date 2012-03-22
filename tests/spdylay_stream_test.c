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
#include "spdylay_stream_test.h"

#include <CUnit/CUnit.h>

#include "spdylay_stream.h"

void test_spdylay_stream_add_pushed_stream(void)
{
  spdylay_stream stream;
  int i, n;
  spdylay_stream_init(&stream, 1, SPDYLAY_CTRL_FLAG_NONE, 3, 65536,
                      SPDYLAY_STREAM_OPENING, NULL);
  n = 26;
  for(i = 2; i < n; i += 2) {
    CU_ASSERT(0 == spdylay_stream_add_pushed_stream(&stream, i));
    CU_ASSERT((size_t)i/2 == stream.pushed_streams_length);
  }
  for(i = 2; i < n; i += 2) {
    CU_ASSERT(i == stream.pushed_streams[i/2-1]);
  }
  spdylay_stream_free(&stream);
}
