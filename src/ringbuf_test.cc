/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
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
#include "ringbuf_test.h"

#include <cstring>
#include <iostream>
#include <tuple>

#include <CUnit/CUnit.h>

#include <nghttp2/nghttp2.h>

#include "ringbuf.h"

namespace nghttp2 {

void test_ringbuf_write(void) {
  RingBuf<16> b;
  CU_ASSERT(0 == b.rleft());
  CU_ASSERT(16 == b.wleft());

  b.write("012", 3);

  CU_ASSERT(3 == b.rleft());
  CU_ASSERT(13 == b.wleft());
  CU_ASSERT(0 == b.pos);
  CU_ASSERT(3 == b.len);

  b.drain(3);

  CU_ASSERT(0 == b.rleft());
  CU_ASSERT(16 == b.wleft());
  CU_ASSERT(3 == b.pos);
  CU_ASSERT(0 == b.len);

  b.write("0123456789ABCDEF", 16);

  CU_ASSERT(16 == b.rleft());
  CU_ASSERT(0 == b.wleft());
  CU_ASSERT(3 == b.pos);
  CU_ASSERT(16 == b.len);
  CU_ASSERT(0 == memcmp(b.begin, "DEF0123456789ABC", 16));

  const void *p;
  size_t len;
  std::tie(p, len) = b.get();
  CU_ASSERT(13 == len);
  CU_ASSERT(0 == memcmp(p, "0123456789ABC", len));

  b.drain(14);

  CU_ASSERT(2 == b.rleft());
  CU_ASSERT(14 == b.wleft());
  CU_ASSERT(1 == b.pos);
  CU_ASSERT(2 == b.len);

  std::tie(p, len) = b.get();
  CU_ASSERT(2 == len);
  CU_ASSERT(0 == memcmp(p, "EF", len));
}

void test_ringbuf_iovec(void) {
  RingBuf<16> b;
  struct iovec iov[2];

  auto rv = b.riovec(iov);

  CU_ASSERT(0 == rv);

  rv = b.wiovec(iov);

  CU_ASSERT(1 == rv);
  CU_ASSERT(b.begin == iov[0].iov_base);
  CU_ASSERT(16 == iov[0].iov_len);

  // set pos to somewhere middle of the buffer, this will require 2
  // iovec for writing.
  b.pos = 6;

  rv = b.riovec(iov);

  CU_ASSERT(0 == rv);

  rv = b.wiovec(iov);

  CU_ASSERT(2 == rv);
  CU_ASSERT(b.begin + b.pos == iov[0].iov_base);
  CU_ASSERT(10 == iov[0].iov_len);
  CU_ASSERT(b.begin == iov[1].iov_base);
  CU_ASSERT(6 == iov[1].iov_len);

  // occupy first region of buffer
  b.pos = 0;
  b.len = 10;

  rv = b.riovec(iov);

  CU_ASSERT(1 == rv);
  CU_ASSERT(b.begin == iov[0].iov_base);
  CU_ASSERT(10 == iov[0].iov_len);

  rv = b.wiovec(iov);

  CU_ASSERT(1 == rv);
  CU_ASSERT(b.begin + b.len == iov[0].iov_base);
  CU_ASSERT(6 == iov[0].iov_len);

  // occupy last region of buffer
  b.pos = 6;
  b.len = 10;

  rv = b.riovec(iov);

  CU_ASSERT(1 == rv);
  CU_ASSERT(b.begin + b.pos == iov[0].iov_base);
  CU_ASSERT(10 == iov[0].iov_len);

  rv = b.wiovec(iov);

  CU_ASSERT(1 == rv);
  CU_ASSERT(b.begin == iov[0].iov_base);
  CU_ASSERT(6 == iov[0].iov_len);

  // occupy middle of buffer
  b.pos = 3;
  b.len = 10;

  rv = b.riovec(iov);

  CU_ASSERT(1 == rv);
  CU_ASSERT(b.begin + b.pos == iov[0].iov_base);
  CU_ASSERT(10 == iov[0].iov_len);

  rv = b.wiovec(iov);

  CU_ASSERT(2 == rv);
  CU_ASSERT(b.begin + b.pos + b.len == iov[0].iov_base);
  CU_ASSERT(3 == iov[0].iov_len);
  CU_ASSERT(b.begin == iov[1].iov_base);
  CU_ASSERT(3 == iov[1].iov_len);

  // crossover
  b.pos = 13;
  b.len = 10;

  rv = b.riovec(iov);

  CU_ASSERT(2 == rv);
  CU_ASSERT(b.begin + b.pos == iov[0].iov_base);
  CU_ASSERT(3 == iov[0].iov_len);
  CU_ASSERT(b.begin == iov[1].iov_base);
  CU_ASSERT(7 == iov[1].iov_len);

  rv = b.wiovec(iov);

  CU_ASSERT(1 == rv);
  CU_ASSERT(b.begin + 7 == iov[0].iov_base);
  CU_ASSERT(6 == iov[0].iov_len);
}

} // namespace nghttp2
