/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2025 nghttp2 contributors
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
#include "siphash_test.h"

#include <cstring>
#include <array>
#include <numeric>

#include "munitxx.h"

#include <nghttp2/nghttp2.h>

#include "siphash.h"

namespace nghttp2 {

namespace {
const MunitTest tests[]{
  munit_void_test(test_siphash),
  munit_test_end(),
};
} // namespace

const MunitSuite siphash_suite{
  "/siphash", tests, nullptr, 1, MUNIT_SUITE_OPTION_NONE,
};

void test_siphash(void) {
  std::array<uint8_t, 16> key_bytes;
  std::iota(std::ranges::begin(key_bytes), std::ranges::end(key_bytes), 0);

  std::array<uint64_t, 2> key;
  memcpy(key.data(), key_bytes.data(), key_bytes.size());

  if constexpr (std::endian::native == std::endian::big) {
    key[0] = byteswap(key[0]);
    key[1] = byteswap(key[1]);
  }

  std::array<uint8_t, 15> input;
  std::iota(std::ranges::begin(input), std::ranges::end(input), 0);

  assert_uint64(0xa129ca6149be45e5ull, ==, siphash24(key, input));
}

} // namespace nghttp2
