/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2016 Tatsuhiro Tsujikawa
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
#include "base64_test.h"

#include <cstring>

#include <nghttp2/nghttp2.h>

#include "base64.h"

using namespace std::literals;

namespace nghttp2 {

namespace {
const MunitTest tests[]{
  munit_void_test(test_base64_encode),
  munit_void_test(test_base64_decode),
  munit_test_end(),
};
} // namespace

const MunitSuite base64_suite{
  .prefix = "/base64",
  .tests = tests,
};

void test_base64_encode(void) {
  assert_eq("/w==", base64::encode("\xff"sv));
  assert_eq("//4=", base64::encode("\xff\xfe"sv));
  assert_eq("//79", base64::encode("\xff\xfe\xfd"sv));
  assert_eq("//79/A==", base64::encode("\xff\xfe\xfd\xfc"sv));
}

void test_base64_decode(void) {
  BlockAllocator balloc(4096, 4096);

  assert_eq("\xff"sv, as_string_view(base64::decode(balloc, "/w=="sv)));
  assert_eq("\xff\xfe"sv, as_string_view(base64::decode(balloc, "//4="sv)));
  assert_eq("\xff\xfe\xfd"sv, as_string_view(base64::decode(balloc, "//79"sv)));
  assert_eq("\xff\xfe\xfd\xfc"sv,
            as_string_view(base64::decode(balloc, "//79/A=="sv)));

  // we check the number of valid input must be multiples of 4
  assert_eq(""sv, as_string_view(base64::decode(balloc, "//79="sv)));

  // ending invalid character at the boundary of multiples of 4 is
  // bad
  assert_eq(""sv, as_string_view(base64::decode(balloc, "bmdodHRw\n"sv)));

  // after seeing '=', subsequent input must be also '='.
  assert_eq(""sv, as_string_view(base64::decode(balloc, "//79/A=A"sv)));

  // additional '=' at the end is bad
  assert_eq(""sv, as_string_view(base64::decode(balloc, "//79/A======"sv)));

  // Chars with high bit set
  assert_eq(""sv, as_string_view(base64::decode(balloc, "\xCA\xFE\xCA\xCE"sv)));
}

} // namespace nghttp2
