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
#include "shrpx_http_test.h"

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif // HAVE_UNISTD_H

#include <cstdlib>

#include "munitxx.h"

#include "shrpx_http.h"
#include "shrpx_config.h"
#include "shrpx_log.h"

using namespace std::literals;

namespace shrpx {

namespace {
const MunitTest tests[]{
  munit_void_test(test_shrpx_http_create_forwarded),
  munit_void_test(test_shrpx_http_create_via_header_value),
  munit_void_test(test_shrpx_http_create_affinity_cookie),
  munit_void_test(test_shrpx_http_create_altsvc_header_value),
  munit_void_test(test_shrpx_http_check_http_scheme),
  munit_test_end(),
};
} // namespace

const MunitSuite http_suite{
  "/http", tests, nullptr, 1, MUNIT_SUITE_OPTION_NONE,
};

void test_shrpx_http_create_forwarded(void) {
  BlockAllocator balloc(1024, 1024);

  assert_stdsv_equal(
    "by=\"example.com:3000\";for=\"[::1]\";host=\"www.example.com\";"
    "proto=https"sv,
    http::create_forwarded(
      balloc, FORWARDED_BY | FORWARDED_FOR | FORWARDED_HOST | FORWARDED_PROTO,
      "example.com:3000"sv, "[::1]"sv, "www.example.com"sv, "https"sv));

  assert_stdsv_equal("for=192.168.0.1"sv,
                     http::create_forwarded(balloc, FORWARDED_FOR, "alpha"sv,
                                            "192.168.0.1"sv, "bravo"sv,
                                            "charlie"sv));

  assert_stdsv_equal(
    "by=_hidden;for=\"[::1]\""sv,
    http::create_forwarded(balloc, FORWARDED_BY | FORWARDED_FOR, "_hidden"sv,
                           "[::1]"sv, ""sv, ""sv));

  assert_stdsv_equal(
    "by=\"[::1]\";for=_hidden"sv,
    http::create_forwarded(balloc, FORWARDED_BY | FORWARDED_FOR, "[::1]"sv,
                           "_hidden"sv, ""sv, ""sv));

  assert_stdsv_equal(""sv,
                     http::create_forwarded(balloc,
                                            FORWARDED_BY | FORWARDED_FOR |
                                              FORWARDED_HOST | FORWARDED_PROTO,
                                            ""sv, ""sv, ""sv, ""sv));
}

void test_shrpx_http_create_via_header_value(void) {
  std::array<char, 16> buf;

  auto end = http::create_via_header_value(std::ranges::begin(buf), 1, 1);

  assert_stdstring_equal("1.1 nghttpx",
                         (std::string{std::ranges::begin(buf), end}));

  std::ranges::fill(buf, '\0');

  end = http::create_via_header_value(std::ranges::begin(buf), 2, 0);

  assert_stdstring_equal("2 nghttpx",
                         (std::string{std::ranges::begin(buf), end}));
}

void test_shrpx_http_create_affinity_cookie(void) {
  BlockAllocator balloc(1024, 1024);
  std::string_view c;

  c = http::create_affinity_cookie(balloc, "cookie-val"sv, 0xf1e2d3c4u, ""sv,
                                   false);

  assert_stdsv_equal("cookie-val=f1e2d3c4"sv, c);

  c = http::create_affinity_cookie(balloc, "alpha"sv, 0x00000000u, ""sv, true);

  assert_stdsv_equal("alpha=00000000; Secure"sv, c);

  c = http::create_affinity_cookie(balloc, "bravo"sv, 0x01111111u, "bar"sv,
                                   false);

  assert_stdsv_equal("bravo=01111111; Path=bar"sv, c);

  c = http::create_affinity_cookie(balloc, "charlie"sv, 0x01111111u, "bar"sv,
                                   true);

  assert_stdsv_equal("charlie=01111111; Path=bar; Secure"sv, c);
}

void test_shrpx_http_create_altsvc_header_value(void) {
  {
    BlockAllocator balloc(1024, 1024);
    std::vector<AltSvc> altsvcs{
      AltSvc{
        .protocol_id = "h3"sv,
        .host = "127.0.0.1"sv,
        .service = "443"sv,
        .params = "ma=3600"sv,
      },
    };

    assert_stdsv_equal(R"(h3="127.0.0.1:443"; ma=3600)"sv,
                       http::create_altsvc_header_value(balloc, altsvcs));
  }

  {
    BlockAllocator balloc(1024, 1024);
    std::vector<AltSvc> altsvcs{
      AltSvc{
        .protocol_id = "h3"sv,
        .service = "443"sv,
        .params = "ma=3600"sv,
      },
      AltSvc{
        .protocol_id = "h3%"sv,
        .host = "\"foo\""sv,
        .service = "4433"sv,
      },
    };

    assert_stdsv_equal(R"(h3=":443"; ma=3600, h3%25="\"foo\":4433")"sv,
                       http::create_altsvc_header_value(balloc, altsvcs));
  }
}

void test_shrpx_http_check_http_scheme(void) {
  assert_true(http::check_http_scheme("https"sv, true));
  assert_false(http::check_http_scheme("https"sv, false));
  assert_false(http::check_http_scheme("http"sv, true));
  assert_true(http::check_http_scheme("http"sv, false));
  assert_false(http::check_http_scheme("foo"sv, true));
  assert_false(http::check_http_scheme("foo"sv, false));
  assert_false(http::check_http_scheme(""sv, true));
  assert_false(http::check_http_scheme(""sv, false));
}

} // namespace shrpx
