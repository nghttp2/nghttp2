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
    "/http", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

void test_shrpx_http_create_forwarded(void) {
  BlockAllocator balloc(1024, 1024);

  assert_stdstring_equal(
      "by=\"example.com:3000\";for=\"[::1]\";host=\"www.example.com\";"
      "proto=https",
      http::create_forwarded(
          balloc,
          FORWARDED_BY | FORWARDED_FOR | FORWARDED_HOST | FORWARDED_PROTO,
          StringRef::from_lit("example.com:3000"), StringRef::from_lit("[::1]"),
          StringRef::from_lit("www.example.com"), StringRef::from_lit("https"))
          .str());

  assert_stdstring_equal(
      "for=192.168.0.1",
      http::create_forwarded(
          balloc, FORWARDED_FOR, StringRef::from_lit("alpha"),
          StringRef::from_lit("192.168.0.1"), StringRef::from_lit("bravo"),
          StringRef::from_lit("charlie"))
          .str());

  assert_stdstring_equal(
      "by=_hidden;for=\"[::1]\"",
      http::create_forwarded(balloc, FORWARDED_BY | FORWARDED_FOR,
                             StringRef::from_lit("_hidden"),
                             StringRef::from_lit("[::1]"),
                             StringRef::from_lit(""), StringRef::from_lit(""))
          .str());

  assert_stdstring_equal(
      "by=\"[::1]\";for=_hidden",
      http::create_forwarded(balloc, FORWARDED_BY | FORWARDED_FOR,
                             StringRef::from_lit("[::1]"),
                             StringRef::from_lit("_hidden"),
                             StringRef::from_lit(""), StringRef::from_lit(""))
          .str());

  assert_stdstring_equal(
      "", http::create_forwarded(
              balloc,
              FORWARDED_BY | FORWARDED_FOR | FORWARDED_HOST | FORWARDED_PROTO,
              StringRef::from_lit(""), StringRef::from_lit(""),
              StringRef::from_lit(""), StringRef::from_lit(""))
              .str());
}

void test_shrpx_http_create_via_header_value(void) {
  std::array<char, 16> buf;

  auto end = http::create_via_header_value(std::begin(buf), 1, 1);

  assert_stdstring_equal("1.1 nghttpx", (std::string{std::begin(buf), end}));

  std::fill(std::begin(buf), std::end(buf), '\0');

  end = http::create_via_header_value(std::begin(buf), 2, 0);

  assert_stdstring_equal("2 nghttpx", (std::string{std::begin(buf), end}));
}

void test_shrpx_http_create_affinity_cookie(void) {
  BlockAllocator balloc(1024, 1024);
  StringRef c;

  c = http::create_affinity_cookie(balloc, StringRef::from_lit("cookie-val"),
                                   0xf1e2d3c4u, StringRef{}, false);

  assert_stdstring_equal("cookie-val=f1e2d3c4", c.str());

  c = http::create_affinity_cookie(balloc, StringRef::from_lit("alpha"),
                                   0x00000000u, StringRef{}, true);

  assert_stdstring_equal("alpha=00000000; Secure", c.str());

  c = http::create_affinity_cookie(balloc, StringRef::from_lit("bravo"),
                                   0x01111111u, StringRef::from_lit("bar"),
                                   false);

  assert_stdstring_equal("bravo=01111111; Path=bar", c.str());

  c = http::create_affinity_cookie(balloc, StringRef::from_lit("charlie"),
                                   0x01111111u, StringRef::from_lit("bar"),
                                   true);

  assert_stdstring_equal("charlie=01111111; Path=bar; Secure", c.str());
}

void test_shrpx_http_create_altsvc_header_value(void) {
  {
    BlockAllocator balloc(1024, 1024);
    std::vector<AltSvc> altsvcs{
        AltSvc{
            .protocol_id = StringRef::from_lit("h3"),
            .host = StringRef::from_lit("127.0.0.1"),
            .service = StringRef::from_lit("443"),
            .params = StringRef::from_lit("ma=3600"),
        },
    };

    assert_stdstring_equal(
        R"(h3="127.0.0.1:443"; ma=3600)",
        http::create_altsvc_header_value(balloc, altsvcs).str());
  }

  {
    BlockAllocator balloc(1024, 1024);
    std::vector<AltSvc> altsvcs{
        AltSvc{
            .protocol_id = StringRef::from_lit("h3"),
            .service = StringRef::from_lit("443"),
            .params = StringRef::from_lit("ma=3600"),
        },
        AltSvc{
            .protocol_id = StringRef::from_lit("h3%"),
            .host = StringRef::from_lit("\"foo\""),
            .service = StringRef::from_lit("4433"),
        },
    };

    assert_stdstring_equal(
        R"(h3=":443"; ma=3600, h3%25="\"foo\":4433")",
        http::create_altsvc_header_value(balloc, altsvcs).str());
  }
}

void test_shrpx_http_check_http_scheme(void) {
  assert_true(http::check_http_scheme(StringRef::from_lit("https"), true));
  assert_false(http::check_http_scheme(StringRef::from_lit("https"), false));
  assert_false(http::check_http_scheme(StringRef::from_lit("http"), true));
  assert_true(http::check_http_scheme(StringRef::from_lit("http"), false));
  assert_false(http::check_http_scheme(StringRef::from_lit("foo"), true));
  assert_false(http::check_http_scheme(StringRef::from_lit("foo"), false));
  assert_false(http::check_http_scheme(StringRef{}, true));
  assert_false(http::check_http_scheme(StringRef{}, false));
}

} // namespace shrpx
