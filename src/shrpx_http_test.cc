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
#include <unistd.h>
#endif // HAVE_UNISTD_H

#include <cstdlib>

#include <CUnit/CUnit.h>

#include "shrpx_http.h"
#include "shrpx_config.h"

namespace shrpx {

void test_shrpx_http_create_forwarded(void) {
  BlockAllocator balloc(1024, 1024);

  CU_ASSERT("by=\"example.com:3000\";for=\"[::1]\";host=\"www.example.com\";"
            "proto=https" ==
            http::create_forwarded(balloc, FORWARDED_BY | FORWARDED_FOR |
                                               FORWARDED_HOST | FORWARDED_PROTO,
                                   StringRef::from_lit("example.com:3000"),
                                   StringRef::from_lit("[::1]"),
                                   StringRef::from_lit("www.example.com"),
                                   StringRef::from_lit("https")));

  CU_ASSERT("for=192.168.0.1" ==
            http::create_forwarded(
                balloc, FORWARDED_FOR, StringRef::from_lit("alpha"),
                StringRef::from_lit("192.168.0.1"),
                StringRef::from_lit("bravo"), StringRef::from_lit("charlie")));

  CU_ASSERT("by=_hidden;for=\"[::1]\"" ==
            http::create_forwarded(
                balloc, FORWARDED_BY | FORWARDED_FOR,
                StringRef::from_lit("_hidden"), StringRef::from_lit("[::1]"),
                StringRef::from_lit(""), StringRef::from_lit("")));

  CU_ASSERT("by=\"[::1]\";for=_hidden" ==
            http::create_forwarded(
                balloc, FORWARDED_BY | FORWARDED_FOR,
                StringRef::from_lit("[::1]"), StringRef::from_lit("_hidden"),
                StringRef::from_lit(""), StringRef::from_lit("")));

  CU_ASSERT("" == http::create_forwarded(
                      balloc, FORWARDED_BY | FORWARDED_FOR | FORWARDED_HOST |
                                  FORWARDED_PROTO,
                      StringRef::from_lit(""), StringRef::from_lit(""),
                      StringRef::from_lit(""), StringRef::from_lit("")));
}

void test_shrpx_http_create_via_header_value(void) {
  std::array<char, 16> buf;

  auto end = http::create_via_header_value(std::begin(buf), 1, 1);

  CU_ASSERT(("1.1 nghttpx" == StringRef{std::begin(buf), end}));

  std::fill(std::begin(buf), std::end(buf), '\0');

  end = http::create_via_header_value(std::begin(buf), 2, 0);

  CU_ASSERT(("2 nghttpx" == StringRef{std::begin(buf), end}));
}

} // namespace shrpx
