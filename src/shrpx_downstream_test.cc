/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
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
#include "shrpx_downstream_test.h"

#include <iostream>

#include "munitxx.h"

#include "shrpx_downstream.h"

using namespace std::literals;

namespace shrpx {

namespace {
const MunitTest tests[]{
  munit_void_test(test_downstream_field_store_append_last_header),
  munit_void_test(test_downstream_field_store_header),
  munit_void_test(test_downstream_crumble_request_cookie),
  munit_void_test(test_downstream_assemble_request_cookie),
  munit_void_test(test_downstream_rewrite_location_response_header),
  munit_void_test(test_downstream_supports_non_final_response),
  munit_void_test(test_downstream_find_affinity_cookie),
  munit_test_end(),
};
} // namespace

const MunitSuite downstream_suite{
  "/downstream", tests, nullptr, 1, MUNIT_SUITE_OPTION_NONE,
};

void test_downstream_field_store_append_last_header(void) {
  BlockAllocator balloc(16, 16);
  FieldStore fs(balloc, 0);
  fs.alloc_add_header_name("alpha"sv);
  auto bravo = "BRAVO"sv;
  fs.append_last_header_key(bravo);
  // Add more characters so that relloc occurs
  auto golf = "golF0123456789"sv;
  fs.append_last_header_key(golf);

  auto charlie = "Charlie"sv;
  fs.append_last_header_value(charlie);
  auto delta = "deltA"sv;
  fs.append_last_header_value(delta);
  // Add more characters so that relloc occurs
  auto echo = "echo0123456789"sv;
  fs.append_last_header_value(echo);

  fs.add_header_token("echo"sv, "foxtrot"sv, false, -1);

  auto ans =
    HeaderRefs{{"alphabravogolf0123456789"sv, "CharliedeltAecho0123456789"sv},
               {"echo"sv, "foxtrot"sv}};
  assert_true(ans == fs.headers());
}

void test_downstream_field_store_header(void) {
  BlockAllocator balloc(16, 16);
  FieldStore fs(balloc, 0);
  fs.add_header_token("alpha"sv, "0"sv, false, -1);
  fs.add_header_token(":authority"sv, "1"sv, false, http2::HD__AUTHORITY);
  fs.add_header_token("content-length"sv, "2"sv, false,
                      http2::HD_CONTENT_LENGTH);

  // By token
  assert_true(HeaderRef(":authority"sv, "1"sv) ==
              *fs.header(http2::HD__AUTHORITY));
  assert_null(fs.header(http2::HD__METHOD));

  // By name
  assert_true(HeaderRef("alpha"sv, "0"sv) == *fs.header("alpha"sv));
  assert_null(fs.header("bravo"sv));
}

void test_downstream_crumble_request_cookie(void) {
  Downstream d(nullptr, nullptr, 0);
  auto &req = d.request();
  req.fs.add_header_token(":method"sv, "get"sv, false, -1);
  req.fs.add_header_token(":path"sv, "/"sv, false, -1);
  req.fs.add_header_token("cookie"sv, "alpha; bravo; ; ;; charlie;;"sv, true,
                          http2::HD_COOKIE);
  req.fs.add_header_token("cookie"sv, ";delta"sv, false, http2::HD_COOKIE);
  req.fs.add_header_token("cookie"sv, "echo"sv, false, http2::HD_COOKIE);

  std::vector<nghttp2_nv> nva;
  d.crumble_request_cookie(nva);

  auto num_cookies = d.count_crumble_request_cookie();

  assert_size(5, ==, nva.size());
  assert_size(5, ==, num_cookies);

  HeaderRefs cookies;
  std::ranges::transform(nva, std::back_inserter(cookies), [](const auto &nv) {
    return HeaderRef(as_string_view(nv.name, nv.namelen),
                     as_string_view(nv.value, nv.valuelen),
                     nv.flags & NGHTTP2_NV_FLAG_NO_INDEX);
  });

  HeaderRefs ans = {{"cookie"sv, "alpha"sv},
                    {"cookie"sv, "bravo"sv},
                    {"cookie"sv, "charlie"sv},
                    {"cookie"sv, "delta"sv},
                    {"cookie"sv, "echo"sv}};

  assert_true(ans == cookies);
  assert_true(cookies[0].no_index);
  assert_true(cookies[1].no_index);
  assert_true(cookies[2].no_index);
}

void test_downstream_assemble_request_cookie(void) {
  Downstream d(nullptr, nullptr, 0);
  auto &req = d.request();

  req.fs.add_header_token(":method"sv, "get"sv, false, -1);
  req.fs.add_header_token(":path"sv, "/"sv, false, -1);
  req.fs.add_header_token("cookie"sv, "alpha"sv, false, http2::HD_COOKIE);
  req.fs.add_header_token("cookie"sv, "bravo;"sv, false, http2::HD_COOKIE);
  req.fs.add_header_token("cookie"sv, "charlie; "sv, false, http2::HD_COOKIE);
  req.fs.add_header_token("cookie"sv, "delta;;"sv, false, http2::HD_COOKIE);
  assert_stdsv_equal("alpha; bravo; charlie; delta"sv,
                     d.assemble_request_cookie());
}

void test_downstream_rewrite_location_response_header(void) {
  Downstream d(nullptr, nullptr, 0);
  auto &req = d.request();
  auto &resp = d.response();
  d.set_request_downstream_host("localhost2"sv);
  req.authority = "localhost:8443"sv;
  resp.fs.add_header_token("location"sv, "http://localhost2:3000/"sv, false,
                           http2::HD_LOCATION);
  d.rewrite_location_response_header("https"sv);
  auto location = resp.fs.header(http2::HD_LOCATION);
  assert_stdsv_equal("https://localhost:8443/"sv, (*location).value);
}

void test_downstream_supports_non_final_response(void) {
  Downstream d(nullptr, nullptr, 0);
  auto &req = d.request();

  req.http_major = 3;
  req.http_minor = 0;

  assert_true(d.supports_non_final_response());

  req.http_major = 2;
  req.http_minor = 0;

  assert_true(d.supports_non_final_response());

  req.http_major = 1;
  req.http_minor = 1;

  assert_true(d.supports_non_final_response());

  req.http_major = 1;
  req.http_minor = 0;

  assert_false(d.supports_non_final_response());

  req.http_major = 0;
  req.http_minor = 9;

  assert_false(d.supports_non_final_response());
}

void test_downstream_find_affinity_cookie(void) {
  Downstream d(nullptr, nullptr, 0);

  auto &req = d.request();
  req.fs.add_header_token("cookie"sv, ""sv, false, http2::HD_COOKIE);
  req.fs.add_header_token("cookie"sv, "a=b;;c=d"sv, false, http2::HD_COOKIE);
  req.fs.add_header_token("content-length"sv, "599"sv, false,
                          http2::HD_CONTENT_LENGTH);
  req.fs.add_header_token("cookie"sv, "lb=deadbeef;LB=f1f2f3f4"sv, false,
                          http2::HD_COOKIE);
  req.fs.add_header_token("cookie"sv, "short=e1e2e3e"sv, false,
                          http2::HD_COOKIE);

  uint32_t aff;

  aff = d.find_affinity_cookie("lb"sv);

  assert_uint32(0xdeadbeef, ==, aff);

  aff = d.find_affinity_cookie("LB"sv);

  assert_uint32(0xf1f2f3f4, ==, aff);

  aff = d.find_affinity_cookie("short"sv);

  assert_uint32(0, ==, aff);
}

} // namespace shrpx
