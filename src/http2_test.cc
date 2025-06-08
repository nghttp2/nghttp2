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
#include "http2_test.h"

#include <cassert>
#include <cstring>
#include <iostream>

#include "munitxx.h"

#include "urlparse.h"

#include "http2.h"
#include "util.h"

using namespace nghttp2;
using namespace std::literals;

#define MAKE_NV(K, V)                                                          \
  {                                                                            \
    (uint8_t *)K,  (uint8_t *)V,         sizeof(K) - 1,                        \
    sizeof(V) - 1, NGHTTP2_NV_FLAG_NONE,                                       \
  }

namespace shrpx {

namespace {
const MunitTest tests[]{
  munit_void_test(test_http2_add_header),
  munit_void_test(test_http2_get_header),
  munit_void_test(test_http2_copy_headers_to_nva),
  munit_void_test(test_http2_build_http1_headers_from_headers),
  munit_void_test(test_http2_rewrite_location_uri),
  munit_void_test(test_http2_parse_http_status_code),
  munit_void_test(test_http2_index_header),
  munit_void_test(test_http2_lookup_token),
  munit_void_test(test_http2_parse_link_header),
  munit_void_test(test_http2_path_join),
  munit_void_test(test_http2_normalize_path),
  munit_void_test(test_http2_rewrite_clean_path),
  munit_void_test(test_http2_get_pure_path_component),
  munit_void_test(test_http2_construct_push_component),
  munit_void_test(test_http2_contains_trailers),
  munit_void_test(test_http2_check_transfer_encoding),
  munit_void_test(test_http2_capitalize),
  munit_test_end(),
};
} // namespace

const MunitSuite http2_suite{
  "/http2", tests, nullptr, 1, MUNIT_SUITE_OPTION_NONE,
};

namespace {
void check_nv(const HeaderRef &a, const nghttp2_nv *b) {
  assert_size(a.name.size(), ==, b->namelen);
  assert_size(a.value.size(), ==, b->valuelen);
  assert_memory_equal(b->namelen, a.name.data(), b->name);
  assert_memory_equal(b->valuelen, a.value.data(), b->value);
}
} // namespace

void test_http2_add_header(void) {
  auto nva = Headers();

  http2::add_header(nva, "alpha"sv, "123"sv, false, -1);
  assert_true(Headers::value_type("alpha", "123") == nva[0]);
  assert_false(nva[0].no_index);

  nva.clear();

  http2::add_header(nva, "alpha"sv, ""sv, true, -1);
  assert_true(Headers::value_type("alpha", "") == nva[0]);
  assert_true(nva[0].no_index);

  nva.clear();

  http2::add_header(nva, "a"sv, "b"sv, false, -1);
  assert_true(Headers::value_type("a", "b") == nva[0]);

  nva.clear();

  http2::add_header(nva, "te"sv, "trailers"sv, false, http2::HD_TE);
  assert_int32(http2::HD_TE, ==, nva[0].token);
}

void test_http2_get_header(void) {
  auto nva = Headers{{"alpha", "1"},         {"bravo", "2"}, {"bravo", "3"},
                     {"charlie", "4"},       {"delta", "5"}, {"echo", "6"},
                     {"content-length", "7"}};
  const Headers::value_type *rv;
  rv = http2::get_header(nva, "delta"sv);
  assert_not_null(rv);
  assert_stdstring_equal("delta", rv->name);

  rv = http2::get_header(nva, "bravo"sv);
  assert_not_null(rv);
  assert_stdstring_equal("bravo", rv->name);

  rv = http2::get_header(nva, "foxtrot"sv);
  assert_null(rv);
}

namespace {
auto headers =
  HeaderRefs{{"alpha"sv, "0"sv, true},
             {"bravo"sv, "1"sv},
             {"connection"sv, "2"sv, false, http2::HD_CONNECTION},
             {"connection"sv, "3"sv, false, http2::HD_CONNECTION},
             {"delta"sv, "4"sv},
             {"expect"sv, "5"sv},
             {"foxtrot"sv, "6"sv},
             {"tango"sv, "7"sv},
             {"te"sv, "8"sv, false, http2::HD_TE},
             {"te"sv, "9"sv, false, http2::HD_TE},
             {"x-forwarded-proto"sv, "10"sv, false, http2::HD_X_FORWARDED_FOR},
             {"x-forwarded-proto"sv, "11"sv, false, http2::HD_X_FORWARDED_FOR},
             {"zulu"sv, "12"sv}};
} // namespace

namespace {
auto headers2 = HeaderRefs{
  {"x-forwarded-for"sv, "xff1"sv, false, http2::HD_X_FORWARDED_FOR},
  {"x-forwarded-for"sv, "xff2"sv, false, http2::HD_X_FORWARDED_FOR},
  {"x-forwarded-proto"sv, "xfp1"sv, false, http2::HD_X_FORWARDED_PROTO},
  {"x-forwarded-proto"sv, "xfp2"sv, false, http2::HD_X_FORWARDED_PROTO},
  {"forwarded"sv, "fwd1"sv, false, http2::HD_FORWARDED},
  {"forwarded"sv, "fwd2"sv, false, http2::HD_FORWARDED},
  {"via"sv, "via1"sv, false, http2::HD_VIA},
  {"via"sv, "via2"sv, false, http2::HD_VIA},
};
} // namespace

void test_http2_copy_headers_to_nva(void) {
  auto ans = std::vector<size_t>{0, 1, 4, 5, 6, 7, 12};
  std::vector<nghttp2_nv> nva;

  http2::copy_headers_to_nva_nocopy(nva, headers,
                                    http2::HDOP_STRIP_X_FORWARDED_FOR);
  assert_size(7, ==, nva.size());
  for (size_t i = 0; i < ans.size(); ++i) {
    check_nv(headers[ans[i]], &nva[i]);

    if (ans[i] == 0) {
      assert_uint8((NGHTTP2_NV_FLAG_NO_COPY_NAME |
                    NGHTTP2_NV_FLAG_NO_COPY_VALUE | NGHTTP2_NV_FLAG_NO_INDEX),
                   ==, nva[i].flags);
    } else {
      assert_uint8(
        (NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE), ==,
        nva[i].flags);
    }
  }

  nva.clear();
  http2::copy_headers_to_nva(nva, headers, http2::HDOP_STRIP_X_FORWARDED_FOR);
  assert_size(7, ==, nva.size());
  for (size_t i = 0; i < ans.size(); ++i) {
    check_nv(headers[ans[i]], &nva[i]);

    if (ans[i] == 0) {
      assert_true(nva[i].flags & NGHTTP2_NV_FLAG_NO_INDEX);
    } else {
      assert_false(nva[i].flags);
    }
  }

  nva.clear();

  auto ans2 = std::vector<size_t>{0, 2, 4, 6};
  http2::copy_headers_to_nva(nva, headers2, http2::HDOP_NONE);
  assert_size(ans2.size(), ==, nva.size());
  for (size_t i = 0; i < ans2.size(); ++i) {
    check_nv(headers2[ans2[i]], &nva[i]);
  }

  nva.clear();

  http2::copy_headers_to_nva(nva, headers2, http2::HDOP_STRIP_ALL);
  assert_true(nva.empty());
}

void test_http2_build_http1_headers_from_headers(void) {
  MemchunkPool pool;
  DefaultMemchunks buf(&pool);
  http2::build_http1_headers_from_headers(&buf, headers,
                                          http2::HDOP_STRIP_X_FORWARDED_FOR);
  auto hdrs = std::string(buf.head->pos, buf.head->last);
  assert_stdstring_equal("Alpha: 0\r\n"
                         "Bravo: 1\r\n"
                         "Delta: 4\r\n"
                         "Expect: 5\r\n"
                         "Foxtrot: 6\r\n"
                         "Tango: 7\r\n"
                         "Te: 8\r\n"
                         "Te: 9\r\n"
                         "Zulu: 12\r\n",
                         hdrs);

  buf.reset();

  http2::build_http1_headers_from_headers(&buf, headers2, http2::HDOP_NONE);
  hdrs = std::string(buf.head->pos, buf.head->last);
  assert_stdstring_equal("X-Forwarded-For: xff1\r\n"
                         "X-Forwarded-Proto: xfp1\r\n"
                         "Forwarded: fwd1\r\n"
                         "Via: via1\r\n",
                         hdrs);

  buf.reset();

  http2::build_http1_headers_from_headers(&buf, headers2,
                                          http2::HDOP_STRIP_ALL);
  assert_size(0, ==, buf.rleft());
}

namespace {
void check_rewrite_location_uri(const std::string &want, const std::string &uri,
                                const std::string &match_host,
                                const std::string &req_authority,
                                const std::string &upstream_scheme) {
  BlockAllocator balloc(4096, 4096);
  urlparse_url u;
  assert_int(0, ==, urlparse_parse_url(uri.c_str(), uri.size(), 0, &u));
  auto got = http2::rewrite_location_uri(balloc, uri, u, match_host,
                                         req_authority, upstream_scheme);
  assert_stdsv_equal(want, got);
}
} // namespace

void test_http2_rewrite_location_uri(void) {
  check_rewrite_location_uri("https://localhost:3000/alpha?bravo#charlie",
                             "http://localhost:3001/alpha?bravo#charlie",
                             "localhost:3001", "localhost:3000", "https");
  check_rewrite_location_uri("https://localhost/", "http://localhost:3001/",
                             "localhost", "localhost", "https");
  check_rewrite_location_uri("http://localhost/", "http://localhost:3001/",
                             "localhost", "localhost", "http");
  check_rewrite_location_uri("http://localhost:443/", "http://localhost:3001/",
                             "localhost", "localhost:443", "http");
  check_rewrite_location_uri("https://localhost:80/", "http://localhost:3001/",
                             "localhost", "localhost:80", "https");
  check_rewrite_location_uri("", "http://localhost:3001/", "127.0.0.1",
                             "127.0.0.1", "https");
  check_rewrite_location_uri("https://localhost:3000/",
                             "http://localhost:3001/", "localhost",
                             "localhost:3000", "https");
  check_rewrite_location_uri("https://localhost:3000/", "http://localhost/",
                             "localhost", "localhost:3000", "https");

  // match_host != req_authority
  check_rewrite_location_uri("https://example.org", "http://127.0.0.1:8080",
                             "127.0.0.1", "example.org", "https");
  check_rewrite_location_uri("", "http://example.org", "127.0.0.1",
                             "example.org", "https");
}

void test_http2_parse_http_status_code(void) {
  assert_int(200, ==, http2::parse_http_status_code("200"sv));
  assert_int(102, ==, http2::parse_http_status_code("102"sv));
  assert_int(-1, ==, http2::parse_http_status_code("099"sv));
  assert_int(-1, ==, http2::parse_http_status_code("99"sv));
  assert_int(-1, ==, http2::parse_http_status_code("-1"sv));
  assert_int(-1, ==, http2::parse_http_status_code("20a"sv));
  assert_int(-1, ==, http2::parse_http_status_code(""sv));
}

void test_http2_index_header(void) {
  http2::HeaderIndex hdidx;
  http2::init_hdidx(hdidx);

  http2::index_header(hdidx, http2::HD__AUTHORITY, 0);
  http2::index_header(hdidx, -1, 1);

  assert_int16(0, ==, hdidx[http2::HD__AUTHORITY]);
}

void test_http2_lookup_token(void) {
  assert_int(http2::HD__AUTHORITY, ==, http2::lookup_token(":authority"sv));
  assert_int(-1, ==, http2::lookup_token(":authorit"sv));
  assert_int(-1, ==, http2::lookup_token(":Authority"sv));
  assert_int(http2::HD_EXPECT, ==, http2::lookup_token("expect"sv));
}

void test_http2_parse_link_header(void) {
  {
    // only URI appears; we don't extract URI unless it bears rel=preload
    auto res = http2::parse_link_header("<url>"sv);
    assert_size(0, ==, res.size());
  }
  {
    // URI url should be extracted
    auto res = http2::parse_link_header("<url>; rel=preload"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // With extra link-param.  URI url should be extracted
    auto res = http2::parse_link_header("<url>; rel=preload; as=file"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // With extra link-param.  URI url should be extracted
    auto res = http2::parse_link_header("<url>; as=file; rel=preload"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // With extra link-param and quote-string.  URI url should be
    // extracted
    auto res =
      http2::parse_link_header(R"(<url>; rel=preload; title="foo,bar")"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // With extra link-param and quote-string.  URI url should be
    // extracted
    auto res =
      http2::parse_link_header(R"(<url>; title="foo,bar"; rel=preload)"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // ',' after quote-string
    auto res = http2::parse_link_header(
      R"(<url>; title="foo,bar", <url2>; rel=preload)"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url2"sv, res[0].uri);
  }
  {
    // Only first URI should be extracted.
    auto res = http2::parse_link_header("<url>; rel=preload, <url2>"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // Both have rel=preload, so both urls should be extracted
    auto res =
      http2::parse_link_header("<url>; rel=preload, <url2>; rel=preload"sv);
    assert_size(2, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
    assert_stdsv_equal("url2"sv, res[1].uri);
  }
  {
    // Second URI uri should be extracted.
    auto res = http2::parse_link_header("<url>, <url2>;rel=preload"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url2"sv, res[0].uri);
  }
  {
    // Error if input ends with ';'
    auto res = http2::parse_link_header("<url>;rel=preload;"sv);
    assert_size(0, ==, res.size());
  }
  {
    // Error if link header ends with ';'
    auto res = http2::parse_link_header("<url>;rel=preload;, <url>"sv);
    assert_size(0, ==, res.size());
  }
  {
    // OK if input ends with ','
    auto res = http2::parse_link_header("<url>;rel=preload,"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // Multiple repeated ','s between fields is OK
    auto res = http2::parse_link_header("<url>,,,<url2>;rel=preload"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url2"sv, res[0].uri);
  }
  {
    // Error if url is not enclosed by <>
    auto res = http2::parse_link_header("url>;rel=preload"sv);
    assert_size(0, ==, res.size());
  }
  {
    // Error if url is not enclosed by <>
    auto res = http2::parse_link_header("<url;rel=preload"sv);
    assert_size(0, ==, res.size());
  }
  {
    // Empty parameter value is not allowed
    auto res = http2::parse_link_header("<url>;rel=preload; as="sv);
    assert_size(0, ==, res.size());
  }
  {
    // Empty parameter value is not allowed
    auto res = http2::parse_link_header("<url>;as=;rel=preload"sv);
    assert_size(0, ==, res.size());
  }
  {
    // Empty parameter value is not allowed
    auto res = http2::parse_link_header("<url>;as=, <url>;rel=preload"sv);
    assert_size(0, ==, res.size());
  }
  {
    // Empty parameter name is not allowed
    auto res = http2::parse_link_header("<url>; =file; rel=preload"sv);
    assert_size(0, ==, res.size());
  }
  {
    // Without whitespaces
    auto res = http2::parse_link_header(
      "<url>;as=file;rel=preload,<url2>;rel=preload"sv);
    assert_size(2, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
    assert_stdsv_equal("url2"sv, res[1].uri);
  }
  {
    // link-extension may have no value
    auto res = http2::parse_link_header("<url>; as; rel=preload"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // ext-name-star
    auto res = http2::parse_link_header("<url>; foo*=bar; rel=preload"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // '*' is not allowed expect for trailing one
    auto res = http2::parse_link_header("<url>; *=bar; rel=preload"sv);
    assert_size(0, ==, res.size());
  }
  {
    // '*' is not allowed expect for trailing one
    auto res = http2::parse_link_header("<url>; foo*bar=buzz; rel=preload"sv);
    assert_size(0, ==, res.size());
  }
  {
    // ext-name-star must be followed by '='
    auto res = http2::parse_link_header("<url>; foo*; rel=preload"sv);
    assert_size(0, ==, res.size());
  }
  {
    // '>' is not followed by ';'
    auto res = http2::parse_link_header("<url> rel=preload"sv);
    assert_size(0, ==, res.size());
  }
  {
    // Starting with whitespace is no problem.
    auto res = http2::parse_link_header("  <url>; rel=preload"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // preload is a prefix of bogus rel parameter value
    auto res = http2::parse_link_header("<url>; rel=preloadx"sv);
    assert_size(0, ==, res.size());
  }
  {
    // preload in relation-types list
    auto res = http2::parse_link_header(R"(<url>; rel="preload")"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // preload in relation-types list followed by another parameter
    auto res = http2::parse_link_header(R"(<url>; rel="preload foo")"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // preload in relation-types list following another parameter
    auto res = http2::parse_link_header(R"(<url>; rel="foo preload")"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // preload in relation-types list between other parameters
    auto res = http2::parse_link_header(R"(<url>; rel="foo preload bar")"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // preload in relation-types list between other parameters
    auto res =
      http2::parse_link_header(R"(<url>; rel="foo   preload   bar")"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // no preload in relation-types list
    auto res = http2::parse_link_header(R"(<url>; rel="foo")"sv);
    assert_size(0, ==, res.size());
  }
  {
    // no preload in relation-types list, multiple unrelated elements.
    auto res = http2::parse_link_header(R"(<url>; rel="foo bar")"sv);
    assert_size(0, ==, res.size());
  }
  {
    // preload in relation-types list, followed by another link-value.
    auto res = http2::parse_link_header(R"(<url>; rel="preload", <url2>)"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // preload in relation-types list, following another link-value.
    auto res = http2::parse_link_header(R"(<url>, <url2>; rel="preload")"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url2"sv, res[0].uri);
  }
  {
    // preload in relation-types list, followed by another link-param.
    auto res = http2::parse_link_header(R"(<url>; rel="preload"; as="font")"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // preload in relation-types list, followed by character other
    // than ';' or ','
    auto res = http2::parse_link_header(R"(<url>; rel="preload".)"sv);
    assert_size(0, ==, res.size());
  }
  {
    // preload in relation-types list, followed by ';' but it
    // terminates input
    auto res = http2::parse_link_header(R"(<url>; rel="preload";)"sv);
    assert_size(0, ==, res.size());
  }
  {
    // preload in relation-types list, followed by ',' but it
    // terminates input
    auto res = http2::parse_link_header(R"(<url>; rel="preload",)"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // preload in relation-types list but there is preceding white
    // space.
    auto res = http2::parse_link_header(R"(<url>; rel=" preload")"sv);
    assert_size(0, ==, res.size());
  }
  {
    // preload in relation-types list but there is trailing white
    // space.
    auto res = http2::parse_link_header(R"(<url>; rel="preload ")"sv);
    assert_size(0, ==, res.size());
  }
  {
    // backslash escaped characters in quoted-string
    auto res = http2::parse_link_header(
      R"(<url>; rel=preload; title="foo\"baz\"bar")"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // anchor="" is acceptable
    auto res = http2::parse_link_header(R"(<url>; rel=preload; anchor="")"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // With anchor="#foo", url should be ignored
    auto res =
      http2::parse_link_header(R"(<url>; rel=preload; anchor="#foo")"sv);
    assert_size(0, ==, res.size());
  }
  {
    // With anchor=f, url should be ignored
    auto res = http2::parse_link_header("<url>; rel=preload; anchor=f"sv);
    assert_size(0, ==, res.size());
  }
  {
    // First url is ignored With anchor="#foo", but url should be
    // accepted.
    auto res = http2::parse_link_header(
      R"(<url>; rel=preload; anchor="#foo", <url2>; rel=preload)"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url2"sv, res[0].uri);
  }
  {
    // With loadpolicy="next", url should be ignored
    auto res =
      http2::parse_link_header(R"(<url>; rel=preload; loadpolicy="next")"sv);
    assert_size(0, ==, res.size());
  }
  {
    // url should be picked up if empty loadpolicy is specified
    auto res =
      http2::parse_link_header(R"(<url>; rel=preload; loadpolicy="")"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // case-insensitive match
    auto res = http2::parse_link_header(
      R"(<url>; rel=preload; ANCHOR="#foo", <url2>; )"
      R"(REL=PRELOAD, <url3>; REL="foo PRELOAD bar")"sv);
    assert_size(2, ==, res.size());
    assert_stdsv_equal("url2"sv, res[0].uri);
    assert_stdsv_equal("url3"sv, res[1].uri);
  }
  {
    // nopush at the end of input
    auto res = http2::parse_link_header("<url>; rel=preload; nopush"sv);
    assert_size(0, ==, res.size());
  }
  {
    // nopush followed by ';'
    auto res = http2::parse_link_header("<url>; rel=preload; nopush; foo"sv);
    assert_size(0, ==, res.size());
  }
  {
    // nopush followed by ','
    auto res = http2::parse_link_header("<url>; nopush; rel=preload"sv);
    assert_size(0, ==, res.size());
  }
  {
    // string whose prefix is nopush
    auto res = http2::parse_link_header("<url>; nopushyes; rel=preload"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
  {
    // rel=preload twice
    auto res = http2::parse_link_header("<url>; rel=preload; rel=preload"sv);
    assert_size(1, ==, res.size());
    assert_stdsv_equal("url"sv, res[0].uri);
  }
}

void test_http2_path_join(void) {
  {
    auto base = "/"sv;
    auto rel = "/"sv;
    assert_stdstring_equal("/", http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    auto base = "/"sv;
    auto rel = "/alpha"sv;
    assert_stdstring_equal("/alpha", http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // rel ends with trailing '/'
    auto base = "/"sv;
    auto rel = "/alpha/"sv;
    assert_stdstring_equal("/alpha/", http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // rel contains multiple components
    auto base = "/"sv;
    auto rel = "/alpha/bravo"sv;
    assert_stdstring_equal("/alpha/bravo",
                           http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // rel is relative
    auto base = "/"sv;
    auto rel = "alpha/bravo"sv;
    assert_stdstring_equal("/alpha/bravo",
                           http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // rel is relative and base ends without /, which means it refers
    // to file.
    auto base = "/alpha"sv;
    auto rel = "bravo/charlie"sv;
    assert_stdstring_equal("/bravo/charlie",
                           http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // rel contains repeated '/'s
    auto base = "/"sv;
    auto rel = "/alpha/////bravo/////"sv;
    assert_stdstring_equal("/alpha/bravo/",
                           http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // base ends with '/', so '..' eats 'bravo'
    auto base = "/alpha/bravo/"sv;
    auto rel = "../charlie/delta"sv;
    assert_stdstring_equal("/alpha/charlie/delta",
                           http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // base does not end with '/', so '..' eats 'alpha/bravo'
    auto base = "/alpha/bravo"sv;
    auto rel = "../charlie"sv;
    assert_stdstring_equal("/charlie", http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // 'charlie' is eaten by following '..'
    auto base = "/alpha/bravo/"sv;
    auto rel = "../charlie/../delta"sv;
    assert_stdstring_equal("/alpha/delta",
                           http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // excessive '..' results in '/'
    auto base = "/alpha/bravo/"sv;
    auto rel = "../../../"sv;
    assert_stdstring_equal("/", http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // excessive '..'  and  path component
    auto base = "/alpha/bravo/"sv;
    auto rel = "../../../charlie"sv;
    assert_stdstring_equal("/charlie", http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // rel ends with '..'
    auto base = "/alpha/bravo/"sv;
    auto rel = "charlie/.."sv;
    assert_stdstring_equal("/alpha/bravo/",
                           http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // base empty and rel contains '..'
    auto base = ""sv;
    auto rel = "charlie/.."sv;
    assert_stdstring_equal("/", http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // '.' is ignored
    auto base = "/"sv;
    auto rel = "charlie/././././delta"sv;
    assert_stdstring_equal("/charlie/delta",
                           http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // trailing '.' is ignored
    auto base = "/"sv;
    auto rel = "charlie/."sv;
    assert_stdstring_equal("/charlie/",
                           http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // query
    auto base = "/"sv;
    auto rel = "/"sv;
    auto relq = "q"sv;
    assert_stdstring_equal("/?q", http2::path_join(base, ""sv, rel, relq));
  }
  {
    // empty rel and query
    auto base = "/alpha"sv;
    auto rel = ""sv;
    auto relq = "q"sv;
    assert_stdstring_equal("/alpha?q", http2::path_join(base, ""sv, rel, relq));
  }
  {
    // both rel and query are empty
    auto base = "/alpha"sv;
    auto baseq = "r"sv;
    auto rel = ""sv;
    auto relq = ""sv;
    assert_stdstring_equal("/alpha?r",
                           http2::path_join(base, baseq, rel, relq));
  }
  {
    // empty base
    auto base = ""sv;
    auto rel = "/alpha"sv;
    assert_stdstring_equal("/alpha", http2::path_join(base, ""sv, rel, ""sv));
  }
  {
    // everything is empty
    assert_stdstring_equal("/", http2::path_join(""sv, ""sv, ""sv, ""sv));
  }
  {
    // only baseq is not empty
    auto base = ""sv;
    auto baseq = "r"sv;
    auto rel = ""sv;
    assert_stdstring_equal("/?r", http2::path_join(base, baseq, rel, ""sv));
  }
  {
    // path starts with multiple '/'s.
    auto base = ""sv;
    auto baseq = ""sv;
    auto rel = "//alpha//bravo"sv;
    auto relq = "charlie"sv;
    assert_stdstring_equal("/alpha/bravo?charlie",
                           http2::path_join(base, baseq, rel, relq));
  }
  // Test cases from RFC 3986, section 5.4.
  constexpr auto base = "/b/c/d;p"sv;
  constexpr auto baseq = "q"sv;
  {
    auto rel = "g"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/g", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "./g"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/g", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "g/"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/g/", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "/g"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/g", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = ""sv;
    auto relq = "y"sv;
    assert_stdstring_equal("/b/c/d;p?y",
                           http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "g"sv;
    auto relq = "y"sv;
    assert_stdstring_equal("/b/c/g?y",
                           http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = ";x"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/;x", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "g;x"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/g;x",
                           http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "g;x"sv;
    auto relq = "y"sv;
    assert_stdstring_equal("/b/c/g;x?y",
                           http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = ""sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/d;p?q",
                           http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "."sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "./"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = ".."sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "../"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "../g"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/g", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "../.."sv;
    auto relq = ""sv;
    assert_stdstring_equal("/", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "../../"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "../../g"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/g", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "../../../g"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/g", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "../../../../g"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/g", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "/./g"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/g", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "/../g"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/g", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "g."sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/g.", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = ".g"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/.g", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "g.."sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/g..",
                           http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "..g"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/..g",
                           http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "./../g"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/g", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "./g/."sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/g/", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "g/./h"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/g/h",
                           http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "g/../h"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/h", http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "g;x=1/./y"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/g;x=1/y",
                           http2::path_join(base, baseq, rel, relq));
  }
  {
    auto rel = "g;x=1/../y"sv;
    auto relq = ""sv;
    assert_stdstring_equal("/b/c/y", http2::path_join(base, baseq, rel, relq));
  }
}

void test_http2_normalize_path(void) {
  assert_stdstring_equal(
    "/alpha/charlie", http2::normalize_path("/alpha/bravo/../charlie"sv, ""sv));

  assert_stdstring_equal("/alpha",
                         http2::normalize_path("/a%6c%70%68%61"sv, ""sv));

  assert_stdstring_equal("/alpha%2F%3A",
                         http2::normalize_path("/alpha%2f%3a"sv, ""sv));

  assert_stdstring_equal("/%2F", http2::normalize_path("%2f"sv, ""sv));

  assert_stdstring_equal("/%f", http2::normalize_path("%f"sv, ""sv));

  assert_stdstring_equal("/%", http2::normalize_path("%"sv, ""sv));

  assert_stdstring_equal("/", http2::normalize_path(""sv, ""sv));

  assert_stdstring_equal("/alpha?bravo",
                         http2::normalize_path("/alpha"sv, "bravo"sv));
}

void test_http2_rewrite_clean_path(void) {
  BlockAllocator balloc(4096, 4096);

  // unreserved characters
  assert_stdsv_equal("/alpha/bravo/"sv,
                     http2::rewrite_clean_path(balloc, "/alpha/%62ravo/"sv));

  // percent-encoding is converted to upper case.
  assert_stdsv_equal("/delta%3A"sv,
                     http2::rewrite_clean_path(balloc, "/delta%3a"sv));

  // path component is normalized before matching
  assert_stdsv_equal("/alpha/bravo/"sv,
                     http2::rewrite_clean_path(
                       balloc, "/alpha/charlie/%2e././bravo/delta/.."sv));

  assert_stdsv_equal("alpha%3a"sv,
                     http2::rewrite_clean_path(balloc, "alpha%3a"sv));

  assert_stdsv_equal(""sv, http2::rewrite_clean_path(balloc, ""sv));

  assert_stdsv_equal("/alpha?bravo"sv,
                     http2::rewrite_clean_path(balloc, "//alpha?bravo"sv));
}

void test_http2_get_pure_path_component(void) {
  assert_stdsv_equal("/"sv, http2::get_pure_path_component("/"sv));

  assert_stdsv_equal("/foo"sv, http2::get_pure_path_component("/foo"sv));

  assert_stdsv_equal(
    "/bar"sv, http2::get_pure_path_component("https://example.org/bar"sv));

  assert_stdsv_equal("/alpha"sv, http2::get_pure_path_component(
                                   "https://example.org/alpha?q=a"sv));

  assert_stdsv_equal("/bravo"sv, http2::get_pure_path_component(
                                   "https://example.org/bravo?q=a#fragment"sv));

  assert_stdsv_equal(""sv, http2::get_pure_path_component("\x01\x02"sv));
}

void test_http2_construct_push_component(void) {
  BlockAllocator balloc(4096, 4096);
  std::string_view base, uri;
  std::string_view scheme, authority, path;

  base = "/b/"sv;
  uri = "https://example.org/foo"sv;

  assert_int(0, ==,
             http2::construct_push_component(balloc, scheme, authority, path,
                                             base, uri));
  assert_stdsv_equal("https"sv, scheme);
  assert_stdsv_equal("example.org"sv, authority);
  assert_stdsv_equal("/foo"sv, path);

  scheme = ""sv;
  authority = ""sv;
  path = ""sv;

  uri = "/foo/bar?q=a"sv;

  assert_int(0, ==,
             http2::construct_push_component(balloc, scheme, authority, path,
                                             base, uri));
  assert_stdsv_equal(""sv, scheme);
  assert_stdsv_equal(""sv, authority);
  assert_stdsv_equal("/foo/bar?q=a"sv, path);

  scheme = ""sv;
  authority = ""sv;
  path = ""sv;

  uri = "foo/../bar?q=a"sv;

  assert_int(0, ==,
             http2::construct_push_component(balloc, scheme, authority, path,
                                             base, uri));
  assert_stdsv_equal(""sv, scheme);
  assert_stdsv_equal(""sv, authority);
  assert_stdsv_equal("/b/bar?q=a"sv, path);

  scheme = ""sv;
  authority = ""sv;
  path = ""sv;

  uri = ""sv;

  assert_int(-1, ==,
             http2::construct_push_component(balloc, scheme, authority, path,
                                             base, uri));
  scheme = ""sv;
  authority = ""sv;
  path = ""sv;

  uri = "?q=a"sv;

  assert_int(0, ==,
             http2::construct_push_component(balloc, scheme, authority, path,
                                             base, uri));
  assert_stdsv_equal(""sv, scheme);
  assert_stdsv_equal(""sv, authority);
  assert_stdsv_equal("/b/?q=a"sv, path);
}

void test_http2_contains_trailers(void) {
  assert_false(http2::contains_trailers(""sv));
  assert_true(http2::contains_trailers("trailers"sv));
  // Match must be case-insensitive.
  assert_true(http2::contains_trailers("TRAILERS"sv));
  assert_false(http2::contains_trailers("trailer"sv));
  assert_false(http2::contains_trailers("trailers  3"sv));
  assert_true(http2::contains_trailers("trailers,"sv));
  assert_true(http2::contains_trailers("trailers,foo"sv));
  assert_true(http2::contains_trailers("foo,trailers"sv));
  assert_true(http2::contains_trailers("foo,trailers,bar"sv));
  assert_true(http2::contains_trailers("foo, trailers ,bar"sv));
  assert_true(http2::contains_trailers(",trailers"sv));
}

void test_http2_check_transfer_encoding(void) {
  assert_true(http2::check_transfer_encoding("chunked"sv));
  assert_true(http2::check_transfer_encoding("foo,chunked"sv));
  assert_true(http2::check_transfer_encoding("foo,  chunked"sv));
  assert_true(http2::check_transfer_encoding("foo   ,  chunked"sv));
  assert_true(http2::check_transfer_encoding("chunked;foo=bar"sv));
  assert_true(http2::check_transfer_encoding("chunked ; foo=bar"sv));
  assert_true(http2::check_transfer_encoding(R"(chunked;foo="bar")"sv));
  assert_true(
    http2::check_transfer_encoding(R"(chunked;foo="\bar\"";FOO=BAR)"sv));
  assert_true(http2::check_transfer_encoding(R"(chunked;foo="")"sv));
  assert_true(http2::check_transfer_encoding(R"(chunked;foo="bar" , gzip)"sv));

  assert_false(http2::check_transfer_encoding(""sv));
  assert_false(http2::check_transfer_encoding(",chunked"sv));
  assert_false(http2::check_transfer_encoding("chunked,"sv));
  assert_false(http2::check_transfer_encoding("chunked, "sv));
  assert_false(http2::check_transfer_encoding("foo,,chunked"sv));
  assert_false(http2::check_transfer_encoding("chunked;foo"sv));
  assert_false(http2::check_transfer_encoding("chunked;"sv));
  assert_false(http2::check_transfer_encoding("chunked;foo=bar;"sv));
  assert_false(http2::check_transfer_encoding("chunked;?=bar"sv));
  assert_false(http2::check_transfer_encoding("chunked;=bar"sv));
  assert_false(http2::check_transfer_encoding("chunked;;"sv));
  assert_false(http2::check_transfer_encoding("chunked?"sv));
  assert_false(http2::check_transfer_encoding(","sv));
  assert_false(http2::check_transfer_encoding(" "sv));
  assert_false(http2::check_transfer_encoding(";"sv));
  assert_false(http2::check_transfer_encoding("\""sv));
  assert_false(http2::check_transfer_encoding(R"(chunked;foo="bar)"sv));
  assert_false(http2::check_transfer_encoding(R"(chunked;foo="bar\)"sv));
  assert_false(http2::check_transfer_encoding(R"(chunked;foo="bar\)"
                                              "\x0a"
                                              R"(")"sv));
  assert_false(http2::check_transfer_encoding(R"(chunked;foo=")"
                                              "\x0a"
                                              R"(")"sv));
  assert_false(http2::check_transfer_encoding(R"(chunked;foo="bar",,gzip)"sv));
}

void test_http2_capitalize(void) {
  MemchunkPool pool;
  DefaultMemchunks m{&pool};
  iovec iov;

  {
    http2::capitalize(&m, "content-length"sv);
    auto iovcnt = m.riovec(&iov, 1);

    assert_int(1, ==, iovcnt);
    assert_stdsv_equal(
      "Content-Length"sv,
      (std::string_view{static_cast<const char *>(iov.iov_base), iov.iov_len}));

    m.reset();
  }

  {
    http2::capitalize(&m, "altsvc"sv);
    auto iovcnt = m.riovec(&iov, 1);

    assert_int(1, ==, iovcnt);
    assert_stdsv_equal(
      "Altsvc"sv,
      (std::string_view{static_cast<const char *>(iov.iov_base), iov.iov_len}));

    m.reset();
  }

  {
    http2::capitalize(&m, "altsvc-"sv);
    auto iovcnt = m.riovec(&iov, 1);

    assert_int(1, ==, iovcnt);
    assert_stdsv_equal(
      "Altsvc-"sv,
      (std::string_view{static_cast<const char *>(iov.iov_base), iov.iov_len}));

    m.reset();
  }

  {
    http2::capitalize(&m, "alt--svc"sv);
    auto iovcnt = m.riovec(&iov, 1);

    assert_int(1, ==, iovcnt);
    assert_stdsv_equal(
      "Alt--Svc"sv,
      (std::string_view{static_cast<const char *>(iov.iov_base), iov.iov_len}));

    m.reset();
  }

  {
    http2::capitalize(&m, "sec-websocket----------------key"sv);
    auto iovcnt = m.riovec(&iov, 1);

    assert_int(1, ==, iovcnt);
    assert_stdsv_equal(
      "Sec-Websocket----------------Key"sv,
      (std::string_view{static_cast<const char *>(iov.iov_base), iov.iov_len}));

    m.reset();
  }

  {
    http2::capitalize(&m, "content--------------------length"sv);
    auto iovcnt = m.riovec(&iov, 1);

    assert_int(1, ==, iovcnt);
    assert_stdsv_equal(
      "Content--------------------Length"sv,
      (std::string_view{static_cast<const char *>(iov.iov_base), iov.iov_len}));

    m.reset();
  }

  {
    http2::capitalize(&m, "content--------------------length-"sv);
    auto iovcnt = m.riovec(&iov, 1);

    assert_int(1, ==, iovcnt);
    assert_stdsv_equal(
      "Content--------------------Length-"sv,
      (std::string_view{static_cast<const char *>(iov.iov_base), iov.iov_len}));

    m.reset();
  }
}

} // namespace shrpx
