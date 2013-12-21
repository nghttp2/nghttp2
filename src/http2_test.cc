/*
 * nghttp2 - HTTP/2.0 C Library
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

#include <CUnit/CUnit.h>

#include "http-parser/http_parser.h"

#include "http2.h"
#include "util.h"

using namespace nghttp2;

#define MAKE_NV(K, V) {(uint8_t*)K, (uint8_t*)V,        \
      (uint16_t)(sizeof(K)-1), (uint16_t)(sizeof(V)-1)}

namespace shrpx {

namespace {
void check_nv(const std::pair<std::string, std::string>& a,
              const nghttp2_nv *b)
{
  CU_ASSERT(a.first.size() == b->namelen);
  CU_ASSERT(a.second.size() == b->valuelen);
  CU_ASSERT(memcmp(a.first.c_str(), b->name, b->namelen) == 0);
  CU_ASSERT(memcmp(a.second.c_str(), b->value, b->valuelen) == 0);
}
} // namespace

void test_http2_sort_nva(void)
{
  // Last 0 is stripped in MAKE_NV
  const uint8_t concatval[] = { '4', 0x00, 0x00, '6', 0x00, '5', 0x00 };
  nghttp2_nv nv[] = {MAKE_NV("alpha", "1"),
                     MAKE_NV("charlie", "3"),
                     MAKE_NV("bravo", "2"),
                     MAKE_NV("delta", concatval)};
  auto nvlen = sizeof(nv)/sizeof(nv[0]);
  auto nva = http2::sort_nva(nv, nvlen);
  CU_ASSERT(6 == nva.size());
  check_nv({"alpha", "1"}, &nva[0]);
  check_nv({"bravo", "2"}, &nva[1]);
  check_nv({"charlie", "3"}, &nva[2]);
  check_nv({"delta", "4"}, &nva[3]);
  check_nv({"delta", "6"}, &nva[4]);
  check_nv({"delta", "5"}, &nva[5]);
}

void test_http2_check_http2_headers(void)
{
  nghttp2_nv nv1[] = {MAKE_NV("alpha", "1"),
                      MAKE_NV("bravo", "2"),
                      MAKE_NV("upgrade", "http2")};
  CU_ASSERT(!http2::check_http2_headers(http2::sort_nva(nv1, 3)));

  nghttp2_nv nv2[] = {MAKE_NV("connection", "1"),
                      MAKE_NV("delta", "2"),
                      MAKE_NV("echo", "3")};
  CU_ASSERT(!http2::check_http2_headers(http2::sort_nva(nv2, 3)));

  nghttp2_nv nv3[] = {MAKE_NV("alpha", "1"),
                      MAKE_NV("bravo", "2"),
                      MAKE_NV("te2", "3")};
  CU_ASSERT(http2::check_http2_headers(http2::sort_nva(nv3, 3)));
}

void test_http2_get_unique_header(void)
{
  nghttp2_nv nv[] = {MAKE_NV("alpha", "1"),
                     MAKE_NV("bravo", "2"),
                     MAKE_NV("bravo", "3"),
                     MAKE_NV("charlie", "4"),
                     MAKE_NV("delta", "5"),
                     MAKE_NV("echo", "6"),};
  size_t nvlen = sizeof(nv)/sizeof(nv[0]);
  auto nva = http2::sort_nva(nv, nvlen);
  const nghttp2_nv *rv;
  rv = http2::get_unique_header(nva, "delta");
  CU_ASSERT(rv != nullptr);
  CU_ASSERT(util::streq("delta", rv->name, rv->namelen));

  rv = http2::get_unique_header(nva, "bravo");
  CU_ASSERT(rv == nullptr);

  rv = http2::get_unique_header(nva, "foxtrot");
  CU_ASSERT(rv == nullptr);
}

void test_http2_get_header(void)
{
  nghttp2_nv nv[] = {MAKE_NV("alpha", "1"),
                     MAKE_NV("bravo", "2"),
                     MAKE_NV("bravo", "3"),
                     MAKE_NV("charlie", "4"),
                     MAKE_NV("delta", "5"),
                     MAKE_NV("echo", "6"),};
  size_t nvlen = sizeof(nv)/sizeof(nv[0]);
  auto nva = http2::sort_nva(nv, nvlen);
  const nghttp2_nv *rv;
  rv = http2::get_header(nva, "delta");
  CU_ASSERT(rv != nullptr);
  CU_ASSERT(util::streq("delta", rv->name, rv->namelen));

  rv = http2::get_header(nva, "bravo");
  CU_ASSERT(rv != nullptr);
  CU_ASSERT(util::streq("bravo", rv->name, rv->namelen));

  rv = http2::get_header(nva, "foxtrot");
  CU_ASSERT(rv == nullptr);
}

void test_http2_value_lws(void)
{
  nghttp2_nv nv[] = {MAKE_NV("0", "alpha"),
                     MAKE_NV("1", " alpha"),
                     MAKE_NV("2", ""),
                     MAKE_NV("3", " "),
                     MAKE_NV("4", "  a ")};
  CU_ASSERT(!http2::value_lws(&nv[0]));
  CU_ASSERT(!http2::value_lws(&nv[1]));
  CU_ASSERT(http2::value_lws(&nv[2]));
  CU_ASSERT(http2::value_lws(&nv[3]));
  CU_ASSERT(!http2::value_lws(&nv[4]));
}

namespace {
auto headers = std::vector<std::pair<std::string, std::string>>
  {{"alpha", "0"},
   {"bravo", "1"},
   {"connection", "2"},
   {"connection", "3"},
   {"delta", "4"},
   {"expect", "5"},
   {"foxtrot", "6"},
   {"tango", "7"},
   {"te", "8"},
   {"te", "9"},
   {"x-forwarded-proto", "10"},
   {"x-forwarded-proto", "11"},
   {"zulu", "12"}};
} // namespace

void test_http2_concat_norm_headers(void)
{
  auto hds = headers;
  hds.emplace_back("cookie", "foo");
  hds.emplace_back("cookie", "bar");
  hds.emplace_back("set-cookie", "baz");
  hds.emplace_back("set-cookie", "buzz");
  auto res = http2::concat_norm_headers(hds);
  CU_ASSERT(14 == res.size());
  CU_ASSERT(std::string("2") + '\0' + std::string("3") == res[2].second);
}

void test_http2_copy_norm_headers_to_nva(void)
{
  std::vector<nghttp2_nv> nva;
  http2::copy_norm_headers_to_nva(nva, headers);
  CU_ASSERT(6 == nva.size());
  auto ans = std::vector<int>{0, 1, 4, 6, 7, 12};
  for(size_t i = 0; i < ans.size(); ++i) {
    check_nv(headers[ans[i]], &nva[i]);
  }
}

void test_http2_build_http1_headers_from_norm_headers(void)
{
  std::string hdrs;
  http2::build_http1_headers_from_norm_headers(hdrs, headers);
  CU_ASSERT(hdrs ==
            "Alpha: 0\r\n"
            "Bravo: 1\r\n"
            "Delta: 4\r\n"
            "Foxtrot: 6\r\n"
            "Tango: 7\r\n"
            "Te: 8\r\n"
            "Te: 9\r\n"
            "Zulu: 12\r\n");

  hdrs.clear();
  auto hd2 = std::vector<std::pair<std::string, std::string>>
    {{"alpha", "bravo\r\ncharlie\r\n"}};
  http2::build_http1_headers_from_norm_headers(hdrs, hd2);
  CU_ASSERT(hdrs == "Alpha: bravo  charlie  \r\n");
}

void test_http2_check_header_value(void)
{
  CU_ASSERT(http2::check_header_value("alpha"));
  CU_ASSERT(!http2::check_header_value("alpha\r"));
  CU_ASSERT(!http2::check_header_value("alpha\n"));

  nghttp2_nv nv1 = MAKE_NV("alpha", "bravo");
  CU_ASSERT(http2::check_header_value(&nv1));
  nghttp2_nv nv2 = MAKE_NV("alpha", "bravo\r");
  CU_ASSERT(!http2::check_header_value(&nv2));
  nghttp2_nv nv3 = MAKE_NV("alpha", "bravo\n");
  CU_ASSERT(!http2::check_header_value(&nv3));
}

namespace {
void check_rewrite_location_uri(const std::string& new_uri,
                                const std::string& uri,
                                const std::string& req_host,
                                const std::string& upstream_scheme,
                                uint16_t upstream_port)
{
  http_parser_url u;
  CU_ASSERT(0 == http_parser_parse_url(uri.c_str(), uri.size(), 0, &u));
  CU_ASSERT(new_uri ==
            http2::rewrite_location_uri(uri, u, req_host,
                                        upstream_scheme, upstream_port));
}
} // namespace

void test_http2_rewrite_location_uri(void)
{
  check_rewrite_location_uri("https://localhost:3000/alpha?bravo#charlie",
                             "http://localhost:3001/alpha?bravo#charlie",
                             "localhost:3001", "https", 3000);
  check_rewrite_location_uri("https://localhost/",
                             "http://localhost:3001/",
                             "localhost:3001", "https", 443);
  check_rewrite_location_uri("http://localhost/",
                             "http://localhost:3001/",
                             "localhost:3001", "http", 80);
  check_rewrite_location_uri("http://localhost:443/",
                             "http://localhost:3001/",
                             "localhost:3001", "http", 443);
  check_rewrite_location_uri("https://localhost:80/",
                             "http://localhost:3001/",
                             "localhost:3001", "https", 80);
  check_rewrite_location_uri("",
                             "http://localhost:3001/",
                             "127.0.0.1", "https", 3000);
  check_rewrite_location_uri("https://localhost:3000/",
                             "http://localhost:3001/",
                             "localhost", "https", 3000);
  check_rewrite_location_uri("",
                             "https://localhost:3001/",
                             "localhost", "https", 3000);
  check_rewrite_location_uri("https://localhost:3000/",
                             "http://localhost/",
                             "localhost", "https", 3000);
}

} // namespace shrpx
