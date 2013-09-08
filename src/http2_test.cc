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

#include <iostream>

#include <CUnit/CUnit.h>

#include "http2.h"
#include "util.h"

using namespace nghttp2;

#define MAKE_NV(K, V) {(uint8_t*)K, (uint8_t*)V,        \
      (uint16_t)strlen(K), (uint16_t)strlen(V)}

namespace shrpx {

void test_http2_check_http2_headers(void)
{
  nghttp2_nv nv1[] = {MAKE_NV("alpha", "1"),
                      MAKE_NV("bravo", "2"),
                      MAKE_NV("upgrade", "http2")};
  CU_ASSERT(!http2::check_http2_headers(nv1, 3));

  nghttp2_nv nv2[] = {MAKE_NV("connection", "1"),
                      MAKE_NV("delta", "2"),
                      MAKE_NV("echo", "3")};
  CU_ASSERT(!http2::check_http2_headers(nv2, 3));

  nghttp2_nv nv3[] = {MAKE_NV("alpha", "1"),
                      MAKE_NV("bravo", "2"),
                      MAKE_NV("te2", "3")};
  CU_ASSERT(http2::check_http2_headers(nv3, 3));
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
  const nghttp2_nv *rv;
  rv = http2::get_unique_header(nv, nvlen, "delta");
  CU_ASSERT(rv != nullptr);
  CU_ASSERT(util::streq("delta", rv->name, rv->namelen));

  rv = http2::get_unique_header(nv, nvlen, "bravo");
  CU_ASSERT(rv == nullptr);

  rv = http2::get_unique_header(nv, nvlen, "foxtrot");
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
  const nghttp2_nv *rv;
  rv = http2::get_header(nv, nvlen, "delta");
  CU_ASSERT(rv != nullptr);
  CU_ASSERT(util::streq("delta", rv->name, rv->namelen));

  rv = http2::get_header(nv, nvlen, "bravo");
  CU_ASSERT(rv != nullptr);
  CU_ASSERT(util::streq("bravo", rv->name, rv->namelen));

  rv = http2::get_header(nv, nvlen, "foxtrot");
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

void test_http2_copy_norm_headers_to_nv(void)
{
  const char* nv[30];
  size_t nvlen = http2::copy_norm_headers_to_nv(nv, headers);
  CU_ASSERT(12 == nvlen);
  CU_ASSERT(strcmp(nv[0], "alpha") == 0);
  CU_ASSERT(strcmp(nv[1], "0") == 0);
  CU_ASSERT(strcmp(nv[2], "bravo") == 0);
  CU_ASSERT(strcmp(nv[3], "1") == 0);
  CU_ASSERT(strcmp(nv[4], "delta") == 0);
  CU_ASSERT(strcmp(nv[5], "4") == 0);
  CU_ASSERT(strcmp(nv[6], "foxtrot") == 0);
  CU_ASSERT(strcmp(nv[7], "6") == 0);
  CU_ASSERT(strcmp(nv[8], "tango") == 0);
  CU_ASSERT(strcmp(nv[9], "7") == 0);
  CU_ASSERT(strcmp(nv[10], "zulu") == 0);
  CU_ASSERT(strcmp(nv[11], "12") == 0);
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
}

} // namespace shrpx
