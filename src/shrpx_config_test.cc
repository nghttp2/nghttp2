/*
 * nghttp2 - HTTP/2.0 C Library
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
#include "shrpx_config_test.h"

#include <CUnit/CUnit.h>

#include "shrpx_config.h"

namespace shrpx {

void test_shrpx_config_parse_config_str_list(void)
{
  size_t outlen;
  auto res = parse_config_str_list(&outlen, "a");
  CU_ASSERT(1 == outlen);
  CU_ASSERT(0 == strcmp("a", res[0]));

  res = parse_config_str_list(&outlen, "a,");
  CU_ASSERT(2 == outlen);
  CU_ASSERT(0 == strcmp("a", res[0]));
  CU_ASSERT(0 == strcmp("", res[1]));

  res = parse_config_str_list(&outlen, ",a,,");
  CU_ASSERT(4 == outlen);
  CU_ASSERT(0 == strcmp("", res[0]));
  CU_ASSERT(0 == strcmp("a", res[1]));
  CU_ASSERT(0 == strcmp("", res[2]));
  CU_ASSERT(0 == strcmp("", res[3]));

  res = parse_config_str_list(&outlen, "");
  CU_ASSERT(1 == outlen);
  CU_ASSERT(0 == strcmp("", res[0]));

  res = parse_config_str_list(&outlen, "alpha,bravo,charlie");
  CU_ASSERT(3 == outlen);
  CU_ASSERT(0 == strcmp("alpha", res[0]));
  CU_ASSERT(0 == strcmp("bravo", res[1]));
  CU_ASSERT(0 == strcmp("charlie", res[2]));
}

} // namespace shrpx
