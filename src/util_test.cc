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
#include "util_test.h"

#include <iostream>

#include <CUnit/CUnit.h>

#include "util.h"

using namespace nghttp2;

namespace shrpx {

void test_util_streq(void)
{
  CU_ASSERT(util::streq("alpha", (const uint8_t*)"alpha", 5));
  CU_ASSERT(util::streq("alpha", (const uint8_t*)"alphabravo", 5));
  CU_ASSERT(!util::streq("alpha", (const uint8_t*)"alphabravo", 6));
  CU_ASSERT(!util::streq("alphabravo", (const uint8_t*)"alpha", 5));
  CU_ASSERT(!util::streq("alpha", (const uint8_t*)"alphA", 5));
  CU_ASSERT(!util::streq("", (const uint8_t*)"a", 1));
  CU_ASSERT(util::streq("", (const uint8_t*)"", 0));
  CU_ASSERT(!util::streq("alpha", (const uint8_t*)"", 0));

  CU_ASSERT(util::streq((const uint8_t*)"alpha", 5,
                        (const uint8_t*)"alpha", 5));
  CU_ASSERT(!util::streq((const uint8_t*)"alpha", 4,
                         (const uint8_t*)"alpha", 5));
  CU_ASSERT(!util::streq((const uint8_t*)"alpha", 5,
                         (const uint8_t*)"alpha", 4));
  CU_ASSERT(!util::streq((const uint8_t*)"alpha", 5,
                         (const uint8_t*)"alphA", 5));
  CU_ASSERT(util::streq(nullptr, 0,  nullptr, 0));
}

void test_util_inp_strlower(void)
{
  std::string a("alPha");
  util::inp_strlower(a);
  CU_ASSERT("alpha" == a);

  a = "ALPHA123BRAVO";
  util::inp_strlower(a);
  CU_ASSERT("alpha123bravo" == a);

  a = "";
  util::inp_strlower(a);
  CU_ASSERT("" == a);
}

} // namespace shrpx
