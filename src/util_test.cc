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
  char *a = nullptr;
  char *b = nullptr;
  CU_ASSERT(util::streq(a, 0,  b, 0));
}

void test_util_strieq(void)
{
  CU_ASSERT(util::strieq(std::string("alpha"), std::string("alpha")));
  CU_ASSERT(util::strieq(std::string("alpha"), std::string("AlPhA")));
  CU_ASSERT(util::strieq(std::string(), std::string()));
  CU_ASSERT(!util::strieq(std::string("alpha"), std::string("AlPhA ")));
  CU_ASSERT(!util::strieq(std::string(), std::string("AlPhA ")));
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

void test_util_to_base64(void)
{
  std::string x = "AAA--B_";
  util::to_base64(x);
  CU_ASSERT("AAA++B/=" == x);

  x = "AAA--B_B";
  util::to_base64(x);
  CU_ASSERT("AAA++B/B" == x);
}

void test_util_percent_encode_token(void)
{
  CU_ASSERT("h2" == util::percent_encode_token("h2"));
  CU_ASSERT("h3~" == util::percent_encode_token("h3~"));
  CU_ASSERT("100%25" == util::percent_encode_token("100%"));
  CU_ASSERT("http%202" == util::percent_encode_token("http 2"));
}

void test_util_quote_string(void)
{
  CU_ASSERT("alpha" == util::quote_string("alpha"));
  CU_ASSERT("" == util::quote_string(""));
  CU_ASSERT("\\\"alpha\\\"" == util::quote_string("\"alpha\""));
}

void test_util_utox(void)
{
  CU_ASSERT("0" == util::utox(0));
  CU_ASSERT("1" == util::utox(1));
  CU_ASSERT("F" == util::utox(15));
  CU_ASSERT("10" == util::utox(16));
  CU_ASSERT("3B9ACA07" == util::utox(1000000007));
  CU_ASSERT("100000000" == util::utox(1LL << 32));
}

} // namespace shrpx
