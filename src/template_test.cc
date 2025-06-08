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
#include "template_test.h"

#include <cstring>
#include <iostream>
#include <sstream>

#include "munitxx.h"

#include "template.h"

using namespace std::literals;

namespace nghttp2 {

namespace {
const MunitTest tests[]{
  munit_void_test(test_template_immutable_string),
  munit_void_test(test_template_as_uint8_span),
  munit_void_test(test_template_as_string_view),
  munit_void_test(test_template_as_string_view),
  munit_test_end(),
};
} // namespace

const MunitSuite template_suite{
  "/template", tests, nullptr, 1, MUNIT_SUITE_OPTION_NONE,
};

void test_template_immutable_string(void) {
  ImmutableString null;

  assert_string_equal("", null.c_str());
  assert_size(0, ==, null.size());
  assert_true(null.empty());

  ImmutableString from_cstr("alpha");

  assert_string_equal("alpha", from_cstr.c_str());
  assert_size(5, ==, from_cstr.size());
  assert_false(from_cstr.empty());
  assert_true("alpha" == from_cstr);
  assert_true(from_cstr == "alpha");
  assert_true(std::string("alpha") == from_cstr);
  assert_true(from_cstr == std::string("alpha"));

  ImmutableString from_stdstr("alpha"s);

  assert_true("alpha" == from_stdstr);

  // copy constructor
  ImmutableString src("charlie");
  ImmutableString copy = src;

  assert_string_equal("charlie", copy.c_str());
  assert_size(7, ==, copy.size());

  // copy assignment
  ImmutableString copy2;
  copy2 = src;

  assert_string_equal("charlie", copy2.c_str());
  assert_size(7, ==, copy2.size());

  // move constructor
  ImmutableString move = std::move(copy);

  assert_string_equal("charlie", move.c_str());
  assert_size(7, ==, move.size());
  assert_string_equal("", copy.c_str());
  assert_size(0, ==, copy.size());

  // move assignment
  move = std::move(from_cstr);

  assert_string_equal("alpha", move.c_str());
  assert_size(5, ==, move.size());
  assert_string_equal("", from_cstr.c_str());
  assert_size(0, ==, from_cstr.size());

  // from string literal
  auto from_lit = "bravo"_is;

  assert_string_equal("bravo", from_lit.c_str());
  assert_size(5, ==, from_lit.size());

  // equality
  ImmutableString eq("delta");

  assert_true("delta1" != eq);
  assert_true("delt" != eq);
  assert_true(eq != "delta1");
  assert_true(eq != "delt");

  // operator[]
  ImmutableString br_op("foxtrot");

  assert_char('f', ==, br_op[0]);
  assert_char('o', ==, br_op[1]);
  assert_char('t', ==, br_op[6]);
  assert_char('\0', ==, br_op[7]);

  // operator==(const ImmutableString &, const ImmutableString &)
  {
    ImmutableString a("foo");
    ImmutableString b("foo");
    ImmutableString c("fo");

    assert_true(a == b);
    assert_true(a != c);
    assert_true(c != b);
  }

  // operator<<
  {
    ImmutableString a("foo");
    std::stringstream ss;
    ss << a;

    assert_stdstring_equal("foo", ss.str());
  }

  // operator +=(std::string &, const ImmutableString &)
  {
    std::string a = "alpha";
    a += ImmutableString("bravo");

    assert_stdstring_equal("alphabravo", a);
  }
}

void test_template_as_uint8_span(void) {
  uint32_t a[2];

  memcpy(&a, "\xc0\xc1\xc2\xc3\xf0\xf1\xf2\xf3", sizeof(a));

  // dynamic extent
  auto s = as_uint8_span(std::span{a, 2});

  assert_size(sizeof(a), ==, s.size());
  assert_size(std::dynamic_extent, ==, s.extent);
  assert_memory_equal(s.size(), &a, s.data());

  // non-dynamic extent
  auto t = as_uint8_span(std::span<uint32_t, 2>{a, 2});

  assert_size(sizeof(a), ==, t.size());
  assert_size(sizeof(a), ==, t.extent);
  assert_memory_equal(t.size(), &a, t.data());
}

void test_template_as_string_view(void) {
  {
    auto a = std::to_array<uint8_t>({'a', 'l', 'p', 'h', 'a'});

    assert_stdsv_equal("alpha"sv, as_string_view(a));
    assert_stdsv_equal("alpha"sv, as_string_view(a.begin(), a.end()));
    assert_stdsv_equal("alp"sv, as_string_view(a.begin(), 3));
  }

  {
    auto s = ""s;

    assert_stdsv_equal(""sv, as_string_view(s));
    assert_stdsv_equal(""sv, as_string_view(s.begin(), s.end()));
  }
}

} // namespace nghttp2
