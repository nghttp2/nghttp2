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
#ifndef __APPLE__
#  include <spanstream>
#endif // !defined(__APPLE__)

#include "template.h"

using namespace std::literals;

namespace nghttp2 {

namespace {
const MunitTest tests[]{
  munit_void_test(test_template_immutable_string),
  munit_void_test(test_template_as_uint8_span),
  munit_void_test(test_template_as_string_view),
  munit_void_test(test_template_dlist),
  munit_test_end(),
};
} // namespace

const MunitSuite template_suite{
  .prefix = "/template",
  .tests = tests,
};

void test_template_immutable_string(void) {
  ImmutableString null;

  assert_eq("", as_string_view(null));
  assert_string_equal("", null.c_str());
  assert_eq(0, null.size());
  assert_true(null.empty());

  ImmutableString from_cstr("alpha");

  assert_eq("alpha", as_string_view(from_cstr));
  assert_string_equal("alpha", from_cstr.c_str());
  assert_eq(5, from_cstr.size());
  assert_false(from_cstr.empty());
  assert_true("alpha" == from_cstr);
  assert_true(from_cstr == "alpha");
  assert_true(std::string("alpha") == from_cstr);
  assert_true(from_cstr == std::string("alpha"));

  ImmutableString from_stdstr("alpha"s);

  assert_eq("alpha", as_string_view(from_stdstr));

  // copy constructor
  ImmutableString src("charlie");
  ImmutableString copy = src;

  assert_eq("charlie", as_string_view(copy));
  assert_eq(7, copy.size());

  // copy assignment
  ImmutableString copy2;
  copy2 = src;

  assert_eq("charlie", as_string_view(copy2));
  assert_eq(7, copy2.size());

  // move constructor
  ImmutableString move = std::move(copy);

  assert_eq("charlie", as_string_view(move));
  assert_eq(7, move.size());
  assert_eq("", as_string_view(copy));
  assert_eq(0, copy.size());

  // move assignment
  move = std::move(from_cstr);

  assert_eq("alpha", as_string_view(move));
  assert_eq(5, move.size());
  assert_eq("", as_string_view(from_cstr));
  assert_eq(0, from_cstr.size());

  // from string literal
  auto from_lit = "bravo"_is;

  assert_eq("bravo", as_string_view(from_lit));
  assert_eq(5, from_lit.size());

  // equality
  ImmutableString eq("delta");

  assert_true("delta1" != eq);
  assert_true("delt" != eq);
  assert_true(eq != "delta1");
  assert_true(eq != "delt");

  // operator[]
  ImmutableString br_op("foxtrot");

  assert_eq('f', br_op[0]);
  assert_eq('o', br_op[1]);
  assert_eq('t', br_op[6]);
  assert_eq('\0', br_op[7]);

  // operator==(const ImmutableString &, const ImmutableString &)
  {
    ImmutableString a("foo");
    ImmutableString b("foo");
    ImmutableString c("fo");

    assert_true(a == b);
    assert_true(a != c);
    assert_true(c != b);
  }

#ifndef __APPLE__
  // operator<<
  {
    ImmutableString a("foo");
    std::array<char, 256> buf;
    std::spanstream ss{buf};
    ss << a;

    assert_eq("foo", as_string_view(ss.span()));
  }
#endif // !defined(__APPLE__)

  // operator +=(std::string &, const ImmutableString &)
  {
    std::string a = "alpha";
    a += ImmutableString("bravo");

    assert_eq("alphabravo", a);
  }
}

void test_template_as_uint8_span(void) {
  uint32_t a[2];

  memcpy(&a, "\xc0\xc1\xc2\xc3\xf0\xf1\xf2\xf3", sizeof(a));

  // dynamic extent
  auto s = as_uint8_span(std::span{a, 2});

  assert_eq(sizeof(a), s.size());
  assert_eq(std::dynamic_extent, s.extent);
  assert_memory_equal(s.size(), &a, s.data());

  // non-dynamic extent
  auto t = as_uint8_span(std::span<uint32_t, 2>{a, 2});

  assert_eq(sizeof(a), t.size());
  assert_eq(sizeof(a), t.extent);
  assert_memory_equal(t.size(), &a, t.data());
}

void test_template_as_string_view(void) {
  {
    static constexpr auto a = std::to_array<uint8_t>({'a', 'l', 'p', 'h', 'a'});

    assert_eq("alpha"sv, as_string_view(a));
    assert_eq("alpha"sv,
              as_string_view(std::ranges::begin(a), std::ranges::end(a)));
    assert_eq("alp"sv, as_string_view(std::ranges::begin(a), 3));
  }

  {
    static constexpr auto s = ""s;

    assert_eq(""sv, as_string_view(s));
    assert_eq(""sv, as_string_view(std::ranges::begin(s), std::ranges::end(s)));
  }
}

struct Foo {
  Foo(int n) : dlprev{nullptr}, dlnext{nullptr}, n{n} {}

  Foo *dlprev, *dlnext;
  int n;
};

void test_template_dlist(void) {
  std::array<std::unique_ptr<Foo>, 10> arr;
  int n = 0;
  for (auto &f : arr) {
    f = std::make_unique<Foo>(++n);
  }

  DList<Foo> dl;

  // append
  n = 0;

  for (auto &f : arr) {
    ++n;
    dl.append(f.get());

    assert_eq(static_cast<size_t>(n), dl.size());
  }

  // iteration
  n = 0;

  for (auto f = dl.head; f; f = f->dlnext) {
    ++n;

    assert_eq(n, f->n);
  }

  // move constructor
  auto dl_move = std::move(dl);

  assert_eq(0, dl.size());
  assert_eq(arr.size(), dl_move.size());

  n = 0;

  for (auto f = dl_move.head; f; f = f->dlnext) {
    ++n;

    assert_eq(n, f->n);
  }

  // move assignment
  dl = std::move(dl_move);

  assert_eq(0, dl_move.size());
  assert_eq(arr.size(), dl.size());

  n = 0;

  for (auto f = dl.head; f; f = f->dlnext) {
    ++n;

    assert_eq(n, f->n);
  }

  // remove
  auto del = std::to_array({1, 2, 10, 6, 8});

  for (size_t i = 0; i < del.size(); ++i) {
    dl.remove(arr[static_cast<size_t>(del[i] - 1)].get());

    assert_eq(arr.size() - i - 1, dl.size());
  }

  auto left = std::to_array<int>({3, 4, 5, 7, 9});
  auto head = dl.head;

  for (size_t i = 0; i < left.size(); ++i, head = head->dlnext) {
    assert_not_null(head);
    assert_eq(left[i], head->n);
  }

  head = dl.tail;

  for (size_t i = left.size(); i > 0; --i, head = head->dlprev) {
    assert_not_null(head);
    assert_eq(left[i - 1], head->n);
  }

  // not empty
  assert_false(dl.empty());

  // delete elements while iterating list
  for (auto head = dl.head; head;) {
    auto next = head->dlnext;

    dl.remove(head);

    head = next;
  }

  // empty
  assert_true(dl.empty());
}

} // namespace nghttp2
