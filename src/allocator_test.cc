/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2026 nghttp2 contributors
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
#include "allocator_test.h"

#include "munitxx.h"

#include <nghttp2/nghttp2.h>

#include "util.h"
#include "template.h"

using namespace std::literals;

namespace nghttp2 {

namespace {
const MunitTest tests[]{
  munit_void_test(test_allocator_alloc),
  munit_void_test(test_allocator_realloc),
  munit_void_test(test_make_string_ref),
  munit_void_test(test_concat_string_ref),
  munit_void_test(test_realloc_concat_string_ref),
  munit_test_end(),
};
} // namespace

const MunitSuite allocator_suite{
  .prefix = "/allocator",
  .tests = tests,
};

namespace {
auto data = []() {
  std::array<uint8_t, 4096> data;

  std::ranges::fill(data, 0xfe);

  return data;
}();
} // namespace

void test_allocator_alloc(void) {
  {
    BlockAllocator balloc{4096, 1024};

    auto p = balloc.alloc(117);

    assert_size(117, ==, std::ranges::size(p));

    // Check p is writable
    std::ranges::copy(std::span{data}.first(std::ranges::size(p)),
                      std::ranges::begin(p));

    assert_memory_equal(std::ranges::size(p), std::ranges::data(data),
                        std::ranges::data(p));

    // Check the isolation threshold works.
    assert_ptr_equal(balloc.retain, balloc.head);

    p = balloc.alloc(1024);

    std::ranges::copy(std::span{data}.first(std::ranges::size(p)),
                      std::ranges::begin(p));

    assert_memory_equal(std::ranges::size(p), std::ranges::data(data),
                        std::ranges::data(p));
    assert_ptr_not_equal(balloc.retain, balloc.head);
  }

  {
    BlockAllocator balloc{32, 32};

    // This consumes the allocated block.
    auto p = balloc.alloc(8);

    assert_size(8, ==, std::ranges::size(p));
    assert_ptr_equal(balloc.head->last, balloc.head->end);

    // This allocates new block.
    p = balloc.alloc(8);

    assert_not_null(balloc.retain->next);
  }
}

void test_allocator_realloc(void) {
  {
    BlockAllocator balloc{4096, 1024};

    constexpr size_t alloclen = 100;

    auto p = balloc.alloc(alloclen);
    auto orig_ptr = std::ranges::data(p);

    p = balloc.realloc(std::ranges::data(p), 110);

    assert_ptr_not_equal(orig_ptr, std::ranges::data(p));
    assert_size(200, ==, balloc.get_alloc_length(std::ranges::data(p)));
    assert_size(110, ==, std::ranges::size(p));
  }

  {
    BlockAllocator balloc{4096, 1024};

    auto p = balloc.alloc(100);
    auto orig_ptr = std::ranges::data(p);

    p = balloc.realloc(std::ranges::data(p), 100);

    assert_ptr_equal(orig_ptr, std::ranges::data(p));
    assert_size(100, ==, std::ranges::size(p));
  }
}

void test_make_string_ref(void) {
  BlockAllocator balloc{256, 256};

  auto s = make_string_ref(balloc, "foo the bar"sv);

  assert_stdsv_equal("foo the bar"sv, s);
}

void test_concat_string_ref(void) {
  BlockAllocator balloc{256, 256};

  auto s = concat_string_ref(balloc, "alpha "sv, "bravo "sv, "charlie"sv);

  assert_stdsv_equal("alpha bravo charlie"sv, s);
}

void test_realloc_concat_string_ref(void) {
  BlockAllocator balloc{256, 256};

  auto s = make_string_ref(balloc, "alpha"sv);
  assert_size(6, ==,
              balloc.get_alloc_length(
                reinterpret_cast<const uint8_t *>(std::ranges::data(s))));

  auto t = realloc_concat_string_ref(balloc, s, " "sv, "bravo"sv);

  assert_stdsv_equal("alpha bravo"sv, t);
  assert_ptr_not_equal(std::ranges::data(s), std::ranges::data(t));
  assert_size(12, ==,
              balloc.get_alloc_length(
                reinterpret_cast<const uint8_t *>(std::ranges::data(t))));

  auto u = realloc_concat_string_ref(balloc, t, " charlie"sv);

  assert_stdsv_equal("alpha bravo charlie"sv, u);
  assert_ptr_not_equal(std::ranges::data(t), std::ranges::data(u));
  assert_size(24, ==,
              balloc.get_alloc_length(
                reinterpret_cast<const uint8_t *>(std::ranges::data(u))));

  auto v = realloc_concat_string_ref(balloc, u, " delta"sv);

  assert_stdsv_equal("alpha bravo charlie delta"sv, v);
  assert_ptr_not_equal(std::ranges::data(u), std::ranges::data(v));
  assert_size(48, ==,
              balloc.get_alloc_length(
                reinterpret_cast<const uint8_t *>(std::ranges::data(v))));

  auto w = realloc_concat_string_ref(balloc, v, " echo"sv);

  assert_stdsv_equal("alpha bravo charlie delta echo"sv, w);
  assert_ptr_equal(std::ranges::data(v), std::ranges::data(w));
}

} // namespace nghttp2
