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
#ifndef BASE64_H
#define BASE64_H

#include "nghttp2_config.h"

#include <string>

#include "template.h"
#include "allocator.h"

namespace nghttp2 {

namespace base64 {

namespace {
constexpr char B64_CHARS[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
};
} // namespace

constexpr size_t encode_length(size_t n) { return (n + 2) / 3 * 4; }

template <std::input_iterator I, std::weakly_incrementable O>
requires(std::indirectly_writable<O, char>)
constexpr O encode(I first, I last, O result) {
  using result_type = std::iter_value_t<O>;

  auto len = std::ranges::distance(first, last);
  if (len == 0) {
    return result;
  }

  auto p = result;

  for (;;) {
    len = std::ranges::distance(first, last);
    if (len < 3) {
      break;
    }

    auto n = static_cast<uint32_t>(static_cast<uint8_t>(*first++) << 16);
    n += static_cast<uint32_t>(static_cast<uint8_t>(*first++) << 8);
    n += static_cast<uint8_t>(*first++);
    *p++ = static_cast<result_type>(B64_CHARS[n >> 18]);
    *p++ = static_cast<result_type>(B64_CHARS[(n >> 12) & 0x3fu]);
    *p++ = static_cast<result_type>(B64_CHARS[(n >> 6) & 0x3fu]);
    *p++ = static_cast<result_type>(B64_CHARS[n & 0x3fu]);
  }

  switch (len) {
  case 2: {
    auto n = static_cast<uint32_t>(static_cast<uint8_t>(*first++) << 16);
    n += static_cast<uint32_t>(static_cast<uint8_t>(*first++) << 8);
    *p++ = static_cast<result_type>(B64_CHARS[n >> 18]);
    *p++ = static_cast<result_type>(B64_CHARS[(n >> 12) & 0x3fu]);
    *p++ = static_cast<result_type>(B64_CHARS[(n >> 6) & 0x3fu]);
    *p++ = '=';
    break;
  }
  case 1: {
    auto n = static_cast<uint32_t>(static_cast<uint8_t>(*first++) << 16);
    *p++ = static_cast<result_type>(B64_CHARS[n >> 18]);
    *p++ = static_cast<result_type>(B64_CHARS[(n >> 12) & 0x3fu]);
    *p++ = '=';
    *p++ = '=';
    break;
  }
  }

  return p;
}

template <std::ranges::input_range R, std::weakly_incrementable O>
requires(std::indirectly_writable<O, char> &&
         !std::is_array_v<std::remove_cvref_t<R>>)
constexpr O encode(R &&r, O result) {
  return encode(std::ranges::begin(r), std::ranges::end(r), std::move(result));
}

template <std::ranges::input_range R>
requires(!std::is_array_v<std::remove_cvref_t<R>>)
constexpr std::string encode(R &&r) {
  std::string res;
  auto len = std::ranges::size(r);
  if (len == 0) {
    return res;
  }

  res.resize((len + 2) / 3 * 4);

  encode(std::forward<R>(r), std::ranges::begin(res));

  return res;
}

constinit const int B64_INDEX_TABLE[] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60,
  61, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
  11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1,
  -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
  43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1};

template <std::input_iterator I, std::weakly_incrementable O>
requires(std::indirectly_writable<O, uint8_t>)
constexpr O decode(I first, I last, O result) {
  using result_type = std::iter_value_t<O>;

  assert(std::ranges::distance(first, last) % 4 == 0);
  auto p = result;
  for (; first != last;) {
    uint32_t n = 0;
    for (int i = 1; i <= 4; ++i, ++first) {
      auto idx = B64_INDEX_TABLE[static_cast<size_t>(*first)];
      if (idx == -1) {
        if (i <= 2) {
          return result;
        }
        if (i == 3) {
          if (*first == '=' && *std::ranges::next(first, 1) == '=' &&
              std::ranges::next(first, 2) == last) {
            *p++ = static_cast<result_type>(n >> 16);
            return p;
          }
          return result;
        }
        if (*first == '=' && std::ranges::next(first, 1) == last) {
          *p++ = static_cast<result_type>(n >> 16);
          *p++ = n >> 8 & 0xffu;
          return p;
        }
        return result;
      }

      n += static_cast<uint32_t>(idx) << (24 - i * 6);
    }

    *p++ = static_cast<result_type>(n >> 16);
    *p++ = n >> 8 & 0xffu;
    *p++ = n & 0xffu;
  }

  return p;
}

template <std::ranges::input_range R>
requires(!std::is_array_v<std::remove_cvref_t<R>>)
std::span<const uint8_t> decode(BlockAllocator &balloc, R &&r) {
  auto len = std::ranges::size(r);
  if (len % 4 != 0) {
    return {};
  }
  auto iov = make_byte_ref(balloc, len / 4 * 3 + 1);
  auto p = std::ranges::begin(iov);

  p = decode(std::ranges::begin(r), std::ranges::end(r), p);
  *p = '\0';

  return {std::ranges::begin(iov), p};
}

} // namespace base64

} // namespace nghttp2

#endif // BASE64_H
