/*
 * nghttp2 - HTTP/2 C Library
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
#ifndef BUFFER_H
#define BUFFER_H

#include "nghttp2_config.h"

#include <algorithm>

#include "template.h"

namespace nghttp2 {

template <size_t N> struct Buffer {
  constexpr Buffer() noexcept : pos(buf), last(pos) {}
  // Returns the number of bytes to read.
  constexpr size_t rleft() const noexcept { return as_unsigned(last - pos); }
  // Returns the number of bytes this buffer can store.
  constexpr size_t wleft() const noexcept {
    return as_unsigned(&buf[N] - last);
  }
  // Writes up to min(wleft(), |count|) bytes from buffer pointed by
  // |src|.  Returns number of bytes written.
  constexpr size_t write(const void *src, size_t count) {
    count = std::min(count, wleft());
    auto p = static_cast<const uint8_t *>(src);
    last = std::ranges::copy_n(p, as_signed(count), last).out;
    return count;
  }
  constexpr size_t write(size_t count) {
    count = std::min(count, wleft());
    last += count;
    return count;
  }
  // Drains min(rleft(), |count|) bytes from start of the buffer.
  constexpr size_t drain(size_t count) {
    count = std::min(count, rleft());
    pos += count;
    return count;
  }
  constexpr size_t drain_reset(size_t count) {
    count = std::min(count, rleft());
    last = std::ranges::copy(pos + count, last, buf).out;
    pos = buf;
    return count;
  }
  constexpr void reset() noexcept { pos = last = buf; }
  constexpr uint8_t *begin() noexcept { return buf; }
  constexpr uint8_t &operator[](size_t n) { return buf[n]; }
  constexpr const uint8_t &operator[](size_t n) const { return buf[n]; }
  uint8_t buf[N];
  uint8_t *pos, *last;
};

} // namespace nghttp2

#endif // BUFFER_H
