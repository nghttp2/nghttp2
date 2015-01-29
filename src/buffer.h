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

#include <cstring>
#include <algorithm>

namespace nghttp2 {

template <size_t N> struct Buffer {
  Buffer() : pos(begin), last(begin) {}
  // Returns the number of bytes to read.
  size_t rleft() const { return last - pos; }
  // Returns the number of bytes this buffer can store.
  size_t wleft() const { return begin + N - last; }
  // Writes up to min(wleft(), |count|) bytes from buffer pointed by
  // |buf|.  Returns number of bytes written.
  size_t write(const void *buf, size_t count) {
    count = std::min(count, wleft());
    memcpy(last, buf, count);
    last += count;
    return count;
  }
  size_t write(size_t count) {
    count = std::min(count, wleft());
    last += count;
    return count;
  }
  // Drains min(rleft(), |count|) bytes from start of the buffer.
  size_t drain(size_t count) {
    count = std::min(count, rleft());
    pos += count;
    return count;
  }
  void reset() { pos = last = begin; }
  uint8_t begin[N];
  uint8_t *pos, *last;
};

} // namespace nghttp2

#endif // RINGBUF_H
