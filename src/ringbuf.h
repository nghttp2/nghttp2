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
#ifndef RINGBUF_H
#define RINGBUF_H

#include <sys/uio.h>

#include <cstring>
#include <algorithm>

namespace nghttp2 {

template <size_t N> struct RingBuf {
  RingBuf() : pos(0), len(0) {}
  // Returns the number of bytes to read.
  size_t rleft() const { return len; }
  // Returns the number of bytes this buffer can store.
  size_t wleft() const { return N - len; }
  // Writes up to min(wleft(), |count|) bytes from buffer pointed by
  // |buf|.  Returns number of bytes written.
  size_t write(const void *buf, size_t count) {
    count = std::min(count, wleft());
    auto last = (pos + len) % N;
    if (count > N - last) {
      auto c = N - last;
      memcpy(begin + last, buf, c);
      memcpy(begin, reinterpret_cast<const uint8_t *>(buf) + c, count - c);
    } else {
      memcpy(begin + last, buf, count);
    }
    len += count;
    return count;
  }
  // Drains min(rleft(), |count|) bytes from start of the buffer.
  size_t drain(size_t count) {
    count = std::min(count, rleft());
    pos = (pos + count) % N;
    len -= count;
    return count;
  }
  // Returns pointer to the next contiguous readable buffer and its
  // length.
  std::pair<const void *, size_t> get() const {
    if (pos + len > N) {
      return {begin + pos, N - pos};
    }
    return {begin + pos, len};
  }
  void reset() { pos = len = 0; }
  // Fills |iov| for reading.  |iov| must contain at least 2 elements.
  // Returns the number of filled elements.
  int riovec(struct iovec *iov) {
    if (len == 0) {
      return 0;
    }
    if (pos + len > N) {
      auto c = N - pos;
      iov[0].iov_base = begin + pos;
      iov[0].iov_len = c;
      iov[1].iov_base = begin;
      iov[1].iov_len = len - c;
      return 2;
    }
    iov[0].iov_base = begin + pos;
    iov[0].iov_len = len;
    return 1;
  }
  // Fills |iov| for writing.  |iov| must contain at least 2 elements.
  // Returns the number of filled elements.
  int wiovec(struct iovec *iov) {
    if (len == N) {
      return 0;
    }
    if (pos == 0) {
      iov[0].iov_base = begin + pos + len;
      iov[0].iov_len = N - pos - len;
      return 1;
    }
    if (pos + len < N) {
      auto c = N - pos - len;
      iov[0].iov_base = begin + pos + len;
      iov[0].iov_len = c;
      iov[1].iov_base = begin;
      iov[1].iov_len = N - len - c;
      return 2;
    }
    auto last = (pos + len) % N;
    iov[0].iov_base = begin + last;
    iov[0].iov_len = N - len;
    return 1;
  }
  size_t pos;
  size_t len;
  uint8_t begin[N];
};

} // namespace nghttp2

#endif // RINGBUF_H
