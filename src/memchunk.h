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
#ifndef MEMCHUNK_H
#define MEMCHUNK_H

#include "nghttp2_config.h"

#include <limits.h>
#ifdef _WIN32
/* Structure for scatter/gather I/O.  */
struct iovec {
  void *iov_base; /* Pointer to data.  */
  size_t iov_len; /* Length of data.  */
};
#else // !_WIN32
#  include <sys/uio.h>
#endif // !_WIN32

#include <cassert>
#include <cstring>
#include <memory>
#include <array>
#include <algorithm>
#include <string>
#include <utility>

#include "template.h"

namespace nghttp2 {

#define DEFAULT_WR_IOVCNT 16

#if defined(IOV_MAX) && IOV_MAX < DEFAULT_WR_IOVCNT
#  define MAX_WR_IOVCNT IOV_MAX
#else // !defined(IOV_MAX) || IOV_MAX >= DEFAULT_WR_IOVCNT
#  define MAX_WR_IOVCNT DEFAULT_WR_IOVCNT
#endif // !defined(IOV_MAX) || IOV_MAX >= DEFAULT_WR_IOVCNT

template <size_t N> struct Memchunk {
  Memchunk(Memchunk *next_chunk)
    : pos(std::ranges::begin(buf)),
      last(pos),
      knext(next_chunk),
      next(nullptr) {}
  size_t len() const { return as_unsigned(last - pos); }
  size_t left() const {
    return static_cast<size_t>(std::ranges::end(buf) - last);
  }
  void reset() { pos = last = std::ranges::begin(buf); }
  std::array<uint8_t, N> buf;
  uint8_t *pos, *last;
  Memchunk *knext;
  Memchunk *next;
  static const size_t size = N;
};

template <typename T> struct Pool {
  Pool() : pool(nullptr), freelist(nullptr), poolsize(0), freelistsize(0) {}
  ~Pool() { clear(); }
  T *get() {
    if (freelist) {
      auto m = freelist;
      freelist = freelist->next;
      m->next = nullptr;
      m->reset();
      freelistsize -= T::size;
      return m;
    }

    pool = new T{pool};
    poolsize += T::size;
    return pool;
  }
  void recycle(T *m) {
    m->next = freelist;
    freelist = m;
    freelistsize += T::size;
  }
  void clear() {
    freelist = nullptr;
    freelistsize = 0;
    for (auto p = pool; p;) {
      auto knext = p->knext;
      delete p;
      p = knext;
    }
    pool = nullptr;
    poolsize = 0;
  }
  using value_type = T;
  T *pool;
  T *freelist;
  size_t poolsize;
  size_t freelistsize;
};

template <typename Memchunk> struct Memchunks {
  Memchunks(Pool<Memchunk> *pool)
    : pool(pool),
      head(nullptr),
      tail(nullptr),
      len(0),
      mark(nullptr),
      mark_pos(nullptr),
      mark_offset(0) {}
  Memchunks(const Memchunks &) = delete;
  Memchunks(Memchunks &&other) noexcept
    : pool{other.pool}, // keep other.pool
      head{std::exchange(other.head, nullptr)},
      tail{std::exchange(other.tail, nullptr)},
      len{std::exchange(other.len, 0)},
      mark{std::exchange(other.mark, nullptr)},
      mark_pos{std::exchange(other.mark_pos, nullptr)},
      mark_offset{std::exchange(other.mark_offset, 0)} {}
  Memchunks &operator=(const Memchunks &) = delete;
  Memchunks &operator=(Memchunks &&other) noexcept {
    if (this == &other) {
      return *this;
    }

    reset();

    pool = other.pool;
    head = std::exchange(other.head, nullptr);
    tail = std::exchange(other.tail, nullptr);
    len = std::exchange(other.len, 0);
    mark = std::exchange(other.mark, nullptr);
    mark_pos = std::exchange(other.mark_pos, nullptr);
    mark_offset = std::exchange(other.mark_offset, 0);

    return *this;
  }
  ~Memchunks() {
    if (!pool) {
      return;
    }
    for (auto m = head; m;) {
      auto next = m->next;
      pool->recycle(m);
      m = next;
    }
  }
  void append(char c) {
    if (!tail) {
      head = tail = pool->get();
    } else if (tail->left() == 0) {
      tail->next = pool->get();
      tail = tail->next;
    }
    *tail->last++ = as_unsigned(c);
    ++len;
  }
  template <std::input_iterator I> void append(I first, I last) {
    if (first == last) {
      return;
    }

    if (!tail) {
      head = tail = pool->get();
    }

    for (;;) {
      auto n = std::min(static_cast<size_t>(std::ranges::distance(first, last)),
                        tail->left());
      auto iores = std::ranges::copy_n(first, as_signed(n), tail->last);
      first = iores.in;
      tail->last = iores.out;
      len += n;
      if (first == last) {
        break;
      }

      tail->next = pool->get();
      tail = tail->next;
    }

    return;
  }
  void append(const void *src, size_t count) {
    auto s = static_cast<const uint8_t *>(src);
    append(s, s + count);
  }
  template <std::ranges::input_range R>
  requires(!std::is_array_v<std::remove_cvref_t<R>>)
  void append(R &&r) {
    append(std::ranges::begin(r), std::ranges::end(r));
  }
  // first ensures that at least |max_count| bytes are available to
  // store in the current buffer, assuming that the chunk size of the
  // underlying Memchunk is at least |max_count| bytes.  Then call
  // |f|(tail->last) to write data into buffer directly.  |f| must not
  // write more than |max_count| bytes.  It must return the position
  // of the buffer past the last position written.
  template <typename F>
  requires(std::invocable<F &, uint8_t *> &&
           std::is_same_v<std::invoke_result_t<F &, uint8_t *>, uint8_t *>)
  void append(size_t max_count, F f) {
    if (!tail) {
      head = tail = pool->get();
    } else if (tail->left() < max_count) {
      tail->next = pool->get();
      tail = tail->next;
    }

    assert(tail->left() >= max_count);

    auto last = f(tail->last);
    len += static_cast<size_t>(last - tail->last);
    tail->last = last;
  }
  size_t copy(Memchunks &dest) {
    auto m = head;
    while (m) {
      dest.append(m->pos, m->len());
      m = m->next;
    }
    return len;
  }
  size_t remove(void *dest, size_t count) {
    assert(mark == nullptr);

    if (!tail || count == 0) {
      return 0;
    }

    auto first = static_cast<uint8_t *>(dest);
    auto last = first + count;

    auto m = head;

    while (m) {
      auto next = m->next;
      auto n = std::min(static_cast<size_t>(last - first), m->len());

      assert(m->len());
      auto iores = std::ranges::copy_n(m->pos, as_signed(n), first);
      m->pos = iores.in;
      first = iores.out;
      len -= n;
      if (m->len() > 0) {
        break;
      }
      pool->recycle(m);
      m = next;
    }
    head = m;
    if (head == nullptr) {
      tail = nullptr;
    }

    return as_unsigned(first - static_cast<uint8_t *>(dest));
  }
  size_t remove(Memchunks &dest, size_t count) {
    assert(mark == nullptr);

    if (!tail || count == 0) {
      return 0;
    }

    auto left = count;
    auto m = head;

    while (m) {
      auto next = m->next;
      auto n = std::min(left, m->len());

      assert(m->len());
      dest.append(m->pos, n);
      m->pos += n;
      len -= n;
      left -= n;
      if (m->len() > 0) {
        break;
      }
      pool->recycle(m);
      m = next;
    }
    head = m;
    if (head == nullptr) {
      tail = nullptr;
    }

    return count - left;
  }
  size_t remove(Memchunks &dest) {
    assert(pool == dest.pool);
    assert(mark == nullptr);

    if (head == nullptr) {
      return 0;
    }

    auto n = len;

    if (dest.tail == nullptr) {
      dest.head = head;
    } else {
      dest.tail->next = head;
    }

    dest.tail = tail;
    dest.len += len;

    head = tail = nullptr;
    len = 0;

    return n;
  }
  size_t drain(size_t count) {
    assert(mark == nullptr);

    auto ndata = count;
    auto m = head;
    while (m) {
      auto next = m->next;
      auto n = std::min(count, m->len());
      m->pos += n;
      count -= n;
      len -= n;
      if (m->len() > 0) {
        break;
      }

      pool->recycle(m);
      m = next;
    }
    head = m;
    if (head == nullptr) {
      tail = nullptr;
    }
    return ndata - count;
  }
  size_t drain_mark(size_t count) {
    auto ndata = count;
    auto m = head;
    while (m) {
      auto next = m->next;
      auto n = std::min(count, m->len());
      m->pos += n;
      count -= n;
      len -= n;
      mark_offset -= n;

      if (m->len() > 0) {
        assert(mark != m || m->pos <= mark_pos);
        break;
      }
      if (mark == m) {
        assert(m->pos <= mark_pos);

        mark = nullptr;
        mark_pos = nullptr;
        mark_offset = 0;
      }

      pool->recycle(m);
      m = next;
    }
    head = m;
    if (head == nullptr) {
      tail = nullptr;
    }
    return ndata - count;
  }
  int riovec(struct iovec *iov, int iovcnt) const {
    if (!head) {
      return 0;
    }
    auto m = head;
    int i;
    for (i = 0; i < iovcnt && m; ++i, m = m->next) {
      iov[i].iov_base = m->pos;
      iov[i].iov_len = m->len();
    }
    return i;
  }
  int riovec_mark(struct iovec *iov, int iovcnt) {
    if (!head || iovcnt == 0) {
      return 0;
    }

    int i = 0;
    Memchunk *m;
    if (mark) {
      if (mark_pos != mark->last) {
        iov[0].iov_base = mark_pos;
        iov[0].iov_len = mark->len() - as_unsigned(mark_pos - mark->pos);

        mark_pos = mark->last;
        mark_offset += iov[0].iov_len;
        i = 1;
      }
      m = mark->next;
    } else {
      i = 0;
      m = head;
    }

    for (; i < iovcnt && m; ++i, m = m->next) {
      iov[i].iov_base = m->pos;
      iov[i].iov_len = m->len();

      mark = m;
      mark_pos = m->last;
      mark_offset += m->len();
    }

    return i;
  }
  size_t rleft() const { return len; }
  size_t rleft_mark() const { return len - mark_offset; }
  void reset() {
    for (auto m = head; m;) {
      auto next = m->next;
      pool->recycle(m);
      m = next;
    }
    len = 0;
    head = tail = mark = nullptr;
    mark_pos = nullptr;
    mark_offset = 0;
  }

  Pool<Memchunk> *pool;
  Memchunk *head, *tail;
  size_t len;
  Memchunk *mark;
  uint8_t *mark_pos;
  size_t mark_offset;
};

using Memchunk16K = Memchunk<16_k>;
using MemchunkPool = Pool<Memchunk16K>;
using DefaultMemchunks = Memchunks<Memchunk16K>;

inline int limit_iovec(struct iovec *iov, int iovcnt, size_t max) {
  if (max == 0) {
    return 0;
  }
  for (int i = 0; i < iovcnt; ++i) {
    auto d = std::min(max, iov[i].iov_len);
    iov[i].iov_len = d;
    max -= d;
    if (max == 0) {
      return i + 1;
    }
  }
  return iovcnt;
}

// MemchunkBuffer is similar to Buffer, but it uses pooled Memchunk
// for its underlying buffer.
template <typename Memchunk> struct MemchunkBuffer {
  MemchunkBuffer(Pool<Memchunk> *pool) : pool(pool), chunk(nullptr) {}
  MemchunkBuffer(const MemchunkBuffer &) = delete;
  MemchunkBuffer(MemchunkBuffer &&other) noexcept
    : pool(other.pool), chunk(other.chunk) {
    other.chunk = nullptr;
  }
  MemchunkBuffer &operator=(const MemchunkBuffer &) = delete;
  MemchunkBuffer &operator=(MemchunkBuffer &&other) noexcept {
    if (this == &other) {
      return *this;
    }

    pool = other.pool;
    chunk = other.chunk;

    other.chunk = nullptr;

    return *this;
  }

  ~MemchunkBuffer() {
    if (!pool || !chunk) {
      return;
    }
    pool->recycle(chunk);
  }

  // Ensures that the underlying buffer is allocated.
  void ensure_chunk() {
    if (chunk) {
      return;
    }
    chunk = pool->get();
  }

  // Releases the underlying buffer.
  void release_chunk() {
    if (!chunk) {
      return;
    }
    pool->recycle(chunk);
    chunk = nullptr;
  }

  // Returns true if the underlying buffer is allocated.
  bool chunk_avail() const { return chunk != nullptr; }

  // The functions below must be called after the underlying buffer is
  // allocated (use ensure_chunk).

  // MemchunkBuffer provides the same interface functions with Buffer.
  // Since we has chunk as a member variable, pos and last are
  // implemented as wrapper functions.

  uint8_t *pos() const { return chunk->pos; }
  uint8_t *last() const { return chunk->last; }

  size_t rleft() const { return chunk->len(); }
  size_t wleft() const { return chunk->left(); }
  size_t write(const void *src, size_t count) {
    count = std::min(count, wleft());
    auto p = static_cast<const uint8_t *>(src);
    chunk->last = std::ranges::copy_n(p, count, chunk->last).out;
    return count;
  }
  size_t write(size_t count) {
    count = std::min(count, wleft());
    chunk->last += count;
    return count;
  }
  size_t drain(size_t count) {
    count = std::min(count, rleft());
    chunk->pos += count;
    return count;
  }
  size_t drain_reset(size_t count) {
    count = std::min(count, rleft());
    chunk->last = std::ranges::copy(chunk->pos + count, chunk->last,
                                    std::ranges::begin(chunk->buf))
                    .out;
    chunk->pos = std::ranges::begin(chunk->buf);
    return count;
  }
  void reset() { chunk->reset(); }
  uint8_t *begin() { return std::ranges::begin(chunk->buf); }
  uint8_t &operator[](size_t n) { return chunk->buf[n]; }
  const uint8_t &operator[](size_t n) const { return chunk->buf[n]; }

  Pool<Memchunk> *pool;
  Memchunk *chunk;
};

using DefaultMemchunkBuffer = MemchunkBuffer<Memchunk16K>;

} // namespace nghttp2

#endif // MEMCHUNK_H
