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

#include <sys/uio.h>

#include <cstring>
#include <memory>
#include <array>

#include "util.h"

namespace nghttp2 {

template <size_t N> struct Memchunk {
  Memchunk(std::unique_ptr<Memchunk> next_chunk)
      : pos(std::begin(buf)), last(pos), knext(std::move(next_chunk)),
        kprev(nullptr), next(nullptr) {
    if (knext) {
      knext->kprev = this;
    }
  }
  size_t len() const { return last - pos; }
  size_t left() const { return std::end(buf) - last; }
  void reset() { pos = last = std::begin(buf); }
  std::array<uint8_t, N> buf;
  uint8_t *pos, *last;
  std::unique_ptr<Memchunk> knext;
  Memchunk *kprev;
  Memchunk *next;
  static const size_t size = N;
};

template <typename T> struct Pool {
  Pool() : pool(nullptr), freelist(nullptr), poolsize(0) {}
  T *get() {
    if (freelist) {
      auto m = freelist;
      freelist = freelist->next;
      m->next = nullptr;
      m->reset();
      return m;
    }

    pool = util::make_unique<T>(std::move(pool));
    poolsize += T::size;
    return pool.get();
  }
  void recycle(T *m) {
    if (freelist) {
      m->next = freelist;
    } else {
      m->next = nullptr;
    }
    freelist = m;
  }
  void shrink(size_t max) {
    auto m = freelist;
    for (; m && poolsize > max;) {
      auto next = m->next;
      poolsize -= T::size;
      auto p = m->kprev;
      if (p) {
        p->knext = std::move(m->knext);
        if (p->knext) {
          p->knext->kprev = p;
        }
      } else {
        pool = std::move(m->knext);
        if (pool) {
          pool->kprev = nullptr;
        }
      }
      m = next;
    }
    freelist = m;
  }
  using value_type = T;
  std::unique_ptr<T> pool;
  T *freelist;
  size_t poolsize;
};

template <typename Memchunk> struct Memchunks {
  Memchunks(Pool<Memchunk> *pool)
      : pool(pool), head(nullptr), tail(nullptr), len(0) {}
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
  size_t append(const void *src, size_t count) {
    if (count == 0) {
      return 0;
    }

    auto first = static_cast<const uint8_t *>(src);
    auto last = first + count;

    if (!tail) {
      head = tail = pool->get();
    }

    for (;;) {
      auto n = std::min(static_cast<size_t>(last - first), tail->left());
      tail->last = std::copy_n(first, n, tail->last);
      first += n;
      len += n;
      if (first == last) {
        break;
      }

      tail->next = pool->get();
      tail = tail->next;
    }

    return count;
  }
  template <size_t N> size_t append(const char (&s)[N]) {
    return append(s, N - 1);
  }
  size_t remove(void *dest, size_t count) {
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
      first = std::copy_n(m->pos, n, first);
      m->pos += n;
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

    return first - static_cast<uint8_t *>(dest);
  }
  size_t drain(size_t count) {
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
  int riovec(struct iovec *iov, int iovcnt) {
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
  size_t rleft() const { return len; }

  Pool<Memchunk> *pool;
  Memchunk *head, *tail;
  size_t len;
};

using Memchunk16K = Memchunk<16384>;
using MemchunkPool = Pool<Memchunk16K>;
using DefaultMemchunks = Memchunks<Memchunk16K>;

#define DEFAULT_WR_IOVCNT 16

#if defined(IOV_MAX) && IOV_MAX < DEFAULT_WR_IOVCNT
#define MAX_WR_IOVCNT IOV_MAX
#else // !defined(IOV_MAX) || IOV_MAX >= DEFAULT_WR_IOVCNT
#define MAX_WR_IOVCNT DEFAULT_WR_IOVCNT
#endif // !defined(IOV_MAX) || IOV_MAX >= DEFAULT_WR_IOVCNT

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

} // namespace nghttp2

#endif // MEMCHUNK_H
