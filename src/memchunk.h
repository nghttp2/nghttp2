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

#include "util.h"

namespace nghttp2 {

template <size_t N> struct Memchunk {
  Memchunk()
      : kprev(nullptr), next(nullptr), pos(begin), last(begin), end(begin + N) {
  }
  size_t len() const { return last - pos; }
  size_t left() const { return end - last; }
  void reset() { pos = last = begin; }
  std::unique_ptr<Memchunk> knext;
  Memchunk *kprev;
  Memchunk *next;
  uint8_t *pos, *last;
  uint8_t *end;
  uint8_t begin[N];
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

    auto m = util::make_unique<T>();
    auto p = m.get();
    if (pool) {
      m->knext = std::move(pool);
      m->knext->kprev = m.get();
    }
    pool = std::move(m);
    poolsize += T::size;
    return p;
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

inline void *cpymem(void *dest, const void *src, size_t count) {
  memcpy(dest, src, count);
  return reinterpret_cast<uint8_t *>(dest) + count;
}

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
  size_t append(const void *data, size_t count) {
    if (count == 0) {
      return 0;
    }

    auto p = reinterpret_cast<const uint8_t *>(data);

    if (!tail) {
      head = tail = pool->get();
    }
    auto all = count;

    while (count > 0) {
      auto n = std::min(count, tail->left());
      tail->last = reinterpret_cast<uint8_t *>(cpymem(tail->last, p, n));
      p += n;
      count -= n;
      len += n;
      if (count == 0) {
        break;
      }

      tail->next = pool->get();

      assert(tail != tail->next);
      tail = tail->next;
    }

    return all;
  }
  template <size_t N> size_t append(const char (&s)[N]) {
    return append(s, N - 1);
  }
  size_t remove(void *data, size_t count) {
    if (!tail || count == 0) {
      return 0;
    }
    auto ndata = count;
    auto m = head;

    while (m) {
      auto next = m->next;
      auto n = std::min(count, m->len());

      assert(m->len());
      data = cpymem(data, m->pos, n);
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

} // namespace nghttp2

#endif // MEMCHUNK_H
