/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2015 Tatsuhiro Tsujikawa
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
#include "memchunk_test.h"

#include <nghttp2/nghttp2.h>

#include "memchunk.h"
#include "util.h"

using namespace std::literals;

namespace nghttp2 {

namespace {
const MunitTest tests[]{
  munit_void_test(test_pool_recycle),
  munit_void_test(test_memchunks_append),
  munit_void_test(test_memchunks_drain),
  munit_void_test(test_memchunks_remove),
  munit_void_test(test_memchunks_riovec),
  munit_void_test(test_memchunks_peek),
  munit_void_test(test_memchunks_recycle),
  munit_void_test(test_memchunks_reset),
  munit_void_test(test_memchunks_reserve),
  munit_void_test(test_memchunkbuffer_drain_reset),
  munit_void_test(test_memchunkbuffer_peek),
  munit_test_end(),
};
} // namespace

const MunitSuite memchunk_suite{
  .prefix = "/memchunk",
  .tests = tests,
};

void test_pool_recycle(void) {
  MemchunkPool pool;

  assert_null(pool.pool);
  assert_eq(0, pool.poolsize);
  assert_null(pool.freelist);

  auto m1 = pool.get();

  assert_eq(m1, pool.pool);
  assert_eq(MemchunkPool::value_type::size, pool.poolsize);
  assert_null(pool.freelist);

  auto m2 = pool.get();

  assert_eq(m2, pool.pool);
  assert_eq(2 * MemchunkPool::value_type::size, pool.poolsize);
  assert_null(pool.freelist);
  assert_eq(m1, m2->knext);
  assert_null(m1->knext);

  auto m3 = pool.get();

  assert_eq(m3, pool.pool);
  assert_eq(3 * MemchunkPool::value_type::size, pool.poolsize);
  assert_null(pool.freelist);

  pool.recycle(m3);

  assert_eq(m3, pool.pool);
  assert_eq(3 * MemchunkPool::value_type::size, pool.poolsize);
  assert_eq(m3, pool.freelist);

  auto m4 = pool.get();

  assert_eq(m3, m4);
  assert_eq(m4, pool.pool);
  assert_eq(3 * MemchunkPool::value_type::size, pool.poolsize);
  assert_null(pool.freelist);

  pool.recycle(m2);
  pool.recycle(m1);

  assert_eq(m1, pool.freelist);
  assert_eq(m2, m1->next);
  assert_null(m2->next);
}

using Memchunk16 = Memchunk<16>;
using MemchunkPool16 = Pool<Memchunk16>;
using Memchunks16 = Memchunks<Memchunk16>;
using MemchunkBuffer16 = MemchunkBuffer<Memchunk16>;

void test_memchunks_append(void) {
  MemchunkPool16 pool;
  Memchunks16 chunks(&pool);

  chunks.append("012"sv);

  auto m = chunks.tail;

  assert_eq(3, m->len());
  assert_eq(13, m->left());

  chunks.append("3456789abcdef@"sv);

  assert_eq(16, m->len());
  assert_eq(0, m->left());

  m = chunks.tail;

  assert_eq(1, m->len());
  assert_eq(15, m->left());
  assert_eq(17, chunks.rleft());

  std::array<uint8_t, 16> buf;
  size_t nread;

  nread = chunks.remove(std::span{buf}.first(8));

  assert_eq("01234567"sv, as_string_view(std::span{buf}.first(nread)));
  assert_eq(9, chunks.rleft());

  nread = chunks.remove(buf);

  assert_eq("89abcdef@"sv, as_string_view(std::span{buf}.first(nread)));
  assert_eq(0, chunks.rleft());
  assert_null(chunks.head);
  assert_null(chunks.tail);
  assert_eq(32, pool.poolsize);
}

void test_memchunks_drain(void) {
  MemchunkPool16 pool;
  Memchunks16 chunks(&pool);

  chunks.append("0123456789"sv);

  size_t nread;

  nread = chunks.drain(3);

  assert_eq(3, nread);

  std::array<uint8_t, 16> buf;

  nread = chunks.remove(buf);

  assert_eq("3456789"sv, as_string_view(std::span{buf}.first(nread)));
}

void test_memchunks_remove(void) {
  MemchunkPool16 pool;
  Memchunks16 chunks(&pool);

  chunks.append("0123456789"sv);

  std::array<uint8_t, 16> buf;

  auto nread = chunks.remove(std::span{buf}.first(1));

  assert_eq("0"sv, as_string_view(std::span{buf}.first(nread)));

  nread = chunks.remove(buf);

  assert_eq("123456789"sv, as_string_view(std::span{buf}.first(nread)));
}

void test_memchunks_riovec(void) {
  MemchunkPool16 pool;
  Memchunks16 chunks(&pool);

  std::array<char, 3 * 16> buf{};

  chunks.append(buf.data(), buf.size());

  std::array<struct iovec, 2> iovbuf;
  auto iov = chunks.riovec(iovbuf);

  auto m = chunks.head;

  assert_eq(2, iov.size());
  assert_eq(m->buf.data(), iov[0].iov_base);
  assert_eq(m->len(), iov[0].iov_len);

  m = m->next;

  assert_eq(m->buf.data(), iov[1].iov_base);
  assert_eq(m->len(), iov[1].iov_len);

  chunks.drain(2 * 16);

  iov = chunks.riovec(iovbuf);

  assert_eq(1, iov.size());

  m = chunks.head;
  assert_eq(m->buf.data(), iov[0].iov_base);
  assert_eq(m->len(), iov[0].iov_len);
}

void test_memchunks_peek(void) {
  MemchunkPool16 pool;
  Memchunks16 chunks(&pool);

  assert_true(chunks.peek().empty());

  std::array<char, 3 * 16> buf{};

  chunks.append(buf.data(), buf.size());

  auto data = chunks.peek();

  auto m = chunks.head;

  assert_eq(m->buf.data(), data.data());
  assert_eq(m->len(), data.size());
}

void test_memchunks_recycle(void) {
  MemchunkPool16 pool;
  {
    Memchunks16 chunks(&pool);
    std::array<char, 32> buf{};
    chunks.append(buf.data(), buf.size());
  }
  assert_eq(32, pool.poolsize);
  assert_not_null(pool.freelist);

  auto m = pool.freelist;
  m = m->next;

  assert_not_null(m);
  assert_null(m->next);
}

void test_memchunks_reset(void) {
  MemchunkPool16 pool;
  Memchunks16 chunks(&pool);

  std::array<uint8_t, 32> b{};

  chunks.append(b.data(), b.size());

  assert_eq(32, chunks.rleft());

  chunks.reset();

  assert_eq(0, chunks.rleft());
  assert_null(chunks.head);
  assert_null(chunks.tail);

  auto m = pool.freelist;

  assert_not_null(m);
  assert_not_null(m->next);
  assert_null(m->next->next);
}

void test_memchunks_reserve(void) {
  MemchunkPool16 pool;
  Memchunks16 chunks(&pool);
  std::array<iovec, 2> iovbuf;

  chunks.append(8, [](auto result) {
    return std::ranges::copy("foobar00"sv, std::move(result)).out;
  });

  assert_eq(8, chunks.rleft());

  assert_eq((std::vector{
              {
                "foobar00"sv,
              },
            }),
            chunks.riovec(iovbuf) | std::ranges::views::transform([](auto &&r) {
              return as_string_view(
                std::span{static_cast<const char *>(r.iov_base), r.iov_len});
            }) |
              std::ranges::to<std::vector>());

  chunks.reset();

  chunks.append("012345678"sv);
  chunks.append(8, [](auto result) {
    return std::ranges::copy("foobar00"sv, std::move(result)).out;
  });

  assert_eq(17, chunks.rleft());

  assert_eq((std::vector{
              {
                "012345678"sv,
                "foobar00"sv,
              },
            }),
            chunks.riovec(iovbuf) | std::ranges::views::transform([](auto &&r) {
              return as_string_view(
                std::span{static_cast<const char *>(r.iov_base), r.iov_len});
            }) |
              std::ranges::to<std::vector>());
}

void test_memchunkbuffer_drain_reset(void) {
  MemchunkPool16 pool;
  MemchunkBuffer16 buf(&pool);

  buf.ensure_chunk();
  auto data = "0123456789"sv;
  std::ranges::copy(data, buf.begin());
  buf.write(data.size());

  auto nread = buf.drain_reset(3);

  assert_eq(3, nread);
  assert_eq(buf.begin(), buf.chunk->pos);
  assert_eq(7, buf.rleft());
  assert_eq(buf.begin() + buf.rleft(), buf.chunk->last);
}

void test_memchunkbuffer_peek(void) {
  MemchunkPool16 pool;
  MemchunkBuffer16 buf(&pool);

  buf.ensure_chunk();
  static constexpr auto data = "0123456789"sv;
  std::ranges::copy(data, buf.begin());
  buf.write(data.size());

  assert_eq(data, as_string_view(buf.peek()));
}

} // namespace nghttp2
