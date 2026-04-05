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
#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include "nghttp2_config.h"

#ifndef _WIN32
#  include <sys/uio.h>
#endif // !defined(_WIN32)

#include <cassert>
#include <utility>
#include <span>
#include <algorithm>

#include "template.h"

namespace nghttp2 {

struct MemBlock {
  // The next MemBlock to chain them.  This is for book keeping
  // purpose to free them later.
  MemBlock *next;
  // begin is the pointer to the beginning of buffer.  last is the
  // location of next write.  end is the one beyond of the end of the
  // buffer.
  uint8_t *begin, *last, *end;
};

inline constexpr size_t ALIGNMENT = 16;
static_assert((sizeof(MemBlock) & (ALIGNMENT - 1)) == 0);

struct ChunkHead {
  union {
    size_t size;
    uint64_t pad1;
  };
  uint64_t pad2;
};

static_assert(sizeof(ChunkHead) == ALIGNMENT);

// BlockAllocator allocates memory block with given size at once, and
// cuts the region from it when allocation is requested.  If the
// requested size is larger than given threshold (plus small internal
// overhead), it will be allocated in a distinct buffer on demand.
// The |isolation_threshold| must be less than or equal to
// |block_size|.
struct BlockAllocator {
  BlockAllocator(size_t block_size, size_t isolation_threshold)
    : block_size{block_size},
      isolation_threshold{std::min(block_size, isolation_threshold)} {
    assert(isolation_threshold <= block_size);
  }

  ~BlockAllocator() { reset(); }

  BlockAllocator(BlockAllocator &&other) noexcept
    : retain{std::exchange(other.retain, nullptr)},
      head{std::exchange(other.head, nullptr)},
      block_size{other.block_size},
      isolation_threshold{other.isolation_threshold} {}

  BlockAllocator &operator=(BlockAllocator &&other) noexcept {
    if (this == &other) {
      return *this;
    }

    reset();

    retain = std::exchange(other.retain, nullptr);
    head = std::exchange(other.head, nullptr);
    block_size = other.block_size;
    isolation_threshold = other.isolation_threshold;

    return *this;
  }

  BlockAllocator(const BlockAllocator &) = delete;
  BlockAllocator &operator=(const BlockAllocator &) = delete;

  void reset() {
    for (auto mb = retain; mb;) {
      auto next = mb->next;
      operator delete[](reinterpret_cast<uint8_t *>(mb),
                        std::align_val_t(ALIGNMENT));
      mb = next;
    }

    retain = nullptr;
    head = nullptr;
  }

  MemBlock *alloc_mem_block(size_t size) {
    auto space = sizeof(MemBlock) + size;
    auto block = new (std::align_val_t(ALIGNMENT)) uint8_t[space];
    auto mb = new (block) MemBlock{
      .next = retain,
      .begin = block + sizeof(MemBlock),
      .last = block + sizeof(MemBlock),
      .end = block + space,
    };

    retain = mb;

    return mb;
  }

  constexpr size_t alloc_unit(size_t size) { return sizeof(ChunkHead) + size; }

  std::span<uint8_t> alloc(size_t size) {
    auto au = alloc_unit(size);

    if (au >= isolation_threshold) {
      // We will store the allocated size in size_t field.
      auto mb = alloc_mem_block(alloc_unit(size));
      auto ch = new (mb->begin) ChunkHead{};
      ch->size = size;
      mb->last = mb->end;
      return {mb->begin + sizeof(ChunkHead), size};
    }

    if (!head || static_cast<size_t>(head->end - head->last) < au) {
      head = alloc_mem_block(block_size);
    }

    // We will store the allocated size in size_t field.
    auto ch = new (head->last) ChunkHead();
    ch->size = size;

    auto res = head->last + sizeof(ChunkHead);
    head->last += au;

    auto space = as_unsigned(head->end - head->last);
    void *ptr = head->last;
    if (std::align(ALIGNMENT, sizeof(ChunkHead), ptr, space)) {
      head->last = static_cast<uint8_t *>(ptr);
    } else {
      head->last = head->end;
    }

    return {res, size};
  }

  // Returns allocated size for memory pointed by |ptr|.  We assume
  // that |ptr| was returned from alloc() or realloc().
  size_t get_alloc_length(const uint8_t *ptr) {
    return reinterpret_cast<const ChunkHead *>(ptr - sizeof(ChunkHead))->size;
  }

  // Allocates memory of at least |size| bytes.  If |ptr| is nullptr,
  // this is equivalent to alloc(size).  If |ptr| is not nullptr,
  // obtain the allocated size for |ptr|, assuming that |ptr| was
  // returned from alloc() or realloc().  If the allocated size is
  // greater than or equal to size, std::span{|ptr|, |size|} is
  // returned.  Otherwise, allocates at least |size| bytes of memory,
  // and the original content pointed by |ptr| is copied to the newly
  // allocated memory, and returns the std::span{p, |size|}, where p
  // is the pointer to the allocated memory.
  std::span<uint8_t> realloc(const uint8_t *ptr, size_t size) {
    if (!ptr) {
      return alloc(size);
    }

    auto alloclen = get_alloc_length(ptr);
    if (size <= alloclen) {
      return {const_cast<uint8_t *>(ptr), size};
    }

    auto nalloclen = std::max(size, alloclen * 2);
    auto res = alloc(nalloclen);

    std::ranges::copy(std::span{ptr, alloclen}, std::ranges::begin(res));

    return res.first(size);
  }

  // This holds live memory block to free them in dtor.
  MemBlock *retain{};
  // Current memory block to use.
  MemBlock *head{};
  // size of single memory block
  size_t block_size;
  // if allocation greater or equal to isolation_threshold bytes is
  // requested, allocate dedicated block.
  size_t isolation_threshold;
};

// Makes a copy of a range [|first|, |last|).  The resulting string
// will be NULL-terminated.
template <std::forward_iterator I>
std::string_view make_string_ref(BlockAllocator &alloc, I first, I last) {
  auto len = as_unsigned(std::ranges::distance(first, last));
  auto res = alloc.alloc(len + 1);
  *std::ranges::copy(first, last, std::ranges::begin(res)).out = '\0';

  return as_string_view(res.first(len));
}

// Makes a copy of |r| as std::string_view.  The resulting string will be
// NULL-terminated.
template <std::ranges::forward_range R>
requires(!std::is_array_v<std::remove_cvref_t<R>>)
std::string_view make_string_ref(BlockAllocator &alloc, R &&r) {
  return make_string_ref(alloc, std::ranges::begin(r), std::ranges::end(r));
}

// private function used in concat_string_ref.  this is the base
// function of concat_string_ref_count().
constexpr size_t concat_string_ref_count(size_t acc) { return acc; }

// private function used in concat_string_ref.  This function counts
// the sum of length of given arguments.  The calculated length is
// accumulated, and passed to the next function.
template <std::ranges::sized_range R, std::ranges::sized_range... Args>
requires(!std::is_array_v<std::remove_cvref_t<R>>)
constexpr size_t concat_string_ref_count(size_t acc, R &&r, Args &&...args) {
  return concat_string_ref_count(acc + std::ranges::size(r), args...);
}

// private function used in concat_string_ref.  this is the base
// function of concat_string_ref_copy().
inline constexpr void concat_string_ref_copy(std::span<uint8_t> dst) {}

// private function used in concat_string_ref.  This function copies
// given strings into |dst|.
template <std::ranges::sized_range R, std::ranges::sized_range... Args>
requires(!std::is_array_v<std::remove_cvref_t<R>>)
constexpr void concat_string_ref_copy(std::span<uint8_t> dst, R &&r,
                                      Args &&...args) {
  concat_string_ref_copy(
    {std::ranges::copy(std::forward<R>(r), std::ranges::begin(dst)).out,
     std::ranges::end(dst)},
    std::forward<Args>(args)...);
}

// Returns the string which is the concatenation of |args| in the
// given order.  The resulting string will be NULL-terminated.
template <std::ranges::sized_range... Args>
std::string_view concat_string_ref(BlockAllocator &alloc, Args &&...args) {
  auto len = concat_string_ref_count(0, args...);
  auto res = alloc.alloc(len + 1);

  concat_string_ref_copy(res, std::forward<Args>(args)...);
  res.back() = '\0';

  return as_string_view(res.first(len));
}

// Returns the string which is the concatenation of |value| and |args|
// in the given order.  The resulting string will be NULL-terminated.
// This function assumes that value.data() was obtained from
// alloc.alloc() or alloc.realloc(), and attempts to use unused memory
// region by using alloc.realloc().  If value is empty, then just call
// concat_string_ref().
template <std::ranges::sized_range... Args>
std::string_view realloc_concat_string_ref(BlockAllocator &alloc,
                                           std::string_view value,
                                           Args &&...args) {
  if (value.empty()) {
    return concat_string_ref(alloc, std::forward<Args>(args)...);
  }

  auto len = value.size() + concat_string_ref_count(0, args...);
  auto res =
    alloc.realloc(reinterpret_cast<const uint8_t *>(value.data()), len + 1);
  concat_string_ref_copy(res.subspan(value.size()),
                         std::forward<Args>(args)...);
  res.back() = '\0';

  return as_string_view(res.first(len));
}

// Makes an uninitialized buffer with given size.
inline std::span<uint8_t> make_byte_ref(BlockAllocator &alloc, size_t size) {
  return alloc.alloc(size);
}

} // namespace nghttp2

#endif // !defined(ALLOCATOR_H)
