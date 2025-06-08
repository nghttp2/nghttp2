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
#endif // !_WIN32

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

static_assert((sizeof(MemBlock) & 0xf) == 0);

struct ChunkHead {
  union {
    size_t size;
    uint64_t pad1;
  };
  uint64_t pad2;
};

static_assert(sizeof(ChunkHead) == 16);

// BlockAllocator allocates memory block with given size at once, and
// cuts the region from it when allocation is requested.  If the
// requested size is larger than given threshold (plus small internal
// overhead), it will be allocated in a distinct buffer on demand.
// The |isolation_threshold| must be less than or equal to
// |block_size|.
struct BlockAllocator {
  BlockAllocator(size_t block_size, size_t isolation_threshold)
    : retain(nullptr),
      head(nullptr),
      block_size(block_size),
      isolation_threshold(std::min(block_size, isolation_threshold)) {
    assert(isolation_threshold <= block_size);
  }

  ~BlockAllocator() { reset(); }

  BlockAllocator(BlockAllocator &&other) noexcept
    : retain{std::exchange(other.retain, nullptr)},
      head{std::exchange(other.head, nullptr)},
      block_size(other.block_size),
      isolation_threshold(other.isolation_threshold) {}

  BlockAllocator &operator=(BlockAllocator &&other) noexcept {
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
      operator delete[](reinterpret_cast<uint8_t *>(mb), std::align_val_t(16));
      mb = next;
    }

    retain = nullptr;
    head = nullptr;
  }

  MemBlock *alloc_mem_block(size_t size) {
    auto block = new (std::align_val_t(16)) uint8_t[sizeof(MemBlock) + size];
    auto mb = reinterpret_cast<MemBlock *>(block);

    mb->next = retain;
    mb->begin = mb->last = reinterpret_cast<uint8_t *>(
      (reinterpret_cast<intptr_t>(block + sizeof(MemBlock)) + 0xf) & ~0xf);
    mb->end = mb->begin + size;
    retain = mb;
    return mb;
  }

  constexpr size_t alloc_unit(size_t size) { return sizeof(ChunkHead) + size; }

  void *alloc(size_t size) {
    auto au = alloc_unit(size);

    if (au >= isolation_threshold) {
      size = std::max(static_cast<size_t>(16), size);
      // We will store the allocated size in size_t field.
      auto mb = alloc_mem_block(alloc_unit(size));
      auto ch = reinterpret_cast<ChunkHead *>(mb->begin);
      ch->size = size;
      mb->last = mb->end;
      return mb->begin + sizeof(ChunkHead);
    }

    if (!head || static_cast<size_t>(head->end - head->last) < au) {
      head = alloc_mem_block(block_size);
    }

    // We will store the allocated size in size_t field.
    auto res = head->last + sizeof(ChunkHead);
    auto ch = reinterpret_cast<ChunkHead *>(head->last);
    ch->size = size;

    head->last = reinterpret_cast<uint8_t *>(
      (reinterpret_cast<intptr_t>(res + size) + 0xf) & ~0xf);

    return res;
  }

  // Returns allocated size for memory pointed by |ptr|.  We assume
  // that |ptr| was returned from alloc() or realloc().
  size_t get_alloc_length(void *ptr) {
    return reinterpret_cast<ChunkHead *>(static_cast<uint8_t *>(ptr) -
                                         sizeof(ChunkHead))
      ->size;
  }

  // Allocates memory of at least |size| bytes.  If |ptr| is nullptr,
  // this is equivalent to alloc(size).  If |ptr| is not nullptr,
  // obtain the allocated size for |ptr|, assuming that |ptr| was
  // returned from alloc() or realloc().  If the allocated size is
  // greater than or equal to size, |ptr| is returned.  Otherwise,
  // allocates at least |size| bytes of memory, and the original
  // content pointed by |ptr| is copied to the newly allocated memory.
  void *realloc(void *ptr, size_t size) {
    if (!ptr) {
      return alloc(size);
    }
    auto alloclen = get_alloc_length(ptr);
    auto p = reinterpret_cast<uint8_t *>(ptr);
    if (size <= alloclen) {
      return ptr;
    }

    auto nalloclen = std::max(size + 1, alloclen * 2);

    auto res = alloc(nalloclen);
    std::ranges::copy_n(p, as_signed(alloclen), static_cast<uint8_t *>(res));

    return res;
  }

  // This holds live memory block to free them in dtor.
  MemBlock *retain;
  // Current memory block to use.
  MemBlock *head;
  // size of single memory block
  size_t block_size;
  // if allocation greater or equal to isolation_threshold bytes is
  // requested, allocate dedicated block.
  size_t isolation_threshold;
};

// Makes a copy of a range [|first|, |last|).  The resulting string
// will be NULL-terminated.
template <std::input_iterator I>
std::string_view make_string_ref(BlockAllocator &alloc, I first, I last) {
  auto dst = static_cast<char *>(
    alloc.alloc(static_cast<size_t>(std::ranges::distance(first, last) + 1)));
  auto p = std::ranges::copy(first, last, dst).out;
  *p = '\0';

  return std::string_view{dst, p};
}

// Makes a copy of |r| as std::string_view.  The resulting string will be
// NULL-terminated.
template <std::ranges::input_range R>
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
template <std::ranges::input_range R, std::ranges::input_range... Args>
requires(!std::is_array_v<std::remove_cvref_t<R>>)
constexpr size_t concat_string_ref_count(size_t acc, R &&r, Args &&...args) {
  return concat_string_ref_count(acc + std::ranges::size(r), args...);
}

// private function used in concat_string_ref.  this is the base
// function of concat_string_ref_copy().
inline uint8_t *concat_string_ref_copy(uint8_t *p) { return p; }

// private function used in concat_string_ref.  This function copies
// given strings into |p|.  |p| is incremented by the copied length,
// and returned.  In the end, return value points to the location one
// beyond the last byte written.
template <std::ranges::input_range R, std::ranges::input_range... Args>
requires(!std::is_array_v<std::remove_cvref_t<R>>)
uint8_t *concat_string_ref_copy(uint8_t *p, R &&r, Args &&...args) {
  return concat_string_ref_copy(std::ranges::copy(std::forward<R>(r), p).out,
                                std::forward<Args>(args)...);
}

// Returns the string which is the concatenation of |args| in the
// given order.  The resulting string will be NULL-terminated.
template <std::ranges::input_range... Args>
std::string_view concat_string_ref(BlockAllocator &alloc, Args &&...args) {
  auto len = concat_string_ref_count(0, args...);
  auto dst = static_cast<uint8_t *>(alloc.alloc(len + 1));
  auto p = dst;
  p = concat_string_ref_copy(p, std::forward<Args>(args)...);
  *p = '\0';
  return as_string_view(dst, p);
}

// Returns the string which is the concatenation of |value| and |args|
// in the given order.  The resulting string will be NULL-terminated.
// This function assumes that the pointer value value.c_str() was
// obtained from alloc.alloc() or alloc.realloc(), and attempts to use
// unused memory region by using alloc.realloc().  If value is empty,
// then just call concat_string_ref().
template <std::ranges::input_range... Args>
std::string_view realloc_concat_string_ref(BlockAllocator &alloc,
                                           const std::string_view &value,
                                           Args &&...args) {
  if (value.empty()) {
    return concat_string_ref(alloc, std::forward<Args>(args)...);
  }

  auto len = value.size() + concat_string_ref_count(0, args...);
  auto dst = static_cast<uint8_t *>(alloc.realloc(
    const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(value.data())),
    len + 1));
  auto p = dst + value.size();
  p = concat_string_ref_copy(p, std::forward<Args>(args)...);
  *p = '\0';

  return as_string_view(dst, p);
}

// Makes an uninitialized buffer with given size.
inline std::span<uint8_t> make_byte_ref(BlockAllocator &alloc, size_t size) {
  return {static_cast<uint8_t *>(alloc.alloc(size)), size};
}

} // namespace nghttp2

#endif // ALLOCATOR_H
