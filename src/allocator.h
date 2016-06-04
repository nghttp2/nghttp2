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

#include <sys/uio.h>

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

// BlockAllocator allocates memory block with given size at once, and
// cuts the region from it when allocation is requested.  If the
// requested size is larger than given threshold, it will be allocated
// in a distinct buffer on demand.
struct BlockAllocator {
  BlockAllocator(size_t block_size, size_t isolation_threshold)
      : retain(nullptr),
        head(nullptr),
        block_size(block_size),
        isolation_threshold(std::min(block_size, isolation_threshold)) {}

  ~BlockAllocator() { reset(); }

  BlockAllocator(BlockAllocator &&other) noexcept
      : retain(other.retain),
        head(other.head),
        block_size(other.block_size),
        isolation_threshold(other.isolation_threshold) {
    other.retain = nullptr;
    other.head = nullptr;
  }

  BlockAllocator &operator=(BlockAllocator &&other) noexcept {
    reset();

    retain = other.retain;
    head = other.head;
    block_size = other.block_size;
    isolation_threshold = other.isolation_threshold;

    other.retain = nullptr;
    other.head = nullptr;

    return *this;
  }

  BlockAllocator(const BlockAllocator &) = delete;
  BlockAllocator &operator=(const BlockAllocator &) = delete;

  void reset() {
    for (auto mb = retain; mb;) {
      auto next = mb->next;
      delete[] reinterpret_cast<uint8_t *>(mb);
      mb = next;
    }

    retain = nullptr;
    head = nullptr;
  }

  MemBlock *alloc_mem_block(size_t size) {
    auto block = new uint8_t[sizeof(MemBlock) + size];
    auto mb = reinterpret_cast<MemBlock *>(block);

    mb->next = retain;
    mb->begin = mb->last = block + sizeof(MemBlock);
    mb->end = mb->begin + size;
    retain = mb;
    return mb;
  }

  void *alloc(size_t size) {
    if (size >= isolation_threshold) {
      auto mb = alloc_mem_block(size);
      mb->last = mb->end;
      return mb->begin;
    }

    if (!head || head->end - head->last < static_cast<ssize_t>(size)) {
      head = alloc_mem_block(block_size);
    }

    auto res = head->last;

    head->last = reinterpret_cast<uint8_t *>(
        (reinterpret_cast<intptr_t>(head->last + size) + 0xf) & ~0xf);

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

// Makes a copy of |src|.  The resulting string will be
// NULL-terminated.
template <typename BlockAllocator>
StringRef make_string_ref(BlockAllocator &alloc, const StringRef &src) {
  auto dst = static_cast<uint8_t *>(alloc.alloc(src.size() + 1));
  auto p = dst;
  p = std::copy(std::begin(src), std::end(src), p);
  *p = '\0';
  return StringRef{dst, src.size()};
}

// private function used in concat_string_ref.  this is the base
// function of concat_string_ref_count().
inline size_t concat_string_ref_count(size_t acc) { return acc; }

// private function used in concat_string_ref.  This function counts
// the sum of length of given arguments.  The calculated length is
// accumulated, and passed to the next function.
template <typename... Args>
size_t concat_string_ref_count(size_t acc, const StringRef &value,
                               Args &&... args) {
  return concat_string_ref_count(acc + value.size(),
                                 std::forward<Args>(args)...);
}

// private function used in concat_string_ref.  this is the base
// function of concat_string_ref_copy().
inline uint8_t *concat_string_ref_copy(uint8_t *p) { return p; }

// private function used in concat_string_ref.  This function copies
// given strings into |p|.  |p| is incremented by the copied length,
// and returned.  In the end, return value points to the location one
// beyond the last byte written.
template <typename... Args>
uint8_t *concat_string_ref_copy(uint8_t *p, const StringRef &value,
                                Args &&... args) {
  p = std::copy(std::begin(value), std::end(value), p);
  return concat_string_ref_copy(p, std::forward<Args>(args)...);
}

// Returns the string which is the concatenation of |args| in the
// given order.  The resulting string will be NULL-terminated.
template <typename BlockAllocator, typename... Args>
StringRef concat_string_ref(BlockAllocator &alloc, Args &&... args) {
  size_t len = concat_string_ref_count(0, std::forward<Args>(args)...);
  auto dst = static_cast<uint8_t *>(alloc.alloc(len + 1));
  auto p = dst;
  p = concat_string_ref_copy(p, std::forward<Args>(args)...);
  *p = '\0';
  return StringRef{dst, len};
}

struct ByteRef {
  // The pointer to the beginning of the buffer.
  uint8_t *base;
  // The length of the buffer.
  size_t len;
};

// Makes a buffer with given size.  The resulting byte string might
// not be NULL-terminated.
template <typename BlockAllocator>
ByteRef make_byte_ref(BlockAllocator &alloc, size_t size) {
  auto dst = static_cast<uint8_t *>(alloc.alloc(size));
  return {dst, size};
}

} // namespace aria2

#endif // ALLOCATOR_H
