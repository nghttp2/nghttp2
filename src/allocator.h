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

#include "template.h"

namespace nghttp2 {

struct MemBlock {
  MemBlock *next;
  uint8_t *begin, *last, *end;
};

struct BlockAllocator {
  BlockAllocator(size_t block_size, size_t isolation_threshold)
      : retain(nullptr),
        head(nullptr),
        block_size(block_size),
        isolation_threshold(std::min(block_size, isolation_threshold)) {}

  ~BlockAllocator() {
    for (auto mb = retain; mb;) {
      auto next = mb->next;
      delete[] reinterpret_cast<uint8_t *>(mb);
      mb = next;
    }
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

  MemBlock *retain;
  MemBlock *head;
  // size of single memory block
  size_t block_size;
  // if allocation greater or equal to isolation_threshold bytes is
  // requested, allocate dedicated block.
  size_t isolation_threshold;
};

template <typename BlockAllocator>
StringRef make_string_ref(BlockAllocator &alloc, const StringRef &src) {
  auto dst = static_cast<uint8_t *>(alloc.alloc(src.size() + 1));
  auto p = dst;
  p = std::copy(std::begin(src), std::end(src), p);
  *p = '\0';
  return StringRef{dst, src.size()};
}

template <typename BlockAllocator>
StringRef concat_string_ref(BlockAllocator &alloc, const StringRef &a,
                            const StringRef &b) {
  auto dst = static_cast<uint8_t *>(alloc.alloc(a.size() + b.size() + 1));
  auto p = dst;
  p = std::copy(std::begin(a), std::end(a), p);
  p = std::copy(std::begin(b), std::end(b), p);
  *p = '\0';
  return StringRef{dst, a.size() + b.size()};
}

} // namespace aria2

#endif // ALLOCATOR_H
