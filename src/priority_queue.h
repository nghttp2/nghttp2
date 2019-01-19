/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2019 Tatsuhiro Tsujikawa
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
#ifndef PRIORITY_QUEUE_H
#define PRIORITY_QUEUE_H

#include "nghttp2_config.h"

#include <cassert>
#include <functional>
#include <utility>
#include <vector>

namespace nghttp2 {

template <typename KeyType, typename ValueType, typename Compare = std::less<>>
class PriorityQueue {
public:
  const ValueType &top() const;
  const KeyType &key_top() const;
  void push(const KeyType &key, const ValueType &value);
  void push(KeyType &&key, ValueType &&value);
  template <typename... Args> void emplace(Args &&... args);
  void pop();
  bool empty() const;
  size_t size() const;

private:
  void bubble_up(size_t idx);
  void bubble_down(size_t idx);

  std::vector<std::pair<KeyType, ValueType>> c_;
  Compare comp_;
};

template <typename KeyType, typename ValueType, typename Compare>
const ValueType &PriorityQueue<KeyType, ValueType, Compare>::top() const {
  assert(!c_.empty());
  return c_[0].second;
}

template <typename KeyType, typename ValueType, typename Compare>
const KeyType &PriorityQueue<KeyType, ValueType, Compare>::key_top() const {
  assert(!c_.empty());
  return c_[0].first;
}

template <typename KeyType, typename ValueType, typename Compare>
void PriorityQueue<KeyType, ValueType, Compare>::push(const KeyType &key,
                                                      const ValueType &value) {
  c_.push_back(std::pair<KeyType, ValueType>{key, value});
  bubble_up(c_.size() - 1);
}

template <typename KeyType, typename ValueType, typename Compare>
void PriorityQueue<KeyType, ValueType, Compare>::push(KeyType &&key,
                                                      ValueType &&value) {
  c_.push_back(std::pair<KeyType, ValueType>{std::move(key), std::move(value)});
  bubble_up(c_.size() - 1);
}

template <typename KeyType, typename ValueType, typename Compare>
template <typename... Args>
void PriorityQueue<KeyType, ValueType, Compare>::emplace(Args &&... args) {
  c_.emplace_back(std::forward<Args>(args)...);
  bubble_up(c_.size() - 1);
}

template <typename KeyType, typename ValueType, typename Compare>
void PriorityQueue<KeyType, ValueType, Compare>::pop() {
  assert(!c_.empty());
  c_[0] = std::move(c_.back());
  c_.resize(c_.size() - 1);
  bubble_down(0);
}

template <typename KeyType, typename ValueType, typename Compare>
bool PriorityQueue<KeyType, ValueType, Compare>::empty() const {
  return c_.empty();
}

template <typename KeyType, typename ValueType, typename Compare>
size_t PriorityQueue<KeyType, ValueType, Compare>::size() const {
  return c_.size();
}

template <typename KeyType, typename ValueType, typename Compare>
void PriorityQueue<KeyType, ValueType, Compare>::bubble_up(size_t idx) {
  using std::swap;
  while (idx != 0) {
    auto parent = (idx - 1) / 2;
    if (!comp_(c_[idx].first, c_[parent].first)) {
      return;
    }
    swap(c_[idx], c_[parent]);
    idx = parent;
  }
}

template <typename KeyType, typename ValueType, typename Compare>
void PriorityQueue<KeyType, ValueType, Compare>::bubble_down(size_t idx) {
  using std::swap;
  for (;;) {
    auto j = idx * 2 + 1;
    auto minidx = idx;
    for (auto i = 0; i < 2; ++i, ++j) {
      if (j >= c_.size()) {
        break;
      }
      if (comp_(c_[j].first, c_[minidx].first)) {
        minidx = j;
      }
    }
    if (minidx == idx) {
      return;
    }
    swap(c_[idx], c_[minidx]);
    idx = minidx;
  }
}

} // namespace nghttp2

#endif // PRIORITY_QUEUE_H
