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
#include "priority_queue_test.h"

#include <string>

#include <CUnit/CUnit.h>

#include "priority_queue.h"

namespace nghttp2 {

void test_priority_queue_push(void) {
  PriorityQueue<std::string, int64_t> pq;

  CU_ASSERT(pq.empty());
  CU_ASSERT(0 == pq.size());

  pq.push("foo", 1);

  CU_ASSERT(!pq.empty());
  CU_ASSERT(1 == pq.size());

  auto top = pq.top();

  CU_ASSERT(1 == top);

  pq.emplace("bar", 2);
  top = pq.top();

  CU_ASSERT(2 == top);

  pq.push("baz", 3);
  top = pq.top();

  CU_ASSERT(2 == top);

  pq.push("C", 4);

  CU_ASSERT(4 == pq.size());

  top = pq.top();

  CU_ASSERT(4 == top);

  pq.pop();

  CU_ASSERT(3 == pq.size());

  top = pq.top();

  CU_ASSERT(2 == top);

  pq.pop();

  top = pq.top();

  CU_ASSERT(3 == top);

  pq.pop();
  top = pq.top();

  CU_ASSERT(1 == top);

  pq.pop();

  CU_ASSERT(pq.empty());
  CU_ASSERT(0 == pq.size());
}

} // namespace nghttp2
