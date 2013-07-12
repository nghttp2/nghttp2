/*
 * nghttp2 - HTTP/2.0 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
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
#include "nghttp2_pq_test.h"

#include <CUnit/CUnit.h>

#include "nghttp2_pq.h"

static int pq_compar(const void *lhs, const void *rhs)
{
  return strcmp(lhs, rhs);
}

void test_nghttp2_pq(void)
{
  int i;
  nghttp2_pq pq;
  nghttp2_pq_init(&pq, pq_compar);
  CU_ASSERT(nghttp2_pq_empty(&pq));
  CU_ASSERT(0 == nghttp2_pq_size(&pq));
  CU_ASSERT(0 == nghttp2_pq_push(&pq, (void*)"foo"));
  CU_ASSERT(0 == nghttp2_pq_empty(&pq));
  CU_ASSERT(1 == nghttp2_pq_size(&pq));
  CU_ASSERT(strcmp("foo", nghttp2_pq_top(&pq)) == 0);
  CU_ASSERT(0 == nghttp2_pq_push(&pq, (void*)"bar"));
  CU_ASSERT(strcmp("bar", nghttp2_pq_top(&pq)) == 0);
  CU_ASSERT(0 == nghttp2_pq_push(&pq, (void*)"baz"));
  CU_ASSERT(strcmp("bar", nghttp2_pq_top(&pq)) == 0);
  CU_ASSERT(0 == nghttp2_pq_push(&pq, (void*)"C"));
  CU_ASSERT(4 == nghttp2_pq_size(&pq));
  CU_ASSERT(strcmp("C", nghttp2_pq_top(&pq)) == 0);
  nghttp2_pq_pop(&pq);
  CU_ASSERT(3 == nghttp2_pq_size(&pq));
  CU_ASSERT(strcmp("bar", nghttp2_pq_top(&pq)) == 0);
  nghttp2_pq_pop(&pq);
  CU_ASSERT(strcmp("baz", nghttp2_pq_top(&pq)) == 0);
  nghttp2_pq_pop(&pq);
  CU_ASSERT(strcmp("foo", nghttp2_pq_top(&pq)) == 0);
  nghttp2_pq_pop(&pq);
  CU_ASSERT(nghttp2_pq_empty(&pq));
  CU_ASSERT(0 == nghttp2_pq_size(&pq));
  CU_ASSERT(NULL == nghttp2_pq_top(&pq));

  /* Add bunch of entry to see realloc works */
  for(i = 0; i < 10000; ++i) {
    CU_ASSERT(0 == nghttp2_pq_push(&pq, (void*)"foo"));
    CU_ASSERT((size_t)(i+1) == nghttp2_pq_size(&pq));
  }
  for(i = 10000; i > 0; --i) {
    CU_ASSERT(NULL != nghttp2_pq_top(&pq));
    nghttp2_pq_pop(&pq);
    CU_ASSERT((size_t)(i-1) == nghttp2_pq_size(&pq));
  }

  nghttp2_pq_free(&pq);
}

