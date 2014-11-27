/*
 * nghttp2 - HTTP/2 C Library
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

static int pq_compar(const void *lhs, const void *rhs) {
  return strcmp(lhs, rhs);
}

void test_nghttp2_pq(void) {
  int i;
  nghttp2_pq pq;
  nghttp2_pq_init(&pq, pq_compar);
  CU_ASSERT(nghttp2_pq_empty(&pq));
  CU_ASSERT(0 == nghttp2_pq_size(&pq));
  CU_ASSERT(0 == nghttp2_pq_push(&pq, (void *)"foo"));
  CU_ASSERT(0 == nghttp2_pq_empty(&pq));
  CU_ASSERT(1 == nghttp2_pq_size(&pq));
  CU_ASSERT(strcmp("foo", nghttp2_pq_top(&pq)) == 0);
  CU_ASSERT(0 == nghttp2_pq_push(&pq, (void *)"bar"));
  CU_ASSERT(strcmp("bar", nghttp2_pq_top(&pq)) == 0);
  CU_ASSERT(0 == nghttp2_pq_push(&pq, (void *)"baz"));
  CU_ASSERT(strcmp("bar", nghttp2_pq_top(&pq)) == 0);
  CU_ASSERT(0 == nghttp2_pq_push(&pq, (void *)"C"));
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
  for (i = 0; i < 10000; ++i) {
    CU_ASSERT(0 == nghttp2_pq_push(&pq, (void *)"foo"));
    CU_ASSERT((size_t)(i + 1) == nghttp2_pq_size(&pq));
  }
  for (i = 10000; i > 0; --i) {
    CU_ASSERT(NULL != nghttp2_pq_top(&pq));
    nghttp2_pq_pop(&pq);
    CU_ASSERT((size_t)(i - 1) == nghttp2_pq_size(&pq));
  }

  nghttp2_pq_free(&pq);
}

typedef struct {
  int key;
  int val;
} node;

static int node_compar(const void *lhs, const void *rhs) {
  node *ln = (node *)lhs;
  node *rn = (node *)rhs;
  return ln->key - rn->key;
}

static int node_update(void *item, void *arg _U_) {
  node *nd = (node *)item;
  if ((nd->key % 2) == 0) {
    nd->key *= -1;
    return 1;
  } else {
    return 0;
  }
}

void test_nghttp2_pq_update(void) {
  nghttp2_pq pq;
  node nodes[10];
  int i;
  node *nd;
  int ans[] = {-8, -6, -4, -2, 0, 1, 3, 5, 7, 9};

  nghttp2_pq_init(&pq, node_compar);

  for (i = 0; i < (int)(sizeof(nodes) / sizeof(nodes[0])); ++i) {
    nodes[i].key = i;
    nodes[i].val = i;
    nghttp2_pq_push(&pq, &nodes[i]);
  }

  nghttp2_pq_update(&pq, node_update, NULL);

  for (i = 0; i < (int)(sizeof(nodes) / sizeof(nodes[0])); ++i) {
    nd = nghttp2_pq_top(&pq);
    CU_ASSERT(ans[i] == nd->key);
    nghttp2_pq_pop(&pq);
  }

  nghttp2_pq_free(&pq);
}
