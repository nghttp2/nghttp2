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
#include "nghttp2_pq.h"

int nghttp2_pq_init(nghttp2_pq *pq, nghttp2_compar compar, nghttp2_mem *mem) {
  pq->mem = mem;
  pq->capacity = 128;
  pq->q = nghttp2_mem_malloc(mem, pq->capacity * sizeof(void *));
  if (pq->q == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  pq->length = 0;
  pq->compar = compar;
  return 0;
}

void nghttp2_pq_free(nghttp2_pq *pq) {
  nghttp2_mem_free(pq->mem, pq->q);
  pq->q = NULL;
}

static void swap(nghttp2_pq *pq, size_t i, size_t j) {
  void *t = pq->q[i];
  pq->q[i] = pq->q[j];
  pq->q[j] = t;
}

static void bubble_up(nghttp2_pq *pq, size_t index) {
  if (index == 0) {
    return;
  } else {
    size_t parent = (index - 1) / 2;
    if (pq->compar(pq->q[parent], pq->q[index]) > 0) {
      swap(pq, parent, index);
      bubble_up(pq, parent);
    }
  }
}

int nghttp2_pq_push(nghttp2_pq *pq, void *item) {
  if (pq->capacity <= pq->length) {
    void *nq;
    nq = nghttp2_mem_realloc(pq->mem, pq->q,
                             (pq->capacity * 2) * sizeof(void *));
    if (nq == NULL) {
      return NGHTTP2_ERR_NOMEM;
    }
    pq->capacity *= 2;
    pq->q = nq;
  }
  pq->q[pq->length] = item;
  ++pq->length;
  bubble_up(pq, pq->length - 1);
  return 0;
}

void *nghttp2_pq_top(nghttp2_pq *pq) {
  if (pq->length == 0) {
    return NULL;
  } else {
    return pq->q[0];
  }
}

static void bubble_down(nghttp2_pq *pq, size_t index) {
  size_t lchild = index * 2 + 1;
  size_t minindex = index;
  size_t i, j;
  for (i = 0; i < 2; ++i) {
    j = lchild + i;
    if (j >= pq->length) {
      break;
    }
    if (pq->compar(pq->q[minindex], pq->q[j]) > 0) {
      minindex = j;
    }
  }
  if (minindex != index) {
    swap(pq, index, minindex);
    bubble_down(pq, minindex);
  }
}

void nghttp2_pq_pop(nghttp2_pq *pq) {
  if (pq->length > 0) {
    pq->q[0] = pq->q[pq->length - 1];
    --pq->length;
    bubble_down(pq, 0);
  }
}

int nghttp2_pq_empty(nghttp2_pq *pq) { return pq->length == 0; }

size_t nghttp2_pq_size(nghttp2_pq *pq) { return pq->length; }

void nghttp2_pq_update(nghttp2_pq *pq, nghttp2_pq_item_cb fun, void *arg) {
  size_t i;
  int rv = 0;
  if (pq->length == 0) {
    return;
  }
  for (i = 0; i < pq->length; ++i) {
    rv |= (*fun)(pq->q[i], arg);
  }
  if (rv) {
    for (i = pq->length; i > 0; --i) {
      bubble_down(pq, i - 1);
    }
  }
}

int nghttp2_pq_each(nghttp2_pq *pq, nghttp2_pq_item_cb fun, void *arg) {
  size_t i;

  if (pq->length == 0) {
    return 0;
  }
  for (i = 0; i < pq->length; ++i) {
    if ((*fun)(pq->q[i], arg)) {
      return 1;
    }
  }
  return 0;
}
