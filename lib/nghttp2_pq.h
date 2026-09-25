/*
 * nghttp2
 *
 * Copyright (c) 2026 nghttp2 contributors
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
#ifndef NGHTTP2_PQ_H
#define NGHTTP2_PQ_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <nghttp2v2/nghttp2.h>

#include "nghttp2_mem.h"

/* Implementation of priority queue */

/* NGHTTP2_PQ_BAD_INDEX is the priority queue index which indicates
   that an entry is not queued.  Assigning this value to
   nghttp2_pq_entry.index can check that the entry is queued or
   not. */
#define NGHTTP2_PQ_BAD_INDEX SIZE_MAX

typedef struct nghttp2_pq_entry {
  size_t index;
} nghttp2_pq_entry;

/* nghttp2_pq_less is a "less" function, that returns nonzero if |lhs|
   is considered to be less than |rhs|. */
typedef int (*nghttp2_pq_less)(const nghttp2_pq_entry *lhs,
                               const nghttp2_pq_entry *rhs);

typedef struct nghttp2_pq {
  /* q is a pointer to an array that stores the items. */
  nghttp2_pq_entry **q;
  /* mem is a memory allocator. */
  const nghttp2_mem *mem;
  /* length is the number of items stored. */
  size_t length;
  /* capacity is the maximum number of items this queue can store.
     This is automatically extended when length is reached to this
     limit. */
  size_t capacity;
  /* less is the less function to compare items. */
  nghttp2_pq_less less;
} nghttp2_pq;

/*
 * nghttp2_pq_init initializes |pq| with compare function |cmp|.
 */
void nghttp2_pq_init(nghttp2_pq *pq, nghttp2_pq_less less,
                     const nghttp2_mem *mem);

/*
 * nghttp2_pq_free deallocates any resources allocated for |pq|.  The
 * stored items are not freed by this function.
 */
void nghttp2_pq_free(nghttp2_pq *pq);

/*
 * nghttp2_pq_push adds |item| to |pq|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_pq_push(nghttp2_pq *pq, nghttp2_pq_entry *item);

/*
 * nghttp2_pq_top returns item at the top of |pq|.  It is undefined if
 * |pq| is empty.
 */
nghttp2_pq_entry *nghttp2_pq_top(const nghttp2_pq *pq);

/*
 * nghttp2_pq_pop pops item at the top of |pq|.  The popped item is
 * not freed by this function.  It is undefined if |pq| is empty.
 */
void nghttp2_pq_pop(nghttp2_pq *pq);

/*
 * nghttp2_pq_empty returns nonzero if |pq| is empty.
 */
int nghttp2_pq_empty(const nghttp2_pq *pq);

/*
 * nghttp2_pq_size returns the number of items |pq| contains.
 */
size_t nghttp2_pq_size(const nghttp2_pq *pq);

/*
 * nghttp2_pq_remove removes |item| from |pq|.  |pq| must contain
 * |item| otherwise the behavior is undefined.
 */
void nghttp2_pq_remove(nghttp2_pq *pq, nghttp2_pq_entry *item);

/*
 * nghttp2_pq_clear removes all items from |pq|.
 */
void nghttp2_pq_clear(nghttp2_pq *pq);

#endif /* !defined(NGHTTP2_PQ_H) */
