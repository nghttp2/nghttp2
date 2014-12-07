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
#ifndef NGHTTP2_PQ_H
#define NGHTTP2_PQ_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <nghttp2/nghttp2.h>
#include "nghttp2_int.h"
#include "nghttp2_mem.h"

/* Implementation of priority queue */

typedef struct {
  /* The pointer to the pointer to the item stored */
  void **q;
  /* Memory allocator */
  nghttp2_mem *mem;
  /* The number of items sotred */
  size_t length;
  /* The maximum number of items this pq can store. This is
     automatically extended when length is reached to this value. */
  size_t capacity;
  /* The compare function between items */
  nghttp2_compar compar;
} nghttp2_pq;

/*
 * Initializes priority queue |pq| with compare function |cmp|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_pq_init(nghttp2_pq *pq, nghttp2_compar cmp, nghttp2_mem *mem);

/*
 * Deallocates any resources allocated for |pq|.  The stored items are
 * not freed by this function.
 */
void nghttp2_pq_free(nghttp2_pq *pq);

/*
 * Adds |item| to the priority queue |pq|.
 *
 * This function returns 0 if it succeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_pq_push(nghttp2_pq *pq, void *item);

/*
 * Returns item at the top of the queue |pq|. If the queue is empty,
 * this function returns NULL.
 */
void *nghttp2_pq_top(nghttp2_pq *pq);

/*
 * Pops item at the top of the queue |pq|. The popped item is not
 * freed by this function.
 */
void nghttp2_pq_pop(nghttp2_pq *pq);

/*
 * Returns nonzero if the queue |pq| is empty.
 */
int nghttp2_pq_empty(nghttp2_pq *pq);

/*
 * Returns the number of items in the queue |pq|.
 */
size_t nghttp2_pq_size(nghttp2_pq *pq);

typedef int (*nghttp2_pq_item_cb)(void *item, void *arg);

/*
 * Updates each item in |pq| using function |fun| and re-construct
 * priority queue. The |fun| must return non-zero if it modifies the
 * item in a way that it affects ordering in the priority queue. The
 * |arg| is passed to the 2nd parameter of |fun|.
 */
void nghttp2_pq_update(nghttp2_pq *pq, nghttp2_pq_item_cb fun, void *arg);

#endif /* NGHTTP2_PQ_H */
