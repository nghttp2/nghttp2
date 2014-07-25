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
#include "nghttp2_stream.h"

#include <assert.h>
#include <stdio.h>

#include "nghttp2_helper.h"

void nghttp2_stream_init(nghttp2_stream *stream, int32_t stream_id,
                         uint8_t flags,
                         nghttp2_stream_state initial_state,
                         int32_t weight,
                         nghttp2_stream_roots *roots,
                         int32_t remote_initial_window_size,
                         int32_t local_initial_window_size,
                         void *stream_user_data)
{
  nghttp2_map_entry_init(&stream->map_entry, stream_id);
  stream->stream_id = stream_id;
  stream->flags = flags;
  stream->state = initial_state;
  stream->shut_flags = NGHTTP2_SHUT_NONE;
  stream->stream_user_data = stream_user_data;
  stream->data_item = NULL;
  stream->remote_window_size = remote_initial_window_size;
  stream->local_window_size = local_initial_window_size;
  stream->recv_window_size = 0;
  stream->consumed_size = 0;
  stream->recv_reduction = 0;
  stream->blocked_sent = 0;

  stream->dep_prev = NULL;
  stream->dep_next = NULL;
  stream->sib_prev = NULL;
  stream->sib_next = NULL;

  stream->closed_next = NULL;

  stream->dpri = NGHTTP2_STREAM_DPRI_NO_DATA;
  stream->num_substreams = 1;
  stream->weight = weight;
  stream->effective_weight = stream->weight;
  stream->sum_dep_weight = 0;
  stream->sum_norest_weight = 0;

  stream->roots = roots;
  stream->root_prev = NULL;
  stream->root_next = NULL;
}

void nghttp2_stream_free(nghttp2_stream *stream)
{
  if(stream->flags & NGHTTP2_STREAM_FLAG_DEFERRED_ALL) {
    nghttp2_outbound_item_free(stream->data_item);
    free(stream->data_item);
  }

  /* We don't free stream->data_item otherwise. */
}

void nghttp2_stream_shutdown(nghttp2_stream *stream, nghttp2_shut_flag flag)
{
  stream->shut_flags |= flag;
}

static int stream_push_data(nghttp2_stream *stream, nghttp2_pq *pq,
                            uint64_t cycle)
{
  int rv;

  assert(stream->data_item);
  assert(stream->data_item->queued == 0);

  if(stream->data_item->weight > stream->effective_weight) {
    stream->data_item->weight = stream->effective_weight;
  }

  stream->data_item->cycle = cycle;

  rv = nghttp2_pq_push(pq, stream->data_item);

  if(rv != 0) {
    return rv;
  }

  stream->data_item->queued = 1;

  return 0;
}

static nghttp2_stream* stream_first_sib(nghttp2_stream *stream)
{
  for(; stream->sib_prev; stream = stream->sib_prev);

  return stream;
}

static nghttp2_stream* stream_last_sib(nghttp2_stream *stream)
{
  for(; stream->sib_next; stream = stream->sib_next);

  return stream;
}

static nghttp2_stream* stream_update_dep_length(nghttp2_stream *stream,
                                                ssize_t delta)
{
  stream->num_substreams += delta;

  stream = stream_first_sib(stream);

  if(stream->dep_prev) {
    return stream_update_dep_length(stream->dep_prev, delta);
  }

  return stream;
}

int32_t nghttp2_stream_dep_distributed_weight(nghttp2_stream *stream,
                                              int32_t weight)
{
  weight = stream->weight * weight / stream->sum_dep_weight;

  return nghttp2_max(1, weight);
}

int32_t nghttp2_stream_dep_distributed_effective_weight
(nghttp2_stream *stream, int32_t weight)
{
  if(stream->sum_norest_weight == 0) {
    return stream->effective_weight;
  }

  weight = stream->effective_weight * weight / stream->sum_norest_weight;

  return nghttp2_max(1, weight);
}

/* Updates effective_weight of descendant streams in subtree of
   |stream|.  We assume that stream->effective_weight is already set
   right. */
static void stream_update_dep_effective_weight(nghttp2_stream *stream)
{
  nghttp2_stream *si;

  DEBUGF(fprintf(stderr, "stream: update_dep_effective_weight "
                 "stream(%p)=%d, weight=%d, sum_norest_weight=%d\n",
                 stream, stream->stream_id, stream->weight,
                 stream->sum_norest_weight));

  /* stream->sum_norest_weight == 0 means there is no
     NGHTTP2_STREAM_DPRI_TOP under stream */
  if(stream->dpri != NGHTTP2_STREAM_DPRI_NO_DATA ||
     stream->sum_norest_weight == 0) {
    return;
  }

  for(si = stream->dep_next; si; si = si->sib_next) {
    if(si->dpri != NGHTTP2_STREAM_DPRI_REST) {
      si->effective_weight = nghttp2_stream_dep_distributed_effective_weight
        (stream, si->weight);
    }

    stream_update_dep_effective_weight(si);
  }
}

static void stream_update_dep_set_rest(nghttp2_stream *stream)
{
  if(stream == NULL) {
    return;
  }

  if(stream->dpri == NGHTTP2_STREAM_DPRI_REST) {
    return;
  }

  if(stream->dpri == NGHTTP2_STREAM_DPRI_TOP) {
    stream->dpri = NGHTTP2_STREAM_DPRI_REST;

    stream_update_dep_set_rest(stream->sib_next);

    return;
  }

  stream_update_dep_set_rest(stream->sib_next);
  stream_update_dep_set_rest(stream->dep_next);
}

/*
 * Performs dfs starting |stream|, search stream which can become
 * NGHTTP2_STREAM_DPRI_TOP and queues its data_item.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
static int stream_update_dep_set_top(nghttp2_stream *stream, nghttp2_pq *pq,
                                     uint64_t cycle)
{
  int rv;
  nghttp2_stream *si;

  if(stream->dpri == NGHTTP2_STREAM_DPRI_TOP) {
    return 0;
  }

  if(stream->dpri == NGHTTP2_STREAM_DPRI_REST) {
    DEBUGF(fprintf(stderr, "stream: stream=%d data is top\n",
                   stream->stream_id));

    if(!stream->data_item->queued) {
      rv = stream_push_data(stream, pq, cycle);

      if(rv != 0) {
        return rv;
      }
    }

    stream->dpri = NGHTTP2_STREAM_DPRI_TOP;

    return 0;
  }

  for(si = stream->dep_next; si; si = si->sib_next) {
    rv = stream_update_dep_set_top(si, pq, cycle);

    if(rv != 0) {
      return rv;
    }
  }

  return 0;
}

/*
 * Updates stream->sum_norest_weight recursively.  We have to gather
 * effective sum of weight of descendants.  If stream->dpri ==
 * NGHTTP2_STREAM_DPRI_NO_DATA, we have to go deeper and check that
 * any of its descendants has dpri value of NGHTTP2_STREAM_DPRI_TOP.
 * If so, we have to add weight of its direct descendants to
 * stream->sum_norest_weight.  To make this work, this function
 * returns 1 if any of its descendants has dpri value of
 * NGHTTP2_STREAM_DPRI_TOP, otherwise 0.
 */
static int stream_update_dep_sum_norest_weight(nghttp2_stream *stream)
{
  nghttp2_stream *si;
  int rv;

  stream->sum_norest_weight = 0;

  if(stream->dpri == NGHTTP2_STREAM_DPRI_TOP) {
    return 1;
  }

  if(stream->dpri == NGHTTP2_STREAM_DPRI_REST) {
    return 0;
  }

  rv = 0;

  for(si = stream->dep_next; si; si = si->sib_next) {

    if(stream_update_dep_sum_norest_weight(si)) {
      rv = 1;
      stream->sum_norest_weight += si->weight;
    }
  }

  return rv;
}

static int stream_update_dep_on_attach_data(nghttp2_stream *stream,
                                            nghttp2_pq *pq, uint64_t cycle)
{
  int rv;
  nghttp2_stream *root_stream;

  stream->dpri = NGHTTP2_STREAM_DPRI_REST;

  stream_update_dep_set_rest(stream->dep_next);

  root_stream = nghttp2_stream_get_dep_root(stream);

  DEBUGF(fprintf(stderr, "root=%p, stream=%p\n", root_stream, stream));

  rv = stream_update_dep_set_top(root_stream, pq, cycle);

  if(rv != 0) {
    return rv;
  }

  stream_update_dep_sum_norest_weight(root_stream);
  stream_update_dep_effective_weight(root_stream);

  return 0;
}

static int stream_update_dep_on_detach_data(nghttp2_stream *stream,
                                            nghttp2_pq *pq, uint64_t cycle)
{
  int rv;
  nghttp2_stream *root_stream;

  stream->dpri = NGHTTP2_STREAM_DPRI_NO_DATA;

  root_stream = nghttp2_stream_get_dep_root(stream);

  rv = stream_update_dep_set_top(root_stream, pq, cycle);

  if(rv != 0) {
    return rv;
  }

  stream_update_dep_sum_norest_weight(root_stream);
  stream_update_dep_effective_weight(root_stream);

  return 0;
}

int nghttp2_stream_attach_data(nghttp2_stream *stream,
                               nghttp2_outbound_item *data_item,
                               nghttp2_pq *pq,
                               uint64_t cycle)
{
  assert((stream->flags & NGHTTP2_STREAM_FLAG_DEFERRED_ALL) == 0);
  assert(stream->data_item == NULL);

  DEBUGF(fprintf(stderr, "stream: stream=%d attach data=%p\n",
                 stream->stream_id, data_item));

  stream->data_item = data_item;

  return stream_update_dep_on_attach_data(stream, pq, cycle);
}

int nghttp2_stream_detach_data(nghttp2_stream *stream, nghttp2_pq *pq,
                               uint64_t cycle)
{
  DEBUGF(fprintf(stderr, "stream: stream=%d detach data=%p\n",
                 stream->stream_id, stream->data_item));

  stream->data_item = NULL;
  stream->flags &= ~NGHTTP2_STREAM_FLAG_DEFERRED_ALL;

  return stream_update_dep_on_detach_data(stream, pq, cycle);
}

int nghttp2_stream_defer_data(nghttp2_stream *stream, uint8_t flags,
                              nghttp2_pq *pq, uint64_t cycle)
{
  assert(stream->data_item);

  DEBUGF(fprintf(stderr, "stream: stream=%d defer data=%p cause=%02x\n",
                 stream->stream_id, stream->data_item, flags));

  stream->flags |= flags;

  return stream_update_dep_on_detach_data(stream, pq, cycle);
}

int nghttp2_stream_resume_deferred_data(nghttp2_stream *stream,
                                        nghttp2_pq *pq, uint64_t cycle)
{
  assert(stream->data_item);

  DEBUGF(fprintf(stderr, "stream: stream=%d resume data=%p\n",
                 stream->stream_id, stream->data_item));

  stream->flags &= ~NGHTTP2_STREAM_FLAG_DEFERRED_ALL;

  return stream_update_dep_on_attach_data(stream, pq, cycle);
}

int nghttp2_stream_check_deferred_data(nghttp2_stream *stream)
{
  return stream->data_item &&
    (stream->flags & NGHTTP2_STREAM_FLAG_DEFERRED_ALL);
}

int nghttp2_stream_check_deferred_by_flow_control(nghttp2_stream *stream)
{
  return stream->data_item &&
    (stream->flags & NGHTTP2_STREAM_FLAG_DEFERRED_FLOW_CONTROL);
}

static int update_initial_window_size
(int32_t *window_size_ptr,
 int32_t new_initial_window_size,
 int32_t old_initial_window_size)
{
  int64_t new_window_size = (int64_t)(*window_size_ptr) +
    new_initial_window_size - old_initial_window_size;
  if(INT32_MIN > new_window_size ||
     new_window_size > NGHTTP2_MAX_WINDOW_SIZE) {
    return -1;
  }
  *window_size_ptr = (int32_t)new_window_size;
  return 0;
}

int nghttp2_stream_update_remote_initial_window_size
(nghttp2_stream *stream,
 int32_t new_initial_window_size,
 int32_t old_initial_window_size)
{
  return update_initial_window_size(&stream->remote_window_size,
                                    new_initial_window_size,
                                    old_initial_window_size);
}

int nghttp2_stream_update_local_initial_window_size
(nghttp2_stream *stream,
 int32_t new_initial_window_size,
 int32_t old_initial_window_size)
{
  return update_initial_window_size(&stream->local_window_size,
                                    new_initial_window_size,
                                    old_initial_window_size);
}

void nghttp2_stream_promise_fulfilled(nghttp2_stream *stream)
{
  stream->state = NGHTTP2_STREAM_OPENED;
}

nghttp2_stream* nghttp2_stream_get_dep_root(nghttp2_stream *stream)
{
  for(;;) {
    if(stream->sib_prev) {
      stream = stream->sib_prev;

      continue;
    }

    if(stream->dep_prev) {
      stream = stream->dep_prev;

      continue;
    }

    break;
  }

  return stream;
}

int nghttp2_stream_dep_subtree_find(nghttp2_stream *stream,
                                    nghttp2_stream *target)
{
  if(stream == NULL) {
    return 0;
  }

  if(stream == target) {
    return 1;
  }

  if(nghttp2_stream_dep_subtree_find(stream->sib_next, target)) {
    return 1;
  }

  return nghttp2_stream_dep_subtree_find(stream->dep_next, target);
}

void nghttp2_stream_dep_insert(nghttp2_stream *dep_stream,
                               nghttp2_stream *stream)
{
  nghttp2_stream *si;
  nghttp2_stream *root_stream;

  assert(stream->data_item == NULL);

  DEBUGF(fprintf(stderr,
                 "stream: dep_insert dep_stream(%p)=%d, stream(%p)=%d\n",
                 dep_stream, dep_stream->stream_id,
                 stream, stream->stream_id));

  stream->sum_dep_weight = dep_stream->sum_dep_weight;
  dep_stream->sum_dep_weight = stream->weight;

  if(dep_stream->dep_next) {
    for(si = dep_stream->dep_next; si; si = si->sib_next) {
      stream->num_substreams += si->num_substreams;
    }

    stream->dep_next = dep_stream->dep_next;
    stream->dep_next->dep_prev = stream;
  }

  dep_stream->dep_next = stream;
  stream->dep_prev = dep_stream;

  root_stream = stream_update_dep_length(dep_stream, 1);

  stream_update_dep_sum_norest_weight(root_stream);
  stream_update_dep_effective_weight(root_stream);

  ++stream->roots->num_streams;
}

void nghttp2_stream_dep_add(nghttp2_stream *dep_stream,
                            nghttp2_stream *stream)
{
  nghttp2_stream *last_sib;
  nghttp2_stream *root_stream;

  assert(stream->data_item == NULL);

  DEBUGF(fprintf(stderr,
                 "stream: dep_add dep_stream(%p)=%d, stream(%p)=%d\n",
                 dep_stream, dep_stream->stream_id,
                 stream, stream->stream_id));

  root_stream = stream_update_dep_length(dep_stream, 1);

  dep_stream->sum_dep_weight += stream->weight;

  if(dep_stream->dep_next == NULL) {
    dep_stream->dep_next = stream;
    stream->dep_prev = dep_stream;
  } else {
    last_sib = stream_last_sib(dep_stream->dep_next);
    last_sib->sib_next = stream;
    stream->sib_prev = last_sib;
  }

  stream_update_dep_sum_norest_weight(root_stream);
  stream_update_dep_effective_weight(root_stream);

  ++stream->roots->num_streams;
}

void nghttp2_stream_dep_remove(nghttp2_stream *stream)
{
  nghttp2_stream *prev, *next, *dep_next, *dep_prev, *si, *root_stream;
  int32_t sum_dep_weight_delta;

  root_stream = NULL;

  DEBUGF(fprintf(stderr, "stream: dep_remove stream(%p)=%d\n",
                 stream, stream->stream_id));

  /* Distribute weight of |stream| to direct descendants */
  sum_dep_weight_delta = -stream->weight;

  for(si = stream->dep_next; si; si = si->sib_next) {
    si->weight = nghttp2_stream_dep_distributed_weight(stream, si->weight);

    sum_dep_weight_delta += si->weight;
  }

  prev = stream_first_sib(stream);

  dep_prev = prev->dep_prev;

  if(dep_prev) {
    root_stream = stream_update_dep_length(dep_prev, -1);

    dep_prev->sum_dep_weight += sum_dep_weight_delta;
  }

  if(stream->sib_prev) {
    prev = stream->sib_prev;
    dep_next = stream->dep_next;

    if(dep_next) {
      dep_next->dep_prev = NULL;

      prev->sib_next = dep_next;
      dep_next->sib_prev = prev;
    } else {
      next = stream->sib_next;

      prev->sib_next = next;

      if(next) {
        next->sib_prev = prev;
      }
    }
  } else if(stream->dep_prev) {
    prev = stream->dep_prev;
    dep_next = stream->dep_next;

    if(dep_next) {
      prev->dep_next = dep_next;
      dep_next->dep_prev = prev;
    } else if(stream->sib_next) {
      next = stream->sib_next;

      prev->dep_next = next;
      next->dep_prev = prev;

      next->sib_prev = NULL;
    } else {
      prev->dep_next = NULL;
      dep_next = NULL;
    }
  } else {
    nghttp2_stream_roots_remove(stream->roots, stream);

    dep_next = NULL;

    /* stream is a root of tree.  Removing stream makes its
       descendants a root of its own subtree. */

    for(si = stream->dep_next; si;) {
      next = si->sib_next;

      si->dep_prev = NULL;
      si->sib_prev = NULL;
      si->sib_next = NULL;

      /* We already distributed weight of |stream| to this. */
      si->effective_weight = si->weight;

      nghttp2_stream_roots_add(si->roots, si);

      si = next;
    }
  }

  if(dep_next && stream->sib_next) {
    prev = stream_last_sib(dep_next);
    next = stream->sib_next;

    prev->sib_next = next;
    next->sib_prev = prev;
  }

  if(root_stream) {
    stream_update_dep_sum_norest_weight(root_stream);
    stream_update_dep_effective_weight(root_stream);
  }

  stream->num_substreams = 1;
  stream->sum_dep_weight = 0;

  stream->dep_prev = NULL;
  stream->dep_next = NULL;
  stream->sib_prev = NULL;
  stream->sib_next = NULL;

  --stream->roots->num_streams;
}

int nghttp2_stream_dep_insert_subtree(nghttp2_stream *dep_stream,
                                      nghttp2_stream *stream,
                                      nghttp2_pq *pq,
                                      uint64_t cycle)
{
  nghttp2_stream *last_sib;
  nghttp2_stream *dep_next;
  nghttp2_stream *root_stream;
  size_t delta_substreams;
  int rv;

  DEBUGF(fprintf(stderr, "stream: dep_insert_subtree dep_stream(%p)=%d "
                 "stream(%p)=%d\n",
                 dep_stream, dep_stream->stream_id,
                 stream, stream->stream_id));

  delta_substreams = stream->num_substreams;

  stream_update_dep_set_rest(stream);

  if(dep_stream->dep_next) {
    /* dep_stream->num_substreams includes dep_stream itself */
    stream->num_substreams += dep_stream->num_substreams - 1;

    stream->sum_dep_weight += dep_stream->sum_dep_weight;
    dep_stream->sum_dep_weight = stream->weight;

    dep_next = dep_stream->dep_next;

    stream_update_dep_set_rest(dep_next);

    dep_stream->dep_next = stream;
    stream->dep_prev = dep_stream;

    if(stream->dep_next) {
      last_sib = stream_last_sib(stream->dep_next);

      last_sib->sib_next = dep_next;
      dep_next->sib_prev = last_sib;

      dep_next->dep_prev = NULL;
    } else {
      stream->dep_next = dep_next;
      dep_next->dep_prev = stream;
    }
  } else {
    dep_stream->dep_next = stream;
    stream->dep_prev = dep_stream;

    assert(dep_stream->sum_dep_weight == 0);
    dep_stream->sum_dep_weight = stream->weight;
  }

  root_stream = stream_update_dep_length(dep_stream, delta_substreams);

  rv = stream_update_dep_set_top(root_stream, pq, cycle);

  if(rv != 0) {
    return rv;
  }

  stream_update_dep_sum_norest_weight(root_stream);
  stream_update_dep_effective_weight(root_stream);

  return 0;
}

int nghttp2_stream_dep_add_subtree(nghttp2_stream *dep_stream,
                                   nghttp2_stream *stream,
                                   nghttp2_pq *pq,
                                   uint64_t cycle)
{
  nghttp2_stream *last_sib;
  nghttp2_stream *root_stream;
  int rv;

  DEBUGF(fprintf(stderr, "stream: dep_add_subtree dep_stream(%p)=%d "
                 "stream(%p)=%d\n",
                 dep_stream, dep_stream->stream_id,
                 stream, stream->stream_id));

  stream_update_dep_set_rest(stream);

  if(dep_stream->dep_next) {
    dep_stream->sum_dep_weight += stream->weight;

    last_sib = stream_last_sib(dep_stream->dep_next);

    last_sib->sib_next = stream;
    stream->sib_prev = last_sib;
  } else {
    dep_stream->dep_next = stream;
    stream->dep_prev = dep_stream;

    assert(dep_stream->sum_dep_weight == 0);
    dep_stream->sum_dep_weight = stream->weight;
  }

  root_stream = stream_update_dep_length(dep_stream, stream->num_substreams);

  rv = stream_update_dep_set_top(root_stream, pq, cycle);

  if(rv != 0) {
    return rv;
  }

  stream_update_dep_sum_norest_weight(root_stream);
  stream_update_dep_effective_weight(root_stream);

  return 0;
}

void nghttp2_stream_dep_remove_subtree(nghttp2_stream *stream)
{
  nghttp2_stream *prev, *next, *dep_prev, *root_stream;

  DEBUGF(fprintf(stderr, "stream: dep_remove_subtree stream(%p)=%d\n",
                 stream, stream->stream_id));

  if(stream->sib_prev) {
    prev = stream->sib_prev;

    prev->sib_next = stream->sib_next;
    if(prev->sib_next) {
      prev->sib_next->sib_prev = prev;
    }

    prev = stream_first_sib(prev);

    dep_prev = prev->dep_prev;

  } else if(stream->dep_prev) {
    dep_prev = stream->dep_prev;
    next = stream->sib_next;

    dep_prev->dep_next = next;

    if(next) {
      next->dep_prev = dep_prev;

      next->sib_prev = NULL;
    }

  } else {
    nghttp2_stream_roots_remove(stream->roots, stream);

    dep_prev = NULL;
  }

  if(dep_prev) {
    dep_prev->sum_dep_weight -= stream->weight;

    root_stream = stream_update_dep_length(dep_prev, -stream->num_substreams);

    stream_update_dep_sum_norest_weight(root_stream);
    stream_update_dep_effective_weight(root_stream);
  }

  stream->sib_prev = NULL;
  stream->sib_next = NULL;
  stream->dep_prev = NULL;
}

int nghttp2_stream_dep_make_root(nghttp2_stream *stream, nghttp2_pq *pq,
                                 uint64_t cycle)
{
  int rv;

  DEBUGF(fprintf(stderr, "stream: dep_make_root stream(%p)=%d\n",
                 stream, stream->stream_id));

  nghttp2_stream_roots_add(stream->roots, stream);

  stream_update_dep_set_rest(stream);

  stream->effective_weight = stream->weight;

  rv = stream_update_dep_set_top(stream, pq, cycle);

  if(rv != 0) {
    return rv;
  }

  stream_update_dep_sum_norest_weight(stream);
  stream_update_dep_effective_weight(stream);

  return 0;
}

int nghttp2_stream_dep_all_your_stream_are_belong_to_us
(nghttp2_stream *stream, nghttp2_pq *pq, uint64_t cycle)
{
  nghttp2_stream *first, *si;

  DEBUGF(fprintf(stderr, "stream: ALL YOUR STREAM ARE BELONG TO US "
                 "stream(%p)=%d\n",
                 stream, stream->stream_id));

  first = stream->roots->head;

  /* stream must not be include in stream->roots->head list */
  assert(first != stream);

  if(first) {
    nghttp2_stream *prev;

    prev = first;

    DEBUGF(fprintf(stderr, "stream: root stream(%p)=%d\n",
                   first, first->stream_id));

    stream->sum_dep_weight += first->weight;
    stream->num_substreams += first->num_substreams;

    for(si = first->root_next; si; si = si->root_next) {

      assert(si != stream);

      DEBUGF(fprintf(stderr, "stream: root stream(%p)=%d\n",
                     si, si->stream_id));

      stream->sum_dep_weight += si->weight;
      stream->num_substreams += si->num_substreams;

      si->sib_prev = prev;
      prev->sib_next = si;

      prev = si;
    }

    if(stream->dep_next) {
      nghttp2_stream *last_sib;

      last_sib = stream_last_sib(stream->dep_next);

      last_sib->sib_next = first;
      first->sib_prev = last_sib;
    } else {
      stream->dep_next = first;
      first->dep_prev = stream;
    }
  }

  nghttp2_stream_roots_remove_all(stream->roots);

  return nghttp2_stream_dep_make_root(stream, pq, cycle);
}

int nghttp2_stream_in_dep_tree(nghttp2_stream *stream)
{
  return stream->dep_prev || stream->dep_next ||
    stream->sib_prev || stream->sib_next ||
    stream->root_next || stream->root_prev ||
    stream->roots->head == stream;
}

void nghttp2_stream_roots_init(nghttp2_stream_roots *roots)
{
  roots->head = NULL;
  roots->num_streams = 0;
}

void nghttp2_stream_roots_free(nghttp2_stream_roots *roots)
{}

void nghttp2_stream_roots_add(nghttp2_stream_roots *roots,
                              nghttp2_stream *stream)
{
  if(roots->head) {
    stream->root_next = roots->head;
    roots->head->root_prev = stream;
  }

  roots->head = stream;
}

void nghttp2_stream_roots_remove(nghttp2_stream_roots *roots,
                                 nghttp2_stream *stream)
{
  nghttp2_stream *root_prev, *root_next;

  root_prev = stream->root_prev;
  root_next = stream->root_next;

  if(root_prev) {
    root_prev->root_next = root_next;

    if(root_next) {
      root_next->root_prev = root_prev;
    }
  } else {
    if(root_next) {
      root_next->root_prev = NULL;
    }

    roots->head = root_next;
  }

  stream->root_prev = NULL;
  stream->root_next = NULL;
}

void nghttp2_stream_roots_remove_all(nghttp2_stream_roots *roots)
{
  nghttp2_stream *si, *next;

  for(si = roots->head; si;) {
    next = si->root_next;

    si->root_prev = NULL;
    si->root_next = NULL;

    si = next;
  }

  roots->head = NULL;
}
