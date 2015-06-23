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

#include "nghttp2_session.h"
#include "nghttp2_helper.h"

void nghttp2_stream_init(nghttp2_stream *stream, int32_t stream_id,
                         uint8_t flags, nghttp2_stream_state initial_state,
                         int32_t weight, nghttp2_stream_roots *roots,
                         int32_t remote_initial_window_size,
                         int32_t local_initial_window_size,
                         void *stream_user_data) {
  nghttp2_map_entry_init(&stream->map_entry, stream_id);
  stream->stream_id = stream_id;
  stream->flags = flags;
  stream->state = initial_state;
  stream->shut_flags = NGHTTP2_SHUT_NONE;
  stream->stream_user_data = stream_user_data;
  stream->item = NULL;
  stream->remote_window_size = remote_initial_window_size;
  stream->local_window_size = local_initial_window_size;
  stream->recv_window_size = 0;
  stream->consumed_size = 0;
  stream->recv_reduction = 0;

  stream->dep_prev = NULL;
  stream->dep_next = NULL;
  stream->sib_prev = NULL;
  stream->sib_next = NULL;

  stream->closed_prev = NULL;
  stream->closed_next = NULL;

  stream->dpri = NGHTTP2_STREAM_DPRI_NO_ITEM;
  stream->num_substreams = 1;
  stream->weight = weight;
  stream->sum_dep_weight = 0;
  stream->sum_norest_weight = 0;

  stream->roots = roots;
  stream->root_prev = NULL;
  stream->root_next = NULL;

  stream->http_flags = NGHTTP2_HTTP_FLAG_NONE;
  stream->content_length = -1;
  stream->recv_content_length = 0;
  stream->status_code = -1;
}

void nghttp2_stream_free(nghttp2_stream *stream _U_) {
  /* We don't free stream->item.  If it is assigned to aob, then
     active_outbound_item_reset() will delete it.  If it is queued,
     then it is deleted when pq is deleted in nghttp2_session_del().
     Otherwise, nghttp2_session_del() will delete it. */
}

void nghttp2_stream_shutdown(nghttp2_stream *stream, nghttp2_shut_flag flag) {
  stream->shut_flags |= flag;
}

static int stream_push_item(nghttp2_stream *stream, nghttp2_session *session) {
  /* This is required for Android NDK r10d */
  int rv = 0;
  nghttp2_outbound_item *item;

  assert(stream->item);
  assert(stream->item->queued == 0);

  item = stream->item;

  /* If item is now sent, don't push it to the queue.  Otherwise, we
     may push same item twice. */
  if (session->aob.item == item) {
    return 0;
  }

  switch (item->frame.hd.type) {
  case NGHTTP2_DATA:
    /* Penalize item by delaying scheduling according to effective
       weight.  This will delay low priority stream, which is good.
       OTOH, this may incur delay for high priority item.  Will
       see. */
    item->cycle = session->last_cycle +
                  NGHTTP2_DATA_PAYLOADLEN * NGHTTP2_MAX_WEIGHT /
                      nghttp2_stream_compute_effective_weight(stream);

    rv = nghttp2_pq_push(&session->ob_da_pq, item);
    if (rv != 0) {
      return rv;
    }
    break;
  case NGHTTP2_HEADERS:
    if (stream->state == NGHTTP2_STREAM_RESERVED) {
      nghttp2_outbound_queue_push(&session->ob_syn, item);
    } else {
      nghttp2_outbound_queue_push(&session->ob_reg, item);
    }
    break;
  default:
    /* should not reach here */
    assert(0);
  }

  item->queued = 1;

  return 0;
}

static nghttp2_stream *stream_last_sib(nghttp2_stream *stream) {
  for (; stream->sib_next; stream = stream->sib_next)
    ;

  return stream;
}

static void stream_update_dep_length(nghttp2_stream *stream, ssize_t delta) {
  stream->num_substreams += delta;

  if (stream->dep_prev) {
    stream_update_dep_length(stream->dep_prev, delta);
  }
}

int32_t nghttp2_stream_dep_distributed_weight(nghttp2_stream *stream,
                                              int32_t weight) {
  weight = stream->weight * weight / stream->sum_dep_weight;

  return nghttp2_max(1, weight);
}

static void stream_update_dep_set_rest(nghttp2_stream *stream) {
  if (stream == NULL) {
    return;
  }

  DEBUGF(fprintf(stderr, "stream: stream=%d is rest\n", stream->stream_id));

  if (stream->dpri == NGHTTP2_STREAM_DPRI_REST) {
    return;
  }

  if (stream->dpri == NGHTTP2_STREAM_DPRI_TOP) {
    stream->dpri = NGHTTP2_STREAM_DPRI_REST;

    stream_update_dep_set_rest(stream->sib_next);

    return;
  }

  stream_update_dep_set_rest(stream->sib_next);
  stream_update_dep_set_rest(stream->dep_next);
}

/*
 * Performs dfs starting |stream|, search stream which can become
 * NGHTTP2_STREAM_DPRI_TOP and set its dpri.  This function also
 * updates sum_norest_weight if stream->dpri ==
 * NGHTTP2_STREAM_DPRI_NO_ITEM.  This function returns nonzero if
 * stream's subtree contains at least one NGHTTP2_STRAEM_DPRI_TOP
 * stream.
 */
static int stream_update_dep_set_top(nghttp2_stream *stream) {
  nghttp2_stream *si;

  if (!stream) {
    return 0;
  }

  if (stream->dpri == NGHTTP2_STREAM_DPRI_TOP) {
    return 1;
  }

  stream->sum_norest_weight = 0;

  if (stream->dpri == NGHTTP2_STREAM_DPRI_REST) {
    DEBUGF(
        fprintf(stderr, "stream: stream=%d item is top\n", stream->stream_id));

    stream->dpri = NGHTTP2_STREAM_DPRI_TOP;

    return 1;
  }

  for (si = stream->dep_next; si; si = si->sib_next) {
    if (stream_update_dep_set_top(si)) {
      stream->sum_norest_weight += si->weight;
    }
  }

  return stream->sum_norest_weight > 0;
}

/*
 * Performs dfs starting |stream|, and dueue stream whose dpri is
 * NGHTTP2_STREAM_DPRI_TOP and has not been queued yet.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
static int stream_update_dep_queue_top(nghttp2_stream *stream,
                                       nghttp2_session *session) {
  int rv;
  nghttp2_stream *si;

  if (stream->dpri == NGHTTP2_STREAM_DPRI_REST) {
    return 0;
  }

  if (stream->dpri == NGHTTP2_STREAM_DPRI_TOP) {
    if (!stream->item->queued) {
      DEBUGF(fprintf(stderr, "stream: stream=%d enqueue\n", stream->stream_id));
      rv = stream_push_item(stream, session);

      if (rv != 0) {
        return rv;
      }
    }

    return 0;
  }

  if (stream->sum_norest_weight == 0) {
    return 0;
  }

  for (si = stream->dep_next; si; si = si->sib_next) {
    rv = stream_update_dep_queue_top(si, session);

    if (rv != 0) {
      return rv;
    }
  }

  return 0;
}

/*
 * Updates stream->sum_norest_weight recursively towards root.
 * |delta| must not be 0.  We have to gather effective sum of weight
 * of descendants.  |delta| is added to stream->sum_norest_weight.  If
 * stream->sum_norest_weight becomes 0, we have to update parent
 * stream, decreasing its sum_norest_weight by stream->weight.  If
 * stream->sum_norest_weight becomes from 0 to positive, then we have
 * to update parent stream, increasing its sum_norest_weight by
 * stream->weight.  Otherwise, we stop recursive call.
 */
static void stream_update_dep_sum_norest_weight(nghttp2_stream *stream,
                                                int32_t delta) {
  int32_t old;

  if (!stream) {
    return;
  }

  assert(delta != 0);
  assert(stream->sum_norest_weight + delta >= 0);

  old = stream->sum_norest_weight;
  stream->sum_norest_weight += delta;

  if (old == 0) {
    assert(delta > 0);
    stream_update_dep_sum_norest_weight(stream->dep_prev, stream->weight);
    return;
  }

  assert(old > 0);

  if (stream->sum_norest_weight == 0) {
    stream_update_dep_sum_norest_weight(stream->dep_prev, -stream->weight);
  }
}

/*
 * Returns stream whose dpri is NGHTTP2_STREAM_DPRI_NO_ITEM along the
 * path following stream->dep_prev (stream's ancestors, including
 * itself).  In other words, find stream which blocks the descendant
 * streams.  If there is no such stream, returns NULL.
 */
static nghttp2_stream *stream_get_dep_blocking(nghttp2_stream *stream) {
  for (; stream; stream = stream->dep_prev) {
    if (stream->dpri != NGHTTP2_STREAM_DPRI_NO_ITEM) {
      return stream;
    }
  }
  return NULL;
}

static int stream_update_dep_on_attach_item(nghttp2_stream *stream,
                                            nghttp2_session *session) {
  nghttp2_stream *blocking_stream;
  int rv;

  stream->dpri = NGHTTP2_STREAM_DPRI_REST;

  blocking_stream = stream_get_dep_blocking(stream->dep_prev);

  /* If we found REST or TOP in ascendants, we don't have to update
     any metadata. */
  if (blocking_stream) {
    return 0;
  }

  stream->dpri = NGHTTP2_STREAM_DPRI_TOP;
  if (stream->sum_norest_weight == 0) {
    stream_update_dep_sum_norest_weight(stream->dep_prev, stream->weight);
  } else {
    stream_update_dep_set_rest(stream->dep_next);
  }

  if (!stream->item->queued) {
    DEBUGF(fprintf(stderr, "stream: stream=%d enqueue\n", stream->stream_id));
    rv = stream_push_item(stream, session);

    if (rv != 0) {
      return rv;
    }
  }

  return 0;
}

static int stream_update_dep_on_detach_item(nghttp2_stream *stream,
                                            nghttp2_session *session) {
  if (stream->dpri == NGHTTP2_STREAM_DPRI_REST) {
    stream->dpri = NGHTTP2_STREAM_DPRI_NO_ITEM;
    return 0;
  }

  if (stream->dpri == NGHTTP2_STREAM_DPRI_NO_ITEM) {
    /* nghttp2_stream_defer_item() does not clear stream->item, but
       set dpri = NGHTTP2_STREAM_DPRI_NO_ITEM.  Catch this case
       here. */
    return 0;
  }

  stream->dpri = NGHTTP2_STREAM_DPRI_NO_ITEM;

  if (stream_update_dep_set_top(stream) == 0) {
    stream_update_dep_sum_norest_weight(stream->dep_prev, -stream->weight);
    return 0;
  }

  return stream_update_dep_queue_top(stream->dep_next, session);
}

int nghttp2_stream_attach_item(nghttp2_stream *stream,
                               nghttp2_outbound_item *item,
                               nghttp2_session *session) {
  assert((stream->flags & NGHTTP2_STREAM_FLAG_DEFERRED_ALL) == 0);
  assert(stream->item == NULL);

  DEBUGF(fprintf(stderr, "stream: stream=%d attach item=%p\n",
                 stream->stream_id, item));

  stream->item = item;

  return stream_update_dep_on_attach_item(stream, session);
}

int nghttp2_stream_detach_item(nghttp2_stream *stream,
                               nghttp2_session *session) {
  DEBUGF(fprintf(stderr, "stream: stream=%d detach item=%p\n",
                 stream->stream_id, stream->item));

  stream->item = NULL;
  stream->flags &= ~NGHTTP2_STREAM_FLAG_DEFERRED_ALL;

  return stream_update_dep_on_detach_item(stream, session);
}

int nghttp2_stream_defer_item(nghttp2_stream *stream, uint8_t flags,
                              nghttp2_session *session) {
  assert(stream->item);

  DEBUGF(fprintf(stderr, "stream: stream=%d defer item=%p cause=%02x\n",
                 stream->stream_id, stream->item, flags));

  stream->flags |= flags;

  return stream_update_dep_on_detach_item(stream, session);
}

int nghttp2_stream_resume_deferred_item(nghttp2_stream *stream, uint8_t flags,
                                        nghttp2_session *session) {
  assert(stream->item);

  DEBUGF(fprintf(stderr, "stream: stream=%d resume item=%p flags=%02x\n",
                 stream->stream_id, stream->item, flags));

  stream->flags &= ~flags;

  if (stream->flags & NGHTTP2_STREAM_FLAG_DEFERRED_ALL) {
    return 0;
  }

  return stream_update_dep_on_attach_item(stream, session);
}

int nghttp2_stream_check_deferred_item(nghttp2_stream *stream) {
  return stream->item && (stream->flags & NGHTTP2_STREAM_FLAG_DEFERRED_ALL);
}

int nghttp2_stream_check_deferred_by_flow_control(nghttp2_stream *stream) {
  return stream->item &&
         (stream->flags & NGHTTP2_STREAM_FLAG_DEFERRED_FLOW_CONTROL);
}

static int update_initial_window_size(int32_t *window_size_ptr,
                                      int32_t new_initial_window_size,
                                      int32_t old_initial_window_size) {
  int64_t new_window_size = (int64_t)(*window_size_ptr) +
                            new_initial_window_size - old_initial_window_size;
  if (INT32_MIN > new_window_size ||
      new_window_size > NGHTTP2_MAX_WINDOW_SIZE) {
    return -1;
  }
  *window_size_ptr = (int32_t)new_window_size;
  return 0;
}

int nghttp2_stream_update_remote_initial_window_size(
    nghttp2_stream *stream, int32_t new_initial_window_size,
    int32_t old_initial_window_size) {
  return update_initial_window_size(&stream->remote_window_size,
                                    new_initial_window_size,
                                    old_initial_window_size);
}

int nghttp2_stream_update_local_initial_window_size(
    nghttp2_stream *stream, int32_t new_initial_window_size,
    int32_t old_initial_window_size) {
  return update_initial_window_size(&stream->local_window_size,
                                    new_initial_window_size,
                                    old_initial_window_size);
}

void nghttp2_stream_promise_fulfilled(nghttp2_stream *stream) {
  stream->state = NGHTTP2_STREAM_OPENED;
  stream->flags &= ~NGHTTP2_STREAM_FLAG_PUSH;
}

nghttp2_stream *nghttp2_stream_get_dep_root(nghttp2_stream *stream) {
  for (; stream->dep_prev; stream = stream->dep_prev)
    ;
  return stream;
}

int nghttp2_stream_dep_subtree_find(nghttp2_stream *stream,
                                    nghttp2_stream *target) {
  if (stream == NULL) {
    return 0;
  }

  if (stream == target) {
    return 1;
  }

  if (nghttp2_stream_dep_subtree_find(stream->sib_next, target)) {
    return 1;
  }

  return nghttp2_stream_dep_subtree_find(stream->dep_next, target);
}

int32_t nghttp2_stream_compute_effective_weight(nghttp2_stream *stream) {
  int32_t weight;

  if (!stream->dep_prev) {
    return stream->weight;
  }

  weight = nghttp2_stream_compute_effective_weight(stream->dep_prev) *
           stream->weight / stream->dep_prev->sum_norest_weight;

  return nghttp2_max(1, weight);
}

void nghttp2_stream_dep_insert(nghttp2_stream *dep_stream,
                               nghttp2_stream *stream) {
  nghttp2_stream *si;
  nghttp2_stream *blocking_stream;

  assert(stream->dpri == NGHTTP2_STREAM_DPRI_NO_ITEM);

  DEBUGF(fprintf(stderr,
                 "stream: dep_insert dep_stream(%p)=%d, stream(%p)=%d\n",
                 dep_stream, dep_stream->stream_id, stream, stream->stream_id));

  stream->sum_dep_weight = dep_stream->sum_dep_weight;
  dep_stream->sum_dep_weight = stream->weight;

  blocking_stream = stream_get_dep_blocking(dep_stream);

  stream->sum_norest_weight = 0;

  if (dep_stream->dep_next) {
    assert(dep_stream->num_substreams >= 1);
    /* num_substreams includes node itself */
    stream->num_substreams = dep_stream->num_substreams;

    for (si = dep_stream->dep_next; si; si = si->sib_next) {
      si->dep_prev = stream;
      if (!blocking_stream && (si->dpri == NGHTTP2_STREAM_DPRI_TOP ||
                               (si->dpri == NGHTTP2_STREAM_DPRI_NO_ITEM &&
                                si->sum_norest_weight))) {
        stream->sum_norest_weight += si->weight;
      }
    }

    stream->dep_next = dep_stream->dep_next;
  }

  dep_stream->dep_next = stream;
  stream->dep_prev = dep_stream;

  if (stream->sum_norest_weight) {
    dep_stream->sum_norest_weight = stream->weight;
  }

  stream_update_dep_length(dep_stream, 1);

  ++stream->roots->num_streams;
}

static void set_dep_prev(nghttp2_stream *stream, nghttp2_stream *dep) {
  for (; stream; stream = stream->sib_next) {
    stream->dep_prev = dep;
  }
}

static void link_dep(nghttp2_stream *dep_stream, nghttp2_stream *stream) {
  dep_stream->dep_next = stream;
  if (stream) {
    stream->dep_prev = dep_stream;
  }
}

static void link_sib(nghttp2_stream *a, nghttp2_stream *b) {
  a->sib_next = b;
  if (b) {
    b->sib_prev = a;
  }
}

static void insert_link_dep(nghttp2_stream *dep_stream,
                            nghttp2_stream *stream) {
  nghttp2_stream *sib_next;

  assert(stream->sib_prev == NULL);

  sib_next = dep_stream->dep_next;

  link_sib(stream, sib_next);

  link_dep(dep_stream, stream);
}

static void unlink_sib(nghttp2_stream *stream) {
  nghttp2_stream *prev, *next, *dep_next;

  prev = stream->sib_prev;
  dep_next = stream->dep_next;

  assert(prev);

  if (dep_next) {
    /*
     *  prev--stream(--sib_next--...)
     *         |
     *        dep_next
     */

    link_sib(prev, dep_next);

    set_dep_prev(dep_next, stream->dep_prev);

    if (stream->sib_next) {
      link_sib(stream_last_sib(dep_next), stream->sib_next);
    }
  } else {
    /*
     *  prev--stream(--sib_next--...)
     */
    next = stream->sib_next;

    prev->sib_next = next;

    if (next) {
      next->sib_prev = prev;
    }
  }
}

static void unlink_dep(nghttp2_stream *stream) {
  nghttp2_stream *prev, *next, *dep_next;

  prev = stream->dep_prev;
  dep_next = stream->dep_next;

  assert(prev);

  if (dep_next) {
    /*
     * prev
     *   |
     * stream(--sib_next--...)
     *   |
     * dep_next
     */
    link_dep(prev, dep_next);

    set_dep_prev(dep_next, stream->dep_prev);

    if (stream->sib_next) {
      link_sib(stream_last_sib(dep_next), stream->sib_next);
    }

  } else if (stream->sib_next) {
    /*
     * prev
     *   |
     * stream--sib_next
     */
    next = stream->sib_next;

    next->sib_prev = NULL;

    link_dep(prev, next);
  } else {
    prev->dep_next = NULL;
  }
}

void nghttp2_stream_dep_add(nghttp2_stream *dep_stream,
                            nghttp2_stream *stream) {
  assert(stream->dpri == NGHTTP2_STREAM_DPRI_NO_ITEM);

  DEBUGF(fprintf(stderr, "stream: dep_add dep_stream(%p)=%d, stream(%p)=%d\n",
                 dep_stream, dep_stream->stream_id, stream, stream->stream_id));

  stream_update_dep_length(dep_stream, 1);

  dep_stream->sum_dep_weight += stream->weight;

  if (dep_stream->dep_next == NULL) {
    link_dep(dep_stream, stream);
  } else {
    insert_link_dep(dep_stream, stream);
  }

  ++stream->roots->num_streams;
}

void nghttp2_stream_dep_remove(nghttp2_stream *stream) {
  nghttp2_stream *next, *dep_prev, *si, *blocking_stream;
  int32_t sum_dep_weight_delta, sum_norest_weight_delta;

  assert(stream->dpri == NGHTTP2_STREAM_DPRI_NO_ITEM);

  DEBUGF(fprintf(stderr, "stream: dep_remove stream(%p)=%d\n", stream,
                 stream->stream_id));

  blocking_stream = stream_get_dep_blocking(stream->dep_prev);

  /* Distribute weight of |stream| to direct descendants */
  sum_dep_weight_delta = -stream->weight;

  sum_norest_weight_delta = 0;

  /* blocking_stream == NULL means that ascendants are all
     NGHTTP2_STREAM_DPRI_NO_ITEM */
  if (!blocking_stream && stream->sum_norest_weight) {
    sum_norest_weight_delta -= stream->weight;
  }

  for (si = stream->dep_next; si; si = si->sib_next) {
    si->weight = nghttp2_stream_dep_distributed_weight(stream, si->weight);

    sum_dep_weight_delta += si->weight;

    if (!blocking_stream &&
        (si->dpri == NGHTTP2_STREAM_DPRI_TOP ||
         (si->dpri == NGHTTP2_STREAM_DPRI_NO_ITEM && si->sum_norest_weight))) {
      sum_norest_weight_delta += si->weight;
    }
  }

  dep_prev = stream->dep_prev;

  if (dep_prev) {
    stream_update_dep_length(dep_prev, -1);

    dep_prev->sum_dep_weight += sum_dep_weight_delta;
    dep_prev->sum_norest_weight += sum_norest_weight_delta;
  }

  if (stream->sib_prev) {
    unlink_sib(stream);
  } else if (stream->dep_prev) {
    unlink_dep(stream);
  } else {
    nghttp2_stream_roots_remove(stream->roots, stream);

    /* stream is a root of tree.  Removing stream makes its
       descendants a root of its own subtree. */

    for (si = stream->dep_next; si;) {
      next = si->sib_next;

      si->dep_prev = NULL;
      si->sib_prev = NULL;
      si->sib_next = NULL;

      nghttp2_stream_roots_add(si->roots, si);

      si = next;
    }
  }

  stream->num_substreams = 1;
  stream->sum_dep_weight = 0;
  stream->sum_norest_weight = 0;

  stream->dep_prev = NULL;
  stream->dep_next = NULL;
  stream->sib_prev = NULL;
  stream->sib_next = NULL;

  --stream->roots->num_streams;
}

int nghttp2_stream_dep_insert_subtree(nghttp2_stream *dep_stream,
                                      nghttp2_stream *stream,
                                      nghttp2_session *session) {
  nghttp2_stream *last_sib;
  nghttp2_stream *dep_next;
  nghttp2_stream *blocking_stream;
  nghttp2_stream *si;
  size_t delta_substreams;

  DEBUGF(fprintf(stderr, "stream: dep_insert_subtree dep_stream(%p)=%d "
                         "stream(%p)=%d\n",
                 dep_stream, dep_stream->stream_id, stream, stream->stream_id));

  delta_substreams = stream->num_substreams;

  blocking_stream = stream_get_dep_blocking(dep_stream);

  if (dep_stream->dep_next) {
    /* dep_stream->num_substreams includes dep_stream itself */
    stream->num_substreams += dep_stream->num_substreams - 1;

    stream->sum_dep_weight += dep_stream->sum_dep_weight;
    dep_stream->sum_dep_weight = stream->weight;

    dep_next = dep_stream->dep_next;

    if (!blocking_stream && dep_stream->sum_norest_weight) {
      stream_update_dep_set_rest(dep_next);
    }

    link_dep(dep_stream, stream);

    if (stream->dep_next) {
      last_sib = stream_last_sib(stream->dep_next);

      link_sib(last_sib, dep_next);
    } else {
      link_dep(stream, dep_next);
    }

    for (si = dep_next; si; si = si->sib_next) {
      si->dep_prev = stream;
    }
  } else {
    link_dep(dep_stream, stream);

    assert(dep_stream->sum_dep_weight == 0);
    dep_stream->sum_dep_weight = stream->weight;
  }

  stream_update_dep_length(dep_stream, delta_substreams);

  if (blocking_stream) {
    stream_update_dep_set_rest(stream);

    return 0;
  }

  if (stream_update_dep_set_top(stream) == 0) {
    return 0;
  }

  dep_stream->sum_norest_weight = stream->weight;
  stream_update_dep_sum_norest_weight(dep_stream->dep_prev, dep_stream->weight);

  return stream_update_dep_queue_top(stream, session);
}

int nghttp2_stream_dep_add_subtree(nghttp2_stream *dep_stream,
                                   nghttp2_stream *stream,
                                   nghttp2_session *session) {
  nghttp2_stream *blocking_stream;

  DEBUGF(fprintf(stderr, "stream: dep_add_subtree dep_stream(%p)=%d "
                         "stream(%p)=%d\n",
                 dep_stream, dep_stream->stream_id, stream, stream->stream_id));

  if (dep_stream->dep_next) {
    dep_stream->sum_dep_weight += stream->weight;

    insert_link_dep(dep_stream, stream);
  } else {
    link_dep(dep_stream, stream);

    assert(dep_stream->sum_dep_weight == 0);
    dep_stream->sum_dep_weight = stream->weight;
  }

  stream_update_dep_length(dep_stream, stream->num_substreams);

  blocking_stream = stream_get_dep_blocking(dep_stream);

  if (blocking_stream) {
    /* We cannot make any assumption for stream if its dpri is not
       NGHTTP2_DPRI_TOP.  Just dfs under stream here. */
    stream_update_dep_set_rest(stream);

    return 0;
  }

  if (stream->dpri == NGHTTP2_STREAM_DPRI_TOP) {
    stream_update_dep_sum_norest_weight(dep_stream, stream->weight);
    return 0;
  }

  if (stream_update_dep_set_top(stream) == 0) {
    return 0;
  }

  /* Newly added subtree contributes to dep_stream's
     sum_norest_weight */
  stream_update_dep_sum_norest_weight(dep_stream, stream->weight);

  return stream_update_dep_queue_top(stream, session);
}

void nghttp2_stream_dep_remove_subtree(nghttp2_stream *stream) {
  nghttp2_stream *next, *dep_prev, *blocking_stream;

  DEBUGF(fprintf(stderr, "stream: dep_remove_subtree stream(%p)=%d\n", stream,
                 stream->stream_id));

  if (stream->sib_prev) {
    link_sib(stream->sib_prev, stream->sib_next);
    dep_prev = stream->dep_prev;
  } else if (stream->dep_prev) {
    dep_prev = stream->dep_prev;
    next = stream->sib_next;

    link_dep(dep_prev, next);

    if (next) {
      next->sib_prev = NULL;
    }
  } else {
    nghttp2_stream_roots_remove(stream->roots, stream);

    dep_prev = NULL;
  }

  if (dep_prev) {
    dep_prev->sum_dep_weight -= stream->weight;

    stream_update_dep_length(dep_prev, -stream->num_substreams);

    blocking_stream = stream_get_dep_blocking(dep_prev);

    if (!blocking_stream && (stream->dpri == NGHTTP2_STREAM_DPRI_TOP ||
                             (stream->dpri == NGHTTP2_STREAM_DPRI_NO_ITEM &&
                              stream->sum_norest_weight))) {
      stream_update_dep_sum_norest_weight(dep_prev, -stream->weight);
    }
  }

  stream->sib_prev = NULL;
  stream->sib_next = NULL;
  stream->dep_prev = NULL;
}

int nghttp2_stream_dep_make_root(nghttp2_stream *stream,
                                 nghttp2_session *session) {
  DEBUGF(fprintf(stderr, "stream: dep_make_root stream(%p)=%d\n", stream,
                 stream->stream_id));

  nghttp2_stream_roots_add(stream->roots, stream);

  if (stream_update_dep_set_top(stream) == 0) {
    return 0;
  }

  return stream_update_dep_queue_top(stream, session);
}

int
nghttp2_stream_dep_all_your_stream_are_belong_to_us(nghttp2_stream *stream,
                                                    nghttp2_session *session) {
  nghttp2_stream *first, *si;

  DEBUGF(fprintf(stderr, "stream: ALL YOUR STREAM ARE BELONG TO US "
                         "stream(%p)=%d\n",
                 stream, stream->stream_id));

  first = stream->roots->head;

  /* stream must not be include in stream->roots->head list */
  assert(first != stream);

  if (first) {
    nghttp2_stream *prev;

    prev = first;

    DEBUGF(fprintf(stderr, "stream: root stream(%p)=%d\n", first,
                   first->stream_id));

    stream->sum_dep_weight += first->weight;
    stream->num_substreams += first->num_substreams;

    if (stream->dpri != NGHTTP2_STREAM_DPRI_NO_ITEM &&
        (first->dpri == NGHTTP2_STREAM_DPRI_TOP ||
         (first->dpri == NGHTTP2_STREAM_DPRI_NO_ITEM &&
          first->sum_norest_weight))) {
      stream_update_dep_set_rest(first);
    }

    for (si = first->root_next; si; si = si->root_next) {

      assert(si != stream);

      DEBUGF(
          fprintf(stderr, "stream: root stream(%p)=%d\n", si, si->stream_id));

      stream->sum_dep_weight += si->weight;
      stream->num_substreams += si->num_substreams;

      if (stream->dpri != NGHTTP2_STREAM_DPRI_NO_ITEM &&
          (si->dpri == NGHTTP2_STREAM_DPRI_TOP ||
           (si->dpri == NGHTTP2_STREAM_DPRI_NO_ITEM &&
            si->sum_norest_weight))) {
        stream_update_dep_set_rest(si);
      }

      link_sib(prev, si);
      si->dep_prev = stream;

      prev = si;
    }

    if (stream->dep_next) {
      nghttp2_stream *sib_next;

      sib_next = stream->dep_next;

      first->dep_prev = stream;
      link_sib(first, sib_next);
      link_dep(stream, prev);
    } else {
      link_dep(stream, first);
    }
  }

  nghttp2_stream_roots_remove_all(stream->roots);

  return nghttp2_stream_dep_make_root(stream, session);
}

int nghttp2_stream_in_dep_tree(nghttp2_stream *stream) {
  return stream->dep_prev || stream->dep_next || stream->sib_prev ||
         stream->sib_next || stream->root_next || stream->root_prev ||
         stream->roots->head == stream;
}

void nghttp2_stream_roots_init(nghttp2_stream_roots *roots) {
  roots->head = NULL;
  roots->num_streams = 0;
}

void nghttp2_stream_roots_free(nghttp2_stream_roots *roots _U_) {}

void nghttp2_stream_roots_add(nghttp2_stream_roots *roots,
                              nghttp2_stream *stream) {
  if (roots->head) {
    stream->root_next = roots->head;
    roots->head->root_prev = stream;
  }

  roots->head = stream;
}

void nghttp2_stream_roots_remove(nghttp2_stream_roots *roots,
                                 nghttp2_stream *stream) {
  nghttp2_stream *root_prev, *root_next;

  root_prev = stream->root_prev;
  root_next = stream->root_next;

  if (root_prev) {
    root_prev->root_next = root_next;

    if (root_next) {
      root_next->root_prev = root_prev;
    }
  } else {
    if (root_next) {
      root_next->root_prev = NULL;
    }

    roots->head = root_next;
  }

  stream->root_prev = NULL;
  stream->root_next = NULL;
}

void nghttp2_stream_roots_remove_all(nghttp2_stream_roots *roots) {
  nghttp2_stream *si, *next;

  for (si = roots->head; si;) {
    next = si->root_next;

    si->root_prev = NULL;
    si->root_next = NULL;

    si = next;
  }

  roots->head = NULL;
}
