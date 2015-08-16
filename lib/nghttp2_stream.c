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
                         int32_t weight, int32_t remote_initial_window_size,
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
  stream->weight = weight;
  stream->sum_dep_weight = 0;
  stream->sum_norest_weight = 0;

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

typedef enum {
  DFS_NOERROR,
  /* Don't traverse descendants */
  DFS_SKIP_DESCENDANT,
  /* Stop traversal, and return immediately */
  DFS_ABORT
} dfs_error_code;

/* depth first traversal, starting at |stream|.  |precb| is, if non
 * NULL, called against stream before traversing its descendants.
 * |postcb| is, if non NULL, called against stream just after
 * traversing its all descendants.  |data| is arbitrary pointer, which
 * gets passed to |precb| and |postcb|.
 *
 * The application can change dfs behaviour by adjusting return value
 * from |precb|.  Returning DFS_NOERROR will resume traversal.
 * Returning DFS_SKIP_DESCENDANT will skip all traversal for the
 * descendant streams.  Returning DFS_ABORT will immediately return
 * from this function, and dfs returns DFS_ABORT.  Returning any other
 * values will also make this function return immediately, and dfs
 * returns the value |precb| returned.
 */
static int dfs(nghttp2_stream *stream,
               int (*precb)(nghttp2_stream *stream, void *data),
               void (*postcb)(nghttp2_stream *stream, void *data), void *data) {
  int rv;
  nghttp2_stream *start;

  start = stream;

  for (;;) {
    if (precb) {
      rv = precb(stream, data);
      switch (rv) {
      case DFS_NOERROR:
        break;
      case DFS_SKIP_DESCENDANT:
        goto back;
      case DFS_ABORT:
      default:
        return rv;
      }
    }
    if (!stream->dep_next) {
      goto back;
    }
    stream = stream->dep_next;
    continue;

  back:
    for (;;) {
      if (postcb) {
        postcb(stream, data);
      }
      if (stream == start) {
        return 0;
      }
      if (stream->sib_next) {
        stream = stream->sib_next;
        break;
      }
      stream = stream->dep_prev;
    }
  }
}

static nghttp2_stream *stream_last_sib(nghttp2_stream *stream) {
  for (; stream->sib_next; stream = stream->sib_next)
    ;

  return stream;
}

int32_t nghttp2_stream_dep_distributed_weight(nghttp2_stream *stream,
                                              int32_t weight) {
  weight = stream->weight * weight / stream->sum_dep_weight;

  return nghttp2_max(1, weight);
}

static int stream_update_dep_set_rest_precb(nghttp2_stream *stream,
                                            void *data _U_) {
  DEBUGF(fprintf(stderr, "stream: stream=%d is rest\n", stream->stream_id));

  if (stream->dpri == NGHTTP2_STREAM_DPRI_REST) {
    return DFS_SKIP_DESCENDANT;
  }

  if (stream->dpri == NGHTTP2_STREAM_DPRI_TOP) {
    stream->dpri = NGHTTP2_STREAM_DPRI_REST;
    return DFS_SKIP_DESCENDANT;
  }

  return DFS_NOERROR;
}

static void stream_update_dep_set_rest(nghttp2_stream *stream) {
  dfs(stream, stream_update_dep_set_rest_precb, NULL, NULL);
}

static int stream_update_dep_set_top_precb(nghttp2_stream *stream,
                                           void *data _U_) {
  stream->sum_norest_weight = 0;

  if (stream->dpri == NGHTTP2_STREAM_DPRI_TOP) {
    return DFS_SKIP_DESCENDANT;
  }

  if (stream->dpri == NGHTTP2_STREAM_DPRI_REST) {
    DEBUGF(
        fprintf(stderr, "stream: stream=%d item is top\n", stream->stream_id));

    stream->dpri = NGHTTP2_STREAM_DPRI_TOP;

    return DFS_SKIP_DESCENDANT;
  }

  return DFS_NOERROR;
}

static void stream_update_dep_set_top_postcb(nghttp2_stream *stream,
                                             void *data) {
  nghttp2_stream *start;

  start = data;

  if (start == stream) {
    return;
  }

  if (stream->dpri == NGHTTP2_STREAM_DPRI_TOP ||
      (stream->dpri == NGHTTP2_STREAM_DPRI_NO_ITEM &&
       stream->sum_norest_weight > 0)) {
    stream->dep_prev->sum_norest_weight += stream->weight;
  }
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
  dfs(stream, stream_update_dep_set_top_precb, stream_update_dep_set_top_postcb,
      stream);
  return stream->dpri == NGHTTP2_STREAM_DPRI_TOP ||
         (stream->dpri == NGHTTP2_STREAM_DPRI_NO_ITEM &&
          stream->sum_norest_weight > 0);
}

static int stream_update_dep_queue_top_precb(nghttp2_stream *stream,
                                             void *data) {
  int rv;
  nghttp2_session *session;

  session = data;

  if (stream->dpri == NGHTTP2_STREAM_DPRI_REST) {
    return DFS_SKIP_DESCENDANT;
  }

  if (stream->dpri == NGHTTP2_STREAM_DPRI_TOP) {
    if (!stream->item->queued) {
      DEBUGF(fprintf(stderr, "stream: stream=%d enqueue\n", stream->stream_id));
      rv = stream_push_item(stream, session);

      if (rv != 0) {
        return rv;
      }
    }

    return DFS_SKIP_DESCENDANT;
  }

  if (stream->sum_norest_weight == 0) {
    return DFS_SKIP_DESCENDANT;
  }

  return DFS_NOERROR;
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
  return dfs(stream, stream_update_dep_queue_top_precb, NULL, session);
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

  for (;;) {
    if (!stream) {
      return;
    }

    assert(delta != 0);
    assert(stream->sum_norest_weight + delta >= 0);

    old = stream->sum_norest_weight;
    stream->sum_norest_weight += delta;

    if (old == 0) {
      assert(delta > 0);
      delta = stream->weight;
      stream = stream->dep_prev;
      continue;
    }

    assert(old > 0);

    if (stream->sum_norest_weight == 0) {
      delta = -stream->weight;
      stream = stream->dep_prev;
      continue;
    }

    break;
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

#ifdef STREAM_DEP_DEBUG

static void ensure_rest_or_no_item(nghttp2_stream *stream) {
  nghttp2_stream *si;
  switch (stream->dpri) {
  case NGHTTP2_STREAM_DPRI_TOP:
    fprintf(stderr, "NGHTTP2_STREAM_DPRI_TOP; want REST or NO_ITEM\n");
    assert(0);
    break;
  case NGHTTP2_STREAM_DPRI_REST:
  case NGHTTP2_STREAM_DPRI_NO_ITEM:
    for (si = stream->dep_next; si; si = si->sib_next) {
      ensure_rest_or_no_item(si);
    }
    break;
  default:
    fprintf(stderr, "invalid dpri %d\n", stream->dpri);
    assert(0);
  }
}

static void check_dpri(nghttp2_stream *stream) {
  nghttp2_stream *si;
  switch (stream->dpri) {
  case NGHTTP2_STREAM_DPRI_TOP:
    if (!stream->item->queued) {
      fprintf(stderr, "stream->item->queued is not nonzero while it is in "
                      "NGHTTP2_STREAM_DPRI_TOP\n");
      assert(0);
    }
  /* fall through */
  case NGHTTP2_STREAM_DPRI_REST:
    for (si = stream->dep_next; si; si = si->sib_next) {
      ensure_rest_or_no_item(si);
    }
    break;
  case NGHTTP2_STREAM_DPRI_NO_ITEM:
    for (si = stream->dep_next; si; si = si->sib_next) {
      check_dpri(si);
    }
    break;
  default:
    fprintf(stderr, "invalid dpri %d\n", stream->dpri);
    assert(0);
  }
}

static void check_sum_dep(nghttp2_stream *stream) {
  nghttp2_stream *si;
  int32_t n = 0;
  for (si = stream->dep_next; si; si = si->sib_next) {
    n += si->weight;
  }
  if (n != stream->sum_dep_weight) {
    fprintf(stderr, "stream(%p)=%d, sum_dep_weight = %d; want %d\n", stream,
            stream->stream_id, n, stream->sum_dep_weight);
    assert(0);
  }
  for (si = stream->dep_next; si; si = si->sib_next) {
    check_sum_dep(si);
  }
}

static int check_sum_norest(nghttp2_stream *stream) {
  nghttp2_stream *si;
  int32_t n = 0;
  switch (stream->dpri) {
  case NGHTTP2_STREAM_DPRI_TOP:
    return 1;
  case NGHTTP2_STREAM_DPRI_REST:
    return 0;
  case NGHTTP2_STREAM_DPRI_NO_ITEM:
    for (si = stream->dep_next; si; si = si->sib_next) {
      if (check_sum_norest(si)) {
        n += si->weight;
      }
    }
    break;
  default:
    fprintf(stderr, "invalid dpri %d\n", stream->dpri);
    assert(0);
  }
  if (n != stream->sum_norest_weight) {
    fprintf(stderr, "stream(%p)=%d, sum_norest_weight = %d; want %d\n", stream,
            stream->stream_id, n, stream->sum_norest_weight);
    assert(0);
  }
  return n > 0;
}

static void check_dep_prev(nghttp2_stream *stream) {
  nghttp2_stream *si;
  for (si = stream->dep_next; si; si = si->sib_next) {
    if (si->dep_prev != stream) {
      fprintf(stderr, "si->dep_prev = %p; want %p\n", si->dep_prev, stream);
      assert(0);
    }
    check_dep_prev(si);
  }
}

#endif /* STREAM_DEP_DEBUG */

#ifdef STREAM_DEP_DEBUG
static void validate_tree(nghttp2_stream *stream) {
  if (!stream) {
    return;
  }

  for (; stream->dep_prev; stream = stream->dep_prev)
    ;

  check_dpri(stream);
  check_sum_dep(stream);
  check_sum_norest(stream);
  check_dep_prev(stream);
}
#else /* !STREAM_DEP_DEBUG */
static void validate_tree(nghttp2_stream *stream _U_) {}
#endif /* !STREAM_DEP_DEBUG*/

static int stream_update_dep_on_attach_item(nghttp2_stream *stream,
                                            nghttp2_session *session) {
  nghttp2_stream *blocking_stream, *si;
  int rv;

  stream->dpri = NGHTTP2_STREAM_DPRI_REST;

  blocking_stream = stream_get_dep_blocking(stream->dep_prev);

  /* If we found REST or TOP in ascendants, we don't have to update
     any metadata. */
  if (blocking_stream) {
    validate_tree(stream);
    return 0;
  }

  stream->dpri = NGHTTP2_STREAM_DPRI_TOP;
  if (stream->sum_norest_weight == 0) {
    stream_update_dep_sum_norest_weight(stream->dep_prev, stream->weight);
  } else {
    for (si = stream->dep_next; si; si = si->sib_next) {
      stream_update_dep_set_rest(si);
    }
  }

  if (!stream->item->queued) {
    DEBUGF(fprintf(stderr, "stream: stream=%d enqueue\n", stream->stream_id));
    rv = stream_push_item(stream, session);

    if (rv != 0) {
      return rv;
    }
  }

  validate_tree(stream);
  return 0;
}

static int stream_update_dep_on_detach_item(nghttp2_stream *stream,
                                            nghttp2_session *session) {
  int rv;

  if (stream->dpri == NGHTTP2_STREAM_DPRI_REST) {
    stream->dpri = NGHTTP2_STREAM_DPRI_NO_ITEM;
    validate_tree(stream);
    return 0;
  }

  if (stream->dpri == NGHTTP2_STREAM_DPRI_NO_ITEM) {
    /* nghttp2_stream_defer_item() does not clear stream->item, but
       set dpri = NGHTTP2_STREAM_DPRI_NO_ITEM.  Catch this case
       here. */
    validate_tree(stream);
    return 0;
  }

  stream->dpri = NGHTTP2_STREAM_DPRI_NO_ITEM;

  if (stream_update_dep_set_top(stream) == 0) {
    stream_update_dep_sum_norest_weight(stream->dep_prev, -stream->weight);
    validate_tree(stream);
    return 0;
  }

  rv = stream_update_dep_queue_top(stream, session);
  if (rv != 0) {
    return rv;
  }

  validate_tree(stream);

  return 0;
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

static int stream_dep_subtree_find_precb(nghttp2_stream *stream, void *data) {
  nghttp2_stream *target;

  target = data;

  if (target == stream) {
    return DFS_ABORT;
  }

  return DFS_NOERROR;
}

int nghttp2_stream_dep_subtree_find(nghttp2_stream *stream,
                                    nghttp2_stream *target) {
  return dfs(stream, stream_dep_subtree_find_precb, NULL, target) == DFS_ABORT;
}

int32_t nghttp2_stream_compute_effective_weight(nghttp2_stream *stream) {
  int32_t weight;

  assert(stream->dep_prev);

  weight = stream->weight * 100;

  for (;;) {
    stream = stream->dep_prev;
    /* Not consider weight of root; it could make weight too small */
    if (!stream || !stream->dep_prev) {
      break;
    }
    weight = stream->weight * weight / stream->sum_norest_weight;
  }

  return nghttp2_max(1, weight / 100);
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

  validate_tree(stream);
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

  dep_stream->sum_dep_weight += stream->weight;

  if (dep_stream->dep_next == NULL) {
    link_dep(dep_stream, stream);
  } else {
    insert_link_dep(dep_stream, stream);
  }

  validate_tree(stream);
}

void nghttp2_stream_dep_remove(nghttp2_stream *stream) {
  nghttp2_stream *dep_prev, *si, *blocking_stream;
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

  assert(stream->dep_prev);

  dep_prev = stream->dep_prev;

  dep_prev->sum_dep_weight += sum_dep_weight_delta;
  dep_prev->sum_norest_weight += sum_norest_weight_delta;

  if (stream->sib_prev) {
    unlink_sib(stream);
  } else {
    unlink_dep(stream);
  }

  stream->sum_dep_weight = 0;
  stream->sum_norest_weight = 0;

  stream->dep_prev = NULL;
  stream->dep_next = NULL;
  stream->sib_prev = NULL;
  stream->sib_next = NULL;

  validate_tree(dep_prev);
}

int nghttp2_stream_dep_insert_subtree(nghttp2_stream *dep_stream,
                                      nghttp2_stream *stream,
                                      nghttp2_session *session) {
  nghttp2_stream *last_sib;
  nghttp2_stream *dep_next;
  nghttp2_stream *blocking_stream;
  nghttp2_stream *si;
  int rv;

  DEBUGF(fprintf(stderr, "stream: dep_insert_subtree dep_stream(%p)=%d "
                         "stream(%p)=%d\n",
                 dep_stream, dep_stream->stream_id, stream, stream->stream_id));

  blocking_stream = stream_get_dep_blocking(dep_stream);

  if (blocking_stream) {
    stream_update_dep_set_rest(stream);
  }

  if (dep_stream->dep_next) {
    stream->sum_dep_weight += dep_stream->sum_dep_weight;
    dep_stream->sum_dep_weight = stream->weight;

    dep_next = dep_stream->dep_next;

    if (!blocking_stream && dep_stream->sum_norest_weight) {
      for (si = dep_next; si; si = si->sib_next) {
        stream_update_dep_set_rest(si);
      }
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

  if (blocking_stream) {
    validate_tree(dep_stream);
    return 0;
  }

  if (stream_update_dep_set_top(stream) == 0) {
    validate_tree(dep_stream);
    return 0;
  }

  /* If dep_stream has stream whose dpri is NGHTTP2_DPRI_TOP in its
     subtree, parent stream already accounted dep_stream->weight in
     its sum_norest_weight */
  if (dep_stream->sum_norest_weight == 0) {
    stream_update_dep_sum_norest_weight(dep_stream->dep_prev,
                                        dep_stream->weight);
  }
  dep_stream->sum_norest_weight = stream->weight;

  rv = stream_update_dep_queue_top(stream, session);
  if (rv != 0) {
    return rv;
  }

  validate_tree(dep_stream);

  return 0;
}

int nghttp2_stream_dep_add_subtree(nghttp2_stream *dep_stream,
                                   nghttp2_stream *stream,
                                   nghttp2_session *session) {
  nghttp2_stream *blocking_stream;
  int rv;

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

  blocking_stream = stream_get_dep_blocking(dep_stream);

  if (blocking_stream) {
    /* We cannot make any assumption for stream if its dpri is not
       NGHTTP2_DPRI_TOP.  Just dfs under stream here. */
    stream_update_dep_set_rest(stream);

    validate_tree(dep_stream);
    return 0;
  }

  if (stream->dpri == NGHTTP2_STREAM_DPRI_TOP) {
    stream_update_dep_sum_norest_weight(dep_stream, stream->weight);
    validate_tree(dep_stream);
    return 0;
  }

  if (stream_update_dep_set_top(stream) == 0) {
    validate_tree(dep_stream);
    return 0;
  }

  /* Newly added subtree contributes to dep_stream's
     sum_norest_weight */
  stream_update_dep_sum_norest_weight(dep_stream, stream->weight);

  rv = stream_update_dep_queue_top(stream, session);
  if (rv != 0) {
    return rv;
  }

  validate_tree(dep_stream);

  return 0;
}

void nghttp2_stream_dep_remove_subtree(nghttp2_stream *stream) {
  nghttp2_stream *next, *dep_prev, *blocking_stream;

  DEBUGF(fprintf(stderr, "stream: dep_remove_subtree stream(%p)=%d\n", stream,
                 stream->stream_id));

  assert(stream->dep_prev);

  dep_prev = stream->dep_prev;

  if (stream->sib_prev) {
    link_sib(stream->sib_prev, stream->sib_next);
  } else {
    next = stream->sib_next;

    link_dep(dep_prev, next);

    if (next) {
      next->sib_prev = NULL;
    }
  }

  dep_prev->sum_dep_weight -= stream->weight;

  blocking_stream = stream_get_dep_blocking(dep_prev);

  if (!blocking_stream && (stream->dpri == NGHTTP2_STREAM_DPRI_TOP ||
                           (stream->dpri == NGHTTP2_STREAM_DPRI_NO_ITEM &&
                            stream->sum_norest_weight))) {
    stream_update_dep_sum_norest_weight(dep_prev, -stream->weight);
  }

  validate_tree(dep_prev);

  stream->sib_prev = NULL;
  stream->sib_next = NULL;
  stream->dep_prev = NULL;
}

int nghttp2_stream_in_dep_tree(nghttp2_stream *stream) {
  return stream->dep_prev || stream->dep_next || stream->sib_prev ||
         stream->sib_next;
}
