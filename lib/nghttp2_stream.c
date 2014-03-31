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
  stream->data = NULL;
  stream->deferred_data = NULL;
  stream->deferred_flags = NGHTTP2_DEFERRED_NONE;
  stream->remote_window_size = remote_initial_window_size;
  stream->local_window_size = local_initial_window_size;
  stream->recv_window_size = 0;
  stream->recv_reduction = 0;

  stream->dep_prev = NULL;
  stream->dep_next = NULL;
  stream->sib_prev = NULL;
  stream->sib_next = NULL;

  stream->closed_next = NULL;

  stream->stream_group = NULL;
  stream->dpri = NGHTTP2_STREAM_DPRI_NO_DATA;
  stream->num_substreams = 1;
  stream->num_subtop = 0;
}

void nghttp2_stream_free(nghttp2_stream *stream)
{
  nghttp2_outbound_item_free(stream->deferred_data);
  free(stream->deferred_data);

  /* We don't free stream->data. */
}

void nghttp2_stream_shutdown(nghttp2_stream *stream, nghttp2_shut_flag flag)
{
  stream->shut_flags |= flag;
}

static int stream_push_data(nghttp2_stream *stream, nghttp2_pq *pq)
{
  int rv;
  ssize_t weight;

  assert(stream->data);
  assert(stream->data->queued == 0);

  weight = nghttp2_stream_group_shared_wait(stream->stream_group);

  if(stream->data->weight > weight) {
    stream->data->weight = weight;
  }

  rv = nghttp2_pq_push(pq, stream->data);

  if(rv != 0) {
    return rv;
  }

  stream->data->queued = 1;

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

static nghttp2_stream* stream_update_dep_both_length(nghttp2_stream *stream,
                                                     ssize_t delta_stream,
                                                     ssize_t delta_top)
{
  stream->num_substreams += delta_stream;
  stream->num_subtop += delta_top;

  stream = stream_first_sib(stream);

  if(stream->dep_prev) {
    return stream_update_dep_both_length(stream->dep_prev, delta_stream,
                                         delta_top);
  }

  return stream;
}

static void stream_update_dep_set_rest_stream_group
(nghttp2_stream *stream, nghttp2_stream_group *stream_group)
{
  if(stream == NULL) {
    return;
  }

  nghttp2_stream_group_remove_stream(stream->stream_group, stream);
  nghttp2_stream_group_add_stream(stream_group, stream);

  if(stream->dpri == NGHTTP2_STREAM_DPRI_TOP) {
    stream->dpri = NGHTTP2_STREAM_DPRI_REST;
  }

  stream_update_dep_set_rest_stream_group(stream->sib_next, stream_group);
  stream_update_dep_set_rest_stream_group(stream->dep_next, stream_group);
}

static void stream_update_dep_set_rest(nghttp2_stream *stream)
{
  if(stream == NULL) {
    return;
  }

  if(stream->dpri == NGHTTP2_STREAM_DPRI_REST) {
    return;
  }

  stream->num_subtop = 0;

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
 * NGHTTP2_STREAM_DPRI_TOP and queues its data.
 *
 * This function returns the number of stream marked as
 * NGHTTP2_STREAM_DPRI_TOP (including already marked as such) if it
 * succeeds, or one of the following negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
static ssize_t stream_update_dep_set_top(nghttp2_stream *stream,
                                         nghttp2_pq *pq)
{
  ssize_t rv;
  ssize_t num_top;

  if(stream == NULL) {
    return 0;
  }

  if(stream->dpri == NGHTTP2_STREAM_DPRI_TOP) {
    rv = stream_update_dep_set_top(stream->sib_next, pq);

    if(rv < 0) {
      return rv;
    }

    stream->num_subtop = 1;

    return stream->num_subtop + rv;
  }

  if(stream->dpri == NGHTTP2_STREAM_DPRI_REST) {

    DEBUGF(fprintf(stderr, "stream: stream=%d data is top\n",
                   stream->stream_id));

    if(!stream->data->queued) {
      rv = stream_push_data(stream, pq);

      if(rv != 0) {
        return rv;
      }
    }

    stream->dpri = NGHTTP2_STREAM_DPRI_TOP;

    rv = stream_update_dep_set_top(stream->sib_next, pq);

    if(rv < 0) {
      return rv;
    }

    stream->num_subtop = 1;

    return stream->num_subtop + rv;
  }

  assert(stream->dpri == NGHTTP2_STREAM_DPRI_NO_DATA);

  rv = stream_update_dep_set_top(stream->sib_next, pq);

  if(rv < 0) {
    return rv;
  }

  num_top = rv;

  rv = stream_update_dep_set_top(stream->dep_next, pq);

  if(rv < 0) {
    return rv;
  }

  stream->num_subtop = rv;

  return stream->num_subtop + num_top;
}

static ssize_t stream_update_dep_on_attach_data(nghttp2_stream *stream,
                                                nghttp2_pq *pq)
{
  ssize_t rv;
  nghttp2_stream *root_stream;
  ssize_t old_num_subtop;

  stream->dpri = NGHTTP2_STREAM_DPRI_REST;

  stream_update_dep_set_rest(stream->dep_next);

  root_stream = nghttp2_stream_get_dep_root(stream);

  DEBUGF(fprintf(stderr, "root=%p, stream=%p\n", root_stream, stream));

  old_num_subtop = root_stream->num_subtop;

  rv = stream_update_dep_set_top(root_stream, pq);

  if(rv < 0) {
    return rv;
  }

  nghttp2_stream_group_update_num_top
    (root_stream->stream_group, root_stream->num_subtop - old_num_subtop);

  return 0;
}

static int stream_update_dep_on_detach_data(nghttp2_stream *stream,
                                            nghttp2_pq *pq)
{
  ssize_t rv;
  nghttp2_stream *root_stream;
  ssize_t old_num_subtop;

  if(stream->dpri != NGHTTP2_STREAM_DPRI_TOP) {
    stream->dpri = NGHTTP2_STREAM_DPRI_NO_DATA;

    return 0;
  }

  stream->dpri = NGHTTP2_STREAM_DPRI_NO_DATA;

  root_stream = nghttp2_stream_get_dep_root(stream);

  old_num_subtop = root_stream->num_subtop;

  rv = stream_update_dep_set_top(root_stream, pq);

  if(rv < 0) {
    return rv;
  }

  nghttp2_stream_group_update_num_top
    (root_stream->stream_group, root_stream->num_subtop - old_num_subtop);

  return 0;
}

int nghttp2_stream_attach_data(nghttp2_stream *stream,
                               nghttp2_outbound_item *data,
                               nghttp2_pq *pq)
{
  assert(stream->data == NULL);
  assert(stream->deferred_data == NULL);

  stream->data = data;

  DEBUGF(fprintf(stderr, "stream: stream=%d attach data=%p\n",
                 stream->stream_id, data));

  return stream_update_dep_on_attach_data(stream, pq);
}

int nghttp2_stream_detach_data(nghttp2_stream *stream, nghttp2_pq *pq)
{
  DEBUGF(fprintf(stderr, "stream: stream=%d detach data=%p\n",
                 stream->stream_id, stream->data));

  stream->data = NULL;

  return stream_update_dep_on_detach_data(stream, pq);
}

void nghttp2_stream_defer_data(nghttp2_stream *stream,
                               nghttp2_outbound_item *data,
                               uint8_t flags)
{
  assert(stream->data);
  assert(stream->data == data);
  assert(stream->deferred_data == NULL);

  stream->deferred_data = data;
  stream->deferred_flags = flags;

  stream->data = NULL;
}

int nghttp2_stream_detach_deferred_data(nghttp2_stream *stream,
                                        nghttp2_pq *pq)
{
  nghttp2_outbound_item *data;
  assert(stream->data == NULL);
  assert(stream->deferred_data);

  data = stream->deferred_data;

  stream->deferred_data = NULL;
  stream->deferred_flags = NGHTTP2_DEFERRED_NONE;

  return nghttp2_stream_attach_data(stream, data, pq);
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
  *window_size_ptr = new_window_size;
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

  assert(stream->data == NULL);

  DEBUGF(fprintf(stderr,
                 "stream: dep_insert dep_stream(%p)=%d, stream(%p)=%d\n",
                 dep_stream, dep_stream->stream_id,
                 stream, stream->stream_id));

  if(dep_stream->dep_next) {
    for(si = dep_stream->dep_next; si; si = si->sib_next) {
      stream->num_substreams += si->num_substreams;
    }

    stream->dep_next = dep_stream->dep_next;
    stream->dep_next->dep_prev = stream;
  }

  dep_stream->dep_next = stream;
  stream->dep_prev = dep_stream;

  stream_update_dep_length(dep_stream, 1);
}

void nghttp2_stream_dep_add(nghttp2_stream *dep_stream,
                            nghttp2_stream *stream)
{
  nghttp2_stream *last_sib;

  assert(stream->data == NULL);

  DEBUGF(fprintf(stderr,
                 "stream: dep_add dep_stream(%p)=%d, stream(%p)=%d\n",
                 dep_stream, dep_stream->stream_id,
                 stream, stream->stream_id));

  stream_update_dep_length(dep_stream, 1);

  if(dep_stream->dep_next == NULL) {
    dep_stream->dep_next = stream;
    stream->dep_prev = dep_stream;

    return;
  }

  last_sib = stream_last_sib(dep_stream->dep_next);
  last_sib->sib_next = stream;
  stream->sib_prev = last_sib;
}

void nghttp2_stream_dep_remove(nghttp2_stream *stream)
{
  nghttp2_stream *prev, *next, *dep_next;

  DEBUGF(fprintf(stderr, "stream: dep_remove stream(%p)=%d\n",
                 stream, stream->stream_id));

  prev = stream_first_sib(stream);

  if(prev->dep_prev) {
    stream_update_dep_length(prev->dep_prev, -1);
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
    nghttp2_stream *si;

    dep_next = NULL;

    /* stream is a root of tree.  Removing stream makes its
       descendants a root of its own subtree. */

    for(si = stream->dep_next; si;) {
      next = si->sib_next;

      si->dep_prev = NULL;
      si->sib_prev = NULL;
      si->sib_next = NULL;

      si = next;
    }
  }

  if(dep_next && stream->sib_next) {
    prev = stream_last_sib(dep_next);
    next = stream->sib_next;

    prev->sib_next = next;
    next->sib_prev = prev;
  }

  stream->num_substreams = 1;
  stream->dep_prev = NULL;
  stream->dep_next = NULL;
  stream->sib_prev = NULL;
  stream->sib_next = NULL;
}

int nghttp2_stream_dep_insert_subtree(nghttp2_stream *dep_stream,
                                      nghttp2_stream *stream,
                                      nghttp2_pq *pq)
{
  nghttp2_stream *last_sib;
  nghttp2_stream *dep_next;
  nghttp2_stream *root_stream;
  nghttp2_stream *si;
  size_t delta_substreams;
  ssize_t old_num_subtop;
  ssize_t rv;

  DEBUGF(fprintf(stderr, "stream: dep_insert_subtree dep_stream(%p)=%d "
                 "stream(%p)=%d\n",
                 dep_stream, dep_stream->stream_id,
                 stream, stream->stream_id));

  delta_substreams = stream->num_substreams;

  nghttp2_stream_group_update_num_top
    (stream->stream_group, -stream->num_subtop);

  stream_update_dep_set_rest_stream_group(stream, dep_stream->stream_group);

  if(dep_stream->dep_next) {
    dep_next = dep_stream->dep_next;

    for(si = dep_stream->dep_next; si; si = si->sib_next) {
      stream->num_substreams += si->num_substreams;
    }

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
  }

  root_stream = stream_update_dep_length(dep_stream, delta_substreams);

  old_num_subtop = root_stream->num_subtop;

  rv = stream_update_dep_set_top(root_stream, pq);

  if(rv < 0) {
    return rv;
  }

  nghttp2_stream_group_update_num_top
    (root_stream->stream_group, root_stream->num_subtop - old_num_subtop);

  return 0;
}

int nghttp2_stream_dep_add_subtree(nghttp2_stream *dep_stream,
                                   nghttp2_stream *stream,
                                   nghttp2_pq *pq)
{
  nghttp2_stream *last_sib;
  nghttp2_stream *root_stream;
  ssize_t old_num_subtop;
  ssize_t rv;

  DEBUGF(fprintf(stderr, "stream: dep_add_subtree dep_stream(%p)=%d "
                 "stream(%p)=%d\n",
                 dep_stream, dep_stream->stream_id,
                 stream, stream->stream_id));

  nghttp2_stream_group_update_num_top
    (stream->stream_group, -stream->num_subtop);

  stream_update_dep_set_rest_stream_group(stream, dep_stream->stream_group);

  if(dep_stream->dep_next) {
    last_sib = stream_last_sib(dep_stream->dep_next);

    last_sib->sib_next = stream;
    stream->sib_prev = last_sib;
  } else {
    dep_stream->dep_next = stream;
    stream->dep_prev = dep_stream;
  }

  root_stream = stream_update_dep_length(dep_stream, stream->num_substreams);

  old_num_subtop = root_stream->num_subtop;

  rv = stream_update_dep_set_top(root_stream, pq);

  if(rv < 0) {
    return rv;
  }

  nghttp2_stream_group_update_num_top
    (root_stream->stream_group, root_stream->num_subtop - old_num_subtop);

  return 0;
}

void nghttp2_stream_dep_remove_subtree(nghttp2_stream *stream)
{
  nghttp2_stream *prev, *next;

  DEBUGF(fprintf(stderr, "stream: dep_remove_subtree stream(%p)=%d\n",
                 stream, stream->stream_id));

  /* Removing subtree does not change stream_group->num_top */

  if(stream->sib_prev) {
    prev = stream->sib_prev;

    prev->sib_next = stream->sib_next;
    if(prev->sib_next) {
      prev->sib_next->sib_prev = prev;
    }

    prev = stream_first_sib(prev);
    if(prev->dep_prev) {
      stream_update_dep_both_length(prev->dep_prev, -stream->num_substreams,
                                    -stream->num_subtop);
    }
  } else if(stream->dep_prev) {
    prev = stream->dep_prev;
    next = stream->sib_next;

    prev->dep_next = next;

    if(next) {
      next->dep_prev = prev;

      next->sib_prev = NULL;
    }

    stream_update_dep_both_length(prev, -stream->num_substreams,
                                  -stream->num_subtop);
  }

  stream->sib_prev = NULL;
  stream->sib_next = NULL;
  stream->dep_prev = NULL;
}

int nghttp2_stream_dep_make_root(nghttp2_stream_group *stream_group,
                                 nghttp2_stream *stream,
                                 nghttp2_pq *pq)
{
  ssize_t rv;

  DEBUGF(fprintf(stderr, "stream: dep_make_root new_stream_group(%p)=%d, "
                 "old_stream_group(%p)=%d, stream(%p)=%d\n",
                 stream_group, stream_group->pri_group_id,
                 stream->stream_group, stream->stream_group->pri_group_id,
                 stream, stream->stream_id));

  /* First update num_top of old stream_group */
  nghttp2_stream_group_update_num_top
    (stream->stream_group, -stream->num_subtop);

  stream_update_dep_set_rest_stream_group(stream, stream_group);

  rv = stream_update_dep_set_top(stream, pq);

  if(rv < 0) {
    return rv;
  }

  nghttp2_stream_group_update_num_top(stream_group, stream->num_subtop);

  return 0;
}

void nghttp2_stream_group_init(nghttp2_stream_group *stream_group,
                               int32_t pri_group_id,
                               int32_t weight)
{
  nghttp2_map_entry_init(&stream_group->map_entry, pri_group_id);

  stream_group->num_streams = 0;
  stream_group->num_top = 0;
  stream_group->pri_group_id = pri_group_id;
  stream_group->weight = weight;
}

void nghttp2_stream_group_free(nghttp2_stream_group *stream_group)
{}

void nghttp2_stream_group_add_stream(nghttp2_stream_group *stream_group,
                                     nghttp2_stream *stream)
{
  DEBUGF(fprintf(stderr, "stream_group: stream_group(%p)=%d "
                 "add stream(%p)=%d\n",
                 stream_group, stream_group->pri_group_id,
                 stream, stream->stream_id));

  stream->stream_group = stream_group;

  ++stream_group->num_streams;
}

void nghttp2_stream_group_remove_stream(nghttp2_stream_group *stream_group,
                                        nghttp2_stream *stream)
{
  DEBUGF(fprintf(stderr, "stream_group: stream_group(%p)=%d "
                 "remove stream(%p)=%d\n",
                 stream_group, stream_group->pri_group_id,
                 stream, stream->stream_id));

  stream->stream_group = NULL;

  --stream_group->num_streams;
}

void nghttp2_stream_group_update_num_top(nghttp2_stream_group *stream_group,
                                         ssize_t delta)
{
  DEBUGF(fprintf(stderr, "stream_group: stream_group(%p)=%d "
                 "update num_top current=%zd, delta=%zd, after=%zd\n",
                 stream_group->num_top, delta, stream_group->num_top + delta));

  stream_group->num_top += delta;

  assert(stream_group->num_top >= 0);
}

size_t nghttp2_stream_group_shared_wait(nghttp2_stream_group *stream_group)
{
  if(stream_group->num_top == 0) {
    return 1;
  }

  return nghttp2_max(1, stream_group->weight / stream_group->num_top);
}
