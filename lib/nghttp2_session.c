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
#include "nghttp2_session.h"

#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>

#include "nghttp2_helper.h"
#include "nghttp2_net.h"
#include "nghttp2_priority_spec.h"
#include "nghttp2_option.h"

/*
 * Returns non-zero if the number of outgoing opened streams is larger
 * than or equal to
 * remote_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS].
 */
static int nghttp2_session_is_outgoing_concurrent_streams_max
(nghttp2_session *session)
{
  return session->remote_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS]
    <= session->num_outgoing_streams;
}

/*
 * Returns non-zero if the number of incoming opened streams is larger
 * than or equal to
 * local_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS].
 */
static int nghttp2_session_is_incoming_concurrent_streams_max
(nghttp2_session *session)
{
  return session->local_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS]
    <= session->num_incoming_streams;
}

/*
 * Returns non-zero if the number of incoming opened streams is larger
 * than or equal to
 * session->pending_local_max_concurrent_stream.
 */
static int nghttp2_session_is_incoming_concurrent_streams_pending_max
(nghttp2_session *session)
{
  return session->pending_local_max_concurrent_stream
    <= session->num_incoming_streams;
}

/*
 * Returns non-zero if |lib_error| is non-fatal error.
 */
static int nghttp2_is_non_fatal(int lib_error)
{
  return lib_error < 0 && lib_error > NGHTTP2_ERR_FATAL;
}

int nghttp2_is_fatal(int lib_error)
{
  return lib_error < NGHTTP2_ERR_FATAL;
}

/* Returns nonzero if the |stream| is in reserved(remote) state */
static int state_reserved_remote(nghttp2_session *session,
                                 nghttp2_stream *stream)
{
  return stream->state == NGHTTP2_STREAM_RESERVED &&
    !nghttp2_session_is_my_stream_id(session, stream->stream_id);
}

/* Returns nonzero if the |stream| is in reserved(local) state */
static int state_reserved_local(nghttp2_session *session,
                                nghttp2_stream *stream)
{
  return stream->state == NGHTTP2_STREAM_RESERVED &&
    nghttp2_session_is_my_stream_id(session, stream->stream_id);
}

int nghttp2_session_terminate_session(nghttp2_session *session,
                                      nghttp2_error_code error_code)
{
  if(session->goaway_flags & NGHTTP2_GOAWAY_FAIL_ON_SEND) {
    return 0;
  }
  session->goaway_flags |= NGHTTP2_GOAWAY_FAIL_ON_SEND;
  if(session->goaway_flags & NGHTTP2_GOAWAY_SEND) {
    return 0;
  }
  return nghttp2_submit_goaway(session, NGHTTP2_FLAG_NONE, error_code,
                               NULL, 0);
}

int nghttp2_session_is_my_stream_id(nghttp2_session *session,
                                    int32_t stream_id)
{
  int rem;
  if(stream_id == 0) {
    return 0;
  }
  rem = stream_id & 0x1;
  if(session->server) {
    return rem == 0;
  }
  return rem == 1;
}

nghttp2_stream* nghttp2_session_get_stream(nghttp2_session *session,
                                           int32_t stream_id)
{
  nghttp2_stream *stream;

  stream = (nghttp2_stream*)nghttp2_map_find(&session->streams, stream_id);

  if(stream == NULL || (stream->flags & NGHTTP2_STREAM_FLAG_CLOSED)) {
    return NULL;
  }

  return stream;
}

nghttp2_stream* nghttp2_session_get_stream_raw(nghttp2_session *session,
                                               int32_t stream_id)
{
  return (nghttp2_stream*)nghttp2_map_find(&session->streams, stream_id);
}

static int nghttp2_outbound_item_compar(const void *lhsx, const void *rhsx)
{
  const nghttp2_outbound_item *lhs, *rhs;

  lhs = (const nghttp2_outbound_item*)lhsx;
  rhs = (const nghttp2_outbound_item*)rhsx;

  if(lhs->weight == rhs->weight) {
    return (lhs->seq < rhs->seq) ? -1 : ((lhs->seq > rhs->seq) ? 1 : 0);
  }

  /* Larger weight has higher precedence */
  return rhs->weight - lhs->weight;
}

static void nghttp2_inbound_frame_reset(nghttp2_session *session)
{
  nghttp2_inbound_frame *iframe = &session->iframe;
  /* A bit risky code, since if this function is called from
     nghttp2_session_new(), we rely on the fact that
     iframe->frame.hd.type is 0, so that no free is performed. */
  switch(iframe->frame.hd.type) {
  case NGHTTP2_HEADERS:
    nghttp2_frame_headers_free(&iframe->frame.headers);
    break;
  case NGHTTP2_PRIORITY:
    nghttp2_frame_priority_free(&iframe->frame.priority);
    break;
  case NGHTTP2_RST_STREAM:
    nghttp2_frame_rst_stream_free(&iframe->frame.rst_stream);
    break;
  case NGHTTP2_SETTINGS:
    nghttp2_frame_settings_free(&iframe->frame.settings);
    break;
  case NGHTTP2_PUSH_PROMISE:
    nghttp2_frame_push_promise_free(&iframe->frame.push_promise);
    break;
  case NGHTTP2_PING:
    nghttp2_frame_ping_free(&iframe->frame.ping);
    break;
  case NGHTTP2_GOAWAY:
    nghttp2_frame_goaway_free(&iframe->frame.goaway);
    break;
  case NGHTTP2_WINDOW_UPDATE:
    nghttp2_frame_window_update_free(&iframe->frame.window_update);
    break;
  case NGHTTP2_ALTSVC:
    nghttp2_frame_altsvc_free(&iframe->frame.altsvc);
    break;
  case NGHTTP2_BLOCKED:
    nghttp2_frame_blocked_free(&iframe->frame.blocked);
    break;
  }
  memset(&iframe->frame, 0, sizeof(nghttp2_frame));

  iframe->state = NGHTTP2_IB_READ_HEAD;

  nghttp2_buf_wrap_init(&iframe->sbuf, iframe->raw_sbuf,
                        sizeof(iframe->raw_sbuf));
  iframe->sbuf.mark += NGHTTP2_FRAME_HDLEN;

  nghttp2_buf_free(&iframe->lbuf);
  nghttp2_buf_wrap_init(&iframe->lbuf, NULL, 0);

  iframe->niv = 0;
  iframe->payloadleft = 0;
  iframe->padlen = 0;
}

static void init_settings(uint32_t *settings)
{
  settings[NGHTTP2_SETTINGS_HEADER_TABLE_SIZE] =
    NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE;
  settings[NGHTTP2_SETTINGS_ENABLE_PUSH] = 1;
  settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS] =
    NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS;
  settings[NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE] =
    NGHTTP2_INITIAL_WINDOW_SIZE;
  settings[NGHTTP2_SETTINGS_COMPRESS_DATA] = 0;
}

static void nghttp2_active_outbound_item_reset
(nghttp2_active_outbound_item *aob)
{
  DEBUGF(fprintf(stderr, "send: reset nghttp2_active_outbound_item\n"));
  DEBUGF(fprintf(stderr, "send: aob->item = %p\n", aob->item));
  nghttp2_outbound_item_free(aob->item);
  free(aob->item);
  aob->item = NULL;
  nghttp2_bufs_reset(&aob->framebufs);
  aob->state = NGHTTP2_OB_POP_ITEM;
}

typedef struct {
  nghttp2_session *session;
  int rv;
} header_cb_arg;

static int nghttp2_session_new(nghttp2_session **session_ptr,
                               const nghttp2_session_callbacks *callbacks,
                               void *user_data,
                               int server,
                               const nghttp2_option *option)
{
  int rv;

  *session_ptr = calloc(1, sizeof(nghttp2_session));
  if(*session_ptr == NULL) {
    rv = NGHTTP2_ERR_NOMEM;
    goto fail_session;
  }

  /* next_stream_id is initialized in either
     nghttp2_session_client_new2 or nghttp2_session_server_new2 */

  rv = nghttp2_pq_init(&(*session_ptr)->ob_pq, nghttp2_outbound_item_compar);
  if(rv != 0) {
    goto fail_ob_pq;
  }
  rv = nghttp2_pq_init(&(*session_ptr)->ob_ss_pq, nghttp2_outbound_item_compar);
  if(rv != 0) {
    goto fail_ob_ss_pq;
  }

  rv = nghttp2_hd_deflate_init(&(*session_ptr)->hd_deflater);
  if(rv != 0) {
    goto fail_hd_deflater;
  }
  rv = nghttp2_hd_inflate_init(&(*session_ptr)->hd_inflater);
  if(rv != 0) {
    goto fail_hd_inflater;
  }
  rv = nghttp2_map_init(&(*session_ptr)->streams);
  if(rv != 0) {
    goto fail_map;
  }

  nghttp2_stream_roots_init(&(*session_ptr)->roots);

  (*session_ptr)->next_seq = 0;

  (*session_ptr)->remote_window_size = NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE;
  (*session_ptr)->recv_window_size = 0;
  (*session_ptr)->recv_reduction = 0;
  (*session_ptr)->local_window_size = NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE;

  (*session_ptr)->goaway_flags = NGHTTP2_GOAWAY_NONE;
  (*session_ptr)->last_stream_id = 0;

  (*session_ptr)->inflight_niv = -1;

  (*session_ptr)->pending_local_max_concurrent_stream =
    NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS;

  if(server) {
    (*session_ptr)->server = 1;
  }

  /* 2 for PAD_HIGH and PAD_LOW. */
  rv = nghttp2_bufs_init3(&(*session_ptr)->aob.framebufs,
                          NGHTTP2_FRAMEBUF_CHUNKLEN, 8, 1,
                          NGHTTP2_FRAME_HDLEN + 2);
  if(rv != 0) {
    goto fail_aob_framebuf;
  }

  nghttp2_active_outbound_item_reset(&(*session_ptr)->aob);

  init_settings((*session_ptr)->remote_settings);
  init_settings((*session_ptr)->local_settings);


  if(option) {
    if((option->opt_set_mask & NGHTTP2_OPT_NO_AUTO_STREAM_WINDOW_UPDATE) &&
       option->no_auto_stream_window_update) {

      (*session_ptr)->opt_flags |=
        NGHTTP2_OPTMASK_NO_AUTO_STREAM_WINDOW_UPDATE;

    }

    if((option->opt_set_mask & NGHTTP2_OPT_NO_AUTO_CONNECTION_WINDOW_UPDATE) &&
       option->no_auto_connection_window_update) {

      (*session_ptr)->opt_flags |=
        NGHTTP2_OPTMASK_NO_AUTO_CONNECTION_WINDOW_UPDATE;

    }

    if(option->opt_set_mask & NGHTTP2_OPT_PEER_MAX_CONCURRENT_STREAMS) {

      (*session_ptr)->
        remote_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS] =
        option->peer_max_concurrent_streams;

    }
  }

  (*session_ptr)->callbacks = *callbacks;
  (*session_ptr)->user_data = user_data;

  nghttp2_inbound_frame_reset(*session_ptr);

  return 0;

 fail_aob_framebuf:
  nghttp2_map_free(&(*session_ptr)->streams);
 fail_map:
  nghttp2_hd_inflate_free(&(*session_ptr)->hd_inflater);
 fail_hd_inflater:
  nghttp2_hd_deflate_free(&(*session_ptr)->hd_deflater);
 fail_hd_deflater:
  nghttp2_pq_free(&(*session_ptr)->ob_ss_pq);
 fail_ob_ss_pq:
  nghttp2_pq_free(&(*session_ptr)->ob_pq);
 fail_ob_pq:
  free(*session_ptr);
 fail_session:
  return rv;
}

int nghttp2_session_client_new(nghttp2_session **session_ptr,
                               const nghttp2_session_callbacks *callbacks,
                               void *user_data)
{
  return nghttp2_session_client_new2(session_ptr, callbacks, user_data, NULL);
}

int nghttp2_session_client_new2(nghttp2_session **session_ptr,
                                const nghttp2_session_callbacks *callbacks,
                                void *user_data,
                                const nghttp2_option *option)
{
  int rv;
  /* For client side session, header compression is disabled. */
  rv = nghttp2_session_new(session_ptr, callbacks, user_data, 0, option);

  if(rv != 0) {
    return rv;
  }
  /* IDs for use in client */
  (*session_ptr)->next_stream_id = 1;
  return 0;
}

int nghttp2_session_server_new(nghttp2_session **session_ptr,
                               const nghttp2_session_callbacks *callbacks,
                               void *user_data)
{
  return nghttp2_session_server_new2(session_ptr, callbacks, user_data, NULL);
}

int nghttp2_session_server_new2(nghttp2_session **session_ptr,
                                const nghttp2_session_callbacks *callbacks,
                                void *user_data,
                                const nghttp2_option *option)
{
  int rv;
  /* Enable header compression on server side. */
  rv = nghttp2_session_new(session_ptr, callbacks, user_data, 1, option);

  if(rv != 0) {
    return rv;
  }
  /* IDs for use in client */
  (*session_ptr)->next_stream_id = 2;
  return 0;
}

static int nghttp2_free_streams(nghttp2_map_entry *entry, void *ptr)
{
  nghttp2_stream_free((nghttp2_stream*)entry);
  free(entry);

  return 0;
}

static void nghttp2_session_ob_pq_free(nghttp2_pq *pq)
{
  while(!nghttp2_pq_empty(pq)) {
    nghttp2_outbound_item *item = (nghttp2_outbound_item*)nghttp2_pq_top(pq);
    nghttp2_outbound_item_free(item);
    free(item);
    nghttp2_pq_pop(pq);
  }
  nghttp2_pq_free(pq);
}

void nghttp2_session_del(nghttp2_session *session)
{
  if(session == NULL) {
    return;
  }
  free(session->inflight_iv);

  nghttp2_stream_roots_free(&session->roots);

  /* Have to free streams first, so that we can check
     stream->data_item->queued */
  nghttp2_map_each_free(&session->streams, nghttp2_free_streams, NULL);
  nghttp2_map_free(&session->streams);

  nghttp2_session_ob_pq_free(&session->ob_pq);
  nghttp2_session_ob_pq_free(&session->ob_ss_pq);
  nghttp2_active_outbound_item_reset(&session->aob);
  nghttp2_inbound_frame_reset(session);
  nghttp2_hd_deflate_free(&session->hd_deflater);
  nghttp2_hd_inflate_free(&session->hd_inflater);
  nghttp2_bufs_free(&session->aob.framebufs);
  free(session);
}

int nghttp2_session_reprioritize_stream
(nghttp2_session *session, nghttp2_stream *stream,
 const nghttp2_priority_spec *pri_spec)
{
  int rv;
  nghttp2_stream *dep_stream;
  nghttp2_stream *root_stream;

  if(pri_spec->stream_id == stream->stream_id) {
    return nghttp2_session_terminate_session(session,
                                             NGHTTP2_PROTOCOL_ERROR);
  }

  if(pri_spec->stream_id == 0) {
    nghttp2_stream_dep_remove_subtree(stream);

    /* We have to update weight after removing stream from tree */
    stream->weight = pri_spec->weight;

    if(pri_spec->exclusive &&
       session->roots.num_streams <= NGHTTP2_MAX_DEP_TREE_LENGTH) {

      rv = nghttp2_stream_dep_all_your_stream_are_belong_to_us
        (stream, &session->ob_pq);
    } else {
      rv = nghttp2_stream_dep_make_root(stream, &session->ob_pq);
    }

    return rv;
  }

  dep_stream = nghttp2_session_get_stream_raw(session, pri_spec->stream_id);

  if(!dep_stream || !nghttp2_stream_in_dep_tree(dep_stream)) {
    return 0;
  }

  if(nghttp2_stream_dep_subtree_find(stream, dep_stream)) {
    DEBUGF(fprintf(stderr,
                   "stream: cycle detected, dep_stream(%p)=%d "
                   "stream(%p)=%d\n",
                   dep_stream, dep_stream->stream_id,
                   stream, stream->stream_id));

    nghttp2_stream_dep_remove_subtree(dep_stream);
    nghttp2_stream_dep_make_root(dep_stream, &session->ob_pq);
  }

  nghttp2_stream_dep_remove_subtree(stream);

  /* We have to update weight after removing stream from tree */
  stream->weight = pri_spec->weight;

  root_stream = nghttp2_stream_get_dep_root(dep_stream);

  if(root_stream->num_substreams + stream->num_substreams >
     NGHTTP2_MAX_DEP_TREE_LENGTH) {
    rv = nghttp2_stream_dep_make_root(stream, &session->ob_pq);
  } else {
    if(pri_spec->exclusive) {
      rv = nghttp2_stream_dep_insert_subtree(dep_stream, stream,
                                             &session->ob_pq);
    } else {
      rv = nghttp2_stream_dep_add_subtree(dep_stream, stream,
                                          &session->ob_pq);
    }
  }

  if(rv != 0) {
    return rv;
  }

  return 0;
}

int nghttp2_session_add_frame(nghttp2_session *session,
                              nghttp2_frame_category frame_cat,
                              void *abs_frame,
                              void *aux_data)
{
  /* TODO Return error if stream is not found for the frame requiring
     stream presence. */
  int rv = 0;
  nghttp2_outbound_item *item;

  item = malloc(sizeof(nghttp2_outbound_item));
  if(item == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  item->frame_cat = frame_cat;
  item->frame = abs_frame;
  item->aux_data = aux_data;
  item->seq = session->next_seq++;

  item->weight = NGHTTP2_OB_EX_WEIGHT;
  item->queued = 0;

  if(frame_cat == NGHTTP2_CAT_CTRL) {
    nghttp2_frame *frame = (nghttp2_frame*)abs_frame;
    nghttp2_stream *stream;
    nghttp2_stream *dep_stream;

    stream = nghttp2_session_get_stream(session, frame->hd.stream_id);

    switch(frame->hd.type) {
    case NGHTTP2_HEADERS:
      if(frame->hd.stream_id == -1) {
        /* Initial HEADERS, which will open stream */

        /* TODO If we always frame.headers.pri_spec filled in, we
           don't have to check flags */
        if(frame->hd.flags & NGHTTP2_FLAG_PRIORITY) {
          if(frame->headers.pri_spec.stream_id == 0) {
            item->weight = frame->headers.pri_spec.weight;
          } else {
            dep_stream = nghttp2_session_get_stream
              (session, frame->headers.pri_spec.stream_id);

            if(dep_stream) {
              item->weight = nghttp2_stream_dep_distributed_effective_weight
                (dep_stream, frame->headers.pri_spec.weight);
            } else {
              item->weight = frame->headers.pri_spec.weight;
            }
          }
        } else {
          item->weight = NGHTTP2_DEFAULT_WEIGHT;
        }

      } else if(stream) {
        /* Otherwise, the frame must have stream ID.  We use its
           effective_weight. */
        item->weight = stream->effective_weight;
      }
      break;
    case NGHTTP2_PRIORITY:
      break;
    case NGHTTP2_RST_STREAM:
      if(stream) {
        /* We rely on the stream state to decide whether number of
           streams should be decremented or not. For purly reserved
           streams, they are not counted to those numbers and we must
           keep this state in order not to decrement the number. */
        if(stream->state != NGHTTP2_STREAM_RESERVED) {
          stream->state = NGHTTP2_STREAM_CLOSING;
        }
      }

      break;
    case NGHTTP2_SETTINGS:
      item->weight = NGHTTP2_OB_SETTINGS_WEIGHT;

      break;
    case NGHTTP2_PUSH_PROMISE:
      /* Use priority of associated stream */
      if(stream) {
        item->weight = stream->effective_weight;
      }

      break;
    case NGHTTP2_PING:
      /* Ping has highest priority. */
      item->weight = NGHTTP2_OB_PING_WEIGHT;

      break;
    case NGHTTP2_GOAWAY:
      /* Should GOAWAY have higher priority? */
      break;
    case NGHTTP2_WINDOW_UPDATE:
      break;
    case NGHTTP2_ALTSVC:
      break;
    case NGHTTP2_BLOCKED:
      break;
    }

    if(frame->hd.type == NGHTTP2_HEADERS &&
       (frame->hd.stream_id == -1 ||
        (stream && stream->state == NGHTTP2_STREAM_RESERVED))) {
      /* We push request HEADERS and push response HEADERS to
         dedicated queue because their transmission is affected by
         SETTINGS_MAX_CONCURRENT_STREAMS */
      /* TODO If 2 HEADERS are submitted for reserved stream, then
         both of them are queued into ob_ss_pq, which is not
         desirable. */
      rv = nghttp2_pq_push(&session->ob_ss_pq, item);
    } else {
      rv = nghttp2_pq_push(&session->ob_pq, item);
    }

    item->queued = 1;

  } else if(frame_cat == NGHTTP2_CAT_DATA) {
    nghttp2_private_data *data_frame = (nghttp2_private_data*)abs_frame;
    nghttp2_stream *stream;

    stream = nghttp2_session_get_stream(session, data_frame->hd.stream_id);
    if(stream) {
      if(stream->data_item) {
        rv = NGHTTP2_ERR_DATA_EXIST;
      } else {
        item->weight = stream->effective_weight;

        rv = nghttp2_stream_attach_data(stream, item, &session->ob_pq);
      }
    }

  } else {
    /* Unreachable */
    assert(0);
  }

  if(rv != 0) {
    free(item);
    return rv;
  }

  return 0;
}

int nghttp2_session_add_rst_stream(nghttp2_session *session,
                                   int32_t stream_id,
                                   nghttp2_error_code error_code)
{
  int rv;
  nghttp2_frame *frame;
  nghttp2_stream *stream;

  stream = nghttp2_session_get_stream(session, stream_id);
  if(stream && stream->state == NGHTTP2_STREAM_CLOSING) {
    return 0;
  }

  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  nghttp2_frame_rst_stream_init(&frame->rst_stream, stream_id, error_code);
  rv = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  if(rv != 0) {
    nghttp2_frame_rst_stream_free(&frame->rst_stream);
    free(frame);
    return rv;
  }
  return 0;
}

nghttp2_stream* nghttp2_session_open_stream(nghttp2_session *session,
                                            int32_t stream_id,
                                            uint8_t flags,
                                            nghttp2_priority_spec *pri_spec,
                                            nghttp2_stream_state initial_state,
                                            void *stream_user_data)
{
  int rv;
  nghttp2_stream *stream;
  nghttp2_stream *dep_stream;
  nghttp2_stream *root_stream;

  if(session->server && !nghttp2_session_is_my_stream_id(session, stream_id)) {
    nghttp2_session_adjust_closed_stream(session, 1);
  }

  stream = malloc(sizeof(nghttp2_stream));
  if(stream == NULL) {
    return NULL;
  }

  nghttp2_stream_init(stream, stream_id, flags, initial_state,
                      pri_spec->weight, &session->roots,
                      session->remote_settings
                      [NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE],
                      session->local_settings
                      [NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE],
                      stream_user_data);

  rv = nghttp2_map_insert(&session->streams, &stream->map_entry);
  if(rv != 0) {
    free(stream);
    return NULL;
  }

  if(initial_state == NGHTTP2_STREAM_RESERVED) {
    if(nghttp2_session_is_my_stream_id(session, stream_id)) {
      /* half closed (remote) */
      nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
    } else {
      /* half closed (local) */
      nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
    }
    /* Reserved stream does not count in the concurrent streams
       limit. That is one of the DOS vector. */
  } else {
    if(nghttp2_session_is_my_stream_id(session, stream_id)) {
      ++session->num_outgoing_streams;
    } else {
      ++session->num_incoming_streams;
    }
  }

  /* We don't have to track dependency of received reserved stream */
  if(stream->shut_flags & NGHTTP2_SHUT_WR) {
    return stream;
  }

  if(pri_spec->stream_id == 0) {

    ++session->roots.num_streams;

    if(pri_spec->exclusive &&
       session->roots.num_streams <= NGHTTP2_MAX_DEP_TREE_LENGTH) {
      rv = nghttp2_stream_dep_all_your_stream_are_belong_to_us
        (stream, &session->ob_pq);

      /* Since no dpri is changed in dependency tree, the above
         function call never fail. */
      assert(rv == 0);
    } else {
      nghttp2_stream_roots_add(&session->roots, stream);
    }

    return stream;
  }

  dep_stream = nghttp2_session_get_stream_raw(session, pri_spec->stream_id);

  /* If dep_stream is not part of dependency tree, we don't use it. */
  if(!dep_stream || !nghttp2_stream_in_dep_tree(dep_stream)) {
    return stream;
  }

  /* TODO Client does not have to track dependencies of streams except
     for those which have upload data.  Currently, we just track
     everything. */

  root_stream = nghttp2_stream_get_dep_root(dep_stream);

  if(root_stream->num_substreams < NGHTTP2_MAX_DEP_TREE_LENGTH) {
    if(pri_spec->exclusive) {
      nghttp2_stream_dep_insert(dep_stream, stream);
    } else {
      nghttp2_stream_dep_add(dep_stream, stream);
    }
  }

  return stream;
}

int nghttp2_session_close_stream(nghttp2_session *session, int32_t stream_id,
                                 nghttp2_error_code error_code)
{
  int rv;
  nghttp2_stream *stream;

  stream = nghttp2_session_get_stream(session, stream_id);

  if(!stream) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }

  DEBUGF(fprintf(stderr, "stream: stream(%p)=%d close\n",
                 stream, stream->stream_id));

  if(stream->data_item) {
    nghttp2_outbound_item *item;

    item = stream->data_item;

    rv = nghttp2_stream_detach_data(stream, &session->ob_pq);

    if(rv != 0) {
      return rv;
    }

    /* If item is queued, it will be deleted when it is popped
       (nghttp2_session_prep_frame() will fail).  If session->aob.item
       points to this item, let nghttp2_active_outbound_item_reset()
       free the item. */
    if(!item->queued && item != session->aob.item) {
      free(item);
    }
  }

  /* We call on_stream_close_callback even if stream->state is
     NGHTTP2_STREAM_INITIAL. This will happen while sending request
     HEADERS, a local endpoint receives RST_STREAM for that stream. It
     may be PROTOCOL_ERROR, but without notifying stream closure will
     hang the stream in a local endpoint.
  */

  if(session->callbacks.on_stream_close_callback) {
    if(session->callbacks.on_stream_close_callback
       (session, stream_id, error_code, session->user_data) != 0) {

      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  if(stream->state != NGHTTP2_STREAM_RESERVED) {
    if(nghttp2_session_is_my_stream_id(session, stream_id)) {
      --session->num_outgoing_streams;
    } else {
      --session->num_incoming_streams;
    }
  }

  /* Closes both directions just in case they are not closed yet */
  stream->flags |= NGHTTP2_STREAM_FLAG_CLOSED;

  if(session->server &&
     nghttp2_stream_in_dep_tree(stream) &&
     !nghttp2_session_is_my_stream_id(session, stream_id)) {
    /* On server side, retain incoming stream object at most
       MAX_CONCURRENT_STREAMS combined with the current active streams
       to make dependency tree work better. */
    nghttp2_session_keep_closed_stream(session, stream);
  } else {
    nghttp2_session_destroy_stream(session, stream);
  }

  return 0;
}

void nghttp2_session_destroy_stream(nghttp2_session *session,
                                    nghttp2_stream *stream)
{
  DEBUGF(fprintf(stderr, "stream: destroy closed stream(%p)=%d\n",
                 stream, stream->stream_id));

  nghttp2_stream_dep_remove(stream);

  nghttp2_map_remove(&session->streams, stream->stream_id);
  nghttp2_stream_free(stream);
  free(stream);
}

void nghttp2_session_keep_closed_stream(nghttp2_session *session,
                                        nghttp2_stream *stream)
{
  DEBUGF(fprintf(stderr, "stream: keep closed stream(%p)=%d\n",
                 stream, stream->stream_id));

  if(session->closed_stream_tail) {
    session->closed_stream_tail->closed_next = stream;
  } else {
    session->closed_stream_head = stream;
  }
  session->closed_stream_tail = stream;

  ++session->num_closed_streams;

  nghttp2_session_adjust_closed_stream(session, 0);
}

void nghttp2_session_adjust_closed_stream(nghttp2_session *session,
                                          ssize_t offset)
{
  DEBUGF(fprintf(stderr, "stream: adjusting kept closed streams "
                 "num_closed_streams=%zu, num_incoming_streams=%zu, "
                 "max_concurrent_streams=%u\n",
                 session->num_closed_streams, session->num_incoming_streams,
                 session->pending_local_max_concurrent_stream));

  while(session->num_closed_streams > 0 &&
        session->num_closed_streams + session->num_incoming_streams + offset
        > session->pending_local_max_concurrent_stream) {
    nghttp2_stream *head_stream;

    head_stream = session->closed_stream_head;

    session->closed_stream_head = head_stream->closed_next;

    if(session->closed_stream_tail == head_stream) {
      session->closed_stream_tail = NULL;
    }

    nghttp2_session_destroy_stream(session, head_stream);
    /* head_stream is now freed */
    --session->num_closed_streams;
  }
}

/*
 * Closes stream with stream ID |stream_id| if both transmission and
 * reception of the stream were disallowed. The |error_code| indicates
 * the reason of the closure.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_ARGUMENT
 *   The stream is not found.
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *   The callback function failed.
 */
int nghttp2_session_close_stream_if_shut_rdwr(nghttp2_session *session,
                                              nghttp2_stream *stream)
{
  if((stream->shut_flags & NGHTTP2_SHUT_RDWR) == NGHTTP2_SHUT_RDWR) {
    return nghttp2_session_close_stream(session, stream->stream_id,
                                        NGHTTP2_NO_ERROR);
  }
  return 0;
}

/*
 * Check that we can send a frame to the |stream|. This function
 * returns 0 if we can send a frame to the |frame|, or one of the
 * following negative error codes:
 *
 * NGHTTP2_ERR_STREAM_CLOSED
 *   The stream is already closed.
 * NGHTTP2_ERR_STREAM_SHUT_WR
 *   The stream is half-closed for transmission.
 */
static int nghttp2_predicate_stream_for_send(nghttp2_stream *stream)
{
  if(stream == NULL) {
    return NGHTTP2_ERR_STREAM_CLOSED;
  }
  if(stream->shut_flags & NGHTTP2_SHUT_WR) {
    return NGHTTP2_ERR_STREAM_SHUT_WR;
  }
  return 0;
}

/*
 * This function checks HEADERS frame |frame|, which opens stream, can
 * be sent at this time.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_START_STREAM_NOT_ALLOWED
 *     New stream cannot be created because GOAWAY is already sent or
 *     received.
 * NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE
 *     Stream ID has reached the maximum value. Therefore no stream ID
 *     is available.
 */
static int nghttp2_session_predicate_request_headers_send
(nghttp2_session *session, nghttp2_headers *frame)
{
  if(session->goaway_flags) {
    /* When GOAWAY is sent or received, peer must not send new request
       HEADERS. */
    return NGHTTP2_ERR_START_STREAM_NOT_ALLOWED;
  }
  /* All 32bit signed stream IDs are spent. */
  if(session->next_stream_id > INT32_MAX) {
    return NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE;
  }
  return 0;
}

/*
 * This function checks HEADERS, which is the first frame from the
 * server, with the stream ID |stream_id| can be sent at this time.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_STREAM_CLOSED
 *     The stream is already closed or does not exist.
 * NGHTTP2_ERR_STREAM_SHUT_WR
 *     The transmission is not allowed for this stream (e.g., a frame
 *     with END_STREAM flag set has already sent)
 * NGHTTP2_ERR_INVALID_STREAM_ID
 *     The stream ID is invalid.
 * NGHTTP2_ERR_STREAM_CLOSING
 *     RST_STREAM was queued for this stream.
 * NGHTTP2_ERR_INVALID_STREAM_STATE
 *     The state of the stream is not valid.
 */
static int nghttp2_session_predicate_response_headers_send
(nghttp2_session *session, int32_t stream_id)
{
  nghttp2_stream *stream = nghttp2_session_get_stream(session, stream_id);
  int rv;
  rv = nghttp2_predicate_stream_for_send(stream);
  if(rv != 0) {
    return rv;
  }
  if(nghttp2_session_is_my_stream_id(session, stream_id)) {
    return NGHTTP2_ERR_INVALID_STREAM_ID;
  }
  if(stream->state == NGHTTP2_STREAM_OPENING) {
    return 0;
  }
  if(stream->state == NGHTTP2_STREAM_CLOSING) {
    return NGHTTP2_ERR_STREAM_CLOSING;
  }
  return NGHTTP2_ERR_INVALID_STREAM_STATE;
}

/*
 * This function checks HEADERS for reserved stream can be sent. The
 * stream |stream_id| must be reserved state and the |session| is
 * server side.
 *
 * This function returns 0 if it succeeds, or one of the following
 * error codes:
 *
 * NGHTTP2_ERR_STREAM_CLOSED
 *   The stream is already closed.
 * NGHTTP2_ERR_STREAM_SHUT_WR
 *   The stream is half-closed for transmission.
 * NGHTTP2_ERR_PROTO
 *   The stream is not reserved state
 * NGHTTP2_ERR_STREAM_CLOSED
 *   RST_STREAM was queued for this stream.
 */
static int nghttp2_session_predicate_push_response_headers_send
(nghttp2_session *session, int32_t stream_id)
{
  nghttp2_stream *stream = nghttp2_session_get_stream(session, stream_id);
  int rv;
  /* TODO Should disallow HEADERS if GOAWAY has already been issued? */
  rv = nghttp2_predicate_stream_for_send(stream);
  if(rv != 0) {
    return rv;
  }
  if(stream->state != NGHTTP2_STREAM_RESERVED) {
    return NGHTTP2_ERR_PROTO;
  }
  if(stream->state == NGHTTP2_STREAM_CLOSING) {
    return NGHTTP2_ERR_STREAM_CLOSING;
  }
  return 0;
}

/*
 * This function checks frames belongs to the stream |stream_id| can
 * be sent.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_STREAM_CLOSED
 *     The stream is already closed or does not exist.
 * NGHTTP2_ERR_STREAM_SHUT_WR
 *     The transmission is not allowed for this stream (e.g., a frame
 *     with END_STREAM flag set has already sent)
 * NGHTTP2_ERR_STREAM_CLOSING
 *     RST_STREAM was queued for this stream.
 * NGHTTP2_ERR_INVALID_STREAM_STATE
 *     The state of the stream is not valid.
 */
static int nghttp2_session_predicate_stream_frame_send
(nghttp2_session* session, int32_t stream_id)
{
  nghttp2_stream *stream = nghttp2_session_get_stream(session, stream_id);
  int rv;
  rv = nghttp2_predicate_stream_for_send(stream);
  if(rv != 0) {
    return rv;
  }
  if(nghttp2_session_is_my_stream_id(session, stream_id)) {
    if(stream->state == NGHTTP2_STREAM_CLOSING) {
      return NGHTTP2_ERR_STREAM_CLOSING;
    }
    return 0;
  }
  if(stream->state == NGHTTP2_STREAM_OPENED) {
    return 0;
  }
  if(stream->state == NGHTTP2_STREAM_CLOSING) {
    return NGHTTP2_ERR_STREAM_CLOSING;
  }
  return NGHTTP2_ERR_INVALID_STREAM_STATE;
}

/*
 * This function checks HEADERS, which is neither stream-opening nor
 * first response header, with the stream ID |stream_id| can be sent
 * at this time.
 */
static int nghttp2_session_predicate_headers_send(nghttp2_session *session,
                                                  int32_t stream_id)
{
  return nghttp2_session_predicate_stream_frame_send(session, stream_id);
}

/*
 * This function checks PRIORITY frame with stream ID |stream_id| can
 * be sent at this time.
 */
static int nghttp2_session_predicate_priority_send
(nghttp2_session *session, int32_t stream_id)
{
  nghttp2_stream *stream;
  stream = nghttp2_session_get_stream(session, stream_id);
  if(stream == NULL) {
    return NGHTTP2_ERR_STREAM_CLOSED;
  }
  if(stream->state == NGHTTP2_STREAM_CLOSING) {
    return NGHTTP2_ERR_STREAM_CLOSING;
  }
  /* PRIORITY must not be sent in reserved(local) */
  if(state_reserved_local(session, stream)) {
    return NGHTTP2_ERR_INVALID_STREAM_STATE;
  }
  /* Sending PRIORITY in reserved(remote) state is OK */
  return 0;
}

/*
 * This function checks PUSH_PROMISE frame |frame| with stream ID
 * |stream_id| can be sent at this time.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_START_STREAM_NOT_ALLOWED
 *     New stream cannot be created because GOAWAY is already sent or
 *     received.
 * NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE
 *     Stream ID has reached the maximum value. Therefore no stream ID
 *     is available.
 * NGHTTP2_ERR_PROTO
 *     The client side attempts to send PUSH_PROMISE, or the server
 *     sends PUSH_PROMISE for the stream not initiated by the client.
 * NGHTTP2_ERR_STREAM_CLOSED
 *     The stream is already closed or does not exist.
 * NGHTTP2_ERR_STREAM_CLOSING
 *     RST_STREAM was queued for this stream.
 * NGHTTP2_ERR_STREAM_SHUT_WR
 *     The transmission is not allowed for this stream (e.g., a frame
 *     with END_STREAM flag set has already sent)
 * NGHTTP2_ERR_PUSH_DISABLED
 *     The remote peer disabled reception of PUSH_PROMISE.
 */
static int nghttp2_session_predicate_push_promise_send
(nghttp2_session *session, int32_t stream_id)
{
  int rv;
  nghttp2_stream *stream;
  if(!session->server) {
    return NGHTTP2_ERR_PROTO;
  }
  if(nghttp2_session_is_my_stream_id(session, stream_id)) {
    /* The associated stream must be initiated by the remote peer */
    return NGHTTP2_ERR_PROTO;
  }
  stream = nghttp2_session_get_stream(session, stream_id);
  rv = nghttp2_predicate_stream_for_send(stream);
  if(rv != 0) {
    return rv;
  }
  if(session->remote_settings[NGHTTP2_SETTINGS_ENABLE_PUSH] == 0) {
    return NGHTTP2_ERR_PUSH_DISABLED;
  }
  if(stream->state == NGHTTP2_STREAM_CLOSING) {
    return NGHTTP2_ERR_STREAM_CLOSING;
  }
  if(session->goaway_flags) {
    /* When GOAWAY is sent or received, peer must not promise new
       stream ID */
    return NGHTTP2_ERR_START_STREAM_NOT_ALLOWED;
  }
  /* All 32bit signed stream IDs are spent. */
  if(session->next_stream_id > INT32_MAX) {
    return NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE;
  }
  return 0;
}

/*
 * This function checks WINDOW_UPDATE with the stream ID |stream_id|
 * can be sent at this time. Note that END_STREAM flag of the previous
 * frame does not affect the transmission of the WINDOW_UPDATE frame.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_STREAM_CLOSED
 *     The stream is already closed or does not exist.
 * NGHTTP2_ERR_STREAM_CLOSING
 *     RST_STREAM was queued for this stream.
 * NGHTTP2_ERR_INVALID_STREAM_STATE
 *     The state of the stream is not valid.
 */
static int nghttp2_session_predicate_window_update_send
(nghttp2_session *session, int32_t stream_id)
{
  nghttp2_stream *stream;
  if(stream_id == 0) {
    /* Connection-level window update */
    return 0;
  }
  stream = nghttp2_session_get_stream(session, stream_id);
  if(stream == NULL) {
    return NGHTTP2_ERR_STREAM_CLOSED;
  }
  if(stream->state == NGHTTP2_STREAM_CLOSING) {
    return NGHTTP2_ERR_STREAM_CLOSING;
  }
  if(stream->state == NGHTTP2_STREAM_RESERVED) {
    return NGHTTP2_ERR_INVALID_STREAM_STATE;
  }
  return 0;
}

/*
 * This function checks ALTSVC with the stream ID |stream_id| can be
 * sent at this time.  If |stream_id| is 0, ATLSVC frame is always
 * allowed to send.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_STREAM_CLOSED
 *     The stream is already closed or does not exist.
 * NGHTTP2_ERR_STREAM_CLOSING
 *     RST_STREAM was queued for this stream.
 */
static int nghttp2_session_predicate_altsvc_send
(nghttp2_session *session, int32_t stream_id)
{
  nghttp2_stream *stream;

  if(stream_id == 0) {
    return 0;
  }

  stream = nghttp2_session_get_stream(session, stream_id);

  if(stream == NULL) {
    return NGHTTP2_ERR_STREAM_CLOSED;
  }

  if(stream->state == NGHTTP2_STREAM_CLOSING) {
    return NGHTTP2_ERR_STREAM_CLOSING;
  }

  return 0;
}

/*
 * This function checks BLOCKED with the stream ID |stream_id| can be
 * sent at this time.  If |stream_id| is 0, BLOCKED frame is always
 * allowed to send.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_STREAM_CLOSED
 *     The stream is already closed or does not exist.
 * NGHTTP2_ERR_STREAM_CLOSING
 *     RST_STREAM was queued for this stream.
 */
static int nghttp2_session_predicate_blocked_send
(nghttp2_session *session, int32_t stream_id)
{
  nghttp2_stream *stream;

  if(stream_id == 0) {
    return 0;
  }

  stream = nghttp2_session_get_stream(session, stream_id);

  if(stream == NULL) {
    return NGHTTP2_ERR_STREAM_CLOSED;
  }

  if(stream->state == NGHTTP2_STREAM_CLOSING) {
    return NGHTTP2_ERR_STREAM_CLOSING;
  }

  return 0;
}

/*
 * This function checks SETTINGS can be sent at this time.
 *
 * Currently this function always returns 0.
 */
static int nghttp2_session_predicate_settings_send(nghttp2_session *session,
                                                   nghttp2_frame *frame)
{
  return 0;
}

/*
 * Returns the maximum length of next data read. If the
 * connection-level and/or stream-wise flow control are enabled, the
 * return value takes into account those current window sizes.
 */
static size_t nghttp2_session_next_data_read(nghttp2_session *session,
                                             nghttp2_stream *stream)
{
  int32_t window_size = NGHTTP2_DATA_PAYLOADLEN;

  DEBUGF(fprintf(stderr,
                 "send: remote windowsize connection=%d, "
                 "stream(id %d)=%d\n",
                 session->remote_window_size,
                 stream->stream_id,
                 stream->remote_window_size));

  /* Take into account both connection-level flow control here */
  window_size = nghttp2_min(window_size, session->remote_window_size);
  window_size = nghttp2_min(window_size, stream->remote_window_size);

  DEBUGF(fprintf(stderr, "send: available window=%d\n", window_size));

  if(window_size > 0) {
    return window_size;
  }
  return 0;
}

/*
 * This function checks DATA with the stream ID |stream_id| can be
 * sent at this time.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_STREAM_CLOSED
 *     The stream is already closed or does not exist.
 * NGHTTP2_ERR_STREAM_SHUT_WR
 *     The transmission is not allowed for this stream (e.g., a frame
 *     with END_STREAM flag set has already sent)
 * NGHTTP2_ERR_STREAM_CLOSING
 *     RST_STREAM was queued for this stream.
 * NGHTTP2_ERR_INVALID_STREAM_STATE
 *     The state of the stream is not valid.
 */
static int nghttp2_session_predicate_data_send(nghttp2_session *session,
                                               int32_t stream_id)
{
  nghttp2_stream *stream = nghttp2_session_get_stream(session, stream_id);
  int rv;
  rv = nghttp2_predicate_stream_for_send(stream);
  if(rv != 0) {
    return rv;
  }
  if(nghttp2_session_is_my_stream_id(session, stream_id)) {
    /* Request body data */
    /* If stream->state is NGHTTP2_STREAM_CLOSING, RST_STREAM was
       queued but not yet sent. In this case, we won't send DATA
       frames. */
    if(stream->state == NGHTTP2_STREAM_CLOSING) {
      return NGHTTP2_ERR_STREAM_CLOSING;
    }
    if(stream->state == NGHTTP2_STREAM_RESERVED) {
      return NGHTTP2_ERR_INVALID_STREAM_STATE;
    }
    return 0;
  }
  /* Response body data */
  if(stream->state == NGHTTP2_STREAM_OPENED) {
    return 0;
  }
  if(stream->state == NGHTTP2_STREAM_CLOSING) {
    return NGHTTP2_ERR_STREAM_CLOSING;
  }
  return NGHTTP2_ERR_INVALID_STREAM_STATE;
}

static ssize_t session_call_select_padding(nghttp2_session *session,
                                           const nghttp2_frame *frame,
                                           size_t max_payloadlen)
{
  ssize_t rv;
  if(session->callbacks.select_padding_callback) {
    rv = session->callbacks.select_padding_callback(session, frame,
                                                    max_payloadlen,
                                                    session->user_data);
    if(rv < (ssize_t)frame->hd.length || rv > (ssize_t)max_payloadlen) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return rv;
  }
  return frame->hd.length;
}

/* Add padding to HEADERS or PUSH_PROMISE. We use
   frame->headers.padlen in this function to use the fact that
   frame->push_promise has also padlen in the same position. */
static int session_headers_add_pad(nghttp2_session *session,
                                   nghttp2_frame *frame)
{
  int rv;
  ssize_t padded_payloadlen;
  nghttp2_active_outbound_item *aob;
  nghttp2_bufs *framebufs;
  size_t padlen;

  aob = &session->aob;
  framebufs = &aob->framebufs;

  padded_payloadlen = session_call_select_padding(session, frame,
                                                  frame->hd.length + 1024);
  if(nghttp2_is_fatal(padded_payloadlen)) {
    return padded_payloadlen;
  }

  padlen = padded_payloadlen - frame->hd.length;

  DEBUGF(fprintf(stderr,
                 "send: padding selected: payloadlen=%zu, padlen=%zu\n",
                 padded_payloadlen, padlen));

  rv = nghttp2_frame_add_pad(framebufs, &frame->hd, padlen,
                             NGHTTP2_CONTINUATION);
  if(rv != 0) {
    return rv;
  }

  frame->headers.padlen = padlen;

  return 0;
}

/*
 * Adds BLOCKED frame to outbound queue.  The |stream_id| could be 0,
 * which means DATA is blocked by connection level flow control.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
static int session_add_blocked(nghttp2_session *session, int32_t stream_id)
{
  int rv;
  nghttp2_frame *frame;

  frame = malloc(sizeof(nghttp2_frame));

  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  nghttp2_frame_blocked_init(&frame->blocked, stream_id);

  rv = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);

  if(rv != 0) {
    nghttp2_frame_blocked_free(&frame->blocked);
    free(frame);

    return rv;
  }
  return 0;
}

/*
 * Adds BLOCKED frame(s) to outbound queue if they are allowed to
 * send.  We check BLOCKED frame can be sent for connection and stream
 * individually.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
static int session_consider_blocked(nghttp2_session *session,
                                    nghttp2_stream *stream)
{
  if(session->blocked_sent == 0 && session->remote_window_size <= 0) {
    session->blocked_sent = 1;

    return session_add_blocked(session, 0);
  }

  if(stream->blocked_sent == 0 && stream->remote_window_size <= 0) {
    stream->blocked_sent = 1;

    return session_add_blocked(session, stream->stream_id);
  }

  return 0;
}

static int session_call_adjust_priority(nghttp2_session *session,
                                        nghttp2_frame *frame,
                                        nghttp2_stream *stream)
{
  int rv;

  if(session->callbacks.adjust_priority_callback) {
    nghttp2_priority_spec pri_spec;

    pri_spec = frame->headers.pri_spec;

    rv = session->callbacks.adjust_priority_callback(session, frame,
                                                     &pri_spec,
                                                     session->user_data);

    if(rv != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    frame->headers.pri_spec = pri_spec;

    if(nghttp2_priority_spec_check_default(&pri_spec)) {
      rv = nghttp2_session_reprioritize_stream(session, stream, &pri_spec);

      if(nghttp2_is_fatal(rv)) {
        return rv;
      }

      frame->hd.flags &= ~NGHTTP2_FLAG_PRIORITY;
    } else {
      frame->hd.flags |= NGHTTP2_FLAG_PRIORITY;
    }
  }

  return 0;
}

/*
 * This function serializes frame for transmission.
 *
 * This function returns 0 if it succeeds, or one of negative error
 * codes, including both fatal and non-fatal ones.
 */
static int nghttp2_session_prep_frame(nghttp2_session *session,
                                      nghttp2_outbound_item *item)
{
  ssize_t framerv = 0;
  int rv;

  if(item->frame_cat == NGHTTP2_CAT_CTRL) {
    nghttp2_frame *frame;
    frame = nghttp2_outbound_item_get_ctrl_frame(item);
    switch(frame->hd.type) {
    case NGHTTP2_HEADERS: {
      nghttp2_headers_aux_data *aux_data;

      aux_data = (nghttp2_headers_aux_data*)item->aux_data;

      if(frame->hd.stream_id == -1) {
        nghttp2_priority_spec pri_spec_default;
        nghttp2_stream *stream;

        /* initial HEADERS, which opens stream */
        frame->headers.cat = NGHTTP2_HCAT_REQUEST;
        rv = nghttp2_session_predicate_request_headers_send(session,
                                                            &frame->headers);
        if(rv != 0) {
          return rv;
        }
        frame->hd.stream_id = session->next_stream_id;
        session->next_stream_id += 2;

        /* We first open strea with default priority.  This is because
        priority may be adjusted in callback. */
        nghttp2_priority_spec_default_init(&pri_spec_default);

        stream = nghttp2_session_open_stream
          (session, frame->hd.stream_id,
           NGHTTP2_STREAM_FLAG_NONE,
           &pri_spec_default,
           NGHTTP2_STREAM_INITIAL,
           aux_data ? aux_data->stream_user_data : NULL);

        if(stream == NULL) {
          return NGHTTP2_ERR_NOMEM;
        }

        /* We need to call this after stream was opened so that we can
           use nghttp2_session_get_stream_user_data() */
        rv = session_call_adjust_priority(session, frame, stream);

        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

      } else if(nghttp2_session_predicate_push_response_headers_send
                (session, frame->hd.stream_id) == 0) {
        frame->headers.cat = NGHTTP2_HCAT_PUSH_RESPONSE;
      } else if(nghttp2_session_predicate_response_headers_send
                (session, frame->hd.stream_id) == 0) {
        frame->headers.cat = NGHTTP2_HCAT_RESPONSE;
      } else {
        frame->headers.cat = NGHTTP2_HCAT_HEADERS;
        rv = nghttp2_session_predicate_headers_send(session,
                                                   frame->hd.stream_id);
        if(rv != 0) {
          return rv;
        }
      }

      framerv = nghttp2_frame_pack_headers(&session->aob.framebufs,
                                           &frame->headers,
                                           &session->hd_deflater);

      if(framerv < 0) {
        if(!nghttp2_is_fatal(framerv)) {
          rv = nghttp2_session_close_stream(session, frame->hd.stream_id,
                                            NGHTTP2_NO_ERROR);

          if(nghttp2_is_fatal(rv)) {
            return rv;
          }
        }

        return framerv;
      }

      DEBUGF(fprintf(stderr,
                     "send: before padding, HEADERS serialized in %zd bytes\n",
                     nghttp2_bufs_len(&session->aob.framebufs)));

      framerv = session_headers_add_pad(session, frame);
      if(framerv < 0) {
        return framerv;
      }

      if(frame->headers.cat == NGHTTP2_HCAT_PUSH_RESPONSE) {
        if(aux_data && aux_data->stream_user_data) {
          nghttp2_stream *stream;
          stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
          stream->stream_user_data = aux_data->stream_user_data;
        }
      }

      DEBUGF(fprintf(stderr, "send: HEADERS finally serialized in %zd bytes\n",
                     nghttp2_bufs_len(&session->aob.framebufs)));

      break;
    }
    case NGHTTP2_PRIORITY: {
      rv = nghttp2_session_predicate_priority_send
        (session, frame->hd.stream_id);
      if(rv != 0) {
        return rv;
      }
      framerv = nghttp2_frame_pack_priority(&session->aob.framebufs,
                                            &frame->priority);
      if(framerv < 0) {
        return framerv;
      }
      break;
    }
    case NGHTTP2_RST_STREAM:
      framerv = nghttp2_frame_pack_rst_stream(&session->aob.framebufs,
                                              &frame->rst_stream);
      if(framerv < 0) {
        return framerv;
      }
      break;
    case NGHTTP2_SETTINGS: {
      rv = nghttp2_session_predicate_settings_send(session, frame);
      if(rv != 0) {
        return rv;
      }
      framerv = nghttp2_frame_pack_settings(&session->aob.framebufs,
                                            &frame->settings);
      if(framerv < 0) {
        return framerv;
      }
      break;
    }
    case NGHTTP2_PUSH_PROMISE: {
      nghttp2_stream *stream;
      nghttp2_headers_aux_data *aux_data;
      nghttp2_priority_spec pri_spec;

      aux_data = (nghttp2_headers_aux_data*)item->aux_data;

      rv = nghttp2_session_predicate_push_promise_send(session,
                                                      frame->hd.stream_id);
      if(rv != 0) {
        return rv;
      }
      frame->push_promise.promised_stream_id = session->next_stream_id;
      session->next_stream_id += 2;
      framerv = nghttp2_frame_pack_push_promise(&session->aob.framebufs,
                                                &frame->push_promise,
                                                &session->hd_deflater);
      if(framerv < 0) {
        return framerv;
      }
      framerv = session_headers_add_pad(session, frame);
      if(framerv < 0) {
        return framerv;
      }

      stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
      assert(stream);

      /* TODO It is unclear reserved stream dpeneds on associated
         stream with or without exclusive flag set */
      nghttp2_priority_spec_init(&pri_spec, stream->stream_id,
                                 NGHTTP2_DEFAULT_WEIGHT, 0);

      if(!nghttp2_session_open_stream
         (session, frame->push_promise.promised_stream_id,
          NGHTTP2_STREAM_FLAG_PUSH,
          &pri_spec,
          NGHTTP2_STREAM_RESERVED,
          aux_data ?
          aux_data->stream_user_data : NULL)) {
        return NGHTTP2_ERR_NOMEM;
      }
      break;
    }
    case NGHTTP2_PING:
      framerv = nghttp2_frame_pack_ping(&session->aob.framebufs,
                                        &frame->ping);
      if(framerv < 0) {
        return framerv;
      }
      break;
    case NGHTTP2_WINDOW_UPDATE: {
      rv = nghttp2_session_predicate_window_update_send
        (session, frame->hd.stream_id);
      if(rv != 0) {
        return rv;
      }
      framerv = nghttp2_frame_pack_window_update(&session->aob.framebufs,
                                                 &frame->window_update);
      if(framerv < 0) {
        return framerv;
      }
      break;
    }
    case NGHTTP2_GOAWAY:
      if(session->goaway_flags & NGHTTP2_GOAWAY_SEND) {
        /* TODO The spec does not mandate that both endpoints have to
           exchange GOAWAY. This implementation allows receiver of
           first GOAWAY can sent its own GOAWAY to tell the remote
           peer that last-stream-id. */
        return NGHTTP2_ERR_GOAWAY_ALREADY_SENT;
      }
      framerv = nghttp2_frame_pack_goaway(&session->aob.framebufs,
                                          &frame->goaway);
      if(framerv < 0) {
        return framerv;
      }
      break;
    case NGHTTP2_ALTSVC:
      rv = nghttp2_session_predicate_altsvc_send(session, frame->hd.stream_id);
      if(rv != 0) {
        return rv;
      }

      framerv = nghttp2_frame_pack_altsvc(&session->aob.framebufs,
                                          &frame->altsvc);

      if(framerv < 0) {
        return framerv;
      }

      break;
    case NGHTTP2_BLOCKED:
      rv = nghttp2_session_predicate_blocked_send(session,
                                                  frame->hd.stream_id);
      if(rv != 0) {
        return rv;
      }

      framerv = nghttp2_frame_pack_blocked(&session->aob.framebufs,
                                           &frame->blocked);

      if(framerv < 0) {
        return framerv;
      }

      break;
    default:
      return NGHTTP2_ERR_INVALID_ARGUMENT;
    }
    return 0;
  } else if(item->frame_cat == NGHTTP2_CAT_DATA) {
    size_t next_readmax;
    nghttp2_stream *stream;
    nghttp2_private_data *data_frame;

    data_frame = nghttp2_outbound_item_get_data_frame(item);
    stream = nghttp2_session_get_stream(session, data_frame->hd.stream_id);

    if(stream) {
      assert(stream->data_item == item);
    }

    rv = nghttp2_session_predicate_data_send(session, data_frame->hd.stream_id);
    if(rv != 0) {
      int rv2;

      if(stream) {
        rv2 = nghttp2_stream_detach_data(stream, &session->ob_pq);

        if(nghttp2_is_fatal(rv2)) {
          return rv2;
        }
      }

      return rv;
    }
    /* Assuming stream is not NULL */
    assert(stream);
    next_readmax = nghttp2_session_next_data_read(session, stream);

    if(next_readmax == 0) {
      rv = session_consider_blocked(session, stream);

      if(nghttp2_is_fatal(rv)) {
        return rv;
      }

      rv = nghttp2_stream_defer_data(stream,
                                     NGHTTP2_STREAM_FLAG_DEFERRED_FLOW_CONTROL,
                                     &session->ob_pq);

      if(nghttp2_is_fatal(rv)) {
        return rv;
      }

      session->aob.item = NULL;
      nghttp2_active_outbound_item_reset(&session->aob);
      return NGHTTP2_ERR_DEFERRED;
    }
    framerv = nghttp2_session_pack_data(session,
                                        &session->aob.framebufs,
                                        next_readmax,
                                        data_frame);
    if(framerv == NGHTTP2_ERR_DEFERRED) {
      rv = nghttp2_stream_defer_data(stream, NGHTTP2_STREAM_FLAG_DEFERRED_USER,
                                     &session->ob_pq);

      if(nghttp2_is_fatal(rv)) {
        return rv;
      }

      session->aob.item = NULL;
      nghttp2_active_outbound_item_reset(&session->aob);
      return NGHTTP2_ERR_DEFERRED;
    }
    if(framerv == NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE) {
      rv = nghttp2_stream_detach_data(stream, &session->ob_pq);

      if(nghttp2_is_fatal(rv)) {
        return rv;
      }

      rv = nghttp2_session_add_rst_stream(session, data_frame->hd.stream_id,
                                          NGHTTP2_INTERNAL_ERROR);
      if(rv != 0) {
        return rv;
      }
      return framerv;
    }
    if(framerv < 0) {
      return framerv;
    }
    return 0;
  } else {
    /* Unreachable */
    assert(0);
  }
}

nghttp2_outbound_item* nghttp2_session_get_ob_pq_top
(nghttp2_session *session)
{
  return (nghttp2_outbound_item*)nghttp2_pq_top(&session->ob_pq);
}

nghttp2_outbound_item* nghttp2_session_get_next_ob_item
(nghttp2_session *session)
{
  if(nghttp2_pq_empty(&session->ob_pq)) {
    if(nghttp2_pq_empty(&session->ob_ss_pq)) {
      return NULL;
    } else {
      /* Return item only when concurrent connection limit is not
         reached */
      if(nghttp2_session_is_outgoing_concurrent_streams_max(session)) {
        return NULL;
      } else {
        return nghttp2_pq_top(&session->ob_ss_pq);
      }
    }
  } else {
    if(nghttp2_pq_empty(&session->ob_ss_pq)) {
      return nghttp2_pq_top(&session->ob_pq);
    } else {
      nghttp2_outbound_item *item, *headers_item;
      item = nghttp2_pq_top(&session->ob_pq);
      headers_item = nghttp2_pq_top(&session->ob_ss_pq);
      if(nghttp2_session_is_outgoing_concurrent_streams_max(session) ||
         item->weight > headers_item->weight ||
         (item->weight == headers_item->weight &&
          item->seq < headers_item->seq)) {
        return item;
      } else {
        return headers_item;
      }
    }
  }
}

nghttp2_outbound_item* nghttp2_session_pop_next_ob_item
(nghttp2_session *session)
{
  if(nghttp2_pq_empty(&session->ob_pq)) {
    if(nghttp2_pq_empty(&session->ob_ss_pq)) {
      return NULL;
    } else {
      /* Pop item only when concurrent connection limit is not
         reached */
      if(nghttp2_session_is_outgoing_concurrent_streams_max(session)) {
        return NULL;
      } else {
        nghttp2_outbound_item *item;
        item = nghttp2_pq_top(&session->ob_ss_pq);
        nghttp2_pq_pop(&session->ob_ss_pq);

        item->queued = 0;

        return item;
      }
    }
  } else {
    if(nghttp2_pq_empty(&session->ob_ss_pq)) {
      nghttp2_outbound_item *item;
      item = nghttp2_pq_top(&session->ob_pq);
      nghttp2_pq_pop(&session->ob_pq);

      item->queued = 0;

      return item;
    } else {
      nghttp2_outbound_item *item, *headers_item;
      item = nghttp2_pq_top(&session->ob_pq);
      headers_item = nghttp2_pq_top(&session->ob_ss_pq);
      if(nghttp2_session_is_outgoing_concurrent_streams_max(session) ||
         item->weight > headers_item->weight ||
         (item->weight == headers_item->weight &&
          item->seq < headers_item->seq)) {
        nghttp2_pq_pop(&session->ob_pq);

        item->queued = 0;

        return item;
      } else {
        nghttp2_pq_pop(&session->ob_ss_pq);

        headers_item->queued = 0;

        return headers_item;
      }
    }
  }
}

static int session_call_before_frame_send(nghttp2_session *session,
                                          nghttp2_frame *frame)
{
  int rv;
  if(session->callbacks.before_frame_send_callback) {
    rv = session->callbacks.before_frame_send_callback(session, frame,
                                                       session->user_data);
    if(rv != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

static int session_call_on_frame_send(nghttp2_session *session,
                                      nghttp2_frame *frame)
{
  int rv;
  if(session->callbacks.on_frame_send_callback) {
    rv = session->callbacks.on_frame_send_callback(session, frame,
                                                   session->user_data);
    if(rv != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

static void outbound_item_cycle_weight(nghttp2_outbound_item *item,
                                       int32_t ini_weight)
{
  if(item->weight == NGHTTP2_MIN_WEIGHT || item->weight > ini_weight) {
    item->weight = ini_weight;
  } else {
    --item->weight;
  }
}

/*
 * Called after a frame is sent.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *     The callback function failed.
 */
static int nghttp2_session_after_frame_sent(nghttp2_session *session)
{
  int rv;
  nghttp2_active_outbound_item *aob = &session->aob;
  nghttp2_outbound_item *item = aob->item;
  nghttp2_bufs *framebufs = &aob->framebufs;

  if(item->frame_cat == NGHTTP2_CAT_CTRL) {
    nghttp2_frame *frame;

    frame = nghttp2_outbound_item_get_ctrl_frame(item);

    if(frame->hd.type == NGHTTP2_HEADERS ||
       frame->hd.type == NGHTTP2_PUSH_PROMISE) {

      if(nghttp2_bufs_next_present(framebufs)) {
        framebufs->cur = framebufs->cur->next;

        DEBUGF(fprintf(stderr, "send: next CONTINUATION frame, %zu bytes\n",
                       nghttp2_buf_len(&framebufs->cur->buf)));

        return 0;
      }
    }
    rv = session_call_on_frame_send(session, frame);
    if(nghttp2_is_fatal(rv)) {
      return rv;
    }
    switch(frame->hd.type) {
    case NGHTTP2_HEADERS: {
      nghttp2_headers_aux_data *aux_data;
      nghttp2_stream *stream =
        nghttp2_session_get_stream(session, frame->hd.stream_id);
      if(!stream) {
        break;
      }
      switch(frame->headers.cat) {
      case NGHTTP2_HCAT_REQUEST: {
        stream->state = NGHTTP2_STREAM_OPENING;
        if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
          nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
        }
        rv = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }
        /* We assume aux_data is a pointer to nghttp2_headers_aux_data */
        aux_data = (nghttp2_headers_aux_data*)item->aux_data;
        if(aux_data && aux_data->data_prd) {
          /* nghttp2_submit_data() makes a copy of aux_data->data_prd */
          rv = nghttp2_submit_data(session, NGHTTP2_FLAG_END_STREAM,
                                   frame->hd.stream_id, aux_data->data_prd);
          if(nghttp2_is_fatal(rv)) {
            return rv;
          }
          /* TODO nghttp2_submit_data() may fail if stream has already
             DATA frame item.  We might have to handle it here. */
        }
        break;
      }
      case NGHTTP2_HCAT_PUSH_RESPONSE:
        ++session->num_outgoing_streams;
        /* Fall through */
      case NGHTTP2_HCAT_RESPONSE:
        stream->state = NGHTTP2_STREAM_OPENED;
        if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
          nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
        }
        rv = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }
        /* We assume aux_data is a pointer to nghttp2_headers_aux_data */
        aux_data = (nghttp2_headers_aux_data*)item->aux_data;
        if(aux_data && aux_data->data_prd) {
          rv = nghttp2_submit_data(session, NGHTTP2_FLAG_END_STREAM,
                                   frame->hd.stream_id, aux_data->data_prd);
          if(nghttp2_is_fatal(rv)) {
            return rv;
          }
          /* If rv is not fatal, the only possible error is closed
             stream, so we have nothing to do here. */
        }
        break;
      case NGHTTP2_HCAT_HEADERS:
        if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
          nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
        }
        rv = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }
        break;
      }
      break;
    }
    case NGHTTP2_PRIORITY: {
      nghttp2_stream *stream;
      stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
      if(!stream) {
        break;
      }
      /* Only update priority of the stream, only if it is not pushed
         stream and is initiated by local peer, or it is pushed stream
         and is initiated by remote peer */
      if(((stream->flags & NGHTTP2_STREAM_FLAG_PUSH) == 0 &&
          nghttp2_session_is_my_stream_id(session, frame->hd.stream_id)) ||
         ((stream->flags & NGHTTP2_STREAM_FLAG_PUSH) &&
          !nghttp2_session_is_my_stream_id(session, frame->hd.stream_id))) {
        rv = nghttp2_session_reprioritize_stream(session, stream,
                                                 &frame->priority.pri_spec);

        if(nghttp2_is_fatal(rv)) {
          return rv;
        }
      }
      break;
    }
    case NGHTTP2_RST_STREAM:
      rv = nghttp2_session_close_stream(session, frame->hd.stream_id,
                                       frame->rst_stream.error_code);
      if(nghttp2_is_fatal(rv)) {
        return rv;
      }
      break;
    case NGHTTP2_SETTINGS:
      /* nothing to do */
      break;
    case NGHTTP2_PUSH_PROMISE:
      /* nothing to do */
      break;
    case NGHTTP2_PING:
      /* nothing to do */
      break;
    case NGHTTP2_GOAWAY:
      session->goaway_flags |= NGHTTP2_GOAWAY_SEND;
      break;
    case NGHTTP2_WINDOW_UPDATE:
      /* nothing to do */
      break;
    case NGHTTP2_ALTSVC:
      /* nothing to do */
      break;
    case NGHTTP2_BLOCKED:
      /* nothing to do */
      break;
    }
    nghttp2_active_outbound_item_reset(&session->aob);
    return 0;
  } else if(item->frame_cat == NGHTTP2_CAT_DATA) {
    nghttp2_private_data *data_frame;
    nghttp2_outbound_item* next_item;
    nghttp2_stream *stream;

    data_frame = nghttp2_outbound_item_get_data_frame(aob->item);
    stream = nghttp2_session_get_stream(session, data_frame->hd.stream_id);
    /* We update flow control window after a frame was completely
       sent. This is possible because we choose payload length not to
       exceed the window */
    session->remote_window_size -= data_frame->hd.length;
    if(stream) {
      stream->remote_window_size -= data_frame->hd.length;
    }

    if(session->callbacks.on_frame_send_callback) {
      nghttp2_frame public_data_frame;
      nghttp2_frame_data_init(&public_data_frame.data, data_frame);
      rv = session_call_on_frame_send(session, &public_data_frame);
      if(nghttp2_is_fatal(rv)) {
        return rv;
      }
    }

    if(stream && data_frame->eof) {
      rv = nghttp2_stream_detach_data(stream, &session->ob_pq);

      if(nghttp2_is_fatal(rv)) {
        return rv;
      }

      if(data_frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {

        nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);

        rv = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }
        /* stream may be NULL if it was closed */
      }
    }
    /* If session is closed or RST_STREAM was queued, we won't send
       further data. */
    if(data_frame->eof ||
       nghttp2_session_predicate_data_send(session,
                                           data_frame->hd.stream_id) != 0) {

      nghttp2_active_outbound_item_reset(aob);

      return 0;
    }

    /* Assuming stream is not NULL */
    assert(stream);
    next_item = nghttp2_session_get_next_ob_item(session);

    outbound_item_cycle_weight(aob->item, stream->effective_weight);

    /* If priority of this stream is higher or equal to other stream
       waiting at the top of the queue, we continue to send this
       data. */
    if(stream->dpri == NGHTTP2_STREAM_DPRI_TOP &&
       (next_item == NULL || aob->item->weight > next_item->weight)) {
      size_t next_readmax;

      next_readmax = nghttp2_session_next_data_read(session, stream);

      if(next_readmax == 0) {
        rv = session_consider_blocked(session, stream);

        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        rv = nghttp2_stream_defer_data
          (stream, NGHTTP2_STREAM_FLAG_DEFERRED_FLOW_CONTROL, &session->ob_pq);

        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        aob->item = NULL;
        nghttp2_active_outbound_item_reset(aob);

        return 0;
      }

      nghttp2_bufs_reset(framebufs);

      rv = nghttp2_session_pack_data(session, framebufs, next_readmax,
                                     data_frame);
      if(nghttp2_is_fatal(rv)) {
        return rv;
      }
      if(rv == NGHTTP2_ERR_DEFERRED) {
        rv = nghttp2_stream_defer_data(stream,
                                       NGHTTP2_STREAM_FLAG_DEFERRED_USER,
                                       &session->ob_pq);

        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        aob->item = NULL;
        nghttp2_active_outbound_item_reset(aob);

        return 0;
      }
      if(rv == NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE) {
        /* Stop DATA frame chain and issue RST_STREAM to close the
           stream.  We don't return
           NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE intentionally. */
        rv = nghttp2_session_add_rst_stream(session,
                                            data_frame->hd.stream_id,
                                            NGHTTP2_INTERNAL_ERROR);

        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        rv = nghttp2_stream_detach_data(stream, &session->ob_pq);

        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        nghttp2_active_outbound_item_reset(aob);

        return 0;
      }
      assert(rv == 0);

      return 0;
    }
    /* Update seq to interleave other streams with the same
       priority. */
    aob->item->seq = session->next_seq++;

    if(stream->dpri == NGHTTP2_STREAM_DPRI_TOP) {
      rv = nghttp2_pq_push(&session->ob_pq, aob->item);

      if(nghttp2_is_fatal(rv)) {
        return rv;
      }

      aob->item->queued = 1;
    }

    aob->item = NULL;
    nghttp2_active_outbound_item_reset(&session->aob);
    return 0;
  }
  /* Unreachable */
  assert(0);
}

ssize_t nghttp2_session_mem_send(nghttp2_session *session,
                                 const uint8_t **data_ptr)
{
  int rv;
  nghttp2_active_outbound_item *aob;
  nghttp2_bufs *framebufs;

  aob = &session->aob;
  framebufs = &aob->framebufs;

  *data_ptr = NULL;
  for(;;) {
    switch(aob->state) {
    case NGHTTP2_OB_POP_ITEM: {
      nghttp2_outbound_item *item;

      item = nghttp2_session_pop_next_ob_item(session);
      if(item == NULL) {
        return 0;
      }

      if(item->frame_cat == NGHTTP2_CAT_DATA) {
        nghttp2_private_data *data;
        nghttp2_stream *stream;

        data = nghttp2_outbound_item_get_data_frame(item);

        stream = nghttp2_session_get_stream(session, data->hd.stream_id);

        if(stream && stream->dpri != NGHTTP2_STREAM_DPRI_TOP) {
          /* We have DATA with higher priority in queue within the
             same dependency tree. */
          break;
        }
      }

      rv = nghttp2_session_prep_frame(session, item);
      if(rv == NGHTTP2_ERR_DEFERRED) {
        DEBUGF(fprintf(stderr, "send: frame transmission deferred\n"));
        break;
      }
      if(rv < 0) {
        DEBUGF(fprintf(stderr, "send: frame preparation failed with %s\n",
                       nghttp2_strerror(rv)));
        /* TODO If the error comes from compressor, the connection
           must be closed. */
        if(item->frame_cat == NGHTTP2_CAT_CTRL &&
           session->callbacks.on_frame_not_send_callback &&
           nghttp2_is_non_fatal(rv)) {
          /* The library is responsible for the transmission of
             WINDOW_UPDATE frame, so we don't call error callback for
             it. */
          nghttp2_frame *frame = nghttp2_outbound_item_get_ctrl_frame(item);
          if(frame->hd.type != NGHTTP2_WINDOW_UPDATE) {
            if(session->callbacks.on_frame_not_send_callback
               (session, frame, rv, session->user_data) != 0) {

              nghttp2_outbound_item_free(item);
              free(item);

              return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
          }
        }
        nghttp2_outbound_item_free(item);
        free(item);
        nghttp2_active_outbound_item_reset(aob);

        if(rv == NGHTTP2_ERR_HEADER_COMP) {
          /* If header compression error occurred, should terminiate
             connection. */
          rv = nghttp2_session_terminate_session(session,
                                                 NGHTTP2_INTERNAL_ERROR);
        }
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }
        break;
      }

      aob->item = item;

      nghttp2_bufs_rewind(framebufs);

      if(item->frame_cat == NGHTTP2_CAT_CTRL) {
        nghttp2_frame *frame;

        frame = nghttp2_outbound_item_get_ctrl_frame(item);

        DEBUGF(fprintf(stderr,
                       "send: next frame: payloadlen=%zu, type=%u, "
                       "flags=0x%02x, stream_id=%d\n",
                       frame->hd.length, frame->hd.type, frame->hd.flags,
                       frame->hd.stream_id));

        rv = session_call_before_frame_send(session, frame);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }
      } else {
        DEBUGF(fprintf(stderr, "send: next frame: DATA\n"));
      }

      DEBUGF(fprintf(stderr,
                     "send: start transmitting frame type=%u, length=%zd\n",
                     framebufs->cur->buf.pos[2],
                     framebufs->cur->buf.last - framebufs->cur->buf.pos));

      aob->state = NGHTTP2_OB_SEND_DATA;

      break;
    }
    case NGHTTP2_OB_SEND_DATA: {
      size_t datalen;
      nghttp2_buf *buf;

      buf = &framebufs->cur->buf;

      if(buf->pos == buf->last) {
        DEBUGF(fprintf(stderr, "send: end transmission of a frame\n"));

        /* Frame has completely sent */
        rv = nghttp2_session_after_frame_sent(session);
        if(rv < 0) {
          /* FATAL */
          assert(nghttp2_is_fatal(rv));
          return rv;
        }
        /* We have already adjusted the next state */
        break;
      }

      *data_ptr = buf->pos;
      datalen = nghttp2_buf_len(buf);

      /* We increment the offset here. If send_callback does not send
         everything, we will adjust it. */
      buf->pos += datalen;

      return datalen;
    }
    }
  }
}

int nghttp2_session_send(nghttp2_session *session)
{
  const uint8_t *data;
  ssize_t datalen;
  ssize_t sentlen;
  nghttp2_bufs *framebufs;

  framebufs = &session->aob.framebufs;

  for(;;) {
    datalen = nghttp2_session_mem_send(session, &data);
    if(datalen <= 0) {
      return datalen;
    }
    sentlen = session->callbacks.send_callback(session, data, datalen, 0,
                                               session->user_data);
    if(sentlen < 0) {
      if(sentlen == NGHTTP2_ERR_WOULDBLOCK) {
        /* Transmission canceled. Rewind the offset */
        framebufs->cur->buf.pos -= datalen;

        return 0;
      }
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    /* Rewind the offset to the amount of unsent bytes */
    framebufs->cur->buf.pos -= datalen - sentlen;
  }

  return 0;
}

static ssize_t nghttp2_recv(nghttp2_session *session, uint8_t *buf, size_t len)
{
  ssize_t rv;
  rv = session->callbacks.recv_callback(session, buf, len, 0,
                                        session->user_data);
  if(rv > 0) {
    if((size_t)rv > len) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  } else if(rv < 0 && rv != NGHTTP2_ERR_WOULDBLOCK && rv != NGHTTP2_ERR_EOF) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  return rv;
}

static int nghttp2_session_call_on_frame_received
(nghttp2_session *session, nghttp2_frame *frame)
{
  int rv;
  if(session->callbacks.on_frame_recv_callback) {
    rv = session->callbacks.on_frame_recv_callback(session, frame,
                                                   session->user_data);
    if(rv != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

static int session_call_on_begin_headers(nghttp2_session *session,
                                         nghttp2_frame *frame)
{
  int rv;
  DEBUGF(fprintf(stderr, "recv: call on_begin_headers callback stream_id=%d\n",
                 frame->hd.stream_id));
  if(session->callbacks.on_begin_headers_callback) {
    rv = session->callbacks.on_begin_headers_callback(session, frame,
                                                      session->user_data);
    if(rv != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

static int session_call_on_header(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  const nghttp2_nv *nv)
{
  int rv;
  if(session->callbacks.on_header_callback) {
    rv = session->callbacks.on_header_callback(session, frame,
                                               nv->name, nv->namelen,
                                               nv->value, nv->valuelen,
                                               nv->flags,
                                               session->user_data);
    if(rv == NGHTTP2_ERR_PAUSE ||
       rv == NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE) {
      return rv;
    }
    if(rv != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

/*
 * Checks whether received stream_id is valid.
 * This function returns 1 if it succeeds, or 0.
 */
static int nghttp2_session_is_new_peer_stream_id(nghttp2_session *session,
                                                 int32_t stream_id)
{
  if(stream_id == 0 || session->last_recv_stream_id >= stream_id) {
    return 0;
  }
  if(session->server) {
    return stream_id % 2 == 1;
  } else {
    return stream_id % 2 == 0;
  }
}

static int session_detect_idle_stream(nghttp2_session *session,
                                      int32_t stream_id)
{
  /* Assume that stream object with stream_id does not exist */
  if(nghttp2_session_is_my_stream_id(session, stream_id)) {
    if(session->next_stream_id <= (uint32_t)stream_id) {
      return 1;
    }
    return 0;
  }
  if(nghttp2_session_is_new_peer_stream_id(session, stream_id)) {
    return 1;
  }
  return 0;
}

/*
 * Handles frame size error.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *   Out of memory.
 */
static int session_handle_frame_size_error(nghttp2_session *session,
                                           nghttp2_frame *frame)
{
  /* TODO Currently no callback is called for this error, because we
     call this callback before reading any payload */
  return nghttp2_session_terminate_session(session, NGHTTP2_FRAME_SIZE_ERROR);
}

static int nghttp2_session_handle_invalid_stream
(nghttp2_session *session,
 nghttp2_frame *frame,
 nghttp2_error_code error_code)
{
  int rv;
  rv = nghttp2_session_add_rst_stream(session, frame->hd.stream_id, error_code);
  if(rv != 0) {
    return rv;
  }
  if(session->callbacks.on_invalid_frame_recv_callback) {
    if(session->callbacks.on_invalid_frame_recv_callback
       (session, frame, error_code, session->user_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

static int nghttp2_session_inflate_handle_invalid_stream
(nghttp2_session *session,
 nghttp2_frame *frame,
 nghttp2_error_code error_code)
{
  int rv;
  rv = nghttp2_session_handle_invalid_stream(session, frame, error_code);
  if(nghttp2_is_fatal(rv)) {
    return rv;
  }
  return NGHTTP2_ERR_IGN_HEADER_BLOCK;
}

/*
 * Handles invalid frame which causes connection error.
 */
static int nghttp2_session_handle_invalid_connection
(nghttp2_session *session,
 nghttp2_frame *frame,
 nghttp2_error_code error_code)
{
  if(session->callbacks.on_invalid_frame_recv_callback) {
    if(session->callbacks.on_invalid_frame_recv_callback
       (session, frame, error_code, session->user_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return nghttp2_session_terminate_session(session, error_code);
}

static int nghttp2_session_inflate_handle_invalid_connection
(nghttp2_session *session,
 nghttp2_frame *frame,
 nghttp2_error_code error_code)
{
  int rv;
  rv = nghttp2_session_handle_invalid_connection(session, frame, error_code);
  if(nghttp2_is_fatal(rv)) {
    return rv;
  }
  return NGHTTP2_ERR_IGN_HEADER_BLOCK;
}

/*
 * Inflates header block in the memory pointed by |in| with |inlen|
 * bytes. If this function returns NGHTTP2_ERR_PAUSE, the caller must
 * call this function again, until it returns 0 or one of negative
 * error code.  If |call_header_cb| is zero, the on_header_callback
 * are not invoked and the function never return NGHTTP2_ERR_PAUSE. If
 * the given |in| is the last chunk of header block, the |final| must
 * be nonzero. If header block is successfully processed (which is
 * indicated by the return value 0, NGHTTP2_ERR_PAUSE or
 * NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE), the number of processed
 * input bytes is assigned to the |*readlen_ptr|.
 *
 * This function return 0 if it succeeds, or one of the negative error
 * codes:
 *
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *     The callback function failed.
 * NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE
 *     The callback returns this error code, indicating that this
 *     stream should be RST_STREAMed.
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_PAUSE
 *     The callback function returned NGHTTP2_ERR_PAUSE
 * NGHTTP2_ERR_HEADER_COMP
 *     Header decompression failed
 */
static ssize_t inflate_header_block(nghttp2_session *session,
                                    nghttp2_frame *frame,
                                    size_t *readlen_ptr,
                                    uint8_t *in, size_t inlen,
                                    int final, int call_header_cb)
{
  ssize_t rv;
  int inflate_flags;
  nghttp2_nv nv;
  nghttp2_stream *stream;

  *readlen_ptr = 0;

  DEBUGF(fprintf(stderr, "recv: decoding header block %zu bytes\n", inlen));
  for(;;) {
    inflate_flags = 0;
    rv = nghttp2_hd_inflate_hd(&session->hd_inflater, &nv, &inflate_flags,
                               in, inlen, final);
    if(nghttp2_is_fatal(rv)) {
      return rv;
    }
    if(rv < 0) {
      if(session->iframe.state == NGHTTP2_IB_READ_HEADER_BLOCK) {
        stream = nghttp2_session_get_stream(session, frame->hd.stream_id);

        if(stream && stream->state != NGHTTP2_STREAM_CLOSING) {
          /* Adding RST_STREAM here is very important. It prevents
             from invoking subsequent callbacks for the same stream
             ID. */
          rv = nghttp2_session_add_rst_stream(session, frame->hd.stream_id,
                                              NGHTTP2_COMPRESSION_ERROR);

          if(nghttp2_is_fatal(rv)) {
            return rv;
          }
        }
      }
      rv = nghttp2_session_terminate_session(session,
                                             NGHTTP2_COMPRESSION_ERROR);
      if(nghttp2_is_fatal(rv)) {
        return rv;
      }

      return NGHTTP2_ERR_HEADER_COMP;
    }
    in += rv;
    inlen -= rv;
    *readlen_ptr += rv;
    if(call_header_cb && (inflate_flags & NGHTTP2_HD_INFLATE_EMIT)) {
      rv = session_call_on_header(session, frame, &nv);
      /* This handles NGHTTP2_ERR_PAUSE and
         NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE as well */
      if(rv != 0) {
        return rv;
      }
    }
    if(inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
      nghttp2_hd_inflate_end_headers(&session->hd_inflater);
      break;
    }
    if((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && inlen == 0) {
      break;
    }
  }
  return 0;
}

/*
 * Decompress header blocks of incoming request HEADERS and also call
 * additional callbacks. This function can be called again if this
 * function returns NGHTTP2_ERR_PAUSE.
 *
 * This function returns 0 if it succeeds, or one of negative error
 * codes:
 *
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *     The callback function failed.
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_end_request_headers_received(nghttp2_session *session,
                                                 nghttp2_frame *frame,
                                                 nghttp2_stream *stream)
{
  if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
  }
  /* Here we assume that stream is not shutdown in NGHTTP2_SHUT_WR */
  return 0;
}

/*
 * Decompress header blocks of incoming (push-)response HEADERS and
 * also call additional callbacks. This function can be called again
 * if this function returns NGHTTP2_ERR_PAUSE.
 *
 * This function returns 0 if it succeeds, or one of negative error
 * codes:
 *
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *     The callback function failed.
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_end_response_headers_received(nghttp2_session *session,
                                                  nghttp2_frame *frame,
                                                  nghttp2_stream *stream)
{
  int rv;
  if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    /* This is the last frame of this stream, so disallow
       further receptions. */
    nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
    rv = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
    if(nghttp2_is_fatal(rv)) {
      return rv;
    }
  }
  return 0;
}

/*
 * Decompress header blocks of incoming HEADERS and also call
 * additional callbacks. This function can be called again if this
 * function returns NGHTTP2_ERR_PAUSE.
 *
 * This function returns 0 if it succeeds, or one of negative error
 * codes:
 *
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *     The callback function failed.
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_end_headers_received(nghttp2_session *session,
                                         nghttp2_frame *frame,
                                         nghttp2_stream *stream)
{
  int rv;
  if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    if(!nghttp2_session_is_my_stream_id(session, frame->hd.stream_id)) {
    }
    nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
    rv = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
    if(nghttp2_is_fatal(rv)) {
      return rv;
    }
  }
  return 0;
}

static int session_after_header_block_received(nghttp2_session *session)
{
  int rv;
  nghttp2_frame *frame = &session->iframe.frame;
  nghttp2_stream *stream;

  /* We don't call on_frame_recv_callback if stream has been closed
     already or being closed. */
  stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
  if(!stream || stream->state == NGHTTP2_STREAM_CLOSING) {
    return 0;
  }

  rv = nghttp2_session_call_on_frame_received(session, frame);
  if(nghttp2_is_fatal(rv)) {
    return rv;
  }

  if(frame->hd.type !=  NGHTTP2_HEADERS) {
    return 0;
  }

  switch(frame->headers.cat) {
  case NGHTTP2_HCAT_REQUEST:
    return nghttp2_session_end_request_headers_received
      (session, frame, stream);
  case NGHTTP2_HCAT_RESPONSE:
  case NGHTTP2_HCAT_PUSH_RESPONSE:
    return nghttp2_session_end_response_headers_received
      (session, frame, stream);
  case NGHTTP2_HCAT_HEADERS:
    return nghttp2_session_end_headers_received(session, frame, stream);
  default:
    assert(0);
  }
  return 0;
}

int nghttp2_session_on_request_headers_received(nghttp2_session *session,
                                                nghttp2_frame *frame)
{
  int rv = 0;
  nghttp2_stream *stream;
  if(frame->hd.stream_id == 0) {
    return nghttp2_session_inflate_handle_invalid_connection
      (session, frame, NGHTTP2_PROTOCOL_ERROR);
  }
  if(session->goaway_flags) {
    /* We don't accept new stream after GOAWAY is sent or received. */
    return NGHTTP2_ERR_IGN_HEADER_BLOCK;
  }
  if(!nghttp2_session_is_new_peer_stream_id(session, frame->hd.stream_id)) {
    /* The spec says if an endpoint receives a HEADERS with invalid
       stream ID, it MUST issue connection error with error code
       PROTOCOL_ERROR */
    return nghttp2_session_inflate_handle_invalid_connection
      (session, frame, NGHTTP2_PROTOCOL_ERROR);
  }
  session->last_recv_stream_id = frame->hd.stream_id;

  if(nghttp2_session_is_incoming_concurrent_streams_max(session)) {
    return nghttp2_session_inflate_handle_invalid_connection
      (session, frame, NGHTTP2_ENHANCE_YOUR_CALM);
  }

  if(frame->headers.pri_spec.stream_id == frame->hd.stream_id) {
    return nghttp2_session_inflate_handle_invalid_connection
      (session, frame, NGHTTP2_PROTOCOL_ERROR);
  }

  if(nghttp2_session_is_incoming_concurrent_streams_pending_max(session)) {
    return nghttp2_session_inflate_handle_invalid_stream
      (session, frame, NGHTTP2_REFUSED_STREAM);
  }

  stream = nghttp2_session_open_stream(session,
                                       frame->hd.stream_id,
                                       NGHTTP2_STREAM_FLAG_NONE,
                                       &frame->headers.pri_spec,
                                       NGHTTP2_STREAM_OPENING,
                                       NULL);
  if(!stream) {
    return NGHTTP2_ERR_NOMEM;
  }
  session->last_proc_stream_id = session->last_recv_stream_id;
  rv = session_call_on_begin_headers(session, frame);
  if(rv != 0) {
    return rv;
  }
  return 0;
}

int nghttp2_session_on_response_headers_received(nghttp2_session *session,
                                                 nghttp2_frame *frame,
                                                 nghttp2_stream *stream)
{
  int rv;
  /* This function is only called if stream->state ==
     NGHTTP2_STREAM_OPENING and stream_id is local side initiated. */
  assert(stream->state == NGHTTP2_STREAM_OPENING &&
         nghttp2_session_is_my_stream_id(session, frame->hd.stream_id));
  if(frame->hd.stream_id == 0) {
    return nghttp2_session_inflate_handle_invalid_connection
      (session, frame, NGHTTP2_PROTOCOL_ERROR);
  }
  if(stream->shut_flags & NGHTTP2_SHUT_RD) {
    /* half closed (remote): from the spec:

       If an endpoint receives additional frames for a stream that is
       in this state it MUST respond with a stream error (Section
       5.4.2) of type STREAM_CLOSED.
    */
    return nghttp2_session_inflate_handle_invalid_stream
      (session, frame, NGHTTP2_STREAM_CLOSED);
  }
  stream->state = NGHTTP2_STREAM_OPENED;
  rv = session_call_on_begin_headers(session, frame);
  if(rv != 0) {
    return rv;
  }
  return 0;
}

int nghttp2_session_on_push_response_headers_received(nghttp2_session *session,
                                                      nghttp2_frame *frame,
                                                      nghttp2_stream *stream)
{
  int rv = 0;
  assert(stream->state == NGHTTP2_STREAM_RESERVED);
  if(frame->hd.stream_id == 0) {
    return nghttp2_session_inflate_handle_invalid_connection
      (session, frame, NGHTTP2_PROTOCOL_ERROR);
  }
  if(session->goaway_flags) {
    /* We don't accept new stream after GOAWAY is sent or received. */
    return NGHTTP2_ERR_IGN_HEADER_BLOCK;
  }

  if(nghttp2_session_is_incoming_concurrent_streams_max(session)) {
    return nghttp2_session_inflate_handle_invalid_connection
      (session, frame, NGHTTP2_ENHANCE_YOUR_CALM);
  }
  if(nghttp2_session_is_incoming_concurrent_streams_pending_max(session)) {
    return nghttp2_session_inflate_handle_invalid_stream
      (session, frame, NGHTTP2_REFUSED_STREAM);
  }

  nghttp2_stream_promise_fulfilled(stream);
  ++session->num_incoming_streams;
  rv = session_call_on_begin_headers(session, frame);
  if(rv != 0) {
    return rv;
  }
  return 0;
}

int nghttp2_session_on_headers_received(nghttp2_session *session,
                                        nghttp2_frame *frame,
                                        nghttp2_stream *stream)
{
  int rv = 0;
  if(frame->hd.stream_id == 0) {
    return nghttp2_session_inflate_handle_invalid_connection
      (session, frame, NGHTTP2_PROTOCOL_ERROR);
  }
  if(stream->state == NGHTTP2_STREAM_RESERVED) {
    /* reserved. The valid push response HEADERS is processed by
       nghttp2_session_on_push_response_headers_received(). This
       generic HEADERS is called invalid cases for HEADERS against
       reserved state. */
    return nghttp2_session_inflate_handle_invalid_connection
      (session, frame, NGHTTP2_PROTOCOL_ERROR);
  }
  if((stream->shut_flags & NGHTTP2_SHUT_RD)) {
    /* half closed (remote): from the spec:

       If an endpoint receives additional frames for a stream that is
       in this state it MUST respond with a stream error (Section
       5.4.2) of type STREAM_CLOSED.
    */
    return nghttp2_session_inflate_handle_invalid_stream
      (session, frame, NGHTTP2_STREAM_CLOSED);
  }
  if(nghttp2_session_is_my_stream_id(session, frame->hd.stream_id)) {
    if(stream->state == NGHTTP2_STREAM_OPENED) {
      rv = session_call_on_begin_headers(session, frame);
      if(rv != 0) {
        return rv;
      }
      return 0;
    } else if(stream->state == NGHTTP2_STREAM_CLOSING) {
      /* This is race condition. NGHTTP2_STREAM_CLOSING indicates
         that we queued RST_STREAM but it has not been sent. It will
         eventually sent, so we just ignore this frame. */
      return NGHTTP2_ERR_IGN_HEADER_BLOCK;
    } else {
      return nghttp2_session_inflate_handle_invalid_stream
        (session, frame, NGHTTP2_PROTOCOL_ERROR);
    }
  }
  /* If this is remote peer initiated stream, it is OK unless it
     has sent END_STREAM frame already. But if stream is in
     NGHTTP2_STREAM_CLOSING, we discard the frame. This is a race
     condition. */
  if(stream->state != NGHTTP2_STREAM_CLOSING) {
    rv = session_call_on_begin_headers(session, frame);
    if(rv != 0) {
      return rv;
    }
    return 0;
  }
  return NGHTTP2_ERR_IGN_HEADER_BLOCK;
}

static int session_process_headers_frame(nghttp2_session *session)
{
  int rv;
  nghttp2_inbound_frame *iframe = &session->iframe;
  nghttp2_frame *frame = &iframe->frame;
  nghttp2_stream *stream;

  rv = nghttp2_frame_unpack_headers_payload(&frame->headers,
                                            iframe->sbuf.pos,
                                            nghttp2_buf_len(&iframe->sbuf));

  if(rv != 0) {
    return nghttp2_session_terminate_session(session, NGHTTP2_PROTOCOL_ERROR);
  }
  stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
  if(!stream) {
    frame->headers.cat = NGHTTP2_HCAT_REQUEST;
    return nghttp2_session_on_request_headers_received(session, frame);
  }

  if(nghttp2_session_is_my_stream_id(session, frame->hd.stream_id)) {
    if(stream->state == NGHTTP2_STREAM_OPENING) {
      frame->headers.cat = NGHTTP2_HCAT_RESPONSE;
      return nghttp2_session_on_response_headers_received(session, frame,
                                                          stream);
    }
    frame->headers.cat = NGHTTP2_HCAT_HEADERS;
    return nghttp2_session_on_headers_received(session, frame, stream);
  }
  if(stream->state == NGHTTP2_STREAM_RESERVED) {
    frame->headers.cat = NGHTTP2_HCAT_PUSH_RESPONSE;
    return nghttp2_session_on_push_response_headers_received(session, frame,
                                                             stream);
  }
  frame->headers.cat = NGHTTP2_HCAT_HEADERS;
  return nghttp2_session_on_headers_received(session, frame, stream);
}

int nghttp2_session_on_priority_received(nghttp2_session *session,
                                         nghttp2_frame *frame)
{
  int rv;
  nghttp2_stream *stream;

  if(frame->hd.stream_id == 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
  if(!stream) {
    if(session_detect_idle_stream(session, frame->hd.stream_id)) {
      return nghttp2_session_handle_invalid_connection(session, frame,
                                                       NGHTTP2_PROTOCOL_ERROR);
    }
    return 0;
  }
  if(state_reserved_remote(session, stream)) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  /* Only update priority of the stream, only if it is not pushed
     stream and is initiated by remote peer, or it is pushed stream
     and is initiated by local peer */
  if(((stream->flags & NGHTTP2_STREAM_FLAG_PUSH) == 0 &&
      !nghttp2_session_is_my_stream_id(session, frame->hd.stream_id)) ||
     ((stream->flags & NGHTTP2_STREAM_FLAG_PUSH) &&
      nghttp2_session_is_my_stream_id(session, frame->hd.stream_id))) {

    rv = nghttp2_session_reprioritize_stream(session, stream,
                                             &frame->priority.pri_spec);

    if(nghttp2_is_fatal(rv)) {
      return rv;
    }
  }
  return nghttp2_session_call_on_frame_received(session, frame);
}

static int session_process_priority_frame(nghttp2_session *session)
{
  nghttp2_inbound_frame *iframe = &session->iframe;
  nghttp2_frame *frame = &iframe->frame;

  nghttp2_frame_unpack_priority_payload(&frame->priority,
                                        iframe->sbuf.pos,
                                        nghttp2_buf_len(&iframe->sbuf));

  return nghttp2_session_on_priority_received(session, frame);
}

int nghttp2_session_on_rst_stream_received(nghttp2_session *session,
                                           nghttp2_frame *frame)
{
  int rv;
  nghttp2_stream *stream;
  if(frame->hd.stream_id == 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
  if(!stream) {
    if(session_detect_idle_stream(session, frame->hd.stream_id)) {
      return nghttp2_session_handle_invalid_connection(session, frame,
                                                       NGHTTP2_PROTOCOL_ERROR);
    }
  }

  rv = nghttp2_session_call_on_frame_received(session, frame);
  if(rv != 0) {
    return rv;
  }
  rv = nghttp2_session_close_stream(session, frame->hd.stream_id,
                                    frame->rst_stream.error_code);
  if(nghttp2_is_fatal(rv)) {
    return rv;
  }
  return 0;
}

static int session_process_rst_stream_frame(nghttp2_session *session)
{
  nghttp2_inbound_frame *iframe = &session->iframe;
  nghttp2_frame *frame = &iframe->frame;

  nghttp2_frame_unpack_rst_stream_payload(&frame->rst_stream,
                                          iframe->sbuf.pos,
                                          nghttp2_buf_len(&iframe->sbuf));

  return nghttp2_session_on_rst_stream_received(session, frame);
}

static int nghttp2_update_remote_initial_window_size_func
(nghttp2_map_entry *entry, void *ptr)
{
  int rv;
  nghttp2_update_window_size_arg *arg;
  nghttp2_stream *stream;

  arg = (nghttp2_update_window_size_arg*)ptr;
  stream = (nghttp2_stream*)entry;

  rv = nghttp2_stream_update_remote_initial_window_size(stream,
                                                        arg->new_window_size,
                                                        arg->old_window_size);
  if(rv != 0) {
    return nghttp2_session_terminate_session(arg->session,
                                             NGHTTP2_FLOW_CONTROL_ERROR);
  }

  if(stream->remote_window_size > 0) {
    stream->blocked_sent = 0;
  }

  /* If window size gets positive, push deferred DATA frame to
     outbound queue. */
  if(nghttp2_stream_check_deferred_by_flow_control(stream) &&
     stream->remote_window_size > 0 &&
     arg->session->remote_window_size > 0) {

    rv = nghttp2_stream_resume_deferred_data(stream, &arg->session->ob_pq);

    if(nghttp2_is_fatal(rv)) {
      return rv;
    }
  }
  return 0;
}

/*
 * Updates the remote initial window size of all active streams.  If
 * error occurs, all streams may not be updated.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
static int nghttp2_session_update_remote_initial_window_size
(nghttp2_session *session,
 int32_t new_initial_window_size)
{
  nghttp2_update_window_size_arg arg;
  arg.session = session;
  arg.new_window_size = new_initial_window_size;
  arg.old_window_size =
    session->remote_settings[NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE];
  return nghttp2_map_each(&session->streams,
                          nghttp2_update_remote_initial_window_size_func,
                          &arg);
}

static int nghttp2_update_local_initial_window_size_func
(nghttp2_map_entry *entry,
 void *ptr)
{
  int rv;
  nghttp2_update_window_size_arg *arg;
  nghttp2_stream *stream;
  arg = (nghttp2_update_window_size_arg*)ptr;
  stream = (nghttp2_stream*)entry;
  rv = nghttp2_stream_update_local_initial_window_size(stream,
                                                       arg->new_window_size,
                                                       arg->old_window_size);
  if(rv != 0) {
    return nghttp2_session_terminate_session(arg->session,
                                             NGHTTP2_FLOW_CONTROL_ERROR);
  }
  if(!(arg->session->opt_flags &
       NGHTTP2_OPTMASK_NO_AUTO_STREAM_WINDOW_UPDATE)) {
    if(nghttp2_should_send_window_update(stream->local_window_size,
                                         stream->recv_window_size)) {
      rv = nghttp2_session_add_window_update(arg->session,
                                             NGHTTP2_FLAG_NONE,
                                             stream->stream_id,
                                             stream->recv_window_size);
      if(rv != 0) {
        return rv;
      }
      stream->recv_window_size = 0;
    }
  }
  return 0;
}

/*
 * Updates the local initial window size of all active streams.  If
 * error occurs, all streams may not be updated.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
static int nghttp2_session_update_local_initial_window_size
(nghttp2_session *session,
 int32_t new_initial_window_size,
 int32_t old_initial_window_size)
{
  nghttp2_update_window_size_arg arg;
  arg.session = session;
  arg.new_window_size = new_initial_window_size;
  arg.old_window_size = old_initial_window_size;
  return nghttp2_map_each(&session->streams,
                          nghttp2_update_local_initial_window_size_func,
                          &arg);
}

/*
 * Apply SETTINGS values |iv| having |niv| elements to the local
 * settings.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_HEADER_COMP
 *     The header table size is out of range
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_session_update_local_settings(nghttp2_session *session,
                                          nghttp2_settings_entry *iv,
                                          size_t niv)
{
  int rv;
  size_t i;
  int32_t new_initial_window_size = -1;
  int32_t header_table_size = -1;
  uint8_t header_table_size_seen = 0;
  /* Use the value last seen. */
  for(i = 0; i < niv; ++i) {
    switch(iv[i].settings_id) {
    case NGHTTP2_SETTINGS_HEADER_TABLE_SIZE:
      header_table_size_seen = 1;
      header_table_size = iv[i].value;
      break;
    case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
      new_initial_window_size = iv[i].value;
      break;
    }
  }
  if(header_table_size_seen) {
    if(header_table_size < 0 ||
       header_table_size > NGHTTP2_MAX_HEADER_TABLE_SIZE) {
      return NGHTTP2_ERR_HEADER_COMP;
    }
    rv = nghttp2_hd_inflate_change_table_size(&session->hd_inflater,
                                              header_table_size);
    if(rv != 0) {
      return rv;
    }
  }
  if(new_initial_window_size != -1) {
    rv = nghttp2_session_update_local_initial_window_size
      (session,
       new_initial_window_size,
       session->local_settings[NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE]);
    if(rv != 0) {
      return rv;
    }
  }
  for(i = 0; i < niv; ++i) {
    if(iv[i].settings_id > 0 && iv[i].settings_id <= NGHTTP2_SETTINGS_MAX) {
      session->local_settings[iv[i].settings_id] = iv[i].value;
    }
  }
  session->pending_local_max_concurrent_stream =
    NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS;
  return 0;
}

int nghttp2_session_on_settings_received(nghttp2_session *session,
                                         nghttp2_frame *frame,
                                         int noack)
{
  int rv;
  int i;
  int check[NGHTTP2_SETTINGS_MAX+1];
  if(frame->hd.stream_id != 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  if(frame->hd.flags & NGHTTP2_FLAG_ACK) {
    if(frame->settings.niv != 0) {
      return nghttp2_session_handle_invalid_connection
        (session, frame, NGHTTP2_FRAME_SIZE_ERROR);
    }
    if(session->inflight_niv == -1) {
      return nghttp2_session_handle_invalid_connection(session, frame,
                                                       NGHTTP2_PROTOCOL_ERROR);
    }
    rv = nghttp2_session_update_local_settings(session, session->inflight_iv,
                                               session->inflight_niv);
    free(session->inflight_iv);
    session->inflight_iv = NULL;
    session->inflight_niv = -1;
    if(rv != 0) {
      nghttp2_error_code error_code = NGHTTP2_INTERNAL_ERROR;
      if(nghttp2_is_fatal(rv)) {
        return rv;
      }
      if(rv == NGHTTP2_ERR_HEADER_COMP) {
        error_code = NGHTTP2_COMPRESSION_ERROR;
      }
      return nghttp2_session_handle_invalid_connection(session, frame,
                                                       error_code);
    }
    return nghttp2_session_call_on_frame_received(session, frame);
  }
  /* Check ID/value pairs and persist them if necessary. */
  memset(check, 0, sizeof(check));
  for(i = (int)frame->settings.niv - 1; i >= 0; --i) {
    nghttp2_settings_entry *entry = &frame->settings.iv[i];
    /* The spec says the settings values are processed in the order
       they appear in the payload. In other words, if the multiple
       values for the same ID were found, use the last one and ignore
       the rest. */
    if(entry->settings_id > NGHTTP2_SETTINGS_MAX || entry->settings_id <= 0 ||
       check[entry->settings_id] == 1) {
      continue;
    }
    check[entry->settings_id] = 1;
    switch(entry->settings_id) {
    case NGHTTP2_SETTINGS_HEADER_TABLE_SIZE:
      if(entry->value > NGHTTP2_MAX_HEADER_TABLE_SIZE) {
        return nghttp2_session_handle_invalid_connection
          (session, frame, NGHTTP2_COMPRESSION_ERROR);
      }
      rv = nghttp2_hd_deflate_change_table_size(&session->hd_deflater,
                                                entry->value);
      if(rv != 0) {
        if(nghttp2_is_fatal(rv)) {
          return rv;
        } else {
          return nghttp2_session_handle_invalid_connection
            (session, frame, NGHTTP2_COMPRESSION_ERROR);
        }
      }
      break;
    case NGHTTP2_SETTINGS_ENABLE_PUSH:
      if(entry->value != 0 && entry->value != 1) {
        return nghttp2_session_handle_invalid_connection
          (session, frame, NGHTTP2_PROTOCOL_ERROR);
      }
      if(!session->server && entry->value != 0) {
        return nghttp2_session_handle_invalid_connection
          (session, frame, NGHTTP2_PROTOCOL_ERROR);
      }
      break;
    case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
      /* Update the initial window size of the all active streams */
      /* Check that initial_window_size < (1u << 31) */
      if(entry->value > NGHTTP2_MAX_WINDOW_SIZE) {
        return nghttp2_session_handle_invalid_connection
          (session, frame, NGHTTP2_FLOW_CONTROL_ERROR);
      }
      rv = nghttp2_session_update_remote_initial_window_size
        (session, entry->value);
      if(nghttp2_is_fatal(rv)) {
        return rv;
      }
      if(rv != 0) {
        return nghttp2_session_handle_invalid_connection
          (session, frame, NGHTTP2_FLOW_CONTROL_ERROR);
      }
      break;
    case NGHTTP2_SETTINGS_COMPRESS_DATA:
      if(entry->value != 0 && entry->value != 1) {
        return nghttp2_session_handle_invalid_connection
          (session, frame, NGHTTP2_PROTOCOL_ERROR);
      }
      break;
    }
    session->remote_settings[entry->settings_id] = entry->value;
  }
  if(!noack) {
    rv = nghttp2_session_add_settings(session, NGHTTP2_FLAG_ACK, NULL, 0);
    if(rv != 0) {
      if(nghttp2_is_fatal(rv)) {
        return rv;
      }
      return nghttp2_session_handle_invalid_connection
        (session, frame, NGHTTP2_INTERNAL_ERROR);
    }
  }
  return nghttp2_session_call_on_frame_received(session, frame);
}

static int session_process_settings_frame(nghttp2_session *session)
{
  int rv;
  nghttp2_inbound_frame *iframe = &session->iframe;
  nghttp2_frame *frame = &iframe->frame;

  rv = nghttp2_frame_unpack_settings_payload(&frame->settings,
                                             iframe->iv, iframe->niv);
  if(rv != 0) {
    assert(nghttp2_is_fatal(rv));
    return rv;
  }
  return nghttp2_session_on_settings_received(session, frame, 0 /* ACK */);
}

int nghttp2_session_on_push_promise_received(nghttp2_session *session,
                                             nghttp2_frame *frame)
{
  int rv;
  nghttp2_stream *stream;
  nghttp2_stream *promised_stream;
  nghttp2_priority_spec pri_spec;

  if(frame->hd.stream_id == 0) {
    return nghttp2_session_inflate_handle_invalid_connection
      (session, frame, NGHTTP2_PROTOCOL_ERROR);
  }
  if(session->server ||
     session->local_settings[NGHTTP2_SETTINGS_ENABLE_PUSH] == 0) {
    return nghttp2_session_inflate_handle_invalid_connection
      (session, frame, NGHTTP2_PROTOCOL_ERROR);
  }
  if(session->goaway_flags) {
    /* We just dicard PUSH_PROMISE after GOAWAY is sent or
       received. */
    return NGHTTP2_ERR_IGN_HEADER_BLOCK;
  }
  if(!nghttp2_session_is_new_peer_stream_id
     (session, frame->push_promise.promised_stream_id)) {
    /* The spec says if an endpoint receives a PUSH_PROMISE with
       illegal stream ID is subject to a connection error of type
       PROTOCOL_ERROR. */
    return nghttp2_session_inflate_handle_invalid_connection
      (session, frame, NGHTTP2_PROTOCOL_ERROR);
  }
  session->last_recv_stream_id = frame->push_promise.promised_stream_id;
  if(!nghttp2_session_is_my_stream_id(session, frame->hd.stream_id)) {
    return nghttp2_session_inflate_handle_invalid_connection
      (session, frame, NGHTTP2_PROTOCOL_ERROR);
  }
  stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
  if(!stream || stream->state == NGHTTP2_STREAM_CLOSING) {
    if(!stream) {
      if(session_detect_idle_stream(session, frame->hd.stream_id)) {
        return nghttp2_session_inflate_handle_invalid_connection
          (session, frame, NGHTTP2_PROTOCOL_ERROR);
      }
    }
    rv = nghttp2_session_add_rst_stream
      (session, frame->push_promise.promised_stream_id,
       NGHTTP2_REFUSED_STREAM);
    if(rv != 0) {
      return rv;
    }
    return NGHTTP2_ERR_IGN_HEADER_BLOCK;
  }
  if(stream->shut_flags & NGHTTP2_SHUT_RD) {
    if(session->callbacks.on_invalid_frame_recv_callback) {
      if(session->callbacks.on_invalid_frame_recv_callback
         (session, frame, NGHTTP2_PROTOCOL_ERROR, session->user_data) != 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }
    rv = nghttp2_session_add_rst_stream
      (session, frame->push_promise.promised_stream_id,
       NGHTTP2_PROTOCOL_ERROR);
    if(rv != 0) {
      return rv;
    }
    return NGHTTP2_ERR_IGN_HEADER_BLOCK;
  }

  /* TODO It is unclear reserved stream dpeneds on associated
     stream with or without exclusive flag set */
  nghttp2_priority_spec_init(&pri_spec, stream->stream_id,
                             NGHTTP2_DEFAULT_WEIGHT, 0);

  promised_stream = nghttp2_session_open_stream
    (session,
     frame->push_promise.promised_stream_id,
     NGHTTP2_STREAM_FLAG_PUSH,
     &pri_spec,
     NGHTTP2_STREAM_RESERVED,
     NULL);

  if(!promised_stream) {
    return NGHTTP2_ERR_NOMEM;
  }

  session->last_proc_stream_id = session->last_recv_stream_id;
  rv = session_call_on_begin_headers(session, frame);
  if(rv != 0) {
    return rv;
  }
  return 0;
}

static int session_process_push_promise_frame(nghttp2_session *session)
{
  int rv;
  nghttp2_inbound_frame *iframe = &session->iframe;
  nghttp2_frame *frame = &iframe->frame;

  rv = nghttp2_frame_unpack_push_promise_payload
    (&frame->push_promise,
     iframe->sbuf.pos, nghttp2_buf_len(&iframe->sbuf));

  if(rv != 0) {
    return nghttp2_session_terminate_session(session, NGHTTP2_PROTOCOL_ERROR);
  }

  return nghttp2_session_on_push_promise_received(session, frame);
}

int nghttp2_session_on_ping_received(nghttp2_session *session,
                                     nghttp2_frame *frame)
{
  int rv = 0;
  if(frame->hd.stream_id != 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  if((frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) {
    /* Peer sent ping, so ping it back */
    rv = nghttp2_session_add_ping(session, NGHTTP2_FLAG_ACK,
                                  frame->ping.opaque_data);
    if(rv != 0) {
      return rv;
    }
  }
  return nghttp2_session_call_on_frame_received(session, frame);
}

static int session_process_ping_frame(nghttp2_session *session)
{
  nghttp2_inbound_frame *iframe = &session->iframe;
  nghttp2_frame *frame = &iframe->frame;

  nghttp2_frame_unpack_ping_payload(&frame->ping,
                                    iframe->sbuf.pos,
                                    nghttp2_buf_len(&iframe->sbuf));

  return nghttp2_session_on_ping_received(session, frame);
}

int nghttp2_session_on_goaway_received(nghttp2_session *session,
                                       nghttp2_frame *frame)
{
  if(frame->hd.stream_id != 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  session->last_stream_id = frame->goaway.last_stream_id;
  session->goaway_flags |= NGHTTP2_GOAWAY_RECV;
  return nghttp2_session_call_on_frame_received(session, frame);
}

static int session_process_goaway_frame(nghttp2_session *session)
{
  nghttp2_inbound_frame *iframe = &session->iframe;
  nghttp2_frame *frame = &iframe->frame;

  nghttp2_frame_unpack_goaway_payload(&frame->goaway,
                                      iframe->sbuf.pos,
                                      nghttp2_buf_len(&iframe->sbuf),
                                      iframe->lbuf.pos,
                                      nghttp2_buf_len(&iframe->lbuf));

  nghttp2_buf_wrap_init(&iframe->lbuf, NULL, 0);

  return nghttp2_session_on_goaway_received(session, frame);
}

int nghttp2_session_on_altsvc_received(nghttp2_session *session,
                                       nghttp2_frame *frame)
{
  /* ALTSVC is exptected to be received by client only.  We have
     already rejected ALTSVC if it is received by server. */
  if(frame->hd.stream_id != 0 &&
     !nghttp2_session_is_my_stream_id(session, frame->hd.stream_id)) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }

  return nghttp2_session_call_on_frame_received(session, frame);
}

static int session_process_altsvc_frame(nghttp2_session *session)
{
  nghttp2_inbound_frame *iframe = &session->iframe;
  nghttp2_frame *frame = &iframe->frame;
  int rv;

  rv = nghttp2_frame_unpack_altsvc_payload(&frame->altsvc,
                                           iframe->sbuf.pos,
                                           nghttp2_buf_len(&iframe->sbuf),
                                           iframe->lbuf.pos,
                                           nghttp2_buf_len(&iframe->lbuf));

  if(rv != 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_FRAME_SIZE_ERROR);
  }

  nghttp2_buf_wrap_init(&iframe->lbuf, NULL, 0);

  return nghttp2_session_on_altsvc_received(session, frame);
}

int nghttp2_session_on_blocked_received(nghttp2_session *session,
                                        nghttp2_frame *frame)
{
  return nghttp2_session_call_on_frame_received(session, frame);
}

static int session_process_blocked_frame(nghttp2_session *session)
{
  nghttp2_inbound_frame *iframe = &session->iframe;
  nghttp2_frame *frame = &iframe->frame;

  return nghttp2_session_on_blocked_received(session, frame);
}

static int nghttp2_push_back_deferred_data_func(nghttp2_map_entry *entry,
                                                void *ptr)
{
  int rv;
  nghttp2_session *session;
  nghttp2_stream *stream;

  session = (nghttp2_session*)ptr;
  stream = (nghttp2_stream*)entry;

  /* If DATA frame is deferred due to flow control, push it back to
     outbound queue. */
  if(nghttp2_stream_check_deferred_by_flow_control(stream) &&
     stream->remote_window_size > 0) {

    rv = nghttp2_stream_resume_deferred_data(stream, &session->ob_pq);

    if(nghttp2_is_fatal(rv)) {
      return rv;
    }
  }
  return 0;
}

/*
 * Push back deferred DATA frames to queue if they are deferred due to
 * connection-level flow control.
 */
static int nghttp2_session_push_back_deferred_data(nghttp2_session *session)
{
  return nghttp2_map_each(&session->streams,
                          nghttp2_push_back_deferred_data_func, session);
}

static int session_on_connection_window_update_received
(nghttp2_session *session, nghttp2_frame *frame)
{
  int rv;
  /* Handle connection-level flow control */
  if(NGHTTP2_MAX_WINDOW_SIZE - frame->window_update.window_size_increment <
     session->remote_window_size) {
    return nghttp2_session_handle_invalid_connection
      (session, frame, NGHTTP2_FLOW_CONTROL_ERROR);
  }
  session->remote_window_size += frame->window_update.window_size_increment;
  /* To queue the DATA deferred by connection-level flow-control, we
     have to check all streams. Bad. */
  if(session->remote_window_size > 0) {
    session->blocked_sent = 0;

    rv = nghttp2_session_push_back_deferred_data(session);
    if(rv != 0) {
      /* FATAL */
      assert(rv < NGHTTP2_ERR_FATAL);
      return rv;
    }
  }
  return nghttp2_session_call_on_frame_received(session, frame);
}

static int session_on_stream_window_update_received
(nghttp2_session *session, nghttp2_frame *frame)
{
  int rv;
  nghttp2_stream *stream;
  stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
  if(!stream) {
    if(session_detect_idle_stream(session, frame->hd.stream_id)) {
      return nghttp2_session_handle_invalid_connection(session, frame,
                                                       NGHTTP2_PROTOCOL_ERROR);
    }
    return 0;
  }
  if(stream->state == NGHTTP2_STREAM_RESERVED) {
    return nghttp2_session_handle_invalid_connection
      (session, frame, NGHTTP2_PROTOCOL_ERROR);
  }
  if(NGHTTP2_MAX_WINDOW_SIZE - frame->window_update.window_size_increment <
     stream->remote_window_size) {
    return nghttp2_session_handle_invalid_stream(session, frame,
                                                 NGHTTP2_FLOW_CONTROL_ERROR);
  }
  stream->remote_window_size += frame->window_update.window_size_increment;

  if(stream->remote_window_size > 0) {
    stream->blocked_sent = 0;
  }

  if(stream->remote_window_size > 0 &&
     session->remote_window_size > 0 &&
     nghttp2_stream_check_deferred_by_flow_control(stream)) {

    rv = nghttp2_stream_resume_deferred_data(stream, &session->ob_pq);

    if(nghttp2_is_fatal(rv)) {
      return rv;
    }
  }
  return nghttp2_session_call_on_frame_received(session, frame);
}

int nghttp2_session_on_window_update_received(nghttp2_session *session,
                                              nghttp2_frame *frame)
{
  if(frame->hd.stream_id == 0) {
    return session_on_connection_window_update_received(session, frame);
  } else {
    return session_on_stream_window_update_received(session, frame);
  }
}

static int session_process_window_update_frame(nghttp2_session *session)
{
  nghttp2_inbound_frame *iframe = &session->iframe;
  nghttp2_frame *frame = &iframe->frame;

  nghttp2_frame_unpack_window_update_payload(&frame->window_update,
                                             iframe->sbuf.pos,
                                             nghttp2_buf_len(&iframe->sbuf));

  return nghttp2_session_on_window_update_received(session, frame);
}

/* static int get_error_code_from_lib_error_code(int lib_error_code) */
/* { */
/*   switch(lib_error_code) { */
/*   case NGHTTP2_ERR_HEADER_COMP: */
/*     return NGHTTP2_COMPRESSION_ERROR; */
/*   case NGHTTP2_ERR_FRAME_SIZE_ERROR: */
/*     return NGHTTP2_FRAME_SIZE_ERROR; */
/*   default: */
/*     return NGHTTP2_PROTOCOL_ERROR; */
/*   } */
/* } */

int nghttp2_session_on_data_received(nghttp2_session *session,
                                     nghttp2_frame *frame)
{
  int rv = 0;
  nghttp2_stream *stream;

  /* We don't call on_frame_recv_callback if stream has been closed
     already or being closed. */
  stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
  if(!stream || stream->state == NGHTTP2_STREAM_CLOSING) {
    /* This should be treated as stream error, but it results in lots
       of RST_STREAM. So just ignore frame against nonexistent stream
       for now. */
    return 0;
  }

  rv = nghttp2_session_call_on_frame_received(session, frame);
  if(nghttp2_is_fatal(rv)) {
    return rv;
  }

  if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
    rv = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
    if(nghttp2_is_fatal(rv)) {
      return rv;
    }
  }
  return 0;
}

/* For errors, this function only returns FATAL error. */
static int nghttp2_session_process_data_frame(nghttp2_session *session)
{
  int rv;
  nghttp2_frame *public_data_frame = &session->iframe.frame;
  rv = nghttp2_session_on_data_received(session, public_data_frame);
  if(nghttp2_is_fatal(rv)) {
    return rv;
  }
  return 0;
}

/*
 * Now we have SETTINGS synchronization, flow control error can be
 * detected strictly. If DATA frame is received with length > 0 and
 * current received window size + delta length is strictly larger than
 * local window size, it is subject to FLOW_CONTROL_ERROR, so return
 * -1. Note that local_window_size is calculated after SETTINGS ACK is
 * received from peer, so peer must honor this limit. If the resulting
 * recv_window_size is strictly larger than NGHTTP2_MAX_WINDOW_SIZE,
 * return -1 too.
 */
static int adjust_recv_window_size(int32_t *recv_window_size_ptr,
                                   int32_t delta,
                                   int32_t local_window_size)
{
  if(*recv_window_size_ptr > local_window_size - delta ||
     *recv_window_size_ptr > NGHTTP2_MAX_WINDOW_SIZE - delta) {
    return -1;
  }
  *recv_window_size_ptr += delta;
  return 0;
}

/*
 * Accumulates received bytes |delta_size| for stream-level flow
 * control and decides whether to send WINDOW_UPDATE to that
 * stream. If NGHTTP2_OPT_NO_AUTO_STREAM_WINDOW_UPDATE is set,
 * WINDOW_UPDATE will not be sent.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
static int nghttp2_session_update_recv_stream_window_size
(nghttp2_session *session,
 nghttp2_stream *stream,
 int32_t delta_size,
 int send_window_update)
{
  int rv;
  rv = adjust_recv_window_size(&stream->recv_window_size, delta_size,
                               stream->local_window_size);
  if(rv != 0) {
    return nghttp2_session_add_rst_stream(session, stream->stream_id,
                                          NGHTTP2_FLOW_CONTROL_ERROR);
  }
  /* We don't have to send WINDOW_UPDATE if the data received is the
     last chunk in the incoming stream. */
  if(send_window_update &&
     !(session->opt_flags & NGHTTP2_OPTMASK_NO_AUTO_STREAM_WINDOW_UPDATE)) {
    /* We have to use local_settings here because it is the constraint
       the remote endpoint should honor. */
    if(nghttp2_should_send_window_update(stream->local_window_size,
                                         stream->recv_window_size)) {
      rv = nghttp2_session_add_window_update(session,
                                            NGHTTP2_FLAG_NONE,
                                            stream->stream_id,
                                            stream->recv_window_size);
      if(rv == 0) {
        stream->recv_window_size = 0;
      } else {
        return rv;
      }
    }
  }
  return 0;
}

/*
 * Accumulates received bytes |delta_size| for connection-level flow
 * control and decides whether to send WINDOW_UPDATE to the
 * connection.  If NGHTTP2_OPT_NO_AUTO_CONNECTION_WINDOW_UPDATE is
 * set, WINDOW_UPDATE will not be sent.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
static int nghttp2_session_update_recv_connection_window_size
(nghttp2_session *session,
 int32_t delta_size)
{
  int rv;
  rv = adjust_recv_window_size(&session->recv_window_size, delta_size,
                               session->local_window_size);
  if(rv != 0) {
    return nghttp2_session_terminate_session(session,
                                             NGHTTP2_FLOW_CONTROL_ERROR);
  }
  if(!(session->opt_flags &
       NGHTTP2_OPTMASK_NO_AUTO_CONNECTION_WINDOW_UPDATE)) {
    if(nghttp2_should_send_window_update(session->local_window_size,
                                         session->recv_window_size)) {
      /* Use stream ID 0 to update connection-level flow control
         window */
      rv = nghttp2_session_add_window_update(session,
                                            NGHTTP2_FLAG_NONE,
                                            0,
                                            session->recv_window_size);
      if(rv == 0) {
        session->recv_window_size = 0;
      } else {
        return rv;
      }
    }
  }
  return 0;
}

/*
 * Checks that we can receive the DATA frame for stream, which is
 * indicated by |session->iframe.frame.hd.stream_id|. If it is a
 * connection error situation, GOAWAY frame will be issued by this
 * function.
 *
 * If the DATA frame is allowed, returns 0.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_IGN_PAYLOAD
 *   The reception of DATA frame is connection error; or should be
 *   ignored.
 * NGHTTP2_ERR_NOMEM
 *   Out of memory.
 */
static int nghttp2_session_on_data_received_fail_fast(nghttp2_session *session)
{
  int rv;
  nghttp2_stream *stream;
  nghttp2_inbound_frame *iframe;
  int32_t stream_id;

  iframe = &session->iframe;
  stream_id = iframe->frame.hd.stream_id;

  if(stream_id == 0) {
    /* The spec says that if a DATA frame is received whose stream ID
       is 0, the recipient MUST respond with a connection error of
       type PROTOCOL_ERROR. */
    goto fail;
  }
  stream = nghttp2_session_get_stream(session, stream_id);
  if(!stream) {
    if(session_detect_idle_stream(session, stream_id)) {
      goto fail;
    }
    return NGHTTP2_ERR_IGN_PAYLOAD;
  }
  if(stream->shut_flags & NGHTTP2_SHUT_RD) {
    goto fail;
  }

  if((iframe->frame.hd.flags & NGHTTP2_FLAG_COMPRESSED) &&
     session->local_settings[NGHTTP2_SETTINGS_COMPRESS_DATA] == 0) {
    goto fail;
  }

  if(nghttp2_session_is_my_stream_id(session, stream_id)) {
    if(stream->state == NGHTTP2_STREAM_CLOSING) {
      return NGHTTP2_ERR_IGN_PAYLOAD;
    }
    if(stream->state != NGHTTP2_STREAM_OPENED) {
      goto fail;
    }
    return 0;
  }
  if(stream->state == NGHTTP2_STREAM_RESERVED) {
    goto fail;
  }
  if(stream->state == NGHTTP2_STREAM_CLOSING) {
    return NGHTTP2_ERR_IGN_PAYLOAD;
  }
  return 0;
 fail:
  rv = nghttp2_session_terminate_session(session, NGHTTP2_PROTOCOL_ERROR);
  if(nghttp2_is_fatal(rv)) {
    return rv;
  }
  return NGHTTP2_ERR_IGN_PAYLOAD;
}

static size_t inbound_frame_payload_readlen(nghttp2_inbound_frame *iframe,
                                         const uint8_t *in,
                                         const uint8_t *last)
{
  return nghttp2_min((size_t)(last - in), iframe->payloadleft);
}

/*
 * Resets iframe->sbuf and advance its mark pointer by |left| bytes.
 */
static void inbound_frame_set_mark(nghttp2_inbound_frame *iframe, size_t left)
{
  nghttp2_buf_reset(&iframe->sbuf);
  iframe->sbuf.mark += left;
}

static size_t inbound_frame_buf_read(nghttp2_inbound_frame *iframe,
                                     const uint8_t *in, const uint8_t *last)
{
  size_t readlen;

  readlen = nghttp2_min(last - in,
                        nghttp2_buf_mark_avail(&iframe->sbuf));

  iframe->sbuf.last = nghttp2_cpymem(iframe->sbuf.last, in, readlen);

  return readlen;
}

/*
 * Unpacks SETTINGS entry in iframe->sbuf.
 *
 * This function returns 0 if it succeeds, or -1.
 */
static int inbound_frame_set_settings_entry(nghttp2_inbound_frame *iframe)
{
  nghttp2_settings_entry iv;
  size_t i;

  nghttp2_frame_unpack_settings_entry(&iv, iframe->sbuf.pos);

  switch(iv.settings_id) {
  case NGHTTP2_SETTINGS_HEADER_TABLE_SIZE:
  case NGHTTP2_SETTINGS_ENABLE_PUSH:
  case NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
  case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
  case NGHTTP2_SETTINGS_COMPRESS_DATA:
    break;
  default:
    return -1;
  }

  for(i = 0; i < iframe->niv; ++i) {
    if(iframe->iv[i].settings_id == iv.settings_id) {
      iframe->iv[i] = iv;
      break;
    }
  }

  if(i == iframe->niv) {
    iframe->iv[iframe->niv++] = iv;
  }

  return 0;
}

/*
 * Checks PAD_HIGH and PAD_LOW flags and set iframe->sbuf to read them
 * accordingly. If padding is set, this function returns 1. If no
 * padding is set, this function returns 0. On error, returns -1.
 */
static int inbound_frame_handle_pad(nghttp2_inbound_frame *iframe,
                                    nghttp2_frame_hd *hd)
{
  if(hd->flags & NGHTTP2_FLAG_PAD_HIGH) {
    if((hd->flags & NGHTTP2_FLAG_PAD_LOW) == 0) {
      return -1;
    }
    if(hd->length < 2) {
      return -1;
    }
    inbound_frame_set_mark(iframe, 2);
    return 1;
  }
  if(hd->flags & NGHTTP2_FLAG_PAD_LOW) {
    if(hd->length < 1) {
      return -1;
    }
    inbound_frame_set_mark(iframe, 1);
    return 1;
  }
  DEBUGF(fprintf(stderr, "recv: no padding in payload\n"));
  return 0;
}

/*
 * Computes number of padding based on flags. This function returns
 * the calculated length if it succeeds, or -1.
 */
static ssize_t inbound_frame_compute_pad(nghttp2_inbound_frame *iframe)
{
  size_t padlen;

  padlen = iframe->sbuf.pos[0];

  if(iframe->frame.hd.flags & NGHTTP2_FLAG_PAD_HIGH) {
    padlen <<= 8;
    padlen |= iframe->sbuf.pos[1];
    ++padlen;
  }

  ++padlen;

  DEBUGF(fprintf(stderr, "recv: padlen=%zu\n", padlen));

  /* We cannot use iframe->frame.hd.length because of CONTINUATION */
  if(padlen - (padlen > 255) - 1 > iframe->payloadleft) {
    return -1;
  }

  iframe->padlen = padlen;

  return padlen;
}

/*
 * This function returns the effective payload length in the data of
 * length |readlen| when the remaning payload is |payloadleft|. The
 * |payloadleft| does not include |readlen|. If padding was started
 * strictly before this data chunk, this function returns -1.
 */
static ssize_t inbound_frame_effective_readlen(nghttp2_inbound_frame *iframe,
                                               size_t payloadleft,
                                               size_t readlen)
{
  size_t trail_padlen = nghttp2_frame_trail_padlen(&iframe->frame,
                                                   iframe->padlen);

  if(trail_padlen > payloadleft) {
    size_t padlen;
    padlen = trail_padlen - payloadleft;
    if(readlen < padlen) {
      return -1;
    } else {
      return readlen - padlen;
    }
  }
  return readlen;
}

ssize_t nghttp2_session_mem_recv(nghttp2_session *session,
                                 const uint8_t *in, size_t inlen)
{
  const uint8_t *first = in, *last = in + inlen;
  nghttp2_inbound_frame *iframe = &session->iframe;
  size_t readlen;
  int rv;
  int busy = 0;
  nghttp2_frame_hd cont_hd;
  nghttp2_stream *stream;
  size_t pri_fieldlen;

  DEBUGF(fprintf(stderr,
                 "recv: connection recv_window_size=%d, local_window=%d\n",
                 session->recv_window_size, session->local_window_size));

  for(;;) {
    switch(iframe->state) {
    case NGHTTP2_IB_READ_HEAD:
      DEBUGF(fprintf(stderr, "recv: [IB_READ_HEAD]\n"));

      readlen = inbound_frame_buf_read(iframe, in, last);
      in += readlen;

      if(nghttp2_buf_mark_avail(&iframe->sbuf)) {
        return in - first;
      }

      nghttp2_frame_unpack_frame_hd(&iframe->frame.hd, iframe->sbuf.pos);
      iframe->payloadleft = iframe->frame.hd.length;

      DEBUGF(fprintf(stderr,
                     "recv: payloadlen=%zu, type=%u, flags=0x%02x, "
                     "stream_id=%d\n",
                     iframe->frame.hd.length,
                     iframe->frame.hd.type,
                     iframe->frame.hd.flags,
                     iframe->frame.hd.stream_id));

      switch(iframe->frame.hd.type) {
      case NGHTTP2_DATA: {
        DEBUGF(fprintf(stderr, "recv: DATA\n"));

        iframe->frame.hd.flags &= (NGHTTP2_FLAG_END_STREAM |
                                   NGHTTP2_FLAG_END_SEGMENT |
                                   NGHTTP2_FLAG_PAD_LOW |
                                   NGHTTP2_FLAG_PAD_HIGH |
                                   NGHTTP2_FLAG_COMPRESSED);
        /* Check stream is open. If it is not open or closing,
           ignore payload. */
        busy = 1;

        rv = nghttp2_session_on_data_received_fail_fast(session);
        if(rv == NGHTTP2_ERR_IGN_PAYLOAD) {
          DEBUGF(fprintf(stderr, "recv: DATA not allowed stream_id=%d\n",
                         iframe->frame.hd.stream_id));
          iframe->state = NGHTTP2_IB_IGN_DATA;
          break;
        }

        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        rv = inbound_frame_handle_pad(iframe, &iframe->frame.hd);
        if(rv < 0) {
          iframe->state = NGHTTP2_IB_IGN_DATA;
          rv = nghttp2_session_terminate_session(session,
                                                 NGHTTP2_PROTOCOL_ERROR);

          if(nghttp2_is_fatal(rv)) {
            return rv;
          }
          break;
        }

        if(rv == 1) {
          iframe->state = NGHTTP2_IB_READ_PAD_DATA;
          break;
        }

        iframe->state = NGHTTP2_IB_READ_DATA;
        break;
      }
      case NGHTTP2_HEADERS:

        DEBUGF(fprintf(stderr, "recv: HEADERS\n"));

        iframe->frame.hd.flags &= (NGHTTP2_FLAG_END_STREAM |
                                   NGHTTP2_FLAG_END_SEGMENT |
                                   NGHTTP2_FLAG_END_HEADERS |
                                   NGHTTP2_FLAG_PAD_LOW |
                                   NGHTTP2_FLAG_PAD_HIGH |
                                   NGHTTP2_FLAG_PRIORITY);

        rv = inbound_frame_handle_pad(iframe, &iframe->frame.hd);
        if(rv < 0) {
          busy = 1;

          iframe->state = NGHTTP2_IB_IGN_PAYLOAD;

          rv = nghttp2_session_terminate_session(session,
                                                 NGHTTP2_PROTOCOL_ERROR);
          if(nghttp2_is_fatal(rv)) {
            return rv;
          }
          break;
        }

        if(rv == 1) {
          iframe->state = NGHTTP2_IB_READ_NBYTE;
          break;
        }

        pri_fieldlen = nghttp2_frame_priority_len(iframe->frame.hd.flags);

        if(pri_fieldlen > 0) {
          if(iframe->payloadleft < pri_fieldlen) {
            busy = 1;
            iframe->state = NGHTTP2_IB_FRAME_SIZE_ERROR;
            break;
          }

          iframe->state = NGHTTP2_IB_READ_NBYTE;

          inbound_frame_set_mark(iframe, pri_fieldlen);

          break;
        }

        rv = session_process_headers_frame(session);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        busy = 1;

        if(rv == NGHTTP2_ERR_IGN_HEADER_BLOCK) {
          iframe->state = NGHTTP2_IB_IGN_HEADER_BLOCK;
          break;
        }

        iframe->state = NGHTTP2_IB_READ_HEADER_BLOCK;

        break;
      case NGHTTP2_PRIORITY:
        DEBUGF(fprintf(stderr, "recv: PRIORITY\n"));

        iframe->frame.hd.flags = NGHTTP2_FLAG_NONE;

        if(iframe->payloadleft != 5) {
          busy = 1;

          iframe->state = NGHTTP2_IB_FRAME_SIZE_ERROR;

          break;
        }

        iframe->state = NGHTTP2_IB_READ_NBYTE;

        inbound_frame_set_mark(iframe, 5);

        break;
      case NGHTTP2_RST_STREAM:
      case NGHTTP2_WINDOW_UPDATE:
#ifdef DEBUGBUILD
        switch(iframe->frame.hd.type) {
        case NGHTTP2_RST_STREAM:
          DEBUGF(fprintf(stderr, "recv: RST_STREAM\n"));
          break;
        case NGHTTP2_WINDOW_UPDATE:
          DEBUGF(fprintf(stderr, "recv: WINDOW_UPDATE\n"));
          break;
        }
#endif /* DEBUGBUILD */

        iframe->frame.hd.flags = NGHTTP2_FLAG_NONE;

        if(iframe->payloadleft != 4) {
          busy = 1;
          iframe->state = NGHTTP2_IB_FRAME_SIZE_ERROR;
          break;
        }

        iframe->state = NGHTTP2_IB_READ_NBYTE;

        inbound_frame_set_mark(iframe, 4);

        break;
      case NGHTTP2_SETTINGS:
        DEBUGF(fprintf(stderr, "recv: SETTINGS\n"));

        iframe->frame.hd.flags &= NGHTTP2_FLAG_ACK;

        if((iframe->frame.hd.length % NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH) ||
           ((iframe->frame.hd.flags & NGHTTP2_FLAG_ACK) &&
            iframe->payloadleft > 0)) {
          busy = 1;
          iframe->state = NGHTTP2_IB_FRAME_SIZE_ERROR;
          break;
        }

        iframe->state = NGHTTP2_IB_READ_SETTINGS;

        if(iframe->payloadleft) {
          inbound_frame_set_mark(iframe, NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH);
          break;
        }

        busy = 1;

        inbound_frame_set_mark(iframe, 0);

        break;
      case NGHTTP2_PUSH_PROMISE:
        DEBUGF(fprintf(stderr, "recv: PUSH_PROMISE\n"));

        iframe->frame.hd.flags &= (NGHTTP2_FLAG_END_HEADERS |
                                   NGHTTP2_FLAG_PAD_LOW |
                                   NGHTTP2_FLAG_PAD_HIGH);

        rv = inbound_frame_handle_pad(iframe, &iframe->frame.hd);
        if(rv < 0) {
          busy = 1;
          iframe->state = NGHTTP2_IB_IGN_PAYLOAD;
          rv = nghttp2_session_terminate_session(session,
                                                 NGHTTP2_PROTOCOL_ERROR);
          if(nghttp2_is_fatal(rv)) {
            return rv;
          }
          break;
        }

        if(rv == 1) {
          iframe->state = NGHTTP2_IB_READ_NBYTE;
          break;
        }

        if(iframe->payloadleft < 4) {
          busy = 1;
          iframe->state = NGHTTP2_IB_FRAME_SIZE_ERROR;
          break;
        }

        iframe->state = NGHTTP2_IB_READ_NBYTE;

        inbound_frame_set_mark(iframe, 4);

        break;
      case NGHTTP2_PING:
        DEBUGF(fprintf(stderr, "recv: PING\n"));

        iframe->frame.hd.flags &= NGHTTP2_FLAG_ACK;

        if(iframe->payloadleft != 8) {
          busy = 1;
          iframe->state = NGHTTP2_IB_FRAME_SIZE_ERROR;
          break;
        }

        iframe->state = NGHTTP2_IB_READ_NBYTE;
        inbound_frame_set_mark(iframe, 8);

        break;
      case NGHTTP2_GOAWAY:
        DEBUGF(fprintf(stderr, "recv: GOAWAY\n"));

        iframe->frame.hd.flags = NGHTTP2_FLAG_NONE;

        if(iframe->payloadleft < 8) {
          busy = 1;
          iframe->state = NGHTTP2_IB_FRAME_SIZE_ERROR;
          break;
        }

        iframe->state = NGHTTP2_IB_READ_NBYTE;
        inbound_frame_set_mark(iframe, 8);

        break;
      case NGHTTP2_ALTSVC:
        DEBUGF(fprintf(stderr, "recv: ALTSVC\n"));

        iframe->frame.hd.flags = NGHTTP2_FLAG_NONE;

        if(session->server) {
          rv = nghttp2_session_terminate_session(session,
                                                 NGHTTP2_PROTOCOL_ERROR);
          if(nghttp2_is_fatal(rv)) {
            return rv;
          }

          busy = 1;

          iframe->state = NGHTTP2_IB_IGN_PAYLOAD;

          break;
        }

        if(iframe->payloadleft < 9) {
          busy = 1;

          iframe->state = NGHTTP2_IB_FRAME_SIZE_ERROR;

          break;
        }

        iframe->state = NGHTTP2_IB_READ_NBYTE;
        inbound_frame_set_mark(iframe, 8);

        break;
      case NGHTTP2_BLOCKED:
        DEBUGF(fprintf(stderr, "recv: BLOCKED\n"));

        iframe->frame.hd.flags = NGHTTP2_FLAG_NONE;

        if(iframe->payloadleft != 0) {
          busy = 1;

          iframe->state = NGHTTP2_IB_FRAME_SIZE_ERROR;

          break;
        }

        rv = session_process_blocked_frame(session);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        nghttp2_inbound_frame_reset(session);

        break;
      default:
        DEBUGF(fprintf(stderr, "recv: unknown frame\n"));

        /* Receiving unknown frame type and CONTINUATION in this state
           are subject to connection error of type PROTOCOL_ERROR */
        rv = nghttp2_session_terminate_session(session,
                                               NGHTTP2_PROTOCOL_ERROR);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        busy = 1;

        iframe->state = NGHTTP2_IB_IGN_PAYLOAD;

        break;
      }
      break;
    case NGHTTP2_IB_READ_NBYTE:
      DEBUGF(fprintf(stderr, "recv: [IB_READ_NBYTE]\n"));

      readlen = inbound_frame_buf_read(iframe, in, last);
      in += readlen;
      iframe->payloadleft -= readlen;

      DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu, left=%zd\n",
                     readlen, iframe->payloadleft,
                     nghttp2_buf_mark_avail(&iframe->sbuf)));

      if(nghttp2_buf_mark_avail(&iframe->sbuf)) {
        return in - first;
      }

      switch(iframe->frame.hd.type) {
      case NGHTTP2_HEADERS:
        if(iframe->padlen == 0 &&
           iframe->frame.hd.flags & NGHTTP2_FLAG_PAD_LOW) {
          rv = inbound_frame_compute_pad(iframe);
          if(rv < 0) {
            busy = 1;
            rv = nghttp2_session_terminate_session(session,
                                                   NGHTTP2_PROTOCOL_ERROR);
            if(nghttp2_is_fatal(rv)) {
              return rv;
            }
            iframe->state = NGHTTP2_IB_IGN_PAYLOAD;
            break;
          }
          iframe->frame.headers.padlen = rv;

          pri_fieldlen = nghttp2_frame_priority_len(iframe->frame.hd.flags);

          if(pri_fieldlen > 0) {
            if(iframe->payloadleft < pri_fieldlen) {
              busy = 1;
              iframe->state = NGHTTP2_IB_FRAME_SIZE_ERROR;
              break;
            }
            iframe->state = NGHTTP2_IB_READ_NBYTE;
            inbound_frame_set_mark(iframe, pri_fieldlen);
            break;
          } else {
            /* Truncate buffers used for padding spec */
            inbound_frame_set_mark(iframe, 0);
          }
        }

        rv = session_process_headers_frame(session);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        busy = 1;

        if(rv == NGHTTP2_ERR_IGN_HEADER_BLOCK) {
          iframe->state = NGHTTP2_IB_IGN_HEADER_BLOCK;
          break;
        }

        iframe->state = NGHTTP2_IB_READ_HEADER_BLOCK;

        break;
      case NGHTTP2_PRIORITY:
        rv = session_process_priority_frame(session);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        nghttp2_inbound_frame_reset(session);

        break;
      case NGHTTP2_RST_STREAM:
        rv = session_process_rst_stream_frame(session);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        nghttp2_inbound_frame_reset(session);

        break;
      case NGHTTP2_PUSH_PROMISE:
        if(iframe->padlen == 0 &&
           iframe->frame.hd.flags & NGHTTP2_FLAG_PAD_LOW) {
          rv = inbound_frame_compute_pad(iframe);
          if(rv < 0) {
            busy = 1;
            rv = nghttp2_session_terminate_session(session,
                                                   NGHTTP2_PROTOCOL_ERROR);
            if(nghttp2_is_fatal(rv)) {
              return rv;
            }
            iframe->state = NGHTTP2_IB_IGN_PAYLOAD;
            break;
          }

          iframe->frame.push_promise.padlen = rv;

          if(iframe->payloadleft < 4) {
            busy = 1;
            iframe->state = NGHTTP2_IB_FRAME_SIZE_ERROR;
            break;
          }

          iframe->state = NGHTTP2_IB_READ_NBYTE;

          inbound_frame_set_mark(iframe, 4);

          break;
        }

        rv = session_process_push_promise_frame(session);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        busy = 1;

        if(rv == NGHTTP2_ERR_IGN_HEADER_BLOCK) {
          iframe->state = NGHTTP2_IB_IGN_HEADER_BLOCK;
          break;
        }

        iframe->state = NGHTTP2_IB_READ_HEADER_BLOCK;

        break;
      case NGHTTP2_PING:
        rv = session_process_ping_frame(session);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        nghttp2_inbound_frame_reset(session);

        break;
      case NGHTTP2_GOAWAY: {
        size_t debuglen;

        /* 8 is Last-stream-ID + Error Code */
        debuglen = iframe->frame.hd.length - 8;

        if(debuglen > 0) {
          iframe->raw_lbuf = malloc(debuglen);

          if(iframe->raw_lbuf == NULL) {
            return NGHTTP2_ERR_NOMEM;
          }

          nghttp2_buf_wrap_init(&iframe->lbuf, iframe->raw_lbuf, debuglen);
        }

        busy = 1;

        iframe->state = NGHTTP2_IB_READ_GOAWAY_DEBUG;

        break;
      }
      case NGHTTP2_WINDOW_UPDATE:
        rv = session_process_window_update_frame(session);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        nghttp2_inbound_frame_reset(session);

        break;
      case NGHTTP2_ALTSVC: {
        size_t varlen;

        varlen = iframe->frame.hd.length - 8;

        if(varlen > 0) {
          iframe->raw_lbuf = malloc(varlen);

          if(iframe->raw_lbuf == NULL) {
            return NGHTTP2_ERR_NOMEM;
          }

          nghttp2_buf_wrap_init(&iframe->lbuf, iframe->raw_lbuf, varlen);
        }

        busy = 1;

        iframe->state = NGHTTP2_IB_READ_ALTSVC;

        break;
      }
      default:
        /* This is unknown frame */
        nghttp2_inbound_frame_reset(session);

        break;
      }
      break;
    case NGHTTP2_IB_READ_HEADER_BLOCK:
    case NGHTTP2_IB_IGN_HEADER_BLOCK: {
      ssize_t data_readlen;
#ifdef DEBUGBUILD
      if(iframe->state == NGHTTP2_IB_READ_HEADER_BLOCK) {
        fprintf(stderr, "recv: [IB_READ_HEADER_BLOCK]\n");
      } else {
        fprintf(stderr, "recv: [IB_IGN_HEADER_BLOCK]\n");
      }
#endif /* DEBUGBUILD */

      readlen = inbound_frame_payload_readlen(iframe, in, last);

      DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu\n",
                     readlen, iframe->payloadleft - readlen));

      data_readlen = inbound_frame_effective_readlen
        (iframe, iframe->payloadleft - readlen, readlen);
      if(data_readlen >= 0) {
        size_t trail_padlen;
        size_t hd_proclen = 0;
        trail_padlen = nghttp2_frame_trail_padlen(&iframe->frame,
                                                  iframe->padlen);
        DEBUGF(fprintf(stderr, "recv: block final=%d\n",
                       (iframe->frame.hd.flags &
                        NGHTTP2_FLAG_END_HEADERS) &&
                       iframe->payloadleft - data_readlen == trail_padlen));

        rv = inflate_header_block
          (session, &iframe->frame, &hd_proclen,
           (uint8_t*)in, data_readlen,
           (iframe->frame.hd.flags &
            NGHTTP2_FLAG_END_HEADERS) &&
           iframe->payloadleft - data_readlen == trail_padlen,
           iframe->state == NGHTTP2_IB_READ_HEADER_BLOCK);

        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        if(rv == NGHTTP2_ERR_PAUSE) {
          in += hd_proclen;
          iframe->payloadleft -= hd_proclen;

          return in - first;
        }

        in += readlen;
        iframe->payloadleft -= readlen;

        if(rv == NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE) {
          /* The application says no more headers. We decompress the
             rest of the header block but not invoke on_header_callback
             and on_frame_recv_callback. */
          rv = nghttp2_session_add_rst_stream(session,
                                              iframe->frame.hd.stream_id,
                                              NGHTTP2_INTERNAL_ERROR);
          if(nghttp2_is_fatal(rv)) {
            return rv;
          }
          busy = 1;
          iframe->state = NGHTTP2_IB_IGN_HEADER_BLOCK;
          break;
        }
        if(rv == NGHTTP2_ERR_HEADER_COMP) {
          /* GOAWAY is already issued */
          if(iframe->payloadleft == 0) {
            nghttp2_inbound_frame_reset(session);
          } else {
            busy = 1;
            iframe->state = NGHTTP2_IB_IGN_PAYLOAD;
          }
          break;
        }
      } else {
        in += readlen;
        iframe->payloadleft -= readlen;
      }

      if(iframe->payloadleft) {
        break;
      }
      /* Clear PAD_HIGH and PAD_LOW, because we rely on those flags in
         the next CONTINUATION frame. Also we don't show these flags
         to user callback */
      iframe->frame.hd.flags &=
        ~(NGHTTP2_FLAG_PAD_HIGH | NGHTTP2_FLAG_PAD_LOW);

      if((iframe->frame.hd.flags & NGHTTP2_FLAG_END_HEADERS) == 0) {

        inbound_frame_set_mark(iframe, NGHTTP2_FRAME_HDLEN);

        iframe->padlen = 0;

        if(iframe->state == NGHTTP2_IB_READ_HEADER_BLOCK) {
          iframe->state = NGHTTP2_IB_EXPECT_CONTINUATION;
        } else {
          iframe->state = NGHTTP2_IB_IGN_CONTINUATION;
        }
      } else {
        if(iframe->state == NGHTTP2_IB_READ_HEADER_BLOCK) {
          rv = session_after_header_block_received(session);
          if(nghttp2_is_fatal(rv)) {
            return rv;
          }
        }
        nghttp2_inbound_frame_reset(session);
      }
      break;
    }
    case NGHTTP2_IB_IGN_PAYLOAD:
      DEBUGF(fprintf(stderr, "recv: [IB_IGN_PAYLOAD]\n"));

      readlen = inbound_frame_payload_readlen(iframe, in, last);
      iframe->payloadleft -= readlen;
      in += readlen;

      DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu\n",
                     readlen, iframe->payloadleft));

      if(iframe->payloadleft) {
        break;
      }

      switch(iframe->frame.hd.type) {
      case NGHTTP2_HEADERS:
      case NGHTTP2_PUSH_PROMISE:
        /* Mark inflater bad so that we won't perform further decoding */
        session->hd_inflater.ctx.bad = 1;
        break;
      default:
        break;
      }

      nghttp2_inbound_frame_reset(session);

      break;
    case NGHTTP2_IB_FRAME_SIZE_ERROR:
      DEBUGF(fprintf(stderr, "recv: [IB_FRAME_SIZE_ERROR]\n"));

      rv = session_handle_frame_size_error(session, &iframe->frame);
      if(nghttp2_is_fatal(rv)) {
        return rv;
      }

      busy = 1;

      iframe->state = NGHTTP2_IB_IGN_PAYLOAD;

      break;
    case NGHTTP2_IB_READ_SETTINGS:
      DEBUGF(fprintf(stderr, "recv: [IB_READ_SETTINGS]\n"));

      readlen = inbound_frame_buf_read(iframe, in, last);
      iframe->payloadleft -= readlen;
      in += readlen;

      DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu\n",
                     readlen, iframe->payloadleft));

      if(nghttp2_buf_mark_avail(&iframe->sbuf)) {
        break;
      }

      if(readlen > 0) {
        rv = inbound_frame_set_settings_entry(iframe);
        if(rv != 0) {
          DEBUGF(fprintf(stderr, "recv: bad settings received\n"));

          rv = nghttp2_session_terminate_session(session,
                                                 NGHTTP2_PROTOCOL_ERROR);
          if(nghttp2_is_fatal(rv)) {
            return rv;
          }

          if(iframe->payloadleft == 0) {
            nghttp2_inbound_frame_reset(session);
            break;
          }

          iframe->state = NGHTTP2_IB_IGN_PAYLOAD;

          break;
        }
      }
      if(iframe->payloadleft) {
        inbound_frame_set_mark(iframe, NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH);
        break;
      }

      rv = session_process_settings_frame(session);

      if(nghttp2_is_fatal(rv)) {
        return rv;
      }

      nghttp2_inbound_frame_reset(session);

      break;
    case NGHTTP2_IB_READ_GOAWAY_DEBUG:
    case NGHTTP2_IB_READ_ALTSVC:
#ifdef DEBUGBUILD
      if(iframe->state == NGHTTP2_IB_READ_GOAWAY_DEBUG) {
        fprintf(stderr, "recv: [IB_READ_GOAWAY_DEBUG]\n");
      } else {
        fprintf(stderr, "recv: [IB_READ_ALTSVC]\n");
      }
#endif /* DEBUGBUILD */

      readlen = inbound_frame_payload_readlen(iframe, in, last);

      iframe->lbuf.last = nghttp2_cpymem(iframe->lbuf.last, in, readlen);

      iframe->payloadleft -= readlen;
      in += readlen;

      DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu\n",
                     readlen, iframe->payloadleft));

      if(iframe->payloadleft) {
        assert(nghttp2_buf_avail(&iframe->lbuf) > 0);

        break;
      }

      if(iframe->state == NGHTTP2_IB_READ_GOAWAY_DEBUG) {
        rv = session_process_goaway_frame(session);
      } else {
        rv = session_process_altsvc_frame(session);
      }

      if(nghttp2_is_fatal(rv)) {
        return rv;
      }

      nghttp2_inbound_frame_reset(session);

      break;
    case NGHTTP2_IB_EXPECT_CONTINUATION:
    case NGHTTP2_IB_IGN_CONTINUATION:
#ifdef DEBUGBUILD
      if(iframe->state == NGHTTP2_IB_EXPECT_CONTINUATION) {
        fprintf(stderr, "recv: [IB_EXPECT_CONTINUATION]\n");
      } else {
        fprintf(stderr, "recv: [IB_IGN_CONTINUATION]\n");
      }
#endif /* DEBUGBUILD */

      readlen = inbound_frame_buf_read(iframe, in, last);
      in += readlen;

      if(nghttp2_buf_mark_avail(&iframe->sbuf)) {
        return in - first;
      }

      nghttp2_frame_unpack_frame_hd(&cont_hd, iframe->sbuf.pos);
      iframe->payloadleft = cont_hd.length;

      DEBUGF(fprintf(stderr,
                     "recv: payloadlen=%zu, type=%u, flags=0x%02x, "
                     "stream_id=%d\n",
                     cont_hd.length, cont_hd.type, cont_hd.flags,
                     cont_hd.stream_id));

      if(cont_hd.type != NGHTTP2_CONTINUATION ||
         cont_hd.stream_id != iframe->frame.hd.stream_id) {
        DEBUGF(fprintf(stderr,
                       "recv: expected stream_id=%d, type=%d, but "
                       "got stream_id=%d, type=%d\n",
                       iframe->frame.hd.stream_id, NGHTTP2_CONTINUATION,
                       cont_hd.stream_id, cont_hd.type));
        rv = nghttp2_session_terminate_session(session,
                                               NGHTTP2_PROTOCOL_ERROR);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        busy = 1;

        iframe->state = NGHTTP2_IB_IGN_PAYLOAD;

        break;
      }

      iframe->frame.hd.flags |= cont_hd.flags &
        (NGHTTP2_FLAG_END_HEADERS |
         NGHTTP2_FLAG_PAD_HIGH | NGHTTP2_FLAG_PAD_LOW);
      iframe->frame.hd.length += cont_hd.length;

      rv = inbound_frame_handle_pad(iframe, &cont_hd);
      if(rv < 0) {
        busy = 1;

        iframe->state = NGHTTP2_IB_IGN_PAYLOAD;

        rv = nghttp2_session_terminate_session(session,
                                               NGHTTP2_PROTOCOL_ERROR);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }
        break;
      }

      if(rv == 1) {
        if(iframe->state == NGHTTP2_IB_EXPECT_CONTINUATION) {
          iframe->state = NGHTTP2_IB_READ_PAD_CONTINUATION;
        } else {
          iframe->state = NGHTTP2_IB_IGN_PAD_CONTINUATION;
        }
        break;
      }

      busy = 1;

      if(iframe->state == NGHTTP2_IB_EXPECT_CONTINUATION) {
        iframe->state = NGHTTP2_IB_READ_HEADER_BLOCK;
      } else {
        iframe->state = NGHTTP2_IB_IGN_HEADER_BLOCK;
      }

      break;
    case NGHTTP2_IB_READ_PAD_CONTINUATION:
    case NGHTTP2_IB_IGN_PAD_CONTINUATION:
#ifdef DEBUGBUILD
      if(iframe->state == NGHTTP2_IB_READ_PAD_CONTINUATION) {
        fprintf(stderr, "recv: [IB_READ_PAD_CONTINUATION]\n");
      } else {
        fprintf(stderr, "recv: [IB_IGN_PAD_CONTINUATION]\n");
      }
#endif /* DEBUGBUILD */

      readlen = inbound_frame_buf_read(iframe, in, last);
      in += readlen;
      iframe->payloadleft -= readlen;

      DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu, left=%zu\n",
                     readlen, iframe->payloadleft,
                     nghttp2_buf_mark_avail(&iframe->sbuf)));

      if(nghttp2_buf_mark_avail(&iframe->sbuf)) {
        return in - first;
      }

      busy = 1;

      rv = inbound_frame_compute_pad(iframe);
      if(rv < 0) {
        rv = nghttp2_session_terminate_session(session,
                                               NGHTTP2_PROTOCOL_ERROR);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        iframe->state = NGHTTP2_IB_IGN_PAYLOAD;

        break;
      }

      iframe->padlen = rv;

      if(iframe->frame.hd.type == NGHTTP2_HEADERS) {
        iframe->frame.headers.padlen += rv;
      } else {
        iframe->frame.push_promise.padlen += rv;
      }

      if(iframe->state == NGHTTP2_IB_READ_PAD_CONTINUATION) {
        iframe->state = NGHTTP2_IB_READ_HEADER_BLOCK;
      } else {
        iframe->state = NGHTTP2_IB_IGN_HEADER_BLOCK;
      }

      break;
    case NGHTTP2_IB_READ_PAD_DATA:
      DEBUGF(fprintf(stderr, "recv: [IB_READ_PAD_DATA]\n"));

      readlen = inbound_frame_buf_read(iframe, in, last);
      in += readlen;
      iframe->payloadleft -= readlen;

      DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu, left=%zu\n",
                     readlen, iframe->payloadleft,
                     nghttp2_buf_mark_avail(&iframe->sbuf)));

      /* PAD_HIGH and PAD_LOW are subject to flow control */
      rv = nghttp2_session_update_recv_connection_window_size
        (session, readlen);
      if(nghttp2_is_fatal(rv)) {
        return rv;
      }

      stream = nghttp2_session_get_stream(session,
                                          iframe->frame.hd.stream_id);
      if(stream) {
        rv = nghttp2_session_update_recv_stream_window_size
          (session, stream, readlen,
           iframe->payloadleft ||
           (iframe->frame.hd.flags & NGHTTP2_FLAG_END_STREAM) == 0);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }
      }

      if(nghttp2_buf_mark_avail(&iframe->sbuf)) {
        return in - first;
      }

      busy = 1;

      rv = inbound_frame_compute_pad(iframe);
      if(rv < 0) {
        rv = nghttp2_session_terminate_session(session,
                                               NGHTTP2_PROTOCOL_ERROR);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }
        iframe->state = NGHTTP2_IB_IGN_DATA;
        break;
      }

      iframe->frame.data.padlen = rv;

      iframe->state = NGHTTP2_IB_READ_DATA;

      break;
    case NGHTTP2_IB_READ_DATA:
      DEBUGF(fprintf(stderr, "recv: [IB_READ_DATA]\n"));

      readlen = inbound_frame_payload_readlen(iframe, in, last);
      iframe->payloadleft -= readlen;
      in += readlen;

      DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu\n",
                     readlen, iframe->payloadleft));

      if(readlen > 0) {
        ssize_t data_readlen;

        rv = nghttp2_session_update_recv_connection_window_size
          (session, readlen);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }

        stream = nghttp2_session_get_stream(session,
                                            iframe->frame.hd.stream_id);
        if(stream) {
          rv = nghttp2_session_update_recv_stream_window_size
            (session, stream, readlen,
             iframe->payloadleft ||
             (iframe->frame.hd.flags & NGHTTP2_FLAG_END_STREAM) == 0);
          if(nghttp2_is_fatal(rv)) {
            return rv;
          }
        }

        data_readlen = inbound_frame_effective_readlen
          (iframe, iframe->payloadleft, readlen);

        DEBUGF(fprintf(stderr, "recv: data_readlen=%zu\n", data_readlen));

        if(data_readlen > 0 &&
           session->callbacks.on_data_chunk_recv_callback) {
          rv = session->callbacks.on_data_chunk_recv_callback
            (session,
             iframe->frame.hd.flags,
             iframe->frame.hd.stream_id,
             in - readlen,
             data_readlen,
             session->user_data);
          if(rv == NGHTTP2_ERR_PAUSE) {
            return in - first;
          }

          if(nghttp2_is_fatal(rv)) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
          }
        }
      }

      if(iframe->payloadleft) {
        break;
      }

      /* Clear PAD_HIGH and PAD_LOW, because we don't show these flags
         to user callback */
      session->iframe.frame.hd.flags &=
        ~(NGHTTP2_FLAG_PAD_HIGH | NGHTTP2_FLAG_PAD_LOW);

      rv = nghttp2_session_process_data_frame(session);
      if(nghttp2_is_fatal(rv)) {
        return rv;
      }

      nghttp2_inbound_frame_reset(session);

      break;
    case NGHTTP2_IB_IGN_DATA:
      DEBUGF(fprintf(stderr, "recv: [IB_IGN_DATA]\n"));

      readlen = inbound_frame_payload_readlen(iframe, in, last);
      iframe->payloadleft -= readlen;
      in += readlen;

      DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu\n",
                     readlen, iframe->payloadleft));

      if(readlen > 0) {
        /* Update connection-level flow control window for ignored
           DATA frame too */
        rv = nghttp2_session_update_recv_connection_window_size
          (session, readlen);
        if(nghttp2_is_fatal(rv)) {
          return rv;
        }
      }

      if(iframe->payloadleft) {
        break;
      }

      nghttp2_inbound_frame_reset(session);

      break;
    }

    if(!busy && in == last) {
      break;
    }

    busy = 0;
  }

  assert(in == last);

  return in - first;
}

int nghttp2_session_recv(nghttp2_session *session)
{
  uint8_t buf[NGHTTP2_INBOUND_BUFFER_LENGTH];
  while(1) {
    ssize_t readlen;
    readlen = nghttp2_recv(session, buf, sizeof(buf));
    if(readlen > 0) {
      ssize_t proclen = nghttp2_session_mem_recv(session, buf, readlen);
      if(proclen < 0) {
        return proclen;
      }
      assert(proclen == readlen);
    } else if(readlen == 0 || readlen == NGHTTP2_ERR_WOULDBLOCK) {
      return 0;
    } else if(readlen == NGHTTP2_ERR_EOF) {
      return readlen;
    } else if(readlen < 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
}

int nghttp2_session_want_read(nghttp2_session *session)
{
  /* If these flags are set, we don't want to read. The application
     should drop the connection. */
  if((session->goaway_flags & NGHTTP2_GOAWAY_FAIL_ON_SEND) &&
     (session->goaway_flags & NGHTTP2_GOAWAY_SEND)) {
    return 0;
  }
  /* Unless GOAWAY is sent or received, we always want to read
     incoming frames. After GOAWAY is sent or received, we are only
     interested in active streams. */
  return !session->goaway_flags || nghttp2_map_size(&session->streams) > 0;
}

int nghttp2_session_want_write(nghttp2_session *session)
{
  /* If these flags are set, we don't want to write any data. The
     application should drop the connection. */
  if((session->goaway_flags & NGHTTP2_GOAWAY_FAIL_ON_SEND) &&
     (session->goaway_flags & NGHTTP2_GOAWAY_SEND)) {
    return 0;
  }
  /*
   * Unless GOAWAY is sent or received, we want to write frames if
   * there is pending ones. If pending frame is request/push response
   * HEADERS and concurrent stream limit is reached, we don't want to
   * write them.  After GOAWAY is sent or received, we want to write
   * frames if there is pending ones AND there are active frames.
   */
  return (session->aob.item != NULL || !nghttp2_pq_empty(&session->ob_pq) ||
          (!nghttp2_pq_empty(&session->ob_ss_pq) &&
           !nghttp2_session_is_outgoing_concurrent_streams_max(session))) &&
    (!session->goaway_flags || nghttp2_map_size(&session->streams) > 0);
}

int nghttp2_session_add_ping(nghttp2_session *session, uint8_t flags,
                             uint8_t *opaque_data)
{
  int rv;
  nghttp2_frame *frame;
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  nghttp2_frame_ping_init(&frame->ping, flags, opaque_data);
  rv = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  if(rv != 0) {
    nghttp2_frame_ping_free(&frame->ping);
    free(frame);
    return rv;
  }
  return 0;
}

int nghttp2_session_add_goaway(nghttp2_session *session,
                               int32_t last_stream_id,
                               nghttp2_error_code error_code,
                               const uint8_t *opaque_data,
                               size_t opaque_data_len)
{
  int rv;
  nghttp2_frame *frame;
  uint8_t *opaque_data_copy = NULL;
  if(opaque_data_len) {
    if(opaque_data_len + 8 > NGHTTP2_MAX_PAYLOADLEN) {
      return NGHTTP2_ERR_INVALID_ARGUMENT;
    }
    opaque_data_copy = malloc(opaque_data_len);
    if(opaque_data_copy == NULL) {
      return NGHTTP2_ERR_NOMEM;
    }
    memcpy(opaque_data_copy, opaque_data, opaque_data_len);
  }
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    free(opaque_data_copy);
    return NGHTTP2_ERR_NOMEM;
  }
  nghttp2_frame_goaway_init(&frame->goaway, last_stream_id, error_code,
                            opaque_data_copy, opaque_data_len);
  rv = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  if(rv != 0) {
    nghttp2_frame_goaway_free(&frame->goaway);
    free(frame);
    return rv;
  }
  return 0;
}

int nghttp2_session_add_window_update(nghttp2_session *session, uint8_t flags,
                                      int32_t stream_id,
                                      int32_t window_size_increment)
{
  int rv;
  nghttp2_frame *frame;
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  nghttp2_frame_window_update_init(&frame->window_update, flags,
                                   stream_id, window_size_increment);
  rv = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  if(rv != 0) {
    nghttp2_frame_window_update_free(&frame->window_update);
    free(frame);
    return rv;
  }
  return 0;
}

int nghttp2_session_add_settings(nghttp2_session *session, uint8_t flags,
                                 const nghttp2_settings_entry *iv, size_t niv)
{
  nghttp2_frame *frame;
  nghttp2_settings_entry *iv_copy;
  size_t i;
  int rv;

  if(flags & NGHTTP2_FLAG_ACK) {
    if(niv != 0) {
      return NGHTTP2_ERR_INVALID_ARGUMENT;
    }
  } else if(session->inflight_niv != -1) {
    return NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS;
  }

  if(!nghttp2_iv_check(iv, niv)) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  if(niv > 0) {
    iv_copy = nghttp2_frame_iv_copy(iv, niv);
    if(iv_copy == NULL) {
      free(frame);
      return NGHTTP2_ERR_NOMEM;
    }
  } else {
    iv_copy = NULL;
  }

  if((flags & NGHTTP2_FLAG_ACK) == 0) {
    if(niv > 0) {
      session->inflight_iv = nghttp2_frame_iv_copy(iv, niv);

      if(session->inflight_iv == NULL) {
        free(iv_copy);
        free(frame);
        return NGHTTP2_ERR_NOMEM;
      }
    } else {
      session->inflight_iv = NULL;
    }

    session->inflight_niv = niv;
  }

  nghttp2_frame_settings_init(&frame->settings, flags, iv_copy, niv);
  rv = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  if(rv != 0) {
    /* The only expected error is fatal one */
    assert(nghttp2_is_fatal(rv));

    if((flags & NGHTTP2_FLAG_ACK) == 0) {
      free(session->inflight_iv);
      session->inflight_iv = NULL;
      session->inflight_niv = -1;
    }

    nghttp2_frame_settings_free(&frame->settings);
    free(frame);

    return rv;
  }

  /* Extract NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS here and use
     it to refuse the incoming streams with RST_STREAM. */
  for(i = niv; i > 0; --i) {
    if(iv[i - 1].settings_id == NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS) {
      session->pending_local_max_concurrent_stream = iv[i - 1].value;
      break;
    }
  }

  return 0;
}

int nghttp2_session_pack_data(nghttp2_session *session,
                              nghttp2_bufs *bufs,
                              size_t datamax,
                              nghttp2_private_data *frame)
{
  ssize_t rv;
  uint32_t data_flags;
  uint8_t flags;
  ssize_t payloadlen;
  ssize_t padded_payloadlen;
  size_t padlen;
  nghttp2_frame data_frame;
  nghttp2_frame_hd hd;
  nghttp2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->cur->buf;

  /* Current max DATA length is less then buffer chunk size */
  assert(nghttp2_buf_avail(buf) >= (ssize_t)datamax);

  data_flags = NGHTTP2_DATA_FLAG_NONE;
  payloadlen = frame->data_prd.read_callback
    (session, frame->hd.stream_id, buf->pos, datamax,
     &data_flags, &frame->data_prd.source, session->user_data);

  if(payloadlen == NGHTTP2_ERR_DEFERRED ||
     payloadlen == NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE) {
    DEBUGF(fprintf(stderr, "send: DATA postponed due to %s\n",
                   nghttp2_strerror(payloadlen)));

    return payloadlen;
  }

  if(payloadlen < 0 || datamax < (size_t)payloadlen) {
    /* This is the error code when callback is failed. */
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  buf->last = buf->pos + payloadlen;
  buf->pos -= NGHTTP2_FRAME_HDLEN;

  /* Clear flags, because this may contain previous flags of previous
     DATA */
  frame->hd.flags &= (NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_SEGMENT);
  flags = NGHTTP2_FLAG_NONE;

  if(data_flags & NGHTTP2_DATA_FLAG_EOF) {
    frame->eof = 1;
    if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      flags |= NGHTTP2_FLAG_END_STREAM;
    }
    if(frame->hd.flags & NGHTTP2_FLAG_END_SEGMENT) {
      flags |= NGHTTP2_FLAG_END_SEGMENT;
    }
  }

  if(data_flags & NGHTTP2_DATA_FLAG_COMPRESSED) {
    flags |= NGHTTP2_FLAG_COMPRESSED;
  }

  /* The primary reason of data_frame is pass to the user callback */
  data_frame.hd.length = payloadlen;
  data_frame.hd.stream_id = frame->hd.stream_id;
  data_frame.hd.type = NGHTTP2_DATA;
  data_frame.hd.flags = flags;
  data_frame.data.padlen = 0;

  padded_payloadlen = session_call_select_padding(session, &data_frame,
                                                  datamax);
  if(nghttp2_is_fatal(padded_payloadlen)) {
    return padded_payloadlen;
  }

  padlen = padded_payloadlen - payloadlen;

  hd = frame->hd;
  hd.length = payloadlen;
  hd.flags = flags;

  nghttp2_frame_pack_frame_hd(buf->pos, &hd);

  rv = nghttp2_frame_add_pad(bufs, &hd, padlen, NGHTTP2_DATA);
  if(rv != 0) {
    return rv;
  }

  frame->hd.length = hd.length;
  frame->hd.flags |= hd.flags;
  frame->padlen = padlen;

  return 0;
}

void* nghttp2_session_get_stream_user_data(nghttp2_session *session,
                                           int32_t stream_id)
{
  nghttp2_stream *stream;
  stream = nghttp2_session_get_stream(session, stream_id);
  if(stream) {
    return stream->stream_user_data;
  } else {
    return NULL;
  }
}

int nghttp2_session_set_stream_user_data(nghttp2_session *session,
                                         int32_t stream_id,
                                         void *stream_user_data)
{
  nghttp2_stream *stream;
  stream = nghttp2_session_get_stream(session, stream_id);
  if(!stream) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  stream->stream_user_data = stream_user_data;
  return 0;
}

int nghttp2_session_resume_data(nghttp2_session *session, int32_t stream_id)
{
  int rv;
  nghttp2_stream *stream;
  stream = nghttp2_session_get_stream(session, stream_id);
  if(stream == NULL ||
     nghttp2_stream_check_deferred_by_flow_control(stream) ||
     !nghttp2_stream_check_deferred_data(stream)) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }

  rv = nghttp2_stream_resume_deferred_data(stream, &session->ob_pq);

  if(nghttp2_is_fatal(rv)) {
    return rv;
  }

  return rv;
}

size_t nghttp2_session_get_outbound_queue_size(nghttp2_session *session)
{
  return nghttp2_pq_size(&session->ob_pq)+nghttp2_pq_size(&session->ob_ss_pq);
}

int32_t nghttp2_session_get_stream_effective_recv_data_length
(nghttp2_session *session, int32_t stream_id)
{
  nghttp2_stream *stream;
  stream = nghttp2_session_get_stream(session, stream_id);
  if(stream == NULL) {
    return -1;
  }
  return stream->recv_window_size < 0 ? 0 : stream->recv_window_size;
}

int32_t nghttp2_session_get_stream_effective_local_window_size
(nghttp2_session *session, int32_t stream_id)
{
  nghttp2_stream *stream;
  stream = nghttp2_session_get_stream(session, stream_id);
  if(stream == NULL) {
    return -1;
  }
  return stream->local_window_size;
}

int32_t nghttp2_session_get_effective_recv_data_length
(nghttp2_session *session)
{
  return session->recv_window_size < 0 ? 0 : session->recv_window_size;
}

int32_t nghttp2_session_get_effective_local_window_size
(nghttp2_session *session)
{
  return session->local_window_size;
}

int32_t nghttp2_session_get_stream_remote_window_size(nghttp2_session* session,
                                                      int32_t stream_id)
{
  nghttp2_stream *stream;

  stream = nghttp2_session_get_stream(session, stream_id);
  if(stream == NULL) {
    return -1;
  }

  return nghttp2_session_next_data_read(session, stream);
}

int nghttp2_session_upgrade(nghttp2_session *session,
                            const uint8_t *settings_payload,
                            size_t settings_payloadlen,
                            void *stream_user_data)
{
  nghttp2_stream *stream;
  nghttp2_frame frame;
  nghttp2_settings_entry *iv;
  size_t niv;
  int rv;
  nghttp2_priority_spec pri_spec;

  if((!session->server && session->next_stream_id != 1) ||
     (session->server && session->last_recv_stream_id >= 1)) {
    return NGHTTP2_ERR_PROTO;
  }
  if(settings_payloadlen % NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  rv = nghttp2_frame_unpack_settings_payload2(&iv, &niv, settings_payload,
                                              settings_payloadlen);
  if(rv != 0) {
    return rv;
  }

  if(session->server) {
    memset(&frame.hd, 0, sizeof(frame.hd));
    frame.settings.iv = iv;
    frame.settings.niv = niv;
    rv = nghttp2_session_on_settings_received(session, &frame, 1 /* No ACK */);
  } else {
    rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, niv);
  }
  free(iv);
  if(rv != 0) {
    return rv;
  }

  nghttp2_priority_spec_default_init(&pri_spec);

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec, NGHTTP2_STREAM_OPENING,
                                       session->server ?
                                       NULL : stream_user_data);
  if(stream == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  if(session->server) {
    nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
    session->last_recv_stream_id = 1;
    session->last_proc_stream_id = 1;
  } else {
    nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
    session->next_stream_id += 2;
  }
  return 0;
}
