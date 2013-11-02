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
#include "nghttp2_session.h"

#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>

#include "nghttp2_helper.h"
#include "nghttp2_net.h"

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
 * Returns non-zero if |error| is non-fatal error.
 */
static int nghttp2_is_non_fatal(int error)
{
  return error < 0 && error > NGHTTP2_ERR_FATAL;
}

/*
 * Returns non-zero if |error| is fatal error.
 */
static int nghttp2_is_fatal(int error)
{
  return error < NGHTTP2_ERR_FATAL;
}

/* Returns the pushed stream's priority based on the associated stream
   |stream|. */
static int32_t nghttp2_pushed_stream_pri(nghttp2_stream *stream)
{
  return stream->pri == NGHTTP2_PRI_LOWEST ?
    (int32_t)NGHTTP2_PRI_LOWEST : stream->pri + 1;
}

int nghttp2_session_fail_session(nghttp2_session *session,
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
  int r;
  if(stream_id == 0) {
    return 0;
  }
  r = stream_id % 2;
  return (session->server && r == 0) || (!session->server && r == 1);
}

nghttp2_stream* nghttp2_session_get_stream(nghttp2_session *session,
                                           int32_t stream_id)
{
  return (nghttp2_stream*)nghttp2_map_find(&session->streams, stream_id);
}

static int nghttp2_outbound_item_compar(const void *lhsx, const void *rhsx)
{
  const nghttp2_outbound_item *lhs, *rhs;
  lhs = (const nghttp2_outbound_item*)lhsx;
  rhs = (const nghttp2_outbound_item*)rhsx;
  if(lhs->pri == rhs->pri) {
    return (lhs->seq < rhs->seq) ? -1 : ((lhs->seq > rhs->seq) ? 1 : 0);
  } else {
    return lhs->pri - rhs->pri;
  }
}

static void nghttp2_inbound_frame_reset(nghttp2_session *session)
{
  nghttp2_inbound_frame *iframe = &session->iframe;
  if(iframe->error_code == NGHTTP2_ERR_PAUSE) {
    switch(iframe->frame.hd.type) {
    case NGHTTP2_HEADERS:
      nghttp2_frame_headers_free(&iframe->frame.headers);
      nghttp2_hd_end_headers(&session->hd_inflater);
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
      nghttp2_hd_end_headers(&session->hd_inflater);
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
    }
  }
  iframe->state = NGHTTP2_RECV_HEAD;
  iframe->payloadlen = iframe->buflen = iframe->off = 0;
  iframe->headbufoff = 0;
  iframe->error_code = 0;
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
  settings[NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS] = 0;
}

static int nghttp2_session_new(nghttp2_session **session_ptr,
                               const nghttp2_session_callbacks *callbacks,
                               void *user_data,
                               int server)
{
  int r;
  nghttp2_hd_side side_deflate, side_inflate;
  *session_ptr = malloc(sizeof(nghttp2_session));
  if(*session_ptr == NULL) {
    r = NGHTTP2_ERR_NOMEM;
    goto fail_session;
  }
  memset(*session_ptr, 0, sizeof(nghttp2_session));

  /* next_stream_id and last_recv_stream_id are initialized in either
     nghttp2_session_client_new or nghttp2_session_server_new */

  (*session_ptr)->next_seq = 0;

  (*session_ptr)->remote_flow_control = 1;
  (*session_ptr)->local_flow_control = 1;
  (*session_ptr)->remote_window_size = NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE;
  (*session_ptr)->recv_window_size = 0;
  (*session_ptr)->recv_reduction = 0;
  (*session_ptr)->local_window_size = NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE;

  (*session_ptr)->goaway_flags = NGHTTP2_GOAWAY_NONE;
  (*session_ptr)->last_stream_id = 0;

  (*session_ptr)->inflight_niv = -1;

  if(server) {
    (*session_ptr)->server = 1;
    side_deflate = NGHTTP2_HD_SIDE_RESPONSE;
    side_inflate = NGHTTP2_HD_SIDE_REQUEST;
  } else {
    side_deflate = NGHTTP2_HD_SIDE_REQUEST;
    side_inflate = NGHTTP2_HD_SIDE_RESPONSE;
  }
  r = nghttp2_hd_deflate_init(&(*session_ptr)->hd_deflater, side_deflate);
  if(r != 0) {
    goto fail_hd_deflater;
  }
  r = nghttp2_hd_inflate_init(&(*session_ptr)->hd_inflater, side_inflate);
  if(r != 0) {
    goto fail_hd_inflater;
  }
  nghttp2_map_init(&(*session_ptr)->streams);
  r = nghttp2_pq_init(&(*session_ptr)->ob_pq, nghttp2_outbound_item_compar);
  if(r != 0) {
    goto fail_ob_pq;
  }
  r = nghttp2_pq_init(&(*session_ptr)->ob_ss_pq, nghttp2_outbound_item_compar);
  if(r != 0) {
    goto fail_ob_ss_pq;
  }

  (*session_ptr)->aob.framebuf = malloc
    (NGHTTP2_INITIAL_OUTBOUND_FRAMEBUF_LENGTH);
  if((*session_ptr)->aob.framebuf == NULL) {
    r = NGHTTP2_ERR_NOMEM;
    goto fail_aob_framebuf;
  }
  (*session_ptr)->aob.framebufmax = NGHTTP2_INITIAL_OUTBOUND_FRAMEBUF_LENGTH;

  (*session_ptr)->nvbuf = malloc(NGHTTP2_INITIAL_NV_BUFFER_LENGTH);
  if((*session_ptr)->nvbuf == NULL) {
    r = NGHTTP2_ERR_NOMEM;
    goto fail_nvbuf;
  }
  (*session_ptr)->nvbuflen = NGHTTP2_INITIAL_NV_BUFFER_LENGTH;

  memset((*session_ptr)->remote_settings, 0,
         sizeof((*session_ptr)->remote_settings));
  memset((*session_ptr)->local_settings, 0,
         sizeof((*session_ptr)->local_settings));

  init_settings((*session_ptr)->remote_settings);
  init_settings((*session_ptr)->local_settings);

  (*session_ptr)->callbacks = *callbacks;
  (*session_ptr)->user_data = user_data;

  (*session_ptr)->iframe.buf = malloc(NGHTTP2_INITIAL_INBOUND_FRAMEBUF_LENGTH);
  if((*session_ptr)->iframe.buf == NULL) {
    r = NGHTTP2_ERR_NOMEM;
    goto fail_iframe_buf;
  }
  (*session_ptr)->iframe.bufmax = NGHTTP2_INITIAL_INBOUND_FRAMEBUF_LENGTH;

  nghttp2_inbound_frame_reset(*session_ptr);

  return 0;

 fail_iframe_buf:
  free((*session_ptr)->nvbuf);
 fail_nvbuf:
  free((*session_ptr)->aob.framebuf);
 fail_aob_framebuf:
  nghttp2_pq_free(&(*session_ptr)->ob_ss_pq);
 fail_ob_ss_pq:
  nghttp2_pq_free(&(*session_ptr)->ob_pq);
 fail_ob_pq:
  /* No need to free (*session_ptr)->streams) here. */
  nghttp2_hd_inflate_free(&(*session_ptr)->hd_inflater);
 fail_hd_inflater:
  nghttp2_hd_deflate_free(&(*session_ptr)->hd_deflater);
 fail_hd_deflater:
  free(*session_ptr);
 fail_session:
  return r;
}

int nghttp2_session_client_new(nghttp2_session **session_ptr,
                               const nghttp2_session_callbacks *callbacks,
                               void *user_data)
{
  int r;
  /* For client side session, header compression is disabled. */
  r = nghttp2_session_new(session_ptr, callbacks, user_data, 0);
  if(r == 0) {
    /* IDs for use in client */
    (*session_ptr)->next_stream_id = 1;
    (*session_ptr)->last_recv_stream_id = 0;
  }
  return r;
}

int nghttp2_session_server_new(nghttp2_session **session_ptr,
                               const nghttp2_session_callbacks *callbacks,
                               void *user_data)
{
  int r;
  /* Enable header compression on server side. */
  r = nghttp2_session_new(session_ptr, callbacks, user_data, 1);
  if(r == 0) {
    /* IDs for use in client */
    (*session_ptr)->next_stream_id = 2;
    (*session_ptr)->last_recv_stream_id = 0;
  }
  return r;
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

static void nghttp2_active_outbound_item_reset
(nghttp2_active_outbound_item *aob)
{
  nghttp2_outbound_item_free(aob->item);
  free(aob->item);
  aob->item = NULL;
  aob->framebuflen = aob->framebufoff = 0;
}

void nghttp2_session_del(nghttp2_session *session)
{
  if(session == NULL) {
    return;
  }
  free(session->inflight_iv);
  nghttp2_inbound_frame_reset(session);
  nghttp2_map_each_free(&session->streams, nghttp2_free_streams, NULL);
  nghttp2_session_ob_pq_free(&session->ob_pq);
  nghttp2_session_ob_pq_free(&session->ob_ss_pq);
  nghttp2_hd_deflate_free(&session->hd_deflater);
  nghttp2_hd_inflate_free(&session->hd_inflater);
  nghttp2_active_outbound_item_reset(&session->aob);
  free(session->aob.framebuf);
  free(session->nvbuf);
  free(session->iframe.buf);
   free(session);
}

static int outbound_item_update_pri
(nghttp2_outbound_item *item, nghttp2_stream *stream)
{
  if(item->frame_cat == NGHTTP2_CAT_CTRL) {
    if(((nghttp2_frame*)item->frame)->hd.stream_id != stream->stream_id) {
      return 0;
    }
    switch(((nghttp2_frame*)item->frame)->hd.type) {
    case NGHTTP2_HEADERS:
    case NGHTTP2_PUSH_PROMISE:
      break;
    default:
      return 0;
    }
  } else {
    if(((nghttp2_data*)item->frame)->hd.stream_id != stream->stream_id) {
      return 0;
    }
  }
  item->pri = stream->pri;
  return 1;
}

static int update_stream_pri(void *ptr, void *arg)
{
  nghttp2_outbound_item *item = (nghttp2_outbound_item*)ptr;
  nghttp2_stream *stream = (nghttp2_stream*)arg;
  return outbound_item_update_pri(item, stream);
}

void nghttp2_session_reprioritize_stream
(nghttp2_session *session, nghttp2_stream *stream, int32_t pri)
{
  if(stream->pri == pri) {
    return;
  }
  stream->pri = pri;
  nghttp2_pq_update(&session->ob_pq, update_stream_pri, stream);
  nghttp2_pq_update(&session->ob_ss_pq, update_stream_pri, stream);
  if(stream->deferred_data) {
    stream->deferred_data->pri = pri;
  }
  if(session->aob.item) {
    outbound_item_update_pri(session->aob.item, stream);
  }
}

int nghttp2_session_add_frame(nghttp2_session *session,
                              nghttp2_frame_category frame_cat,
                              void *abs_frame,
                              void *aux_data)
{
  /* TODO Return error if stream is not found for the frame requiring
     stream presence. */
  int r = 0;
  nghttp2_outbound_item *item;
  item = malloc(sizeof(nghttp2_outbound_item));
  if(item == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  item->frame_cat = frame_cat;
  item->frame = abs_frame;
  item->aux_data = aux_data;
  item->seq = session->next_seq++;
  /* Set priority to the default value at the moment. */
  item->pri = NGHTTP2_PRI_DEFAULT;
  if(frame_cat == NGHTTP2_CAT_CTRL) {
    nghttp2_frame *frame = (nghttp2_frame*)abs_frame;
    nghttp2_stream *stream = NULL;
    switch(frame->hd.type) {
    case NGHTTP2_HEADERS:
      if(frame->hd.stream_id == -1) {
        /* Initial HEADERS, which will open stream */
        item->pri = frame->headers.pri;
      } else {
        /* Otherwise, the frame must have stream ID. We use its
           priority value. */
        stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
        if(stream) {
          item->pri = stream->pri;
        }
      }
      break;
    case NGHTTP2_PRIORITY:
      item->pri = -1;
      break;
    case NGHTTP2_RST_STREAM:
      stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
      if(stream) {
        stream->state = NGHTTP2_STREAM_CLOSING;
      }
      item->pri = -1;
      break;
    case NGHTTP2_SETTINGS:
      item->pri = NGHTTP2_OB_PRI_SETTINGS;
      break;
    case NGHTTP2_PUSH_PROMISE:
      /* Use priority of associated stream */
      stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
      if(stream) {
        item->pri = stream->pri;
      }
      break;
    case NGHTTP2_PING:
      /* Ping has highest priority. */
      item->pri = NGHTTP2_OB_PRI_PING;
      break;
    case NGHTTP2_GOAWAY:
      /* Should GOAWAY have higher priority? */
      break;
    case NGHTTP2_WINDOW_UPDATE:
      item->pri = -1;
      break;
    }
    if(frame->hd.type == NGHTTP2_HEADERS &&
       (frame->hd.stream_id == -1 ||
        (stream && stream->state == NGHTTP2_STREAM_RESERVED &&
         session->server))) {
      /* TODO If 2 HEADERS are submitted for reserved stream, then
         both of them are queued into ob_ss_pq, which is not
         desirable. */
      r = nghttp2_pq_push(&session->ob_ss_pq, item);
    } else {
      r = nghttp2_pq_push(&session->ob_pq, item);
    }
  } else if(frame_cat == NGHTTP2_CAT_DATA) {
    nghttp2_data *data_frame = (nghttp2_data*)abs_frame;
    nghttp2_stream *stream;
    stream = nghttp2_session_get_stream(session, data_frame->hd.stream_id);
    if(stream) {
      item->pri = stream->pri;
    }
    r = nghttp2_pq_push(&session->ob_pq, item);
  } else {
    /* Unreachable */
    assert(0);
  }
  if(r != 0) {
    free(item);
    return r;
  }
  return 0;
}

int nghttp2_session_add_rst_stream(nghttp2_session *session,
                                   int32_t stream_id,
                                   nghttp2_error_code error_code)
{
  int r;
  nghttp2_frame *frame;
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  nghttp2_frame_rst_stream_init(&frame->rst_stream, stream_id, error_code);
  r = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  if(r != 0) {
    nghttp2_frame_rst_stream_free(&frame->rst_stream);
    free(frame);
    return r;
  }
  return 0;
}

nghttp2_stream* nghttp2_session_open_stream(nghttp2_session *session,
                                            int32_t stream_id,
                                            uint8_t flags, int32_t pri,
                                            nghttp2_stream_state initial_state,
                                            void *stream_user_data)
{
  int r;
  nghttp2_stream *stream = malloc(sizeof(nghttp2_stream));
  if(stream == NULL) {
    return NULL;
  }
  nghttp2_stream_init(stream, stream_id, flags, pri, initial_state,
                      !session->remote_settings
                      [NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS],
                      !session->local_settings
                      [NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS],
                      session->remote_settings
                      [NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE],
                      session->local_settings
                      [NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE],
                      stream_user_data);
  r = nghttp2_map_insert(&session->streams, &stream->map_entry);
  if(r != 0) {
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
  return stream;
}

/*
 * Closes stream with stream ID |stream_id|. The |error_code|
 * indicates the reason of the closure.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_ARGUMENT
 *   The stream is not found.
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *   The callback function failed.
 */
int nghttp2_session_close_stream(nghttp2_session *session, int32_t stream_id,
                                 nghttp2_error_code error_code)
{
  nghttp2_stream *stream = nghttp2_session_get_stream(session, stream_id);
  if(!stream) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  /* We call on_stream_close_callback even if stream->state is
     NGHTTP2_STREAM_INITIAL. This will happen while sending request
     HEADERS, a local endpoint receives RST_STREAM for that stream. It
     may be PROTOCOL_ERROR, but without notifying stream closure will
     hang the stream in a local endpoint.
  */
  /* TODO Should on_stream_close_callback be called against
     NGHTTP2_STREAM_RESERVED? It is actually not opened yet. */
  if(stream->state != NGHTTP2_STREAM_RESERVED) {
    if(session->callbacks.on_stream_close_callback) {
      if(session->callbacks.on_stream_close_callback
         (session, stream_id,
          error_code,
          session->user_data) != 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }
    if(nghttp2_session_is_my_stream_id(session, stream_id)) {
      --session->num_outgoing_streams;
    } else {
      --session->num_incoming_streams;
    }
  }
  nghttp2_map_remove(&session->streams, stream_id);
  nghttp2_stream_free(stream);
  free(stream);
  return 0;
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
  int r;
  r = nghttp2_predicate_stream_for_send(stream);
  if(r != 0) {
    return r;
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
 *   The session is client-side and/or stream is not reserved state
 * NGHTTP2_ERR_STREAM_CLOSED
 *   RST_STREAM was queued for this stream.
 */
static int nghttp2_session_predicate_push_response_headers_send
(nghttp2_session *session, int32_t stream_id)
{
  nghttp2_stream *stream = nghttp2_session_get_stream(session, stream_id);
  int r;
  /* TODO Should disallow HEADERS if GOAWAY has already been issued? */
  r = nghttp2_predicate_stream_for_send(stream);
  if(r != 0) {
    return r;
  }
  if(!session->server || stream->state != NGHTTP2_STREAM_RESERVED) {
    /* Only server can send HEADERS for reserved streams */
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
  int r;
  r = nghttp2_predicate_stream_for_send(stream);
  if(r != 0) {
    return r;
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
  /* Sending PRIORITY to reserved state is OK */
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
 */
static int nghttp2_session_predicate_push_promise_send
(nghttp2_session *session, int32_t stream_id)
{
  int rv;
  nghttp2_stream *stream;
  if(!session->server || nghttp2_session_is_my_stream_id(session, stream_id)) {
    /* Only server is allowed to push. And associated stream must be
       created from client side */
    return NGHTTP2_ERR_PROTO;
  }
  stream = nghttp2_session_get_stream(session, stream_id);
  rv = nghttp2_predicate_stream_for_send(stream);
  if(rv != 0) {
    return rv;
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
 * This function checks SETTINGS can be sent at this time.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS
 *     There is already another in-flight SETTINGS.  Note that the
 *     current implementation only allows 1 in-flight SETTINGS frame
 *     without ACK flag set.
 */
static int nghttp2_session_predicate_settings_send(nghttp2_session *session,
                                                   nghttp2_frame *frame)
{
  if((frame->hd.flags & NGHTTP2_FLAG_ACK) == 0 &&
     session->inflight_niv != -1) {
    return NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS;
  }
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
  int32_t session_window_size;
  int32_t stream_window_size;
  int32_t window_size;
  /* Take into account both connection-level flow control here */
  if(session->remote_flow_control == 0 && stream->remote_flow_control == 0) {
    return NGHTTP2_DATA_PAYLOAD_LENGTH;
  }
  session_window_size =
    session->remote_flow_control ? session->remote_window_size : INT32_MAX;
  stream_window_size =
    stream->remote_flow_control ? stream->remote_window_size : INT32_MAX;
  window_size = nghttp2_min(session_window_size, stream_window_size);
  if(window_size > 0) {
    return nghttp2_min(window_size, NGHTTP2_DATA_PAYLOAD_LENGTH);
  } else {
    return 0;
  }
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
 * NGHTTP2_ERR_DEFERRED_DATA_EXIST
 *     Another DATA frame has already been deferred.
 * NGHTTP2_ERR_STREAM_CLOSING
 *     RST_STREAM was queued for this stream.
 * NGHTTP2_ERR_INVALID_STREAM_STATE
 *     The state of the stream is not valid.
 */
static int nghttp2_session_predicate_data_send(nghttp2_session *session,
                                               int32_t stream_id)
{
  nghttp2_stream *stream = nghttp2_session_get_stream(session, stream_id);
  int r;
  r = nghttp2_predicate_stream_for_send(stream);
  if(r != 0) {
    return r;
  }
  if(stream->deferred_data != NULL) {
    /* stream->deferred_data != NULL means previously queued DATA
       frame has not been sent. We don't allow new DATA frame is sent
       in this case. */
    return NGHTTP2_ERR_DEFERRED_DATA_EXIST;
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

static ssize_t nghttp2_session_prep_frame(nghttp2_session *session,
                                          nghttp2_outbound_item *item)
{
  ssize_t framebuflen = 0;
  if(item->frame_cat == NGHTTP2_CAT_CTRL) {
    nghttp2_frame *frame;
    frame = nghttp2_outbound_item_get_ctrl_frame(item);
    switch(frame->hd.type) {
    case NGHTTP2_HEADERS: {
      if(frame->hd.stream_id == -1) {
        /* initial HEADERS, which opens stream */
        int r;
        frame->headers.cat = NGHTTP2_HCAT_REQUEST;
        r = nghttp2_session_predicate_request_headers_send(session,
                                                           &frame->headers);
        if(r != 0) {
          return r;
        }
        frame->hd.stream_id = session->next_stream_id;
        session->next_stream_id += 2;
      } else if(nghttp2_session_predicate_push_response_headers_send
                (session, frame->hd.stream_id) == 0) {
        frame->headers.cat = NGHTTP2_HCAT_PUSH_RESPONSE;
      } else if(nghttp2_session_predicate_response_headers_send
                (session, frame->hd.stream_id) == 0) {
        frame->headers.cat = NGHTTP2_HCAT_RESPONSE;
      } else {
        int r;
        frame->headers.cat = NGHTTP2_HCAT_HEADERS;
        r = nghttp2_session_predicate_headers_send(session,
                                                   frame->hd.stream_id);
        if(r != 0) {
          return r;
        }
      }
      framebuflen = nghttp2_frame_pack_headers(&session->aob.framebuf,
                                               &session->aob.framebufmax,
                                               &frame->headers,
                                               &session->hd_deflater);
      nghttp2_hd_end_headers(&session->hd_deflater);
      if(framebuflen < 0) {
        return framebuflen;
      }
      switch(frame->headers.cat) {
      case NGHTTP2_HCAT_REQUEST: {
        nghttp2_headers_aux_data *aux_data;
        aux_data = (nghttp2_headers_aux_data*)item->aux_data;
        if(nghttp2_session_open_stream
           (session, frame->hd.stream_id,
            frame->hd.flags,
            frame->headers.pri,
            NGHTTP2_STREAM_INITIAL,
            aux_data ? aux_data->stream_user_data : NULL) == NULL) {
          return NGHTTP2_ERR_NOMEM;
        }
        break;
      }
      case NGHTTP2_HCAT_PUSH_RESPONSE: {
        nghttp2_headers_aux_data *aux_data;
        aux_data = (nghttp2_headers_aux_data*)item->aux_data;
        if(aux_data) {
          nghttp2_stream *stream;
          stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
          stream->stream_user_data = aux_data->stream_user_data;
        }
        break;
      }
      default:
        break;
      }
      break;
    }
    case NGHTTP2_PRIORITY: {
      int r;
      r = nghttp2_session_predicate_priority_send
        (session, frame->hd.stream_id);
      if(r != 0) {
        return r;
      }
      framebuflen = nghttp2_frame_pack_priority(&session->aob.framebuf,
                                                &session->aob.framebufmax,
                                                &frame->priority);
      if(framebuflen < 0) {
        return framebuflen;
      }
      break;
    }
    case NGHTTP2_RST_STREAM:
      framebuflen = nghttp2_frame_pack_rst_stream(&session->aob.framebuf,
                                                  &session->aob.framebufmax,
                                                  &frame->rst_stream);
      if(framebuflen < 0) {
        return framebuflen;
      }
      break;
    case NGHTTP2_SETTINGS: {
      int r;
      r = nghttp2_session_predicate_settings_send(session, frame);
      if(r != 0) {
        return r;
      }
      framebuflen = nghttp2_frame_pack_settings(&session->aob.framebuf,
                                                &session->aob.framebufmax,
                                                &frame->settings);
      if(framebuflen < 0) {
        return framebuflen;
      }
      break;
    }
    case NGHTTP2_PUSH_PROMISE: {
      int r;
      nghttp2_stream *stream;
      r = nghttp2_session_predicate_push_promise_send(session,
                                                      frame->hd.stream_id);
      if(r != 0) {
        return r;
      }
      frame->push_promise.promised_stream_id = session->next_stream_id;
      session->next_stream_id += 2;
      framebuflen = nghttp2_frame_pack_push_promise(&session->aob.framebuf,
                                                    &session->aob.framebufmax,
                                                    &frame->push_promise,
                                                    &session->hd_deflater);
      nghttp2_hd_end_headers(&session->hd_deflater);
      if(framebuflen < 0) {
        return framebuflen;
      }
      stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
      assert(stream);
      if(nghttp2_session_open_stream
         (session, frame->push_promise.promised_stream_id,
          frame->hd.flags,
          nghttp2_pushed_stream_pri(stream),
          NGHTTP2_STREAM_RESERVED,
          NULL) == NULL) {
        return NGHTTP2_ERR_NOMEM;
      }
      break;
    }
    case NGHTTP2_PING:
      framebuflen = nghttp2_frame_pack_ping(&session->aob.framebuf,
                                            &session->aob.framebufmax,
                                            &frame->ping);
      if(framebuflen < 0) {
        return framebuflen;
      }
      break;
    case NGHTTP2_WINDOW_UPDATE: {
      int r;
      r = nghttp2_session_predicate_window_update_send
        (session, frame->hd.stream_id);
      if(r != 0) {
        return r;
      }
      framebuflen = nghttp2_frame_pack_window_update(&session->aob.framebuf,
                                                     &session->aob.framebufmax,
                                                     &frame->window_update);
      if(framebuflen < 0) {
        return framebuflen;
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
      framebuflen = nghttp2_frame_pack_goaway(&session->aob.framebuf,
                                              &session->aob.framebufmax,
                                              &frame->goaway);
      if(framebuflen < 0) {
        return framebuflen;
      }
      break;
    default:
      framebuflen = NGHTTP2_ERR_INVALID_ARGUMENT;
    }
  } else if(item->frame_cat == NGHTTP2_CAT_DATA) {
    size_t next_readmax;
    nghttp2_stream *stream;
    nghttp2_data *data_frame;
    int r;
    data_frame = nghttp2_outbound_item_get_data_frame(item);
    r = nghttp2_session_predicate_data_send(session, data_frame->hd.stream_id);
    if(r != 0) {
      return r;
    }
    stream = nghttp2_session_get_stream(session, data_frame->hd.stream_id);
    /* Assuming stream is not NULL */
    assert(stream);
    next_readmax = nghttp2_session_next_data_read(session, stream);
    if(next_readmax == 0) {
      nghttp2_stream_defer_data(stream, item, NGHTTP2_DEFERRED_FLOW_CONTROL);
      return NGHTTP2_ERR_DEFERRED;
    }
    framebuflen = nghttp2_session_pack_data(session,
                                            &session->aob.framebuf,
                                            &session->aob.framebufmax,
                                            next_readmax,
                                            data_frame);
    if(framebuflen == NGHTTP2_ERR_DEFERRED) {
      nghttp2_stream_defer_data(stream, item, NGHTTP2_DEFERRED_NONE);
      return NGHTTP2_ERR_DEFERRED;
    } else if(framebuflen == NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE) {
      r = nghttp2_session_add_rst_stream(session, data_frame->hd.stream_id,
                                         NGHTTP2_INTERNAL_ERROR);
      if(r == 0) {
        return framebuflen;
      } else {
        return r;
      }
    } else if(framebuflen < 0) {
      return framebuflen;
    }
  } else {
    /* Unreachable */
    assert(0);
  }
  return framebuflen;
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
         item->pri < headers_item->pri ||
         (item->pri == headers_item->pri &&
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
        return item;
      }
    }
  } else {
    if(nghttp2_pq_empty(&session->ob_ss_pq)) {
      nghttp2_outbound_item *item;
      item = nghttp2_pq_top(&session->ob_pq);
      nghttp2_pq_pop(&session->ob_pq);
      return item;
    } else {
      nghttp2_outbound_item *item, *headers_item;
      item = nghttp2_pq_top(&session->ob_pq);
      headers_item = nghttp2_pq_top(&session->ob_ss_pq);
      if(nghttp2_session_is_outgoing_concurrent_streams_max(session) ||
         item->pri < headers_item->pri ||
         (item->pri == headers_item->pri &&
          item->seq < headers_item->seq)) {
        nghttp2_pq_pop(&session->ob_pq);
        return item;
      } else {
        nghttp2_pq_pop(&session->ob_ss_pq);
        return headers_item;
      }
    }
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
  nghttp2_outbound_item *item = session->aob.item;
  if(item->frame_cat == NGHTTP2_CAT_CTRL) {
    int r;
    nghttp2_frame *frame;
    frame = nghttp2_outbound_item_get_ctrl_frame(session->aob.item);
    if(session->callbacks.on_frame_send_callback) {
      if(session->callbacks.on_frame_send_callback(session, frame,
                                                   session->user_data) != 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }
    switch(frame->hd.type) {
    case NGHTTP2_HEADERS: {
      nghttp2_stream *stream =
        nghttp2_session_get_stream(session, frame->hd.stream_id);
      nghttp2_headers_aux_data *aux_data;
      if(stream) {
        switch(frame->headers.cat) {
        case NGHTTP2_HCAT_REQUEST: {
          stream->state = NGHTTP2_STREAM_OPENING;
          if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
          }
          r = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
          if(r != 0 && nghttp2_is_fatal(r)) {
            return r;
          }
          r = 0;
          /* We assume aux_data is a pointer to nghttp2_headers_aux_data */
          aux_data = (nghttp2_headers_aux_data*)item->aux_data;
          if(aux_data && aux_data->data_prd) {
            /* nghttp2_submit_data() makes a copy of aux_data->data_prd */
            r = nghttp2_submit_data(session, NGHTTP2_FLAG_END_STREAM,
                                    frame->hd.stream_id, aux_data->data_prd);
            if(r != 0 &&nghttp2_is_fatal(r)) {
              return r;
            }
            /* If r is not fatal, the only possible error is closed
               stream, so we have nothing to do here. */
            r = 0;
          }
          break;
        }
        case NGHTTP2_HCAT_RESPONSE:
        case NGHTTP2_HCAT_PUSH_RESPONSE:
          stream->state = NGHTTP2_STREAM_OPENED;
          if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
          }
          r = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
          if(r != 0 && nghttp2_is_fatal(r)) {
            return r;
          }
          r = 0;
          /* We assume aux_data is a pointer to nghttp2_headers_aux_data */
          aux_data = (nghttp2_headers_aux_data*)item->aux_data;
          if(aux_data && aux_data->data_prd) {
            r = nghttp2_submit_data(session, NGHTTP2_FLAG_END_STREAM,
                                    frame->hd.stream_id, aux_data->data_prd);
            if(r != 0 && nghttp2_is_fatal(r)) {
              return r;
            }
            /* If r is not fatal, the only possible error is closed
               stream, so we have nothing to do here. */
            r = 0;
          }
          break;
        case NGHTTP2_HCAT_HEADERS:
          if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
          }
          r = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
          if(r != 0 && nghttp2_is_fatal(r)) {
            return r;
          }
          r = 0;
          break;
        }
      }
      break;
    }
    case NGHTTP2_PRIORITY:
      /* nothing to do */
      break;
    case NGHTTP2_RST_STREAM:
      r = nghttp2_session_close_stream(session, frame->hd.stream_id,
                                       frame->rst_stream.error_code);
      if(r != 0 && nghttp2_is_fatal(r)) {
        return r;
      }
      r = 0;
      break;
    case NGHTTP2_SETTINGS: {
      size_t i;
      if(frame->hd.flags & NGHTTP2_FLAG_ACK) {
        break;
      }
      /* Only update max concurrent stream here. Applying it without
         ACK is safe because we can respond to the exceeding streams
         with REFUSED_STREAM and client will retry later. */
      for(i = frame->settings.niv; i > 0; --i) {
        if(frame->settings.iv[i - 1].settings_id ==
           NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS) {
          session->local_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS] =
            frame->settings.iv[i - 1].value;
          break;
        }
      }
      assert(session->inflight_niv == -1);
      session->inflight_iv = frame->settings.iv;
      session->inflight_niv = frame->settings.niv;
      frame->settings.iv = NULL;
      frame->settings.niv = 0;
      break;
    }
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
    }
    nghttp2_active_outbound_item_reset(&session->aob);
  } else if(item->frame_cat == NGHTTP2_CAT_DATA) {
    int r;
    nghttp2_data *data_frame;
    data_frame = nghttp2_outbound_item_get_data_frame(session->aob.item);
    if(session->callbacks.on_data_send_callback) {
      if(session->callbacks.on_data_send_callback
         (session,
          session->aob.framebuflen - NGHTTP2_FRAME_HEAD_LENGTH,
          data_frame->eof ? data_frame->hd.flags :
          (data_frame->hd.flags & (~NGHTTP2_FLAG_END_STREAM)),
          data_frame->hd.stream_id,
          session->user_data) != 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }
    if(data_frame->eof && (data_frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
      nghttp2_stream *stream =
        nghttp2_session_get_stream(session, data_frame->hd.stream_id);
      if(stream) {
        nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
        r = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
        if(r != 0 && nghttp2_is_fatal(r)) {
          return r;
        }
        r = 0;
      }
    }
    /* If session is closed or RST_STREAM was queued, we won't send
       further data. */
    if(data_frame->eof ||
       nghttp2_session_predicate_data_send(session,
                                           data_frame->hd.stream_id) != 0) {
      nghttp2_active_outbound_item_reset(&session->aob);
    } else {
      nghttp2_outbound_item* next_item;
      next_item = nghttp2_session_get_next_ob_item(session);
      /* If priority of this stream is higher or equal to other stream
         waiting at the top of the queue, we continue to send this
         data. */
      if(next_item == NULL || session->aob.item->pri <= next_item->pri) {
        size_t next_readmax;
        nghttp2_stream *stream;
        stream = nghttp2_session_get_stream(session, data_frame->hd.stream_id);
        /* Assuming stream is not NULL */
        assert(stream);
        next_readmax = nghttp2_session_next_data_read(session, stream);
        if(next_readmax == 0) {
          nghttp2_stream_defer_data(stream, session->aob.item,
                                    NGHTTP2_DEFERRED_FLOW_CONTROL);
          session->aob.item = NULL;
          nghttp2_active_outbound_item_reset(&session->aob);
          return 0;
        }
        r = nghttp2_session_pack_data(session,
                                      &session->aob.framebuf,
                                      &session->aob.framebufmax,
                                      next_readmax,
                                      data_frame);
        if(r == NGHTTP2_ERR_DEFERRED) {
          nghttp2_stream_defer_data(stream, session->aob.item,
                                    NGHTTP2_DEFERRED_NONE);
          session->aob.item = NULL;
          nghttp2_active_outbound_item_reset(&session->aob);
        } else if(r == NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE) {
          /* Stop DATA frame chain and issue RST_STREAM to close the
             stream.  We don't return
             NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE intentionally. */
          r = nghttp2_session_add_rst_stream(session, data_frame->hd.stream_id,
                                             NGHTTP2_INTERNAL_ERROR);
          nghttp2_active_outbound_item_reset(&session->aob);
          if(r != 0) {
            return r;
          }
        } else if(r < 0) {
          /* In this context, r is either NGHTTP2_ERR_NOMEM or
             NGHTTP2_ERR_CALLBACK_FAILURE */
          nghttp2_active_outbound_item_reset(&session->aob);
          return r;
        } else {
          session->aob.framebuflen = r;
          session->aob.framebufoff = 0;
        }
      } else {
        r = nghttp2_pq_push(&session->ob_pq, session->aob.item);
        if(r == 0) {
          session->aob.item = NULL;
          nghttp2_active_outbound_item_reset(&session->aob);
        } else {
          /* FATAL error */
          assert(r < NGHTTP2_ERR_FATAL);
          nghttp2_active_outbound_item_reset(&session->aob);
          return r;
        }
      }
    }
  } else {
    /* Unreachable */
    assert(0);
  }
  return 0;
}

int nghttp2_session_send(nghttp2_session *session)
{
  int r;
  while(1) {
    const uint8_t *data;
    size_t datalen;
    ssize_t sentlen;
    if(session->aob.item == NULL) {
      nghttp2_outbound_item *item;
      ssize_t framebuflen;
      item = nghttp2_session_pop_next_ob_item(session);
      if(item == NULL) {
        break;
      }
      framebuflen = nghttp2_session_prep_frame(session, item);
      if(framebuflen == NGHTTP2_ERR_DEFERRED) {
        continue;
      } else if(framebuflen < 0) {
        /* TODO If the error comes from compressor, the connection
           must be closed. */
        if(item->frame_cat == NGHTTP2_CAT_CTRL &&
           session->callbacks.on_frame_not_send_callback &&
           nghttp2_is_non_fatal(framebuflen)) {
          /* The library is responsible for the transmission of
             WINDOW_UPDATE frame, so we don't call error callback for
             it. */
          nghttp2_frame *frame = nghttp2_outbound_item_get_ctrl_frame(item);
          if(frame->hd.type != NGHTTP2_WINDOW_UPDATE) {
            if(session->callbacks.on_frame_not_send_callback
               (session, frame, framebuflen, session->user_data) != 0) {
              return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
          }
        }
        nghttp2_outbound_item_free(item);
        free(item);

        if(framebuflen == NGHTTP2_ERR_HEADER_COMP) {
          /* If header compression error occurred, should terminiate
             connection. */
          framebuflen = nghttp2_session_fail_session(session,
                                                     NGHTTP2_INTERNAL_ERROR);
        }
        if(nghttp2_is_fatal(framebuflen)) {
          return framebuflen;
        } else {
          continue;
        }
      }
      session->aob.item = item;
      session->aob.framebuflen = framebuflen;
      /* Call before_send callback */
      if(item->frame_cat == NGHTTP2_CAT_CTRL &&
         session->callbacks.before_frame_send_callback) {
        if(session->callbacks.before_frame_send_callback
           (session,
            nghttp2_outbound_item_get_ctrl_frame(item),
            session->user_data) != 0) {
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
      }
    }
    data = session->aob.framebuf + session->aob.framebufoff;
    datalen = session->aob.framebuflen - session->aob.framebufoff;
    sentlen = session->callbacks.send_callback(session, data, datalen, 0,
                                               session->user_data);
    if(sentlen < 0) {
      if(sentlen == NGHTTP2_ERR_WOULDBLOCK) {
        return 0;
      } else {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    } else {
      if(session->aob.item->frame_cat == NGHTTP2_CAT_DATA &&
         session->aob.framebufoff + sentlen > NGHTTP2_FRAME_HEAD_LENGTH) {
        nghttp2_data *frame;
        nghttp2_stream *stream;
        uint16_t len;
        if(session->aob.framebufoff < NGHTTP2_FRAME_HEAD_LENGTH) {
          len = session->aob.framebufoff + sentlen - NGHTTP2_FRAME_HEAD_LENGTH;
        } else {
          len = sentlen;
        }
        frame = nghttp2_outbound_item_get_data_frame(session->aob.item);
        stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
        if(stream && stream->remote_flow_control) {
          stream->remote_window_size -= len;
        }
        if(session->remote_flow_control) {
          session->remote_window_size -= len;
        }
      }
      session->aob.framebufoff += sentlen;
      if(session->aob.framebufoff == session->aob.framebuflen) {
        /* Frame has completely sent */
        r = nghttp2_session_after_frame_sent(session);
        if(r < 0) {
          /* FATAL */
          assert(r < NGHTTP2_ERR_FATAL);
          return r;
        }
      }
    }
  }
  return 0;
}

static ssize_t nghttp2_recv(nghttp2_session *session, uint8_t *buf, size_t len)
{
  ssize_t r;
  r = session->callbacks.recv_callback
    (session, buf, len, 0, session->user_data);
  if(r > 0) {
    if((size_t)r > len) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  } else if(r < 0) {
    if(r != NGHTTP2_ERR_WOULDBLOCK && r != NGHTTP2_ERR_EOF) {
      r = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return r;
}

static int nghttp2_session_call_on_request_recv
(nghttp2_session *session, int32_t stream_id)
{
  if(session->callbacks.on_request_recv_callback) {
    if(session->callbacks.on_request_recv_callback(session, stream_id,
                                                   session->user_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

static int nghttp2_session_call_on_frame_received
(nghttp2_session *session, nghttp2_frame *frame)
{
  int rv;
  if(session->callbacks.on_frame_recv_callback) {
    rv = session->callbacks.on_frame_recv_callback(session, frame,
                                                   session->user_data);
    if(rv == NGHTTP2_ERR_PAUSE) {
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

/*
 * Validates received HEADERS frame |frame| with NGHTTP2_HCAT_REQUEST
 * or NGHTTP2_HCAT_PUSH_RESPONSE category, which both opens new
 * stream.
 *
 * This function returns 0 if it succeeds, or non-zero
 * nghttp2_error_code.
 */
static int nghttp2_session_validate_request_headers(nghttp2_session *session,
                                                    nghttp2_headers *frame)
{
  if(nghttp2_session_is_incoming_concurrent_streams_max(session)) {
    /* The spec does not clearly say what to do when max concurrent
       streams number is reached. The mod_spdy sends
       NGHTTP2_REFUSED_STREAM and we think it is reasonable. So we
       follow it. */
    return NGHTTP2_REFUSED_STREAM;
  }
  return 0;
}

static int nghttp2_session_handle_parse_error(nghttp2_session *session,
                                              nghttp2_frame_type type,
                                              int lib_error_code,
                                              nghttp2_error_code error_code)
{
  if(session->callbacks.on_frame_recv_parse_error_callback) {
    if(session->callbacks.on_frame_recv_parse_error_callback
       (session,
        type,
        session->iframe.headbuf,
        sizeof(session->iframe.headbuf),
        session->iframe.buf,
        session->iframe.buflen,
        lib_error_code,
        session->user_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return nghttp2_session_fail_session(session, error_code);
}

static int nghttp2_session_handle_invalid_stream
(nghttp2_session *session,
 nghttp2_frame *frame,
 nghttp2_error_code error_code)
{
  int r;
  r = nghttp2_session_add_rst_stream(session, frame->hd.stream_id, error_code);
  if(r != 0) {
    return r;
  }
  if(session->callbacks.on_invalid_frame_recv_callback) {
    if(session->callbacks.on_invalid_frame_recv_callback
       (session, frame, error_code, session->user_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
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
  return nghttp2_session_fail_session(session, error_code);
}

int nghttp2_session_on_request_headers_received(nghttp2_session *session,
                                                nghttp2_frame *frame)
{
  int rv = 0;
  nghttp2_error_code error_code;
  nghttp2_stream *stream;
  if(frame->hd.stream_id == 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  /* Connection error if header continuation is employed for now */
  if((frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) == 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_INTERNAL_ERROR);
  }
  if(session->goaway_flags) {
    /* We don't accept new stream after GOAWAY is sent or received. */
    return 0;
  }
  if(!nghttp2_session_is_new_peer_stream_id(session, frame->hd.stream_id)) {
    /* The spec says if an endpoint receives a HEADERS with invalid
       stream ID, it MUST issue connection error with error code
       PROTOCOL_ERROR */
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  session->last_recv_stream_id = frame->hd.stream_id;
  error_code = nghttp2_session_validate_request_headers(session,
                                                        &frame->headers);
  if(error_code != NGHTTP2_NO_ERROR) {
    return nghttp2_session_handle_invalid_stream(session, frame, error_code);
  }

  stream = nghttp2_session_open_stream(session,
                                       frame->hd.stream_id,
                                       frame->hd.flags,
                                       frame->headers.pri,
                                       NGHTTP2_STREAM_OPENING,
                                       NULL);
  if(!stream) {
    return NGHTTP2_ERR_NOMEM;
  }
  rv = nghttp2_session_call_on_frame_received(session, frame);
  if(rv != 0) {
    return rv;
  }
  if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
    rv = nghttp2_session_call_on_request_recv(session, frame->hd.stream_id);
  }
  /* Here we assume that stream is not shutdown in NGHTTP2_SHUT_WR */
  return rv;
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
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  /* Connection error if header continuation is employed for now */
  if((frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) == 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_INTERNAL_ERROR);
  }
  if(stream->shut_flags & NGHTTP2_SHUT_RD) {
    /* half closed (remote): from the spec:

       If an endpoint receives additional frames for a stream that is
       in this state it MUST respond with a stream error (Section
       5.4.2) of type STREAM_CLOSED.
    */
    return nghttp2_session_handle_invalid_stream(session, frame,
                                                 NGHTTP2_STREAM_CLOSED);
  }
  stream->state = NGHTTP2_STREAM_OPENED;
  rv = nghttp2_session_call_on_frame_received(session, frame);
  if(rv != 0) {
    return rv;
  }
  if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    /* This is the last frame of this stream, so disallow
       further receptions. */
    nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
    rv = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
    if(rv != 0 && nghttp2_is_fatal(rv)) {
      return rv;
    }
  }
  return 0;
}

int nghttp2_session_on_push_response_headers_received(nghttp2_session *session,
                                                      nghttp2_frame *frame,
                                                      nghttp2_stream *stream)
{
  int rv = 0;
  assert(!session->server && stream->state == NGHTTP2_STREAM_RESERVED);
  if(frame->hd.stream_id == 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  /* Connection error if header continuation is employed for now */
  if((frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) == 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_INTERNAL_ERROR);
  }
  if(session->goaway_flags) {
    /* We don't accept new stream after GOAWAY is sent or received. */
    return 0;
  }
  rv = nghttp2_session_validate_request_headers(session, &frame->headers);
  if(rv != 0) {
    return nghttp2_session_handle_invalid_stream(session, frame, rv);
  }
  nghttp2_stream_promise_fulfilled(stream);
  ++session->num_incoming_streams;
  rv = nghttp2_session_call_on_frame_received(session, frame);
  if(rv != 0) {
    return rv;
  }
  if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    /* This is the last frame of this stream, so disallow further
       receptions. */
    nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
    rv = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
    if(rv != 0 && nghttp2_is_fatal(rv)) {
      return rv;
    }
  }
  return 0;
}

int nghttp2_session_on_headers_received(nghttp2_session *session,
                                        nghttp2_frame *frame,
                                        nghttp2_stream *stream)
{
  int r = 0;
  if(frame->hd.stream_id == 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  /* Connection error if header continuation is employed for now */
  if((frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) == 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_INTERNAL_ERROR);
  }
  if(stream->state == NGHTTP2_STREAM_RESERVED) {
    /* reserved. The valid push response HEADERS is processed by
       nghttp2_session_on_push_response_headers_received(). This
       generic HEADERS is called invalid cases for HEADERS against
       reserved state. */
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  if((stream->shut_flags & NGHTTP2_SHUT_RD)) {
    /* half closed (remote): from the spec:

       If an endpoint receives additional frames for a stream that is
       in this state it MUST respond with a stream error (Section
       5.4.2) of type STREAM_CLOSED.
    */
    return nghttp2_session_handle_invalid_stream(session, frame,
                                                 NGHTTP2_STREAM_CLOSED);
  }
  if(nghttp2_session_is_my_stream_id(session, frame->hd.stream_id)) {
    if(stream->state == NGHTTP2_STREAM_OPENED) {
      r = nghttp2_session_call_on_frame_received(session, frame);
      if(r != 0) {
        return r;
      }
      if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
        nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
        r = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
        if(r != 0 && nghttp2_is_fatal(r)) {
          return r;
        }
      }
      return 0;
    } else if(stream->state == NGHTTP2_STREAM_CLOSING) {
      /* This is race condition. NGHTTP2_STREAM_CLOSING indicates
         that we queued RST_STREAM but it has not been sent. It will
         eventually sent, so we just ignore this frame. */
      return 0;
    } else {
      return nghttp2_session_handle_invalid_stream(session, frame,
                                                   NGHTTP2_PROTOCOL_ERROR);
    }
  } else {
    /* If this is remote peer initiated stream, it is OK unless it
       has sent END_STREAM frame already. But if stream is in
       NGHTTP2_STREAM_CLOSING, we discard the frame. This is a race
       condition. */
    if(stream->state != NGHTTP2_STREAM_CLOSING) {
      r = nghttp2_session_call_on_frame_received(session, frame);
      if(r != 0) {
        return r;
      }
      if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
        r = nghttp2_session_call_on_request_recv(session,
                                                 frame->hd.stream_id);
        if(r != 0) {
          return r;
        }
        nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
        r = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
        if(r != 0 && nghttp2_is_fatal(r)) {
          return r;
        }
      }
    }
    return 0;
  }
}

int nghttp2_session_on_priority_received(nghttp2_session *session,
                                         nghttp2_frame *frame)
{
  nghttp2_stream *stream;
  if(frame->hd.stream_id == 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
  if(!stream) {
    return 0;
  }
  /* Only update priority on server side for now */
  if(session->server) {
    nghttp2_session_reprioritize_stream(session, stream,
                                        frame->priority.pri);
  }
  return nghttp2_session_call_on_frame_received(session, frame);
}

int nghttp2_session_on_rst_stream_received(nghttp2_session *session,
                                           nghttp2_frame *frame)
{
  int rv;
  if(frame->hd.stream_id == 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  rv = nghttp2_session_call_on_frame_received(session, frame);
  if(rv != 0) {
    return rv;
  }
  rv = nghttp2_session_close_stream(session, frame->hd.stream_id,
                                    frame->rst_stream.error_code);
  if(rv != 0 && nghttp2_is_fatal(rv)) {
    return rv;
  }
  return 0;
}

static int nghttp2_update_remote_initial_window_size_func
(nghttp2_map_entry *entry,
 void *ptr)
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
    return nghttp2_session_add_rst_stream(arg->session, stream->stream_id,
                                          NGHTTP2_FLOW_CONTROL_ERROR);
  }
  /* If window size gets positive, push deferred DATA frame to
     outbound queue. */
  if(stream->deferred_data &&
     (stream->deferred_flags & NGHTTP2_DEFERRED_FLOW_CONTROL) &&
     stream->remote_window_size > 0 &&
     (arg->session->remote_flow_control == 0 ||
      arg->session->remote_window_size > 0)) {
    rv = nghttp2_pq_push(&arg->session->ob_pq, stream->deferred_data);
    if(rv != 0) {
      /* FATAL */
      assert(rv < NGHTTP2_ERR_FATAL);
      return rv;
    }
    nghttp2_stream_detach_deferred_data(stream);
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
  if(!stream->local_flow_control) {
    return 0;
  }
  rv = nghttp2_stream_update_local_initial_window_size(stream,
                                                       arg->new_window_size,
                                                       arg->old_window_size);
  if(rv != 0) {
    return nghttp2_session_add_rst_stream(arg->session, stream->stream_id,
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

static int nghttp2_disable_remote_flow_control_func(nghttp2_map_entry *entry,
                                                    void *ptr)
{
  nghttp2_session *session;
  nghttp2_stream *stream;
  session = (nghttp2_session*)ptr;
  stream = (nghttp2_stream*)entry;
  stream->remote_flow_control = 0;
  /* If DATA frame is deferred due to flow control, push it back to
     outbound queue. */
  if(stream->deferred_data &&
     (stream->deferred_flags & NGHTTP2_DEFERRED_FLOW_CONTROL)) {
    int rv;
    rv = nghttp2_pq_push(&session->ob_pq, stream->deferred_data);
    if(rv == 0) {
      nghttp2_stream_detach_deferred_data(stream);
    } else {
      /* FATAL */
      assert(rv < NGHTTP2_ERR_FATAL);
      return rv;
    }
  }
  return 0;
}

/*
 * Disable remote side connection-level flow control and stream-level
 * flow control of existing streams.
 *
 * This function returns 0 if it succeeds, or one of negative error codes.
 *
 * The error code is always FATAL.
 */
static int nghttp2_session_disable_remote_flow_control
(nghttp2_session *session)
{
  session->remote_flow_control = 0;
  return nghttp2_map_each(&session->streams,
                          nghttp2_disable_remote_flow_control_func, session);
}

static int nghttp2_disable_local_flow_control_func(nghttp2_map_entry *entry,
                                                   void *ptr)
{
  nghttp2_stream *stream;
  stream = (nghttp2_stream*)entry;
  stream->local_flow_control = 0;
  return 0;
}

/*
 * Disable stream-level flow control in local side of existing
 * streams.
 */
static void nghttp2_session_disable_local_flow_control
(nghttp2_session *session)
{
  int rv;
  session->local_flow_control = 0;
  rv = nghttp2_map_each(&session->streams,
                        nghttp2_disable_local_flow_control_func, NULL);
  assert(rv == 0);
}

/*
 * Apply SETTINGS values |iv| having |niv| elements to the local
 * settings. SETTINGS_MAX_CONCURRENT_STREAMS is not applied here
 * because it has been already applied on transmission of SETTINGS
 * frame.
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
  uint8_t old_flow_control =
    session->local_settings[NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS];
  uint8_t new_flow_control = old_flow_control;
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
    case  NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS:
      new_flow_control = iv[i].value;
      break;
    }
  }
  if(header_table_size_seen) {
    if(header_table_size < 0 ||
       header_table_size > NGHTTP2_MAX_HEADER_TABLE_SIZE) {
      return NGHTTP2_ERR_HEADER_COMP;
    }
    rv = nghttp2_hd_change_table_size(&session->hd_inflater,
                                      header_table_size);
    if(rv != 0) {
      return rv;
    }
  }
  if(!old_flow_control && !new_flow_control && new_initial_window_size != -1) {
    rv = nghttp2_session_update_local_initial_window_size
      (session,
       new_initial_window_size,
       session->local_settings[NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE]);
    if(rv != 0) {
      return rv;
    }
  }
  for(i = 0; i < niv; ++i) {
    /* SETTINGS_MAX_CONCURRENT_STREAMS has already been applied on
       transmission of the SETTINGS frame. */
    if(iv[i].settings_id > 0 && iv[i].settings_id <= NGHTTP2_SETTINGS_MAX &&
       iv[i].settings_id != NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS) {
      session->local_settings[iv[i].settings_id] = iv[i].value;
    }
  }
  if(old_flow_control == 0 &&
     session->local_settings[NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS]) {
    nghttp2_session_disable_local_flow_control(session);
  }
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
      rv = nghttp2_hd_change_table_size(&session->hd_deflater, entry->value);
      if(rv != 0) {
        if(nghttp2_is_fatal(rv)) {
          return rv;
        } else {
          return nghttp2_session_handle_invalid_connection
            (session, frame, NGHTTP2_COMPRESSION_ERROR);
        }
      }
      break;
    case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
      /* Update the initial window size of the all active streams */
      /* Check that initial_window_size < (1u << 31) */
      if(entry->value <= NGHTTP2_MAX_WINDOW_SIZE) {
        rv = nghttp2_session_update_remote_initial_window_size
          (session, entry->value);
        if(rv != 0) {
          if(nghttp2_is_fatal(rv)) {
            return rv;
          } else {
            return nghttp2_session_handle_invalid_connection
              (session, frame, NGHTTP2_FLOW_CONTROL_ERROR);
          }
        }
      } else {
        return nghttp2_session_handle_invalid_connection
          (session, frame, NGHTTP2_PROTOCOL_ERROR);
      }
      break;
    case NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS:
      if(entry->value & 0x1) {
        if(session->remote_settings[entry->settings_id] == 0) {
          rv = nghttp2_session_disable_remote_flow_control(session);
          if(rv != 0) {
            /* FATAL */
            assert(rv < NGHTTP2_ERR_FATAL);
            return rv;
          }
        }
      } else if(session->remote_settings[entry->settings_id] == 1) {
        /* Re-enabling flow control is subject to connection-level
           error(?) */
        return nghttp2_session_handle_invalid_connection
          (session, frame, NGHTTP2_FLOW_CONTROL_ERROR);
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

int nghttp2_session_on_push_promise_received(nghttp2_session *session,
                                             nghttp2_frame *frame)
{
  nghttp2_stream *stream;
  nghttp2_stream *promised_stream;
  if(session->server || frame->hd.stream_id == 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  /* Connection error if header continuation is employed for now */
  if((frame->hd.flags & NGHTTP2_FLAG_END_PUSH_PROMISE) == 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_INTERNAL_ERROR);
  }
  if(session->goaway_flags) {
    /* We just dicard PUSH_PROMISE after GOAWAY is sent or
       received. */
    return 0;
  }
  if(!nghttp2_session_is_new_peer_stream_id
     (session, frame->push_promise.promised_stream_id)) {
    /* The spec says if an endpoint receives a PUSH_PROMISE with
       illegal stream ID is subject to a connection error of type
       PROTOCOL_ERROR. */
    return nghttp2_session_handle_invalid_connection
      (session, frame, NGHTTP2_PROTOCOL_ERROR);
  }
  session->last_recv_stream_id = frame->push_promise.promised_stream_id;
  stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
  if(!stream) {
    return nghttp2_session_add_rst_stream
      (session,
       frame->push_promise.promised_stream_id,
       NGHTTP2_REFUSED_STREAM);
  }

  if(!nghttp2_session_is_my_stream_id(session, frame->hd.stream_id)) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  if(stream->shut_flags & NGHTTP2_SHUT_RD) {
    if(session->callbacks.on_invalid_frame_recv_callback) {
      if(session->callbacks.on_invalid_frame_recv_callback
         (session, frame, NGHTTP2_PROTOCOL_ERROR, session->user_data) != 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }
    return nghttp2_session_add_rst_stream
      (session,
       frame->push_promise.promised_stream_id,
       NGHTTP2_PROTOCOL_ERROR);
  }
  if(stream->state == NGHTTP2_STREAM_CLOSING) {
    return nghttp2_session_add_rst_stream
      (session,
       frame->push_promise.promised_stream_id,
       NGHTTP2_REFUSED_STREAM);
  }
  promised_stream = nghttp2_session_open_stream
    (session,
     frame->push_promise.promised_stream_id,
     frame->hd.flags,
     nghttp2_pushed_stream_pri(stream),
     NGHTTP2_STREAM_RESERVED,
     NULL);
  if(!promised_stream) {
    return NGHTTP2_ERR_NOMEM;
  }
  return nghttp2_session_call_on_frame_received(session, frame);
}

int nghttp2_session_on_ping_received(nghttp2_session *session,
                                     nghttp2_frame *frame)
{
  int r = 0;
  if(frame->hd.stream_id != 0) {
    return nghttp2_session_handle_invalid_connection(session, frame,
                                                     NGHTTP2_PROTOCOL_ERROR);
  }
  if((frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) {
    /* Peer sent ping, so ping it back */
    r = nghttp2_session_add_ping(session, NGHTTP2_FLAG_ACK,
                                 frame->ping.opaque_data);
    if(r != 0) {
      return r;
    }
  }
  return nghttp2_session_call_on_frame_received(session, frame);
}

int nghttp2_session_on_goaway_received(nghttp2_session *session,
                                       nghttp2_frame *frame)
{
  session->last_stream_id = frame->goaway.last_stream_id;
  session->goaway_flags |= NGHTTP2_GOAWAY_RECV;
  return nghttp2_session_call_on_frame_received(session, frame);
}

static int nghttp2_push_back_deferred_data_func(nghttp2_map_entry *entry,
                                                void *ptr)
{
  nghttp2_session *session;
  nghttp2_stream *stream;
  session = (nghttp2_session*)ptr;
  stream = (nghttp2_stream*)entry;
  /* If DATA frame is deferred due to flow control, push it back to
     outbound queue. */
  if(stream->deferred_data &&
     (stream->deferred_flags & NGHTTP2_DEFERRED_FLOW_CONTROL) &&
     (stream->remote_flow_control == 0 || stream->remote_window_size > 0)) {
    int rv;
    rv = nghttp2_pq_push(&session->ob_pq, stream->deferred_data);
    if(rv == 0) {
      nghttp2_stream_detach_deferred_data(stream);
    } else {
      /* FATAL */
      assert(rv < NGHTTP2_ERR_FATAL);
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
  if(session->remote_flow_control == 0) {
    /* Disabling flow control by sending SETTINGS and receiving
       WINDOW_UPDATE are asynchronous, so it is hard to determine
       that the peer is misbehaving or not without measuring
       RTT. For now, we just ignore such frames. */
    return nghttp2_session_call_on_frame_received(session, frame);
  }
  if(NGHTTP2_MAX_WINDOW_SIZE - frame->window_update.window_size_increment <
     session->remote_window_size) {
    return nghttp2_session_handle_invalid_connection
      (session, frame, NGHTTP2_FLOW_CONTROL_ERROR);
  }
  session->remote_window_size += frame->window_update.window_size_increment;
  /* To queue the DATA deferred by connection-level flow-control, we
     have to check all streams. Bad. */
  if(session->remote_window_size > 0) {
    rv = nghttp2_session_push_back_deferred_data(session);
    if(rv != 0) {
      return 0;
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
    return 0;
  }
  if(stream->state == NGHTTP2_STREAM_RESERVED) {
    return nghttp2_session_handle_invalid_connection
      (session, frame, NGHTTP2_PROTOCOL_ERROR);
  }
  if(stream->remote_flow_control == 0) {
    /* Same reason with connection-level flow control */
    return nghttp2_session_call_on_frame_received(session, frame);
  }
  if(NGHTTP2_MAX_WINDOW_SIZE - frame->window_update.window_size_increment <
     stream->remote_window_size) {
    return nghttp2_session_handle_invalid_stream(session, frame,
                                                 NGHTTP2_FLOW_CONTROL_ERROR);
  }
  stream->remote_window_size += frame->window_update.window_size_increment;
  if(stream->remote_window_size > 0 &&
     (session->remote_flow_control == 0 ||
      session->remote_window_size > 0) &&
     stream->deferred_data != NULL &&
     (stream->deferred_flags & NGHTTP2_DEFERRED_FLOW_CONTROL)) {
    rv = nghttp2_pq_push(&session->ob_pq, stream->deferred_data);
    if(rv != 0) {
      /* FATAL */
      assert(rv < NGHTTP2_ERR_FATAL);
      return rv;
    }
    nghttp2_stream_detach_deferred_data(stream);
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

static int get_error_code_from_lib_error_code(int lib_error_code)
{
  switch(lib_error_code) {
  case NGHTTP2_ERR_HEADER_COMP:
    return NGHTTP2_COMPRESSION_ERROR;
  case NGHTTP2_ERR_FRAME_SIZE_ERROR:
    return NGHTTP2_FRAME_SIZE_ERROR;
  default:
    return NGHTTP2_PROTOCOL_ERROR;
  }
}

/* For errors, this function returns NGHTTP2_ERR_PAUSE, or FATAL
   ones. */
static int nghttp2_session_process_ctrl_frame(nghttp2_session *session)
{
  int r = 0;
  uint16_t type;
  nghttp2_frame *frame = &session->iframe.frame;
  type = session->iframe.headbuf[2];
  switch(type) {
  case NGHTTP2_HEADERS:
    if(session->iframe.error_code == 0) {
      r = nghttp2_frame_unpack_headers(&frame->headers,
                                       session->iframe.headbuf,
                                       sizeof(session->iframe.headbuf),
                                       session->iframe.buf,
                                       session->iframe.buflen,
                                       &session->hd_inflater);
    } else if(session->iframe.error_code == NGHTTP2_ERR_FRAME_SIZE_ERROR) {
      r = nghttp2_frame_unpack_headers_without_nv
        (&frame->headers,
         session->iframe.headbuf, sizeof(session->iframe.headbuf),
         session->iframe.buf, session->iframe.buflen);
      if(r == 0) {
        r = session->iframe.error_code;
      }
    } else {
      r = session->iframe.error_code;
    }
    if(r == 0) {
      nghttp2_stream *stream;
      stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
      if(stream) {
        if(nghttp2_session_is_my_stream_id(session, frame->hd.stream_id)) {
          if(stream->state == NGHTTP2_STREAM_OPENING) {
            frame->headers.cat = NGHTTP2_HCAT_RESPONSE;
            r = nghttp2_session_on_response_headers_received
              (session, frame, stream);
          } else {
            frame->headers.cat = NGHTTP2_HCAT_HEADERS;
            r = nghttp2_session_on_headers_received(session, frame, stream);
          }
        } else if(!session->server &&
                  stream->state == NGHTTP2_STREAM_RESERVED) {
          frame->headers.cat = NGHTTP2_HCAT_PUSH_RESPONSE;
          r = nghttp2_session_on_push_response_headers_received
            (session, frame, stream);
        } else {
          frame->headers.cat = NGHTTP2_HCAT_HEADERS;
          r = nghttp2_session_on_headers_received(session, frame, stream);
        }
      } else {
        frame->headers.cat = NGHTTP2_HCAT_REQUEST;
        r = nghttp2_session_on_request_headers_received(session, frame);
      }
      if(r != NGHTTP2_ERR_PAUSE) {
        nghttp2_frame_headers_free(&frame->headers);
        nghttp2_hd_end_headers(&session->hd_inflater);
      }
    } else if(nghttp2_is_non_fatal(r)) {
      r = nghttp2_session_handle_parse_error
        (session, type, r, get_error_code_from_lib_error_code(r));
    }
    break;
  case NGHTTP2_PRIORITY:
    r = nghttp2_frame_unpack_priority(&frame->priority,
                                      session->iframe.headbuf,
                                      sizeof(session->iframe.headbuf),
                                      session->iframe.buf,
                                      session->iframe.buflen);
    if(r == 0) {
      r = nghttp2_session_on_priority_received(session, frame);
      if(r != NGHTTP2_ERR_PAUSE) {
        nghttp2_frame_priority_free(&frame->priority);
      }
    } else if(nghttp2_is_non_fatal(r)) {
      r = nghttp2_session_handle_parse_error
        (session, type, r, get_error_code_from_lib_error_code(r));
    }
    break;
  case NGHTTP2_RST_STREAM:
    r = nghttp2_frame_unpack_rst_stream(&frame->rst_stream,
                                        session->iframe.headbuf,
                                        sizeof(session->iframe.headbuf),
                                        session->iframe.buf,
                                        session->iframe.buflen);
    if(r == 0) {
      r = nghttp2_session_on_rst_stream_received(session, frame);
      if(r != NGHTTP2_ERR_PAUSE) {
        nghttp2_frame_rst_stream_free(&frame->rst_stream);
      }
    } else if(nghttp2_is_non_fatal(r)) {
      r = nghttp2_session_handle_parse_error
        (session, type, r, get_error_code_from_lib_error_code(r));
    }
    break;
  case NGHTTP2_SETTINGS:
    r = nghttp2_frame_unpack_settings(&frame->settings,
                                      session->iframe.headbuf,
                                      sizeof(session->iframe.headbuf),
                                      session->iframe.buf,
                                      session->iframe.buflen);
    if(r == 0) {
      r = nghttp2_session_on_settings_received(session, frame, 0 /* ACK */);
      if(r != NGHTTP2_ERR_PAUSE) {
        nghttp2_frame_settings_free(&frame->settings);
      }
    } else if(nghttp2_is_non_fatal(r)) {
      r = nghttp2_session_handle_parse_error
        (session, type, r, get_error_code_from_lib_error_code(r));
    }
    break;
  case NGHTTP2_PUSH_PROMISE:
    if(session->iframe.error_code == 0) {
      r = nghttp2_frame_unpack_push_promise(&frame->push_promise,
                                            session->iframe.headbuf,
                                            sizeof(session->iframe.headbuf),
                                            session->iframe.buf,
                                            session->iframe.buflen,
                                            &session->hd_inflater);
    } else {
      r = session->iframe.error_code;
    }
    if(r == 0) {
      r = nghttp2_session_on_push_promise_received(session, frame);
      if(r != NGHTTP2_ERR_PAUSE) {
        nghttp2_frame_push_promise_free(&frame->push_promise);
        nghttp2_hd_end_headers(&session->hd_inflater);
      }
    } else if(nghttp2_is_non_fatal(r)) {
      r = nghttp2_session_handle_parse_error
        (session, type, r, get_error_code_from_lib_error_code(r));
    }
    break;
  case NGHTTP2_PING:
    r = nghttp2_frame_unpack_ping(&frame->ping,
                                  session->iframe.headbuf,
                                  sizeof(session->iframe.headbuf),
                                  session->iframe.buf,
                                  session->iframe.buflen);
    if(r == 0) {
      r = nghttp2_session_on_ping_received(session, frame);
      if(r != NGHTTP2_ERR_PAUSE) {
        nghttp2_frame_ping_free(&frame->ping);
      }
    } else if(nghttp2_is_non_fatal(r)) {
      r = nghttp2_session_handle_parse_error
        (session, type, r, get_error_code_from_lib_error_code(r));
    }
    break;
  case NGHTTP2_GOAWAY:
    r = nghttp2_frame_unpack_goaway(&frame->goaway,
                                    session->iframe.headbuf,
                                    sizeof(session->iframe.headbuf),
                                    session->iframe.buf,
                                    session->iframe.buflen);
    if(r == 0) {
      r = nghttp2_session_on_goaway_received(session, frame);
      if(r != NGHTTP2_ERR_PAUSE) {
        nghttp2_frame_goaway_free(&frame->goaway);
      }
    } else if(nghttp2_is_non_fatal(r)) {
      r = nghttp2_session_handle_parse_error
        (session, type, r, get_error_code_from_lib_error_code(r));
    }
    break;
  case NGHTTP2_WINDOW_UPDATE:
    r = nghttp2_frame_unpack_window_update(&frame->window_update,
                                           session->iframe.headbuf,
                                           sizeof(session->iframe.headbuf),
                                           session->iframe.buf,
                                           session->iframe.buflen);
    if(r == 0) {
      r = nghttp2_session_on_window_update_received(session, frame);
      if(r != NGHTTP2_ERR_PAUSE) {
        nghttp2_frame_window_update_free(&frame->window_update);
      }
    } else if(nghttp2_is_non_fatal(r)) {
      r = nghttp2_session_handle_parse_error
        (session, type, r, get_error_code_from_lib_error_code(r));
    }
    break;
  default:
    /* Unknown frame */
    if(session->callbacks.on_unknown_frame_recv_callback) {
      if(session->callbacks.on_unknown_frame_recv_callback
         (session,
          session->iframe.headbuf,
          sizeof(session->iframe.headbuf),
          session->iframe.buf,
          session->iframe.buflen,
          session->user_data) != 0) {
        r = NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }
  }
  if(r == NGHTTP2_ERR_PAUSE) {
    session->iframe.error_code = NGHTTP2_ERR_PAUSE;
    return r;
  } else if(nghttp2_is_fatal(r)) {
    return r;
  } else {
    return 0;
  }
}

int nghttp2_session_on_data_received(nghttp2_session *session,
                                     uint16_t length, uint8_t flags,
                                     int32_t stream_id)
{
  int rv = 0;
  nghttp2_stream *stream;
  if(stream_id == 0) {
    /* The spec says that if a DATA frame is received whose stream ID
       is 0, the recipient MUST respond with a connection error of
       type PROTOCOL_ERROR. */
    return nghttp2_session_fail_session(session, NGHTTP2_PROTOCOL_ERROR);
  }
  stream = nghttp2_session_get_stream(session, stream_id);
  if(!stream) {
    /* This should be treated as stream error, but it results in lots
       of RST_STREAM. So just ignore frame against nonexistent stream
       for now. */
    return 0;
  }
  if(stream->state == NGHTTP2_STREAM_RESERVED) {
    /* reserved and receiving DATA is connection error */
    return nghttp2_session_fail_session(session, NGHTTP2_PROTOCOL_ERROR);
  }
  if(stream->shut_flags & NGHTTP2_SHUT_RD) {
    /* half closed (remote): from the spec:

       If an endpoint receives additional frames for a stream that is
       in this state it MUST respond with a stream error (Section
       5.4.2) of type STREAM_CLOSED.
    */
    if(stream->state != NGHTTP2_STREAM_CLOSING) {
      return nghttp2_session_add_rst_stream(session, stream_id,
                                            NGHTTP2_STREAM_CLOSED);
    }
    return 0;
  }
  if(nghttp2_session_is_my_stream_id(session, stream_id)) {
    if(stream->state == NGHTTP2_STREAM_OPENED) {
      if(session->callbacks.on_data_recv_callback) {
        if(session->callbacks.on_data_recv_callback
           (session, length, flags, stream_id, session->user_data) != 0) {
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
      }
    } else if(stream->state != NGHTTP2_STREAM_CLOSING) {
      return nghttp2_session_add_rst_stream(session, stream_id,
                                            NGHTTP2_PROTOCOL_ERROR);
    }
  } else if(stream->state != NGHTTP2_STREAM_CLOSING) {
    /* It is OK if this is remote peer initiated stream and we did
       not receive END_STREAM unless stream is in
       NGHTTP2_STREAM_CLOSING state. This is a race condition. */
    if(session->callbacks.on_data_recv_callback) {
      if(session->callbacks.on_data_recv_callback
         (session, length, flags, stream_id, session->user_data) != 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }
    if(flags & NGHTTP2_FLAG_END_STREAM) {
      rv = nghttp2_session_call_on_request_recv(session, stream_id);
      if(rv != 0) {
        return rv;
      }
    }
  }
  if(flags & NGHTTP2_FLAG_END_STREAM) {
    nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
    rv = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
    if(rv != 0 && nghttp2_is_fatal(rv)) {
      return rv;
    }
  }
  return 0;
}

/* For errors, this function only returns FATAL error. */
static int nghttp2_session_process_data_frame(nghttp2_session *session)
{
  int r;
  nghttp2_frame_hd hd;
  nghttp2_frame_unpack_frame_hd(&hd, session->iframe.headbuf);
  r = nghttp2_session_on_data_received(session,  hd.length, hd.flags,
                                       hd.stream_id);
  if(nghttp2_is_fatal(r)) {
    return r;
  } else {
    return 0;
  }
}

/*
 * Now we have SETTINGS synchronization, flow control error can be
 * detected strictly. If DATA frame is received with length > 0 and
 * current received window size is equal to or larger than local
 * window size (latter happens when we shirnk window size), it is
 * subject to FLOW_CONTROL_ERROR, so return -1. If the resulting
 * recv_window_size is strictly larger than NGHTTP2_MAX_WINDOW_SIZE,
 * return -1 too.
 */
static int adjust_recv_window_size(int32_t *recv_window_size_ptr,
                                   int32_t delta,
                                   int32_t local_window_size)
{
  if(*recv_window_size_ptr >= local_window_size ||
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
 int32_t delta_size)
{
  int rv;
  rv = adjust_recv_window_size(&stream->recv_window_size, delta_size,
                               stream->local_window_size);
  if(rv != 0) {
    return nghttp2_session_add_rst_stream(session, stream->stream_id,
                                          NGHTTP2_FLOW_CONTROL_ERROR);
  }
  if(!(session->opt_flags & NGHTTP2_OPTMASK_NO_AUTO_STREAM_WINDOW_UPDATE)) {
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
    return nghttp2_session_fail_session(session, NGHTTP2_FLOW_CONTROL_ERROR);
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
 * Returns nonzero if the reception of DATA for stream |stream_id| is
 * allowed.
 */
static int nghttp2_session_check_data_recv_allowed(nghttp2_session *session,
                                                   int32_t stream_id)
{
  nghttp2_stream *stream;
  stream = nghttp2_session_get_stream(session, stream_id);
  if(stream) {
    if((stream->shut_flags & NGHTTP2_SHUT_RD) == 0) {
      if(nghttp2_session_is_my_stream_id(session, stream_id)) {
        if(stream->state == NGHTTP2_STREAM_OPENED) {
          return 1;
        }
      } else if(stream->state != NGHTTP2_STREAM_CLOSING &&
                stream->state != NGHTTP2_STREAM_RESERVED) {
        /* It is OK if this is remote peer initiated stream and we did
           not receive END_STREAM unless stream is in
           NGHTTP2_STREAM_CLOSING state. This is a race condition. */
        /* But DATA must not be received in reserved state */
        return 1;
      }
    }
  }
  return 0;
}

int nghttp2_session_continue(nghttp2_session *session)
{
  nghttp2_frame *frame = &session->iframe.frame;
  nghttp2_stream *stream;
  int rv = 0;
  if(session->iframe.error_code != NGHTTP2_ERR_PAUSE) {
    return 0;
  }
  switch(frame->hd.type) {
  case NGHTTP2_DATA:
    /* To call on_data_recv_callback */
    return nghttp2_session_mem_recv(session, NULL, 0);
  case NGHTTP2_HEADERS:
    switch(frame->headers.cat) {
    case NGHTTP2_HCAT_REQUEST:
      if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
        rv = nghttp2_session_call_on_request_recv(session, frame->hd.stream_id);
        stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
        nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
      }
      break;
    case NGHTTP2_HCAT_RESPONSE:
    case NGHTTP2_HCAT_PUSH_RESPONSE:
      if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
        stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
        /* This is the last frame of this stream, so disallow
           further receptions. */
        nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
        rv = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
        if(!nghttp2_is_fatal(rv)) {
          rv = 0;
        }
      }
      break;
    case NGHTTP2_HCAT_HEADERS:
      if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
        if(!nghttp2_session_is_my_stream_id(session, frame->hd.stream_id)) {
          rv = nghttp2_session_call_on_request_recv(session,
                                                   frame->hd.stream_id);
          if(rv != 0) {
            break;
          }
        }
        stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
        nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
        rv = nghttp2_session_close_stream_if_shut_rdwr(session, stream);
        if(!nghttp2_is_fatal(rv)) {
          rv = 0;
        }
      }
      break;
    }
    break;
  case NGHTTP2_RST_STREAM:
    rv = nghttp2_session_close_stream(session, frame->hd.stream_id,
                                      frame->rst_stream.error_code);
    if(!nghttp2_is_fatal(rv)) {
      rv = 0;
    }
    break;
  default:
    break;
  }
  nghttp2_inbound_frame_reset(session);
  return rv;
}

ssize_t nghttp2_session_mem_recv(nghttp2_session *session,
                                 const uint8_t *in, size_t inlen)
{
  const uint8_t *inmark, *inlimit;
  inmark = in;
  inlimit = in+inlen;
  while(1) {
    ssize_t r;
    if(session->iframe.state == NGHTTP2_RECV_HEAD) {
      size_t remheadbytes;
      size_t readlen;
      size_t bufavail = inlimit-inmark;
      if(bufavail == 0) {
        break;
      }
      remheadbytes = NGHTTP2_FRAME_HEAD_LENGTH - session->iframe.headbufoff;
      readlen = nghttp2_min(remheadbytes, bufavail);
      memcpy(session->iframe.headbuf+session->iframe.headbufoff,
             inmark, readlen);
      inmark += readlen;
      session->iframe.headbufoff += readlen;
      if(session->iframe.headbufoff == NGHTTP2_FRAME_HEAD_LENGTH) {
        session->iframe.state = NGHTTP2_RECV_PAYLOAD;
        session->iframe.payloadlen =
          nghttp2_get_uint16(&session->iframe.headbuf[0]) &
          NGHTTP2_FRAME_LENGTH_MASK;
        if(!nghttp2_frame_is_data_frame(session->iframe.headbuf)) {
          /* non-DATA frame */
          ssize_t buflen = session->iframe.payloadlen;
          session->iframe.buflen = buflen;
          r = nghttp2_reserve_buffer(&session->iframe.buf,
                                     &session->iframe.bufmax,
                                     buflen);
          if(r != 0) {
            /* FATAL */
            assert(r < NGHTTP2_ERR_FATAL);
            return r;
          }
        } else {
          /* Check stream is open. If it is not open or closing,
             ignore payload. */
          int32_t stream_id;
          stream_id = nghttp2_get_uint32(&session->iframe.headbuf[4]) &
            NGHTTP2_STREAM_ID_MASK;
          if(!nghttp2_session_check_data_recv_allowed(session, stream_id)) {
            session->iframe.state = NGHTTP2_RECV_PAYLOAD_IGN;
          }
        }
      } else {
        break;
      }
    }
    if(session->iframe.state == NGHTTP2_RECV_PAYLOAD ||
       session->iframe.state == NGHTTP2_RECV_PAYLOAD_IGN) {
      size_t rempayloadlen;
      size_t bufavail, readlen;
      int32_t data_stream_id = 0;
      uint8_t data_flags = NGHTTP2_FLAG_NONE;

      rempayloadlen = session->iframe.payloadlen - session->iframe.off;
      bufavail = inlimit - inmark;
      if(rempayloadlen > 0 && bufavail == 0) {
        break;
      }
      readlen =  nghttp2_min(bufavail, rempayloadlen);
      if(!nghttp2_frame_is_data_frame(session->iframe.headbuf)) {
        if(session->iframe.state != NGHTTP2_RECV_PAYLOAD_IGN) {
          memcpy(session->iframe.buf+session->iframe.off, inmark, readlen);
        }
      } else {
        data_stream_id = nghttp2_get_uint32(&session->iframe.headbuf[4]) &
          NGHTTP2_STREAM_ID_MASK;
        data_flags = session->iframe.headbuf[3];
      }
      session->iframe.off += readlen;
      inmark += readlen;

      if(nghttp2_frame_is_data_frame(session->iframe.headbuf) && readlen > 0) {
        if(session->local_flow_control) {
          /* Update connection-level flow control window for ignored
             DATA frame too */
          r = nghttp2_session_update_recv_connection_window_size
            (session, readlen);
          if(r < 0) {
            /* FATAL */
            assert(r < NGHTTP2_ERR_FATAL);
            return r;
          }
        }
        if(session->iframe.state != NGHTTP2_RECV_PAYLOAD_IGN &&
           (session->iframe.payloadlen != session->iframe.off ||
            (data_flags & NGHTTP2_FLAG_END_STREAM) == 0)) {
          nghttp2_stream *stream;
          stream = nghttp2_session_get_stream(session, data_stream_id);
          if(stream && stream->local_flow_control) {
            r = nghttp2_session_update_recv_stream_window_size
              (session, stream, readlen);
            if(r < 0) {
              /* FATAL */
              assert(r < NGHTTP2_ERR_FATAL);
              return r;
            }
          }
        }
        /* For data frame, We don't buffer data. Instead, just pass
           received data to callback function. */
        if(session->iframe.state != NGHTTP2_RECV_PAYLOAD_IGN) {
          if(session->callbacks.on_data_chunk_recv_callback) {
            r = session->callbacks.on_data_chunk_recv_callback
              (session,
               data_flags,
               data_stream_id,
               inmark - readlen,
               readlen,
               session->user_data);
            if(r == NGHTTP2_ERR_PAUSE) {
              /* Set type to NGHTTP2_DATA, so that we can see what was
                 paused in nghttp2_session_continue() */
              session->iframe.error_code = NGHTTP2_ERR_PAUSE;
              session->iframe.frame.hd.type = NGHTTP2_DATA;
              return inmark - in;
            }
            if(r != 0) {
              return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
          }
        }
        /* TODO We need on_ignored_data_chunk_recv_callback, for
           ingored DATA frame, so that the application can calculate
           connection-level window size. */
      }
      if(session->iframe.payloadlen == session->iframe.off) {
        if(session->iframe.error_code != NGHTTP2_ERR_FRAME_SIZE_ERROR) {
          if(!nghttp2_frame_is_data_frame(session->iframe.headbuf)) {
            /* TODO Introduce callback which is invoked when payload is
               ignored, especially for frame too large */
            r = nghttp2_session_process_ctrl_frame(session);
          } else {
            r = nghttp2_session_process_data_frame(session);
          }
          if(r == NGHTTP2_ERR_PAUSE) {
            return inmark - in;
          }
          if(r < 0) {
            /* FATAL */
            assert(r < NGHTTP2_ERR_FATAL);
            return r;
          }
        }
        nghttp2_inbound_frame_reset(session);
      }
    }
  }
  return inmark-in;
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
  int r;
  nghttp2_frame *frame;
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  nghttp2_frame_ping_init(&frame->ping, flags, opaque_data);
  r = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  if(r != 0) {
    nghttp2_frame_ping_free(&frame->ping);
    free(frame);
  }
  return r;
}

int nghttp2_session_add_goaway(nghttp2_session *session,
                               int32_t last_stream_id,
                               nghttp2_error_code error_code,
                               uint8_t *opaque_data, size_t opaque_data_len)
{
  int r;
  nghttp2_frame *frame;
  uint8_t *opaque_data_copy = NULL;
  if(opaque_data_len) {
    if(opaque_data_len > UINT16_MAX - 8) {
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
  r = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  if(r != 0) {
    nghttp2_frame_goaway_free(&frame->goaway);
    free(frame);
  }
  return r;
}

int nghttp2_session_add_window_update(nghttp2_session *session, uint8_t flags,
                                      int32_t stream_id,
                                      int32_t window_size_increment)
{
  int r;
  nghttp2_frame *frame;
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  nghttp2_frame_window_update_init(&frame->window_update, flags,
                                   stream_id, window_size_increment);
  r = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  if(r != 0) {
    nghttp2_frame_window_update_free(&frame->window_update);
    free(frame);
  }
  return r;
}

int nghttp2_session_add_settings(nghttp2_session *session, uint8_t flags,
                                 const nghttp2_settings_entry *iv, size_t niv)
{
  nghttp2_frame *frame;
  nghttp2_settings_entry *iv_copy;
  int r;
  if(!nghttp2_iv_check(iv, niv,
                       session->local_settings
                       [NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS])) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  iv_copy = nghttp2_frame_iv_copy(iv, niv);
  if(iv_copy == NULL) {
    free(frame);
    return NGHTTP2_ERR_NOMEM;
  }
  nghttp2_frame_settings_init(&frame->settings, flags, iv_copy, niv);
  r = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  if(r != 0) {
    /* The only expected error is fatal one */
    assert(r < NGHTTP2_ERR_FATAL);
    nghttp2_frame_settings_free(&frame->settings);
    free(frame);
  }
  return r;
}

ssize_t nghttp2_session_pack_data(nghttp2_session *session,
                                  uint8_t **buf_ptr, size_t *buflen_ptr,
                                  size_t datamax,
                                  nghttp2_data *frame)
{
  ssize_t framelen = datamax+8, r;
  int eof_flags;
  uint8_t flags;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  eof_flags = 0;
  r = frame->data_prd.read_callback
    (session, frame->hd.stream_id, (*buf_ptr)+8, datamax,
     &eof_flags, &frame->data_prd.source, session->user_data);
  if(r == NGHTTP2_ERR_DEFERRED || r == NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE) {
    return r;
  } else if(r < 0 || datamax < (size_t)r) {
    /* This is the error code when callback is failed. */
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  memset(*buf_ptr, 0, NGHTTP2_FRAME_HEAD_LENGTH);
  nghttp2_put_uint16be(&(*buf_ptr)[0], r);
  flags = 0;
  if(eof_flags) {
    frame->eof = 1;
    if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      flags |= NGHTTP2_FLAG_END_STREAM;
    }
  }
  (*buf_ptr)[3] = flags;
  nghttp2_put_uint32be(&(*buf_ptr)[4], frame->hd.stream_id);
  return r+8;
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

int nghttp2_session_resume_data(nghttp2_session *session, int32_t stream_id)
{
  int r;
  nghttp2_stream *stream;
  stream = nghttp2_session_get_stream(session, stream_id);
  if(stream == NULL || stream->deferred_data == NULL ||
     (stream->deferred_flags & NGHTTP2_DEFERRED_FLOW_CONTROL)) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  r = nghttp2_pq_push(&session->ob_pq, stream->deferred_data);
  if(r == 0) {
    nghttp2_stream_detach_deferred_data(stream);
  }
  return r;
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
  if(stream->local_flow_control == 0) {
    return 0;
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
  if(session->local_flow_control == 0) {
    return 0;
  }
  return session->recv_window_size < 0 ? 0 : session->recv_window_size;
}

int32_t nghttp2_session_get_effective_local_window_size
(nghttp2_session *session)
{
  return session->local_window_size;
}

int nghttp2_session_set_option(nghttp2_session *session,
                               int optname, void *optval, size_t optlen)
{
  switch(optname) {
  case NGHTTP2_OPT_NO_AUTO_STREAM_WINDOW_UPDATE:
  case NGHTTP2_OPT_NO_AUTO_CONNECTION_WINDOW_UPDATE: {
    int flag;
    if(optname == NGHTTP2_OPT_NO_AUTO_STREAM_WINDOW_UPDATE) {
      flag = NGHTTP2_OPTMASK_NO_AUTO_STREAM_WINDOW_UPDATE;
    } else {
      flag = NGHTTP2_OPTMASK_NO_AUTO_CONNECTION_WINDOW_UPDATE;
    }
    if(optlen == sizeof(int)) {
      int intval = *(int*)optval;
      if(intval) {
        session->opt_flags |= flag;
      } else {
        session->opt_flags &= ~flag;
      }
    } else {
      return NGHTTP2_ERR_INVALID_ARGUMENT;
    }
    break;
  }
  case NGHTTP2_OPT_PEER_MAX_CONCURRENT_STREAMS: {
    ssize_t sszval;
    if(optlen != sizeof(ssize_t)) {
      return NGHTTP2_ERR_INVALID_ARGUMENT;
    }
    sszval = *(ssize_t*)optval;
    if(sszval <= 0) {
      return NGHTTP2_ERR_INVALID_ARGUMENT;
    }
    session->remote_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS] =
      sszval;
    break;
  }
  default:
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  return 0;
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
  int max_conn_val_seen = 0;
  int ini_win_size_seen = 0;
  size_t i;

  if((!session->server && session->next_stream_id != 1) ||
     (session->server && session->last_recv_stream_id >= 1)) {
    return NGHTTP2_ERR_PROTO;
  }
  if(settings_payloadlen % 8) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  rv = nghttp2_frame_unpack_settings_payload(&iv, &niv, settings_payload,
                                             settings_payloadlen);
  if(rv != 0) {
    return rv;
  }
  for(i = 0; i < niv; ++i) {
    if(iv[i].settings_id == NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS) {
      max_conn_val_seen = 1;
    } else if(iv[i].settings_id == NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE) {
      ini_win_size_seen = 1;
    }
  }
  if(!max_conn_val_seen || !ini_win_size_seen) {
    free(iv);
    return NGHTTP2_ERR_PROTO;
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
  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_END_STREAM,
                                       0, NGHTTP2_STREAM_OPENING,
                                       session->server ?
                                       NULL : stream_user_data);
  if(stream == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  if(session->server) {
    nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
    session->last_recv_stream_id = 1;
  } else {
    nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
    session->next_stream_id += 2;
  }
  return 0;
}
