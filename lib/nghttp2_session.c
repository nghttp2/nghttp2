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

int nghttp2_session_fail_session(nghttp2_session *session,
                                 nghttp2_error_code error_code)
{
  session->goaway_flags |= NGHTTP2_GOAWAY_FAIL_ON_SEND;
  return nghttp2_submit_goaway(session, error_code, NULL, 0);
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

static void nghttp2_inbound_frame_reset(nghttp2_inbound_frame *iframe)
{
  iframe->state = NGHTTP2_RECV_HEAD;
  iframe->payloadlen = iframe->buflen = iframe->off = 0;
  iframe->headbufoff = 0;
  nghttp2_buffer_reset(&iframe->inflatebuf);
  iframe->error_code = 0;
}

/*
 * Returns the number of bytes before name/value header block for the
 * incoming frame. If the incoming frame does not have name/value
 * block, this function returns -1.
 */
static size_t nghttp2_inbound_frame_payload_nv_offset
(nghttp2_inbound_frame *iframe)
{
  ssize_t offset;
  offset = nghttp2_frame_nv_offset(iframe->headbuf);
  if(offset != -1) {
    offset -= NGHTTP2_FRAME_HEAD_LENGTH;
  }
  return offset;
}

static int nghttp2_session_new(nghttp2_session **session_ptr,
                               const nghttp2_session_callbacks *callbacks,
                               void *user_data,
                               int hd_comp)
{
  int r;
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
  (*session_ptr)->window_size = NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE;
  (*session_ptr)->recv_window_size = 0;

  (*session_ptr)->goaway_flags = NGHTTP2_GOAWAY_NONE;
  (*session_ptr)->last_stream_id = 0;

  (*session_ptr)->max_recv_ctrl_frame_buf = (1 << 24)-1;

  r = nghttp2_zlib_deflate_hd_init(&(*session_ptr)->hd_deflater,
                                   hd_comp,
                                   (*session_ptr)->version);
  if(r != 0) {
    goto fail_hd_deflater;
  }
  r = nghttp2_zlib_inflate_hd_init(&(*session_ptr)->hd_inflater,
                                   (*session_ptr)->version);
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
  (*session_ptr)->remote_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS] =
    NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS;
  (*session_ptr)->remote_settings[NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE] =
    NGHTTP2_INITIAL_WINDOW_SIZE;

  memset((*session_ptr)->local_settings, 0,
         sizeof((*session_ptr)->local_settings));
  (*session_ptr)->local_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS] =
    NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS;
  (*session_ptr)->local_settings[NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE] =
    NGHTTP2_INITIAL_WINDOW_SIZE;

  (*session_ptr)->callbacks = *callbacks;
  (*session_ptr)->user_data = user_data;

  (*session_ptr)->iframe.buf = malloc(NGHTTP2_INITIAL_INBOUND_FRAMEBUF_LENGTH);
  if((*session_ptr)->iframe.buf == NULL) {
    r = NGHTTP2_ERR_NOMEM;
    goto fail_iframe_buf;
  }
  (*session_ptr)->iframe.bufmax = NGHTTP2_INITIAL_INBOUND_FRAMEBUF_LENGTH;
  nghttp2_buffer_init(&(*session_ptr)->iframe.inflatebuf, 4096);

  nghttp2_inbound_frame_reset(&(*session_ptr)->iframe);

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
  nghttp2_zlib_inflate_free(&(*session_ptr)->hd_inflater);
 fail_hd_inflater:
  nghttp2_zlib_deflate_free(&(*session_ptr)->hd_deflater);
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
  r = nghttp2_session_new(session_ptr, callbacks, user_data, 1 /* hd_comp */);
  if(r == 0) {
    (*session_ptr)->server = 1;
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
  nghttp2_map_each_free(&session->streams, nghttp2_free_streams, NULL);
  nghttp2_session_ob_pq_free(&session->ob_pq);
  nghttp2_session_ob_pq_free(&session->ob_ss_pq);
  nghttp2_zlib_deflate_free(&session->hd_deflater);
  nghttp2_zlib_inflate_free(&session->hd_inflater);
  nghttp2_active_outbound_item_reset(&session->aob);
  free(session->aob.framebuf);
  free(session->nvbuf);
  nghttp2_buffer_free(&session->iframe.inflatebuf);
  free(session->iframe.buf);
   free(session);
}

int nghttp2_session_add_frame(nghttp2_session *session,
                              nghttp2_frame_category frame_cat,
                              void *abs_frame,
                              void *aux_data)
{
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
    switch(frame->hd.type) {
    case NGHTTP2_HEADERS:
      if(frame->hd.stream_id == -1) {
        /* Initial HEADERS, which will open stream */
        item->pri = frame->headers.pri;
      } else {
        /* Otherwise, the frame must have stream ID. We use its
           priority value. */
        nghttp2_stream *stream;
        stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
        if(stream) {
          item->pri = stream->pri;
        }
      }
      break;
    case NGHTTP2_RST_STREAM: {
      nghttp2_stream *stream;
      stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
      if(stream) {
        stream->state = NGHTTP2_STREAM_CLOSING;
        item->pri = stream->pri;
      }
      break;
    }
    case NGHTTP2_SETTINGS:
      /* Should NGHTTP2_SETTINGS have higher priority? */
      item->pri = -1;
      break;
    case NGHTTP2_PING:
      /* Ping has highest priority. */
      item->pri = NGHTTP2_OB_PRI_PING;
      break;
    case NGHTTP2_GOAWAY:
      /* Should GOAWAY have higher priority? */
      break;
    case NGHTTP2_WINDOW_UPDATE:
      if(frame->hd.stream_id == 0) {
        /* Connection level window update should have higher priority */
        item->pri = -1;
      } else {
        nghttp2_stream *stream;
        stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
        if(stream) {
          item->pri = stream->pri;
        }
      }
      break;
    }
    if(frame->hd.type == NGHTTP2_HEADERS && frame->hd.stream_id == -1) {
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
  item->inipri = item->pri;
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
                      stream_user_data);
  r = nghttp2_map_insert(&session->streams, &stream->map_entry);
  if(r != 0) {
    free(stream);
    stream = NULL;
  }
  if(nghttp2_session_is_my_stream_id(session, stream_id)) {
    ++session->num_outgoing_streams;
  } else {
    ++session->num_incoming_streams;
  }
  return stream;
}

int nghttp2_session_close_stream(nghttp2_session *session, int32_t stream_id,
                                 nghttp2_error_code error_code)
{
  nghttp2_stream *stream = nghttp2_session_get_stream(session, stream_id);
  if(stream) {
    if(stream->state != NGHTTP2_STREAM_INITIAL &&
       session->callbacks.on_stream_close_callback) {
      session->callbacks.on_stream_close_callback(session, stream_id,
                                                  error_code,
                                                  session->user_data);
    }
    if(nghttp2_session_is_my_stream_id(session, stream_id)) {
      --session->num_outgoing_streams;
    } else {
      --session->num_incoming_streams;
    }
    nghttp2_map_remove(&session->streams, stream_id);
    nghttp2_stream_free(stream);
    free(stream);
    return 0;
  } else {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
}

int nghttp2_session_close_stream_if_shut_rdwr(nghttp2_session *session,
                                              nghttp2_stream *stream)
{
  if((stream->shut_flags & NGHTTP2_SHUT_RDWR) == NGHTTP2_SHUT_RDWR) {
    return nghttp2_session_close_stream(session, stream->stream_id,
                                        NGHTTP2_NO_ERROR);
  } else {
    return 0;
  }
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
  } else if(stream->shut_flags & NGHTTP2_SHUT_WR) {
    return NGHTTP2_ERR_STREAM_SHUT_WR;
  } else {
    return 0;
  }
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
static int nghttp2_session_predicate_syn_stream_send
(nghttp2_session *session, nghttp2_headers *frame)
{
  if(session->goaway_flags) {
    /* When GOAWAY is sent or received, peer must not send new
       SYN_STREAM. */
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
 *     with FIN flag set has already sent)
 * NGHTTP2_ERR_INVALID_STREAM_ID
 *     The stream ID is invalid.
 * NGHTTP2_ERR_STREAM_CLOSING
 *     RST_STREAM was queued for this stream.
 * NGHTTP2_ERR_INVALID_STREAM_STATE
 *     The state of the stream is not valid (e.g., SYN_REPLY has
 *     already sent).
 */
static int nghttp2_session_predicate_syn_reply_send(nghttp2_session *session,
                                                    int32_t stream_id)
{
  nghttp2_stream *stream = nghttp2_session_get_stream(session, stream_id);
  int r;
  r = nghttp2_predicate_stream_for_send(stream);
  if(r != 0) {
    return r;
  }
  if(nghttp2_session_is_my_stream_id(session, stream_id)) {
    return NGHTTP2_ERR_INVALID_STREAM_ID;
  } else {
    if(stream->state == NGHTTP2_STREAM_OPENING) {
      return 0;
    } else if(stream->state == NGHTTP2_STREAM_CLOSING) {
      return NGHTTP2_ERR_STREAM_CLOSING;
    } else {
      return NGHTTP2_ERR_INVALID_STREAM_STATE;
    }
  }
}

/*
 * This function checks HEADERS, which is neither stream-opening nor
 * first response header, with the stream ID |stream_id| can be sent
 * at this time.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_STREAM_CLOSED
 *     The stream is already closed or does not exist.
 * NGHTTP2_ERR_STREAM_SHUT_WR
 *     The transmission is not allowed for this stream (e.g., a frame
 *     with FIN flag set has already sent)
 * NGHTTP2_ERR_STREAM_CLOSING
 *     RST_STREAM was queued for this stream.
 * NGHTTP2_ERR_INVALID_STREAM_STATE
 *     The state of the stream is not valid (e.g., if the local peer
 *     is receiving side and SYN_REPLY has not been sent).
 */
static int nghttp2_session_predicate_headers_send(nghttp2_session *session,
                                                  int32_t stream_id)
{
  nghttp2_stream *stream = nghttp2_session_get_stream(session, stream_id);
  int r;
  r = nghttp2_predicate_stream_for_send(stream);
  if(r != 0) {
    return r;
  }
  if(nghttp2_session_is_my_stream_id(session, stream_id)) {
    if(stream->state != NGHTTP2_STREAM_CLOSING) {
      return 0;
    } else {
      return NGHTTP2_ERR_STREAM_CLOSING;
    }
  } else {
    if(stream->state == NGHTTP2_STREAM_OPENED) {
      return 0;
    } else if(stream->state == NGHTTP2_STREAM_CLOSING) {
      return NGHTTP2_ERR_STREAM_CLOSING;
    } else {
      return NGHTTP2_ERR_INVALID_STREAM_STATE;
    }
  }
}

/*
 * This function checks WINDOW_UPDATE with the stream ID |stream_id|
 * can be sent at this time. Note that FIN flag of the previous frame
 * does not affect the transmission of the WINDOW_UPDATE frame.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_STREAM_CLOSED
 *     The stream is already closed or does not exist.
 * NGHTTP2_ERR_STREAM_CLOSING
 *     RST_STREAM was queued for this stream.
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
  if(stream->state != NGHTTP2_STREAM_CLOSING) {
    return 0;
  } else {
    return NGHTTP2_ERR_STREAM_CLOSING;
  }
}

/*
 * Returns the maximum length of next data read. If the
 * connection-level and/or stream-wise flow control are enabled, the
 * return value takes into account those current window sizes.
 */
static size_t nghttp2_session_next_data_read(nghttp2_session *session,
                                             nghttp2_stream *stream)
{
  /* TODO implement connection-level flow control here */
  if(session->remote_flow_control == 0 && stream->remote_flow_control == 0) {
    return NGHTTP2_DATA_PAYLOAD_LENGTH;
  } else {
    int32_t session_window_size =
      session->remote_flow_control ? session->window_size : INT32_MAX;
    int32_t stream_window_size =
      stream->remote_flow_control ? stream->window_size : INT32_MAX;
    int32_t window_size = nghttp2_min(session_window_size,
                                      stream_window_size);
    if(window_size > 0) {
      return window_size < NGHTTP2_DATA_PAYLOAD_LENGTH ?
        window_size : NGHTTP2_DATA_PAYLOAD_LENGTH;
    } else {
      return 0;
    }
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
 *     with FIN flag set has already sent)
 * NGHTTP2_ERR_DEFERRED_DATA_EXIST
 *     Another DATA frame has already been deferred.
 * NGHTTP2_ERR_STREAM_CLOSING
 *     RST_STREAM was queued for this stream.
 * NGHTTP2_ERR_INVALID_STREAM_STATE
 *     The state of the stream is not valid (e.g., if the local peer
 *     is receiving side and SYN_REPLY has not been sent).
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
    /* If stream->state is NGHTTP2_STREAM_CLOSING, RST_STREAM was
       queued but not yet sent. In this case, we won't send DATA
       frames. This is because in the current architecture, DATA and
       RST_STREAM in the same stream have same priority and DATA is
       small seq number. So RST_STREAM will not be sent until all DATA
       frames are sent. This is not desirable situation; we want to
       close stream as soon as possible. To achieve this, we remove
       DATA frame before RST_STREAM. */
    if(stream->state != NGHTTP2_STREAM_CLOSING) {
      return 0;
    } else {
      return NGHTTP2_ERR_STREAM_CLOSING;
    }
  } else {
    if(stream->state == NGHTTP2_STREAM_OPENED) {
      return 0;
    } else if(stream->state == NGHTTP2_STREAM_CLOSING) {
      return NGHTTP2_ERR_STREAM_CLOSING;
    } else {
      return NGHTTP2_ERR_INVALID_STREAM_STATE;
    }
  }
}

static ssize_t nghttp2_session_prep_frame(nghttp2_session *session,
                                          nghttp2_outbound_item *item)
{
  ssize_t framebuflen = 0;
  if(item->frame_cat == NGHTTP2_CAT_CTRL) {
    nghttp2_frame *frame;
    frame = nghttp2_outbound_item_get_ctrl_frame(item);
    switch(frame->hd.type) {
    case NGHTTP2_HEADERS:
      if(frame->hd.stream_id == -1) {
        /* initial HEADERS, which opens stream */
        int32_t stream_id;
        nghttp2_headers_aux_data *aux_data;
        int r;
        frame->headers.cat = NGHTTP2_HCAT_START_STREAM;
        r = nghttp2_session_predicate_syn_stream_send(session,
                                                      &frame->headers);
        if(r != 0) {
          return r;
        }
        stream_id = session->next_stream_id;
        frame->hd.stream_id = stream_id;
        session->next_stream_id += 2;
        framebuflen = nghttp2_frame_pack_headers(&session->aob.framebuf,
                                                 &session->aob.framebufmax,
                                                 &session->nvbuf,
                                                 &session->nvbuflen,
                                                 &frame->headers,
                                                 &session->hd_deflater);
        if(framebuflen < 0) {
          return framebuflen;
        }
        aux_data = (nghttp2_headers_aux_data*)item->aux_data;
        if(nghttp2_session_open_stream
           (session, stream_id,
            frame->hd.flags,
            frame->headers.pri,
            NGHTTP2_STREAM_INITIAL,
            aux_data ? aux_data->stream_user_data : NULL) == NULL) {
          return NGHTTP2_ERR_NOMEM;
        }
      } else if(nghttp2_session_predicate_syn_reply_send
                (session, frame->hd.stream_id) == 0) {
        frame->headers.cat = NGHTTP2_HCAT_REPLY;
        /* first response HEADERS */
        framebuflen = nghttp2_frame_pack_headers(&session->aob.framebuf,
                                                 &session->aob.framebufmax,
                                                 &session->nvbuf,
                                                 &session->nvbuflen,
                                                 &frame->headers,
                                                 &session->hd_deflater);
        if(framebuflen < 0) {
          return framebuflen;
        }

      } else {
        int r;
        frame->headers.cat = NGHTTP2_HCAT_HEADERS;
        r = nghttp2_session_predicate_headers_send(session,
                                                   frame->hd.stream_id);
        if(r != 0) {
          return r;
        }
        framebuflen = nghttp2_frame_pack_headers(&session->aob.framebuf,
                                                 &session->aob.framebufmax,
                                                 &session->nvbuf,
                                                 &session->nvbuflen,
                                                 &frame->headers,
                                                 &session->hd_deflater);
        if(framebuflen < 0) {
          return framebuflen;
        }
      }
      break;
    case NGHTTP2_RST_STREAM:
      framebuflen = nghttp2_frame_pack_rst_stream(&session->aob.framebuf,
                                                  &session->aob.framebufmax,
                                                  &frame->rst_stream);
      if(framebuflen < 0) {
        return framebuflen;
      }
      break;
    case NGHTTP2_SETTINGS:
      framebuflen = nghttp2_frame_pack_settings(&session->aob.framebuf,
                                                &session->aob.framebufmax,
                                                &frame->settings);
      if(framebuflen < 0) {
        return framebuflen;
      }
      break;
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
      nghttp2_outbound_item *item, *syn_stream_item;
      item = nghttp2_pq_top(&session->ob_pq);
      syn_stream_item = nghttp2_pq_top(&session->ob_ss_pq);
      if(nghttp2_session_is_outgoing_concurrent_streams_max(session) ||
         item->pri < syn_stream_item->pri ||
         (item->pri == syn_stream_item->pri &&
          item->seq < syn_stream_item->seq)) {
        return item;
      } else {
        return syn_stream_item;
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
      nghttp2_outbound_item *item, *syn_stream_item;
      item = nghttp2_pq_top(&session->ob_pq);
      syn_stream_item = nghttp2_pq_top(&session->ob_ss_pq);
      if(nghttp2_session_is_outgoing_concurrent_streams_max(session) ||
         item->pri < syn_stream_item->pri ||
         (item->pri == syn_stream_item->pri &&
          item->seq < syn_stream_item->seq)) {
        nghttp2_pq_pop(&session->ob_pq);
        return item;
      } else {
        nghttp2_pq_pop(&session->ob_ss_pq);
        return syn_stream_item;
      }
    }
  }
}

/*
 * Adjust priority of item so that the higher priority long DATA
 * frames don't starve lower priority streams.
 */
static void nghttp2_outbound_item_adjust_pri(nghttp2_session *session,
                                             nghttp2_outbound_item *item)
{
  if(item->pri == NGHTTP2_PRI_LOWEST) {
    item->pri = item->inipri;
  } else if(item->pri > (int32_t)NGHTTP2_PRI_LOWEST/2) {
    item->pri = NGHTTP2_PRI_LOWEST;
  } else {
    item->pri *= 2;
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
    nghttp2_frame *frame;
    frame = nghttp2_outbound_item_get_ctrl_frame(session->aob.item);
    if(session->callbacks.on_frame_send_callback) {
      session->callbacks.on_frame_send_callback(session, frame,
                                                session->user_data);
    }
    switch(frame->hd.type) {
    case NGHTTP2_HEADERS: {
      nghttp2_stream *stream =
        nghttp2_session_get_stream(session, frame->hd.stream_id);
      nghttp2_headers_aux_data *aux_data;
      if(stream) {
        switch(frame->headers.cat) {
        case NGHTTP2_HCAT_START_STREAM: {
          stream->state = NGHTTP2_STREAM_OPENING;
          if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
          }
          nghttp2_session_close_stream_if_shut_rdwr(session, stream);
          /* We assume aux_data is a pointer to nghttp2_headers_aux_data */
          aux_data = (nghttp2_headers_aux_data*)item->aux_data;
          if(aux_data && aux_data->data_prd) {
            int r;
            /* nghttp2_submit_data() makes a copy of aux_data->data_prd */
            r = nghttp2_submit_data(session, NGHTTP2_FLAG_END_STREAM,
                                    frame->hd.stream_id, aux_data->data_prd);
            if(r != 0) {
              /* FATAL error */
              assert(r < NGHTTP2_ERR_FATAL);
              /* TODO If r is not FATAL, we should send RST_STREAM. */
              return r;
            }
          }
          break;
        }
        case NGHTTP2_HCAT_REPLY:
          stream->state = NGHTTP2_STREAM_OPENED;
          if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
          }
          nghttp2_session_close_stream_if_shut_rdwr(session, stream);
          /* We assume aux_data is a pointer to nghttp2_headers_aux_data */
          aux_data = (nghttp2_headers_aux_data*)item->aux_data;
          if(aux_data && aux_data->data_prd) {
            int r;
            r = nghttp2_submit_data(session, NGHTTP2_FLAG_END_STREAM,
                                    frame->hd.stream_id, aux_data->data_prd);
            if(r != 0) {
              /* FATAL error */
              assert(r < NGHTTP2_ERR_FATAL);
              /* TODO If r is not FATAL, we should send RST_STREAM. */
              return r;
            }
          }
          break;
        case NGHTTP2_HCAT_HEADERS:
          if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
          }
          nghttp2_session_close_stream_if_shut_rdwr(session, stream);
          break;
        }
      }
      break;
    }
    case NGHTTP2_RST_STREAM:
      nghttp2_session_close_stream(session, frame->hd.stream_id,
                                   frame->rst_stream.error_code);
      break;
    case NGHTTP2_SETTINGS:
      /* nothing to do */
      break;
    case NGHTTP2_PING:
      /* nothing to do */
      break;
    case NGHTTP2_GOAWAY:
      session->goaway_flags |= NGHTTP2_GOAWAY_SEND;
      break;
    case NGHTTP2_WINDOW_UPDATE:
      if(frame->hd.flags & NGHTTP2_FLAG_END_FLOW_CONTROL) {
        if(frame->hd.stream_id == 0) {
          session->local_flow_control = 0;
        } else {
          nghttp2_stream *stream;
          stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
          if(stream) {
            stream->local_flow_control = 0;
          }
        }
      }
      break;
    }
    nghttp2_active_outbound_item_reset(&session->aob);
  } else if(item->frame_cat == NGHTTP2_CAT_DATA) {
    int r;
    nghttp2_data *data_frame;
    data_frame = nghttp2_outbound_item_get_data_frame(session->aob.item);
    if(session->callbacks.on_data_send_callback) {
      session->callbacks.on_data_send_callback
        (session,
         session->aob.framebuflen - NGHTTP2_FRAME_HEAD_LENGTH,
         data_frame->eof ? data_frame->hd.flags :
         (data_frame->hd.flags & (~NGHTTP2_FLAG_END_STREAM)),
         data_frame->hd.stream_id,
         session->user_data);
    }
    if(data_frame->eof && (data_frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
      nghttp2_stream *stream =
        nghttp2_session_get_stream(session, data_frame->hd.stream_id);
      if(stream) {
        nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
        nghttp2_session_close_stream_if_shut_rdwr(session, stream);
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
      nghttp2_outbound_item_adjust_pri(session, session->aob.item);
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
      if(framebuflen == NGHTTP2_ERR_DEFERRED ||
         framebuflen == NGHTTP2_ERR_CREDENTIAL_PENDING) {
        continue;
      } else if(framebuflen < 0) {
        if(item->frame_cat == NGHTTP2_CAT_CTRL &&
           session->callbacks.on_frame_not_send_callback &&
           nghttp2_is_non_fatal(framebuflen)) {
          /* The library is responsible for the transmission of
             WINDOW_UPDATE frame, so we don't call error callback for
             it. */
          nghttp2_frame *frame = nghttp2_outbound_item_get_ctrl_frame(item);
          if(frame->hd.type != NGHTTP2_WINDOW_UPDATE) {
            session->callbacks.on_frame_not_send_callback
              (session, frame, framebuflen, session->user_data);
          }
        }
        nghttp2_outbound_item_free(item);
        free(item);

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
        session->callbacks.before_frame_send_callback
          (session,
           nghttp2_outbound_item_get_ctrl_frame(item),
           session->user_data);
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
      session->aob.framebufoff += sentlen;
      if(session->aob.item->frame_cat == NGHTTP2_CAT_DATA) {
        nghttp2_data *frame;
        nghttp2_stream *stream;
        uint16_t len = nghttp2_get_uint16(&session->aob.framebuf[0]);
        frame = nghttp2_outbound_item_get_data_frame(session->aob.item);
        stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
        if(stream && stream->remote_flow_control) {
          stream->window_size -= len;
        }
        if(session->remote_flow_control) {
          session->window_size -= len;
        }
      }
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

static void nghttp2_session_call_on_request_recv
(nghttp2_session *session, int32_t stream_id)
{
  if(session->callbacks.on_request_recv_callback) {
    session->callbacks.on_request_recv_callback(session, stream_id,
                                                session->user_data);
  }
}

static void nghttp2_session_call_on_frame_received
(nghttp2_session *session, nghttp2_frame *frame)
{
  if(session->callbacks.on_frame_recv_callback) {
    session->callbacks.on_frame_recv_callback(session, frame,
                                              session->user_data);
  }
}

/*
 * Checks whether received stream_id is valid.
 * This function returns 1 if it succeeds, or 0.
 */
static int nghttp2_session_is_new_peer_stream_id(nghttp2_session *session,
                                                 int32_t stream_id)
{
  if(stream_id == 0) {
    return 0;
  }
  if(session->server) {
    return stream_id % 2 == 1 && session->last_recv_stream_id < stream_id;
  } else {
    return stream_id % 2 == 0 && session->last_recv_stream_id < stream_id;
  }
}

/*
 * Validates received HEADERS frame |frame| with
 * NGHTTP2_HCAT_START_STREAM category_. This function returns 0 if it
 * succeeds, or non-zero nghttp2_error_code.
 */
static int nghttp2_session_validate_syn_stream(nghttp2_session *session,
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


static int nghttp2_session_handle_invalid_stream
(nghttp2_session *session,
 int32_t stream_id,
 nghttp2_frame *frame,
 nghttp2_error_code error_code)
{
  int r;
  r = nghttp2_session_add_rst_stream(session, stream_id, error_code);
  if(r != 0) {
    return r;
  }
  if(session->callbacks.on_invalid_frame_recv_callback) {
    session->callbacks.on_invalid_frame_recv_callback
      (session, frame, error_code, session->user_data);
  }
  return 0;
}

int nghttp2_session_on_syn_stream_received(nghttp2_session *session,
                                           nghttp2_frame *frame)
{
  int r = 0;
  nghttp2_error_code error_code = NGHTTP2_NO_ERROR;
  if(session->goaway_flags) {
    /* We don't accept new stream after GOAWAY is sent or received. */
    return 0;
  }
  if(!nghttp2_session_is_new_peer_stream_id
     (session, frame->hd.stream_id)) {
    /* The spec says if an endpoint receives a HEADERS with invalid
       stream ID, it MUST issue connection error with error code
       PROTOCOL_ERROR */
    if(session->callbacks.on_invalid_frame_recv_callback) {
      session->callbacks.on_invalid_frame_recv_callback
        (session, frame, NGHTTP2_PROTOCOL_ERROR, session->user_data);
    }
    return nghttp2_session_fail_session(session, NGHTTP2_PROTOCOL_ERROR);
  } else {
    session->last_recv_stream_id = frame->hd.stream_id;
    error_code = nghttp2_session_validate_syn_stream(session, &frame->headers);
  }
  if(error_code == 0) {
    uint8_t flags = frame->hd.flags;
    nghttp2_stream *stream;
    stream = nghttp2_session_open_stream(session,
                                         frame->hd.stream_id,
                                         frame->hd.flags,
                                         frame->headers.pri,
                                         NGHTTP2_STREAM_OPENING,
                                         NULL);
    if(!stream) {
      return NGHTTP2_ERR_NOMEM;
    }
    if(flags & NGHTTP2_FLAG_END_STREAM) {
      nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
    }
    nghttp2_session_call_on_frame_received(session, frame);
    if(flags & NGHTTP2_FLAG_END_STREAM) {
      nghttp2_session_call_on_request_recv(session, frame->hd.stream_id);
    }
  } else {
    r = nghttp2_session_handle_invalid_stream
      (session, frame->hd.stream_id, frame, error_code);
  }
  return r;
}

int nghttp2_session_on_syn_reply_received(nghttp2_session *session,
                                          nghttp2_frame *frame,
                                          nghttp2_stream *stream)
{
  int r = 0;
  int valid = 0;
  nghttp2_error_code error_code = NGHTTP2_PROTOCOL_ERROR;
  if((stream->shut_flags & NGHTTP2_SHUT_RD) == 0) {
    if(nghttp2_session_is_my_stream_id(session, frame->hd.stream_id)) {
      if(stream->state == NGHTTP2_STREAM_OPENING) {
        valid = 1;
        stream->state = NGHTTP2_STREAM_OPENED;
        nghttp2_session_call_on_frame_received(session, frame);
        if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
          /* This is the last frame of this stream, so disallow
             further receptions. */
          nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
          nghttp2_session_close_stream_if_shut_rdwr(session, stream);
        }
      } else if(stream->state == NGHTTP2_STREAM_CLOSING) {
        /* This is race condition. NGHTTP2_STREAM_CLOSING indicates
           that we queued RST_STREAM but it has not been sent. It will
           eventually sent, so we just ignore this frame. */
        valid = 1;
      } else {
        /* It seems that the spec does not say what to do if multiple
           HEADERS for the same active stream ID are receives. The
           SPDY/3 spec says it should be treated as stream error with
           error code STREAM_IN_USE. The spec does not such code
           anymore. It would be safer to reject those broken client at
           the moment. Do you accept the web server which responds
           with multiple response headers? */
        if(session->callbacks.on_invalid_frame_recv_callback) {
          session->callbacks.on_invalid_frame_recv_callback
            (session, frame, NGHTTP2_PROTOCOL_ERROR, session->user_data);
        }
        return nghttp2_session_fail_session(session, NGHTTP2_PROTOCOL_ERROR);
      }
    }
  } else {
    /* half closed (remote): from the spec:

       If an endpoint receives additional frames for a stream that is
       in this state it MUST respond with a stream error (Section
       5.4.2) of type STREAM_CLOSED.
    */
    error_code = NGHTTP2_STREAM_CLOSED;
  }
  if(!valid) {
    r = nghttp2_session_handle_invalid_stream
      (session, frame->hd.stream_id, frame, error_code);
  }
  return r;
}

int nghttp2_session_on_headers_received(nghttp2_session *session,
                                        nghttp2_frame *frame,
                                        nghttp2_stream *stream)
{
  int r = 0;
  int valid = 0;
  nghttp2_error_code error_code = NGHTTP2_PROTOCOL_ERROR;
  if((stream->shut_flags & NGHTTP2_SHUT_RD) == 0) {
    if(nghttp2_session_is_my_stream_id(session, frame->hd.stream_id)) {
      if(stream->state == NGHTTP2_STREAM_OPENED) {
        valid = 1;
        nghttp2_session_call_on_frame_received(session, frame);
        if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
          nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
          nghttp2_session_close_stream_if_shut_rdwr(session, stream);
        }
      } else if(stream->state == NGHTTP2_STREAM_CLOSING) {
        /* This is race condition. NGHTTP2_STREAM_CLOSING indicates
           that we queued RST_STREAM but it has not been sent. It will
           eventually sent, so we just ignore this frame. */
        valid = 1;
      }
    } else {
      /* If this is remote peer initiated stream, it is OK unless it
         have sent FIN frame already. But if stream is in
         NGHTTP2_STREAM_CLOSING, we discard the frame. This is a race
         condition. */
      valid = 1;
      if(stream->state != NGHTTP2_STREAM_CLOSING) {
        nghttp2_session_call_on_frame_received(session, frame);
        if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
          nghttp2_session_call_on_request_recv(session, frame->hd.stream_id);
          nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
          nghttp2_session_close_stream_if_shut_rdwr(session, stream);
        }
      }
    }
  } else {
    /* half closed (remote): from the spec:

       If an endpoint receives additional frames for a stream that is
       in this state it MUST respond with a stream error (Section
       5.4.2) of type STREAM_CLOSED.
    */
    error_code = NGHTTP2_STREAM_CLOSED;
  }
  if(!valid) {
    r = nghttp2_session_handle_invalid_stream
      (session, frame->hd.stream_id, frame, error_code);
  }
  return r;
}

int nghttp2_session_on_rst_stream_received(nghttp2_session *session,
                                           nghttp2_frame *frame)
{
  nghttp2_session_call_on_frame_received(session, frame);
  nghttp2_session_close_stream(session, frame->hd.stream_id,
                               frame->rst_stream.error_code);
  return 0;
}

static int nghttp2_update_initial_window_size_func(nghttp2_map_entry *entry,
                                                   void *ptr)
{
  nghttp2_update_window_size_arg *arg;
  nghttp2_stream *stream;
  arg = (nghttp2_update_window_size_arg*)ptr;
  stream = (nghttp2_stream*)entry;
  nghttp2_stream_update_initial_window_size(stream,
                                            arg->new_window_size,
                                            arg->old_window_size);
  /* If window size gets positive, push deferred DATA frame to
     outbound queue. */
  if(stream->deferred_data &&
     (stream->deferred_flags & NGHTTP2_DEFERRED_FLOW_CONTROL) &&
     stream->window_size > 0 &&
     (arg->session->remote_flow_control == 0 ||
      arg->session->window_size > 0)) {
    int rv;
    rv = nghttp2_pq_push(&arg->session->ob_pq, stream->deferred_data);
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
 * Updates the initial window size of all active streams.
 * If error occurs, all streams may not be updated.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
static int nghttp2_session_update_initial_window_size
(nghttp2_session *session,
 int32_t new_initial_window_size)
{
  nghttp2_update_window_size_arg arg;
  arg.session = session;
  arg.new_window_size = new_initial_window_size;
  arg.old_window_size =
    session->remote_settings[NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE];
  return nghttp2_map_each(&session->streams,
                          nghttp2_update_initial_window_size_func,
                          &arg);
}

static int nghttp2_disable_flow_control_func(nghttp2_map_entry *entry,
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
 * Disable connection-level flow control and stream-level flow control
 * of existing streams.
 */
static int nghttp2_session_disable_flow_control(nghttp2_session *session)
{
  session->remote_flow_control = 0;
  return nghttp2_map_each(&session->streams,
                          nghttp2_disable_flow_control_func, session);
}

void nghttp2_session_update_local_settings(nghttp2_session *session,
                                           nghttp2_settings_entry *iv,
                                           size_t niv)
{
  size_t i;
  for(i = 0; i < niv; ++i) {
    assert(iv[i].settings_id > 0 && iv[i].settings_id <= NGHTTP2_SETTINGS_MAX);
    session->local_settings[iv[i].settings_id] = iv[i].value;
  }
}

int nghttp2_session_on_settings_received(nghttp2_session *session,
                                         nghttp2_frame *frame)
{
  int rv;
  size_t i;
  int check[NGHTTP2_SETTINGS_MAX+1];
  /* Check ID/value pairs and persist them if necessary. */
  memset(check, 0, sizeof(check));
  for(i = 0; i < frame->settings.niv; ++i) {
    nghttp2_settings_entry *entry = &frame->settings.iv[i];
    /* The spec says if the multiple values for the same ID were
       found, use the first one and ignore the rest. */
    if(entry->settings_id > NGHTTP2_SETTINGS_MAX || entry->settings_id == 0 ||
       check[entry->settings_id] == 1) {
      continue;
    }
    check[entry->settings_id] = 1;
    switch(entry->settings_id) {
    case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
      /* Update the initial window size of the all active streams */
      /* Check that initial_window_size < (1u << 31) */
      if(entry->value < (1u << 31)) {
        rv = nghttp2_session_update_initial_window_size(session, entry->value);
        if(rv != 0) {
          return rv;
        }
      } else {
        if(session->callbacks.on_invalid_frame_recv_callback) {
          session->callbacks.on_invalid_frame_recv_callback
            (session, frame, NGHTTP2_PROTOCOL_ERROR, session->user_data);
        }
        return nghttp2_session_fail_session(session, NGHTTP2_PROTOCOL_ERROR);
      }
      break;
    case NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS:
      if(entry->value == 1) {
        if(session->remote_settings[entry->settings_id] == 0) {
          rv = nghttp2_session_disable_flow_control(session);
          if(rv != 0) {
            return rv;
          }
        }
      } else if(session->remote_settings[entry->settings_id] == 1) {
        /* Re-enabling flow control is subject to connection-level
           error(?) */
        if(session->callbacks.on_invalid_frame_recv_callback) {
          session->callbacks.on_invalid_frame_recv_callback
            (session, frame, NGHTTP2_PROTOCOL_ERROR, session->user_data);
        }
        return nghttp2_session_fail_session(session,
                                            NGHTTP2_FLOW_CONTROL_ERROR);
      }
      break;
    }
    session->remote_settings[entry->settings_id] = entry->value;
  }
  nghttp2_session_call_on_frame_received(session, frame);
  return 0;
}

int nghttp2_session_on_ping_received(nghttp2_session *session,
                                     nghttp2_frame *frame)
{
  int r = 0;
  if((frame->hd.flags & NGHTTP2_FLAG_PONG) == 0) {
    /* Peer sent ping, so ping it back */
    r = nghttp2_session_add_ping(session, NGHTTP2_FLAG_PONG,
                                 frame->ping.opaque_data);
  }
  nghttp2_session_call_on_frame_received(session, frame);
  return r;
}

int nghttp2_session_on_goaway_received(nghttp2_session *session,
                                       nghttp2_frame *frame)
{
  session->last_stream_id = frame->goaway.last_stream_id;
  session->goaway_flags |= NGHTTP2_GOAWAY_RECV;
  nghttp2_session_call_on_frame_received(session, frame);
  return 0;
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
     (stream->remote_flow_control == 0 || stream->window_size > 0)) {
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

int nghttp2_session_on_window_update_received(nghttp2_session *session,
                                              nghttp2_frame *frame)
{
  if(frame->hd.stream_id == 0) {
    /* Handle connection-level flow control */
    if(session->remote_flow_control == 0) {
      /* The sepc says receiving WINDOW_UPDATE from peer when flow
         control is disabled is error, but disabling flow control and
         receiving WINDOW_UPDATE are asynchronous, so it is hard to
         determine that the peer is misbehaving or not without
         measuring RTT. For now, we just ignore such frames. */
      nghttp2_session_call_on_frame_received(session, frame);
      return 0;
    }
    if(frame->hd.flags & NGHTTP2_FLAG_END_FLOW_CONTROL) {
      if(session->remote_flow_control) {
        /* Disable connection-level flow control and push back
           deferred DATA frame if any */
        session->remote_flow_control = 0;
        nghttp2_session_call_on_frame_received(session, frame);
        return nghttp2_session_push_back_deferred_data(session);
      }
      return 0;
    }
    if(INT32_MAX - frame->window_update.window_size_increment <
       session->window_size) {
      if(session->callbacks.on_invalid_frame_recv_callback) {
        session->callbacks.on_invalid_frame_recv_callback
          (session, frame, NGHTTP2_FLOW_CONTROL_ERROR, session->user_data);
      }
      return nghttp2_session_fail_session
        (session, NGHTTP2_FLOW_CONTROL_ERROR);
    }
    session->window_size += frame->window_update.window_size_increment;
    nghttp2_session_call_on_frame_received(session, frame);
    /* To queue the DATA deferred by connection-level flow-control, we
       have to check all streams. Bad. */
    if(session->window_size > 0) {
      return nghttp2_session_push_back_deferred_data(session);
    } else {
      return 0;
    }
  } else {
    nghttp2_stream *stream;
    stream = nghttp2_session_get_stream(session, frame->hd.stream_id);
    if(stream) {
      if(stream->remote_flow_control == 0) {
        /* Same reason with connection-level flow control */
        nghttp2_session_call_on_frame_received(session, frame);
        return 0;
      }
      if(frame->hd.flags & NGHTTP2_FLAG_END_FLOW_CONTROL) {
        stream->remote_flow_control = 0;
        if(stream->remote_flow_control &&
           stream->deferred_data != NULL &&
           (stream->deferred_flags & NGHTTP2_DEFERRED_FLOW_CONTROL)) {
          int r;
          r = nghttp2_pq_push(&session->ob_pq, stream->deferred_data);
          if(r == 0) {
            nghttp2_stream_detach_deferred_data(stream);
          } else if(r < 0) {
            /* FATAL */
            assert(r < NGHTTP2_ERR_FATAL);
            return r;
          }
        }
        nghttp2_session_call_on_frame_received(session, frame);
        return 0;
      }
      if(INT32_MAX - frame->window_update.window_size_increment <
         stream->window_size) {
        int r;
        r = nghttp2_session_handle_invalid_stream
          (session, frame->hd.stream_id, frame, NGHTTP2_FLOW_CONTROL_ERROR);
        return r;
      } else {
        stream->window_size += frame->window_update.window_size_increment;
        if(stream->window_size > 0 &&
           (session->remote_flow_control == 0 ||
            session->window_size > 0) &&
           stream->deferred_data != NULL &&
           (stream->deferred_flags & NGHTTP2_DEFERRED_FLOW_CONTROL)) {
          int r;
          r = nghttp2_pq_push(&session->ob_pq, stream->deferred_data);
          if(r == 0) {
            nghttp2_stream_detach_deferred_data(stream);
          } else if(r < 0) {
            /* FATAL */
            assert(r < NGHTTP2_ERR_FATAL);
            return r;
          }
        }
        nghttp2_session_call_on_frame_received(session, frame);
      }
    }
  }
  return 0;
}

static void nghttp2_session_handle_parse_error(nghttp2_session *session,
                                               nghttp2_frame_type type,
                                               int lib_error_code)
{
  if(session->callbacks.on_frame_recv_parse_error_callback) {
    session->callbacks.on_frame_recv_parse_error_callback
      (session,
       type,
       session->iframe.headbuf,
       sizeof(session->iframe.headbuf),
       session->iframe.buf,
       session->iframe.buflen,
       lib_error_code,
       session->user_data);
  }
}

static int nghttp2_get_status_code_from_error_code(int lib_error_code)
{
  switch(lib_error_code) {
  case(NGHTTP2_ERR_FRAME_TOO_LARGE):
    return NGHTTP2_FRAME_TOO_LARGE;
  default:
    return NGHTTP2_PROTOCOL_ERROR;
  }
}

/* For errors, this function only returns FATAL error. */
static int nghttp2_session_process_ctrl_frame(nghttp2_session *session)
{
  int r = 0;
  uint16_t type;
  nghttp2_frame frame;
  type = session->iframe.headbuf[2];
  switch(type) {
  case NGHTTP2_HEADERS:
    if(session->iframe.error_code == 0) {
      r = nghttp2_frame_unpack_headers(&frame.headers,
                                       session->iframe.headbuf,
                                       sizeof(session->iframe.headbuf),
                                       session->iframe.buf,
                                       session->iframe.buflen,
                                       &session->iframe.inflatebuf);
    } else if(session->iframe.error_code == NGHTTP2_ERR_FRAME_TOO_LARGE) {
      r = nghttp2_frame_unpack_headers_without_nv
        (&frame.headers,
         session->iframe.headbuf, sizeof(session->iframe.headbuf),
         session->iframe.buf, session->iframe.buflen);
      if(r == 0) {
        r = session->iframe.error_code;
      }
    } else {
      r = session->iframe.error_code;
    }
    if(r == 0) {
      if(nghttp2_session_is_my_stream_id(session, frame.hd.stream_id)) {
        nghttp2_stream *stream;
        stream = nghttp2_session_get_stream(session, frame.hd.stream_id);
        if(stream) {
          if(stream->state == NGHTTP2_STREAM_OPENING) {
            frame.headers.cat = NGHTTP2_HCAT_REPLY;
            r = nghttp2_session_on_syn_reply_received(session, &frame, stream);
          } else {
            frame.headers.cat = NGHTTP2_HCAT_HEADERS;
            r = nghttp2_session_on_headers_received(session, &frame, stream);
          }
        } else {
          r = nghttp2_session_handle_invalid_stream
            (session, frame.hd.stream_id, &frame, NGHTTP2_PROTOCOL_ERROR);
        }
      } else {
        frame.headers.cat = NGHTTP2_HCAT_START_STREAM;
        r = nghttp2_session_on_syn_stream_received(session, &frame);
      }
      nghttp2_frame_headers_free(&frame.headers);
    } else if(r == NGHTTP2_ERR_INVALID_HEADER_BLOCK ||
              r == NGHTTP2_ERR_FRAME_TOO_LARGE) {
      r = nghttp2_session_handle_invalid_stream
        (session, frame.hd.stream_id, &frame,
         nghttp2_get_status_code_from_error_code(r));
      nghttp2_frame_headers_free(&frame.headers);
    } else if(nghttp2_is_non_fatal(r)) {
      nghttp2_session_handle_parse_error(session, type, r);
      r = nghttp2_session_fail_session(session, NGHTTP2_PROTOCOL_ERROR);
    }
    break;
  case NGHTTP2_RST_STREAM:
    r = nghttp2_frame_unpack_rst_stream(&frame.rst_stream,
                                        session->iframe.headbuf,
                                        sizeof(session->iframe.headbuf),
                                        session->iframe.buf,
                                        session->iframe.buflen);
    if(r == 0) {
      r = nghttp2_session_on_rst_stream_received(session, &frame);
      nghttp2_frame_rst_stream_free(&frame.rst_stream);
    } else if(nghttp2_is_non_fatal(r)) {
      nghttp2_session_handle_parse_error(session, type, r);
      r = nghttp2_session_fail_session(session, NGHTTP2_PROTOCOL_ERROR);
    }
    break;
  case NGHTTP2_SETTINGS:
    r = nghttp2_frame_unpack_settings(&frame.settings,
                                      session->iframe.headbuf,
                                      sizeof(session->iframe.headbuf),
                                      session->iframe.buf,
                                      session->iframe.buflen);
    if(r == 0) {
      r = nghttp2_session_on_settings_received(session, &frame);
      nghttp2_frame_settings_free(&frame.settings);
    } else if(nghttp2_is_non_fatal(r)) {
      nghttp2_session_handle_parse_error(session, type, r);
      r = nghttp2_session_fail_session(session, NGHTTP2_PROTOCOL_ERROR);
    }
    break;
  case NGHTTP2_PING:
    r = nghttp2_frame_unpack_ping(&frame.ping,
                                  session->iframe.headbuf,
                                  sizeof(session->iframe.headbuf),
                                  session->iframe.buf,
                                  session->iframe.buflen);
    if(r == 0) {
      r = nghttp2_session_on_ping_received(session, &frame);
      nghttp2_frame_ping_free(&frame.ping);
    } else if(nghttp2_is_non_fatal(r)) {
      nghttp2_session_handle_parse_error(session, type, r);
      r = nghttp2_session_fail_session(session, NGHTTP2_PROTOCOL_ERROR);
    }
    break;
  case NGHTTP2_GOAWAY:
    r = nghttp2_frame_unpack_goaway(&frame.goaway,
                                    session->iframe.headbuf,
                                    sizeof(session->iframe.headbuf),
                                    session->iframe.buf,
                                    session->iframe.buflen);
    if(r == 0) {
      r = nghttp2_session_on_goaway_received(session, &frame);
      nghttp2_frame_goaway_free(&frame.goaway);
    } else if(nghttp2_is_non_fatal(r)) {
      nghttp2_session_handle_parse_error(session, type, r);
      r = nghttp2_session_fail_session(session, NGHTTP2_PROTOCOL_ERROR);
    }
    break;
  case NGHTTP2_WINDOW_UPDATE:
    r = nghttp2_frame_unpack_window_update(&frame.window_update,
                                           session->iframe.headbuf,
                                           sizeof(session->iframe.headbuf),
                                           session->iframe.buf,
                                           session->iframe.buflen);
    if(r == 0) {
      r = nghttp2_session_on_window_update_received(session, &frame);
      nghttp2_frame_window_update_free(&frame.window_update);
    } else if(nghttp2_is_non_fatal(r)) {
      nghttp2_session_handle_parse_error(session, type, r);
      r = nghttp2_session_fail_session(session, NGHTTP2_PROTOCOL_ERROR);
    }
    break;
  default:
    /* Unknown frame */
    if(session->callbacks.on_unknown_frame_recv_callback) {
      session->callbacks.on_unknown_frame_recv_callback
        (session,
         session->iframe.headbuf,
         sizeof(session->iframe.headbuf),
         session->iframe.buf,
         session->iframe.buflen,
         session->user_data);
    }
  }
  if(nghttp2_is_fatal(r)) {
    return r;
  } else {
    return 0;
  }
}

int nghttp2_session_on_data_received(nghttp2_session *session,
                                     uint16_t length, uint8_t flags,
                                     int32_t stream_id)
{
  int r = 0;
  nghttp2_error_code error_code = 0;
  nghttp2_stream *stream;
  if(stream_id == 0) {
    /* The spec says that if a DATA frame is received whose stream ID
       is 0, the recipient MUST respond with a connection error of
       type PROTOCOL_ERROR. */
    return nghttp2_session_fail_session(session, NGHTTP2_PROTOCOL_ERROR);
  }
  stream = nghttp2_session_get_stream(session, stream_id);
  if(stream) {
    if((stream->shut_flags & NGHTTP2_SHUT_RD) == 0) {
      int valid = 0;
      if(nghttp2_session_is_my_stream_id(session, stream_id)) {
        if(stream->state == NGHTTP2_STREAM_OPENED) {
          valid = 1;
          if(session->callbacks.on_data_recv_callback) {
            session->callbacks.on_data_recv_callback
              (session, length, flags, stream_id, session->user_data);
          }
        } else if(stream->state != NGHTTP2_STREAM_CLOSING) {
          error_code = NGHTTP2_PROTOCOL_ERROR;
        }
      } else if(stream->state != NGHTTP2_STREAM_CLOSING) {
        /* It is OK if this is remote peer initiated stream and we did
           not receive FIN unless stream is in NGHTTP2_STREAM_CLOSING
           state. This is a race condition. */
        valid = 1;
        if(session->callbacks.on_data_recv_callback) {
          session->callbacks.on_data_recv_callback
            (session, length, flags, stream_id, session->user_data);
        }
        if(flags & NGHTTP2_FLAG_END_STREAM) {
          nghttp2_session_call_on_request_recv(session, stream_id);
        }
      }
      if(valid) {
        if(flags & NGHTTP2_FLAG_END_STREAM) {
          nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
          nghttp2_session_close_stream_if_shut_rdwr(session, stream);
        }
      }
    } else {
      /* half closed (remote): from the spec:

         If an endpoint receives additional frames for a stream that is
         in this state it MUST respond with a stream error (Section
         5.4.2) of type STREAM_CLOSED.
      */
      error_code = NGHTTP2_STREAM_CLOSED;
    }
  } else {
    error_code = NGHTTP2_PROTOCOL_ERROR;
  }
  if(error_code != 0) {
    r = nghttp2_session_add_rst_stream(session, stream_id, error_code);
  }
  return r;
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

static int32_t adjust_recv_window_size(int32_t recv_window_size, int32_t delta)
{
  /* If NGHTTP2_OPT_NO_AUTO_WINDOW_UPDATE is set and the application
     does not send WINDOW_UPDATE and the remote endpoint keeps
     sending data, stream->recv_window_size will eventually
     overflow. */
  if(recv_window_size > INT32_MAX - delta) {
    recv_window_size = INT32_MAX;
  } else {
    recv_window_size += delta;
  }
  return recv_window_size;
}

/*
 * Accumulates received bytes |delta_size| and decides whether to send
 * WINDOW_UPDATE. If NGHTTP2_OPT_NO_AUTO_WINDOW_UPDATE is set,
 * WINDOW_UPDATE will not be sent.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
static int nghttp2_session_update_recv_window_size(nghttp2_session *session,
                                                   nghttp2_stream *stream,
                                                   int32_t delta_size)
{
  if(stream && stream->local_flow_control) {
    stream->recv_window_size = adjust_recv_window_size
      (stream->recv_window_size, delta_size);
    if(!(session->opt_flags & NGHTTP2_OPTMASK_NO_AUTO_WINDOW_UPDATE)) {
      /* This is just a heuristics. */
      /* We have to use local_settings here because it is the constraint
         the remote endpoint should honor. */
      if((size_t)stream->recv_window_size*2 >=
         session->local_settings[NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE]) {
        int r;
        r = nghttp2_session_add_window_update(session,
                                              NGHTTP2_FLAG_NONE,
                                              stream->stream_id,
                                              stream->recv_window_size);
        if(r == 0) {
          stream->recv_window_size = 0;
        } else {
          return r;
        }
      }
    }
  }
  if(session->local_flow_control) {
    session->recv_window_size = adjust_recv_window_size
      (session->recv_window_size, delta_size);
    if(!(session->opt_flags & NGHTTP2_OPTMASK_NO_AUTO_WINDOW_UPDATE)) {
      /* Same heuristics above */
      if((size_t)session->recv_window_size*2 >=
         NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE) {
        int r;
        /* Use stream ID 0 to update connection-level flow control
           window */
        r = nghttp2_session_add_window_update(session,
                                              NGHTTP2_FLAG_NONE,
                                              0,
                                              session->recv_window_size);
        if(r == 0) {
          session->recv_window_size = 0;
        } else {
          return r;
        }
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
      } else if(stream->state != NGHTTP2_STREAM_CLOSING) {
        /* It is OK if this is remote peer initiated stream and we did
           not receive FIN unless stream is in NGHTTP2_STREAM_CLOSING
           state. This is a race condition. */
        return 1;
      }
    }
  }
  return 0;
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
          nghttp2_get_uint16(&session->iframe.headbuf[0]);
        if(!nghttp2_frame_is_data_frame(session->iframe.headbuf)) {
          /* control frame */
          ssize_t buflen;
          buflen = nghttp2_inbound_frame_payload_nv_offset(&session->iframe);
          if(buflen == -1) {
            /* Check if payloadlen is small enough for buffering */
            if(session->iframe.payloadlen > session->max_recv_ctrl_frame_buf) {
              session->iframe.error_code = NGHTTP2_ERR_FRAME_TOO_LARGE;
              session->iframe.state = NGHTTP2_RECV_PAYLOAD_IGN;
              buflen = 0;
            } else {
              buflen = session->iframe.payloadlen;
            }
          } else if(buflen < (ssize_t)session->iframe.payloadlen) {
            if(session->iframe.payloadlen > session->max_recv_ctrl_frame_buf) {
              session->iframe.error_code = NGHTTP2_ERR_FRAME_TOO_LARGE;
            }
            /* We are going to receive payload even if the receiving
               frame is too large to synchronize zlib context. For
               name/value header block, we will just burn zlib cycle
               and discard outputs. */
            session->iframe.state = NGHTTP2_RECV_PAYLOAD_PRE_NV;
          }
          /* buflen >= session->iframe.payloadlen means frame is
             malformed. In this case, we just buffer these bytes and
             handle error later. */
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
       session->iframe.state == NGHTTP2_RECV_PAYLOAD_PRE_NV ||
       session->iframe.state == NGHTTP2_RECV_PAYLOAD_NV ||
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
      if(session->iframe.state == NGHTTP2_RECV_PAYLOAD_PRE_NV) {
        size_t pnvlen, rpnvlen, readpnvlen;
        pnvlen = nghttp2_inbound_frame_payload_nv_offset(&session->iframe);
        rpnvlen = pnvlen - session->iframe.off;
        readpnvlen = nghttp2_min(rpnvlen, readlen);

        memcpy(session->iframe.buf+session->iframe.off, inmark, readpnvlen);
        readlen -= readpnvlen;
        session->iframe.off += readpnvlen;
        inmark += readpnvlen;

        if(session->iframe.off == pnvlen) {
          session->iframe.state = NGHTTP2_RECV_PAYLOAD_NV;
        }
      }
      if(session->iframe.state == NGHTTP2_RECV_PAYLOAD_NV) {
        /* For frame with name/value header block, the compressed
           portion of the block is incrementally decompressed. The
           result is stored in inflatebuf. */
        if(session->iframe.error_code == 0 ||
           session->iframe.error_code == NGHTTP2_ERR_FRAME_TOO_LARGE) {
          ssize_t decomplen;
          if(session->iframe.error_code == NGHTTP2_ERR_FRAME_TOO_LARGE) {
            nghttp2_buffer_reset(&session->iframe.inflatebuf);
          }
          decomplen = nghttp2_zlib_inflate_hd(&session->hd_inflater,
                                              &session->iframe.inflatebuf,
                                              inmark, readlen);
          if(decomplen < 0) {
            /* We are going to overwrite error_code here if it is
               already set. But it is fine because the only possible
               nonzero error code here is NGHTTP2_ERR_FRAME_TOO_LARGE
               and zlib/fatal error can override it. */
            session->iframe.error_code = decomplen;
          } else if(nghttp2_buffer_length(&session->iframe.inflatebuf)
                    > session->max_recv_ctrl_frame_buf) {
            /* If total length in inflatebuf exceeds certain limit,
               set TOO_LARGE_FRAME to error_code and issue RST_STREAM
               later. */
            session->iframe.error_code = NGHTTP2_ERR_FRAME_TOO_LARGE;
          }
        }
      } else if(!nghttp2_frame_is_data_frame(session->iframe.headbuf)) {
        if(session->iframe.state != NGHTTP2_RECV_PAYLOAD_IGN) {
          memcpy(session->iframe.buf+session->iframe.off, inmark, readlen);
        }
      } else {
        /* For data frame, We don't buffer data. Instead, just pass
           received data to callback function. */
        data_stream_id = nghttp2_get_uint32(&session->iframe.headbuf[4]) &
          NGHTTP2_STREAM_ID_MASK;
        data_flags = session->iframe.headbuf[3];
        if(session->iframe.state != NGHTTP2_RECV_PAYLOAD_IGN) {
          if(session->callbacks.on_data_chunk_recv_callback) {
            session->callbacks.on_data_chunk_recv_callback(session,
                                                           data_flags,
                                                           data_stream_id,
                                                           inmark,
                                                           readlen,
                                                           session->user_data);
          }
        }
      }
      session->iframe.off += readlen;
      inmark += readlen;

      if(session->iframe.state != NGHTTP2_RECV_PAYLOAD_IGN &&
         nghttp2_frame_is_data_frame(session->iframe.headbuf) &&
         readlen > 0 &&
         (session->iframe.payloadlen != session->iframe.off ||
          (data_flags & NGHTTP2_FLAG_END_STREAM) == 0)) {
        nghttp2_stream *stream;
        stream = nghttp2_session_get_stream(session, data_stream_id);
        if(session->local_flow_control || stream->local_flow_control) {
          r = nghttp2_session_update_recv_window_size(session,
                                                      stream,
                                                      readlen);
          if(r < 0) {
            /* FATAL */
            assert(r < NGHTTP2_ERR_FATAL);
            return r;
          }
        }
      }
      if(session->iframe.payloadlen == session->iframe.off) {
        if(!nghttp2_frame_is_data_frame(session->iframe.headbuf)) {
          r = nghttp2_session_process_ctrl_frame(session);
        } else {
          r = nghttp2_session_process_data_frame(session);
        }
        if(r < 0) {
          /* FATAL */
          assert(r < NGHTTP2_ERR_FATAL);
          return r;
        }
        nghttp2_inbound_frame_reset(&session->iframe);
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
   * there is pending ones. If pending frame is SYN_STREAM and
   * concurrent stream limit is reached, we don't want to write
   * SYN_STREAM.  After GOAWAY is sent or received, we want to write
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

int nghttp2_session_set_option(nghttp2_session *session,
                               int optname, void *optval, size_t optlen)
{
  switch(optname) {
  case NGHTTP2_OPT_NO_AUTO_WINDOW_UPDATE:
    if(optlen == sizeof(int)) {
      int intval = *(int*)optval;
      if(intval) {
        session->opt_flags |= NGHTTP2_OPTMASK_NO_AUTO_WINDOW_UPDATE;
      } else {
        session->opt_flags &= ~NGHTTP2_OPTMASK_NO_AUTO_WINDOW_UPDATE;
      }
    } else {
      return NGHTTP2_ERR_INVALID_ARGUMENT;
    }
    break;
  case NGHTTP2_OPT_MAX_RECV_CTRL_FRAME_BUFFER:
    if(optlen == sizeof(uint32_t)) {
      uint32_t intval = *(uint32_t*)optval;
      if((1 << 13) <= intval && intval < (1 << 24)) {
        session->max_recv_ctrl_frame_buf = intval;
      } else {
        return NGHTTP2_ERR_INVALID_ARGUMENT;
      }
    } else {
      return NGHTTP2_ERR_INVALID_ARGUMENT;
    }
    break;
  default:
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  return 0;
}
