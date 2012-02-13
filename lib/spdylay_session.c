/*
 * Spdylay - SPDY Library
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
#include "spdylay_session.h"

#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>

#include "spdylay_helper.h"

/*
 * Returns non-zero if the number of opened streams is larger than or
 * equal to SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS value.
 */
static int spdylay_session_get_max_concurrent_streams_reached
(spdylay_session *session)
{
  return session->settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS]
    <= spdylay_map_size(&session->streams);
}

int spdylay_session_is_my_stream_id(spdylay_session *session,
                                    int32_t stream_id)
{
  int r;
  if(stream_id == 0) {
    return 0;
  }
  r = stream_id % 2;
  return (session->server && r == 0) || (!session->server && r == 1);
}

spdylay_stream* spdylay_session_get_stream(spdylay_session *session,
                                           int32_t stream_id)
{
  return (spdylay_stream*)spdylay_map_find(&session->streams, stream_id);
}

static int spdylay_outbound_item_compar(const void *lhsx, const void *rhsx)
{
  const spdylay_outbound_item *lhs, *rhs;
  lhs = (const spdylay_outbound_item*)lhsx;
  rhs = (const spdylay_outbound_item*)rhsx;
  if(lhs->pri == rhs->pri) {
    return (lhs->seq < rhs->seq) ? -1 : ((lhs->seq > rhs->seq) ? 1 : 0);
  } else {
    return lhs->pri-rhs->pri;
  }
}

static int spdylay_session_new(spdylay_session **session_ptr,
                               const spdylay_session_callbacks *callbacks,
                               void *user_data)
{
  int r;
  *session_ptr = malloc(sizeof(spdylay_session));
  if(*session_ptr == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  memset(*session_ptr, 0, sizeof(spdylay_session));

  /* next_stream_id, last_recv_stream_id and next_unique_id are
     initialized in either spdylay_session_client_new or
     spdylay_session_server_new */

  (*session_ptr)->last_ping_unique_id = 0;

  (*session_ptr)->next_seq = 0;

  (*session_ptr)->goaway_flags = SPDYLAY_GOAWAY_NONE;
  (*session_ptr)->last_good_stream_id = 0;

  r = spdylay_zlib_deflate_hd_init(&(*session_ptr)->hd_deflater);
  if(r != 0) {
    free(*session_ptr);
    return r;
  }
  r = spdylay_zlib_inflate_hd_init(&(*session_ptr)->hd_inflater);
  if(r != 0) {
    spdylay_zlib_deflate_free(&(*session_ptr)->hd_deflater);
    free(*session_ptr);
    return r;
  }
  r = spdylay_map_init(&(*session_ptr)->streams);
  if(r != 0) {
    spdylay_zlib_inflate_free(&(*session_ptr)->hd_inflater);
    spdylay_zlib_deflate_free(&(*session_ptr)->hd_deflater);
    free(*session_ptr);
    return r;
  }
  r = spdylay_pq_init(&(*session_ptr)->ob_pq, spdylay_outbound_item_compar);
  if(r != 0) {
    spdylay_map_free(&(*session_ptr)->streams);
    spdylay_zlib_inflate_free(&(*session_ptr)->hd_inflater);
    spdylay_zlib_deflate_free(&(*session_ptr)->hd_deflater);
    free(*session_ptr);
    return r;
  }
  r = spdylay_pq_init(&(*session_ptr)->ob_ss_pq, spdylay_outbound_item_compar);
  if(r != 0) {
    spdylay_pq_free(&(*session_ptr)->ob_pq);
    spdylay_map_free(&(*session_ptr)->streams);
    spdylay_zlib_inflate_free(&(*session_ptr)->hd_inflater);
    spdylay_zlib_deflate_free(&(*session_ptr)->hd_deflater);
    free(*session_ptr);
    return r;
  }

  memset((*session_ptr)->settings, 0, sizeof((*session_ptr)->settings));
  (*session_ptr)->settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS] =
    SPDYLAY_CONCURRENT_STREAMS_MAX;

  (*session_ptr)->callbacks = *callbacks;
  (*session_ptr)->user_data = user_data;

  (*session_ptr)->ibuf.mark = (*session_ptr)->ibuf.buf;
  (*session_ptr)->ibuf.limit = (*session_ptr)->ibuf.buf;
  
  (*session_ptr)->iframe.state = SPDYLAY_RECV_HEAD;
  return 0;
}

int spdylay_session_client_new(spdylay_session **session_ptr,
                               const spdylay_session_callbacks *callbacks,
                               void *user_data)
{
  int r;
  r = spdylay_session_new(session_ptr, callbacks, user_data);
  if(r == 0) {
    /* IDs for use in client */
    (*session_ptr)->next_stream_id = 1;
    (*session_ptr)->last_recv_stream_id = 0;
    (*session_ptr)->next_unique_id = 1;
  }
  return r;
}

int spdylay_session_server_new(spdylay_session **session_ptr,
                               const spdylay_session_callbacks *callbacks,
                               void *user_data)
{
  int r;
  r = spdylay_session_new(session_ptr, callbacks, user_data);
  if(r == 0) {
    (*session_ptr)->server = 1;
    /* IDs for use in client */
    (*session_ptr)->next_stream_id = 2;
    (*session_ptr)->last_recv_stream_id = 0;
    (*session_ptr)->next_unique_id = 2;
  }
  return r;
}

static void spdylay_free_streams(key_type key, void *val)
{
  spdylay_stream_free((spdylay_stream*)val);
  free(val);
}

void spdylay_outbound_item_free(spdylay_outbound_item *item)
{
  if(item == NULL) {
    return;
  }
  switch(item->frame_type) {
  case SPDYLAY_SYN_STREAM:
    spdylay_frame_syn_stream_free(&item->frame->syn_stream);
    free(((spdylay_syn_stream_aux_data*)item->aux_data)->data_prd);
    break;
  case SPDYLAY_SYN_REPLY:
    spdylay_frame_syn_reply_free(&item->frame->syn_reply);
    break;
  case SPDYLAY_RST_STREAM:
    spdylay_frame_rst_stream_free(&item->frame->rst_stream);
    break;
  case SPDYLAY_SETTINGS:
    spdylay_frame_settings_free(&item->frame->settings);
    break;
  case SPDYLAY_NOOP:
    /* We don't have any public API to add NOOP, so here is
       unreachable. */
    abort();
  case SPDYLAY_PING:
    spdylay_frame_ping_free(&item->frame->ping);
    break;
  case SPDYLAY_GOAWAY:
    spdylay_frame_goaway_free(&item->frame->goaway);
    break;
  case SPDYLAY_HEADERS:
    spdylay_frame_headers_free(&item->frame->headers);
    break;
  case SPDYLAY_DATA:
    spdylay_frame_data_free(&item->frame->data);
    break;
  }
  free(item->frame);
  free(item->aux_data);
}

static void spdylay_session_ob_pq_free(spdylay_pq *pq)
{
  while(!spdylay_pq_empty(pq)) {
    spdylay_outbound_item *item = (spdylay_outbound_item*)spdylay_pq_top(pq);
    spdylay_outbound_item_free(item);
    free(item);
    spdylay_pq_pop(pq);
  }
  spdylay_pq_free(pq);
}

void spdylay_session_del(spdylay_session *session)
{
  if(session == NULL) {
    return;
  }
  spdylay_map_each(&session->streams, spdylay_free_streams);
  spdylay_map_free(&session->streams);
  spdylay_session_ob_pq_free(&session->ob_pq);
  spdylay_session_ob_pq_free(&session->ob_ss_pq);
  spdylay_zlib_deflate_free(&session->hd_deflater);
  spdylay_zlib_inflate_free(&session->hd_inflater);
  free(session->iframe.buf);
  free(session);
}

int spdylay_session_add_frame(spdylay_session *session,
                              spdylay_frame_type frame_type,
                              spdylay_frame *frame,
                              void *aux_data)
{
  int r;
  spdylay_outbound_item *item;
  item = malloc(sizeof(spdylay_outbound_item));
  if(item == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  item->frame_type = frame_type;
  item->frame = frame;
  item->aux_data = aux_data;
  item->seq = session->next_seq++;
  /* Set priority lowest at the moment. */
  item->pri = 3;
  switch(frame_type) {
  case SPDYLAY_SYN_STREAM:
    item->pri = frame->syn_stream.pri;
    break;
  case SPDYLAY_SYN_REPLY: {
    spdylay_stream *stream = spdylay_session_get_stream
      (session, frame->syn_reply.stream_id);
    if(stream) {
      item->pri = stream->pri;
    }
    break;
  }
  case SPDYLAY_RST_STREAM: {
    spdylay_stream *stream = spdylay_session_get_stream
      (session, frame->rst_stream.stream_id);
    if(stream) {
      stream->state = SPDYLAY_STREAM_CLOSING;
      item->pri = stream->pri;
    }
    break;
  }
  case SPDYLAY_SETTINGS:
    /* Should SPDYLAY_SETTINGS have higher priority? */
    break;
  case SPDYLAY_NOOP:
    /* We don't have any public API to add NOOP, so here is
       unreachable. */
    abort();
  case SPDYLAY_PING:
    /* Ping has "height" priority. Give it -1. */
    item->pri = -1;
    break;
  case SPDYLAY_GOAWAY:
    /* Should GOAWAY have higher priority? */
    break;
  case SPDYLAY_HEADERS:
    /* Currently we don't have any API to send HEADERS frame, so this
       is unreachable. */
    abort();
  case SPDYLAY_DATA: {
    spdylay_stream *stream = spdylay_session_get_stream
      (session, frame->data.stream_id);
    if(stream) {
      item->pri = stream->pri;
    }
    break;
  }
  };
  if(frame_type == SPDYLAY_SYN_STREAM) {
    r = spdylay_pq_push(&session->ob_ss_pq, item);
  } else {
    r = spdylay_pq_push(&session->ob_pq, item);
  }
  if(r != 0) {
    free(item);
    return r;
  }
  return 0;
}

int spdylay_session_add_rst_stream(spdylay_session *session,
                                   int32_t stream_id, uint32_t status_code)
{
  int r;
  spdylay_frame *frame;
  frame = malloc(sizeof(spdylay_frame));
  if(frame == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  spdylay_frame_rst_stream_init(&frame->rst_stream, stream_id, status_code);
  r = spdylay_session_add_frame(session, SPDYLAY_RST_STREAM, frame, NULL);
  if(r != 0) {
    spdylay_frame_rst_stream_free(&frame->rst_stream);
    free(frame);
    return r;
  }
  return 0;
}

spdylay_stream* spdylay_session_open_stream(spdylay_session *session,
                                            int32_t stream_id,
                                            uint8_t flags, uint8_t pri,
                                            spdylay_stream_state initial_state,
                                            void *stream_user_data)
{
  int r;
  spdylay_stream *stream = malloc(sizeof(spdylay_stream));
  if(stream == NULL) {
    return NULL;
  }
  spdylay_stream_init(stream, stream_id, flags, pri, initial_state,
                      stream_user_data);
  r = spdylay_map_insert(&session->streams, stream_id, stream);
  if(r != 0) {
    free(stream);
    stream = NULL;
  }
  return stream;
}

int spdylay_session_close_stream(spdylay_session *session, int32_t stream_id,
                                 spdylay_status_code status_code)
{
  spdylay_stream *stream = spdylay_session_get_stream(session, stream_id);
  if(stream) {
    if(stream->state != SPDYLAY_STREAM_INITIAL &&
       session->callbacks.on_stream_close_callback) {
      session->callbacks.on_stream_close_callback(session, stream_id,
                                                  status_code,
                                                  session->user_data);
    }
    spdylay_map_erase(&session->streams, stream_id);
    spdylay_stream_free(stream);
    free(stream);
    return 0;
  } else {
    return SPDYLAY_ERR_INVALID_ARGUMENT;
  }
}

int spdylay_session_close_stream_if_shut_rdwr(spdylay_session *session,
                                              spdylay_stream *stream)
{
  if((stream->shut_flags & SPDYLAY_SHUT_RDWR) == SPDYLAY_SHUT_RDWR) {
    return spdylay_session_close_stream(session, stream->stream_id,
                                        SPDYLAY_OK);
  } else {
    return 0;
  }
}

void spdylay_session_close_pushed_streams(spdylay_session *session,
                                          int32_t stream_id,
                                          spdylay_status_code status_code)
{
  spdylay_stream *stream;
  stream = spdylay_session_get_stream(session, stream_id);
  if(stream) {
    int i;
    for(i = 0; i < stream->pushed_streams_length; ++i) {
      spdylay_session_close_stream(session, stream->pushed_streams[i],
                                   status_code);
    }
  }
}

/*
 * Returns non-zero value if local peer can send SYN_REPLY with stream
 * ID |stream_id| at the moment, or 0.
 */
static int spdylay_session_is_reply_allowed(spdylay_session *session,
                                            int32_t stream_id)
{
  spdylay_stream *stream = spdylay_session_get_stream(session, stream_id);
  if(stream == NULL) {
    return 0;
  }
  if(spdylay_session_is_my_stream_id(session, stream_id)) {
    return 0;
  } else {
    return stream->state == SPDYLAY_STREAM_OPENING &&
      (stream->shut_flags & SPDYLAY_SHUT_WR) == 0;
  }
}

static int spdylay_session_is_data_allowed(spdylay_session *session,
                                           int32_t stream_id)
{
  spdylay_stream *stream = spdylay_session_get_stream(session, stream_id);
  if(stream == NULL) {
    return 0;
  }
  if(spdylay_session_is_my_stream_id(session, stream_id)) {
    return (stream->shut_flags & SPDYLAY_SHUT_WR) == 0;
  } else {
    return stream->state == SPDYLAY_STREAM_OPENED &&
      (stream->shut_flags & SPDYLAY_SHUT_WR) == 0;
  }
}

ssize_t spdylay_session_prep_frame(spdylay_session *session,
                                   spdylay_outbound_item *item,
                                   uint8_t **framebuf_ptr)
{
  /* TODO Get or validate stream ID here */
  /* TODO Validate assoc_stream_id here */
  uint8_t *framebuf;
  ssize_t framebuflen;
  switch(item->frame_type) {
  case SPDYLAY_SYN_STREAM: {
    uint32_t stream_id;
    spdylay_syn_stream_aux_data *aux_data;
    if(session->goaway_flags) {
      /* When GOAWAY is sent or received, peer must not send new
         SYN_STREAM. */
      return SPDYLAY_ERR_INVALID_FRAME;
    }
    stream_id = session->next_stream_id;
    item->frame->syn_stream.stream_id = stream_id;
    session->next_stream_id += 2;
    framebuflen = spdylay_frame_pack_syn_stream(&framebuf,
                                                &item->frame->syn_stream,
                                                &session->hd_deflater);
    if(framebuflen < 0) {
      return framebuflen;
    }
    aux_data = (spdylay_syn_stream_aux_data*)item->aux_data;
    if(spdylay_session_open_stream(session, stream_id,
                                   item->frame->syn_stream.hd.flags,
                                   item->frame->syn_stream.pri,
                                   SPDYLAY_STREAM_INITIAL,
                                   aux_data->stream_user_data) == NULL) {
      free(framebuf);
      return SPDYLAY_ERR_NOMEM;
    }
    break;
  }
  case SPDYLAY_SYN_REPLY: {
    if(!spdylay_session_is_reply_allowed(session,
                                         item->frame->syn_reply.stream_id)) {
      return SPDYLAY_ERR_INVALID_FRAME;
    }
    framebuflen = spdylay_frame_pack_syn_reply(&framebuf,
                                               &item->frame->syn_reply,
                                               &session->hd_deflater);
    if(framebuflen < 0) {
      return framebuflen;
    }
    break;
  }
  case SPDYLAY_RST_STREAM:
    framebuflen = spdylay_frame_pack_rst_stream(&framebuf,
                                                &item->frame->rst_stream);
    if(framebuflen < 0) {
      return framebuflen;
    }
    break;
  case SPDYLAY_SETTINGS:
    framebuflen = spdylay_frame_pack_settings(&framebuf,
                                              &item->frame->settings);
    if(framebuflen < 0) {
      return framebuflen;
    }
    break;
  case SPDYLAY_NOOP:
    /* We don't have any public API to add NOOP, so here is
       unreachable. */
    abort();
  case SPDYLAY_PING:
    framebuflen = spdylay_frame_pack_ping(&framebuf, &item->frame->ping);
    if(framebuflen < 0) {
      return framebuflen;
    }
    break;
  case SPDYLAY_HEADERS:
    /* Currently we don't have any API to send HEADERS frame, so this
       is unreachable. */
    abort();
  case SPDYLAY_GOAWAY:
    if(session->goaway_flags & SPDYLAY_GOAWAY_SEND) {
      /* TODO The spec does not mandate that both endpoints have to
         exchange GOAWAY. This implementation allows receiver of first
         GOAWAY can sent its own GOAWAY to tell the remote peer that
         last-good-stream-id. */
      return SPDYLAY_ERR_INVALID_FRAME;
    }
    framebuflen = spdylay_frame_pack_goaway(&framebuf, &item->frame->goaway);
    if(framebuflen < 0) {
      return framebuflen;
    }
    break;
  case SPDYLAY_DATA: {
    if(!spdylay_session_is_data_allowed(session, item->frame->data.stream_id)) {
      return SPDYLAY_ERR_INVALID_FRAME;
    }
    framebuflen = spdylay_session_pack_data(session, &framebuf,
                                            &item->frame->data);
    if(framebuflen < 0) {
      return framebuflen;
    }
    break;
  }
  default:
    framebuflen = SPDYLAY_ERR_INVALID_ARGUMENT;
  }
  *framebuf_ptr = framebuf;
  return framebuflen;
}

static void spdylay_active_outbound_item_reset
(spdylay_active_outbound_item *aob)
{
  spdylay_outbound_item_free(aob->item);
  free(aob->item);
  free(aob->framebuf);
  memset(aob, 0, sizeof(spdylay_active_outbound_item));
}

spdylay_outbound_item* spdylay_session_get_ob_pq_top
(spdylay_session *session)
{
  return (spdylay_outbound_item*)spdylay_pq_top(&session->ob_pq);
}

spdylay_outbound_item* spdylay_session_get_next_ob_item
(spdylay_session *session)
{
  if(spdylay_pq_empty(&session->ob_pq)) {
    if(spdylay_pq_empty(&session->ob_ss_pq)) {
      return NULL;
    } else {
      /* Return item only when concurrent connection limit is not
         reached */
      if(spdylay_session_get_max_concurrent_streams_reached(session)) {
        return NULL;
      } else {
        return spdylay_pq_top(&session->ob_ss_pq);
      }
    }
  } else {
    if(spdylay_pq_empty(&session->ob_ss_pq)) {
      return spdylay_pq_top(&session->ob_pq);
    } else {
      spdylay_outbound_item *item, *syn_stream_item;
      item = spdylay_pq_top(&session->ob_pq);
      syn_stream_item = spdylay_pq_top(&session->ob_ss_pq);
      if(spdylay_session_get_max_concurrent_streams_reached(session) ||
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

spdylay_outbound_item* spdylay_session_pop_next_ob_item
(spdylay_session *session)
{
  if(spdylay_pq_empty(&session->ob_pq)) {
    if(spdylay_pq_empty(&session->ob_ss_pq)) {
      return NULL;
    } else {
      /* Pop item only when concurrent connection limit is not
         reached */
      if(spdylay_session_get_max_concurrent_streams_reached(session)) {
        return NULL;
      } else {
        spdylay_outbound_item *item;
        item = spdylay_pq_top(&session->ob_ss_pq);
        spdylay_pq_pop(&session->ob_ss_pq);
        return item;
      }
    }
  } else {
    if(spdylay_pq_empty(&session->ob_ss_pq)) {
      spdylay_outbound_item *item;
      item = spdylay_pq_top(&session->ob_pq);
      spdylay_pq_pop(&session->ob_pq);
      return item;
    } else {
      spdylay_outbound_item *item, *syn_stream_item;
      item = spdylay_pq_top(&session->ob_pq);
      syn_stream_item = spdylay_pq_top(&session->ob_ss_pq);
      if(spdylay_session_get_max_concurrent_streams_reached(session) ||
         item->pri < syn_stream_item->pri ||
         (item->pri == syn_stream_item->pri &&
          item->seq < syn_stream_item->seq)) {
        spdylay_pq_pop(&session->ob_pq);
        return item;
      } else {
        spdylay_pq_pop(&session->ob_ss_pq);
        return syn_stream_item;
      }
    }
  }
}

static int spdylay_session_after_frame_sent(spdylay_session *session)
{
  /* TODO handle FIN flag. */
  spdylay_outbound_item *item = session->aob.item;
  spdylay_frame *frame = session->aob.item->frame;
  spdylay_frame_type type = session->aob.item->frame_type;
  if(type == SPDYLAY_DATA) {
    if(session->callbacks.on_data_send_callback) {
      session->callbacks.on_data_send_callback
        (session, frame->data.flags, frame->data.stream_id,
         session->aob.framebuflen-SPDYLAY_HEAD_LEN, session->user_data);
    }
  } else {
    if(session->callbacks.on_ctrl_send_callback) {
      session->callbacks.on_ctrl_send_callback
        (session, type, frame, session->user_data);
    }
  }
  switch(type) {
  case SPDYLAY_SYN_STREAM: {
    spdylay_stream *stream =
      spdylay_session_get_stream(session, frame->syn_stream.stream_id);
    if(stream) {
      spdylay_syn_stream_aux_data *aux_data;
      stream->state = SPDYLAY_STREAM_OPENING;
      if(frame->syn_stream.hd.flags & SPDYLAY_FLAG_FIN) {
        spdylay_stream_shutdown(stream, SPDYLAY_SHUT_WR);
      }
      if(frame->syn_stream.hd.flags & SPDYLAY_FLAG_UNIDIRECTIONAL) {
        spdylay_stream_shutdown(stream, SPDYLAY_SHUT_RD);
      }
      spdylay_session_close_stream_if_shut_rdwr(session, stream);
      /* We assume aux_data is a pointer to spdylay_syn_stream_aux_data */
      aux_data = (spdylay_syn_stream_aux_data*)item->aux_data;
      if(aux_data->data_prd) {
        int r;
        /* spdylay_submit_data() makes a copy of aux_data->data_prd */
        r = spdylay_submit_data(session, frame->syn_stream.stream_id,
                                aux_data->data_prd);
        if(r != 0) {
          /* TODO If r is not FATAL, we should send RST_STREAM. */
          return r;
        }
      }
    }
    break;
  }
  case SPDYLAY_SYN_REPLY: {
    spdylay_stream *stream =
      spdylay_session_get_stream(session, frame->syn_reply.stream_id);
    if(stream) {
      stream->state = SPDYLAY_STREAM_OPENED;
      if(frame->syn_reply.hd.flags & SPDYLAY_FLAG_FIN) {
        spdylay_stream_shutdown(stream, SPDYLAY_SHUT_WR);
      }
      spdylay_session_close_stream_if_shut_rdwr(session, stream);
      if(item->aux_data) {
        /* We assume aux_data is a pointer to spdylay_data_provider */
        spdylay_data_provider *data_prd =
          (spdylay_data_provider*)item->aux_data;
        int r;
        r = spdylay_submit_data(session, frame->syn_reply.stream_id, data_prd);
        if(r != 0) {
          /* TODO If r is not FATAL, we should send RST_STREAM. */
          return r;
        }
      }
    }
    break;
  }
  case SPDYLAY_RST_STREAM:
    if(!session->server &&
       spdylay_session_is_my_stream_id(session, frame->rst_stream.stream_id) &&
       frame->rst_stream.status_code == SPDYLAY_CANCEL) {
      spdylay_session_close_pushed_streams(session, frame->rst_stream.stream_id,
                                           frame->rst_stream.status_code);
    }
    spdylay_session_close_stream(session, frame->rst_stream.stream_id,
                                 frame->rst_stream.status_code);
    break;
  case SPDYLAY_SETTINGS:
    /* nothing to do */
    break;
  case SPDYLAY_NOOP:
    /* We don't have any public API to add NOOP, so here is
       unreachable. */
    abort();
  case SPDYLAY_PING:
    /* We record the time now and show application code RTT when
       reply PING is received. */
    session->last_ping_unique_id = frame->ping.unique_id;
    break;
  case SPDYLAY_GOAWAY:
    session->goaway_flags |= SPDYLAY_GOAWAY_SEND;
    break;
  case SPDYLAY_HEADERS:
    /* Currently we don't have any API to send HEADERS frame, so this
       is unreachable. */
    abort();
  case SPDYLAY_DATA:
    if(frame->data.flags & SPDYLAY_FLAG_FIN) {
      spdylay_stream *stream =
        spdylay_session_get_stream(session, frame->data.stream_id);
      if(stream) {
        spdylay_stream_shutdown(stream, SPDYLAY_SHUT_WR);
        spdylay_session_close_stream_if_shut_rdwr(session, stream);
      }
    }
    break;
  };
  if(type == SPDYLAY_DATA) {
    int r;
    /* If session is canceled by RST_STREAM, we won't send further data. */
    if((frame->data.flags & SPDYLAY_FLAG_FIN) ||
       spdylay_session_get_stream(session, frame->data.stream_id) == NULL) {
      spdylay_active_outbound_item_reset(&session->aob);
    } else {
      spdylay_outbound_item* item = spdylay_session_get_next_ob_item(session);
      if(item == NULL || session->aob.item->pri <= item->pri) {
        /* If priority of this stream is higher or equal to other stream
           waiting at the top of the queue, we continue to send this
           data. */
        /* We assume that buffer has at least
           SPDYLAY_DATA_FRAME_LENGTH. */
        r = spdylay_session_pack_data_overwrite(session,
                                                session->aob.framebuf,
                                                SPDYLAY_DATA_FRAME_LENGTH,
                                                &frame->data);
        if(r < 0) {
          spdylay_active_outbound_item_reset(&session->aob);
          return r;
        }
        session->aob.framebuflen = r;
        session->aob.framebufoff = 0;
      } else {
        r = spdylay_pq_push(&session->ob_pq, session->aob.item);
        if(r == 0) {
          session->aob.item = NULL;
          spdylay_active_outbound_item_reset(&session->aob);
        } else {
          spdylay_active_outbound_item_reset(&session->aob);
          return r;
        }
      }
    }
  } else {
    spdylay_active_outbound_item_reset(&session->aob);
  }
  return 0;
}

int spdylay_session_send(spdylay_session *session)
{
  int r;
  while(1) {
    const uint8_t *data;
    size_t datalen;
    ssize_t sentlen;
    if(session->aob.item == NULL) {
      spdylay_outbound_item *item;
      uint8_t *framebuf;
      ssize_t framebuflen;
      item = spdylay_session_pop_next_ob_item(session);
      if(item == NULL) {
        break;
      }
      framebuflen = spdylay_session_prep_frame(session, item, &framebuf);
      if(framebuflen < 0) {
        /* TODO Call error callback? */
        spdylay_outbound_item_free(item);
        free(item);
        if(framebuflen <= SPDYLAY_ERR_FATAL) {
          return framebuflen;
        } else {
          continue;;
        }
      }
      session->aob.item = item;
      session->aob.framebuf = framebuf;
      session->aob.framebuflen = framebuflen;
      /* Call before_send callback */
      if(item->frame_type != SPDYLAY_DATA &&
         session->callbacks.before_ctrl_send_callback) {
        session->callbacks.before_ctrl_send_callback
          (session, item->frame_type, item->frame, session->user_data);
      }
    }
    data = session->aob.framebuf + session->aob.framebufoff;
    datalen = session->aob.framebuflen - session->aob.framebufoff;
    sentlen = session->callbacks.send_callback(session, data, datalen, 0,
                                               session->user_data);
    if(sentlen < 0) {
      if(sentlen == SPDYLAY_ERR_WOULDBLOCK) {
        return 0;
      } else {
        return sentlen;
      }
    } else {
      session->aob.framebufoff += sentlen;
      if(session->aob.framebufoff == session->aob.framebuflen) {
        /* Frame has completely sent */
        r = spdylay_session_after_frame_sent(session);
        if(r < 0) {
          return r;
        }
      } else {
        /* partial write */
        break;
      }
    }
  }
  return 0;
}

static void spdylay_inbound_buffer_shift(spdylay_inbound_buffer *ibuf)
{
  ptrdiff_t len = ibuf->limit-ibuf->mark;
  memmove(ibuf->buf, ibuf->mark, len);
  ibuf->limit = ibuf->buf+len;
  ibuf->mark = ibuf->buf;
}

static ssize_t spdylay_recv(spdylay_session *session)
{
  ssize_t r;
  size_t recv_max;
  if(session->ibuf.mark != session->ibuf.buf) {
    spdylay_inbound_buffer_shift(&session->ibuf);
  }
  recv_max = session->ibuf.buf+sizeof(session->ibuf.buf)-session->ibuf.limit;
  r = session->callbacks.recv_callback
    (session, session->ibuf.limit, recv_max, 0, session->user_data);
  if(r > 0) {
    if(r > recv_max) {
      return SPDYLAY_ERR_CALLBACK_FAILURE;
    } else {
      session->ibuf.limit += r;
    }
  } else if(r < 0) {
    if(r != SPDYLAY_ERR_WOULDBLOCK) {
      r = SPDYLAY_ERR_CALLBACK_FAILURE;
    }
  }
  return r;
}

static size_t spdylay_inbound_buffer_avail(spdylay_inbound_buffer *ibuf)
{
  return ibuf->limit-ibuf->mark;
}

static void spdylay_inbound_frame_reset(spdylay_inbound_frame *iframe)
{
  iframe->state = SPDYLAY_RECV_HEAD;
  free(iframe->buf);
  iframe->buf = NULL;
  iframe->len = iframe->off = 0;
  iframe->ign = 0;
}

static void spdylay_session_call_on_request_recv
(spdylay_session *session, int32_t stream_id)
{
  if(session->callbacks.on_request_recv_callback) {
    session->callbacks.on_request_recv_callback(session, stream_id,
                                                session->user_data);
  }
}

static void spdylay_session_call_on_ctrl_frame_received
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame)
{
  if(session->callbacks.on_ctrl_recv_callback) {
    session->callbacks.on_ctrl_recv_callback
      (session, type, frame, session->user_data);
  }
}

/*
 * Checks whether received stream_id is valid.
 * This function returns 1 if it succeeds, or 0.
 */
static int spdylay_session_is_new_peer_stream_id(spdylay_session *session,
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
 * Validates SYN_STREAM frame |frame|.  This function returns 0 if it
 * succeeds, or non-zero spdylay_status_code.
 */
static int spdylay_session_validate_syn_stream(spdylay_session *session,
                                               spdylay_syn_stream *frame)
{
  if(!spdylay_session_is_new_peer_stream_id(session, frame->stream_id)) {
    return SPDYLAY_PROTOCOL_ERROR;
  }
  if(frame->hd.version != SPDYLAY_PROTO_VERSION) {
    return SPDYLAY_UNSUPPORTED_VERSION;
  }
  if(session->server) {
    if(frame->assoc_stream_id != 0) {
      return SPDYLAY_PROTOCOL_ERROR;
    }
  } else {
    if(frame->assoc_stream_id == 0) {
      /* spdy/2 spec: When a client receives a SYN_STREAM from the
         server with an Associated-To-Stream-ID of 0, it must reply with
         a RST_STREAM with error code INVALID_STREAM. */
      return SPDYLAY_INVALID_STREAM;
    }
    if((frame->hd.flags & SPDYLAY_FLAG_UNIDIRECTIONAL) == 0 ||
       frame->assoc_stream_id % 2 == 0 ||
       spdylay_session_get_stream(session, frame->assoc_stream_id) == NULL) {
      /* It seems spdy/2 spec does not say which status code should be
         returned in these cases. */
      return SPDYLAY_PROTOCOL_ERROR;
    }
  }
  if(spdylay_session_get_max_concurrent_streams_reached(session)) {
    /* spdy/2 spec does not clearly say what to do when max concurrent
       streams number is reached. The mod_spdy sends
       SPDYLAY_REFUSED_STREAM and we think it is reasonable. So we
       follow it. */
    return SPDYLAY_REFUSED_STREAM;
  }
  return 0;
}

static int spdylay_session_handle_invalid_stream
(spdylay_session *session,
 int32_t stream_id,
 spdylay_frame_type type,
 spdylay_frame *frame,
 spdylay_status_code status_code)
{
  int r;
  r = spdylay_session_add_rst_stream(session, stream_id, status_code);
  if(r != 0) {
    return r;
  }
  if(session->callbacks.on_invalid_ctrl_recv_callback) {
    session->callbacks.on_invalid_ctrl_recv_callback
      (session, type, frame, session->user_data);
  }
  return 0;
}

int spdylay_session_on_syn_stream_received(spdylay_session *session,
                                           spdylay_frame *frame)
{
  int r;
  if(session->goaway_flags) {
    /* We don't accept SYN_STREAM after GOAWAY is sent or received. */
    return 0;
  }
  r = spdylay_session_validate_syn_stream(session, &frame->syn_stream);
  if(r == 0) {
    uint8_t flags = frame->syn_stream.hd.flags;
    if((flags & SPDYLAY_FLAG_FIN) && (flags & SPDYLAY_FLAG_UNIDIRECTIONAL)) {
      /* If the stream is UNIDIRECTIONAL and FIN bit set, we can close
         stream upon receiving SYN_STREAM. So, the stream needs not to
         be opened. */
      r = 0;
    } else {
      spdylay_stream *stream;
      stream = spdylay_session_open_stream(session, frame->syn_stream.stream_id,
                                           frame->syn_stream.hd.flags,
                                           frame->syn_stream.pri,
                                           SPDYLAY_STREAM_OPENING,
                                           NULL);
      if(stream) {
        if(flags & SPDYLAY_FLAG_FIN) {
          spdylay_stream_shutdown(stream, SPDYLAY_SHUT_RD);
        }
        if(flags & SPDYLAY_FLAG_UNIDIRECTIONAL) {
          spdylay_stream_shutdown(stream, SPDYLAY_SHUT_WR);
        }
        /* We don't call spdylay_session_close_stream_if_shut_rdwr()
           here because either SPDYLAY_FLAG_FIN or
           SPDYLAY_FLAG_UNIDIRECTIONAL is not set here. */
      }
    }
    if(r == 0) {
      session->last_recv_stream_id = frame->syn_stream.stream_id;
      spdylay_session_call_on_ctrl_frame_received(session, SPDYLAY_SYN_STREAM,
                                                  frame);
      if(flags & SPDYLAY_FLAG_FIN) {
        spdylay_session_call_on_request_recv(session,
                                             frame->syn_stream.stream_id);
      }
    }
  } else {
    r = spdylay_session_handle_invalid_stream
      (session, frame->syn_stream.stream_id, SPDYLAY_SYN_STREAM, frame, r);
  }
  return r;
}

/*
 * Returns non-zero iff version == SPDYLAY_PROTOCOL_ERROR.
 */
static int spdylay_session_check_version(uint16_t version)
{
  return version == SPDYLAY_PROTO_VERSION;
}

int spdylay_session_on_syn_reply_received(spdylay_session *session,
                                          spdylay_frame *frame)
{
  int r = 0;
  int valid = 0;
  spdylay_stream *stream;
  if(!spdylay_session_check_version(frame->syn_reply.hd.version)) {
    return 0;
  }
  stream = spdylay_session_get_stream(session, frame->syn_reply.stream_id);
  if(stream && (stream->shut_flags & SPDYLAY_SHUT_RD) == 0) {
    if(spdylay_session_is_my_stream_id(session, frame->syn_reply.stream_id)) {
      if(stream->state == SPDYLAY_STREAM_OPENING) {
        valid = 1;
        stream->state = SPDYLAY_STREAM_OPENED;
        spdylay_session_call_on_ctrl_frame_received(session, SPDYLAY_SYN_REPLY,
                                                    frame);
        if(frame->syn_reply.hd.flags & SPDYLAY_FLAG_FIN) {
          /* This is the last frame of this stream, so disallow
             further receptions. */
          spdylay_stream_shutdown(stream, SPDYLAY_SHUT_RD);
          spdylay_session_close_stream_if_shut_rdwr(session, stream);
        }
      } else if(stream->state == SPDYLAY_STREAM_CLOSING) {
        /* This is race condition. SPDYLAY_STREAM_CLOSING indicates
           that we queued RST_STREAM but it has not been sent. It will
           eventually sent, so we just ignore this frame. */
        valid = 1;
      }
    }
  }
  if(!valid) {
    r = spdylay_session_handle_invalid_stream
      (session, frame->syn_reply.stream_id, SPDYLAY_SYN_REPLY, frame,
       SPDYLAY_PROTOCOL_ERROR);
  }
  return r;
}

int spdylay_session_on_rst_stream_received(spdylay_session *session,
                                           spdylay_frame *frame)
{
  if(!spdylay_session_check_version(frame->rst_stream.hd.version)) {
    return 0;
  }
  if(session->server &&
     !spdylay_session_is_my_stream_id(session, frame->rst_stream.stream_id) &&
     frame->rst_stream.status_code == SPDYLAY_CANCEL) {
    spdylay_session_close_pushed_streams(session, frame->rst_stream.stream_id,
                                         frame->rst_stream.status_code);
  }
  spdylay_session_close_stream(session, frame->rst_stream.stream_id,
                               frame->rst_stream.status_code);
  return 0;
}

int spdylay_session_on_settings_received(spdylay_session *session,
                                         spdylay_frame *frame)
{
  if(!spdylay_session_check_version(frame->settings.hd.version)) {
    return 0;
  }
  /* TODO Check ID/value pairs and persist them if necessary. */
  spdylay_session_call_on_ctrl_frame_received(session, SPDYLAY_SETTINGS, frame);
  return 0;
}

int spdylay_session_on_ping_received(spdylay_session *session,
                                     spdylay_frame *frame)
{
  int r = 0;
  if(!spdylay_session_check_version(frame->ping.hd.version)) {
    return 0;
  }
  if(frame->ping.unique_id != 0) {
    if(session->last_ping_unique_id == frame->ping.unique_id) {
      /* This is ping reply from peer */
      /* Assign 0 to last_ping_unique_id so that we can ignore same
         ID. */
      session->last_ping_unique_id = 0;
      spdylay_session_call_on_ctrl_frame_received(session, SPDYLAY_PING, frame);
    } else if((session->server && frame->ping.unique_id % 2 == 1) ||
              (!session->server && frame->ping.unique_id % 2 == 0)) {
      /* Peer sent ping, so ping it back */
      r = spdylay_session_add_ping(session, frame->ping.unique_id);
      spdylay_session_call_on_ctrl_frame_received(session, SPDYLAY_PING, frame);
    }
  }
  return r;
}

int spdylay_session_on_goaway_received(spdylay_session *session,
                                       spdylay_frame *frame)
{
  if(!spdylay_session_check_version(frame->goaway.hd.version)) {
    return 0;
  }
  session->last_good_stream_id = frame->goaway.last_good_stream_id;
  session->goaway_flags |= SPDYLAY_GOAWAY_RECV;
  spdylay_session_call_on_ctrl_frame_received(session, SPDYLAY_GOAWAY, frame);
  return 0;
}

int spdylay_session_on_headers_received(spdylay_session *session,
                                        spdylay_frame *frame)
{
  int r = 0;
  int valid = 0;
  spdylay_stream *stream;
  if(!spdylay_session_check_version(frame->headers.hd.version)) {
    return 0;
  }
  stream = spdylay_session_get_stream(session, frame->headers.stream_id);
  /* First we check readability from this stream. */
  if(stream && (stream->shut_flags & SPDYLAY_SHUT_RD) == 0) {
    if(spdylay_session_is_my_stream_id(session, frame->headers.stream_id)) {
      if(stream->state == SPDYLAY_STREAM_OPENED) {
        valid = 1;
        spdylay_session_call_on_ctrl_frame_received(session, SPDYLAY_HEADERS,
                                                    frame);
        if(frame->headers.hd.flags & SPDYLAY_FLAG_FIN) {
          spdylay_stream_shutdown(stream, SPDYLAY_SHUT_RD);
          spdylay_session_close_stream_if_shut_rdwr(session, stream);
        }
      } else if(stream->state == SPDYLAY_STREAM_CLOSING) {
        /* This is race condition. SPDYLAY_STREAM_CLOSING indicates
           that we queued RST_STREAM but it has not been sent. It will
           eventually sent, so we just ignore this frame. */
        valid = 1;
      }
    } else {
      /* If this is remote peer initiated stream, it is OK unless it
         have sent FIN frame already. But if stream is in
         SPDYLAY_STREAM_CLOSING, we discard the frame. This is a race
         condition. */
      valid = 1;
      if(stream->state != SPDYLAY_STREAM_CLOSING) {
        spdylay_session_call_on_ctrl_frame_received(session, SPDYLAY_HEADERS,
                                                    frame);
        if(frame->headers.hd.flags & SPDYLAY_FLAG_FIN) {
          spdylay_session_call_on_request_recv(session,
                                               frame->headers.stream_id);
          spdylay_stream_shutdown(stream, SPDYLAY_SHUT_RD);
          spdylay_session_close_stream_if_shut_rdwr(session, stream);
        }
      }
    }
  }
  if(!valid) {
    r = spdylay_session_handle_invalid_stream
      (session, frame->headers.stream_id, SPDYLAY_HEADERS, frame,
       SPDYLAY_PROTOCOL_ERROR);
  }
  return r;
}

static int spdylay_session_process_ctrl_frame(spdylay_session *session)
{
  int r = 0;
  uint16_t type;
  spdylay_frame frame;
  memcpy(&type, &session->iframe.headbuf[2], sizeof(uint16_t));
  type = ntohs(type);
  switch(type) {
  case SPDYLAY_SYN_STREAM:
    r = spdylay_frame_unpack_syn_stream(&frame.syn_stream,
                                        session->iframe.headbuf,
                                        sizeof(session->iframe.headbuf),
                                        session->iframe.buf,
                                        session->iframe.len,
                                        &session->hd_inflater);
    if(r == 0) {
      r = spdylay_session_on_syn_stream_received(session, &frame);
      spdylay_frame_syn_stream_free(&frame.syn_stream);
    } else {
      /* TODO if r indicates mulformed NV pairs (multiple nulls) or
         invalid frame, send RST_STREAM with PROTOCOL_ERROR. Same for
         other control frames. */
    }
    break;
  case SPDYLAY_SYN_REPLY:
    r = spdylay_frame_unpack_syn_reply(&frame.syn_reply,
                                       session->iframe.headbuf,
                                       sizeof(session->iframe.headbuf),
                                       session->iframe.buf,
                                       session->iframe.len,
                                       &session->hd_inflater);
    if(r == 0) {
      r = spdylay_session_on_syn_reply_received(session, &frame);
      spdylay_frame_syn_reply_free(&frame.syn_reply);
    }
    break;
  case SPDYLAY_RST_STREAM:
    r = spdylay_frame_unpack_rst_stream(&frame.rst_stream,
                                        session->iframe.headbuf,
                                        sizeof(session->iframe.headbuf),
                                        session->iframe.buf,
                                        session->iframe.len);
    if(r == 0) {
      r = spdylay_session_on_rst_stream_received(session, &frame);
      spdylay_frame_rst_stream_free(&frame.rst_stream);
    }
    break;
  case SPDYLAY_SETTINGS:
    r = spdylay_frame_unpack_settings(&frame.settings,
                                      session->iframe.headbuf,
                                      sizeof(session->iframe.headbuf),
                                      session->iframe.buf,
                                      session->iframe.len);
    if(r == 0) {
      r = spdylay_session_on_settings_received(session, &frame);
      spdylay_frame_settings_free(&frame.settings);
    }
    break;
  case SPDYLAY_NOOP:
    break;
  case SPDYLAY_PING:
    r = spdylay_frame_unpack_ping(&frame.ping,
                                  session->iframe.headbuf,
                                  sizeof(session->iframe.headbuf),
                                  session->iframe.buf,
                                  session->iframe.len);
    if(r == 0) {
      r = spdylay_session_on_ping_received(session, &frame);
      spdylay_frame_ping_free(&frame.ping);
    }
    break;
  case SPDYLAY_GOAWAY:
    r = spdylay_frame_unpack_goaway(&frame.goaway,
                                    session->iframe.headbuf,
                                    sizeof(session->iframe.headbuf),
                                    session->iframe.buf,
                                    session->iframe.len);
    if(r == 0) {
      r = spdylay_session_on_goaway_received(session, &frame);
      spdylay_frame_goaway_free(&frame.goaway);
    }
    break;
  case SPDYLAY_HEADERS:
    r = spdylay_frame_unpack_headers(&frame.headers,
                                     session->iframe.headbuf,
                                     sizeof(session->iframe.headbuf),
                                     session->iframe.buf,
                                     session->iframe.len,
                                     &session->hd_inflater);
    if(r == 0) {
      r = spdylay_session_on_headers_received(session, &frame);
      spdylay_frame_headers_free(&frame.headers);
    }
    break;
  }
  if(r < SPDYLAY_ERR_FATAL) {
    return r;
  } else {
    return 0;
  }
}

int spdylay_session_on_data_received(spdylay_session *session,
                                     uint8_t flags, int32_t length,
                                     int32_t stream_id)
{
  int r = 0;
  spdylay_status_code status_code = 0;
  spdylay_stream *stream;
  stream = spdylay_session_get_stream(session, stream_id);
  if(stream) {
    if((stream->shut_flags & SPDYLAY_SHUT_RD) == 0) {
      int valid = 0;
      if(spdylay_session_is_my_stream_id(session, stream_id)) {
        if(stream->state == SPDYLAY_STREAM_OPENED) {
          valid = 1;
          if(session->callbacks.on_data_recv_callback) {
            session->callbacks.on_data_recv_callback
              (session, flags, stream_id, length, session->user_data);
          }
        } else if(stream->state != SPDYLAY_STREAM_CLOSING) {
          status_code = SPDYLAY_PROTOCOL_ERROR;
        }
      } else if(stream->state != SPDYLAY_STREAM_CLOSING) {
        /* It is OK if this is remote peer initiated stream and we did
           not receive FIN unless stream is in SPDYLAY_STREAM_CLOSING
           state. This is a race condition. */
        valid = 1;
        if(session->callbacks.on_data_recv_callback) {
          session->callbacks.on_data_recv_callback
            (session, flags, stream_id, length, session->user_data);
        }
        if(flags & SPDYLAY_FLAG_FIN) {
          spdylay_session_call_on_request_recv(session, stream_id);
        }
      }
      if(valid) {
        if(flags & SPDYLAY_FLAG_FIN) {
          spdylay_stream_shutdown(stream, SPDYLAY_SHUT_RD);
          spdylay_session_close_stream_if_shut_rdwr(session, stream);
        }
      }
    } else {
      status_code = SPDYLAY_PROTOCOL_ERROR;
    }
  } else {
    status_code = SPDYLAY_INVALID_STREAM;
  }
  if(status_code != 0) {
    r = spdylay_session_add_rst_stream(session, stream_id, status_code);
  }
  return r;
}

static int spdylay_session_process_data_frame(spdylay_session *session)
{
  uint8_t flags;
  int32_t length;
  int32_t stream_id;
  int r;
  stream_id = spdylay_get_uint32(session->iframe.headbuf) &
    SPDYLAY_STREAM_ID_MASK;
  flags = session->iframe.headbuf[4];
  length = spdylay_get_uint32(&session->iframe.headbuf[4]) &
    SPDYLAY_LENGTH_MASK;
  r = spdylay_session_on_data_received(session, flags, length, stream_id);
  if(r < SPDYLAY_ERR_FATAL) {
    return r;
  } else {
    return 0;
  }
}

int spdylay_session_recv(spdylay_session *session)
{
  while(1) {
    ssize_t r;
    if(session->iframe.state == SPDYLAY_RECV_HEAD) {
      uint32_t payloadlen;
      if(spdylay_inbound_buffer_avail(&session->ibuf) < SPDYLAY_HEAD_LEN) {
        r = spdylay_recv(session);
        /* If EOF is reached, r == SPDYLAY_ERR_EOF */
        if(r < 0) {
          if(r == SPDYLAY_ERR_WOULDBLOCK) {
            return 0;
          } else {
            return r;
          }
        }
        if(spdylay_inbound_buffer_avail(&session->ibuf) < SPDYLAY_HEAD_LEN) {
          return 0;
        }
      }
      session->iframe.state = SPDYLAY_RECV_PAYLOAD;
      payloadlen = spdylay_get_uint32(&session->ibuf.mark[4]) &
        SPDYLAY_LENGTH_MASK;
      memcpy(session->iframe.headbuf, session->ibuf.mark, SPDYLAY_HEAD_LEN);
      session->ibuf.mark += SPDYLAY_HEAD_LEN;
      if(spdylay_frame_is_ctrl_frame(session->iframe.headbuf[0])) {
        /* control frame */
        session->iframe.len = payloadlen;
        session->iframe.buf = malloc(session->iframe.len);
        if(session->iframe.buf == NULL) {
          return SPDYLAY_ERR_NOMEM;
        }
        session->iframe.off = 0;
      } else {
        /* TODO validate stream id here */
        session->iframe.len = payloadlen;
        session->iframe.off = 0;
      }
    }
    if(session->iframe.state == SPDYLAY_RECV_PAYLOAD) {
      size_t rempayloadlen = session->iframe.len - session->iframe.off;
      size_t bufavail, readlen;
      if(spdylay_inbound_buffer_avail(&session->ibuf) == 0 &&
         rempayloadlen > 0) {
        r = spdylay_recv(session);
        if(r == 0 || r == SPDYLAY_ERR_WOULDBLOCK) {
          return 0;
        } else if(r < 0) {
          return r;
        }
      }
      bufavail = spdylay_inbound_buffer_avail(&session->ibuf);
      readlen =  bufavail < rempayloadlen ? bufavail : rempayloadlen;
      if(spdylay_frame_is_ctrl_frame(session->iframe.headbuf[0])) {
        memcpy(session->iframe.buf, session->ibuf.mark, readlen);
      } else if(session->callbacks.on_data_chunk_recv_callback) {
        int32_t stream_id;
        uint8_t flags;
        /* For data frame, We don't buffer data. Instead, just pass
           received data to callback function. */
        stream_id = spdylay_get_uint32(session->iframe.headbuf) &
          SPDYLAY_STREAM_ID_MASK;
        flags = session->iframe.headbuf[4];
        session->callbacks.on_data_chunk_recv_callback(session,
                                                       flags,
                                                       stream_id,
                                                       session->ibuf.mark,
                                                       readlen,
                                                       session->user_data);
      }
      session->iframe.off += readlen;
      session->ibuf.mark += readlen;
      if(session->iframe.len == session->iframe.off) {
        if(spdylay_frame_is_ctrl_frame(session->iframe.headbuf[0])) {
          r = spdylay_session_process_ctrl_frame(session);
        } else {
          r = spdylay_session_process_data_frame(session);
        }
        if(r < 0) {
          /* Fatal error */
          return r;
        }
        spdylay_inbound_frame_reset(&session->iframe);
      }
    }
  }
  return 0;
}

int spdylay_session_want_read(spdylay_session *session)
{
  /* Unless GOAWAY is sent or received, we always want to read
     incoming frames. After GOAWAY is sent or received, we are only
     interested in active streams. */
  return !session->goaway_flags || spdylay_map_size(&session->streams) > 0;
}

int spdylay_session_want_write(spdylay_session *session)
{
  /*
   * Unless GOAWAY is sent or received, we want to write frames if
   * there is pending ones. If pending frame is SYN_STREAM and
   * concurrent stream limit is reached, we don't want to write
   * SYN_STREAM.  After GOAWAY is sent or received, we want to write
   * frames if there is pending ones AND there are active frames.
   */
  return (session->aob.item != NULL || !spdylay_pq_empty(&session->ob_pq) ||
          (!spdylay_pq_empty(&session->ob_ss_pq) &&
           !spdylay_session_get_max_concurrent_streams_reached(session))) &&
    (!session->goaway_flags || spdylay_map_size(&session->streams) > 0);
}

int spdylay_session_add_ping(spdylay_session *session, uint32_t unique_id)
{
  int r;
  spdylay_frame *frame;
  frame = malloc(sizeof(spdylay_frame));
  if(frame == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  spdylay_frame_ping_init(&frame->ping, unique_id);
  r = spdylay_session_add_frame(session, SPDYLAY_PING, frame, NULL);
  if(r != 0) {
    spdylay_frame_ping_free(&frame->ping);
    free(frame);
  }
  return r;
}

int spdylay_session_add_goaway(spdylay_session *session,
                               int32_t last_good_stream_id)
{
  int r;
  spdylay_frame *frame;
  frame = malloc(sizeof(spdylay_frame));
  if(frame == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  spdylay_frame_goaway_init(&frame->goaway, last_good_stream_id);
  r = spdylay_session_add_frame(session, SPDYLAY_GOAWAY, frame, NULL);
  if(r != 0) {
    spdylay_frame_goaway_free(&frame->goaway);
    free(frame);
  }
  return r;
}

ssize_t spdylay_session_pack_data(spdylay_session *session,
                                  uint8_t **buf_ptr, spdylay_data *frame)
{
  uint8_t *framebuf;
  ssize_t framelen = SPDYLAY_DATA_FRAME_LENGTH;
  framebuf = malloc(framelen);
  if(framebuf == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  framelen = spdylay_session_pack_data_overwrite(session, framebuf, framelen,
                                                 frame);
  if(framelen < 0) {
    free(framebuf);
  } else {
    *buf_ptr = framebuf;
  }
  return framelen;
}

ssize_t spdylay_session_pack_data_overwrite(spdylay_session *session,
                                            uint8_t *buf, size_t len,
                                            spdylay_data *frame)
{
  ssize_t r;
  int eof = 0;
  uint8_t flags = 0;
  r = frame->data_prd.read_callback
    (session, buf+8, len-8, &eof, &frame->data_prd.source, session->user_data);
  if(r < 0) {
    return r;
  } else if(len < r) {
    return SPDYLAY_ERR_CALLBACK_FAILURE;
  }
  memset(buf, 0, SPDYLAY_HEAD_LEN);
  spdylay_put_uint32be(&buf[0], frame->stream_id);
  spdylay_put_uint32be(&buf[4], r);
  if(eof) {
    flags |= SPDYLAY_FLAG_FIN;
  }
  buf[4] = flags;
  frame->flags = flags;
  return r+8;
}

uint32_t spdylay_session_get_next_unique_id(spdylay_session *session)
{
  uint32_t ret_id;
  if(session->next_unique_id > SPDYLAY_MAX_UNIQUE_ID) {
    if(session->server) {
      session->next_unique_id = 2;
    } else {
      session->next_unique_id = 1;
    }
  }
  ret_id = session->next_unique_id;
  session->next_unique_id += 2;
  return ret_id;
}

void* spdylay_session_get_stream_user_data(spdylay_session *session,
                                           int32_t stream_id)
{
  spdylay_stream *stream;
  stream = spdylay_session_get_stream(session, stream_id);
  if(stream) {
    return stream->stream_user_data;
  } else {
    return NULL;
  }
}
