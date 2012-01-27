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
 * Returns non-zero value if |stream_id| is initiated by local host.
 * Otherwrise returns 0.
 */
static int spdylay_session_is_my_stream_id(spdylay_session *session,
                                           int32_t stream_id)
{
  int r;
  if(stream_id == 0) {
    return 0;
  }
  r = stream_id % 2;
  return (session->server && r == 0) || r == 1;
}

spdylay_stream* spdylay_session_get_stream(spdylay_session *session,
                                           int32_t stream_id)
{
  return (spdylay_stream*)spdylay_map_find(&session->streams, stream_id);
}

int spdylay_outbound_item_compar(const void *lhsx, const void *rhsx)
{
  const spdylay_outbound_item *lhs, *rhs;
  lhs = (const spdylay_outbound_item*)lhsx;
  rhs = (const spdylay_outbound_item*)rhsx;
  return lhs->pri-rhs->pri;
}

int spdylay_session_client_new(spdylay_session **session_ptr,
                               const spdylay_session_callbacks *callbacks,
                               void *user_data)
{
  int r;
  *session_ptr = malloc(sizeof(spdylay_session));
  if(*session_ptr == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  memset(*session_ptr, 0, sizeof(spdylay_session));
  (*session_ptr)->next_stream_id = 1;
  (*session_ptr)->last_recv_stream_id = 0;

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
  (*session_ptr)->callbacks = *callbacks;
  (*session_ptr)->user_data = user_data;

  (*session_ptr)->ibuf.mark = (*session_ptr)->ibuf.buf;
  (*session_ptr)->ibuf.limit = (*session_ptr)->ibuf.buf;
  
  (*session_ptr)->iframe.state = SPDYLAY_RECV_HEAD;
  return 0;
}

static void spdylay_free_streams(key_type key, void *val)
{
  spdylay_stream_free((spdylay_stream*)val);
  free(val);
}

static void spdylay_outbound_item_free(spdylay_outbound_item *item)
{
  if(item == NULL) {
    return;
  }
  switch(item->frame_type) {
  case SPDYLAY_SYN_STREAM:
    spdylay_frame_syn_stream_free(&item->frame->syn_stream);
    break;
  case SPDYLAY_SYN_REPLY:
    spdylay_frame_syn_reply_free(&item->frame->syn_reply);
    break;
  case SPDYLAY_RST_STREAM:
    spdylay_frame_rst_stream_free(&item->frame->rst_stream);
    break;
  case SPDYLAY_DATA:
    spdylay_frame_data_free(&item->frame->data);
    break;
  }
  free(item->frame);
}

void spdylay_session_del(spdylay_session *session)
{
  spdylay_map_each(&session->streams, spdylay_free_streams);
  spdylay_map_free(&session->streams);
  while(!spdylay_pq_empty(&session->ob_pq)) {
    spdylay_outbound_item *item = (spdylay_outbound_item*)
      spdylay_pq_top(&session->ob_pq);
    spdylay_outbound_item_free(item);
    free(item);
    spdylay_pq_pop(&session->ob_pq);
  }
  spdylay_pq_free(&session->ob_pq);
  spdylay_zlib_deflate_free(&session->hd_deflater);
  spdylay_zlib_inflate_free(&session->hd_inflater);
  free(session->iframe.buf);
  free(session);
}

int spdylay_session_add_frame(spdylay_session *session,
                              spdylay_frame_type frame_type,
                              spdylay_frame *frame)
{
  int r;
  spdylay_outbound_item *item;
  item = malloc(sizeof(spdylay_outbound_item));
  if(item == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  item->frame_type = frame_type;
  item->frame = frame;
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
  case SPDYLAY_DATA: {
    spdylay_stream *stream = spdylay_session_get_stream
      (session, frame->data.stream_id);
    if(stream) {
      item->pri = stream->pri;
    }
    break;
  }
  };
  r = spdylay_pq_push(&session->ob_pq, item);
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
  r = spdylay_session_add_frame(session, SPDYLAY_RST_STREAM, frame);
  if(r != 0) {
    spdylay_frame_rst_stream_free(&frame->rst_stream);
    free(frame);
    return r;
  }
  return 0;
}

int spdylay_session_open_stream(spdylay_session *session, int32_t stream_id,
                                uint8_t flags, uint8_t pri,
                                spdylay_stream_state initial_state)
{
  int r;
  spdylay_stream *stream = malloc(sizeof(spdylay_stream));
  if(stream == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  spdylay_stream_init(stream, stream_id, flags, pri, initial_state);
  r = spdylay_map_insert(&session->streams, stream_id, stream);
  if(r != 0) {
    free(stream);
  }
  return r;
}

int spdylay_session_close_stream(spdylay_session *session, int32_t stream_id)
{
  spdylay_stream *stream = spdylay_session_get_stream(session, stream_id);
  if(stream) {
    spdylay_map_erase(&session->streams, stream_id);
    spdylay_stream_free(stream);
    free(stream);
    return 0;
  } else {
    return SPDYLAY_ERR_INVALID_ARGUMENT;
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
      (stream->flags & SPDYLAY_FLAG_UNIDIRECTIONAL) == 0;
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
    return (stream->flags & SPDYLAY_FLAG_FIN) == 0;
  } else {
    return stream->state == SPDYLAY_STREAM_OPENED;
  }
}

ssize_t spdylay_session_prep_frame(spdylay_session *session,
                                   spdylay_outbound_item *item,
                                   uint8_t **framebuf_ptr)
{
  /* TODO Get or validate stream ID here */
  uint8_t *framebuf;
  ssize_t framebuflen;
  int r;
  switch(item->frame_type) {
  case SPDYLAY_SYN_STREAM: {
    item->frame->syn_stream.stream_id = session->next_stream_id;
    session->next_stream_id += 2;
    framebuflen = spdylay_frame_pack_syn_stream(&framebuf,
                                                &item->frame->syn_stream,
                                                &session->hd_deflater);
    if(framebuflen < 0) {
      return framebuflen;
    }
    r = spdylay_session_open_stream(session, item->frame->syn_stream.stream_id,
                                    item->frame->syn_stream.hd.flags,
                                    item->frame->syn_stream.pri,
                                    SPDYLAY_STREAM_INITIAL);
    if(r != 0) {
      free(framebuf);
      return r;
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

static spdylay_outbound_item* spdylay_session_get_ob_pq_top
(spdylay_session *session)
{
  return (spdylay_outbound_item*)spdylay_pq_top(&session->ob_pq);
}

static int spdylay_session_after_frame_sent(spdylay_session *session)
{
  /* TODO handle FIN flag. */
  spdylay_frame *frame = session->aob.item->frame;
  spdylay_frame_type type = session->aob.item->frame_type;
  switch(type) {
  case SPDYLAY_SYN_STREAM: {
    spdylay_stream *stream =
      spdylay_session_get_stream(session, frame->syn_stream.stream_id);
    if(stream) {
      stream->state = SPDYLAY_STREAM_OPENING;
    }
    break;
  }
  case SPDYLAY_SYN_REPLY: {
    spdylay_stream *stream =
      spdylay_session_get_stream(session, frame->syn_reply.stream_id);
    if(stream) {
      stream->state = SPDYLAY_STREAM_OPENED;
    }
    break;
  }
  case SPDYLAY_RST_STREAM:
    spdylay_session_close_stream(session, frame->rst_stream.stream_id);
    break;
  case SPDYLAY_DATA:
    if(frame->data.flags & SPDYLAY_FLAG_FIN) {
      if(spdylay_session_is_my_stream_id(session, frame->data.stream_id)) {
        /* This is the last frame of request DATA (e.g., POST in HTTP
           term), so set FIN bit set in stream. This also happens when
           request HEADERS frame is sent with FIN bit set. */
        spdylay_stream *stream =
          spdylay_session_get_stream(session, frame->data.stream_id);
        if(stream) {
          stream->flags |= SPDYLAY_FLAG_FIN;
        }
      } else {
        /* We send all data requested by peer, so close the stream. */
        spdylay_session_close_stream(session, frame->data.stream_id);
      }
    }
    break;
  };
  if(type == SPDYLAY_DATA) {
    int r;
    if(frame->data.flags & SPDYLAY_FLAG_FIN) {
      spdylay_active_outbound_item_reset(&session->aob);
    } else if(spdylay_pq_empty(&session->ob_pq) ||
              session->aob.item->pri <=
              spdylay_session_get_ob_pq_top(session)->pri) {
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
  } else {
    spdylay_active_outbound_item_reset(&session->aob);
  }
  return 0;
}

int spdylay_session_send(spdylay_session *session)
{
  int r;
  printf("session_send\n");
  while(session->aob.item || !spdylay_pq_empty(&session->ob_pq)) {
    const uint8_t *data;
    size_t datalen;
    ssize_t sentlen;
    if(session->aob.item == NULL) {
      spdylay_outbound_item *item = spdylay_pq_top(&session->ob_pq);
      uint8_t *framebuf;
      ssize_t framebuflen;
      spdylay_pq_pop(&session->ob_pq);
      framebuflen = spdylay_session_prep_frame(session, item, &framebuf);
      if(framebuflen < 0) {
        /* TODO Call error callback? */
        spdylay_outbound_item_free(item);
        free(item);
        continue;;
      }
      session->aob.item = item;
      session->aob.framebuf = framebuf;
      session->aob.framebuflen = framebuflen;
      /* TODO Call before_send callback */
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

static void spdylay_debug_print_nv(char **nv)
{
  int i;
  for(i = 0; nv[i]; i += 2) {
    printf("%s: %s\n", nv[i], nv[i+1]);
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
 * succeeds, or -1.
 */
static int spdylay_session_validate_syn_stream(spdylay_session *session,
                                               spdylay_syn_stream *frame)
{
  /* TODO Check assoc_stream_id */
  if(spdylay_session_is_new_peer_stream_id(session, frame->stream_id)) {
    return 0;
  } else {
    return -1;
  }
}

static int spdylay_session_handle_invalid_ctrl_frame(spdylay_session *session,
                                                     int32_t stream_id,
                                                     spdylay_frame_type type,
                                                     spdylay_frame *frame)
{
  int r;
  r = spdylay_session_add_rst_stream(session, stream_id,
                                     SPDYLAY_PROTOCOL_ERROR);
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
  if(spdylay_session_validate_syn_stream(session, &frame->syn_stream) == 0) {
    uint8_t flags = frame->syn_stream.hd.flags;
    if((flags & SPDYLAY_FLAG_FIN) && (flags & SPDYLAY_FLAG_UNIDIRECTIONAL)) {
      /* If the stream is UNIDIRECTIONAL and FIN bit set, we can close
         stream upon receiving SYN_STREAM. So, the stream needs not to
         be opened. */
      r = 0;
    } else {
      r = spdylay_session_open_stream(session, frame->syn_stream.stream_id,
                                      frame->syn_stream.hd.flags,
                                      frame->syn_stream.pri,
                                      SPDYLAY_STREAM_OPENING);
    }
    if(r == 0) {
      session->last_recv_stream_id = frame->syn_stream.stream_id;
      spdylay_session_call_on_ctrl_frame_received(session, SPDYLAY_SYN_STREAM,
                                                  frame);
    }
  } else {
    r = spdylay_session_handle_invalid_ctrl_frame
      (session, frame->syn_stream.stream_id, SPDYLAY_SYN_STREAM, frame);
  }
  return r;
}

int spdylay_session_on_syn_reply_received(spdylay_session *session,
                                          spdylay_frame *frame)
{
  int r = 0;
  int valid = 0;
  if(spdylay_session_is_my_stream_id(session, frame->syn_reply.stream_id)) {
    spdylay_stream *stream = spdylay_session_get_stream
      (session, frame->syn_reply.stream_id);
    if(stream) {
      if(stream->state == SPDYLAY_STREAM_OPENING) {
        valid = 1;
        stream->state = SPDYLAY_STREAM_OPENED;
        spdylay_session_call_on_ctrl_frame_received(session, SPDYLAY_SYN_REPLY,
                                                    frame);
        if(frame->syn_reply.hd.flags & SPDYLAY_FLAG_FIN) {
          /* This is the last frame of this stream, so close the
             stream. This also happens when DATA and HEADERS frame
             with FIN bit set. */
          spdylay_session_close_stream(session, frame->syn_reply.stream_id);
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
    r = spdylay_session_handle_invalid_ctrl_frame
      (session, frame->syn_reply.stream_id, SPDYLAY_SYN_REPLY, frame);
  }
  return r;
}

int spdylay_session_process_ctrl_frame(spdylay_session *session)
{
  int r = 0;
  uint16_t type;
  spdylay_frame frame;
  memcpy(&type, &session->iframe.headbuf[2], sizeof(uint16_t));
  type = ntohs(type);
  switch(type) {
  case SPDYLAY_SYN_STREAM:
    printf("SYN_STREAM\n");
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
    printf("SYN_REPLY\n");
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
  default:
    /* ignore */
    printf("Received control frame type %x\n", type);
  }
  if(r < SPDYLAY_ERR_FATAL) {
    return r;
  } else {
    return 0;
  }
}

int spdylay_session_process_data_frame(spdylay_session *session)
{
  printf("Received data frame, stream_id %d, %zu bytes, fin=%d\n",
         spdylay_get_uint32(session->iframe.headbuf),
         session->iframe.len,
         session->iframe.headbuf[4] & SPDYLAY_FLAG_FIN);
  return 0;
}

int spdylay_session_recv(spdylay_session *session)
{
  printf("session_recv\n");
  while(1) {
    ssize_t r;
    if(session->iframe.state == SPDYLAY_RECV_HEAD) {
      uint32_t payloadlen;
      if(spdylay_inbound_buffer_avail(&session->ibuf) < SPDYLAY_HEAD_LEN) {
        r = spdylay_recv(session);
        printf("r=%d\n", r);
        /* TODO handle EOF */
        if(r < 0) {
          if(r == SPDYLAY_ERR_WOULDBLOCK) {
            return 0;
          } else {
            return r;
          }
        }
        printf("Recved %d bytes\n", r);
        if(spdylay_inbound_buffer_avail(&session->ibuf) < SPDYLAY_HEAD_LEN) {
          return 0;
        }
      }
      session->iframe.state = SPDYLAY_RECV_PAYLOAD;
      payloadlen = spdylay_get_uint32(&session->ibuf.mark[4]) & 0xffffff;
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
        int32_t stream_id;
        /* data frame */
        /* For data frame, We dont' buffer data. Instead, just pass
           received data to callback function. */
        stream_id = spdylay_get_uint32(session->iframe.headbuf) & 0x7fffffff;
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
        if(r <= 0) {
          if(r == SPDYLAY_ERR_WOULDBLOCK) {
            return 0;
          } else {
            return r;
          }
        }
      }
      bufavail = spdylay_inbound_buffer_avail(&session->ibuf);
      readlen =  bufavail < rempayloadlen ? bufavail : rempayloadlen;
      if(session->iframe.buf != NULL) {
        memcpy(session->iframe.buf, session->ibuf.mark, readlen);
      }
      session->iframe.off += readlen;
      session->ibuf.mark += readlen;
      if(session->iframe.len == session->iframe.off) {
        if(spdylay_frame_is_ctrl_frame(session->iframe.headbuf[0])) {
          r = spdylay_session_process_ctrl_frame(session);
          if(r < 0) {
            /* Fatal error */
            return r;
          }
        } else {
          spdylay_session_process_data_frame(session);
        }
        spdylay_inbound_frame_reset(&session->iframe);
      }
    }
  }
  return 0;
}

int spdylay_session_want_read(spdylay_session *session)
{
  return 1;
}

int spdylay_session_want_write(spdylay_session *session)
{
  return session->aob.item != NULL || !spdylay_pq_empty(&session->ob_pq);
}

int spdylay_reply_submit(spdylay_session *session,
                         int32_t stream_id, const char **nv,
                         spdylay_data_provider *data_prd)
{
  int r;
  spdylay_frame *frame;
  spdylay_frame *data_frame = NULL;
  char **nv_copy;
  uint8_t flags = 0;
  frame = malloc(sizeof(spdylay_frame));
  if(frame == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  nv_copy = spdylay_frame_nv_copy(nv);
  if(nv_copy == NULL) {
    free(frame);
    return SPDYLAY_ERR_NOMEM;
  }
  if(data_prd == NULL) {
    flags |= SPDYLAY_FLAG_FIN;
  }
  spdylay_frame_syn_reply_init(&frame->syn_reply, flags, stream_id,
                               nv_copy);
  r = spdylay_session_add_frame(session, SPDYLAY_SYN_REPLY, frame);
  if(r != 0) {
    spdylay_frame_syn_reply_free(&frame->syn_reply);
    free(frame);
    return r;
  }
  if(data_prd != NULL) {
    /* TODO If error is not FATAL, we should add RST_STREAM frame to
       cancel this stream. */
    data_frame = malloc(sizeof(spdylay_frame));
    if(data_frame == NULL) {
      return SPDYLAY_ERR_NOMEM;
    }
    spdylay_frame_data_init(&data_frame->data, stream_id, data_prd);
    r = spdylay_session_add_frame(session, SPDYLAY_DATA, data_frame);
    if(r != 0) {
      spdylay_frame_data_free(&data_frame->data);
      free(data_frame);
      return r;
    }
  }
  return 0;
}

int spdylay_req_submit(spdylay_session *session, const char *path)
{
  int r;
  spdylay_frame *frame;
  char **nv;
  frame = malloc(sizeof(spdylay_frame));
  nv = malloc(9*sizeof(char*));
  nv[0] = strdup("method");
  nv[1] = strdup("GET");
  nv[2] = strdup("scheme");
  nv[3] = strdup("https");
  nv[4] = strdup("url");
  nv[5] = strdup(path);
  nv[6] = strdup("version");
  nv[7] = strdup("HTTP/1.1");
  nv[8] = NULL;
  spdylay_frame_syn_stream_init(&frame->syn_stream,
                                SPDYLAY_FLAG_FIN, 0, 0, 0, nv);
  r = spdylay_session_add_frame(session, SPDYLAY_SYN_STREAM, frame);
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
  }
  *buf_ptr = framebuf;
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
  memset(buf, 0, len);
  spdylay_put_uint32be(&buf[0], frame->stream_id);
  spdylay_put_uint32be(&buf[4], 8+r);
  if(eof) {
    flags |= SPDYLAY_FLAG_FIN;
  }
  buf[4] = flags;
  frame->flags = flags;
  return r+8;
}
