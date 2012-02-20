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
#include "spdylay_submit.h"

#include "spdylay_session.h"
#include "spdylay_frame.h"

int spdylay_submit_ping(spdylay_session *session)
{
  return spdylay_session_add_ping(session,
                                  spdylay_session_get_next_unique_id(session));
}

int spdylay_submit_rst_stream(spdylay_session *session, int32_t stream_id,
                              uint32_t status_code)
{
  return spdylay_session_add_rst_stream(session, stream_id, status_code);
}

int spdylay_submit_goaway(spdylay_session *session)
{
  return spdylay_session_add_goaway(session, session->last_recv_stream_id);
}

int spdylay_submit_response(spdylay_session *session,
                            int32_t stream_id, const char **nv,
                            spdylay_data_provider *data_prd)
{
  int r;
  spdylay_frame *frame;
  char **nv_copy;
  uint8_t flags = 0;
  spdylay_data_provider *data_prd_copy = NULL;
  if(data_prd) {
    data_prd_copy = malloc(sizeof(spdylay_data_provider));
    if(data_prd_copy == NULL) {
      return SPDYLAY_ERR_NOMEM;
    }
    *data_prd_copy = *data_prd;
  }
  frame = malloc(sizeof(spdylay_frame));
  if(frame == NULL) {
    free(data_prd_copy);
    return SPDYLAY_ERR_NOMEM;
  }
  nv_copy = spdylay_frame_nv_copy(nv);
  if(nv_copy == NULL) {
    free(frame);
    free(data_prd_copy);
    return SPDYLAY_ERR_NOMEM;
  }
  spdylay_frame_nv_downcase(nv_copy);
  spdylay_frame_nv_sort(nv_copy);
  if(data_prd == NULL) {
    flags |= SPDYLAY_FLAG_FIN;
  }
  spdylay_frame_syn_reply_init(&frame->syn_reply, flags, stream_id,
                               nv_copy);
  r = spdylay_session_add_frame(session, SPDYLAY_SYN_REPLY, frame,
                                data_prd_copy);
  if(r != 0) {
    spdylay_frame_syn_reply_free(&frame->syn_reply);
    free(frame);
    free(data_prd_copy);
  }
  return r;
}

int spdylay_submit_data(spdylay_session *session, int32_t stream_id,
                        uint8_t flags,
                        spdylay_data_provider *data_prd)
{
  int r;
  spdylay_frame *frame;
  uint8_t nflags = 0;
  frame = malloc(sizeof(spdylay_frame));
  if(frame == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  if(flags & SPDYLAY_FLAG_FIN) {
    nflags |= SPDYLAY_FLAG_FIN;
  }
  spdylay_frame_data_init(&frame->data, stream_id, nflags, data_prd);
  r = spdylay_session_add_frame(session, SPDYLAY_DATA, frame, NULL);
  if(r != 0) {
    spdylay_frame_data_free(&frame->data);
    free(frame);
  }
  return r;
}

int spdylay_submit_request(spdylay_session *session, uint8_t pri,
                           const char **nv, spdylay_data_provider *data_prd,
                           void *stream_user_data)
{
  int r;
  spdylay_frame *frame;
  char **nv_copy;
  uint8_t flags = 0;
  spdylay_data_provider *data_prd_copy = NULL;
  spdylay_syn_stream_aux_data *aux_data;
  if(pri > 3) {
    return SPDYLAY_ERR_INVALID_ARGUMENT;
  }
  if(data_prd != NULL && data_prd->read_callback != NULL) {
    data_prd_copy = malloc(sizeof(spdylay_data_provider));
    if(data_prd_copy == NULL) {
      return SPDYLAY_ERR_NOMEM;
    }
    *data_prd_copy = *data_prd;
  }
  aux_data = malloc(sizeof(spdylay_syn_stream_aux_data));
  if(aux_data == NULL) {
    free(data_prd_copy);
    return SPDYLAY_ERR_NOMEM;
  }
  aux_data->data_prd = data_prd_copy;
  aux_data->stream_user_data = stream_user_data;

  frame = malloc(sizeof(spdylay_frame));
  if(frame == NULL) {
    free(aux_data);
    free(data_prd_copy);
    return SPDYLAY_ERR_NOMEM;
  }
  nv_copy = spdylay_frame_nv_copy(nv);
  if(nv_copy == NULL) {
    free(frame);
    free(aux_data);
    free(data_prd_copy);
    return SPDYLAY_ERR_NOMEM;
  }
  spdylay_frame_nv_downcase(nv_copy);
  spdylay_frame_nv_sort(nv_copy);
  if(data_prd_copy == NULL) {
    flags |= SPDYLAY_FLAG_FIN;
  }
  spdylay_frame_syn_stream_init(&frame->syn_stream, flags, 0, 0, pri, nv_copy);
  r = spdylay_session_add_frame(session, SPDYLAY_SYN_STREAM, frame,
                                aux_data);
  if(r != 0) {
    spdylay_frame_syn_stream_free(&frame->syn_stream);
    free(frame);
    free(aux_data);
    free(data_prd_copy);
  }
  return r;
}
