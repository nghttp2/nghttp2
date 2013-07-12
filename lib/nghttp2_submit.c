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
#include "nghttp2_submit.h"

#include <string.h>

#include "nghttp2_session.h"
#include "nghttp2_frame.h"
#include "nghttp2_helper.h"

static int nghttp2_submit_syn_stream_shared
(nghttp2_session *session,
 uint8_t flags,
 int32_t assoc_stream_id,
 uint8_t pri,
 const char **nv,
 const nghttp2_data_provider *data_prd,
 void *stream_user_data)
{
  int r;
  nghttp2_frame *frame;
  char **nv_copy;
  uint8_t flags_copy;
  nghttp2_data_provider *data_prd_copy = NULL;
  nghttp2_syn_stream_aux_data *aux_data;
  if(pri > nghttp2_session_get_pri_lowest(session)) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  if(assoc_stream_id != 0 && session->server == 0) {
    assoc_stream_id = 0;
  }
  if(!nghttp2_frame_nv_check_null(nv)) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  if(data_prd != NULL && data_prd->read_callback != NULL) {
    data_prd_copy = malloc(sizeof(nghttp2_data_provider));
    if(data_prd_copy == NULL) {
      return NGHTTP2_ERR_NOMEM;
    }
    *data_prd_copy = *data_prd;
  }
  aux_data = malloc(sizeof(nghttp2_syn_stream_aux_data));
  if(aux_data == NULL) {
    free(data_prd_copy);
    return NGHTTP2_ERR_NOMEM;
  }
  aux_data->data_prd = data_prd_copy;
  aux_data->stream_user_data = stream_user_data;

  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    free(aux_data);
    free(data_prd_copy);
    return NGHTTP2_ERR_NOMEM;
  }
  nv_copy = nghttp2_frame_nv_norm_copy(nv);
  if(nv_copy == NULL) {
    free(frame);
    free(aux_data);
    free(data_prd_copy);
    return NGHTTP2_ERR_NOMEM;
  }
  flags_copy = 0;
  if(flags & NGHTTP2_CTRL_FLAG_FIN) {
    flags_copy |= NGHTTP2_CTRL_FLAG_FIN;
  }
  if(flags & NGHTTP2_CTRL_FLAG_UNIDIRECTIONAL) {
    flags_copy |= NGHTTP2_CTRL_FLAG_UNIDIRECTIONAL;
  }
  nghttp2_frame_syn_stream_init(&frame->syn_stream,
                                session->version, flags_copy,
                                0, assoc_stream_id, pri, nv_copy);
  r = nghttp2_session_add_frame(session, NGHTTP2_CTRL, frame,
                                aux_data);
  if(r != 0) {
    nghttp2_frame_syn_stream_free(&frame->syn_stream);
    free(frame);
    free(aux_data);
    free(data_prd_copy);
  }
  return r;
}

int nghttp2_submit_syn_stream(nghttp2_session *session, uint8_t flags,
                              int32_t assoc_stream_id, uint8_t pri,
                              const char **nv, void *stream_user_data)
{
  return nghttp2_submit_syn_stream_shared(session, flags, assoc_stream_id,
                                          pri, nv, NULL, stream_user_data);
}

int nghttp2_submit_syn_reply(nghttp2_session *session, uint8_t flags,
                             int32_t stream_id, const char **nv)
{
  int r;
  nghttp2_frame *frame;
  char **nv_copy;
  uint8_t flags_copy;
  if(!nghttp2_frame_nv_check_null(nv)) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  nv_copy = nghttp2_frame_nv_norm_copy(nv);
  if(nv_copy == NULL) {
    free(frame);
    return NGHTTP2_ERR_NOMEM;
  }
  flags_copy = 0;
  if(flags & NGHTTP2_CTRL_FLAG_FIN) {
    flags_copy |= NGHTTP2_CTRL_FLAG_FIN;
  }
  nghttp2_frame_syn_reply_init(&frame->syn_reply, session->version, flags_copy,
                               stream_id, nv_copy);
  r = nghttp2_session_add_frame(session, NGHTTP2_CTRL, frame, NULL);
  if(r != 0) {
    nghttp2_frame_syn_reply_free(&frame->syn_reply);
    free(frame);
  }
  return r;
}

int nghttp2_submit_headers(nghttp2_session *session, uint8_t flags,
                           int32_t stream_id, const char **nv)
{
  int r;
  nghttp2_frame *frame;
  char **nv_copy;
  uint8_t flags_copy;
  if(!nghttp2_frame_nv_check_null(nv)) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  nv_copy = nghttp2_frame_nv_norm_copy(nv);
  if(nv_copy == NULL) {
    free(frame);
    return NGHTTP2_ERR_NOMEM;
  }
  flags_copy = 0;
  if(flags & NGHTTP2_CTRL_FLAG_FIN) {
    flags_copy |= NGHTTP2_CTRL_FLAG_FIN;
  }
  nghttp2_frame_headers_init(&frame->headers, session->version, flags_copy,
                             stream_id, nv_copy);
  r = nghttp2_session_add_frame(session, NGHTTP2_CTRL, frame, NULL);
  if(r != 0) {
    nghttp2_frame_headers_free(&frame->headers);
    free(frame);
  }
  return r;
}

int nghttp2_submit_ping(nghttp2_session *session)
{
  return nghttp2_session_add_ping(session,
                                  nghttp2_session_get_next_unique_id(session));
}

int nghttp2_submit_rst_stream(nghttp2_session *session, int32_t stream_id,
                              uint32_t status_code)
{
  return nghttp2_session_add_rst_stream(session, stream_id, status_code);
}

int nghttp2_submit_goaway(nghttp2_session *session, uint32_t status_code)
{
  return nghttp2_session_add_goaway(session, session->last_recv_stream_id,
                                    status_code);
}

int nghttp2_submit_settings(nghttp2_session *session, uint8_t flags,
                            const nghttp2_settings_entry *iv, size_t niv)
{
  nghttp2_frame *frame;
  nghttp2_settings_entry *iv_copy;
  int check[NGHTTP2_SETTINGS_MAX+1];
  size_t i;
  int r;
  memset(check, 0, sizeof(check));
  for(i = 0; i < niv; ++i) {
    if(iv[i].settings_id > NGHTTP2_SETTINGS_MAX || iv[i].settings_id == 0 ||
       check[iv[i].settings_id] == 1) {
      return NGHTTP2_ERR_INVALID_ARGUMENT;
    } else {
      check[iv[i].settings_id] = 1;
    }
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
  nghttp2_frame_iv_sort(iv_copy, niv);
  nghttp2_frame_settings_init(&frame->settings, session->version,
                              flags, iv_copy, niv);
  r = nghttp2_session_add_frame(session, NGHTTP2_CTRL, frame, NULL);
  if(r == 0) {
    nghttp2_session_update_local_settings(session, iv_copy, niv);
  } else {
    nghttp2_frame_settings_free(&frame->settings);
    free(frame);
  }
  return r;
}

int nghttp2_submit_window_update(nghttp2_session *session, int32_t stream_id,
                                 int32_t delta_window_size)
{
  nghttp2_stream *stream;
  if(delta_window_size <= 0) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  stream = nghttp2_session_get_stream(session, stream_id);
  if(stream) {
    stream->recv_window_size -= nghttp2_min(delta_window_size,
                                            stream->recv_window_size);
    return nghttp2_session_add_window_update(session, stream_id,
                                             delta_window_size);
  } else {
    return NGHTTP2_ERR_STREAM_CLOSED;
  }
}

int nghttp2_submit_request(nghttp2_session *session, uint8_t pri,
                           const char **nv,
                           const nghttp2_data_provider *data_prd,
                           void *stream_user_data)
{
  int flags;
  flags = 0;
  if(data_prd == NULL || data_prd->read_callback == NULL) {
    flags |= NGHTTP2_CTRL_FLAG_FIN;
  }
  return nghttp2_submit_syn_stream_shared(session, flags, 0, pri, nv, data_prd,
                                          stream_user_data);
}

int nghttp2_submit_response(nghttp2_session *session,
                            int32_t stream_id, const char **nv,
                            const nghttp2_data_provider *data_prd)
{
  int r;
  nghttp2_frame *frame;
  char **nv_copy;
  uint8_t flags = 0;
  nghttp2_data_provider *data_prd_copy = NULL;
  if(!nghttp2_frame_nv_check_null(nv)) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  if(data_prd != NULL && data_prd->read_callback != NULL) {
    data_prd_copy = malloc(sizeof(nghttp2_data_provider));
    if(data_prd_copy == NULL) {
      return NGHTTP2_ERR_NOMEM;
    }
    *data_prd_copy = *data_prd;
  }
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    free(data_prd_copy);
    return NGHTTP2_ERR_NOMEM;
  }
  nv_copy = nghttp2_frame_nv_norm_copy(nv);
  if(nv_copy == NULL) {
    free(frame);
    free(data_prd_copy);
    return NGHTTP2_ERR_NOMEM;
  }
  if(data_prd_copy == NULL) {
    flags |= NGHTTP2_CTRL_FLAG_FIN;
  }
  nghttp2_frame_syn_reply_init(&frame->syn_reply, session->version, flags,
                               stream_id, nv_copy);
  r = nghttp2_session_add_frame(session, NGHTTP2_CTRL, frame,
                                data_prd_copy);
  if(r != 0) {
    nghttp2_frame_syn_reply_free(&frame->syn_reply);
    free(frame);
    free(data_prd_copy);
  }
  return r;
}

int nghttp2_submit_data(nghttp2_session *session, int32_t stream_id,
                        uint8_t flags,
                        const nghttp2_data_provider *data_prd)
{
  int r;
  nghttp2_data *data_frame;
  uint8_t nflags = 0;
  data_frame = malloc(sizeof(nghttp2_frame));
  if(data_frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  if(flags & NGHTTP2_DATA_FLAG_FIN) {
    nflags |= NGHTTP2_DATA_FLAG_FIN;
  }
  nghttp2_frame_data_init(data_frame, stream_id, nflags, data_prd);
  r = nghttp2_session_add_frame(session, NGHTTP2_DATA, data_frame, NULL);
  if(r != 0) {
    nghttp2_frame_data_free(data_frame);
    free(data_frame);
  }
  return r;
}
