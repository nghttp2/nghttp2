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
#include <assert.h>

#include "nghttp2_session.h"
#include "nghttp2_frame.h"
#include "nghttp2_helper.h"

static int nghttp2_submit_headers_shared
(nghttp2_session *session,
 uint8_t flags,
 int32_t stream_id,
 int32_t pri,
 const char **nv,
 const nghttp2_data_provider *data_prd,
 void *stream_user_data)
{
  int r;
  nghttp2_frame *frame;
  nghttp2_nv *nva_copy;
  ssize_t nvlen;
  uint8_t flags_copy;
  nghttp2_data_provider *data_prd_copy = NULL;
  nghttp2_headers_aux_data *aux_data = NULL;
  if(pri < 0) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
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
  if(data_prd || stream_user_data) {
    aux_data = malloc(sizeof(nghttp2_headers_aux_data));
    if(aux_data == NULL) {
      free(data_prd_copy);
      return NGHTTP2_ERR_NOMEM;
    }
    aux_data->data_prd = data_prd_copy;
    aux_data->stream_user_data = stream_user_data;
  }
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    free(aux_data);
    free(data_prd_copy);
    return NGHTTP2_ERR_NOMEM;
  }
  nvlen = nghttp2_nv_array_from_cstr(&nva_copy, nv);
  if(nvlen < 0) {
    free(frame);
    free(aux_data);
    free(data_prd_copy);
    return nvlen;
  }
  /* TODO Implement header continuation */
  flags_copy = (flags & (NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_PRIORITY)) |
    NGHTTP2_FLAG_END_HEADERS;

  nghttp2_frame_headers_init(&frame->headers, flags_copy, stream_id, pri,
                             nva_copy, nvlen);
  r = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame,
                                aux_data);
  if(r != 0) {
    nghttp2_frame_headers_free(&frame->headers);
    free(frame);
    free(aux_data);
    free(data_prd_copy);
  }
  return r;
}

int nghttp2_submit_headers(nghttp2_session *session, uint8_t flags,
                           int32_t stream_id, int32_t pri,
                           const char **nv, void *stream_user_data)
{
  return nghttp2_submit_headers_shared(session, flags, stream_id,
                                       pri, nv, NULL, stream_user_data);
}


int nghttp2_submit_ping(nghttp2_session *session, uint8_t *opaque_data)
{
  return nghttp2_session_add_ping(session, NGHTTP2_FLAG_NONE, opaque_data);
}

int nghttp2_submit_priority(nghttp2_session *session, int32_t stream_id,
                            int32_t pri)
{
  int r;
  nghttp2_frame *frame;
  nghttp2_stream *stream;
  if(pri < 0) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  stream = nghttp2_session_get_stream(session, stream_id);
  if(stream == NULL) {
    return NGHTTP2_ERR_STREAM_CLOSED;
  }
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  nghttp2_frame_priority_init(&frame->priority, stream_id, pri);
  r = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  if(r != 0) {
    nghttp2_frame_priority_free(&frame->priority);
    free(frame);
    return r;
  }
  /* Only update priority if the sender is client for now */
  if(!session->server) {
    nghttp2_session_reprioritize_stream(session, stream, pri);
  }
  return 0;
}

int nghttp2_submit_rst_stream(nghttp2_session *session, int32_t stream_id,
                              nghttp2_error_code error_code)
{
  return nghttp2_session_add_rst_stream(session, stream_id, error_code);
}

int nghttp2_submit_goaway(nghttp2_session *session,
                          nghttp2_error_code error_code,
                          uint8_t *opaque_data, size_t opaque_data_len)
{
  return nghttp2_session_add_goaway(session, session->last_recv_stream_id,
                                    error_code, opaque_data, opaque_data_len);
}

int nghttp2_submit_settings(nghttp2_session *session,
                            const nghttp2_settings_entry *iv, size_t niv)
{
  nghttp2_frame *frame;
  nghttp2_settings_entry *iv_copy;
  int r;
  if(!nghttp2_settings_check_duplicate(iv, niv)) {
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
  nghttp2_frame_iv_sort(iv_copy, niv);
  nghttp2_frame_settings_init(&frame->settings, iv_copy, niv);

  r = nghttp2_session_update_local_settings(session, iv_copy, niv);
  if(r != 0) {
    nghttp2_frame_settings_free(&frame->settings);
    free(frame);
    return r;
  }
  r = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  if(r != 0) {
    /* The only expected error is fatal one */
    assert(r < NGHTTP2_ERR_FATAL);
    nghttp2_frame_settings_free(&frame->settings);
    free(frame);
  }
  return r;
}

int nghttp2_submit_push_promise(nghttp2_session *session, uint8_t flags,
                                int32_t stream_id, const char **nv)
{
  nghttp2_frame *frame;
  nghttp2_nv *nva;
  ssize_t nvlen;
  uint8_t flags_copy;
  int r;

  if(nghttp2_session_get_stream(session, stream_id) == NULL) {
    return NGHTTP2_ERR_STREAM_CLOSED;
  }
  if(!nghttp2_frame_nv_check_null(nv)) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  nvlen = nghttp2_nv_array_from_cstr(&nva, nv);
  if(nvlen < 0) {
    free(frame);
    return nvlen;
  }
  /* TODO Implement header continuation */
  flags_copy = NGHTTP2_FLAG_END_PUSH_PROMISE;
  nghttp2_frame_push_promise_init(&frame->push_promise, flags_copy,
                                  stream_id, -1, nva, nvlen);
  r = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  if(r != 0) {
    nghttp2_frame_push_promise_free(&frame->push_promise);
    free(frame);
  }
  return 0;
}

int nghttp2_submit_window_update(nghttp2_session *session, uint8_t flags,
                                 int32_t stream_id,
                                 int32_t window_size_increment)
{
  int rv;
  nghttp2_stream *stream;
  flags &= NGHTTP2_FLAG_END_FLOW_CONTROL;
  if(flags & NGHTTP2_FLAG_END_FLOW_CONTROL) {
    if(stream_id == 0) {
      session->local_flow_control = 0;
    } else {
      stream = nghttp2_session_get_stream(session, stream_id);
      if(stream) {
        stream->local_flow_control = 0;
      } else {
        return NGHTTP2_ERR_STREAM_CLOSED;
      }
    }
    return nghttp2_session_add_window_update(session, flags, stream_id, 0);
  } else if(window_size_increment == 0) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  if(stream_id == 0) {
    if(!session->local_flow_control) {
      return NGHTTP2_ERR_INVALID_ARGUMENT;
    }
    rv = nghttp2_adjust_local_window_size(&session->local_window_size,
                                          &session->recv_window_size,
                                          window_size_increment);
    if(rv != 0) {
      return rv;
    }
    if(!(session->opt_flags &
         NGHTTP2_OPTMASK_NO_AUTO_CONNECTION_WINDOW_UPDATE) &&
       window_size_increment < 0 &&
       nghttp2_should_send_window_update(session->local_window_size,
                                         session->recv_window_size)) {
      window_size_increment = session->recv_window_size;
      session->recv_window_size = 0;
    }
  } else {
    stream = nghttp2_session_get_stream(session, stream_id);
    if(stream) {
      if(!stream->local_flow_control) {
        return NGHTTP2_ERR_INVALID_ARGUMENT;
      }
      rv = nghttp2_adjust_local_window_size(&stream->local_window_size,
                                            &stream->recv_window_size,
                                            window_size_increment);
      if(rv != 0) {
        return rv;
      }
      if(!(session->opt_flags &
           NGHTTP2_OPTMASK_NO_AUTO_STREAM_WINDOW_UPDATE) &&
         window_size_increment < 0 &&
         nghttp2_should_send_window_update(stream->local_window_size,
                                           stream->recv_window_size)) {
        window_size_increment = stream->recv_window_size;
        stream->recv_window_size = 0;
      }
    } else {
      return NGHTTP2_ERR_STREAM_CLOSED;
    }
  }
  if(window_size_increment > 0) {
    return nghttp2_session_add_window_update(session, flags, stream_id,
                                             window_size_increment);
  }
  return 0;
}

int nghttp2_submit_request(nghttp2_session *session, int32_t pri,
                           const char **nv,
                           const nghttp2_data_provider *data_prd,
                           void *stream_user_data)
{
  uint8_t flags = NGHTTP2_FLAG_NONE;
  if(data_prd == NULL || data_prd->read_callback == NULL) {
    flags |= NGHTTP2_FLAG_END_STREAM;
  }
  if(pri != NGHTTP2_PRI_DEFAULT) {
    flags |= NGHTTP2_FLAG_PRIORITY;
  }
  return nghttp2_submit_headers_shared(session, flags, -1, pri, nv,
                                       data_prd, stream_user_data);
}

int nghttp2_submit_response(nghttp2_session *session,
                            int32_t stream_id, const char **nv,
                            const nghttp2_data_provider *data_prd)
{
  uint8_t flags = NGHTTP2_FLAG_NONE;
  if(data_prd == NULL || data_prd->read_callback == NULL) {
    flags |= NGHTTP2_FLAG_END_STREAM;
  }
  return nghttp2_submit_headers_shared(session, flags, stream_id,
                                       NGHTTP2_PRI_DEFAULT, nv, data_prd,
                                       NULL);
}

int nghttp2_submit_data(nghttp2_session *session, uint8_t flags,
                        int32_t stream_id,
                        const nghttp2_data_provider *data_prd)
{
  int r;
  nghttp2_data *data_frame;
  uint8_t nflags = 0;

  if(nghttp2_session_get_stream(session, stream_id) == NULL) {
    return NGHTTP2_ERR_STREAM_CLOSED;
  }
  data_frame = malloc(sizeof(nghttp2_frame));
  if(data_frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  if(flags & NGHTTP2_FLAG_END_STREAM) {
    nflags |= NGHTTP2_FLAG_END_STREAM;
  }
  nghttp2_frame_data_init(data_frame, nflags, stream_id, data_prd);
  r = nghttp2_session_add_frame(session, NGHTTP2_CAT_DATA, data_frame, NULL);
  if(r != 0) {
    nghttp2_frame_data_free(data_frame);
    free(data_frame);
  }
  return r;
}

ssize_t nghttp2_pack_settings_payload(uint8_t *buf,
                                      nghttp2_settings_entry *iv, size_t niv)
{
  if(!nghttp2_settings_check_duplicate(iv, niv)) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
  nghttp2_frame_iv_sort(iv, niv);
  return nghttp2_frame_pack_settings_payload(buf, iv, niv);
}
