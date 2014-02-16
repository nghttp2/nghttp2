/*
 * nghttp2 - HTTP/2.0 C Library
 *
 * Copyright (c) 2012, 2013 Tatsuhiro Tsujikawa
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

/* This function takes ownership of |nva_copy|. Regardless of the
   return value, the caller must not free |nva_copy| after this
   function returns. */
static int nghttp2_submit_headers_shared
(nghttp2_session *session,
 uint8_t flags,
 int32_t stream_id,
 int32_t pri,
 nghttp2_nv *nva_copy,
 size_t nvlen,
 const nghttp2_data_provider *data_prd,
 void *stream_user_data)
{
  int rv;
  uint8_t flags_copy;
  nghttp2_frame *frame = NULL;
  nghttp2_data_provider *data_prd_copy = NULL;
  nghttp2_headers_aux_data *aux_data = NULL;
  if(pri < 0) {
    rv = NGHTTP2_ERR_INVALID_ARGUMENT;
    goto fail;
  }
  if(data_prd != NULL && data_prd->read_callback != NULL) {
    data_prd_copy = malloc(sizeof(nghttp2_data_provider));
    if(data_prd_copy == NULL) {
      rv = NGHTTP2_ERR_NOMEM;
      goto fail;
    }
    *data_prd_copy = *data_prd;
  }
  if(data_prd || stream_user_data) {
    aux_data = malloc(sizeof(nghttp2_headers_aux_data));
    if(aux_data == NULL) {
      rv = NGHTTP2_ERR_NOMEM;
      goto fail;
    }
    aux_data->data_prd = data_prd_copy;
    aux_data->stream_user_data = stream_user_data;
  }
  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    rv = NGHTTP2_ERR_NOMEM;
    goto fail;
  }
  flags_copy =
    (flags & (NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_PRIORITY |
              NGHTTP2_FLAG_END_SEGMENT)) |
    NGHTTP2_FLAG_END_HEADERS;

  nghttp2_frame_headers_init(&frame->headers, flags_copy, stream_id, pri,
                             nva_copy, nvlen);
  rv = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame,
                                 aux_data);
  if(rv != 0) {
    nghttp2_frame_headers_free(&frame->headers);
    goto fail2;
  }
  return 0;
 fail:
  /* nghttp2_frame_headers_init() takes ownership of nva_copy. */
  nghttp2_nv_array_del(nva_copy);
 fail2:
  free(frame);
  free(aux_data);
  free(data_prd_copy);
  return rv;
}

static int nghttp2_submit_headers_shared_nva
(nghttp2_session *session,
 uint8_t flags,
 int32_t stream_id,
 int32_t pri,
 const nghttp2_nv *nva,
 size_t nvlen,
 const nghttp2_data_provider *data_prd,
 void *stream_user_data)
{
  ssize_t rv;
  nghttp2_nv *nva_copy;
  rv = nghttp2_nv_array_copy(&nva_copy, nva, nvlen);
  if(rv < 0) {
    return rv;
  }
  return nghttp2_submit_headers_shared(session, flags, stream_id,
                                       pri, nva_copy, rv, data_prd,
                                       stream_user_data);
}

int nghttp2_submit_headers(nghttp2_session *session, uint8_t flags,
                           int32_t stream_id, int32_t pri,
                           const nghttp2_nv *nva, size_t nvlen,
                           void *stream_user_data)
{
  return nghttp2_submit_headers_shared_nva(session, flags, stream_id, pri,
                                           nva, nvlen, NULL, stream_user_data);
}


int nghttp2_submit_ping(nghttp2_session *session, uint8_t flags,
                        uint8_t *opaque_data)
{
  return nghttp2_session_add_ping(session, NGHTTP2_FLAG_NONE, opaque_data);
}

int nghttp2_submit_priority(nghttp2_session *session, uint8_t flags,
                            int32_t stream_id, int32_t pri)
{
  int r;
  nghttp2_frame *frame;
  if(pri < 0) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
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
  return 0;
}

int nghttp2_submit_rst_stream(nghttp2_session *session, uint8_t flags,
                              int32_t stream_id,
                              nghttp2_error_code error_code)
{
  return nghttp2_session_add_rst_stream(session, stream_id, error_code);
}

int nghttp2_submit_goaway(nghttp2_session *session, uint8_t flags,
                          nghttp2_error_code error_code,
                          uint8_t *opaque_data, size_t opaque_data_len)
{
  return nghttp2_session_add_goaway(session, session->last_stream_id,
                                    error_code, opaque_data, opaque_data_len);
}

int nghttp2_submit_settings(nghttp2_session *session, uint8_t flags,
                            const nghttp2_settings_entry *iv, size_t niv)
{
  return nghttp2_session_add_settings(session, NGHTTP2_FLAG_NONE, iv, niv);
}

int nghttp2_submit_push_promise(nghttp2_session *session, uint8_t flags,
                                int32_t stream_id,
                                const nghttp2_nv *nva, size_t nvlen)
{
  nghttp2_frame *frame;
  nghttp2_nv *nva_copy;
  uint8_t flags_copy;
  int rv;

  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  rv = nghttp2_nv_array_copy(&nva_copy, nva, nvlen);
  if(rv < 0) {
    free(frame);
    return rv;
  }
  flags_copy = NGHTTP2_FLAG_END_PUSH_PROMISE;
  nghttp2_frame_push_promise_init(&frame->push_promise, flags_copy,
                                  stream_id, -1, nva_copy, nvlen);
  rv = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  if(rv != 0) {
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
  if(window_size_increment == 0) {
    return 0;
  }
  flags = 0;
  if(stream_id == 0) {
    rv = nghttp2_adjust_local_window_size(&session->local_window_size,
                                          &session->recv_window_size,
                                          &session->recv_reduction,
                                          &window_size_increment);
    if(rv != 0) {
      return rv;
    }
  } else {
    stream = nghttp2_session_get_stream(session, stream_id);
    if(stream) {
      rv = nghttp2_adjust_local_window_size(&stream->local_window_size,
                                            &stream->recv_window_size,
                                            &stream->recv_reduction,
                                            &window_size_increment);
      if(rv != 0) {
        return rv;
      }
    } else {
      return 0;
    }
  }
  if(window_size_increment > 0) {
    return nghttp2_session_add_window_update(session, flags, stream_id,
                                             window_size_increment);
  }
  return 0;
}

static uint8_t set_request_flags(int32_t pri,
                                 const nghttp2_data_provider *data_prd)
{
  uint8_t flags = NGHTTP2_FLAG_NONE;
  if(data_prd == NULL || data_prd->read_callback == NULL) {
    flags |= NGHTTP2_FLAG_END_STREAM;
  }
  if(pri != NGHTTP2_PRI_DEFAULT) {
    flags |= NGHTTP2_FLAG_PRIORITY;
  }
  return flags;
}

int nghttp2_submit_request(nghttp2_session *session, int32_t pri,
                           const nghttp2_nv *nva, size_t nvlen,
                           const nghttp2_data_provider *data_prd,
                           void *stream_user_data)
{
  uint8_t flags = set_request_flags(pri, data_prd);
  return nghttp2_submit_headers_shared_nva(session, flags, -1, pri, nva, nvlen,
                                           data_prd, stream_user_data);
}

static uint8_t set_response_flags(const nghttp2_data_provider *data_prd)
{
  uint8_t flags = NGHTTP2_FLAG_NONE;
  if(data_prd == NULL || data_prd->read_callback == NULL) {
    flags |= NGHTTP2_FLAG_END_STREAM;
  }
  return flags;
}

int nghttp2_submit_response(nghttp2_session *session,
                            int32_t stream_id,
                            const nghttp2_nv *nva, size_t nvlen,
                            const nghttp2_data_provider *data_prd)
{
  uint8_t flags = set_response_flags(data_prd);
  return nghttp2_submit_headers_shared_nva(session, flags, stream_id,
                                           NGHTTP2_PRI_DEFAULT, nva, nvlen,
                                           data_prd, NULL);
}

int nghttp2_submit_data(nghttp2_session *session, uint8_t flags,
                        int32_t stream_id,
                        const nghttp2_data_provider *data_prd)
{
  int r;
  nghttp2_private_data *data_frame;
  uint8_t nflags = 0;

  data_frame = malloc(sizeof(nghttp2_private_data));
  if(data_frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  if(flags & NGHTTP2_FLAG_END_STREAM) {
    nflags |= NGHTTP2_FLAG_END_STREAM;
  }
  nghttp2_frame_private_data_init(data_frame, nflags, stream_id, data_prd);
  r = nghttp2_session_add_frame(session, NGHTTP2_CAT_DATA, data_frame, NULL);
  if(r != 0) {
    nghttp2_frame_private_data_free(data_frame);
    free(data_frame);
  }
  return r;
}

ssize_t nghttp2_pack_settings_payload(uint8_t *buf,
                                      size_t buflen,
                                      const nghttp2_settings_entry *iv,
                                      size_t niv)
{
  if(!nghttp2_iv_check(iv, niv)) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }

  if(buflen < (niv * NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH)) {
    return NGHTTP2_ERR_INSUFF_BUFSIZE;
  }

  return nghttp2_frame_pack_settings_payload(buf, iv, niv);
}
