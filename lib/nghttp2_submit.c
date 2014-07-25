/*
 * nghttp2 - HTTP/2 C Library
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
#include "nghttp2_priority_spec.h"

/* This function takes ownership of |nva_copy|. Regardless of the
   return value, the caller must not free |nva_copy| after this
   function returns. */
static int32_t submit_headers_shared
(nghttp2_session *session,
 uint8_t flags,
 int32_t stream_id,
 const nghttp2_priority_spec *pri_spec,
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
  nghttp2_headers_category hcat;

  if(stream_id == 0) {
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
    (flags & (NGHTTP2_FLAG_END_STREAM |
              NGHTTP2_FLAG_END_SEGMENT |
              NGHTTP2_FLAG_PRIORITY)) |
    NGHTTP2_FLAG_END_HEADERS;

  if(stream_id == -1) {
    if(session->next_stream_id > INT32_MAX) {
      rv = NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE;
      goto fail;
    }

    stream_id = session->next_stream_id;
    session->next_stream_id += 2;

    hcat = NGHTTP2_HCAT_REQUEST;
  } else {
    /* More specific categorization will be done later. */
    hcat = NGHTTP2_HCAT_HEADERS;
  }

  nghttp2_frame_headers_init(&frame->headers, flags_copy, stream_id,
                             hcat, pri_spec, nva_copy, nvlen);


  rv = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame,
                                 aux_data);

  if(rv != 0) {
    nghttp2_frame_headers_free(&frame->headers);
    goto fail2;
  }

  if(hcat == NGHTTP2_HCAT_REQUEST) {
    return stream_id;
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

static void adjust_priority_spec_weight(nghttp2_priority_spec *pri_spec)
{
  if(pri_spec->weight < NGHTTP2_MIN_WEIGHT) {
    pri_spec->weight = NGHTTP2_MIN_WEIGHT;
  } else if(pri_spec->weight > NGHTTP2_MAX_WEIGHT) {
    pri_spec->weight = NGHTTP2_MAX_WEIGHT;
  }
}

static int32_t submit_headers_shared_nva
(nghttp2_session *session,
 uint8_t flags,
 int32_t stream_id,
 const nghttp2_priority_spec *pri_spec,
 const nghttp2_nv *nva,
 size_t nvlen,
 const nghttp2_data_provider *data_prd,
 void *stream_user_data)
{
  int rv;
  nghttp2_nv *nva_copy;
  nghttp2_priority_spec copy_pri_spec;

  if(pri_spec) {
    copy_pri_spec = *pri_spec;
    adjust_priority_spec_weight(&copy_pri_spec);
  } else {
    nghttp2_priority_spec_default_init(&copy_pri_spec);
  }

  rv = nghttp2_nv_array_copy(&nva_copy, nva, nvlen);
  if(rv < 0) {
    return rv;
  }

  return submit_headers_shared(session, flags, stream_id,
                               &copy_pri_spec, nva_copy, nvlen, data_prd,
                               stream_user_data);
}

int32_t nghttp2_submit_headers(nghttp2_session *session, uint8_t flags,
                               int32_t stream_id,
                               const nghttp2_priority_spec *pri_spec,
                               const nghttp2_nv *nva, size_t nvlen,
                               void *stream_user_data)
{
  flags &= NGHTTP2_FLAG_END_STREAM;

  if(pri_spec && !nghttp2_priority_spec_check_default(pri_spec)) {
    flags |= NGHTTP2_FLAG_PRIORITY;
  } else {
    pri_spec = NULL;
  }

  return submit_headers_shared_nva(session, flags, stream_id, pri_spec,
                                   nva, nvlen, NULL, stream_user_data);
}


int nghttp2_submit_ping(nghttp2_session *session, uint8_t flags,
                        const uint8_t *opaque_data)
{
  return nghttp2_session_add_ping(session, NGHTTP2_FLAG_NONE, opaque_data);
}

int nghttp2_submit_priority(nghttp2_session *session, uint8_t flags,
                            int32_t stream_id,
                            const nghttp2_priority_spec *pri_spec)
{
  int rv;
  nghttp2_frame *frame;
  nghttp2_priority_spec copy_pri_spec;

  if(stream_id == 0 || pri_spec == NULL) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }

  if(stream_id == pri_spec->stream_id) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }

  copy_pri_spec = *pri_spec;

  adjust_priority_spec_weight(&copy_pri_spec);

  frame = malloc(sizeof(nghttp2_frame));

  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  nghttp2_frame_priority_init(&frame->priority, stream_id, &copy_pri_spec);

  rv = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);

  if(rv != 0) {
    nghttp2_frame_priority_free(&frame->priority);
    free(frame);

    return rv;
  }

  return 0;
}

int nghttp2_submit_rst_stream(nghttp2_session *session, uint8_t flags,
                              int32_t stream_id,
                              nghttp2_error_code error_code)
{
  if(stream_id == 0) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }

  return nghttp2_session_add_rst_stream(session, stream_id, error_code);
}

int nghttp2_submit_goaway(nghttp2_session *session, uint8_t flags,
                          int32_t last_stream_id,
                          nghttp2_error_code error_code,
                          const uint8_t *opaque_data, size_t opaque_data_len)
{
  return nghttp2_session_add_goaway(session, last_stream_id,
                                    error_code, opaque_data, opaque_data_len);
}

int nghttp2_submit_settings(nghttp2_session *session, uint8_t flags,
                            const nghttp2_settings_entry *iv, size_t niv)
{
  return nghttp2_session_add_settings(session, NGHTTP2_FLAG_NONE, iv, niv);
}

int32_t nghttp2_submit_push_promise(nghttp2_session *session, uint8_t flags,
                                    int32_t stream_id,
                                    const nghttp2_nv *nva, size_t nvlen,
                                    void *promised_stream_user_data)
{
  nghttp2_frame *frame;
  nghttp2_nv *nva_copy;
  uint8_t flags_copy;
  nghttp2_headers_aux_data *aux_data = NULL;
  int32_t promised_stream_id;
  int rv;

  if(stream_id == 0) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }

  if(!session->server) {
    return NGHTTP2_ERR_PROTO;
  }

  frame = malloc(sizeof(nghttp2_frame));
  if(frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  if(promised_stream_user_data) {
    aux_data = malloc(sizeof(nghttp2_headers_aux_data));
    if(aux_data == NULL) {
      free(frame);
      return NGHTTP2_ERR_NOMEM;
    }
    aux_data->data_prd = NULL;
    aux_data->stream_user_data = promised_stream_user_data;
  }
  rv = nghttp2_nv_array_copy(&nva_copy, nva, nvlen);
  if(rv < 0) {
    free(aux_data);
    free(frame);
    return rv;
  }

  flags_copy = NGHTTP2_FLAG_END_HEADERS;

  /* All 32bit signed stream IDs are spent. */
  if(session->next_stream_id > INT32_MAX) {
    free(aux_data);
    free(frame);

    return NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE;
  }

  promised_stream_id = session->next_stream_id;
  session->next_stream_id += 2;

  nghttp2_frame_push_promise_init(&frame->push_promise, flags_copy,
                                  stream_id, promised_stream_id,
                                  nva_copy, nvlen);

  rv = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, aux_data);

  if(rv != 0) {
    nghttp2_frame_push_promise_free(&frame->push_promise);
    free(aux_data);
    free(frame);

    return rv;
  }

  return promised_stream_id;
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
    if(!stream) {
      return 0;
    }

    rv = nghttp2_adjust_local_window_size(&stream->local_window_size,
                                          &stream->recv_window_size,
                                          &stream->recv_reduction,
                                          &window_size_increment);
    if(rv != 0) {
      return rv;
    }
  }

  if(window_size_increment > 0) {
    if(stream_id == 0) {
      session->consumed_size =
        nghttp2_max(0, session->consumed_size - window_size_increment);
    } else {
      stream->consumed_size =
        nghttp2_max(0, stream->consumed_size - window_size_increment);
    }

    return nghttp2_session_add_window_update(session, flags, stream_id,
                                             window_size_increment);
  }
  return 0;
}

int nghttp2_submit_altsvc(nghttp2_session *session, uint8_t flags,
                          int32_t stream_id,
                          uint32_t max_age, uint16_t port,
                          const uint8_t *protocol_id, size_t protocol_id_len,
                          const uint8_t *host, size_t host_len,
                          const uint8_t *origin, size_t origin_len)
{
  int rv;
  size_t varlen;
  uint8_t *var, *varp;
  nghttp2_frame *frame;
  nghttp2_ext_altsvc *altsvc;
  uint8_t *copy_protocol_id, *copy_host, *copy_origin;

  if(!session->server) {
    return NGHTTP2_ERR_PROTO;
  }

  varlen = protocol_id_len + host_len + origin_len;

  /* 9 = fixed part 8 bytes + HOST_LEN 1 byte */
  if(varlen + 9 > NGHTTP2_MAX_PAYLOADLEN) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }

  altsvc = malloc(sizeof(nghttp2_ext_altsvc));

  if(altsvc == NULL) {
    rv = NGHTTP2_ERR_NOMEM;

    goto fail;
  }

  if(varlen == 0) {
    var = NULL;
    copy_protocol_id = NULL;
    copy_host = NULL;
    copy_origin = NULL;
  } else {
    var = malloc(varlen);

    if(var == NULL) {
      rv = NGHTTP2_ERR_NOMEM;

      goto var_alloc_fail;
    }

    varp = var;

    memcpy(varp, protocol_id, protocol_id_len);

    copy_protocol_id = varp;
    varp += protocol_id_len;

    memcpy(varp, host, host_len);

    copy_host = varp;
    varp += host_len;

    memcpy(varp, origin, origin_len);

    copy_origin = varp;
  }

  frame = malloc(sizeof(nghttp2_frame));

  if(frame == NULL) {
    rv = NGHTTP2_ERR_NOMEM;

    goto frame_alloc_fail;
  }

  frame->ext.payload = altsvc;

  nghttp2_frame_altsvc_init(&frame->ext, stream_id, max_age, port,
                            copy_protocol_id, protocol_id_len,
                            copy_host, host_len, copy_origin, origin_len);

  rv = nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);

  if(rv != 0) {
    nghttp2_frame_altsvc_free(&frame->ext);
    free(frame);
    free(altsvc);

    return rv;
  }

  return 0;

 frame_alloc_fail:
  free(var);

 var_alloc_fail:
  free(altsvc);

 fail:
  return rv;
}

static uint8_t set_request_flags(const nghttp2_priority_spec *pri_spec,
                                 const nghttp2_data_provider *data_prd)
{
  uint8_t flags = NGHTTP2_FLAG_NONE;
  if(data_prd == NULL || data_prd->read_callback == NULL) {
    flags |= NGHTTP2_FLAG_END_STREAM;
  }

  if(pri_spec) {
    flags |= NGHTTP2_FLAG_PRIORITY;
  }

  return flags;
}

int32_t nghttp2_submit_request(nghttp2_session *session,
                               const nghttp2_priority_spec *pri_spec,
                               const nghttp2_nv *nva, size_t nvlen,
                               const nghttp2_data_provider *data_prd,
                               void *stream_user_data)
{
  uint8_t flags;

  if(pri_spec && nghttp2_priority_spec_check_default(pri_spec)) {
    pri_spec = NULL;
  }

  flags = set_request_flags(pri_spec, data_prd);

  return submit_headers_shared_nva(session, flags, -1, pri_spec,
                                   nva, nvlen,
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
  return submit_headers_shared_nva(session, flags, stream_id,
                                   NULL, nva, nvlen,
                                   data_prd, NULL);
}

int nghttp2_submit_data(nghttp2_session *session, uint8_t flags,
                        int32_t stream_id,
                        const nghttp2_data_provider *data_prd)
{
  int rv;
  nghttp2_private_data *data_frame;
  uint8_t nflags = flags & (NGHTTP2_FLAG_END_STREAM |
                            NGHTTP2_FLAG_END_SEGMENT);

  if(stream_id == 0) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }

  data_frame = malloc(sizeof(nghttp2_private_data));
  if(data_frame == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  nghttp2_frame_private_data_init(data_frame, nflags, stream_id, data_prd);
  rv = nghttp2_session_add_frame(session, NGHTTP2_CAT_DATA, data_frame, NULL);
  if(rv != 0) {
    nghttp2_frame_private_data_free(data_frame);
    free(data_frame);
    return rv;
  }
  return 0;
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
