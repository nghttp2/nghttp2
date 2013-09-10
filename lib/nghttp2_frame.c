/*
 * nghttp2 - HTTP/2.0 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
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
#include "nghttp2_frame.h"

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#include "nghttp2_helper.h"
#include "nghttp2_net.h"

int nghttp2_frame_is_data_frame(uint8_t *head)
{
  return head[2] == 0;
}

void nghttp2_frame_pack_frame_hd(uint8_t* buf, const nghttp2_frame_hd *hd)
{
  nghttp2_put_uint16be(&buf[0], hd->length);
  buf[2]=  hd->type;
  buf[3] = hd->flags;
  nghttp2_put_uint32be(&buf[4], hd->stream_id);
}

void nghttp2_frame_unpack_frame_hd(nghttp2_frame_hd *hd, const uint8_t* buf)
{
  hd->length = nghttp2_get_uint16(&buf[0]);
  hd->type = buf[2];
  hd->flags = buf[3];
  hd->stream_id = nghttp2_get_uint32(&buf[4]) & NGHTTP2_STREAM_ID_MASK;
}

static void nghttp2_frame_set_hd(nghttp2_frame_hd *hd, uint16_t length,
                                 uint8_t type, uint8_t flags,
                                 int32_t stream_id)
{
  hd->length = length;
  hd->type = type;
  hd->flags = flags;
  hd->stream_id = stream_id;
}

void nghttp2_frame_headers_init(nghttp2_headers *frame,
                                uint8_t flags, int32_t stream_id, int32_t pri,
                                nghttp2_nv *nva, size_t nvlen)
{
  memset(frame, 0, sizeof(nghttp2_headers));
  nghttp2_frame_set_hd(&frame->hd, 0, NGHTTP2_HEADERS, flags, stream_id);
  frame->pri = pri;
  frame->nva = nva;
  frame->nvlen = nvlen;
  frame->cat = NGHTTP2_HCAT_REQUEST;
}

void nghttp2_frame_headers_free(nghttp2_headers *frame)
{
  nghttp2_nv_array_del(frame->nva);
}

void nghttp2_frame_priority_init(nghttp2_priority *frame, int32_t stream_id,
                                 int32_t pri)
{
  memset(frame, 0, sizeof(nghttp2_priority));
  nghttp2_frame_set_hd(&frame->hd, 4, NGHTTP2_PRIORITY, NGHTTP2_FLAG_NONE,
                       stream_id);
  frame->pri = pri;
}

void nghttp2_frame_priority_free(nghttp2_priority *frame)
{}

void nghttp2_frame_rst_stream_init(nghttp2_rst_stream *frame,
                                   int32_t stream_id,
                                   nghttp2_error_code error_code)
{
  memset(frame, 0, sizeof(nghttp2_rst_stream));
  nghttp2_frame_set_hd(&frame->hd, 4, NGHTTP2_RST_STREAM, NGHTTP2_FLAG_NONE,
                       stream_id);
  frame->error_code = error_code;
}

void nghttp2_frame_rst_stream_free(nghttp2_rst_stream *frame)
{}


void nghttp2_frame_settings_init(nghttp2_settings *frame,
                                 nghttp2_settings_entry *iv, size_t niv)
{
  memset(frame, 0, sizeof(nghttp2_settings));
  nghttp2_frame_set_hd(&frame->hd, niv*8, NGHTTP2_SETTINGS, NGHTTP2_FLAG_NONE,
                       0);
  frame->niv = niv;
  frame->iv = iv;
}

void nghttp2_frame_settings_free(nghttp2_settings *frame)
{
  free(frame->iv);
}

void nghttp2_frame_push_promise_init(nghttp2_push_promise *frame,
                                     uint8_t flags, int32_t stream_id,
                                     int32_t promised_stream_id,
                                     nghttp2_nv *nva, size_t nvlen)
{
  memset(frame, 0, sizeof(nghttp2_push_promise));
  nghttp2_frame_set_hd(&frame->hd, 0, NGHTTP2_PUSH_PROMISE, flags, stream_id);
  frame->promised_stream_id = promised_stream_id;
  frame->nva = nva;
  frame->nvlen = nvlen;
}

void nghttp2_frame_push_promise_free(nghttp2_push_promise *frame)
{
  nghttp2_nv_array_del(frame->nva);
}

void nghttp2_frame_ping_init(nghttp2_ping *frame, uint8_t flags,
                             const uint8_t *opaque_data)
{
  memset(frame, 0, sizeof(nghttp2_ping));
  nghttp2_frame_set_hd(&frame->hd, 8, NGHTTP2_PING, flags, 0);
  if(opaque_data) {
    memcpy(frame->opaque_data, opaque_data, sizeof(frame->opaque_data));
  }
}

void nghttp2_frame_ping_free(nghttp2_ping *frame)
{}

void nghttp2_frame_goaway_init(nghttp2_goaway *frame, int32_t last_stream_id,
                               nghttp2_error_code error_code,
                               uint8_t *opaque_data, size_t opaque_data_len)
{
  memset(frame, 0, sizeof(nghttp2_goaway));
  nghttp2_frame_set_hd(&frame->hd, 8+opaque_data_len, NGHTTP2_GOAWAY,
                       NGHTTP2_FLAG_NONE, 0);
  frame->last_stream_id = last_stream_id;
  frame->error_code = error_code;
  frame->opaque_data = opaque_data;
  frame->opaque_data_len = opaque_data_len;
}

void nghttp2_frame_goaway_free(nghttp2_goaway *frame)
{
  free(frame->opaque_data);
}

void nghttp2_frame_window_update_init(nghttp2_window_update *frame,
                                      uint8_t flags,
                                      int32_t stream_id,
                                      int32_t window_size_increment)
{
  memset(frame, 0, sizeof(nghttp2_window_update));
  nghttp2_frame_set_hd(&frame->hd, 4, NGHTTP2_WINDOW_UPDATE, flags, stream_id);
  frame->window_size_increment = window_size_increment;
}

void nghttp2_frame_window_update_free(nghttp2_window_update *frame)
{}

void nghttp2_frame_data_init(nghttp2_data *frame, uint8_t flags,
                             int32_t stream_id,
                             const nghttp2_data_provider *data_prd)
{
  memset(frame, 0, sizeof(nghttp2_data));
  /* At this moment, the length of DATA frame is unknown */
  nghttp2_frame_set_hd(&frame->hd, 0, NGHTTP2_DATA, flags, stream_id);
  frame->data_prd = *data_prd;
}

void nghttp2_frame_data_free(nghttp2_data *frame)
{}

/*
 * Returns the offset of the name/header block in the HEADERS frame,
 * including frame header length.
 */
static size_t headers_nv_offset(nghttp2_headers *frame)
{
  if(frame->hd.flags & NGHTTP2_FLAG_PRIORITY) {
    return NGHTTP2_FRAME_HEAD_LENGTH + 4;
  } else {
    return NGHTTP2_FRAME_HEAD_LENGTH;
  }
}

ssize_t nghttp2_frame_pack_headers(uint8_t **buf_ptr,
                                   size_t *buflen_ptr,
                                   nghttp2_headers *frame,
                                   nghttp2_hd_context *deflater)
{
  ssize_t framelen;
  size_t nv_offset = headers_nv_offset(frame);
  ssize_t rv;
  rv = nghttp2_hd_deflate_hd(deflater, buf_ptr, buflen_ptr, nv_offset,
                             frame->nva, frame->nvlen);
  if(rv < 0) {
    return rv;
  }
  framelen = rv + nv_offset;
  frame->hd.length = framelen - NGHTTP2_FRAME_HEAD_LENGTH;
  /* If frame->nvlen == 0, *buflen_ptr may be smaller than
     nv_offset */
  rv = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, nv_offset);
  if(rv < 0) {
    return rv;
  }
  memset(*buf_ptr, 0, nv_offset);
  /* pack ctrl header after length is determined */
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  if(frame->hd.flags & NGHTTP2_FLAG_PRIORITY) {
    nghttp2_put_uint32be(&(*buf_ptr)[8], frame->pri);
  }
  return framelen;
}

int nghttp2_frame_unpack_headers(nghttp2_headers *frame,
                                 const uint8_t *head, size_t headlen,
                                 const uint8_t *payload, size_t payloadlen,
                                 nghttp2_hd_context *inflater)
{
  ssize_t r;
  size_t pnv_offset;
  r = nghttp2_frame_unpack_headers_without_nv(frame, head, headlen,
                                              payload, payloadlen);
  if(r < 0) {
    return r;
  }
  pnv_offset = headers_nv_offset(frame) - NGHTTP2_FRAME_HEAD_LENGTH;
  r = nghttp2_hd_inflate_hd(inflater, &frame->nva,
                            (uint8_t*)payload + pnv_offset,
                            payloadlen - pnv_offset);
  if(r < 0) {
    return r;
  }
  frame->nvlen = r;
  return 0;
}

int nghttp2_frame_unpack_headers_without_nv(nghttp2_headers *frame,
                                            const uint8_t *head,
                                            size_t headlen,
                                            const uint8_t *payload,
                                            size_t payloadlen)
{
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  /* TODO Return error if header continuation is used for now */
  if((head[3] & NGHTTP2_FLAG_END_HEADERS) == 0) {
    return NGHTTP2_ERR_PROTO;
  }
  if(head[3] & NGHTTP2_FLAG_PRIORITY) {
    if(payloadlen < 4) {
      return NGHTTP2_ERR_INVALID_FRAME;
    }
    frame->pri = nghttp2_get_uint32(payload) & NGHTTP2_PRIORITY_MASK;
  } else {
    frame->pri = NGHTTP2_PRI_DEFAULT;
  }
  frame->nva = NULL;
  frame->nvlen = 0;
  return 0;
}

ssize_t nghttp2_frame_pack_priority(uint8_t **buf_ptr, size_t *buflen_ptr,
                                    nghttp2_priority *frame)
{
  ssize_t framelen= NGHTTP2_FRAME_HEAD_LENGTH + 4;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->pri);
  return framelen;
}

int nghttp2_frame_unpack_priority(nghttp2_priority *frame,
                                  const uint8_t *head, size_t headlen,
                                  const uint8_t *payload, size_t payloadlen)
{
  if(payloadlen != 4) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  frame->pri = nghttp2_get_uint32(payload) & NGHTTP2_PRIORITY_MASK;
  return 0;

}

ssize_t nghttp2_frame_pack_rst_stream(uint8_t **buf_ptr, size_t *buflen_ptr,
                                      nghttp2_rst_stream *frame)
{
  ssize_t framelen = NGHTTP2_FRAME_HEAD_LENGTH + 4;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->error_code);
  return framelen;
}

int nghttp2_frame_unpack_rst_stream(nghttp2_rst_stream *frame,
                                    const uint8_t *head, size_t headlen,
                                    const uint8_t *payload, size_t payloadlen)
{
  if(payloadlen != 4) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  frame->error_code = nghttp2_get_uint32(payload);
  return 0;
}

ssize_t nghttp2_frame_pack_settings(uint8_t **buf_ptr, size_t *buflen_ptr,
                                    nghttp2_settings *frame)
{
  ssize_t framelen = NGHTTP2_FRAME_HEAD_LENGTH + frame->hd.length;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  nghttp2_frame_pack_settings_payload(*buf_ptr + 8, frame->iv, frame->niv);
  return framelen;
}

size_t nghttp2_frame_pack_settings_payload(uint8_t *buf,
                                           const nghttp2_settings_entry *iv,
                                           size_t niv)
{
  size_t i;
  for(i = 0; i < niv; ++i, buf += 8) {
    nghttp2_put_uint32be(buf, iv[i].settings_id);
    nghttp2_put_uint32be(buf + 4, iv[i].value);
  }
  return 8 * niv;
}

int nghttp2_frame_unpack_settings(nghttp2_settings *frame,
                                  const uint8_t *head, size_t headlen,
                                  const uint8_t *payload, size_t payloadlen)
{
  int rv;
  if(payloadlen % 8) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  rv = nghttp2_frame_unpack_settings_payload(&frame->iv, &frame->niv,
                                             payload, payloadlen);
  if(rv != 0) {
    return rv;
  }
  return 0;
}

int nghttp2_frame_unpack_settings_payload(nghttp2_settings_entry **iv_ptr,
                                          size_t *niv_ptr,
                                          const uint8_t *payload,
                                          size_t payloadlen)
{
  size_t i;
  *niv_ptr = payloadlen / 8;
  *iv_ptr = malloc((*niv_ptr)*sizeof(nghttp2_settings_entry));
  if(*iv_ptr == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  for(i = 0; i < *niv_ptr; ++i) {
    size_t off = i*8;
    (*iv_ptr)[i].settings_id = nghttp2_get_uint32(&payload[off]) &
      NGHTTP2_SETTINGS_ID_MASK;
    (*iv_ptr)[i].value = nghttp2_get_uint32(&payload[4+off]);
  }
  return 0;
}

ssize_t nghttp2_frame_pack_push_promise(uint8_t **buf_ptr,
                                        size_t *buflen_ptr,
                                        nghttp2_push_promise *frame,
                                        nghttp2_hd_context *deflater)
{
  ssize_t framelen;
  size_t nv_offset = NGHTTP2_FRAME_HEAD_LENGTH + 4;
  ssize_t rv;
  rv = nghttp2_hd_deflate_hd(deflater, buf_ptr, buflen_ptr, nv_offset,
                             frame->nva, frame->nvlen);
  if(rv < 0) {
    return rv;
  }
  framelen = rv + nv_offset;
  frame->hd.length = framelen - NGHTTP2_FRAME_HEAD_LENGTH;
  /* If frame->nvlen == 0, *buflen_ptr may be smaller than
     nv_offset */
  rv = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, nv_offset);
  if(rv < 0) {
    return rv;
  }
  memset(*buf_ptr, 0, nv_offset);
  /* pack ctrl header after length is determined */
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->promised_stream_id);
  return framelen;
}

int nghttp2_frame_unpack_push_promise(nghttp2_push_promise *frame,
                                      const uint8_t *head, size_t headlen,
                                      const uint8_t *payload,
                                      size_t payloadlen,
                                      nghttp2_hd_context *inflater)
{
  ssize_t r;
  r = nghttp2_frame_unpack_push_promise_without_nv(frame, head, headlen,
                                                   payload, payloadlen);
  if(r < 0) {
    return r;
  }
  r = nghttp2_hd_inflate_hd(inflater, &frame->nva,
                            (uint8_t*)payload + 4, payloadlen - 4);
  if(r < 0) {
    return r;
  }
  frame->nvlen = r;
  return 0;
}

int nghttp2_frame_unpack_push_promise_without_nv(nghttp2_push_promise *frame,
                                                 const uint8_t *head,
                                                 size_t headlen,
                                                 const uint8_t *payload,
                                                 size_t payloadlen)
{
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  /* TODO Return error if header continuation is used for now */
  if((head[3] & NGHTTP2_FLAG_END_PUSH_PROMISE) == 0) {
    return NGHTTP2_ERR_PROTO;
  }
  if(payloadlen < 4) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  frame->promised_stream_id = nghttp2_get_uint32(payload) &
    NGHTTP2_STREAM_ID_MASK;
  frame->nva = NULL;
  frame->nvlen = 0;
  return 0;
}

ssize_t nghttp2_frame_pack_ping(uint8_t **buf_ptr, size_t *buflen_ptr,
                                nghttp2_ping *frame)
{
  ssize_t framelen = NGHTTP2_FRAME_HEAD_LENGTH + 8;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  memcpy(&(*buf_ptr)[8], frame->opaque_data, sizeof(frame->opaque_data));
  return framelen;
}

int nghttp2_frame_unpack_ping(nghttp2_ping *frame,
                              const uint8_t *head, size_t headlen,
                              const uint8_t *payload, size_t payloadlen)
{
  if(payloadlen != 8) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  memcpy(frame->opaque_data, payload, sizeof(frame->opaque_data));
  return 0;
}


ssize_t nghttp2_frame_pack_goaway(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  nghttp2_goaway *frame)
{
  ssize_t framelen = NGHTTP2_FRAME_HEAD_LENGTH + frame->hd.length;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->last_stream_id);
  nghttp2_put_uint32be(&(*buf_ptr)[12], frame->error_code);
  memcpy(&(*buf_ptr)[16], frame->opaque_data, frame->opaque_data_len);
  return framelen;
}

int nghttp2_frame_unpack_goaway(nghttp2_goaway *frame,
                                const uint8_t *head, size_t headlen,
                                const uint8_t *payload, size_t payloadlen)
{
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  if(payloadlen < 8) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  frame->last_stream_id = nghttp2_get_uint32(payload) & NGHTTP2_STREAM_ID_MASK;
  frame->error_code = nghttp2_get_uint32(payload+4);
  frame->opaque_data_len = payloadlen - 8;
  if(frame->opaque_data_len == 0) {
    frame->opaque_data = NULL;
  } else {
    frame->opaque_data = malloc(frame->opaque_data_len);
    if(frame->opaque_data == NULL) {
      return NGHTTP2_ERR_NOMEM;
    }
    memcpy(frame->opaque_data, &payload[8], frame->opaque_data_len);
  }
  return 0;
}

ssize_t nghttp2_frame_pack_window_update(uint8_t **buf_ptr, size_t *buflen_ptr,
                                         nghttp2_window_update *frame)
{
  ssize_t framelen = NGHTTP2_FRAME_HEAD_LENGTH + 4;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->window_size_increment);
  return framelen;
}

int nghttp2_frame_unpack_window_update(nghttp2_window_update *frame,
                                       const uint8_t *head, size_t headlen,
                                       const uint8_t *payload,
                                       size_t payloadlen)
{
  if(payloadlen != 4) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  frame->window_size_increment = nghttp2_get_uint32(payload) &
    NGHTTP2_WINDOW_SIZE_INCREMENT_MASK;
  return 0;
}

nghttp2_settings_entry* nghttp2_frame_iv_copy(const nghttp2_settings_entry *iv,
                                              size_t niv)
{
  nghttp2_settings_entry *iv_copy;
  size_t len = niv*sizeof(nghttp2_settings_entry);
  iv_copy = malloc(len);
  if(iv_copy == NULL) {
    return NULL;
  }
  memcpy(iv_copy, iv, len);
  return iv_copy;
}

int nghttp2_frame_nv_check_null(const char **nv)
{
  size_t i;
  for(i = 0; nv[i]; i += 2) {
    if(nv[i+1] == NULL ||
       !nghttp2_check_header_name_nocase((const uint8_t*)nv[i],
                                         strlen(nv[i]))) {
      return 0;
    }
  }
  return 1;
}

int nghttp2_nv_array_check_null(const nghttp2_nv *nva, size_t nvlen)
{
  size_t i;
  for(i = 0; i < nvlen; ++i) {
    if(!nghttp2_check_header_name_nocase(nva[i].name, nva[i].namelen)) {
      return 0;
    }
  }
  return 1;
}

int nghttp2_nv_equal(const nghttp2_nv *a, const nghttp2_nv *b)
{
  return a->namelen == b->namelen && a->valuelen == b->valuelen &&
    memcmp(a->name, b->name, a->namelen) == 0 &&
    memcmp(a->value, b->value, a->valuelen) == 0;
}

void nghttp2_nv_array_del(nghttp2_nv *nva)
{
  free(nva);
}

static int nghttp2_nv_name_compar(const void *lhs, const void *rhs)
{
  nghttp2_nv *a = (nghttp2_nv*)lhs, *b = (nghttp2_nv*)rhs;
  if(a->namelen == b->namelen) {
    return memcmp(a->name, b->name, a->namelen);
  } else if(a->namelen < b->namelen) {
    int rv = memcmp(a->name, b->name, a->namelen);
    if(rv == 0) {
      return -1;
    } else {
      return rv;
    }
  } else {
    int rv = memcmp(a->name, b->name, b->namelen);
    if(rv == 0) {
      return 1;
    } else {
      return rv;
    }
  }
}

int nghttp2_nv_compare_name(const nghttp2_nv *lhs, const nghttp2_nv *rhs)
{
  return nghttp2_nv_name_compar(lhs, rhs);
}

void nghttp2_nv_array_sort(nghttp2_nv *nva, size_t nvlen)
{
  qsort(nva, nvlen, sizeof(nghttp2_nv), nghttp2_nv_name_compar);
}

ssize_t nghttp2_nv_array_from_cstr(nghttp2_nv **nva_ptr, const char **nv)
{
  int i;
  uint8_t *data;
  size_t buflen = 0, nvlen = 0;
  nghttp2_nv *p;
  for(i = 0; nv[i]; ++i) {
    size_t len = strlen(nv[i]);
    if(len > NGHTTP2_MAX_HD_VALUE_LENGTH) {
      return NGHTTP2_ERR_INVALID_ARGUMENT;
    }
    buflen += len;
  }
  nvlen = i/2;
  /* If all name/value pair is 0-length, remove them */
  if(nvlen == 0 || buflen == 0) {
    *nva_ptr = NULL;
    return 0;
  }
  buflen += sizeof(nghttp2_nv)*nvlen;
  *nva_ptr = malloc(buflen);
  if(*nva_ptr == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  p = *nva_ptr;
  data = (uint8_t*)(*nva_ptr) + sizeof(nghttp2_nv)*nvlen;

  for(i = 0; nv[i]; i += 2) {
    size_t len = strlen(nv[i]);
    memcpy(data, nv[i], len);
    p->name = data;
    p->namelen = len;
    nghttp2_downcase(p->name, p->namelen);
    data += len;
    len = strlen(nv[i+1]);
    memcpy(data, nv[i+1], len);
    p->value = data;
    p->valuelen = len;
    data += len;
    ++p;
  }
  nghttp2_nv_array_sort(*nva_ptr, nvlen);
  return nvlen;
}

ssize_t nghttp2_nv_array_copy(nghttp2_nv **nva_ptr,
                              const nghttp2_nv *nva, size_t nvlen)
{
  size_t i;
  uint8_t *data;
  size_t buflen = 0;
  nghttp2_nv *p;
  for(i = 0; i < nvlen; ++i) {
    if(nva[i].namelen > NGHTTP2_MAX_HD_VALUE_LENGTH ||
       nva[i].valuelen > NGHTTP2_MAX_HD_VALUE_LENGTH) {
      return NGHTTP2_ERR_INVALID_ARGUMENT;
    }
    buflen += nva[i].namelen + nva[i].valuelen;
  }
  /* If all name/value pair is 0-length, remove them */
  if(nvlen == 0 || buflen == 0) {
    *nva_ptr = NULL;
    return 0;
  }
  buflen += sizeof(nghttp2_nv)*nvlen;
  *nva_ptr = malloc(buflen);
  if(*nva_ptr == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  p = *nva_ptr;
  data = (uint8_t*)(*nva_ptr) + sizeof(nghttp2_nv)*nvlen;

  for(i = 0; i < nvlen; ++i) {
    memcpy(data, nva[i].name, nva[i].namelen);
    p->name = data;
    p->namelen = nva[i].namelen;
    nghttp2_downcase(p->name, p->namelen);
    data += nva[i].namelen;
    memcpy(data, nva[i].value, nva[i].valuelen);
    p->value = data;
    p->valuelen = nva[i].valuelen;
    data += nva[i].valuelen;
    ++p;
  }
  nghttp2_nv_array_sort(*nva_ptr, nvlen);
  return nvlen;
}

int nghttp2_iv_check(const nghttp2_settings_entry *iv, size_t niv,
                     int32_t flow_control_opt)
{
  size_t i;
  for(i = 0; i < niv; ++i) {
    switch(iv[i].settings_id) {
    case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
      if(iv[i].value > (uint32_t)NGHTTP2_MAX_WINDOW_SIZE) {
        return 0;
      }
      break;
    case NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS:
      if(flow_control_opt) {
        if((iv[i].value & 0x1) == 0) {
          /* Attempt to re-enabling flow-control is error */
          return 0;
        }
      } else {
        flow_control_opt = iv[i].value & 0x1;
      }
    default:
      break;
    }
  }
  return 1;
}
