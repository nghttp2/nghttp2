/*
 * nghttp2 - HTTP/2 C Library
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
#include "nghttp2_priority_spec.h"

int nghttp2_frame_is_data_frame(uint8_t *head)
{
  return head[2] == 0;
}

void nghttp2_frame_pack_frame_hd(uint8_t* buf, const nghttp2_frame_hd *hd)
{
  nghttp2_put_uint32be(&buf[0], (uint32_t)(hd->length << 8));
  buf[3]=  hd->type;
  buf[4] = hd->flags;
  nghttp2_put_uint32be(&buf[5], hd->stream_id);
}

void nghttp2_frame_unpack_frame_hd(nghttp2_frame_hd *hd, const uint8_t* buf)
{
  hd->length = nghttp2_get_uint32(&buf[0]) >> 8;
  hd->type = buf[3];
  hd->flags = buf[4];
  hd->stream_id = nghttp2_get_uint32(&buf[5]) & NGHTTP2_STREAM_ID_MASK;
}

static void frame_set_hd(nghttp2_frame_hd *hd, size_t length,
                         uint8_t type, uint8_t flags,
                         int32_t stream_id)
{
  hd->length = length;
  hd->type = type;
  hd->flags = flags;
  hd->stream_id = stream_id;
}

void nghttp2_frame_headers_init(nghttp2_headers *frame,
                                uint8_t flags, int32_t stream_id,
                                nghttp2_headers_category cat,
                                const nghttp2_priority_spec *pri_spec,
                                nghttp2_nv *nva, size_t nvlen)
{
  frame_set_hd(&frame->hd, 0, NGHTTP2_HEADERS, flags, stream_id);
  frame->padlen = 0;
  frame->nva = nva;
  frame->nvlen = nvlen;
  frame->cat = cat;

  if(pri_spec) {
    frame->pri_spec = *pri_spec;
  } else {
    nghttp2_priority_spec_default_init(&frame->pri_spec);
  }
}

void nghttp2_frame_headers_free(nghttp2_headers *frame)
{
  nghttp2_nv_array_del(frame->nva);
}

void nghttp2_frame_priority_init(nghttp2_priority *frame, int32_t stream_id,
                                 const nghttp2_priority_spec *pri_spec)
{
  frame_set_hd(&frame->hd, NGHTTP2_PRIORITY_SPECLEN, NGHTTP2_PRIORITY,
               NGHTTP2_FLAG_NONE, stream_id);
  frame->pri_spec = *pri_spec;
}

void nghttp2_frame_priority_free(nghttp2_priority *frame)
{}

void nghttp2_frame_rst_stream_init(nghttp2_rst_stream *frame,
                                   int32_t stream_id,
                                   nghttp2_error_code error_code)
{
  frame_set_hd(&frame->hd, 4, NGHTTP2_RST_STREAM, NGHTTP2_FLAG_NONE,
               stream_id);
  frame->error_code = error_code;
}

void nghttp2_frame_rst_stream_free(nghttp2_rst_stream *frame)
{}


void nghttp2_frame_settings_init(nghttp2_settings *frame, uint8_t flags,
                                 nghttp2_settings_entry *iv, size_t niv)
{
  frame_set_hd(&frame->hd, niv * NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH,
               NGHTTP2_SETTINGS, flags, 0);
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
  frame_set_hd(&frame->hd, 0, NGHTTP2_PUSH_PROMISE, flags, stream_id);
  frame->padlen = 0;
  frame->nva = nva;
  frame->nvlen = nvlen;
  frame->promised_stream_id = promised_stream_id;
}

void nghttp2_frame_push_promise_free(nghttp2_push_promise *frame)
{
  nghttp2_nv_array_del(frame->nva);
}

void nghttp2_frame_ping_init(nghttp2_ping *frame, uint8_t flags,
                             const uint8_t *opaque_data)
{
  frame_set_hd(&frame->hd, 8, NGHTTP2_PING, flags, 0);
  if(opaque_data) {
    memcpy(frame->opaque_data, opaque_data, sizeof(frame->opaque_data));
  } else {
    memset(frame->opaque_data, 0, sizeof(frame->opaque_data));
  }
}

void nghttp2_frame_ping_free(nghttp2_ping *frame)
{}

void nghttp2_frame_goaway_init(nghttp2_goaway *frame, int32_t last_stream_id,
                               nghttp2_error_code error_code,
                               uint8_t *opaque_data, size_t opaque_data_len)
{
  frame_set_hd(&frame->hd, 8+opaque_data_len, NGHTTP2_GOAWAY,
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
  frame_set_hd(&frame->hd, 4, NGHTTP2_WINDOW_UPDATE, flags, stream_id);
  frame->window_size_increment = window_size_increment;
}

void nghttp2_frame_window_update_free(nghttp2_window_update *frame)
{}

void nghttp2_frame_altsvc_init(nghttp2_extension *frame, int32_t stream_id,
                               uint32_t max_age,
                               uint16_t port,
                               uint8_t *protocol_id,
                               size_t protocol_id_len,
                               uint8_t *host, size_t host_len,
                               uint8_t *origin, size_t origin_len)
{
  size_t payloadlen;
  nghttp2_ext_altsvc *altsvc;

  altsvc = frame->payload;

  payloadlen = NGHTTP2_ALTSVC_MINLEN + protocol_id_len + host_len + origin_len;

  frame_set_hd(&frame->hd, payloadlen, NGHTTP2_EXT_ALTSVC, NGHTTP2_FLAG_NONE,
               stream_id);

  altsvc->max_age = max_age;
  altsvc->port = port;
  altsvc->protocol_id = protocol_id;
  altsvc->protocol_id_len = protocol_id_len;
  altsvc->host = host;
  altsvc->host_len = host_len;
  altsvc->origin = origin;
  altsvc->origin_len = origin_len;
}

void nghttp2_frame_altsvc_free(nghttp2_extension *frame)
{
  nghttp2_ext_altsvc *altsvc;

  altsvc = frame->payload;

  if(altsvc == NULL) {
    return;
  }

  free(altsvc->protocol_id);
}

void nghttp2_frame_data_init(nghttp2_data *frame, nghttp2_private_data *pdata)
{
  frame->hd = pdata->hd;
  frame->padlen = pdata->padlen;
  /* flags may have NGHTTP2_FLAG_END_STREAM or
     NGHTTP2_FLAG_END_SEGMENT even if the sent chunk is not the end of
     the stream */
  if(!pdata->eof) {
    frame->hd.flags &= ~(NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_SEGMENT);
  }
}

size_t nghttp2_frame_trail_padlen(nghttp2_frame *frame, size_t padlen)
{
  return padlen - ((frame->hd.flags & NGHTTP2_FLAG_PADDED) > 0);
}

void nghttp2_frame_private_data_init(nghttp2_private_data *frame,
                                     uint8_t flags,
                                     int32_t stream_id,
                                     const nghttp2_data_provider *data_prd)
{
  /* At this moment, the length of DATA frame is unknown */
  frame_set_hd(&frame->hd, 0, NGHTTP2_DATA, flags, stream_id);
  frame->data_prd = *data_prd;
  frame->padlen = 0;
  frame->eof = 0;
}

void nghttp2_frame_private_data_free(nghttp2_private_data *frame)
{}

size_t nghttp2_frame_priority_len(uint8_t flags)
{
  if(flags & NGHTTP2_FLAG_PRIORITY) {
    return NGHTTP2_PRIORITY_SPECLEN;
  }

  return 0;
}

size_t nghttp2_frame_headers_payload_nv_offset(nghttp2_headers *frame)
{
  return nghttp2_frame_priority_len(frame->hd.flags);
}

/*
 * Call this function after payload was serialized, but not before
 * changing buf->pos and serializing frame header.
 *
 * This function assumes bufs->cur points to the last buf chain of the
 * frame(s).
 *
 * This function serializes frame header for HEADERS/PUSH_PROMISE and
 * handles their successive CONTINUATION frames.
 *
 * We don't process any padding here.
 */
static int frame_pack_headers_shared(nghttp2_bufs *bufs,
                                     nghttp2_frame_hd *frame_hd)
{
  nghttp2_buf *buf;
  nghttp2_buf_chain *ci, *ce;
  nghttp2_frame_hd hd;

  buf = &bufs->head->buf;

  hd = *frame_hd;
  hd.length = nghttp2_buf_len(buf);

  DEBUGF(fprintf(stderr,
                 "send: HEADERS/PUSH_PROMISE, payloadlen=%zu\n", hd.length));

  /* We have multiple frame buffers, which means one or more
     CONTINUATION frame is involved. Remove END_HEADERS flag from the
     first frame. */
  if(bufs->head != bufs->cur) {
    hd.flags &= ~NGHTTP2_FLAG_END_HEADERS;
  }

  buf->pos -= NGHTTP2_FRAME_HDLEN;
  nghttp2_frame_pack_frame_hd(buf->pos, &hd);

  if(bufs->head != bufs->cur) {
    /* 2nd and later frames are CONTINUATION frames. */
    hd.type = NGHTTP2_CONTINUATION;
    /* We don't have no flags except for last CONTINUATION */
    hd.flags = NGHTTP2_FLAG_NONE;

    ce = bufs->cur;

    for(ci = bufs->head->next; ci != ce; ci = ci->next) {
      buf = &ci->buf;

      hd.length = nghttp2_buf_len(buf);

      DEBUGF(fprintf(stderr,
                     "send: int CONTINUATION, payloadlen=%zu\n", hd.length));

      buf->pos -= NGHTTP2_FRAME_HDLEN;
      nghttp2_frame_pack_frame_hd(buf->pos, &hd);
    }

    buf = &ci->buf;
    hd.length = nghttp2_buf_len(buf);
    /* Set END_HEADERS flag for last CONTINUATION */
    hd.flags = NGHTTP2_FLAG_END_HEADERS;

    DEBUGF(fprintf(stderr,
                   "send: last CONTINUATION, payloadlen=%zu\n", hd.length));

    buf->pos -= NGHTTP2_FRAME_HDLEN;
    nghttp2_frame_pack_frame_hd(buf->pos, &hd);
  }

  return 0;
}

int nghttp2_frame_pack_headers(nghttp2_bufs *bufs,
                               nghttp2_headers *frame,
                               nghttp2_hd_deflater *deflater)
{
  size_t nv_offset;
  int rv;
  nghttp2_buf *buf;

  assert(bufs->head == bufs->cur);

  nv_offset = nghttp2_frame_headers_payload_nv_offset(frame);

  buf = &bufs->cur->buf;

  buf->pos += nv_offset;
  buf->last = buf->pos;

  /* This call will adjust buf->last to the correct position */
  rv = nghttp2_hd_deflate_hd_bufs(deflater, bufs, frame->nva, frame->nvlen);

  if(rv == NGHTTP2_ERR_BUFFER_ERROR) {
    rv = NGHTTP2_ERR_HEADER_COMP;
  }

  buf->pos -= nv_offset;

  if(rv != 0) {
    return rv;
  }

  if(frame->hd.flags & NGHTTP2_FLAG_PRIORITY) {
    nghttp2_frame_pack_priority_spec(buf->pos, &frame->pri_spec);
  }

  frame->padlen = 0;
  frame->hd.length = nghttp2_bufs_len(bufs);

  return frame_pack_headers_shared(bufs, &frame->hd);
}

void nghttp2_frame_pack_priority_spec(uint8_t *buf,
                                      const nghttp2_priority_spec *pri_spec)
{
  nghttp2_put_uint32be(buf, pri_spec->stream_id);
  if(pri_spec->exclusive) {
    buf[0] |= 0x80;
  }
  buf[4] = pri_spec->weight - 1;
}

void nghttp2_frame_unpack_priority_spec(nghttp2_priority_spec *pri_spec,
                                        uint8_t flags,
                                        const uint8_t *payload,
                                        size_t payloadlen)
{
  int32_t dep_stream_id;
  uint8_t exclusive;
  int32_t weight;

  dep_stream_id = nghttp2_get_uint32(payload) & NGHTTP2_STREAM_ID_MASK;
  exclusive = (payload[0] & 0x80) > 0;
  weight = payload[4] + 1;

  nghttp2_priority_spec_init(pri_spec, dep_stream_id, weight, exclusive);
}

int nghttp2_frame_unpack_headers_payload(nghttp2_headers *frame,
                                         const uint8_t *payload,
                                         size_t payloadlen)
{
  if(frame->hd.flags & NGHTTP2_FLAG_PRIORITY) {
    nghttp2_frame_unpack_priority_spec(&frame->pri_spec, frame->hd.flags,
                                       payload, payloadlen);
  } else {
    nghttp2_priority_spec_default_init(&frame->pri_spec);
  }

  frame->nva = NULL;
  frame->nvlen = 0;

  return 0;
}

int nghttp2_frame_pack_priority(nghttp2_bufs *bufs, nghttp2_priority *frame)
{
  nghttp2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->head->buf;

  assert(nghttp2_buf_avail(buf) >= NGHTTP2_PRIORITY_SPECLEN);

  buf->pos -= NGHTTP2_FRAME_HDLEN;

  nghttp2_frame_pack_frame_hd(buf->pos, &frame->hd);

  nghttp2_frame_pack_priority_spec(buf->last, &frame->pri_spec);

  buf->last += NGHTTP2_PRIORITY_SPECLEN;

  return 0;
}

void nghttp2_frame_unpack_priority_payload(nghttp2_priority *frame,
                                           const uint8_t *payload,
                                           size_t payloadlen)
{
  nghttp2_frame_unpack_priority_spec(&frame->pri_spec, frame->hd.flags,
                                     payload, payloadlen);
}

int nghttp2_frame_pack_rst_stream(nghttp2_bufs *bufs,
                                  nghttp2_rst_stream *frame)
{
  nghttp2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->head->buf;

  assert(nghttp2_buf_avail(buf) >= 4);

  buf->pos -= NGHTTP2_FRAME_HDLEN;

  nghttp2_frame_pack_frame_hd(buf->pos, &frame->hd);

  nghttp2_put_uint32be(buf->last, frame->error_code);
  buf->last += 4;

  return 0;
}

static nghttp2_error_code normalize_error_code(uint32_t error_code)
{
  switch(error_code) {
  case NGHTTP2_NO_ERROR:
  case NGHTTP2_PROTOCOL_ERROR:
  case NGHTTP2_INTERNAL_ERROR:
  case NGHTTP2_FLOW_CONTROL_ERROR:
  case NGHTTP2_SETTINGS_TIMEOUT:
  case NGHTTP2_STREAM_CLOSED:
  case NGHTTP2_FRAME_SIZE_ERROR:
  case NGHTTP2_REFUSED_STREAM:
  case NGHTTP2_CANCEL:
  case NGHTTP2_COMPRESSION_ERROR:
  case NGHTTP2_CONNECT_ERROR:
  case NGHTTP2_ENHANCE_YOUR_CALM:
  case NGHTTP2_INADEQUATE_SECURITY:
    return error_code;
  default:
    return NGHTTP2_INTERNAL_ERROR;
  }
}

void nghttp2_frame_unpack_rst_stream_payload(nghttp2_rst_stream *frame,
                                             const uint8_t *payload,
                                             size_t payloadlen)
{
  frame->error_code = normalize_error_code(nghttp2_get_uint32(payload));
}

int nghttp2_frame_pack_settings(nghttp2_bufs *bufs, nghttp2_settings *frame)
{
  nghttp2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->head->buf;

  if(nghttp2_buf_avail(buf) < (ssize_t)frame->hd.length) {
    return NGHTTP2_ERR_FRAME_SIZE_ERROR;
  }

  buf->pos -= NGHTTP2_FRAME_HDLEN;

  nghttp2_frame_pack_frame_hd(buf->pos, &frame->hd);

  buf->last += nghttp2_frame_pack_settings_payload(buf->last,
                                                   frame->iv, frame->niv);

  return 0;
}

size_t nghttp2_frame_pack_settings_payload(uint8_t *buf,
                                           const nghttp2_settings_entry *iv,
                                           size_t niv)
{
  size_t i;
  for(i = 0; i < niv; ++i, buf += NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH) {
    nghttp2_put_uint16be(buf, iv[i].settings_id);
    nghttp2_put_uint32be(buf + 2, iv[i].value);
  }
  return NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH * niv;
}

int nghttp2_frame_unpack_settings_payload(nghttp2_settings *frame,
                                          nghttp2_settings_entry *iv,
                                          size_t niv)
{
  size_t payloadlen = niv * sizeof(nghttp2_settings_entry);

  if(niv == 0) {
    frame->iv = NULL;
  } else {
    frame->iv = malloc(payloadlen);

    if(frame->iv == NULL) {
      return NGHTTP2_ERR_NOMEM;
    }

    memcpy(frame->iv, iv, payloadlen);
  }

  frame->niv = niv;
  return 0;
}

void nghttp2_frame_unpack_settings_entry(nghttp2_settings_entry *iv,
                                         const uint8_t *payload)
{
  iv->settings_id = nghttp2_get_uint16(&payload[0]);
  iv->value = nghttp2_get_uint32(&payload[2]);
}

int nghttp2_frame_unpack_settings_payload2(nghttp2_settings_entry **iv_ptr,
                                           size_t *niv_ptr,
                                           const uint8_t *payload,
                                           size_t payloadlen)
{
  size_t i;

  *niv_ptr = payloadlen / NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH;

  if(*niv_ptr == 0) {
    *iv_ptr = NULL;

    return 0;
  }


  *iv_ptr = malloc((*niv_ptr)*sizeof(nghttp2_settings_entry));

  if(*iv_ptr == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  for(i = 0; i < *niv_ptr; ++i) {
    size_t off = i * NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH;
    nghttp2_frame_unpack_settings_entry(&(*iv_ptr)[i], &payload[off]);
  }

  return 0;
}

int nghttp2_frame_pack_push_promise(nghttp2_bufs *bufs,
                                    nghttp2_push_promise *frame,
                                    nghttp2_hd_deflater *deflater)
{
  size_t nv_offset = 4;
  int rv;
  nghttp2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->cur->buf;

  buf->pos += nv_offset;
  buf->last = buf->pos;

  /* This call will adjust buf->last to the correct position */
  rv = nghttp2_hd_deflate_hd_bufs(deflater, bufs, frame->nva, frame->nvlen);

  if(rv == NGHTTP2_ERR_BUFFER_ERROR) {
    rv = NGHTTP2_ERR_HEADER_COMP;
  }

  buf->pos -= nv_offset;

  if(rv != 0) {
    return rv;
  }

  nghttp2_put_uint32be(buf->pos, frame->promised_stream_id);

  frame->padlen = 0;
  frame->hd.length = nghttp2_bufs_len(bufs);

  return frame_pack_headers_shared(bufs, &frame->hd);
}

int nghttp2_frame_unpack_push_promise_payload(nghttp2_push_promise *frame,
                                              const uint8_t *payload,
                                              size_t payloadlen)
{
  frame->promised_stream_id = nghttp2_get_uint32(payload) &
    NGHTTP2_STREAM_ID_MASK;
  frame->nva = NULL;
  frame->nvlen = 0;
  return 0;
}

int nghttp2_frame_pack_ping(nghttp2_bufs *bufs, nghttp2_ping *frame)
{
  nghttp2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->head->buf;

  assert(nghttp2_buf_avail(buf) >= 8);

  buf->pos -= NGHTTP2_FRAME_HDLEN;

  nghttp2_frame_pack_frame_hd(buf->pos, &frame->hd);

  buf->last = nghttp2_cpymem(buf->last, frame->opaque_data,
                             sizeof(frame->opaque_data));

  return 0;
}

void nghttp2_frame_unpack_ping_payload(nghttp2_ping *frame,
                                       const uint8_t *payload,
                                       size_t payloadlen)
{
  memcpy(frame->opaque_data, payload, sizeof(frame->opaque_data));
}

int nghttp2_frame_pack_goaway(nghttp2_bufs *bufs, nghttp2_goaway *frame)
{
  int rv;
  nghttp2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->head->buf;

  buf->pos -= NGHTTP2_FRAME_HDLEN;

  nghttp2_frame_pack_frame_hd(buf->pos, &frame->hd);

  nghttp2_put_uint32be(buf->last, frame->last_stream_id);
  buf->last += 4;

  nghttp2_put_uint32be(buf->last, frame->error_code);
  buf->last += 4;

  rv = nghttp2_bufs_add(bufs, frame->opaque_data, frame->opaque_data_len);

  if(rv == NGHTTP2_ERR_BUFFER_ERROR) {
    return NGHTTP2_ERR_FRAME_SIZE_ERROR;
  }

  if(rv != 0) {
    return rv;
  }

  return 0;
}

void nghttp2_frame_unpack_goaway_payload(nghttp2_goaway *frame,
                                         const uint8_t *payload,
                                         size_t payloadlen,
                                         uint8_t *var_gift_payload,
                                         size_t var_gift_payloadlen)
{
  frame->last_stream_id = nghttp2_get_uint32(payload) & NGHTTP2_STREAM_ID_MASK;
  frame->error_code = normalize_error_code(nghttp2_get_uint32(payload + 4));

  frame->opaque_data = var_gift_payload;
  frame->opaque_data_len = var_gift_payloadlen;
}

int nghttp2_frame_unpack_goaway_payload2(nghttp2_goaway *frame,
                                         const uint8_t *payload,
                                         size_t payloadlen)
{
  uint8_t *var_gift_payload;
  size_t var_gift_payloadlen;

  if(payloadlen > 8) {
    var_gift_payloadlen = payloadlen - 8;
  } else {
    var_gift_payloadlen = 0;
  }

  payloadlen -= var_gift_payloadlen;

  if(!var_gift_payloadlen) {
    var_gift_payload = NULL;
  } else {
    var_gift_payload = malloc(var_gift_payloadlen);

    if(var_gift_payload == NULL) {
      return NGHTTP2_ERR_NOMEM;
    }

    memcpy(var_gift_payload, payload + 8, var_gift_payloadlen);
  }

  nghttp2_frame_unpack_goaway_payload(frame, payload, payloadlen,
                                      var_gift_payload, var_gift_payloadlen);

  return 0;
}

int nghttp2_frame_pack_window_update(nghttp2_bufs *bufs,
                                     nghttp2_window_update *frame)
{
  nghttp2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->head->buf;

  assert(nghttp2_buf_avail(buf) >= 4);

  buf->pos -= NGHTTP2_FRAME_HDLEN;

  nghttp2_frame_pack_frame_hd(buf->pos, &frame->hd);

  nghttp2_put_uint32be(buf->last, frame->window_size_increment);
  buf->last += 4;

  return 0;
}

void nghttp2_frame_unpack_window_update_payload(nghttp2_window_update *frame,
                                                const uint8_t *payload,
                                                size_t payloadlen)
{
  frame->window_size_increment = nghttp2_get_uint32(payload) &
    NGHTTP2_WINDOW_SIZE_INCREMENT_MASK;
}

int nghttp2_frame_pack_altsvc(nghttp2_bufs *bufs, nghttp2_extension *frame)
{
  int rv;
  nghttp2_buf *buf;
  nghttp2_ext_altsvc *altsvc;

  assert(bufs->head == bufs->cur);

  altsvc = frame->payload;

  buf = &bufs->head->buf;

  buf->pos -= NGHTTP2_FRAME_HDLEN;

  nghttp2_frame_pack_frame_hd(buf->pos, &frame->hd);

  nghttp2_put_uint32be(buf->last, altsvc->max_age);
  buf->last += 4;

  nghttp2_put_uint16be(buf->last, altsvc->port);
  buf->last += 2;

  buf->last[0] = altsvc->protocol_id_len;
  ++buf->last;

  rv = nghttp2_bufs_add(bufs, altsvc->protocol_id, altsvc->protocol_id_len);
  if(rv != 0) {
    goto fail;
  }

  rv = nghttp2_bufs_addb(bufs, altsvc->host_len);
  if(rv != 0) {
    goto fail;
  }

  rv = nghttp2_bufs_add(bufs, altsvc->host, altsvc->host_len);
  if(rv != 0) {
    goto fail;
  }

  rv = nghttp2_bufs_add(bufs, altsvc->origin, altsvc->origin_len);
  if(rv != 0) {
    goto fail;
  }

  return 0;

 fail:

  if(rv == NGHTTP2_ERR_BUFFER_ERROR) {
    return NGHTTP2_ERR_FRAME_SIZE_ERROR;
  }

  return rv;
}

int nghttp2_frame_unpack_altsvc_payload(nghttp2_extension *frame,
                                        const uint8_t *payload,
                                        size_t payloadlen,
                                        uint8_t *var_gift_payload,
                                        size_t var_gift_payloadlen)
{
  nghttp2_buf buf;
  nghttp2_ext_altsvc *altsvc;

  altsvc = frame->payload;

  altsvc->max_age = nghttp2_get_uint32(payload);
  payload += 4;

  altsvc->port = nghttp2_get_uint16(payload);
  payload += 2;

  altsvc->protocol_id_len = *payload;

  nghttp2_buf_wrap_init(&buf, var_gift_payload, var_gift_payloadlen);
  buf.last += var_gift_payloadlen;

  /* 1 for Host-Len */
  if(nghttp2_buf_len(&buf) < 1 + (ssize_t)altsvc->protocol_id_len) {
    return NGHTTP2_ERR_FRAME_SIZE_ERROR;
  }

  altsvc->protocol_id = buf.pos;
  buf.pos += altsvc->protocol_id_len;

  altsvc->host_len = *buf.pos;
  ++buf.pos;

  if(nghttp2_buf_len(&buf) < (ssize_t)altsvc->host_len) {
    return NGHTTP2_ERR_FRAME_SIZE_ERROR;
  }

  altsvc->host = buf.pos;
  buf.pos += altsvc->host_len;

  altsvc->origin = buf.pos;
  altsvc->origin_len = nghttp2_buf_len(&buf);

  return 0;
}

nghttp2_settings_entry* nghttp2_frame_iv_copy(const nghttp2_settings_entry *iv,
                                              size_t niv)
{
  nghttp2_settings_entry *iv_copy;
  size_t len = niv*sizeof(nghttp2_settings_entry);

  if(len == 0) {
    return NULL;
  }

  iv_copy = malloc(len);

  if(iv_copy == NULL) {
    return NULL;
  }

  memcpy(iv_copy, iv, len);

  return iv_copy;
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

static int bytes_compar(const uint8_t *a, size_t alen,
                        const uint8_t *b, size_t blen)
{
  int rv;

  if(alen == blen) {
    return memcmp(a, b, alen);
  }

  if(alen < blen) {
    rv = memcmp(a, b, alen);

    if(rv == 0) {
      return -1;
    }

    return rv;
  }

  rv = memcmp(a, b, blen);

  if(rv == 0) {
    return 1;
  }

  return rv;
}

int nghttp2_nv_compare_name(const nghttp2_nv *lhs, const nghttp2_nv *rhs)
{
  return bytes_compar(lhs->name, lhs->namelen, rhs->name, rhs->namelen);
}

static int nv_compar(const void *lhs, const void *rhs)
{
  const nghttp2_nv *a = (const nghttp2_nv*)lhs;
  const nghttp2_nv *b = (const nghttp2_nv*)rhs;
  int rv;

  rv = bytes_compar(a->name, a->namelen, b->name, b->namelen);

  if(rv == 0) {
    return bytes_compar(a->value, a->valuelen, b->value, b->valuelen);
  }

  return rv;
}

void nghttp2_nv_array_sort(nghttp2_nv *nva, size_t nvlen)
{
  qsort(nva, nvlen, sizeof(nghttp2_nv), nv_compar);
}

int nghttp2_nv_array_copy(nghttp2_nv **nva_ptr,
                          const nghttp2_nv *nva, size_t nvlen)
{
  size_t i;
  uint8_t *data;
  size_t buflen = 0;
  nghttp2_nv *p;

  for(i = 0; i < nvlen; ++i) {
    buflen += nva[i].namelen + nva[i].valuelen;
  }

  if(nvlen == 0) {
    *nva_ptr = NULL;

    return 0;
  }

  buflen += sizeof(nghttp2_nv)*nvlen;

  *nva_ptr = malloc(buflen);

  if(*nva_ptr == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  p = *nva_ptr;
  data = (uint8_t*)(*nva_ptr) + sizeof(nghttp2_nv) * nvlen;

  for(i = 0; i < nvlen; ++i) {
    p->flags = nva[i].flags;

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
  return 0;
}

int nghttp2_iv_check(const nghttp2_settings_entry *iv, size_t niv)
{
  size_t i;
  for(i = 0; i < niv; ++i) {
    switch(iv[i].settings_id) {
    case NGHTTP2_SETTINGS_HEADER_TABLE_SIZE:
      if(iv[i].value > NGHTTP2_MAX_HEADER_TABLE_SIZE) {
        return 0;
      }
      break;
    case NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
      break;
    case NGHTTP2_SETTINGS_ENABLE_PUSH:
      if(iv[i].value != 0 && iv[i].value != 1) {
        return 0;
      }
      break;
    case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
      if(iv[i].value > (uint32_t)NGHTTP2_MAX_WINDOW_SIZE) {
        return 0;
      }
      break;
    default:
      return 0;
    }
  }
  return 1;
}

static void frame_set_pad(nghttp2_buf *buf, size_t padlen)
{
  size_t trail_padlen;
  size_t newlen;

  DEBUGF(fprintf(stderr, "send: padlen=%zu, shift left 1 bytes\n", padlen));

  memmove(buf->pos - 1, buf->pos, NGHTTP2_FRAME_HDLEN);

  --buf->pos;

  buf->pos[4] |= NGHTTP2_FLAG_PADDED;

  newlen = (nghttp2_get_uint32(buf->pos) >> 8) + padlen;
  nghttp2_put_uint32be(buf->pos, (uint32_t)((newlen << 8) + buf->pos[3]));

  trail_padlen = padlen - 1;
  buf->pos[NGHTTP2_FRAME_HDLEN] = trail_padlen;

  /* zero out padding */
  memset(buf->last, 0, trail_padlen);
  /* extend buffers trail_padlen bytes, since we ate previous padlen -
     trail_padlen byte(s) */
  buf->last += trail_padlen;

  return;
}

int nghttp2_frame_add_pad(nghttp2_bufs *bufs, nghttp2_frame_hd *hd,
                          size_t padlen)
{
  nghttp2_buf *buf;

  if(padlen == 0) {
    DEBUGF(fprintf(stderr, "send: padlen = 0, nothing to do\n"));

    return 0;
  }

  /*
   * We have arranged bufs like this:
   *
   *  0                   1                   2                   3
   *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * | |Frame header     | Frame payload...                          :
   * +-+-----------------+-------------------------------------------+
   * | |Frame header     | Frame payload...                          :
   * +-+-----------------+-------------------------------------------+
   * | |Frame header     | Frame payload...                          :
   * +-+-----------------+-------------------------------------------+
   *
   * We arranged padding so that it is included in the first frame
   * completely.  For padded frame, we are going to adjust buf->pos of
   * frame which includes padding and serialize (memmove) frame header
   * in the correct position.  Also extends buf->last to include
   * padding.
   */

  buf = &bufs->head->buf;

  assert(nghttp2_buf_avail(buf) >= (ssize_t)padlen - 1);

  frame_set_pad(buf, padlen);

  hd->length += padlen;
  hd->flags |= NGHTTP2_FLAG_PADDED;

  DEBUGF(fprintf(stderr, "send: final payloadlen=%zu, padlen=%zu\n",
                 hd->length, padlen));

  return 0;
}
