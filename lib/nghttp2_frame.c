/*
 * nghttp2
 *
 * Copyright (c) 2026 nghttp2 contributors
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

#include "nghttp2_conv.h"
#include "nghttp2_mem.h"
#include "nghttp2_str.h"

uint8_t *nghttp2_frame_encode_hd(uint8_t *dest, const nghttp2_frame_hd *hd) {
  uint8_t *p = dest;

  p = nghttp2_put_uint24be(p, hd->len);
  *p++ = hd->type;
  *p++ = hd->flags;
  p = nghttp2_put_uint32be(p, (uint32_t)hd->stream_id);

  return p;
}

int nghttp2_frame_encode_data(nghttp2_buf *dest, const nghttp2_frame_data *fr) {
  size_t len = NGHTTP2_FRAME_HDLEN + nghttp2_frame_encode_data_payloadlen(fr);
  uint8_t *p;

  if (nghttp2_buf_left(dest) < len) {
    return NGHTTP2_ERR_NOBUF;
  }

  p = dest->last;
  p = nghttp2_frame_encode_hd(p, &fr->hd);

  if (fr->hd.flags & NGHTTP2_HEADERS_FLAG_PADDED) {
    *p++ = (uint8_t)fr->padlen;
  }

  if (fr->datalen) {
    p = nghttp2_cpymem(p, fr->data, fr->datalen);
  }

  if (fr->hd.flags & NGHTTP2_DATA_FLAG_PADDED) {
    p = nghttp2_setmem(p, 0, fr->padlen);
  }

  assert(len == (size_t)(p - dest->last));

  dest->last = p;

  return 0;
}

size_t nghttp2_frame_encode_data_payloadlen(const nghttp2_frame_data *fr) {
  size_t len = fr->datalen;

  if (fr->hd.flags & NGHTTP2_DATA_FLAG_PADDED) {
    len += 1 + fr->padlen;
  }

  return len;
}

int nghttp2_frame_encode_headers(nghttp2_buf *dest,
                                 const nghttp2_frame_headers *fr) {
  size_t len =
    NGHTTP2_FRAME_HDLEN + nghttp2_frame_encode_headers_payloadlen(fr);
  uint8_t *p;

  if (nghttp2_buf_left(dest) < len) {
    return NGHTTP2_ERR_NOBUF;
  }

  p = dest->last;
  p = nghttp2_frame_encode_hd(p, &fr->hd);

  if (fr->hd.flags & NGHTTP2_HEADERS_FLAG_PADDED) {
    *p++ = (uint8_t)fr->padlen;
  }

  if (fr->hd.flags & NGHTTP2_HEADERS_FLAG_PRIORITY) {
    p = nghttp2_setmem(p, 0, 5);
  }

  if (fr->field_blocklen) {
    p = nghttp2_cpymem(p, fr->field_block, fr->field_blocklen);
  }

  if (fr->hd.flags & NGHTTP2_HEADERS_FLAG_PADDED) {
    p = nghttp2_setmem(p, 0, fr->padlen);
  }

  assert(len == (size_t)(p - dest->last));

  dest->last = p;

  return 0;
}

size_t
nghttp2_frame_encode_headers_payloadlen(const nghttp2_frame_headers *fr) {
  size_t len = fr->field_blocklen;

  if (fr->hd.flags & NGHTTP2_HEADERS_FLAG_PADDED) {
    len += 1 + fr->padlen;
  }

  if (fr->hd.flags & NGHTTP2_HEADERS_FLAG_PRIORITY) {
    len += 5;
  }

  return len;
}

int nghttp2_frame_encode_rst_stream(nghttp2_buf *dest,
                                    const nghttp2_frame_rst_stream *fr) {
  size_t len = NGHTTP2_FRAME_HDLEN + 4;
  uint8_t *p;

  if (nghttp2_buf_left(dest) < len) {
    return NGHTTP2_ERR_NOBUF;
  }

  p = dest->last;
  p = nghttp2_frame_encode_hd(p, &fr->hd);
  p = nghttp2_put_uint32be(p, fr->error_code);

  assert(len == (size_t)(p - dest->last));

  dest->last = p;

  return 0;
}

int nghttp2_frame_encode_settings(nghttp2_buf *dest,
                                  const nghttp2_frame_settings *fr) {
  size_t len =
    NGHTTP2_FRAME_HDLEN + nghttp2_frame_encode_settings_payloadlen(fr);
  uint8_t *p;
  size_t i;

  if (nghttp2_buf_left(dest) < len) {
    return NGHTTP2_ERR_NOBUF;
  }

  p = dest->last;
  p = nghttp2_frame_encode_hd(p, &fr->hd);

  for (i = 0; i < fr->niv; ++i) {
    p = nghttp2_put_uint16be(p, fr->iv[i].id);
    p = nghttp2_put_uint32be(p, fr->iv[i].value);
  }

  assert(len == (size_t)(p - dest->last));

  dest->last = p;

  return 0;
}

size_t
nghttp2_frame_encode_settings_payloadlen(const nghttp2_frame_settings *fr) {
  return fr->niv * 6;
}

int nghttp2_frame_encode_ping(nghttp2_buf *dest, const nghttp2_frame_ping *fr) {
  size_t len = NGHTTP2_FRAME_HDLEN + sizeof(fr->data.data);
  uint8_t *p;

  if (nghttp2_buf_left(dest) < len) {
    return NGHTTP2_ERR_NOBUF;
  }

  p = dest->last;
  p = nghttp2_frame_encode_hd(p, &fr->hd);
  p = nghttp2_cpymem(p, fr->data.data, sizeof(fr->data.data));

  assert(len == (size_t)(p - dest->last));

  dest->last = p;

  return 0;
}

int nghttp2_frame_encode_goaway(nghttp2_buf *dest,
                                const nghttp2_frame_goaway *fr) {
  size_t len = NGHTTP2_FRAME_HDLEN + nghttp2_frame_encode_goaway_payloadlen(fr);
  uint8_t *p;

  if (nghttp2_buf_left(dest) < len) {
    return NGHTTP2_ERR_NOBUF;
  }

  p = dest->last;
  p = nghttp2_frame_encode_hd(p, &fr->hd);
  p = nghttp2_put_uint32be(p, fr->last_stream_id);
  p = nghttp2_put_uint32be(p, fr->error_code);

  if (fr->debug_datalen) {
    p = nghttp2_cpymem(p, fr->debug_data, fr->debug_datalen);
  }

  assert(len == (size_t)(p - dest->last));

  dest->last = p;

  return 0;
}

size_t nghttp2_frame_encode_goaway_payloadlen(const nghttp2_frame_goaway *fr) {
  return 8 + fr->debug_datalen;
}

int nghttp2_frame_encode_window_update(nghttp2_buf *dest,
                                       const nghttp2_frame_window_update *fr) {
  size_t len = NGHTTP2_FRAME_HDLEN + 4;
  uint8_t *p;

  if (nghttp2_buf_left(dest) < len) {
    return NGHTTP2_ERR_NOBUF;
  }

  p = dest->last;
  p = nghttp2_frame_encode_hd(p, &fr->hd);
  p = nghttp2_put_uint32be(p, fr->window_size_inc);

  assert(len == (size_t)(p - dest->last));

  dest->last = p;

  return 0;
}

int nghttp2_frame_encode_priority_update(
  nghttp2_buf *dest, const nghttp2_frame_priority_update *fr) {
  size_t len =
    NGHTTP2_FRAME_HDLEN + nghttp2_frame_encode_priority_update_payloadlen(fr);
  uint8_t *p;

  if (nghttp2_buf_left(dest) < len) {
    return NGHTTP2_ERR_NOBUF;
  }

  p = dest->last;
  p = nghttp2_frame_encode_hd(p, &fr->hd);
  p = nghttp2_put_uint32be(p, fr->prioritized_stream_id);

  if (fr->pri) {
    p = nghttp2_cpymem(p, fr->pri, fr->prilen);
  }

  assert(len == (size_t)(p - dest->last));

  dest->last = p;

  return 0;
}

size_t nghttp2_frame_encode_priority_update_payloadlen(
  const nghttp2_frame_priority_update *fr) {
  return 4 + fr->prilen;
}

void nghttp2_frd_init(nghttp2_frd *frd) { (void)frd; }

int nghttp2_frd_decode_buf(nghttp2_frd *frd, nghttp2_frame *dest,
                           nghttp2_buf *src) {
  nghttp2_ssize nread;

  nread = nghttp2_frd_decode(frd, dest, src->pos, nghttp2_buf_len(src));
  if (nread < 0) {
    return (int)nread;
  }

  src->pos += nread;

  return 0;
}

nghttp2_ssize nghttp2_frd_decode(nghttp2_frd *frd, nghttp2_frame *dest,
                                 const uint8_t *src, size_t srclen) {
  if (srclen < NGHTTP2_FRAME_HDLEN) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  switch (*(src + 3)) {
  case NGHTTP2_FRAME_DATA:
    return nghttp2_frame_decode_data(&dest->data, src, srclen);
  case NGHTTP2_FRAME_HEADERS:
    return nghttp2_frame_decode_headers(&dest->headers, src, srclen);
  case NGHTTP2_FRAME_RST_STREAM:
    return nghttp2_frame_decode_rst_stream(&dest->rst_stream, src, srclen);
  case NGHTTP2_FRAME_SETTINGS:
    dest->settings.iv = frd->iv;
    return nghttp2_frame_decode_settings(&dest->settings, src, srclen);
  case NGHTTP2_FRAME_PING:
    return nghttp2_frame_decode_ping(&dest->ping, src, srclen);
  case NGHTTP2_FRAME_GOAWAY:
    return nghttp2_frame_decode_goaway(&dest->goaway, src, srclen);
  case NGHTTP2_FRAME_WINDOW_UPDATE:
    return nghttp2_frame_decode_window_update(&dest->window_update, src,
                                              srclen);
  case NGHTTP2_FRAME_CONTINUATION:
    return nghttp2_frame_decode_continuation(&dest->headers, src, srclen);
  case NGHTTP2_FRAME_PRIORITY_UPDATE:
    return nghttp2_frame_decode_priority_update(&dest->priority_update, src,
                                                srclen);
  default:
    return NGHTTP2_ERR_FRAME_ENCODING;
  }
}

const uint8_t *nghttp2_frame_decode_hd(nghttp2_frame_hd *hd,
                                       const uint8_t *src) {
  const uint8_t *p = src;
  uint32_t stream_id;

  p = nghttp2_get_uint24be(&hd->len, p);
  hd->type = *p++;
  hd->flags = *p++;
  p = nghttp2_get_uint31be(&stream_id, p);
  hd->stream_id = (int64_t)stream_id;

  assert((nghttp2_ssize)(p - src) == NGHTTP2_FRAME_HDLEN);

  return p;
}

nghttp2_ssize nghttp2_frame_decode_data(nghttp2_frame_data *dest,
                                        const uint8_t *src, size_t srclen) {
  const uint8_t *p = src;
  size_t len;

  if (srclen < NGHTTP2_FRAME_HDLEN) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  p = nghttp2_frame_decode_hd(&dest->hd, p);

  if (srclen < NGHTTP2_FRAME_HDLEN + dest->hd.len) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  len = 0;

  if (dest->hd.flags & NGHTTP2_DATA_FLAG_PADDED) {
    ++len;

    if (dest->hd.len < len) {
      return NGHTTP2_ERR_FRAME_ENCODING;
    }

    dest->padlen = *p++;
    len += dest->padlen;

    if (dest->hd.len < len) {
      return NGHTTP2_ERR_FRAME_ENCODING;
    }
  } else {
    dest->padlen = 0;
  }

  dest->datalen = dest->hd.len - len;

  if (dest->datalen) {
    dest->data = p;
  } else {
    dest->data = NULL;
  }

  return (nghttp2_ssize)(NGHTTP2_FRAME_HDLEN + dest->hd.len);
}

nghttp2_ssize nghttp2_frame_decode_headers(nghttp2_frame_headers *dest,
                                           const uint8_t *src, size_t srclen) {
  const uint8_t *p = src;
  size_t len;

  if (srclen < NGHTTP2_FRAME_HDLEN) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  p = nghttp2_frame_decode_hd(&dest->hd, p);

  if (srclen < NGHTTP2_FRAME_HDLEN + dest->hd.len) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  len = 0;

  if (dest->hd.flags & NGHTTP2_HEADERS_FLAG_PADDED) {
    ++len;

    if (dest->hd.len < len) {
      return NGHTTP2_ERR_FRAME_ENCODING;
    }

    dest->padlen = *p++;
    len += dest->padlen;

    if (dest->hd.len < len) {
      return NGHTTP2_ERR_FRAME_ENCODING;
    }
  } else {
    dest->padlen = 0;
  }

  if (dest->hd.flags & NGHTTP2_HEADERS_FLAG_PRIORITY) {
    len += 5;

    if (dest->hd.len < len) {
      return NGHTTP2_ERR_FRAME_ENCODING;
    }

    p += 5;
  }

  dest->field_blocklen = dest->hd.len - len;

  if (dest->field_blocklen) {
    dest->field_block = p;
  } else {
    dest->field_block = NULL;
  }

  return (nghttp2_ssize)(NGHTTP2_FRAME_HDLEN + dest->hd.len);
}

nghttp2_ssize nghttp2_frame_decode_rst_stream(nghttp2_frame_rst_stream *dest,
                                              const uint8_t *src,
                                              size_t srclen) {
  const uint8_t *p = src;

  if (srclen < NGHTTP2_FRAME_HDLEN + 4) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  p = nghttp2_frame_decode_hd(&dest->hd, p);

  if (dest->hd.len != 4) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  nghttp2_get_uint32be(&dest->error_code, p);

  return (nghttp2_ssize)(NGHTTP2_FRAME_HDLEN + 4);
}

nghttp2_ssize nghttp2_frame_decode_settings(nghttp2_frame_settings *dest,
                                            const uint8_t *src, size_t srclen) {
  const uint8_t *p = src;
  size_t i;

  if (srclen < NGHTTP2_FRAME_HDLEN) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  p = nghttp2_frame_decode_hd(&dest->hd, p);

  if (srclen < NGHTTP2_FRAME_HDLEN + dest->hd.len || dest->hd.len % 6) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  dest->niv = dest->hd.len / 6;

  for (i = 0; i < dest->niv; ++i) {
    p = nghttp2_get_uint16be(&dest->iv[i].id, p);
    p = nghttp2_get_uint32be(&dest->iv[i].value, p);
  }

  return (nghttp2_ssize)(NGHTTP2_FRAME_HDLEN + dest->hd.len);
}

nghttp2_ssize nghttp2_frame_decode_ping(nghttp2_frame_ping *dest,
                                        const uint8_t *src, size_t srclen) {
  const uint8_t *p = src;

  if (srclen < NGHTTP2_FRAME_HDLEN + 8) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  p = nghttp2_frame_decode_hd(&dest->hd, p);

  if (dest->hd.len != 8) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  memcpy(dest->data.data, p, sizeof(dest->data.data));

  return (nghttp2_ssize)(NGHTTP2_FRAME_HDLEN + 8);
}

nghttp2_ssize nghttp2_frame_decode_goaway(nghttp2_frame_goaway *dest,
                                          const uint8_t *src, size_t srclen) {
  const uint8_t *p = src;

  if (srclen < NGHTTP2_FRAME_HDLEN + 8) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  p = nghttp2_frame_decode_hd(&dest->hd, p);

  if (srclen < NGHTTP2_FRAME_HDLEN + dest->hd.len || dest->hd.len < 8) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  p = nghttp2_get_uint31be(&dest->last_stream_id, p);
  p = nghttp2_get_uint32be(&dest->error_code, p);
  dest->debug_datalen = dest->hd.len - 8;

  if (dest->debug_datalen) {
    dest->debug_data = p;
  } else {
    dest->debug_data = NULL;
  }

  return (nghttp2_ssize)(NGHTTP2_FRAME_HDLEN + dest->hd.len);
}

nghttp2_ssize
nghttp2_frame_decode_window_update(nghttp2_frame_window_update *dest,
                                   const uint8_t *src, size_t srclen) {
  const uint8_t *p = src;

  if (srclen < NGHTTP2_FRAME_HDLEN + 4) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  p = nghttp2_frame_decode_hd(&dest->hd, p);

  if (dest->hd.len != 4) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  nghttp2_get_uint31be(&dest->window_size_inc, p);

  return (nghttp2_ssize)(NGHTTP2_FRAME_HDLEN + 4);
}

nghttp2_ssize nghttp2_frame_decode_continuation(nghttp2_frame_headers *dest,
                                                const uint8_t *src,
                                                size_t srclen) {
  const uint8_t *p = src;

  if (srclen < NGHTTP2_FRAME_HDLEN) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  p = nghttp2_frame_decode_hd(&dest->hd, p);

  if (srclen < NGHTTP2_FRAME_HDLEN + dest->hd.len) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  dest->padlen = 0;
  dest->field_blocklen = dest->hd.len;

  if (dest->field_blocklen) {
    dest->field_block = p;
  } else {
    dest->field_block = NULL;
  }

  return (nghttp2_ssize)(NGHTTP2_FRAME_HDLEN + dest->hd.len);
}

nghttp2_ssize
nghttp2_frame_decode_priority_update(nghttp2_frame_priority_update *dest,
                                     const uint8_t *src, size_t srclen) {
  const uint8_t *p = src;

  if (srclen < NGHTTP2_FRAME_HDLEN + 4) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  p = nghttp2_frame_decode_hd(&dest->hd, p);

  if (srclen < NGHTTP2_FRAME_HDLEN + dest->hd.len || dest->hd.len < 4) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  p = nghttp2_get_uint31be(&dest->prioritized_stream_id, p);

  dest->prilen = dest->hd.len - 4;

  if (dest->prilen) {
    dest->pri = p;
  } else {
    dest->pri = NULL;
  }

  return (nghttp2_ssize)(NGHTTP2_FRAME_HDLEN + dest->hd.len);
}

int nghttp2_nva_copy(nghttp2_nv **pnva, const nghttp2_nv *nva, size_t nvlen,
                     const nghttp2_mem *mem) {
  size_t i;
  uint8_t *data = NULL;
  size_t buflen = 0;
  nghttp2_nv *p;

  if (nvlen == 0) {
    *pnva = NULL;

    return 0;
  }

  for (i = 0; i < nvlen; ++i) {
    /* + 1 for null-termination */
    if ((nva[i].flags & NGHTTP2_NV_FLAG_NO_COPY_NAME) == 0) {
      buflen += nva[i].namelen + 1;
    }
    if ((nva[i].flags & NGHTTP2_NV_FLAG_NO_COPY_VALUE) == 0) {
      buflen += nva[i].valuelen + 1;
    }
  }

  buflen += sizeof(nghttp2_nv) * nvlen;

  *pnva = nghttp2_mem_malloc(mem, buflen);

  if (*pnva == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  p = *pnva;
  data = (uint8_t *)(*pnva) + sizeof(nghttp2_nv) * nvlen;

  for (i = 0; i < nvlen; ++i) {
    p->flags = nva[i].flags;

    if (nva[i].flags & NGHTTP2_NV_FLAG_NO_COPY_NAME) {
      p->name = nva[i].name;
      p->namelen = nva[i].namelen;
    } else {
      if (nva[i].namelen) {
        memcpy(data, nva[i].name, nva[i].namelen);
        nghttp2_downcase(data, nva[i].namelen);
      }
      p->name = data;
      p->namelen = nva[i].namelen;
      data[p->namelen] = '\0';
      data += nva[i].namelen + 1;
    }

    if (nva[i].flags & NGHTTP2_NV_FLAG_NO_COPY_VALUE) {
      p->value = nva[i].value;
      p->valuelen = nva[i].valuelen;
    } else {
      if (nva[i].valuelen) {
        memcpy(data, nva[i].value, nva[i].valuelen);
      }
      p->value = data;
      p->valuelen = nva[i].valuelen;
      data[p->valuelen] = '\0';
      data += nva[i].valuelen + 1;
    }

    ++p;
  }
  return 0;
}

void nghttp2_nva_del(nghttp2_nv *nva, const nghttp2_mem *mem) {
  nghttp2_mem_free(mem, nva);
}

int nghttp2_ping_data_eq(const nghttp2_ping_data *a,
                         const nghttp2_ping_data *b) {
  return memcmp(a->data, b->data, sizeof(a->data)) == 0;
}
