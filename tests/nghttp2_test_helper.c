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
#include "nghttp2_test_helper.h"
#include "nghttp2_conv.h"
#include "nghttp2_str.h"
#include "nghttp2_unreachable.h"

void write_settings(nghttp2_buf *dest, const nghttp2_settings_entry *iv,
                    size_t ivlen) {
  uint8_t *lenp = dest->last;
  uint8_t *p = dest->last;
  size_t i;

  p += 3;
  *p++ = NGHTTP2_FRAME_SETTINGS;
  *p++ = 0x0U;
  p = nghttp2_put_uint32be(p, 0);

  for (i = 0; i < ivlen; ++i) {
    p = nghttp2_put_uint16be(p, iv[0].id);
    p = nghttp2_put_uint32be(p, iv[0].value);
  }

  nghttp2_put_uint24be(
    lenp, (uint32_t)((size_t)(p - dest->last) - NGHTTP2_FRAME_HDLEN));
  dest->last = p;
}

void write_frame(nghttp2_buf *dest, const nghttp2_frame *fr) {
  uint8_t *lenp = dest->last;
  uint8_t *p = dest->last;

  p += 3;
  *p++ = fr->meta.hd.type;
  *p++ = fr->meta.hd.flags;
  p = nghttp2_put_uint32be(p, (uint32_t)fr->meta.hd.stream_id);

  switch (fr->meta.hd.type) {
  case NGHTTP2_FRAME_DATA:
    if (fr->data.hd.flags & NGHTTP2_DATA_FLAG_PADDED) {
      *p++ = (uint8_t)fr->data.padlen;
    }

    p = nghttp2_setmem(p, 0, fr->data.datalen);
    p = nghttp2_setmem(p, 0, fr->data.padlen);

    break;
  case NGHTTP2_FRAME_HEADERS:
    if (fr->headers.hd.flags & NGHTTP2_HEADERS_FLAG_PADDED) {
      *p++ = (uint8_t)fr->headers.padlen;
    }

    if (fr->headers.hd.flags & NGHTTP2_HEADERS_FLAG_PRIORITY) {
      p = nghttp2_setmem(p, 0, 5);
    }

    if (fr->headers.field_blocklen) {
      p =
        nghttp2_cpymem(p, fr->headers.field_block, fr->headers.field_blocklen);
    }

    p = nghttp2_setmem(p, 0, fr->headers.padlen);

    break;
  case NGHTTP2_FRAME_CONTINUATION:
    if (fr->headers.field_blocklen) {
      p =
        nghttp2_cpymem(p, fr->headers.field_block, fr->headers.field_blocklen);
    }

    break;
  default:
    nghttp2_unreachable();
  }

  nghttp2_put_uint24be(
    lenp, (uint32_t)((size_t)(p - dest->last) - NGHTTP2_FRAME_HDLEN));
  dest->last = p;
}

void check_http2_preface(nghttp2_buf *data) {
  assert_size(nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE), <=,
              nghttp2_buf_len(data));
  assert_memn_equal(NGHTTP2_CLIENT_HTTP2_PREFACE,
                    nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE), data->pos,
                    nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE));

  data->pos += nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE);
}
