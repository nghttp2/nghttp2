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
#include "nghttp2_frame_test.h"

#include <stdio.h>

#include "nghttp2_frame.h"
#include "nghttp2_macro.h"
#include "nghttp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_nghttp2_frame_encode_data),
  munit_void_test(test_nghttp2_frame_encode_headers),
  munit_void_test(test_nghttp2_frame_encode_rst_stream),
  munit_void_test(test_nghttp2_frame_encode_settings),
  munit_void_test(test_nghttp2_frame_encode_ping),
  munit_void_test(test_nghttp2_frame_encode_goaway),
  munit_void_test(test_nghttp2_frame_encode_window_update),
  munit_void_test(test_nghttp2_frame_encode_continuation),
  munit_void_test(test_nghttp2_frame_encode_priority_update),
  munit_test_end(),
};

const MunitSuite frame_suite = {
  .prefix = "/frame",
  .tests = tests,
};

static const uint8_t nulldata[1 << 20];

void test_nghttp2_frame_encode_data(void) {
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  nghttp2_frame_data fr, nfr;
  nghttp2_ssize nread;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  /* With padding */
  fr = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM | NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = 1000000007,
      },
    .padlen = 199,
    .data = nulldata,
    .datalen = 1000,
  };

  fr.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr);

  assert_uint32(200 + 1000, ==, fr.hd.len);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_data(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(nread, ==, (nghttp2_ssize)nghttp2_buf_len(&buf));
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_size(fr.padlen, ==, nfr.padlen);
  assert_memn_equal(fr.data, fr.datalen, nfr.data, nfr.datalen);

  /* Prematurely truncated buffer */
  for (i = 0; i < nghttp2_buf_len(&buf) - 1; ++i) {
    nread = nghttp2_frame_decode_data(&nfr, buf.pos, i);

    assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);
  }

  /* Buffer is too short to encode */
  nghttp2_buf_reset(&buf);
  buf.end = buf.begin + NGHTTP2_FRAME_HDLEN + fr.hd.len - 1;
  rv = nghttp2_frame_encode_data(&buf, &fr);

  assert_int(NGHTTP2_ERR_NOBUF, ==, rv);

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  /* frame length is too short for padlen */
  fr = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM | NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = 1000000007,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_data(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);

  /* frame length is too short for padding */
  fr = (nghttp2_frame_data){
    .hd =
      {
        .len = 1,
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM | NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = 1000000007,
      },
    .padlen = 1,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_data(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);

  /* frame length is too large */
  fr = (nghttp2_frame_data){
    .hd =
      {
        .len = 1,
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
        .stream_id = 1000000007,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_data(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);

  /* Without padding */
  fr = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
        .stream_id = 1000000007,
      },
    .data = nulldata,
    .datalen = 1000,
  };

  fr.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr);

  assert_uint32(1000, ==, fr.hd.len);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_data(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(nread, ==, (nghttp2_ssize)nghttp2_buf_len(&buf));
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_size(fr.padlen, ==, nfr.padlen);
  assert_memn_equal(fr.data, fr.datalen, nfr.data, nfr.datalen);

  /* 0 length */
  fr = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
        .stream_id = 1000000007,
      },
  };

  fr.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr);

  assert_uint32(0, ==, fr.hd.len);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_data(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(nread, ==, (nghttp2_ssize)nghttp2_buf_len(&buf));
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_size(fr.padlen, ==, nfr.padlen);
  assert_size(fr.datalen, ==, nfr.datalen);
  assert_ptr_equal(fr.data, nfr.data);
}

void test_nghttp2_frame_encode_headers(void) {
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  nghttp2_frame_headers fr, nfr;
  nghttp2_ssize nread;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  /* With padding and priority */
  fr = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM | NGHTTP2_HEADERS_FLAG_PADDED |
                 NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 1000000007,
      },
    .padlen = 199,
    .field_block = nulldata,
    .field_blocklen = 77,
  };

  fr.hd.len = (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr);

  assert_uint32(200 + 5 + 77, ==, fr.hd.len);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_headers(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(nread, ==, (nghttp2_ssize)nghttp2_buf_len(&buf));
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_size(fr.padlen, ==, nfr.padlen);
  assert_memn_equal(fr.field_block, fr.field_blocklen, nfr.field_block,
                    nfr.field_blocklen);

  /* Prematurely truncated buffer */
  for (i = 0; i < nghttp2_buf_len(&buf) - 1; ++i) {
    nread = nghttp2_frame_decode_headers(&nfr, buf.pos, i);

    assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);
  }

  /* Buffer is too short to encode */
  nghttp2_buf_reset(&buf);
  buf.end = buf.begin + NGHTTP2_FRAME_HDLEN + fr.hd.len - 1;
  rv = nghttp2_frame_encode_headers(&buf, &fr);

  assert_int(NGHTTP2_ERR_NOBUF, ==, rv);

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  /* frame length is too short for padlen */
  fr = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM | NGHTTP2_HEADERS_FLAG_PADDED |
                 NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 1000000007,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_headers(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);

  /* frame length is too short for padding */
  fr = (nghttp2_frame_headers){
    .hd =
      {
        .len = 1,
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM | NGHTTP2_HEADERS_FLAG_PADDED |
                 NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 1000000007,
      },
    .padlen = 1,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_headers(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);

  /* frame length is too short for priority */
  fr = (nghttp2_frame_headers){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM |
                 NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 1000000007,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_headers(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);

  /* frame length is too large */
  fr = (nghttp2_frame_headers){
    .hd =
      {
        .len = 5,
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 1000000007,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_headers(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);

  /* With padding */
  fr = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM | NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 1000000007,
      },
    .padlen = 199,
    .field_block = nulldata,
    .field_blocklen = 77,
  };

  fr.hd.len = (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr);

  assert_uint32(200 + 77, ==, fr.hd.len);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_headers(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(nread, ==, (nghttp2_ssize)nghttp2_buf_len(&buf));
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_size(fr.padlen, ==, nfr.padlen);
  assert_memn_equal(fr.field_block, fr.field_blocklen, nfr.field_block,
                    nfr.field_blocklen);

  /* With priority */
  fr = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM |
                 NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 1000000007,
      },
    .field_block = nulldata,
    .field_blocklen = 77,
  };

  fr.hd.len = (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr);

  assert_uint32(5 + 77, ==, fr.hd.len);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_headers(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(nread, ==, (nghttp2_ssize)nghttp2_buf_len(&buf));
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_size(fr.padlen, ==, nfr.padlen);
  assert_memn_equal(fr.field_block, fr.field_blocklen, nfr.field_block,
                    nfr.field_blocklen);

  /* 0 length */
  fr = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 1000000007,
      },
  };

  fr.hd.len = (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr);

  assert_uint32(0, ==, fr.hd.len);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_headers(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(nread, ==, (nghttp2_ssize)nghttp2_buf_len(&buf));
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_size(fr.padlen, ==, nfr.padlen);
  assert_size(fr.field_blocklen, ==, nfr.field_blocklen);
  assert_ptr_equal(fr.field_block, nfr.field_block);
}

void test_nghttp2_frame_encode_rst_stream(void) {
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  nghttp2_frame_rst_stream fr, nfr;
  nghttp2_ssize nread;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  fr = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = 1000000007,
      },
    .error_code = NGHTTP2_ENHANCE_YOUR_CALM,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_rst_stream(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_rst_stream(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff((nghttp2_ssize)nghttp2_buf_len(&buf), ==, nread);
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_uint32(fr.error_code, ==, nfr.error_code);

  /* Prematurely truncated buffer */
  for (i = 0; i < nghttp2_buf_len(&buf) - 1; ++i) {
    nread = nghttp2_frame_decode_rst_stream(&nfr, buf.pos, i);

    assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);
  }

  /* Wrong frame length */
  fr = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 5,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = 1000000007,
      },
    .error_code = NGHTTP2_ENHANCE_YOUR_CALM,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_rst_stream(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_rst_stream(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);
}

void test_nghttp2_frame_encode_settings(void) {
  static const nghttp2_settings_entry iv[] = {
    {
      .id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
      .value = 1000000009,
    },
    {
      .id = NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL,
      .value = 12345666,
    },
  };
  nghttp2_settings_entry iv_out[16];
  uint8_t rawbuf[16384];
  nghttp2_buf buf;

  nghttp2_frame_settings fr;
  nghttp2_frame_settings nfr = {
    .iv = iv_out,
  };
  nghttp2_ssize nread;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  fr = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = (nghttp2_settings_entry *)iv,
    .niv = nghttp2_arraylen(iv),
  };

  fr.hd.len = (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr);

  assert_size(6 * 2, ==, fr.hd.len);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_settings(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff((nghttp2_ssize)nghttp2_buf_len(&buf), ==, nread);
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_size(fr.niv, ==, nfr.niv);

  for (i = 0; i < fr.niv; ++i) {
    assert_uint16(fr.iv[i].id, ==, nfr.iv[i].id);
    assert_uint32(fr.iv[i].value, ==, nfr.iv[i].value);
  }

  /* Prematurely truncated buffer */
  for (i = 0; i < nghttp2_buf_len(&buf) - 1; ++i) {
    nread = nghttp2_frame_decode_settings(&nfr, buf.pos, i);

    assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);
  }

  /* Wrong frame length */
  fr = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = (nghttp2_settings_entry *)iv,
    .niv = nghttp2_arraylen(iv),
  };

  fr.hd.len = (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr) + 1;
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_settings(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);

  /* ACK */
  fr = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_settings(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff((nghttp2_ssize)nghttp2_buf_len(&buf), ==, nread);
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_size(fr.niv, ==, nfr.niv);
}

void test_nghttp2_frame_encode_ping(void) {
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  nghttp2_frame_ping fr, nfr;
  nghttp2_ssize nread;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  fr = (nghttp2_frame_ping){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_PING,
      },
    .data =
      {
        .data = {0xBA, 0xAD, 0xCA, 0xFE, 0xBE, 0xEF, 0xCA, 0xCE},
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_ping(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_ping(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff((nghttp2_ssize)nghttp2_buf_len(&buf), ==, nread);
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_true(nghttp2_ping_data_eq(&fr.data, &nfr.data));

  /* Prematurely truncated buffer */
  for (i = 0; i < nghttp2_buf_len(&buf) - 1; ++i) {
    nread = nghttp2_frame_decode_ping(&nfr, buf.pos, i);

    assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);
  }

  /* Wrong frame length */
  fr = (nghttp2_frame_ping){
    .hd =
      {
        .len = 9,
        .type = NGHTTP2_FRAME_PING,
      },
    .data =
      {
        .data = {0xBA, 0xAD, 0xCA, 0xFE, 0xBE, 0xEF, 0xCA, 0xCE},
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_ping(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_ping(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);

  /* ACK */
  fr = (nghttp2_frame_ping){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_PING,
        .flags = NGHTTP2_PING_FLAG_ACK,
      },
    .data =
      {
        .data = {0xBA, 0xAD, 0xCA, 0xFE, 0xBE, 0xEF, 0xCA, 0xCE},
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_ping(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_ping(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff((nghttp2_ssize)nghttp2_buf_len(&buf), ==, nread);
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_true(nghttp2_ping_data_eq(&fr.data, &nfr.data));
}

void test_nghttp2_frame_encode_goaway(void) {
  static const uint8_t debug_data[] = "debug debug debug";
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  nghttp2_frame_goaway fr, nfr;
  nghttp2_ssize nread;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  /* With debug data */
  fr = (nghttp2_frame_goaway){
    .hd =
      {
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .last_stream_id = 1000000009,
    .error_code = NGHTTP2_ENHANCE_YOUR_CALM,
    .debug_data = debug_data,
    .debug_datalen = nghttp2_strlen_lit(debug_data),
  };

  fr.hd.len = (uint32_t)nghttp2_frame_encode_goaway_payloadlen(&fr);

  assert_size(8 + nghttp2_strlen_lit(debug_data), ==, fr.hd.len);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_goaway(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff((nghttp2_ssize)nghttp2_buf_len(&buf), ==, nread);
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_uint32(fr.last_stream_id, ==, nfr.last_stream_id);
  assert_uint32(fr.error_code, ==, nfr.error_code);
  assert_memn_equal(fr.debug_data, fr.debug_datalen, nfr.debug_data,
                    nfr.debug_datalen);

  /* Without debug data */
  fr = (nghttp2_frame_goaway){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .last_stream_id = 1000000009,
    .error_code = NGHTTP2_ENHANCE_YOUR_CALM,
  };

  fr.hd.len = (uint32_t)nghttp2_frame_encode_goaway_payloadlen(&fr);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_goaway(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff((nghttp2_ssize)nghttp2_buf_len(&buf), ==, nread);
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_uint32(fr.last_stream_id, ==, nfr.last_stream_id);
  assert_uint32(fr.error_code, ==, nfr.error_code);
  assert_size(fr.debug_datalen, ==, nfr.debug_datalen);
  assert_ptr_equal(fr.debug_data, nfr.debug_data);

  /* Prematurely truncated buffer */
  for (i = 0; i < nghttp2_buf_len(&buf) - 1; ++i) {
    nread = nghttp2_frame_decode_goaway(&nfr, buf.pos, i);

    assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);
  }

  /* Wrong frame length */
  fr = (nghttp2_frame_goaway){
    .hd =
      {
        .len = 7,
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .last_stream_id = 1000000009,
    .error_code = NGHTTP2_ENHANCE_YOUR_CALM,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_goaway(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);

  /* Wrong frame length */
  fr = (nghttp2_frame_goaway){
    .hd =
      {
        .len = 9,
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .last_stream_id = 1000000009,
    .error_code = NGHTTP2_ENHANCE_YOUR_CALM,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr);

  assert_int(0, ==, rv);

  nread = nghttp2_frame_decode_goaway(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);
}

void test_nghttp2_frame_encode_window_update(void) {
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  nghttp2_frame_window_update fr, nfr;
  nghttp2_ssize nread;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  fr = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
        .stream_id = 1000000007,
      },
    .window_size_inc = 1000000009,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_window_update(&buf, &fr);

  assert_int(0, ==, rv);

  nread =
    nghttp2_frame_decode_window_update(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff((nghttp2_ssize)nghttp2_buf_len(&buf), ==, nread);
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_uint32(fr.window_size_inc, ==, nfr.window_size_inc);

  /* Prematurely truncated buffer */
  for (i = 0; i < nghttp2_buf_len(&buf) - 1; ++i) {
    nread = nghttp2_frame_decode_window_update(&nfr, buf.pos, i);

    assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);
  }

  /* Wrong frame length */
  fr = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 5,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
        .stream_id = 1000000007,
      },
    .window_size_inc = 1000000009,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_window_update(&buf, &fr);

  assert_int(0, ==, rv);

  nread =
    nghttp2_frame_decode_window_update(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);
}

void test_nghttp2_frame_encode_continuation(void) {
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  nghttp2_frame_headers fr, nfr;
  nghttp2_ssize nread;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  fr = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_CONTINUATION,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 1000000007,
      },
    .field_block = nulldata,
    .field_blocklen = 100,
  };

  fr.hd.len = (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr);

  assert_size(100, ==, fr.hd.len);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr);

  assert_int(0, ==, rv);

  nread =
    nghttp2_frame_decode_continuation(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff((nghttp2_ssize)nghttp2_buf_len(&buf), ==, nread);
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_memn_equal(fr.field_block, fr.field_blocklen, nfr.field_block,
                    nfr.field_blocklen);

  /* Prematurely truncated buffer */
  for (i = 0; i < nghttp2_buf_len(&buf) - 1; ++i) {
    nread = nghttp2_frame_decode_continuation(&nfr, buf.pos, i);

    assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);
  }

  /* Wrong frame length */
  fr = (nghttp2_frame_headers){
    .hd =
      {
        .len = 101,
        .type = NGHTTP2_FRAME_CONTINUATION,
        .stream_id = 1000000007,
      },
    .field_block = nulldata,
    .field_blocklen = 100,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr);

  assert_int(0, ==, rv);

  nread =
    nghttp2_frame_decode_continuation(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);
}

void test_nghttp2_frame_encode_priority_update(void) {
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  nghttp2_frame_priority_update fr, nfr;
  nghttp2_ssize nread;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  fr = (nghttp2_frame_priority_update){
    .hd =
      {
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .prioritized_stream_id = 1000000007,
    .pri = nulldata,
    .prilen = 19,
  };

  fr.hd.len = (uint32_t)nghttp2_frame_encode_priority_update_payloadlen(&fr);

  assert_size(4 + 19, ==, fr.hd.len);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_priority_update(&buf, &fr);

  assert_int(0, ==, rv);

  nread =
    nghttp2_frame_decode_priority_update(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff((nghttp2_ssize)nghttp2_buf_len(&buf), ==, nread);
  assert_uint32(fr.hd.len, ==, nfr.hd.len);
  assert_uint8(fr.hd.type, ==, nfr.hd.type);
  assert_uint8(fr.hd.flags, ==, nfr.hd.flags);
  assert_int64(fr.hd.stream_id, ==, nfr.hd.stream_id);
  assert_uint32(fr.prioritized_stream_id, ==, nfr.prioritized_stream_id);
  assert_memn_equal(fr.pri, fr.prilen, nfr.pri, nfr.prilen);

  /* Prematurely truncated buffer */
  for (i = 0; i < nghttp2_buf_len(&buf) - 1; ++i) {
    nread = nghttp2_frame_decode_priority_update(&nfr, buf.pos, i);

    assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);
  }

  /* Wrong frame length */
  fr = (nghttp2_frame_priority_update){
    .hd =
      {
        .len = 3,
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .prioritized_stream_id = 1000000007,
    .pri = nulldata,
    .prilen = 19,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_priority_update(&buf, &fr);

  assert_int(0, ==, rv);

  nread =
    nghttp2_frame_decode_priority_update(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);

  /* Wrong frame length */
  fr = (nghttp2_frame_priority_update){
    .hd =
      {
        .len = 24,
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .prioritized_stream_id = 1000000007,
    .pri = nulldata,
    .prilen = 19,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_priority_update(&buf, &fr);

  assert_int(0, ==, rv);

  nread =
    nghttp2_frame_decode_priority_update(&nfr, buf.pos, nghttp2_buf_len(&buf));

  assert_ptrdiff(NGHTTP2_ERR_FRAME_ENCODING, ==, nread);
}
