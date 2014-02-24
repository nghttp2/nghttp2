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
#include "nghttp2_frame_test.h"

#include <assert.h>
#include <stdio.h>

#include <CUnit/CUnit.h>

#include "nghttp2_frame.h"
#include "nghttp2_helper.h"
#include "nghttp2_test_helper.h"

static nghttp2_nv make_nv(const char *name, const char *value)
{
  nghttp2_nv nv;
  nv.name = (uint8_t*)name;
  nv.value = (uint8_t*)value;
  nv.namelen = strlen(name);
  nv.valuelen = strlen(value);
  return nv;
}

#define HEADERS_LENGTH 7

static nghttp2_nv* headers(void)
{
  nghttp2_nv *nva = malloc(sizeof(nghttp2_nv) * HEADERS_LENGTH);
  nva[0] = make_nv("method", "GET");
  nva[1] = make_nv("scheme", "https");
  nva[2] = make_nv("url", "/");
  nva[3] = make_nv("x-head", "foo");
  nva[4] = make_nv("x-head", "bar");
  nva[5] = make_nv("version", "HTTP/1.1");
  nva[6] = make_nv("x-empty", "");
  return nva;
}

static void check_frame_header(uint16_t length, uint8_t type, uint8_t flags,
                               int32_t stream_id, nghttp2_frame_hd *hd)
{
  CU_ASSERT(length == hd->length);
  CU_ASSERT(type == hd->type);
  CU_ASSERT(flags == hd->flags);
  CU_ASSERT(stream_id == hd->stream_id);
}

void test_nghttp2_frame_pack_headers()
{
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_headers frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  size_t bufoff;
  ssize_t framelen;
  nghttp2_nv *nva;
  ssize_t nvlen;
  nva_out out;
  ssize_t nv_offset;

  nva_out_init(&out);
  nghttp2_hd_deflate_init(&deflater);
  nghttp2_hd_inflate_init(&inflater);

  nva = headers();
  nvlen = HEADERS_LENGTH;
  nghttp2_frame_headers_init(&frame,
                             NGHTTP2_FLAG_END_STREAM|NGHTTP2_FLAG_END_HEADERS,
                             1000000007,
                             1 << 20, nva, nvlen);
  framelen = nghttp2_frame_pack_headers(&buf, &buflen, &bufoff, &frame,
                                        &deflater);

  CU_ASSERT(0 == unpack_frame((nghttp2_frame*)&oframe, buf + bufoff,
                              framelen - bufoff));
  check_frame_header(framelen - bufoff - NGHTTP2_FRAME_HEAD_LENGTH,
                     NGHTTP2_HEADERS,
                     NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_HEADERS,
                     1000000007, &oframe.hd);
  /* We didn't include PRIORITY flag so priority is not packed */
  CU_ASSERT(1 << 30 == oframe.pri);

  nv_offset = bufoff + NGHTTP2_FRAME_HEAD_LENGTH;
  CU_ASSERT(framelen - nv_offset ==
            inflate_hd(&inflater, &out,
                       buf + nv_offset, framelen - nv_offset));

  CU_ASSERT(7 == out.nvlen);
  CU_ASSERT(nvnameeq("method", &out.nva[0]));
  CU_ASSERT(nvvalueeq("GET", &out.nva[0]));

  nghttp2_frame_headers_free(&oframe);
  nva_out_reset(&out);

  memset(&oframe, 0, sizeof(oframe));
  /* Next, include PRIORITY flag */
  frame.hd.flags |= NGHTTP2_FLAG_PRIORITY;
  framelen = nghttp2_frame_pack_headers(&buf, &buflen, &bufoff, &frame,
                                        &deflater);

  CU_ASSERT(0 == unpack_frame((nghttp2_frame*)&oframe, buf + bufoff,
                              framelen - bufoff));
  check_frame_header(framelen - bufoff - NGHTTP2_FRAME_HEAD_LENGTH,
                     NGHTTP2_HEADERS,
                     NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_HEADERS |
                     NGHTTP2_FLAG_PRIORITY,
                     1000000007, &oframe.hd);
  CU_ASSERT(1 << 20 == oframe.pri);

  nv_offset = bufoff + NGHTTP2_FRAME_HEAD_LENGTH + 4;
  CU_ASSERT(framelen - nv_offset ==
            inflate_hd(&inflater, &out,
                       buf + nv_offset, framelen - nv_offset));

  nghttp2_nv_array_sort(out.nva, out.nvlen);
  CU_ASSERT(nvnameeq("method", &out.nva[0]));

  nva_out_reset(&out);
  free(buf);
  nghttp2_frame_headers_free(&oframe);
  nghttp2_frame_headers_free(&frame);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_frame_pack_headers_frame_too_large(void)
{
  nghttp2_hd_deflater deflater;
  nghttp2_headers frame;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  size_t bufoff;
  ssize_t framelen;
  nghttp2_nv *nva;
  ssize_t nvlen;
  size_t big_vallen = NGHTTP2_HD_MAX_VALUE;
  nghttp2_nv big_hds[16];
  size_t big_hdslen = ARRLEN(big_hds);
  size_t i;

  for(i = 0; i < big_hdslen; ++i) {
    big_hds[i].name = (uint8_t*)"header";
    big_hds[i].value = malloc(big_vallen+1);
    memset(big_hds[i].value, '0'+i, big_vallen);
    big_hds[i].value[big_vallen] = '\0';
    big_hds[i].namelen = strlen((char*)big_hds[i].name);
    big_hds[i].valuelen = big_vallen;
  }

  nvlen = nghttp2_nv_array_copy(&nva, big_hds, big_hdslen);
  nghttp2_hd_deflate_init(&deflater);
  nghttp2_frame_headers_init(&frame,
                             NGHTTP2_FLAG_END_STREAM|NGHTTP2_FLAG_END_HEADERS,
                             1000000007,
                             0, nva, nvlen);
  framelen = nghttp2_frame_pack_headers(&buf, &buflen, &bufoff, &frame,
                                        &deflater);
  CU_ASSERT_EQUAL(NGHTTP2_ERR_HEADER_COMP, framelen);

  nghttp2_frame_headers_free(&frame);
  free(buf);
  for(i = 0; i < big_hdslen; ++i) {
    free(big_hds[i].value);
  }
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_frame_pack_priority(void)
{
  nghttp2_priority frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  nghttp2_frame_priority_init(&frame, 1000000007, 1 << 30);
  framelen = nghttp2_frame_pack_priority(&buf, &buflen, &frame);
  CU_ASSERT(0 == unpack_frame((nghttp2_frame*)&oframe, buf, framelen));
  check_frame_header(4, NGHTTP2_PRIORITY, NGHTTP2_FLAG_NONE, 1000000007,
                     &oframe.hd);
  CU_ASSERT(1 << 30 == oframe.pri);
  free(buf);
  nghttp2_frame_priority_free(&oframe);
  nghttp2_frame_priority_free(&frame);
}

void test_nghttp2_frame_pack_rst_stream(void)
{
  nghttp2_rst_stream frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  nghttp2_frame_rst_stream_init(&frame, 1000000007, NGHTTP2_PROTOCOL_ERROR);
  framelen = nghttp2_frame_pack_rst_stream(&buf, &buflen, &frame);
  CU_ASSERT(0 == unpack_frame((nghttp2_frame*)&oframe, buf, framelen));
  check_frame_header(4, NGHTTP2_RST_STREAM, NGHTTP2_FLAG_NONE, 1000000007,
                     &oframe.hd);
  CU_ASSERT(NGHTTP2_PROTOCOL_ERROR == oframe.error_code);
  free(buf);
  nghttp2_frame_rst_stream_free(&oframe);
  nghttp2_frame_rst_stream_free(&frame);
}

void test_nghttp2_frame_pack_settings()
{
  nghttp2_settings frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  int i;
  nghttp2_settings_entry iv[3];
  iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = 256;
  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 16384;
  iv[2].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[2].value = 4096;

  nghttp2_frame_settings_init(&frame, NGHTTP2_FLAG_NONE,
                              nghttp2_frame_iv_copy(iv, 3), 3);
  framelen = nghttp2_frame_pack_settings(&buf, &buflen, &frame);
  CU_ASSERT(NGHTTP2_FRAME_HEAD_LENGTH +
            3 * NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH == framelen);
  CU_ASSERT(0 == unpack_frame((nghttp2_frame*)&oframe, buf, framelen));
  check_frame_header(3 * NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH,
                     NGHTTP2_SETTINGS, NGHTTP2_FLAG_NONE, 0, &oframe.hd);
  CU_ASSERT(3 == oframe.niv);
  for(i = 0; i < 3; ++i) {
    CU_ASSERT(iv[i].settings_id == oframe.iv[i].settings_id);
    CU_ASSERT(iv[i].value == oframe.iv[i].value);
  }

  free(buf);
  nghttp2_frame_settings_free(&frame);
  nghttp2_frame_settings_free(&oframe);
}

void test_nghttp2_frame_pack_push_promise()
{
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_push_promise frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  size_t bufoff;
  ssize_t framelen;
  nghttp2_nv *nva;
  ssize_t nvlen;
  nva_out out;
  ssize_t nv_offset;

  nva_out_init(&out);
  nghttp2_hd_deflate_init(&deflater);
  nghttp2_hd_inflate_init(&inflater);

  nva = headers();
  nvlen = HEADERS_LENGTH;
  nghttp2_frame_push_promise_init(&frame, NGHTTP2_FLAG_END_HEADERS,
                                  1000000007, (1U << 31) - 1, nva, nvlen);
  framelen = nghttp2_frame_pack_push_promise(&buf, &buflen, &bufoff, &frame,
                                             &deflater);

  CU_ASSERT(0 == unpack_frame((nghttp2_frame*)&oframe,
                              buf + bufoff, framelen - bufoff));
  check_frame_header(framelen - bufoff - NGHTTP2_FRAME_HEAD_LENGTH,
                     NGHTTP2_PUSH_PROMISE,
                     NGHTTP2_FLAG_END_HEADERS, 1000000007, &oframe.hd);
  CU_ASSERT((1U << 31) - 1 == oframe.promised_stream_id);

  nv_offset = bufoff + NGHTTP2_FRAME_HEAD_LENGTH + 4;
  CU_ASSERT(framelen - nv_offset ==
            inflate_hd(&inflater, &out, buf + nv_offset, framelen - nv_offset));

  CU_ASSERT(7 == out.nvlen);
  CU_ASSERT(nvnameeq("method", &out.nva[0]));
  CU_ASSERT(nvvalueeq("GET", &out.nva[0]));

  nva_out_reset(&out);
  free(buf);
  nghttp2_frame_push_promise_free(&oframe);
  nghttp2_frame_push_promise_free(&frame);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_frame_pack_ping(void)
{
  nghttp2_ping frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  const uint8_t opaque_data[] = "01234567";
  nghttp2_frame_ping_init(&frame, NGHTTP2_FLAG_ACK, opaque_data);
  framelen = nghttp2_frame_pack_ping(&buf, &buflen, &frame);
  CU_ASSERT(0 == unpack_frame((nghttp2_frame*)&oframe, buf, framelen));
  check_frame_header(8, NGHTTP2_PING, NGHTTP2_FLAG_ACK, 0, &oframe.hd);
  CU_ASSERT(memcmp(opaque_data, oframe.opaque_data, sizeof(opaque_data) - 1)
            == 0);
  free(buf);
  nghttp2_frame_ping_free(&oframe);
  nghttp2_frame_ping_free(&frame);
}

void test_nghttp2_frame_pack_goaway()
{
  nghttp2_goaway frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  size_t opaque_data_len = 16;
  uint8_t *opaque_data = malloc(opaque_data_len);

  memcpy(opaque_data, "0123456789abcdef", opaque_data_len);
  nghttp2_frame_goaway_init(&frame, 1000000007, NGHTTP2_PROTOCOL_ERROR,
                            opaque_data, opaque_data_len);
  framelen = nghttp2_frame_pack_goaway(&buf, &buflen, &frame);
  CU_ASSERT(0 == unpack_frame((nghttp2_frame*)&oframe, buf, framelen));
  check_frame_header(24, NGHTTP2_GOAWAY, NGHTTP2_FLAG_NONE, 0, &oframe.hd);
  CU_ASSERT(1000000007 == oframe.last_stream_id);
  CU_ASSERT(NGHTTP2_PROTOCOL_ERROR == oframe.error_code);
  /* TODO Currently, opaque data is discarded */
  CU_ASSERT(0 == oframe.opaque_data_len);
  CU_ASSERT(NULL == oframe.opaque_data);
  /* CU_ASSERT(opaque_data_len == oframe.opaque_data_len); */
  /* CU_ASSERT(memcmp(opaque_data, oframe.opaque_data, opaque_data_len) == 0); */
  free(buf);
  nghttp2_frame_goaway_free(&oframe);
  nghttp2_frame_goaway_free(&frame);
}

void test_nghttp2_frame_pack_window_update(void)
{
  nghttp2_window_update frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;

  nghttp2_frame_window_update_init(&frame, NGHTTP2_FLAG_NONE,
                                   1000000007, 4096);
  framelen = nghttp2_frame_pack_window_update(&buf, &buflen,
                                              &frame);
  CU_ASSERT(0 == unpack_frame((nghttp2_frame*)&oframe, buf, framelen));
  check_frame_header(4, NGHTTP2_WINDOW_UPDATE, NGHTTP2_FLAG_NONE,
                     1000000007, &oframe.hd);
  CU_ASSERT(4096 == oframe.window_size_increment);
  free(buf);
  nghttp2_frame_window_update_free(&oframe);
  nghttp2_frame_window_update_free(&frame);
}

void test_nghttp2_nv_array_copy(void)
{
  nghttp2_nv *nva;
  ssize_t rv;
  nghttp2_nv emptynv[] = {MAKE_NV("", ""),
                          MAKE_NV("", "")};
  nghttp2_nv nv[] = {MAKE_NV("alpha", "bravo"),
                     MAKE_NV("charlie", "delta")};
  nghttp2_nv bignv;

  bignv.name = (uint8_t*)"echo";
  bignv.namelen = (uint16_t)strlen("echo");
  bignv.valuelen = (1 << 14) - 1;
  bignv.value = malloc(bignv.valuelen);
  memset(bignv.value, '0', bignv.valuelen);

  rv = nghttp2_nv_array_copy(&nva, NULL, 0);
  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == nva);

  rv = nghttp2_nv_array_copy(&nva, emptynv, ARRLEN(emptynv));
  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == nva);

  rv = nghttp2_nv_array_copy(&nva, nv, ARRLEN(nv));
  CU_ASSERT(2 == rv);
  CU_ASSERT(nva[0].namelen == 5);
  CU_ASSERT(0 == memcmp("alpha", nva[0].name, 5));
  CU_ASSERT(nva[0].valuelen = 5);
  CU_ASSERT(0 == memcmp("bravo", nva[0].value, 5));
  CU_ASSERT(nva[1].namelen == 7);
  CU_ASSERT(0 == memcmp("charlie", nva[1].name, 7));
  CU_ASSERT(nva[1].valuelen == 5);
  CU_ASSERT(0 == memcmp("delta", nva[1].value, 5));

  nghttp2_nv_array_del(nva);

  /* Large header field is acceptable */
  rv = nghttp2_nv_array_copy(&nva, &bignv, 1);
  CU_ASSERT(1 == rv);

  free(bignv.value);
}

void test_nghttp2_iv_check(void)
{
  nghttp2_settings_entry iv[5];

  iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = 100;
  iv[1].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[1].value = 1024;

  CU_ASSERT(nghttp2_iv_check(iv, 2));

  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = NGHTTP2_MAX_WINDOW_SIZE;
  CU_ASSERT(nghttp2_iv_check(iv, 2));

  /* Too large window size */
  iv[1].value = (uint32_t)NGHTTP2_MAX_WINDOW_SIZE + 1;
  CU_ASSERT(0 == nghttp2_iv_check(iv, 2));

  /* ENABLE_PUSH only allows 0 or 1 */
  iv[1].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
  iv[1].value = 0;
  CU_ASSERT(nghttp2_iv_check(iv, 2));
  iv[1].value = 1;
  CU_ASSERT(nghttp2_iv_check(iv, 2));
  iv[1].value = 3;
  CU_ASSERT(!nghttp2_iv_check(iv, 2));

  /* Undefined SETTINGS ID */
  iv[1].settings_id = 1000000009;
  iv[1].value = 0;
  CU_ASSERT(!nghttp2_iv_check(iv, 2));
}
