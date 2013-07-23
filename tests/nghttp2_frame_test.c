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

static const char *headers[] = {
  "method", "GET",
  "scheme", "https",
  "url", "/",
  "x-head", "foo",
  "x-head", "bar",
  "version", "HTTP/1.1",
  "x-empty", "",
  NULL
};

void test_nghttp2_frame_nv_sort(void)
{
  char *nv[7];
  nv[0] = (char*)"version";
  nv[1] = (char*)"HTTP/1.1";
  nv[2] = (char*)"method";
  nv[3] = (char*)"GET";
  nv[4] = (char*)"scheme";
  nv[5] = (char*)"https";
  nv[6] = NULL;
  nghttp2_frame_nv_sort(nv);
  CU_ASSERT(strcmp("method", nv[0]) == 0);
  CU_ASSERT(strcmp("GET", nv[1]) == 0);
  CU_ASSERT(strcmp("scheme", nv[2]) == 0);
  CU_ASSERT(strcmp("https", nv[3]) == 0);
  CU_ASSERT(strcmp("version", nv[4]) == 0);
  CU_ASSERT(strcmp("HTTP/1.1", nv[5]) == 0);
}

void test_nghttp2_frame_nv_downcase(void)
{
  const char *nv_src[] = {
    "VERSION", "HTTP/1.1",
    "Content-Length", "1000000007",
    NULL
  };
  char **nv;
  nv = nghttp2_frame_nv_copy(nv_src);
  nghttp2_frame_nv_downcase(nv);
  CU_ASSERT(0 == strcmp("version", nv[0]));
  CU_ASSERT(0 == strcmp("HTTP/1.1", nv[1]));
  CU_ASSERT(0 == strcmp("content-length", nv[2]));
  CU_ASSERT(0 == strcmp("1000000007", nv[3]));
  nghttp2_frame_nv_del(nv);
}

void test_nghttp2_frame_nv_check_null(void)
{
  const char *headers1[] = { "path", "/", "host", "a", NULL };
  const char *headers2[] = { "", "/", "host", "a", NULL };
  const char *headers3[] = { "path", "/", "host\x01", "a", NULL };
  const char *headers4[] = { "path", "/", "host", NULL, NULL };

  CU_ASSERT(nghttp2_frame_nv_check_null(headers1));
  CU_ASSERT(0 == nghttp2_frame_nv_check_null(headers2));
  CU_ASSERT(0 == nghttp2_frame_nv_check_null(headers3));
  CU_ASSERT(0 == nghttp2_frame_nv_check_null(headers4));
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
  nghttp2_hd_context deflater, inflater;
  nghttp2_headers frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  nghttp2_nv *nva;
  ssize_t nvlen;

  nghttp2_hd_deflate_init(&deflater, NGHTTP2_HD_SIDE_CLIENT);
  nghttp2_hd_inflate_init(&inflater, NGHTTP2_HD_SIDE_SERVER);

  nvlen = nghttp2_nv_array_from_cstr(&nva, headers);
  nghttp2_frame_headers_init(&frame, NGHTTP2_FLAG_END_STREAM, 1000000007,
                             1 << 20, nva, nvlen);
  framelen = nghttp2_frame_pack_headers(&buf, &buflen, &frame, &deflater);

  CU_ASSERT(0 == unpack_frame_with_nv_block((nghttp2_frame*)&oframe,
                                            NGHTTP2_HEADERS,
                                            &inflater,
                                            buf, framelen));
  check_frame_header(framelen - NGHTTP2_FRAME_HEAD_LENGTH, NGHTTP2_HEADERS,
                     NGHTTP2_FLAG_END_STREAM, 1000000007, &oframe.hd);
  /* We didn't include PRIORITY flag so priority is not packed */
  CU_ASSERT(1 << 30 == oframe.pri);
  CU_ASSERT(7 == oframe.nvlen);
  CU_ASSERT(memcmp("method", oframe.nva[0].name, oframe.nva[0].namelen) == 0);
  CU_ASSERT(nvnameeq("method", &oframe.nva[0]));
  CU_ASSERT(nvvalueeq("GET", &oframe.nva[0]));

  nghttp2_frame_headers_free(&oframe);
  memset(&oframe, 0, sizeof(oframe));
  /* Next, include PRIORITY flag */
  frame.hd.flags |= NGHTTP2_FLAG_PRIORITY;
  framelen = nghttp2_frame_pack_headers(&buf, &buflen, &frame, &deflater);

  CU_ASSERT(0 == unpack_frame_with_nv_block((nghttp2_frame*)&oframe,
                                            NGHTTP2_HEADERS,
                                            &inflater,
                                            buf, framelen));
  check_frame_header(framelen - NGHTTP2_FRAME_HEAD_LENGTH, NGHTTP2_HEADERS,
                     NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_PRIORITY,
                     1000000007, &oframe.hd);
  CU_ASSERT(1 << 20 == oframe.pri);
  CU_ASSERT(nvnameeq("method", &oframe.nva[0]));

  free(buf);
  nghttp2_frame_headers_free(&oframe);
  nghttp2_frame_headers_free(&frame);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_frame_pack_headers_frame_too_large(void)
{
  nghttp2_hd_context deflater;
  nghttp2_headers frame;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  nghttp2_nv *nva;
  ssize_t nvlen;
  size_t big_vallen = (1 << 16) - 1;
  char *big_val = malloc(big_vallen + 1);
  const char *big_hds[] = { "header", big_val, NULL };

  memset(big_val, '0', big_vallen);
  big_val[big_vallen] = '\0';
  nvlen = nghttp2_nv_array_from_cstr(&nva, big_hds);
  nghttp2_hd_deflate_init(&deflater, NGHTTP2_HD_SIDE_CLIENT);
  nghttp2_frame_headers_init(&frame, NGHTTP2_FLAG_END_STREAM, 1000000007,
                             0, nva, nvlen);
  framelen = nghttp2_frame_pack_headers(&buf, &buflen, &frame, &deflater);
  CU_ASSERT_EQUAL(NGHTTP2_ERR_HEADER_COMP, framelen);

  nghttp2_frame_headers_free(&frame);
  free(buf);
  free(big_val);
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
  CU_ASSERT(0 == nghttp2_frame_unpack_priority
            (&oframe,
             &buf[0], NGHTTP2_FRAME_HEAD_LENGTH,
             &buf[NGHTTP2_FRAME_HEAD_LENGTH],
             framelen - NGHTTP2_FRAME_HEAD_LENGTH));
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
  CU_ASSERT(0 == nghttp2_frame_unpack_rst_stream
            (&oframe,
             &buf[0], NGHTTP2_FRAME_HEAD_LENGTH,
             &buf[NGHTTP2_FRAME_HEAD_LENGTH],
             framelen - NGHTTP2_FRAME_HEAD_LENGTH));
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
  iv[2].settings_id = NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS;
  iv[2].value = 1;

  nghttp2_frame_settings_init(&frame, nghttp2_frame_iv_copy(iv, 3), 3);
  framelen = nghttp2_frame_pack_settings(&buf, &buflen, &frame);
  CU_ASSERT(NGHTTP2_FRAME_HEAD_LENGTH+3*8 == framelen);

  CU_ASSERT(0 == nghttp2_frame_unpack_settings
            (&oframe,
             &buf[0], NGHTTP2_FRAME_HEAD_LENGTH,
             &buf[NGHTTP2_FRAME_HEAD_LENGTH],
             framelen - NGHTTP2_FRAME_HEAD_LENGTH));

  check_frame_header(3*8, NGHTTP2_SETTINGS, NGHTTP2_FLAG_NONE, 0, &oframe.hd);
  CU_ASSERT(3 == oframe.niv);
  for(i = 0; i < 3; ++i) {
    CU_ASSERT(iv[i].settings_id == oframe.iv[i].settings_id);
    CU_ASSERT(iv[i].value == oframe.iv[i].value);
  }

  free(buf);
  nghttp2_frame_settings_free(&frame);
  nghttp2_frame_settings_free(&oframe);
}

void test_nghttp2_frame_pack_ping(void)
{
  nghttp2_ping frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  const uint8_t opaque_data[] = "01234567";
  nghttp2_frame_ping_init(&frame, NGHTTP2_FLAG_PONG, opaque_data);
  framelen = nghttp2_frame_pack_ping(&buf, &buflen, &frame);
  CU_ASSERT(0 == nghttp2_frame_unpack_ping
            (&oframe,
             &buf[0], NGHTTP2_FRAME_HEAD_LENGTH,
             &buf[NGHTTP2_FRAME_HEAD_LENGTH],
             framelen - NGHTTP2_FRAME_HEAD_LENGTH));
  check_frame_header(8, NGHTTP2_PING, NGHTTP2_FLAG_PONG, 0, &oframe.hd);
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
  CU_ASSERT(0 == nghttp2_frame_unpack_goaway
            (&oframe,
             &buf[0], NGHTTP2_FRAME_HEAD_LENGTH,
             &buf[NGHTTP2_FRAME_HEAD_LENGTH],
             framelen-NGHTTP2_FRAME_HEAD_LENGTH));
  check_frame_header(24, NGHTTP2_GOAWAY, NGHTTP2_FLAG_NONE, 0, &oframe.hd);
  CU_ASSERT(1000000007 == oframe.last_stream_id);
  CU_ASSERT(NGHTTP2_PROTOCOL_ERROR == oframe.error_code);
  CU_ASSERT(opaque_data_len == oframe.opaque_data_len);
  CU_ASSERT(memcmp(opaque_data, oframe.opaque_data, opaque_data_len) == 0);
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
  nghttp2_frame_window_update_init(&frame, NGHTTP2_FLAG_END_FLOW_CONTROL,
                                   1000000007, 4096);
  framelen = nghttp2_frame_pack_window_update(&buf, &buflen,
                                              &frame);
  CU_ASSERT(0 == nghttp2_frame_unpack_window_update
            (&oframe,
             &buf[0], NGHTTP2_FRAME_HEAD_LENGTH,
             &buf[NGHTTP2_FRAME_HEAD_LENGTH],
             framelen - NGHTTP2_FRAME_HEAD_LENGTH));
  check_frame_header(4, NGHTTP2_WINDOW_UPDATE, NGHTTP2_FLAG_END_FLOW_CONTROL,
                     1000000007, &oframe.hd);
  CU_ASSERT(4096 == oframe.window_size_increment);
  free(buf);
  nghttp2_frame_window_update_free(&oframe);
  nghttp2_frame_window_update_free(&frame);
}

void test_nghttp2_nv_array_from_cstr(void)
{
  const char *empty[] = {NULL};
  const char *emptynv[] = {"", "", "", "", NULL};
  const char *nv[] = {"alpha", "bravo", "charlie", "delta", NULL};
  const char *bignv[] = {"echo", NULL, NULL};
  size_t bigvallen = 64*1024;
  char *bigval = malloc(bigvallen+1);
  nghttp2_nv *nva;
  ssize_t rv;

  memset(bigval, '0', bigvallen);
  bigval[bigvallen] = '\0';
  bignv[1] = bigval;

  rv = nghttp2_nv_array_from_cstr(&nva, empty);
  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == nva);

  rv = nghttp2_nv_array_from_cstr(&nva, emptynv);
  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == nva);

  rv = nghttp2_nv_array_from_cstr(&nva, nv);
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

  rv = nghttp2_nv_array_from_cstr(&nva, bignv);
  CU_ASSERT(NGHTTP2_ERR_INVALID_ARGUMENT == rv);

  free(bigval);
}
