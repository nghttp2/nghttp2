/*
 * Spdylay - SPDY Library
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
#include "spdylay_frame_test.h"

#include <CUnit/CUnit.h>

#include "spdylay_frame.h"
#include "spdylay_helper.h"

static const char *headers[] = {
  "method", "GET",
  "scheme", "https",
  "url", "/",
  "x-head", "foo",
  "x-head", "bar",
  "version", "HTTP/1.1",
  NULL
};

void test_spdylay_frame_unpack_nv()
{
  uint8_t out[1024];
  char **nv;
  size_t inlen = spdylay_frame_pack_nv(out, (char**)headers);
  CU_ASSERT(0 == spdylay_frame_unpack_nv(&nv, out, inlen));
  CU_ASSERT(strcmp("method", nv[0]) == 0);
  CU_ASSERT(strcmp("GET", nv[1]) == 0);
  CU_ASSERT(strcmp("scheme", nv[2]) == 0);
  CU_ASSERT(strcmp("https", nv[3]) == 0);
  CU_ASSERT(strcmp("url", nv[4]) == 0);
  CU_ASSERT(strcmp("/", nv[5]) == 0);
  CU_ASSERT(strcmp("x-head", nv[6]) == 0);
  CU_ASSERT(strcmp("foo", nv[7]) == 0);
  CU_ASSERT(strcmp("x-head", nv[8]) == 0);
  CU_ASSERT(strcmp("bar", nv[9]) == 0);
  CU_ASSERT(strcmp("version", nv[10]) == 0);
  CU_ASSERT(strcmp("HTTP/1.1", nv[11]) == 0);
  spdylay_frame_nv_del(nv);
}

void test_spdylay_frame_pack_nv_duplicate_keys()
{
  int i;
  uint8_t out[1024];
  const char *nv_src[] = {
    "method", "GET",
    "scheme", "https",
    "url", "/",
    "X-hEad", "foo",
    "x-heaD", "bar",
    "version", "HTTP/1.1",
    NULL
  };
  char **nv = spdylay_frame_nv_copy(nv_src);
  spdylay_frame_nv_downcase(nv);
  spdylay_frame_nv_sort(nv);
  size_t inlen = spdylay_frame_pack_nv(out, nv);
  const uint8_t *outptr = out;
  int pairs = spdylay_get_uint16(outptr);
  CU_ASSERT(pairs == 5);
  outptr += 2;

  int len = spdylay_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 6);
  CU_ASSERT(memcmp(outptr, "method", len) == 0);
  outptr += len;

  len = spdylay_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 3);
  CU_ASSERT(memcmp(outptr, "GET", len) == 0);
  outptr += len;

  len = spdylay_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 6);
  CU_ASSERT(memcmp(outptr, "scheme", len) == 0);
  outptr += len;

  len = spdylay_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 5);
  CU_ASSERT(memcmp(outptr, "https", len) == 0);
  outptr += len;

  len = spdylay_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 3);
  CU_ASSERT(memcmp(outptr, "url", len) == 0);
  outptr += len;

  len = spdylay_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 1);
  CU_ASSERT(memcmp(outptr, "/", len) == 0);
  outptr += len;

  len = spdylay_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 7);
  CU_ASSERT(memcmp(outptr, "version", len) == 0);
  outptr += len;

  len = spdylay_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 8);
  CU_ASSERT(memcmp(outptr, "HTTP/1.1", len) == 0);
  outptr += len;


  len = spdylay_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 6);
  CU_ASSERT(memcmp(outptr, "x-head", len) == 0);
  outptr += len;

  len = spdylay_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 7);
  CU_ASSERT(memcmp(outptr, "foo\0bar", len) == 0);
  outptr += len;

  spdylay_frame_nv_del(nv);
}

void test_spdylay_frame_count_nv_space()
{
  CU_ASSERT(83 == spdylay_frame_count_nv_space((char**)headers));
}

void test_spdylay_frame_count_unpack_nv_space()
{
  size_t nvlen, buflen;
  uint8_t out[1024];
  size_t inlen = spdylay_frame_pack_nv(out, (char**)headers);
  uint16_t temp;
  CU_ASSERT(0 == spdylay_frame_count_unpack_nv_space(&nvlen, &buflen,
                                                     out, inlen));
  CU_ASSERT(6 == nvlen);
  CU_ASSERT(166 == buflen);
  /* Change number of nv pair to a bogus value */
  temp = spdylay_get_uint16(out);
  spdylay_put_uint16be(out, temp+1);
  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_frame_count_unpack_nv_space(&nvlen, &buflen, out, inlen));
  spdylay_put_uint16be(out, temp);

  /* Change the length of name to a bogus value */
  temp = spdylay_get_uint16(out+2);
  spdylay_put_uint16be(out+2, temp+1);
  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_frame_count_unpack_nv_space(&nvlen, &buflen, out, inlen));
  spdylay_put_uint16be(out+2, 65535);
  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_frame_count_unpack_nv_space(&nvlen, &buflen, out, inlen));
}

void test_spdylay_frame_pack_ping()
{
  spdylay_frame frame, oframe;
  uint8_t *buf;
  ssize_t buflen;
  spdylay_frame_ping_init(&frame.ping, 1);
  buflen = spdylay_frame_pack_ping(&buf, &frame.ping);
  CU_ASSERT(0 == spdylay_frame_unpack_ping
            (&oframe.ping,
             &buf[0], SPDYLAY_FRAME_HEAD_LENGTH,
             &buf[SPDYLAY_FRAME_HEAD_LENGTH],
             buflen-SPDYLAY_FRAME_HEAD_LENGTH));
  CU_ASSERT(1 == oframe.ping.unique_id);
  free(buf);
  spdylay_frame_ping_free(&oframe.ping);
  spdylay_frame_ping_free(&frame.ping);
}

void test_spdylay_frame_pack_goaway()
{
  spdylay_frame frame, oframe;
  uint8_t *buf;
  ssize_t buflen;
  spdylay_frame_goaway_init(&frame.goaway, 1000000007);
  buflen = spdylay_frame_pack_goaway(&buf, &frame.goaway);
  CU_ASSERT(0 == spdylay_frame_unpack_goaway
            (&oframe.goaway,
             &buf[0], SPDYLAY_FRAME_HEAD_LENGTH,
             &buf[SPDYLAY_FRAME_HEAD_LENGTH],
             buflen-SPDYLAY_FRAME_HEAD_LENGTH));
  CU_ASSERT(1000000007 == oframe.goaway.last_good_stream_id);
  CU_ASSERT(SPDYLAY_PROTO_VERSION == oframe.headers.hd.version);
  CU_ASSERT(SPDYLAY_GOAWAY == oframe.headers.hd.type);
  CU_ASSERT(SPDYLAY_FLAG_NONE == oframe.headers.hd.flags);
  CU_ASSERT(buflen-SPDYLAY_FRAME_HEAD_LENGTH == oframe.ping.hd.length);
  free(buf);
  spdylay_frame_goaway_free(&oframe.goaway);
  spdylay_frame_goaway_free(&frame.goaway);
}

void test_spdylay_frame_pack_headers()
{
  spdylay_zlib deflater, inflater;
  spdylay_frame frame, oframe;
  uint8_t *buf;
  ssize_t buflen;
  spdylay_zlib_deflate_hd_init(&deflater);
  spdylay_zlib_inflate_hd_init(&inflater);
  spdylay_frame_headers_init(&frame.headers, SPDYLAY_FLAG_FIN, 3,
                             spdylay_frame_nv_copy(headers));
  buflen = spdylay_frame_pack_headers(&buf, &frame.headers, &deflater);
  CU_ASSERT(0 == spdylay_frame_unpack_headers
            (&oframe.headers,
             &buf[0], SPDYLAY_FRAME_HEAD_LENGTH,
             &buf[SPDYLAY_FRAME_HEAD_LENGTH],
             buflen-SPDYLAY_FRAME_HEAD_LENGTH,
             &inflater));
  CU_ASSERT(3 == oframe.headers.stream_id);
  CU_ASSERT(SPDYLAY_PROTO_VERSION == oframe.headers.hd.version);
  CU_ASSERT(SPDYLAY_HEADERS == oframe.headers.hd.type);
  CU_ASSERT(SPDYLAY_FLAG_FIN == oframe.headers.hd.flags);
  CU_ASSERT(buflen-SPDYLAY_FRAME_HEAD_LENGTH == oframe.ping.hd.length);
  CU_ASSERT(strcmp("method", oframe.headers.nv[0]) == 0);
  CU_ASSERT(strcmp("GET", oframe.headers.nv[1]) == 0);
  CU_ASSERT(NULL == oframe.headers.nv[12]);
  free(buf);
  spdylay_frame_headers_free(&oframe.headers);
  spdylay_frame_headers_free(&frame.headers);
  spdylay_zlib_inflate_free(&inflater);
  spdylay_zlib_deflate_free(&deflater);
}

void test_spdylay_frame_pack_settings()
{
  spdylay_frame frame, oframe;
  uint8_t *buf;
  ssize_t buflen;
  int i;
  spdylay_settings_entry iv[3];
  iv[0].settings_id = SPDYLAY_SETTINGS_UPLOAD_BANDWIDTH;
  iv[0].flags = SPDYLAY_ID_FLAG_SETTINGS_PERSIST_VALUE;
  iv[0].value = 256;
  iv[1].settings_id = SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[1].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;
  iv[1].value = 100;
  iv[2].settings_id = SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[2].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;
  iv[2].value = 65536;

  spdylay_frame_settings_init
    (&frame.settings,
     SPDYLAY_FLAG_SETTINGS_CLEAR_PREVIOUSLY_PERSISTED_SETTINGS,
     spdylay_frame_iv_copy(iv, 3), 3);
  buflen = spdylay_frame_pack_settings(&buf, &frame.settings);
  CU_ASSERT(8+4+3*8 == buflen);

  CU_ASSERT(0 == spdylay_frame_unpack_settings
            (&oframe.settings,
             &buf[0], SPDYLAY_FRAME_HEAD_LENGTH,
             &buf[SPDYLAY_FRAME_HEAD_LENGTH],
             buflen-SPDYLAY_FRAME_HEAD_LENGTH));

  CU_ASSERT(SPDYLAY_PROTO_VERSION == oframe.settings.hd.version);
  CU_ASSERT(SPDYLAY_SETTINGS == oframe.settings.hd.type);
  CU_ASSERT(SPDYLAY_FLAG_SETTINGS_CLEAR_PREVIOUSLY_PERSISTED_SETTINGS ==
            oframe.settings.hd.flags);
  CU_ASSERT(buflen-SPDYLAY_FRAME_HEAD_LENGTH == oframe.settings.hd.length);

  CU_ASSERT(3 == oframe.settings.niv);
  for(i = 0; i < 3; ++i) {
    CU_ASSERT(iv[i].settings_id == oframe.settings.iv[i].settings_id);
    CU_ASSERT(iv[i].flags == oframe.settings.iv[i].flags);
    CU_ASSERT(iv[i].value == oframe.settings.iv[i].value);
  }

  free(buf);
  spdylay_frame_settings_free(&frame.settings);
  spdylay_frame_settings_free(&oframe.settings);
}

void test_spdylay_frame_nv_sort()
{
  char *nv[7];
  nv[0] = (char*)"version";
  nv[1] = (char*)"HTTP/1.1";
  nv[2] = (char*)"method";
  nv[3] = (char*)"GET";
  nv[4] = (char*)"scheme";
  nv[5] = (char*)"https";
  nv[6] = NULL;
  spdylay_frame_nv_sort(nv);
  CU_ASSERT(strcmp("method", nv[0]) == 0);
  CU_ASSERT(strcmp("GET", nv[1]) == 0);
  CU_ASSERT(strcmp("scheme", nv[2]) == 0);
  CU_ASSERT(strcmp("https", nv[3]) == 0);
  CU_ASSERT(strcmp("version", nv[4]) == 0);
  CU_ASSERT(strcmp("HTTP/1.1", nv[5]) == 0);
}

void test_spdylay_frame_nv_downcase()
{
  const char *nv_src[] = {
    "VERSION", "HTTP/1.1",
    "Content-Length", "1000000007",
    NULL
  };
  char **nv;
  nv = spdylay_frame_nv_copy(nv_src);
  spdylay_frame_nv_downcase(nv);
  CU_ASSERT(0 == strcmp("version", nv[0]));
  CU_ASSERT(0 == strcmp("HTTP/1.1", nv[1]));
  CU_ASSERT(0 == strcmp("content-length", nv[2]));
  CU_ASSERT(0 == strcmp("1000000007", nv[3]));
  spdylay_frame_nv_del(nv);
}
