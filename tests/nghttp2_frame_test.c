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

/* Reads |len_size| byte from |data| as 2 bytes network byte
   order integer, and returns it in host byte order. */
static int get_packed_hd_len(uint8_t *data, size_t len_size)
{
  return nghttp2_get_uint16(data);
}

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

void test_nghttp2_frame_unpack_nv()
{
  size_t len_size = 2;
  uint8_t out[1024];
  char **nv;
  size_t inlen = nghttp2_frame_pack_nv(out, (char**)headers, len_size);
  nghttp2_buffer buffer;

  nghttp2_buffer_init(&buffer, 4096);
  nghttp2_buffer_write(&buffer, out, inlen);

  CU_ASSERT(0 == nghttp2_frame_unpack_nv(&nv, &buffer, len_size));
  CU_ASSERT(strcmp("method", nv[0]) == 0);
  CU_ASSERT(strcmp("GET", nv[1]) == 0);
  CU_ASSERT(strcmp("scheme", nv[2]) == 0);
  CU_ASSERT(strcmp("https", nv[3]) == 0);
  CU_ASSERT(strcmp("url", nv[4]) == 0);
  CU_ASSERT(strcmp("/", nv[5]) == 0);
  CU_ASSERT(strcmp("version", nv[6]) == 0);
  CU_ASSERT(strcmp("HTTP/1.1", nv[7]) == 0);
  CU_ASSERT(strcmp("x-empty", nv[8]) == 0);
  CU_ASSERT(strcmp("", nv[9]) == 0);
  CU_ASSERT(strcmp("x-head", nv[10]) == 0);
  CU_ASSERT(strcmp("foo", nv[11]) == 0);
  CU_ASSERT(strcmp("x-head", nv[12]) == 0);
  CU_ASSERT(strcmp("bar", nv[13]) == 0);
  nghttp2_frame_nv_del(nv);

  /* Create in-sequence NUL bytes */
  /* Assuming first chunk has enough space to store 1st name/value
     pair. */
  memcpy(&buffer.root.next->data[len_size +
                                 len_size + strlen(headers[0]) +
                                 len_size + strlen(headers[1])-2],
         "\0\0", 2);
  CU_ASSERT(NGHTTP2_ERR_INVALID_HEADER_BLOCK ==
            nghttp2_frame_unpack_nv(&nv, &buffer, len_size));

  nghttp2_frame_nv_del(nv);
  nghttp2_buffer_free(&buffer);
}

/* This function intentionally does not merge same header field into
   one */
static size_t nghttp2_pack_nv(uint8_t *buf, size_t buflen, const char **nv,
                              size_t len_size)
{
  size_t i, n;
  uint8_t *buf_ptr;
  buf_ptr = buf;
  for(n = 0; nv[n]; ++n);
  nghttp2_frame_put_nv_len(buf_ptr, n/2);
  buf_ptr += len_size;
  for(i = 0; i < n; ++i) {
    size_t len = strlen(nv[i]);
    nghttp2_frame_put_nv_len(buf_ptr, len);
    buf_ptr += len_size;
    memcpy(buf_ptr, nv[i], len);
    buf_ptr += len;
  }
  return buf_ptr-buf;
}

static const char *empty_name_headers[] = {
  "method", "GET",
  "", "https",
  "url", "/",
  NULL
};

static const char non_ascii_header_name[] = { (char)0xff };

static const char *non_ascii_headers[] = {
  non_ascii_header_name, "foo",
  NULL
};

void test_nghttp2_frame_unpack_nv_check_name()
{
  size_t len_size = 2;
  uint8_t nvbuf[1024];
  size_t nvbuflen;
  nghttp2_buffer buffer;
  char **nv;

  nghttp2_buffer_init(&buffer, 32);

  nvbuflen = nghttp2_pack_nv(nvbuf, sizeof(nvbuf), headers, len_size);
  nghttp2_buffer_write(&buffer, nvbuf, nvbuflen);

  CU_ASSERT(NGHTTP2_ERR_INVALID_HEADER_BLOCK ==
            nghttp2_frame_unpack_nv(&nv, &buffer, len_size));

  nghttp2_frame_nv_del(nv);
  nghttp2_buffer_reset(&buffer);

  nvbuflen = nghttp2_pack_nv(nvbuf, sizeof(nvbuf), empty_name_headers,
                             len_size);
  nghttp2_buffer_write(&buffer, nvbuf, nvbuflen);

  CU_ASSERT(NGHTTP2_ERR_INVALID_HEADER_BLOCK ==
            nghttp2_frame_unpack_nv(&nv, &buffer, len_size));

  nghttp2_frame_nv_del(nv);
  nghttp2_buffer_reset(&buffer);

  nvbuflen = nghttp2_pack_nv(nvbuf, sizeof(nvbuf), non_ascii_headers,
                             len_size);
  nghttp2_buffer_write(&buffer, nvbuf, nvbuflen);
  CU_ASSERT(NGHTTP2_ERR_INVALID_HEADER_BLOCK ==
            nghttp2_frame_unpack_nv(&nv, &buffer, len_size));

  nghttp2_frame_nv_del(nv);
  nghttp2_buffer_free(&buffer);
}

void test_nghttp2_frame_unpack_nv_last_empty_value()
{
  size_t len_size = 2;
  size_t nvbuflen;
  uint8_t nvbuf[256];
  uint8_t *nvbufptr;
  nghttp2_buffer buffer;
  char **outnv = 0;
  const char hdname[] = "method";

  nvbufptr = nvbuf;
  nghttp2_frame_put_nv_len(nvbufptr, 1);
  nvbufptr += len_size;
  nghttp2_frame_put_nv_len(nvbufptr, sizeof(hdname)-1);
  nvbufptr += len_size;
  memcpy(nvbufptr, hdname, sizeof(hdname)-1);
  nvbufptr += sizeof(hdname)-1;
  nghttp2_frame_put_nv_len(nvbufptr, 4);
  nvbufptr += len_size;
  /* Copy including terminating NULL */
  memcpy(nvbufptr, "GET", 4);
  nvbufptr += 4;
  nvbuflen = nvbufptr - nvbuf;

  nghttp2_buffer_init(&buffer, 32);

  nghttp2_buffer_write(&buffer, nvbuf, nvbuflen);
  CU_ASSERT(NGHTTP2_ERR_INVALID_HEADER_BLOCK ==
            nghttp2_frame_unpack_nv(&outnv, &buffer, len_size));

  nghttp2_frame_nv_del(outnv);
  nghttp2_buffer_free(&buffer);
}

void test_nghttp2_frame_pack_nv_duplicate_keys(void)
{
  uint8_t out[1024];
  size_t len_size = 2;
  const char *nv_src[] = {
    "method", "GET",
    "scheme", "https",
    "url", "/",
    "X-hEad", "foo",
    "x-heaD", "bar",
    "version", "HTTP/1.1",
    NULL
  };
  char **nv = nghttp2_frame_nv_norm_copy(nv_src);
  const uint8_t *outptr;
  int pairs, len;
  /* size_t inlen = */ nghttp2_frame_pack_nv(out, nv, len_size);
  outptr = out;

  pairs = nghttp2_get_uint16(outptr);
  CU_ASSERT(pairs == 5);
  outptr += 2;

  len = nghttp2_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 6);
  CU_ASSERT(memcmp(outptr, "method", len) == 0);
  outptr += len;

  len = nghttp2_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 3);
  CU_ASSERT(memcmp(outptr, "GET", len) == 0);
  outptr += len;

  len = nghttp2_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 6);
  CU_ASSERT(memcmp(outptr, "scheme", len) == 0);
  outptr += len;

  len = nghttp2_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 5);
  CU_ASSERT(memcmp(outptr, "https", len) == 0);
  outptr += len;

  len = nghttp2_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 3);
  CU_ASSERT(memcmp(outptr, "url", len) == 0);
  outptr += len;

  len = nghttp2_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 1);
  CU_ASSERT(memcmp(outptr, "/", len) == 0);
  outptr += len;

  len = nghttp2_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 7);
  CU_ASSERT(memcmp(outptr, "version", len) == 0);
  outptr += len;

  len = nghttp2_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 8);
  CU_ASSERT(memcmp(outptr, "HTTP/1.1", len) == 0);
  outptr += len;


  len = nghttp2_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 6);
  CU_ASSERT(memcmp(outptr, "x-head", len) == 0);
  outptr += len;

  len = nghttp2_get_uint16(outptr);
  outptr += 2;
  CU_ASSERT(len == 7);
  CU_ASSERT(memcmp(outptr, "foo\0bar", len) == 0);
  outptr += len;

  nghttp2_frame_nv_del(nv);
}

static const char *multi_empty_headers1[] = {
  "a", "",
  "a", "",
  NULL
};

static const char *multi_empty_headers2[] = {
  "a", "/",
  "a", "",
  NULL
};

static const char *multi_empty_headers3[] = {
  "a", "",
  "a", "/",
  NULL
};

void test_nghttp2_frame_count_nv_space(void)
{
  size_t len_size = 2;
  CU_ASSERT(85 == nghttp2_frame_count_nv_space((char**)headers, len_size));
  len_size = 4;
  CU_ASSERT(111 == nghttp2_frame_count_nv_space((char**)headers, len_size));
  /* only ("a", "") is counted */
  CU_ASSERT(13 == nghttp2_frame_count_nv_space((char**)multi_empty_headers1,
                                               len_size));
  /* only ("a", "/") is counted */
  CU_ASSERT(14 == nghttp2_frame_count_nv_space((char**)multi_empty_headers2,
                                               len_size));
  /* only ("a", "/") is counted */
  CU_ASSERT(14 == nghttp2_frame_count_nv_space((char**)multi_empty_headers3,
                                               len_size));
}

static void frame_pack_nv_empty_value_check(uint8_t *outptr,
                                            int vallen,
                                            const char *val,
                                            size_t len_size)
{
  int len;
  len = get_packed_hd_len(outptr, len_size);
  CU_ASSERT(1 == len);
  outptr += len_size;
  len = get_packed_hd_len(outptr, len_size);
  CU_ASSERT(1 == len);
  outptr += len_size;
  CU_ASSERT(0 == memcmp("a", outptr, len));
  outptr += len;
  len = get_packed_hd_len(outptr, len_size);
  CU_ASSERT(vallen == len);
  len += len_size;
  if(vallen == len) {
    CU_ASSERT(0 == memcmp(val, outptr, vallen));
  }
}

void test_nghttp2_frame_pack_nv_empty_value()
{
  size_t len_size = 2;
  uint8_t out[256];
  char **nv;
  ssize_t rv;
  int off = (len_size == 2 ? -6 : 0);

  nv = nghttp2_frame_nv_copy(multi_empty_headers1);
  rv = nghttp2_frame_pack_nv(out, nv, len_size);
  CU_ASSERT(13+off == rv);
  frame_pack_nv_empty_value_check(out, 0, NULL, len_size);
  nghttp2_frame_nv_del(nv);

  nv = nghttp2_frame_nv_copy(multi_empty_headers2);
  rv = nghttp2_frame_pack_nv(out, nv, len_size);
  CU_ASSERT(14+off == rv);
  frame_pack_nv_empty_value_check(out, 1, "/", len_size);
  nghttp2_frame_nv_del(nv);

  nv = nghttp2_frame_nv_copy(multi_empty_headers3);
  rv = nghttp2_frame_pack_nv(out, nv, len_size);
  CU_ASSERT(14+off == rv);
  frame_pack_nv_empty_value_check(out, 1, "/", len_size);
  nghttp2_frame_nv_del(nv);
}

void test_nghttp2_frame_count_unpack_nv_space(void)
{
  size_t nvlen, buflen;
  uint8_t out[1024];
  size_t len_size = 2;
  size_t inlen = nghttp2_frame_pack_nv(out, (char**)headers, len_size);
  uint16_t temp;
  size_t expected_buflen;
  nghttp2_buffer buffer;
  uint8_t *chunk;

  nghttp2_buffer_init(&buffer, 4096);
  nghttp2_buffer_write(&buffer, out, inlen);

  CU_ASSERT(0 == nghttp2_frame_count_unpack_nv_space(&nvlen, &buflen,
                                                     &buffer, len_size));
  CU_ASSERT(7 == nvlen);
  expected_buflen = 71+(nvlen*2+1)*sizeof(char*);
  CU_ASSERT(expected_buflen == buflen);

  chunk = buffer.root.next->data;
  /* Change number of nv pair to a bogus value */
  temp = nghttp2_get_uint16(chunk);
  nghttp2_put_uint16be(chunk, temp+1);
  CU_ASSERT(NGHTTP2_ERR_INVALID_FRAME ==
            nghttp2_frame_count_unpack_nv_space(&nvlen, &buflen, &buffer,
                                                len_size));
  nghttp2_put_uint16be(chunk, temp);

  /* Change the length of name to a bogus value */
  temp = nghttp2_get_uint16(chunk+2);
  nghttp2_put_uint16be(chunk+2, temp+1);
  CU_ASSERT(NGHTTP2_ERR_INVALID_FRAME ==
            nghttp2_frame_count_unpack_nv_space(&nvlen, &buflen, &buffer,
                                                len_size));
  nghttp2_put_uint16be(chunk+2, 65535);
  CU_ASSERT(NGHTTP2_ERR_INVALID_FRAME ==
            nghttp2_frame_count_unpack_nv_space(&nvlen, &buflen, &buffer,
                                                len_size));

  /* Trailing garbage */
  nghttp2_buffer_advance(&buffer, 2);
  CU_ASSERT(NGHTTP2_ERR_INVALID_FRAME ==
            nghttp2_frame_count_unpack_nv_space(&nvlen, &buflen,
                                                &buffer, len_size));
  /* We advanced buffer 2 bytes, so it is not valid any more. */
  nghttp2_buffer_free(&buffer);
}

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
  nghttp2_zlib deflater, inflater;
  nghttp2_headers frame, oframe;
  uint8_t *buf = NULL, *nvbuf = NULL;
  size_t buflen = 0, nvbuflen = 0;
  ssize_t framelen;
  nghttp2_zlib_deflate_hd_init(&deflater, 1, 0);
  nghttp2_zlib_inflate_hd_init(&inflater, 0);
  nghttp2_frame_headers_init(&frame, NGHTTP2_FLAG_END_STREAM, 1000000007,
                             1 << 20, nghttp2_frame_nv_copy(headers));
  framelen = nghttp2_frame_pack_headers(&buf, &buflen, &nvbuf, &nvbuflen,
                                        &frame, &deflater);

  CU_ASSERT(0 == unpack_frame_with_nv_block((nghttp2_frame*)&oframe,
                                            NGHTTP2_HEADERS,
                                            &inflater,
                                            buf, framelen));
  check_frame_header(framelen - NGHTTP2_FRAME_HEAD_LENGTH, NGHTTP2_HEADERS,
                     NGHTTP2_FLAG_END_STREAM, 1000000007, &oframe.hd);
  /* We didn't include PRIORITY flag so priority is not packed */
  CU_ASSERT(1 << 30 == oframe.pri);
  CU_ASSERT(strcmp("method", oframe.nv[0]) == 0);
  CU_ASSERT(strcmp("GET", oframe.nv[1]) == 0);
  CU_ASSERT(NULL == oframe.nv[14]);

  nghttp2_frame_headers_free(&oframe);
  memset(&oframe, 0, sizeof(oframe));
  /* Next, include PRIORITY flag */
  frame.hd.flags |= NGHTTP2_FLAG_PRIORITY;
  framelen = nghttp2_frame_pack_headers(&buf, &buflen, &nvbuf, &nvbuflen,
                                        &frame, &deflater);

  CU_ASSERT(0 == unpack_frame_with_nv_block((nghttp2_frame*)&oframe,
                                            NGHTTP2_HEADERS,
                                            &inflater,
                                            buf, framelen));
  check_frame_header(framelen - NGHTTP2_FRAME_HEAD_LENGTH, NGHTTP2_HEADERS,
                     NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_PRIORITY,
                     1000000007, &oframe.hd);
  CU_ASSERT(1 << 20 == oframe.pri);
  CU_ASSERT(strcmp("method", oframe.nv[0]) == 0);

  free(buf);
  free(nvbuf);
  nghttp2_frame_headers_free(&oframe);
  nghttp2_frame_headers_free(&frame);
  nghttp2_zlib_inflate_free(&inflater);
  nghttp2_zlib_deflate_free(&deflater);
}

void test_nghttp2_frame_pack_headers_frame_too_large(void)
{
  nghttp2_zlib deflater;
  nghttp2_headers frame;
  uint8_t *buf = NULL, *nvbuf = NULL;
  size_t buflen = 0, nvbuflen = 0;
  ssize_t framelen;
  size_t big_vallen = 1 << 16;
  char *big_val = malloc(big_vallen + 1);
  const char *big_hds[] = { "header", big_val, NULL };
  memset(big_val, '0', big_vallen);
  big_val[big_vallen] = '\0';
  /* No compression */
  nghttp2_zlib_deflate_hd_init(&deflater, 0, 0);
  nghttp2_frame_headers_init(&frame, NGHTTP2_FLAG_END_STREAM, 1000000007,
                             0, nghttp2_frame_nv_copy(big_hds));
  framelen = nghttp2_frame_pack_headers(&buf, &buflen,
                                        &nvbuf, &nvbuflen,
                                        &frame, &deflater);
  CU_ASSERT_EQUAL(NGHTTP2_ERR_FRAME_TOO_LARGE, framelen);

  nghttp2_frame_headers_free(&frame);
  free(buf);
  free(nvbuf);
  free(big_val);
  nghttp2_zlib_deflate_free(&deflater);
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
