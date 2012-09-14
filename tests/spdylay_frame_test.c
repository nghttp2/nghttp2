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
#include "spdylay_test_helper.h"

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

static void test_spdylay_frame_unpack_nv_with(size_t len_size)
{
  uint8_t out[1024];
  char **nv;
  size_t inlen = spdylay_frame_pack_nv(out, (char**)headers, len_size);
  spdylay_buffer buffer;

  spdylay_buffer_init(&buffer, 4096);
  spdylay_buffer_write(&buffer, out, inlen);

  CU_ASSERT(0 == spdylay_frame_unpack_nv(&nv, &buffer, len_size));
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
  spdylay_frame_nv_del(nv);

  /* Create in-sequence NUL bytes */
  /* Assuming first chunk has enough space to store 1st name/value
     pair. */
  memcpy(&buffer.root.next->data[len_size +
                                 len_size + strlen(headers[0]) +
                                 len_size + strlen(headers[1])-2],
         "\0\0", 2);
  CU_ASSERT(SPDYLAY_ERR_INVALID_HEADER_BLOCK ==
            spdylay_frame_unpack_nv(&nv, &buffer, len_size));

  spdylay_frame_nv_del(nv);
  spdylay_buffer_free(&buffer);
}

void test_spdylay_frame_unpack_nv_spdy2(void)
{
  test_spdylay_frame_unpack_nv_with
    (spdylay_frame_get_len_size(SPDYLAY_PROTO_SPDY2));
}

void test_spdylay_frame_unpack_nv_spdy3(void)
{
  test_spdylay_frame_unpack_nv_with
    (spdylay_frame_get_len_size(SPDYLAY_PROTO_SPDY2));
}

void test_spdylay_frame_pack_nv_duplicate_keys(void)
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
  char **nv = spdylay_frame_nv_norm_copy(nv_src);
  const uint8_t *outptr;
  int pairs, len;
  /* size_t inlen = */ spdylay_frame_pack_nv(out, nv, len_size);
  outptr = out;

  pairs = spdylay_get_uint16(outptr);
  CU_ASSERT(pairs == 5);
  outptr += 2;

  len = spdylay_get_uint16(outptr);
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

void test_spdylay_frame_count_nv_space(void)
{
  size_t len_size = 2;
  CU_ASSERT(85 == spdylay_frame_count_nv_space((char**)headers, len_size));
  len_size = 4;
  CU_ASSERT(111 == spdylay_frame_count_nv_space((char**)headers, len_size));
}

void test_spdylay_frame_count_unpack_nv_space(void)
{
  size_t nvlen, buflen;
  uint8_t out[1024];
  size_t len_size = 2;
  size_t inlen = spdylay_frame_pack_nv(out, (char**)headers, len_size);
  uint16_t temp;
  size_t expected_buflen;
  spdylay_buffer buffer;
  uint8_t *chunk;

  spdylay_buffer_init(&buffer, 4096);
  spdylay_buffer_write(&buffer, out, inlen);

  CU_ASSERT(0 == spdylay_frame_count_unpack_nv_space(&nvlen, &buflen,
                                                     &buffer, len_size));
  CU_ASSERT(7 == nvlen);
  expected_buflen = 71+(nvlen*2+1)*sizeof(char*);
  CU_ASSERT(expected_buflen == buflen);

  chunk = buffer.root.next->data;
  /* Change number of nv pair to a bogus value */
  temp = spdylay_get_uint16(chunk);
  spdylay_put_uint16be(chunk, temp+1);
  CU_ASSERT(SPDYLAY_ERR_INVALID_FRAME ==
            spdylay_frame_count_unpack_nv_space(&nvlen, &buflen, &buffer,
                                                len_size));
  spdylay_put_uint16be(chunk, temp);

  /* Change the length of name to a bogus value */
  temp = spdylay_get_uint16(chunk+2);
  spdylay_put_uint16be(chunk+2, temp+1);
  CU_ASSERT(SPDYLAY_ERR_INVALID_FRAME ==
            spdylay_frame_count_unpack_nv_space(&nvlen, &buflen, &buffer,
                                                len_size));
  spdylay_put_uint16be(chunk+2, 65535);
  CU_ASSERT(SPDYLAY_ERR_INVALID_FRAME ==
            spdylay_frame_count_unpack_nv_space(&nvlen, &buflen, &buffer,
                                                len_size));

  /* Trailing garbage */
  spdylay_buffer_advance(&buffer, 2);
  CU_ASSERT(SPDYLAY_ERR_INVALID_FRAME ==
            spdylay_frame_count_unpack_nv_space(&nvlen, &buflen,
                                                &buffer, len_size));
  /* We advanced buffer 2 bytes, so it is not valid any more. */
  spdylay_buffer_free(&buffer);
}

void test_spdylay_frame_pack_ping(void)
{
  spdylay_frame frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  spdylay_frame_ping_init(&frame.ping, SPDYLAY_PROTO_SPDY2, 1);
  framelen = spdylay_frame_pack_ping(&buf, &buflen, &frame.ping);
  CU_ASSERT(0 == spdylay_frame_unpack_ping
            (&oframe.ping,
             &buf[0], SPDYLAY_FRAME_HEAD_LENGTH,
             &buf[SPDYLAY_FRAME_HEAD_LENGTH],
             framelen-SPDYLAY_FRAME_HEAD_LENGTH));
  CU_ASSERT(1 == oframe.ping.unique_id);
  free(buf);
  spdylay_frame_ping_free(&oframe.ping);
  spdylay_frame_ping_free(&frame.ping);
}

static void test_spdylay_frame_pack_goaway_version(uint16_t version)
{
  spdylay_frame frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  spdylay_frame_goaway_init(&frame.goaway, version, 1000000007,
                            SPDYLAY_GOAWAY_PROTOCOL_ERROR);
  framelen = spdylay_frame_pack_goaway(&buf, &buflen, &frame.goaway);
  CU_ASSERT(0 == spdylay_frame_unpack_goaway
            (&oframe.goaway,
             &buf[0], SPDYLAY_FRAME_HEAD_LENGTH,
             &buf[SPDYLAY_FRAME_HEAD_LENGTH],
             framelen-SPDYLAY_FRAME_HEAD_LENGTH));
  CU_ASSERT(1000000007 == oframe.goaway.last_good_stream_id);
  if(version == SPDYLAY_PROTO_SPDY2) {
    /* The status code is ignored in SPDY/2 */
    CU_ASSERT(0 == oframe.goaway.status_code);
  } else if(version == SPDYLAY_PROTO_SPDY3) {
    CU_ASSERT(SPDYLAY_GOAWAY_PROTOCOL_ERROR == oframe.goaway.status_code);
  }
  CU_ASSERT(version == oframe.goaway.hd.version);
  CU_ASSERT(SPDYLAY_GOAWAY == oframe.goaway.hd.type);
  CU_ASSERT(SPDYLAY_CTRL_FLAG_NONE == oframe.goaway.hd.flags);
  CU_ASSERT(framelen-SPDYLAY_FRAME_HEAD_LENGTH == oframe.goaway.hd.length);
  free(buf);
  spdylay_frame_goaway_free(&oframe.goaway);
  spdylay_frame_goaway_free(&frame.goaway);
}

void test_spdylay_frame_pack_goaway_spdy2(void)
{
  test_spdylay_frame_pack_goaway_version(SPDYLAY_PROTO_SPDY2);
}

void test_spdylay_frame_pack_goaway_spdy3(void)
{
  test_spdylay_frame_pack_goaway_version(SPDYLAY_PROTO_SPDY3);
}

static void test_spdylay_frame_pack_syn_stream_version(uint16_t version)
{
  spdylay_zlib deflater, inflater;
  spdylay_frame frame, oframe;
  uint8_t *buf = NULL, *nvbuf = NULL;
  size_t buflen = 0, nvbuflen = 0;
  ssize_t framelen;

  spdylay_zlib_deflate_hd_init(&deflater, 1, version);
  spdylay_zlib_inflate_hd_init(&inflater, version);
  spdylay_frame_syn_stream_init(&frame.syn_stream, version,
                                SPDYLAY_CTRL_FLAG_FIN, 65536, 1000000007, 3,
                                spdylay_frame_nv_copy(headers));
  framelen = spdylay_frame_pack_syn_stream(&buf, &buflen,
                                           &nvbuf, &nvbuflen,
                                           &frame.syn_stream, &deflater);

  CU_ASSERT(0 == unpack_frame_with_nv_block(SPDYLAY_SYN_STREAM,
                                            version,
                                            &oframe,
                                            &inflater,
                                            buf, framelen));
  CU_ASSERT(65536 == oframe.syn_stream.stream_id);
  CU_ASSERT(1000000007 == oframe.syn_stream.assoc_stream_id);
  CU_ASSERT(version == oframe.syn_stream.hd.version);
  CU_ASSERT(SPDYLAY_SYN_STREAM == oframe.syn_stream.hd.type);
  CU_ASSERT(SPDYLAY_CTRL_FLAG_FIN == oframe.syn_stream.hd.flags);
  CU_ASSERT(framelen-SPDYLAY_FRAME_HEAD_LENGTH == oframe.syn_stream.hd.length);
  CU_ASSERT(strcmp("method", oframe.syn_stream.nv[0]) == 0);
  CU_ASSERT(strcmp("GET", oframe.syn_stream.nv[1]) == 0);
  CU_ASSERT(NULL == oframe.syn_stream.nv[14]);
  free(buf);
  free(nvbuf);
  spdylay_frame_syn_stream_free(&oframe.syn_stream);
  spdylay_frame_syn_stream_free(&frame.syn_stream);
  spdylay_zlib_inflate_free(&inflater);
  spdylay_zlib_deflate_free(&deflater);
}

void test_spdylay_frame_pack_syn_stream_spdy2(void)
{
  test_spdylay_frame_pack_syn_stream_version(SPDYLAY_PROTO_SPDY2);
}

void test_spdylay_frame_pack_syn_stream_spdy3(void)
{
  test_spdylay_frame_pack_syn_stream_version(SPDYLAY_PROTO_SPDY3);
}

void test_spdylay_frame_pack_syn_stream_frame_too_large(void)
{
  spdylay_zlib deflater;
  spdylay_frame frame;
  uint8_t *buf = NULL, *nvbuf = NULL;
  size_t buflen = 0, nvbuflen = 0;
  ssize_t framelen;
  size_t big_vallen = 16777215;
  char *big_val = malloc(big_vallen + 1);
  const char *big_hds[] = { "header", big_val, NULL };
  memset(big_val, '0', big_vallen);
  big_val[big_vallen] = '\0';
  /* No compression */
  spdylay_zlib_deflate_hd_init(&deflater, 0, SPDYLAY_PROTO_SPDY3);
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_PROTO_SPDY3,
                                SPDYLAY_CTRL_FLAG_FIN, 65536, 1000000007, 3,
                                spdylay_frame_nv_copy(big_hds));
  framelen = spdylay_frame_pack_syn_stream(&buf, &buflen,
                                           &nvbuf, &nvbuflen,
                                           &frame.syn_stream, &deflater);
  CU_ASSERT_EQUAL(SPDYLAY_ERR_FRAME_TOO_LARGE, framelen);

  spdylay_frame_syn_stream_free(&frame.syn_stream);
  free(buf);
  free(nvbuf);
  free(big_val);
  spdylay_zlib_deflate_free(&deflater);
}

static void test_spdylay_frame_pack_syn_reply_version(uint16_t version)
{
  spdylay_zlib deflater, inflater;
  spdylay_frame frame, oframe;
  uint8_t *buf = NULL, *nvbuf = NULL;
  size_t buflen = 0, nvbuflen = 0;
  ssize_t framelen;
  spdylay_zlib_deflate_hd_init(&deflater, 1, version);
  spdylay_zlib_inflate_hd_init(&inflater, version);
  spdylay_frame_syn_reply_init(&frame.syn_reply, version,
                               SPDYLAY_CTRL_FLAG_FIN, 3,
                               spdylay_frame_nv_copy(headers));
  framelen = spdylay_frame_pack_syn_reply(&buf, &buflen,
                                          &nvbuf, &nvbuflen,
                                          &frame.syn_reply, &deflater);
  CU_ASSERT(0 == unpack_frame_with_nv_block(SPDYLAY_SYN_REPLY,
                                            version,
                                            &oframe,
                                            &inflater,
                                            buf, framelen));
  CU_ASSERT(3 == oframe.syn_reply.stream_id);
  CU_ASSERT(version == oframe.syn_reply.hd.version);
  CU_ASSERT(SPDYLAY_SYN_REPLY == oframe.syn_reply.hd.type);
  CU_ASSERT(SPDYLAY_CTRL_FLAG_FIN == oframe.syn_reply.hd.flags);
  CU_ASSERT(framelen-SPDYLAY_FRAME_HEAD_LENGTH == oframe.syn_reply.hd.length);
  CU_ASSERT(strcmp("method", oframe.syn_reply.nv[0]) == 0);
  CU_ASSERT(strcmp("GET", oframe.syn_reply.nv[1]) == 0);
  CU_ASSERT(NULL == oframe.syn_reply.nv[14]);
  free(buf);
  free(nvbuf);
  spdylay_frame_syn_reply_free(&oframe.syn_reply);
  spdylay_frame_syn_reply_free(&frame.syn_reply);
  spdylay_zlib_inflate_free(&inflater);
  spdylay_zlib_deflate_free(&deflater);
}

void test_spdylay_frame_pack_syn_reply_spdy2(void)
{
  test_spdylay_frame_pack_syn_reply_version(SPDYLAY_PROTO_SPDY2);
}

void test_spdylay_frame_pack_syn_reply_spdy3(void)
{
  test_spdylay_frame_pack_syn_reply_version(SPDYLAY_PROTO_SPDY3);
}

static void test_spdylay_frame_pack_headers_version(uint16_t version)
{
  spdylay_zlib deflater, inflater;
  spdylay_frame frame, oframe;
  uint8_t *buf = NULL, *nvbuf = NULL;
  size_t buflen = 0, nvbuflen = 0;
  spdylay_buffer inflatebuf;
  ssize_t framelen;
  spdylay_buffer_init(&inflatebuf, 4096);
  spdylay_zlib_deflate_hd_init(&deflater, 1, version);
  spdylay_zlib_inflate_hd_init(&inflater, version);
  spdylay_frame_headers_init(&frame.headers, version,
                             SPDYLAY_CTRL_FLAG_FIN, 3,
                             spdylay_frame_nv_copy(headers));
  framelen = spdylay_frame_pack_headers(&buf, &buflen,
                                        &nvbuf, &nvbuflen,
                                        &frame.headers, &deflater);
  CU_ASSERT(0 == unpack_frame_with_nv_block(SPDYLAY_HEADERS,
                                            version,
                                            &oframe,
                                            &inflater,
                                            buf, framelen));
  CU_ASSERT(3 == oframe.headers.stream_id);
  CU_ASSERT(version == oframe.headers.hd.version);
  CU_ASSERT(SPDYLAY_HEADERS == oframe.headers.hd.type);
  CU_ASSERT(SPDYLAY_CTRL_FLAG_FIN == oframe.headers.hd.flags);
  CU_ASSERT(framelen-SPDYLAY_FRAME_HEAD_LENGTH == oframe.headers.hd.length);
  CU_ASSERT(strcmp("method", oframe.headers.nv[0]) == 0);
  CU_ASSERT(strcmp("GET", oframe.headers.nv[1]) == 0);
  CU_ASSERT(NULL == oframe.headers.nv[14]);
  free(buf);
  free(nvbuf);
  spdylay_frame_headers_free(&oframe.headers);
  spdylay_frame_headers_free(&frame.headers);
  spdylay_zlib_inflate_free(&inflater);
  spdylay_zlib_deflate_free(&deflater);
  spdylay_buffer_free(&inflatebuf);
}

void test_spdylay_frame_pack_headers_spdy2(void)
{
  test_spdylay_frame_pack_headers_version(SPDYLAY_PROTO_SPDY2);
}

void test_spdylay_frame_pack_headers_spdy3(void)
{
  test_spdylay_frame_pack_headers_version(SPDYLAY_PROTO_SPDY3);
}

void test_spdylay_frame_pack_window_update(void)
{
  spdylay_frame frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  spdylay_frame_window_update_init(&frame.window_update, SPDYLAY_PROTO_SPDY3,
                                   1000000007, 4096);
  framelen = spdylay_frame_pack_window_update(&buf, &buflen,
                                              &frame.window_update);
  CU_ASSERT(0 == spdylay_frame_unpack_window_update
            (&oframe.window_update,
             &buf[0], SPDYLAY_FRAME_HEAD_LENGTH,
             &buf[SPDYLAY_FRAME_HEAD_LENGTH],
             framelen-SPDYLAY_FRAME_HEAD_LENGTH));
  CU_ASSERT(1000000007 == oframe.window_update.stream_id);
  CU_ASSERT(4096 == oframe.window_update.delta_window_size);
  CU_ASSERT(SPDYLAY_PROTO_SPDY3 == oframe.window_update.hd.version);
  CU_ASSERT(SPDYLAY_WINDOW_UPDATE == oframe.window_update.hd.type);
  CU_ASSERT(SPDYLAY_CTRL_FLAG_NONE == oframe.window_update.hd.flags);
  CU_ASSERT(framelen-SPDYLAY_FRAME_HEAD_LENGTH ==
            oframe.window_update.hd.length);
  free(buf);
  spdylay_frame_window_update_free(&oframe.window_update);
  spdylay_frame_window_update_free(&frame.window_update);
}


static void test_spdylay_frame_pack_settings_version(uint16_t version)
{
  spdylay_frame frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
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
    (&frame.settings, version, SPDYLAY_FLAG_SETTINGS_CLEAR_SETTINGS,
     spdylay_frame_iv_copy(iv, 3), 3);
  framelen = spdylay_frame_pack_settings(&buf, &buflen, &frame.settings);
  CU_ASSERT(8+4+3*8 == framelen);

  CU_ASSERT(0 == spdylay_frame_unpack_settings
            (&oframe.settings,
             &buf[0], SPDYLAY_FRAME_HEAD_LENGTH,
             &buf[SPDYLAY_FRAME_HEAD_LENGTH],
             framelen-SPDYLAY_FRAME_HEAD_LENGTH));

  CU_ASSERT(version == oframe.settings.hd.version);
  CU_ASSERT(SPDYLAY_SETTINGS == oframe.settings.hd.type);
  CU_ASSERT(SPDYLAY_FLAG_SETTINGS_CLEAR_SETTINGS == oframe.settings.hd.flags);
  CU_ASSERT(framelen-SPDYLAY_FRAME_HEAD_LENGTH == oframe.settings.hd.length);

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

void test_spdylay_frame_pack_settings_spdy2(void)
{
  test_spdylay_frame_pack_settings_version(SPDYLAY_PROTO_SPDY2);
}

void test_spdylay_frame_pack_settings_spdy3(void)
{
  test_spdylay_frame_pack_settings_version(SPDYLAY_PROTO_SPDY3);
}

static char* strcopy(const char* s)
{
  size_t len = strlen(s);
  char *dest = malloc(len+1);
  memcpy(dest, s, len);
  dest[len] = '\0';
  return dest;
}

void test_spdylay_frame_pack_credential(void)
{
  spdylay_frame frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  spdylay_mem_chunk proof;
  spdylay_mem_chunk *certs;
  size_t ncerts;
  proof.data = (uint8_t*)strcopy("PROOF");
  proof.length = strlen("PROOF");
  ncerts = 2;
  certs = malloc(sizeof(spdylay_mem_chunk)*ncerts);
  certs[0].data = (uint8_t*)strcopy("CERT0");
  certs[0].length = strlen("CERT0");
  certs[1].data = (uint8_t*)strcopy("CERT1");
  certs[1].length = strlen("CERT1");
  spdylay_frame_credential_init(&frame.credential, SPDYLAY_PROTO_SPDY3,
                                1, &proof, certs, ncerts);
  framelen = spdylay_frame_pack_credential(&buf, &buflen, &frame.credential);
  CU_ASSERT(0 == spdylay_frame_unpack_credential
            (&oframe.credential,
             &buf[0], SPDYLAY_FRAME_HEAD_LENGTH,
             &buf[SPDYLAY_FRAME_HEAD_LENGTH],
             framelen-SPDYLAY_FRAME_HEAD_LENGTH));
  CU_ASSERT(1 == oframe.credential.slot);
  CU_ASSERT(5 == oframe.credential.proof.length);
  CU_ASSERT(memcmp("PROOF", oframe.credential.proof.data, 5) == 0);
  CU_ASSERT(2 == oframe.credential.ncerts);
  CU_ASSERT(5 == oframe.credential.certs[0].length);
  CU_ASSERT(memcmp("CERT0", oframe.credential.certs[0].data, 5) == 0);
  CU_ASSERT(5 == oframe.credential.certs[1].length);
  CU_ASSERT(memcmp("CERT1", oframe.credential.certs[1].data, 5) == 0);
  CU_ASSERT(SPDYLAY_PROTO_SPDY3 == oframe.credential.hd.version);
  CU_ASSERT(SPDYLAY_CREDENTIAL == oframe.credential.hd.type);
  CU_ASSERT(SPDYLAY_CTRL_FLAG_NONE == oframe.credential.hd.flags);
  CU_ASSERT(framelen-SPDYLAY_FRAME_HEAD_LENGTH == oframe.credential.hd.length);
  spdylay_frame_credential_free(&oframe.credential);

  /* Put large certificate length */
  spdylay_put_uint32be(&buf[8+2+4+5], INT32_MAX);
  CU_ASSERT(SPDYLAY_ERR_INVALID_FRAME == spdylay_frame_unpack_credential
            (&oframe.credential,
             &buf[0], SPDYLAY_FRAME_HEAD_LENGTH,
             &buf[SPDYLAY_FRAME_HEAD_LENGTH],
             framelen-SPDYLAY_FRAME_HEAD_LENGTH));

  free(buf);
  spdylay_frame_credential_free(&frame.credential);
}

void test_spdylay_frame_nv_sort(void)
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

void test_spdylay_frame_nv_downcase(void)
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

void test_spdylay_frame_nv_2to3(void)
{
  const char *nv_src[] = {
    "host", "localhost",
    "method", "GET",
    "url", "/",
    "accept", "*/*",
    "scheme", "https",
    "status", "200 OK",
    "version", "HTTP/1.1",
    NULL
  };
  char **nv;
  nv = spdylay_frame_nv_copy(nv_src);
  spdylay_frame_nv_2to3(nv);
  CU_ASSERT(0 == strcmp(":host", nv[0]));
  CU_ASSERT(0 == strcmp(":method", nv[2]));
  CU_ASSERT(0 == strcmp(":path", nv[4]));
  CU_ASSERT(0 == strcmp("accept", nv[6]));
  CU_ASSERT(0 == strcmp(":scheme", nv[8]));
  CU_ASSERT(0 == strcmp(":status", nv[10]));
  CU_ASSERT(0 == strcmp(":version", nv[12]));
  spdylay_frame_nv_del(nv);
}

void test_spdylay_frame_nv_3to2(void)
{
  const char *nv_src[] = {
    ":host", "localhost",
    ":method", "GET",
    ":path", "/",
    "accept", "*/*",
    ":scheme", "https",
    ":status", "200 OK",
    ":version", "HTTP/1.1",
    NULL
  };
  char **nv;
  nv = spdylay_frame_nv_copy(nv_src);
  spdylay_frame_nv_3to2(nv);
  CU_ASSERT(0 == strcmp("host", nv[0]));
  CU_ASSERT(0 == strcmp("method", nv[2]));
  CU_ASSERT(0 == strcmp("url", nv[4]));
  CU_ASSERT(0 == strcmp("accept", nv[6]));
  CU_ASSERT(0 == strcmp("scheme", nv[8]));
  CU_ASSERT(0 == strcmp("status", nv[10]));
  CU_ASSERT(0 == strcmp("version", nv[12]));
  spdylay_frame_nv_del(nv);
}

static size_t spdylay_pack_nv(uint8_t *buf, size_t buflen, const char **nv,
                              size_t len_size)
{
  size_t i, n;
  uint8_t *buf_ptr;
  buf_ptr = buf;
  for(n = 0; nv[n]; ++n);
  spdylay_frame_put_nv_len(buf_ptr, n/2, len_size);
  buf_ptr += len_size;
  for(i = 0; i < n; ++i) {
    size_t len = strlen(nv[i]);
    spdylay_frame_put_nv_len(buf_ptr, len, len_size);
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

static void test_spdylay_frame_unpack_nv_check_name_with(size_t len_size)
{
  uint8_t nvbuf[1024];
  size_t nvbuflen;
  spdylay_buffer buffer;
  char **nv;

  spdylay_buffer_init(&buffer, 32);

  nvbuflen = spdylay_pack_nv(nvbuf, sizeof(nvbuf), headers, len_size);
  spdylay_buffer_write(&buffer, nvbuf, nvbuflen);

  CU_ASSERT(SPDYLAY_ERR_INVALID_HEADER_BLOCK ==
            spdylay_frame_unpack_nv(&nv, &buffer, len_size));

  spdylay_frame_nv_del(nv);
  spdylay_buffer_reset(&buffer);

  nvbuflen = spdylay_pack_nv(nvbuf, sizeof(nvbuf), empty_name_headers,
                             len_size);
  spdylay_buffer_write(&buffer, nvbuf, nvbuflen);

  CU_ASSERT(SPDYLAY_ERR_INVALID_HEADER_BLOCK ==
            spdylay_frame_unpack_nv(&nv, &buffer, len_size));

  spdylay_frame_nv_del(nv);
  spdylay_buffer_reset(&buffer);

  nvbuflen = spdylay_pack_nv(nvbuf, sizeof(nvbuf), non_ascii_headers,
                             len_size);
  spdylay_buffer_write(&buffer, nvbuf, nvbuflen);
  CU_ASSERT(SPDYLAY_ERR_INVALID_HEADER_BLOCK ==
            spdylay_frame_unpack_nv(&nv, &buffer, len_size));

  spdylay_frame_nv_del(nv);
  spdylay_buffer_free(&buffer);
}

void test_spdylay_frame_unpack_nv_check_name_spdy2(void)
{
  test_spdylay_frame_unpack_nv_check_name_with
    (spdylay_frame_get_len_size(SPDYLAY_PROTO_SPDY2));
}

void test_spdylay_frame_unpack_nv_check_name_spdy3(void)
{
  test_spdylay_frame_unpack_nv_check_name_with
    (spdylay_frame_get_len_size(SPDYLAY_PROTO_SPDY3));
}

void test_spdylay_frame_nv_set_origin(void)
{
  spdylay_origin origin;
  const char *nv1[] = {
    ":host", "example.org",
    ":scheme", "https",
    NULL
  };
  const char *nv2[] = {
    ":host", "example.org:8443",
    ":scheme", "https",
    NULL
  };
  const char *nv3[] = {
    ":host", "example.org:0",
    ":scheme", "https",
    NULL
  };
  const char *nv4[] = {
    ":host", "example.org",
    NULL
  };
  const char *nv5[] = {
    ":scheme", "https",
    NULL
  };
  CU_ASSERT(0 == spdylay_frame_nv_set_origin((char**)nv1, &origin));
  CU_ASSERT(strcmp("https", origin.scheme) == 0);
  CU_ASSERT(strcmp("example.org", origin.host) == 0);
  CU_ASSERT(443 == origin.port);

  CU_ASSERT(0 == spdylay_frame_nv_set_origin((char**)nv2, &origin));
  CU_ASSERT(strcmp("https", origin.scheme) == 0);
  CU_ASSERT(strcmp("example.org", origin.host) == 0);
  CU_ASSERT(8443 == origin.port);

  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_frame_nv_set_origin((char**)nv3, &origin));

  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_frame_nv_set_origin((char**)nv4, &origin));

  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_frame_nv_set_origin((char**)nv5, &origin));
}
