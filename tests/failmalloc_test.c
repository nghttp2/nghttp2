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
#include "failmalloc_test.h"

#include <CUnit/CUnit.h>

#include <stdio.h>
#include <assert.h>

#include "nghttp2_session.h"
#include "nghttp2_stream.h"
#include "nghttp2_frame.h"
#include "nghttp2_helper.h"
#include "malloc_wrapper.h"
#include "nghttp2_test_helper.h"

typedef struct {
  uint8_t data[8192];
  uint8_t *datamark, *datalimit;
} data_feed;

typedef struct {
  data_feed *df;
  size_t data_source_length;
} my_user_data;

static void data_feed_init(data_feed *df, uint8_t *data, size_t data_length)
{
  assert(data_length <= sizeof(df->data));
  memcpy(df->data, data, data_length);
  df->datamark = df->data;
  df->datalimit = df->data+data_length;
}

static ssize_t null_send_callback(nghttp2_session *session,
                                  const uint8_t* data, size_t len, int flags,
                                  void *user_data)
{
  return len;
}

static ssize_t data_feed_recv_callback(nghttp2_session *session,
                                       uint8_t* data, size_t len, int flags,
                                       void *user_data)
{
  data_feed *df = ((my_user_data*)user_data)->df;
  size_t avail = df->datalimit - df->datamark;
  size_t wlen = nghttp2_min(avail, len);
  memcpy(data, df->datamark, wlen);
  df->datamark += wlen;
  return wlen;
}

static ssize_t fixed_length_data_source_read_callback
(nghttp2_session *session, int32_t stream_id,
 uint8_t *buf, size_t len, int *eof,
 nghttp2_data_source *source, void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  size_t wlen;
  if(len < ud->data_source_length) {
    wlen = len;
  } else {
    wlen = ud->data_source_length;
  }
  ud->data_source_length -= wlen;
  if(ud->data_source_length == 0) {
    *eof = 1;
  }
  return wlen;
}

#define TEST_FAILMALLOC_RUN(FUN)                        \
  size_t nmalloc, i;                                    \
                                                        \
  nghttp2_failmalloc = 0;                               \
  nghttp2_nmalloc = 0;                                  \
  FUN();                                                \
  nmalloc = nghttp2_nmalloc;                            \
                                                        \
  nghttp2_failmalloc = 1;                               \
  for(i = 0; i < nmalloc; ++i) {                        \
    nghttp2_nmalloc = 0;                                \
    nghttp2_failstart = i;                              \
    /* printf("i=%zu\n", i); */                         \
    FUN();                                              \
    /* printf("nmalloc=%d\n", nghttp2_nmalloc); */      \
  }                                                     \
  nghttp2_failmalloc = 0;

static void run_nghttp2_session_send(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_nv nv[] = {
    MAKE_NV(":host", "example.org"),
    MAKE_NV(":scheme", "https")
  };
  nghttp2_data_provider data_prd;
  nghttp2_settings_entry iv[2];
  my_user_data ud;
  int rv;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 64*1024;

  iv[0].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 4096;
  iv[1].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[1].value = 100;

  rv = nghttp2_session_client_new(&session, &callbacks, &ud);
  if(rv != 0) {
    goto client_new_fail;
  }
  rv = nghttp2_submit_request(session, 3, nv, ARRLEN(nv), &data_prd, NULL);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_submit_headers(session, NGHTTP2_FLAG_NONE, -1,
                              NGHTTP2_PRI_DEFAULT, nv, ARRLEN(nv), NULL);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_session_send(session);
  if(rv != 0) {
    goto fail;
  }
  /* The HEADERS submitted by the previous nghttp2_submit_headers will
     have stream ID 3. Send HEADERS to that stream. */
  rv = nghttp2_submit_headers(session, NGHTTP2_FLAG_NONE, 3,
                              NGHTTP2_PRI_DEFAULT, nv, ARRLEN(nv), NULL);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_submit_data(session, NGHTTP2_FLAG_END_STREAM, 3, &data_prd);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_session_send(session);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, 3,
                                 NGHTTP2_CANCEL);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_session_send(session);
  if(rv != 0) {
    goto fail;
  }
  /* Sending against half-closed stream */
  rv = nghttp2_submit_headers(session, NGHTTP2_FLAG_NONE, 3,
                              NGHTTP2_PRI_DEFAULT, nv, ARRLEN(nv), NULL);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_submit_data(session, NGHTTP2_FLAG_END_STREAM, 3, &data_prd);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_submit_ping(session, NGHTTP2_FLAG_NONE, NULL);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 2);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_session_send(session);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_submit_goaway(session, NGHTTP2_FLAG_NONE, NGHTTP2_NO_ERROR,
                             NULL, 0);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_session_send(session);
  if(rv != 0) {
    goto fail;
  }
 fail:
  nghttp2_session_del(session);
 client_new_fail:
  ;
}

void test_nghttp2_session_send(void)
{
  TEST_FAILMALLOC_RUN(run_nghttp2_session_send);
}

static void run_nghttp2_session_recv(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_hd_context deflater;
  nghttp2_frame frame;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  nghttp2_nv nv[] = {
    MAKE_NV(":authority", "example.org"),
    MAKE_NV(":scheme", "https")
  };
  nghttp2_settings_entry iv[2];
  my_user_data ud;
  data_feed df;
  int rv;
  nghttp2_nv *nva;
  ssize_t nvlen;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.recv_callback = data_feed_recv_callback;
  ud.df = &df;

  nghttp2_failmalloc_pause();
  nvlen = nghttp2_nv_array_copy(&nva, nv, ARRLEN(nv));
  nghttp2_hd_deflate_init(&deflater, NGHTTP2_HD_SIDE_REQUEST);
  nghttp2_session_server_new(&session, &callbacks, &ud);
  nghttp2_failmalloc_unpause();

  /* HEADERS */
  nghttp2_failmalloc_pause();
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_STREAM,
                             1, NGHTTP2_PRI_DEFAULT, nva, nvlen);
  framelen = nghttp2_frame_pack_headers(&buf, &buflen, &frame.headers,
                                        &deflater);
  nghttp2_frame_headers_free(&frame.headers);
  data_feed_init(&df, buf, framelen);
  nghttp2_failmalloc_unpause();

  rv = nghttp2_session_recv(session);
  if(rv != 0) {
    goto fail;
  }

  /* PING */
  nghttp2_failmalloc_pause();
  nghttp2_frame_ping_init(&frame.ping, NGHTTP2_FLAG_NONE, NULL);
  framelen = nghttp2_frame_pack_ping(&buf, &buflen, &frame.ping);
  nghttp2_frame_ping_free(&frame.ping);
  data_feed_init(&df, buf, framelen);
  nghttp2_failmalloc_unpause();

  rv = nghttp2_session_recv(session);
  if(rv != 0) {
    goto fail;
  }

  /* RST_STREAM */
  nghttp2_failmalloc_pause();
  nghttp2_frame_rst_stream_init(&frame.rst_stream, 1, NGHTTP2_PROTOCOL_ERROR);
  framelen = nghttp2_frame_pack_rst_stream(&buf, &buflen, &frame.rst_stream);
  nghttp2_frame_rst_stream_free(&frame.rst_stream);
  nghttp2_failmalloc_unpause();

  rv = nghttp2_session_recv(session);
  if(rv != 0) {
    goto fail;
  }

  /* SETTINGS */
  nghttp2_failmalloc_pause();
  iv[0].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 4096;
  iv[1].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[1].value = 100;
  nghttp2_frame_settings_init(&frame.settings, NGHTTP2_FLAG_NONE,
                              nghttp2_frame_iv_copy(iv, 2), 2);
  framelen = nghttp2_frame_pack_settings(&buf, &buflen, &frame.settings);
  nghttp2_frame_settings_free(&frame.settings);
  nghttp2_failmalloc_unpause();

  rv = nghttp2_session_recv(session);
  if(rv != 0) {
    goto fail;
  }

 fail:
  free(buf);
  nghttp2_session_del(session);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_session_recv(void)
{
  TEST_FAILMALLOC_RUN(run_nghttp2_session_recv);
}

static void run_nghttp2_frame_pack_headers(void)
{
  nghttp2_hd_context deflater, inflater;
  nghttp2_frame frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  nghttp2_nv nv[] = {
    MAKE_NV(":host", "example.org"),
    MAKE_NV(":scheme", "https")
  };
  int rv;
  nghttp2_nv *nva;
  ssize_t nvlen;

  rv = nghttp2_hd_deflate_init(&deflater, NGHTTP2_HD_SIDE_REQUEST);
  if(rv != 0) {
    goto deflate_init_fail;
  }
  rv = nghttp2_hd_inflate_init(&inflater, NGHTTP2_HD_SIDE_REQUEST);
  if(rv != 0) {
    goto inflate_init_fail;
  }
  nvlen = nghttp2_nv_array_copy(&nva, nv, ARRLEN(nv));
  if(nvlen < 0) {
    goto nv_copy_fail;
  }
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_STREAM,
                             1, NGHTTP2_PRI_DEFAULT, nva, nvlen);
  framelen = nghttp2_frame_pack_headers(&buf, &buflen, &frame.headers,
                                        &deflater);
  if(framelen < 0) {
    goto fail;
  }
  rv = unpack_frame_with_nv_block(&oframe, NGHTTP2_HEADERS, &inflater,
                                  buf, framelen);
  if(rv != 0) {
    goto fail;
  }
  nghttp2_frame_headers_free(&oframe.headers);
 fail:
  free(buf);
  nghttp2_frame_headers_free(&frame.headers);
 nv_copy_fail:
  nghttp2_hd_inflate_free(&inflater);
 inflate_init_fail:
  nghttp2_hd_deflate_free(&deflater);
 deflate_init_fail:
  ;
}

static void run_nghttp2_frame_pack_ping(void)
{
  nghttp2_frame frame;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  nghttp2_frame_ping_init(&frame.ping, NGHTTP2_FLAG_NONE, NULL);
  nghttp2_frame_pack_ping(&buf, &buflen, &frame.ping);
  free(buf);
  nghttp2_frame_ping_free(&frame.ping);
}

static void run_nghttp2_frame_pack_goaway(void)
{
  nghttp2_frame frame;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  nghttp2_frame_goaway_init(&frame.goaway, 1000000007, NGHTTP2_PROTOCOL_ERROR,
                            NULL, 0);
  nghttp2_frame_pack_goaway(&buf, &buflen, &frame.goaway);
  free(buf);
  nghttp2_frame_goaway_free(&frame.goaway);
}

static void run_nghttp2_frame_pack_rst_stream(void)
{
  nghttp2_frame frame;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  nghttp2_frame_rst_stream_init(&frame.rst_stream, 1, NGHTTP2_PROTOCOL_ERROR);
  nghttp2_frame_pack_rst_stream(&buf, &buflen, &frame.rst_stream);
  free(buf);
  nghttp2_frame_rst_stream_free(&frame.rst_stream);
}

static void run_nghttp2_frame_pack_window_update(void)
{
  nghttp2_frame frame;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  nghttp2_frame_window_update_init(&frame.window_update, NGHTTP2_FLAG_NONE,
                                   1000000007, 4096);
  nghttp2_frame_pack_window_update(&buf, &buflen,
                                   &frame.window_update);
  free(buf);
  nghttp2_frame_window_update_free(&frame.window_update);
}

static void run_nghttp2_frame_pack_settings(void)
{
  nghttp2_frame frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  nghttp2_settings_entry iv[2], *iv_copy;
  int rv;

  iv[0].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 4096;
  iv[1].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[1].value = 100;

  iv_copy = nghttp2_frame_iv_copy(iv, 2);
  if(iv_copy == NULL) {
    goto iv_copy_fail;
  }
  nghttp2_frame_settings_init(&frame.settings, NGHTTP2_FLAG_NONE, iv_copy, 2);
  framelen = nghttp2_frame_pack_settings(&buf, &buflen, &frame.settings);
  if(framelen < 0) {
    goto fail;
  }
  rv = nghttp2_frame_unpack_settings(&oframe.settings,
                                     &buf[0], NGHTTP2_FRAME_HEAD_LENGTH,
                                     &buf[NGHTTP2_FRAME_HEAD_LENGTH],
                                     framelen-NGHTTP2_FRAME_HEAD_LENGTH);
  if(rv != 0) {
    goto fail;
  }
  nghttp2_frame_settings_free(&oframe.settings);
 fail:
  free(buf);
  nghttp2_frame_settings_free(&frame.settings);
 iv_copy_fail:
  ;
}

static void run_nghttp2_frame(void)
{
  run_nghttp2_frame_pack_headers();
  run_nghttp2_frame_pack_ping();
  run_nghttp2_frame_pack_goaway();
  run_nghttp2_frame_pack_rst_stream();
  run_nghttp2_frame_pack_window_update();
  run_nghttp2_frame_pack_settings();
}

void test_nghttp2_frame(void)
{
  TEST_FAILMALLOC_RUN(run_nghttp2_frame);
}
