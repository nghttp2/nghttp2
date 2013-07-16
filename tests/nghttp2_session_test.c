/*
 * nghttp2 - HTTP/2.0 C Library
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
#include "nghttp2_session_test.h"

#include <CUnit/CUnit.h>

#include <stdio.h>
#include <assert.h>

#include "nghttp2_session.h"
#include "nghttp2_stream.h"
#include "nghttp2_net.h"
#include "nghttp2_helper.h"
#include "nghttp2_test_helper.h"

#define OB_CTRL(ITEM) nghttp2_outbound_item_get_ctrl_frame(ITEM)
#define OB_CTRL_TYPE(ITEM) nghttp2_outbound_item_get_ctrl_frame_type(ITEM)
#define OB_DATA(ITEM) nghttp2_outbound_item_get_data_frame(ITEM)

typedef struct {
  uint8_t buf[4096];
  size_t length;
} accumulator;

typedef struct {
  uint8_t data[8192];
  uint8_t* datamark;
  uint8_t* datalimit;
  size_t feedseq[8192];
  size_t seqidx;
} scripted_data_feed;

typedef struct {
  accumulator *acc;
  scripted_data_feed *df;
  int frame_recv_cb_called, invalid_frame_recv_cb_called;
  int frame_send_cb_called;
  nghttp2_frame_type sent_frame_type;
  int frame_not_send_cb_called;
  nghttp2_frame_type not_sent_frame_type;
  int not_sent_error;
  int stream_close_cb_called;
  size_t data_source_length;
  int32_t stream_id;
  size_t block_count;
  int data_chunk_recv_cb_called;
  int data_recv_cb_called;
} my_user_data;

static void scripted_data_feed_init(scripted_data_feed *df,
                                    uint8_t *data, size_t data_length)
{
  memset(df, 0, sizeof(scripted_data_feed));
  memcpy(df->data, data, data_length);
  df->datamark = df->data;
  df->datalimit = df->data+data_length;
  df->feedseq[0] = data_length;
}

static ssize_t null_send_callback(nghttp2_session *session,
                                  const uint8_t* data, size_t len, int flags,
                                  void *user_data)
{
  return len;
}

static ssize_t fail_send_callback(nghttp2_session *session,
                                  const uint8_t *data, size_t len, int flags,
                                  void *user_data)
{
  return NGHTTP2_ERR_CALLBACK_FAILURE;
}

static ssize_t scripted_recv_callback(nghttp2_session *session,
                                      uint8_t* data, size_t len, int flags,
                                      void *user_data)
{
  scripted_data_feed *df = ((my_user_data*)user_data)->df;
  size_t wlen = df->feedseq[df->seqidx] > len ? len : df->feedseq[df->seqidx];
  memcpy(data, df->datamark, wlen);
  df->datamark += wlen;
  if(wlen <= len) {
    ++df->seqidx;
  } else {
    df->feedseq[df->seqidx] -= wlen;
  }
  return wlen;
}

static ssize_t eof_recv_callback(nghttp2_session *session,
                                      uint8_t* data, size_t len, int flags,
                                      void *user_data)
{
  return NGHTTP2_ERR_EOF;
}

static ssize_t accumulator_send_callback(nghttp2_session *session,
                                         const uint8_t *buf, size_t len,
                                         int flags, void* user_data)
{
  accumulator *acc = ((my_user_data*)user_data)->acc;
  assert(acc->length+len < sizeof(acc->buf));
  memcpy(acc->buf+acc->length, buf, len);
  acc->length += len;
  return len;
}

static void on_frame_recv_callback(nghttp2_session *session,
                                   nghttp2_frame *frame,
                                   void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->frame_recv_cb_called;
}

static void on_invalid_frame_recv_callback(nghttp2_session *session,
                                           nghttp2_frame *frame,
                                           nghttp2_error_code error_code,
                                           void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->invalid_frame_recv_cb_called;
}

static void on_frame_send_callback(nghttp2_session *session,
                                   nghttp2_frame *frame,
                                   void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->frame_send_cb_called;
  ud->sent_frame_type = frame->hd.type;
}

static void on_frame_not_send_callback(nghttp2_session *session,
                                       nghttp2_frame *frame,
                                       int lib_error,
                                       void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->frame_not_send_cb_called;
  ud->not_sent_frame_type = frame->hd.type;
  ud->not_sent_error = lib_error;
}

static void on_data_chunk_recv_callback(nghttp2_session *session,
                                        uint8_t flags, int32_t stream_id,
                                        const uint8_t *data, size_t len,
                                        void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->data_chunk_recv_cb_called;
}

static void on_data_recv_callback(nghttp2_session *session,
                                  uint16_t length, uint8_t flags,
                                  int32_t stream_id, void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->data_recv_cb_called;
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

static ssize_t temporal_failure_data_source_read_callback
(nghttp2_session *session, int32_t stream_id,
 uint8_t *buf, size_t len, int *eof,
 nghttp2_data_source *source, void *user_data)
{
  return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
}

static ssize_t fail_data_source_read_callback
(nghttp2_session *session, int32_t stream_id,
 uint8_t *buf, size_t len, int *eof,
 nghttp2_data_source *source, void *user_data)
{
  return NGHTTP2_ERR_CALLBACK_FAILURE;
}

static void on_request_recv_callback(nghttp2_session *session,
                                     int32_t stream_id,
                                     void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ud->stream_id = stream_id;
}

/* static void no_stream_user_data_stream_close_callback */
/* (nghttp2_session *session, */
/*  int32_t stream_id, */
/*  nghttp2_error_code error_code, */
/*  void *user_data) */
/* { */
/*   my_user_data* my_data = (my_user_data*)user_data; */
/*   ++my_data->stream_close_cb_called; */
/* } */

static ssize_t block_count_send_callback(nghttp2_session* session,
                                         const uint8_t *data, size_t len,
                                         int flags,
                                         void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  int r;
  if(ud->block_count == 0) {
    r = NGHTTP2_ERR_WOULDBLOCK;
  } else {
    --ud->block_count;
    r = len;
  }
  return r;
}

static ssize_t defer_data_source_read_callback
(nghttp2_session *session, int32_t stream_id,
 uint8_t *buf, size_t len, int *eof,
 nghttp2_data_source *source, void *user_data)
{
  return NGHTTP2_ERR_DEFERRED;
}

static void stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                  nghttp2_error_code error_code,
                                  void *user_data)
{
  my_user_data* my_data = (my_user_data*)user_data;
  void *stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
  ++my_data->stream_close_cb_called;
  CU_ASSERT(stream_data != NULL);
}

static char** dup_nv(const char **src)
{
  return nghttp2_frame_nv_copy(src);
}

static nghttp2_settings_entry* dup_iv(const nghttp2_settings_entry *iv,
                                      size_t niv)
{
  return nghttp2_frame_iv_copy(iv, niv);
}

static const char *empty_name_nv[] = { "Version", "HTTP/1.1",
                                       "", "empty name",
                                       NULL };

static const char *null_val_nv[] = { "Version", "HTTP/1.1",
                                     "Foo", NULL,
                                     NULL };

void test_nghttp2_session_recv(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  scripted_data_feed df;
  my_user_data user_data;
  const char *nv[] = {
    "url", "/", NULL
  };
  const char *upcase_nv[] = {
    "URL", "/", NULL
  };
  const char *empty_nv[] = {
    NULL
  };
  const char *mid_nv[] = {
    "method", "GET",
    "scheme", "https",
    "url", "/",
    "x-head", "foo",
    "x-head", "bar",
    "version", "HTTP/1.1",
    "x-empty", "",
    NULL
  };
  uint8_t *framedata = NULL, *nvbuf = NULL;
  size_t framedatalen = 0, nvbuflen = 0;
  ssize_t framelen;
  nghttp2_frame frame;
  int i;
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.recv_callback = scripted_recv_callback;
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  user_data.df = &df;
  nghttp2_session_server_new(&session, &callbacks, &user_data);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS,
                             1, NGHTTP2_PRI_DEFAULT, dup_nv(nv));
  framelen = nghttp2_frame_pack_headers(&framedata, &framedatalen,
                                        &nvbuf, &nvbuflen,
                                        &frame.headers,
                                        &session->hd_deflater);
  scripted_data_feed_init(&df, framedata, framelen);
  /* Send 1 byte per each read */
  for(i = 0; i < framelen; ++i) {
    df.feedseq[i] = 1;
  }
  nghttp2_frame_headers_free(&frame.headers);

  user_data.frame_recv_cb_called = 0;
  while((ssize_t)df.seqidx < framelen) {
    CU_ASSERT(0 == nghttp2_session_recv(session));
  }
  CU_ASSERT(1 == user_data.frame_recv_cb_called);

  /* Receive HEADERS with invalid header block */
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS,
                             3, NGHTTP2_PRI_DEFAULT, dup_nv(upcase_nv));
  framelen = nghttp2_frame_pack_headers(&framedata, &framedatalen,
                                        &nvbuf, &nvbuflen,
                                        &frame.headers,
                                        &session->hd_deflater);
  nghttp2_frame_headers_free(&frame.headers);

  scripted_data_feed_init(&df, framedata, framelen);
  user_data.frame_recv_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_recv(session));
  CU_ASSERT(0 == user_data.frame_recv_cb_called);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_PROTOCOL_ERROR == OB_CTRL(item)->rst_stream.error_code);
  CU_ASSERT(0 == nghttp2_session_send(session));

  /* Received HEADERS without header block, which is valid */
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS,
                             5, NGHTTP2_PRI_DEFAULT, dup_nv(empty_nv));
  framelen = nghttp2_frame_pack_headers(&framedata, &framedatalen,
                                        &nvbuf, &nvbuflen,
                                        &frame.headers,
                                        &session->hd_deflater);
  nghttp2_frame_headers_free(&frame.headers);

  scripted_data_feed_init(&df, framedata, framelen);
  user_data.frame_recv_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_recv(session));
  CU_ASSERT(1 == user_data.frame_recv_cb_called);

  nghttp2_session_del(session);

  /* Some tests for frame too large */
  nghttp2_session_server_new(&session, &callbacks, &user_data);
  /* made max buffer small to cause error intentionally */
  session->max_recv_ctrl_frame_buf = 8;

  /* Receive HEADERS with too large payload */
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS,
                             1, NGHTTP2_PRI_DEFAULT, dup_nv(mid_nv));
  framelen = nghttp2_frame_pack_headers(&framedata, &framedatalen,
                                        &nvbuf, &nvbuflen,
                                        &frame.headers,
                                        &session->hd_deflater);
  nghttp2_frame_headers_free(&frame.headers);

  scripted_data_feed_init(&df, framedata, framelen);
  user_data.frame_recv_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_recv(session));
  CU_ASSERT(0 == user_data.frame_recv_cb_called);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_FRAME_TOO_LARGE == OB_CTRL(item)->rst_stream.error_code);
  CU_ASSERT(1 == OB_CTRL(item)->hd.stream_id);
  CU_ASSERT(0 == nghttp2_session_send(session));

  /* Receive PING with too large payload */
  nghttp2_frame_ping_init(&frame.ping, NGHTTP2_FLAG_NONE, NULL);
  nghttp2_reserve_buffer(&framedata, &framedatalen, 77);
  framelen = nghttp2_frame_pack_ping(&framedata, &framedatalen, &frame.ping);
  nghttp2_frame_ping_free(&frame.ping);

  nghttp2_put_uint16be(&framedata[0],
                       framedatalen - NGHTTP2_FRAME_HEAD_LENGTH);
  scripted_data_feed_init(&df, framedata, framedatalen);
  user_data.frame_recv_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_recv(session));
  CU_ASSERT(0 == user_data.frame_recv_cb_called);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_PROTOCOL_ERROR == OB_CTRL(item)->goaway.error_code);
  CU_ASSERT(0 == nghttp2_session_send(session));

  nghttp2_session_del(session);

  nghttp2_session_client_new(&session, &callbacks, &user_data);
  /* Receive HEADERS with invalid header block */
  nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                              NGHTTP2_PRI_DEFAULT,
                              NGHTTP2_STREAM_OPENING, NULL);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS, 1,
                             NGHTTP2_PRI_DEFAULT, dup_nv(upcase_nv));
  framelen = nghttp2_frame_pack_headers(&framedata, &framedatalen,
                                        &nvbuf, &nvbuflen,
                                        &frame.headers,
                                        &session->hd_deflater);
  nghttp2_frame_headers_free(&frame.headers);

  scripted_data_feed_init(&df, framedata, framelen);
  user_data.frame_recv_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_recv(session));
  CU_ASSERT(0 == user_data.frame_recv_cb_called);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_PROTOCOL_ERROR == OB_CTRL(item)->rst_stream.error_code);

  CU_ASSERT(0 == nghttp2_session_send(session));

  free(framedata);
  free(nvbuf);
  nghttp2_session_del(session);
}

void test_nghttp2_session_recv_invalid_stream_id(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  scripted_data_feed df;
  my_user_data user_data;
  const char *nv[] = { NULL };
  uint8_t *framedata = NULL, *nvbuf = NULL;
  size_t framedatalen = 0, nvbuflen = 0;
  ssize_t framelen;
  nghttp2_frame frame;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.recv_callback = scripted_recv_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  user_data.df = &df;
  user_data.invalid_frame_recv_cb_called = 0;
  nghttp2_session_server_new(&session, &callbacks, &user_data);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS, 2,
                             NGHTTP2_PRI_DEFAULT, dup_nv(nv));
  framelen = nghttp2_frame_pack_headers(&framedata, &framedatalen,
                                        &nvbuf, &nvbuflen,
                                        &frame.headers,
                                        &session->hd_deflater);
  scripted_data_feed_init(&df, framedata, framelen);
  nghttp2_frame_headers_free(&frame.headers);

  CU_ASSERT(0 == nghttp2_session_recv(session));
  CU_ASSERT(1 == user_data.invalid_frame_recv_cb_called);

  free(framedata);
  free(nvbuf);
  nghttp2_session_del(session);
}

void test_nghttp2_session_recv_invalid_frame(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  scripted_data_feed df;
  my_user_data user_data;
  const char *nv[] = {
    "url", "/", NULL
  };
  uint8_t *framedata = NULL, *nvbuf = NULL;
  size_t framedatalen = 0, nvbuflen = 0;
  ssize_t framelen;
  nghttp2_frame frame;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.recv_callback = scripted_recv_callback;
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  user_data.df = &df;
  user_data.frame_send_cb_called = 0;
  nghttp2_session_server_new(&session, &callbacks, &user_data);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS, 1,
                             NGHTTP2_PRI_DEFAULT, dup_nv(nv));
  framelen = nghttp2_frame_pack_headers(&framedata, &framedatalen,
                                        &nvbuf, &nvbuflen,
                                        &frame.headers,
                                        &session->hd_deflater);
  scripted_data_feed_init(&df, framedata, framelen);

  CU_ASSERT(0 == nghttp2_session_recv(session));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == user_data.frame_send_cb_called);

  /* Receive exactly same bytes of SYN_STREAM causes error */
  scripted_data_feed_init(&df, framedata, framelen);

  CU_ASSERT(0 == nghttp2_session_recv(session));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == user_data.frame_send_cb_called);
  CU_ASSERT(NGHTTP2_GOAWAY == user_data.sent_frame_type);

  free(framedata);
  free(nvbuf);
  nghttp2_frame_headers_free(&frame.headers);

  nghttp2_session_del(session);
}

void test_nghttp2_session_recv_eof(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.recv_callback = eof_recv_callback;

  nghttp2_session_client_new(&session, &callbacks, NULL);
  CU_ASSERT(NGHTTP2_ERR_EOF == nghttp2_session_recv(session));

  nghttp2_session_del(session);
}

void test_nghttp2_session_recv_data(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data ud;
  uint8_t data[8092];
  int rv;
  nghttp2_outbound_item *item;
  nghttp2_stream *stream;
  nghttp2_frame_hd hd;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks.on_data_recv_callback = on_data_recv_callback;

  nghttp2_session_client_new(&session, &callbacks, &ud);

  /* Create DATA frame with length 4KiB */
  memset(data, 0, sizeof(data));
  hd.length = 4096;
  hd.type = NGHTTP2_DATA;
  hd.flags = NGHTTP2_FLAG_NONE;
  hd.stream_id = 1;
  nghttp2_frame_pack_frame_hd(data, &hd);

  /* stream 1 is not opened, so it must be responded with RST_STREAM,
     well actually, this is not mandated by the spec */
  ud.data_chunk_recv_cb_called = 0;
  ud.data_recv_cb_called = 0;
  rv = nghttp2_session_mem_recv(session, data, 8+4096);
  CU_ASSERT(8+4096 == rv);

  CU_ASSERT(0 == ud.data_chunk_recv_cb_called);
  CU_ASSERT(0 == ud.data_recv_cb_called);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_RST_STREAM == OB_CTRL_TYPE(item));

  CU_ASSERT(0 == nghttp2_session_send(session));

  /* Create stream 1 with CLOSING state. DATA is ignored. */
  stream = nghttp2_session_open_stream(session, 1,
                                       NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_CLOSING, NULL);

  ud.data_chunk_recv_cb_called = 0;
  ud.data_recv_cb_called = 0;
  rv = nghttp2_session_mem_recv(session, data, 8+4096);
  CU_ASSERT(8+4096 == rv);

  CU_ASSERT(0 == ud.data_chunk_recv_cb_called);
  CU_ASSERT(0 == ud.data_recv_cb_called);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NULL == item);

  /* This is normal case. DATA is acceptable. */
  stream->state = NGHTTP2_STREAM_OPENED;

  ud.data_chunk_recv_cb_called = 0;
  ud.data_recv_cb_called = 0;
  rv = nghttp2_session_mem_recv(session, data, 8+4096);
  CU_ASSERT(8+4096 == rv);

  CU_ASSERT(1 == ud.data_chunk_recv_cb_called);
  CU_ASSERT(1 == ud.data_recv_cb_called);

  /* Reception of DATA with stream ID = 0 causes connection error */
  hd.length = 4096;
  hd.type = NGHTTP2_DATA;
  hd.flags = NGHTTP2_FLAG_NONE;
  hd.stream_id = 0;
  nghttp2_frame_pack_frame_hd(data, &hd);

  ud.data_chunk_recv_cb_called = 0;
  ud.data_recv_cb_called = 0;
  rv = nghttp2_session_mem_recv(session, data, 8+4096);
  CU_ASSERT(8+4096 == rv);

  CU_ASSERT(0 == ud.data_chunk_recv_cb_called);
  CU_ASSERT(0 == ud.data_recv_cb_called);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_PROTOCOL_ERROR == OB_CTRL(item)->goaway.error_code);

  nghttp2_session_del(session);
}

void test_nghttp2_session_add_frame(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  accumulator acc;
  my_user_data user_data;
  const char *nv[] = {
    "method", "GET",
    "scheme", "https",
    "url", "/",
    "version", "HTTP/1.1",
    NULL
  };
  nghttp2_frame *frame;
  nghttp2_headers_aux_data *aux_data =
    malloc(sizeof(nghttp2_headers_aux_data));
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;
  memset(aux_data, 0, sizeof(nghttp2_headers_aux_data));
  acc.length = 0;
  user_data.acc = &acc;
  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, &user_data));

  frame = malloc(sizeof(nghttp2_frame));
  nghttp2_frame_headers_init(&frame->headers,
                             NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_PRIORITY,
                             -1, NGHTTP2_PRI_DEFAULT, dup_nv(nv));

  CU_ASSERT(0 == nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame,
                                           aux_data));
  CU_ASSERT(0 == nghttp2_pq_empty(&session->ob_ss_pq));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NGHTTP2_HEADERS == acc.buf[2]);
  CU_ASSERT((NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_PRIORITY) == acc.buf[3]);
  /* check stream id */
  CU_ASSERT(1 == nghttp2_get_uint32(&acc.buf[4]));

  nghttp2_session_del(session);
}

void test_nghttp2_session_on_syn_stream_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  const char *nv[] = { NULL };
  nghttp2_frame frame;
  nghttp2_stream *stream;
  int32_t stream_id = 1;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
  user_data.frame_recv_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  nghttp2_session_server_new(&session, &callbacks, &user_data);
  nghttp2_frame_headers_init(&frame.headers,
                             NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_PRIORITY,
                             stream_id, 1 << 20, dup_nv(nv));

  CU_ASSERT(0 == nghttp2_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.frame_recv_cb_called);
  stream = nghttp2_session_get_stream(session, stream_id);
  CU_ASSERT(NGHTTP2_STREAM_OPENING == stream->state);
  CU_ASSERT(1 << 20 == stream->pri);

  nghttp2_frame_headers_free(&frame.headers);

  /* More than max concurrent streams leads REFUSED_STREAM */
  session->local_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS] = 1;
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS,
                             3, NGHTTP2_PRI_DEFAULT, dup_nv(nv));
  user_data.invalid_frame_recv_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid_frame_recv_cb_called);
  CU_ASSERT(0 == (session->goaway_flags & NGHTTP2_GOAWAY_FAIL_ON_SEND));

  nghttp2_frame_headers_free(&frame.headers);
  session->local_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS] =
    NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS;

  /* Stream ID less than or equal to the previouly received SYN_STREAM
     leads to connection error */
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS,
                             3, NGHTTP2_PRI_DEFAULT, dup_nv(nv));
  user_data.invalid_frame_recv_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid_frame_recv_cb_called);
  CU_ASSERT(session->goaway_flags & NGHTTP2_GOAWAY_FAIL_ON_SEND);

  nghttp2_frame_headers_free(&frame.headers);

  nghttp2_session_del(session);
}

void test_nghttp2_session_on_syn_reply_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  const char *nv[] = { NULL };
  nghttp2_frame frame;
  nghttp2_stream *stream;
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
  user_data.frame_recv_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  nghttp2_session_client_new(&session, &callbacks, &user_data);
  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_OPENING, NULL);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS, 1,
                             NGHTTP2_PRI_DEFAULT, dup_nv(nv));

  CU_ASSERT(0 == nghttp2_session_on_syn_reply_received(session, &frame,
                                                       stream));
  CU_ASSERT(1 == user_data.frame_recv_cb_called);
  CU_ASSERT(NGHTTP2_STREAM_OPENED == stream->state);

  /* Check the situation when response HEADERS is received after peer
     sends FIN */
  stream = nghttp2_session_open_stream(session, 3, NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_OPENED, NULL);
  nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
  frame.hd.stream_id = 3;

  CU_ASSERT(0 == nghttp2_session_on_syn_reply_received(session, &frame,
                                                       stream));
  CU_ASSERT(1 == user_data.invalid_frame_recv_cb_called);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_STREAM_CLOSED == OB_CTRL(item)->rst_stream.error_code);

  nghttp2_frame_headers_free(&frame.headers);
  nghttp2_session_del(session);
}

void test_nghttp2_session_on_headers_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  const char *nv[] = { NULL };
  nghttp2_frame frame;
  nghttp2_stream *stream;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
  user_data.frame_recv_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  nghttp2_session_client_new(&session, &callbacks, &user_data);
  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_OPENED, NULL);
  nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS, 1,
                             NGHTTP2_PRI_DEFAULT, dup_nv(nv));

  CU_ASSERT(0 == nghttp2_session_on_headers_received(session, &frame, stream));
  CU_ASSERT(1 == user_data.frame_recv_cb_called);
  CU_ASSERT(NGHTTP2_STREAM_OPENED == stream->state);

  /* stream closed */
  frame.hd.flags |= NGHTTP2_FLAG_END_STREAM;

  CU_ASSERT(0 == nghttp2_session_on_headers_received(session, &frame, stream));
  CU_ASSERT(2 == user_data.frame_recv_cb_called);
  CU_ASSERT(NULL == nghttp2_session_get_stream(session, 1));

  /* Check to see when NGHTTP2_STREAM_CLOSING, incoming HEADERS is
     discarded. */
  stream = nghttp2_session_open_stream(session, 3, NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_CLOSING, NULL);
  frame.hd.stream_id = 3;
  frame.hd.flags = NGHTTP2_FLAG_NONE;
  CU_ASSERT(0 == nghttp2_session_on_headers_received(session, &frame, stream));
  /* See no counters are updated */
  CU_ASSERT(2 == user_data.frame_recv_cb_called);
  CU_ASSERT(0 == user_data.invalid_frame_recv_cb_called);

  /* Server initiated stream */
  stream = nghttp2_session_open_stream(session, 2, NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_OPENING, NULL);

  /* half closed (remote) */
  frame.hd.flags = NGHTTP2_FLAG_END_STREAM;
  frame.hd.stream_id = 2;

  CU_ASSERT(0 == nghttp2_session_on_headers_received(session, &frame, stream));
  CU_ASSERT(3 == user_data.frame_recv_cb_called);
  CU_ASSERT(NGHTTP2_STREAM_OPENING == stream->state);
  CU_ASSERT(stream->shut_flags & NGHTTP2_SHUT_RD);
  /* Further reception of HEADERS is subject to stream error */
  CU_ASSERT(0 == nghttp2_session_on_headers_received(session, &frame, stream));
  CU_ASSERT(1 == user_data.invalid_frame_recv_cb_called);

  nghttp2_frame_headers_free(&frame.headers);

  nghttp2_session_del(session);
}

void test_nghttp2_session_on_rst_stream_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_frame frame;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  nghttp2_session_server_new(&session, &callbacks, &user_data);
  nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                              NGHTTP2_PRI_DEFAULT,
                              NGHTTP2_STREAM_OPENING, NULL);

  nghttp2_frame_rst_stream_init(&frame.rst_stream, 1, NGHTTP2_PROTOCOL_ERROR);

  CU_ASSERT(0 == nghttp2_session_on_rst_stream_received(session, &frame));
  CU_ASSERT(NULL == nghttp2_session_get_stream(session, 1));

  nghttp2_frame_rst_stream_free(&frame.rst_stream);
  nghttp2_session_del(session);
}

void test_nghttp2_session_on_settings_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_stream *stream1, *stream2;
  nghttp2_frame frame;
  const size_t niv = 5;
  nghttp2_settings_entry iv[255];

  iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = 1000000009;

  iv[1].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[1].value = 50;

  iv[2].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[2].value = 64*1024;

  iv[3].settings_id = NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS;
  iv[3].value = 1;

  /* Unknown settings ID */
  iv[4].settings_id = 999;
  iv[4].value = 0;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  nghttp2_session_client_new(&session, &callbacks, &user_data);
  session->remote_settings[NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE] = 16*1024;

  stream1 = nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                                        NGHTTP2_PRI_DEFAULT,
                                        NGHTTP2_STREAM_OPENING, NULL);
  stream2 = nghttp2_session_open_stream(session, 2, NGHTTP2_FLAG_NONE,
                                        NGHTTP2_PRI_DEFAULT,
                                        NGHTTP2_STREAM_OPENING, NULL);
  /* Set window size for each streams and will see how settings
     updates these values */
  stream1->window_size = 16*1024;
  stream2->window_size = -48*1024;

  nghttp2_frame_settings_init(&frame.settings, dup_iv(iv, niv), niv);

  CU_ASSERT(0 == nghttp2_session_on_settings_received(session, &frame));
  CU_ASSERT(1000000009 ==
            session->remote_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS]);
  CU_ASSERT(64*1024 ==
            session->remote_settings[NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE]);
  CU_ASSERT(1 ==
            session->remote_settings[NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS]);

  CU_ASSERT(64*1024 == stream1->window_size);
  CU_ASSERT(0 == stream2->window_size);

  frame.settings.iv[2].value = 16*1024;

  CU_ASSERT(0 == nghttp2_session_on_settings_received(session, &frame));

  CU_ASSERT(16*1024 == stream1->window_size);
  CU_ASSERT(-48*1024 == stream2->window_size);

  CU_ASSERT(0 == stream1->remote_flow_control);
  CU_ASSERT(0 == stream2->remote_flow_control);
  CU_ASSERT(0 == session->remote_flow_control);

  nghttp2_frame_settings_free(&frame.settings);

  nghttp2_session_del(session);
}

void test_nghttp2_session_on_ping_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_frame frame;
  nghttp2_outbound_item *top;
  const uint8_t opaque_data[] = "01234567";

  user_data.frame_recv_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  nghttp2_session_client_new(&session, &callbacks, &user_data);
  nghttp2_frame_ping_init(&frame.ping, NGHTTP2_FLAG_PONG, opaque_data);

  CU_ASSERT(0 == nghttp2_session_on_ping_received(session, &frame));
  CU_ASSERT(1 == user_data.frame_recv_cb_called);

  /* Since this ping frame has PONG flag set, no further action is
     performed. */
  CU_ASSERT(NULL == nghttp2_session_get_ob_pq_top(session));

  /* Clear the flag, and receive it again */
  frame.hd.flags = NGHTTP2_FLAG_NONE;

  CU_ASSERT(0 == nghttp2_session_on_ping_received(session, &frame));
  CU_ASSERT(2 == user_data.frame_recv_cb_called);
  top = nghttp2_session_get_ob_pq_top(session);
  CU_ASSERT(NGHTTP2_PING == OB_CTRL_TYPE(top));
  CU_ASSERT(NGHTTP2_FLAG_PONG == OB_CTRL(top)->hd.flags);
  CU_ASSERT(memcmp(opaque_data, OB_CTRL(top)->ping.opaque_data, 8) == 0);

  nghttp2_frame_ping_free(&frame.ping);
  nghttp2_session_del(session);
}

void test_nghttp2_session_on_goaway_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_frame frame;
  user_data.frame_recv_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  nghttp2_session_client_new(&session, &callbacks, &user_data);
  nghttp2_frame_goaway_init(&frame.goaway, 1, NGHTTP2_PROTOCOL_ERROR, NULL, 0);

  CU_ASSERT(0 == nghttp2_session_on_goaway_received(session, &frame));
  CU_ASSERT(1 == user_data.frame_recv_cb_called);
  CU_ASSERT(session->goaway_flags == NGHTTP2_GOAWAY_RECV);

  nghttp2_frame_goaway_free(&frame.goaway);
  nghttp2_session_del(session);
}

void test_nghttp2_session_on_window_update_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_frame frame;
  nghttp2_stream *stream;
  nghttp2_outbound_item *data_item;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
  user_data.frame_recv_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  nghttp2_session_client_new(&session, &callbacks, &user_data);
  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_OPENED, NULL);
  nghttp2_frame_window_update_init(&frame.window_update, NGHTTP2_FLAG_NONE,
                                   1, 16*1024);

  CU_ASSERT(0 == nghttp2_session_on_window_update_received(session, &frame));
  CU_ASSERT(1 == user_data.frame_recv_cb_called);
  CU_ASSERT(64*1024+16*1024 == stream->window_size);

  data_item = malloc(sizeof(nghttp2_outbound_item));
  memset(data_item, 0, sizeof(nghttp2_outbound_item));
  data_item->frame_cat = NGHTTP2_CAT_DATA;
  nghttp2_stream_defer_data(stream, data_item, NGHTTP2_DEFERRED_FLOW_CONTROL);

  CU_ASSERT(0 == nghttp2_session_on_window_update_received(session, &frame));
  CU_ASSERT(2 == user_data.frame_recv_cb_called);
  CU_ASSERT(64*1024+16*1024*2 == stream->window_size);
  CU_ASSERT(NULL == stream->deferred_data);

  nghttp2_frame_window_update_free(&frame.window_update);
  nghttp2_session_del(session);
}

void test_nghttp2_session_on_data_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_outbound_item *top;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));

  nghttp2_session_client_new(&session, &callbacks, &user_data);
  stream = nghttp2_session_open_stream(session, 2, NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_OPENING, NULL);
  CU_ASSERT(0 == nghttp2_session_on_data_received(session, 4096,
                                                  NGHTTP2_FLAG_NONE, 2));
  CU_ASSERT(0 == stream->shut_flags);
  CU_ASSERT(0 == nghttp2_session_on_data_received(session, 4096,
                                                  NGHTTP2_FLAG_END_STREAM, 2));
  CU_ASSERT(NGHTTP2_SHUT_RD == stream->shut_flags);

  /* If NGHTTP2_STREAM_CLOSING state, DATA frame is discarded. */
  stream = nghttp2_session_open_stream(session, 4, NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_CLOSING, NULL);
  CU_ASSERT(0 == nghttp2_session_on_data_received(session, 4096,
                                                  NGHTTP2_FLAG_NONE, 4));
  CU_ASSERT(NULL == nghttp2_session_get_ob_pq_top(session));

  /* Check INVALID_STREAM case: DATA frame with stream ID which does
     not exist. */
  CU_ASSERT(0 == nghttp2_session_on_data_received(session, 4096,
                                                  NGHTTP2_FLAG_NONE, 6));
  top = nghttp2_session_get_ob_pq_top(session);
  CU_ASSERT(NGHTTP2_RST_STREAM == OB_CTRL_TYPE(top));
  CU_ASSERT(NGHTTP2_PROTOCOL_ERROR == OB_CTRL(top)->rst_stream.error_code);

  nghttp2_session_del(session);
}

void test_nghttp2_session_send_headers_start_stream(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { NULL };
  nghttp2_frame *frame = malloc(sizeof(nghttp2_frame));
  nghttp2_stream *stream;
  nghttp2_headers_aux_data *aux_data =
    malloc(sizeof(nghttp2_headers_aux_data));
  memset(aux_data, 0, sizeof(nghttp2_headers_aux_data));
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  nghttp2_session_client_new(&session, &callbacks, NULL);
  nghttp2_frame_headers_init(&frame->headers, NGHTTP2_FLAG_END_HEADERS, -1,
                             NGHTTP2_PRI_DEFAULT, dup_nv(nv));
  nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, aux_data);
  CU_ASSERT(0 == nghttp2_session_send(session));
  stream = nghttp2_session_get_stream(session, 1);
  CU_ASSERT(NGHTTP2_STREAM_OPENING == stream->state);

  nghttp2_session_del(session);
}

void test_nghttp2_session_send_headers_reply(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { NULL };
  nghttp2_frame *frame = malloc(sizeof(nghttp2_frame));
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, NULL));
  nghttp2_session_open_stream(session, 2, NGHTTP2_FLAG_NONE,
                              NGHTTP2_PRI_DEFAULT,
                              NGHTTP2_STREAM_OPENING, NULL);
  nghttp2_frame_headers_init(&frame->headers, NGHTTP2_FLAG_END_HEADERS, 2,
                             NGHTTP2_PRI_DEFAULT, dup_nv(nv));
  nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  CU_ASSERT(0 == nghttp2_session_send(session));
  stream = nghttp2_session_get_stream(session, 2);
  CU_ASSERT(NGHTTP2_STREAM_OPENED == stream->state);

  nghttp2_session_del(session);
}

void test_nghttp2_session_send_rst_stream(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_frame *frame;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  nghttp2_session_client_new(&session, &callbacks, &user_data);
  nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                              NGHTTP2_PRI_DEFAULT,
                              NGHTTP2_STREAM_OPENING, NULL);

  frame = malloc(sizeof(nghttp2_frame));
  nghttp2_frame_rst_stream_init(&frame->rst_stream, 1, NGHTTP2_PROTOCOL_ERROR);
  nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  CU_ASSERT(0 == nghttp2_session_send(session));

  CU_ASSERT(NULL == nghttp2_session_get_stream(session, 1));

  nghttp2_session_del(session);
}

void test_nghttp2_session_is_my_stream_id(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  nghttp2_session_server_new(&session, &callbacks, NULL);

  CU_ASSERT(0 == nghttp2_session_is_my_stream_id(session, 0));
  CU_ASSERT(0 == nghttp2_session_is_my_stream_id(session, 1));
  CU_ASSERT(1 == nghttp2_session_is_my_stream_id(session, 2));

  nghttp2_session_del(session);

  nghttp2_session_client_new(&session, &callbacks, NULL);

  CU_ASSERT(0 == nghttp2_session_is_my_stream_id(session, 0));
  CU_ASSERT(1 == nghttp2_session_is_my_stream_id(session, 1));
  CU_ASSERT(0 == nghttp2_session_is_my_stream_id(session, 2));

  nghttp2_session_del(session);
}

void test_nghttp2_submit_response(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { "Content-Length", "1024", NULL };
  nghttp2_data_provider data_prd;
  my_user_data ud;
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 64*1024;
  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, &ud));
  nghttp2_session_open_stream(session, 2, NGHTTP2_FLAG_NONE,
                              NGHTTP2_PRI_DEFAULT,
                              NGHTTP2_STREAM_OPENING, NULL);
  CU_ASSERT(0 == nghttp2_submit_response(session, 2, nv, &data_prd));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp("content-length", OB_CTRL(item)->headers.nv[0]));
  CU_ASSERT(0 == nghttp2_session_send(session));
  nghttp2_session_del(session);
}

void test_nghttp2_submit_response_without_data(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  accumulator acc;
  const char *nv[] = { ":Version", "HTTP/1.1", NULL };
  nghttp2_data_provider data_prd = {{-1}, NULL};
  nghttp2_outbound_item *item;
  my_user_data ud;
  nghttp2_frame frame;

  acc.length = 0;
  ud.acc = &acc;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = accumulator_send_callback;
  CU_ASSERT(0 == nghttp2_session_server_new(&session, &callbacks, &ud));
  nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_END_STREAM,
                              NGHTTP2_PRI_DEFAULT,
                              NGHTTP2_STREAM_OPENING, NULL);
  CU_ASSERT(0 == nghttp2_submit_response(session, 1, nv, &data_prd));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp(":version", OB_CTRL(item)->headers.nv[0]));
  CU_ASSERT(OB_CTRL(item)->hd.flags & NGHTTP2_FLAG_END_STREAM);

  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == unpack_frame_with_nv_block(&frame, NGHTTP2_HEADERS,
                                            &session->hd_inflater,
                                            acc.buf, acc.length));
  CU_ASSERT(0 == strcmp(":version", frame.headers.nv[0]));
  nghttp2_frame_headers_free(&frame.headers);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_request_with_data(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { ":Version", "HTTP/1.1", NULL };
  nghttp2_data_provider data_prd;
  my_user_data ud;
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 64*1024;
  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, &ud));
  CU_ASSERT(0 == nghttp2_submit_request(session, NGHTTP2_PRI_DEFAULT, nv,
                                        &data_prd, NULL));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp(":version", OB_CTRL(item)->headers.nv[0]));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == ud.data_source_length);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_request_without_data(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  accumulator acc;
  const char *nv[] = { ":Version", "HTTP/1.1", NULL };
  nghttp2_data_provider data_prd = {{-1}, NULL};
  nghttp2_outbound_item *item;
  my_user_data ud;
  nghttp2_frame frame;

  acc.length = 0;
  ud.acc = &acc;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;
  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, &ud));
  CU_ASSERT(0 == nghttp2_submit_request(session, NGHTTP2_PRI_DEFAULT, nv,
                                        &data_prd, NULL));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp(":version", OB_CTRL(item)->headers.nv[0]));
  CU_ASSERT(OB_CTRL(item)->hd.flags & NGHTTP2_FLAG_END_STREAM);

  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == unpack_frame_with_nv_block(&frame, NGHTTP2_HEADERS,
                                            &session->hd_inflater,
                                            acc.buf, acc.length));
  CU_ASSERT(0 == strcmp(":version", frame.headers.nv[0]));
  nghttp2_frame_headers_free(&frame.headers);

  nghttp2_session_del(session);
}


void test_nghttp2_submit_headers_start_stream(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { ":version", "HTTP/1.1", NULL };
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, NULL));
  CU_ASSERT(0 == nghttp2_submit_headers(session,
                                        NGHTTP2_FLAG_END_STREAM,
                                        -1, NGHTTP2_PRI_DEFAULT,
                                        nv, NULL));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp(":version", OB_CTRL(item)->headers.nv[0]));
  CU_ASSERT((NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_END_STREAM) ==
            OB_CTRL(item)->hd.flags);
  CU_ASSERT(NGHTTP2_PRI_DEFAULT == OB_CTRL(item)->headers.pri);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_headers_reply(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { ":version", "HTTP/1.1", NULL };
  my_user_data ud;
  nghttp2_outbound_item *item;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  CU_ASSERT(0 == nghttp2_session_server_new(&session, &callbacks, &ud));
  CU_ASSERT(0 == nghttp2_submit_headers(session,
                                        NGHTTP2_FLAG_END_STREAM,
                                        1, NGHTTP2_PRI_DEFAULT,
                                        nv, NULL));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp(":version", OB_CTRL(item)->headers.nv[0]));
  CU_ASSERT((NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_HEADERS) ==
            OB_CTRL(item)->hd.flags);

  ud.frame_send_cb_called = 0;
  ud.sent_frame_type = 0;
  /* The transimission will be canceled because the stream 1 is not
     open. */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == ud.frame_send_cb_called);

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_OPENING, NULL);

  CU_ASSERT(0 == nghttp2_submit_headers(session,
                                        NGHTTP2_FLAG_END_STREAM,
                                        1, NGHTTP2_PRI_DEFAULT,
                                        nv, NULL));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == ud.frame_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == ud.sent_frame_type);
  CU_ASSERT(stream->shut_flags & NGHTTP2_SHUT_WR);

  nghttp2_session_del(session);
}


void test_nghttp2_submit_headers(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { ":Version", "HTTP/1.1", NULL };
  my_user_data ud;
  nghttp2_outbound_item *item;
  nghttp2_stream *stream;
  accumulator acc;
  nghttp2_frame frame;

  acc.length = 0;
  ud.acc = &acc;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, &ud));
  CU_ASSERT(0 == nghttp2_submit_headers(session,
                                        NGHTTP2_FLAG_END_STREAM,
                                        1, NGHTTP2_PRI_DEFAULT,
                                        nv, NULL));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp(":version", OB_CTRL(item)->headers.nv[0]));
  CU_ASSERT((NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_HEADERS) ==
            OB_CTRL(item)->hd.flags);

  ud.frame_send_cb_called = 0;
  ud.sent_frame_type = 0;
  /* The transimission will be canceled because the stream 1 is not
     open. */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == ud.frame_send_cb_called);

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_OPENING, NULL);

  CU_ASSERT(0 == nghttp2_submit_headers(session,
                                        NGHTTP2_FLAG_END_STREAM,
                                        1, NGHTTP2_PRI_DEFAULT,
                                        nv, NULL));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == ud.frame_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == ud.sent_frame_type);
  CU_ASSERT(stream->shut_flags & NGHTTP2_SHUT_WR);

  CU_ASSERT(0 == unpack_frame_with_nv_block(&frame,
                                            NGHTTP2_HEADERS,
                                            &session->hd_inflater,
                                            acc.buf, acc.length));
  CU_ASSERT(0 == strcmp(":version", frame.headers.nv[0]));
  nghttp2_frame_headers_free(&frame.headers);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_settings(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data ud;
  nghttp2_outbound_item *item;
  nghttp2_frame *frame;
  nghttp2_settings_entry iv[3];

  iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = 50;

  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 16*1024;

  /* This is duplicate entry */
  iv[2].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[2].value = 150;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  nghttp2_session_server_new(&session, &callbacks, &ud);

  CU_ASSERT(NGHTTP2_ERR_INVALID_ARGUMENT ==
            nghttp2_submit_settings(session, iv, 3));

  /* Make sure that local settings are not changed */
  CU_ASSERT(NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS ==
            session->local_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS]);
  CU_ASSERT(NGHTTP2_INITIAL_WINDOW_SIZE ==
            session->local_settings[NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE]);

  /* Now sends without 3rd one */
  CU_ASSERT(0 == nghttp2_submit_settings(session, iv, 2));

  /* Make sure that local settings are changed */
  CU_ASSERT(50 ==
            session->local_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS]);
  CU_ASSERT(16*1024 ==
            session->local_settings[NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE]);

  item = nghttp2_session_get_next_ob_item(session);

  CU_ASSERT(NGHTTP2_SETTINGS == OB_CTRL_TYPE(item));

  frame = item->frame;
  CU_ASSERT(2 == frame->settings.niv);
  CU_ASSERT(50 == frame->settings.iv[0].value);
  CU_ASSERT(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS ==
            frame->settings.iv[0].settings_id);

  CU_ASSERT(16*1024 == frame->settings.iv[1].value);
  CU_ASSERT(NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE ==
            frame->settings.iv[1].settings_id);

  ud.frame_send_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == ud.frame_send_cb_called);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_window_update(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data ud;
  nghttp2_outbound_item *item;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  nghttp2_session_client_new(&session, &callbacks, &ud);
  stream = nghttp2_session_open_stream(session, 2,
                                       NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_OPENED, NULL);
  stream->recv_window_size = 4096;

  CU_ASSERT(0 == nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 2,
                                              1024));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_WINDOW_UPDATE == OB_CTRL_TYPE(item));
  CU_ASSERT(1024 == OB_CTRL(item)->window_update.window_size_increment);
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(3072 == stream->recv_window_size);

  CU_ASSERT(0 == nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 2,
                                              4096));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_WINDOW_UPDATE == OB_CTRL_TYPE(item));
  CU_ASSERT(4096 == OB_CTRL(item)->window_update.window_size_increment);
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == stream->recv_window_size);

  CU_ASSERT(0 == nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 2,
                                              4096));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_WINDOW_UPDATE == OB_CTRL_TYPE(item));
  CU_ASSERT(4096 == OB_CTRL(item)->window_update.window_size_increment);
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == stream->recv_window_size);

  CU_ASSERT(NGHTTP2_ERR_INVALID_ARGUMENT ==
            nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 2, 0));
  CU_ASSERT(NGHTTP2_ERR_INVALID_ARGUMENT ==
            nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 2, -1));
  CU_ASSERT(NGHTTP2_ERR_STREAM_CLOSED ==
            nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 4, 4096));

  nghttp2_session_del(session);
}

void test_nghttp2_submit_invalid_nv(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));

  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, NULL));

  /* nghttp2_submit_request */
  CU_ASSERT(NGHTTP2_ERR_INVALID_ARGUMENT ==
            nghttp2_submit_request(session, NGHTTP2_PRI_DEFAULT,
                                   empty_name_nv, NULL, NULL));

  CU_ASSERT(NGHTTP2_ERR_INVALID_ARGUMENT ==
            nghttp2_submit_request(session, NGHTTP2_PRI_DEFAULT,
                                   null_val_nv, NULL, NULL));

  /* nghttp2_submit_response */
  CU_ASSERT(NGHTTP2_ERR_INVALID_ARGUMENT ==
            nghttp2_submit_response(session, 2, empty_name_nv, NULL));

  CU_ASSERT(NGHTTP2_ERR_INVALID_ARGUMENT ==
            nghttp2_submit_response(session, 2, null_val_nv, NULL));

  /* nghttp2_submit_headers */
  CU_ASSERT(NGHTTP2_ERR_INVALID_ARGUMENT ==
            nghttp2_submit_headers(session, NGHTTP2_FLAG_NONE, -1,
                                   NGHTTP2_PRI_DEFAULT, empty_name_nv, NULL));

  CU_ASSERT(NGHTTP2_ERR_INVALID_ARGUMENT ==
            nghttp2_submit_headers(session, NGHTTP2_FLAG_NONE, -1,
                                   NGHTTP2_PRI_DEFAULT, null_val_nv, NULL));

  nghttp2_session_del(session);
}

void test_nghttp2_session_get_next_ob_item(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { NULL };
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  nghttp2_session_server_new(&session, &callbacks, NULL);
  session->remote_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS] = 2;

  CU_ASSERT(NULL == nghttp2_session_get_next_ob_item(session));
  nghttp2_submit_ping(session, NULL);
  CU_ASSERT(NGHTTP2_PING ==
            OB_CTRL_TYPE(nghttp2_session_get_next_ob_item(session)));

  nghttp2_submit_request(session, NGHTTP2_PRI_DEFAULT, nv, NULL, NULL);
  CU_ASSERT(NGHTTP2_PING ==
            OB_CTRL_TYPE(nghttp2_session_get_next_ob_item(session)));

  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NULL == nghttp2_session_get_next_ob_item(session));

  /* Incoming stream does not affect the number of outgoing max
     concurrent streams. */
  nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                              NGHTTP2_PRI_DEFAULT,
                              NGHTTP2_STREAM_OPENING, NULL);

  nghttp2_submit_request(session, 0, nv, NULL, NULL);
  CU_ASSERT(NGHTTP2_HEADERS ==
            OB_CTRL_TYPE(nghttp2_session_get_next_ob_item(session)));
  CU_ASSERT(0 == nghttp2_session_send(session));

  nghttp2_submit_request(session, 0, nv, NULL, NULL);
  CU_ASSERT(NULL == nghttp2_session_get_next_ob_item(session));

  session->remote_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS] = 3;

  CU_ASSERT(NGHTTP2_HEADERS ==
            OB_CTRL_TYPE(nghttp2_session_get_next_ob_item(session)));

  nghttp2_session_del(session);
}

void test_nghttp2_session_pop_next_ob_item(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { NULL };
  nghttp2_outbound_item *item;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  nghttp2_session_server_new(&session, &callbacks, NULL);
  session->remote_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS] = 1;

  CU_ASSERT(NULL == nghttp2_session_pop_next_ob_item(session));
  nghttp2_submit_ping(session, NULL);
  nghttp2_submit_request(session, 1, nv, NULL, NULL);

  item = nghttp2_session_pop_next_ob_item(session);
  CU_ASSERT(NGHTTP2_PING == OB_CTRL_TYPE(item));
  nghttp2_outbound_item_free(item);
  free(item);

  item = nghttp2_session_pop_next_ob_item(session);
  CU_ASSERT(NGHTTP2_HEADERS == OB_CTRL_TYPE(item));
  nghttp2_outbound_item_free(item);
  free(item);

  CU_ASSERT(NULL == nghttp2_session_pop_next_ob_item(session));

  /* Incoming stream does not affect the number of outgoing max
     concurrent streams. */
  nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                              3, NGHTTP2_STREAM_OPENING, NULL);
  /* In-flight outgoing stream */
  nghttp2_session_open_stream(session, 4, NGHTTP2_FLAG_NONE,
                              3, NGHTTP2_STREAM_OPENING, NULL);

  nghttp2_submit_request(session, 0, nv, NULL, NULL);
  nghttp2_submit_response(session, 1, nv, NULL);

  item = nghttp2_session_pop_next_ob_item(session);
  CU_ASSERT(NGHTTP2_HEADERS == OB_CTRL_TYPE(item));
  CU_ASSERT(1 == OB_CTRL(item)->hd.stream_id);
  nghttp2_outbound_item_free(item);
  free(item);

  CU_ASSERT(NULL == nghttp2_session_pop_next_ob_item(session));

  session->remote_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS] = 2;

  item = nghttp2_session_pop_next_ob_item(session);
  CU_ASSERT(NGHTTP2_HEADERS == OB_CTRL_TYPE(item));
  nghttp2_outbound_item_free(item);
  free(item);

  nghttp2_session_del(session);
}

void test_nghttp2_session_reply_fail(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { NULL };
  nghttp2_data_provider data_prd;
  my_user_data ud;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = fail_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 4*1024;
  CU_ASSERT(0 == nghttp2_session_server_new(&session, &callbacks, &ud));
  nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                              NGHTTP2_PRI_DEFAULT,
                              NGHTTP2_STREAM_OPENING, NULL);
  CU_ASSERT(0 == nghttp2_submit_response(session, 1, nv, &data_prd));
  CU_ASSERT(NGHTTP2_ERR_CALLBACK_FAILURE == nghttp2_session_send(session));
  nghttp2_session_del(session);
}

void test_nghttp2_session_max_concurrent_streams(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_frame frame;
  const char *nv[] = { NULL };
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  nghttp2_session_server_new(&session, &callbacks, NULL);
  nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                              NGHTTP2_PRI_DEFAULT,
                              NGHTTP2_STREAM_OPENED, NULL);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_NONE, 3,
                             NGHTTP2_PRI_DEFAULT, dup_nv(nv));
  session->local_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS] = 1;

  CU_ASSERT(0 == nghttp2_session_on_syn_stream_received(session, &frame));

  item = nghttp2_session_get_ob_pq_top(session);
  CU_ASSERT(NGHTTP2_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_REFUSED_STREAM == OB_CTRL(item)->rst_stream.error_code)

  nghttp2_frame_headers_free(&frame.headers);
  nghttp2_session_del(session);
}

/*
 * Check that on_stream_close_callback is called when server pushed
 * SYN_STREAM have NGHTTP2_CTRL_FLAG_FIN.
 */
void test_nghttp2_session_stream_close_on_headers_push(void)
{
  /* nghttp2_session *session; */
  /* nghttp2_session_callbacks callbacks; */
  /* const char *nv[] = { NULL }; */
  /* my_user_data ud; */
  /* nghttp2_frame frame; */

  /* memset(&callbacks, 0, sizeof(nghttp2_session_callbacks)); */
  /* callbacks.on_stream_close_callback = */
  /*   no_stream_user_data_stream_close_callback; */
  /* ud.stream_close_cb_called = 0; */

  /* nghttp2_session_client_new(&session, NGHTTP2_PROTO_SPDY2, &callbacks, &ud); */
  /* nghttp2_session_open_stream(session, 1, NGHTTP2_CTRL_FLAG_NONE, 3, */
  /*                             NGHTTP2_STREAM_OPENING, NULL); */
  /* nghttp2_frame_syn_stream_init(&frame.syn_stream, NGHTTP2_PROTO_SPDY2, */
  /*                               NGHTTP2_CTRL_FLAG_FIN | */
  /*                               NGHTTP2_CTRL_FLAG_UNIDIRECTIONAL, */
  /*                               2, 1, 3, dup_nv(nv)); */

  /* CU_ASSERT(0 == nghttp2_session_on_syn_stream_received(session, &frame)); */

  /* nghttp2_frame_syn_stream_free(&frame.syn_stream); */
  /* nghttp2_session_del(session); */
}

void test_nghttp2_session_stop_data_with_rst_stream(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { NULL };
  my_user_data ud;
  nghttp2_data_provider data_prd;
  nghttp2_frame frame;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.send_callback = block_count_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.frame_send_cb_called = 0;
  ud.data_source_length = 16*1024;

  nghttp2_session_server_new(&session, &callbacks, &ud);
  nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                              NGHTTP2_PRI_DEFAULT,
                              NGHTTP2_STREAM_OPENING, NULL);
  nghttp2_submit_response(session, 1, nv, &data_prd);

  ud.block_count = 2;
  /* Sends SYN_REPLY + DATA[0] */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NGHTTP2_HEADERS == ud.sent_frame_type);
  /* data for DATA[1] is read from data_prd but it is not sent */
  CU_ASSERT(ud.data_source_length == 8*1024);

  nghttp2_frame_rst_stream_init(&frame.rst_stream, 1, NGHTTP2_CANCEL);
  CU_ASSERT(0 == nghttp2_session_on_rst_stream_received(session, &frame));
  nghttp2_frame_rst_stream_free(&frame.rst_stream);

  /* Big enough number to send all DATA frames potentially. */
  ud.block_count = 100;
  /* Nothing will be sent in the following call. */
  CU_ASSERT(0 == nghttp2_session_send(session));
  /* With RST_STREAM, stream is canceled and further DATA on that
     stream are not sent. */
  CU_ASSERT(ud.data_source_length == 8*1024);

  CU_ASSERT(NULL == nghttp2_session_get_stream(session, 1));

  nghttp2_session_del(session);
}

void test_nghttp2_session_defer_data(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { NULL };
  my_user_data ud;
  nghttp2_data_provider data_prd;
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.send_callback = block_count_send_callback;
  data_prd.read_callback = defer_data_source_read_callback;

  ud.frame_send_cb_called = 0;
  ud.data_source_length = 16*1024;

  nghttp2_session_server_new(&session, &callbacks, &ud);
  nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                              NGHTTP2_PRI_DEFAULT,
                              NGHTTP2_STREAM_OPENING, NULL);
  nghttp2_submit_response(session, 1, nv, &data_prd);

  ud.block_count = 1;
  /* Sends HEADERS reply */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NGHTTP2_HEADERS == ud.sent_frame_type);
  /* No data is read */
  CU_ASSERT(ud.data_source_length == 16*1024);

  ud.block_count = 1;
  nghttp2_submit_ping(session, NULL);
  /* Sends PING */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NGHTTP2_PING == ud.sent_frame_type);

  /* Resume deferred DATA */
  CU_ASSERT(0 == nghttp2_session_resume_data(session, 1));
  item = nghttp2_session_get_ob_pq_top(session);
  OB_DATA(item)->data_prd.read_callback =
    fixed_length_data_source_read_callback;
  ud.block_count = 1;
  /* Reads 2 4KiB blocks */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(ud.data_source_length == 8*1024);

  /* Deferred again */
  OB_DATA(item)->data_prd.read_callback = defer_data_source_read_callback;
  /* This is needed since 4KiB block is already read and waiting to be
     sent. No read_callback invocation. */
  ud.block_count = 1;
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(ud.data_source_length == 8*1024);

  /* Resume deferred DATA */

  CU_ASSERT(0 == nghttp2_session_resume_data(session, 1));
  item = nghttp2_session_get_ob_pq_top(session);
  OB_DATA(item)->data_prd.read_callback =
    fixed_length_data_source_read_callback;
  ud.block_count = 1;
  /* Reads 2 4KiB blocks */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(ud.data_source_length == 0);

  nghttp2_session_del(session);
}

void test_nghttp2_session_flow_control(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { NULL };
  my_user_data ud;
  nghttp2_data_provider data_prd;
  nghttp2_frame frame;
  nghttp2_stream *stream;
  int32_t new_initial_window_size;
  nghttp2_settings_entry iv[1];
  nghttp2_frame settings_frame;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.frame_send_cb_called = 0;
  ud.data_source_length = 128*1024;

  /* Initial window size is 64KiB */
  nghttp2_session_client_new(&session, &callbacks, &ud);
  nghttp2_submit_request(session, NGHTTP2_PRI_DEFAULT, nv, &data_prd, NULL);

  /* Sends 64KiB data */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(64*1024 == ud.data_source_length);

  /* Back 32KiB in stream window */
  nghttp2_frame_window_update_init(&frame.window_update, NGHTTP2_FLAG_NONE,
                                   1, 32*1024);
  nghttp2_session_on_window_update_received(session, &frame);

  /* Send nothing because of connection-level window */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(64*1024 == ud.data_source_length);

  /* Back 32KiB in connection-level window */
  frame.hd.stream_id = 0;
  nghttp2_session_on_window_update_received(session, &frame);

  /* Sends another 32KiB data */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(32*1024 == ud.data_source_length);

  stream = nghttp2_session_get_stream(session, 1);
  /* Change initial window size to 16KiB. The window_size becomes
     negative. */
  new_initial_window_size = 16*1024;
  stream->window_size = new_initial_window_size-
    (session->remote_settings[NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE]
     -stream->window_size);
  session->remote_settings[NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE] =
    new_initial_window_size;
  CU_ASSERT(-48*1024 == stream->window_size);

  /* Back 48KiB to stream window */
  frame.hd.stream_id = 1;
  frame.window_update.window_size_increment = 48*1024;
  nghttp2_session_on_window_update_received(session, &frame);

  /* Nothing is sent because window_size is 0 */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(32*1024 == ud.data_source_length);

  /* Back 16KiB in stream window */
  frame.hd.stream_id = 1;
  frame.window_update.window_size_increment = 16*1024;
  nghttp2_session_on_window_update_received(session, &frame);


  /* Back 24KiB in connection-level window */
  frame.hd.stream_id = 0;
  frame.window_update.window_size_increment = 24*1024;
  nghttp2_session_on_window_update_received(session, &frame);

  /* Sends another 16KiB data */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(16*1024 == ud.data_source_length);

  /* Increase initial window size to 32KiB */
  iv[0].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[0].value = 32*1024;

  nghttp2_frame_settings_init(&settings_frame.settings, dup_iv(iv, 1), 1);
  nghttp2_session_on_settings_received(session, &settings_frame);
  nghttp2_frame_settings_free(&settings_frame.settings);

  /* Sends another 8KiB data */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(8*1024 == ud.data_source_length);

  /* Back 8KiB in connection-level window */
  frame.hd.stream_id = 0;
  frame.window_update.window_size_increment = 8*1024;
  nghttp2_session_on_window_update_received(session, &frame);

  /* Sends last 8KiB data */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == ud.data_source_length);
  CU_ASSERT(nghttp2_session_get_stream(session, 1)->shut_flags &
            NGHTTP2_SHUT_WR);

  nghttp2_frame_window_update_free(&frame.window_update);
  nghttp2_session_del(session);
}

void test_nghttp2_session_data_read_temporal_failure(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { NULL };
  my_user_data ud;
  nghttp2_data_provider data_prd;
  nghttp2_frame frame;
  nghttp2_data *data_frame;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.data_source_length = 128*1024;

  /* Initial window size is 64KiB */
  nghttp2_session_client_new(&session, &callbacks, &ud);
  nghttp2_submit_request(session, 3, nv, &data_prd, NULL);

  /* Sends 64KiB data */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(64*1024 == ud.data_source_length);

  stream = nghttp2_session_get_stream(session, 1);
  CU_ASSERT(NULL != stream->deferred_data);
  CU_ASSERT(NGHTTP2_CAT_DATA == stream->deferred_data->frame_cat);
  data_frame = (nghttp2_data*)stream->deferred_data->frame;
  data_frame->data_prd.read_callback =
    temporal_failure_data_source_read_callback;

  /* Back 64KiB to both connection-level and stream-wise window */
  nghttp2_frame_window_update_init(&frame.window_update, NGHTTP2_FLAG_NONE,
                                   1, 64*1024);
  nghttp2_session_on_window_update_received(session, &frame);
  frame.hd.stream_id = 0;
  nghttp2_session_on_window_update_received(session, &frame);
  nghttp2_frame_window_update_free(&frame.window_update);

  /* Sending data will fail (soft fail) and treated as stream error */
  ud.frame_send_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(64*1024 == ud.data_source_length);

  CU_ASSERT(1 == ud.frame_send_cb_called);
  CU_ASSERT(NGHTTP2_RST_STREAM == ud.sent_frame_type);

  data_prd.read_callback = fail_data_source_read_callback;
  nghttp2_submit_request(session, 3, nv, &data_prd, NULL);
  /* Sending data will fail (hard fail) and session tear down */
  CU_ASSERT(NGHTTP2_ERR_CALLBACK_FAILURE == nghttp2_session_send(session));

  nghttp2_session_del(session);
}

void test_nghttp2_session_on_request_recv_callback(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  const char *nv[] = { NULL };
  nghttp2_frame frame;
  nghttp2_stream *stream;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_request_recv_callback = on_request_recv_callback;
  user_data.stream_id = 0;

  nghttp2_session_server_new(&session, &callbacks, &user_data);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS,
                             1, NGHTTP2_PRI_DEFAULT, dup_nv(nv));
  CU_ASSERT(0 == nghttp2_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(0 == user_data.stream_id);

  frame.hd.stream_id = 3;
  frame.hd.flags |= NGHTTP2_FLAG_END_STREAM;

  CU_ASSERT(0 == nghttp2_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(3 == user_data.stream_id);

  nghttp2_frame_headers_free(&frame.headers);

  user_data.stream_id = 0;

  stream = nghttp2_session_open_stream(session, 5, NGHTTP2_FLAG_NONE,
                              NGHTTP2_PRI_DEFAULT,
                              NGHTTP2_STREAM_OPENING, NULL);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS,
                             5, NGHTTP2_PRI_DEFAULT, dup_nv(nv));

  CU_ASSERT(0 == nghttp2_session_on_headers_received(session, &frame, stream));
  CU_ASSERT(0 == user_data.stream_id);

  frame.headers.hd.flags |= NGHTTP2_FLAG_END_STREAM;

  CU_ASSERT(0 == nghttp2_session_on_headers_received(session, &frame, stream));
  CU_ASSERT(5 == user_data.stream_id);

  nghttp2_frame_headers_free(&frame.headers);
  nghttp2_session_del(session);
}

void test_nghttp2_session_on_stream_close(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_stream_close_callback = stream_close_callback;
  user_data.stream_close_cb_called = 0;

  nghttp2_session_client_new(&session, &callbacks, &user_data);
  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_OPENED, &user_data);
  CU_ASSERT(stream != NULL);
  CU_ASSERT(nghttp2_session_close_stream(session, 1, NGHTTP2_NO_ERROR) == 0);
  CU_ASSERT(user_data.stream_close_cb_called == 1);
  nghttp2_session_del(session);
}

void test_nghttp2_session_on_ctrl_not_send(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_stream *stream;
  const char *nv[] = { NULL };

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_not_send_callback = on_frame_not_send_callback;
  callbacks.send_callback = null_send_callback;
  user_data.frame_not_send_cb_called = 0;
  user_data.not_sent_frame_type = 0;
  user_data.not_sent_error = 0;

  nghttp2_session_server_new(&session, &callbacks, &user_data);
  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_OPENING, &user_data);

  /* Check SYN_REPLY */
  /* Send bogus stream ID */
  CU_ASSERT(0 ==
            nghttp2_submit_headers(session, NGHTTP2_FLAG_END_STREAM, 3,
                                   NGHTTP2_PRI_DEFAULT, nv, NULL));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == user_data.frame_not_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == user_data.not_sent_frame_type);
  CU_ASSERT(NGHTTP2_ERR_STREAM_CLOSED == user_data.not_sent_error);

  user_data.frame_not_send_cb_called = 0;
  /* Shutdown transmission */
  stream->shut_flags |= NGHTTP2_SHUT_WR;
  CU_ASSERT(0 ==
            nghttp2_submit_headers(session, NGHTTP2_FLAG_END_STREAM, 1,
                                   NGHTTP2_PRI_DEFAULT, nv, NULL));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == user_data.frame_not_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == user_data.not_sent_frame_type);
  CU_ASSERT(NGHTTP2_ERR_STREAM_SHUT_WR == user_data.not_sent_error);

  stream->shut_flags = NGHTTP2_SHUT_NONE;
  user_data.frame_not_send_cb_called = 0;
  /* Queue RST_STREAM */
  CU_ASSERT(0 ==
            nghttp2_submit_headers(session, NGHTTP2_FLAG_END_STREAM, 1,
                                   NGHTTP2_PRI_DEFAULT, nv, NULL));
  CU_ASSERT(0 == nghttp2_submit_rst_stream(session, 1, NGHTTP2_INTERNAL_ERROR));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == user_data.frame_not_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == user_data.not_sent_frame_type);
  CU_ASSERT(NGHTTP2_ERR_STREAM_CLOSING == user_data.not_sent_error);

  stream = nghttp2_session_open_stream(session, 3, NGHTTP2_FLAG_NONE,
                                       NGHTTP2_PRI_DEFAULT,
                                       NGHTTP2_STREAM_OPENED, &user_data);

  /* Check HEADERS */
  user_data.frame_not_send_cb_called = 0;
  /* Queue RST_STREAM */
  CU_ASSERT(0 ==
            nghttp2_submit_headers(session, NGHTTP2_FLAG_END_STREAM, 3,
                                   NGHTTP2_PRI_DEFAULT, nv, NULL));
  CU_ASSERT(0 == nghttp2_submit_rst_stream(session, 3, NGHTTP2_INTERNAL_ERROR));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == user_data.frame_not_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == user_data.not_sent_frame_type);
  CU_ASSERT(NGHTTP2_ERR_STREAM_CLOSING == user_data.not_sent_error);

  nghttp2_session_del(session);

  /* Check SYN_STREAM */
  user_data.frame_not_send_cb_called = 0;
  CU_ASSERT(nghttp2_session_client_new(&session, &callbacks, &user_data) == 0);
  /* Maximum Stream ID is reached */
  session->next_stream_id = (1u << 31)+1;
  CU_ASSERT(0 == nghttp2_submit_headers(session, NGHTTP2_FLAG_END_STREAM, -1,
                                        NGHTTP2_PRI_DEFAULT, nv, NULL));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == user_data.frame_not_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == user_data.not_sent_frame_type);
  CU_ASSERT(NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE == user_data.not_sent_error);

  session->next_stream_id = 1;
  user_data.frame_not_send_cb_called = 0;
  /* Send GOAWAY */
  CU_ASSERT(0 == nghttp2_submit_goaway(session, NGHTTP2_NO_ERROR, NULL, 0));
  CU_ASSERT(0 == nghttp2_submit_headers(session, NGHTTP2_FLAG_END_STREAM, -1,
                                        NGHTTP2_PRI_DEFAULT, nv, NULL));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == user_data.frame_not_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == user_data.not_sent_frame_type);
  CU_ASSERT(NGHTTP2_ERR_START_STREAM_NOT_ALLOWED == user_data.not_sent_error);

  nghttp2_session_del(session);
}

void test_nghttp2_session_get_outbound_queue_size(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, NULL));
  CU_ASSERT(0 == nghttp2_session_get_outbound_queue_size(session));

  CU_ASSERT(0 == nghttp2_submit_ping(session, NULL));
  CU_ASSERT(1 == nghttp2_session_get_outbound_queue_size(session));

  CU_ASSERT(0 == nghttp2_submit_goaway(session, NGHTTP2_NO_ERROR, NULL, 0));
  CU_ASSERT(2 == nghttp2_session_get_outbound_queue_size(session));

  nghttp2_session_del(session);
}

void test_nghttp2_session_set_option(void)
{
  nghttp2_session* session;
  nghttp2_session_callbacks callbacks;
  int intval;
  char charval;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  nghttp2_session_client_new(&session, &callbacks, NULL);

  intval = 1;
  CU_ASSERT(0 ==
            nghttp2_session_set_option(session,
                                       NGHTTP2_OPT_NO_AUTO_WINDOW_UPDATE,
                                       &intval, sizeof(intval)));
  CU_ASSERT(session->opt_flags & NGHTTP2_OPTMASK_NO_AUTO_WINDOW_UPDATE);

  intval = 0;
  CU_ASSERT(0 ==
            nghttp2_session_set_option(session,
                                       NGHTTP2_OPT_NO_AUTO_WINDOW_UPDATE,
                                       &intval, sizeof(intval)));
  CU_ASSERT((session->opt_flags & NGHTTP2_OPTMASK_NO_AUTO_WINDOW_UPDATE) == 0);

  CU_ASSERT(NGHTTP2_ERR_INVALID_ARGUMENT ==
            nghttp2_session_set_option(session, 0, /* 0 is invalid optname */
                                       &intval, sizeof(intval)));

  charval = 1;
  CU_ASSERT(NGHTTP2_ERR_INVALID_ARGUMENT ==
            nghttp2_session_set_option(session,
                                       NGHTTP2_OPT_NO_AUTO_WINDOW_UPDATE,
                                       &charval, sizeof(charval)));

  nghttp2_session_del(session);
}

void test_nghttp2_session_data_backoff_by_high_pri_frame(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char *nv[] = { NULL };
  my_user_data ud;
  nghttp2_data_provider data_prd;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = block_count_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.frame_send_cb_called = 0;
  ud.data_source_length = 16*1024;

  nghttp2_session_client_new(&session, &callbacks, &ud);
  nghttp2_submit_request(session, NGHTTP2_PRI_DEFAULT, nv, &data_prd, NULL);

  ud.block_count = 2;
  /* Sends SYN_STREAM + DATA[0] */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NGHTTP2_HEADERS == ud.sent_frame_type);
  /* data for DATA[1] is read from data_prd but it is not sent */
  CU_ASSERT(ud.data_source_length == 8*1024);

  nghttp2_submit_ping(session, NULL);
  ud.block_count = 2;
  /* Sends DATA[1] + PING, PING is interleaved in DATA sequence */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NGHTTP2_PING == ud.sent_frame_type);
  /* data for DATA[2] is read from data_prd but it is not sent */
  CU_ASSERT(ud.data_source_length == 4*1024);

  ud.block_count = 2;
  /* Sends DATA[2..3] */
  CU_ASSERT(0 == nghttp2_session_send(session));

  stream = nghttp2_session_get_stream(session, 1);
  CU_ASSERT(stream->shut_flags & NGHTTP2_SHUT_WR);

  nghttp2_session_del(session);
}
