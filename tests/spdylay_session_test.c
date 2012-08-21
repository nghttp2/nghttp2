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
#include "spdylay_session_test.h"

#include <CUnit/CUnit.h>

#include <stdio.h>
#include <assert.h>

#include "spdylay_session.h"
#include "spdylay_stream.h"
#include "spdylay_net.h"
#include "spdylay_helper.h"
#include "spdylay_test_helper.h"

#define OB_CTRL(ITEM) spdylay_outbound_item_get_ctrl_frame(ITEM)
#define OB_CTRL_TYPE(ITEM) spdylay_outbound_item_get_ctrl_frame_type(ITEM)
#define OB_DATA(ITEM) spdylay_outbound_item_get_data_frame(ITEM)

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
  int ctrl_recv_cb_called, invalid_ctrl_recv_cb_called;
  int ctrl_send_cb_called;
  spdylay_frame_type sent_frame_type;
  int ctrl_not_send_cb_called;
  spdylay_frame_type not_sent_frame_type;
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

static ssize_t null_send_callback(spdylay_session *session,
                                  const uint8_t* data, size_t len, int flags,
                                  void *user_data)
{
  return len;
}

static ssize_t fail_send_callback(spdylay_session *session,
                                  const uint8_t *data, size_t len, int flags,
                                  void *user_data)
{
  return SPDYLAY_ERR_CALLBACK_FAILURE;
}

static ssize_t scripted_recv_callback(spdylay_session *session,
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

static ssize_t eof_recv_callback(spdylay_session *session,
                                      uint8_t* data, size_t len, int flags,
                                      void *user_data)
{
  return SPDYLAY_ERR_EOF;
}

static ssize_t accumulator_send_callback(spdylay_session *session,
                                         const uint8_t *buf, size_t len,
                                         int flags, void* user_data)
{
  accumulator *acc = ((my_user_data*)user_data)->acc;
  assert(acc->length+len < sizeof(acc->buf));
  memcpy(acc->buf+acc->length, buf, len);
  acc->length += len;
  return len;
}

static void on_ctrl_recv_callback(spdylay_session *session,
                                  spdylay_frame_type type,
                                  spdylay_frame *frame,
                                  void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->ctrl_recv_cb_called;
}

static void on_invalid_ctrl_recv_callback(spdylay_session *session,
                                          spdylay_frame_type type,
                                          spdylay_frame *frame,
                                          uint32_t status_code,
                                          void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->invalid_ctrl_recv_cb_called;
}

static void on_ctrl_send_callback(spdylay_session *session,
                                  spdylay_frame_type type,
                                  spdylay_frame *frame,
                                  void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->ctrl_send_cb_called;
  ud->sent_frame_type = type;
}

static void on_ctrl_not_send_callback(spdylay_session *session,
                                      spdylay_frame_type type,
                                      spdylay_frame *frame,
                                      int error,
                                      void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->ctrl_not_send_cb_called;
  ud->not_sent_frame_type = type;
  ud->not_sent_error = error;
}

static void on_data_chunk_recv_callback(spdylay_session *session,
                                        uint8_t flags, int32_t stream_id,
                                        const uint8_t *data, size_t len,
                                        void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->data_chunk_recv_cb_called;
}

static void on_data_recv_callback(spdylay_session *session,
                                  uint8_t flags, int32_t stream_id,
                                  int32_t length, void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->data_recv_cb_called;
}

static ssize_t fixed_length_data_source_read_callback
(spdylay_session *session, int32_t stream_id,
 uint8_t *buf, size_t len, int *eof,
 spdylay_data_source *source, void *user_data)
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
(spdylay_session *session, int32_t stream_id,
 uint8_t *buf, size_t len, int *eof,
 spdylay_data_source *source, void *user_data)
{
  return SPDYLAY_ERR_TEMPORAL_CALLBACK_FAILURE;
}

static ssize_t fail_data_source_read_callback
(spdylay_session *session, int32_t stream_id,
 uint8_t *buf, size_t len, int *eof,
 spdylay_data_source *source, void *user_data)
{
  return SPDYLAY_ERR_CALLBACK_FAILURE;
}

static void on_request_recv_callback(spdylay_session *session,
                                     int32_t stream_id,
                                     void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ud->stream_id = stream_id;
}

static void no_stream_user_data_stream_close_callback
(spdylay_session *session,
 int32_t stream_id,
 spdylay_status_code status_code,
 void *user_data)
{
  my_user_data* my_data = (my_user_data*)user_data;
  ++my_data->stream_close_cb_called;
}

static char** dup_nv(const char **src)
{
  return spdylay_frame_nv_copy(src);
}

static spdylay_settings_entry* dup_iv(const spdylay_settings_entry *iv,
                                      size_t niv)
{
  return spdylay_frame_iv_copy(iv, niv);
}

static const char *empty_name_nv[] = { "Version", "HTTP/1.1",
                                       "", "empty name",
                                       NULL };

static const char *null_val_nv[] = { "Version", "HTTP/1.1",
                                     "Foo", NULL,
                                     NULL };

void test_spdylay_session_recv(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  scripted_data_feed df;
  my_user_data user_data;
  const char *nv[] = {
    "url", "/", NULL
  };
  const char *upcase_nv[] = {
    "URL", "/", NULL
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
  spdylay_frame frame;
  int i;
  spdylay_outbound_item *item;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.recv_callback = scripted_recv_callback;
  callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback;
  user_data.df = &df;
  spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks,
                             &user_data);
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_PROTO_SPDY2,
                                SPDYLAY_CTRL_FLAG_NONE,
                                1, 0, 3, dup_nv(nv));
  framelen = spdylay_frame_pack_syn_stream(&framedata, &framedatalen,
                                           &nvbuf, &nvbuflen,
                                           &frame.syn_stream,
                                           &session->hd_deflater);
  scripted_data_feed_init(&df, framedata, framelen);
  /* Send 1 byte per each read */
  for(i = 0; i < framelen; ++i) {
    df.feedseq[i] = 1;
  }
  spdylay_frame_syn_stream_free(&frame.syn_stream);

  user_data.ctrl_recv_cb_called = 0;
  while((ssize_t)df.seqidx < framelen) {
    CU_ASSERT(0 == spdylay_session_recv(session));
  }
  CU_ASSERT(1 == user_data.ctrl_recv_cb_called);

  /* Receive SYN_STREAM with invalid header block */
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_PROTO_SPDY2,
                                SPDYLAY_CTRL_FLAG_NONE,
                                3, 0, 3, dup_nv(upcase_nv));
  framelen = spdylay_frame_pack_syn_stream(&framedata, &framedatalen,
                                           &nvbuf, &nvbuflen,
                                           &frame.syn_stream,
                                           &session->hd_deflater);
  spdylay_frame_syn_stream_free(&frame.syn_stream);
  scripted_data_feed_init(&df, framedata, framelen);
  user_data.ctrl_recv_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_recv(session));
  CU_ASSERT(0 == user_data.ctrl_recv_cb_called);
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(SPDYLAY_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(SPDYLAY_PROTOCOL_ERROR == OB_CTRL(item)->rst_stream.status_code);
  CU_ASSERT(0 == spdylay_session_send(session));

  /* Received SYN_STREAM without name/value header block */
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_PROTO_SPDY2,
                                SPDYLAY_CTRL_FLAG_NONE,
                                5, 0, 3, dup_nv(upcase_nv));
  framelen = spdylay_frame_pack_syn_stream(&framedata, &framedatalen,
                                           &nvbuf, &nvbuflen,
                                           &frame.syn_stream,
                                           &session->hd_deflater);
  spdylay_frame_syn_stream_free(&frame.syn_stream);
  /* Use bytes that come before name/value header block */
  spdylay_put_uint32be(&framedata[4],
                       SPDYLAY_SYN_STREAM_NV_OFFSET - SPDYLAY_HEAD_LEN);
  scripted_data_feed_init(&df, framedata, SPDYLAY_SYN_STREAM_NV_OFFSET);
  user_data.ctrl_recv_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_recv(session));
  CU_ASSERT(0 == user_data.ctrl_recv_cb_called);
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(SPDYLAY_GOAWAY == OB_CTRL_TYPE(item));

  spdylay_session_del(session);

  /* Some tests for frame too large */
  spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY3, &callbacks,
                             &user_data);
  /* made max buffer small to cause error intentionally */
  /* Inflated wire format of mid_nv will be 111 in SPDY/3. So payload
     length will be 121. Setting max buffer size to 110 will cause
     error while inflating name/value header block. */
  session->max_recv_ctrl_frame_buf = 110;

  /* Receive SYN_STREAM with too large payload */
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_PROTO_SPDY3,
                                SPDYLAY_CTRL_FLAG_NONE,
                                1, 0, 3, dup_nv(mid_nv));
  framelen = spdylay_frame_pack_syn_stream(&framedata, &framedatalen,
                                           &nvbuf, &nvbuflen,
                                           &frame.syn_stream,
                                           &session->hd_deflater);
  spdylay_frame_syn_stream_free(&frame.syn_stream);
  scripted_data_feed_init(&df, framedata, framelen);
  user_data.ctrl_recv_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_recv(session));
  CU_ASSERT(0 == user_data.ctrl_recv_cb_called);
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(SPDYLAY_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(SPDYLAY_FRAME_TOO_LARGE == OB_CTRL(item)->rst_stream.status_code);
  CU_ASSERT(1 == OB_CTRL(item)->rst_stream.stream_id);
  CU_ASSERT(0 == spdylay_session_send(session));

  /* For SYN_REPLY and SYN_HEADERS, make max buffer even smaller */
  session->max_recv_ctrl_frame_buf = 8;

  /* Receive SYN_REPLY with too large payload */
  spdylay_frame_syn_reply_init(&frame.syn_reply, SPDYLAY_PROTO_SPDY3,
                               SPDYLAY_CTRL_FLAG_NONE,
                               1, dup_nv(mid_nv));
  framelen = spdylay_frame_pack_syn_reply(&framedata, &framedatalen,
                                          &nvbuf, &nvbuflen,
                                          &frame.syn_reply,
                                          &session->hd_deflater);
  spdylay_frame_syn_reply_free(&frame.syn_reply);
  scripted_data_feed_init(&df, framedata, framelen);
  user_data.ctrl_recv_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_recv(session));
  CU_ASSERT(0 == user_data.ctrl_recv_cb_called);
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(SPDYLAY_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(SPDYLAY_FRAME_TOO_LARGE == OB_CTRL(item)->rst_stream.status_code);
  CU_ASSERT(1 == OB_CTRL(item)->rst_stream.stream_id);
  CU_ASSERT(0 == spdylay_session_send(session));

  /* Receive HEADERS with too large payload */
  spdylay_frame_headers_init(&frame.headers, SPDYLAY_PROTO_SPDY3,
                             SPDYLAY_CTRL_FLAG_NONE,
                             1, dup_nv(mid_nv));
  framelen = spdylay_frame_pack_headers(&framedata, &framedatalen,
                                        &nvbuf, &nvbuflen,
                                        &frame.headers,
                                        &session->hd_deflater);
  spdylay_frame_headers_free(&frame.headers);
  scripted_data_feed_init(&df, framedata, framelen);
  user_data.ctrl_recv_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_recv(session));
  CU_ASSERT(0 == user_data.ctrl_recv_cb_called);
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(SPDYLAY_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(SPDYLAY_FRAME_TOO_LARGE == OB_CTRL(item)->rst_stream.status_code);
  CU_ASSERT(1 == OB_CTRL(item)->rst_stream.stream_id);
  CU_ASSERT(0 == spdylay_session_send(session));

  /* Receive PING with too large payload */
  spdylay_frame_ping_init(&frame.ping, SPDYLAY_PROTO_SPDY3, 1);
  spdylay_reserve_buffer(&framedata, &framedatalen, 77);
  framelen = spdylay_frame_pack_ping(&framedata, &framedatalen, &frame.ping);
  spdylay_frame_ping_free(&frame.ping);
  spdylay_put_uint32be(&framedata[4], framedatalen - SPDYLAY_HEAD_LEN);
  scripted_data_feed_init(&df, framedata, framedatalen);
  user_data.ctrl_recv_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_recv(session));
  CU_ASSERT(0 == user_data.ctrl_recv_cb_called);
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(SPDYLAY_GOAWAY == OB_CTRL_TYPE(item));
  CU_ASSERT(SPDYLAY_GOAWAY_PROTOCOL_ERROR ==
            OB_CTRL(item)->rst_stream.status_code);
  CU_ASSERT(0 == spdylay_session_send(session));

  spdylay_session_del(session);

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks,
                             &user_data);
  /* Receive SYN_REPLY with invalid header block */
  spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE, 3,
                              SPDYLAY_STREAM_OPENING, NULL);
  spdylay_frame_syn_reply_init(&frame.syn_reply, SPDYLAY_PROTO_SPDY2,
                               SPDYLAY_CTRL_FLAG_NONE, 1, dup_nv(upcase_nv));
  framelen = spdylay_frame_pack_syn_reply(&framedata, &framedatalen,
                                          &nvbuf, &nvbuflen,
                                          &frame.syn_reply,
                                          &session->hd_deflater);
  spdylay_frame_syn_reply_free(&frame.syn_reply);
  scripted_data_feed_init(&df, framedata, framelen);
  user_data.ctrl_recv_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_recv(session));
  CU_ASSERT(0 == user_data.ctrl_recv_cb_called);
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(SPDYLAY_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(SPDYLAY_PROTOCOL_ERROR == OB_CTRL(item)->rst_stream.status_code);

  CU_ASSERT(0 == spdylay_session_send(session));

  /* Receive HEADERS with invalid header block */
  spdylay_session_open_stream(session, 3, SPDYLAY_CTRL_FLAG_NONE, 3,
                              SPDYLAY_STREAM_OPENED, NULL);
  spdylay_frame_headers_init(&frame.headers, SPDYLAY_PROTO_SPDY2,
                             SPDYLAY_CTRL_FLAG_NONE, 3, dup_nv(upcase_nv));
  framelen = spdylay_frame_pack_headers(&framedata, &framedatalen,
                                        &nvbuf, &nvbuflen,
                                        &frame.headers,
                                        &session->hd_deflater);
  spdylay_frame_headers_free(&frame.headers);
  scripted_data_feed_init(&df, framedata, framelen);
  user_data.ctrl_recv_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_recv(session));
  CU_ASSERT(0 == user_data.ctrl_recv_cb_called);
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(SPDYLAY_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(SPDYLAY_PROTOCOL_ERROR == OB_CTRL(item)->rst_stream.status_code);

  free(framedata);
  free(nvbuf);
  spdylay_session_del(session);
}

void test_spdylay_session_add_frame(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  accumulator acc;
  my_user_data user_data;
  const char *nv[] = {
    "method", "GET",
    "scheme", "https",
    "url", "/",
    "version", "HTTP/1.1",
    NULL
  };
  spdylay_frame *frame;
  spdylay_syn_stream_aux_data *aux_data =
    malloc(sizeof(spdylay_syn_stream_aux_data));
  const uint8_t hd_ans1[] = {
    0x80, 0x02, 0x00, 0x01
  };
  uint32_t temp32;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;
  memset(aux_data, 0, sizeof(spdylay_syn_stream_aux_data));
  acc.length = 0;
  user_data.acc = &acc;
  CU_ASSERT(0 == spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2,
                                            &callbacks, &user_data));

  frame = malloc(sizeof(spdylay_frame));
  spdylay_frame_syn_stream_init(&frame->syn_stream, SPDYLAY_PROTO_SPDY2,
                                SPDYLAY_CTRL_FLAG_NONE, 0, 0, 3, dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_add_frame(session, SPDYLAY_CTRL, frame,
                                           aux_data));
  CU_ASSERT(0 == spdylay_pq_empty(&session->ob_ss_pq));
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(memcmp(hd_ans1, acc.buf, 4) == 0);
  /* check stream id */
  memcpy(&temp32, &acc.buf[8], 4);
  temp32 = ntohl(temp32);
  CU_ASSERT(1 == temp32);
  /* check assoc stream id */
  memcpy(&temp32, &acc.buf[12], 4);
  temp32 = ntohl(temp32);
  CU_ASSERT(0 == temp32);
  /* check pri */
  temp32 = (acc.buf[16] >> 6) & 0x3;
  CU_ASSERT(3 == temp32);

  spdylay_session_del(session);
}

void test_spdylay_session_recv_invalid_stream_id(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  scripted_data_feed df;
  my_user_data user_data;
  const char *nv[] = { NULL };
  uint8_t *framedata = NULL, *nvbuf = NULL;
  size_t framedatalen = 0, nvbuflen = 0;
  ssize_t framelen;
  spdylay_frame frame;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.recv_callback = scripted_recv_callback;
  callbacks.on_invalid_ctrl_recv_callback = on_invalid_ctrl_recv_callback;

  user_data.df = &df;
  user_data.invalid_ctrl_recv_cb_called = 0;
  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks,
                             &user_data);
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_PROTO_SPDY2,
                                SPDYLAY_CTRL_FLAG_NONE, 1, 0, 3, dup_nv(nv));
  framelen = spdylay_frame_pack_syn_stream(&framedata, &framedatalen,
                                           &nvbuf, &nvbuflen,
                                           &frame.syn_stream,
                                           &session->hd_deflater);
  scripted_data_feed_init(&df, framedata, framelen);
  spdylay_frame_syn_stream_free(&frame.syn_stream);

  CU_ASSERT(0 == spdylay_session_recv(session));
  CU_ASSERT(1 == user_data.invalid_ctrl_recv_cb_called);

  spdylay_frame_syn_reply_init(&frame.syn_reply, SPDYLAY_PROTO_SPDY2,
                               SPDYLAY_CTRL_FLAG_NONE, 100, dup_nv(nv));
  framelen = spdylay_frame_pack_syn_reply(&framedata, &framedatalen,
                                          &nvbuf, &nvbuflen,
                                          &frame.syn_reply,
                                          &session->hd_deflater);
  scripted_data_feed_init(&df, framedata, framelen);
  spdylay_frame_syn_reply_free(&frame.syn_reply);

  CU_ASSERT(0 == spdylay_session_recv(session));
  CU_ASSERT(2 == user_data.invalid_ctrl_recv_cb_called);

  free(framedata);
  free(nvbuf);
  spdylay_session_del(session);
}

void test_spdylay_session_on_syn_stream_received(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  const char *nv[] = { NULL };
  spdylay_frame frame;
  spdylay_stream *stream;
  int32_t stream_id = 1;
  uint8_t pri = 3;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback;
  callbacks.on_invalid_ctrl_recv_callback = on_invalid_ctrl_recv_callback;
  user_data.ctrl_recv_cb_called = 0;
  user_data.invalid_ctrl_recv_cb_called = 0;

  spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks,
                             &user_data);
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_PROTO_SPDY2,
                                SPDYLAY_CTRL_FLAG_NONE,
                                stream_id, 0, pri, dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.ctrl_recv_cb_called);
  stream = spdylay_session_get_stream(session, stream_id);
  CU_ASSERT(SPDYLAY_STREAM_OPENING == stream->state);
  CU_ASSERT(pri == stream->pri);

  /* Same stream ID twice leads stream error */
  user_data.invalid_ctrl_recv_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid_ctrl_recv_cb_called);
  CU_ASSERT(SPDYLAY_STREAM_CLOSING == stream->state);

  /* assoc_stream_id != 0 from client is invalid. */
  frame.syn_stream.stream_id = 3;
  frame.syn_stream.assoc_stream_id = 1;
  user_data.invalid_ctrl_recv_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid_ctrl_recv_cb_called);

  spdylay_frame_syn_stream_free(&frame.syn_stream);


  /* More than max concurrent streams leads REFUSED_STREAM */
  session->local_settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS] = 1;
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_PROTO_SPDY2,
                                SPDYLAY_CTRL_FLAG_NONE,
                                5, 0, 3, dup_nv(nv));
  user_data.invalid_ctrl_recv_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid_ctrl_recv_cb_called);

  spdylay_frame_syn_stream_free(&frame.syn_stream);
  session->local_settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS] =
    SPDYLAY_INITIAL_MAX_CONCURRENT_STREAMS;

  /* Stream ID less than previouly received SYN_STREAM leads session
     error */
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_PROTO_SPDY2,
                                SPDYLAY_CTRL_FLAG_NONE,
                                1, 0, 3, dup_nv(nv));
  user_data.invalid_ctrl_recv_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid_ctrl_recv_cb_called);
  CU_ASSERT(session->goaway_flags & SPDYLAY_GOAWAY_FAIL_ON_SEND);

  spdylay_frame_syn_stream_free(&frame.syn_stream);

  spdylay_session_del(session);
}

void test_spdylay_session_on_syn_stream_received_with_push(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  const char *nv[] = { NULL };
  spdylay_frame frame;
  spdylay_stream *stream;
  int32_t stream_id = 2;
  int32_t assoc_stream_id = 1;
  uint8_t pri = 3;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback;
  callbacks.on_invalid_ctrl_recv_callback = on_invalid_ctrl_recv_callback;
  user_data.ctrl_recv_cb_called = 0;
  user_data.invalid_ctrl_recv_cb_called = 0;

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks,
                             &user_data);
  spdylay_session_open_stream(session, assoc_stream_id, SPDYLAY_CTRL_FLAG_NONE,
                              pri, SPDYLAY_STREAM_OPENED, NULL);
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_PROTO_SPDY2,
                                SPDYLAY_CTRL_FLAG_UNIDIRECTIONAL,
                                stream_id, assoc_stream_id, pri, dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.ctrl_recv_cb_called);
  stream = spdylay_session_get_stream(session, stream_id);
  CU_ASSERT(SPDYLAY_STREAM_OPENING == stream->state);

  /* assoc_stream_id == 0 is invalid */
  frame.syn_stream.stream_id = 4;
  frame.syn_stream.assoc_stream_id = 0;
  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid_ctrl_recv_cb_called);

  /* Push without SPDYLAY_CTRL_FLAG_UNIDIRECTIONAL is invalid */
  frame.syn_stream.stream_id = 6;
  frame.syn_stream.assoc_stream_id = 1;
  frame.syn_stream.hd.flags = SPDYLAY_CTRL_FLAG_FIN;
  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(2 == user_data.invalid_ctrl_recv_cb_called);

  /* Push to non-existent stream is invalid */
  frame.syn_stream.stream_id = 8;
  frame.syn_stream.assoc_stream_id = 3;
  frame.syn_stream.hd.flags = SPDYLAY_CTRL_FLAG_UNIDIRECTIONAL;
  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(3 == user_data.invalid_ctrl_recv_cb_called);

  spdylay_frame_syn_stream_free(&frame.syn_stream);
  spdylay_session_del(session);
}

void test_spdylay_session_on_syn_reply_received(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  const char *nv[] = { NULL };
  spdylay_frame frame;
  spdylay_stream *stream;
  spdylay_outbound_item *item;
  user_data.ctrl_recv_cb_called = 0;
  user_data.invalid_ctrl_recv_cb_called = 0;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback;
  callbacks.on_invalid_ctrl_recv_callback = on_invalid_ctrl_recv_callback;
  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks,
                             &user_data);
  spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE, 0,
                              SPDYLAY_STREAM_OPENING, NULL);
  spdylay_frame_syn_reply_init(&frame.syn_reply, SPDYLAY_PROTO_SPDY2,
                               SPDYLAY_CTRL_FLAG_NONE, 1, dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_on_syn_reply_received(session, &frame));
  CU_ASSERT(1 == user_data.ctrl_recv_cb_called);
  CU_ASSERT(SPDYLAY_STREAM_OPENED ==
            ((spdylay_stream*)spdylay_map_find(&session->streams, 1))->state);

  CU_ASSERT(0 == spdylay_session_on_syn_reply_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid_ctrl_recv_cb_called);
  CU_ASSERT(SPDYLAY_STREAM_CLOSING ==
            ((spdylay_stream*)spdylay_map_find(&session->streams, 1))->state);

  /* Check the situation when SYN_REPLY is received after peer sends
     FIN */
  stream = spdylay_session_open_stream(session, 3, SPDYLAY_CTRL_FLAG_NONE, 0,
                                       SPDYLAY_STREAM_OPENED, NULL);
  spdylay_stream_shutdown(stream, SPDYLAY_SHUT_RD);
  frame.syn_reply.stream_id = 3;

  CU_ASSERT(0 == spdylay_session_on_syn_reply_received(session, &frame));
  CU_ASSERT(2 == user_data.invalid_ctrl_recv_cb_called);

  spdylay_frame_syn_reply_free(&frame.syn_reply);

  spdylay_session_del(session);

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY3, &callbacks,
                             &user_data);

  /* Multiple SYN_REPLY frames for the same active stream ID */
  spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE, 0,
                              SPDYLAY_STREAM_OPENED, NULL);
  spdylay_frame_syn_reply_init(&frame.syn_reply, SPDYLAY_PROTO_SPDY3,
                               SPDYLAY_CTRL_FLAG_NONE, 1, dup_nv(nv));
  user_data.invalid_ctrl_recv_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_on_syn_reply_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid_ctrl_recv_cb_called);
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(SPDYLAY_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(SPDYLAY_STREAM_IN_USE == OB_CTRL(item)->rst_stream.status_code);

  spdylay_frame_syn_reply_free(&frame.syn_reply);

  spdylay_session_del(session);
}

void test_spdylay_session_send_syn_stream(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { NULL };
  spdylay_frame *frame = malloc(sizeof(spdylay_frame));
  spdylay_stream *stream;
  spdylay_syn_stream_aux_data *aux_data =
    malloc(sizeof(spdylay_syn_stream_aux_data));
  memset(aux_data, 0, sizeof(spdylay_syn_stream_aux_data));
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks, NULL);
  spdylay_frame_syn_stream_init(&frame->syn_stream, SPDYLAY_PROTO_SPDY2,
                                SPDYLAY_CTRL_FLAG_NONE, 0, 0, 3, dup_nv(nv));
  spdylay_session_add_frame(session, SPDYLAY_CTRL, frame, aux_data);
  CU_ASSERT(0 == spdylay_session_send(session));
  stream = spdylay_session_get_stream(session, 1);
  CU_ASSERT(SPDYLAY_STREAM_OPENING == stream->state);

  spdylay_session_del(session);
}

void test_spdylay_session_send_syn_reply(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { NULL };
  spdylay_frame *frame = malloc(sizeof(spdylay_frame));
  spdylay_stream *stream;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;

  CU_ASSERT(0 == spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2,
                                            &callbacks, NULL));
  spdylay_session_open_stream(session, 2, SPDYLAY_CTRL_FLAG_NONE, 3,
                              SPDYLAY_STREAM_OPENING, NULL);
  spdylay_frame_syn_reply_init(&frame->syn_reply, SPDYLAY_PROTO_SPDY2,
                               SPDYLAY_CTRL_FLAG_NONE, 2, dup_nv(nv));
  spdylay_session_add_frame(session, SPDYLAY_CTRL, frame, NULL);
  CU_ASSERT(0 == spdylay_session_send(session));
  stream = spdylay_session_get_stream(session, 2);
  CU_ASSERT(SPDYLAY_STREAM_OPENED == stream->state);

  spdylay_session_del(session);
}

void test_spdylay_submit_response(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { "Content-Length", "1024", NULL };
  int32_t stream_id = 2;
  spdylay_data_provider data_prd;
  my_user_data ud;
  spdylay_outbound_item *item;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 64*1024;
  CU_ASSERT(0 == spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2,
                                            &callbacks, &ud));
  spdylay_session_open_stream(session, stream_id, SPDYLAY_CTRL_FLAG_NONE, 3,
                              SPDYLAY_STREAM_OPENING, NULL);
  CU_ASSERT(0 == spdylay_submit_response(session, stream_id, nv, &data_prd));
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp("content-length", OB_CTRL(item)->syn_reply.nv[0]));
  CU_ASSERT(0 == spdylay_session_send(session));
  spdylay_session_del(session);
}

void test_spdylay_submit_response_with_null_data_read_callback(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  accumulator acc;
  const char *nv[] = { ":Version", "HTTP/1.1", NULL };
  spdylay_data_provider data_prd = {{-1}, NULL};
  spdylay_outbound_item *item;
  my_user_data ud;
  spdylay_frame frame;

  acc.length = 0;
  ud.acc = &acc;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = accumulator_send_callback;
  CU_ASSERT(0 == spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2,
                                            &callbacks, &ud));
  spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_FIN, 3,
                              SPDYLAY_STREAM_OPENING, NULL);
  CU_ASSERT(0 == spdylay_submit_response(session, 1, nv, &data_prd));
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp(":version", OB_CTRL(item)->syn_reply.nv[0]));
  CU_ASSERT(OB_CTRL(item)->syn_reply.hd.flags & SPDYLAY_CTRL_FLAG_FIN);

  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(0 == unpack_frame_with_nv_block(SPDYLAY_SYN_REPLY,
                                            SPDYLAY_PROTO_SPDY2,
                                            &frame,
                                            &session->hd_inflater,
                                            acc.buf, acc.length));
  CU_ASSERT(0 == strcmp("version", frame.syn_reply.nv[0]));
  spdylay_frame_syn_reply_free(&frame.syn_reply);

  spdylay_session_del(session);
}

void test_spdylay_submit_request_with_data(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { "Version", "HTTP/1.1", NULL };
  spdylay_data_provider data_prd;
  my_user_data ud;
  spdylay_outbound_item *item;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 64*1024;
  CU_ASSERT(0 == spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2,
                                            &callbacks, &ud));
  CU_ASSERT(0 == spdylay_submit_request(session, 3, nv, &data_prd, NULL));
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp("version", OB_CTRL(item)->syn_stream.nv[0]));
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(0 == ud.data_source_length);

  spdylay_session_del(session);
}

void test_spdylay_submit_request_with_null_data_read_callback(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  accumulator acc;
  const char *nv[] = { ":Version", "HTTP/1.1", NULL };
  spdylay_data_provider data_prd = {{-1}, NULL};
  spdylay_outbound_item *item;
  my_user_data ud;
  spdylay_frame frame;

  acc.length = 0;
  ud.acc = &acc;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;
  CU_ASSERT(0 == spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2,
                                            &callbacks, &ud));
  CU_ASSERT(0 == spdylay_submit_request(session, 3, nv, &data_prd, NULL));
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp(":version", OB_CTRL(item)->syn_stream.nv[0]));
  CU_ASSERT(OB_CTRL(item)->syn_stream.hd.flags & SPDYLAY_CTRL_FLAG_FIN);

  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(0 == unpack_frame_with_nv_block(SPDYLAY_SYN_STREAM,
                                            SPDYLAY_PROTO_SPDY2,
                                            &frame,
                                            &session->hd_inflater,
                                            acc.buf, acc.length));
  CU_ASSERT(0 == strcmp("version", frame.syn_stream.nv[0]));
  spdylay_frame_syn_stream_free(&frame.syn_stream);

  spdylay_session_del(session);
}

void test_spdylay_submit_syn_stream(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { "version", "HTTP/1.1", NULL };
  spdylay_outbound_item *item;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  CU_ASSERT(0 == spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2,
                                            &callbacks, NULL));
  CU_ASSERT(0 == spdylay_submit_syn_stream(session, SPDYLAY_CTRL_FLAG_FIN, 1, 3,
                                           nv, NULL));
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp("version", OB_CTRL(item)->syn_stream.nv[0]));
  CU_ASSERT(SPDYLAY_CTRL_FLAG_FIN == OB_CTRL(item)->syn_stream.hd.flags);
  /* See assoc-stream-ID is ignored */
  CU_ASSERT(0 == OB_CTRL(item)->syn_stream.assoc_stream_id);
  CU_ASSERT(3 == OB_CTRL(item)->syn_stream.pri);

  spdylay_session_del(session);

  CU_ASSERT(0 == spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2,
                                            &callbacks, NULL));
  CU_ASSERT(0 == spdylay_submit_syn_stream(session, SPDYLAY_CTRL_FLAG_FIN, 1, 3,
                                           nv, NULL));
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp("version", OB_CTRL(item)->syn_stream.nv[0]));
  CU_ASSERT(SPDYLAY_CTRL_FLAG_FIN == OB_CTRL(item)->syn_stream.hd.flags);
  CU_ASSERT(1 == OB_CTRL(item)->syn_stream.assoc_stream_id);
  CU_ASSERT(3 == OB_CTRL(item)->syn_stream.pri);

  /* Invalid assoc-stream-ID */
  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_submit_syn_stream(session, SPDYLAY_CTRL_FLAG_FIN, 2, 3,
                                      nv, NULL));

  spdylay_session_del(session);
}

void test_spdylay_submit_syn_reply(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { "version", "HTTP/1.1", NULL };
  my_user_data ud;
  spdylay_outbound_item *item;
  spdylay_stream *stream;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_ctrl_send_callback = on_ctrl_send_callback;

  CU_ASSERT(0 == spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2,
                                            &callbacks, &ud));
  CU_ASSERT(0 == spdylay_submit_syn_reply(session, SPDYLAY_CTRL_FLAG_FIN, 1,
                                          nv));
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp("version", OB_CTRL(item)->syn_reply.nv[0]));
  CU_ASSERT(SPDYLAY_CTRL_FLAG_FIN == OB_CTRL(item)->syn_reply.hd.flags);

  ud.ctrl_send_cb_called = 0;
  ud.sent_frame_type = 0;
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(0 == ud.ctrl_send_cb_called);

  stream = spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE, 3,
                                       SPDYLAY_STREAM_OPENING, NULL);

  CU_ASSERT(0 == spdylay_submit_syn_reply(session, SPDYLAY_CTRL_FLAG_FIN, 1,
                                          nv));
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(1 == ud.ctrl_send_cb_called);
  CU_ASSERT(SPDYLAY_SYN_REPLY == ud.sent_frame_type);
  CU_ASSERT(stream->shut_flags & SPDYLAY_SHUT_WR);

  spdylay_session_del(session);
}

void test_spdylay_submit_headers(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { ":Version", "HTTP/1.1", NULL };
  my_user_data ud;
  spdylay_outbound_item *item;
  spdylay_stream *stream;
  accumulator acc;
  spdylay_frame frame;

  acc.length = 0;
  ud.acc = &acc;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;
  callbacks.on_ctrl_send_callback = on_ctrl_send_callback;

  CU_ASSERT(0 == spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2,
                                            &callbacks, &ud));
  CU_ASSERT(0 == spdylay_submit_headers(session, SPDYLAY_CTRL_FLAG_FIN, 1, nv));
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(0 == strcmp(":version", OB_CTRL(item)->headers.nv[0]));
  CU_ASSERT(SPDYLAY_CTRL_FLAG_FIN == OB_CTRL(item)->headers.hd.flags);

  ud.ctrl_send_cb_called = 0;
  ud.sent_frame_type = 0;
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(0 == ud.ctrl_send_cb_called);

  stream = spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE, 3,
                                       SPDYLAY_STREAM_OPENING, NULL);

  CU_ASSERT(0 == spdylay_submit_headers(session, SPDYLAY_CTRL_FLAG_FIN, 1, nv));
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(1 == ud.ctrl_send_cb_called);
  CU_ASSERT(SPDYLAY_HEADERS == ud.sent_frame_type);
  CU_ASSERT(stream->shut_flags & SPDYLAY_SHUT_WR);

  CU_ASSERT(0 == unpack_frame_with_nv_block(SPDYLAY_HEADERS,
                                            SPDYLAY_PROTO_SPDY2,
                                            &frame,
                                            &session->hd_inflater,
                                            acc.buf, acc.length));
  CU_ASSERT(0 == strcmp("version", frame.headers.nv[0]));
  spdylay_frame_headers_free(&frame.headers);

  spdylay_session_del(session);
}

void test_spdylay_submit_invalid_nv(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));

  CU_ASSERT(0 == spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY3,
                                            &callbacks, NULL));

  /* spdylay_submit_request */
  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_submit_request(session, 3, empty_name_nv, NULL, NULL));

  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_submit_request(session, 3, null_val_nv, NULL, NULL));

  /* spdylay_submit_response */
  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_submit_response(session, 2, empty_name_nv, NULL));

  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_submit_response(session, 2, null_val_nv, NULL));

  /* spdylay_submit_syn_stream */
  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_submit_syn_stream(session, SPDYLAY_CTRL_FLAG_NONE, 0,
                                      0, empty_name_nv, NULL));

  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_submit_syn_stream(session, SPDYLAY_CTRL_FLAG_NONE, 0,
                                      0, null_val_nv, NULL));

  /* spdylay_submit_syn_reply */
  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_submit_syn_reply(session, SPDYLAY_CTRL_FLAG_NONE, 2,
                                     empty_name_nv));

  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_submit_syn_reply(session, SPDYLAY_CTRL_FLAG_NONE, 2,
                                     null_val_nv));

  /* spdylay_submit_headers */
  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_submit_headers(session, SPDYLAY_CTRL_FLAG_NONE, 2,
                                   empty_name_nv));

  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_submit_headers(session, SPDYLAY_CTRL_FLAG_NONE, 2,
                                   null_val_nv));

  spdylay_session_del(session);
}

void test_spdylay_session_reply_fail(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { NULL };
  int32_t stream_id = 2;
  spdylay_data_provider data_prd;
  my_user_data ud;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = fail_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 4*1024;
  CU_ASSERT(0 == spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2,
                                            &callbacks, &ud));
  CU_ASSERT(0 == spdylay_submit_response(session, stream_id, nv, &data_prd));
  CU_ASSERT(0 == spdylay_session_send(session));
  spdylay_session_del(session);
}

void test_spdylay_session_on_headers_received(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  const char *nv[] = { NULL };
  spdylay_frame frame;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback;
  callbacks.on_invalid_ctrl_recv_callback = on_invalid_ctrl_recv_callback;
  user_data.ctrl_recv_cb_called = 0;
  user_data.invalid_ctrl_recv_cb_called = 0;

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks,
                             &user_data);
  spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE, 0,
                              SPDYLAY_STREAM_OPENED, NULL);
  spdylay_stream_shutdown(spdylay_session_get_stream(session, 1),
                          SPDYLAY_SHUT_WR);
  spdylay_frame_headers_init(&frame.headers, SPDYLAY_PROTO_SPDY2,
                             SPDYLAY_CTRL_FLAG_NONE, 1, dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(1 == user_data.ctrl_recv_cb_called);
  CU_ASSERT(SPDYLAY_STREAM_OPENED ==
            spdylay_session_get_stream(session, 1)->state);

  frame.headers.hd.flags |= SPDYLAY_CTRL_FLAG_FIN;

  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(2 == user_data.ctrl_recv_cb_called);
  CU_ASSERT(NULL == spdylay_session_get_stream(session, 1));

  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid_ctrl_recv_cb_called);

  /* Check to see when SPDYLAY_STREAM_CLOSING, incoming HEADERS is
     discarded. */
  spdylay_session_open_stream(session, 3, SPDYLAY_CTRL_FLAG_NONE, 0,
                              SPDYLAY_STREAM_CLOSING, NULL);
  frame.headers.stream_id = 3;
  frame.headers.hd.flags = SPDYLAY_CTRL_FLAG_NONE;
  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(2 == user_data.ctrl_recv_cb_called);
  CU_ASSERT(1 == user_data.invalid_ctrl_recv_cb_called);

  /* Server initiated stream */
  spdylay_session_open_stream(session, 2, SPDYLAY_CTRL_FLAG_NONE, 0,
                              SPDYLAY_STREAM_OPENING, NULL);

  frame.headers.hd.flags = SPDYLAY_CTRL_FLAG_FIN;
  frame.headers.stream_id = 2;

  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(3 == user_data.ctrl_recv_cb_called);
  CU_ASSERT(SPDYLAY_STREAM_OPENING ==
            spdylay_session_get_stream(session, 2)->state);
  CU_ASSERT(spdylay_session_get_stream(session, 2)->shut_flags &
            SPDYLAY_SHUT_RD);

  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(2 == user_data.invalid_ctrl_recv_cb_called);

  spdylay_frame_headers_free(&frame.headers);

  spdylay_session_del(session);
}

void test_spdylay_session_on_window_update_received(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  spdylay_frame frame;
  spdylay_stream *stream;
  spdylay_outbound_item *data_item;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback;
  callbacks.on_invalid_ctrl_recv_callback = on_invalid_ctrl_recv_callback;
  user_data.ctrl_recv_cb_called = 0;
  user_data.invalid_ctrl_recv_cb_called = 0;

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY3, &callbacks,
                             &user_data);
  stream = spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE, 0,
                                       SPDYLAY_STREAM_OPENED, NULL);
  spdylay_frame_window_update_init(&frame.window_update, SPDYLAY_PROTO_SPDY3,
                                   1, 16*1024);

  CU_ASSERT(0 == spdylay_session_on_window_update_received(session, &frame));
  CU_ASSERT(1 == user_data.ctrl_recv_cb_called);
  CU_ASSERT(64*1024+16*1024 == stream->window_size);

  data_item = malloc(sizeof(spdylay_outbound_item));
  memset(data_item, 0, sizeof(spdylay_outbound_item));
  data_item->frame_cat = SPDYLAY_DATA;
  spdylay_stream_defer_data(stream, data_item, SPDYLAY_DEFERRED_FLOW_CONTROL);

  CU_ASSERT(0 == spdylay_session_on_window_update_received(session, &frame));
  CU_ASSERT(2 == user_data.ctrl_recv_cb_called);
  CU_ASSERT(64*1024+16*1024*2 == stream->window_size);
  CU_ASSERT(NULL == stream->deferred_data);

  spdylay_frame_window_update_free(&frame.window_update);
  spdylay_session_del(session);
}

void test_spdylay_session_on_ping_received(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  spdylay_frame frame;
  spdylay_outbound_item *top;
  uint32_t unique_id;
  user_data.ctrl_recv_cb_called = 0;
  user_data.invalid_ctrl_recv_cb_called = 0;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback;
  callbacks.on_invalid_ctrl_recv_callback = on_invalid_ctrl_recv_callback;

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks,
                             &user_data);
  unique_id = 2;
  spdylay_frame_ping_init(&frame.ping, SPDYLAY_PROTO_SPDY2, unique_id);

  CU_ASSERT(0 == spdylay_session_on_ping_received(session, &frame));
  CU_ASSERT(1 == user_data.ctrl_recv_cb_called);
  top = spdylay_session_get_ob_pq_top(session);
  CU_ASSERT(SPDYLAY_PING == OB_CTRL_TYPE(top));
  CU_ASSERT(unique_id == OB_CTRL(top)->ping.unique_id);

  session->last_ping_unique_id = 1;
  frame.ping.unique_id = 1;

  CU_ASSERT(0 == spdylay_session_on_ping_received(session, &frame));
  CU_ASSERT(2 == user_data.ctrl_recv_cb_called);

  spdylay_frame_ping_free(&frame.ping);
  spdylay_session_del(session);
}

void test_spdylay_session_on_goaway_received(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  spdylay_frame frame;
  int32_t stream_id = 1000000007;
  user_data.ctrl_recv_cb_called = 0;
  user_data.invalid_ctrl_recv_cb_called = 0;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback;
  callbacks.on_invalid_ctrl_recv_callback = on_invalid_ctrl_recv_callback;

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks,
                             &user_data);
  spdylay_frame_goaway_init(&frame.goaway, SPDYLAY_PROTO_SPDY2, stream_id,
                            SPDYLAY_GOAWAY_OK);

  CU_ASSERT(0 == spdylay_session_on_goaway_received(session, &frame));
  CU_ASSERT(1 == user_data.ctrl_recv_cb_called);
  CU_ASSERT(session->goaway_flags == SPDYLAY_GOAWAY_RECV);

  spdylay_frame_goaway_free(&frame.goaway);
  spdylay_session_del(session);
}

void test_spdylay_session_on_data_received(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  spdylay_outbound_item *top;
  int32_t stream_id = 2;
  spdylay_stream *stream;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks,
                             &user_data);
  stream = spdylay_session_open_stream(session, stream_id,
                                       SPDYLAY_CTRL_FLAG_NONE,
                                       3, SPDYLAY_STREAM_OPENING, NULL);
  CU_ASSERT(0 == spdylay_session_on_data_received(session,
                                                  SPDYLAY_DATA_FLAG_NONE,
                                                  4096, stream_id));
  CU_ASSERT(0 == stream->shut_flags);

  CU_ASSERT(0 == spdylay_session_on_data_received(session,
                                                  SPDYLAY_DATA_FLAG_FIN,
                                                  4096, stream_id));
  CU_ASSERT(SPDYLAY_SHUT_RD == stream->shut_flags);

  /* If SPDYLAY_STREAM_CLOSING state, DATA frame is discarded. */
  stream_id = 4;

  spdylay_session_open_stream(session, stream_id, SPDYLAY_CTRL_FLAG_NONE,
                              3, SPDYLAY_STREAM_CLOSING, NULL);
  CU_ASSERT(0 == spdylay_session_on_data_received(session,
                                                  SPDYLAY_DATA_FLAG_NONE,
                                                  4096, stream_id));
  CU_ASSERT(NULL == spdylay_session_get_ob_pq_top(session));

  /* Check INVALID_STREAM case: DATA frame with stream ID which does
     not exist. */
  stream_id = 6;

  CU_ASSERT(0 == spdylay_session_on_data_received(session,
                                                  SPDYLAY_DATA_FLAG_NONE,
                                                  4096, stream_id));
  top = spdylay_session_get_ob_pq_top(session);
  CU_ASSERT(SPDYLAY_RST_STREAM == OB_CTRL_TYPE(top));
  CU_ASSERT(SPDYLAY_INVALID_STREAM == OB_CTRL(top)->rst_stream.status_code);

  spdylay_session_del(session);
}

void test_spdylay_session_is_my_stream_id(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks, NULL);

  CU_ASSERT(0 == spdylay_session_is_my_stream_id(session, 0));
  CU_ASSERT(0 == spdylay_session_is_my_stream_id(session, 1));
  CU_ASSERT(1 == spdylay_session_is_my_stream_id(session, 2));

  spdylay_session_del(session);

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks, NULL);

  CU_ASSERT(0 == spdylay_session_is_my_stream_id(session, 0));
  CU_ASSERT(1 == spdylay_session_is_my_stream_id(session, 1));
  CU_ASSERT(0 == spdylay_session_is_my_stream_id(session, 2));

  spdylay_session_del(session);
}

void test_spdylay_session_on_rst_received(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  spdylay_stream *stream;
  spdylay_frame frame;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks,
                             &user_data);
  stream = spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE,
                                       3, SPDYLAY_STREAM_OPENING, NULL);
  /* server push */
  spdylay_session_open_stream(session, 2, SPDYLAY_CTRL_FLAG_NONE,
                              3, SPDYLAY_STREAM_OPENING, NULL);
  spdylay_stream_add_pushed_stream(stream, 2);
  spdylay_session_open_stream(session, 4, SPDYLAY_CTRL_FLAG_NONE,
                              3, SPDYLAY_STREAM_OPENING, NULL);
  spdylay_stream_add_pushed_stream(stream, 4);

  spdylay_frame_rst_stream_init(&frame.rst_stream, SPDYLAY_PROTO_SPDY2, 1,
                                SPDYLAY_CANCEL);

  CU_ASSERT(0 == spdylay_session_on_rst_stream_received(session, &frame));

  CU_ASSERT(NULL == spdylay_session_get_stream(session, 1));
  CU_ASSERT(NULL == spdylay_session_get_stream(session, 2));
  CU_ASSERT(NULL == spdylay_session_get_stream(session, 4));

  spdylay_frame_rst_stream_free(&frame.rst_stream);
  spdylay_session_del(session);
}

void test_spdylay_session_send_rst_stream(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  spdylay_stream *stream;
  spdylay_frame *frame;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;
  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks,
                             &user_data);
  stream = spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE,
                                       3, SPDYLAY_STREAM_OPENING, NULL);
  /* server push */
  spdylay_session_open_stream(session, 2, SPDYLAY_CTRL_FLAG_NONE,
                              3, SPDYLAY_STREAM_OPENING, NULL);
  spdylay_stream_add_pushed_stream(stream, 2);
  spdylay_session_open_stream(session, 4, SPDYLAY_CTRL_FLAG_NONE,
                              3, SPDYLAY_STREAM_OPENING, NULL);
  spdylay_stream_add_pushed_stream(stream, 4);

  frame = malloc(sizeof(spdylay_frame));
  spdylay_frame_rst_stream_init(&frame->rst_stream, SPDYLAY_PROTO_SPDY2, 1,
                                SPDYLAY_CANCEL);
  spdylay_session_add_frame(session, SPDYLAY_CTRL, frame, NULL);
  CU_ASSERT(0 == spdylay_session_send(session));

  CU_ASSERT(NULL == spdylay_session_get_stream(session, 1));
  CU_ASSERT(NULL == spdylay_session_get_stream(session, 2));
  CU_ASSERT(NULL == spdylay_session_get_stream(session, 4));

  spdylay_session_del(session);
}

void test_spdylay_session_get_next_ob_item(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { NULL };
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;

  spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks, NULL);
  session->remote_settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS] = 2;

  CU_ASSERT(NULL == spdylay_session_get_next_ob_item(session));
  spdylay_submit_ping(session);
  CU_ASSERT(SPDYLAY_PING ==
            OB_CTRL_TYPE(spdylay_session_get_next_ob_item(session)));

  spdylay_submit_request(session, 0, nv, NULL, NULL);
  CU_ASSERT(SPDYLAY_PING ==
            OB_CTRL_TYPE(spdylay_session_get_next_ob_item(session)));

  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(NULL == spdylay_session_get_next_ob_item(session));

  /* Incoming stream does not affect the number of outgoing max
     concurrent streams. */
  spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE,
                              3, SPDYLAY_STREAM_OPENING, NULL);

  spdylay_submit_request(session, 0, nv, NULL, NULL);
  CU_ASSERT(SPDYLAY_SYN_STREAM ==
            OB_CTRL_TYPE(spdylay_session_get_next_ob_item(session)));
  CU_ASSERT(0 == spdylay_session_send(session));

  spdylay_submit_request(session, 0, nv, NULL, NULL);
  CU_ASSERT(NULL == spdylay_session_get_next_ob_item(session));

  session->remote_settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS] = 3;

  CU_ASSERT(SPDYLAY_SYN_STREAM ==
            OB_CTRL_TYPE(spdylay_session_get_next_ob_item(session)));

  spdylay_session_del(session);
}

void test_spdylay_session_pop_next_ob_item(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { NULL };
  spdylay_outbound_item *item;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;

  spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks, NULL);
  session->remote_settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS] = 1;

  CU_ASSERT(NULL == spdylay_session_pop_next_ob_item(session));
  spdylay_submit_ping(session);
  spdylay_submit_request(session, 1, nv, NULL, NULL);

  item = spdylay_session_pop_next_ob_item(session);
  CU_ASSERT(SPDYLAY_PING == OB_CTRL_TYPE(item));
  spdylay_outbound_item_free(item);
  free(item);

  item = spdylay_session_pop_next_ob_item(session);
  CU_ASSERT(SPDYLAY_SYN_STREAM == OB_CTRL_TYPE(item));
  spdylay_outbound_item_free(item);
  free(item);

  CU_ASSERT(NULL == spdylay_session_pop_next_ob_item(session));

  /* Incoming stream does not affect the number of outgoing max
     concurrent streams. */
  spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE,
                              3, SPDYLAY_STREAM_OPENING, NULL);

  /* In-flight outgoing stream */
  spdylay_session_open_stream(session, 4, SPDYLAY_CTRL_FLAG_NONE,
                              3, SPDYLAY_STREAM_OPENING, NULL);

  spdylay_submit_request(session, 0, nv, NULL, NULL);
  spdylay_submit_response(session, 1, nv, NULL);

  item = spdylay_session_pop_next_ob_item(session);
  CU_ASSERT(SPDYLAY_SYN_REPLY == OB_CTRL_TYPE(item));
  spdylay_outbound_item_free(item);
  free(item);

  CU_ASSERT(NULL == spdylay_session_pop_next_ob_item(session));

  session->remote_settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS] = 2;

  item = spdylay_session_pop_next_ob_item(session);
  CU_ASSERT(SPDYLAY_SYN_STREAM == OB_CTRL_TYPE(item));
  spdylay_outbound_item_free(item);
  free(item);

  spdylay_session_del(session);
}

void test_spdylay_session_on_request_recv_callback(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  const char *nv[] = { NULL };
  spdylay_frame frame;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.on_request_recv_callback = on_request_recv_callback;
  user_data.stream_id = 0;

  spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks,
                             &user_data);
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_PROTO_SPDY2,
                                SPDYLAY_CTRL_FLAG_NONE, 1, 0, 3, dup_nv(nv));
  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(0 == user_data.stream_id);

  frame.syn_stream.stream_id = 3;
  frame.syn_stream.hd.flags |= SPDYLAY_CTRL_FLAG_FIN;

  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(3 == user_data.stream_id);

  user_data.stream_id = 0;

  frame.syn_stream.stream_id = 0;

  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(0 == user_data.stream_id);

  spdylay_frame_syn_stream_free(&frame.syn_stream);

  user_data.stream_id = 0;

  spdylay_session_open_stream(session, 5, SPDYLAY_CTRL_FLAG_NONE, 0,
                              SPDYLAY_STREAM_OPENING, NULL);
  spdylay_frame_headers_init(&frame.headers, SPDYLAY_PROTO_SPDY2,
                             SPDYLAY_CTRL_FLAG_NONE, 5, dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(0 == user_data.stream_id);

  frame.headers.hd.flags |= SPDYLAY_CTRL_FLAG_FIN;

  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(5 == user_data.stream_id);

  user_data.stream_id = 0;

  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(0 == user_data.stream_id);

  spdylay_frame_headers_free(&frame.headers);
  spdylay_session_del(session);
}

static void stream_close_callback(spdylay_session *session, int32_t stream_id,
                                  spdylay_status_code status_code,
                                  void *user_data)
{
  my_user_data* my_data = (my_user_data*)user_data;
  void *stream_data = spdylay_session_get_stream_user_data(session, stream_id);
  ++my_data->stream_close_cb_called;
  CU_ASSERT(stream_data != NULL);
}

void test_spdylay_session_on_stream_close(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  spdylay_stream *stream;
  int32_t stream_id = 1;
  uint8_t pri = 3;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.on_stream_close_callback = stream_close_callback;
  user_data.stream_close_cb_called = 0;

  CU_ASSERT(spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2,
                                       &callbacks, &user_data) == 0);
  stream = spdylay_session_open_stream(session, stream_id,
                                       SPDYLAY_CTRL_FLAG_NONE,
                                       pri, SPDYLAY_STREAM_OPENED, &user_data);
  CU_ASSERT(stream != NULL);
  CU_ASSERT(spdylay_session_close_stream(session, stream_id, SPDYLAY_OK) == 0);
  CU_ASSERT(user_data.stream_close_cb_called == 1);
  spdylay_session_del(session);
}

void test_spdylay_session_max_concurrent_streams(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  spdylay_frame frame;
  const char *nv[] = { NULL };
  spdylay_outbound_item *item;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks, NULL);
  spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE, 3,
                              SPDYLAY_STREAM_OPENED, NULL);
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_PROTO_SPDY2,
                                SPDYLAY_CTRL_FLAG_NONE, 3, 0, 3, dup_nv(nv));
  session->local_settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS] = 1;

  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));

  item = spdylay_session_get_ob_pq_top(session);
  CU_ASSERT(SPDYLAY_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(SPDYLAY_REFUSED_STREAM == OB_CTRL(item)->rst_stream.status_code)

  spdylay_frame_syn_stream_free(&frame.syn_stream);

  spdylay_session_del(session);
}

static ssize_t block_count_send_callback(spdylay_session* session,
                                         const uint8_t *data, size_t len,
                                         int flags,
                                         void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  int r;
  if(ud->block_count == 0) {
    r = SPDYLAY_ERR_WOULDBLOCK;
  } else {
    --ud->block_count;
    r = len;
  }
  return r;
}

void test_spdylay_session_data_backoff_by_high_pri_frame(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { NULL };
  my_user_data ud;
  spdylay_data_provider data_prd;
  spdylay_stream *stream;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = block_count_send_callback;
  callbacks.on_ctrl_send_callback = on_ctrl_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.ctrl_send_cb_called = 0;
  ud.data_source_length = 16*1024;

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks, &ud);
  spdylay_submit_request(session, 3, nv, &data_prd, NULL);

  ud.block_count = 2;
  /* Sends SYN_STREAM + DATA[0] */
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(SPDYLAY_SYN_STREAM == ud.sent_frame_type);
  /* data for DATA[1] is read from data_prd but it is not sent */
  CU_ASSERT(ud.data_source_length == 8*1024);

  spdylay_submit_ping(session);
  ud.block_count = 2;
  /* Sends DATA[1] + PING, PING is interleaved in DATA sequence */
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(SPDYLAY_PING == ud.sent_frame_type);
  /* data for DATA[2] is read from data_prd but it is not sent */
  CU_ASSERT(ud.data_source_length == 4*1024);

  ud.block_count = 2;
  /* Sends DATA[2..3] */
  CU_ASSERT(0 == spdylay_session_send(session));

  stream = spdylay_session_get_stream(session, 1);
  CU_ASSERT(stream->shut_flags & SPDYLAY_SHUT_WR);

  spdylay_session_del(session);
}

void test_spdylay_session_stop_data_with_rst_stream(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { NULL };
  my_user_data ud;
  spdylay_data_provider data_prd;
  spdylay_frame frame;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.on_ctrl_send_callback = on_ctrl_send_callback;
  callbacks.send_callback = block_count_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.ctrl_send_cb_called = 0;
  ud.data_source_length = 16*1024;

  spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks, &ud);
  spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE, 3,
                              SPDYLAY_STREAM_OPENING, NULL);
  spdylay_submit_response(session, 1, nv, &data_prd);

  ud.block_count = 2;
  /* Sends SYN_REPLY + DATA[0] */
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(SPDYLAY_SYN_REPLY == ud.sent_frame_type);
  /* data for DATA[1] is read from data_prd but it is not sent */
  CU_ASSERT(ud.data_source_length == 8*1024);

  spdylay_frame_rst_stream_init(&frame.rst_stream, SPDYLAY_PROTO_SPDY2, 1,
                                SPDYLAY_CANCEL);
  CU_ASSERT(0 == spdylay_session_on_rst_stream_received(session, &frame));
  spdylay_frame_rst_stream_free(&frame.rst_stream);

  /* Big enough number to send all DATA frames potentially. */
  ud.block_count = 100;
  /* Nothing will be sent in the following call. */
  CU_ASSERT(0 == spdylay_session_send(session));
  /* With RST_STREAM, stream is canceled and further DATA on that
     stream are not sent. */
  CU_ASSERT(ud.data_source_length == 8*1024);

  CU_ASSERT(NULL == spdylay_session_get_stream(session, 1));

  spdylay_session_del(session);
}

/*
 * Check that on_stream_close_callback is called when server pushed
 * SYN_STREAM have SPDYLAY_CTRL_FLAG_FIN.
 */
void test_spdylay_session_stream_close_on_syn_stream(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { NULL };
  my_user_data ud;
  spdylay_frame frame;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.on_stream_close_callback =
    no_stream_user_data_stream_close_callback;
  ud.stream_close_cb_called = 0;

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks, &ud);
  spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE, 3,
                              SPDYLAY_STREAM_OPENING, NULL);
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_PROTO_SPDY2,
                                SPDYLAY_CTRL_FLAG_FIN |
                                SPDYLAY_CTRL_FLAG_UNIDIRECTIONAL,
                                2, 1, 3, dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));

  spdylay_frame_syn_stream_free(&frame.syn_stream);
  spdylay_session_del(session);
}

void test_spdylay_session_recv_invalid_frame(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  scripted_data_feed df;
  my_user_data user_data;
  const char *nv[] = {
    "url", "/", NULL
  };
  uint8_t *framedata = NULL, *nvbuf = NULL;
  size_t framedatalen = 0, nvbuflen = 0;
  ssize_t framelen;
  spdylay_frame frame;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.recv_callback = scripted_recv_callback;
  callbacks.send_callback = null_send_callback;
  callbacks.on_ctrl_send_callback = on_ctrl_send_callback;

  user_data.df = &df;
  user_data.ctrl_send_cb_called = 0;
  spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks,
                             &user_data);
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_PROTO_SPDY2,
                                SPDYLAY_CTRL_FLAG_NONE, 1, 0, 3, dup_nv(nv));
  framelen = spdylay_frame_pack_syn_stream(&framedata, &framedatalen,
                                           &nvbuf, &nvbuflen,
                                           &frame.syn_stream,
                                           &session->hd_deflater);
  scripted_data_feed_init(&df, framedata, framelen);

  CU_ASSERT(0 == spdylay_session_recv(session));
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(0 == user_data.ctrl_send_cb_called);

  /* Receive exactly same bytes of SYN_STREAM causes error */
  scripted_data_feed_init(&df, framedata, framelen);

  CU_ASSERT(0 == spdylay_session_recv(session));
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(1 == user_data.ctrl_send_cb_called);
  CU_ASSERT(SPDYLAY_GOAWAY == user_data.sent_frame_type);

  free(framedata);
  free(nvbuf);
  spdylay_frame_syn_stream_free(&frame.syn_stream);

  spdylay_session_del(session);
}

static ssize_t defer_data_source_read_callback
(spdylay_session *session, int32_t stream_id,
 uint8_t *buf, size_t len, int *eof,
 spdylay_data_source *source, void *user_data)
{
  return SPDYLAY_ERR_DEFERRED;
}

void test_spdylay_session_defer_data(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { NULL };
  my_user_data ud;
  spdylay_data_provider data_prd;
  spdylay_outbound_item *item;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.on_ctrl_send_callback = on_ctrl_send_callback;
  callbacks.send_callback = block_count_send_callback;
  data_prd.read_callback = defer_data_source_read_callback;

  ud.ctrl_send_cb_called = 0;
  ud.data_source_length = 16*1024;

  spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2, &callbacks, &ud);
  spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE, 3,
                              SPDYLAY_STREAM_OPENING, NULL);
  spdylay_submit_response(session, 1, nv, &data_prd);

  ud.block_count = 1;
  /* Sends SYN_REPLY */
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(SPDYLAY_SYN_REPLY == ud.sent_frame_type);
  /* No data is read */
  CU_ASSERT(ud.data_source_length == 16*1024);

  ud.block_count = 1;
  spdylay_submit_ping(session);
  /* Sends PING */
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(SPDYLAY_PING == ud.sent_frame_type);

  /* Resume deferred DATA */
  CU_ASSERT(0 == spdylay_session_resume_data(session, 1));
  item = spdylay_session_get_ob_pq_top(session);
  OB_DATA(item)->data_prd.read_callback =
    fixed_length_data_source_read_callback;
  ud.block_count = 1;
  /* Reads 2 4KiB blocks */
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(ud.data_source_length == 8*1024);

  /* Deferred again */
  OB_DATA(item)->data_prd.read_callback = defer_data_source_read_callback;
  /* This is needed since 4KiB block is already read and waiting to be
     sent. No read_callback invocation. */
  ud.block_count = 1;
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(ud.data_source_length == 8*1024);

  /* Resume deferred DATA */

  CU_ASSERT(0 == spdylay_session_resume_data(session, 1));
  item = spdylay_session_get_ob_pq_top(session);
  OB_DATA(item)->data_prd.read_callback =
    fixed_length_data_source_read_callback;
  ud.block_count = 1;
  /* Reads 2 4KiB blocks */
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(ud.data_source_length == 0);

  spdylay_session_del(session);
}

void test_spdylay_session_flow_control(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { NULL };
  my_user_data ud;
  spdylay_data_provider data_prd;
  spdylay_frame frame;
  spdylay_stream *stream;
  int32_t new_initial_window_size;
  spdylay_settings_entry iv[1];
  spdylay_frame settings_frame;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_ctrl_send_callback = on_ctrl_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.ctrl_send_cb_called = 0;
  ud.data_source_length = 128*1024;

  /* Initial window size is 64KiB */
  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY3, &callbacks, &ud);
  spdylay_submit_request(session, 3, nv, &data_prd, NULL);

  /* Sends 64KiB data */
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(64*1024 == ud.data_source_length);

  /* Back 32KiB */
  spdylay_frame_window_update_init(&frame.window_update, SPDYLAY_PROTO_SPDY3,
                                   1, 32*1024);
  spdylay_session_on_window_update_received(session, &frame);

  /* Sends another 32KiB data */
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(32*1024 == ud.data_source_length);

  stream = spdylay_session_get_stream(session, 1);
  /* Change initial window size to 16KiB. The window_size becomes
     negative. */
  new_initial_window_size = 16*1024;
  stream->window_size = new_initial_window_size-
    (session->remote_settings[SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE]
     -stream->window_size);
  session->remote_settings[SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE] =
    new_initial_window_size;
  CU_ASSERT(-48*1024 == stream->window_size);

  /* Back 48KiB */
  frame.window_update.delta_window_size = 48*1024;
  spdylay_session_on_window_update_received(session, &frame);

  /* Nothing is sent because window_size is less than 0 */
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(32*1024 == ud.data_source_length);

  /* Back 16KiB */
  frame.window_update.delta_window_size = 16*1024;
  spdylay_session_on_window_update_received(session, &frame);

  /* Sends another 16KiB data */
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(16*1024 == ud.data_source_length);

  /* Increase initial window size to 32KiB */
  iv[0].settings_id = SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[0].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;
  iv[0].value = 32*1024;

  spdylay_frame_settings_init(&settings_frame.settings, SPDYLAY_PROTO_SPDY3,
                              SPDYLAY_FLAG_SETTINGS_NONE, dup_iv(iv, 1), 1);
  spdylay_session_on_settings_received(session, &settings_frame);
  spdylay_frame_settings_free(&settings_frame.settings);

  /* Sends another 16KiB data */
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(0 == ud.data_source_length);
  CU_ASSERT(spdylay_session_get_stream(session, 1)->shut_flags &
            SPDYLAY_SHUT_WR);

  spdylay_frame_window_update_free(&frame.window_update);
  spdylay_session_del(session);
}

void test_spdylay_session_on_ctrl_not_send(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  spdylay_stream *stream;
  const char *nv[] = { NULL };

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.on_ctrl_not_send_callback = on_ctrl_not_send_callback;
  callbacks.send_callback = null_send_callback;
  user_data.ctrl_not_send_cb_called = 0;
  user_data.not_sent_frame_type = 0;
  user_data.not_sent_error = 0;

  CU_ASSERT(spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY2,
                                       &callbacks, &user_data) == 0);
  stream = spdylay_session_open_stream(session, 1,
                                       SPDYLAY_CTRL_FLAG_NONE,
                                       3, SPDYLAY_STREAM_OPENED, &user_data);
  /* Check SYN_STREAM */
  CU_ASSERT(0 == spdylay_submit_syn_stream(session, SPDYLAY_CTRL_FLAG_FIN, 3, 3,
                                           nv, NULL));

  user_data.ctrl_not_send_cb_called = 0;
  /* Associated stream closed */
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(1 == user_data.ctrl_not_send_cb_called);
  CU_ASSERT(SPDYLAY_SYN_STREAM == user_data.not_sent_frame_type);
  CU_ASSERT(SPDYLAY_ERR_STREAM_CLOSED == user_data.not_sent_error);

  /* Check SYN_REPLY */
  CU_ASSERT(0 ==
            spdylay_submit_syn_reply(session, SPDYLAY_CTRL_FLAG_FIN, 1, nv));
  user_data.ctrl_not_send_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(1 == user_data.ctrl_not_send_cb_called);
  CU_ASSERT(SPDYLAY_SYN_REPLY == user_data.not_sent_frame_type);
  CU_ASSERT(SPDYLAY_ERR_INVALID_STREAM_STATE == user_data.not_sent_error);

  stream->state = SPDYLAY_STREAM_OPENING;
  user_data.ctrl_not_send_cb_called = 0;
  /* Send bogus stream ID */
  CU_ASSERT(0 ==
            spdylay_submit_syn_reply(session, SPDYLAY_CTRL_FLAG_FIN, 3, nv));
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(1 == user_data.ctrl_not_send_cb_called);
  CU_ASSERT(SPDYLAY_SYN_REPLY == user_data.not_sent_frame_type);
  CU_ASSERT(SPDYLAY_ERR_STREAM_CLOSED == user_data.not_sent_error);

  user_data.ctrl_not_send_cb_called = 0;
  /* Shutdown transmission */
  stream->shut_flags |= SPDYLAY_SHUT_WR;
  CU_ASSERT(0 ==
            spdylay_submit_syn_reply(session, SPDYLAY_CTRL_FLAG_FIN, 1, nv));
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(1 == user_data.ctrl_not_send_cb_called);
  CU_ASSERT(SPDYLAY_SYN_REPLY == user_data.not_sent_frame_type);
  CU_ASSERT(SPDYLAY_ERR_STREAM_SHUT_WR == user_data.not_sent_error);

  stream->shut_flags = SPDYLAY_SHUT_NONE;
  user_data.ctrl_not_send_cb_called = 0;
  /* Queue RST_STREAM */
  CU_ASSERT(0 ==
            spdylay_submit_syn_reply(session, SPDYLAY_CTRL_FLAG_FIN, 1, nv));
  CU_ASSERT(0 == spdylay_submit_rst_stream(session, 1, SPDYLAY_INTERNAL_ERROR));
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(1 == user_data.ctrl_not_send_cb_called);
  CU_ASSERT(SPDYLAY_SYN_REPLY == user_data.not_sent_frame_type);
  CU_ASSERT(SPDYLAY_ERR_STREAM_CLOSING == user_data.not_sent_error);

  stream = spdylay_session_open_stream(session, 3,
                                       SPDYLAY_CTRL_FLAG_NONE,
                                       3, SPDYLAY_STREAM_OPENED, &user_data);

  /* Check HEADERS */
  user_data.ctrl_not_send_cb_called = 0;
  stream->state = SPDYLAY_STREAM_OPENING;
  CU_ASSERT(0 ==
            spdylay_submit_headers(session, SPDYLAY_CTRL_FLAG_FIN, 3, nv));
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(1 == user_data.ctrl_not_send_cb_called);
  CU_ASSERT(SPDYLAY_HEADERS == user_data.not_sent_frame_type);
  CU_ASSERT(SPDYLAY_ERR_INVALID_STREAM_STATE == user_data.not_sent_error);

  stream->state = SPDYLAY_STREAM_OPENED;
  user_data.ctrl_not_send_cb_called = 0;
  /* Queue RST_STREAM */
  CU_ASSERT(0 ==
            spdylay_submit_headers(session, SPDYLAY_CTRL_FLAG_FIN, 3, nv));
  CU_ASSERT(0 == spdylay_submit_rst_stream(session, 3, SPDYLAY_INTERNAL_ERROR));
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(1 == user_data.ctrl_not_send_cb_called);
  CU_ASSERT(SPDYLAY_HEADERS == user_data.not_sent_frame_type);
  CU_ASSERT(SPDYLAY_ERR_STREAM_CLOSING == user_data.not_sent_error);

  spdylay_session_del(session);

  /* Check SYN_STREAM */
  user_data.ctrl_not_send_cb_called = 0;
  CU_ASSERT(spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY2,
                                       &callbacks, &user_data) == 0);
  /* Maximum Stream ID is reached */
  session->next_stream_id = (1u << 31)+1;
  CU_ASSERT(0 == spdylay_submit_syn_stream(session, SPDYLAY_CTRL_FLAG_FIN, 0,
                                           3, nv, NULL));
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(1 == user_data.ctrl_not_send_cb_called);
  CU_ASSERT(SPDYLAY_SYN_STREAM == user_data.not_sent_frame_type);
  CU_ASSERT(SPDYLAY_ERR_STREAM_ID_NOT_AVAILABLE == user_data.not_sent_error);

  session->next_stream_id = 1;
  user_data.ctrl_not_send_cb_called = 0;
  /* Send GOAWAY */
  CU_ASSERT(0 == spdylay_submit_goaway(session, SPDYLAY_GOAWAY_OK));
  CU_ASSERT(0 == spdylay_submit_syn_stream(session, SPDYLAY_CTRL_FLAG_FIN, 0,
                                           3, nv, NULL));
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(1 == user_data.ctrl_not_send_cb_called);
  CU_ASSERT(SPDYLAY_SYN_STREAM == user_data.not_sent_frame_type);
  CU_ASSERT(SPDYLAY_ERR_SYN_STREAM_NOT_ALLOWED == user_data.not_sent_error);

  spdylay_session_del(session);
}

void test_spdylay_session_on_settings_received(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  spdylay_stream *stream1, *stream2;
  spdylay_frame frame;
  const size_t niv = 5;
  spdylay_settings_entry iv[255];

  iv[0].settings_id = SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = 1000000009;
  iv[0].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;

  iv[1].settings_id = SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[1].value = 50;
  iv[1].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;

  iv[2].settings_id = SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[2].value = 64*1024;
  iv[2].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;

  iv[3].settings_id = SPDYLAY_SETTINGS_CLIENT_CERTIFICATE_VECTOR_SIZE;
  iv[3].value = 512;
  iv[3].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;

  iv[4].settings_id = 999;
  iv[4].value = 0;
  iv[4].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY3, &callbacks,
                             &user_data);
  session->remote_settings[SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE] = 16*1024;

  stream1 = spdylay_session_open_stream(session, 1, SPDYLAY_CTRL_FLAG_NONE,
                                        3, SPDYLAY_STREAM_OPENING, NULL);
  stream2 = spdylay_session_open_stream(session, 2, SPDYLAY_CTRL_FLAG_NONE,
                                        3, SPDYLAY_STREAM_OPENING, NULL);
  stream1->window_size = 16*1024;
  stream2->window_size = -48*1024;

  spdylay_frame_settings_init(&frame.settings, SPDYLAY_PROTO_SPDY3,
                              SPDYLAY_FLAG_SETTINGS_NONE, dup_iv(iv, niv), niv);

  CU_ASSERT(0 == spdylay_session_on_settings_received(session, &frame));

  CU_ASSERT(1000000009 ==
            session->remote_settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS]);
  CU_ASSERT(64*1024 ==
            session->remote_settings[SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE]);
  /* We limit certificate vector in reasonable size. */
  CU_ASSERT(SPDYLAY_MAX_CLIENT_CERT_VECTOR_LENGTH ==
            session->remote_settings
            [SPDYLAY_SETTINGS_CLIENT_CERTIFICATE_VECTOR_SIZE]);
  CU_ASSERT(SPDYLAY_MAX_CLIENT_CERT_VECTOR_LENGTH == session->cli_certvec.size);
  CU_ASSERT(64*1024 == stream1->window_size);
  CU_ASSERT(0 == stream2->window_size);

  frame.settings.iv[2].value = 16*1024;

  CU_ASSERT(0 == spdylay_session_on_settings_received(session, &frame));

  CU_ASSERT(16*1024 == stream1->window_size);
  CU_ASSERT(-48*1024 == stream2->window_size);

  spdylay_frame_settings_free(&frame.settings);

  spdylay_session_del(session);
}

void test_spdylay_submit_settings(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data ud;
  spdylay_outbound_item *item;
  spdylay_frame *frame;
  spdylay_settings_entry iv[3];

  iv[0].settings_id = SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = 50;
  iv[0].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;

  iv[1].settings_id = SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 16*1024;
  iv[1].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;

  /* This is duplicate entry */
  iv[2].settings_id = SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[2].value = 150;
  iv[2].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_ctrl_send_callback = on_ctrl_send_callback;
  spdylay_session_server_new(&session, SPDYLAY_PROTO_SPDY3, &callbacks, &ud);

  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_submit_settings(session, SPDYLAY_FLAG_SETTINGS_NONE,
                                    iv, 3));

  /* Make sure that local settings are not changed */
  CU_ASSERT(SPDYLAY_INITIAL_MAX_CONCURRENT_STREAMS ==
            session->local_settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS]);
  CU_ASSERT(SPDYLAY_INITIAL_WINDOW_SIZE ==
            session->local_settings[SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE]);

  CU_ASSERT(0 == spdylay_submit_settings(session,
                                         SPDYLAY_FLAG_SETTINGS_CLEAR_SETTINGS,
                                         iv, 2));

  /* Make sure that local settings are changed */
  CU_ASSERT(50 ==
            session->local_settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS]);
  CU_ASSERT(16*1024 ==
            session->local_settings[SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE]);

  item = spdylay_session_get_next_ob_item(session);

  CU_ASSERT(SPDYLAY_SETTINGS == OB_CTRL_TYPE(item));

  frame = item->frame;
  CU_ASSERT(2 == frame->settings.niv);
  CU_ASSERT(SPDYLAY_FLAG_SETTINGS_CLEAR_SETTINGS == frame->settings.hd.flags);

  CU_ASSERT(50 == frame->settings.iv[0].value);
  CU_ASSERT(SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS ==
            frame->settings.iv[0].settings_id);
  CU_ASSERT(SPDYLAY_FLAG_SETTINGS_NONE ==
            frame->settings.iv[0].flags);

  CU_ASSERT(16*1024 == frame->settings.iv[1].value);
  CU_ASSERT(SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE ==
            frame->settings.iv[1].settings_id);
  CU_ASSERT(SPDYLAY_FLAG_SETTINGS_NONE ==
            frame->settings.iv[1].flags);

  ud.ctrl_send_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(1 == ud.ctrl_send_cb_called);

  spdylay_session_del(session);
}

void test_spdylay_session_get_outbound_queue_size(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { "version", "HTTP/1.1", NULL };

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  CU_ASSERT(0 == spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY3,
                                            &callbacks, NULL));
  CU_ASSERT(0 == spdylay_session_get_outbound_queue_size(session));

  CU_ASSERT(0 == spdylay_submit_syn_stream(session, SPDYLAY_CTRL_FLAG_FIN, 1, 7,
                                           nv, NULL));
  CU_ASSERT(1 == spdylay_session_get_outbound_queue_size(session));

  CU_ASSERT(0 == spdylay_submit_goaway(session, SPDYLAY_GOAWAY_OK));
  CU_ASSERT(2 == spdylay_session_get_outbound_queue_size(session));

  spdylay_session_del(session);
}

static ssize_t get_credential_ncerts(spdylay_session *session,
                                     const spdylay_origin *origin,
                                     void *user_data)
{
  if(strcmp("example.org", origin->host) == 0 &&
     strcmp("https", origin->scheme) == 0 &&
     443 == origin->port) {
    return 2;
  } else {
    return 0;
  }
}

static ssize_t get_credential_cert(spdylay_session *session,
                                   const spdylay_origin *origin,
                                   size_t idx,
                                   uint8_t *cert, size_t certlen,
                                   void *user_data)
{
  size_t len = strlen(origin->host);
  if(certlen == 0) {
    return len;
  } else {
    assert(certlen == len);
    memcpy(cert, origin->host, len);
    return 0;
  }
}

static ssize_t get_credential_proof(spdylay_session *session,
                                    const spdylay_origin *origin,
                                    uint8_t *proof, size_t prooflen,
                                    void *uer_data)
{
  size_t len = strlen(origin->scheme);
  if(prooflen == 0) {
    return len;
  } else {
    assert(prooflen == len);
    memcpy(proof, origin->scheme, len);
    return 0;
  }
}

void test_spdylay_session_prep_credential(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { ":host", "example.org",
                       ":scheme", "https",
                       NULL };
  const char *nv_nocert[] = { ":host", "nocert",
                              ":scheme", "https",
                              NULL };
  spdylay_frame frame, *cred_frame;
  spdylay_outbound_item *item;
  size_t i;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.get_credential_ncerts = get_credential_ncerts;
  callbacks.get_credential_cert = get_credential_cert;
  callbacks.get_credential_proof = get_credential_proof;
  CU_ASSERT(0 == spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY3,
                                            &callbacks, NULL));
  spdylay_frame_syn_stream_init(&frame.syn_stream, session->version,
                                SPDYLAY_CTRL_FLAG_NONE, 1, 0, 0,
                                dup_nv(nv));
  CU_ASSERT(SPDYLAY_ERR_CREDENTIAL_PENDING ==
            spdylay_session_prep_credential(session, &frame.syn_stream));
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(SPDYLAY_CREDENTIAL == OB_CTRL_TYPE(item));
  CU_ASSERT(SPDYLAY_OB_PRI_CREDENTIAL == item->pri);
  cred_frame = OB_CTRL(item);
  CU_ASSERT(strlen("https") == cred_frame->credential.proof.length);
  CU_ASSERT(memcmp("https", cred_frame->credential.proof.data,
                   cred_frame->credential.proof.length) == 0);
  CU_ASSERT(2 == cred_frame->credential.ncerts);
  for(i = 0; i < cred_frame->credential.ncerts; ++i) {
    CU_ASSERT(strlen("example.org") == cred_frame->credential.certs[i].length);
    CU_ASSERT(memcmp("example.org", cred_frame->credential.certs[i].data,
                     cred_frame->credential.certs[i].length) == 0);
  }
  /* Next spdylay_session_get_next_ob_item() call returns slot index */
  CU_ASSERT(1 ==  spdylay_session_prep_credential(session, &frame.syn_stream));

  spdylay_frame_syn_stream_free(&frame.syn_stream);

  spdylay_frame_syn_stream_init(&frame.syn_stream, session->version,
                                SPDYLAY_CTRL_FLAG_NONE, 1, 0, 0,
                                dup_nv(nv_nocert));
  CU_ASSERT(0 == spdylay_session_prep_credential(session, &frame.syn_stream));
  spdylay_frame_syn_stream_free(&frame.syn_stream);

  spdylay_session_del(session);
}

void test_spdylay_submit_syn_stream_with_credential(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { ":host", "example.org",
                       ":scheme", "https",
                       NULL };
  my_user_data ud;
  accumulator acc;

  ud.acc = &acc;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = block_count_send_callback;
  callbacks.on_ctrl_send_callback = on_ctrl_send_callback;
  callbacks.get_credential_ncerts = get_credential_ncerts;
  callbacks.get_credential_cert = get_credential_cert;
  callbacks.get_credential_proof = get_credential_proof;

  CU_ASSERT(0 == spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY3,
                                            &callbacks, &ud));

  CU_ASSERT(0 == spdylay_submit_request(session, 0, nv, NULL, NULL));

  ud.block_count = 1;
  ud.ctrl_send_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_send(session));

  CU_ASSERT(1 == ud.ctrl_send_cb_called);
  CU_ASSERT(SPDYLAY_CREDENTIAL == ud.sent_frame_type);

  session->callbacks.send_callback = accumulator_send_callback;
  acc.length = 0;
  ud.ctrl_send_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(1 == ud.ctrl_send_cb_called);
  CU_ASSERT(SPDYLAY_SYN_STREAM == ud.sent_frame_type);
  /* Check slot */
  CU_ASSERT(1 == acc.buf[17]);

  spdylay_session_del(session);
}

void test_spdylay_session_set_initial_client_cert_origin(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const spdylay_origin *origin;
  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY3, &callbacks, NULL);
  CU_ASSERT(0 == spdylay_session_set_initial_client_cert_origin
            (session, "https", "example.org", 443));
  origin = spdylay_session_get_client_cert_origin(session, 1);
  CU_ASSERT(NULL != origin);
  CU_ASSERT(strcmp("https", spdylay_origin_get_scheme(origin)) == 0);
  CU_ASSERT(strcmp("example.org", spdylay_origin_get_host(origin)) == 0);
  CU_ASSERT(443 == spdylay_origin_get_port(origin));

  spdylay_session_del(session);
}

void test_spdylay_session_set_option(void)
{
  spdylay_session* session;
  spdylay_session_callbacks callbacks;
  int intval;
  char charval;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY3, &callbacks, NULL);

  intval = 1;
  CU_ASSERT(0 ==
            spdylay_session_set_option(session,
                                       SPDYLAY_OPT_NO_AUTO_WINDOW_UPDATE,
                                       &intval, sizeof(intval)));
  CU_ASSERT(session->opt_flags & SPDYLAY_OPTMASK_NO_AUTO_WINDOW_UPDATE);

  intval = 0;
  CU_ASSERT(0 ==
            spdylay_session_set_option(session,
                                       SPDYLAY_OPT_NO_AUTO_WINDOW_UPDATE,
                                       &intval, sizeof(intval)));
  CU_ASSERT((session->opt_flags & SPDYLAY_OPTMASK_NO_AUTO_WINDOW_UPDATE) == 0);

  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_session_set_option(session, 0, /* 0 is invalid optname */
                                       &intval, sizeof(intval)));

  charval = 1;
  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_session_set_option(session,
                                       SPDYLAY_OPT_NO_AUTO_WINDOW_UPDATE,
                                       &charval, sizeof(charval)));

  spdylay_session_del(session);
}

void test_spdylay_submit_window_update(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  int32_t stream_id = 2;
  my_user_data ud;
  spdylay_outbound_item *item;
  spdylay_stream *stream;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY3,
                             &callbacks, &ud);
  stream = spdylay_session_open_stream(session, stream_id,
                                       SPDYLAY_CTRL_FLAG_NONE, 3,
                                       SPDYLAY_STREAM_OPENED, NULL);
  stream->recv_window_size = 4096;

  CU_ASSERT(0 == spdylay_submit_window_update(session, stream_id, 1024));
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(SPDYLAY_WINDOW_UPDATE == OB_CTRL_TYPE(item));
  CU_ASSERT(1024 == OB_CTRL(item)->window_update.delta_window_size);
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(3072 == stream->recv_window_size);

  CU_ASSERT(0 == spdylay_submit_window_update(session, stream_id, 4096));
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(SPDYLAY_WINDOW_UPDATE == OB_CTRL_TYPE(item));
  CU_ASSERT(4096 == OB_CTRL(item)->window_update.delta_window_size);
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(0 == stream->recv_window_size);

  CU_ASSERT(0 == spdylay_submit_window_update(session, stream_id, 4096));
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(SPDYLAY_WINDOW_UPDATE == OB_CTRL_TYPE(item));
  CU_ASSERT(4096 == OB_CTRL(item)->window_update.delta_window_size);
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(0 == stream->recv_window_size);

  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_submit_window_update(session, stream_id, 0));
  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_submit_window_update(session, stream_id, -1));
  CU_ASSERT(SPDYLAY_ERR_STREAM_CLOSED ==
            spdylay_submit_window_update(session, 4, 4096));

  spdylay_session_del(session);
}

void test_spdylay_session_data_read_temporal_failure(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { NULL };
  my_user_data ud;
  spdylay_data_provider data_prd;
  spdylay_frame frame;
  spdylay_data *data_frame;
  spdylay_stream *stream;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_ctrl_send_callback = on_ctrl_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.data_source_length = 128*1024;

  /* Initial window size is 64KiB */
  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY3, &callbacks, &ud);
  spdylay_submit_request(session, 3, nv, &data_prd, NULL);

  /* Sends 64KiB data */
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(64*1024 == ud.data_source_length);

  stream = spdylay_session_get_stream(session, 1);
  CU_ASSERT(NULL != stream->deferred_data);
  CU_ASSERT(SPDYLAY_DATA == stream->deferred_data->frame_cat);
  data_frame = (spdylay_data*)stream->deferred_data->frame;
  data_frame->data_prd.read_callback =
    temporal_failure_data_source_read_callback;

  /* Back 64KiB */
  spdylay_frame_window_update_init(&frame.window_update, SPDYLAY_PROTO_SPDY3,
                                   1, 64*1024);
  spdylay_session_on_window_update_received(session, &frame);
  spdylay_frame_window_update_free(&frame.window_update);

  /* Sending data will fail */
  ud.ctrl_send_cb_called = 0;
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(64*1024 == ud.data_source_length);

  CU_ASSERT(1 == ud.ctrl_send_cb_called);
  CU_ASSERT(SPDYLAY_RST_STREAM == ud.sent_frame_type);

  data_prd.read_callback = fail_data_source_read_callback;
  spdylay_submit_request(session, 3, nv, &data_prd, NULL);
  /* Sending data will fail */
  CU_ASSERT(SPDYLAY_ERR_CALLBACK_FAILURE == spdylay_session_send(session));

  spdylay_session_del(session);
}

void test_spdylay_session_recv_eof(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.recv_callback = eof_recv_callback;

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY3,
                             &callbacks, NULL);

  CU_ASSERT(SPDYLAY_ERR_EOF == spdylay_session_recv(session));

  spdylay_session_del(session);
}

void test_spdylay_session_recv_data(void)
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data ud;
  uint8_t data[8092];
  int rv;
  spdylay_outbound_item *item;
  spdylay_stream *stream;

  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks.on_data_recv_callback = on_data_recv_callback;

  spdylay_session_client_new(&session, SPDYLAY_PROTO_SPDY3, &callbacks, &ud);

  /* Create DATA frame with length 4KiB */
  memset(data, 0, sizeof(data));
  spdylay_put_uint32be(data, 1);
  spdylay_put_uint32be(data+4, 4096);

  /* stream 1 is not opened, so it must be responded with RST_STREAM */
  ud.data_chunk_recv_cb_called = 0;
  ud.data_recv_cb_called = 0;
  rv = spdylay_session_mem_recv(session, data, 8+4096);
  CU_ASSERT(8+4096 == rv);

  CU_ASSERT(0 == ud.data_chunk_recv_cb_called);
  CU_ASSERT(0 == ud.data_recv_cb_called);
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(SPDYLAY_RST_STREAM == OB_CTRL_TYPE(item));

  CU_ASSERT(0 == spdylay_session_send(session));

  /* Create stream 1 with CLOSING state. It is ignored. */
  stream = spdylay_session_open_stream(session, 1,
                                       SPDYLAY_CTRL_FLAG_NONE, 3,
                                       SPDYLAY_STREAM_CLOSING, NULL);

  ud.data_chunk_recv_cb_called = 0;
  ud.data_recv_cb_called = 0;
  rv = spdylay_session_mem_recv(session, data, 8+4096);
  CU_ASSERT(8+4096 == rv);

  CU_ASSERT(0 == ud.data_chunk_recv_cb_called);
  CU_ASSERT(0 == ud.data_recv_cb_called);
  item = spdylay_session_get_next_ob_item(session);
  CU_ASSERT(NULL == item);

  /* This is normal case. DATA is acceptable. */
  stream->state = SPDYLAY_STREAM_OPENED;

  ud.data_chunk_recv_cb_called = 0;
  ud.data_recv_cb_called = 0;
  rv = spdylay_session_mem_recv(session, data, 8+4096);
  CU_ASSERT(8+4096 == rv);

  CU_ASSERT(1 == ud.data_chunk_recv_cb_called);
  CU_ASSERT(1 == ud.data_recv_cb_called);

  spdylay_session_del(session);
}
