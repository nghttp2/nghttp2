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
#include <arpa/inet.h>

#include "spdylay_session.h"
#include "spdylay_stream.h"

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
  int valid, invalid;
  size_t data_source_length;
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
  ++ud->valid;
}

static void on_invalid_ctrl_recv_callback(spdylay_session *session,
                                          spdylay_frame_type type,
                                          spdylay_frame *frame,
                                          void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->invalid;
}

static ssize_t fixed_length_data_source_read_callback
(spdylay_session *session, uint8_t *buf, size_t len, int *eof,
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

static char** dup_nv(const char **src)
{
  return spdylay_frame_nv_copy(src);
}

void test_spdylay_session_recv()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks = {
    NULL,
    scripted_recv_callback
  };
  scripted_data_feed df;
  my_user_data user_data;
  const char *nv[] = {
    "url", "/", NULL
  };
  uint8_t *framedata;
  size_t framelen;
  spdylay_frame frame;

  user_data.df = &df;
  spdylay_session_client_new(&session, &callbacks, &user_data);
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_FLAG_NONE, 0, 0, 3,
                                dup_nv(nv));
  framelen = spdylay_frame_pack_syn_stream(&framedata, &frame.syn_stream,
                                           &session->hd_deflater);
  scripted_data_feed_init(&df, framedata, framelen);
  free(framedata);
  spdylay_frame_syn_stream_free(&frame.syn_stream);

  CU_ASSERT(0 == spdylay_session_recv(session));
  spdylay_session_del(session);
}

void test_spdylay_session_add_frame()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks = {
    accumulator_send_callback,
    NULL,
  };
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
  memset(aux_data, 0, sizeof(spdylay_syn_stream_aux_data));
  acc.length = 0;
  user_data.acc = &acc;
  CU_ASSERT(0 == spdylay_session_client_new(&session, &callbacks, &user_data));

  frame = malloc(sizeof(spdylay_frame));
  spdylay_frame_syn_stream_init(&frame->syn_stream, SPDYLAY_FLAG_NONE, 0, 0, 3,
                                dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_add_frame(session, SPDYLAY_SYN_STREAM, frame,
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

void test_spdylay_session_recv_invalid_stream_id()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks = {
    NULL,
    scripted_recv_callback,
    NULL,
    on_invalid_ctrl_recv_callback
  };
  scripted_data_feed df;
  my_user_data user_data;
  const char *nv[] = { NULL };
  uint8_t *framedata;
  size_t framelen;
  spdylay_frame frame;

  user_data.df = &df;
  user_data.invalid = 0;
  spdylay_session_client_new(&session, &callbacks, &user_data);
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_FLAG_NONE, 1, 0, 3,
                                dup_nv(nv));
  framelen = spdylay_frame_pack_syn_stream(&framedata, &frame.syn_stream,
                                           &session->hd_deflater);
  scripted_data_feed_init(&df, framedata, framelen);
  free(framedata);
  spdylay_frame_syn_stream_free(&frame.syn_stream);

  CU_ASSERT(0 == spdylay_session_recv(session));
  CU_ASSERT(1 == user_data.invalid);

  spdylay_frame_syn_reply_init(&frame.syn_reply, SPDYLAY_FLAG_NONE, 100,
                               dup_nv(nv));
  framelen = spdylay_frame_pack_syn_reply(&framedata, &frame.syn_reply,
                                          &session->hd_deflater);
  scripted_data_feed_init(&df, framedata, framelen);
  free(framedata);
  spdylay_frame_syn_reply_free(&frame.syn_reply);

  CU_ASSERT(0 == spdylay_session_recv(session));
  CU_ASSERT(2 == user_data.invalid);

  spdylay_session_del(session);
}

void test_spdylay_session_on_syn_stream_received()
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
  user_data.valid = 0;
  user_data.invalid = 0;

  spdylay_session_server_new(&session, &callbacks, &user_data);
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_FLAG_NONE,
                                stream_id, 0, pri, dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.valid);
  stream = spdylay_session_get_stream(session, stream_id);
  CU_ASSERT(SPDYLAY_STREAM_OPENING == stream->state);
  CU_ASSERT(pri == stream->pri);

  /* Same stream ID twice leads stream closing */
  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid);
  CU_ASSERT(SPDYLAY_STREAM_CLOSING ==
            spdylay_session_get_stream(session, stream_id)->state);

  /* assoc_stream_id != 0 from client is invalid. */
  frame.syn_stream.assoc_stream_id = 1;
  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(2 == user_data.invalid);

  spdylay_frame_syn_stream_free(&frame.syn_stream);
  spdylay_session_del(session);
}

void test_spdylay_session_on_syn_stream_received_with_push()
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
  user_data.valid = 0;
  user_data.invalid = 0;

  spdylay_session_client_new(&session, &callbacks, &user_data);
  spdylay_session_open_stream(session, assoc_stream_id, SPDYLAY_FLAG_NONE,
                              pri, SPDYLAY_STREAM_OPENED, NULL);
  spdylay_frame_syn_stream_init(&frame.syn_stream,
                                SPDYLAY_FLAG_UNIDIRECTIONAL,
                                stream_id, assoc_stream_id, pri, dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.valid);
  stream = spdylay_session_get_stream(session, stream_id);
  CU_ASSERT(SPDYLAY_STREAM_OPENING == stream->state);

  /* assoc_stream_id == 0 is invalid */
  frame.syn_stream.stream_id = 4;
  frame.syn_stream.assoc_stream_id = 0;
  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid);

  /* Push without SPDYLAY_FLAG_UNIDIRECTIONAL is invalid */
  frame.syn_stream.stream_id = 6;
  frame.syn_stream.assoc_stream_id = 1;
  frame.syn_stream.hd.flags = SPDYLAY_FLAG_FIN;
  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(2 == user_data.invalid);

  /* Push to non-existent stream is invalid */
  frame.syn_stream.stream_id = 8;
  frame.syn_stream.assoc_stream_id = 3;
  frame.syn_stream.hd.flags = SPDYLAY_FLAG_UNIDIRECTIONAL;
  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(3 == user_data.invalid);

  spdylay_frame_syn_stream_free(&frame.syn_stream);
  spdylay_session_del(session);
}

void test_spdylay_session_on_syn_reply_received()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks = {
    NULL,
    NULL,
    on_ctrl_recv_callback,
    on_invalid_ctrl_recv_callback
  };
  my_user_data user_data;
  const char *nv[] = { NULL };
  spdylay_frame frame;
  spdylay_stream *stream;
  user_data.valid = 0;
  user_data.invalid = 0;

  spdylay_session_client_new(&session, &callbacks, &user_data);
  spdylay_session_open_stream(session, 1, SPDYLAY_FLAG_NONE, 0,
                              SPDYLAY_STREAM_OPENING, NULL);
  spdylay_frame_syn_reply_init(&frame.syn_reply, SPDYLAY_FLAG_NONE, 1,
                               dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_on_syn_reply_received(session, &frame));
  CU_ASSERT(1 == user_data.valid);
  CU_ASSERT(SPDYLAY_STREAM_OPENED ==
            ((spdylay_stream*)spdylay_map_find(&session->streams, 1))->state);

  CU_ASSERT(0 == spdylay_session_on_syn_reply_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid);
  CU_ASSERT(SPDYLAY_STREAM_CLOSING ==
            ((spdylay_stream*)spdylay_map_find(&session->streams, 1))->state);

  /* Check the situation when SYN_REPLY is received after peer sends
     FIN */
  stream = spdylay_session_open_stream(session, 3, SPDYLAY_FLAG_NONE, 0,
                                       SPDYLAY_STREAM_OPENED, NULL);
  spdylay_stream_shutdown(stream, SPDYLAY_SHUT_RD);
  frame.syn_reply.stream_id = 3;

  CU_ASSERT(0 == spdylay_session_on_syn_reply_received(session, &frame));
  CU_ASSERT(2 == user_data.invalid);

  spdylay_frame_syn_reply_free(&frame.syn_reply);
  spdylay_session_del(session);
}

void test_spdylay_session_send_syn_stream()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks = {
    null_send_callback,
    NULL,
    NULL,
    NULL
  };
  const char *nv[] = { NULL };
  spdylay_frame *frame = malloc(sizeof(spdylay_frame));
  spdylay_stream *stream;
  spdylay_syn_stream_aux_data *aux_data =
    malloc(sizeof(spdylay_syn_stream_aux_data));
  memset(aux_data, 0, sizeof(spdylay_syn_stream_aux_data));

  spdylay_session_client_new(&session, &callbacks, NULL);
  spdylay_frame_syn_stream_init(&frame->syn_stream, SPDYLAY_FLAG_NONE,
                                0, 0, 3, dup_nv(nv));
  spdylay_session_add_frame(session, SPDYLAY_SYN_STREAM, frame, aux_data);
  CU_ASSERT(0 == spdylay_session_send(session));
  stream = spdylay_session_get_stream(session, 1);
  CU_ASSERT(SPDYLAY_STREAM_OPENING == stream->state);

  spdylay_session_del(session);
}

void test_spdylay_session_send_syn_reply()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks = {
    null_send_callback,
    NULL,
    NULL,
    NULL
  };
  const char *nv[] = { NULL };
  spdylay_frame *frame = malloc(sizeof(spdylay_frame));
  spdylay_stream *stream;

  CU_ASSERT(0 == spdylay_session_client_new(&session, &callbacks, NULL));
  spdylay_session_open_stream(session, 2, SPDYLAY_FLAG_NONE, 3,
                              SPDYLAY_STREAM_OPENING, NULL);
  spdylay_frame_syn_reply_init(&frame->syn_reply, SPDYLAY_FLAG_NONE,
                               2, dup_nv(nv));
  spdylay_session_add_frame(session, SPDYLAY_SYN_REPLY, frame, NULL);
  CU_ASSERT(0 == spdylay_session_send(session));
  stream = spdylay_session_get_stream(session, 2);
  CU_ASSERT(SPDYLAY_STREAM_OPENED == stream->state);

  spdylay_session_del(session);
}

void test_spdylay_submit_response()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks = {
    null_send_callback,
    NULL,
    NULL,
    NULL
  };
  const char *nv[] = { NULL };
  int32_t stream_id = 2;
  spdylay_data_provider data_prd;
  my_user_data ud;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 64*1024;
  CU_ASSERT(0 == spdylay_session_client_new(&session, &callbacks, &ud));
  spdylay_session_open_stream(session, stream_id, SPDYLAY_FLAG_NONE, 3,
                              SPDYLAY_STREAM_OPENING, NULL);
  CU_ASSERT(0 == spdylay_submit_response(session, stream_id, nv, &data_prd));
  CU_ASSERT(0 == spdylay_session_send(session));
  spdylay_session_del(session);
}

void test_spdylay_submit_request_with_data()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks = {
    null_send_callback,
    NULL,
    NULL,
    NULL
  };
  const char *nv[] = { NULL };
  spdylay_data_provider data_prd;
  my_user_data ud;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 64*1024;
  CU_ASSERT(0 == spdylay_session_client_new(&session, &callbacks, &ud));
  CU_ASSERT(0 == spdylay_submit_request(session, 3, nv, &data_prd, NULL));
  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(0 == ud.data_source_length);

  spdylay_session_del(session);
}

void test_spdylay_session_reply_fail()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks = {
    fail_send_callback,
    NULL,
    NULL,
    NULL
  };
  const char *nv[] = { NULL };
  int32_t stream_id = 2;
  spdylay_data_provider data_prd;
  my_user_data ud;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 4*1024;
  CU_ASSERT(0 == spdylay_session_client_new(&session, &callbacks, &ud));
  CU_ASSERT(0 == spdylay_submit_response(session, stream_id, nv, &data_prd));
  CU_ASSERT(0 == spdylay_session_send(session));
  spdylay_session_del(session);
}

void test_spdylay_session_on_headers_received()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks = {
    NULL,
    NULL,
    on_ctrl_recv_callback,
    on_invalid_ctrl_recv_callback
  };
  my_user_data user_data;
  const char *nv[] = { NULL };
  spdylay_frame frame;
  user_data.valid = 0;
  user_data.invalid = 0;

  spdylay_session_client_new(&session, &callbacks, &user_data);
  spdylay_session_open_stream(session, 1, SPDYLAY_FLAG_NONE, 0,
                              SPDYLAY_STREAM_OPENED, NULL);
  spdylay_stream_shutdown(spdylay_session_get_stream(session, 1),
                          SPDYLAY_SHUT_WR);
  spdylay_frame_headers_init(&frame.headers, SPDYLAY_FLAG_NONE, 1,
                             dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(1 == user_data.valid);
  CU_ASSERT(SPDYLAY_STREAM_OPENED ==
            spdylay_session_get_stream(session, 1)->state);

  frame.headers.hd.flags |= SPDYLAY_FLAG_FIN;

  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(2 == user_data.valid);
  CU_ASSERT(NULL == spdylay_session_get_stream(session, 1));

  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid);

  /* Check to see when SPDYLAY_STREAM_CLOSING, incoming HEADERS is
     discarded. */
  spdylay_session_open_stream(session, 3, SPDYLAY_FLAG_NONE, 0,
                              SPDYLAY_STREAM_CLOSING, NULL);
  frame.headers.stream_id = 3;
  frame.headers.hd.flags = SPDYLAY_FLAG_NONE;
  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(2 == user_data.valid);
  CU_ASSERT(1 == user_data.invalid);

  /* Server initiated stream */
  spdylay_session_open_stream(session, 2, SPDYLAY_FLAG_NONE, 0,
                              SPDYLAY_STREAM_OPENING, NULL);

  frame.headers.hd.flags = SPDYLAY_FLAG_FIN;
  frame.headers.stream_id = 2;

  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(3 == user_data.valid);
  CU_ASSERT(SPDYLAY_STREAM_OPENING ==
            spdylay_session_get_stream(session, 2)->state);
  CU_ASSERT(spdylay_session_get_stream(session, 2)->shut_flags &
            SPDYLAY_SHUT_RD);

  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(2 == user_data.invalid);

  spdylay_frame_headers_free(&frame.headers);
  spdylay_session_del(session);
}

void test_spdylay_session_on_ping_received()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks = {
    NULL,
    NULL,
    on_ctrl_recv_callback,
    on_invalid_ctrl_recv_callback
  };
  my_user_data user_data;
  spdylay_frame frame;
  spdylay_outbound_item *top;
  uint32_t unique_id;
  user_data.valid = 0;
  user_data.invalid = 0;

  spdylay_session_client_new(&session, &callbacks, &user_data);
  unique_id = 2;
  spdylay_frame_ping_init(&frame.ping, unique_id);

  CU_ASSERT(0 == spdylay_session_on_ping_received(session, &frame));
  CU_ASSERT(1 == user_data.valid);
  top = spdylay_session_get_ob_pq_top(session);
  CU_ASSERT(SPDYLAY_PING == top->frame_type);
  CU_ASSERT(unique_id == top->frame->ping.unique_id);

  session->last_ping_unique_id = 1;
  frame.ping.unique_id = 1;

  CU_ASSERT(0 == spdylay_session_on_ping_received(session, &frame));
  CU_ASSERT(2 == user_data.valid);

  spdylay_frame_ping_free(&frame.ping);
  spdylay_session_del(session);
}

void test_spdylay_session_on_goaway_received()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks = {
    NULL,
    NULL,
    on_ctrl_recv_callback,
    on_invalid_ctrl_recv_callback,
  };
  my_user_data user_data;
  spdylay_frame frame;
  int32_t stream_id = 1000000007;
  user_data.valid = 0;
  user_data.invalid = 0;

  spdylay_session_client_new(&session, &callbacks, &user_data);
  spdylay_frame_goaway_init(&frame.goaway, stream_id);

  CU_ASSERT(0 == spdylay_session_on_goaway_received(session, &frame));
  CU_ASSERT(1 == user_data.valid);
  CU_ASSERT(session->goaway_flags == SPDYLAY_GOAWAY_RECV);

  spdylay_frame_goaway_free(&frame.goaway);
  spdylay_session_del(session);
}

void test_spdylay_session_on_data_received()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  my_user_data user_data;
  spdylay_outbound_item *top;
  int32_t stream_id = 2;
  spdylay_stream *stream;

  spdylay_session_client_new(&session, &callbacks, &user_data);
  stream = spdylay_session_open_stream(session, stream_id, SPDYLAY_FLAG_NONE,
                                       3, SPDYLAY_STREAM_OPENING, NULL);
  CU_ASSERT(0 == spdylay_session_on_data_received(session, SPDYLAY_FLAG_NONE,
                                                  4096, stream_id));
  CU_ASSERT(0 == stream->shut_flags);

  CU_ASSERT(0 == spdylay_session_on_data_received(session, SPDYLAY_FLAG_FIN,
                                                  4096, stream_id));
  CU_ASSERT(SPDYLAY_SHUT_RD == stream->shut_flags);

  /* If SPDYLAY_STREAM_CLOSING state, DATA frame is discarded. */
  stream_id = 4;

  spdylay_session_open_stream(session, stream_id, SPDYLAY_FLAG_NONE,
                              3, SPDYLAY_STREAM_CLOSING, NULL);
  CU_ASSERT(0 == spdylay_session_on_data_received(session, SPDYLAY_FLAG_NONE,
                                                  4096, stream_id));
  CU_ASSERT(NULL == spdylay_session_get_ob_pq_top(session));

  /* Check INVALID_STREAM case: DATA frame with stream ID which does
     not exist. */
  stream_id = 6;

  CU_ASSERT(0 == spdylay_session_on_data_received(session, SPDYLAY_FLAG_NONE,
                                                  4096, stream_id));
  top = spdylay_session_get_ob_pq_top(session);
  CU_ASSERT(SPDYLAY_RST_STREAM == top->frame_type);
  CU_ASSERT(SPDYLAY_INVALID_STREAM == top->frame->rst_stream.status_code);

  spdylay_session_del(session);
}

void test_spdylay_session_is_my_stream_id()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  spdylay_session_server_new(&session, &callbacks, NULL);

  CU_ASSERT(0 == spdylay_session_is_my_stream_id(session, 0));
  CU_ASSERT(0 == spdylay_session_is_my_stream_id(session, 1));
  CU_ASSERT(1 == spdylay_session_is_my_stream_id(session, 2));

  spdylay_session_del(session);

  spdylay_session_client_new(&session, &callbacks, NULL);

  CU_ASSERT(0 == spdylay_session_is_my_stream_id(session, 0));
  CU_ASSERT(1 == spdylay_session_is_my_stream_id(session, 1));
  CU_ASSERT(0 == spdylay_session_is_my_stream_id(session, 2));

  spdylay_session_del(session);
}

void test_spdylay_session_on_rst_received()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  spdylay_stream *stream;
  spdylay_frame frame;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  spdylay_session_server_new(&session, &callbacks, &user_data);
  stream = spdylay_session_open_stream(session, 1, SPDYLAY_FLAG_NONE,
                                       3, SPDYLAY_STREAM_OPENING, NULL);
  /* server push */
  spdylay_session_open_stream(session, 2, SPDYLAY_FLAG_NONE,
                              3, SPDYLAY_STREAM_OPENING, NULL);
  spdylay_stream_add_pushed_stream(stream, 2);
  spdylay_session_open_stream(session, 4, SPDYLAY_FLAG_NONE,
                              3, SPDYLAY_STREAM_OPENING, NULL);
  spdylay_stream_add_pushed_stream(stream, 4);

  spdylay_frame_rst_stream_init(&frame.rst_stream, 1, SPDYLAY_CANCEL);

  CU_ASSERT(0 == spdylay_session_on_rst_stream_received(session, &frame));

  CU_ASSERT(NULL == spdylay_session_get_stream(session, 1));
  CU_ASSERT(NULL == spdylay_session_get_stream(session, 2));
  CU_ASSERT(NULL == spdylay_session_get_stream(session, 4));

  spdylay_frame_rst_stream_free(&frame.rst_stream);
  spdylay_session_del(session);
}

void test_spdylay_session_send_rst_stream()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  my_user_data user_data;
  spdylay_stream *stream;
  spdylay_frame *frame;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;
  spdylay_session_client_new(&session, &callbacks, &user_data);
  stream = spdylay_session_open_stream(session, 1, SPDYLAY_FLAG_NONE,
                                       3, SPDYLAY_STREAM_OPENING, NULL);
  /* server push */
  spdylay_session_open_stream(session, 2, SPDYLAY_FLAG_NONE,
                              3, SPDYLAY_STREAM_OPENING, NULL);
  spdylay_stream_add_pushed_stream(stream, 2);
  spdylay_session_open_stream(session, 4, SPDYLAY_FLAG_NONE,
                              3, SPDYLAY_STREAM_OPENING, NULL);
  spdylay_stream_add_pushed_stream(stream, 4);

  frame = malloc(sizeof(spdylay_frame));
  spdylay_frame_rst_stream_init(&frame->rst_stream, 1, SPDYLAY_CANCEL);
  spdylay_session_add_frame(session, SPDYLAY_RST_STREAM, frame, NULL);
  CU_ASSERT(0 == spdylay_session_send(session));

  CU_ASSERT(NULL == spdylay_session_get_stream(session, 1));
  CU_ASSERT(NULL == spdylay_session_get_stream(session, 2));
  CU_ASSERT(NULL == spdylay_session_get_stream(session, 4));

  spdylay_session_del(session);
}

void test_spdylay_session_get_next_ob_item()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { NULL };
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;

  spdylay_session_server_new(&session, &callbacks, NULL);
  session->settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS] = 2;

  CU_ASSERT(NULL == spdylay_session_get_next_ob_item(session));
  spdylay_submit_ping(session);
  CU_ASSERT(SPDYLAY_PING ==
            spdylay_session_get_next_ob_item(session)->frame_type);

  spdylay_submit_request(session, 0, nv, NULL, NULL);
  CU_ASSERT(SPDYLAY_PING ==
            spdylay_session_get_next_ob_item(session)->frame_type);

  CU_ASSERT(0 == spdylay_session_send(session));
  CU_ASSERT(NULL == spdylay_session_get_next_ob_item(session));

  spdylay_session_open_stream(session, 1, SPDYLAY_FLAG_NONE,
                              3, SPDYLAY_STREAM_OPENING, NULL);

  spdylay_submit_request(session, 0, nv, NULL, NULL);
  CU_ASSERT(NULL == spdylay_session_get_next_ob_item(session));

  spdylay_submit_response(session, 1, nv, NULL);
  CU_ASSERT(SPDYLAY_SYN_REPLY ==
            spdylay_session_get_next_ob_item(session)->frame_type);

  session->settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS] = 3;

  CU_ASSERT(SPDYLAY_SYN_STREAM ==
            spdylay_session_get_next_ob_item(session)->frame_type);

  spdylay_session_del(session);
}

void test_spdylay_session_pop_next_ob_item()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks;
  const char *nv[] = { NULL };
  spdylay_outbound_item *item;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = null_send_callback;

  spdylay_session_server_new(&session, &callbacks, NULL);
  session->settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS] = 1;

  CU_ASSERT(NULL == spdylay_session_pop_next_ob_item(session));
  spdylay_submit_ping(session);
  spdylay_submit_request(session, 0, nv, NULL, NULL);

  item = spdylay_session_pop_next_ob_item(session);
  CU_ASSERT(SPDYLAY_PING == item->frame_type);
  spdylay_outbound_item_free(item);
  free(item);

  item = spdylay_session_pop_next_ob_item(session);
  CU_ASSERT(SPDYLAY_SYN_STREAM == item->frame_type);
  spdylay_outbound_item_free(item);
  free(item);

  CU_ASSERT(NULL == spdylay_session_pop_next_ob_item(session));

  spdylay_session_open_stream(session, 1, SPDYLAY_FLAG_NONE,
                              3, SPDYLAY_STREAM_OPENING, NULL);

  spdylay_submit_request(session, 0, nv, NULL, NULL);
  spdylay_submit_response(session, 1, nv, NULL);

  item = spdylay_session_pop_next_ob_item(session);
  CU_ASSERT(SPDYLAY_SYN_REPLY == item->frame_type);
  spdylay_outbound_item_free(item);
  free(item);

  CU_ASSERT(NULL == spdylay_session_pop_next_ob_item(session));

  spdylay_submit_response(session, 1, nv, NULL);
  session->settings[SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS] = 2;

  item = spdylay_session_pop_next_ob_item(session);
  CU_ASSERT(SPDYLAY_SYN_STREAM == item->frame_type);
  spdylay_outbound_item_free(item);
  free(item);

  spdylay_session_del(session);
}
