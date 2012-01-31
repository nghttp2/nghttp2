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
  int i;
  char **dst;
  for(i = 0; src[i]; ++i);
  dst = malloc((i+1)*sizeof(char*));
  for(i = 0; src[i]; ++i) {
    dst[i] = strdup(src[i]);
  }
  dst[i] = NULL;
  return dst;
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
  const uint8_t hd_ans1[] = {
    0x80, 0x02, 0x00, 0x01
  };
  uint32_t temp32;
  acc.length = 0;
  user_data.acc = &acc;
  CU_ASSERT(0 == spdylay_session_client_new(&session, &callbacks, &user_data));

  frame = malloc(sizeof(spdylay_frame));
  spdylay_frame_syn_stream_init(&frame->syn_stream, SPDYLAY_FLAG_NONE, 0, 0, 3,
                                dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_add_frame(session, SPDYLAY_SYN_STREAM, frame,
                                           NULL));
  CU_ASSERT(0 == spdylay_pq_empty(&session->ob_pq));
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
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_FLAG_NONE,
                                2, 0, 3, dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.valid);
  stream = (spdylay_stream*)spdylay_map_find(&session->streams, 2);
  CU_ASSERT(SPDYLAY_STREAM_OPENING == stream->state);
  CU_ASSERT(3 == stream->pri);

  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid);
  CU_ASSERT(SPDYLAY_STREAM_CLOSING ==
            ((spdylay_stream*)spdylay_map_find(&session->streams, 2))->state);

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
                              SPDYLAY_STREAM_OPENING);
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
                                       SPDYLAY_STREAM_OPENED);
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

  spdylay_session_client_new(&session, &callbacks, NULL);
  spdylay_frame_syn_stream_init(&frame->syn_stream, SPDYLAY_FLAG_NONE,
                                0, 0, 3, dup_nv(nv));
  spdylay_session_add_frame(session, SPDYLAY_SYN_STREAM, frame, NULL);
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
                              SPDYLAY_STREAM_OPENING);
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
                              SPDYLAY_STREAM_OPENING);
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
  CU_ASSERT(0 == spdylay_submit_request(session, 3, nv, &data_prd));
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

void test_spdylay_session_on_syn_stream_received_with_unidir_fin()
{
  spdylay_session *session;
  spdylay_session_callbacks callbacks = {
    NULL,
    NULL,
    on_ctrl_recv_callback,
    NULL
  };
  my_user_data user_data;
  const char *nv[] = { NULL };
  spdylay_frame frame;
  spdylay_stream *stream;
  user_data.valid = 0;
  user_data.invalid = 0;

  spdylay_session_client_new(&session, &callbacks, &user_data);
  spdylay_frame_syn_stream_init(&frame.syn_stream,
                                SPDYLAY_FLAG_FIN | SPDYLAY_FLAG_UNIDIRECTIONAL,
                                2, 0, 3, dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.valid);
  stream = (spdylay_stream*)spdylay_map_find(&session->streams, 2);
  CU_ASSERT(NULL == stream);

  spdylay_frame_syn_stream_free(&frame.syn_stream);
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
                              SPDYLAY_STREAM_OPENED);
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
                              SPDYLAY_STREAM_CLOSING);
  frame.headers.stream_id = 3;
  frame.headers.hd.flags = SPDYLAY_FLAG_NONE;
  CU_ASSERT(0 == spdylay_session_on_headers_received(session, &frame));
  CU_ASSERT(2 == user_data.valid);
  CU_ASSERT(1 == user_data.invalid);

  /* Server initiated stream */
  spdylay_session_open_stream(session, 2, SPDYLAY_FLAG_NONE, 0,
                              SPDYLAY_STREAM_OPENING);

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
                                       3, SPDYLAY_STREAM_OPENING);
  CU_ASSERT(0 == spdylay_session_on_data_received(session, SPDYLAY_FLAG_NONE,
                                                  4096, stream_id));
  CU_ASSERT(0 == stream->shut_flags);

  CU_ASSERT(0 == spdylay_session_on_data_received(session, SPDYLAY_FLAG_FIN,
                                                  4096, stream_id));
  CU_ASSERT(SPDYLAY_SHUT_RD == stream->shut_flags);

  /* If SPDYLAY_STREAM_CLOSING state, DATA frame is discarded. */
  stream_id = 4;

  spdylay_session_open_stream(session, stream_id, SPDYLAY_FLAG_NONE,
                              3, SPDYLAY_STREAM_CLOSING);
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
