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

  CU_ASSERT(0 == spdylay_session_add_frame(session, SPDYLAY_SYN_STREAM, frame));
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
  user_data.valid = 0;
  user_data.invalid = 0;

  spdylay_session_client_new(&session, &callbacks, &user_data);
  spdylay_frame_syn_stream_init(&frame.syn_stream, SPDYLAY_FLAG_NONE,
                                2, 0, 3, dup_nv(nv));

  CU_ASSERT(0 == spdylay_session_on_syn_stream_received(session, &frame));
  CU_ASSERT(1 == user_data.valid);
  CU_ASSERT(SPDYLAY_STREAM_OPENING ==
            ((spdylay_stream*)spdylay_map_find(&session->streams, 2))->state);

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
  user_data.valid = 0;
  user_data.invalid = 0;

  spdylay_session_client_new(&session, &callbacks, &user_data);
  spdylay_session_open_stream(session, 1, SPDYLAY_FLAG_NONE, 0);
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

  spdylay_frame_syn_reply_free(&frame.syn_reply);
  spdylay_session_del(session);
}
