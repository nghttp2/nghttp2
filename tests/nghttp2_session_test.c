/*
 * nghttp2 - HTTP/2 C Library
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

#include <stdio.h>
#include <assert.h>

#include <CUnit/CUnit.h>

#include "nghttp2_session.h"
#include "nghttp2_stream.h"
#include "nghttp2_net.h"
#include "nghttp2_helper.h"
#include "nghttp2_test_helper.h"
#include "nghttp2_priority_spec.h"

#define OB_CTRL(ITEM) nghttp2_outbound_item_get_ctrl_frame(ITEM)
#define OB_CTRL_TYPE(ITEM) nghttp2_outbound_item_get_ctrl_frame_type(ITEM)
#define OB_DATA(ITEM) nghttp2_outbound_item_get_data_frame(ITEM)

typedef struct {
  uint8_t buf[65535];
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
  uint8_t recv_frame_type;
  int frame_send_cb_called;
  uint8_t sent_frame_type;
  int frame_not_send_cb_called;
  uint8_t not_sent_frame_type;
  int not_sent_error;
  int stream_close_cb_called;
  size_t data_source_length;
  int32_t stream_id;
  size_t block_count;
  int data_chunk_recv_cb_called;
  const nghttp2_frame *frame;
  size_t fixed_sendlen;
  int header_cb_called;
  int begin_headers_cb_called;
  nghttp2_nv nv;
  size_t data_chunk_len;
  size_t padlen;
} my_user_data;

static void scripted_data_feed_init2(scripted_data_feed *df,
                                     nghttp2_bufs *bufs)
{
  nghttp2_buf_chain *ci;
  nghttp2_buf *buf;
  uint8_t *ptr;
  size_t len;

  memset(df, 0, sizeof(scripted_data_feed));
  ptr = df->data;
  len = 0;

  for(ci = bufs->head; ci; ci = ci->next) {
    buf = &ci->buf;
    ptr = nghttp2_cpymem(ptr, buf->pos, nghttp2_buf_len(buf));
    len += nghttp2_buf_len(buf);
  }

  df->datamark = df->data;
  df->datalimit = df->data + len;
  df->feedseq[0] = len;
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

static ssize_t fixed_bytes_send_callback(nghttp2_session *session,
                                         const uint8_t *data, size_t len,
                                         int flags, void *user_data)
{
  size_t fixed_sendlen = ((my_user_data*)user_data)->fixed_sendlen;
  return fixed_sendlen < len ? fixed_sendlen : len;
}


static ssize_t scripted_recv_callback(nghttp2_session *session,
                                      uint8_t* data, size_t len, int flags,
                                      void *user_data)
{
  scripted_data_feed *df = ((my_user_data*)user_data)->df;
  size_t wlen = df->feedseq[df->seqidx] > len ? len : df->feedseq[df->seqidx];
  memcpy(data, df->datamark, wlen);
  df->datamark += wlen;
  df->feedseq[df->seqidx] -= wlen;
  if(df->feedseq[df->seqidx] == 0) {
    ++df->seqidx;
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

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->frame_recv_cb_called;
  ud->recv_frame_type = frame->hd.type;
  return 0;
}

static int on_invalid_frame_recv_callback(nghttp2_session *session,
                                          const nghttp2_frame *frame,
                                          nghttp2_error_code error_code,
                                          void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->invalid_frame_recv_cb_called;
  return 0;
}

static int on_frame_send_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->frame_send_cb_called;
  ud->sent_frame_type = frame->hd.type;
  return 0;
}

static int on_frame_not_send_callback(nghttp2_session *session,
                                      const nghttp2_frame *frame,
                                      int lib_error,
                                      void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->frame_not_send_cb_called;
  ud->not_sent_frame_type = frame->hd.type;
  ud->not_sent_error = lib_error;
  return 0;
}

static int on_data_chunk_recv_callback(nghttp2_session *session,
                                       uint8_t flags, int32_t stream_id,
                                       const uint8_t *data, size_t len,
                                       void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->data_chunk_recv_cb_called;
  ud->data_chunk_len = len;
  return 0;
}

static int pause_on_data_chunk_recv_callback(nghttp2_session *session,
                                             uint8_t flags, int32_t stream_id,
                                             const uint8_t *data, size_t len,
                                             void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->data_chunk_recv_cb_called;
  return NGHTTP2_ERR_PAUSE;
}

static ssize_t select_padding_callback(nghttp2_session *session,
                                       const nghttp2_frame *frame,
                                       size_t max_payloadlen,
                                       void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  return nghttp2_min(max_payloadlen, frame->hd.length + ud->padlen);
}

static ssize_t fixed_length_data_source_read_callback
(nghttp2_session *session, int32_t stream_id,
 uint8_t *buf, size_t len, uint32_t *data_flags,
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
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }
  return wlen;
}

static ssize_t temporal_failure_data_source_read_callback
(nghttp2_session *session, int32_t stream_id,
 uint8_t *buf, size_t len, uint32_t *data_flags,
 nghttp2_data_source *source, void *user_data)
{
  return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
}

static ssize_t fail_data_source_read_callback
(nghttp2_session *session, int32_t stream_id,
 uint8_t *buf, size_t len, uint32_t *data_flags,
 nghttp2_data_source *source, void *user_data)
{
  return NGHTTP2_ERR_CALLBACK_FAILURE;
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
  ssize_t r;
  if(ud->block_count == 0) {
    r = NGHTTP2_ERR_WOULDBLOCK;
  } else {
    --ud->block_count;
    r = len;
  }
  return r;
}

static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              const uint8_t *name, size_t namelen,
                              const uint8_t *value, size_t valuelen,
                              uint8_t flags,
                              void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->header_cb_called;
  ud->nv.name = (uint8_t*)name;
  ud->nv.namelen = namelen;
  ud->nv.value = (uint8_t*)value;
  ud->nv.valuelen = valuelen;

  ud->frame = frame;
  return 0;
}

static int pause_on_header_callback(nghttp2_session *session,
                                    const nghttp2_frame *frame,
                                    const uint8_t *name, size_t namelen,
                                    const uint8_t *value, size_t valuelen,
                                    uint8_t flags,
                                    void *user_data)
{
  on_header_callback(session, frame, name, namelen, value, valuelen, flags,
                     user_data);
  return NGHTTP2_ERR_PAUSE;
}

static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data)
{
  my_user_data *ud = (my_user_data*)user_data;
  ++ud->begin_headers_cb_called;
  return 0;
}

static ssize_t defer_data_source_read_callback
(nghttp2_session *session, int32_t stream_id,
 uint8_t *buf, size_t len, uint32_t *data_flags,
 nghttp2_data_source *source, void *user_data)
{
  return NGHTTP2_ERR_DEFERRED;
}

static int stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                 nghttp2_error_code error_code,
                                 void *user_data)
{
  my_user_data* my_data = (my_user_data*)user_data;
  void *stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
  ++my_data->stream_close_cb_called;
  CU_ASSERT(stream_data != NULL);
  return 0;
}

static nghttp2_settings_entry* dup_iv(const nghttp2_settings_entry *iv,
                                      size_t niv)
{
  return nghttp2_frame_iv_copy(iv, niv);
}

static nghttp2_priority_spec pri_spec_default = {
  0, NGHTTP2_DEFAULT_WEIGHT, 0
};

void test_nghttp2_session_recv(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  scripted_data_feed df;
  my_user_data user_data;
  const nghttp2_nv nv[] = {
    MAKE_NV("url", "/")
  };
  nghttp2_bufs bufs;
  ssize_t framelen;
  nghttp2_frame frame;
  ssize_t i;
  nghttp2_outbound_item *item;
  nghttp2_nv *nva;
  ssize_t nvlen;
  nghttp2_hd_deflater deflater;
  int rv;

  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.recv_callback = scripted_recv_callback;
  callbacks.on_frame_recv_callback = on_frame_recv_callback;

  user_data.df = &df;

  nghttp2_session_server_new(&session, &callbacks, &user_data);
  nghttp2_hd_deflate_init(&deflater);

  nvlen = ARRLEN(nv);
  nghttp2_nv_array_copy(&nva, nv, nvlen);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS,
                             1, NGHTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  rv = nghttp2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  CU_ASSERT(0 == rv);

  scripted_data_feed_init2(&df, &bufs);

  framelen = nghttp2_bufs_len(&bufs);

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

  nghttp2_bufs_reset(&bufs);

  /* Received HEADERS without header block, which is valid */
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS,
                             5, NGHTTP2_HCAT_HEADERS, NULL, NULL, 0);
  rv = nghttp2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  CU_ASSERT(0 == rv);

  nghttp2_frame_headers_free(&frame.headers);

  scripted_data_feed_init2(&df, &bufs);
  user_data.frame_recv_cb_called = 0;

  CU_ASSERT(0 == nghttp2_session_recv(session));
  CU_ASSERT(1 == user_data.frame_recv_cb_called);

  nghttp2_hd_deflate_free(&deflater);
  nghttp2_session_del(session);

  /* Some tests for frame too large */
  nghttp2_session_server_new(&session, &callbacks, &user_data);

  nghttp2_bufs_reset(&bufs);

  /* Receive PING with too large payload */
  nghttp2_frame_ping_init(&frame.ping, NGHTTP2_FLAG_NONE, NULL);

  rv = nghttp2_frame_pack_ping(&bufs, &frame.ping);

  CU_ASSERT(0 == rv);

  /* Add extra 16 bytes */
  nghttp2_bufs_seek_last_present(&bufs);
  assert(nghttp2_buf_len(&bufs.cur->buf) >= 16);

  bufs.cur->buf.last += 16;
  nghttp2_put_uint32be(bufs.cur->buf.pos,
                       (uint32_t)(((frame.hd.length + 16) << 8) +
                                  bufs.cur->buf.pos[3]));

  nghttp2_frame_ping_free(&frame.ping);

  scripted_data_feed_init2(&df, &bufs);
  user_data.frame_recv_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_recv(session));
  CU_ASSERT(0 == user_data.frame_recv_cb_called);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_FRAME_SIZE_ERROR == OB_CTRL(item)->goaway.error_code);
  CU_ASSERT(0 == nghttp2_session_send(session));

  nghttp2_bufs_free(&bufs);
  nghttp2_session_del(session);
}

void test_nghttp2_session_recv_invalid_stream_id(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  scripted_data_feed df;
  my_user_data user_data;
  nghttp2_bufs bufs;
  nghttp2_frame frame;
  nghttp2_hd_deflater deflater;
  int rv;

  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.recv_callback = scripted_recv_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  user_data.df = &df;
  user_data.invalid_frame_recv_cb_called = 0;
  nghttp2_session_server_new(&session, &callbacks, &user_data);
  nghttp2_hd_deflate_init(&deflater);

  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS, 2,
                             NGHTTP2_HCAT_HEADERS, NULL, NULL, 0);
  rv = nghttp2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  scripted_data_feed_init2(&df, &bufs);
  nghttp2_frame_headers_free(&frame.headers);

  CU_ASSERT(0 == nghttp2_session_recv(session));
  CU_ASSERT(1 == user_data.invalid_frame_recv_cb_called);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_deflate_free(&deflater);
  nghttp2_session_del(session);
}

void test_nghttp2_session_recv_invalid_frame(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  scripted_data_feed df;
  my_user_data user_data;
  const nghttp2_nv nv[] = {
    MAKE_NV("url", "/")
  };
  nghttp2_bufs bufs;
  nghttp2_frame frame;
  nghttp2_nv *nva;
  ssize_t nvlen;
  nghttp2_hd_deflater deflater;
  int rv;

  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.recv_callback = scripted_recv_callback;
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  user_data.df = &df;
  user_data.frame_send_cb_called = 0;
  nghttp2_session_server_new(&session, &callbacks, &user_data);
  nghttp2_hd_deflate_init(&deflater);
  nvlen = ARRLEN(nv);
  nghttp2_nv_array_copy(&nva, nv, nvlen);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS, 1,
                             NGHTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  rv = nghttp2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  scripted_data_feed_init2(&df, &bufs);

  CU_ASSERT(0 == nghttp2_session_recv(session));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == user_data.frame_send_cb_called);

  /* Receive exactly same bytes of HEADERS is treated as subsequent
     HEADERS (e.g., trailers */
  scripted_data_feed_init2(&df, &bufs);

  CU_ASSERT(0 == nghttp2_session_recv(session));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == user_data.frame_send_cb_called);

  nghttp2_bufs_free(&bufs);
  nghttp2_frame_headers_free(&frame.headers);

  nghttp2_hd_deflate_free(&deflater);
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
  ssize_t rv;
  nghttp2_outbound_item *item;
  nghttp2_stream *stream;
  nghttp2_frame_hd hd;
  int i;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks.on_frame_recv_callback = on_frame_recv_callback;

  nghttp2_session_client_new(&session, &callbacks, &ud);

  /* Create DATA frame with length 4KiB */
  memset(data, 0, sizeof(data));
  hd.length = 4096;
  hd.type = NGHTTP2_DATA;
  hd.flags = NGHTTP2_FLAG_NONE;
  hd.stream_id = 1;
  nghttp2_frame_pack_frame_hd(data, &hd);

  /* stream 1 is not opened, so it must be responded with connection
     error.  This is not mandated by the spec */
  ud.data_chunk_recv_cb_called = 0;
  ud.frame_recv_cb_called = 0;
  rv = nghttp2_session_mem_recv(session, data, NGHTTP2_FRAME_HDLEN + 4096);
  CU_ASSERT(NGHTTP2_FRAME_HDLEN + 4096 == rv);

  CU_ASSERT(0 == ud.data_chunk_recv_cb_called);
  CU_ASSERT(0 == ud.frame_recv_cb_called);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));

  nghttp2_session_del(session);

  nghttp2_session_client_new(&session, &callbacks, &ud);

  /* Create stream 1 with CLOSING state. DATA is ignored. */
  stream = nghttp2_session_open_stream(session, 1,
                                       NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_CLOSING, NULL);
  /* Set initial window size 16383 to check stream flow control,
     isolating it from the conneciton flow control */
  stream->local_window_size = 16383;

  ud.data_chunk_recv_cb_called = 0;
  ud.frame_recv_cb_called = 0;
  rv = nghttp2_session_mem_recv(session, data, NGHTTP2_FRAME_HDLEN + 4096);
  CU_ASSERT(NGHTTP2_FRAME_HDLEN + 4096 == rv);

  CU_ASSERT(0 == ud.data_chunk_recv_cb_called);
  CU_ASSERT(0 == ud.frame_recv_cb_called);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NULL == item);

  /* This is normal case. DATA is acceptable. */
  stream->state = NGHTTP2_STREAM_OPENED;

  ud.data_chunk_recv_cb_called = 0;
  ud.frame_recv_cb_called = 0;
  rv = nghttp2_session_mem_recv(session, data, NGHTTP2_FRAME_HDLEN + 4096);
  CU_ASSERT(NGHTTP2_FRAME_HDLEN + 4096 == rv);

  CU_ASSERT(1 == ud.data_chunk_recv_cb_called);
  CU_ASSERT(1 == ud.frame_recv_cb_called);

  CU_ASSERT(NULL == nghttp2_session_get_next_ob_item(session));

  ud.data_chunk_recv_cb_called = 0;
  ud.frame_recv_cb_called = 0;
  rv = nghttp2_session_mem_recv(session, data, NGHTTP2_FRAME_HDLEN + 4096);
  CU_ASSERT(NGHTTP2_FRAME_HDLEN + 4096 == rv);

  /* Now we got data more than initial-window-size / 2, WINDOW_UPDATE
     must be queued */
  CU_ASSERT(1 == ud.data_chunk_recv_cb_called);
  CU_ASSERT(1 == ud.frame_recv_cb_called);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_WINDOW_UPDATE == OB_CTRL_TYPE(item));
  CU_ASSERT(1 == OB_CTRL(item)->window_update.hd.stream_id);
  CU_ASSERT(0 == nghttp2_session_send(session));

  /* Set initial window size to 1MiB, so that we can check connection
     flow control individually */
  stream->local_window_size = 1 << 20;
  /* Connection flow control takes into account DATA which is received
     in the error condition. We have received 4096 * 4 bytes of
     DATA. Additional 4 DATA frames, connection flow control will kick
     in. */
  for(i = 0; i < 5; ++i) {
    rv = nghttp2_session_mem_recv(session, data, NGHTTP2_FRAME_HDLEN + 4096);
    CU_ASSERT(NGHTTP2_FRAME_HDLEN + 4096 == rv);
  }
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_WINDOW_UPDATE == OB_CTRL_TYPE(item));
  CU_ASSERT(0 == OB_CTRL(item)->window_update.hd.stream_id);
  CU_ASSERT(0 == nghttp2_session_send(session));

  /* Reception of DATA with stream ID = 0 causes connection error */
  hd.length = 4096;
  hd.type = NGHTTP2_DATA;
  hd.flags = NGHTTP2_FLAG_NONE;
  hd.stream_id = 0;
  nghttp2_frame_pack_frame_hd(data, &hd);

  ud.data_chunk_recv_cb_called = 0;
  ud.frame_recv_cb_called = 0;
  rv = nghttp2_session_mem_recv(session, data, NGHTTP2_FRAME_HDLEN + 4096);
  CU_ASSERT(NGHTTP2_FRAME_HDLEN + 4096 == rv);

  CU_ASSERT(0 == ud.data_chunk_recv_cb_called);
  CU_ASSERT(0 == ud.frame_recv_cb_called);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_PROTOCOL_ERROR == OB_CTRL(item)->goaway.error_code);

  nghttp2_session_del(session);
}

void test_nghttp2_session_recv_continuation(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const nghttp2_nv nv1[] = {
    MAKE_NV("method", "GET"),
    MAKE_NV("path", "/")
  };
  nghttp2_nv *nva;
  size_t nvlen;
  nghttp2_frame frame;
  nghttp2_bufs bufs;
  nghttp2_buf *buf;
  ssize_t rv;
  my_user_data ud;
  nghttp2_hd_deflater deflater;
  uint8_t data[1024];
  size_t datalen;
  nghttp2_frame_hd cont_hd;
  nghttp2_priority_spec pri_spec;

  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_header_callback = on_header_callback;
  callbacks.on_begin_headers_callback = on_begin_headers_callback;

  nghttp2_session_server_new(&session, &callbacks, &ud);

  nghttp2_hd_deflate_init(&deflater);

  /* Make 1 HEADERS and insert CONTINUATION header */
  nvlen = ARRLEN(nv1);
  nghttp2_nv_array_copy(&nva, nv1, nvlen);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_NONE, 1,
                             NGHTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  rv = nghttp2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  /* make sure that all data is in the first buf */
  buf = &bufs.head->buf;
  assert(nghttp2_bufs_len(&bufs) == nghttp2_buf_len(buf));

  nghttp2_frame_headers_free(&frame.headers);

  /* HEADERS's payload is 1 byte */
  memcpy(data, buf->pos, NGHTTP2_FRAME_HDLEN + 1);
  datalen = NGHTTP2_FRAME_HDLEN + 1;
  buf->pos += NGHTTP2_FRAME_HDLEN + 1;

  nghttp2_put_uint32be(data, (1 << 8) + data[3]);

  /* First CONTINUATION, 2 bytes */
  cont_hd.length = 2;
  cont_hd.type = NGHTTP2_CONTINUATION;
  cont_hd.flags = NGHTTP2_FLAG_NONE;
  cont_hd.stream_id = 1;

  nghttp2_frame_pack_frame_hd(data + datalen, &cont_hd);
  datalen += NGHTTP2_FRAME_HDLEN;

  memcpy(data + datalen, buf->pos, cont_hd.length);
  datalen += cont_hd.length;
  buf->pos += cont_hd.length;

  /* Second CONTINUATION, rest of the bytes */
  cont_hd.length = nghttp2_buf_len(buf);
  cont_hd.flags = NGHTTP2_FLAG_END_HEADERS;
  cont_hd.stream_id = 1;

  nghttp2_frame_pack_frame_hd(data + datalen, &cont_hd);
  datalen += NGHTTP2_FRAME_HDLEN;

  memcpy(data + datalen, buf->pos, cont_hd.length);
  datalen += cont_hd.length;
  buf->pos += cont_hd.length;

  CU_ASSERT(0 == nghttp2_buf_len(buf));

  ud.header_cb_called = 0;
  rv = nghttp2_session_mem_recv(session, data, datalen);
  CU_ASSERT((ssize_t)datalen == rv);
  CU_ASSERT(2 == ud.header_cb_called);

  nghttp2_hd_deflate_free(&deflater);
  nghttp2_session_del(session);

  /* Expecting CONTINUATION, but get the other frame */
  nghttp2_session_server_new(&session, &callbacks, &ud);

  nghttp2_hd_deflate_init(&deflater);

  /* HEADERS without END_HEADERS flag */
  nvlen = ARRLEN(nv1);
  nghttp2_nv_array_copy(&nva, nv1, nvlen);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_NONE, 1,
                             NGHTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  nghttp2_bufs_reset(&bufs);
  rv = nghttp2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  nghttp2_frame_headers_free(&frame.headers);

  /* make sure that all data is in the first buf */
  buf = &bufs.head->buf;
  assert(nghttp2_bufs_len(&bufs) == nghttp2_buf_len(buf));

  memcpy(data, buf->pos, nghttp2_buf_len(buf));
  datalen = nghttp2_buf_len(buf);

  /* Followed by PRIORITY */
  nghttp2_priority_spec_default_init(&pri_spec);

  nghttp2_frame_priority_init(&frame.priority, 1, &pri_spec);
  nghttp2_bufs_reset(&bufs);

  rv = nghttp2_frame_pack_priority(&bufs, &frame.priority);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  memcpy(data + datalen, buf->pos, nghttp2_buf_len(buf));
  datalen += nghttp2_buf_len(buf);

  ud.begin_headers_cb_called = 0;
  rv = nghttp2_session_mem_recv(session, data, datalen);
  CU_ASSERT((ssize_t)datalen == rv);

  CU_ASSERT(1 == ud.begin_headers_cb_called);
  CU_ASSERT(NGHTTP2_GOAWAY ==
            OB_CTRL_TYPE(nghttp2_session_get_next_ob_item(session)));

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_deflate_free(&deflater);
  nghttp2_session_del(session);
}

void test_nghttp2_session_recv_headers_with_priority(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const nghttp2_nv nv1[] = {
    MAKE_NV("method", "GET"),
    MAKE_NV("path", "/")
  };
  nghttp2_nv *nva;
  size_t nvlen;
  nghttp2_frame frame;
  nghttp2_bufs bufs;
  nghttp2_buf *buf;
  ssize_t rv;
  my_user_data ud;
  nghttp2_hd_deflater deflater;
  nghttp2_outbound_item *item;
  nghttp2_priority_spec pri_spec;
  nghttp2_stream *stream;

  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;

  nghttp2_session_server_new(&session, &callbacks, &ud);

  nghttp2_hd_deflate_init(&deflater);

  open_stream(session, 1);

  /* With NGHTTP2_FLAG_PRIORITY without exclusive flag set */
  nvlen = ARRLEN(nv1);
  nghttp2_nv_array_copy(&nva, nv1, nvlen);

  nghttp2_priority_spec_init(&pri_spec, 1, 99, 0);

  nghttp2_frame_headers_init(&frame.headers,
                             NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_PRIORITY,
                             3, NGHTTP2_HCAT_HEADERS, &pri_spec, nva, nvlen);

  rv = nghttp2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  nghttp2_frame_headers_free(&frame.headers);

  buf = &bufs.head->buf;
  assert(nghttp2_bufs_len(&bufs) == nghttp2_buf_len(buf));

  ud.frame_recv_cb_called = 0;

  rv = nghttp2_session_mem_recv(session, buf->pos, nghttp2_buf_len(buf));

  CU_ASSERT(nghttp2_buf_len(buf) == rv);
  CU_ASSERT(1 == ud.frame_recv_cb_called);

  stream = nghttp2_session_get_stream(session, 3);

  CU_ASSERT(99 == stream->weight);
  CU_ASSERT(1 == stream->dep_prev->stream_id);

  nghttp2_bufs_reset(&bufs);

  /* With NGHTTP2_FLAG_PRIORITY, but cut last 1 byte to make it
     invalid. */
  nvlen = ARRLEN(nv1);
  nghttp2_nv_array_copy(&nva, nv1, nvlen);

  nghttp2_priority_spec_init(&pri_spec, 0, 99, 0);

  nghttp2_frame_headers_init(&frame.headers,
                             NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_PRIORITY,
                             5, NGHTTP2_HCAT_HEADERS, &pri_spec, nva, nvlen);

  rv = nghttp2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NGHTTP2_FRAME_HDLEN + 5 + 2 == nghttp2_bufs_len(&bufs));

  nghttp2_frame_headers_free(&frame.headers);

  buf = &bufs.head->buf;
  /* Make payload shorter than required length to store priroty
     group */
  nghttp2_put_uint32be(buf->pos, (4 << 8) + buf->pos[3]);

  ud.frame_recv_cb_called = 0;

  rv = nghttp2_session_mem_recv(session, buf->pos, nghttp2_buf_len(buf));

  CU_ASSERT(nghttp2_buf_len(buf) == rv);
  CU_ASSERT(0 == ud.frame_recv_cb_called);

  stream = nghttp2_session_get_stream(session, 5);

  CU_ASSERT(NULL == stream);

  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NULL != item);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_FRAME_SIZE_ERROR == OB_CTRL(item)->goaway.error_code);

  nghttp2_bufs_reset(&bufs);

  nghttp2_hd_deflate_free(&deflater);
  nghttp2_session_del(session);

  /* Check dep_stream_id == stream_id */
  nghttp2_session_server_new(&session, &callbacks, &ud);

  nghttp2_hd_deflate_init(&deflater);

  nvlen = ARRLEN(nv1);
  nghttp2_nv_array_copy(&nva, nv1, nvlen);

  nghttp2_priority_spec_init(&pri_spec, 1, 0, 0);

  nghttp2_frame_headers_init(&frame.headers,
                             NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_PRIORITY,
                             1, NGHTTP2_HCAT_HEADERS, &pri_spec, nva, nvlen);

  rv = nghttp2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  nghttp2_frame_headers_free(&frame.headers);

  buf = &bufs.head->buf;
  assert(nghttp2_bufs_len(&bufs) == nghttp2_buf_len(buf));

  ud.frame_recv_cb_called = 0;

  rv = nghttp2_session_mem_recv(session, buf->pos, nghttp2_buf_len(buf));

  CU_ASSERT(nghttp2_buf_len(buf) == rv);
  CU_ASSERT(0 == ud.frame_recv_cb_called);

  stream = nghttp2_session_get_stream(session, 1);

  CU_ASSERT(NULL == stream);

  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NULL != item);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_PROTOCOL_ERROR == OB_CTRL(item)->goaway.error_code);

  nghttp2_bufs_reset(&bufs);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_deflate_free(&deflater);
  nghttp2_session_del(session);
}

void test_nghttp2_session_recv_premature_headers(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const nghttp2_nv nv1[] = {
    MAKE_NV("method", "GET"),
    MAKE_NV("path", "/")
  };
  nghttp2_nv *nva;
  size_t nvlen;
  nghttp2_frame frame;
  nghttp2_bufs bufs;
  nghttp2_buf *buf;
  ssize_t rv;
  my_user_data ud;
  nghttp2_hd_deflater deflater;
  nghttp2_outbound_item *item;

  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));

  nghttp2_session_server_new(&session, &callbacks, &ud);

  nghttp2_hd_deflate_init(&deflater);

  nvlen = ARRLEN(nv1);
  nghttp2_nv_array_copy(&nva, nv1, nvlen);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS, 1,
                             NGHTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  rv = nghttp2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  nghttp2_frame_headers_free(&frame.headers);

  buf = &bufs.head->buf;
  assert(nghttp2_bufs_len(&bufs) == nghttp2_buf_len(buf));

  /* Intentionally feed payload cutting last 1 byte off */
  nghttp2_put_uint32be(buf->pos,
                       (uint32_t)(((frame.hd.length - 1) << 8) + buf->pos[3]));
  rv = nghttp2_session_mem_recv(session, buf->pos, nghttp2_buf_len(buf) - 1);

  CU_ASSERT((ssize_t)(nghttp2_buf_len(buf) - 1) == rv);

  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NULL != item);
  CU_ASSERT(NGHTTP2_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_COMPRESSION_ERROR == OB_CTRL(item)->rst_stream.error_code);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_deflate_free(&deflater);
  nghttp2_session_del(session);
}

void test_nghttp2_session_recv_altsvc(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_frame frame;
  nghttp2_ext_altsvc altsvc;
  size_t protocol_id_len, host_len, origin_len;
  uint8_t *protocol_id, *host, *origin;
  uint8_t *data;
  size_t datalen;
  nghttp2_bufs bufs;
  nghttp2_buf *buf;
  ssize_t rv;
  my_user_data ud;
  nghttp2_outbound_item *item;

  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;

  protocol_id_len = strlen("h2");
  host_len = strlen("h2.example.org");
  origin_len = strlen("www.example.org");

  datalen = protocol_id_len + host_len + origin_len;
  data = malloc(datalen);

  memcpy(data, "h2", protocol_id_len);
  protocol_id = data;

  memcpy(data + protocol_id_len, "h2.example.org", host_len);
  host = data + protocol_id_len;

  memcpy(data + protocol_id_len + host_len,
         "http://www.example.org", origin_len);
  origin = data + protocol_id_len + host_len;

  frame.ext.payload = &altsvc;

  nghttp2_frame_altsvc_init(&frame.ext, 1000000007, 1u << 31, 4000,
                            protocol_id, protocol_id_len,
                            host, host_len, origin, origin_len);

  rv = nghttp2_frame_pack_altsvc(&bufs, &frame.ext);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  nghttp2_frame_altsvc_free(&frame.ext);

  buf = &bufs.head->buf;
  assert(nghttp2_bufs_len(&bufs) == nghttp2_buf_len(buf));

  /* error if server receives ALTSVC */
  nghttp2_session_server_new(&session, &callbacks, &ud);

  ud.frame_recv_cb_called = 0;

  rv = nghttp2_session_mem_recv(session, buf->pos, nghttp2_buf_len(buf));

  CU_ASSERT(rv == nghttp2_buf_len(buf));
  CU_ASSERT(0 == ud.frame_recv_cb_called);

  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));

  nghttp2_session_del(session);

  nghttp2_session_client_new(&session, &callbacks, &ud);

  ud.frame_recv_cb_called = 0;

  rv = nghttp2_session_mem_recv(session, buf->pos, nghttp2_buf_len(buf));

  CU_ASSERT(rv == nghttp2_buf_len(buf));
  CU_ASSERT(1 == ud.frame_recv_cb_called);
  CU_ASSERT(NGHTTP2_EXT_ALTSVC == ud.recv_frame_type);

  /* premature payload */
  nghttp2_put_uint32be(buf->pos, (8 << 8) + buf->pos[3]);

  ud.frame_recv_cb_called = 0;

  rv = nghttp2_session_mem_recv(session, buf->pos, NGHTTP2_FRAME_HDLEN + 8);

  CU_ASSERT(rv == NGHTTP2_FRAME_HDLEN + 8);
  CU_ASSERT(0 == ud.frame_recv_cb_called);

  item = nghttp2_session_get_next_ob_item(session);

  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));

  nghttp2_bufs_free(&bufs);
  nghttp2_session_del(session);
}

void test_nghttp2_session_recv_unknown_frame(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data ud;
  uint8_t data[16384];
  size_t datalen;
  nghttp2_frame_hd hd;
  ssize_t rv;

  hd.length = 16000;
  hd.stream_id = 0;
  hd.type = 99;
  hd.flags = NGHTTP2_FLAG_NONE;

  nghttp2_frame_pack_frame_hd(data, &hd);
  datalen = NGHTTP2_FRAME_HDLEN + hd.length;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;

  nghttp2_session_server_new(&session, &callbacks, &ud);

  ud.frame_recv_cb_called = 0;

  /* Unknown frame must be ignored */
  rv = nghttp2_session_mem_recv(session, data, datalen);

  CU_ASSERT(rv == (ssize_t)datalen);
  CU_ASSERT(0 == ud.frame_recv_cb_called);
  CU_ASSERT(NULL == nghttp2_session_get_next_ob_item(session));

  nghttp2_session_del(session);
}

void test_nghttp2_session_recv_unexpected_continuation(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data ud;
  uint8_t data[16384];
  size_t datalen;
  nghttp2_frame_hd hd;
  ssize_t rv;
  nghttp2_outbound_item *item;

  hd.length = 16000;
  hd.stream_id = 1;
  hd.type = NGHTTP2_CONTINUATION;
  hd.flags = NGHTTP2_FLAG_END_HEADERS;

  nghttp2_frame_pack_frame_hd(data, &hd);
  datalen = NGHTTP2_FRAME_HDLEN + hd.length;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;

  nghttp2_session_server_new(&session, &callbacks, &ud);

  open_stream(session, 1);

  ud.frame_recv_cb_called = 0;

  /* unexpected CONTINUATION must be treated as connection error */
  rv = nghttp2_session_mem_recv(session, data, datalen);

  CU_ASSERT(rv == (ssize_t)datalen);
  CU_ASSERT(0 == ud.frame_recv_cb_called);

  item = nghttp2_session_get_next_ob_item(session);

  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));

  nghttp2_session_del(session);
}

void test_nghttp2_session_recv_settings_header_table_size(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_frame frame;
  nghttp2_bufs bufs;
  nghttp2_buf *buf;
  ssize_t rv;
  my_user_data ud;
  nghttp2_settings_entry iv[3];
  nghttp2_nv nv = MAKE_NV(":authority", "example.org");

  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.send_callback = null_send_callback;

  nghttp2_session_client_new(&session, &callbacks, &ud);

  iv[0].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 3000;

  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 16384;

  nghttp2_frame_settings_init(&frame.settings, NGHTTP2_FLAG_NONE,
                              dup_iv(iv, 2), 2);

  rv = nghttp2_frame_pack_settings(&bufs, &frame.settings);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  nghttp2_frame_settings_free(&frame.settings);

  buf = &bufs.head->buf;
  assert(nghttp2_bufs_len(&bufs) == nghttp2_buf_len(buf));

  ud.frame_recv_cb_called = 0;

  rv = nghttp2_session_mem_recv(session, buf->pos, nghttp2_buf_len(buf));

  CU_ASSERT(rv == nghttp2_buf_len(buf));
  CU_ASSERT(1 == ud.frame_recv_cb_called);

  CU_ASSERT(3000 == session->remote_settings.header_table_size);
  CU_ASSERT(16384 == session->remote_settings.initial_window_size);

  nghttp2_bufs_reset(&bufs);

  /* 2 SETTINGS_HEADER_TABLE_SIZE */
  iv[0].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 3001;

  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 16383;

  iv[2].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[2].value = 3001;

  nghttp2_frame_settings_init(&frame.settings, NGHTTP2_FLAG_NONE,
                              dup_iv(iv, 3), 3);

  rv = nghttp2_frame_pack_settings(&bufs, &frame.settings);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  nghttp2_frame_settings_free(&frame.settings);

  buf = &bufs.head->buf;
  assert(nghttp2_bufs_len(&bufs) == nghttp2_buf_len(buf));

  ud.frame_recv_cb_called = 0;

  rv = nghttp2_session_mem_recv(session, buf->pos, nghttp2_buf_len(buf));

  CU_ASSERT(rv == nghttp2_buf_len(buf));
  CU_ASSERT(1 == ud.frame_recv_cb_called);

  CU_ASSERT(3001 == session->remote_settings.header_table_size);
  CU_ASSERT(16383 == session->remote_settings.initial_window_size);

  nghttp2_bufs_reset(&bufs);

  /* 2 SETTINGS_HEADER_TABLE_SIZE; first entry clears dynamic header
     table. */

  nghttp2_submit_request(session, NULL, &nv, 1, NULL, NULL);
  nghttp2_session_send(session);

  CU_ASSERT(0 < session->hd_deflater.ctx.hd_table.len);

  iv[0].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 0;

  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 16382;

  iv[2].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[2].value = 4096;

  nghttp2_frame_settings_init(&frame.settings, NGHTTP2_FLAG_NONE,
                              dup_iv(iv, 3), 3);

  rv = nghttp2_frame_pack_settings(&bufs, &frame.settings);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  nghttp2_frame_settings_free(&frame.settings);

  buf = &bufs.head->buf;
  assert(nghttp2_bufs_len(&bufs) == nghttp2_buf_len(buf));

  ud.frame_recv_cb_called = 0;

  rv = nghttp2_session_mem_recv(session, buf->pos, nghttp2_buf_len(buf));

  CU_ASSERT(rv == nghttp2_buf_len(buf));
  CU_ASSERT(1 == ud.frame_recv_cb_called);

  CU_ASSERT(4096 == session->remote_settings.header_table_size);
  CU_ASSERT(16382 == session->remote_settings.initial_window_size);
  CU_ASSERT(0 == session->hd_deflater.ctx.hd_table.len);

  nghttp2_bufs_reset(&bufs);

  /* 2 SETTINGS_HEADER_TABLE_SIZE; second entry clears dynamic header
     table. */

  nghttp2_submit_request(session, NULL, &nv, 1, NULL, NULL);
  nghttp2_session_send(session);

  CU_ASSERT(0 < session->hd_deflater.ctx.hd_table.len);

  iv[0].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 3000;

  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 16381;

  iv[2].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[2].value = 0;

  nghttp2_frame_settings_init(&frame.settings, NGHTTP2_FLAG_NONE,
                              dup_iv(iv, 3), 3);

  rv = nghttp2_frame_pack_settings(&bufs, &frame.settings);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  nghttp2_frame_settings_free(&frame.settings);

  buf = &bufs.head->buf;
  assert(nghttp2_bufs_len(&bufs) == nghttp2_buf_len(buf));

  ud.frame_recv_cb_called = 0;

  rv = nghttp2_session_mem_recv(session, buf->pos, nghttp2_buf_len(buf));

  CU_ASSERT(rv == nghttp2_buf_len(buf));
  CU_ASSERT(1 == ud.frame_recv_cb_called);

  CU_ASSERT(0 == session->remote_settings.header_table_size);
  CU_ASSERT(16381 == session->remote_settings.initial_window_size);
  CU_ASSERT(0 == session->hd_deflater.ctx.hd_table.len);

  nghttp2_bufs_reset(&bufs);

  nghttp2_bufs_free(&bufs);
  nghttp2_session_del(session);
}

void test_nghttp2_session_continue(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  const nghttp2_nv nv1[] = {
    MAKE_NV(":method", "GET"),
    MAKE_NV(":path", "/")
  };
  const nghttp2_nv nv2[] = {
    MAKE_NV("user-agent", "nghttp2/1.0.0"),
    MAKE_NV("alpha", "bravo")
  };
  nghttp2_bufs bufs;
  nghttp2_buf *buf;
  size_t framelen1, framelen2;
  ssize_t rv;
  uint8_t buffer[4096];
  nghttp2_buf databuf;
  nghttp2_frame frame;
  nghttp2_nv *nva;
  ssize_t nvlen;
  const nghttp2_frame *recv_frame;
  nghttp2_frame_hd data_hd;
  nghttp2_hd_deflater deflater;

  frame_pack_bufs_init(&bufs);
  nghttp2_buf_wrap_init(&databuf, buffer, sizeof(buffer));

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_data_chunk_recv_callback = pause_on_data_chunk_recv_callback;
  callbacks.on_header_callback = pause_on_header_callback;
  callbacks.on_begin_headers_callback = on_begin_headers_callback;

  nghttp2_session_server_new(&session, &callbacks, &user_data);

  nghttp2_hd_deflate_init(&deflater);

  /* Make 2 HEADERS frames */
  nvlen = ARRLEN(nv1);
  nghttp2_nv_array_copy(&nva, nv1, nvlen);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS, 1,
                             NGHTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  rv = nghttp2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  nghttp2_frame_headers_free(&frame.headers);

  buf = &bufs.head->buf;
  assert(nghttp2_bufs_len(&bufs) == nghttp2_buf_len(buf));

  framelen1 = nghttp2_buf_len(buf);
  databuf.last = nghttp2_cpymem(databuf.last, buf->pos, nghttp2_buf_len(buf));

  nvlen = ARRLEN(nv2);
  nghttp2_nv_array_copy(&nva, nv2, nvlen);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS, 3,
                             NGHTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  nghttp2_bufs_reset(&bufs);
  rv = nghttp2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  CU_ASSERT(0 == rv);
  CU_ASSERT(nghttp2_bufs_len(&bufs) > 0);

  nghttp2_frame_headers_free(&frame.headers);

  assert(nghttp2_bufs_len(&bufs) == nghttp2_buf_len(buf));

  framelen2 = nghttp2_buf_len(buf);
  databuf.last = nghttp2_cpymem(databuf.last, buf->pos, nghttp2_buf_len(buf));

  /* Receive 1st HEADERS and pause */
  user_data.begin_headers_cb_called = 0;
  user_data.header_cb_called = 0;
  rv = nghttp2_session_mem_recv(session,
                                databuf.pos, nghttp2_buf_len(&databuf));

  CU_ASSERT(rv >= 0);
  databuf.pos += rv;

  recv_frame = user_data.frame;
  CU_ASSERT(NGHTTP2_HEADERS == recv_frame->hd.type);
  CU_ASSERT(framelen1 - NGHTTP2_FRAME_HDLEN == recv_frame->hd.length);

  CU_ASSERT(1 == user_data.begin_headers_cb_called);
  CU_ASSERT(1 == user_data.header_cb_called);

  CU_ASSERT(nghttp2_nv_equal(&nv1[0], &user_data.nv));

  /* get 2nd header field */
  user_data.begin_headers_cb_called = 0;
  user_data.header_cb_called = 0;
  rv = nghttp2_session_mem_recv(session,
                                databuf.pos, nghttp2_buf_len(&databuf));

  CU_ASSERT(rv >= 0);
  databuf.pos += rv;

  CU_ASSERT(0 == user_data.begin_headers_cb_called);
  CU_ASSERT(1 == user_data.header_cb_called);

  CU_ASSERT(nghttp2_nv_equal(&nv1[1], &user_data.nv));

  /* will call end_headers_callback and receive 2nd HEADERS and pause */
  user_data.begin_headers_cb_called = 0;
  user_data.header_cb_called = 0;
  rv = nghttp2_session_mem_recv(session,
                                databuf.pos, nghttp2_buf_len(&databuf));

  CU_ASSERT(rv >= 0);
  databuf.pos += rv;

  recv_frame = user_data.frame;
  CU_ASSERT(NGHTTP2_HEADERS == recv_frame->hd.type);
  CU_ASSERT(framelen2 - NGHTTP2_FRAME_HDLEN == recv_frame->hd.length);

  CU_ASSERT(1 == user_data.begin_headers_cb_called);
  CU_ASSERT(1 == user_data.header_cb_called);

  CU_ASSERT(nghttp2_nv_equal(&nv2[0], &user_data.nv));

  /* get 2nd header field */
  user_data.begin_headers_cb_called = 0;
  user_data.header_cb_called = 0;
  rv = nghttp2_session_mem_recv(session,
                                databuf.pos, nghttp2_buf_len(&databuf));

  CU_ASSERT(rv >= 0);
  databuf.pos += rv;

  CU_ASSERT(0 == user_data.begin_headers_cb_called);
  CU_ASSERT(1 == user_data.header_cb_called);

  CU_ASSERT(nghttp2_nv_equal(&nv2[1], &user_data.nv));

  /* No input data, frame_recv_callback is called */
  user_data.begin_headers_cb_called = 0;
  user_data.header_cb_called = 0;
  user_data.frame_recv_cb_called = 0;
  rv = nghttp2_session_mem_recv(session,
                                databuf.pos, nghttp2_buf_len(&databuf));

  CU_ASSERT(rv >= 0);
  databuf.pos += rv;

  CU_ASSERT(0 == user_data.begin_headers_cb_called);
  CU_ASSERT(0 == user_data.header_cb_called);
  CU_ASSERT(1 == user_data.frame_recv_cb_called);

  /* Receive DATA */
  data_hd.length = 16;
  data_hd.type = NGHTTP2_DATA;
  data_hd.flags = NGHTTP2_FLAG_NONE;
  data_hd.stream_id = 1;

  nghttp2_buf_reset(&databuf);
  nghttp2_frame_pack_frame_hd(databuf.pos, &data_hd);

  /* Intentionally specify larger buffer size to see pause is kicked
     in. */
  databuf.last = databuf.end;

  user_data.frame_recv_cb_called = 0;
  rv = nghttp2_session_mem_recv(session,
                                databuf.pos, nghttp2_buf_len(&databuf));

  CU_ASSERT(16 + NGHTTP2_FRAME_HDLEN == rv);
  CU_ASSERT(0 == user_data.frame_recv_cb_called);

  /* Next nghttp2_session_mem_recv invokes on_frame_recv_callback and
     pause again in on_data_chunk_recv_callback since we pass same
     DATA frame. */
  user_data.frame_recv_cb_called = 0;
  rv = nghttp2_session_mem_recv(session,
                                databuf.pos, nghttp2_buf_len(&databuf));
  CU_ASSERT(16 + NGHTTP2_FRAME_HDLEN == rv);
  CU_ASSERT(1 == user_data.frame_recv_cb_called);

  /* And finally call on_frame_recv_callback with 0 size input */
  user_data.frame_recv_cb_called = 0;
  rv = nghttp2_session_mem_recv(session, NULL, 0);
  CU_ASSERT(0 == rv);
  CU_ASSERT(1 == user_data.frame_recv_cb_called);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_deflate_free(&deflater);
  nghttp2_session_del(session);
}

void test_nghttp2_session_add_frame(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  accumulator acc;
  my_user_data user_data;
  const nghttp2_nv nv[] = {
    MAKE_NV("method", "GET"),
    MAKE_NV("scheme", "https"),
    MAKE_NV("url", "/"),
    MAKE_NV("version", "HTTP/1.1")
  };
  nghttp2_frame *frame;
  nghttp2_headers_aux_data *aux_data =
    malloc(sizeof(nghttp2_headers_aux_data));
  nghttp2_nv *nva;
  ssize_t nvlen;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;

  memset(aux_data, 0, sizeof(nghttp2_headers_aux_data));
  acc.length = 0;
  user_data.acc = &acc;

  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, &user_data));

  frame = malloc(sizeof(nghttp2_frame));
  nvlen = ARRLEN(nv);
  nghttp2_nv_array_copy(&nva, nv, nvlen);

  nghttp2_frame_headers_init(&frame->headers,
                             NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_PRIORITY,
                             session->next_stream_id,
                             NGHTTP2_HCAT_REQUEST, NULL, nva, nvlen);

  session->next_stream_id += 2;

  CU_ASSERT(0 == nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame,
                                           aux_data));
  CU_ASSERT(0 == nghttp2_pq_empty(&session->ob_ss_pq));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NGHTTP2_HEADERS == acc.buf[3]);
  CU_ASSERT((NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_PRIORITY) ==
            acc.buf[4]);
  /* check stream id */
  CU_ASSERT(1 == nghttp2_get_uint32(&acc.buf[5]));

  nghttp2_session_del(session);
}

void test_nghttp2_session_on_request_headers_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_frame frame;
  nghttp2_stream *stream;
  int32_t stream_id = 1;
  nghttp2_nv malformed_nva[] = { MAKE_NV(":path", "\x01") };
  nghttp2_nv *nva;
  size_t nvlen;
  nghttp2_priority_spec pri_spec;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_begin_headers_callback = on_begin_headers_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  nghttp2_session_server_new(&session, &callbacks, &user_data);

  nghttp2_priority_spec_init(&pri_spec, 0, 255, 0);

  nghttp2_frame_headers_init(&frame.headers,
                             NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_PRIORITY,
                             stream_id, NGHTTP2_HCAT_REQUEST, &pri_spec,
                             NULL, 0);

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  CU_ASSERT(0 == nghttp2_session_on_request_headers_received(session, &frame));
  CU_ASSERT(1 == user_data.begin_headers_cb_called);
  stream = nghttp2_session_get_stream(session, stream_id);
  CU_ASSERT(NGHTTP2_STREAM_OPENING == stream->state);
  CU_ASSERT(255 == stream->weight);

  nghttp2_frame_headers_free(&frame.headers);

  /* More than un-ACKed max concurrent streams leads REFUSED_STREAM */
  session->pending_local_max_concurrent_stream = 1;
  nghttp2_frame_headers_init(&frame.headers,
                             NGHTTP2_FLAG_END_HEADERS |
                             NGHTTP2_FLAG_PRIORITY,
                             3, NGHTTP2_HCAT_HEADERS, NULL, NULL, 0);
  user_data.invalid_frame_recv_cb_called = 0;
  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_request_headers_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid_frame_recv_cb_called);
  CU_ASSERT(0 == (session->goaway_flags & NGHTTP2_GOAWAY_FAIL_ON_SEND));

  nghttp2_frame_headers_free(&frame.headers);
  session->local_settings.max_concurrent_streams =
    NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS;

  /* Stream ID less than or equal to the previouly received request
     HEADERS leads to connection error */
  nghttp2_frame_headers_init(&frame.headers,
                             NGHTTP2_FLAG_END_HEADERS |
                             NGHTTP2_FLAG_PRIORITY,
                             3, NGHTTP2_HCAT_HEADERS, NULL, NULL, 0);
  user_data.invalid_frame_recv_cb_called = 0;
  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_request_headers_received(session, &frame));
  CU_ASSERT(1 == user_data.invalid_frame_recv_cb_called);
  CU_ASSERT(session->goaway_flags & NGHTTP2_GOAWAY_FAIL_ON_SEND);

  nghttp2_frame_headers_free(&frame.headers);

  nghttp2_session_del(session);

  /* Check malformed headers. The library accept it. */
  nghttp2_session_server_new(&session, &callbacks, &user_data);

  nvlen = ARRLEN(malformed_nva);
  nghttp2_nv_array_copy(&nva, malformed_nva, nvlen);
  nghttp2_frame_headers_init(&frame.headers,
                             NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_PRIORITY,
                             1, NGHTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_on_request_headers_received(session, &frame));
  CU_ASSERT(1 == user_data.begin_headers_cb_called);
  CU_ASSERT(0 == user_data.invalid_frame_recv_cb_called);

  nghttp2_frame_headers_free(&frame.headers);

  nghttp2_session_del(session);
}

void test_nghttp2_session_on_response_headers_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_frame frame;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_begin_headers_callback = on_begin_headers_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  nghttp2_session_client_new(&session, &callbacks, &user_data);
  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, NULL);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS, 1,
                             NGHTTP2_HCAT_HEADERS, NULL, NULL, 0);

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  CU_ASSERT(0 == nghttp2_session_on_response_headers_received
            (session, &frame, stream));
  CU_ASSERT(1 == user_data.begin_headers_cb_called);
  CU_ASSERT(NGHTTP2_STREAM_OPENED == stream->state);

  nghttp2_frame_headers_free(&frame.headers);
  nghttp2_session_del(session);
}

void test_nghttp2_session_on_headers_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_frame frame;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_begin_headers_callback = on_begin_headers_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  nghttp2_session_client_new(&session, &callbacks, &user_data);
  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENED, NULL);
  nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS, 1,
                             NGHTTP2_HCAT_HEADERS, NULL, NULL, 0);

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  CU_ASSERT(0 == nghttp2_session_on_headers_received(session, &frame, stream));
  CU_ASSERT(1 == user_data.begin_headers_cb_called);
  CU_ASSERT(NGHTTP2_STREAM_OPENED == stream->state);

  /* stream closed */
  frame.hd.flags |= NGHTTP2_FLAG_END_STREAM;

  CU_ASSERT(0 == nghttp2_session_on_headers_received(session, &frame, stream));
  CU_ASSERT(2 == user_data.begin_headers_cb_called);

  /* Check to see when NGHTTP2_STREAM_CLOSING, incoming HEADERS is
     discarded. */
  stream = nghttp2_session_open_stream(session, 3, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_CLOSING, NULL);
  frame.hd.stream_id = 3;
  frame.hd.flags = NGHTTP2_FLAG_END_HEADERS;
  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_headers_received(session, &frame, stream));
  /* See no counters are updated */
  CU_ASSERT(2 == user_data.begin_headers_cb_called);
  CU_ASSERT(0 == user_data.invalid_frame_recv_cb_called);

  /* Server initiated stream */
  stream = nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, NULL);

  /* half closed (remote) */
  frame.hd.flags = NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_END_STREAM;
  frame.hd.stream_id = 2;

  CU_ASSERT(0 == nghttp2_session_on_headers_received(session, &frame, stream));
  CU_ASSERT(3 == user_data.begin_headers_cb_called);
  CU_ASSERT(NGHTTP2_STREAM_OPENING == stream->state);

  nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);

  /* Further reception of HEADERS is subject to stream error */
  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_headers_received(session, &frame, stream));
  CU_ASSERT(1 == user_data.invalid_frame_recv_cb_called);

  nghttp2_frame_headers_free(&frame.headers);

  nghttp2_session_del(session);
}

void test_nghttp2_session_on_push_response_headers_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_frame frame;
  nghttp2_stream *stream;
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_begin_headers_callback = on_begin_headers_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  nghttp2_session_client_new(&session, &callbacks, &user_data);
  stream = nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_RESERVED, NULL);
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS, 2,
                             NGHTTP2_HCAT_HEADERS, NULL, NULL, 0);
  /* nghttp2_session_on_push_response_headers_received assumes
     stream's state is NGHTTP2_STREAM_RESERVED and session->server is
     0. */

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  CU_ASSERT(0 == nghttp2_session_on_push_response_headers_received
            (session, &frame, stream));
  CU_ASSERT(1 == user_data.begin_headers_cb_called);
  CU_ASSERT(NGHTTP2_STREAM_OPENED == stream->state);
  CU_ASSERT(1 == session->num_incoming_streams);

  /* If un-ACKed max concurrent streams limit is exceeded,
     RST_STREAMed */
  session->pending_local_max_concurrent_stream = 1;
  stream = nghttp2_session_open_stream(session, 4, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_RESERVED, NULL);
  frame.hd.stream_id = 4;
  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_push_response_headers_received
            (session, &frame, stream));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_REFUSED_STREAM == OB_CTRL(item)->rst_stream.error_code);
  CU_ASSERT(1 == session->num_incoming_streams);

  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == session->num_incoming_streams);

  /* If ACKed max concurrent streams limit is exceeded, GOAWAY is
     issued */
  session->local_settings.max_concurrent_streams = 1;

  stream = nghttp2_session_open_stream(session, 6, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_RESERVED, NULL);
  frame.hd.stream_id = 6;

  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_push_response_headers_received
            (session, &frame, stream));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_ENHANCE_YOUR_CALM == OB_CTRL(item)->goaway.error_code);
  CU_ASSERT(1 == session->num_incoming_streams);

  nghttp2_frame_headers_free(&frame.headers);
  nghttp2_session_del(session);
}

void test_nghttp2_session_on_priority_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_frame frame;
  nghttp2_stream *stream, *dep_stream;
  nghttp2_priority_spec pri_spec;
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  nghttp2_session_server_new(&session, &callbacks, &user_data);
  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, NULL);

  nghttp2_priority_spec_init(&pri_spec, 0, 2, 0);

  nghttp2_frame_priority_init(&frame.priority, 1, &pri_spec);

  /* non-push and initiated by remote peer */
  CU_ASSERT(0 == nghttp2_session_on_priority_received(session, &frame));

  CU_ASSERT(2 == stream->weight);

  /* push and initiated by remote peer: no update */
  stream->flags = NGHTTP2_STREAM_FLAG_PUSH;

  frame.priority.pri_spec.weight = 3;

  CU_ASSERT(0 == nghttp2_session_on_priority_received(session, &frame));

  CU_ASSERT(2 == stream->weight);

  stream = nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, NULL);

  dep_stream = nghttp2_session_open_stream(session, 3,
                                           NGHTTP2_STREAM_FLAG_NONE,
                                           &pri_spec_default,
                                           NGHTTP2_STREAM_OPENING, NULL);

  frame.hd.stream_id = 2;
  /* non-push and initiated by local peer: no update */
  CU_ASSERT(0 == nghttp2_session_on_priority_received(session, &frame));

  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == stream->weight);

  /* push and initiated by local peer */
  stream->flags = NGHTTP2_STREAM_FLAG_PUSH;

  nghttp2_priority_spec_init(&frame.priority.pri_spec, 3, 1, 0);

  CU_ASSERT(0 == nghttp2_session_on_priority_received(session, &frame));
  CU_ASSERT(dep_stream == stream->dep_prev);

  nghttp2_frame_priority_free(&frame.priority);
  nghttp2_session_del(session);

  /* Check that receiving PRIORITY in reserved(remote) is error */
  nghttp2_session_server_new(&session, &callbacks, &user_data);
  nghttp2_session_open_stream(session, 3, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default,
                              NGHTTP2_STREAM_RESERVED, NULL);

  nghttp2_frame_priority_init(&frame.priority, 3, &pri_spec_default);

  user_data.frame_recv_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_on_priority_received(session, &frame));
  CU_ASSERT(0 == user_data.frame_recv_cb_called);
  CU_ASSERT(1 == user_data.invalid_frame_recv_cb_called);

  nghttp2_frame_priority_free(&frame.priority);
  nghttp2_session_del(session);

  /* Check dep_stream_id == stream_id case */
  nghttp2_session_server_new(&session, &callbacks, &user_data);
  nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default,
                              NGHTTP2_STREAM_OPENED, NULL);

  nghttp2_priority_spec_init(&pri_spec, 1, 0, 0);

  nghttp2_frame_priority_init(&frame.priority, 1, &pri_spec);

  CU_ASSERT(0 == nghttp2_session_on_priority_received(session, &frame));

  item = nghttp2_session_get_next_ob_item(session);

  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));

  nghttp2_frame_priority_free(&frame.priority);
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
  nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default,
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
  nghttp2_outbound_item *item;
  nghttp2_nv nv = MAKE_NV(":authority", "example.org");

  iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = 50;

  iv[1].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[1].value = 1000000009;

  iv[2].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[2].value = 64*1024;

  iv[3].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[3].value = 1024;

  iv[4].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
  iv[4].value = 0;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  nghttp2_session_client_new(&session, &callbacks, &user_data);
  session->remote_settings.initial_window_size = 16*1024;

  stream1 = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                        &pri_spec_default,
                                        NGHTTP2_STREAM_OPENING, NULL);
  stream2 = nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                                        &pri_spec_default,
                                        NGHTTP2_STREAM_OPENING, NULL);
  /* Set window size for each streams and will see how settings
     updates these values */
  stream1->remote_window_size = 16*1024;
  stream2->remote_window_size = -48*1024;

  nghttp2_frame_settings_init(&frame.settings, NGHTTP2_FLAG_NONE,
                              dup_iv(iv, niv), niv);

  CU_ASSERT(0 == nghttp2_session_on_settings_received(session, &frame, 0));
  CU_ASSERT(1000000009 == session->remote_settings.max_concurrent_streams);
  CU_ASSERT(64*1024 == session->remote_settings.initial_window_size);
  CU_ASSERT(1024 == session->remote_settings.header_table_size);
  CU_ASSERT(0 == session->remote_settings.enable_push);

  CU_ASSERT(64*1024 == stream1->remote_window_size);
  CU_ASSERT(0 == stream2->remote_window_size);

  frame.settings.iv[2].value = 16*1024;

  CU_ASSERT(0 == nghttp2_session_on_settings_received(session, &frame, 0));

  CU_ASSERT(16*1024 == stream1->remote_window_size);
  CU_ASSERT(-48*1024 == stream2->remote_window_size);

  nghttp2_frame_settings_free(&frame.settings);

  nghttp2_session_del(session);

  /* Check ACK with niv > 0 */
  nghttp2_session_server_new(&session, &callbacks, NULL);
  nghttp2_frame_settings_init(&frame.settings, NGHTTP2_FLAG_ACK,
                              dup_iv(iv, 1), 1);
  /* Specify inflight_iv deliberately */
  session->inflight_iv = frame.settings.iv;
  session->inflight_niv = frame.settings.niv;

  CU_ASSERT(0 == nghttp2_session_on_settings_received(session, &frame, 0));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(item != NULL);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));

  session->inflight_iv = NULL;
  session->inflight_niv = -1;

  nghttp2_frame_settings_free(&frame.settings);
  nghttp2_session_del(session);

  /* Check ACK against no inflight SETTINGS */
  nghttp2_session_server_new(&session, &callbacks, NULL);
  nghttp2_frame_settings_init(&frame.settings, NGHTTP2_FLAG_ACK, NULL, 0);

  CU_ASSERT(0 == nghttp2_session_on_settings_received(session, &frame, 0));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(item != NULL);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));

  nghttp2_frame_settings_free(&frame.settings);
  nghttp2_session_del(session);

  /* Check that 2 SETTINGS_HEADER_TABLE_SIZE 0 and 4096 are included
     and header table size is once cleared to 0. */
  nghttp2_session_client_new(&session, &callbacks, NULL);

  nghttp2_submit_request(session, NULL, &nv, 1, NULL, NULL);

  nghttp2_session_send(session);

  CU_ASSERT(session->hd_deflater.ctx.hd_table.len > 0);

  iv[0].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 0;

  iv[1].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[1].value = 2048;

  nghttp2_frame_settings_init(&frame.settings, NGHTTP2_FLAG_NONE,
                              dup_iv(iv, 2), 2);

  CU_ASSERT(0 == nghttp2_session_on_settings_received(session, &frame, 0));

  CU_ASSERT(0 == session->hd_deflater.ctx.hd_table.len);
  CU_ASSERT(2048 == session->hd_deflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(2048 == session->remote_settings.header_table_size);

  nghttp2_frame_settings_free(&frame.settings);
  nghttp2_session_del(session);
}

void test_nghttp2_session_on_push_promise_received(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data user_data;
  nghttp2_frame frame;
  nghttp2_stream *stream, *promised_stream;
  nghttp2_outbound_item *item;
  nghttp2_nv malformed_nva[] = { MAKE_NV(":path", "\x01") };
  nghttp2_nv *nva;
  size_t nvlen;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_begin_headers_callback = on_begin_headers_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  nghttp2_session_client_new(&session, &callbacks, &user_data);

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, NULL);
  nghttp2_frame_push_promise_init(&frame.push_promise,
                                  NGHTTP2_FLAG_END_HEADERS, 1, 2,
                                  NULL, 0);

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  CU_ASSERT(0 == nghttp2_session_on_push_promise_received(session, &frame));

  CU_ASSERT(1 == user_data.begin_headers_cb_called);
  promised_stream = nghttp2_session_get_stream(session, 2);
  CU_ASSERT(NGHTTP2_STREAM_RESERVED == promised_stream->state);
  CU_ASSERT(2 == session->last_recv_stream_id);

  /* Attempt to PUSH_PROMISE against half close (remote) */
  nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_RD);
  frame.push_promise.promised_stream_id = 4;

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_push_promise_received(session, &frame));

  CU_ASSERT(0 == user_data.begin_headers_cb_called);
  CU_ASSERT(1 == user_data.invalid_frame_recv_cb_called);
  CU_ASSERT(NULL == nghttp2_session_get_stream(session, 4));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(4 == OB_CTRL(item)->hd.stream_id);
  CU_ASSERT(NGHTTP2_PROTOCOL_ERROR == OB_CTRL(item)->rst_stream.error_code);
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(4 == session->last_recv_stream_id);

  /* Attempt to PUSH_PROMISE against stream in closing state */
  stream->shut_flags = NGHTTP2_SHUT_NONE;
  stream->state = NGHTTP2_STREAM_CLOSING;
  frame.push_promise.promised_stream_id = 6;

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_push_promise_received(session, &frame));

  CU_ASSERT(0 == user_data.begin_headers_cb_called);
  CU_ASSERT(NULL == nghttp2_session_get_stream(session, 6));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(6 == OB_CTRL(item)->hd.stream_id);
  CU_ASSERT(NGHTTP2_REFUSED_STREAM == OB_CTRL(item)->rst_stream.error_code);
  CU_ASSERT(0 == nghttp2_session_send(session));

  /* Attempt to PUSH_PROMISE against non-existent stream */
  frame.hd.stream_id = 3;
  frame.push_promise.promised_stream_id = 8;

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_push_promise_received(session, &frame));

  CU_ASSERT(0 == user_data.begin_headers_cb_called);
  CU_ASSERT(NULL == nghttp2_session_get_stream(session, 8));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));
  CU_ASSERT(0 == OB_CTRL(item)->hd.stream_id);
  CU_ASSERT(NGHTTP2_PROTOCOL_ERROR == OB_CTRL(item)->goaway.error_code);
  CU_ASSERT(0 == nghttp2_session_send(session));

  nghttp2_session_del(session);

  nghttp2_session_client_new(&session, &callbacks, &user_data);

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, NULL);

  /* Same ID twice */
  stream->state = NGHTTP2_STREAM_OPENING;

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_push_promise_received(session, &frame));

  CU_ASSERT(0 == user_data.begin_headers_cb_called);
  CU_ASSERT(NULL == nghttp2_session_get_stream(session, 8));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_PROTOCOL_ERROR == OB_CTRL(item)->goaway.error_code);
  CU_ASSERT(0 == nghttp2_session_send(session));

  /* After GOAWAY, PUSH_PROMISE will be discarded */
  frame.push_promise.promised_stream_id = 10;

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_push_promise_received(session, &frame));

  CU_ASSERT(0 == user_data.begin_headers_cb_called);
  CU_ASSERT(NULL == nghttp2_session_get_stream(session, 10));
  CU_ASSERT(NULL == nghttp2_session_get_next_ob_item(session));

  nghttp2_frame_push_promise_free(&frame.push_promise);
  nghttp2_session_del(session);

  nghttp2_session_client_new(&session, &callbacks, &user_data);

  stream = nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_RESERVED, NULL);
  /* Attempt to PUSH_PROMISE against reserved (remote) stream */
  nghttp2_frame_push_promise_init(&frame.push_promise,
                                  NGHTTP2_FLAG_END_HEADERS, 2, 4,
                                  NULL, 0);

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_push_promise_received(session, &frame));

  CU_ASSERT(0 == user_data.begin_headers_cb_called);
  CU_ASSERT(1 == user_data.invalid_frame_recv_cb_called);

  nghttp2_frame_push_promise_free(&frame.push_promise);
  nghttp2_session_del(session);

  /* Disable PUSH */
  nghttp2_session_client_new(&session, &callbacks, &user_data);

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, NULL);

  session->local_settings.enable_push = 0;

  nghttp2_frame_push_promise_init(&frame.push_promise,
                                  NGHTTP2_FLAG_END_HEADERS, 1, 2,
                                  NULL, 0);

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_push_promise_received(session, &frame));

  CU_ASSERT(0 == user_data.begin_headers_cb_called);
  CU_ASSERT(1 == user_data.invalid_frame_recv_cb_called);

  nghttp2_frame_push_promise_free(&frame.push_promise);
  nghttp2_session_del(session);

  /* Check malformed headers. We accept malformed headers */
  nghttp2_session_client_new(&session, &callbacks, &user_data);

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, NULL);
  nvlen = ARRLEN(malformed_nva);
  nghttp2_nv_array_copy(&nva, malformed_nva, nvlen);
  nghttp2_frame_push_promise_init(&frame.push_promise,
                                  NGHTTP2_FLAG_END_HEADERS, 1, 2,
                                  nva, nvlen);
  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_on_push_promise_received(session, &frame));

  CU_ASSERT(1 == user_data.begin_headers_cb_called);
  CU_ASSERT(0 == user_data.invalid_frame_recv_cb_called);

  nghttp2_frame_push_promise_free(&frame.push_promise);
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
  nghttp2_frame_ping_init(&frame.ping, NGHTTP2_FLAG_ACK, opaque_data);

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
  CU_ASSERT(NGHTTP2_FLAG_ACK == OB_CTRL(top)->hd.flags);
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

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENED, NULL);

  data_item = malloc(sizeof(nghttp2_outbound_item));
  memset(data_item, 0, sizeof(nghttp2_outbound_item));
  data_item->frame_cat = NGHTTP2_CAT_DATA;

  CU_ASSERT(0 == nghttp2_stream_attach_data(stream, data_item,
                                            &session->ob_pq,
                                            session->last_cycle));

  nghttp2_frame_window_update_init(&frame.window_update, NGHTTP2_FLAG_NONE,
                                   1, 16*1024);

  CU_ASSERT(0 == nghttp2_session_on_window_update_received(session, &frame));
  CU_ASSERT(1 == user_data.frame_recv_cb_called);
  CU_ASSERT(NGHTTP2_INITIAL_WINDOW_SIZE+16*1024 == stream->remote_window_size);

  CU_ASSERT(0 == nghttp2_stream_defer_data
            (stream, NGHTTP2_STREAM_FLAG_DEFERRED_FLOW_CONTROL,
             &session->ob_pq, session->last_cycle));

  CU_ASSERT(0 == nghttp2_session_on_window_update_received(session, &frame));
  CU_ASSERT(2 == user_data.frame_recv_cb_called);
  CU_ASSERT(NGHTTP2_INITIAL_WINDOW_SIZE+16*1024*2 ==
            stream->remote_window_size);
  CU_ASSERT(0 == (stream->flags & NGHTTP2_STREAM_FLAG_DEFERRED_ALL));

  nghttp2_frame_window_update_free(&frame.window_update);

  /* WINDOW_UPDATE against reserved stream is a connection error */
  stream = nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_RESERVED, NULL);

  nghttp2_frame_window_update_init(&frame.window_update, NGHTTP2_FLAG_NONE,
                                   2, 4096);

  CU_ASSERT(!(session->goaway_flags & NGHTTP2_GOAWAY_FAIL_ON_SEND));
  CU_ASSERT(0 == nghttp2_session_on_window_update_received(session, &frame));
  CU_ASSERT(session->goaway_flags & NGHTTP2_GOAWAY_FAIL_ON_SEND);

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
  nghttp2_frame frame;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));

  nghttp2_session_client_new(&session, &callbacks, &user_data);
  stream = nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, NULL);

  frame.hd.length = 4096;
  frame.hd.flags = NGHTTP2_FLAG_NONE;
  frame.hd.stream_id = 2;

  CU_ASSERT(0 == nghttp2_session_on_data_received(session, &frame));
  CU_ASSERT(0 == stream->shut_flags);

  frame.hd.flags = NGHTTP2_FLAG_END_STREAM;

  CU_ASSERT(0 == nghttp2_session_on_data_received(session, &frame));
  CU_ASSERT(NGHTTP2_SHUT_RD == stream->shut_flags);

  /* If NGHTTP2_STREAM_CLOSING state, DATA frame is discarded. */
  stream = nghttp2_session_open_stream(session, 4, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_CLOSING, NULL);

  frame.hd.flags = NGHTTP2_FLAG_NONE;
  frame.hd.stream_id = 4;

  CU_ASSERT(0 == nghttp2_session_on_data_received(session, &frame));
  CU_ASSERT(NULL == nghttp2_session_get_ob_pq_top(session));

  /* Check INVALID_STREAM case: DATA frame with stream ID which does
     not exist. */

  frame.hd.stream_id = 6;

  CU_ASSERT(0 == nghttp2_session_on_data_received(session, &frame));
  top = nghttp2_session_get_ob_pq_top(session);
  /* DATA against nonexistent stream is just ignored for now */
  CU_ASSERT(top == NULL);
  /* CU_ASSERT(NGHTTP2_RST_STREAM == OB_CTRL_TYPE(top)); */
  /* CU_ASSERT(NGHTTP2_PROTOCOL_ERROR == OB_CTRL(top)->rst_stream.error_code); */

  nghttp2_session_del(session);
}

void test_nghttp2_session_send_headers_start_stream(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_frame *frame = malloc(sizeof(nghttp2_frame));
  nghttp2_stream *stream;
  nghttp2_headers_aux_data *aux_data =
    malloc(sizeof(nghttp2_headers_aux_data));

  memset(aux_data, 0, sizeof(nghttp2_headers_aux_data));
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  nghttp2_session_client_new(&session, &callbacks, NULL);

  nghttp2_frame_headers_init(&frame->headers, NGHTTP2_FLAG_END_HEADERS,
                             session->next_stream_id,
                             NGHTTP2_HCAT_REQUEST, NULL, NULL, 0);
  session->next_stream_id += 2;

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
  nghttp2_frame *frame = malloc(sizeof(nghttp2_frame));
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, NULL));
  nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default,
                              NGHTTP2_STREAM_OPENING, NULL);
  nghttp2_frame_headers_init(&frame->headers, NGHTTP2_FLAG_END_HEADERS, 2,
                             NGHTTP2_HCAT_HEADERS, NULL, NULL, 0);
  nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  CU_ASSERT(0 == nghttp2_session_send(session));
  stream = nghttp2_session_get_stream(session, 2);
  CU_ASSERT(NGHTTP2_STREAM_OPENED == stream->state);

  nghttp2_session_del(session);
}

void test_nghttp2_session_send_headers_frame_size_error(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_frame *frame = malloc(sizeof(nghttp2_frame));
  nghttp2_nv *nva;
  ssize_t nvlen;
  size_t vallen = NGHTTP2_HD_MAX_NV;
  nghttp2_nv nv[28];
  size_t nnv = ARRLEN(nv);
  size_t i;
  my_user_data ud;

  for(i = 0; i < nnv; ++i) {
    nv[i].name = (uint8_t*)"header";
    nv[i].namelen = strlen((const char*)nv[i].name);
    nv[i].value = malloc(vallen+1);
    memset(nv[i].value, '0' + (int)i, vallen);
    nv[i].value[vallen] = '\0';
    nv[i].valuelen = vallen;
    nv[i].flags = NGHTTP2_NV_FLAG_NONE;
  }

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_not_send_callback = on_frame_not_send_callback;

  nghttp2_session_client_new(&session, &callbacks, &ud);
  nvlen = nnv;
  nghttp2_nv_array_copy(&nva, nv, nvlen);

  nghttp2_frame_headers_init(&frame->headers, NGHTTP2_FLAG_END_HEADERS,
                             session->next_stream_id,
                             NGHTTP2_HCAT_REQUEST, NULL, nva, nvlen);

  session->next_stream_id += 2;

  nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);

  ud.frame_not_send_cb_called = 0;

  CU_ASSERT(0 == nghttp2_session_send(session));

  CU_ASSERT(1 == ud.frame_not_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == ud.not_sent_frame_type);
  CU_ASSERT(NGHTTP2_ERR_FRAME_SIZE_ERROR == ud.not_sent_error);

  for(i = 0; i < nnv; ++i) {
    free(nv[i].value);
  }
  nghttp2_session_del(session);
}

void test_nghttp2_session_send_headers_push_reply(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_frame *frame = malloc(sizeof(nghttp2_frame));
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  CU_ASSERT(0 == nghttp2_session_server_new(&session, &callbacks, NULL));
  nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default,
                              NGHTTP2_STREAM_RESERVED, NULL);
  nghttp2_frame_headers_init(&frame->headers, NGHTTP2_FLAG_END_HEADERS, 2,
                             NGHTTP2_HCAT_HEADERS, NULL, NULL, 0);
  nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  CU_ASSERT(0 == session->num_outgoing_streams);
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == session->num_outgoing_streams);
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
  nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default,
                              NGHTTP2_STREAM_OPENING, NULL);

  frame = malloc(sizeof(nghttp2_frame));
  nghttp2_frame_rst_stream_init(&frame->rst_stream, 1, NGHTTP2_PROTOCOL_ERROR);
  nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  CU_ASSERT(0 == nghttp2_session_send(session));

  CU_ASSERT(NULL == nghttp2_session_get_stream(session, 1));

  nghttp2_session_del(session);
}

void test_nghttp2_session_send_push_promise(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_frame *frame = malloc(sizeof(nghttp2_frame));
  nghttp2_stream *stream;
  nghttp2_settings_entry iv;
  my_user_data ud;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_not_send_callback = on_frame_not_send_callback;

  nghttp2_session_server_new(&session, &callbacks, &ud);
  nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, NGHTTP2_STREAM_OPENING,
                              NULL);
  nghttp2_frame_push_promise_init(&frame->push_promise,
                                  NGHTTP2_FLAG_END_HEADERS, 1,
                                  session->next_stream_id,
                                  NULL, 0);

  session->next_stream_id += 2;

  nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);

  CU_ASSERT(0 == nghttp2_session_send(session));
  stream = nghttp2_session_get_stream(session, 2);
  CU_ASSERT(NGHTTP2_STREAM_RESERVED == stream->state);

  /* Received ENABLE_PUSH = 0 */
  iv.settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
  iv.value = 0;
  frame = malloc(sizeof(nghttp2_frame));
  nghttp2_frame_settings_init(&frame->settings, NGHTTP2_FLAG_NONE,
                              dup_iv(&iv, 1), 1);
  nghttp2_session_on_settings_received(session, frame, 1);
  nghttp2_frame_settings_free(&frame->settings);
  free(frame);

  frame = malloc(sizeof(nghttp2_frame));
  nghttp2_frame_push_promise_init(&frame->push_promise,
                                  NGHTTP2_FLAG_END_HEADERS, 1, -1,
                                  NULL, 0);
  nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);
  ud.frame_not_send_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_send(session));

  CU_ASSERT(1 == ud.frame_not_send_cb_called);
  CU_ASSERT(NGHTTP2_PUSH_PROMISE == ud.not_sent_frame_type);
  CU_ASSERT(NGHTTP2_ERR_PUSH_DISABLED == ud.not_sent_error);

  nghttp2_session_del(session);

  /* PUSH_PROMISE from client is error */
  nghttp2_session_client_new(&session, &callbacks, &ud);
  nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, NGHTTP2_STREAM_OPENING,
                              NULL);
  frame = malloc(sizeof(nghttp2_frame));
  nghttp2_frame_push_promise_init(&frame->push_promise,
                                  NGHTTP2_FLAG_END_HEADERS, 1, -1,
                                  NULL, 0);
  nghttp2_session_add_frame(session, NGHTTP2_CAT_CTRL, frame, NULL);

  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NULL == nghttp2_session_get_stream(session, 3));

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

void test_nghttp2_session_upgrade(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  uint8_t settings_payload[128];
  size_t settings_payloadlen;
  nghttp2_settings_entry iv[16];
  nghttp2_stream *stream;
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = 1;
  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 4095;
  settings_payloadlen = nghttp2_pack_settings_payload(settings_payload,
                                                      sizeof(settings_payload),
                                                      iv, 2);

  /* Check client side */
  nghttp2_session_client_new(&session, &callbacks, NULL);
  CU_ASSERT(0 == nghttp2_session_upgrade(session, settings_payload,
                                         settings_payloadlen, &callbacks));
  stream = nghttp2_session_get_stream(session, 1);
  CU_ASSERT(stream != NULL);
  CU_ASSERT(&callbacks == stream->stream_user_data);
  CU_ASSERT(NGHTTP2_SHUT_WR == stream->shut_flags);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_SETTINGS == OB_CTRL_TYPE(item));
  CU_ASSERT(2 == OB_CTRL(item)->settings.niv);
  CU_ASSERT(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS ==
            OB_CTRL(item)->settings.iv[0].settings_id);
  CU_ASSERT(1 == OB_CTRL(item)->settings.iv[0].value);
  CU_ASSERT(NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE ==
            OB_CTRL(item)->settings.iv[1].settings_id);
  CU_ASSERT(4095 == OB_CTRL(item)->settings.iv[1].value);

  /* Call nghttp2_session_upgrade() again is error */
  CU_ASSERT(NGHTTP2_ERR_PROTO == nghttp2_session_upgrade(session,
                                                         settings_payload,
                                                         settings_payloadlen,
                                                         &callbacks));
  nghttp2_session_del(session);

  /* Check server side */
  nghttp2_session_server_new(&session, &callbacks, NULL);
  CU_ASSERT(0 == nghttp2_session_upgrade(session, settings_payload,
                                         settings_payloadlen, &callbacks));
  stream = nghttp2_session_get_stream(session, 1);
  CU_ASSERT(stream != NULL);
  CU_ASSERT(NULL == stream->stream_user_data);
  CU_ASSERT(NGHTTP2_SHUT_RD == stream->shut_flags);
  CU_ASSERT(NULL == nghttp2_session_get_next_ob_item(session));
  CU_ASSERT(1 == session->remote_settings.max_concurrent_streams);
  CU_ASSERT(4095 == session->remote_settings.initial_window_size);
  /* Call nghttp2_session_upgrade() again is error */
  CU_ASSERT(NGHTTP2_ERR_PROTO == nghttp2_session_upgrade(session,
                                                         settings_payload,
                                                         settings_payloadlen,
                                                         &callbacks));
  nghttp2_session_del(session);

  /* Empty SETTINGS is OK */
  settings_payloadlen = nghttp2_pack_settings_payload(settings_payload,
                                                      sizeof(settings_payload),
                                                      NULL, 0);

  nghttp2_session_client_new(&session, &callbacks, NULL);
  CU_ASSERT(0 == nghttp2_session_upgrade(session, settings_payload,
                                         settings_payloadlen, NULL));
  nghttp2_session_del(session);
}

void test_nghttp2_session_reprioritize_stream(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data ud;
  nghttp2_stream *stream;
  nghttp2_stream *dep_stream;
  nghttp2_priority_spec pri_spec;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = block_count_send_callback;

  nghttp2_session_server_new(&session, &callbacks, &ud);

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, NULL);

  nghttp2_priority_spec_init(&pri_spec, 0, 10, 0);

  nghttp2_session_reprioritize_stream(session, stream, &pri_spec);

  CU_ASSERT(10 == stream->weight);
  CU_ASSERT(NULL == stream->dep_prev);

  /* dep_stream does not exist */

  nghttp2_priority_spec_init(&pri_spec, 3, 99, 0);

  nghttp2_session_reprioritize_stream(session, stream, &pri_spec);

  CU_ASSERT(10 == stream->weight);
  CU_ASSERT(NULL == stream->dep_prev);

  dep_stream = open_stream(session, 3);

  nghttp2_session_reprioritize_stream(session, stream, &pri_spec);

  CU_ASSERT(99 == stream->weight);
  CU_ASSERT(dep_stream == stream->dep_prev);

  /* Test circular dependency; stream 1 is first removed and becomes
     root.  Then stream 3 depends on it. */
  nghttp2_priority_spec_init(&pri_spec, 1, 1, 0);

  nghttp2_session_reprioritize_stream(session, dep_stream, &pri_spec);

  CU_ASSERT(1 == dep_stream->weight);
  CU_ASSERT(stream == dep_stream->dep_prev);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_data(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_data_provider data_prd;
  my_user_data ud;
  nghttp2_private_data *data_frame;
  nghttp2_frame_hd hd;
  nghttp2_active_outbound_item *aob;
  nghttp2_bufs *framebufs;
  nghttp2_buf *buf;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = block_count_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = NGHTTP2_DATA_PAYLOADLEN * 2;
  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, &ud));
  aob = &session->aob;
  framebufs = &aob->framebufs;

  nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, NGHTTP2_STREAM_OPENING,
                              NULL);
  CU_ASSERT(0 == nghttp2_submit_data(session,
                                     NGHTTP2_FLAG_END_STREAM |
                                     NGHTTP2_FLAG_END_SEGMENT, 1, &data_prd));

  ud.block_count = 0;
  CU_ASSERT(0 == nghttp2_session_send(session));
  data_frame = nghttp2_outbound_item_get_data_frame(aob->item);

  buf = &framebufs->head->buf;
  nghttp2_frame_unpack_frame_hd(&hd, buf->pos);

  CU_ASSERT(NGHTTP2_FLAG_NONE == hd.flags);
  /* frame->hd.flags has these flags */
  CU_ASSERT((NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_SEGMENT) ==
            data_frame->hd.flags);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_request_with_data(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_nv nva[] = {
    MAKE_NV(":version", "HTTP/1.1")
  };
  nghttp2_data_provider data_prd;
  my_user_data ud;
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 64*1024 - 1;
  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, &ud));
  CU_ASSERT(1 == nghttp2_submit_request(session, NULL,
                                        nva, ARRLEN(nva), &data_prd, NULL));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(nvnameeq(":version", &OB_CTRL(item)->headers.nva[0]));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == ud.data_source_length);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_request_without_data(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  accumulator acc;
  nghttp2_nv nva[] = {
    MAKE_NV(":version", "HTTP/1.1")
  };
  nghttp2_data_provider data_prd = {{-1}, NULL};
  nghttp2_outbound_item *item;
  my_user_data ud;
  nghttp2_frame frame;
  nghttp2_hd_inflater inflater;
  nva_out out;
  nghttp2_bufs bufs;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  acc.length = 0;
  ud.acc = &acc;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;
  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, &ud));

  nghttp2_hd_inflate_init(&inflater);
  CU_ASSERT(1 == nghttp2_submit_request(session, NULL,
                                        nva, ARRLEN(nva), &data_prd, NULL));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(nvnameeq(":version", &OB_CTRL(item)->headers.nva[0]));
  CU_ASSERT(OB_CTRL(item)->hd.flags & NGHTTP2_FLAG_END_STREAM);

  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == unpack_frame(&frame, acc.buf, acc.length));

  nghttp2_bufs_add(&bufs, acc.buf, acc.length);
  inflate_hd(&inflater, &out, &bufs, NGHTTP2_FRAME_HDLEN);

  CU_ASSERT(nvnameeq(":version", &out.nva[0]));
  nghttp2_frame_headers_free(&frame.headers);
  nva_out_reset(&out);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_session_del(session);
}

void test_nghttp2_submit_response_with_data(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_nv nva[] = {
    MAKE_NV(":version", "HTTP/1.1")
  };
  nghttp2_data_provider data_prd;
  my_user_data ud;
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 64*1024 - 1;
  CU_ASSERT(0 == nghttp2_session_server_new(&session, &callbacks, &ud));
  nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_END_STREAM,
                              &pri_spec_default,
                              NGHTTP2_STREAM_OPENING, NULL);
  CU_ASSERT(0 == nghttp2_submit_response(session, 1, nva, ARRLEN(nva),
                                         &data_prd));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(nvnameeq(":version", &OB_CTRL(item)->headers.nva[0]));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == ud.data_source_length);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_response_without_data(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  accumulator acc;
  nghttp2_nv nva[] = {
    MAKE_NV(":version", "HTTP/1.1")
  };
  nghttp2_data_provider data_prd = {{-1}, NULL};
  nghttp2_outbound_item *item;
  my_user_data ud;
  nghttp2_frame frame;
  nghttp2_hd_inflater inflater;
  nva_out out;
  nghttp2_bufs bufs;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  acc.length = 0;
  ud.acc = &acc;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;
  CU_ASSERT(0 == nghttp2_session_server_new(&session, &callbacks, &ud));

  nghttp2_hd_inflate_init(&inflater);
  nghttp2_session_open_stream(session, 1, NGHTTP2_FLAG_END_STREAM,
                              &pri_spec_default,
                              NGHTTP2_STREAM_OPENING, NULL);
  CU_ASSERT(0 == nghttp2_submit_response(session, 1, nva, ARRLEN(nva),
                                         &data_prd));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(nvnameeq(":version", &OB_CTRL(item)->headers.nva[0]));
  CU_ASSERT(OB_CTRL(item)->hd.flags & NGHTTP2_FLAG_END_STREAM);

  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == unpack_frame(&frame, acc.buf, acc.length));

  nghttp2_bufs_add(&bufs, acc.buf, acc.length);
  inflate_hd(&inflater, &out, &bufs, NGHTTP2_FRAME_HDLEN);

  CU_ASSERT(nvnameeq(":version", &out.nva[0]));

  nva_out_reset(&out);
  nghttp2_bufs_free(&bufs);
  nghttp2_frame_headers_free(&frame.headers);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_session_del(session);
}

void test_nghttp2_submit_headers_start_stream(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const nghttp2_nv nv[] = {
    MAKE_NV(":version", "HTTP/1.1")
  };
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, NULL));
  CU_ASSERT(1 == nghttp2_submit_headers(session,
                                        NGHTTP2_FLAG_END_STREAM,
                                        -1, NULL,
                                        nv, ARRLEN(nv), NULL));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(nvnameeq(":version", &OB_CTRL(item)->headers.nva[0]));
  CU_ASSERT((NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_END_STREAM) ==
            OB_CTRL(item)->hd.flags);
  CU_ASSERT(0 == (OB_CTRL(item)->hd.flags & NGHTTP2_FLAG_PRIORITY));

  nghttp2_session_del(session);
}

void test_nghttp2_submit_headers_reply(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const nghttp2_nv nv[] = {
    MAKE_NV(":version", "HTTP/1.1")
  };
  my_user_data ud;
  nghttp2_outbound_item *item;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  CU_ASSERT(0 == nghttp2_session_server_new(&session, &callbacks, &ud));
  CU_ASSERT(0 == nghttp2_submit_headers(session,
                                        NGHTTP2_FLAG_END_STREAM,
                                        1, NULL,
                                        nv, ARRLEN(nv), NULL));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(nvnameeq(":version", &OB_CTRL(item)->headers.nva[0]));
  CU_ASSERT((NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_HEADERS) ==
            OB_CTRL(item)->hd.flags);

  ud.frame_send_cb_called = 0;
  ud.sent_frame_type = 0;
  /* The transimission will be canceled because the stream 1 is not
     open. */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == ud.frame_send_cb_called);

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, NULL);

  CU_ASSERT(0 == nghttp2_submit_headers(session,
                                        NGHTTP2_FLAG_END_STREAM,
                                        1, NULL,
                                        nv, ARRLEN(nv), NULL));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == ud.frame_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == ud.sent_frame_type);
  CU_ASSERT(stream->shut_flags & NGHTTP2_SHUT_WR);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_headers_push_reply(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const nghttp2_nv nv[] = {
    MAKE_NV(":version", "HTTP/1.1")
  };
  my_user_data ud;
  nghttp2_stream *stream;
  int foo;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  CU_ASSERT(0 == nghttp2_session_server_new(&session, &callbacks, &ud));
  stream = nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_RESERVED, NULL);
  CU_ASSERT(0 == nghttp2_submit_headers(session,
                                        NGHTTP2_FLAG_NONE,
                                        2, NULL,
                                        nv, ARRLEN(nv), &foo));

  ud.frame_send_cb_called = 0;
  ud.sent_frame_type = 0;
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == ud.frame_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == ud.sent_frame_type);
  CU_ASSERT(NGHTTP2_STREAM_OPENED == stream->state);
  CU_ASSERT(&foo == stream->stream_user_data);

  nghttp2_session_del(session);

  /* Sending HEADERS from client against stream in reserved state is
     error */
  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, &ud));
  stream = nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_RESERVED, NULL);
  CU_ASSERT(0 == nghttp2_submit_headers(session,
                                        NGHTTP2_FLAG_NONE,
                                        2, NULL,
                                        nv, ARRLEN(nv), NULL));

  ud.frame_send_cb_called = 0;
  ud.sent_frame_type = 0;
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == ud.frame_send_cb_called);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_headers(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const nghttp2_nv nv[] = {
    MAKE_NV(":version", "HTTP/1.1")
  };
  my_user_data ud;
  nghttp2_outbound_item *item;
  nghttp2_stream *stream;
  accumulator acc;
  nghttp2_frame frame;
  nghttp2_hd_inflater inflater;
  nva_out out;
  nghttp2_bufs bufs;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  acc.length = 0;
  ud.acc = &acc;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, &ud));

  nghttp2_hd_inflate_init(&inflater);
  CU_ASSERT(0 == nghttp2_submit_headers(session,
                                        NGHTTP2_FLAG_END_STREAM,
                                        1, NULL,
                                        nv, ARRLEN(nv), NULL));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(nvnameeq(":version", &OB_CTRL(item)->headers.nva[0]));
  CU_ASSERT((NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_HEADERS) ==
            OB_CTRL(item)->hd.flags);

  ud.frame_send_cb_called = 0;
  ud.sent_frame_type = 0;
  /* The transimission will be canceled because the stream 1 is not
     open. */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == ud.frame_send_cb_called);

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, NULL);

  CU_ASSERT(0 == nghttp2_submit_headers(session,
                                        NGHTTP2_FLAG_END_STREAM,
                                        1, NULL,
                                        nv, ARRLEN(nv), NULL));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == ud.frame_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == ud.sent_frame_type);
  CU_ASSERT(stream->shut_flags & NGHTTP2_SHUT_WR);

  CU_ASSERT(0 == unpack_frame(&frame, acc.buf, acc.length));

  nghttp2_bufs_add(&bufs, acc.buf, acc.length);
  inflate_hd(&inflater, &out, &bufs, NGHTTP2_FRAME_HDLEN);

  CU_ASSERT(nvnameeq(":version", &out.nva[0]));

  nva_out_reset(&out);
  nghttp2_bufs_free(&bufs);
  nghttp2_frame_headers_free(&frame.headers);

  nghttp2_hd_inflate_free(&inflater);
  nghttp2_session_del(session);
}

void test_nghttp2_submit_headers_continuation(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_nv nv[] = {
    MAKE_NV("h1", ""),
    MAKE_NV("h1", ""),
    MAKE_NV("h1", ""),
    MAKE_NV("h1", ""),
    MAKE_NV("h1", ""),
    MAKE_NV("h1", ""),
    MAKE_NV("h1", ""),
  };
  nghttp2_outbound_item *item;
  uint8_t data[4096];
  size_t i;
  my_user_data ud;

  memset(data, '0', sizeof(data));
  for(i = 0; i < ARRLEN(nv); ++i) {
    nv[i].valuelen = sizeof(data);
    nv[i].value = data;
  }

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, &ud));
  CU_ASSERT(1 == nghttp2_submit_headers(session,
                                        NGHTTP2_FLAG_END_STREAM,
                                        -1, NULL,
                                        nv, ARRLEN(nv), NULL));
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_HEADERS == OB_CTRL_TYPE(item));
  CU_ASSERT((NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_HEADERS) ==
            OB_CTRL(item)->hd.flags);
  CU_ASSERT(0 == (OB_CTRL(item)->hd.flags & NGHTTP2_FLAG_PRIORITY));

  ud.frame_send_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == ud.frame_send_cb_called);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_priority(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_stream *stream;
  my_user_data ud;
  nghttp2_priority_spec pri_spec;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.on_frame_not_send_callback = on_frame_not_send_callback;

  nghttp2_session_client_new(&session, &callbacks, &ud);
  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, NULL);

  nghttp2_priority_spec_init(&pri_spec, 0, 3, 0);

  /* non-push stream and initiated by local peer */
  CU_ASSERT(0 == nghttp2_submit_priority(session, NGHTTP2_FLAG_NONE, 1,
                                         &pri_spec));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(3 == stream->weight);

  /* push stream and initiated by local peer: no update */
  stream->flags = NGHTTP2_STREAM_FLAG_PUSH;

  nghttp2_priority_spec_init(&pri_spec, 0, 2, 0);

  CU_ASSERT(0 == nghttp2_submit_priority(session, NGHTTP2_FLAG_NONE, 1,
                                         &pri_spec));
  CU_ASSERT(0 == nghttp2_session_send(session));

  CU_ASSERT(3 == stream->weight);

  /* non-push stream and initiated by remote peer: no update */
  stream = nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, NULL);
  CU_ASSERT(0 == nghttp2_submit_priority(session, NGHTTP2_FLAG_NONE, 2,
                                         &pri_spec));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == stream->weight);

  /* push stream and initiated by remote peer */
  stream->flags = NGHTTP2_STREAM_FLAG_PUSH;
  CU_ASSERT(0 == nghttp2_submit_priority(session, NGHTTP2_FLAG_NONE, 2,
                                         &pri_spec));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(2 == stream->weight);

  nghttp2_session_del(session);

  /* Check that transmission of PRIORITY in reserved(local) is
     error */
  nghttp2_session_server_new(&session, &callbacks, &ud);
  stream = nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_RESERVED, NULL);

  CU_ASSERT(0 == nghttp2_submit_priority(session, NGHTTP2_FLAG_NONE, 2,
                                         &pri_spec));

  ud.frame_send_cb_called = 0;
  ud.frame_not_send_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == ud.frame_send_cb_called);
  CU_ASSERT(1 == ud.frame_not_send_cb_called);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_settings(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data ud;
  nghttp2_outbound_item *item;
  nghttp2_frame *frame;
  nghttp2_settings_entry iv[6];
  nghttp2_frame ack_frame;

  iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = 5;

  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 16*1024;

  iv[2].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[2].value = 50;

  iv[3].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[3].value = 0;

  iv[4].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[4].value = (uint32_t)NGHTTP2_MAX_WINDOW_SIZE + 1;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  nghttp2_session_server_new(&session, &callbacks, &ud);

  CU_ASSERT(NGHTTP2_ERR_INVALID_ARGUMENT ==
            nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 5));

  /* Make sure that local settings are not changed */
  CU_ASSERT(NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS ==
            session->local_settings.max_concurrent_streams);
  CU_ASSERT(NGHTTP2_INITIAL_WINDOW_SIZE ==
            session->local_settings.initial_window_size);

  /* Now sends without 5th one */
  CU_ASSERT(0 == nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 4));

  item = nghttp2_session_get_next_ob_item(session);

  CU_ASSERT(NGHTTP2_SETTINGS == OB_CTRL_TYPE(item));

  frame = item->frame;
  CU_ASSERT(4 == frame->settings.niv);
  CU_ASSERT(5 == frame->settings.iv[0].value);
  CU_ASSERT(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS ==
            frame->settings.iv[0].settings_id);

  CU_ASSERT(16*1024 == frame->settings.iv[1].value);
  CU_ASSERT(NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE ==
            frame->settings.iv[1].settings_id);

  ud.frame_send_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == ud.frame_send_cb_called);

  CU_ASSERT(50 == session->pending_local_max_concurrent_stream);

  nghttp2_frame_settings_init(&ack_frame.settings, NGHTTP2_FLAG_ACK, NULL, 0);
  CU_ASSERT(0 == nghttp2_session_on_settings_received(session, &ack_frame, 0));
  nghttp2_frame_settings_free(&ack_frame.settings);

  CU_ASSERT(16*1024 == session->local_settings.initial_window_size);
  CU_ASSERT(0 == session->hd_inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(50 == session->local_settings.max_concurrent_streams);
  CU_ASSERT(NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS ==
            session->pending_local_max_concurrent_stream);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_settings_update_local_window_size(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_outbound_item *item;
  nghttp2_settings_entry iv[4];
  nghttp2_stream *stream;
  nghttp2_frame ack_frame;

  nghttp2_frame_settings_init(&ack_frame.settings, NGHTTP2_FLAG_ACK, NULL, 0);

  iv[0].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[0].value = 16*1024;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  nghttp2_session_server_new(&session, &callbacks, NULL);

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENED, NULL);
  stream->local_window_size = NGHTTP2_INITIAL_WINDOW_SIZE + 100;
  stream->recv_window_size = 32768;

  stream = nghttp2_session_open_stream(session, 3, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENED, NULL);

  CU_ASSERT(0 == nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 1));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == nghttp2_session_on_settings_received(session, &ack_frame, 0));

  stream = nghttp2_session_get_stream(session, 1);
  CU_ASSERT(0 == stream->recv_window_size);
  CU_ASSERT(16*1024 + 100 == stream->local_window_size);

  stream = nghttp2_session_get_stream(session, 3);
  CU_ASSERT(16*1024 == stream->local_window_size);

  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_WINDOW_UPDATE == OB_CTRL_TYPE(item));
  CU_ASSERT(32768 == OB_CTRL(item)->window_update.window_size_increment);

  nghttp2_session_del(session);

  /* Check overflow case */
  iv[0].value = 128*1024;
  nghttp2_session_server_new(&session, &callbacks, NULL);
  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENED, NULL);
  stream->local_window_size = NGHTTP2_MAX_WINDOW_SIZE;

  CU_ASSERT(0 == nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 1));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(0 == nghttp2_session_on_settings_received(session, &ack_frame, 0));


  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_FLOW_CONTROL_ERROR == OB_CTRL(item)->goaway.error_code);

  nghttp2_session_del(session);
  nghttp2_frame_settings_free(&ack_frame.settings);
}

void test_nghttp2_submit_push_promise(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const nghttp2_nv nv[] = {
    MAKE_NV(":version", "HTTP/1.1")
  };
  my_user_data ud;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  CU_ASSERT(0 == nghttp2_session_server_new(&session, &callbacks, &ud));
  nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default,
                              NGHTTP2_STREAM_OPENING, NULL);
  CU_ASSERT(2 == nghttp2_submit_push_promise(session, NGHTTP2_FLAG_NONE, 1,
                                             nv, ARRLEN(nv), &ud));

  ud.frame_send_cb_called = 0;
  ud.sent_frame_type = 0;
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == ud.frame_send_cb_called);
  CU_ASSERT(NGHTTP2_PUSH_PROMISE == ud.sent_frame_type);
  stream = nghttp2_session_get_stream(session, 2);
  CU_ASSERT(NGHTTP2_STREAM_RESERVED == stream->state);
  CU_ASSERT(&ud == nghttp2_session_get_stream_user_data(session, 2));

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
                                       NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
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

  CU_ASSERT(0 ==
            nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 2, 0));
  /* It is ok if stream is closed or does not exist at the call
     time */
  CU_ASSERT(0 ==
            nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 4, 4096));

  nghttp2_session_del(session);
}

void test_nghttp2_submit_window_update_local_window_size(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_outbound_item *item;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  nghttp2_session_client_new(&session, &callbacks, NULL);
  stream = nghttp2_session_open_stream(session, 2,
                                       NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENED, NULL);
  stream->recv_window_size = 4096;

  CU_ASSERT(0 == nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 2,
                                              stream->recv_window_size + 1));
  CU_ASSERT(NGHTTP2_INITIAL_WINDOW_SIZE + 1 == stream->local_window_size);
  CU_ASSERT(0 == stream->recv_window_size);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_WINDOW_UPDATE == OB_CTRL_TYPE(item));
  CU_ASSERT(4097 == OB_CTRL(item)->window_update.window_size_increment);

  CU_ASSERT(0 == nghttp2_session_send(session));

  /* Let's decrement local window size */
  stream->recv_window_size = 4096;
  CU_ASSERT(0 == nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 2,
                                              -stream->local_window_size / 2));
  CU_ASSERT(32768 == stream->local_window_size);
  CU_ASSERT(-28672 == stream->recv_window_size);
  CU_ASSERT(32768 == stream->recv_reduction);

  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(item == NULL);

  /* Increase local window size */
  CU_ASSERT(0 == nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 2,
                                              16384));
  CU_ASSERT(49152 == stream->local_window_size);
  CU_ASSERT(-12288 == stream->recv_window_size);
  CU_ASSERT(16384 == stream->recv_reduction);
  CU_ASSERT(NULL == nghttp2_session_get_next_ob_item(session));

  CU_ASSERT(NGHTTP2_ERR_FLOW_CONTROL ==
            nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 2,
                                         NGHTTP2_MAX_WINDOW_SIZE));

  CU_ASSERT(0 == nghttp2_session_send(session));

  /* Check connection-level flow control */
  session->recv_window_size = 4096;
  CU_ASSERT(0 == nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 0,
                                              session->recv_window_size + 1));
  CU_ASSERT(NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE + 1 ==
            session->local_window_size);
  CU_ASSERT(0 == session->recv_window_size);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_WINDOW_UPDATE == OB_CTRL_TYPE(item));
  CU_ASSERT(4097 == OB_CTRL(item)->window_update.window_size_increment);

  CU_ASSERT(0 == nghttp2_session_send(session));

  /* Go decrement part */
  session->recv_window_size = 4096;
  CU_ASSERT(0 == nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 0,
                                              -session->local_window_size/2));
  CU_ASSERT(32768 == session->local_window_size);
  CU_ASSERT(-28672 == session->recv_window_size);
  CU_ASSERT(32768 == session->recv_reduction);
  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(item == NULL);

  /* Increase local window size */
  CU_ASSERT(0 == nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 0,
                                              16384));
  CU_ASSERT(49152 == session->local_window_size);
  CU_ASSERT(-12288 == session->recv_window_size);
  CU_ASSERT(16384 == session->recv_reduction);
  CU_ASSERT(NULL == nghttp2_session_get_next_ob_item(session));

  CU_ASSERT(NGHTTP2_ERR_FLOW_CONTROL ==
            nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 0,
                                         NGHTTP2_MAX_WINDOW_SIZE));

  nghttp2_session_del(session);
}

void test_nghttp2_submit_altsvc(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  const char protocol_id[] = "h2";
  const char host[] = "localhost";
  const char origin[] = "http://localhost/";
  nghttp2_frame *frame;
  nghttp2_ext_altsvc *altsvc;
  nghttp2_outbound_item *item;
  my_user_data ud;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  nghttp2_session_client_new(&session, &callbacks, NULL);

  CU_ASSERT(NGHTTP2_ERR_PROTO ==
            nghttp2_submit_altsvc(session, NGHTTP2_FLAG_NONE,
                                  0, 0, 3000,
                                  (const uint8_t*)protocol_id,
                                  strlen(protocol_id),
                                  (const uint8_t*)host, strlen(host),
                                  (const uint8_t*)origin, strlen(origin)));

  nghttp2_session_del(session);

  nghttp2_session_server_new(&session, &callbacks, &ud);

  open_stream(session, 9);

  CU_ASSERT(0 ==
            nghttp2_submit_altsvc(session, NGHTTP2_FLAG_NONE,
                                  9, 12345, 3000,
                                  (const uint8_t*)protocol_id,
                                  strlen(protocol_id),
                                  (const uint8_t*)host, strlen(host),
                                  (const uint8_t*)origin, strlen(origin)));

  item = nghttp2_session_get_next_ob_item(session);

  frame = OB_CTRL(item);

  CU_ASSERT(NGHTTP2_EXT_ALTSVC == frame->hd.type);
  CU_ASSERT(9 == frame->hd.stream_id);

  altsvc = frame->ext.payload;

  CU_ASSERT(12345 == altsvc->max_age);
  CU_ASSERT(3000 == altsvc->port);

  CU_ASSERT(strlen(protocol_id) == altsvc->protocol_id_len);
  CU_ASSERT(strlen(host) == altsvc->host_len);
  CU_ASSERT(strlen(origin) == altsvc->origin_len);

  CU_ASSERT(0 == memcmp(protocol_id, altsvc->protocol_id,
                        altsvc->protocol_id_len));
  CU_ASSERT(0 == memcmp(host, altsvc->host, altsvc->host_len));
  CU_ASSERT(0 == memcmp(origin, altsvc->origin,
                        altsvc->origin_len));

  ud.frame_send_cb_called = 0;

  CU_ASSERT(0 == nghttp2_session_send(session));

  CU_ASSERT(1 == ud.frame_send_cb_called);
  CU_ASSERT(NGHTTP2_EXT_ALTSVC == ud.sent_frame_type);

  nghttp2_session_del(session);
}

void test_nghttp2_submit_invalid_nv(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_nv empty_name_nv[] = {
    MAKE_NV("Version", "HTTP/1.1"),
    MAKE_NV("", "empty name")
  };

  /* Now invalid header name/value pair in HTTP/1.1 is accepted in
     nghttp2 */

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));

  CU_ASSERT(0 == nghttp2_session_server_new(&session, &callbacks, NULL));

  /* nghttp2_submit_request */
  CU_ASSERT(0 <
            nghttp2_submit_request(session, NULL,
                                   empty_name_nv, ARRLEN(empty_name_nv),
                                   NULL, NULL));

  /* nghttp2_submit_response */
  CU_ASSERT(0 ==
            nghttp2_submit_response(session, 2,
                                    empty_name_nv, ARRLEN(empty_name_nv),
                                    NULL));

  /* nghttp2_submit_headers */
  CU_ASSERT(0 <
            nghttp2_submit_headers(session, NGHTTP2_FLAG_NONE, -1,
                                   NULL,
                                   empty_name_nv, ARRLEN(empty_name_nv),
                                   NULL));

  /* nghttp2_submit_push_promise */
  CU_ASSERT(0 <
            nghttp2_submit_push_promise(session, NGHTTP2_FLAG_NONE, 2,
                                        empty_name_nv, ARRLEN(empty_name_nv),
                                        NULL));

  nghttp2_session_del(session);
}

void test_nghttp2_session_open_stream(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_stream *stream;
  nghttp2_priority_spec pri_spec;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  nghttp2_session_server_new(&session, &callbacks, NULL);

  nghttp2_priority_spec_init(&pri_spec, 0, 245, 0);

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec, NGHTTP2_STREAM_OPENED,
                                       NULL);
  CU_ASSERT(1 == session->num_incoming_streams);
  CU_ASSERT(0 == session->num_outgoing_streams);
  CU_ASSERT(NGHTTP2_STREAM_OPENED == stream->state);
  CU_ASSERT(245 == stream->weight);
  CU_ASSERT(NULL == stream->dep_prev);
  CU_ASSERT(NGHTTP2_SHUT_NONE == stream->shut_flags);

  stream = nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING,
                                       NULL);
  CU_ASSERT(1 == session->num_incoming_streams);
  CU_ASSERT(1 == session->num_outgoing_streams);
  CU_ASSERT(NULL == stream->dep_prev);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == stream->weight);
  CU_ASSERT(NGHTTP2_SHUT_NONE == stream->shut_flags);

  stream = nghttp2_session_open_stream(session, 4, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_RESERVED,
                                       NULL);
  CU_ASSERT(1 == session->num_incoming_streams);
  CU_ASSERT(1 == session->num_outgoing_streams);
  CU_ASSERT(NULL == stream->dep_prev);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == stream->weight);
  CU_ASSERT(NGHTTP2_SHUT_RD == stream->shut_flags);

  nghttp2_priority_spec_init(&pri_spec, 1, 17, 1);

  stream = nghttp2_session_open_stream(session, 3, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec, NGHTTP2_STREAM_OPENED,
                                       NULL);
  CU_ASSERT(17 == stream->weight);
  CU_ASSERT(1 == stream->dep_prev->stream_id);

  nghttp2_session_del(session);

  nghttp2_session_client_new(&session, &callbacks, NULL);
  stream = nghttp2_session_open_stream(session, 4, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_RESERVED,
                                       NULL);
  CU_ASSERT(0 == session->num_incoming_streams);
  CU_ASSERT(0 == session->num_outgoing_streams);
  CU_ASSERT(NULL == stream->dep_prev);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == stream->weight);
  CU_ASSERT(NGHTTP2_SHUT_WR == stream->shut_flags);

  nghttp2_session_del(session);
}

void test_nghttp2_session_get_next_ob_item(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_priority_spec pri_spec;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  nghttp2_session_server_new(&session, &callbacks, NULL);
  session->remote_settings.max_concurrent_streams = 2;

  CU_ASSERT(NULL == nghttp2_session_get_next_ob_item(session));
  nghttp2_submit_ping(session, NGHTTP2_FLAG_NONE, NULL);
  CU_ASSERT(NGHTTP2_PING ==
            OB_CTRL_TYPE(nghttp2_session_get_next_ob_item(session)));

  nghttp2_submit_request(session, NULL, NULL, 0, NULL, NULL);
  CU_ASSERT(NGHTTP2_PING ==
            OB_CTRL_TYPE(nghttp2_session_get_next_ob_item(session)));

  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NULL == nghttp2_session_get_next_ob_item(session));

  /* Incoming stream does not affect the number of outgoing max
     concurrent streams. */
  nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default,
                              NGHTTP2_STREAM_OPENING, NULL);

  nghttp2_priority_spec_init(&pri_spec, 0, NGHTTP2_MAX_WEIGHT, 0);

  nghttp2_submit_request(session, &pri_spec, NULL, 0, NULL, NULL);
  CU_ASSERT(NGHTTP2_HEADERS ==
            OB_CTRL_TYPE(nghttp2_session_get_next_ob_item(session)));
  CU_ASSERT(0 == nghttp2_session_send(session));

  nghttp2_submit_request(session, &pri_spec, NULL, 0, NULL, NULL);
  CU_ASSERT(NULL == nghttp2_session_get_next_ob_item(session));

  session->remote_settings.max_concurrent_streams = 3;

  CU_ASSERT(NGHTTP2_HEADERS ==
            OB_CTRL_TYPE(nghttp2_session_get_next_ob_item(session)));

  nghttp2_session_del(session);
}

void test_nghttp2_session_pop_next_ob_item(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_outbound_item *item;
  nghttp2_priority_spec pri_spec;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  nghttp2_session_server_new(&session, &callbacks, NULL);
  session->remote_settings.max_concurrent_streams = 1;

  CU_ASSERT(NULL == nghttp2_session_pop_next_ob_item(session));

  nghttp2_submit_ping(session, NGHTTP2_FLAG_NONE, NULL);

  nghttp2_priority_spec_init(&pri_spec, 0, 254, 0);

  nghttp2_submit_request(session, &pri_spec, NULL, 0, NULL, NULL);

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
  nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, NGHTTP2_STREAM_OPENING, NULL);
  /* In-flight outgoing stream */
  nghttp2_session_open_stream(session, 4, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, NGHTTP2_STREAM_OPENING, NULL);

  nghttp2_priority_spec_init(&pri_spec, 0, NGHTTP2_MAX_WEIGHT, 0);

  nghttp2_submit_request(session, &pri_spec, NULL, 0, NULL, NULL);
  nghttp2_submit_response(session, 1, NULL, 0, NULL);

  item = nghttp2_session_pop_next_ob_item(session);
  CU_ASSERT(NGHTTP2_HEADERS == OB_CTRL_TYPE(item));
  CU_ASSERT(1 == OB_CTRL(item)->hd.stream_id);
  nghttp2_outbound_item_free(item);
  free(item);

  CU_ASSERT(NULL == nghttp2_session_pop_next_ob_item(session));

  session->remote_settings.max_concurrent_streams = 2;

  item = nghttp2_session_pop_next_ob_item(session);
  CU_ASSERT(NGHTTP2_HEADERS == OB_CTRL_TYPE(item));
  nghttp2_outbound_item_free(item);
  free(item);

  nghttp2_session_del(session);

  /* Check that push reply HEADERS are queued into ob_ss_pq */
  nghttp2_session_server_new(&session, &callbacks, NULL);
  session->remote_settings.max_concurrent_streams = 0;
  nghttp2_session_open_stream(session, 2, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, NGHTTP2_STREAM_RESERVED,
                              NULL);
  CU_ASSERT(0 == nghttp2_submit_headers(session, NGHTTP2_FLAG_END_STREAM,
                                        2, NULL, NULL, 0,
                                        NULL));
  CU_ASSERT(NULL == nghttp2_session_pop_next_ob_item(session));
  CU_ASSERT(1 == nghttp2_pq_size(&session->ob_ss_pq));
  nghttp2_session_del(session);
}

void test_nghttp2_session_reply_fail(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_data_provider data_prd;
  my_user_data ud;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = fail_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 4*1024;
  CU_ASSERT(0 == nghttp2_session_server_new(&session, &callbacks, &ud));
  nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default,
                              NGHTTP2_STREAM_OPENING, NULL);
  CU_ASSERT(0 == nghttp2_submit_response(session, 1, NULL, 0, &data_prd));
  CU_ASSERT(NGHTTP2_ERR_CALLBACK_FAILURE == nghttp2_session_send(session));
  nghttp2_session_del(session);
}

void test_nghttp2_session_max_concurrent_streams(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_frame frame;
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  nghttp2_session_server_new(&session, &callbacks, NULL);
  nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default,
                              NGHTTP2_STREAM_OPENED, NULL);

  /* Check un-ACKed SETTINGS_MAX_CONCURRENT_STREAMS */
  nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS, 3,
                             NGHTTP2_HCAT_HEADERS, NULL, NULL, 0);
  session->pending_local_max_concurrent_stream = 1;

  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_request_headers_received(session, &frame));

  item = nghttp2_session_get_ob_pq_top(session);
  CU_ASSERT(NGHTTP2_RST_STREAM == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_REFUSED_STREAM == OB_CTRL(item)->rst_stream.error_code);

  CU_ASSERT(0 == nghttp2_session_send(session));

  /* Check ACKed SETTINGS_MAX_CONCURRENT_STREAMS */
  session->local_settings.max_concurrent_streams = 1;
  frame.hd.stream_id = 5;

  CU_ASSERT(NGHTTP2_ERR_IGN_HEADER_BLOCK ==
            nghttp2_session_on_request_headers_received(session, &frame));

  item = nghttp2_session_get_ob_pq_top(session);
  CU_ASSERT(NGHTTP2_GOAWAY == OB_CTRL_TYPE(item));
  CU_ASSERT(NGHTTP2_ENHANCE_YOUR_CALM == OB_CTRL(item)->goaway.error_code);

  nghttp2_frame_headers_free(&frame.headers);
  nghttp2_session_del(session);
}

/*
 * Check that on_stream_close_callback is called when server pushed
 * HEADERS have NGHTTP2_FLAG_END_STREAM.
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

  /* CU_ASSERT(0 == nghttp2_session_on_request_headers_received(session, &frame)); */

  /* nghttp2_frame_syn_stream_free(&frame.syn_stream); */
  /* nghttp2_session_del(session); */
}

void test_nghttp2_session_stop_data_with_rst_stream(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data ud;
  nghttp2_data_provider data_prd;
  nghttp2_frame frame;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.send_callback = block_count_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.frame_send_cb_called = 0;
  ud.data_source_length = NGHTTP2_DATA_PAYLOADLEN * 4;

  nghttp2_session_server_new(&session, &callbacks, &ud);
  nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default,
                              NGHTTP2_STREAM_OPENING, NULL);
  nghttp2_submit_response(session, 1, NULL, 0, &data_prd);

  ud.block_count = 2;
  /* Sends response HEADERS + DATA[0] */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NGHTTP2_DATA == ud.sent_frame_type);
  /* data for DATA[1] is read from data_prd but it is not sent */
  CU_ASSERT(ud.data_source_length == NGHTTP2_DATA_PAYLOADLEN * 2);

  nghttp2_frame_rst_stream_init(&frame.rst_stream, 1, NGHTTP2_CANCEL);
  CU_ASSERT(0 == nghttp2_session_on_rst_stream_received(session, &frame));
  nghttp2_frame_rst_stream_free(&frame.rst_stream);

  /* Big enough number to send all DATA frames potentially. */
  ud.block_count = 100;
  /* Nothing will be sent in the following call. */
  CU_ASSERT(0 == nghttp2_session_send(session));
  /* With RST_STREAM, stream is canceled and further DATA on that
     stream are not sent. */
  CU_ASSERT(ud.data_source_length == NGHTTP2_DATA_PAYLOADLEN * 2);

  CU_ASSERT(NULL == nghttp2_session_get_stream(session, 1));

  nghttp2_session_del(session);
}

void test_nghttp2_session_defer_data(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data ud;
  nghttp2_data_provider data_prd;
  nghttp2_outbound_item *item;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.send_callback = block_count_send_callback;
  data_prd.read_callback = defer_data_source_read_callback;

  ud.frame_send_cb_called = 0;
  ud.data_source_length = NGHTTP2_DATA_PAYLOADLEN * 4;

  nghttp2_session_server_new(&session, &callbacks, &ud);
  nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default,
                              NGHTTP2_STREAM_OPENING, NULL);
  nghttp2_submit_response(session, 1, NULL, 0, &data_prd);

  ud.block_count = 1;
  /* Sends HEADERS reply */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NGHTTP2_HEADERS == ud.sent_frame_type);
  /* No data is read */
  CU_ASSERT(ud.data_source_length == NGHTTP2_DATA_PAYLOADLEN * 4);

  ud.block_count = 1;
  nghttp2_submit_ping(session, NGHTTP2_FLAG_NONE, NULL);
  /* Sends PING */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NGHTTP2_PING == ud.sent_frame_type);

  /* Resume deferred DATA */
  CU_ASSERT(0 == nghttp2_session_resume_data(session, 1));
  item = nghttp2_session_get_ob_pq_top(session);
  OB_DATA(item)->data_prd.read_callback =
    fixed_length_data_source_read_callback;
  ud.block_count = 1;
  /* Reads 2 DATA chunks */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(ud.data_source_length == NGHTTP2_DATA_PAYLOADLEN * 2);

  /* Deferred again */
  OB_DATA(item)->data_prd.read_callback = defer_data_source_read_callback;
  /* This is needed since 4KiB block is already read and waiting to be
     sent. No read_callback invocation. */
  ud.block_count = 1;
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(ud.data_source_length == NGHTTP2_DATA_PAYLOADLEN * 2);

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
  my_user_data ud;
  nghttp2_data_provider data_prd;
  nghttp2_frame frame;
  nghttp2_stream *stream;
  int32_t new_initial_window_size;
  nghttp2_settings_entry iv[1];
  nghttp2_frame settings_frame;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = fixed_bytes_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.frame_send_cb_called = 0;
  ud.data_source_length = 128*1024;
  /* Use smaller emission count so that we can check outbound flow
     control window calculation is correct. */
  ud.fixed_sendlen = 2*1024;

  /* Initial window size to 64KiB - 1*/
  nghttp2_session_client_new(&session, &callbacks, &ud);
  /* Change it to 64KiB for easy calculation */
  session->remote_window_size = 64*1024;
  session->remote_settings.initial_window_size = 64*1024;

  nghttp2_submit_request(session, NULL, NULL, 0, &data_prd, NULL);

  /* Sends 64KiB - 1 data */
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
  stream->remote_window_size = new_initial_window_size-
    (session->remote_settings.initial_window_size
     - stream->remote_window_size);
  session->remote_settings.initial_window_size = new_initial_window_size;
  CU_ASSERT(-48*1024 == stream->remote_window_size);

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

  nghttp2_frame_settings_init(&settings_frame.settings, NGHTTP2_FLAG_NONE,
                              dup_iv(iv, 1), 1);
  nghttp2_session_on_settings_received(session, &settings_frame, 1);
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

void test_nghttp2_session_flow_control_data_recv(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  uint8_t data[64*1024+16];
  nghttp2_frame_hd hd;
  nghttp2_outbound_item *item;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  /* Initial window size to 64KiB - 1*/
  nghttp2_session_client_new(&session, &callbacks, NULL);

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENED, NULL);

  session->next_stream_id = 3;

  nghttp2_stream_shutdown(stream, NGHTTP2_SHUT_WR);

  session->local_window_size = NGHTTP2_MAX_PAYLOADLEN;
  stream->local_window_size = NGHTTP2_MAX_PAYLOADLEN;

  /* Create DATA frame */
  memset(data, 0, sizeof(data));
  hd.length = NGHTTP2_MAX_PAYLOADLEN;
  hd.type = NGHTTP2_DATA;
  hd.flags = NGHTTP2_FLAG_END_STREAM;
  hd.stream_id = 1;
  nghttp2_frame_pack_frame_hd(data, &hd);
  CU_ASSERT(NGHTTP2_MAX_PAYLOADLEN+NGHTTP2_FRAME_HDLEN ==
            nghttp2_session_mem_recv(session, data,
                                     NGHTTP2_MAX_PAYLOADLEN +
                                     NGHTTP2_FRAME_HDLEN));

  item = nghttp2_session_get_next_ob_item(session);
  /* Since this is the last frame, stream-level WINDOW_UPDATE is not
     issued, but connection-level is. */
  CU_ASSERT(NGHTTP2_WINDOW_UPDATE == OB_CTRL_TYPE(item));
  CU_ASSERT(0 == OB_CTRL(item)->hd.stream_id);
  CU_ASSERT(NGHTTP2_MAX_PAYLOADLEN ==
            OB_CTRL(item)->window_update.window_size_increment);

  CU_ASSERT(0 == nghttp2_session_send(session));

  /* Receive DATA for closed stream. They are still subject to under
     connection-level flow control, since this situation arises when
     RST_STREAM is issued by the remote, but the local side keeps
     sending DATA frames. Without calculating connection-level window,
     the subsequent flow control gets confused. */
  CU_ASSERT(NGHTTP2_MAX_PAYLOADLEN+NGHTTP2_FRAME_HDLEN ==
            nghttp2_session_mem_recv(session, data,
                                     NGHTTP2_MAX_PAYLOADLEN +
                                     NGHTTP2_FRAME_HDLEN));

  item = nghttp2_session_get_next_ob_item(session);
  CU_ASSERT(NGHTTP2_WINDOW_UPDATE == OB_CTRL_TYPE(item));
  CU_ASSERT(0 == OB_CTRL(item)->hd.stream_id);
  CU_ASSERT(NGHTTP2_MAX_PAYLOADLEN ==
            OB_CTRL(item)->window_update.window_size_increment);

  nghttp2_session_del(session);
}

void test_nghttp2_session_flow_control_data_with_padding_recv(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  uint8_t data[1024];
  nghttp2_frame_hd hd;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  /* Initial window size to 64KiB - 1*/
  nghttp2_session_client_new(&session, &callbacks, NULL);

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENED, NULL);

  /* Create DATA frame */
  memset(data, 0, sizeof(data));
  hd.length = 357;
  hd.type = NGHTTP2_DATA;
  hd.flags = NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_PADDED;
  hd.stream_id = 1;
  nghttp2_frame_pack_frame_hd(data, &hd);
  /* Set Pad Length field, which itself is padding */
  data[NGHTTP2_FRAME_HDLEN] = 255;

  CU_ASSERT((ssize_t)(NGHTTP2_FRAME_HDLEN + hd.length) ==
            nghttp2_session_mem_recv(session, data,
                                     NGHTTP2_FRAME_HDLEN + hd.length));

  CU_ASSERT((int32_t)hd.length == session->recv_window_size);
  CU_ASSERT((int32_t)hd.length == stream->recv_window_size);

  nghttp2_session_del(session);
}

void test_nghttp2_session_data_read_temporal_failure(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data ud;
  nghttp2_data_provider data_prd;
  nghttp2_frame frame;
  nghttp2_private_data *data_frame;
  nghttp2_stream *stream;
  size_t data_size = 128*1024;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.data_source_length = data_size;

  /* Initial window size is 64KiB - 1 */
  nghttp2_session_client_new(&session, &callbacks, &ud);
  nghttp2_submit_request(session, NULL, NULL, 0, &data_prd, NULL);

  /* Sends NGHTTP2_INITIAL_WINDOW_SIZE data, assuming, it is equal to
     or smaller than NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(data_size - NGHTTP2_INITIAL_WINDOW_SIZE == ud.data_source_length);

  stream = nghttp2_session_get_stream(session, 1);
  CU_ASSERT(nghttp2_stream_check_deferred_by_flow_control(stream));
  CU_ASSERT(NGHTTP2_CAT_DATA == stream->data_item->frame_cat);
  data_frame = (nghttp2_private_data*)stream->data_item->frame;
  data_frame->data_prd.read_callback =
    temporal_failure_data_source_read_callback;

  /* Back NGHTTP2_INITIAL_WINDOW_SIZE to both connection-level and
     stream-wise window */
  nghttp2_frame_window_update_init(&frame.window_update, NGHTTP2_FLAG_NONE,
                                   1, NGHTTP2_INITIAL_WINDOW_SIZE);
  nghttp2_session_on_window_update_received(session, &frame);
  frame.hd.stream_id = 0;
  nghttp2_session_on_window_update_received(session, &frame);
  nghttp2_frame_window_update_free(&frame.window_update);

  /* Sending data will fail (soft fail) and treated as stream error */
  ud.frame_send_cb_called = 0;
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(data_size - NGHTTP2_INITIAL_WINDOW_SIZE == ud.data_source_length);

  CU_ASSERT(1 == ud.frame_send_cb_called);
  CU_ASSERT(NGHTTP2_RST_STREAM == ud.sent_frame_type);

  data_prd.read_callback = fail_data_source_read_callback;
  nghttp2_submit_request(session, NULL, NULL, 0, &data_prd, NULL);
  /* Sending data will fail (hard fail) and session tear down */
  CU_ASSERT(NGHTTP2_ERR_CALLBACK_FAILURE == nghttp2_session_send(session));

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
  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
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

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_frame_not_send_callback = on_frame_not_send_callback;
  callbacks.send_callback = null_send_callback;
  user_data.frame_not_send_cb_called = 0;
  user_data.not_sent_frame_type = 0;
  user_data.not_sent_error = 0;

  nghttp2_session_server_new(&session, &callbacks, &user_data);
  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENING, &user_data);

  /* Check response HEADERS */
  /* Send bogus stream ID */
  CU_ASSERT(0 ==
            nghttp2_submit_headers(session, NGHTTP2_FLAG_END_STREAM, 3,
                                   NULL, NULL, 0, NULL));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == user_data.frame_not_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == user_data.not_sent_frame_type);
  CU_ASSERT(NGHTTP2_ERR_STREAM_CLOSED == user_data.not_sent_error);

  user_data.frame_not_send_cb_called = 0;
  /* Shutdown transmission */
  stream->shut_flags |= NGHTTP2_SHUT_WR;
  CU_ASSERT(0 ==
            nghttp2_submit_headers(session, NGHTTP2_FLAG_END_STREAM, 1,
                                   NULL, NULL, 0, NULL));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == user_data.frame_not_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == user_data.not_sent_frame_type);
  CU_ASSERT(NGHTTP2_ERR_STREAM_SHUT_WR == user_data.not_sent_error);

  stream->shut_flags = NGHTTP2_SHUT_NONE;
  user_data.frame_not_send_cb_called = 0;
  /* Queue RST_STREAM */
  CU_ASSERT(0 ==
            nghttp2_submit_headers(session, NGHTTP2_FLAG_END_STREAM, 1,
                                   NULL, NULL, 0, NULL));
  CU_ASSERT(0 == nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, 1,
                                           NGHTTP2_INTERNAL_ERROR));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == user_data.frame_not_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == user_data.not_sent_frame_type);
  CU_ASSERT(NGHTTP2_ERR_STREAM_CLOSED == user_data.not_sent_error);

  stream = nghttp2_session_open_stream(session, 3, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENED, &user_data);

  /* Check HEADERS */
  user_data.frame_not_send_cb_called = 0;
  /* Queue RST_STREAM */
  CU_ASSERT(0 ==
            nghttp2_submit_headers(session, NGHTTP2_FLAG_END_STREAM, 3,
                                   NULL, NULL, 0, NULL));
  CU_ASSERT(0 == nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, 3,
                                           NGHTTP2_INTERNAL_ERROR));
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(1 == user_data.frame_not_send_cb_called);
  CU_ASSERT(NGHTTP2_HEADERS == user_data.not_sent_frame_type);
  CU_ASSERT(NGHTTP2_ERR_STREAM_CLOSED == user_data.not_sent_error);

  nghttp2_session_del(session);

  /* Check request HEADERS */
  user_data.frame_not_send_cb_called = 0;
  CU_ASSERT(nghttp2_session_client_new(&session, &callbacks, &user_data) == 0);
  /* Maximum Stream ID is reached */
  session->next_stream_id = (1u << 31)+1;
  CU_ASSERT(NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE ==
            nghttp2_submit_headers(session, NGHTTP2_FLAG_END_STREAM, -1,
                                   NULL, NULL, 0, NULL));

  user_data.frame_not_send_cb_called = 0;
  /* Send GOAWAY */
  CU_ASSERT(0 == nghttp2_submit_goaway(session, NGHTTP2_FLAG_NONE,
                                       (1u << 31) - 1, NGHTTP2_NO_ERROR,
                                       NULL, 0));

  session->next_stream_id = 9;

  CU_ASSERT(0 < nghttp2_submit_headers(session, NGHTTP2_FLAG_END_STREAM, -1,
                                       NULL, NULL, 0, NULL));
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

  CU_ASSERT(0 == nghttp2_submit_ping(session, NGHTTP2_FLAG_NONE, NULL));
  CU_ASSERT(1 == nghttp2_session_get_outbound_queue_size(session));

  CU_ASSERT(0 == nghttp2_submit_goaway(session, NGHTTP2_FLAG_NONE,
                                       3, NGHTTP2_NO_ERROR, NULL, 0));
  CU_ASSERT(2 == nghttp2_session_get_outbound_queue_size(session));

  nghttp2_session_del(session);
}

void test_nghttp2_session_get_effective_local_window_size(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  CU_ASSERT(0 == nghttp2_session_client_new(&session, &callbacks, NULL));

  stream = nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       NGHTTP2_STREAM_OPENED, NULL);

  CU_ASSERT(NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE ==
            nghttp2_session_get_effective_local_window_size(session));
  CU_ASSERT(0 == nghttp2_session_get_effective_recv_data_length(session));

  CU_ASSERT(NGHTTP2_INITIAL_WINDOW_SIZE ==
            nghttp2_session_get_stream_effective_local_window_size
            (session, 1));
  CU_ASSERT(0 ==
            nghttp2_session_get_stream_effective_recv_data_length(session, 1));

  /* Check connection flow control */
  session->recv_window_size = 100;
  nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 0, 1100);

  CU_ASSERT(NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE + 1000 ==
            nghttp2_session_get_effective_local_window_size(session));
  CU_ASSERT(0 == nghttp2_session_get_effective_recv_data_length(session));

  nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 0, -50);
  /* Now session->recv_window_size = -50 */
  CU_ASSERT(NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE + 950 ==
            nghttp2_session_get_effective_local_window_size(session));
  CU_ASSERT(0 == nghttp2_session_get_effective_recv_data_length(session));

  session->recv_window_size += 50;
  /* Now session->recv_window_size = 0 */
  nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 0, 100);
  CU_ASSERT(NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE + 1050 ==
            nghttp2_session_get_effective_local_window_size(session));
  CU_ASSERT(50 == nghttp2_session_get_effective_recv_data_length(session));

  /* Check stream flow control */
  stream->recv_window_size = 100;
  nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 1, 1100);

  CU_ASSERT(NGHTTP2_INITIAL_WINDOW_SIZE + 1000 ==
            nghttp2_session_get_stream_effective_local_window_size
            (session, 1));
  CU_ASSERT(0 == nghttp2_session_get_stream_effective_recv_data_length
            (session, 1));

  nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 1, -50);
  /* Now stream->recv_window_size = -50 */
  CU_ASSERT(NGHTTP2_INITIAL_WINDOW_SIZE + 950 ==
            nghttp2_session_get_stream_effective_local_window_size
            (session, 1));
  CU_ASSERT(0 == nghttp2_session_get_stream_effective_recv_data_length
            (session, 1));

  stream->recv_window_size += 50;
  /* Now stream->recv_window_size = 0 */
  nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 1, 100);
  CU_ASSERT(NGHTTP2_INITIAL_WINDOW_SIZE + 1050 ==
            nghttp2_session_get_stream_effective_local_window_size
            (session, 1));
  CU_ASSERT(50 ==
            nghttp2_session_get_stream_effective_recv_data_length
            (session, 1));

  nghttp2_session_del(session);
}

void test_nghttp2_session_set_option(void)
{
  nghttp2_session* session;
  nghttp2_session_callbacks callbacks;
  nghttp2_option *option;

  nghttp2_option_new(&option);

  nghttp2_option_set_no_auto_stream_window_update(option, 1);

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  nghttp2_session_client_new2(&session, &callbacks, NULL, option);

  CU_ASSERT(session->opt_flags & NGHTTP2_OPTMASK_NO_AUTO_STREAM_WINDOW_UPDATE);
  CU_ASSERT(!(session->opt_flags &
              NGHTTP2_OPTMASK_NO_AUTO_CONNECTION_WINDOW_UPDATE));
  nghttp2_session_del(session);

  nghttp2_option_set_no_auto_stream_window_update(option, 0);
  nghttp2_option_set_no_auto_connection_window_update(option, 1);

  nghttp2_session_server_new2(&session, &callbacks, NULL, option);

  CU_ASSERT(!(session->opt_flags &
              NGHTTP2_OPTMASK_NO_AUTO_STREAM_WINDOW_UPDATE));
  CU_ASSERT(session->opt_flags &
            NGHTTP2_OPTMASK_NO_AUTO_CONNECTION_WINDOW_UPDATE);
  nghttp2_session_del(session);

  nghttp2_option_set_peer_max_concurrent_streams(option, 100);

  nghttp2_session_client_new2(&session, &callbacks, NULL, option);

  CU_ASSERT(100 == session->remote_settings.max_concurrent_streams);
  nghttp2_session_del(session);

  nghttp2_option_del(option);
}

void test_nghttp2_session_data_backoff_by_high_pri_frame(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data ud;
  nghttp2_data_provider data_prd;
  nghttp2_stream *stream;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = block_count_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.frame_send_cb_called = 0;
  ud.data_source_length = NGHTTP2_DATA_PAYLOADLEN * 4;

  nghttp2_session_client_new(&session, &callbacks, &ud);
  nghttp2_submit_request(session, NULL, NULL, 0, &data_prd, NULL);

  ud.block_count = 2;
  /* Sends request HEADERS + DATA[0] */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NGHTTP2_DATA == ud.sent_frame_type);
  /* data for DATA[1] is read from data_prd but it is not sent */
  CU_ASSERT(ud.data_source_length == NGHTTP2_DATA_PAYLOADLEN * 2);

  nghttp2_submit_ping(session, NGHTTP2_FLAG_NONE, NULL);
  ud.block_count = 2;
  /* Sends DATA[1] + PING, PING is interleaved in DATA sequence */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NGHTTP2_PING == ud.sent_frame_type);
  /* data for DATA[2] is read from data_prd but it is not sent */
  CU_ASSERT(ud.data_source_length == NGHTTP2_DATA_PAYLOADLEN);

  ud.block_count = 2;
  /* Sends DATA[2..3] */
  CU_ASSERT(0 == nghttp2_session_send(session));

  stream = nghttp2_session_get_stream(session, 1);
  CU_ASSERT(stream->shut_flags & NGHTTP2_SHUT_WR);

  nghttp2_session_del(session);
}

static void check_session_recv_data_with_padding(nghttp2_bufs *bufs,
                                                 size_t datalen)
{
  nghttp2_session *session;
  my_user_data ud;
  nghttp2_session_callbacks callbacks;
  uint8_t *in;
  size_t inlen;

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  nghttp2_session_server_new(&session, &callbacks, &ud);

  nghttp2_session_open_stream(session, 1, NGHTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, NGHTTP2_STREAM_OPENING,
                              NULL);

  inlen = nghttp2_bufs_remove(bufs, &in);

  ud.frame_recv_cb_called = 0;
  ud.data_chunk_len = 0;

  CU_ASSERT((ssize_t)inlen == nghttp2_session_mem_recv(session, in, inlen));

  CU_ASSERT(1 == ud.frame_recv_cb_called);
  CU_ASSERT(datalen == ud.data_chunk_len);

  free(in);
  nghttp2_session_del(session);
}

void test_nghttp2_session_pack_data_with_padding(void)
{
  nghttp2_session *session;
  my_user_data ud;
  nghttp2_session_callbacks callbacks;
  nghttp2_data_provider data_prd;
  nghttp2_private_data *frame;
  size_t datalen = 55;

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = block_count_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.select_padding_callback = select_padding_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;

  nghttp2_session_client_new(&session, &callbacks, &ud);

  ud.padlen = 63;

  nghttp2_submit_request(session, NULL, NULL, 0, &data_prd, NULL);
  ud.block_count = 1;
  ud.data_source_length = datalen;
  /* Sends HEADERS */
  CU_ASSERT(0 == nghttp2_session_send(session));
  CU_ASSERT(NGHTTP2_HEADERS == ud.sent_frame_type);

  frame = OB_DATA(session->aob.item);

  CU_ASSERT(ud.padlen == frame->padlen);
  CU_ASSERT(frame->hd.flags & NGHTTP2_FLAG_PADDED);

  /* Check reception of this DATA frame */
  check_session_recv_data_with_padding(&session->aob.framebufs, datalen);

  nghttp2_session_del(session);
}

void test_nghttp2_session_pack_headers_with_padding(void)
{
  nghttp2_session *session, *sv_session;
  accumulator acc;
  my_user_data ud;
  nghttp2_session_callbacks callbacks;
  nghttp2_nv nv = MAKE_NV(":path", "/");

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = accumulator_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.select_padding_callback = select_padding_callback;
  callbacks.on_frame_recv_callback = on_frame_recv_callback;

  acc.length = 0;
  ud.acc = &acc;

  nghttp2_session_client_new(&session, &callbacks, &ud);
  nghttp2_session_server_new(&sv_session, &callbacks, &ud);

  ud.padlen = 163;

  CU_ASSERT(1 == nghttp2_submit_request(session, NULL, &nv, 1, NULL, NULL));
  CU_ASSERT(0 == nghttp2_session_send(session));

  CU_ASSERT(acc.length < NGHTTP2_MAX_PAYLOADLEN);
  ud.frame_recv_cb_called = 0;
  CU_ASSERT((ssize_t)acc.length ==
            nghttp2_session_mem_recv(sv_session, acc.buf, acc.length));
  CU_ASSERT(1 == ud.frame_recv_cb_called);
  CU_ASSERT(NULL == nghttp2_session_get_next_ob_item(sv_session));

  nghttp2_session_del(sv_session);
  nghttp2_session_del(session);
}

void test_nghttp2_pack_settings_payload(void)
{
  nghttp2_settings_entry iv[2];
  uint8_t buf[64];
  ssize_t len;
  nghttp2_settings_entry *resiv;
  size_t resniv;

  iv[0].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 1023;
  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 4095;

  len = nghttp2_pack_settings_payload(buf, sizeof(buf), iv, 2);
  CU_ASSERT(2 * NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH == len);
  CU_ASSERT(0 == nghttp2_frame_unpack_settings_payload2(&resiv, &resniv,
                                                        buf, len));
  CU_ASSERT(2 == resniv);
  CU_ASSERT(NGHTTP2_SETTINGS_HEADER_TABLE_SIZE == resiv[0].settings_id);
  CU_ASSERT(1023 == resiv[0].value);
  CU_ASSERT(NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE == resiv[1].settings_id);
  CU_ASSERT(4095 == resiv[1].value);

  free(resiv);

  len = nghttp2_pack_settings_payload(buf, 9 /* too small */, iv, 2);
  CU_ASSERT(NGHTTP2_ERR_INSUFF_BUFSIZE == len);
}

#define check_stream_dep_sib(STREAM, DEP_PREV, DEP_NEXT, SIB_PREV, SIB_NEXT) \
  do {                                                                  \
    CU_ASSERT(DEP_PREV == STREAM->dep_prev);                            \
    CU_ASSERT(DEP_NEXT == STREAM->dep_next);                            \
    CU_ASSERT(SIB_PREV == STREAM->sib_prev);                            \
    CU_ASSERT(SIB_NEXT == STREAM->sib_next);                            \
  } while(0)

/* nghttp2_stream_dep_add() and its families functions should be
   tested in nghttp2_stream_test.c, but it is easier to use
   nghttp2_session_open_stream().  Therefore, we test them here. */
void test_nghttp2_session_stream_dep_add(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_stream *a, *b, *c, *d, *e;

  memset(&callbacks, 0, sizeof(callbacks));

  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);

  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * b--c
   *    |
   *    d
   */

  CU_ASSERT(4 == a->num_substreams);
  CU_ASSERT(1 == b->num_substreams);
  CU_ASSERT(2 == c->num_substreams);
  CU_ASSERT(1 == d->num_substreams);

  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT * 2 == a->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == c->sum_dep_weight);
  CU_ASSERT(0 == d->sum_dep_weight);

  check_stream_dep_sib(a, NULL, b, NULL, NULL);
  check_stream_dep_sib(b, a, NULL, NULL, c);
  check_stream_dep_sib(c, NULL, d, b, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);

  CU_ASSERT(4 == session->roots.num_streams);
  CU_ASSERT(a == session->roots.head);
  CU_ASSERT(NULL == a->root_next);

  e = open_stream_with_dep_excl(session, 9, a);

  /* a
   * |
   * e
   * |
   * b--c
   *    |
   *    d
   */

  CU_ASSERT(5 == a->num_substreams);
  CU_ASSERT(4 == e->num_substreams);
  CU_ASSERT(1 == b->num_substreams);
  CU_ASSERT(2 == c->num_substreams);
  CU_ASSERT(1 == d->num_substreams);

  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == a->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT * 2 == e->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == c->sum_dep_weight);
  CU_ASSERT(0 == d->sum_dep_weight);

  check_stream_dep_sib(a, NULL, e, NULL, NULL);
  check_stream_dep_sib(e, a, b, NULL, NULL);
  check_stream_dep_sib(b, e, NULL, NULL, c);
  check_stream_dep_sib(c, NULL, d, b, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);

  CU_ASSERT(5 == session->roots.num_streams);
  CU_ASSERT(a == session->roots.head);
  CU_ASSERT(NULL == a->root_next);

  nghttp2_session_del(session);
}

void test_nghttp2_session_stream_dep_remove(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_stream *a, *b, *c, *d, *e, *f;

  memset(&callbacks, 0, sizeof(callbacks));

  /* Remove root */
  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * b--c
   *    |
   *    d
   */

  nghttp2_stream_dep_remove(a);

  /* becomes:
   * b    c
   *      |
   *      d
   */

  CU_ASSERT(1 == a->num_substreams);
  CU_ASSERT(1 == b->num_substreams);
  CU_ASSERT(2 == c->num_substreams);
  CU_ASSERT(1 == d->num_substreams);

  CU_ASSERT(0 == a->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == c->sum_dep_weight);
  CU_ASSERT(0 == d->sum_dep_weight);

  check_stream_dep_sib(a, NULL, NULL, NULL, NULL);
  check_stream_dep_sib(b, NULL, NULL, NULL, NULL);
  check_stream_dep_sib(c, NULL, d, NULL, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);

  CU_ASSERT(3 == session->roots.num_streams);
  CU_ASSERT(c == session->roots.head);
  CU_ASSERT(b == c->root_next);
  CU_ASSERT(NULL == b->root_next);

  nghttp2_session_del(session);

  /* Remove left most stream */
  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * b--c
   *    |
   *    d
   */

  nghttp2_stream_dep_remove(b);

  /* becomes:
   * a
   * |
   * c
   * |
   * d
   */

  CU_ASSERT(3 == a->num_substreams);
  CU_ASSERT(1 == b->num_substreams);
  CU_ASSERT(2 == c->num_substreams);
  CU_ASSERT(1 == d->num_substreams);

  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == a->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == c->sum_dep_weight);
  CU_ASSERT(0 == d->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);

  check_stream_dep_sib(a, NULL, c, NULL, NULL);
  check_stream_dep_sib(b, NULL, NULL, NULL, NULL);
  check_stream_dep_sib(c, a, d, NULL, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);

  CU_ASSERT(3 == session->roots.num_streams);
  CU_ASSERT(a == session->roots.head);
  CU_ASSERT(NULL == a->root_next);

  nghttp2_session_del(session);

  /* Remove right most stream */
  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * b--c
   *    |
   *    d
   */

  nghttp2_stream_dep_remove(c);

  /* becomes:
   * a
   * |
   * b--d
   */

  CU_ASSERT(3 == a->num_substreams);
  CU_ASSERT(1 == b->num_substreams);
  CU_ASSERT(1 == c->num_substreams);
  CU_ASSERT(1 == d->num_substreams);

  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT * 2 == a->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);
  CU_ASSERT(0 == d->sum_dep_weight);
  CU_ASSERT(0 == c->sum_dep_weight);

  check_stream_dep_sib(a, NULL, b, NULL, NULL);
  check_stream_dep_sib(b, a, NULL, NULL, d);
  check_stream_dep_sib(c, NULL, NULL, NULL, NULL);
  check_stream_dep_sib(d, NULL, NULL, b, NULL);

  nghttp2_session_del(session);

  /* Remove middle stream */
  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, a);
  e = open_stream_with_dep(session, 9, c);
  f = open_stream_with_dep(session, 11, c);

  /* a
   * |
   * b--c--d
   *    |
   *    e--f
   */

  CU_ASSERT(6 == a->num_substreams);
  CU_ASSERT(1 == b->num_substreams);
  CU_ASSERT(3 == c->num_substreams);
  CU_ASSERT(1 == d->num_substreams);
  CU_ASSERT(1 == e->num_substreams);
  CU_ASSERT(1 == f->num_substreams);

  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT * 3 == a->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT * 2 == c->sum_dep_weight);
  CU_ASSERT(0 == d->sum_dep_weight);
  CU_ASSERT(0 == e->sum_dep_weight);
  CU_ASSERT(0 == f->sum_dep_weight);

  nghttp2_stream_dep_remove(c);

  /* becomes:
   * a
   * |
   * b--e--f--d
   */

  CU_ASSERT(5 == a->num_substreams);
  CU_ASSERT(1 == b->num_substreams);
  CU_ASSERT(1 == c->num_substreams);
  CU_ASSERT(1 == d->num_substreams);
  CU_ASSERT(1 == e->num_substreams);
  CU_ASSERT(1 == f->num_substreams);

  /* c's weight 16 is distributed evenly to e and f.  Each weight of e
     and f becomes 8. */
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT * 2 + 8 * 2 == a->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);
  CU_ASSERT(0 == c->sum_dep_weight);
  CU_ASSERT(0 == d->sum_dep_weight);
  CU_ASSERT(0 == e->sum_dep_weight);
  CU_ASSERT(0 == f->sum_dep_weight);

  check_stream_dep_sib(a, NULL, b, NULL, NULL);
  check_stream_dep_sib(b, a, NULL, NULL, e);
  check_stream_dep_sib(c, NULL, NULL, NULL, NULL);
  check_stream_dep_sib(e, NULL, NULL, b, f);
  check_stream_dep_sib(f, NULL, NULL, e, d);
  check_stream_dep_sib(d, NULL, NULL, f, NULL);

  nghttp2_session_del(session);
}

void test_nghttp2_session_stream_dep_add_subtree(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_stream *a, *b, *c, *d, *e, *f;

  memset(&callbacks, 0, sizeof(callbacks));

  /* dep_stream has dep_next */
  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  e = open_stream(session, 9);
  f = open_stream_with_dep(session, 11, e);

  /* a         e
   * |         |
   * b--c      f
   *    |
   *    d
   */

  nghttp2_stream_dep_add_subtree(a, e, &session->ob_pq, session->last_cycle);

  /* becomes
   * a
   * |
   * b--c--e
   *    |  |
   *    d  f
   */

  CU_ASSERT(6 == a->num_substreams);
  CU_ASSERT(1 == b->num_substreams);
  CU_ASSERT(2 == c->num_substreams);
  CU_ASSERT(1 == d->num_substreams);
  CU_ASSERT(2 == e->num_substreams);
  CU_ASSERT(1 == f->num_substreams);

  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT * 3 == a->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == c->sum_dep_weight);
  CU_ASSERT(0 == d->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == e->sum_dep_weight);
  CU_ASSERT(0 == f->sum_dep_weight);

  check_stream_dep_sib(a, NULL, b, NULL, NULL);
  check_stream_dep_sib(b, a, NULL, NULL, c);
  check_stream_dep_sib(c, NULL, d, b, e);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);
  check_stream_dep_sib(e, NULL, f, c, NULL);
  check_stream_dep_sib(f, e, NULL, NULL, NULL);

  nghttp2_session_del(session);

  /* dep_stream has dep_next and now we insert subtree */
  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  e = open_stream(session, 9);
  f = open_stream_with_dep(session, 11, e);

  /* a         e
   * |         |
   * b--c      f
   *    |
   *    d
   */

  nghttp2_stream_dep_insert_subtree(a, e, &session->ob_pq, session->last_cycle);

  /* becomes
   * a
   * |
   * e
   * |
   * f--b--c
   *       |
   *       d
   */

  CU_ASSERT(6 == a->num_substreams);
  CU_ASSERT(1 == b->num_substreams);
  CU_ASSERT(2 == c->num_substreams);
  CU_ASSERT(1 == d->num_substreams);
  CU_ASSERT(5 == e->num_substreams);
  CU_ASSERT(1 == f->num_substreams);

  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == a->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == c->sum_dep_weight);
  CU_ASSERT(0 == d->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT * 3 == e->sum_dep_weight);
  CU_ASSERT(0 == f->sum_dep_weight);

  check_stream_dep_sib(a, NULL, e, NULL, NULL);
  check_stream_dep_sib(e, a, f, NULL, NULL);
  check_stream_dep_sib(f, e, NULL, NULL, b);
  check_stream_dep_sib(b, NULL, NULL, f, c);
  check_stream_dep_sib(c, NULL, d, b, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);

  nghttp2_session_del(session);
}

void test_nghttp2_session_stream_dep_remove_subtree(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_stream *a, *b, *c, *d, *e;

  memset(&callbacks, 0, sizeof(callbacks));

  /* Remove left most stream */
  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * b--c
   *    |
   *    d
   */

  nghttp2_stream_dep_remove_subtree(c);

  /* becomes
   * a  c
   * |  |
   * b  d
   */

  CU_ASSERT(2 == a->num_substreams);
  CU_ASSERT(1 == b->num_substreams);
  CU_ASSERT(2 == c->num_substreams);
  CU_ASSERT(1 == d->num_substreams);

  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == a->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == c->sum_dep_weight);
  CU_ASSERT(0 == d->sum_dep_weight);

  check_stream_dep_sib(a, NULL, b, NULL, NULL);
  check_stream_dep_sib(b, a, NULL, NULL, NULL);
  check_stream_dep_sib(c, NULL, d, NULL, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);

  nghttp2_session_del(session);

  /* Remove right most stream */
  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * b--c
   *    |
   *    d
   */

  nghttp2_stream_dep_remove_subtree(b);

  /* becomes
   * a  b
   * |
   * c
   * |
   * d
   */

  CU_ASSERT(3 == a->num_substreams);
  CU_ASSERT(1 == b->num_substreams);
  CU_ASSERT(2 == c->num_substreams);
  CU_ASSERT(1 == d->num_substreams);

  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == a->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == c->sum_dep_weight);
  CU_ASSERT(0 == d->sum_dep_weight);

  check_stream_dep_sib(a, NULL, c, NULL, NULL);
  check_stream_dep_sib(c, a, d, NULL, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);
  check_stream_dep_sib(b, NULL, NULL, NULL, NULL);

  nghttp2_session_del(session);

  /* Remove middle stream */
  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);
  e = open_stream_with_dep(session, 9, a);

  /* a
   * |
   * b--c--e
   *    |
   *    d
   */

  nghttp2_stream_dep_remove_subtree(c);

  /* becomes
   * a     c
   * |     |
   * b--e  d
   */

  CU_ASSERT(3 == a->num_substreams);
  CU_ASSERT(1 == b->num_substreams);
  CU_ASSERT(1 == e->num_substreams);
  CU_ASSERT(2 == c->num_substreams);
  CU_ASSERT(1 == d->num_substreams);

  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT * 2 == a->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == c->sum_dep_weight);
  CU_ASSERT(0 == d->sum_dep_weight);
  CU_ASSERT(0 == e->sum_dep_weight);

  check_stream_dep_sib(a, NULL, b, NULL, NULL);
  check_stream_dep_sib(b, a, NULL, NULL, e);
  check_stream_dep_sib(e, NULL, NULL, b, NULL);
  check_stream_dep_sib(c, NULL, d, NULL, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);

  nghttp2_session_del(session);
}

void test_nghttp2_session_stream_dep_all_your_stream_are_belong_to_us(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_stream *a, *b, *c, *d;

  memset(&callbacks, 0, sizeof(callbacks));

  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);

  c = open_stream(session, 5);

  /* a     c
   * |
   * b
   */

  nghttp2_stream_dep_remove_subtree(c);
  CU_ASSERT(0 == nghttp2_stream_dep_all_your_stream_are_belong_to_us
            (c, &session->ob_pq, session->last_cycle));

  /*
   * c
   * |
   * a
   * |
   * b
   */

  CU_ASSERT(3 == c->num_substreams);
  CU_ASSERT(2 == a->num_substreams);
  CU_ASSERT(1 == b->num_substreams);

  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == c->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == a->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);

  check_stream_dep_sib(c, NULL, a, NULL, NULL);
  check_stream_dep_sib(a, c, b, NULL, NULL);
  check_stream_dep_sib(b, a, NULL, NULL, NULL);

  nghttp2_session_del(session);

  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);

  b = open_stream(session, 3);

  c = open_stream(session, 5);

  /*
   * a  b   c
   */

  nghttp2_stream_dep_remove_subtree(c);
  CU_ASSERT(0 == nghttp2_stream_dep_all_your_stream_are_belong_to_us
            (c, &session->ob_pq, session->last_cycle));

  /*
   * c
   * |
   * b--a
   */

  CU_ASSERT(3 == c->num_substreams);
  CU_ASSERT(1 == a->num_substreams);
  CU_ASSERT(1 == b->num_substreams);

  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT * 2 == c->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);
  CU_ASSERT(0 == a->sum_dep_weight);

  check_stream_dep_sib(c, NULL, b, NULL, NULL);
  check_stream_dep_sib(b, c, NULL, NULL, a);
  check_stream_dep_sib(a, NULL, NULL, b, NULL);

  nghttp2_session_del(session);

  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);

  c = open_stream(session, 5);
  d = open_stream_with_dep(session, 7, c);

  /* a     c
   * |     |
   * b     d
   */

  nghttp2_stream_dep_remove_subtree(c);
  CU_ASSERT(0 == nghttp2_stream_dep_all_your_stream_are_belong_to_us
            (c, &session->ob_pq, session->last_cycle));

  /*
   * c
   * |
   * d--a
   *    |
   *    b
   */

  CU_ASSERT(4 == c->num_substreams);
  CU_ASSERT(1 == d->num_substreams);
  CU_ASSERT(2 == a->num_substreams);
  CU_ASSERT(1 == b->num_substreams);

  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT * 2 == c->sum_dep_weight);
  CU_ASSERT(0 == d->sum_dep_weight);
  CU_ASSERT(NGHTTP2_DEFAULT_WEIGHT == a->sum_dep_weight);
  CU_ASSERT(0 == b->sum_dep_weight);

  check_stream_dep_sib(c, NULL, d, NULL, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, a);
  check_stream_dep_sib(a, NULL, b, d, NULL);
  check_stream_dep_sib(b, a, NULL, NULL, NULL);

  nghttp2_session_del(session);
}

void test_nghttp2_session_stream_attach_data(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_stream *a, *b, *c, *d;
  nghttp2_outbound_item *da, *db, *dc, *dd;

  memset(&callbacks, 0, sizeof(callbacks));

  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * b--c
   *    |
   *    d
   */

  db = create_data_ob_item();

  nghttp2_stream_attach_data(b, db, &session->ob_pq, session->last_cycle);

  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == a->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == b->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == c->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == d->dpri);

  CU_ASSERT(16 == b->effective_weight);

  CU_ASSERT(16 == a->sum_norest_weight);

  CU_ASSERT(1 == db->queued);

  dc = create_data_ob_item();

  nghttp2_stream_attach_data(c, dc, &session->ob_pq, session->last_cycle);

  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == a->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == b->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == c->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == d->dpri);

  CU_ASSERT(16 * 16 / 32 == b->effective_weight);
  CU_ASSERT(16 * 16 / 32 == c->effective_weight);

  CU_ASSERT(32 == a->sum_norest_weight);

  CU_ASSERT(1 == dc->queued);

  da = create_data_ob_item();

  nghttp2_stream_attach_data(a, da, &session->ob_pq, session->last_cycle);

  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == a->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_REST == b->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_REST == c->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == d->dpri);

  CU_ASSERT(16 == a->effective_weight);

  CU_ASSERT(1 == da->queued);

  nghttp2_stream_detach_data(a, &session->ob_pq, session->last_cycle);

  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == a->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == b->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == c->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == d->dpri);

  CU_ASSERT(16 * 16 / 32 == b->effective_weight);
  CU_ASSERT(16 * 16 / 32 == c->effective_weight);

  dd = create_data_ob_item();

  nghttp2_stream_attach_data(d, dd, &session->ob_pq, session->last_cycle);

  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == a->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == b->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == c->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_REST == d->dpri);

  CU_ASSERT(16 * 16 / 32 == b->effective_weight);
  CU_ASSERT(16 * 16 / 32 == c->effective_weight);

  CU_ASSERT(0 == dd->queued);

  nghttp2_stream_detach_data(c, &session->ob_pq, session->last_cycle);

  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == a->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == b->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == c->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == d->dpri);

  CU_ASSERT(16 * 16 / 32 == b->effective_weight);
  CU_ASSERT(16 * 16 / 32 == d->effective_weight);

  CU_ASSERT(1 == dd->queued);

  nghttp2_session_del(session);
}

void test_nghttp2_session_stream_attach_data_subtree(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  nghttp2_stream *a, *b, *c, *d, *e, *f;
  nghttp2_outbound_item *db, *dd, *de;

  memset(&callbacks, 0, sizeof(callbacks));

  nghttp2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  e = open_stream(session, 9);
  f = open_stream_with_dep(session, 11, e);
  /*
   * a        e
   * |        |
   * b--c     f
   *    |
   *    d
   */

  de = create_data_ob_item();

  nghttp2_stream_attach_data(e, de, &session->ob_pq, session->last_cycle);

  db = create_data_ob_item();

  nghttp2_stream_attach_data(b, db, &session->ob_pq, session->last_cycle);

  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == a->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == b->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == c->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == d->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == e->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == f->dpri);

  CU_ASSERT(16 == b->effective_weight);
  CU_ASSERT(16 == e->effective_weight);

  /* Insert subtree e under a */

  nghttp2_stream_dep_remove_subtree(e);
  nghttp2_stream_dep_insert_subtree(a, e, &session->ob_pq, session->last_cycle);

  /*
   * a
   * |
   * e
   * |
   * f--b--c
   *       |
   *       d
   */

  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == a->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_REST == b->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == c->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == d->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == e->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == f->dpri);

  CU_ASSERT(16 == e->effective_weight);

  /* Remove subtree b */

  nghttp2_stream_dep_remove_subtree(b);

  nghttp2_stream_dep_make_root(b, &session->ob_pq, session->last_cycle);

  /*
   * a       b
   * |
   * e
   * |
   * f--c
   *    |
   *    d
   */

  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == a->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == b->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == c->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == d->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == e->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == f->dpri);

  CU_ASSERT(16 == b->effective_weight);
  CU_ASSERT(16 == e->effective_weight);

  /* Remove subtree a */

  nghttp2_stream_dep_remove_subtree(a);

  nghttp2_stream_dep_make_root(a, &session->ob_pq, session->last_cycle);

  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == a->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == b->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == c->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == d->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == e->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == f->dpri);

  /* Remove subtree c */

  nghttp2_stream_dep_remove_subtree(c);

  nghttp2_stream_dep_make_root(c, &session->ob_pq, session->last_cycle);

  /*
   * a       b     c
   * |             |
   * e             d
   * |
   * f
   */

  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == a->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == b->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == c->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == d->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == e->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == f->dpri);

  dd = create_data_ob_item();

  nghttp2_stream_attach_data(d, dd, &session->ob_pq, session->last_cycle);

  /* Add subtree c to a */

  nghttp2_stream_dep_remove_subtree(c);
  nghttp2_stream_dep_add_subtree(a, c, &session->ob_pq, session->last_cycle);

  /*
   * a       b
   * |
   * e--c
   * |  |
   * f  d
   */

  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == a->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == b->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == c->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == d->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == e->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == f->dpri);

  CU_ASSERT(16 == b->effective_weight);
  CU_ASSERT(16 * 16 / 32 == e->effective_weight);
  CU_ASSERT(16 * 16 / 32 == d->effective_weight);

  CU_ASSERT(32 == a->sum_norest_weight);
  CU_ASSERT(16 == c->sum_norest_weight);

  /* Insert b under a */

  nghttp2_stream_dep_remove_subtree(b);
  nghttp2_stream_dep_insert_subtree(a, b, &session->ob_pq, session->last_cycle);

  /*
   * a
   * |
   * b
   * |
   * e--c
   * |  |
   * f  d
   */

  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == a->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == b->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == c->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_REST == d->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_REST == e->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == f->dpri);

  CU_ASSERT(16 == b->effective_weight);

  CU_ASSERT(16 == a->sum_norest_weight);
  CU_ASSERT(0 == b->sum_norest_weight);

  /* Remove subtree b */

  nghttp2_stream_dep_remove_subtree(b);
  nghttp2_stream_dep_make_root(b, &session->ob_pq, session->last_cycle);

  /*
   * b       a
   * |
   * e--c
   * |  |
   * f  d
   */

  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == a->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_TOP == b->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == c->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_REST == d->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_REST == e->dpri);
  CU_ASSERT(NGHTTP2_STREAM_DPRI_NO_DATA == f->dpri);

  CU_ASSERT(0 == a->sum_norest_weight);
  CU_ASSERT(0 == b->sum_norest_weight);

  nghttp2_session_del(session);
}

void test_nghttp2_session_keep_closed_stream(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  /* nghttp2_stream *stream; */
  const size_t max_concurrent_streams = 5;
  nghttp2_settings_entry iv = {
    NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
    max_concurrent_streams
  };
  size_t i;

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = null_send_callback;

  nghttp2_session_server_new(&session, &callbacks, NULL);

  nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, &iv, 1);

  for(i = 0; i < max_concurrent_streams; ++i) {
    open_stream(session, (int)i * 2 + 1);
  }

  CU_ASSERT(0 == session->num_closed_streams);

  nghttp2_session_close_stream(session, 1, NGHTTP2_NO_ERROR);

  CU_ASSERT(1 == session->num_closed_streams);
  CU_ASSERT(1 == session->closed_stream_tail->stream_id);
  CU_ASSERT(session->closed_stream_tail == session->closed_stream_head);

  nghttp2_session_close_stream(session, 5, NGHTTP2_NO_ERROR);

  CU_ASSERT(2 == session->num_closed_streams);
  CU_ASSERT(5 == session->closed_stream_tail->stream_id);
  CU_ASSERT(1 == session->closed_stream_head->stream_id);

  open_stream(session, 11);

  CU_ASSERT(1 == session->num_closed_streams);
  CU_ASSERT(5 == session->closed_stream_tail->stream_id);
  CU_ASSERT(session->closed_stream_tail == session->closed_stream_head);

  open_stream(session, 13);

  CU_ASSERT(0 == session->num_closed_streams);
  CU_ASSERT(NULL == session->closed_stream_tail);
  CU_ASSERT(NULL == session->closed_stream_head);

  nghttp2_session_del(session);
}

void test_nghttp2_session_graceful_shutdown(void)
{
  nghttp2_session *session;
  nghttp2_session_callbacks callbacks;
  my_user_data ud;

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = block_count_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  nghttp2_session_server_new(&session, &callbacks, &ud);

  CU_ASSERT(0 == nghttp2_submit_goaway(session, NGHTTP2_FLAG_NONE,
                                       (1u << 31) - 1, NGHTTP2_NO_ERROR,
                                       NULL, 0));

  ud.block_count = 1;
  ud.frame_send_cb_called = 0;

  CU_ASSERT(0 == nghttp2_session_send(session));

  CU_ASSERT(1 == ud.frame_send_cb_called);
  CU_ASSERT((1u << 31) - 1 == session->local_last_stream_id);

  CU_ASSERT(0 == nghttp2_session_terminate_session2(session, 300,
                                                    NGHTTP2_NO_ERROR));

  ud.block_count = 1;
  ud.frame_send_cb_called = 0;

  CU_ASSERT(0 == nghttp2_session_send(session));

  CU_ASSERT(1 == ud.frame_send_cb_called);
  CU_ASSERT(300 == session->local_last_stream_id);

  nghttp2_session_del(session);
}
