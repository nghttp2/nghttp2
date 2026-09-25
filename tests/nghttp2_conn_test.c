/*
 * nghttp2
 *
 * Copyright (c) 2026 nghttp2 contributors
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
#include "nghttp2_conn_test.h"

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif /* defined(HAVE_UNISTD_H) */
#include <errno.h>

#include "nghttp2_conn.h"
#include "nghttp2_test_helper.h"
#include "nghttp2_str.h"

static const MunitTest tests[] = {
  munit_void_test(test_nghttp2_conn_read_request),
  munit_void_test(test_nghttp2_conn_submit_request),
  munit_void_test(test_nghttp2_conn_read_preface),
  munit_void_test(test_nghttp2_conn_recv_frame_hd),
  munit_void_test(test_nghttp2_conn_recv_headers),
  munit_void_test(test_nghttp2_conn_recv_continuation),
  munit_void_test(test_nghttp2_conn_recv_data),
  munit_void_test(test_nghttp2_conn_recv_rst_stream),
  munit_void_test(test_nghttp2_conn_recv_settings),
  munit_void_test(test_nghttp2_conn_recv_ping),
  munit_void_test(test_nghttp2_conn_recv_push_promise),
  munit_void_test(test_nghttp2_conn_recv_goaway),
  munit_void_test(test_nghttp2_conn_recv_window_update),
  munit_void_test(test_nghttp2_conn_recv_priority_update),
  munit_void_test(test_nghttp2_conn_recv_unknown_frame),
  munit_void_test(test_nghttp2_conn_recv_settings_ack),
  munit_void_test(test_nghttp2_conn_conn_rx_flow_control),
  munit_void_test(test_nghttp2_conn_stream_rx_flow_control),
  munit_void_test(test_nghttp2_conn_submit_ping),
  munit_void_test(test_nghttp2_conn_send_ping_ack),
  munit_void_test(test_nghttp2_conn_shutdown_stream),
  munit_void_test(test_nghttp2_conn_recv_rst_stream_mid_tx_frame),
  munit_void_test(test_nghttp2_conn_http_writer),
  munit_void_test(test_nghttp2_conn_graceful_shutdown),
  munit_void_test(test_nghttp2_conn_stream_concurrency),
  munit_void_test(test_nghttp2_conn_rx_flow_control),
  munit_void_test(test_nghttp2_conn_tx_flow_control),
  munit_void_test(test_nghttp2_conn_http_resp_header),
  munit_void_test(test_nghttp2_conn_http_req_header),
  munit_void_test(test_nghttp2_conn_http_content_length),
  munit_void_test(test_nghttp2_conn_http_content_length_mismatch),
  munit_void_test(test_nghttp2_conn_http_non_final_response),
  munit_void_test(test_nghttp2_conn_http_trailers),
  munit_void_test(test_nghttp2_conn_http_ignore_content_length),
  munit_void_test(test_nghttp2_conn_http_record_request_method),
  munit_void_test(test_nghttp2_conn_http_error),
  munit_void_test(test_nghttp2_conn_resume_stream),
  munit_void_test(test_nghttp2_conn_terminate),
  munit_void_test(test_nghttp2_conn_handle_expiry),
  munit_void_test(test_nghttp2_conn_client_priority_update),
  munit_void_test(test_nghttp2_conn_server_priority_update),
  munit_void_test(test_nghttp2_conn_rate_limit),
  munit_void_test(test_nghttp2_conn_get_streams_left),
  munit_void_test(test_nghttp2_conn_is_server),
  munit_void_test(test_nghttp2_conn_get_timestamp),
  munit_void_test(test_nghttp2_conn_get_stream_priority),
  munit_test_end(),
};

const MunitSuite conn_suite = {
  .prefix = "/conn",
  .tests = tests,
};

static const nghttp2_nv reqnva[] = {
  MAKE_NV(":method", "GET"),
  MAKE_NV(":scheme", "https"),
  MAKE_NV(":authority", "example.com"),
  MAKE_NV(":path", "/"),
  MAKE_NV("user-agent", "libnghttp2 client"),
};

static const nghttp2_nv pri_reqnva[] = {
  MAKE_NV(":method", "GET"),
  MAKE_NV(":scheme", "https"),
  MAKE_NV(":authority", "example.com"),
  MAKE_NV(":path", "/"),
  MAKE_NV("user-agent", "libnghttp2 client"),
  MAKE_NV("priority", "u=2,i"),
};

static const nghttp2_nv respnva[] = {
  MAKE_NV(":status", "200"),
  MAKE_NV("server", "libnghttp2 server"),
};

static const nghttp2_nv notfound_respnva[] = {
  MAKE_NV(":status", "404"),
  MAKE_NV("server", "libnghttp2 server"),
};

static const nghttp2_nv infonva[] = {
  MAKE_NV(":status", "103"),
  MAKE_NV("link", "</style.css>; rel=preload; as=style"),
  MAKE_NV("link", "</script.css>; rel=preload; as=script"),
};

static const nghttp2_nv trnva[] = {
  MAKE_NV("trailer1", "foo"),
  MAKE_NV("trailer2", "bar"),
};

static const uint8_t large_field[4096];

static const nghttp2_nv large_reqnva[] = {
  MAKE_NV(":method", "GET"),
  MAKE_NV(":scheme", "https"),
  MAKE_NV(":authority", "example.com"),
  MAKE_NV(":path", "/"),
  MAKE_NV_NEVER_INDEX("foo", large_field),
  MAKE_NV_NEVER_INDEX("foo", large_field),
  MAKE_NV_NEVER_INDEX("foo", large_field),
  MAKE_NV_NEVER_INDEX("foo", large_field),
  MAKE_NV_NEVER_INDEX("foo", large_field),
  MAKE_NV_NEVER_INDEX("foo", large_field),
  MAKE_NV_NEVER_INDEX("foo", large_field),
  MAKE_NV_NEVER_INDEX("foo", large_field),
};

typedef struct conn_options {
  const nghttp2_callbacks *callbacks;
  const nghttp2_settings *settings;
  const nghttp2_mem *mem;
  void *user_data;
} conn_options;

typedef struct userdata {
  struct {
    size_t ncalled;
    nghttp2_proto_settings settings;
  } recv_settings;
  struct {
    size_t ncalled;
    int64_t stream_id;
  } begin_headers;
  struct {
    size_t ncalled;
    int64_t stream_id;
    const nghttp2_nv *expect_nva;
    size_t expect_nvlen;
    size_t expect_offset;
  } recv_header;
  struct {
    size_t ncalled;
    int64_t stream_id;
    int fin;
  } end_headers;
  struct {
    size_t ncalled;
    int64_t stream_id;
  } begin_trailers;
  struct {
    size_t ncalled;
    int64_t stream_id;
    const nghttp2_nv *expect_nva;
    size_t expect_nvlen;
    size_t expect_offset;
  } recv_trailer;
  struct {
    size_t ncalled;
    int64_t stream_id;
    int fin;
  } end_trailers;
  struct {
    size_t ncalled;
    int64_t stream_id;
    size_t datalen;
    int fin;
  } recv_data;
  struct {
    size_t ncalled;
    int64_t stream_id;
  } end_stream;
  struct {
    size_t ncalled;
    uint32_t flags;
    int64_t stream_id;
    uint32_t error_code;
  } stream_close;
  struct {
    size_t ncalled;
    int64_t last_stream_id;
    uint32_t error_code;
  } shutdown;
  struct {
    size_t ncalled;
    nghttp2_ping_data data;
  } recv_ping_ack;
  struct {
    size_t ncalled;
    int64_t stream_id;
    uint64_t offset;
    size_t datalen;
  } write_stream_data_offset;
  struct {
    size_t ncalled;
    size_t block_after;
  } read_data;
} userdata;

static void genrand(uint8_t *dest, size_t destlen) { memset(dest, 0, destlen); }

static int recv_settings(nghttp2_conn *conn,
                         const nghttp2_proto_settings *settings,
                         void *user_data) {
  userdata *ud = user_data;
  (void)conn;

  ++ud->recv_settings.ncalled;
  ud->recv_settings.settings = *settings;

  return 0;
}

static int begin_headers(nghttp2_conn *conn, int64_t stream_id,
                         void *conn_user_data, void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;
  (void)stream_user_data;

  ++ud->begin_headers.ncalled;
  ud->begin_headers.stream_id = stream_id;

  return 0;
}

static int end_headers(nghttp2_conn *conn, int64_t stream_id, int fin,
                       void *conn_user_data, void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;
  (void)stream_user_data;

  ++ud->end_headers.ncalled;
  ud->end_headers.stream_id = stream_id;
  ud->end_headers.fin = fin;

  return 0;
}

static int begin_trailers(nghttp2_conn *conn, int64_t stream_id,
                          void *conn_user_data, void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;
  (void)stream_user_data;

  ++ud->begin_trailers.ncalled;
  ud->begin_trailers.stream_id = stream_id;

  return 0;
}

static int end_trailers(nghttp2_conn *conn, int64_t stream_id, int fin,
                        void *conn_user_data, void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;
  (void)stream_user_data;

  ++ud->end_trailers.ncalled;
  ud->end_trailers.stream_id = stream_id;
  ud->end_trailers.fin = fin;

  return 0;
}

static int recv_header(nghttp2_conn *conn, int64_t stream_id, int32_t token,
                       nghttp2_rcbuf *name, nghttp2_rcbuf *value, uint8_t flags,
                       void *conn_user_data, void *stream_user_data) {
  userdata *ud = conn_user_data;
  const nghttp2_nv *nv;
  (void)conn;
  (void)token;
  (void)flags;
  (void)stream_user_data;

  ++ud->recv_header.ncalled;
  ud->recv_header.stream_id = stream_id;

  assert_size(ud->recv_header.expect_nvlen, >, ud->recv_header.expect_offset);

  nv = &ud->recv_header.expect_nva[ud->recv_header.expect_offset++];

  assert_memn_equal(nv->name, nv->namelen, name->base, name->len);
  assert_memn_equal(nv->value, nv->valuelen, value->base, value->len);

  return 0;
}

static int recv_header_rst_stream(nghttp2_conn *conn, int64_t stream_id,
                                  int32_t token, nghttp2_rcbuf *name,
                                  nghttp2_rcbuf *value, uint8_t flags,
                                  void *conn_user_data,
                                  void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)token;
  (void)name;
  (void)value;
  (void)flags;
  (void)stream_user_data;

  ++ud->recv_header.ncalled;

  nghttp2_conn_shutdown_stream(conn, 0x00, stream_id, NGHTTP2_INTERNAL_ERROR);

  return 0;
}

static int recv_trailer(nghttp2_conn *conn, int64_t stream_id, int32_t token,
                        nghttp2_rcbuf *name, nghttp2_rcbuf *value,
                        uint8_t flags, void *conn_user_data,
                        void *stream_user_data) {
  userdata *ud = conn_user_data;
  const nghttp2_nv *nv;
  (void)conn;
  (void)token;
  (void)flags;
  (void)stream_user_data;

  ++ud->recv_trailer.ncalled;
  ud->recv_trailer.stream_id = stream_id;

  assert_size(ud->recv_trailer.expect_nvlen, >, ud->recv_trailer.expect_offset);

  nv = &ud->recv_trailer.expect_nva[ud->recv_trailer.expect_offset++];

  assert_memn_equal(nv->name, nv->namelen, name->base, name->len);
  assert_memn_equal(nv->value, nv->valuelen, value->base, value->len);

  return 0;
}

static int recv_data(nghttp2_conn *conn, int64_t stream_id, const uint8_t *data,
                     size_t datalen, int fin, void *conn_user_data,
                     void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;
  (void)data;
  (void)stream_user_data;

  ++ud->recv_data.ncalled;
  ud->recv_data.stream_id = stream_id;
  ud->recv_data.datalen += datalen;
  ud->recv_data.fin = fin;

  return 0;
}

static int end_stream(nghttp2_conn *conn, int64_t stream_id,
                      void *conn_user_data, void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;
  (void)stream_user_data;

  ++ud->end_stream.ncalled;
  ud->end_stream.stream_id = stream_id;

  return 0;
}

static int stream_close(nghttp2_conn *conn, uint32_t flags, int64_t stream_id,
                        uint32_t error_code, void *conn_user_data,
                        void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;
  (void)stream_user_data;

  ++ud->stream_close.ncalled;
  ud->stream_close.flags = flags;
  ud->stream_close.stream_id = stream_id;
  ud->stream_close.error_code = error_code;

  return 0;
}

static int shutdown(nghttp2_conn *conn, int64_t last_stream_id,
                    uint32_t error_code, void *conn_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;

  ++ud->shutdown.ncalled;
  ud->shutdown.last_stream_id = last_stream_id;
  ud->shutdown.error_code = error_code;

  return 0;
}

static int recv_ping_ack(nghttp2_conn *conn, const nghttp2_ping_data *data,
                         void *conn_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;

  ++ud->recv_ping_ack.ncalled;
  ud->recv_ping_ack.data = *data;

  return 0;
}

static int write_stream_data_offset(nghttp2_conn *conn, int64_t stream_id,
                                    uint64_t offset, size_t len,
                                    void *conn_user_data,
                                    void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;
  (void)stream_user_data;

  ++ud->write_stream_data_offset.ncalled;
  ud->write_stream_data_offset.stream_id = stream_id;
  ud->write_stream_data_offset.offset = offset;
  ud->write_stream_data_offset.datalen = len;

  return 0;
}

static void log_write(void *user_data, char *msg, size_t len) {
#ifndef WIN32
  ssize_t nwrite;
  (void)user_data;

  msg[len++] = '\n';

  while ((nwrite = write(fileno(stderr), msg, len)) == -1 && errno == EINTR)
    ;

  assert_ssize((ssize_t)len, ==, nwrite);
#else  /* defined(WIN32) */
  (void)user_data;
  (void)msg;
  (void)len;
#endif /* defined(WIN32) */
}

static uint8_t nulldata[1 << 20];

static nghttp2_ssize read_data_nk(nghttp2_conn *conn, int64_t stream_id,
                                  nghttp2_vec *vec, size_t veccnt,
                                  uint32_t *pflags, void *conn_user_data,
                                  void *stream_user_data, size_t n) {
  (void)conn;
  (void)stream_id;
  (void)veccnt;
  (void)conn_user_data;
  (void)stream_user_data;

  vec[0] = (nghttp2_vec){
    .base = nulldata,
    .len = n,
  };

  *pflags |= NGHTTP2_READ_DATA_FLAG_EOF;

  return 1;
}

static nghttp2_ssize read_data_0k(nghttp2_conn *conn, int64_t stream_id,
                                  nghttp2_vec *vec, size_t veccnt,
                                  uint32_t *pflags, void *conn_user_data,
                                  void *stream_user_data) {
  return read_data_nk(conn, stream_id, vec, veccnt, pflags, conn_user_data,
                      stream_user_data, 0);
}

static nghttp2_ssize read_data_4k(nghttp2_conn *conn, int64_t stream_id,
                                  nghttp2_vec *vec, size_t veccnt,
                                  uint32_t *pflags, void *conn_user_data,
                                  void *stream_user_data) {
  return read_data_nk(conn, stream_id, vec, veccnt, pflags, conn_user_data,
                      stream_user_data, 1 << 12);
}

static nghttp2_ssize read_data_48k(nghttp2_conn *conn, int64_t stream_id,
                                   nghttp2_vec *vec, size_t veccnt,
                                   uint32_t *pflags, void *conn_user_data,
                                   void *stream_user_data) {
  return read_data_nk(conn, stream_id, vec, veccnt, pflags, conn_user_data,
                      stream_user_data, 48 * 1024);
}

static nghttp2_ssize read_data_80k(nghttp2_conn *conn, int64_t stream_id,
                                   nghttp2_vec *vec, size_t veccnt,
                                   uint32_t *pflags, void *conn_user_data,
                                   void *stream_user_data) {
  return read_data_nk(conn, stream_id, vec, veccnt, pflags, conn_user_data,
                      stream_user_data, 80 * 1024);
}

static nghttp2_ssize read_data_128k(nghttp2_conn *conn, int64_t stream_id,
                                    nghttp2_vec *vec, size_t veccnt,
                                    uint32_t *pflags, void *conn_user_data,
                                    void *stream_user_data) {
  return read_data_nk(conn, stream_id, vec, veccnt, pflags, conn_user_data,
                      stream_user_data, 1 << 17);
}

static nghttp2_ssize read_data_block(nghttp2_conn *conn, int64_t stream_id,
                                     nghttp2_vec *vec, size_t veccnt,
                                     uint32_t *pflags, void *conn_user_data,
                                     void *stream_user_data) {
  userdata *ud = stream_user_data;
  (void)conn;
  (void)stream_id;
  (void)veccnt;
  (void)pflags;
  (void)conn_user_data;

  ++ud->read_data.ncalled;

  if (ud->read_data.block_after == 0) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }

  --ud->read_data.block_after;

  vec[0] = (nghttp2_vec){
    .base = nulldata,
    .len = 1 << 12,
  };

  return 1;
}

static size_t server_default_remote_settings(nghttp2_settings_entry *iv) {
  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
    .value = 100,
  };

  return 1;
}

static void server_default_callbacks(nghttp2_callbacks *callbacks) {
  *callbacks = (nghttp2_callbacks){
    .rand = genrand,
  };
}

static void server_default_settings(nghttp2_settings *settings) {
  nghttp2_settings_default(settings);
  settings->max_concurrent_streams_remote = 100;
  settings->log_write = log_write;
}

static void setup_default_server_with_options(nghttp2_conn **pconn,
                                              conn_options opts) {
  nghttp2_callbacks callbacks;
  nghttp2_settings settings;
  int rv;

  if (!opts.callbacks) {
    server_default_callbacks(&callbacks);
    opts.callbacks = &callbacks;
  }

  if (!opts.settings) {
    server_default_settings(&settings);
    opts.settings = &settings;
  }

  rv = nghttp2_conn_server_new(pconn, opts.callbacks, opts.settings, opts.mem,
                               opts.user_data);

  assert_int(0, ==, rv);
}

static void setup_default_server(nghttp2_conn **pconn) {
  setup_default_server_with_options(pconn, (conn_options){0});
}

/* static size_t client_default_remote_settings(nghttp2_settings_entry *iv) { */
/*   iv[0] = (nghttp2_settings_entry){ */
/*     .id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, */
/*     .value = 100, */
/*   }; */

/*   return 1; */
/* } */

static void client_default_callbacks(nghttp2_callbacks *callbacks) {
  *callbacks = (nghttp2_callbacks){
    .rand = genrand,
  };
}

static void client_default_settings(nghttp2_settings *settings) {
  nghttp2_settings_default(settings);
  settings->log_write = log_write;
}

static void setup_default_client_with_options(nghttp2_conn **pconn,
                                              conn_options opts) {
  nghttp2_callbacks callbacks;
  nghttp2_settings settings;
  int rv;

  if (!opts.callbacks) {
    client_default_callbacks(&callbacks);
    opts.callbacks = &callbacks;
  }

  if (!opts.settings) {
    client_default_settings(&settings);
    opts.settings = &settings;
  }

  rv = nghttp2_conn_client_new(pconn, opts.callbacks, opts.settings, opts.mem,
                               opts.user_data);

  assert_int(0, ==, rv);
}

static void setup_default_client(nghttp2_conn **pconn) {
  setup_default_client_with_options(pconn, (conn_options){0});
}

static void read_client_preface(nghttp2_conn *conn,
                                const nghttp2_settings_entry *iv, size_t ivlen,
                                nghttp2_tstamp ts) {
  int rv;
  uint8_t rawbuf[256];
  nghttp2_buf buf;

  rv = nghttp2_conn_read(conn, (const uint8_t *)NGHTTP2_CLIENT_HTTP2_PREFACE,
                         nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE), ts);

  assert_int(0, ==, rv);

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  write_settings(&buf, iv, ivlen);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ts);

  assert_int(0, ==, rv);
}

static void read_server_preface(nghttp2_conn *conn,
                                const nghttp2_settings_entry *iv, size_t ivlen,
                                nghttp2_tstamp ts) {
  int rv;
  uint8_t rawbuf[256];
  nghttp2_buf buf;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  write_settings(&buf, iv, ivlen);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ts);

  assert_int(0, ==, rv);
}

static void write_preface_with_window_update(nghttp2_conn *conn,
                                             uint32_t window_size_inc,
                                             nghttp2_tstamp ts) {
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  nghttp2_ssize nwrite;
  nghttp2_frd frd;
  nghttp2_frame fr;
  int rv;

  nghttp2_frd_init(&frd);
  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  nwrite = nghttp2_conn_write(conn, buf.last, nghttp2_buf_left(&buf), ts);

  assert_ptrdiff(0, <, nwrite);

  buf.last += nwrite;

  if (!conn->server) {
    assert_size(nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE), <,
                nghttp2_buf_len(&buf));
    assert_memory_equal(nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE),
                        NGHTTP2_CLIENT_HTTP2_PREFACE, buf.pos);

    buf.pos += nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE);
  }

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_SETTINGS, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.settings.hd.flags);

  if (window_size_inc == UINT32_MAX) {
    assert_size(0, ==, nghttp2_buf_len(&buf));
    return;
  }

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_WINDOW_UPDATE, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.window_update.hd.flags);
  assert_int64(0x00, ==, fr.window_update.hd.stream_id);
  assert_uint32(window_size_inc, ==, fr.window_update.window_size_inc);
  assert_size(0, ==, nghttp2_buf_len(&buf));
}

static void write_preface(nghttp2_conn *conn, nghttp2_tstamp ts) {
  write_preface_with_window_update(conn, UINT32_MAX, ts);
}

static void read_settings_ack(nghttp2_conn *conn, nghttp2_tstamp ts) {
  uint8_t rawbuf[256];
  nghttp2_buf buf;
  nghttp2_frame fr;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
      },
  };

  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ts);

  assert_int(0, ==, rv);
}

static void write_settings_ack(nghttp2_conn *conn, nghttp2_tstamp ts) {
  uint8_t rawbuf[256];
  nghttp2_buf buf;
  nghttp2_ssize nwrite;
  nghttp2_frd frd;
  nghttp2_frame fr;
  int rv;

  nghttp2_frd_init(&frd);
  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  nwrite = nghttp2_conn_write(conn, buf.last, nghttp2_buf_left(&buf), ts);

  assert_ptrdiff(0, <, nwrite);

  buf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint32(0, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_SETTINGS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_SETTINGS_FLAG_ACK, ==, fr.settings.hd.flags);
  assert_size(0, ==, nghttp2_buf_len(&buf));
}

void test_nghttp2_conn_read_request(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  nghttp2_settings_entry iv[16];
  size_t ivlen;
  nghttp2_frame fr;
  nghttp2_hpack_encoder enc;
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  nghttp2_buf hbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_stream *stream;
  userdata ud;
  nghttp2_callbacks callbacks;
  conn_options opts;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  /* Read request without data */
  server_default_callbacks(&callbacks);
  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.end_stream = end_stream;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ivlen = server_default_remote_settings(iv);
  read_client_preface(conn, iv, ivlen, ts);

  nghttp2_buf_init(&hbuf);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 1,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){
    .recv_header.expect_nva = reqnva,
    .recv_header.expect_nvlen = nghttp2_arraylen(reqnva),
  };
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_int64(1, ==, ud.begin_headers.stream_id);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_int64(1, ==, ud.end_headers.stream_id);
  assert_true(ud.end_headers.fin);
  assert_size(nghttp2_arraylen(reqnva), ==, ud.recv_header.ncalled);
  assert_int64(1, ==, ud.recv_header.stream_id);
  assert_size(nghttp2_arraylen(reqnva), ==, ud.recv_header.expect_offset);
  assert_size(1, ==, ud.end_stream.ncalled);
  assert_int64(1, ==, ud.end_stream.stream_id);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_buf_free(&hbuf, mem);
  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Read request with data */
  server_default_callbacks(&callbacks);
  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.end_stream = end_stream;
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ivlen = server_default_remote_settings(iv);
  read_client_preface(conn, iv, ivlen, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_init(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 1,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){
    .recv_header.expect_nva = reqnva,
    .recv_header.expect_nvlen = nghttp2_arraylen(reqnva),
  };
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_int64(1, ==, ud.begin_headers.stream_id);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_int64(1, ==, ud.end_headers.stream_id);
  assert_false(ud.end_headers.fin);
  assert_size(nghttp2_arraylen(reqnva), ==, ud.recv_header.ncalled);
  assert_int64(1, ==, ud.recv_header.stream_id);
  assert_size(nghttp2_arraylen(reqnva), ==, ud.recv_header.expect_offset);
  assert_size(0, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = 1,
      },
    .datalen = 77,
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.recv_data.ncalled);
  assert_int64(1, ==, ud.recv_data.stream_id);
  assert_size(77, ==, ud.recv_data.datalen);
  assert_false(ud.recv_data.fin);
  assert_size(0, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
        .stream_id = 1,
      },
    .datalen = 22,
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.recv_data.ncalled);
  assert_int64(1, ==, ud.recv_data.stream_id);
  assert_size(22, ==, ud.recv_data.datalen);
  assert_true(ud.recv_data.fin);
  assert_size(1, ==, ud.end_stream.ncalled);
  assert_int64(1, ==, ud.end_stream.stream_id);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_buf_free(&hbuf, mem);
  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Read request with data and trailers */
  server_default_callbacks(&callbacks);
  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.begin_trailers = begin_trailers;
  callbacks.recv_trailer = recv_trailer;
  callbacks.end_trailers = end_trailers;
  callbacks.end_stream = end_stream;
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ivlen = server_default_remote_settings(iv);
  read_client_preface(conn, iv, ivlen, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_init(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 1,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){
    .recv_header.expect_nva = reqnva,
    .recv_header.expect_nvlen = nghttp2_arraylen(reqnva),
  };
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_int64(1, ==, ud.begin_headers.stream_id);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_int64(1, ==, ud.end_headers.stream_id);
  assert_false(ud.end_headers.fin);
  assert_size(nghttp2_arraylen(reqnva), ==, ud.recv_header.ncalled);
  assert_int64(1, ==, ud.recv_header.stream_id);
  assert_size(nghttp2_arraylen(reqnva), ==, ud.recv_header.expect_offset);
  assert_size(0, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = 1,
      },
    .datalen = 77,
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.recv_data.ncalled);
  assert_int64(1, ==, ud.recv_data.stream_id);
  assert_size(77, ==, ud.recv_data.datalen);
  assert_false(ud.recv_data.fin);
  assert_size(0, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, trnva, nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 1,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){
    .recv_trailer.expect_nva = trnva,
    .recv_trailer.expect_nvlen = nghttp2_arraylen(trnva),
  };
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_trailers.ncalled);
  assert_int64(1, ==, ud.begin_trailers.stream_id);
  assert_size(1, ==, ud.end_trailers.ncalled);
  assert_int64(1, ==, ud.end_trailers.stream_id);
  assert_true(ud.end_trailers.fin);
  assert_size(nghttp2_arraylen(trnva), ==, ud.recv_trailer.ncalled);
  assert_int64(1, ==, ud.recv_trailer.stream_id);
  assert_size(nghttp2_arraylen(trnva), ==, ud.recv_trailer.expect_offset);
  assert_size(1, ==, ud.end_stream.ncalled);
  assert_int64(1, ==, ud.end_stream.stream_id);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_buf_free(&hbuf, mem);
  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Read request including CONTINUATION without data */
  server_default_callbacks(&callbacks);
  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.end_stream = end_stream;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ivlen = server_default_remote_settings(iv);
  read_client_preface(conn, iv, ivlen, ts);

  nghttp2_buf_init(&hbuf);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 1,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf) - 1,
  };

  hbuf.pos += fr.headers.field_blocklen;
  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){
    .recv_header.expect_nva = reqnva,
    .recv_header.expect_nvlen = nghttp2_arraylen(reqnva) - 1,
  };
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_int64(1, ==, ud.begin_headers.stream_id);
  assert_size(0, ==, ud.end_headers.ncalled);
  assert_size(nghttp2_arraylen(reqnva) - 1, ==, ud.recv_header.ncalled);
  assert_int64(1, ==, ud.recv_header.stream_id);
  assert_size(nghttp2_arraylen(reqnva) - 1, ==, ud.recv_header.expect_offset);
  assert_size(0, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_CONTINUATION,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 1,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){
    .recv_header.expect_nva = &reqnva[nghttp2_arraylen(reqnva) - 1],
    .recv_header.expect_nvlen = 1,
  };
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(0, ==, ud.begin_headers.ncalled);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_int64(1, ==, ud.end_headers.stream_id);
  assert_true(ud.end_headers.fin);
  assert_size(1, ==, ud.recv_header.ncalled);
  assert_int64(1, ==, ud.recv_header.stream_id);
  assert_size(1, ==, ud.recv_header.expect_offset);
  assert_size(1, ==, ud.end_stream.ncalled);
  assert_int64(1, ==, ud.end_stream.stream_id);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_buf_free(&hbuf, mem);
  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_submit_request(void) {
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  int64_t stream_id;
  nghttp2_ssize nwrite;
  nghttp2_tstamp ts = 0;
  nghttp2_stream *stream;
  nghttp2_frame fr;
  nghttp2_frd frd;
  nghttp2_callbacks callbacks;
  userdata ud;
  conn_options opts;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  /* 4k data */
  setup_default_client(&conn);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_4k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&buf);
  nwrite = nghttp2_conn_write(conn, buf.last, nghttp2_buf_left(&buf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  buf.last += nwrite;

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_WR);

  check_http2_preface(&buf);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_SETTINGS, ==, fr.meta.hd.type);
  assert_uint8(0x00U, ==, fr.settings.hd.flags);
  assert_int64(0, ==, fr.settings.hd.stream_id);
  assert_size(2, ==, fr.settings.niv);
  assert_uint16(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, ==,
                fr.settings.iv[0].id);
  assert_uint32(0, ==, fr.settings.iv[0].value);
  assert_uint16(NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES, ==,
                fr.settings.iv[1].id);
  assert_uint32(1, ==, fr.settings.iv[1].value);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);
  assert_size(0, ==, fr.headers.padlen);
  assert_size(0, <, fr.headers.field_blocklen);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_DATA_FLAG_END_STREAM, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.data.hd.stream_id);
  assert_size(0, ==, fr.data.padlen);
  assert_size(4096, ==, fr.data.datalen);
  assert_size(0, ==, nghttp2_buf_len(&buf));

  nghttp2_conn_del(conn);

  /* 128k data */
  client_default_callbacks(&callbacks);
  callbacks.write_stream_data_offset = write_stream_data_offset;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_client_with_options(&conn, opts);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_128k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  ud = (userdata){0};

  for (;;) {
    nghttp2_buf_reset(&buf);
    nwrite = nghttp2_conn_write(conn, buf.last, nghttp2_buf_left(&buf), ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }
  }

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_FC_BLOCKED);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_WR);
  assert_false(nghttp2_http_writer_empty(&stream->tx.hw));

  conn->tx.max_offset += 65537;
  stream->tx.max_offset += 65537;

  for (;;) {
    nghttp2_buf_reset(&buf);
    nwrite = nghttp2_conn_write(conn, buf.last, nghttp2_buf_left(&buf), ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }
  }

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(nghttp2_http_writer_empty(&stream->tx.hw));
  assert_uint64(1 << 17, ==,
                ud.write_stream_data_offset.offset +
                  ud.write_stream_data_offset.datalen);

  nghttp2_conn_del(conn);

  /* trailers */
  setup_default_client(&conn);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_4k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  rv = nghttp2_conn_submit_trailers(conn, stream_id, trnva,
                                    nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&buf);
  nwrite = nghttp2_conn_write(conn, buf.last, nghttp2_buf_left(&buf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  buf.last += nwrite;

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_WR);

  check_http2_preface(&buf);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_SETTINGS, ==, fr.meta.hd.type);
  assert_uint8(0x00U, ==, fr.settings.hd.flags);
  assert_int64(0, ==, fr.settings.hd.stream_id);
  assert_size(2, ==, fr.settings.niv);
  assert_uint16(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, ==,
                fr.settings.iv[0].id);
  assert_uint32(0, ==, fr.settings.iv[0].value);
  assert_uint16(NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES, ==,
                fr.settings.iv[1].id);
  assert_uint32(1, ==, fr.settings.iv[1].value);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);
  assert_size(0, ==, fr.headers.padlen);
  assert_size(0, <, fr.headers.field_blocklen);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(0x00U, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.data.hd.stream_id);
  assert_size(0, ==, fr.data.padlen);
  assert_size(4096, ==, fr.data.datalen);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM,
               ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);
  assert_size(0, ==, fr.headers.padlen);
  assert_size(0, <, fr.headers.field_blocklen);
  assert_size(0, ==, nghttp2_buf_len(&buf));

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_read_preface(void) {
  static const nghttp2_frame_settings settings = {
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
  };
  static const nghttp2_frame_window_update wu = {
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
      },
    .window_size_inc = 1000,
  };
  nghttp2_conn *conn;
  nghttp2_tstamp ts = 0;
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  /* server: read client preface */
  setup_default_server(&conn);

  rv =
    nghttp2_conn_read(conn, (const uint8_t *)NGHTTP2_CLIENT_HTTP2_PREFACE,
                      nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* server: read client preface one byte at a time */
  setup_default_server(&conn);

  for (i = 0; i < nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE); ++i) {
    rv = nghttp2_conn_read(
      conn, (const uint8_t *)NGHTTP2_CLIENT_HTTP2_PREFACE + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &settings);

  assert_int(0, ==, rv);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* server: receive bad HTTP/2 preface */
  setup_default_server(&conn);

  for (i = 0; i < nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE) - 1; ++i) {
    rv = nghttp2_conn_read(
      conn, (const uint8_t *)NGHTTP2_CLIENT_HTTP2_PREFACE + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  rv = nghttp2_conn_read(conn, (const uint8_t *)"\0", 1, ++ts);

  assert_int(NGHTTP2_ERR_PROTO, ==, rv);

  nghttp2_conn_del(conn);

  /* server: receive a frame other than SETTINGS as the first frame */
  setup_default_server(&conn);

  rv =
    nghttp2_conn_read(conn, (const uint8_t *)NGHTTP2_CLIENT_HTTP2_PREFACE,
                      nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_window_update(&buf, &wu);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(NGHTTP2_ERR_PROTO, ==, rv);

  nghttp2_conn_del(conn);

  /* client: receive server preface */
  setup_default_client(&conn);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* client: receive server preface one byte at a time */
  setup_default_client(&conn);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &settings);

  assert_int(0, ==, rv);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* client: receive client preface */
  setup_default_client(&conn);

  /* This would lead to very large frame length */
  rv =
    nghttp2_conn_read(conn, (const uint8_t *)NGHTTP2_CLIENT_HTTP2_PREFACE,
                      nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE), ++ts);

  assert_int(NGHTTP2_ERR_PROTO, ==, rv);

  nghttp2_conn_del(conn);

  /* client: receive a frame other than SETTINGS as the first frame */
  setup_default_client(&conn);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_window_update(&buf, &wu);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(NGHTTP2_ERR_PROTO, ==, rv);

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_recv_frame_hd(void) {
  nghttp2_conn *conn;
  nghttp2_tstamp ts = 0;
  int rv;

  /* Frame length is too large */
  setup_default_server(&conn);

  read_client_preface(conn, NULL, 0, ts);

  rv = nghttp2_conn_read(conn, (const uint8_t *)"\x00\x40\x01", 3, ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_FRAME_SIZE_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* The largest frame length */
  setup_default_server(&conn);

  read_client_preface(conn, NULL, 0, ts);

  rv = nghttp2_conn_read(conn, (const uint8_t *)"\xFF\xFF\xFF", 3, ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_FRAME_SIZE_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_recv_headers(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_frame fr;
  nghttp2_hpack_encoder enc;
  nghttp2_stream *stream;
  nghttp2_callbacks callbacks;
  userdata ud;
  conn_options opts;
  int64_t stream_id;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* Receive HEADERS with END_HEADERS, END_STREAM, PADDED, and
     PRIORITY flags set */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM | NGHTTP2_HEADERS_FLAG_PADDED |
                 NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 0x01,
      },
    .padlen = 11,
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Read 1 byte at a time */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_HEADERS, END_STREAM, and PADDED flags
     set */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM | NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .padlen = 11,
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_HEADERS, END_STREAM, and PRIORITY flags
     set */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM |
                 NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_HEADERS and END_STREAM flags set */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_HEADERS flags set */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with no flags set */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_HEADERS, END_STREAM, and PADDED flags
     set, and the length of padding is 0 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM | NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with PADDED flags set */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .padlen = 1,
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with stream ID == 0 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with stream ID == 2 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x02,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with PADDED flag set and the length is too
     short */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with PADDED flag set and the length is too
     short */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .padlen = 10,
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers) - 1;

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with PRIORITY flag set and the length is too
     short */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with PADDED and PRIORITY flags set and the length
     is too short */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .len = 5,
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PADDED | NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with PADDED flag set and the length is too
     short */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PADDED | NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 0x01,
      },
    .padlen = 10,
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers) - 1;

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_HEADERS flag set and it is 0 length */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive HEADERS without END_HEADERS flag set and it is 0 length */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_STREAMS flag set and it is 0 length */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with just 1 byte padding */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with just 2 byte padding and no field block */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .padlen = 1,
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with just priority */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 0x01,
      },
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Receive trailer HEADERS with END_HEADERS and 0 length field
     block */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive trailer HEADERS without END_STREAM */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive trailer HEADERS with END_HEADERS and PADDED, and 1 padded byte
     and 0 length field block */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM | NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive trailer HEADERS with END_HEADERS and PRIORITY, and 0
     length field block */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM |
                 NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 0x01,
      },
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS for the closed stream */
  server_default_callbacks(&callbacks);

  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.end_stream = end_stream;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x03,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  ud.recv_header.expect_nva = reqnva;
  ud.recv_header.expect_nvlen = nghttp2_arraylen(reqnva);
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_size(5, ==, ud.recv_header.ncalled);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_size(1, ==, ud.end_stream.ncalled);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(0, ==, ud.begin_headers.ncalled);
  assert_size(0, ==, ud.recv_header.ncalled);
  assert_size(0, ==, ud.end_headers.ncalled);
  assert_size(0, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_null(stream);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS to idle stream */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, respnva,
                                   nghttp2_arraylen(respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS to the stream that client has not requested
     yet */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, respnva,
                                   nghttp2_arraylen(respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_recv_continuation(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_frame fr;
  nghttp2_hpack_encoder enc;
  nghttp2_stream *stream;
  nghttp2_callbacks callbacks;
  userdata ud;
  conn_options opts;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* Receive HEADERS with END_STREAM and CONTINUATION. */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf) / 2,
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  hbuf.pos += nghttp2_buf_len(&hbuf) / 2;

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_CONTINUATION,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_STREAM followed by 0-length
     CONTINUATION */
  server_default_callbacks(&callbacks);

  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.end_stream = end_stream;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_CONTINUATION,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  ud.recv_header.expect_nva = reqnva;
  ud.recv_header.expect_nvlen = nghttp2_arraylen(reqnva);
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_size(5, ==, ud.recv_header.ncalled);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_size(1, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_STREAM followed by 0-length CONTINUATION
     without END_HEADERS then another CONTINUATION */
  server_default_callbacks(&callbacks);

  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.end_stream = end_stream;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_CONTINUATION,
        .stream_id = 0x01,
      },
  };

  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_CONTINUATION,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  ud.recv_header.expect_nva = reqnva;
  ud.recv_header.expect_nvlen = nghttp2_arraylen(reqnva);
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_size(5, ==, ud.recv_header.ncalled);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_size(1, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* 2 CONTINUATION frames */
  server_default_callbacks(&callbacks);

  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.end_stream = end_stream;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf) / 2,
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  hbuf.pos += nghttp2_buf_len(&hbuf) / 2;

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_CONTINUATION,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf) / 2,
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  hbuf.pos += nghttp2_buf_len(&hbuf) / 2;

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_CONTINUATION,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  ud.recv_header.expect_nva = reqnva;
  ud.recv_header.expect_nvlen = nghttp2_arraylen(reqnva);
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_size(5, ==, ud.recv_header.ncalled);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_size(1, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Read 1 byte at a time */
  server_default_callbacks(&callbacks);

  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.end_stream = end_stream;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);

  ud = (userdata){0};
  ud.recv_header.expect_nva = reqnva;
  ud.recv_header.expect_nvlen = nghttp2_arraylen(reqnva);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_size(5, ==, ud.recv_header.ncalled);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_size(1, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_conn_del(conn);

  /* Receive CONTINUATION and its length is too large */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .len = NGHTTP2_DEFAULT_MAX_FRAME_SIZE + 1,
        .type = NGHTTP2_FRAME_CONTINUATION,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  buf.last = nghttp2_frame_encode_hd(buf.last, &fr.headers.hd);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_FRAME_SIZE_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS when CONTINUATION is expected */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .len = 1,
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  buf.last = nghttp2_frame_encode_hd(buf.last, &fr.headers.hd);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive CONTINUATION with the wrong stream ID */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x03,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .len = 1,
        .type = NGHTTP2_FRAME_CONTINUATION,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  buf.last = nghttp2_frame_encode_hd(buf.last, &fr.headers.hd);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive CONTINUATION that does not follow HEADERS */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_CONTINUATION,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  buf.last = nghttp2_frame_encode_hd(buf.last, &fr.headers.hd);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_recv_data(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_frame fr;
  nghttp2_hpack_encoder enc;
  nghttp2_stream *stream;
  nghttp2_callbacks callbacks;
  userdata ud;
  conn_options opts;
  int64_t stream_id;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* Receive DATA with PADDED and END_STREAM set */
  server_default_callbacks(&callbacks);
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM | NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .padlen = 11,
    .data = nulldata,
    .datalen = 111,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.recv_data.ncalled);
  assert_int64(0x01, ==, ud.recv_data.stream_id);
  assert_size(111, ==, ud.recv_data.datalen);
  assert_true(ud.recv_data.fin);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive 1 byte at a time */
  server_default_callbacks(&callbacks);
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);

  ud = (userdata){0};

  for (i = 0; i < nghttp2_buf_len(&buf) - 12; ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_size(110, ==, ud.recv_data.ncalled);
  assert_int64(0x01, ==, ud.recv_data.stream_id);
  assert_size(110, ==, ud.recv_data.datalen);
  assert_false(ud.recv_data.fin);

  for (i = nghttp2_buf_len(&buf) - 12; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(111, ==, ud.recv_data.ncalled);
  assert_int64(0x01, ==, ud.recv_data.stream_id);
  assert_size(111, ==, ud.recv_data.datalen);
  assert_true(ud.recv_data.fin);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_conn_del(conn);

  /* Receive DATA with PADDED and no END_STREAM set */
  server_default_callbacks(&callbacks);
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .padlen = 11,
    .data = nulldata,
    .datalen = 111,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.recv_data.ncalled);
  assert_int64(0x01, ==, ud.recv_data.stream_id);
  assert_size(111, ==, ud.recv_data.datalen);
  assert_false(ud.recv_data.fin);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive DATA without PADDED flag set */
  server_default_callbacks(&callbacks);
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .data = nulldata,
    .datalen = 111,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.recv_data.ncalled);
  assert_int64(0x01, ==, ud.recv_data.stream_id);
  assert_size(111, ==, ud.recv_data.datalen);
  assert_true(ud.recv_data.fin);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive DATA with PADDED flag set and the length is too short */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = 0x01,
      },
  };

  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive DATA with PADDED flag set and the length is too short */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .len = 1,
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .padlen = 1,
  };

  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive 0 length DATA */
  server_default_callbacks(&callbacks);
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
  };

  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.recv_data.ncalled);
  assert_int64(0x01, ==, ud.recv_data.stream_id);
  assert_size(0, ==, ud.recv_data.datalen);
  assert_true(ud.recv_data.fin);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive 0 length DATA with 1 byte padding */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM | NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = 0x01,
      },
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive DATA on the closed stream  */
  server_default_callbacks(&callbacks);
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x03,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .data = nulldata,
    .datalen = 99,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(0, ==, ud.recv_data.ncalled);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_null(stream);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive DATA with stream ID = 0x00  */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
      },
    .data = nulldata,
    .datalen = 99,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive DATA to idle stream  */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .data = nulldata,
    .datalen = 99,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive DATA to the stream the local endpoint has not sent */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .data = nulldata,
    .datalen = 99,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_recv_rst_stream(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  uint8_t outbuf[16384];
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_frame fr;
  nghttp2_hpack_encoder enc;
  nghttp2_stream *stream;
  nghttp2_ssize nwrite;
  int64_t stream_id;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* Receive RST_STREAM */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = 0x01,
      },
    .error_code = NGHTTP2_PROTOCOL_ERROR,
  };

  rv = nghttp2_frame_encode_rst_stream(&buf, &fr.rst_stream);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_null(stream);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive 1 byte at a time */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_null(stream);

  nghttp2_conn_del(conn);

  /* Receive RST_STREAM with stream ID == 0 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_RST_STREAM,
      },
    .error_code = NGHTTP2_PROTOCOL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_rst_stream(&buf, &fr.rst_stream);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive RST_STREAM with frame length != 4 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = 0x01,
      },
    .error_code = NGHTTP2_PROTOCOL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_rst_stream(&buf, &fr.rst_stream);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive RST_STREAM against the idle stream */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = 0x01,
      },
    .error_code = NGHTTP2_PROTOCOL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_rst_stream(&buf, &fr.rst_stream);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive RST_STREAM on the closed stream */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x03,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = 0x01,
      },
    .error_code = NGHTTP2_PROTOCOL_ERROR,
  };

  rv = nghttp2_frame_encode_rst_stream(&buf, &fr.rst_stream);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x03);

  assert_not_null(stream);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive RST_STREAM to the stream that client has not requested */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = 0x01,
      },
    .error_code = NGHTTP2_PROTOCOL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_rst_stream(&buf, &fr.rst_stream);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive RST_STREAM twice */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, NGHTTP2_FRAME_HDLEN, ++ts);

  assert_ptrdiff(0, <, nwrite);

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = 0x01,
      },
    .error_code = NGHTTP2_PROTOCOL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_rst_stream(&buf, &fr.rst_stream);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_recv_settings(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  nghttp2_frame fr;
  nghttp2_settings_entry iv[16];
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_hpack_encoder enc;
  nghttp2_stream *stream;
  userdata ud;
  nghttp2_callbacks callbacks;
  conn_options opts;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* Receive empty SETTINGS */
  server_default_callbacks(&callbacks);
  callbacks.recv_settings = recv_settings;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_size(1, ==, ud.recv_settings.ncalled);
  assert_size(NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, ==,
              ud.recv_settings.settings.hpack_max_dtable_capacity);
  assert_uint32(0, ==, ud.recv_settings.settings.max_concurrent_streams);
  assert_uint32(NGHTTP2_INITIAL_WINDOW_SIZE, ==,
                ud.recv_settings.settings.initial_max_stream_data);
  assert_uint32(0, ==, ud.recv_settings.settings.max_field_section_size);
  assert_uint32(0, ==, ud.recv_settings.settings.enable_connect_protocol);

  nghttp2_conn_del(conn);

  /* Receive non-empty SETTINGS */
  server_default_callbacks(&callbacks);
  callbacks.recv_settings = recv_settings;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
    .value = 1024,
  };
  iv[1] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
    .value = 2048,
  };
  iv[2] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
    .value = 111,
  };
  iv[3] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
    .value = INT32_MAX,
  };
  iv[4] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
    .value = UINT32_MAX,
  };
  iv[5] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL,
    .value = 1,
  };
  iv[6] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_PUSH,
    .value = 1,
  };
  iv[7] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
    .value = 1 << 20,
  };
  iv[8] = (nghttp2_settings_entry){
    .id = UINT16_MAX,
    .value = UINT32_MAX,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 9,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_size(1, ==, ud.recv_settings.ncalled);
  assert_size(2048, ==, ud.recv_settings.settings.hpack_max_dtable_capacity);
  assert_uint32(0, ==, ud.recv_settings.settings.max_concurrent_streams);
  assert_uint32(INT32_MAX, ==,
                ud.recv_settings.settings.initial_max_stream_data);
  assert_uint32(UINT32_MAX, ==,
                ud.recv_settings.settings.max_field_section_size);
  assert_uint32(1, ==, ud.recv_settings.settings.enable_connect_protocol);

  nghttp2_conn_del(conn);

  /* Read 1 byte at a time */
  server_default_callbacks(&callbacks);
  callbacks.recv_settings = recv_settings;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);

  ud = (userdata){0};

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_size(1, ==, ud.recv_settings.ncalled);
  assert_size(2048, ==, ud.recv_settings.settings.hpack_max_dtable_capacity);
  assert_uint32(0, ==, ud.recv_settings.settings.max_concurrent_streams);
  assert_uint32(INT32_MAX, ==,
                ud.recv_settings.settings.initial_max_stream_data);
  assert_uint32(UINT32_MAX, ==,
                ud.recv_settings.settings.max_field_section_size);
  assert_uint32(1, ==, ud.recv_settings.settings.enable_connect_protocol);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS_ENABLE_PUSH other than 0 or 1 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_PUSH,
    .value = 2,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 1,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS_ENABLE_CONNECT_PROTOCOL turned on then turned
     off */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL,
    .value = 1,
  };
  iv[1] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 2,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS_INITIAL_WINDOW_SIZE that exceeds the maximum
     value */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
    .value = NGHTTP2_MAX_WINDOW_SIZE + 1U,
  };
  iv[1] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
    .value = NGHTTP2_MAX_WINDOW_SIZE,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 2,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS_MAX_FRAME_SIZE that is less than the minimum
     value. */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
    .value = NGHTTP2_DEFAULT_MAX_FRAME_SIZE - 1U,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 1,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS_MAX_FRAME_SIZE that exceeds the maximum
     value. */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
    .value = NGHTTP2_HARD_MAX_FRAME_SIZE + 1U,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 1,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS with stream_id != 0 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS with ACK flag set which is unexpected */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS with ACK flag */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  conn->flags |= NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK;

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_uint32(100, ==, conn->rx.max_concurrent_streams);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS with ACK flag with non-zero payload*/
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  conn->flags |= NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK;

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .len = 6,
        .type = NGHTTP2_FRAME_SETTINGS,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS with length is not multiple of 6 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .len = 17,
        .type = NGHTTP2_FRAME_SETTINGS,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS with SETTINGS_ENABLE_PUSH = 1 from server */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_PUSH,
    .value = 1,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 1,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS with SETTINGS_ENABLE_PUSH = 0 from server */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_PUSH,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 1,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Value is split into 2 */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_PUSH,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 1,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, NGHTTP2_FRAME_HDLEN + 3, ++ts);

  assert_int(0, ==, rv);

  buf.pos += NGHTTP2_FRAME_HDLEN + 3;

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Apply new remote limits */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
    .value = 32768,
  };
  iv[1] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
  };
  iv[2] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
    .value = 2048,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 3,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint64(32768, ==, stream->tx.max_offset);
  assert_uint64(NGHTTP2_INITIAL_WINDOW_SIZE, ==, conn->tx.max_offset);
  assert_size(0, ==, conn->tx.henc.min_dtable_capacity);
  assert_size(2048, ==, conn->tx.henc.ctx.max_dtable_capacity);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Set maximum window size */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
    .value = INT32_MAX,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 1,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint64(INT32_MAX, ==, stream->tx.max_offset);
  assert_uint64(NGHTTP2_INITIAL_WINDOW_SIZE, ==, conn->tx.max_offset);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Applying window size causes flow control window overflow */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.window_update = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
        .stream_id = 0x01,
      },
    .window_size_inc = NGHTTP2_MAX_WINDOW_SIZE - NGHTTP2_INITIAL_WINDOW_SIZE,
  };

  rv = nghttp2_frame_encode_window_update(&buf, &fr.window_update);

  assert_int(0, ==, rv);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
    .value = NGHTTP2_INITIAL_WINDOW_SIZE + 1,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 1,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_FLOW_CONTROL_ERROR, ==, conn->tx.goaway.error_code);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint64(INT32_MAX, ==, stream->tx.max_offset);
  assert_uint64(NGHTTP2_INITIAL_WINDOW_SIZE, ==, conn->tx.max_offset);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_recv_ping(void) {
  nghttp2_conn *conn;
  nghttp2_frame fr;
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  nghttp2_tstamp ts = 0;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  /* Receive PING */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.ping = (nghttp2_frame_ping){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_PING,
      },
    .data =
      {
        .data = {0xFA, 0xCE, 0xCA, 0xFE},
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_ping(&buf, &fr.ping);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_size(1, ==, nghttp2_ringbuf_len(&conn->rx.ping.data.rb));

  nghttp2_conn_del(conn);

  /* Read 1 byte at a time */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_size(1, ==, nghttp2_ringbuf_len(&conn->rx.ping.data.rb));

  nghttp2_conn_del(conn);

  /* Receive PING with bad length */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.ping = (nghttp2_frame_ping){
    .hd =
      {
        .len = 7,
        .type = NGHTTP2_FRAME_PING,
      },
    .data =
      {
        .data = {0xFA, 0xCE, 0xCA, 0xFE},
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_ping(&buf, &fr.ping);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive PING with nonzero stream ID */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.ping = (nghttp2_frame_ping){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_PING,
        .stream_id = 0x01,
      },
    .data =
      {
        .data = {0xFA, 0xCE, 0xCA, 0xFE},
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_ping(&buf, &fr.ping);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive PING more than we can cope with */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.ping = (nghttp2_frame_ping){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_PING,
      },
    .data =
      {
        .data = {0xFA, 0xCE, 0xCA, 0xFE},
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_ping(&buf, &fr.ping);

  assert_int(0, ==, rv);

  for (i = 0; i < NGHTTP2_MAX_PING_ACK; ++i) {
    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    assert_int(0, ==, rv);
    assert_size(i + 1, ==, nghttp2_ringbuf_len(&conn->rx.ping.data.rb));
  }

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_recv_push_promise(void) {
  nghttp2_conn *conn;
  nghttp2_frame fr;
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  nghttp2_tstamp ts = 0;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  /* Receive PUSH_PROMISE */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  fr.meta.hd = (nghttp2_frame_hd){
    .type = NGHTTP2_FRAME_PUSH_PROMISE,
    .stream_id = 0x01,
  };

  nghttp2_buf_reset(&buf);
  buf.last = nghttp2_frame_encode_hd(buf.last, &fr.meta.hd);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_recv_goaway(void) {
  nghttp2_conn *conn;
  nghttp2_frame fr;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_tstamp ts = 0;
  int64_t stream_id;
  uint8_t outbuf[16384];
  nghttp2_ssize nwrite;
  nghttp2_callbacks callbacks;
  userdata ud;
  conn_options opts;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* Receive GOAWAY */
  client_default_callbacks(&callbacks);
  callbacks.shutdown = shutdown;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_client_with_options(&conn, opts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  fr.goaway = (nghttp2_frame_goaway){
    .hd =
      {
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .last_stream_id = (uint32_t)stream_id,
    .error_code = NGHTTP2_INTERNAL_ERROR,
    .debug_data = (const uint8_t *)"hello world",
    .debug_datalen = nghttp2_strlen_lit("hello world"),
  };

  fr.goaway.hd.len =
    (uint32_t)nghttp2_frame_encode_goaway_payloadlen(&fr.goaway);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr.goaway);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_true(conn->flags & NGHTTP2_CONN_FLAG_GOAWAY_RECVED);
  assert_int64(stream_id, ==, conn->rx.goaway.last_stream_id);
  assert_size(1, ==, ud.shutdown.ncalled);
  assert_int64(0x01, ==, ud.shutdown.last_stream_id);
  assert_uint32(NGHTTP2_INTERNAL_ERROR, ==, ud.shutdown.error_code);

  stream_id = nghttp2_conn_get_next_stream_id(conn);

  assert_int64(INT32_MAX, <, stream_id);

  nghttp2_conn_del(conn);

  /* Receive 1 byte at a time */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_true(conn->flags & NGHTTP2_CONN_FLAG_GOAWAY_RECVED);

  nghttp2_conn_del(conn);

  /* Receive GOAWAY without debug data */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  fr.goaway = (nghttp2_frame_goaway){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .last_stream_id = (uint32_t)stream_id,
    .error_code = NGHTTP2_INTERNAL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr.goaway);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_true(conn->flags & NGHTTP2_CONN_FLAG_GOAWAY_RECVED);

  nghttp2_conn_del(conn);

  /* Receive GOAWAY with bad length */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  fr.goaway = (nghttp2_frame_goaway){
    .hd =
      {
        .len = 7,
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .last_stream_id = (uint32_t)stream_id,
    .error_code = NGHTTP2_INTERNAL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr.goaway);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_GOAWAY_RECVED);

  nghttp2_conn_del(conn);

  /* Receive GOAWAY with nonzero stream ID */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  fr.goaway = (nghttp2_frame_goaway){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_GOAWAY,
        .stream_id = 0x01,
      },
    .error_code = NGHTTP2_INTERNAL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr.goaway);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_GOAWAY_RECVED);

  nghttp2_conn_del(conn);

  /* client: Receive GOAWAY with even stream ID in last_stream_id */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  fr.goaway = (nghttp2_frame_goaway){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .last_stream_id = 0x02,
    .error_code = NGHTTP2_INTERNAL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr.goaway);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_GOAWAY_RECVED);

  nghttp2_conn_del(conn);

  /* client: Receive GOAWAY with stream ID == 0 in last_stream_id */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  fr.goaway = (nghttp2_frame_goaway){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .error_code = NGHTTP2_INTERNAL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr.goaway);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_true(conn->flags & NGHTTP2_CONN_FLAG_GOAWAY_RECVED);

  nghttp2_conn_del(conn);

  /* server: Receive GOAWAY with odd stream ID in last_stream_id */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.goaway = (nghttp2_frame_goaway){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .last_stream_id = 0x01,
    .error_code = NGHTTP2_INTERNAL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr.goaway);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_GOAWAY_RECVED);

  nghttp2_conn_del(conn);

  /* server: Receive GOAWAY with stream ID == 0 in last_stream_id */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.goaway = (nghttp2_frame_goaway){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .error_code = NGHTTP2_INTERNAL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr.goaway);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_true(conn->flags & NGHTTP2_CONN_FLAG_GOAWAY_RECVED);

  nghttp2_conn_del(conn);

  /* Receive GOAWAY that increases last_stream_id */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  fr.goaway = (nghttp2_frame_goaway){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .error_code = NGHTTP2_INTERNAL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr.goaway);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_true(conn->flags & NGHTTP2_CONN_FLAG_GOAWAY_RECVED);

  fr.goaway = (nghttp2_frame_goaway){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .last_stream_id = 0x01,
    .error_code = NGHTTP2_INTERNAL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr.goaway);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_recv_window_update(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  nghttp2_hpack_encoder enc;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_frame fr;
  nghttp2_tstamp ts = 0;
  nghttp2_stream *stream;
  int64_t stream_id;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* Receive WINDOW_UPDATE to the active stream */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.window_update = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
        .stream_id = 0x01,
      },
    .window_size_inc = 1 << 17,
  };

  rv = nghttp2_frame_encode_window_update(&buf, &fr.window_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint64(NGHTTP2_INITIAL_WINDOW_SIZE + (1 << 17), ==,
                stream->tx.max_offset);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive 1 byte at a time */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint64(NGHTTP2_INITIAL_WINDOW_SIZE + (1 << 17), ==,
                stream->tx.max_offset);

  nghttp2_conn_del(conn);

  /* Receive WINDOW_UPDATE to the active stream that causes the flow
     control window to overflow */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.window_update = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
        .stream_id = 0x01,
      },
    .window_size_inc =
      NGHTTP2_MAX_WINDOW_SIZE - NGHTTP2_INITIAL_WINDOW_SIZE + 1,
  };

  rv = nghttp2_frame_encode_window_update(&buf, &fr.window_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_FLOW_CONTROL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive WINDOW_UPDATE to connection */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.window_update = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
      },
    .window_size_inc = 1 << 18,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_window_update(&buf, &fr.window_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_uint64(NGHTTP2_INITIAL_WINDOW_SIZE + (1 << 18), ==,
                conn->tx.max_offset);

  nghttp2_conn_del(conn);

  /* Receive WINDOW_UPDATE to connection that causes flow control
     window to overflow */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.window_update = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
      },
    .window_size_inc =
      NGHTTP2_MAX_WINDOW_SIZE - NGHTTP2_INITIAL_WINDOW_SIZE + 1,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_window_update(&buf, &fr.window_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_FLOW_CONTROL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive WINDOW_UPDATE with bad length */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.window_update = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 3,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
      },
    .window_size_inc = 1 << 20,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_window_update(&buf, &fr.window_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive WINDOW_UPDATE for an idle stream */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.window_update = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
        .stream_id = 0x01,
      },
    .window_size_inc = NGHTTP2_MAX_WINDOW_SIZE - NGHTTP2_INITIAL_WINDOW_SIZE,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_window_update(&buf, &fr.window_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive WINDOW_UPDATE to the closed stream */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x03,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.window_update = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
        .stream_id = 0x01,
      },
    .window_size_inc = 1,
  };

  rv = nghttp2_frame_encode_window_update(&buf, &fr.window_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive WINDOW_UPDATE to stream ID = 0x02 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.window_update = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
        .stream_id = 0x02,
      },
    .window_size_inc = 1 << 17,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_window_update(&buf, &fr.window_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive WINDOW_UPDATE to the stream that client has not
     requested */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  fr.window_update = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
        .stream_id = stream_id,
      },
    .window_size_inc = 1 << 17,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_window_update(&buf, &fr.window_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_recv_priority_update(void) {
  static const uint8_t prival[] = "u=2,i";
  static const uint8_t bad_prival[] = "u=3,\xee";
  static const uint8_t long_prival[] = "u=2,    i";
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  nghttp2_hpack_encoder enc;
  uint8_t outbuf[16384];
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_frame fr;
  nghttp2_tstamp ts = 0;
  nghttp2_stream *stream;
  nghttp2_ssize nwrite;
  int64_t stream_id;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* Receive PRIORITY_UPDATE to the active stream */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.priority_update = (nghttp2_frame_priority_update){
    .hd =
      {
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .prioritized_stream_id = 0x01,
    .pri = prival,
    .prilen = nghttp2_strlen_lit(prival),
  };

  fr.priority_update.hd.len =
    (uint32_t)nghttp2_frame_encode_priority_update_payloadlen(
      &fr.priority_update);
  rv = nghttp2_frame_encode_priority_update(&buf, &fr.priority_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint32(2, ==, stream->sched.pri.urgency);
  assert_true(stream->sched.pri.inc);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive 1 byte at a time */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint32(2, ==, stream->sched.pri.urgency);
  assert_true(stream->sched.pri.inc);

  nghttp2_conn_del(conn);

  /* Ignore PRIORITY_UPDATE to the idle stream */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.priority_update = (nghttp2_frame_priority_update){
    .hd =
      {
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .prioritized_stream_id = 0x01,
    .pri = prival,
    .prilen = nghttp2_strlen_lit(prival),
  };

  fr.priority_update.hd.len =
    (uint32_t)nghttp2_frame_encode_priority_update_payloadlen(
      &fr.priority_update);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_priority_update(&buf, &fr.priority_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_null(stream);

  nghttp2_conn_del(conn);

  /* client: Receive PRIORITY_UPDATE from server */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  fr.priority_update = (nghttp2_frame_priority_update){
    .hd =
      {
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .prioritized_stream_id = (uint32_t)stream_id,
    .pri = prival,
    .prilen = nghttp2_strlen_lit(prival),
  };

  fr.priority_update.hd.len =
    (uint32_t)nghttp2_frame_encode_priority_update_payloadlen(
      &fr.priority_update);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_priority_update(&buf, &fr.priority_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Receive PRIORITY_UPDATE with invalid length */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.priority_update = (nghttp2_frame_priority_update){
    .hd =
      {
        .len = 3,
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .prioritized_stream_id = 0x01,
    .pri = prival,
    .prilen = nghttp2_strlen_lit(prival),
  };

  rv = nghttp2_frame_encode_priority_update(&buf, &fr.priority_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive PRIORITY_UPDATE with prioritized_stream_id == 0 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.priority_update = (nghttp2_frame_priority_update){
    .hd =
      {
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .pri = prival,
    .prilen = nghttp2_strlen_lit(prival),
  };

  fr.priority_update.hd.len =
    (uint32_t)nghttp2_frame_encode_priority_update_payloadlen(
      &fr.priority_update);
  rv = nghttp2_frame_encode_priority_update(&buf, &fr.priority_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive PRIORITY_UPDATE to the half-closed(local) stream */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  rv = nghttp2_conn_submit_response(conn, 0x01, respnva,
                                    nghttp2_arraylen(respnva), NULL);

  assert_int(0, ==, rv);

  fr.priority_update = (nghttp2_frame_priority_update){
    .hd =
      {
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .prioritized_stream_id = 0x01,
    .pri = prival,
    .prilen = nghttp2_strlen_lit(prival),
  };

  fr.priority_update.hd.len =
    (uint32_t)nghttp2_frame_encode_priority_update_payloadlen(
      &fr.priority_update);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_priority_update(&buf, &fr.priority_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint32(NGHTTP2_DEFAULT_URGENCY, ==, stream->sched.pri.urgency);
  assert_false(stream->sched.pri.inc);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive PRIORITY_UPDATE with invalid priority field value */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.priority_update = (nghttp2_frame_priority_update){
    .hd =
      {
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .prioritized_stream_id = 0x01,
    .pri = bad_prival,
    .prilen = nghttp2_strlen_lit(bad_prival),
  };

  fr.priority_update.hd.len =
    (uint32_t)nghttp2_frame_encode_priority_update_payloadlen(
      &fr.priority_update);
  rv = nghttp2_frame_encode_priority_update(&buf, &fr.priority_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint32(NGHTTP2_DEFAULT_URGENCY, ==, stream->sched.pri.urgency);
  assert_false(stream->sched.pri.inc);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive PRIORITY_UPDATE with empty priority field value */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.priority_update = (nghttp2_frame_priority_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .prioritized_stream_id = 0x01,
  };

  rv = nghttp2_frame_encode_priority_update(&buf, &fr.priority_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint32(NGHTTP2_DEFAULT_URGENCY, ==, stream->sched.pri.urgency);
  assert_false(stream->sched.pri.inc);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive PRIORITY_UPDATE with too long priority field value */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.priority_update = (nghttp2_frame_priority_update){
    .hd =
      {
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .prioritized_stream_id = 0x01,
    .pri = long_prival,
    .prilen = nghttp2_strlen_lit(long_prival),
  };

  fr.priority_update.hd.len =
    (uint32_t)nghttp2_frame_encode_priority_update_payloadlen(
      &fr.priority_update);
  rv = nghttp2_frame_encode_priority_update(&buf, &fr.priority_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint32(NGHTTP2_DEFAULT_URGENCY, ==, stream->sched.pri.urgency);
  assert_false(stream->sched.pri.inc);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_recv_unknown_frame(void) {
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  nghttp2_tstamp ts = 0;
  nghttp2_frame fr;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  /* Receive an unknown frame */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.meta.hd = (nghttp2_frame_hd){
    .len = 100,
    .type = 0xFFU,
    .flags = 0xEEU,
    .stream_id = 0xBEEF00U,
  };

  nghttp2_buf_reset(&buf);
  buf.last = nghttp2_frame_encode_hd(buf.last, &fr.meta.hd);
  buf.last = nghttp2_setmem(buf.last, 0, fr.meta.hd.len);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Read 1 byte at a time */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Receive 0 length unknown frame */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.meta.hd = (nghttp2_frame_hd){
    .type = 0xFFU,
    .flags = 0xEEU,
    .stream_id = 0xBEEF00U,
  };

  nghttp2_buf_reset(&buf);
  buf.last = nghttp2_frame_encode_hd(buf.last, &fr.meta.hd);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_recv_settings_ack(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  nghttp2_hpack_encoder enc;
  nghttp2_frame fr;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf, obuf;
  nghttp2_tstamp ts = 0;
  nghttp2_settings settings;
  conn_options opts;
  nghttp2_stream *stream;
  uint8_t outbuf[16384];
  nghttp2_ssize nwrite;
  nghttp2_frd frd;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);
  nghttp2_buf_wrap_init(&obuf, outbuf, sizeof(outbuf));
  nghttp2_frd_init(&frd);

  /* Receive SETTINGS ACK */
  setup_default_server(&conn);

  assert_false(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK);

  write_preface(conn, ts);

  assert_true(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK);

  read_client_preface(conn, NULL, 0, ts);

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK);
  assert_uint32(100, ==, conn->rx.max_concurrent_streams);

  nghttp2_conn_del(conn);

  /* Apply flow control limits */
  server_default_settings(&settings);
  settings.initial_max_stream_data = 1 << 17;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
      },
  };

  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK);
  assert_uint32(100, ==, conn->rx.max_concurrent_streams);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint64(1 << 17, ==, stream->rx.max_offset);
  assert_uint64(NGHTTP2_INITIAL_WINDOW_SIZE +
                  ((1 << 17) - NGHTTP2_INITIAL_WINDOW_SIZE) * 2,
                ==, stream->rx.unsent_max_offset);
  assert_uint64(1 << 17, ==, stream->rx.max_offset);
  assert_uint32(1 << 17, ==, conn->rx.stream_window);
  assert_not_null(stream->strmq_prev);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);
  assert_uint64(stream->rx.unsent_max_offset, ==, stream->rx.max_offset);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_SETTINGS, ==, fr.meta.hd.type);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_WINDOW_UPDATE, ==, fr.meta.hd.type);
  assert_int64(0x01, ==, fr.window_update.hd.stream_id);
  assert_uint32(NGHTTP2_INITIAL_WINDOW_SIZE +
                  ((1 << 17) - NGHTTP2_INITIAL_WINDOW_SIZE) * 2 - (1 << 17),
                ==, fr.window_update.window_size_inc);
  assert_null(stream->strmq_prev);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Apply flow control limits causes overflow */
  server_default_settings(&settings);
  settings.initial_max_stream_data = NGHTTP2_INITIAL_WINDOW_SIZE + 1;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_extend_max_stream_offset(
    conn, 0x01, NGHTTP2_MAX_WINDOW_SIZE - NGHTTP2_INITIAL_WINDOW_SIZE);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint64(NGHTTP2_MAX_WINDOW_SIZE, ==, stream->rx.max_offset);

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_FLOW_CONTROL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Decrease flow control limit */
  server_default_settings(&settings);
  settings.initial_max_stream_data = 1 << 15;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = 0x01,
      },
    .data = nulldata,
    .datalen = 8193,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  rv = nghttp2_conn_extend_max_stream_offset(conn, 0x01, 8193);

  assert_int(0, ==, rv);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_null(stream->strmq_prev);

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint64(8194, ==, stream->rx.unsent_max_offset);
  assert_uint64(1 << 15, ==, stream->rx.max_offset);
  assert_uint32(1 << 15, ==, conn->rx.stream_window);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Decrease flow control limit down to 0 */
  server_default_settings(&settings);
  settings.initial_max_stream_data = 0;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = 0x01,
      },
    .data = nulldata,
    .datalen = 8193,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  rv = nghttp2_conn_extend_max_stream_offset(conn, 0x01, 8193);

  assert_int(0, ==, rv);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_null(stream->strmq_prev);

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint64((uint64_t)-57342, ==, stream->rx.unsent_max_offset);
  assert_uint64(0, ==, stream->rx.max_offset);
  assert_uint32(0, ==, conn->rx.stream_window);
  assert_null(stream->strmq_prev);

  rv = nghttp2_conn_extend_max_stream_offset(conn, 0x01, 57341);

  assert_int(0, ==, rv);
  assert_uint64((uint64_t)-1, ==, stream->rx.unsent_max_offset);
  assert_null(stream->strmq_prev);

  rv = nghttp2_conn_extend_max_stream_offset(conn, 0x01, 1);

  assert_int(0, ==, rv);
  assert_uint64(0, ==, stream->rx.unsent_max_offset);
  assert_null(stream->strmq_prev);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_conn_rx_flow_control(void) {
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, obuf;
  nghttp2_tstamp ts = 0;
  nghttp2_settings settings;
  uint8_t outbuf[16384];
  nghttp2_ssize nwrite;
  conn_options opts;
  nghttp2_frd frd;
  nghttp2_frame fr;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_wrap_init(&obuf, outbuf, sizeof(outbuf));
  nghttp2_frd_init(&frd);

  /* Increase connection flow control window */
  server_default_settings(&settings);
  settings.initial_max_data = 1 << 20;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface_with_window_update(conn, 983041, ts);
  read_client_preface(conn, NULL, 0, ts);

  assert_uint64(1 << 20, ==, conn->rx.unsent_max_offset);
  assert_uint64(1 << 20, ==, conn->rx.max_offset);
  assert_uint32(1 << 20, ==, conn->rx.window);

  nghttp2_conn_del(conn);

  /* Decrease connection flow control window */
  server_default_settings(&settings);
  settings.initial_max_data = 1 << 15;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  assert_uint64(32768, ==, conn->rx.unsent_max_offset);
  assert_uint64(NGHTTP2_INITIAL_WINDOW_SIZE, ==, conn->rx.max_offset);
  assert_uint32(1 << 15, ==, conn->rx.window);

  nghttp2_conn_del(conn);

  /* Decrease connection flow control window down to 0 */
  server_default_settings(&settings);
  settings.initial_max_data = 0;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  assert_uint64(0, ==, conn->rx.unsent_max_offset);
  assert_uint64(NGHTTP2_INITIAL_WINDOW_SIZE, ==, conn->rx.max_offset);
  assert_uint32(0, ==, conn->rx.window);

  nghttp2_conn_del(conn);

  /* Extend max offset */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  assert_uint64(NGHTTP2_INITIAL_WINDOW_SIZE, ==, conn->rx.unsent_max_offset);

  rv = nghttp2_conn_extend_max_offset(conn, 16384);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  assert_uint64(NGHTTP2_INITIAL_WINDOW_SIZE + 16384, ==,
                conn->rx.unsent_max_offset);
  assert_uint64(conn->rx.unsent_max_offset, ==, conn->rx.max_offset);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_WINDOW_UPDATE, ==, fr.meta.hd.type);
  assert_int64(0x00, ==, fr.window_update.hd.stream_id);
  assert_uint32(16384, ==, fr.window_update.window_size_inc);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_del(conn);

  /* Flow control window overflow */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  assert_uint64(NGHTTP2_INITIAL_WINDOW_SIZE, ==, conn->rx.unsent_max_offset);

  rv = nghttp2_conn_extend_max_offset(conn, NGHTTP2_MAX_WINDOW_SIZE);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_extend_max_offset(conn, 1);

  assert_int(NGHTTP2_ERR_FLOW_CONTROL, ==, rv);

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_stream_rx_flow_control(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  nghttp2_hpack_encoder enc;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf, obuf;
  nghttp2_frame fr;
  nghttp2_tstamp ts = 0;
  nghttp2_stream *stream;
  nghttp2_ssize nwrite;
  nghttp2_frd frd;
  uint8_t outbuf[16384];
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);
  nghttp2_buf_wrap_init(&obuf, outbuf, sizeof(outbuf));
  nghttp2_frd_init(&frd);

  /* Send WINDOW_UPDATE */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_extend_max_stream_offset(conn, 0x01, 16383);

  assert_int(0, ==, rv);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_null(stream->strmq_prev);

  rv = nghttp2_conn_extend_max_stream_offset(conn, 0x01, 1);

  assert_int(0, ==, rv);
  assert_not_null(stream->strmq_prev);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint64(NGHTTP2_INITIAL_WINDOW_SIZE + 16384, ==,
                stream->rx.unsent_max_offset);
  assert_uint64(stream->rx.unsent_max_offset, ==, stream->rx.max_offset);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_WINDOW_UPDATE, ==, fr.meta.hd.type);
  assert_uint32(16384, ==, fr.window_update.window_size_inc);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Flow control window overflow */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  rv =
    nghttp2_conn_extend_max_stream_offset(conn, 0x01, NGHTTP2_MAX_WINDOW_SIZE);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_extend_max_stream_offset(conn, 0x01, 1);

  assert_int(NGHTTP2_ERR_FLOW_CONTROL, ==, rv);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Stream not found */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  rv =
    nghttp2_conn_extend_max_stream_offset(conn, 0x01, NGHTTP2_MAX_WINDOW_SIZE);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_extend_max_stream_offset(conn, 0x01, 1);

  assert_int(0, ==, rv);

  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_submit_ping(void) {
  static const nghttp2_ping_data data = {
    .data = {0xCA, 0xFE, 0xBA, 0xAD, 0xCA, 0xCE, 0xBE, 0xEF},
  };
  nghttp2_conn *conn;
  nghttp2_frame fr;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, obuf;
  nghttp2_tstamp ts = 0;
  uint8_t outbuf[16384];
  nghttp2_frd frd;
  nghttp2_ssize nwrite;
  nghttp2_callbacks callbacks;
  userdata ud;
  conn_options opts;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_wrap_init(&obuf, outbuf, sizeof(outbuf));
  nghttp2_frd_init(&frd);

  /* Send PING and receive its ACK */
  server_default_callbacks(&callbacks);
  callbacks.recv_ping_ack = recv_ping_ack;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  rv = nghttp2_conn_submit_ping(conn, &data);

  assert_int(0, ==, rv);
  assert_true(conn->flags & NGHTTP2_CONN_FLAG_SEND_PING);
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_PING_ACK);

  rv = nghttp2_conn_submit_ping(conn, &data);

  assert_int(NGHTTP2_ERR_INVALID_STATE, ==, rv);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(8, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_PING, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.ping.hd.flags);
  assert_int64(0x00, ==, fr.ping.hd.stream_id);
  assert_true(nghttp2_ping_data_eq(&data, &conn->tx.ping.data));
  assert_size(0, ==, nghttp2_buf_len(&obuf));
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_SEND_PING);
  assert_true(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_PING_ACK);

  fr.ping = (nghttp2_frame_ping){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_PING,
        .flags = NGHTTP2_PING_FLAG_ACK,
      },
    .data = data,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_ping(&buf, &fr.ping);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_size(1, ==, ud.recv_ping_ack.ncalled);
  assert_true(nghttp2_ping_data_eq(&data, &ud.recv_ping_ack.data));
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_SEND_PING);
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_PING_ACK);

  nghttp2_conn_del(conn);

  /* Send PING and receive its ACK with the wrong data */
  server_default_callbacks(&callbacks);
  callbacks.recv_ping_ack = recv_ping_ack;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  rv = nghttp2_conn_submit_ping(conn, &data);

  assert_int(0, ==, rv);
  assert_true(conn->flags & NGHTTP2_CONN_FLAG_SEND_PING);
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_PING_ACK);

  rv = nghttp2_conn_submit_ping(conn, &data);

  assert_int(NGHTTP2_ERR_INVALID_STATE, ==, rv);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(8, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_PING, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.ping.hd.flags);
  assert_int64(0x00, ==, fr.ping.hd.stream_id);
  assert_true(nghttp2_ping_data_eq(&data, &conn->tx.ping.data));
  assert_size(0, ==, nghttp2_buf_len(&obuf));
  assert_false(conn->flags & NGHTTP2_CONN_FLAG_SEND_PING);
  assert_true(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_PING_ACK);

  fr.ping = (nghttp2_frame_ping){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_PING,
        .flags = NGHTTP2_PING_FLAG_ACK,
      },
    .data =
      {
        .data = {0xCA, 0xFE, 0xBA, 0xAD, 0xCA, 0xCE, 0xBE, 0xEE},
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_ping(&buf, &fr.ping);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);
  assert_size(0, ==, ud.recv_ping_ack.ncalled);
  assert_true(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_PING_ACK);

  nghttp2_conn_del(conn);

  /* Receive unexpected PING ACK */
  server_default_callbacks(&callbacks);
  callbacks.recv_ping_ack = recv_ping_ack;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  fr.ping = (nghttp2_frame_ping){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_PING,
        .flags = NGHTTP2_PING_FLAG_ACK,
      },
    .data = data,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_ping(&buf, &fr.ping);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);
  assert_size(0, ==, ud.recv_ping_ack.ncalled);

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_send_ping_ack(void) {
  static const nghttp2_ping_data data = {
    .data = {0xCA, 0xFE, 0xBA, 0xAD, 0xCA, 0xCE, 0xBE, 0xEF},
  };
  nghttp2_conn *conn;
  nghttp2_frame fr;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, obuf;
  nghttp2_tstamp ts = 0;
  uint8_t outbuf[16384];
  nghttp2_frd frd;
  nghttp2_ssize nwrite;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_wrap_init(&obuf, outbuf, sizeof(outbuf));
  nghttp2_frd_init(&frd);

  /* Receive PING and send PING ACK back */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  fr.ping = (nghttp2_frame_ping){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_PING,
      },
    .data = data,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_ping(&buf, &fr.ping);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_size(1, ==, nghttp2_ringbuf_len(&conn->rx.ping.data.rb));

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(8, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_PING, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_PING_FLAG_ACK, ==, fr.ping.hd.flags);
  assert_int64(0, ==, fr.ping.hd.stream_id);
  assert_true(nghttp2_ping_data_eq(&data, &fr.ping.data));
  assert_size(0, ==, nghttp2_ringbuf_len(&conn->rx.ping.data.rb));

  nghttp2_conn_del(conn);

  /* Receive too many PING frames */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  fr.ping = (nghttp2_frame_ping){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_PING,
      },
    .data = data,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_ping(&buf, &fr.ping);

  assert_int(0, ==, rv);

  for (i = 0; i < NGHTTP2_MAX_PING_ACK; ++i) {
    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    assert_int(0, ==, rv);
  }

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_shutdown_stream(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  nghttp2_hpack_encoder enc;
  uint8_t rawbuf[16384];
  uint8_t outbuf[16384];
  nghttp2_buf buf, hbuf, obuf;
  nghttp2_tstamp ts = 0;
  nghttp2_stream *stream;
  nghttp2_ssize nwrite;
  nghttp2_frd frd;
  nghttp2_frame fr;
  nghttp2_callbacks callbacks;
  userdata ud;
  conn_options opts;
  int64_t stream_id;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);
  nghttp2_buf_wrap_init(&obuf, outbuf, sizeof(outbuf));
  nghttp2_frd_init(&frd);

  /* Call nghttp2_conn_shutdown_stream against non-existing stream */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_conn_shutdown_stream(conn, 0x00, 0x01, NGHTTP2_INTERNAL_ERROR);

  assert_null(nghttp2_conn_find_stream(conn, 0x01));

  nghttp2_conn_del(conn);

  /* Calling nghttp2_conn_shutdown_stream twice */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_conn_shutdown_stream(conn, 0x00, stream_id, NGHTTP2_INTERNAL_ERROR);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SEND_RST_STREAM);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_WR);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_ERROR_CODE_SET);
  assert_uint32(NGHTTP2_INTERNAL_ERROR, ==, stream->error_code);

  nghttp2_conn_shutdown_stream(conn, 0x00, 0x01, NGHTTP2_INTERNAL_ERROR);

  nghttp2_conn_del(conn);

  /* RST_STREAM is sent after HEADERS */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_conn_shutdown_stream(conn, 0x00, stream_id, NGHTTP2_INTERNAL_ERROR);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SEND_RST_STREAM);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_RST_STREAM, ==, fr.meta.hd.type);
  assert_size(0, ==, nghttp2_buf_len(&buf));

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_null(stream);

  nghttp2_conn_del(conn);

  /* Send RST_STREAM */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_conn_shutdown_stream(conn, 0x00, stream_id, NGHTTP2_INTERNAL_ERROR);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SEND_RST_STREAM);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(4, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_RST_STREAM, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.rst_stream.hd.flags);
  assert_int64(0x01, ==, fr.rst_stream.hd.stream_id);
  assert_uint32(NGHTTP2_INTERNAL_ERROR, ==, fr.rst_stream.error_code);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_null(stream);

  nghttp2_conn_del(conn);

  /* Wait HEADERS to finish sending before sending RST_STREAM. */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(nghttp2_http_writer_inprogress(&stream->tx.hw));

  nghttp2_conn_shutdown_stream(conn, 0x00, stream_id, NGHTTP2_INTERNAL_ERROR);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SEND_RST_STREAM);

  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM,
               ==, fr.rst_stream.hd.flags);
  assert_int64(stream_id, ==, fr.rst_stream.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(4, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_RST_STREAM, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.rst_stream.hd.flags);
  assert_int64(stream_id, ==, fr.rst_stream.hd.stream_id);
  assert_uint32(NGHTTP2_INTERNAL_ERROR, ==, fr.rst_stream.error_code);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_null(stream);

  nghttp2_conn_del(conn);

  /* Wait DATA to finish sending before sending RST_STREAM. */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_4k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, 4096, ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(nghttp2_http_writer_inprogress(&stream->tx.hw));

  nghttp2_conn_shutdown_stream(conn, 0x00, stream_id, NGHTTP2_INTERNAL_ERROR);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SEND_RST_STREAM);

  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.rst_stream.hd.flags);
  assert_int64(stream_id, ==, fr.rst_stream.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_DATA_FLAG_END_STREAM, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.rst_stream.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(4, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_RST_STREAM, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.rst_stream.hd.flags);
  assert_int64(stream_id, ==, fr.rst_stream.hd.stream_id);
  assert_uint32(NGHTTP2_INTERNAL_ERROR, ==, fr.rst_stream.error_code);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_null(stream);

  nghttp2_conn_del(conn);

  /* Shutdown stream and send RST_STREAM while receiving HEADERS; we
     stop receiving HEADERS and notifying it to application. */
  server_default_callbacks(&callbacks);
  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.stream_close = stream_close;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  ud.recv_header.expect_nva = reqnva;
  ud.recv_header.expect_nvlen = 1;
  rv = nghttp2_conn_read(conn, buf.pos, NGHTTP2_FRAME_HDLEN + 1, ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_HEADERS_FIELD_BLOCK, ==,
              conn->rx.frrd.state);

  buf.pos += NGHTTP2_FRAME_HDLEN + 1;

  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_size(1, ==, ud.recv_header.ncalled);

  nghttp2_conn_shutdown_stream(conn, 0x00, 0x01, NGHTTP2_PROTOCOL_ERROR);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SEND_RST_STREAM);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_OPENED);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);
  assert_size(1, ==, ud.stream_close.ncalled);
  assert_true(ud.stream_close.flags & NGHTTP2_STREAM_CLOSE_FLAG_ERROR_CODE_SET);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, ud.stream_close.error_code);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_RST_STREAM, ==, fr.meta.hd.type);
  assert_null(nghttp2_conn_find_stream(conn, 0x01));

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_size(1, ==, ud.recv_header.ncalled);
  assert_size(0, ==, ud.end_headers.ncalled);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Shutdown stream while receiving HEADERS and send RST_STREAM after
     receiving all HEADERS; we stop receiving HEADERS and notifying it
     to application. */
  server_default_callbacks(&callbacks);
  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.stream_close = stream_close;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  ud.recv_header.expect_nva = reqnva;
  ud.recv_header.expect_nvlen = 1;
  rv = nghttp2_conn_read(conn, buf.pos, NGHTTP2_FRAME_HDLEN + 1, ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_HEADERS_FIELD_BLOCK, ==,
              conn->rx.frrd.state);

  buf.pos += NGHTTP2_FRAME_HDLEN + 1;

  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_size(1, ==, ud.recv_header.ncalled);

  nghttp2_conn_shutdown_stream(conn, 0x00, 0x01, NGHTTP2_PROTOCOL_ERROR);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SEND_RST_STREAM);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_OPENED);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_size(1, ==, ud.recv_header.ncalled);
  assert_size(0, ==, ud.end_headers.ncalled);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);
  assert_size(1, ==, ud.stream_close.ncalled);
  assert_true(ud.stream_close.flags & NGHTTP2_STREAM_CLOSE_FLAG_ERROR_CODE_SET);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, ud.stream_close.error_code);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_RST_STREAM, ==, fr.meta.hd.type);
  assert_null(nghttp2_conn_find_stream(conn, 0x01));

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Shutdown stream in recv_header callback; we stop receiving
     HEADERS and DATA and notifying it to application. */
  server_default_callbacks(&callbacks);
  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header_rst_stream;
  callbacks.end_headers = end_headers;
  callbacks.recv_data = recv_data;
  callbacks.stream_close = stream_close;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .data = nulldata,
    .datalen = 333,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_size(1, ==, ud.recv_header.ncalled);
  assert_size(0, ==, ud.end_headers.ncalled);
  assert_size(0, ==, ud.recv_data.ncalled);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SEND_RST_STREAM);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_OPENED);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);
  assert_size(1, ==, ud.stream_close.ncalled);
  assert_true(ud.stream_close.flags & NGHTTP2_STREAM_CLOSE_FLAG_ERROR_CODE_SET);
  assert_uint32(NGHTTP2_INTERNAL_ERROR, ==, ud.stream_close.error_code);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_RST_STREAM, ==, fr.meta.hd.type);
  assert_null(nghttp2_conn_find_stream(conn, 0x01));

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_recv_rst_stream_mid_tx_frame(void) {
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  uint8_t outbuf[16384];
  nghttp2_buf obuf;
  nghttp2_tstamp ts = 0;
  nghttp2_frame fr;
  nghttp2_stream *stream;
  nghttp2_ssize nwrite;
  nghttp2_frd frd;
  int64_t stream_id;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_wrap_init(&obuf, outbuf, sizeof(outbuf));
  nghttp2_frd_init(&frd);

  /* Receive RST_STREAM while sending HEADERS */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_4k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(nghttp2_http_writer_inprogress(&stream->tx.hw));

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = stream_id,
      },
    .error_code = NGHTTP2_REFUSED_STREAM,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_rst_stream(&buf, &fr.rst_stream);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM_RECVED);

  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_null(stream);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_http_writer(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  uint8_t outbuf[1 << 19];
  nghttp2_buf buf, hbuf, obuf, dbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_ssize nread, nwrite;
  nghttp2_frd frd;
  nghttp2_frame fr;
  nghttp2_hpack_encoder enc;
  nghttp2_hpack_decoder dec;
  nghttp2_hpack_nv nv;
  uint8_t hflags;
  int64_t stream_id;
  size_t nv_index;
  int rv;

#define DECODE_FIELDS(NVA, FIN)                                                \
  nghttp2_buf_wrap_init(&dbuf, (uint8_t *)fr.headers.field_block,              \
                        fr.headers.field_blocklen);                            \
  dbuf.last += fr.headers.field_blocklen;                                      \
                                                                               \
  for (;;) {                                                                   \
    nread = nghttp2_hpack_decoder_read(&dec, &nv, &hflags, dbuf.pos,           \
                                       nghttp2_buf_len(&dbuf), (FIN));         \
    assert_ptrdiff(0, <=, nread);                                              \
                                                                               \
    dbuf.pos += nread;                                                         \
                                                                               \
    if (hflags & NGHTTP2_HPACK_DECODE_FLAG_EMIT) {                             \
      assert_size(nghttp2_arraylen((NVA)), >, nv_index);                       \
      assert_memn_equal((NVA)[nv_index].name, (NVA)[nv_index].namelen,         \
                        nv.name->base, nv.name->len);                          \
      assert_memn_equal((NVA)[nv_index].value, (NVA)[nv_index].valuelen,       \
                        nv.value->base, nv.value->len);                        \
                                                                               \
      nghttp2_rcbuf_decref(nv.name);                                           \
      nghttp2_rcbuf_decref(nv.value);                                          \
                                                                               \
      ++nv_index;                                                              \
    }                                                                          \
                                                                               \
    if (!(FIN)) {                                                              \
      assert_false(hflags & NGHTTP2_HPACK_DECODE_FLAG_FINAL);                  \
    }                                                                          \
                                                                               \
    if (nread == 0) {                                                          \
      if ((FIN)) {                                                             \
        assert_true(hflags & NGHTTP2_HPACK_DECODE_FLAG_FINAL);                 \
        assert_size(nghttp2_arraylen((NVA)), ==, nv_index);                    \
      }                                                                        \
                                                                               \
      break;                                                                   \
    }                                                                          \
  }

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_wrap_init(&obuf, outbuf, sizeof(outbuf));
  nghttp2_buf_init(&hbuf);
  nghttp2_frd_init(&frd);

  /* Write HEADERS in chunks */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);

  for (;;) {
    nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }

    obuf.last += nwrite;
  }

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM,
               ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_hpack_decoder_init(&dec, mem);

  nv_index = 0;

  DECODE_FIELDS(reqnva, 1);

  assert_size(nghttp2_arraylen(reqnva), ==, nv_index);

  nghttp2_hpack_decoder_free(&dec);
  nghttp2_conn_del(conn);

  /* Write HEADERS and DATA in chunks */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_4k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);

  for (;;) {
    nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }

    obuf.last += nwrite;
  }

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_DATA_FLAG_END_STREAM, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.data.hd.stream_id);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_del(conn);

  /* Write HEADERS, DATA, and HEADERS in chunks */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_4k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  rv = nghttp2_conn_submit_trailers(conn, stream_id, trnva,
                                    nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&obuf);

  for (;;) {
    nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }

    obuf.last += nwrite;
  }

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.data.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM,
               ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_del(conn);

  /* Write HEADERS and DATA in chunks, sending stream-level
     WINDOW_UPDATE after HEADERS. */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_4k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);

  nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

  assert_ptrdiff(NGHTTP2_FRAME_HDLEN, ==, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_conn_extend_max_stream_offset(conn, stream_id, 32768);

  assert_int(0, ==, rv);

  for (;;) {
    nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN + 4, ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }

    obuf.last += nwrite;
  }

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_WINDOW_UPDATE, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.window_update.hd.flags);
  assert_int64(stream_id, ==, fr.window_update.hd.stream_id);
  assert_uint32(32768, ==, fr.window_update.window_size_inc);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_DATA_FLAG_END_STREAM, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.data.hd.stream_id);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_del(conn);

  /* Write HEADERS and DATA in chunks, sending connection-level
     WINDOW_UPDATE after HEADERS. */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_4k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);

  nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

  assert_ptrdiff(NGHTTP2_FRAME_HDLEN, ==, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_conn_extend_max_offset(conn, 32768);

  assert_int(0, ==, rv);

  for (;;) {
    nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN + 4, ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }

    obuf.last += nwrite;
  }

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_WINDOW_UPDATE, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.window_update.hd.flags);
  assert_int64(0x00, ==, fr.window_update.hd.stream_id);
  assert_uint32(32768, ==, fr.window_update.window_size_inc);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_DATA_FLAG_END_STREAM, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.data.hd.stream_id);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_del(conn);

  /* Write HEADERS, CONTINUATION, and DATA in chunks */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id = nghttp2_conn_submit_request(conn, large_reqnva,
                                          nghttp2_arraylen(large_reqnva),
                                          &(nghttp2_data_reader){
                                            .read_data = read_data_4k,
                                          },
                                          NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);

  for (;;) {
    nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }

    obuf.last += nwrite;
  }

  nghttp2_hpack_decoder_init(&dec, mem);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  nv_index = 0;

  DECODE_FIELDS(large_reqnva, 0);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_CONTINUATION, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  DECODE_FIELDS(large_reqnva, 0);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_CONTINUATION, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  DECODE_FIELDS(large_reqnva, 1);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_DATA_FLAG_END_STREAM, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.data.hd.stream_id);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_hpack_decoder_free(&dec);
  nghttp2_conn_del(conn);

  /* Write HEADERS, CONTINUATION, and DATA in chunks.  WINDOW_UPDATE
     will be sent after END_HEADERS. */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id = nghttp2_conn_submit_request(conn, large_reqnva,
                                          nghttp2_arraylen(large_reqnva),
                                          &(nghttp2_data_reader){
                                            .read_data = read_data_4k,
                                          },
                                          NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);

  nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_conn_extend_max_stream_offset(conn, stream_id, 32768);

  assert_int(0, ==, rv);

  for (;;) {
    nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN + 4, ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }

    obuf.last += nwrite;
  }

  nghttp2_hpack_decoder_init(&dec, mem);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  nv_index = 0;

  DECODE_FIELDS(large_reqnva, 0);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_CONTINUATION, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  DECODE_FIELDS(large_reqnva, 0);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_CONTINUATION, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  DECODE_FIELDS(large_reqnva, 1);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_WINDOW_UPDATE, ==, fr.meta.hd.type);
  assert_int64(stream_id, ==, fr.window_update.hd.stream_id);
  assert_uint32(32768, ==, fr.window_update.window_size_inc);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_DATA_FLAG_END_STREAM, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.data.hd.stream_id);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_hpack_decoder_free(&dec);
  nghttp2_conn_del(conn);

  /* Write HEADERS, HEADERS, HEADERS, DATA, and HEADERS in chunks */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_submit_info(conn, 0x01, infonva, nghttp2_arraylen(infonva));

  assert_int(0, ==, rv);

  rv = nghttp2_conn_submit_info(conn, 0x01, infonva, nghttp2_arraylen(infonva));

  assert_int(0, ==, rv);

  rv =
    nghttp2_conn_submit_response(conn, 0x01, respnva, nghttp2_arraylen(respnva),
                                 &(nghttp2_data_reader){
                                   .read_data = read_data_4k,
                                 });

  assert_int(0, ==, rv);

  rv = nghttp2_conn_submit_trailers(conn, stream_id, trnva,
                                    nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&obuf);

  for (;;) {
    nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }

    obuf.last += nwrite;
  }

  nghttp2_hpack_decoder_init(&dec, mem);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  nv_index = 0;

  DECODE_FIELDS(infonva, 1);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  nv_index = 0;

  DECODE_FIELDS(infonva, 1);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  nv_index = 0;

  DECODE_FIELDS(respnva, 1);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.data.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM,
               ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nv_index = 0;

  DECODE_FIELDS(trnva, 1);

  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Write HEADERS, DATA, and HEADERS which is 0 length in chunks */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_4k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  rv = nghttp2_conn_submit_trailers(conn, stream_id, NULL, 0);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&obuf);

  for (;;) {
    nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }

    obuf.last += nwrite;
  }

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.data.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM,
               ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);
  assert_size(0, ==, fr.headers.field_blocklen);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_del(conn);

  /* Write HEADERS, multiple DATA in chunks */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_48k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);

  for (;;) {
    nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }

    obuf.last += nwrite;
  }

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(16384, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.data.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(16384, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.data.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(16384, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_DATA_FLAG_END_STREAM, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.data.hd.stream_id);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_del(conn);

  /* Write HEADERS, DATA which is 0 length in chunks */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_0k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);

  for (;;) {
    nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }

    obuf.last += nwrite;
  }

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(0, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_DATA_FLAG_END_STREAM, ==, fr.data.hd.flags);
  assert_int64(stream_id, ==, fr.data.hd.stream_id);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_del(conn);

  /* Write HEADERS, DATA which is 0 length, and HEADERS in chunks */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_0k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  rv = nghttp2_conn_submit_trailers(conn, stream_id, trnva,
                                    nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&obuf);

  for (;;) {
    nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }

    obuf.last += nwrite;
  }

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM,
               ==, fr.headers.hd.flags);
  assert_int64(stream_id, ==, fr.headers.hd.stream_id);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_graceful_shutdown(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  nghttp2_tstamp ts = 0;
  uint8_t outbuf[16384];
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf, obuf;
  nghttp2_frd frd;
  nghttp2_frame fr;
  nghttp2_hpack_encoder enc;
  nghttp2_ssize nwrite;
  int64_t stream_id;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&obuf, outbuf, sizeof(outbuf));
  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);
  nghttp2_frd_init(&frd);

  /* Send notice and then start graceful shutdown while there is no
     active streams */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_conn_submit_shutdown_notice(conn);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(8, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_GOAWAY, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.goaway.hd.flags);
  assert_int64(0x00, ==, fr.goaway.hd.stream_id);
  assert_uint32(INT32_MAX, ==, fr.goaway.last_stream_id);
  assert_uint32(NGHTTP2_NO_ERROR, ==, fr.goaway.error_code);
  assert_size(0, ==, fr.goaway.debug_datalen);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_shutdown(conn);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(8, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_GOAWAY, ==, fr.meta.hd.type);
  assert_uint8(0x00, ==, fr.goaway.hd.flags);
  assert_int64(0x00, ==, fr.goaway.hd.stream_id);
  assert_uint32(0, ==, fr.goaway.last_stream_id);
  assert_uint32(NGHTTP2_NO_ERROR, ==, fr.goaway.error_code);
  assert_size(0, ==, fr.goaway.debug_datalen);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(NGHTTP2_ERR_CLOSING, ==, nwrite);

  nghttp2_conn_del(conn);

  /* Start graceful shutdown while there is active stream.  Connection
     closed when both sides close. */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  nghttp2_conn_shutdown(conn);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  rv = nghttp2_conn_submit_response(conn, 0x01, respnva,
                                    nghttp2_arraylen(respnva), NULL);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.pos, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_int64(0x01, ==, fr.headers.hd.stream_id);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(NGHTTP2_ERR_CLOSING, ==, nwrite);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Start graceful shutdown while there is active stream.  Connection
     closed on incoming RST_STREAM. */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  nghttp2_conn_shutdown(conn);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = 0x01,
      },
    .error_code = NGHTTP2_CANCEL,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_rst_stream(&buf, &fr.rst_stream);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(NGHTTP2_ERR_CLOSING, ==, nwrite);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Start graceful shutdown while there is active stream.  Connection
     closed on outgoing RST_STREAM. */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  nghttp2_conn_shutdown(conn);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_conn_shutdown_stream(conn, 0x00, 0x01, NGHTTP2_REFUSED_STREAM);

  assert_not_null(nghttp2_conn_find_stream(conn, 0x01));

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_RST_STREAM, ==, fr.meta.hd.type);
  assert_int64(0x01, ==, fr.rst_stream.hd.stream_id);
  assert_uint32(NGHTTP2_REFUSED_STREAM, ==, fr.rst_stream.error_code);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(NGHTTP2_ERR_CLOSING, ==, nwrite);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Start graceful shutdown while there is active stream.  Connection
     closed on outgoing RST_STREAM while refusing new streams. */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  nghttp2_conn_shutdown(conn);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  stream_id = 0x03;

  for (i = 0; i < 102; ++i, stream_id += 2) {
    fr.headers = (nghttp2_frame_headers){
      .hd =
        {
          .type = NGHTTP2_FRAME_HEADERS,
          .flags =
            NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
          .stream_id = stream_id,
        },
      .field_block = hbuf.pos,
      .field_blocklen = nghttp2_buf_len(&hbuf),
    };

    fr.headers.hd.len =
      (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

    nghttp2_buf_reset(&buf);
    rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

    assert_int(0, ==, rv);

    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    assert_int(0, ==, rv);

    nghttp2_buf_reset(&obuf);
    nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

    if (i >= 100) {
      assert_ptrdiff(0, ==, nwrite);
      continue;
    }

    assert_ptrdiff(0, <, nwrite);

    obuf.last += nwrite;

    rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

    assert_int(0, ==, rv);
    assert_uint8(NGHTTP2_FRAME_RST_STREAM, ==, fr.meta.hd.type);
    assert_int64(stream_id, ==, fr.rst_stream.hd.stream_id);
    assert_uint32(NGHTTP2_REFUSED_STREAM, ==, fr.rst_stream.error_code);
    assert_size(0, ==, nghttp2_buf_len(&obuf));
  }

  nghttp2_conn_shutdown_stream(conn, 0x00, 0x01, NGHTTP2_REFUSED_STREAM);

  assert_not_null(nghttp2_conn_find_stream(conn, 0x01));

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_RST_STREAM, ==, fr.meta.hd.type);
  assert_int64(0x01, ==, fr.rst_stream.hd.stream_id);
  assert_uint32(NGHTTP2_REFUSED_STREAM, ==, fr.rst_stream.error_code);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(NGHTTP2_ERR_CLOSING, ==, nwrite);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* On client side, after GOAWAY is received, it simply cannot make
     new request */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  fr.goaway = (nghttp2_frame_goaway){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .last_stream_id = INT32_MAX,
    .error_code = NGHTTP2_NO_ERROR,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_goaway(&buf, &fr.goaway);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(NGHTTP2_ERR_REFUSED_STREAM, ==, stream_id);

  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_stream_concurrency(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  uint8_t outbuf[16384];
  nghttp2_buf buf, hbuf, obuf;
  nghttp2_tstamp ts = 0;
  nghttp2_hpack_encoder enc;
  nghttp2_frame fr;
  nghttp2_settings settings;
  nghttp2_frd frd;
  nghttp2_ssize nwrite;
  nghttp2_stream *stream;
  conn_options opts;
  int64_t stream_id;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_wrap_init(&obuf, outbuf, sizeof(outbuf));
  nghttp2_buf_init(&hbuf);
  nghttp2_frd_init(&frd);

  /* Before SETTINGS ACK, refuse unwanted streams */
  server_default_settings(&settings);
  settings.max_concurrent_streams_remote = 2;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  stream_id = 0x01;

  for (i = 0; i < 10; ++i, stream_id += 2) {
    fr.headers = (nghttp2_frame_headers){
      .hd =
        {
          .type = NGHTTP2_FRAME_HEADERS,
          .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
          .stream_id = stream_id,
        },
      .field_block = hbuf.pos,
      .field_blocklen = nghttp2_buf_len(&hbuf),
    };

    fr.headers.hd.len =
      (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

    nghttp2_buf_reset(&buf);
    rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

    assert_int(0, ==, rv);

    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    assert_int(0, ==, rv);

    nghttp2_buf_reset(&obuf);
    nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

    if (i < settings.max_concurrent_streams_remote) {
      assert_ptrdiff(0, ==, nwrite);

      continue;
    }

    assert_ptrdiff(0, <, nwrite);

    obuf.last += nwrite;

    rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

    assert_int(0, ==, rv);
    assert_uint8(NGHTTP2_FRAME_RST_STREAM, ==, fr.meta.hd.type);
    assert_int64(stream_id, ==, fr.rst_stream.hd.stream_id);
    assert_uint32(NGHTTP2_REFUSED_STREAM, ==, fr.rst_stream.error_code);
    assert_size(0, ==, nghttp2_buf_len(&obuf));
  }

  assert_size(2, ==, nghttp2_conn_get_num_active_streams(conn));

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* After SETTINGS ACK, streams that exceeds concurrency limit is
     treated as error. */
  server_default_settings(&settings);
  settings.max_concurrent_streams_remote = 2;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);
  read_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  stream_id = 0x01;

  for (i = 0; i < 3; ++i, stream_id += 2) {
    fr.headers = (nghttp2_frame_headers){
      .hd =
        {
          .type = NGHTTP2_FRAME_HEADERS,
          .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
          .stream_id = stream_id,
        },
      .field_block = hbuf.pos,
      .field_blocklen = nghttp2_buf_len(&hbuf),
    };

    fr.headers.hd.len =
      (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

    nghttp2_buf_reset(&buf);
    rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

    assert_int(0, ==, rv);

    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    assert_int(0, ==, rv);

    nghttp2_buf_reset(&obuf);
    nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

    if (i < settings.max_concurrent_streams_remote) {
      assert_ptrdiff(0, ==, nwrite);

      continue;
    }

    assert_ptrdiff(0, <, nwrite);

    obuf.last += nwrite;

    rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

    assert_int(0, ==, rv);
    assert_size(8, ==, fr.meta.hd.len);
    assert_uint8(NGHTTP2_FRAME_GOAWAY, ==, fr.meta.hd.type);
    assert_int64(0, ==, fr.goaway.hd.stream_id);
    assert_uint32(0x3, ==, fr.goaway.last_stream_id);
    assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, fr.goaway.error_code);
    assert_size(0, ==, nghttp2_buf_len(&obuf));
  }

  assert_size(2, ==, nghttp2_conn_get_num_active_streams(conn));

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* The stream that is writing HEADERS, when RST_STREAM is received
     against it, is not counted toward active streams */
  server_default_settings(&settings);
  settings.max_concurrent_streams_remote = 1;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);
  read_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_submit_response(conn, 0x01, respnva,
                                    nghttp2_arraylen(respnva), NULL);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

  assert_ptrdiff(0, <, nwrite);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(nghttp2_http_writer_inprogress(&stream->tx.hw));

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = 0x01,
      },
    .error_code = NGHTTP2_CANCEL,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_rst_stream(&buf, &fr.rst_stream);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM_RECVED);
  assert_size(0, ==, nghttp2_conn_get_num_active_streams(conn));

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_rx_flow_control(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  uint8_t rawbuf[1 << 19];
  uint8_t outbuf[16384];
  nghttp2_hpack_encoder enc;
  nghttp2_buf buf, hbuf;
  nghttp2_settings settings;
  nghttp2_frame fr;
  nghttp2_stream *stream;
  nghttp2_tstamp ts = 0;
  nghttp2_ssize nwrite;
  conn_options opts;
  int64_t stream_id;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* connection-level flow control */
  client_default_settings(&settings);
  settings.initial_max_stream_data = 1 << 17;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_client_with_options(&conn, opts);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);
  read_settings_ack(conn, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, respnva,
                                   nghttp2_arraylen(respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  for (i = 0; i < 3; ++i) {
    fr.data = (nghttp2_frame_data){
      .hd =
        {
          .type = NGHTTP2_FRAME_DATA,
          .stream_id = stream_id,
        },
      .data = nulldata,
      .datalen = 16384,
    };

    fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

    rv = nghttp2_frame_encode_data(&buf, &fr.data);

    assert_int(0, ==, rv);
  }

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = stream_id,
      },
    .data = nulldata,
    .datalen = 16383,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_uint64(stream->rx.max_offset, >, stream->rx.offset);
  assert_uint64(conn->rx.max_offset, ==, conn->rx.offset);

  /* Allow another 16384 bytes */
  rv = nghttp2_conn_extend_max_offset(conn, 16384);

  assert_int(0, ==, rv);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = stream_id,
      },
    .padlen = 200,
    .data = nulldata,
    .datalen = 16183,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_uint64(stream->rx.max_offset, >, stream->rx.offset);
  assert_uint64(conn->rx.max_offset, ==, conn->rx.offset);

  /* 0 length DATA is fine */
  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = stream_id,
      },
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_uint64(stream->rx.max_offset, >, stream->rx.offset);
  assert_uint64(conn->rx.max_offset, ==, conn->rx.offset);

  /* connection-level flow control error */
  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = stream_id,
      },
    .data = nulldata,
    .datalen = 1,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_FLOW_CONTROL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* stream-level flow control */
  client_default_settings(&settings);
  settings.initial_max_stream_data = 1000;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_client_with_options(&conn, opts);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);
  read_settings_ack(conn, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, respnva,
                                   nghttp2_arraylen(respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = stream_id,
      },
    .data = nulldata,
    .datalen = 1000,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_uint64(stream->rx.max_offset, ==, stream->rx.offset);

  /* Allow another 400 bytes */
  rv = nghttp2_conn_extend_max_stream_offset(conn, stream_id, 400);

  assert_int(0, ==, rv);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = stream_id,
      },
    .padlen = 200,
    .data = nulldata,
    .datalen = 199,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_uint64(stream->rx.max_offset, ==, stream->rx.offset);

  /* 0 length DATA is fine */
  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = stream_id,
      },
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_uint64(stream->rx.max_offset, ==, stream->rx.offset);

  /* stream-level flow control error */
  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = stream_id,
      },
    .data = nulldata,
    .datalen = 1,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_FLOW_CONTROL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_tx_flow_control(void) {
  static const nghttp2_settings_entry iv[] = {
    {
      .id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
      .value = 32767,
    },
  };
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  uint8_t outbuf[1 << 19];
  nghttp2_buf buf, obuf;
  nghttp2_frd frd;
  nghttp2_frame fr;
  nghttp2_tstamp ts = 0;
  nghttp2_ssize nwrite;
  int64_t stream_id;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_wrap_init(&obuf, outbuf, sizeof(outbuf));

  /* connection-level flow control */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_80k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);

  for (;;) {
    nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }

    obuf.last += nwrite;
  }

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(16384, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(16384, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(16384, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(16383, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  fr.window_update = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
        .stream_id = stream_id,
      },
    .window_size_inc = 16384,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_window_update(&buf, &fr.window_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, ==, nwrite);

  fr.window_update = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
      },
    .window_size_inc = 999,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_window_update(&buf, &fr.window_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(999, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_del(conn);

  /* stream-level flow control */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, iv, nghttp2_arraylen(iv), ts);
  write_settings_ack(conn, ts);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_48k,
                                },
                                NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);

  for (;;) {
    nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

    assert_ptrdiff(0, <=, nwrite);

    if (nwrite == 0) {
      break;
    }

    obuf.last += nwrite;
  }

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(16384, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(16383, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  fr.window_update = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
        .stream_id = stream_id,
      },
    .window_size_inc = 20,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_window_update(&buf, &fr.window_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(20, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_del(conn);
}

static void check_http_header(const nghttp2_nv *nva, size_t nvlen, int request,
                              int fail) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  uint8_t outbuf[16384];
  uint8_t rawbuf[4096];
  nghttp2_buf buf, hbuf;
  nghttp2_frame fr;
  nghttp2_conn *conn;
  nghttp2_settings settings;
  nghttp2_ssize nwrite;
  nghttp2_hpack_encoder enc;
  conn_options opts;
  int64_t stream_id;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  nghttp2_buf_init(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, nva, nvlen);

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  if (request) {
    server_default_settings(&settings);
    settings.enable_connect_protocol = 1;

    opts = (conn_options){
      .settings = &settings,
    };

    setup_default_server_with_options(&conn, opts);
    read_client_preface(conn, NULL, 0, 0);
  } else {
    client_default_settings(&settings);

    opts = (conn_options){
      .settings = &settings,
    };

    setup_default_client_with_options(&conn, opts);
    read_server_preface(conn, NULL, 0, 0);

    stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                            nghttp2_arraylen(reqnva), NULL, 0);

    assert_int64(0x01, ==, stream_id);

    nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), 0);

    assert_ptrdiff(0, <, nwrite);
  }

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), 0);

  assert_int(0, ==, rv);

  if (fail) {
    assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
                conn->rx.frrd.state);
    assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);
  } else {
    assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
                ==, conn->rx.frrd.state);
  }

  nghttp2_buf_free(&hbuf, mem);
  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);
}

static void check_http_resp_header_ok(const nghttp2_nv *nva, size_t nvlen) {
  check_http_header(nva, nvlen, /* request = */ 0, /* fail = */ 0);
}

static void check_http_resp_header_err(const nghttp2_nv *nva, size_t nvlen) {
  check_http_header(nva, nvlen, /* request = */ 0, /* fail = */ 1);
}

static void check_http_req_header_ok(const nghttp2_nv *nva, size_t nvlen) {
  check_http_header(nva, nvlen, /* request = */ 1, /* fail = */ 0);
}

static void check_http_req_header_err(const nghttp2_nv *nva, size_t nvlen) {
  check_http_header(nva, nvlen, /* request = */ 1, /* fail = */ 1);
}

void test_nghttp2_conn_http_resp_header(void) {
  /* test case for response */
  /* response header lacks :status */
  static const nghttp2_nv nostatus_resnva[] = {
    MAKE_NV("server", "foo"),
  };
  /* response header has 2 :status */
  static const nghttp2_nv dupstatus_resnva[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV(":status", "200"),
  };
  /* response header has bad pseudo header :scheme */
  static const nghttp2_nv badpseudo_resnva[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV(":scheme", "https"),
  };
  /* response header has :status after regular header field */
  static const nghttp2_nv latepseudo_resnva[] = {
    MAKE_NV("server", "foo"),
    MAKE_NV(":status", "200"),
  };
  /* response header has bad status code */
  static const nghttp2_nv badstatus_resnva[] = {
    MAKE_NV(":status", "2000"),
  };
  /* response header has bad content-length */
  static const nghttp2_nv badcl_resnva[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV("content-length", "-1"),
  };
  /* response header has multiple content-length */
  static const nghttp2_nv dupcl_resnva[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV("content-length", "0"),
    MAKE_NV("content-length", "0"),
  };
  /* response header has disallowed header field */
  static const nghttp2_nv badhd_resnva[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV("connection", "close"),
  };
  /* response header has content-length with 100 status code */
  static const nghttp2_nv cl1xx_resnva[] = {
    MAKE_NV(":status", "100"),
    MAKE_NV("content-length", "0"),
  };
  /* response header has 0 content-length with 204 status code */
  static const nghttp2_nv cl204_resnva[] = {
    MAKE_NV(":status", "204"),
    MAKE_NV("content-length", "0"),
  };
  /* response header has nonzero content-length with 204 status
     code */
  static const nghttp2_nv clnonzero204_resnva[] = {
    MAKE_NV(":status", "204"),
    MAKE_NV("content-length", "100"),
  };
  /* status code 101 should not be used in HTTP/3 because it is used
     for HTTP Upgrade which HTTP/3 removes. */
  static const nghttp2_nv status101_resnva[] = {
    MAKE_NV(":status", "101"),
  };
  /* response header has te header field that contains invalid
     value. */
  static const nghttp2_nv invalidte_resnva[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV("te", "trailer2"),
  };
  /* response header has te header field that contains TRAiLERS. */
  static const nghttp2_nv te_resnva[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV("te", "TRAiLERS"),
  };
  /* response header has a bad header value. */
  static const nghttp2_nv badvalue_resnva[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV("foo", "\x7F"),
  };
  /* response header has empty header name followed by a pseudo
     header. */
  static const nghttp2_nv emptynamepseudo_resnva[] = {
    MAKE_NV("", "foo"),
    MAKE_NV(":status", "200"),
  };
  /* response header contains a upper-cased header name. */
  static const nghttp2_nv upcasename_resnva[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV("Cookie", "foo=bar"),
  };
  /* response header contains status code that includes the leading
     zero. */
  static const nghttp2_nv lzstatus_resnva[] = {
    MAKE_NV(":status", "022"),
  };
  /* response header contains status code that consists of 2
     digits. */
  static const nghttp2_nv twodigstatus_resnva[] = {
    MAKE_NV(":status", "20"),
  };

  check_http_resp_header_err(nostatus_resnva,
                             nghttp2_arraylen(nostatus_resnva));
  check_http_resp_header_err(dupstatus_resnva,
                             nghttp2_arraylen(dupstatus_resnva));
  check_http_resp_header_err(badpseudo_resnva,
                             nghttp2_arraylen(badpseudo_resnva));
  check_http_resp_header_err(latepseudo_resnva,
                             nghttp2_arraylen(latepseudo_resnva));
  check_http_resp_header_err(badstatus_resnva,
                             nghttp2_arraylen(badstatus_resnva));
  check_http_resp_header_err(badcl_resnva, nghttp2_arraylen(badcl_resnva));
  check_http_resp_header_err(dupcl_resnva, nghttp2_arraylen(dupcl_resnva));
  check_http_resp_header_err(badhd_resnva, nghttp2_arraylen(badhd_resnva));
  /* Ignore content-length in 1xx response. */
  check_http_resp_header_ok(cl1xx_resnva, nghttp2_arraylen(cl1xx_resnva));
  /* This is allowed to work with widely used services. */
  check_http_resp_header_ok(cl204_resnva, nghttp2_arraylen(cl204_resnva));
  check_http_resp_header_err(clnonzero204_resnva,
                             nghttp2_arraylen(clnonzero204_resnva));
  check_http_resp_header_err(status101_resnva,
                             nghttp2_arraylen(status101_resnva));
  check_http_resp_header_err(invalidte_resnva,
                             nghttp2_arraylen(invalidte_resnva));
  check_http_resp_header_ok(te_resnva, nghttp2_arraylen(te_resnva));
  check_http_resp_header_ok(badvalue_resnva, nghttp2_arraylen(badvalue_resnva));
  check_http_resp_header_err(emptynamepseudo_resnva,
                             nghttp2_arraylen(emptynamepseudo_resnva));
  check_http_resp_header_err(upcasename_resnva,
                             nghttp2_arraylen(upcasename_resnva));
  check_http_resp_header_err(lzstatus_resnva,
                             nghttp2_arraylen(lzstatus_resnva));
  check_http_resp_header_err(twodigstatus_resnva,
                             nghttp2_arraylen(twodigstatus_resnva));
}

void test_nghttp2_conn_http_req_header(void) {
  /* test case for request */
  /* request header has no :path */
  static const nghttp2_nv nopath_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"),
  };
  /* request header has CONNECT method, but followed by :path */
  static const nghttp2_nv earlyconnect_reqnva[] = {
    MAKE_NV(":method", "CONNECT"),
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":path", "/"),
    MAKE_NV(":authority", "localhost"),
  };
  /* request header has CONNECT method following :path */
  static const nghttp2_nv lateconnect_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":path", "/"),
    MAKE_NV(":method", "CONNECT"),
    MAKE_NV(":authority", "localhost"),
  };
  /* request header has multiple :path */
  static const nghttp2_nv duppath_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"),
    MAKE_NV(":path", "/"),
    MAKE_NV(":path", "/"),
  };
  /* request header has bad content-length */
  static const nghttp2_nv badcl_reqnva[] = {
    MAKE_NV(":scheme", "https"),        MAKE_NV(":method", "POST"),
    MAKE_NV(":authority", "localhost"), MAKE_NV(":path", "/"),
    MAKE_NV("content-length", "-1"),
  };
  /* request header has multiple content-length */
  static const nghttp2_nv dupcl_reqnva[] = {
    MAKE_NV(":scheme", "https"),        MAKE_NV(":method", "POST"),
    MAKE_NV(":authority", "localhost"), MAKE_NV(":path", "/"),
    MAKE_NV("content-length", "0"),     MAKE_NV("content-length", "0"),
  };
  /* request header has content-length that is empty string */
  static const nghttp2_nv emptycl_reqnva[] = {
    MAKE_NV(":scheme", "https"),        MAKE_NV(":method", "POST"),
    MAKE_NV(":authority", "localhost"), MAKE_NV(":path", "/"),
    MAKE_NV("content-length", ""),
  };
  /* request header has content-length that is greater than
     NGHTTP2_MAX_VARINT */
  static const nghttp2_nv toolargecl_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":method", "POST"),
    MAKE_NV(":authority", "localhost"),
    MAKE_NV(":path", "/"),
    MAKE_NV("content-length", "4611686018427387904"),
  };
  /* request header has content-length that is much greater than
     NGHTTP2_MAX_VARINT */
  static const nghttp2_nv fartoolargecl_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":method", "POST"),
    MAKE_NV(":authority", "localhost"),
    MAKE_NV(":path", "/"),
    MAKE_NV("content-length", "5611686018427387904"),
  };
  /* request header has content-length that is equal to
     NGHTTP2_MAX_VARINT */
  static const nghttp2_nv largestcl_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":method", "POST"),
    MAKE_NV(":authority", "localhost"),
    MAKE_NV(":path", "/"),
    MAKE_NV("content-length", "4611686018427387903"),
  };
  /* request header has disallowed header field */
  static const nghttp2_nv badhd_reqnva[] = {
    MAKE_NV(":scheme", "https"),        MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"), MAKE_NV(":path", "/"),
    MAKE_NV("connection", "close"),
  };
  /* request header has :authority header field containing illegal
     characters */
  static const nghttp2_nv badauthority_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "\x0D\x0Alocalhost"),
    MAKE_NV(":path", "/"),
  };
  /* request header has regular header field containing illegal
     character before all mandatory header fields are seen. */
  static const nghttp2_nv badhdbtw_reqnva[] = {
    MAKE_NV(":scheme", "https"), MAKE_NV(":method", "GET"),
    MAKE_NV("foo", "\x0D\x0A"),  MAKE_NV(":authority", "localhost"),
    MAKE_NV(":path", "/"),
  };
  /* request header has "*" in :path header field while method is GET.
     :path is received before :method */
  static const nghttp2_nv asteriskget1_reqnva[] = {
    MAKE_NV(":path", "*"),
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":authority", "localhost"),
    MAKE_NV(":method", "GET"),
  };
  /* request header has "*" in :path header field while method is GET.
     :method is received before :path */
  static const nghttp2_nv asteriskget2_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":authority", "localhost"),
    MAKE_NV(":method", "GET"),
    MAKE_NV(":path", "*"),
  };
  /* OPTIONS method can include "*" in :path header field.  :path is
     received before :method. */
  static const nghttp2_nv asteriskoptions1_reqnva[] = {
    MAKE_NV(":path", "*"),
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":authority", "localhost"),
    MAKE_NV(":method", "OPTIONS"),
  };
  /* OPTIONS method can include "*" in :path header field.  :method is
     received before :path. */
  static const nghttp2_nv asteriskoptions2_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":authority", "localhost"),
    MAKE_NV(":method", "OPTIONS"),
    MAKE_NV(":path", "*"),
  };
  /* header name contains invalid character */
  static const nghttp2_nv invalidname_reqnva[] = {
    MAKE_NV(":scheme", "https"),        MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"), MAKE_NV(":path", "/"),
    MAKE_NV("\x0Foo", "zzz"),
  };
  /* header value contains invalid character */
  static const nghttp2_nv invalidvalue_reqnva[] = {
    MAKE_NV(":scheme", "https"),        MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"), MAKE_NV(":path", "/"),
    MAKE_NV("foo", "\x0zzz"),
  };
  /* :protocol is not allowed unless it is enabled by the local
     endpoint. */
  /* :protocol is allowed if SETTINGS_CONNECT_PROTOCOL is enabled by
     the local endpoint. */
  static const nghttp2_nv connectproto_reqnva[] = {
    MAKE_NV(":scheme", "https"),       MAKE_NV(":path", "/"),
    MAKE_NV(":method", "CONNECT"),     MAKE_NV(":authority", "localhost"),
    MAKE_NV(":protocol", "websocket"),
  };
  /* :protocol is only allowed with CONNECT method. */
  static const nghttp2_nv connectprotoget_reqnva[] = {
    MAKE_NV(":scheme", "https"),       MAKE_NV(":path", "/"),
    MAKE_NV(":method", "GET"),         MAKE_NV(":authority", "localhost"),
    MAKE_NV(":protocol", "websocket"),
  };
  /* CONNECT method with :protocol requires :path. */
  static const nghttp2_nv connectprotonopath_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":method", "CONNECT"),
    MAKE_NV(":authority", "localhost"),
    MAKE_NV(":protocol", "websocket"),
  };
  /* CONNECT method with :protocol requires :authority. */
  static const nghttp2_nv connectprotonoauth_reqnva[] = {
    MAKE_NV(":scheme", "http"),        MAKE_NV(":path", "/"),
    MAKE_NV(":method", "CONNECT"),     MAKE_NV("host", "localhost"),
    MAKE_NV(":protocol", "websocket"),
  };
  /* regular CONNECT method should succeed with
     SETTINGS_CONNECT_PROTOCOL */
  static const nghttp2_nv regularconnect_reqnva[] = {
    MAKE_NV(":method", "CONNECT"),
    MAKE_NV(":authority", "localhost"),
  };
  /* scheme is an empty string. */
  static const nghttp2_nv emptyscheme_reqnva[] = {
    MAKE_NV(":scheme", ""),
    MAKE_NV(":path", "/"),
    MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"),
  };
  /* scheme contains a string that starts with a character that is not
     in [a-zA-Z]. */
  static const nghttp2_nv badprefixscheme_reqnva[] = {
    MAKE_NV(":scheme", "@"),
    MAKE_NV(":path", "/"),
    MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"),
  };
  /* scheme contains a bad character. */
  static const nghttp2_nv badcharscheme_reqnva[] = {
    MAKE_NV(":scheme", "http*"),
    MAKE_NV(":path", "/"),
    MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"),
  };
  /* scheme contains all allowed characters. */
  static const nghttp2_nv allcharscheme_reqnva[] = {
    MAKE_NV(
      ":scheme",
      "aabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-."),
    MAKE_NV(":path", "/"),
    MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"),
  };
  /* method is an empty string. */
  static const nghttp2_nv emptymethod_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":path", "/"),
    MAKE_NV(":method", ""),
    MAKE_NV(":authority", "localhost"),
  };
  /* method contains a bad character. */
  static const nghttp2_nv badcharmethod_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":path", "/"),
    MAKE_NV(":method", "GET\xB2"),
    MAKE_NV(":authority", "localhost"),
  };
  /* empty :path for https URI. */
  static const nghttp2_nv emptyhttpspath_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":path", ""),
    MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"),
  };
  /* empty :path for http URI. */
  static const nghttp2_nv emptyhttppath_reqnva[] = {
    MAKE_NV(":scheme", "http"),
    MAKE_NV(":path", ""),
    MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"),
  };
  /* empty :path for non-https/http URI. */
  static const nghttp2_nv emptypath_reqnva[] = {
    MAKE_NV(":scheme", "something"),
    MAKE_NV(":path", ""),
    MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"),
  };
  /* :path contains a bad character. */
  static const nghttp2_nv badcharpath_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":path", "/\x01"),
    MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"),
  };
  /* HEAD method is used. */
  static const nghttp2_nv headmethod_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":path", "/"),
    MAKE_NV(":method", "HEAD"),
    MAKE_NV(":authority", "localhost"),
  };
  /* :protocol is given twice. */
  static const nghttp2_nv dupproto_reqnva[] = {
    MAKE_NV(":scheme", "https"),       MAKE_NV(":path", "/"),
    MAKE_NV(":method", "CONNECT"),     MAKE_NV(":authority", "localhost"),
    MAKE_NV(":protocol", "websocket"), MAKE_NV(":protocol", "websocket"),
  };
  /* host contains a bad character. */
  static const nghttp2_nv badcharhost_reqnva[] = {
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":path", "/"),
    MAKE_NV(":method", "HEAD"),
    MAKE_NV("host", "localhost\x99"),
  };
  /* host is given twice. */
  static const nghttp2_nv duphost_reqnva[] = {
    MAKE_NV(":scheme", "https"),  MAKE_NV(":path", "/"),
    MAKE_NV(":method", "HEAD"),   MAKE_NV("host", "localhost"),
    MAKE_NV("host", "localhost"),
  };
  /* request header has te header field that contains invalid
     value. */
  static const nghttp2_nv invalidte_reqnva[] = {
    MAKE_NV(":scheme", "https"), MAKE_NV(":path", "/"),
    MAKE_NV(":method", "GET"),   MAKE_NV(":authority", "localhost"),
    MAKE_NV("te", "trailer2"),
  };
  /* request header has te header field that contains TRAiLERS. */
  static const nghttp2_nv te_reqnva[] = {
    MAKE_NV(":scheme", "https"), MAKE_NV(":path", "/"),
    MAKE_NV(":method", "GET"),   MAKE_NV(":authority", "localhost"),
    MAKE_NV("te", "TRAiLERS"),
  };
  /* priority header has a bad character. */
  static const nghttp2_nv badcharpriority_reqnva[] = {
    MAKE_NV(":scheme", "https"), MAKE_NV(":path", "/"),
    MAKE_NV(":method", "GET"),   MAKE_NV(":authority", "localhost"),
    MAKE_NV("priority", "\x7F"),
  };
  /* priority header is followed by bad priority header. */
  static const nghttp2_nv dupbadcharpriority_reqnva[] = {
    MAKE_NV(":scheme", "https"), MAKE_NV(":path", "/"),
    MAKE_NV(":method", "GET"),   MAKE_NV(":authority", "localhost"),
    MAKE_NV("priority", "\x7F"), MAKE_NV("priority", "i"),
  };
  /* request header has :status header. */
  static const nghttp2_nv unknownpseudohd_reqnva[] = {
    MAKE_NV(":scheme", "https"),     MAKE_NV(":path", "/"),
    MAKE_NV(":method", "GET"),       MAKE_NV(":authority", "localhost"),
    MAKE_NV(":status", "localhost"),
  };

  /* request header has no :path */
  check_http_req_header_err(nopath_reqnva, nghttp2_arraylen(nopath_reqnva));
  check_http_req_header_err(earlyconnect_reqnva,
                            nghttp2_arraylen(earlyconnect_reqnva));
  check_http_req_header_err(lateconnect_reqnva,
                            nghttp2_arraylen(lateconnect_reqnva));
  check_http_req_header_err(duppath_reqnva, nghttp2_arraylen(duppath_reqnva));
  check_http_req_header_err(badcl_reqnva, nghttp2_arraylen(badcl_reqnva));
  check_http_req_header_err(dupcl_reqnva, nghttp2_arraylen(dupcl_reqnva));
  check_http_req_header_err(emptycl_reqnva, nghttp2_arraylen(emptycl_reqnva));
  check_http_req_header_ok(largestcl_reqnva,
                           nghttp2_arraylen(largestcl_reqnva));
  check_http_req_header_err(toolargecl_reqnva,
                            nghttp2_arraylen(toolargecl_reqnva));
  check_http_req_header_err(fartoolargecl_reqnva,
                            nghttp2_arraylen(fartoolargecl_reqnva));
  check_http_req_header_err(badhd_reqnva, nghttp2_arraylen(badhd_reqnva));
  check_http_req_header_err(badauthority_reqnva,
                            nghttp2_arraylen(badauthority_reqnva));
  check_http_req_header_err(badhdbtw_reqnva, nghttp2_arraylen(badhdbtw_reqnva));
  check_http_req_header_err(asteriskget1_reqnva,
                            nghttp2_arraylen(asteriskget1_reqnva));
  check_http_req_header_err(asteriskget2_reqnva,
                            nghttp2_arraylen(asteriskget2_reqnva));
  check_http_req_header_ok(asteriskoptions1_reqnva,
                           nghttp2_arraylen(asteriskoptions1_reqnva));
  check_http_req_header_ok(asteriskoptions2_reqnva,
                           nghttp2_arraylen(asteriskoptions2_reqnva));
  check_http_req_header_ok(invalidname_reqnva,
                           nghttp2_arraylen(invalidname_reqnva));
  check_http_req_header_ok(invalidvalue_reqnva,
                           nghttp2_arraylen(invalidvalue_reqnva));
  check_http_req_header_ok(connectproto_reqnva,
                           nghttp2_arraylen(connectproto_reqnva));
  check_http_req_header_err(connectprotoget_reqnva,
                            nghttp2_arraylen(connectprotoget_reqnva));
  check_http_req_header_err(connectprotonopath_reqnva,
                            nghttp2_arraylen(connectprotonopath_reqnva));
  check_http_req_header_err(connectprotonoauth_reqnva,
                            nghttp2_arraylen(connectprotonoauth_reqnva));
  check_http_req_header_ok(regularconnect_reqnva,
                           nghttp2_arraylen(regularconnect_reqnva));
  check_http_req_header_err(emptyscheme_reqnva,
                            nghttp2_arraylen(emptyscheme_reqnva));
  check_http_req_header_err(badprefixscheme_reqnva,
                            nghttp2_arraylen(badprefixscheme_reqnva));
  check_http_req_header_err(badcharscheme_reqnva,
                            nghttp2_arraylen(badcharscheme_reqnva));
  check_http_req_header_ok(allcharscheme_reqnva,
                           nghttp2_arraylen(allcharscheme_reqnva));
  check_http_req_header_err(emptymethod_reqnva,
                            nghttp2_arraylen(emptymethod_reqnva));
  check_http_req_header_err(badcharmethod_reqnva,
                            nghttp2_arraylen(badcharmethod_reqnva));
  check_http_req_header_err(emptyhttpspath_reqnva,
                            nghttp2_arraylen(emptyhttpspath_reqnva));
  check_http_req_header_err(emptyhttppath_reqnva,
                            nghttp2_arraylen(emptyhttppath_reqnva));
  check_http_req_header_err(emptypath_reqnva,
                            nghttp2_arraylen(emptypath_reqnva));
  check_http_req_header_err(badcharpath_reqnva,
                            nghttp2_arraylen(badcharpath_reqnva));
  check_http_req_header_ok(headmethod_reqnva,
                           nghttp2_arraylen(headmethod_reqnva));
  check_http_req_header_err(dupproto_reqnva, nghttp2_arraylen(dupproto_reqnva));
  check_http_req_header_err(badcharhost_reqnva,
                            nghttp2_arraylen(badcharhost_reqnva));
  check_http_req_header_err(duphost_reqnva, nghttp2_arraylen(duphost_reqnva));
  check_http_req_header_err(invalidte_reqnva,
                            nghttp2_arraylen(invalidte_reqnva));
  check_http_req_header_ok(te_reqnva, nghttp2_arraylen(te_reqnva));
  check_http_req_header_ok(badcharpriority_reqnva,
                           nghttp2_arraylen(badcharpriority_reqnva));
  check_http_req_header_ok(dupbadcharpriority_reqnva,
                           nghttp2_arraylen(dupbadcharpriority_reqnva));
  check_http_req_header_err(unknownpseudohd_reqnva,
                            nghttp2_arraylen(unknownpseudohd_reqnva));
}

void test_nghttp2_conn_http_content_length(void) {
  static const nghttp2_nv cl_reqnva[] = {
    MAKE_NV(":path", "/"),        MAKE_NV(":method", "PUT"),
    MAKE_NV(":scheme", "https"),  MAKE_NV("te", "trailers"),
    MAKE_NV("host", "localhost"), MAKE_NV("content-length", "9000000000"),
  };
  static const nghttp2_nv cl_respnva[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV("te", "trailers"),
    MAKE_NV("content-length", "9000000000"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  uint8_t rawbuf[16384];
  uint8_t outbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_frame fr;
  nghttp2_conn *conn;
  nghttp2_ssize nwrite;
  nghttp2_hpack_encoder enc;
  nghttp2_stream *stream;
  nghttp2_tstamp ts = 0;
  int64_t stream_id;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* client */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, cl_respnva,
                                   nghttp2_arraylen(cl_respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_int64(9000000000LL, ==, stream->rx.http.content_length);
  assert_int32(200, ==, stream->rx.http.status_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* server */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, cl_reqnva,
                                   nghttp2_arraylen(cl_reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_int64(9000000000LL, ==, stream->rx.http.content_length);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_http_content_length_mismatch(void) {
  static const nghttp2_nv cl_reqnva[] = {
    MAKE_NV(":path", "/"),
    MAKE_NV(":method", "PUT"),
    MAKE_NV(":authority", "localhost"),
    MAKE_NV(":scheme", "https"),
    MAKE_NV("content-length", "20"),
  };
  static const nghttp2_nv cl_respnva[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV("content-length", "20"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  uint8_t rawbuf[16384];
  uint8_t outbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_frame fr;
  nghttp2_conn *conn;
  nghttp2_ssize nwrite;
  nghttp2_hpack_encoder enc;
  nghttp2_tstamp ts = 0;
  int64_t stream_id;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* content-length is 20, but no DATA is present and see
     END_STREAM */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, cl_reqnva,
                                   nghttp2_arraylen(cl_reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* content-length is 20, but no DATA is present and stream is
     reset */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, cl_reqnva,
                                   nghttp2_arraylen(cl_reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  nghttp2_conn_shutdown_stream(conn, 0x00, 0x01, NGHTTP2_NO_ERROR);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);
  assert_null(nghttp2_conn_find_stream(conn, 0x01));
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* content-length is 20, but server receives 21 bytes of DATA. */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, cl_reqnva,
                                   nghttp2_arraylen(cl_reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = 0x01,
      },
    .data = nulldata,
    .datalen = 21,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Check client side as well */

  /* content-length is 20, but no DATA is present and see
     END_STREAM */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, cl_respnva,
                                   nghttp2_arraylen(cl_respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* content-length is 20, but no DATA is present and stream is
     reset */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, cl_respnva,
                                   nghttp2_arraylen(cl_respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_shutdown_stream(conn, 0x00, stream_id, NGHTTP2_NO_ERROR);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);
  assert_null(nghttp2_conn_find_stream(conn, stream_id));
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* content-length is 20, but server receives 21 bytes DATA. */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, cl_respnva,
                                   nghttp2_arraylen(cl_respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = stream_id,
      },
    .data = nulldata,
    .datalen = 21,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_http_non_final_response(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  uint8_t rawbuf[16384];
  uint8_t outbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_frame fr;
  nghttp2_conn *conn;
  nghttp2_ssize nwrite;
  nghttp2_hpack_encoder enc;
  nghttp2_tstamp ts = 0;
  int64_t stream_id;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* non-final followed by DATA is illegal.  */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, infonva,
                                   nghttp2_arraylen(infonva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = stream_id,
      },
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* 2 non-finals followed by final headers */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, infonva,
                                   nghttp2_arraylen(infonva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, infonva,
                                   nghttp2_arraylen(infonva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, respnva,
                                   nghttp2_arraylen(respnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* non-finals followed by trailers; this trailer is treated as
     another non-final or final header fields.  Since it does not
     include mandatory header field, it is treated as error. */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, infonva,
                                   nghttp2_arraylen(infonva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, trnva, nghttp2_arraylen(trnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_http_trailers(void) {
  static const nghttp2_nv connect_reqnva[] = {
    MAKE_NV(":method", "CONNECT"),
    MAKE_NV(":authority", "localhost"),
  };
  static const nghttp2_nv cl_trnva[] = {
    MAKE_NV("content-length", "0"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  uint8_t rawbuf[16384];
  uint8_t outbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_frame fr;
  nghttp2_conn *conn;
  nghttp2_ssize nwrite;
  nghttp2_hpack_encoder enc;
  nghttp2_tstamp ts = 0;
  nghttp2_callbacks callbacks;
  userdata ud;
  conn_options opts;
  int64_t stream_id;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* final response followed by trailers */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, respnva,
                                   nghttp2_arraylen(respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, trnva, nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* trailers contain :status */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, respnva,
                                   nghttp2_arraylen(respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, respnva,
                                   nghttp2_arraylen(respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receiving trailers HEADERS without END_STREAM is invalid*/
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, respnva,
                                   nghttp2_arraylen(respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, trnva, nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* We do not expect response trailers after HEADERS with CONNECT
     request */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(
    conn, connect_reqnva, nghttp2_arraylen(connect_reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, respnva,
                                   nghttp2_arraylen(respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, trnva, nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* The response trailers in CONNECT stream after HEADERS are
     acceptable if the status code is not 2xx. */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(
    conn, connect_reqnva, nghttp2_arraylen(connect_reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, notfound_respnva,
                                   nghttp2_arraylen(notfound_respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, trnva, nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* We do not expect response trailers after DATA with CONNECT
     request */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(
    conn, connect_reqnva, nghttp2_arraylen(connect_reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, respnva,
                                   nghttp2_arraylen(respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = stream_id,
      },
    .data = nulldata,
    .datalen = 10,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, trnva, nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* The response trailers after DATA in CONNECT stream are acceptable
     if the status code is not 2xx. */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(
    conn, connect_reqnva, nghttp2_arraylen(connect_reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, notfound_respnva,
                                   nghttp2_arraylen(notfound_respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = stream_id,
      },
    .data = nulldata,
    .datalen = 10,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, trnva, nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* request followed by trailers */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, trnva, nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* request followed by trailers which contains pseudo headers */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* request followed by trailers that do not have END_STREAM */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, trnva, nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* We do not expect trailers after HEADERS with CONNECT request */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, connect_reqnva,
                                   nghttp2_arraylen(connect_reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, trnva, nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* We do not expect trailers after DATA with CONNECT request */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, connect_reqnva,
                                   nghttp2_arraylen(connect_reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = 0x01,
      },
    .data = nulldata,
    .datalen = 10,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, trnva, nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* server: content-length in request trailers is ignored and
     removed. */
  server_default_callbacks(&callbacks);
  callbacks.recv_trailer = recv_trailer;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, cl_trnva,
                                   nghttp2_arraylen(cl_trnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(0, ==, ud.recv_trailer.ncalled);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* client: content-length in request trailers is ignored and
     removed. */
  client_default_callbacks(&callbacks);
  callbacks.recv_trailer = recv_trailer;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_client_with_options(&conn, opts);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, respnva,
                                   nghttp2_arraylen(respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, cl_trnva,
                                   nghttp2_arraylen(cl_trnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(0, ==, ud.recv_trailer.ncalled);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_http_ignore_content_length(void) {
  static const nghttp2_nv connectcl_reqnva[] = {
    MAKE_NV(":authority", "localhost"),
    MAKE_NV(":method", "CONNECT"),
    MAKE_NV("content-length", "999999"),
  };
  static const nghttp2_nv notmodifiedcl_respnva[] = {
    MAKE_NV(":status", "304"),
    MAKE_NV("content-length", "20"),
  };
  static const nghttp2_nv zerocl_respnva[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV("content-length", "0"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  uint8_t outbuf[16384];
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_frame fr;
  nghttp2_conn *conn;
  nghttp2_ssize nwrite;
  nghttp2_hpack_encoder enc;
  nghttp2_tstamp ts = 0;
  nghttp2_stream *stream;
  int64_t stream_id;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* If status code is 304, content-length must be ignored. */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, notmodifiedcl_respnva,
                                   nghttp2_arraylen(notmodifiedcl_respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_int64(0, ==, stream->rx.http.content_length);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* If method is CONNECT, content-length must be ignored. */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, connectcl_reqnva,
                                   nghttp2_arraylen(connectcl_reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_int64(-1, ==, stream->rx.http.content_length);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Content-Length in 200 response to CONNECT is ignored */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(
    conn, connectcl_reqnva, nghttp2_arraylen(connectcl_reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, zerocl_respnva,
                                   nghttp2_arraylen(zerocl_respnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_int64(-1, ==, stream->rx.http.content_length);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_http_record_request_method(void) {
  static const nghttp2_nv connect_reqnva[] = {
    MAKE_NV(":authority", "localhost"),
    MAKE_NV(":method", "CONNECT"),
  };
  static const nghttp2_nv head_reqnva[] = {
    MAKE_NV(":authority", "localhost"),
    MAKE_NV(":method", "HEAD"),
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":path", "/"),
  };
  static const nghttp2_nv cl_respnva[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV("content-length", "1000000007"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  uint8_t outbuf[16384];
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_frame fr;
  nghttp2_conn *conn;
  nghttp2_ssize nwrite;
  nghttp2_hpack_encoder enc;
  nghttp2_stream *stream;
  nghttp2_tstamp ts = 0;
  int64_t stream_id;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* content-length is not allowed with 200 status code in response to
     CONNECT request.  Just ignore it. */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(
    conn, connect_reqnva, nghttp2_arraylen(connect_reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, cl_respnva,
                                   nghttp2_arraylen(cl_respnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_int64(-1, ==, stream->rx.http.content_length);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* The content-length in response to HEAD request must be
     ignored. */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  stream_id = nghttp2_conn_submit_request(
    conn, head_reqnva, nghttp2_arraylen(head_reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, cl_respnva,
                                   nghttp2_arraylen(cl_respnva));

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_int64(0, ==, stream->rx.http.content_length);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_http_error(void) {
  static const nghttp2_nv dupscheme_reqnva[] = {
    MAKE_NV(":path", "/"),
    MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"),
    MAKE_NV(":scheme", "https"),
    MAKE_NV(":scheme", "https"),
  };
  static const nghttp2_nv noscheme_reqnva[] = {
    MAKE_NV(":path", "/"),
    MAKE_NV(":method", "GET"),
    MAKE_NV(":authority", "localhost"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_frame fr;
  nghttp2_conn *conn;
  nghttp2_hpack_encoder enc;
  nghttp2_tstamp ts = 0;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* duplicated :scheme */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, dupscheme_reqnva,
                                   nghttp2_arraylen(dupscheme_reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* without :scheme */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, noscheme_reqnva,
                                   nghttp2_arraylen(noscheme_reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_resume_stream(void) {
  nghttp2_conn *conn;
  int64_t stream_id;
  uint8_t outbuf[16384];
  nghttp2_buf obuf;
  nghttp2_frame fr;
  nghttp2_tstamp ts = 0;
  nghttp2_frd frd;
  nghttp2_ssize nwrite;
  nghttp2_stream *stream;
  userdata ud;
  int rv;

  nghttp2_buf_wrap_init(&obuf, outbuf, sizeof(outbuf));

  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id =
    nghttp2_conn_submit_request(conn, reqnva, nghttp2_arraylen(reqnva),
                                &(nghttp2_data_reader){
                                  .read_data = read_data_block,
                                },
                                &ud);

  assert_int64(0x01, ==, stream_id);

  ud = (userdata){0};
  ud.read_data.block_after = 1;
  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);
  assert_size(2, ==, ud.read_data.ncalled);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(4096, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_READ_DATA_BLOCKED);

  ud = (userdata){0};
  ud.read_data.block_after = 1;
  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, ==, nwrite);
  assert_size(0, ==, ud.read_data.ncalled);

  rv = nghttp2_conn_resume_stream(conn, stream_id);

  assert_int(0, ==, rv);

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_READ_DATA_BLOCKED);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);
  assert_size(2, ==, ud.read_data.ncalled);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(4096, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_READ_DATA_BLOCKED);

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_terminate(void) {
  nghttp2_conn *conn;
  int64_t stream_id;
  uint8_t outbuf[16384];
  nghttp2_buf obuf;
  nghttp2_frame fr;
  nghttp2_tstamp ts = 0;
  nghttp2_frd frd;
  nghttp2_ssize nwrite;
  int rv;

  nghttp2_buf_wrap_init(&obuf, outbuf, sizeof(outbuf));

  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, NGHTTP2_FRAME_HDLEN, ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  nghttp2_conn_terminate(conn, NGHTTP2_ENHANCE_YOUR_CALM);

  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_GOAWAY, ==, fr.meta.hd.type);
  assert_uint32(0, ==, fr.goaway.last_stream_id);
  assert_uint32(NGHTTP2_ENHANCE_YOUR_CALM, ==, fr.goaway.error_code);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(NGHTTP2_ERR_CLOSING, ==, nwrite);

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_handle_expiry(void) {
  nghttp2_conn *conn;
  nghttp2_tstamp ts = NGHTTP2_SECONDS;
  nghttp2_tstamp expiry;
  nghttp2_settings settings;
  conn_options opts;
  int rv;

  /* SETTINGS ACK received before timeout */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  expiry = nghttp2_conn_get_expiry(conn);

  assert_uint64(ts + conn->settings.settings_timeout, ==, expiry);

  ts += conn->settings.settings_timeout - 1;

  rv = nghttp2_conn_handle_expiry(conn, ts);

  assert_int(0, ==, rv);

  read_settings_ack(conn, ts);

  expiry = nghttp2_conn_get_expiry(conn);

  assert_uint64(UINT64_MAX, ==, expiry);

  nghttp2_conn_del(conn);

  /* SETTINGS ACK timer fires */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  expiry = nghttp2_conn_get_expiry(conn);

  assert_uint64(ts + conn->settings.settings_timeout, ==, expiry);

  ts += conn->settings.settings_timeout;

  rv = nghttp2_conn_handle_expiry(conn, ts);

  assert_int(NGHTTP2_ERR_SETTINGS_TIMEOUT, ==, rv);

  nghttp2_conn_del(conn);

  /* SETTINGS ACK timer disabled */
  client_default_settings(&settings);
  settings.settings_timeout = UINT64_MAX;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_client_with_options(&conn, opts);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);

  expiry = nghttp2_conn_get_expiry(conn);

  assert_uint64(UINT64_MAX, ==, expiry);

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_client_priority_update(void) {
  static const uint8_t prival[] = "u=1,i";
  nghttp2_conn *conn;
  uint8_t outbuf[16384];
  nghttp2_buf obuf;
  nghttp2_tstamp ts = 0;
  nghttp2_frd frd;
  nghttp2_frame fr;
  nghttp2_ssize nwrite;
  nghttp2_stream *stream;
  int64_t stream_id;
  int rv;

  nghttp2_buf_wrap_init(&obuf, outbuf, sizeof(outbuf));
  nghttp2_frd_init(&frd);

  /* Send PRIORITY_UPDATE */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  rv = nghttp2_conn_set_client_stream_priority(conn, stream_id, prival,
                                               nghttp2_strlen_lit(prival));

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SEND_PRIORITY_UPDATE);
  assert_null(stream->tx.priority.client_pri.base);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(4 + nghttp2_strlen_lit(prival), ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_PRIORITY_UPDATE, ==, fr.meta.hd.type);
  assert_int64(0x00, ==, fr.priority_update.hd.stream_id);
  assert_uint32((uint32_t)stream_id, ==,
                fr.priority_update.prioritized_stream_id);
  assert_memn_equal(prival, nghttp2_strlen_lit(prival), fr.priority_update.pri,
                    fr.priority_update.prilen);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_del(conn);

  /* Sending 0 length payload */
  setup_default_client(&conn);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  rv = nghttp2_conn_set_client_stream_priority(conn, stream_id, NULL, 0);

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&obuf);
  nwrite = nghttp2_conn_write(conn, obuf.last, nghttp2_buf_left(&obuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  obuf.last += nwrite;

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SEND_PRIORITY_UPDATE);
  assert_null(stream->tx.priority.client_pri.base);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &obuf);

  assert_int(0, ==, rv);
  assert_uint32(4, ==, fr.meta.hd.len);
  assert_uint8(NGHTTP2_FRAME_PRIORITY_UPDATE, ==, fr.meta.hd.type);
  assert_int64(0x00, ==, fr.priority_update.hd.stream_id);
  assert_uint32((uint32_t)stream_id, ==,
                fr.priority_update.prioritized_stream_id);
  assert_size(0, ==, fr.priority_update.prilen);
  assert_null(fr.priority_update.pri);
  assert_size(0, ==, nghttp2_buf_len(&obuf));

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_server_priority_update(void) {
  static const uint8_t prival[] = "u=2,i";
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  nghttp2_hpack_encoder enc;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_frame fr;
  nghttp2_stream *stream;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* server overrides client priority */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, pri_reqnva,
                                   nghttp2_arraylen(pri_reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint32(2, ==, stream->sched.pri.urgency);
  assert_true(stream->sched.pri.inc);

  rv = nghttp2_conn_set_server_stream_priority(conn, 0x01,
                                               &(nghttp2_pri){
                                                 .urgency = 7,
                                               });

  assert_int(0, ==, rv);
  assert_uint32(7, ==, stream->sched.pri.urgency);
  assert_false(stream->sched.pri.inc);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SERVER_PRIORITY_SET);

  /* client priority is ignored */
  fr.priority_update = (nghttp2_frame_priority_update){
    .hd =
      {
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .prioritized_stream_id = 0x01,
    .pri = prival,
    .prilen = nghttp2_arraylen(prival),
  };

  fr.priority_update.hd.len =
    (uint32_t)nghttp2_frame_encode_priority_update_payloadlen(
      &fr.priority_update);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_priority_update(&buf, &fr.priority_update);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint32(7, ==, stream->sched.pri.urgency);
  assert_false(stream->sched.pri.inc);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_rate_limit(void) {
  static const nghttp2_settings_entry
    large_iv[NGHTTP2_MAX_SETTINGS_ENTRIES + 1] = {0};
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  nghttp2_hpack_encoder enc;
  nghttp2_frame fr;
  uint8_t outbuf[16384];
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_settings_entry iv[8];
  nghttp2_settings settings;
  nghttp2_tstamp ts = 0;
  nghttp2_ssize nwrite;
  conn_options opts;
  int64_t stream_id;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* Receiving too many CONTINUATION frames */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  read_settings_ack(conn, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_CONTINUATION,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  for (i = 0; i < NGHTTP2_MAX_CONTINUATIONS; ++i) {
    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    assert_int(0, ==, rv);
    assert_enum(nghttp2_frame_read_state,
                NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
                conn->rx.frrd.state);
  }

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receiving SETTINGS that contains too many entries */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  read_settings_ack(conn, ts);

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = (nghttp2_settings_entry *)large_iv,
    .niv = nghttp2_arraylen(large_iv),
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);

  nghttp2_conn_del(conn);

  /* Receiving too many DATA frames to the closed stream */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  read_settings_ack(conn, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x03,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .len = 1,
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = 0x01,
      },
    .data = nulldata,
    .datalen = 1,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  for (;;) {
    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    if (rv != 0) {
      assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);
      break;
    }
  }

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receiving too many 0 length DATA frames without END_STREAM flag
     set */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  read_settings_ack(conn, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_data(&buf, &fr.data);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  for (;;) {
    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    if (rv != 0) {
      assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);
      break;
    }
  }

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* server: Receiving too many HEADERS frames to the closed stream */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  read_settings_ack(conn, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x03,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  for (;;) {
    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    if (rv != 0) {
      assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);
      break;
    }
  }

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* client: Receiving too many HEADERS frames to the closed stream */
  client_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_client_with_options(&conn, opts);
  write_preface(conn, ts);
  read_server_preface(conn, NULL, 0, ts);
  read_settings_ack(conn, ts);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x03, ==, stream_id);

  nghttp2_conn_shutdown_stream(conn, 0x00, 0x01, NGHTTP2_CANCEL);

  nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  for (;;) {
    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);
    if (rv != 0) {
      assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);
      break;
    }
  }

  nghttp2_conn_del(conn);

  /* Refusing too many streams during graceful shutdown */
  server_default_settings(&settings);
  settings.log_write = NULL;
  settings.max_concurrent_streams_remote = INT32_MAX;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  read_settings_ack(conn, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  stream_id = 0x01;
  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_shutdown(conn);

  for (;;) {
    stream_id += 2;

    fr.headers = (nghttp2_frame_headers){
      .hd =
        {
          .type = NGHTTP2_FRAME_HEADERS,
          .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
          .stream_id = stream_id,
        },
      .field_block = hbuf.pos,
      .field_blocklen = nghttp2_buf_len(&hbuf),
    };

    fr.headers.hd.len =
      (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
    nghttp2_buf_reset(&buf);
    rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

    assert_int(0, ==, rv);

    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);
    if (rv != 0) {
      assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);
      break;
    }

    assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
                ==, conn->rx.frrd.state);
  }

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Refusing too many streams before getting SETTINGS ACK */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  stream_id = 0x01;
  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = stream_id,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  for (;;) {
    stream_id += 2;

    fr.headers = (nghttp2_frame_headers){
      .hd =
        {
          .type = NGHTTP2_FRAME_HEADERS,
          .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
          .stream_id = stream_id,
        },
      .field_block = hbuf.pos,
      .field_blocklen = nghttp2_buf_len(&hbuf),
    };

    fr.headers.hd.len =
      (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
    nghttp2_buf_reset(&buf);
    rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

    assert_int(0, ==, rv);

    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    assert_int(0, ==, rv);

    if (conn->rx.frrd.state != NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH) {
      assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING,
                  ==, conn->rx.frrd.state);
      assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

      break;
    }
  }

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receiving too many RST_STREAM */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  read_settings_ack(conn, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  for (stream_id = 0x01;; stream_id += 2) {
    fr.headers = (nghttp2_frame_headers){
      .hd =
        {
          .type = NGHTTP2_FRAME_HEADERS,
          .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
          .stream_id = stream_id,
        },
      .field_block = hbuf.pos,
      .field_blocklen = nghttp2_buf_len(&hbuf),
    };

    fr.headers.hd.len =
      (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
    nghttp2_buf_reset(&buf);
    rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

    assert_int(0, ==, rv);

    fr.rst_stream = (nghttp2_frame_rst_stream){
      .hd =
        {
          .len = 4,
          .type = NGHTTP2_FRAME_RST_STREAM,
          .stream_id = stream_id,
        },
      .error_code = NGHTTP2_CANCEL,
    };

    rv = nghttp2_frame_encode_rst_stream(&buf, &fr.rst_stream);

    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    if (rv != 0) {
      assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);
      break;
    }

    assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
                ==, conn->rx.frrd.state);
  }

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receiving too many SETTINGS */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);
  read_settings_ack(conn, ts);

  for (;;) {
    fr.settings = (nghttp2_frame_settings){
      .hd =
        {
          .type = NGHTTP2_FRAME_SETTINGS,
        },
    };

    nghttp2_buf_reset(&buf);
    rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

    assert_int(0, ==, rv);

    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);
    if (rv != 0) {
      assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);
      break;
    }

    assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
                ==, conn->rx.frrd.state);

    write_settings_ack(conn, ++ts);
  }

  nghttp2_conn_del(conn);

  /* Receiving too many SETTINGS with dynamic table size change */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);
  read_settings_ack(conn, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
    .value = 1 << 20,
  };

  for (;;) {
    --iv[0].value;

    fr.settings = (nghttp2_frame_settings){
      .hd =
        {
          .type = NGHTTP2_FRAME_SETTINGS,
        },
      .iv = iv,
      .niv = 1,
    };

    fr.settings.hd.len =
      (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);
    nghttp2_buf_reset(&buf);
    rv = nghttp2_frame_encode_settings(&buf, &fr.settings);

    assert_int(0, ==, rv);

    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);
    if (rv != 0) {
      assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);
      break;
    }

    assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
                ==, conn->rx.frrd.state);

    write_settings_ack(conn, ++ts);
  }

  nghttp2_conn_del(conn);

  /* Receiving too many PING */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);
  read_settings_ack(conn, ts);

  for (;;) {
    fr.ping = (nghttp2_frame_ping){
      .hd =
        {
          .len = 8,
          .type = NGHTTP2_FRAME_PING,
        },
    };

    nghttp2_buf_reset(&buf);
    rv = nghttp2_frame_encode_ping(&buf, &fr.ping);

    assert_int(0, ==, rv);

    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);
    if (rv != 0) {
      assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);
      break;
    }

    assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
                ==, conn->rx.frrd.state);

    nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);

    assert_ptrdiff(0, <, nwrite);
  }

  nghttp2_conn_del(conn);

  /* Receiving too many GOAWAY */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);
  read_settings_ack(conn, ts);

  for (;;) {
    fr.goaway = (nghttp2_frame_goaway){
      .hd =
        {
          .len = 8,
          .type = NGHTTP2_FRAME_GOAWAY,
        },
    };

    nghttp2_buf_reset(&buf);
    rv = nghttp2_frame_encode_goaway(&buf, &fr.goaway);

    assert_int(0, ==, rv);

    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);
    if (rv != 0) {
      assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);
      break;
    }

    assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
                ==, conn->rx.frrd.state);
  }

  nghttp2_conn_del(conn);

  /* Receiving too many WINDOW_UPDATE frames to the closed stream */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  read_settings_ack(conn, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x03,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  fr.window_update = (nghttp2_frame_window_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_window_update(&buf, &fr.window_update);

  assert_int(0, ==, rv);

  for (;;) {
    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    if (rv != 0) {
      assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);
      break;
    }

    assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
                ==, conn->rx.frrd.state);
  }

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receiving too many PRIORITY_UPDATE frames to the idle stream */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  read_settings_ack(conn, ts);

  fr.priority_update = (nghttp2_frame_priority_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .prioritized_stream_id = 0x01,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_priority_update(&buf, &fr.priority_update);

  assert_int(0, ==, rv);

  for (;;) {
    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    if (rv != 0) {
      assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);
      break;
    }

    assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
                ==, conn->rx.frrd.state);
  }

  nghttp2_conn_del(conn);

  /* Receiving too many PRIORITY_UPDATE frames to the active stream */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  read_settings_ack(conn, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  fr.priority_update = (nghttp2_frame_priority_update){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
      },
    .prioritized_stream_id = 0x01,
  };

  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_priority_update(&buf, &fr.priority_update);

  assert_int(0, ==, rv);

  for (;;) {
    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    if (rv != 0) {
      assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);
      break;
    }

    assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
                ==, conn->rx.frrd.state);
  }

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receiving too many unknown frames */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  read_settings_ack(conn, ts);

  fr.meta = (nghttp2_frame_meta){
    .hd =
      {
        .type = 0xEE,
      },
  };

  nghttp2_buf_reset(&buf);
  buf.last = nghttp2_frame_encode_hd(buf.last, &fr.meta.hd);

  for (;;) {
    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    if (rv != 0) {
      assert_int(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, rv);
      break;
    }

    assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
                ==, conn->rx.frrd.state);
  }

  nghttp2_conn_del(conn);

  /* Sending too many RST_STREAM */
  server_default_settings(&settings);
  settings.log_write = NULL;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  read_settings_ack(conn, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  for (stream_id = 0x01;; stream_id += 2) {
    fr.headers = (nghttp2_frame_headers){
      .hd =
        {
          .type = NGHTTP2_FRAME_HEADERS,
          .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
          .stream_id = stream_id,
        },
      .field_block = hbuf.pos,
      .field_blocklen = nghttp2_buf_len(&hbuf),
    };

    fr.headers.hd.len =
      (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
    nghttp2_buf_reset(&buf);
    rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

    assert_int(0, ==, rv);

    rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

    assert_int(0, ==, rv);
    assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
                ==, conn->rx.frrd.state);

    nghttp2_conn_shutdown_stream(conn, 0x00, stream_id, NGHTTP2_REFUSED_STREAM);

    nwrite = nghttp2_conn_write(conn, outbuf, sizeof(outbuf), ++ts);
    if (nwrite < 0) {
      assert_ptrdiff(NGHTTP2_ERR_EXCESSIVE_LOAD, ==, nwrite);
      break;
    }
  }

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_get_streams_left(void) {
  static const nghttp2_settings_entry iv[] = {
    {
      .id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
      .value = 10,
    },
  };
  nghttp2_conn *conn;
  nghttp2_tstamp ts = 0;
  int64_t stream_id;
  size_t i;

  /* Before and after reading server preface */
  setup_default_client(&conn);
  write_preface(conn, ts);

  assert_size(100, ==, nghttp2_conn_get_streams_left(conn));

  read_server_preface(conn, iv, 1, ts);

  assert_size(10, ==, nghttp2_conn_get_streams_left(conn));

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(0x01, ==, stream_id);
  assert_size(9, ==, nghttp2_conn_get_streams_left(conn));

  nghttp2_conn_del(conn);

  /* Temporally exceed the limit */
  setup_default_client(&conn);
  write_preface(conn, ts);

  assert_size(100, ==, nghttp2_conn_get_streams_left(conn));

  for (i = 0; i < 100; ++i) {
    stream_id = nghttp2_conn_submit_request(
      conn, reqnva, nghttp2_arraylen(reqnva), NULL, NULL);

    assert_int64((int64_t)(i * 2 + 1), ==, stream_id);
    assert_size(100 - i - 1, ==, nghttp2_conn_get_streams_left(conn));
  }

  stream_id = nghttp2_conn_submit_request(conn, reqnva,
                                          nghttp2_arraylen(reqnva), NULL, NULL);

  assert_int64(NGHTTP2_ERR_STREAM_ID_BLOCKED, ==, stream_id);

  read_server_preface(conn, iv, 1, ts);

  assert_size(0, ==, nghttp2_conn_get_streams_left(conn));

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_is_server(void) {
  nghttp2_conn *conn;

  /* server */
  setup_default_server(&conn);

  assert_true(nghttp2_conn_is_server(conn));

  nghttp2_conn_del(conn);

  /* client */
  setup_default_client(&conn);

  assert_false(nghttp2_conn_is_server(conn));

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_get_timestamp(void) {
  nghttp2_conn *conn;
  nghttp2_settings settings;
  conn_options opts;

  client_default_settings(&settings);
  settings.initial_ts = 100 * NGHTTP2_SECONDS;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_client_with_options(&conn, opts);

  assert_uint64(100 * NGHTTP2_SECONDS, ==, nghttp2_conn_get_timestamp(conn));

  write_preface(conn, 200 * NGHTTP2_SECONDS);

  assert_uint64(200 * NGHTTP2_SECONDS, ==, nghttp2_conn_get_timestamp(conn));

  read_server_preface(conn, NULL, 0, 300 * NGHTTP2_SECONDS);

  assert_uint64(300 * NGHTTP2_SECONDS, ==, nghttp2_conn_get_timestamp(conn));

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_get_stream_priority(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  nghttp2_hpack_encoder enc;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_frame fr;
  nghttp2_pri pri;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* get stream priority */
  setup_default_server(&conn);
  write_preface(conn, ts);
  read_client_preface(conn, NULL, 0, ts);
  write_settings_ack(conn, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, pri_reqnva,
                                   nghttp2_arraylen(pri_reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);
  nghttp2_buf_reset(&buf);
  rv = nghttp2_frame_encode_headers(&buf, &fr.headers);

  assert_int(0, ==, rv);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  rv = nghttp2_conn_get_stream_priority(conn, &pri, 0x01);

  assert_int(0, ==, rv);
  assert_uint32(2, ==, pri.urgency);
  assert_true(pri.inc);

  /* stream not found */
  rv = nghttp2_conn_get_stream_priority(conn, &pri, 0x03);

  assert_int(NGHTTP2_ERR_STREAM_NOT_FOUND, ==, rv);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}
