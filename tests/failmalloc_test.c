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

static char* strcopy(const char* s)
{
  size_t len = strlen(s);
  char *dest = malloc(len+1);
  if(dest == NULL) {
    return NULL;
  }
  memcpy(dest, s, len);
  dest[len] = '\0';
  return dest;
}

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

static ssize_t get_credential_ncerts(nghttp2_session *session,
                                     const nghttp2_origin *origin,
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

static ssize_t get_credential_cert(nghttp2_session *session,
                                   const nghttp2_origin *origin,
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

static ssize_t get_credential_proof(nghttp2_session *session,
                                    const nghttp2_origin *origin,
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
  const char *nv[] = { ":host", "example.org",
                       ":scheme", "https",
                       NULL };
  nghttp2_data_provider data_prd;
  nghttp2_settings_entry iv[2];
  my_user_data ud;
  int rv;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.get_credential_ncerts = get_credential_ncerts;
  callbacks.get_credential_cert = get_credential_cert;
  callbacks.get_credential_proof = get_credential_proof;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 64*1024;

  iv[0].settings_id = NGHTTP2_SETTINGS_UPLOAD_BANDWIDTH;
  iv[0].flags = NGHTTP2_ID_FLAG_SETTINGS_PERSIST_VALUE;
  iv[0].value = 256;
  iv[1].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[1].flags = NGHTTP2_ID_FLAG_SETTINGS_NONE;
  iv[1].value = 100;

  rv = nghttp2_session_client_new(&session, NGHTTP2_PROTO_SPDY3,
                                  &callbacks, &ud);
  if(rv != 0) {
    goto client_new_fail;
  }
  rv = nghttp2_submit_request(session, 3, nv, &data_prd, NULL);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_submit_syn_stream(session, NGHTTP2_CTRL_FLAG_NONE,
                                 0, 3, nv, NULL);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_session_send(session);
  if(rv != 0) {
    goto fail;
  }
  /* The SYN_STREAM submitted by the previous
     nghttp2_submit_syn_stream will have stream ID 3. Send HEADERS to
     that stream. */
  rv = nghttp2_submit_headers(session, NGHTTP2_CTRL_FLAG_NONE, 3, nv);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_submit_data(session, 3, NGHTTP2_DATA_FLAG_FIN, &data_prd);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_session_send(session);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_submit_rst_stream(session, 3, NGHTTP2_CANCEL);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_session_send(session);
  if(rv != 0) {
    goto fail;
  }
  /* Sending against half-closed stream */
  rv = nghttp2_submit_headers(session, NGHTTP2_CTRL_FLAG_NONE, 3, nv);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_submit_data(session, 3, NGHTTP2_DATA_FLAG_FIN, &data_prd);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_submit_ping(session);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_SETTINGS_NONE, iv, 2);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_session_send(session);
  if(rv != 0) {
    goto fail;
  }
  rv = nghttp2_submit_goaway(session, NGHTTP2_GOAWAY_OK);
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
  nghttp2_zlib deflater;
  nghttp2_frame frame;
  uint8_t *buf = NULL, *nvbuf = NULL;
  size_t buflen = 0, nvbuflen = 0;
  ssize_t framelen;
  const char *nv[] = { ":host", "example.org",
                       ":scheme", "https",
                       NULL };
  nghttp2_settings_entry iv[2];
  nghttp2_mem_chunk proof;
  nghttp2_mem_chunk *certs;
  size_t ncerts;
  my_user_data ud;
  data_feed df;
  int rv;

  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.recv_callback = data_feed_recv_callback;
  ud.df = &df;

  nghttp2_failmalloc_pause();
  nghttp2_zlib_deflate_hd_init(&deflater, 1, NGHTTP2_PROTO_SPDY3);
  nghttp2_session_server_new(&session, NGHTTP2_PROTO_SPDY3, &callbacks, &ud);
  nghttp2_failmalloc_unpause();

  /* SYN_STREAM */
  nghttp2_failmalloc_pause();
  nghttp2_frame_syn_stream_init(&frame.syn_stream, NGHTTP2_PROTO_SPDY3,
                                NGHTTP2_CTRL_FLAG_FIN, 1, 0, 2,
                                nghttp2_frame_nv_copy(nv));
  framelen = nghttp2_frame_pack_syn_stream(&buf, &buflen,
                                           &nvbuf, &nvbuflen,
                                           &frame.syn_stream, &deflater);
  nghttp2_frame_syn_stream_free(&frame.syn_stream);
  data_feed_init(&df, buf, framelen);
  nghttp2_failmalloc_unpause();

  rv = nghttp2_session_recv(session);
  if(rv != 0) {
    goto fail;
  }

  /* PING */
  nghttp2_failmalloc_pause();
  nghttp2_frame_ping_init(&frame.ping, NGHTTP2_PROTO_SPDY3, 1);
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
  nghttp2_frame_rst_stream_init(&frame.rst_stream, NGHTTP2_PROTO_SPDY3, 1,
                                NGHTTP2_PROTOCOL_ERROR);
  framelen = nghttp2_frame_pack_rst_stream(&buf, &buflen, &frame.rst_stream);
  nghttp2_frame_rst_stream_free(&frame.rst_stream);
  nghttp2_failmalloc_unpause();

  rv = nghttp2_session_recv(session);
  if(rv != 0) {
    goto fail;
  }

  /* SETTINGS */
  nghttp2_failmalloc_pause();
  iv[0].settings_id = NGHTTP2_SETTINGS_UPLOAD_BANDWIDTH;
  iv[0].flags = NGHTTP2_ID_FLAG_SETTINGS_PERSIST_VALUE;
  iv[0].value = 256;
  iv[1].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[1].flags = NGHTTP2_ID_FLAG_SETTINGS_NONE;
  iv[1].value = 100;
  nghttp2_frame_settings_init(&frame.settings, NGHTTP2_PROTO_SPDY3,
                              NGHTTP2_FLAG_SETTINGS_CLEAR_SETTINGS,
                              nghttp2_frame_iv_copy(iv, 2), 2);
  framelen = nghttp2_frame_pack_settings(&buf, &buflen, &frame.settings);
  nghttp2_frame_settings_free(&frame.settings);
  nghttp2_failmalloc_unpause();

  rv = nghttp2_session_recv(session);
  if(rv != 0) {
    goto fail;
  }

  /* CREDENTIAL */
  nghttp2_failmalloc_pause();
  proof.data = (uint8_t*)strcopy("PROOF");
  proof.length = strlen("PROOF");
  ncerts = 2;
  certs = malloc(sizeof(nghttp2_mem_chunk)*ncerts);
  certs[0].data = (uint8_t*)strcopy("CERT0");
  certs[0].length = strlen("CERT0");
  certs[1].data = (uint8_t*)strcopy("CERT1");
  certs[1].length = strlen("CERT1");
  nghttp2_frame_credential_init(&frame.credential, NGHTTP2_PROTO_SPDY3,
                                1, &proof, certs, ncerts);
  framelen = nghttp2_frame_pack_credential(&buf, &buflen, &frame.credential);
  nghttp2_frame_credential_free(&frame.credential);
  nghttp2_failmalloc_unpause();

  rv = nghttp2_session_recv(session);
  if(rv != 0) {
    goto fail;
  }

 fail:
  free(buf);
  free(nvbuf);
  nghttp2_session_del(session);
  nghttp2_zlib_deflate_free(&deflater);
}

void test_nghttp2_session_recv(void)
{
  TEST_FAILMALLOC_RUN(run_nghttp2_session_recv);
}

static void run_nghttp2_frame_pack_syn_stream(void)
{
  nghttp2_zlib deflater, inflater;
  nghttp2_frame frame, oframe;
  uint8_t *buf = NULL, *nvbuf = NULL;
  size_t buflen = 0, nvbuflen = 0;
  nghttp2_buffer inflatebuf;
  ssize_t framelen;
  const char *nv[] = { ":host", "example.org",
                       ":scheme", "https",
                       NULL };
  char **nv_copy;
  int rv;

  nghttp2_buffer_init(&inflatebuf, 4096);
  rv = nghttp2_zlib_deflate_hd_init(&deflater, 1, NGHTTP2_PROTO_SPDY3);
  if(rv != 0) {
    goto deflate_init_fail;
  }
  rv = nghttp2_zlib_inflate_hd_init(&inflater, NGHTTP2_PROTO_SPDY3);
  if(rv != 0) {
    goto inflate_init_fail;
  }
  nv_copy = nghttp2_frame_nv_copy(nv);
  if(nv_copy == NULL) {
    goto nv_copy_fail;
  }
  nghttp2_frame_syn_stream_init(&frame.syn_stream, NGHTTP2_PROTO_SPDY3,
                                NGHTTP2_CTRL_FLAG_FIN, 1, 0, 2, nv_copy);
  framelen = nghttp2_frame_pack_syn_stream(&buf, &buflen,
                                           &nvbuf, &nvbuflen,
                                           &frame.syn_stream, &deflater);
  if(framelen < 0) {
    goto fail;
  }
  rv = unpack_frame_with_nv_block(NGHTTP2_SYN_STREAM, NGHTTP2_PROTO_SPDY3,
                                  &oframe, &inflater, buf, framelen);
  if(rv != 0) {
    goto fail;
  }
  nghttp2_frame_syn_stream_free(&oframe.syn_stream);
 fail:
  free(buf);
  free(nvbuf);
  nghttp2_frame_syn_stream_free(&frame.syn_stream);
 nv_copy_fail:
  nghttp2_zlib_inflate_free(&inflater);
 inflate_init_fail:
  nghttp2_zlib_deflate_free(&deflater);
 deflate_init_fail:
  nghttp2_buffer_free(&inflatebuf);
}

static void run_nghttp2_frame_pack_ping(void)
{
  nghttp2_frame frame;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  nghttp2_frame_ping_init(&frame.ping, NGHTTP2_PROTO_SPDY3, 1);
  nghttp2_frame_pack_ping(&buf, &buflen, &frame.ping);
  free(buf);
  nghttp2_frame_ping_free(&frame.ping);
}

static void run_nghttp2_frame_pack_goaway(void)
{
  nghttp2_frame frame;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  nghttp2_frame_goaway_init(&frame.goaway, NGHTTP2_PROTO_SPDY3, 1000000007,
                            NGHTTP2_GOAWAY_PROTOCOL_ERROR);
  nghttp2_frame_pack_goaway(&buf, &buflen, &frame.goaway);
  free(buf);
  nghttp2_frame_goaway_free(&frame.goaway);
}

static void run_nghttp2_frame_pack_rst_stream(void)
{
  nghttp2_frame frame;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  nghttp2_frame_rst_stream_init(&frame.rst_stream, NGHTTP2_PROTO_SPDY3, 1,
                                NGHTTP2_PROTOCOL_ERROR);
  nghttp2_frame_pack_rst_stream(&buf, &buflen, &frame.rst_stream);
  free(buf);
  nghttp2_frame_rst_stream_free(&frame.rst_stream);
}

static void run_nghttp2_frame_pack_window_update(void)
{
  nghttp2_frame frame;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  nghttp2_frame_window_update_init(&frame.window_update, NGHTTP2_PROTO_SPDY3,
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

  iv[0].settings_id = NGHTTP2_SETTINGS_UPLOAD_BANDWIDTH;
  iv[0].flags = NGHTTP2_ID_FLAG_SETTINGS_PERSIST_VALUE;
  iv[0].value = 256;
  iv[1].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[1].flags = NGHTTP2_ID_FLAG_SETTINGS_NONE;
  iv[1].value = 100;

  iv_copy = nghttp2_frame_iv_copy(iv, 2);
  if(iv_copy == NULL) {
    goto iv_copy_fail;
  }
  nghttp2_frame_settings_init(&frame.settings, NGHTTP2_PROTO_SPDY3,
                              NGHTTP2_FLAG_SETTINGS_CLEAR_SETTINGS,
                              iv_copy, 2);
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

static void run_nghttp2_frame_pack_credential(void)
{
  nghttp2_frame frame, oframe;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t framelen;
  nghttp2_mem_chunk proof;
  nghttp2_mem_chunk *certs;
  size_t ncerts;
  int rv;

  nghttp2_failmalloc_pause();

  proof.data = (uint8_t*)strcopy("PROOF");
  proof.length = strlen("PROOF");
  ncerts = 2;
  certs = malloc(sizeof(nghttp2_mem_chunk)*ncerts);
  certs[0].data = (uint8_t*)strcopy("CERT0");
  certs[0].length = strlen("CERT0");
  certs[1].data = (uint8_t*)strcopy("CERT1");
  certs[1].length = strlen("CERT1");

  nghttp2_failmalloc_unpause();

  nghttp2_frame_credential_init(&frame.credential, NGHTTP2_PROTO_SPDY3,
                                1, &proof, certs, ncerts);
  framelen = nghttp2_frame_pack_credential(&buf, &buflen, &frame.credential);
  if(framelen < 0) {
    goto fail;
  }
  rv = nghttp2_frame_unpack_credential(&oframe.credential,
                                       &buf[0], NGHTTP2_FRAME_HEAD_LENGTH,
                                       &buf[NGHTTP2_FRAME_HEAD_LENGTH],
                                       framelen-NGHTTP2_FRAME_HEAD_LENGTH);
  if(rv != 0) {
    goto fail;
  }
  nghttp2_frame_credential_free(&oframe.credential);
 fail:
  free(buf);
  nghttp2_frame_credential_free(&frame.credential);
}

static void run_nghttp2_frame(void)
{
  run_nghttp2_frame_pack_syn_stream();
  run_nghttp2_frame_pack_ping();
  run_nghttp2_frame_pack_goaway();
  run_nghttp2_frame_pack_rst_stream();
  run_nghttp2_frame_pack_window_update();
  run_nghttp2_frame_pack_settings();
  run_nghttp2_frame_pack_credential();
}

void test_nghttp2_frame(void)
{
  TEST_FAILMALLOC_RUN(run_nghttp2_frame);
}
