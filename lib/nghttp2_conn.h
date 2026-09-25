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
#ifndef NGHTTP2_CONN_H
#define NGHTTP2_CONN_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <nghttp2v2/nghttp2.h>

#include "nghttp2_frame_reader.h"
#include "nghttp2_map.h"
#include "nghttp2_hpack.h"
#include "nghttp2_stream.h"
#include "nghttp2_log.h"
#include "nghttp2_ringbuf.h"
#include "nghttp2_ratelim.h"

/* NGHTTP2_HARD_MAX_FRAME_SIZE is the maximum HTTP/2 frame. */
#define NGHTTP2_HARD_MAX_FRAME_SIZE ((size_t)((1U << 24) - 1))
/* NGHTTP2_MAX_SETTINGS_ENTRIES is the maximum SETTINGS entries in one
   SETTINGS frame.*/
#define NGHTTP2_MAX_SETTINGS_ENTRIES 32
/* NGHTTP2_MAX_CONTINUATIONS is the maximum number of CONTINUATION
   frames that can follow HEADERS frame */
#define NGHTTP2_MAX_CONTINUATIONS 8

#define NGHTTP2_CONN_FLAG_SETTINGS_SEEN 0x01U
#define NGHTTP2_CONN_FLAG_SETTINGS_SENT 0x02U
#define NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK 0x04U
#define NGHTTP2_CONN_FLAG_HTTP2_PREFACE_SENT 0x08U
/* NGHTTP2_CONN_FLAG_SEND_GOAWAY indicates that there is pending
   GOAWAY frame transmission. */
#define NGHTTP2_CONN_FLAG_SEND_GOAWAY 0x10U
/* NGHTTP2_CONN_FLAG_SEND_PING indicates that there is pending PING
   frame transmission. */
#define NGHTTP2_CONN_FLAG_SEND_PING 0x20U
/* NGHTTP2_CONN_FLAG_EXPECT_PING_ACK indicates that the local endpoint
   expects PING ACK. */
#define NGHTTP2_CONN_FLAG_EXPECT_PING_ACK 0x40U
/* NGHTTP2_CONN_FLAG_CLOSE_ABRUPTLY indicates that the connection
   should be closed after sending GOAWAY. */
#define NGHTTP2_CONN_FLAG_CLOSE_ABRUPTLY 0x80U
/* NGHTTP2_CONN_FLAG_CLOSE_GRACEFULLY indicates that the connection
   should be closed after process all active streams. */
#define NGHTTP2_CONN_FLAG_CLOSE_GRACEFULLY 0x0100U
/* NGHTTP2_CONN_FLAG_GOAWAY_RECVED indicates that GOAWAY has been
   received. */
#define NGHTTP2_CONN_FLAG_GOAWAY_RECVED 0x0200U

/* NGHTTP2_MAX_PING_ACK is the maximum number of PING ACK to send. */
#define NGHTTP2_MAX_PING_ACK 8

nghttp2_static_ringbuf_def(ping_data, NGHTTP2_MAX_PING_ACK,
                           sizeof(nghttp2_ping_data))

struct nghttp2_conn {
  const nghttp2_mem *mem;
  nghttp2_callbacks callbacks;
  nghttp2_settings settings;
  void *user_data;

  struct {
    nghttp2_proto_settings settings;
  } remote;

  struct {
    nghttp2_hpack_decoder hdec;
    nghttp2_int_reader ird;
    nghttp2_frame_reader frrd;

    struct {
      /* last_stream_id is the last_stream_id received along with
         GOAWAY. */
      int64_t last_stream_id;
    } goaway;

    struct {
      /* data contains received PING data.  It has the statically
         allocated storage area.  Receiving PING when data is full is
         treated as a connection error.  */
      nghttp2_static_ringbuf_ping_data data;
    } ping;

    /* unsent_max_offset is the maximum offset that remote endpoint
       can send without extending MAX_DATA.  This limit is not yet
       notified to the remote endpoint. */
    uint64_t unsent_max_offset;
    /* offset is the cumulative sum of stream data received for this
       connection. */
    uint64_t offset;
    /* max_offset is the maximum offset that remote endpoint can
       send. */
    uint64_t max_offset;
    /* window is the connection-level flow control window size. */
    uint32_t window;
    /* stream_window is the stream-level flow control window size. */
    uint32_t stream_window;
    /* max_concurrent_streams is the number of streams that the remote
       endpoint can open concurrently. */
    uint32_t max_concurrent_streams;
    /* last_stream_id is the latest stream ID received so far. */
    int64_t last_stream_id;
    /* last_processed_stream_id is the largest stream ID that is
       processed in some way.  This will be sent along with GOAWAY. */
    int64_t last_processed_stream_id;
  } rx;

  struct {
    nghttp2_hpack_encoder henc;

    struct {
      int64_t last_stream_id;
      uint32_t error_code;
      /* num_refused_streams is the number of streams refused during
         graceful shutdown period. */
      size_t num_refused_streams;
    } goaway;

    struct {
      /* data contains the PING data to send or sent. */
      nghttp2_ping_data data;
    } ping;

    struct {
      /* ack_expiry is the time instant when SETTINGS ACK timer
         fires */
      nghttp2_tstamp ack_expiry;
      /* ack_left is the number of SETTINGS ACK to send */
      size_t ack_left;
    } settings;

    /* offset is the offset the local endpoint has sent to the remote
       endpoint. */
    uint64_t offset;
    /* max_offset is the maximum offset that local endpoint can
       send. */
    uint64_t max_offset;
    /* next_stream_id is the stream ID which the local endpoint opens
       next. */
    int64_t next_stream_id;
  } tx;

  struct {
    nghttp2_pq pq[NGHTTP2_URGENCY_LEVELS];
    /* stream points to the stream that has a frame not fully sent.
       HEADERS and DATA frames are those frames that can span across
       multiple write calls. */
    nghttp2_stream *stream_inprogress;
  } sched;

  nghttp2_map streams;
  nghttp2_ratelim grlim;
  nghttp2_stream *strmq_head;
  nghttp2_stream **strmq_tail;
  nghttp2_log log;
  uint32_t flags;
  int server;
};

int nghttp2_conn_handle_error(nghttp2_conn *conn, int liberr);

nghttp2_stream *nghttp2_conn_find_stream(const nghttp2_conn *conn,
                                         int64_t stream_id);

int nghttp2_conn_create_stream(nghttp2_conn *conn, nghttp2_stream **pstream,
                               int64_t stream_id, void *stream_user_data);

int nghttp2_conn_close_stream_if_shut_rdwr(nghttp2_conn *conn,
                                           nghttp2_stream *stream);

int nghttp2_conn_should_close_stream(const nghttp2_conn *conn,
                                     const nghttp2_stream *stream);

int nghttp2_conn_close_stream(nghttp2_conn *conn, nghttp2_stream *stream);

int nghttp2_conn_decode_field_block(nghttp2_conn *conn, int64_t stream_id,
                                    const uint8_t *src, size_t srclen, int fin);

nghttp2_stream *nghttp2_conn_get_next_tx_stream(nghttp2_conn *conn);

int nghttp2_conn_write_stream(nghttp2_conn *conn, nghttp2_buf *dest,
                              nghttp2_stream *stream, nghttp2_tstamp ts);

int nghttp2_conn_write_stream_flow_controlled(nghttp2_conn *conn,
                                              nghttp2_buf *dest,
                                              nghttp2_stream *stream);

int nghttp2_conn_write_settings(nghttp2_conn *conn, nghttp2_buf *dest,
                                nghttp2_tstamp ts);

int nghttp2_conn_write_settings_ack(nghttp2_conn *conn, nghttp2_buf *dest);

int nghttp2_conn_write_connection_wide_frames(nghttp2_conn *conn,
                                              nghttp2_buf *dest,
                                              nghttp2_tstamp ts);

int nghttp2_conn_schedule_stream(nghttp2_conn *conn, nghttp2_stream *stream);

void nghttp2_conn_unschedule_stream(nghttp2_conn *conn, nghttp2_stream *stream);

void nghttp2_conn_strmq_push(nghttp2_conn *conn, nghttp2_stream *stream);

void nghttp2_conn_strmq_remove(nghttp2_conn *conn, nghttp2_stream *stream);

size_t nghttp2_conn_get_num_active_streams(const nghttp2_conn *conn);

#endif /* !defined(NGHTTP2_CONN_H) */
