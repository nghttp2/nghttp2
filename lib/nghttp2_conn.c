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
#include "nghttp2_conn.h"

#include <string.h>
#include <assert.h>

#include "nghttp2_macro.h"
#include "nghttp2_mem.h"
#include "nghttp2_stream.h"
#include "nghttp2_unreachable.h"
#include "nghttp2_http.h"
#include "nghttp2_str.h"

static int conn_idle_stream(const nghttp2_conn *conn, int64_t stream_id) {
  if (conn->server) {
    return stream_id > conn->rx.last_stream_id;
  }

  return stream_id >= conn->tx.next_stream_id;
}

static int client_stream_id(int64_t stream_id) { return stream_id & 0x1; }

static int conn_call_begin_headers(nghttp2_conn *conn,
                                   const nghttp2_stream *stream) {
  int rv;

  if (!conn->callbacks.begin_headers) {
    return 0;
  }

  rv = conn->callbacks.begin_headers(conn, stream->stream_id, conn->user_data,
                                     stream->user_data);
  if (rv != 0) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_call_end_headers(nghttp2_conn *conn,
                                 const nghttp2_stream *stream, int fin) {
  int rv;

  if (!conn->callbacks.end_headers) {
    return 0;
  }

  rv = conn->callbacks.end_headers(conn, stream->stream_id, fin,
                                   conn->user_data, stream->user_data);
  if (rv != 0) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_call_begin_trailers(nghttp2_conn *conn,
                                    const nghttp2_stream *stream) {
  int rv;

  if (!conn->callbacks.begin_trailers) {
    return 0;
  }

  rv = conn->callbacks.begin_trailers(conn, stream->stream_id, conn->user_data,
                                      stream->user_data);
  if (rv != 0) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_call_end_trailers(nghttp2_conn *conn,
                                  const nghttp2_stream *stream, int fin) {
  int rv;

  if (!conn->callbacks.end_trailers) {
    return 0;
  }

  rv = conn->callbacks.end_trailers(conn, stream->stream_id, fin,
                                    conn->user_data, stream->user_data);
  if (rv != 0) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_call_recv_data(nghttp2_conn *conn, const nghttp2_stream *stream,
                               const uint8_t *data, size_t datalen, int fin) {
  int rv;

  if (!conn->callbacks.recv_data) {
    return 0;
  }

  rv = conn->callbacks.recv_data(conn, stream->stream_id, data, datalen, fin,
                                 conn->user_data, stream->user_data);
  if (rv != 0) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_call_end_stream(nghttp2_conn *conn,
                                const nghttp2_stream *stream) {
  int rv;

  if (!conn->callbacks.end_stream) {
    return 0;
  }

  rv = conn->callbacks.end_stream(conn, stream->stream_id, conn->user_data,
                                  stream->user_data);
  if (rv != 0) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_call_stream_open(nghttp2_conn *conn,
                                 const nghttp2_stream *stream) {
  int rv;

  if (!conn->callbacks.stream_open) {
    return 0;
  }

  rv = conn->callbacks.stream_open(conn, stream->stream_id, conn->user_data);
  if (rv != 0) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_call_stream_close(nghttp2_conn *conn,
                                  const nghttp2_stream *stream) {
  uint32_t flags = NGHTTP2_STREAM_CLOSE_FLAG_NONE;
  int rv;

  if (!conn->callbacks.stream_close) {
    return 0;
  }

  if (stream->flags & NGHTTP2_STREAM_FLAG_ERROR_CODE_SET) {
    flags |= NGHTTP2_STREAM_CLOSE_FLAG_ERROR_CODE_SET;
  }

  rv = conn->callbacks.stream_close(conn, flags, stream->stream_id,
                                    stream->error_code, conn->user_data,
                                    stream->user_data);
  if (rv != 0) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

#define NGHTTP2_MAX_CYCLE_GAP (1ULL << 24)

static int cycle_less(const nghttp2_pq_entry *lhsx,
                      const nghttp2_pq_entry *rhsx) {
  const nghttp2_stream *lhs = nghttp2_struct_of(lhsx, nghttp2_stream, sched);
  const nghttp2_stream *rhs = nghttp2_struct_of(rhsx, nghttp2_stream, sched);

  if (lhs->sched.cycle == rhs->sched.cycle) {
    return lhs->stream_id < rhs->stream_id;
  }

  return rhs->sched.cycle - lhs->sched.cycle <= NGHTTP2_MAX_CYCLE_GAP;
}

static void conn_update_timestamp(nghttp2_conn *conn, nghttp2_tstamp ts) {
  assert(conn->log.last_ts <= ts);

  conn->log.last_ts = ts;
}

static void conn_adjust_connection_window(nghttp2_conn *conn,
                                          const nghttp2_settings *settings) {
  uint64_t delta;

  delta = (uint64_t)settings->initial_max_data -
          (uint64_t)NGHTTP2_INITIAL_WINDOW_SIZE;

  conn->rx.unsent_max_offset = (uint64_t)NGHTTP2_INITIAL_WINDOW_SIZE + delta;
  conn->rx.max_offset = NGHTTP2_INITIAL_WINDOW_SIZE;
  conn->rx.window = settings->initial_max_data;
}

static int conn_update_glitch_ratelim(nghttp2_conn *conn, uint64_t tokens,
                                      nghttp2_tstamp ts) {
  int rv;

  rv = nghttp2_ratelim_drain(&conn->grlim, tokens, ts);
  if (rv != 0) {
    return NGHTTP2_ERR_EXCESSIVE_LOAD;
  }

  return 0;
}

static int conn_new(nghttp2_conn **pconn, const nghttp2_callbacks *callbacks,
                    const nghttp2_settings *settings, const nghttp2_mem *mem,
                    void *user_data, int server) {
  void *ptr;
  nghttp2_conn *conn;
  char *logbuf;
  uint64_t seed;
  size_t i;

  assert(callbacks);
  assert(callbacks->rand);
  assert(settings);

  if (!mem) {
    mem = nghttp2_mem_default();
  }

  ptr = nghttp2_mem_calloc(mem, 1, sizeof(*conn) + NGHTTP2_LOG_BUFLEN);
  if (!ptr) {
    return NGHTTP2_ERR_NOMEM;
  }

  conn = ptr;
  logbuf = (char *)ptr + sizeof(*conn);

  conn->mem = mem;
  conn->server = server;
  conn->callbacks = *callbacks;
  conn->settings = *settings;

  if (server) {
    conn->settings.max_concurrent_streams_local = 0;
  } else {
    conn->settings.max_concurrent_streams_remote = 0;
  }

  settings = &conn->settings;
  conn->user_data = user_data;

  conn->remote.settings = (nghttp2_proto_settings){
    .hpack_max_dtable_capacity = NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY,
    .max_concurrent_streams = settings->max_concurrent_streams_local,
    .initial_max_stream_data = NGHTTP2_INITIAL_WINDOW_SIZE,
  };

  if (server) {
    /* The unlimited stream concurrency is insane.  Because we require
       nghttp2_stream to send RST_STREAM, we limit this to much lower
       value.  Just mindlessly sending too many stream knowing that the
       initial limit is unlimited is a kind of DoS attack.*/
    if (settings->max_concurrent_streams_remote > INT32_MAX / 2) {
      conn->rx.max_concurrent_streams = INT32_MAX;
    } else {
      conn->rx.max_concurrent_streams =
        nghttp2_max(256, settings->max_concurrent_streams_remote * 2);
    }
  }

  conn_adjust_connection_window(conn, settings);

  conn->rx.stream_window = NGHTTP2_INITIAL_WINDOW_SIZE;

  if (server) {
    nghttp2_frame_reader_server_init(&conn->rx.frrd);
  } else {
    nghttp2_frame_reader_reset(&conn->rx.frrd);
  }

  conn->rx.goaway.last_stream_id = INT32_MAX;

  conn->tx.max_offset = NGHTTP2_INITIAL_WINDOW_SIZE;
  conn->tx.goaway.last_stream_id = INT32_MAX;
  conn->tx.settings.ack_expiry = UINT64_MAX;

  callbacks->rand((uint8_t *)&seed, sizeof(seed));
  nghttp2_log_init(&conn->log, settings->conn_id, settings->log_write, logbuf,
                   settings->initial_ts, user_data);
  nghttp2_map_init(&conn->streams, seed, mem);
  nghttp2_hpack_encoder_init(&conn->tx.henc,
                             settings->hpack_encoder_max_dtable_capacity, mem);
  nghttp2_hpack_decoder_init(&conn->rx.hdec, mem);
  nghttp2_ratelim_init(&conn->grlim, settings->glitch_ratelim_burst,
                       settings->glitch_ratelim_rate, settings->initial_ts);

  for (i = 0; i < nghttp2_arraylen(conn->sched.pq); ++i) {
    nghttp2_pq_init(&conn->sched.pq[i], cycle_less, mem);
  }

  nghttp2_static_ringbuf_ping_data_init(&conn->rx.ping.data);

  conn->strmq_head = NULL;
  conn->strmq_tail = &conn->strmq_head;

  *pconn = conn;

  return 0;
}

int nghttp2_conn_server_new(nghttp2_conn **pconn,
                            const nghttp2_callbacks *callbacks,
                            const nghttp2_settings *settings,
                            const nghttp2_mem *mem, void *user_data) {
  return conn_new(pconn, callbacks, settings, mem, user_data, /* server = */ 1);
}

int nghttp2_conn_client_new(nghttp2_conn **pconn,
                            const nghttp2_callbacks *callbacks,
                            const nghttp2_settings *settings,
                            const nghttp2_mem *mem, void *user_data) {
  int rv;

  rv = conn_new(pconn, callbacks, settings, mem, user_data, /* server = */ 0);
  if (rv != 0) {
    return rv;
  }

  (*pconn)->tx.next_stream_id = 1;

  return 0;
}

static int stream_delete(void *data, void *ptr) {
  nghttp2_stream *stream = data;
  const nghttp2_mem *mem = ptr;

  nghttp2_stream_free(stream);
  nghttp2_mem_free(mem, stream);

  return 0;
}

void nghttp2_conn_del(nghttp2_conn *conn) {
  const nghttp2_mem *mem;
  size_t i;

  if (!conn) {
    return;
  }

  mem = conn->mem;

  nghttp2_hpack_decoder_free(&conn->rx.hdec);
  nghttp2_hpack_encoder_free(&conn->tx.henc);

  for (i = 0; i < nghttp2_arraylen(conn->sched.pq); ++i) {
    nghttp2_pq_free(&conn->sched.pq[i]);
  }

  nghttp2_map_each(&conn->streams, stream_delete, (void *)mem);
  nghttp2_map_free(&conn->streams);
  nghttp2_mem_free(mem, conn);
}

int nghttp2_conn_handle_error(nghttp2_conn *conn, int liberr) {
  if (nghttp2_err_is_fatal(liberr)) {
    return liberr;
  }

  nghttp2_conn_terminate(conn, nghttp2_err_infer_http2_error_code(liberr));

  return 0;
}

/*
 * conn_should_send_stream_window_update_data returns nonzero if
 * WINDOW_UPDATE frame should be send for |stream|.
 */
static int conn_should_send_stream_window_update(const nghttp2_conn *conn,
                                                 const nghttp2_stream *stream) {
  return stream->rx.unsent_max_offset - stream->rx.max_offset <=
           NGHTTP2_MAX_WINDOW_SIZE &&
         conn->rx.stream_window <
           4 * (stream->rx.unsent_max_offset - stream->rx.max_offset);
}

/*
 * conn_should_send_connection_window_update_data returns nonzero if
 * WINDOW_UPDATE frame should be send for |conn|.
 */
static int conn_should_send_connection_window_update(const nghttp2_conn *conn) {
  return conn->rx.unsent_max_offset > conn->rx.max_offset &&
         conn->rx.window <
           4 * (conn->rx.unsent_max_offset - conn->rx.max_offset);
}

static nghttp2_ssize frame_reader_read_preface(nghttp2_frame_reader *frrd,
                                               const uint8_t *src,
                                               size_t srclen) {
  size_t nread = nghttp2_min(srclen, frrd->left);

  if (memcmp(&NGHTTP2_CLIENT_HTTP2_PREFACE
               [nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE) - frrd->left],
             src, nread) != 0) {
    return NGHTTP2_ERR_PROTO;
  }

  frrd->left -= nread;

  return (nghttp2_ssize)nread;
}

nghttp2_stream *nghttp2_conn_find_stream(const nghttp2_conn *conn,
                                         int64_t stream_id) {
  return nghttp2_map_find(&conn->streams, (uint64_t)stream_id);
}

int nghttp2_conn_create_stream(nghttp2_conn *conn, nghttp2_stream **pstream,
                               int64_t stream_id, void *stream_user_data) {
  nghttp2_stream *stream;
  int rv;

  stream = nghttp2_mem_calloc(conn->mem, 1, sizeof(*stream));
  if (!stream) {
    return NGHTTP2_ERR_NOMEM;
  }

  nghttp2_stream_init(
    stream, stream_id,
    &(nghttp2_stream_callbacks){
      .write_stream_data_offset = conn->callbacks.write_stream_data_offset,
    },
    NGHTTP2_STREAM_FLAG_NONE, conn->rx.stream_window,
    conn->remote.settings.initial_max_stream_data, stream_user_data, conn->mem);

  if (conn->server) {
    stream->rx.hstate = NGHTTP2_HTTP_STATE_REQ_INITIAL;
  } else {
    stream->rx.hstate = NGHTTP2_HTTP_STATE_RESP_INITIAL;
    stream->sched.pri.inc = 1;
  }

  rv = nghttp2_map_insert(&conn->streams,
                          (nghttp2_map_key_type)stream->stream_id, stream);
  if (rv != 0) {
    nghttp2_stream_free(stream);
    nghttp2_mem_free(conn->mem, stream);

    return rv;
  }

  *pstream = stream;

  return 0;
}

int nghttp2_conn_should_close_stream(const nghttp2_conn *conn,
                                     const nghttp2_stream *stream) {
  (void)conn;

  return
    /* Before RST_STREAM is involved, both sides are closed and must
       send all frames */
    ((!(stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM) &&
      (stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD) &&
      (stream->flags & NGHTTP2_STREAM_FLAG_SHUT_WR) &&
      nghttp2_http_writer_empty(&stream->tx.hw)) ||
     /* After RST_STREAM is sent or received, close stream on
        frame boundary. */
     ((stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM) &&
      !(stream->flags & NGHTTP2_STREAM_FLAG_SEND_RST_STREAM) &&
      !nghttp2_http_writer_inprogress(&stream->tx.hw)));
}

int nghttp2_conn_close_stream_if_shut_rdwr(nghttp2_conn *conn,
                                           nghttp2_stream *stream) {
  if (!nghttp2_conn_should_close_stream(conn, stream)) {
    return 0;
  }

  return nghttp2_conn_close_stream(conn, stream);
}

int nghttp2_conn_close_stream(nghttp2_conn *conn, nghttp2_stream *stream) {
  int rv;

  if (!(stream->flags & NGHTTP2_STREAM_FLAG_REFUSED)) {
    rv = conn_call_stream_close(conn, stream);
    if (rv != 0) {
      return rv;
    }
  }

  assert(conn->sched.stream_inprogress != stream);

  nghttp2_conn_strmq_remove(conn, stream);
  nghttp2_conn_unschedule_stream(conn, stream);

  rv =
    nghttp2_map_remove(&conn->streams, (nghttp2_map_key_type)stream->stream_id);

  assert(0 == rv);

  nghttp2_stream_free(stream);
  nghttp2_mem_free(conn->mem, stream);

  return 0;
}

static int conn_max_data_violated(nghttp2_conn *conn, size_t datalen) {
  return conn->rx.max_offset - conn->rx.offset < datalen;
}

static int conn_on_end_data(nghttp2_conn *conn, nghttp2_stream *stream,
                            const nghttp2_frame_data *fr) {
  int rv;

  nghttp2_log_rx_data(&conn->log, fr);

  rv =
    nghttp2_stream_transit_rx_http_state(stream, NGHTTP2_HTTP_EVENT_DATA_END);
  if (rv != 0) {
    return rv;
  }

  if (!(fr->hd.flags & NGHTTP2_DATA_FLAG_END_STREAM)) {
    return 0;
  }

  rv = nghttp2_stream_transit_rx_http_state(stream, NGHTTP2_HTTP_EVENT_MSG_END);
  if (rv != 0) {
    return rv;
  }

  stream->flags |= NGHTTP2_STREAM_FLAG_SHUT_RD;

  return conn_call_end_stream(conn, stream);
}

static int conn_on_data(nghttp2_conn *conn, const nghttp2_frame_data *fr,
                        const uint8_t *data, size_t datalen, int fin) {
  nghttp2_stream *stream;
  int rv;

  stream = nghttp2_conn_find_stream(conn, fr->hd.stream_id);
  if (!stream || (stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM)) {
    return 0;
  }

  rv = nghttp2_http_on_data_chunk(stream, datalen);
  if (rv != 0) {
    return rv;
  }

  return conn_call_recv_data(conn, stream, data, datalen, fin);
}

static int conn_recv_data(nghttp2_conn *conn, const nghttp2_frame_data *fr) {
  nghttp2_stream *stream;
  int rv;

  stream = nghttp2_conn_find_stream(conn, fr->hd.stream_id);
  if (!stream || (stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM)) {
    return 0;
  }

  if (fr->hd.flags & NGHTTP2_DATA_FLAG_PADDED) {
    stream->rx.unsent_max_offset += fr->padlen + 1;

    if (nghttp2_stream_require_strmq(stream)) {
      nghttp2_conn_strmq_push(conn, stream);
    }
  }

  if ((fr->hd.flags & NGHTTP2_DATA_FLAG_END_STREAM) && fr->datalen == 0) {
    rv = conn_call_recv_data(conn, stream, NULL, 0, /* fin = */ 1);
    if (rv != 0) {
      return rv;
    }

    if (stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM) {
      return 0;
    }
  }

  return conn_on_end_data(conn, stream, fr);
}

static int conn_recv_data_hd(nghttp2_conn *conn, nghttp2_frame_data *fr,
                             nghttp2_tstamp ts) {
  nghttp2_stream *stream;
  uint64_t end_offset;
  int rv;

  if ((fr->hd.flags & NGHTTP2_DATA_FLAG_PADDED) && fr->hd.len == 0) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  fr->padlen = 0;
  fr->datalen = 0;

  if (!client_stream_id(fr->hd.stream_id) ||
      conn_idle_stream(conn, fr->hd.stream_id)) {
    return NGHTTP2_ERR_PROTO;
  }

  /* The flow control is applied for entire DATA frame, including
     padding.  Note that we might have max_offset < offset.  In this
     case, we do not expect any non-zero length DATA frames, but zero
     length DATA frame is allowed. */

  stream = nghttp2_conn_find_stream(conn, fr->hd.stream_id);
  if (!stream) {
    /* The stream is gone.  We have no idea how this stream ended or
       even existed.  Just ignore.  Count the stream data to the
       connection-level flow control. */

    rv = conn_update_glitch_ratelim(conn, 1, ts);
    if (rv != 0) {
      return rv;
    }

    /* Even if we could not find the stream, connection flow control
       must be validated and its data must be counted toward
       connection-level flow control limit. */
    if (fr->hd.len && conn_max_data_violated(conn, fr->hd.len)) {
      return NGHTTP2_ERR_FLOW_CONTROL;
    }

    conn->rx.offset += fr->hd.len;

    return 0;
  }

  if (!(stream->flags & NGHTTP2_STREAM_FLAG_OPENED)) {
    return NGHTTP2_ERR_PROTO;
  }

  if (stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM) {
    return 0;
  }

  rv =
    nghttp2_stream_transit_rx_http_state(stream, NGHTTP2_HTTP_EVENT_DATA_BEGIN);
  if (rv != 0) {
    return rv;
  }

  if (fr->hd.len) {
    end_offset = stream->rx.offset + fr->hd.len;

    if (stream->rx.max_offset < end_offset ||
        conn_max_data_violated(conn, fr->hd.len)) {
      return NGHTTP2_ERR_FLOW_CONTROL;
    }

    stream->rx.offset = end_offset;
    conn->rx.offset += fr->hd.len;

    return 0;
  }

  /* No need to validate flow control if the frame length is zero. */

  if (fr->hd.flags & NGHTTP2_DATA_FLAG_END_STREAM) {
    rv = conn_call_recv_data(conn, stream, NULL, 0, /* fin = */ 1);
    if (rv != 0) {
      return rv;
    }

    if (stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM) {
      return 0;
    }
  } else {
    rv = conn_update_glitch_ratelim(conn, 1, ts);
    if (rv != 0) {
      return rv;
    }
  }

  return conn_on_end_data(conn, stream, fr);
}

static int conn_update_stream_priority(nghttp2_conn *conn,
                                       nghttp2_stream *stream,
                                       const nghttp2_pri *pri) {
  if (nghttp2_pri_eq(&stream->sched.pri, pri)) {
    return 0;
  }

  nghttp2_conn_unschedule_stream(conn, stream);

  stream->sched.pri = *pri;

  if (nghttp2_stream_require_schedule(stream)) {
    return nghttp2_conn_schedule_stream(conn, stream);
  }

  return 0;
}

static int conn_on_end_headers(nghttp2_conn *conn, nghttp2_stream *stream,
                               const nghttp2_frame_headers *fr) {
  int rv;

  nghttp2_log_rx_headers(&conn->log, fr);

  switch (stream->rx.hstate) {
  case NGHTTP2_HTTP_STATE_REQ_HEADERS_BEGIN:
    rv = nghttp2_http_on_request_headers(&stream->rx.http);
    if (rv != 0) {
      return rv;
    }

    /* Only server utilizes priority information to schedule
       streams. */
    if (conn->server && (stream->rx.http.flags & NGHTTP2_HTTP_FLAG_PRIORITY) &&
        !(stream->flags & NGHTTP2_STREAM_FLAG_SERVER_PRIORITY_SET)) {
      rv = conn_update_stream_priority(conn, stream, &stream->rx.http.pri);
      if (rv != 0) {
        return rv;
      }
    }

    rv = conn_call_end_headers(conn, stream,
                               fr->hd.flags & NGHTTP2_HEADERS_FLAG_END_STREAM);
    if (rv != 0) {
      return rv;
    }

    break;
  case NGHTTP2_HTTP_STATE_RESP_HEADERS_BEGIN:
    rv = nghttp2_http_on_response_headers(&stream->rx.http);
    if (rv != 0) {
      return rv;
    }

    rv = conn_call_end_headers(conn, stream,
                               fr->hd.flags & NGHTTP2_HEADERS_FLAG_END_STREAM);
    if (rv != 0) {
      return rv;
    }

    break;
  case NGHTTP2_HTTP_STATE_REQ_TRAILERS_BEGIN:
  case NGHTTP2_HTTP_STATE_RESP_TRAILERS_BEGIN:
    rv = conn_call_end_trailers(conn, stream,
                                fr->hd.flags & NGHTTP2_HEADERS_FLAG_END_STREAM);
    if (rv != 0) {
      return rv;
    }

    break;
  default:
    nghttp2_unreachable();
  }

  rv = nghttp2_stream_transit_rx_http_state(stream,
                                            NGHTTP2_HTTP_EVENT_HEADERS_END);
  assert(0 == rv);

  if (!(fr->hd.flags & NGHTTP2_HEADERS_FLAG_END_STREAM)) {
    switch (stream->rx.hstate) {
    case NGHTTP2_HTTP_STATE_REQ_TRAILERS_END:
    case NGHTTP2_HTTP_STATE_RESP_TRAILERS_END:
      return NGHTTP2_ERR_PROTO;
    default:
      return 0;
    }
  }

  rv = nghttp2_stream_transit_rx_http_state(stream, NGHTTP2_HTTP_EVENT_MSG_END);
  if (rv != 0) {
    return rv;
  }

  stream->flags |= NGHTTP2_STREAM_FLAG_SHUT_RD;

  return conn_call_end_stream(conn, stream);
}

static int conn_recv_headers(nghttp2_conn *conn,
                             const nghttp2_frame_headers *fr) {
  nghttp2_stream *stream;
  int rv;

  stream = nghttp2_conn_find_stream(conn, fr->hd.stream_id);
  if (!stream || (stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM)) {
    return 0;
  }

  if (fr->field_blocklen == 0) {
    rv = nghttp2_stream_empty_headers_allowed(stream);
    if (rv != 0) {
      return rv;
    }
  }

  return conn_on_end_headers(conn, stream, fr);
}

static int conn_recv_headers_hd(nghttp2_conn *conn, nghttp2_frame_headers *fr,
                                nghttp2_tstamp ts) {
  nghttp2_stream *stream;
  size_t num_streams;
  size_t min_len = 0;
  int rv;

  if (fr->hd.flags & NGHTTP2_HEADERS_FLAG_PADDED) {
    ++min_len;
  }

  if (fr->hd.flags & NGHTTP2_HEADERS_FLAG_PRIORITY) {
    min_len += 5;
  }

  if (fr->hd.len < min_len) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  /* Because we do not support server push, this must be client
     initiated stream ID */
  if (!client_stream_id(fr->hd.stream_id)) {
    return NGHTTP2_ERR_PROTO;
  }

  fr->padlen = 0;
  fr->field_blocklen = 0;
  conn->rx.frrd.scratch.headers.num_continuations = 0;

  if (!conn->server) {
    if (conn->tx.next_stream_id <= fr->hd.stream_id) {
      return NGHTTP2_ERR_PROTO;
    }

    stream = nghttp2_conn_find_stream(conn, fr->hd.stream_id);
    if (!stream) {
      /* The stream is gone.  We have no idea how this stream ended or
         even existed.  Just ignore.  Count the stream data to the
         connection-level flow control. */
      return conn_update_glitch_ratelim(conn, 1, ts);
    }

    if (!(stream->flags & NGHTTP2_STREAM_FLAG_OPENED)) {
      return NGHTTP2_ERR_PROTO;
    }
  } else if (conn->rx.last_stream_id >= fr->hd.stream_id) {
    stream = nghttp2_conn_find_stream(conn, fr->hd.stream_id);
    if (!stream) {
      /* The stream is gone.  We have no idea how this stream ended or
         even existed.  Just ignore.  Count the stream data to the
         connection-level flow control. */
      return conn_update_glitch_ratelim(conn, 1, ts);
    }
  } else {
    conn->rx.last_stream_id = fr->hd.stream_id;

    num_streams = nghttp2_conn_get_num_active_streams(conn);

    /* This is hard max */
    if (num_streams >= conn->rx.max_concurrent_streams) {
      return NGHTTP2_ERR_STREAM_LIMIT;
    }

    if (fr->hd.stream_id > conn->tx.goaway.last_stream_id &&
        conn->tx.goaway.num_refused_streams >=
          conn->settings.max_concurrent_streams_remote) {
      /* Ignore excessive streams created by the remote endpoint
         during graceful shutdown. */
      return 0;
    }

    rv = nghttp2_conn_create_stream(conn, &stream, fr->hd.stream_id, NULL);
    if (rv != 0) {
      return rv;
    }

    stream->flags |= NGHTTP2_STREAM_FLAG_OPENED;

    if (fr->hd.stream_id > conn->tx.goaway.last_stream_id) {
      ++conn->tx.goaway.num_refused_streams;

      stream->flags |= NGHTTP2_STREAM_FLAG_REFUSED;

      nghttp2_conn_shutdown_stream(conn, 0, stream->stream_id,
                                   NGHTTP2_REFUSED_STREAM);

      rv = conn_update_glitch_ratelim(conn, 1, ts);
      if (rv != 0) {
        return rv;
      }
    } else if (num_streams >= conn->settings.max_concurrent_streams_remote) {
      /* This is soft max, the temporary limit before receiving ACK. */
      stream->flags |= NGHTTP2_STREAM_FLAG_REFUSED;

      nghttp2_conn_shutdown_stream(conn, 0, stream->stream_id,
                                   NGHTTP2_REFUSED_STREAM);

      rv = conn_update_glitch_ratelim(conn, 1, ts);
      if (rv != 0) {
        return rv;
      }
    } else {
      conn->rx.last_processed_stream_id = fr->hd.stream_id;

      rv = conn_call_stream_open(conn, stream);
      if (rv != 0) {
        return rv;
      }
    }
  }

  assert(stream);

  if (stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM) {
    return 0;
  }

  rv = nghttp2_stream_transit_rx_http_state(stream,
                                            NGHTTP2_HTTP_EVENT_HEADERS_BEGIN);
  if (rv != 0) {
    return rv;
  }

  switch (stream->rx.hstate) {
  case NGHTTP2_HTTP_STATE_REQ_HEADERS_BEGIN:
  case NGHTTP2_HTTP_STATE_RESP_HEADERS_BEGIN:
    rv = conn_call_begin_headers(conn, stream);
    if (rv != 0) {
      return rv;
    }

    break;
  case NGHTTP2_HTTP_STATE_REQ_TRAILERS_BEGIN:
  case NGHTTP2_HTTP_STATE_RESP_TRAILERS_BEGIN:
    rv = conn_call_begin_trailers(conn, stream);
    if (rv != 0) {
      return rv;
    }

    break;
  default:
    nghttp2_unreachable();
  }

  if (fr->hd.len || !(fr->hd.flags & NGHTTP2_HEADERS_FLAG_END_HEADERS)) {
    return 0;
  }

  rv = nghttp2_stream_empty_headers_allowed(stream);
  if (rv != 0) {
    return rv;
  }

  return conn_on_end_headers(conn, stream, fr);
}

int nghttp2_conn_decode_field_block(nghttp2_conn *conn, int64_t stream_id,
                                    const uint8_t *src, size_t srclen,
                                    int fin) {
  nghttp2_stream *stream;
  nghttp2_ssize nread;
  nghttp2_hpack_decoder *hdec = &conn->rx.hdec;
  nghttp2_hpack_nv nv;
  nghttp2_buf buf;
  nghttp2_recv_field recv_header = NULL;
  int request = 0;
  int trailers = 0;
  int rv;
  uint8_t flags;

  stream = nghttp2_conn_find_stream(conn, stream_id);
  /* stream could be NULL.  In that case, do not call any
     callbacks. */
  if (stream) {
    if (stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM) {
      stream = NULL;
    } else {
      switch (stream->rx.hstate) {
      case NGHTTP2_HTTP_STATE_REQ_HEADERS_BEGIN:
        request = 1;
        /* Fall through */
      case NGHTTP2_HTTP_STATE_RESP_HEADERS_BEGIN:
        recv_header = conn->callbacks.recv_header;
        break;
      case NGHTTP2_HTTP_STATE_REQ_TRAILERS_BEGIN:
        request = 1;
        /* Fall through */
      case NGHTTP2_HTTP_STATE_RESP_TRAILERS_BEGIN:
        trailers = 1;
        recv_header = conn->callbacks.recv_trailer;

        break;
      default:
        nghttp2_unreachable();
      }
    }
  }

  nghttp2_buf_wrap_init(&buf, (uint8_t *)src, srclen);
  buf.last += srclen;

  for (;;) {
    nread = nghttp2_hpack_decoder_read(hdec, &nv, &flags, buf.pos,
                                       nghttp2_buf_len(&buf), fin);
    if (nread < 0) {
      return (int)nread;
    }

    buf.pos += nread;

    if ((flags & NGHTTP2_HPACK_DECODE_FLAG_FINAL) || nread == 0) {
      break;
    }

    if (flags & NGHTTP2_HPACK_DECODE_FLAG_EMIT) {
      if (stream) {
        rv = nghttp2_http_on_header(&stream->rx.http, &nv, request, trailers,
                                    conn->server &&
                                      conn->settings.enable_connect_protocol);
        if (rv != 0) {
          if (rv == NGHTTP2_ERR_REMOVE_HTTP_HEADER) {
            rv = 0;
          }
        } else if (recv_header) {
          rv = recv_header(conn, stream->stream_id, nv.token, nv.name, nv.value,
                           nv.flags, conn->user_data, stream->user_data);
          if (rv != 0) {
            rv = NGHTTP2_ERR_CALLBACK_FAILURE;
          }
        }

        if (stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM) {
          stream = NULL;
        }
      } else {
        rv = 0;
      }

      nghttp2_rcbuf_decref(nv.name);
      nghttp2_rcbuf_decref(nv.value);

      if (rv != 0) {
        return rv;
      }
    }
  }

  return 0;
}

static int conn_recv_rst_stream_hd(nghttp2_conn *conn,
                                   nghttp2_frame_rst_stream *fr,
                                   nghttp2_tstamp ts) {
  if (fr->hd.len != 4) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  if (!client_stream_id(fr->hd.stream_id) ||
      conn_idle_stream(conn, fr->hd.stream_id)) {
    return NGHTTP2_ERR_PROTO;
  }

  return conn_update_glitch_ratelim(conn, 1, ts);
}

static int conn_recv_rst_stream(nghttp2_conn *conn,
                                const nghttp2_frame_rst_stream *fr) {
  nghttp2_stream *stream;

  nghttp2_log_rx_rst_stream(&conn->log, fr);

  stream = nghttp2_conn_find_stream(conn, fr->hd.stream_id);
  if (!stream) {
    return 0;
  }

  if (!(stream->flags & NGHTTP2_STREAM_FLAG_OPENED) ||
      (stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM_RECVED)) {
    return NGHTTP2_ERR_PROTO;
  }

  nghttp2_stream_set_error_code(stream, fr->error_code);
  stream->flags |= NGHTTP2_STREAM_FLAG_RST_STREAM |
                   NGHTTP2_STREAM_FLAG_RST_STREAM_RECVED |
                   NGHTTP2_STREAM_FLAG_SHUT_RD | NGHTTP2_STREAM_FLAG_SHUT_WR;

  return nghttp2_conn_close_stream_if_shut_rdwr(conn, stream);
}

static int conn_recv_settings_hd(nghttp2_conn *conn, nghttp2_frame_settings *fr,
                                 nghttp2_tstamp ts) {
  int rv;

  if (fr->hd.stream_id != 0) {
    return NGHTTP2_ERR_PROTO;
  }

  if (fr->hd.flags & NGHTTP2_SETTINGS_FLAG_ACK) {
    if (!(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK)) {
      return NGHTTP2_ERR_PROTO;
    }

    if (fr->hd.len) {
      return NGHTTP2_ERR_FRAME_ENCODING;
    }

    return 0;
  }

  if (fr->hd.len % 6) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  if (fr->hd.len / 6 > NGHTTP2_MAX_SETTINGS_ENTRIES) {
    return NGHTTP2_ERR_EXCESSIVE_LOAD;
  }

  rv = conn_update_glitch_ratelim(conn, 1, ts);
  if (rv != 0) {
    return rv;
  }

  fr->settings = &conn->rx.frrd.scratch.settings.data;
  *fr->settings = conn->remote.settings;

  return 0;
}

typedef struct nghttp2_apply_max_stream_data {
  nghttp2_conn *conn;
  uint64_t delta;
} nghttp2_apply_max_stream_data;

static int stream_apply_rx_initial_max_stream_data(void *data, void *ptr) {
  nghttp2_stream *stream = data;
  const nghttp2_apply_max_stream_data *arg = ptr;
  uint64_t max_offset;

  max_offset = stream->rx.max_offset + arg->delta;

  if (max_offset > stream->rx.offset &&
      max_offset - stream->rx.offset > NGHTTP2_MAX_WINDOW_SIZE) {
    return NGHTTP2_ERR_FLOW_CONTROL;
  }

  stream->rx.max_offset = max_offset;
  stream->rx.unsent_max_offset += arg->delta * 2;

  if (!(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD) &&
      conn_should_send_stream_window_update(arg->conn, stream)) {
    stream->flags |= NGHTTP2_STREAM_FLAG_SEND_WINDOW_UPDATE;
    nghttp2_conn_strmq_push(arg->conn, stream);
  }

  return 0;
}

static int conn_recv_settings_ack(nghttp2_conn *conn,
                                  const nghttp2_frame_settings *fr) {
  uint64_t delta;
  int rv;

  conn->flags &= ~NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK;
  conn->tx.settings.ack_expiry = UINT64_MAX;

  nghttp2_log_rx_settings(&conn->log, fr);

  conn->rx.max_concurrent_streams =
    conn->settings.max_concurrent_streams_remote;

  if (conn->rx.stream_window != conn->settings.initial_max_stream_data) {
    delta = (uint64_t)conn->settings.initial_max_stream_data -
            (uint64_t)conn->rx.stream_window;

    conn->rx.stream_window = conn->settings.initial_max_stream_data;

    rv =
      nghttp2_map_each(&conn->streams, stream_apply_rx_initial_max_stream_data,
                       &(nghttp2_apply_max_stream_data){
                         .conn = conn,
                         .delta = delta,
                       });
    if (rv != 0) {
      return rv;
    }
  }

  return nghttp2_hpack_decoder_set_max_dtable_capacity(
    &conn->rx.hdec, conn->settings.hpack_max_dtable_capacity);
}

static int conn_recv_settings_entry(nghttp2_conn *conn,
                                    nghttp2_frame_settings *fr, uint16_t id,
                                    uint32_t value) {
  nghttp2_proto_settings *settings = fr->settings;

  switch (id) {
  case NGHTTP2_SETTINGS_HEADER_TABLE_SIZE:
    conn->rx.frrd.scratch.settings.min_dtable_capacity =
      nghttp2_min(conn->rx.frrd.scratch.settings.min_dtable_capacity, value);
    settings->hpack_max_dtable_capacity = value;

    break;
  case NGHTTP2_SETTINGS_ENABLE_PUSH:
    if (value > 1 || (!conn->server && value)) {
      return NGHTTP2_ERR_PROTO;
    }

    break;
  case NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
    settings->max_concurrent_streams = value;
    break;
  case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
    if (value > NGHTTP2_MAX_WINDOW_SIZE) {
      return NGHTTP2_ERR_PROTO;
    }

    settings->initial_max_stream_data = value;

    break;
  case NGHTTP2_SETTINGS_MAX_FRAME_SIZE:
    if (value < NGHTTP2_DEFAULT_MAX_FRAME_SIZE ||
        value > NGHTTP2_HARD_MAX_FRAME_SIZE) {
      return NGHTTP2_ERR_PROTO;
    }

    break;
  case NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
    settings->max_field_section_size = value;
    break;
  case NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL:
    if (value > 1 || (!value && settings->enable_connect_protocol)) {
      return NGHTTP2_ERR_PROTO;
    }

    settings->enable_connect_protocol = (uint8_t)value;

    break;
  default:
    break;
  }

  return 0;
}

static int stream_apply_tx_initial_max_stream_data(void *data, void *ptr) {
  nghttp2_stream *stream = data;
  const nghttp2_apply_max_stream_data *arg = ptr;
  int rv;

  rv = nghttp2_stream_add_tx_max_offset(stream, arg->delta);
  if (rv != 0) {
    return rv;
  }

  if (nghttp2_stream_require_schedule(stream)) {
    return nghttp2_conn_schedule_stream(arg->conn, stream);
  }

  return 0;
}

static int conn_recv_settings(nghttp2_conn *conn,
                              const nghttp2_frame_settings *fr,
                              nghttp2_tstamp ts) {
  nghttp2_proto_settings *settings = &conn->remote.settings;
  const nghttp2_proto_settings *new_settings = fr->settings;
  uint64_t delta;
  uint32_t min_dtable_capacity;
  int rv;

  nghttp2_log_rx_settings(&conn->log, fr);

  if (settings->hpack_max_dtable_capacity !=
      new_settings->hpack_max_dtable_capacity) {
    rv = conn_update_glitch_ratelim(conn, 2, ts);
    if (rv != 0) {
      return rv;
    }

    min_dtable_capacity = conn->rx.frrd.scratch.settings.min_dtable_capacity;

    assert(min_dtable_capacity != UINT32_MAX);

    if (min_dtable_capacity != new_settings->hpack_max_dtable_capacity) {
      nghttp2_hpack_encoder_set_max_dtable_capacity(&conn->tx.henc,
                                                    min_dtable_capacity);
    }

    nghttp2_hpack_encoder_set_max_dtable_capacity(
      &conn->tx.henc, new_settings->hpack_max_dtable_capacity);
  }

  if (settings->initial_max_stream_data !=
      new_settings->initial_max_stream_data) {
    rv = conn_update_glitch_ratelim(conn, 2, ts);
    if (rv != 0) {
      return rv;
    }

    delta = (uint64_t)new_settings->initial_max_stream_data -
            (uint64_t)settings->initial_max_stream_data;

    rv =
      nghttp2_map_each(&conn->streams, stream_apply_tx_initial_max_stream_data,
                       &(nghttp2_apply_max_stream_data){
                         .conn = conn,
                         .delta = delta,
                       });
    if (rv != 0) {
      return rv;
    }
  }

  *settings = *new_settings;
  settings->max_concurrent_streams =
    nghttp2_min(settings->max_concurrent_streams,
                conn->settings.max_concurrent_streams_local);

  if (conn->callbacks.recv_settings) {
    rv = conn->callbacks.recv_settings(conn, settings, conn->user_data);
    if (rv != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  ++conn->tx.settings.ack_left;

  return 0;
}

static int conn_recv_ping_hd(nghttp2_conn *conn, nghttp2_frame_ping *fr,
                             nghttp2_tstamp ts) {
  if (fr->hd.len != sizeof(nghttp2_ping_data)) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  if (fr->hd.stream_id != 0) {
    return NGHTTP2_ERR_PROTO;
  }

  return conn_update_glitch_ratelim(conn, 1, ts);
}

static int conn_recv_ping(nghttp2_conn *conn, const nghttp2_frame_ping *fr) {
  nghttp2_ping_data *data;
  int rv;

  nghttp2_log_rx_ping(&conn->log, fr);

  if (fr->hd.flags & NGHTTP2_PING_FLAG_ACK) {
    if (!(conn->flags & NGHTTP2_CONN_FLAG_EXPECT_PING_ACK)) {
      return NGHTTP2_ERR_PROTO;
    }

    if (!nghttp2_ping_data_eq(&conn->tx.ping.data, &fr->data)) {
      return NGHTTP2_ERR_PROTO;
    }

    if (conn->callbacks.recv_ping_ack) {
      rv = conn->callbacks.recv_ping_ack(conn, &conn->tx.ping.data,
                                         conn->user_data);
      if (rv != 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }

    conn->flags &= ~NGHTTP2_CONN_FLAG_EXPECT_PING_ACK;

    return 0;
  }

  if (nghttp2_ringbuf_full(&conn->rx.ping.data.rb)) {
    return NGHTTP2_ERR_EXCESSIVE_LOAD;
  }

  data = nghttp2_ringbuf_push_back(&conn->rx.ping.data.rb);
  *data = fr->data;

  return 0;
}

static int conn_recv_goaway_hd(nghttp2_conn *conn, nghttp2_frame_goaway *fr,
                               nghttp2_tstamp ts) {
  int rv;

  if (fr->hd.len < 8) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  if (fr->hd.stream_id) {
    return NGHTTP2_ERR_PROTO;
  }

  rv = conn_update_glitch_ratelim(conn, 1, ts);
  if (rv != 0) {
    return rv;
  }

  fr->debug_data = NULL;
  fr->debug_datalen = 0;

  return 0;
}

static int conn_recv_goaway(nghttp2_conn *conn,
                            const nghttp2_frame_goaway *fr) {
  int rv;

  nghttp2_log_rx_goaway(&conn->log, fr);

  if (fr->last_stream_id) {
    if (conn->server) {
      if (client_stream_id(fr->last_stream_id)) {
        return NGHTTP2_ERR_PROTO;
      }
    } else if (!client_stream_id(fr->last_stream_id)) {
      return NGHTTP2_ERR_PROTO;
    }
  }

  if (conn->rx.goaway.last_stream_id < fr->last_stream_id) {
    return NGHTTP2_ERR_PROTO;
  }

  conn->rx.goaway.last_stream_id = fr->last_stream_id;
  conn->flags |= NGHTTP2_CONN_FLAG_GOAWAY_RECVED;

  if (conn->callbacks.shutdown) {
    rv = conn->callbacks.shutdown(conn, fr->last_stream_id, fr->error_code,
                                  conn->user_data);
    if (rv != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  return 0;
}

static int conn_recv_window_update_hd(nghttp2_conn *conn,
                                      nghttp2_frame_window_update *fr) {
  if (fr->hd.len != 4) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  if (fr->hd.stream_id && (!client_stream_id(fr->hd.stream_id) ||
                           conn_idle_stream(conn, fr->hd.stream_id))) {
    return NGHTTP2_ERR_PROTO;
  }

  return 0;
}

static int conn_recv_window_update(nghttp2_conn *conn,
                                   const nghttp2_frame_window_update *fr,
                                   nghttp2_tstamp ts) {
  nghttp2_stream *stream;
  uint64_t max_offset;
  int rv;

  nghttp2_log_rx_window_update(&conn->log, fr);

  if (fr->hd.stream_id == 0) {
    max_offset = conn->tx.max_offset + fr->window_size_inc;
    if (max_offset - conn->tx.offset > NGHTTP2_MAX_WINDOW_SIZE) {
      return NGHTTP2_ERR_FLOW_CONTROL;
    }

    conn->tx.max_offset = max_offset;

    return 0;
  }

  stream = nghttp2_conn_find_stream(conn, fr->hd.stream_id);
  if (!stream) {
    return conn_update_glitch_ratelim(conn, 1, ts);
  }

  if (!(stream->flags & NGHTTP2_STREAM_FLAG_OPENED)) {
    return NGHTTP2_ERR_PROTO;
  }

  rv = nghttp2_stream_add_tx_max_offset(stream, fr->window_size_inc);
  if (rv != 0) {
    return rv;
  }

  if (nghttp2_stream_require_schedule(stream)) {
    return nghttp2_conn_schedule_stream(conn, stream);
  }

  return 0;
}

static int conn_recv_priority_update_hd(nghttp2_conn *conn,
                                        nghttp2_frame_priority_update *fr) {
  if (fr->hd.len < 4) {
    return NGHTTP2_ERR_FRAME_ENCODING;
  }

  if (!conn->server || fr->hd.stream_id) {
    return NGHTTP2_ERR_PROTO;
  }

  fr->pri = NULL;
  fr->prilen = 0;
  conn->rx.frrd.scratch.priority_update.prilen = 0;

  return 0;
}

static int conn_recv_priority_update(nghttp2_conn *conn,
                                     const nghttp2_frame_priority_update *fr,
                                     nghttp2_tstamp ts) {
  nghttp2_pri pri = {
    .urgency = NGHTTP2_DEFAULT_URGENCY,
  };
  nghttp2_stream *stream;
  int rv;

  nghttp2_log_rx_priority_update(&conn->log, fr);

  if (!client_stream_id(fr->prioritized_stream_id)) {
    return NGHTTP2_ERR_PROTO;
  }

  stream = nghttp2_conn_find_stream(conn, fr->prioritized_stream_id);
  if (!stream) {
    /* PRIORITY_UPDATE to the idle stream is ignored due to the
       bizarre nature of idle stream in HTTP/2. */
    return conn_update_glitch_ratelim(conn, 1, ts);
  }

  if (stream->flags & NGHTTP2_STREAM_FLAG_PRIORITY_UPDATE_RECVED) {
    rv = conn_update_glitch_ratelim(conn, 1, ts);
    if (rv != 0) {
      return NGHTTP2_ERR_EXCESSIVE_LOAD;
    }
  }

  stream->flags |= NGHTTP2_STREAM_FLAG_PRIORITY_UPDATE_RECVED;

  if (stream->flags & NGHTTP2_STREAM_FLAG_SHUT_WR) {
    return 0;
  }

  if (nghttp2_http_parse_priority(&pri, fr->pri, fr->prilen) != 0) {
    return 0;
  }

  return conn_update_stream_priority(conn, stream, &pri);
}

int nghttp2_conn_read(nghttp2_conn *conn, const uint8_t *data, size_t datalen,
                      nghttp2_tstamp ts) {
  const uint8_t *p, *end;
  nghttp2_int_reader *ird = &conn->rx.ird;
  nghttp2_frame_reader *frrd = &conn->rx.frrd;
  nghttp2_ssize nread;
  size_t len;
  int rv;

  conn_update_timestamp(conn, ts);

  if (datalen == 0) {
    return 0;
  }

  p = data;
  end = p + datalen;

  for (; p != end;) {
    switch (frrd->state) {
    case NGHTTP2_FRAME_READ_STATE_PREFACE:
      nread = frame_reader_read_preface(frrd, p, (size_t)(end - p));
      if (nread < 0) {
        /* connection preface error */
        return (int)nread;
      }

      p += nread;

      if (frrd->left) {
        return 0;
      }

      frrd->state = NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH:
      len = nghttp2_int_reader_read(ird, p, (size_t)(end - p), 3);

      p += len;

      if (!nghttp2_int_reader_done(ird)) {
        return 0;
      }

      frrd->fr.meta.hd.len = nghttp2_int_reader_final(ird);

      if (frrd->fr.meta.hd.len > NGHTTP2_DEFAULT_MAX_FRAME_SIZE) {
        if (!(conn->flags & NGHTTP2_CONN_FLAG_SETTINGS_SEEN)) {
          /* connection preface error */
          return NGHTTP2_ERR_PROTO;
        }

        return nghttp2_conn_handle_error(conn, NGHTTP2_ERR_FRAME_SIZE);
      }

      frrd->state = NGHTTP2_FRAME_READ_STATE_FRAME_TYPE;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_FRAME_TYPE:
      frrd->fr.meta.hd.type = *p++;

      if (!(conn->flags & NGHTTP2_CONN_FLAG_SETTINGS_SEEN) &&
          frrd->fr.meta.hd.type != NGHTTP2_FRAME_SETTINGS) {
        /* connection preface error */
        return NGHTTP2_ERR_PROTO;
      }

      frrd->state = NGHTTP2_FRAME_READ_STATE_FRAME_FLAGS;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_FRAME_FLAGS:
      frrd->fr.meta.hd.flags = *p++;

      frrd->state = NGHTTP2_FRAME_READ_STATE_FRAME_STREAM_ID;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_FRAME_STREAM_ID:
      len = nghttp2_int_reader_read(ird, p, (size_t)(end - p), 4);

      p += len;

      if (!nghttp2_int_reader_done(ird)) {
        return 0;
      }

      frrd->fr.meta.hd.stream_id = nghttp2_int_reader_final31(ird);

      switch (frrd->fr.meta.hd.type) {
      case NGHTTP2_FRAME_DATA:
        rv = conn_recv_data_hd(conn, &frrd->fr.data, ts);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        if (frrd->fr.data.hd.len == 0) {
          goto frame_done;
        }

        frrd->left = frrd->fr.data.hd.len;

        if (frrd->fr.data.hd.flags & NGHTTP2_DATA_FLAG_PADDED) {
          frrd->state = NGHTTP2_FRAME_READ_STATE_DATA_PADLEN;
        } else {
          frrd->state = NGHTTP2_FRAME_READ_STATE_DATA_DATA;
          frrd->field_left = frrd->left;
          frrd->fr.data.datalen = frrd->field_left;
        }

        break;
      case NGHTTP2_FRAME_HEADERS:
        rv = conn_recv_headers_hd(conn, &frrd->fr.headers, ts);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        if (frrd->fr.headers.hd.len == 0) {
          if (frrd->fr.headers.hd.flags & NGHTTP2_HEADERS_FLAG_END_HEADERS) {
            goto frame_done;
          }

          frrd->state = NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH;

          break;
        }

        frrd->left = frrd->fr.headers.hd.len;

        /* The absence of nghttp2_stream object means that it should
           be ignored; no callback should called.  But the received
           data should be counted toward connection-level flow
           control. */
        if (frrd->fr.headers.hd.flags & NGHTTP2_HEADERS_FLAG_PADDED) {
          frrd->state = NGHTTP2_FRAME_READ_STATE_HEADERS_PADLEN;
        } else {
          if (frrd->fr.headers.hd.flags & NGHTTP2_HEADERS_FLAG_PRIORITY) {
            frrd->state = NGHTTP2_FRAME_READ_STATE_HEADERS_PRIORITY;
            frrd->field_left = 5;
          } else {
            frrd->state = NGHTTP2_FRAME_READ_STATE_HEADERS_FIELD_BLOCK;
            frrd->field_left = frrd->left;
            frrd->fr.headers.field_blocklen = frrd->field_left;
          }
        }

        break;
      case NGHTTP2_FRAME_RST_STREAM:
        rv = conn_recv_rst_stream_hd(conn, &frrd->fr.rst_stream, ts);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        frrd->state = NGHTTP2_FRAME_READ_STATE_RST_STREAM_ERROR_CODE;
        frrd->left = frrd->fr.rst_stream.hd.len;

        break;
      case NGHTTP2_FRAME_SETTINGS:
        conn->flags |= NGHTTP2_CONN_FLAG_SETTINGS_SEEN;

        rv = conn_recv_settings_hd(conn, &frrd->fr.settings, ts);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        if (frrd->fr.settings.hd.flags & NGHTTP2_SETTINGS_FLAG_ACK) {
          rv = conn_recv_settings_ack(conn, &frrd->fr.settings);
          if (rv != 0) {
            return nghttp2_conn_handle_error(conn, rv);
          }

          goto frame_done;
        }

        if (frrd->fr.settings.hd.len == 0) {
          rv = conn_recv_settings(conn, &frrd->fr.settings, ts);
          if (rv != 0) {
            return nghttp2_conn_handle_error(conn, rv);
          }

          goto frame_done;
        }

        frrd->state = NGHTTP2_FRAME_READ_STATE_SETTINGS_SETTINGS;
        frrd->left = frrd->fr.settings.hd.len;
        frrd->scratch.settings.min_dtable_capacity = UINT32_MAX;

        break;
      case NGHTTP2_FRAME_PUSH_PROMISE:
        /* We do not expect receiving PUSH_PROMISE because we do not
           support server push. */
        return nghttp2_conn_handle_error(conn, NGHTTP2_ERR_PROTO);
      case NGHTTP2_FRAME_PING:
        rv = conn_recv_ping_hd(conn, &frrd->fr.ping, ts);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        frrd->state = NGHTTP2_FRAME_READ_STATE_PING_DATA;
        frrd->left = frrd->fr.ping.hd.len;

        break;
      case NGHTTP2_FRAME_GOAWAY:
        rv = conn_recv_goaway_hd(conn, &frrd->fr.goaway, ts);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        frrd->state = NGHTTP2_FRAME_READ_STATE_GOAWAY_LAST_STREAM_ID;
        frrd->left = frrd->fr.goaway.hd.len;

        break;
      case NGHTTP2_FRAME_WINDOW_UPDATE:
        rv = conn_recv_window_update_hd(conn, &frrd->fr.window_update);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        frrd->state = NGHTTP2_FRAME_READ_STATE_WINDOW_UPDATE_WINDOW_SIZE_INC;
        frrd->left = frrd->fr.window_update.hd.len;

        break;
      case NGHTTP2_FRAME_CONTINUATION:
        return nghttp2_conn_handle_error(conn, NGHTTP2_ERR_PROTO);
      case NGHTTP2_FRAME_PRIORITY_UPDATE:
        rv = conn_recv_priority_update_hd(conn, &frrd->fr.priority_update);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        frrd->state =
          NGHTTP2_FRAME_READ_STATE_PRIORITY_UPDATE_PRIORITIZED_STREAM_ID;
        frrd->left = frrd->fr.priority_update.hd.len;

        break;
      default:
        nghttp2_log_rx_unknown_frame(&conn->log, &frrd->fr.meta);

        rv = conn_update_glitch_ratelim(conn, 1, ts);
        if (rv != 0) {
          return rv;
        }

        frrd->state = NGHTTP2_FRAME_READ_STATE_DISCARD_FRAME;
        frrd->left = frrd->fr.meta.hd.len;

        if (frrd->left == 0) {
          goto frame_done;
        }

        break;
      }

      break;
    case NGHTTP2_FRAME_READ_STATE_DATA_PADLEN:
      frrd->fr.data.padlen = *p++;

      --frrd->left;

      if (frrd->fr.data.padlen > frrd->left) {
        return nghttp2_conn_handle_error(conn, NGHTTP2_ERR_PROTO);
      }

      if (frrd->left == 0) {
        rv = conn_recv_data(conn, &frrd->fr.data);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        goto frame_done;
      }

      frrd->fr.data.datalen = frrd->left - frrd->fr.data.padlen;
      frrd->state = NGHTTP2_FRAME_READ_STATE_DATA_DATA;
      frrd->field_left = frrd->fr.data.datalen;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_DATA_DATA:
      len = nghttp2_min(frrd->field_left, (size_t)(end - p));

      p += len;
      frrd->field_left -= len;
      frrd->left -= len;

      rv =
        conn_on_data(conn, &frrd->fr.data, p, len,
                     (frrd->fr.data.hd.flags & NGHTTP2_DATA_FLAG_END_STREAM) &&
                       frrd->field_left == 0);
      if (rv != 0) {
        return nghttp2_conn_handle_error(conn, rv);
      }

      if (frrd->field_left) {
        return 0;
      }

      if (frrd->left == 0) {
        rv = conn_recv_data(conn, &frrd->fr.data);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        goto frame_done;
      }

      assert(frrd->fr.data.padlen);

      frrd->state = NGHTTP2_FRAME_READ_STATE_DATA_PADDING;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_DATA_PADDING:
      len = nghttp2_min(frrd->left, (size_t)(end - p));

      p += len;
      frrd->left -= len;

      if (frrd->left) {
        return 0;
      }

      rv = conn_recv_data(conn, &frrd->fr.data);
      if (rv != 0) {
        return nghttp2_conn_handle_error(conn, rv);
      }

      goto frame_done;
    case NGHTTP2_FRAME_READ_STATE_HEADERS_PADLEN:
      frrd->fr.headers.padlen = *p++;

      --frrd->left;

      if (frrd->fr.headers.hd.flags & NGHTTP2_HEADERS_FLAG_PRIORITY) {
        frrd->state = NGHTTP2_FRAME_READ_STATE_HEADERS_PRIORITY;
        frrd->field_left = 5;

        if (frrd->fr.headers.padlen + frrd->field_left > frrd->left) {
          return nghttp2_conn_handle_error(conn, NGHTTP2_ERR_PROTO);
        }
      } else {
        if (frrd->fr.headers.padlen > frrd->left) {
          return nghttp2_conn_handle_error(conn, NGHTTP2_ERR_PROTO);
        }

        if (frrd->left == 0) {
          if (frrd->fr.headers.hd.flags & NGHTTP2_HEADERS_FLAG_END_HEADERS) {
            rv = conn_recv_headers(conn, &frrd->fr.headers);
            if (rv != 0) {
              return nghttp2_conn_handle_error(conn, rv);
            }

            goto frame_done;
          }

          frrd->state = NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH;

          break;
        }

        frrd->state = NGHTTP2_FRAME_READ_STATE_HEADERS_FIELD_BLOCK;
        frrd->field_left = frrd->left - frrd->fr.headers.padlen;
        frrd->fr.headers.field_blocklen = frrd->field_left;

        break;
      }

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_HEADERS_PRIORITY:
      len = nghttp2_min(frrd->field_left, (size_t)(end - p));

      p += len;
      frrd->left -= len;
      frrd->field_left -= len;

      if (frrd->field_left) {
        return 0;
      }

      if (frrd->left == 0) {
        if (frrd->fr.headers.hd.flags & NGHTTP2_HEADERS_FLAG_END_HEADERS) {
          rv = conn_recv_headers(conn, &frrd->fr.headers);
          if (rv != 0) {
            return nghttp2_conn_handle_error(conn, rv);
          }

          goto frame_done;
        }

        frrd->state = NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH;

        break;
      }

      frrd->state = NGHTTP2_FRAME_READ_STATE_HEADERS_FIELD_BLOCK;
      frrd->field_left = frrd->left - frrd->fr.headers.padlen;
      frrd->fr.headers.field_blocklen = frrd->field_left;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_HEADERS_FIELD_BLOCK:
      len = nghttp2_min(frrd->field_left, (size_t)(end - p));

      rv = nghttp2_conn_decode_field_block(
        conn, frrd->fr.headers.hd.stream_id, p, len,
        (frrd->fr.headers.hd.flags & NGHTTP2_HEADERS_FLAG_END_HEADERS) &&
          frrd->field_left == len);
      if (rv != 0) {
        return nghttp2_conn_handle_error(conn, rv);
      }

      p += len;
      frrd->left -= len;
      frrd->field_left -= len;

      if (frrd->field_left) {
        return 0;
      }

      if (frrd->left == 0) {
        assert(frrd->fr.headers.padlen == 0);

        if (frrd->fr.headers.hd.flags & NGHTTP2_HEADERS_FLAG_END_HEADERS) {
          rv = conn_recv_headers(conn, &frrd->fr.headers);
          if (rv != 0) {
            return nghttp2_conn_handle_error(conn, rv);
          }

          goto frame_done;
        }

        frrd->state = NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH;

        break;
      }

      assert(frrd->fr.headers.padlen);

      frrd->state = NGHTTP2_FRAME_READ_STATE_HEADERS_PADDING;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_HEADERS_PADDING:
      len = nghttp2_min(frrd->left, (size_t)(end - p));

      p += len;
      frrd->left -= len;

      if (frrd->left) {
        return 0;
      }

      if (frrd->fr.headers.hd.flags & NGHTTP2_HEADERS_FLAG_END_HEADERS) {
        rv = conn_recv_headers(conn, &frrd->fr.headers);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        goto frame_done;
      }

      frrd->state = NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH:
      if (frrd->scratch.headers.num_continuations >=
          NGHTTP2_MAX_CONTINUATIONS) {
        return NGHTTP2_ERR_EXCESSIVE_LOAD;
      }

      ++frrd->scratch.headers.num_continuations;

      len = nghttp2_int_reader_read(ird, p, (size_t)(end - p), 3);

      p += len;

      if (!nghttp2_int_reader_done(ird)) {
        return 0;
      }

      frrd->left = nghttp2_int_reader_final(ird);

      if (frrd->left > NGHTTP2_DEFAULT_MAX_FRAME_SIZE) {
        return nghttp2_conn_handle_error(conn, NGHTTP2_ERR_FRAME_SIZE);
      }

      /* We treat HEADERS + CONTINUATIONS... as a one big HEADERS. */
      frrd->fr.headers.hd.len += (uint32_t)frrd->left;
      frrd->fr.headers.field_blocklen += frrd->left;

      frrd->state = NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_TYPE;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_TYPE:
      if (*p++ != NGHTTP2_FRAME_CONTINUATION) {
        return nghttp2_conn_handle_error(conn, NGHTTP2_ERR_PROTO);
      }

      frrd->state = NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_FLAGS;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_FLAGS:
      frrd->fr.headers.hd.flags |= *p++ & NGHTTP2_HEADERS_FLAG_END_HEADERS;
      frrd->state = NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_STREAM_ID;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_STREAM_ID:
      len = nghttp2_int_reader_read(ird, p, (size_t)(end - p), 4);

      p += len;

      if (!nghttp2_int_reader_done(ird)) {
        return 0;
      }

      if (frrd->fr.headers.hd.stream_id != nghttp2_int_reader_final31(ird)) {
        return nghttp2_conn_handle_error(conn, NGHTTP2_ERR_PROTO);
      }

      if (frrd->left == 0) {
        /* 0 length CONTINUATION */
        if (frrd->fr.headers.hd.flags & NGHTTP2_HEADERS_FLAG_END_HEADERS) {
          rv = nghttp2_conn_decode_field_block(
            conn, frrd->fr.headers.hd.stream_id, NULL, 0,
            /* fin = */ 1);
          if (rv != 0) {
            return nghttp2_conn_handle_error(conn, rv);
          }

          rv = conn_recv_headers(conn, &frrd->fr.headers);
          if (rv != 0) {
            return nghttp2_conn_handle_error(conn, rv);
          }

          goto frame_done;
        }

        frrd->state = NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH;

        break;
      }

      frrd->state = NGHTTP2_FRAME_READ_STATE_HEADERS_FIELD_BLOCK;
      frrd->field_left = frrd->left;

      break;
    case NGHTTP2_FRAME_READ_STATE_RST_STREAM_ERROR_CODE:
      len = nghttp2_int_reader_read(ird, p, (size_t)(end - p), 4);

      p += len;
      frrd->left -= len;

      if (!nghttp2_int_reader_done(ird)) {
        return 0;
      }

      assert(frrd->left == 0);

      frrd->fr.rst_stream.error_code = nghttp2_int_reader_final(ird);

      rv = conn_recv_rst_stream(conn, &frrd->fr.rst_stream);
      if (rv != 0) {
        return nghttp2_conn_handle_error(conn, rv);
      }

      goto frame_done;
    case NGHTTP2_FRAME_READ_STATE_SETTINGS_SETTINGS:
      for (;;) {
        len = nghttp2_int_reader_read(ird, p, (size_t)(end - p), 2);

        p += len;
        frrd->left -= len;

        assert(frrd->left);

        if (!nghttp2_int_reader_done(ird)) {
          return 0;
        }

        frrd->scratch.settings.id = (uint16_t)nghttp2_int_reader_final(ird);

        if (p == end) {
          frrd->state = NGHTTP2_FRAME_READ_STATE_SETTINGS_VALUE;
          return 0;
        }

        len = nghttp2_int_reader_read(ird, p, (size_t)(end - p), 4);

        p += len;
        frrd->left -= len;

        if (!nghttp2_int_reader_done(ird)) {
          frrd->state = NGHTTP2_FRAME_READ_STATE_SETTINGS_VALUE;
          return 0;
        }

        frrd->scratch.settings.value = nghttp2_int_reader_final(ird);

        rv = conn_recv_settings_entry(conn, &frrd->fr.settings,
                                      frrd->scratch.settings.id,
                                      frrd->scratch.settings.value);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        if (frrd->left == 0) {
          rv = conn_recv_settings(conn, &frrd->fr.settings, ts);
          if (rv != 0) {
            return nghttp2_conn_handle_error(conn, rv);
          }

          goto frame_done;
        }

        if (p == end) {
          return 0;
        }
      }
    case NGHTTP2_FRAME_READ_STATE_SETTINGS_VALUE:
      len = nghttp2_int_reader_read(ird, p, (size_t)(end - p), 4);

      p += len;
      frrd->left -= len;

      if (!nghttp2_int_reader_done(ird)) {
        return 0;
      }

      frrd->scratch.settings.value = nghttp2_int_reader_final(ird);

      rv = conn_recv_settings_entry(conn, &frrd->fr.settings,
                                    frrd->scratch.settings.id,
                                    frrd->scratch.settings.value);
      if (rv != 0) {
        return nghttp2_conn_handle_error(conn, rv);
      }

      if (frrd->left == 0) {
        rv = conn_recv_settings(conn, &frrd->fr.settings, ts);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        goto frame_done;
      }

      frrd->state = NGHTTP2_FRAME_READ_STATE_SETTINGS_SETTINGS;

      break;
    case NGHTTP2_FRAME_READ_STATE_PING_DATA:
      len = nghttp2_min(frrd->left, (size_t)(end - p));

      memcpy(frrd->fr.ping.data.data +
               (sizeof(frrd->fr.ping.data.data) - frrd->left),
             p, len);

      p += len;
      frrd->left -= len;

      if (frrd->left) {
        return 0;
      }

      rv = conn_recv_ping(conn, &frrd->fr.ping);
      if (rv != 0) {
        return nghttp2_conn_handle_error(conn, rv);
      }

      goto frame_done;
    case NGHTTP2_FRAME_READ_STATE_GOAWAY_LAST_STREAM_ID:
      len = nghttp2_int_reader_read(ird, p, (size_t)(end - p), 4);

      p += len;
      frrd->left -= len;

      if (!nghttp2_int_reader_done(ird)) {
        return 0;
      }

      frrd->fr.goaway.last_stream_id = nghttp2_int_reader_final31(ird);

      frrd->state = NGHTTP2_FRAME_READ_STATE_GOAWAY_ERROR_CODE;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_GOAWAY_ERROR_CODE:
      len = nghttp2_int_reader_read(ird, p, (size_t)(end - p), 4);

      p += len;
      frrd->left -= len;

      if (!nghttp2_int_reader_done(ird)) {
        return 0;
      }

      frrd->fr.goaway.error_code = nghttp2_int_reader_final(ird);

      if (frrd->left == 0) {
        rv = conn_recv_goaway(conn, &frrd->fr.goaway);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        goto frame_done;
      }

      frrd->state = NGHTTP2_FRAME_READ_STATE_GOAWAY_DEBUG_DATA;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_GOAWAY_DEBUG_DATA:
      len = nghttp2_min(frrd->left, (size_t)(end - p));

      p += len;
      frrd->left -= len;

      if (frrd->left) {
        return 0;
      }

      rv = conn_recv_goaway(conn, &frrd->fr.goaway);
      if (rv != 0) {
        return nghttp2_conn_handle_error(conn, rv);
      }

      goto frame_done;
    case NGHTTP2_FRAME_READ_STATE_WINDOW_UPDATE_WINDOW_SIZE_INC:
      len = nghttp2_int_reader_read(ird, p, (size_t)(end - p), 4);

      p += len;
      frrd->left -= len;

      if (!nghttp2_int_reader_done(ird)) {
        return 0;
      }

      assert(frrd->left == 0);

      frrd->fr.window_update.window_size_inc = nghttp2_int_reader_final31(ird);

      rv = conn_recv_window_update(conn, &frrd->fr.window_update, ts);
      if (rv != 0) {
        return nghttp2_conn_handle_error(conn, rv);
      }

      goto frame_done;
    case NGHTTP2_FRAME_READ_STATE_PRIORITY_UPDATE_PRIORITIZED_STREAM_ID:
      len = nghttp2_int_reader_read(ird, p, (size_t)(end - p), 4);

      p += len;
      frrd->left -= len;

      if (!nghttp2_int_reader_done(ird)) {
        return 0;
      }

      frrd->fr.priority_update.prioritized_stream_id =
        nghttp2_int_reader_final31(ird);

      if (frrd->left == 0) {
        rv = conn_recv_priority_update(conn, &frrd->fr.priority_update, ts);
        if (rv != 0) {
          return nghttp2_conn_handle_error(conn, rv);
        }

        goto frame_done;
      }

      if (frrd->left > sizeof(frrd->scratch.priority_update.pri)) {
        frrd->state = NGHTTP2_FRAME_READ_STATE_DISCARD_FRAME;
        break;
      }

      frrd->state = NGHTTP2_FRAME_READ_STATE_PRIORITY_UPDATE_PRI;

      if (p == end) {
        return 0;
      }

      /* Fall through */
    case NGHTTP2_FRAME_READ_STATE_PRIORITY_UPDATE_PRI:
      len = nghttp2_min(frrd->left, (size_t)(end - p));

      p += len;
      frrd->left -= len;

      assert(len + frrd->scratch.priority_update.prilen <=
             sizeof(frrd->scratch.priority_update.pri));

      if (frrd->left == 0 && frrd->scratch.priority_update.prilen == 0) {
        /* The incoming buffer contains the complete priority field
           value */
        frrd->fr.priority_update.pri = p - len;
        frrd->fr.priority_update.prilen = len;
      } else {
        memcpy(frrd->scratch.priority_update.pri +
                 frrd->scratch.priority_update.prilen,
               p - len, len);
        frrd->scratch.priority_update.prilen += len;

        if (frrd->left) {
          return 0;
        }

        frrd->fr.priority_update.pri = frrd->scratch.priority_update.pri;
        frrd->fr.priority_update.prilen = frrd->scratch.priority_update.prilen;
      }

      rv = conn_recv_priority_update(conn, &frrd->fr.priority_update, ts);
      if (rv != 0) {
        return nghttp2_conn_handle_error(conn, rv);
      }

      goto frame_done;
    case NGHTTP2_FRAME_READ_STATE_CLOSING:
      return 0;
    case NGHTTP2_FRAME_READ_STATE_DISCARD_FRAME:
      len = nghttp2_min(frrd->left, (size_t)(end - p));

      p += len;
      frrd->left -= len;

      if (frrd->left) {
        return 0;
      }

      goto frame_done;
    default:
      assert(0);
    }

    continue;

  frame_done:
    nghttp2_frame_reader_reset(frrd);
  }

  return 0;
}

static int conn_write(nghttp2_conn *conn, nghttp2_buf *dest,
                      nghttp2_tstamp ts) {
  nghttp2_stream *stream;
  int rv;

  if (conn->sched.stream_inprogress) {
    if (nghttp2_http_writer_frame_flow_controlled(
          &conn->sched.stream_inprogress->tx.hw)) {
      rv = nghttp2_conn_write_stream_flow_controlled(
        conn, dest, conn->sched.stream_inprogress);
    } else {
      rv = nghttp2_conn_write_stream(conn, dest, conn->sched.stream_inprogress,
                                     ts);
    }

    if (rv != 0) {
      return rv;
    }

    if (conn->sched.stream_inprogress) {
      return 0;
    }
  }

  rv = nghttp2_conn_write_connection_wide_frames(conn, dest, ts);
  if (rv != 0) {
    return rv;
  }

  for (; conn->strmq_head;) {
    stream = conn->strmq_head;

    rv = nghttp2_conn_write_stream(conn, dest, stream, ts);
    if (rv != 0) {
      return rv;
    }

    /* stream might be deleted.  Do not touch it. */

    if (conn->sched.stream_inprogress) {
      return 0;
    }
  }

  for (;;) {
    if (conn->tx.max_offset <= conn->tx.offset) {
      return 0;
    }

    stream = nghttp2_conn_get_next_tx_stream(conn);
    if (!stream) {
      return 0;
    }

    rv = nghttp2_conn_write_stream_flow_controlled(conn, dest, stream);
    if (rv != 0) {
      return rv;
    }

    /* stream might be deleted.  Do not touch it. */

    if (conn->sched.stream_inprogress) {
      return 0;
    }
  }

  return 0;
}

static int conn_should_close(const nghttp2_conn *conn) {
  return !(conn->flags & NGHTTP2_CONN_FLAG_SEND_GOAWAY) &&
         ((conn->flags & NGHTTP2_CONN_FLAG_CLOSE_ABRUPTLY) ||
          ((conn->flags & NGHTTP2_CONN_FLAG_CLOSE_GRACEFULLY) &&
           nghttp2_conn_get_num_active_streams(conn) == 0));
}

nghttp2_ssize nghttp2_conn_write(nghttp2_conn *conn, uint8_t *rawdest,
                                 size_t rawdestlen, nghttp2_tstamp ts) {
  nghttp2_buf dest;
  nghttp2_ssize nwrite;

  conn_update_timestamp(conn, ts);

  if (conn_should_close(conn)) {
    return NGHTTP2_ERR_CLOSING;
  }

  if (rawdestlen == 0) {
    return 0;
  }

  nghttp2_buf_wrap_init(&dest, rawdest, rawdestlen);

  nwrite = conn_write(conn, &dest, ts);
  if (nwrite < 0 && nwrite != NGHTTP2_ERR_NOBUF) {
    return nwrite;
  }

  return (nghttp2_ssize)nghttp2_buf_len(&dest);
}

nghttp2_stream *nghttp2_conn_get_next_tx_stream(nghttp2_conn *conn) {
  size_t i;
  nghttp2_pq *pq;

  assert(!conn->sched.stream_inprogress);

  for (i = 0; i < nghttp2_arraylen(conn->sched.pq); ++i) {
    pq = &conn->sched.pq[i];
    if (nghttp2_pq_empty(pq)) {
      continue;
    }

    return nghttp2_struct_of(nghttp2_pq_top(pq), nghttp2_stream, sched);
  }

  return NULL;
}

int nghttp2_conn_write_stream(nghttp2_conn *conn, nghttp2_buf *dest,
                              nghttp2_stream *stream, nghttp2_tstamp ts) {
  nghttp2_frame fr;
  int rv;

  if ((stream->flags & NGHTTP2_STREAM_FLAG_OPENED) &&
      !nghttp2_http_writer_inprogress(&stream->tx.hw)) {
    if (stream->flags & NGHTTP2_STREAM_FLAG_SEND_RST_STREAM) {
      assert(stream->flags & NGHTTP2_STREAM_FLAG_ERROR_CODE_SET);

      /* This may be doubly counted, but do not care.  RST_STREAM must
         be severely rate limited. */
      rv = conn_update_glitch_ratelim(conn, 1, ts);
      if (rv != 0) {
        return NGHTTP2_ERR_EXCESSIVE_LOAD;
      }

      fr.rst_stream = (nghttp2_frame_rst_stream){
        .hd =
          {
            .len = 4,
            .type = NGHTTP2_FRAME_RST_STREAM,
            .stream_id = stream->stream_id,
          },
        .error_code = stream->error_code,
      };

      rv = nghttp2_frame_encode_rst_stream(dest, &fr.rst_stream);
      if (rv != 0) {
        return rv;
      }

      nghttp2_log_tx_rst_stream(&conn->log, &fr.rst_stream);

      stream->flags &= ~NGHTTP2_STREAM_FLAG_SEND_RST_STREAM;

      /* After sending RST_STREAM (or cancelled), the stream is
         finished.  No need to send more streams on it. */

      goto fin;
    }

    if (stream->flags & NGHTTP2_STREAM_FLAG_SEND_WINDOW_UPDATE) {
      if (conn_should_send_stream_window_update(conn, stream)) {
        fr.window_update = (nghttp2_frame_window_update){
          .hd =
            {
              .len = 4,
              .type = NGHTTP2_FRAME_WINDOW_UPDATE,
              .stream_id = stream->stream_id,
            },
          .window_size_inc =
            (uint32_t)(stream->rx.unsent_max_offset - stream->rx.max_offset),
        };

        rv = nghttp2_frame_encode_window_update(dest, &fr.window_update);
        if (rv != 0) {
          return rv;
        }

        nghttp2_log_tx_window_update(&conn->log, &fr.window_update);

        stream->rx.max_offset = stream->rx.unsent_max_offset;
      }

      stream->flags &= ~NGHTTP2_STREAM_FLAG_SEND_WINDOW_UPDATE;
    }

    if (stream->flags & NGHTTP2_STREAM_FLAG_SEND_PRIORITY_UPDATE) {
      fr.priority_update = (nghttp2_frame_priority_update){
        .hd =
          {
            .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
          },
        .prioritized_stream_id = (uint32_t)stream->stream_id,
        .pri = stream->tx.priority.client_pri.base,
        .prilen = stream->tx.priority.client_pri.len,
      };

      fr.priority_update.hd.len =
        (uint32_t)nghttp2_frame_encode_priority_update_payloadlen(
          &fr.priority_update);

      rv = nghttp2_frame_encode_priority_update(dest, &fr.priority_update);
      if (rv != 0) {
        return rv;
      }

      nghttp2_log_tx_priority_update(&conn->log, &fr.priority_update);

      stream->flags &= ~NGHTTP2_STREAM_FLAG_SEND_PRIORITY_UPDATE;

      nghttp2_stream_free_client_pri(stream);
    }
  }

  if (!nghttp2_http_writer_frame_flow_controlled(&stream->tx.hw)) {
    rv = nghttp2_http_writer_write(&stream->tx.hw, dest, &conn->tx.henc, stream,
                                   conn, &conn->log);
    if (rv != 0) {
      return rv;
    }

    if (conn->sched.stream_inprogress) {
      assert(conn->sched.stream_inprogress == stream);

      if (!nghttp2_http_writer_inprogress(&stream->tx.hw)) {
        conn->sched.stream_inprogress = NULL;
      }
    } else if (nghttp2_http_writer_inprogress(&stream->tx.hw)) {
      conn->sched.stream_inprogress = stream;
    }
  }

fin:
  if (nghttp2_conn_should_close_stream(conn, stream)) {
    return nghttp2_conn_close_stream(conn, stream);
  }

  if (!nghttp2_stream_require_strmq(stream)) {
    nghttp2_conn_strmq_remove(conn, stream);
  }

  return 0;
}

int nghttp2_conn_write_stream_flow_controlled(nghttp2_conn *conn,
                                              nghttp2_buf *dest,
                                              nghttp2_stream *stream) {
  int rv;

  rv = nghttp2_http_writer_write(&stream->tx.hw, dest, &conn->tx.henc, stream,
                                 conn, &conn->log);
  if (rv != 0) {
    return rv;
  }

  if (conn->sched.stream_inprogress) {
    assert(conn->sched.stream_inprogress == stream);

    if (!nghttp2_http_writer_inprogress(&stream->tx.hw)) {
      conn->sched.stream_inprogress = NULL;
    }
  } else if (nghttp2_http_writer_inprogress(&stream->tx.hw)) {
    conn->sched.stream_inprogress = stream;
  }

  if (nghttp2_conn_should_close_stream(conn, stream)) {
    return nghttp2_conn_close_stream(conn, stream);
  }

  if (nghttp2_stream_require_strmq(stream)) {
    nghttp2_conn_strmq_push(conn, stream);
  }

  if (nghttp2_stream_require_schedule(stream)) {
    return nghttp2_conn_schedule_stream(conn, stream);
  }

  nghttp2_conn_unschedule_stream(conn, stream);

  return 0;
}

int nghttp2_conn_write_settings(nghttp2_conn *conn, nghttp2_buf *dest,
                                nghttp2_tstamp ts) {
  const nghttp2_settings *settings = &conn->settings;
  nghttp2_settings_entry iv[5];
  size_t niv = 2;
  nghttp2_frame_settings fr;
  int rv;

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
    .value = settings->max_concurrent_streams_remote,
  };
  iv[1] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES,
    .value = 1,
  };

  if (settings->hpack_max_dtable_capacity !=
      NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY) {
    iv[niv++] = (nghttp2_settings_entry){
      .id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
      .value = (uint32_t)settings->hpack_max_dtable_capacity,
    };
  }

  if (settings->initial_max_stream_data != NGHTTP2_INITIAL_WINDOW_SIZE) {
    iv[niv++] = (nghttp2_settings_entry){
      .id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
      .value = settings->initial_max_stream_data,
    };
  }

  if (settings->enable_connect_protocol) {
    iv[niv++] = (nghttp2_settings_entry){
      .id = NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL,
      .value = 1,
    };
  }

  fr = (nghttp2_frame_settings){
    .hd =
      {
        .len = (uint32_t)niv * 6,
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = niv,
  };

  rv = nghttp2_frame_encode_settings(dest, &fr);
  if (rv != 0) {
    return rv;
  }

  nghttp2_log_tx_settings(&conn->log, &fr);

  conn->flags |=
    NGHTTP2_CONN_FLAG_SETTINGS_SENT | NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK;

  if (conn->settings.settings_timeout != UINT64_MAX) {
    conn->tx.settings.ack_expiry = ts + conn->settings.settings_timeout;
  }

  return 0;
}

int nghttp2_conn_write_settings_ack(nghttp2_conn *conn, nghttp2_buf *dest) {
  static const uint8_t settings_ack[] = {
    /* len */
    0x00,
    0x00,
    0x00,
    /* type */
    NGHTTP2_FRAME_SETTINGS,
    /* flags */
    NGHTTP2_SETTINGS_FLAG_ACK,
    /* stream_id */
    0x00,
    0x00,
    0x00,
    0x00,
  };
  static const nghttp2_frame_settings fr = {
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
      },
  };

  if (conn->tx.settings.ack_left == 0) {
    return 0;
  }

  for (; conn->tx.settings.ack_left; --conn->tx.settings.ack_left) {
    if (nghttp2_buf_left(dest) < sizeof(settings_ack)) {
      return NGHTTP2_ERR_NOBUF;
    }

    dest->last = nghttp2_cpymem(dest->last, settings_ack, sizeof(settings_ack));

    nghttp2_log_tx_settings(&conn->log, &fr);
  }

  return 0;
}

int nghttp2_conn_write_connection_wide_frames(nghttp2_conn *conn,
                                              nghttp2_buf *dest,
                                              nghttp2_tstamp ts) {
  nghttp2_frame fr;
  int rv;

  if (!conn->server && !(conn->flags & NGHTTP2_CONN_FLAG_HTTP2_PREFACE_SENT)) {
    if (nghttp2_buf_left(dest) <
        nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE)) {
      return 0;
    }

    dest->last =
      nghttp2_cpymem(dest->last, NGHTTP2_CLIENT_HTTP2_PREFACE,
                     nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE));

    conn->flags |= NGHTTP2_CONN_FLAG_HTTP2_PREFACE_SENT;
  }

  if (!(conn->flags & NGHTTP2_CONN_FLAG_SETTINGS_SENT)) {
    rv = nghttp2_conn_write_settings(conn, dest, ts);
    if (rv != 0) {
      return rv;
    }
  }

  if (conn->flags & NGHTTP2_CONN_FLAG_SEND_GOAWAY) {
    fr.goaway = (nghttp2_frame_goaway){
      .hd =
        {
          .len = 8,
          .type = NGHTTP2_FRAME_GOAWAY,
        },
      .last_stream_id = (uint32_t)conn->tx.goaway.last_stream_id,
      .error_code = conn->tx.goaway.error_code,
    };

    rv = nghttp2_frame_encode_goaway(dest, &fr.goaway);
    if (rv != 0) {
      return rv;
    }

    nghttp2_log_tx_goaway(&conn->log, &fr.goaway);

    conn->flags &= ~NGHTTP2_CONN_FLAG_SEND_GOAWAY;

    if (conn->flags & NGHTTP2_CONN_FLAG_CLOSE_ABRUPTLY) {
      /* Abrupt close.  No need to send more frames. */
      return 0;
    }
  }

  rv = nghttp2_conn_write_settings_ack(conn, dest);
  if (rv != 0) {
    return rv;
  }

  for (; nghttp2_ringbuf_len(&conn->rx.ping.data.rb);) {
    fr.ping = (nghttp2_frame_ping){
      .hd =
        {
          .len = sizeof(fr.ping.data.data),
          .type = NGHTTP2_FRAME_PING,
          .flags = NGHTTP2_PING_FLAG_ACK,
        },
      .data =
        *(nghttp2_ping_data *)nghttp2_ringbuf_get(&conn->rx.ping.data.rb, 0),
    };

    rv = nghttp2_frame_encode_ping(dest, &fr.ping);
    if (rv != 0) {
      return rv;
    }

    nghttp2_log_tx_ping(&conn->log, &fr.ping);

    nghttp2_ringbuf_pop_front(&conn->rx.ping.data.rb);
  }

  if (conn->flags & NGHTTP2_CONN_FLAG_SEND_PING) {
    fr.ping = (nghttp2_frame_ping){
      .hd =
        {
          .len = sizeof(fr.ping.data.data),
          .type = NGHTTP2_FRAME_PING,
        },
      .data = conn->tx.ping.data,
    };

    rv = nghttp2_frame_encode_ping(dest, &fr.ping);
    if (rv != 0) {
      return rv;
    }

    nghttp2_log_tx_ping(&conn->log, &fr.ping);

    conn->flags &= ~NGHTTP2_CONN_FLAG_SEND_PING;
    conn->flags |= NGHTTP2_CONN_FLAG_EXPECT_PING_ACK;
  }

  if (conn_should_send_connection_window_update(conn)) {
    fr.window_update = (nghttp2_frame_window_update){
      .hd =
        {
          .len = 4,
          .type = NGHTTP2_FRAME_WINDOW_UPDATE,
        },
      .window_size_inc =
        (uint32_t)(conn->rx.unsent_max_offset - conn->rx.max_offset),
    };

    rv = nghttp2_frame_encode_window_update(dest, &fr.window_update);
    if (rv != 0) {
      return rv;
    }

    nghttp2_log_tx_window_update(&conn->log, &fr.window_update);

    conn->rx.max_offset = conn->rx.unsent_max_offset;
  }

  return 0;
}

static nghttp2_pq *conn_get_sched_pq(nghttp2_conn *conn,
                                     nghttp2_stream *stream) {
  assert(stream->sched.pri.urgency < NGHTTP2_URGENCY_LEVELS);

  return &conn->sched.pq[stream->sched.pri.urgency];
}

int nghttp2_conn_schedule_stream(nghttp2_conn *conn, nghttp2_stream *stream) {
  int rv;

  /* Assume that stream stays on the same urgency level */
  rv = nghttp2_stream_schedule(stream, conn_get_sched_pq(conn, stream),
                               stream->sched.unscheduled_nwrite);
  if (rv != 0) {
    return rv;
  }

  stream->sched.unscheduled_nwrite = 0;

  return 0;
}

void nghttp2_conn_unschedule_stream(nghttp2_conn *conn,
                                    nghttp2_stream *stream) {
  /* Assume that stream stays on the same urgency level */
  nghttp2_stream_unschedule(stream, conn_get_sched_pq(conn, stream));
}

static void conn_rst_stream(nghttp2_conn *conn, nghttp2_stream *stream,
                            uint32_t error_code) {
  stream->flags |= NGHTTP2_STREAM_FLAG_RST_STREAM |
                   NGHTTP2_STREAM_FLAG_SEND_RST_STREAM |
                   NGHTTP2_STREAM_FLAG_SHUT_WR;

  nghttp2_stream_set_error_code(stream, error_code);

  nghttp2_conn_strmq_push(conn, stream);
}

void nghttp2_conn_shutdown_stream(nghttp2_conn *conn, uint32_t flags,
                                  int64_t stream_id, uint32_t error_code) {
  nghttp2_stream *stream;
  (void)flags;

  stream = nghttp2_conn_find_stream(conn, stream_id);
  if (!stream) {
    return;
  }

  if (stream->flags & NGHTTP2_STREAM_FLAG_RST_STREAM) {
    return;
  }

  conn_rst_stream(conn, stream, error_code);
}

void nghttp2_conn_strmq_push(nghttp2_conn *conn, nghttp2_stream *stream) {
  if (stream->strmq_prev) {
    return;
  }

  *conn->strmq_tail = stream;
  stream->strmq_prev = conn->strmq_tail;
  conn->strmq_tail = &stream->strmq_next;
}

void nghttp2_conn_strmq_remove(nghttp2_conn *conn, nghttp2_stream *stream) {
  if (!stream->strmq_prev) {
    return;
  }

  *stream->strmq_prev = stream->strmq_next;

  if (stream->strmq_next) {
    stream->strmq_next->strmq_prev = stream->strmq_prev;
  } else {
    conn->strmq_tail = stream->strmq_prev;
  }

  stream->strmq_prev = NULL;
  stream->strmq_next = NULL;
}

static int conn_submit_headers_data(nghttp2_conn *conn, nghttp2_stream *stream,
                                    const nghttp2_nv *nva, size_t nvlen,
                                    const nghttp2_data_reader *dr) {
  nghttp2_nv *nnva;
  nghttp2_frame *fr;
  int rv;

  rv = nghttp2_nva_copy(&nnva, nva, nvlen, conn->mem);
  if (rv != 0) {
    return rv;
  }

  rv = nghttp2_http_writer_emplace(&stream->tx.hw, &fr);
  if (rv != 0) {
    nghttp2_nva_del(nnva, conn->mem);
    return rv;
  }

  fr->headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        /* END_HEADERS flag will be added by nghttp2_http_writer. */
        .flags = (stream->flags & NGHTTP2_STREAM_FLAG_SHUT_WR)
                   ? NGHTTP2_HEADERS_FLAG_END_STREAM
                   : 0x00U,
        .stream_id = stream->stream_id,
      },
    .nva = nnva,
    .nvlen = nvlen,
  };

  if (nghttp2_stream_require_strmq(stream)) {
    nghttp2_conn_strmq_push(conn, stream);
  }

  if (dr) {
    rv = nghttp2_http_writer_emplace(&stream->tx.hw, &fr);
    if (rv != 0) {
      return rv;
    }

    fr->data = (nghttp2_frame_data){
      .hd =
        {
          .type = NGHTTP2_FRAME_DATA,
          .stream_id = stream->stream_id,
        },
      .dr = *dr,
    };

    if (nghttp2_stream_require_schedule(stream)) {
      rv = nghttp2_conn_schedule_stream(conn, stream);
      if (rv != 0) {
        return rv;
      }
    }
  }

  return 0;
}

int64_t nghttp2_conn_get_next_stream_id(const nghttp2_conn *conn) {
  assert(!conn->server);

  if (conn->flags & NGHTTP2_CONN_FLAG_GOAWAY_RECVED) {
    return (int64_t)INT32_MAX + 2;
  }

  return conn->tx.next_stream_id;
}

int64_t nghttp2_conn_submit_request(nghttp2_conn *conn, const nghttp2_nv *nva,
                                    size_t nvlen, const nghttp2_data_reader *dr,
                                    void *stream_user_data) {
  int64_t stream_id;
  nghttp2_stream *stream;
  int rv;

  assert(!conn->server);

  if (conn->flags & NGHTTP2_CONN_FLAG_GOAWAY_RECVED) {
    return NGHTTP2_ERR_REFUSED_STREAM;
  }

  if (nghttp2_conn_get_num_active_streams(conn) >=
        conn->remote.settings.max_concurrent_streams ||
      conn->tx.next_stream_id > INT32_MAX) {
    return NGHTTP2_ERR_STREAM_ID_BLOCKED;
  }

  stream_id = conn->tx.next_stream_id;
  conn->tx.next_stream_id += 2;

  rv = nghttp2_conn_create_stream(conn, &stream, stream_id, stream_user_data);
  if (rv != 0) {
    return rv;
  }

  stream->user_data = stream_user_data;

  stream->flags |= NGHTTP2_STREAM_FLAG_HEADERS_SUBMITTED;

  nghttp2_http_record_request_method(stream, nva, nvlen);

  if (!dr) {
    stream->flags |= NGHTTP2_STREAM_FLAG_SHUT_WR;
  }

  rv = conn_submit_headers_data(conn, stream, nva, nvlen, dr);
  if (rv != 0) {
    return rv;
  }

  return stream_id;
}

int nghttp2_conn_submit_info(nghttp2_conn *conn, int64_t stream_id,
                             const nghttp2_nv *nva, size_t nvlen) {
  nghttp2_stream *stream;

  assert(conn->server);
  assert(client_stream_id(stream_id));
  assert(stream_id <= INT32_MAX);

  stream = nghttp2_conn_find_stream(conn, stream_id);
  if (!stream) {
    return NGHTTP2_ERR_STREAM_NOT_FOUND;
  }

  if (stream->flags & NGHTTP2_STREAM_FLAG_HEADERS_SUBMITTED) {
    return NGHTTP2_ERR_STREAM_STATE;
  }

  if (stream->flags & NGHTTP2_STREAM_FLAG_SHUT_WR) {
    return NGHTTP2_ERR_STREAM_SHUT_WR;
  }

  return conn_submit_headers_data(conn, stream, nva, nvlen, NULL);
}

int nghttp2_conn_submit_response(nghttp2_conn *conn, int64_t stream_id,
                                 const nghttp2_nv *nva, size_t nvlen,
                                 const nghttp2_data_reader *dr) {
  nghttp2_stream *stream;

  assert(conn->server);
  assert(client_stream_id(stream_id));
  assert(stream_id <= INT32_MAX);

  stream = nghttp2_conn_find_stream(conn, stream_id);
  if (!stream) {
    return NGHTTP2_ERR_STREAM_NOT_FOUND;
  }

  if (stream->flags & NGHTTP2_STREAM_FLAG_HEADERS_SUBMITTED) {
    return NGHTTP2_ERR_STREAM_STATE;
  }

  if (stream->flags & NGHTTP2_STREAM_FLAG_SHUT_WR) {
    return NGHTTP2_ERR_STREAM_SHUT_WR;
  }

  stream->flags |= NGHTTP2_STREAM_FLAG_HEADERS_SUBMITTED;

  if (!dr) {
    stream->flags |= NGHTTP2_STREAM_FLAG_SHUT_WR;
  }

  return conn_submit_headers_data(conn, stream, nva, nvlen, dr);
}

int nghttp2_conn_submit_trailers(nghttp2_conn *conn, int64_t stream_id,
                                 const nghttp2_nv *nva, size_t nvlen) {
  nghttp2_stream *stream;

  assert(client_stream_id(stream_id));
  assert(stream_id <= INT32_MAX);

  stream = nghttp2_conn_find_stream(conn, stream_id);
  if (!stream) {
    return NGHTTP2_ERR_STREAM_NOT_FOUND;
  }

  if (!(stream->flags & NGHTTP2_STREAM_FLAG_HEADERS_SUBMITTED)) {
    return NGHTTP2_ERR_STREAM_STATE;
  }

  if (stream->flags & NGHTTP2_STREAM_FLAG_SHUT_WR) {
    return NGHTTP2_ERR_STREAM_SHUT_WR;
  }

  stream->flags |=
    NGHTTP2_STREAM_FLAG_SHUT_WR | NGHTTP2_STREAM_FLAG_TRAILERS_SUBMITTED;

  return conn_submit_headers_data(conn, stream, nva, nvlen, NULL);
}

int nghttp2_conn_extend_max_stream_offset(nghttp2_conn *conn, int64_t stream_id,
                                          uint32_t datalen) {
  nghttp2_stream *stream;
  uint64_t max_offset;

  assert(client_stream_id(stream_id));
  assert(stream_id <= INT32_MAX);

  stream = nghttp2_conn_find_stream(conn, stream_id);
  if (!stream) {
    return 0;
  }

  max_offset = stream->rx.unsent_max_offset + datalen;

  if (stream->rx.unsent_max_offset - stream->rx.max_offset <=
      NGHTTP2_MAX_WINDOW_SIZE) {
    if (max_offset - stream->rx.max_offset > NGHTTP2_MAX_WINDOW_SIZE) {
      return NGHTTP2_ERR_FLOW_CONTROL;
    }
  }

  if (max_offset - stream->rx.max_offset > NGHTTP2_MAX_WINDOW_SIZE) {
    /* unsent_max_offset is still "negative" or smaller than
       max_offset.  */
    stream->rx.unsent_max_offset = max_offset;

    return 0;
  }

  stream->rx.unsent_max_offset = nghttp2_min(max_offset, NGHTTP2_MAX_INT);

  if (!(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD) &&
      conn_should_send_stream_window_update(conn, stream)) {
    stream->flags |= NGHTTP2_STREAM_FLAG_SEND_WINDOW_UPDATE;
    nghttp2_conn_strmq_push(conn, stream);
  }

  return 0;
}

int nghttp2_conn_extend_max_offset(nghttp2_conn *conn, uint32_t datalen) {
  uint64_t max_offset;

  max_offset = conn->rx.unsent_max_offset + datalen;

  if (max_offset > conn->rx.max_offset &&
      max_offset - conn->rx.max_offset > NGHTTP2_MAX_WINDOW_SIZE) {
    return NGHTTP2_ERR_FLOW_CONTROL;
  }

  conn->rx.unsent_max_offset = nghttp2_min(max_offset, NGHTTP2_MAX_INT);

  return 0;
}

int nghttp2_conn_submit_ping(nghttp2_conn *conn,
                             const nghttp2_ping_data *data) {
  if (conn->flags &
      (NGHTTP2_CONN_FLAG_SEND_PING | NGHTTP2_CONN_FLAG_EXPECT_PING_ACK)) {
    return NGHTTP2_ERR_INVALID_STATE;
  }

  conn->tx.ping.data = *data;

  conn->flags |= NGHTTP2_CONN_FLAG_SEND_PING;

  return 0;
}

void nghttp2_conn_submit_shutdown_notice(nghttp2_conn *conn) {
  /* This will send GOAWAY with last_stream_id=INT32_MAX.  If any
     GOAWAY are sent or scheduled by nghttp2_conn_shutdown or
     nghttp2_conn_handle_error, this function is no-op. */
  if (conn->flags &
      (NGHTTP2_CONN_FLAG_SEND_GOAWAY | NGHTTP2_CONN_FLAG_CLOSE_ABRUPTLY |
       NGHTTP2_CONN_FLAG_CLOSE_GRACEFULLY)) {
    return;
  }

  conn->flags |= NGHTTP2_CONN_FLAG_SEND_GOAWAY;
}

void nghttp2_conn_shutdown(nghttp2_conn *conn) {
  if (conn->flags &
      (NGHTTP2_CONN_FLAG_CLOSE_ABRUPTLY | NGHTTP2_CONN_FLAG_CLOSE_GRACEFULLY)) {
    return;
  }

  conn->tx.goaway.last_stream_id = conn->rx.last_processed_stream_id;
  conn->tx.goaway.error_code = NGHTTP2_NO_ERROR;
  conn->flags |=
    NGHTTP2_CONN_FLAG_SEND_GOAWAY | NGHTTP2_CONN_FLAG_CLOSE_GRACEFULLY;
}

void nghttp2_conn_terminate(nghttp2_conn *conn, uint32_t error_code) {
  if (conn->flags & NGHTTP2_CONN_FLAG_CLOSE_ABRUPTLY) {
    return;
  }

  conn->tx.goaway.last_stream_id = nghttp2_min(
    conn->tx.goaway.last_stream_id, conn->rx.last_processed_stream_id);
  conn->tx.goaway.error_code = error_code;
  conn->rx.frrd.state = NGHTTP2_FRAME_READ_STATE_CLOSING;
  conn->flags |=
    NGHTTP2_CONN_FLAG_SEND_GOAWAY | NGHTTP2_CONN_FLAG_CLOSE_ABRUPTLY;
  /* Clear graceful shutdown flag.  We are closing the connection
     abruptly. */
  conn->flags &= ~NGHTTP2_CONN_FLAG_CLOSE_GRACEFULLY;
}

size_t nghttp2_conn_get_num_active_streams(const nghttp2_conn *conn) {
  size_t n;

  n = nghttp2_map_size(&conn->streams);

  if (conn->sched.stream_inprogress &&
      (conn->sched.stream_inprogress->flags &
       NGHTTP2_STREAM_FLAG_RST_STREAM_RECVED)) {
    --n;
  }

  return n;
}

int nghttp2_conn_resume_stream(nghttp2_conn *conn, int64_t stream_id) {
  nghttp2_stream *stream;

  stream = nghttp2_conn_find_stream(conn, stream_id);
  if (!stream) {
    return 0;
  }

  stream->flags &= ~NGHTTP2_STREAM_FLAG_READ_DATA_BLOCKED;

  if (nghttp2_stream_require_schedule(stream)) {
    return nghttp2_conn_schedule_stream(conn, stream);
  }

  return 0;
}

nghttp2_tstamp nghttp2_conn_get_expiry(const nghttp2_conn *conn) {
  if (conn->tx.settings.ack_expiry != UINT64_MAX) {
    return conn->tx.settings.ack_expiry;
  }

  return UINT64_MAX;
}

int nghttp2_conn_handle_expiry(nghttp2_conn *conn, nghttp2_tstamp ts) {
  if (conn->tx.settings.ack_expiry != UINT64_MAX &&
      conn->tx.settings.ack_expiry <= ts) {
    return NGHTTP2_ERR_SETTINGS_TIMEOUT;
  }

  return 0;
}

int nghttp2_conn_set_client_stream_priority(nghttp2_conn *conn,
                                            int64_t stream_id,
                                            const uint8_t *data,
                                            size_t datalen) {
  nghttp2_stream *stream;
  uint8_t *buf = NULL;

  assert(!conn->server);

  stream = nghttp2_conn_find_stream(conn, stream_id);
  if (!stream) {
    return 0;
  }

  if (datalen) {
    buf = nghttp2_mem_malloc(stream->mem, datalen);
    if (!buf) {
      return NGHTTP2_ERR_NOMEM;
    }

    memcpy(buf, data, datalen);
  }

  nghttp2_stream_free_client_pri(stream);

  stream->tx.priority.client_pri = (nghttp2_vec){
    .base = buf,
    .len = datalen,
  };
  stream->flags |= NGHTTP2_STREAM_FLAG_SEND_PRIORITY_UPDATE;

  nghttp2_conn_strmq_push(conn, stream);

  return 0;
}

int nghttp2_conn_set_server_stream_priority(nghttp2_conn *conn,
                                            int64_t stream_id,
                                            const nghttp2_pri *pri) {
  nghttp2_stream *stream;

  assert(conn->server);
  assert(pri->urgency < NGHTTP2_URGENCY_LEVELS);
  assert(pri->inc == 0 || pri->inc == 1);

  stream = nghttp2_conn_find_stream(conn, stream_id);
  if (!stream) {
    return 0;
  }

  stream->flags |= NGHTTP2_STREAM_FLAG_SERVER_PRIORITY_SET;

  return conn_update_stream_priority(conn, stream, pri);
}

int nghttp2_conn_get_stream_priority(const nghttp2_conn *conn,
                                     nghttp2_pri *dest, int64_t stream_id) {
  nghttp2_stream *stream;

  assert(conn->server);
  assert(stream_id & 0x1);

  stream = nghttp2_conn_find_stream(conn, stream_id);
  if (!stream) {
    return NGHTTP2_ERR_STREAM_NOT_FOUND;
  }

  *dest = stream->sched.pri;

  return 0;
}

size_t nghttp2_conn_get_streams_left(const nghttp2_conn *conn) {
  size_t num_streams;

  assert(!conn->server);

  num_streams = nghttp2_conn_get_num_active_streams(conn);
  if (conn->remote.settings.max_concurrent_streams <= num_streams) {
    return 0;
  }

  return conn->remote.settings.max_concurrent_streams - num_streams;
}

int nghttp2_conn_is_server(const nghttp2_conn *conn) { return conn->server; }

nghttp2_tstamp nghttp2_conn_get_timestamp(const nghttp2_conn *conn) {
  return conn->log.last_ts;
}
