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
#ifndef NGHTTP2_STREAM_H
#define NGHTTP2_STREAM_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <nghttp2v2/nghttp2.h>

#include "nghttp2_pq.h"
#include "nghttp2_http_writer.h"

#define NGHTTP2_STREAM_MIN_WRITELEN (16384 - NGHTTP2_FRAME_HDLEN)

#define NGHTTP2_STREAM_FLAG_NONE 0x00U
#define NGHTTP2_STREAM_FLAG_SHUT_RD 0x01U
#define NGHTTP2_STREAM_FLAG_SHUT_WR 0x02U
#define NGHTTP2_STREAM_FLAG_ERROR_CODE_SET 0x04U
/* NGHTTP2_STREAM_FLAG_FC_BLOCKED indicates that stream is blocked by
   stream-level flow control. */
#define NGHTTP2_STREAM_FLAG_FC_BLOCKED 0x08U
/* NGHTTP2_STREAM_FLAG_READ_DATA_BLOCKED indicates that application is
   temporarily unable to provide data. */
#define NGHTTP2_STREAM_FLAG_READ_DATA_BLOCKED 0x10U
/* NGHTTP2_STREAM_FLAG_HEADERS_SUBMITTED indicates that the header
   field (and data) has been submitted to this stream. */
#define NGHTTP2_STREAM_FLAG_HEADERS_SUBMITTED 0x20U
/* NGHTTP2_STREAM_FLAG_TRAILERS_SUBMITTED indicates that the trailer
   field has been submitted to this stream. */
#define NGHTTP2_STREAM_FLAG_TRAILERS_SUBMITTED 0x40U
/* NGHTTP2_STREAM_FLAG_SEND_RST_STREAM indicates that RST_STREAM
   should be sent in this stream. */
#define NGHTTP2_STREAM_FLAG_SEND_RST_STREAM 0x80U
/* NGHTTP2_STREAM_FLAG_RST_STREAM indicates that RST_STREAM has been
   sent or received. */
#define NGHTTP2_STREAM_FLAG_RST_STREAM 0x0100U
/* NGHTTP2_STREAM_FLAG_RST_STREAM_RECVED indicates that RST_STREAM has
   been received. */
#define NGHTTP2_STREAM_FLAG_RST_STREAM_RECVED 0x0200U
/* NGHTTP2_STREAM_FLAG_OPENED indicates that some activity has been
   seen in this stream.  RST_STREAM can be sent to this stream. */
#define NGHTTP2_STREAM_FLAG_OPENED 0x0400U
/* NGHTTP2_STREAM_FLAG_REFUSED indicates that the stream is refused
   and not processed in any way. */
#define NGHTTP2_STREAM_FLAG_REFUSED 0x0800U
/* NGHTTP2_STREAM_FLAG_SEND_WINDOW_UPDATE indicates that WINDOW_UPDATE
   should be sent in this stream. */
#define NGHTTP2_STREAM_FLAG_SEND_WINDOW_UPDATE 0x1000U
/* NGHTTP2_STREAM_FLAG_SERVER_PRIORITY_SET is set when server
   overrides stream priority with its own. */
#define NGHTTP2_STREAM_FLAG_SERVER_PRIORITY_SET 0x2000U
/* NGHTTP2_STREAM_FLAG_SEND_PRIORITY_UPDATE indicates that
   PRIORITY_UPDATE should be sent for this stream. */
#define NGHTTP2_STREAM_FLAG_SEND_PRIORITY_UPDATE 0x4000U
/* NGHTTP2_STREAM_FLAG_PRIORITY_UPDATE_RECVED is set when
   PRIORITY_UPDATE frame is received from client */
#define NGHTTP2_STREAM_FLAG_PRIORITY_UPDATE_RECVED 0x8000U

typedef enum nghttp2_stream_http_state {
  NGHTTP2_HTTP_STATE_NONE,
  NGHTTP2_HTTP_STATE_REQ_INITIAL,
  NGHTTP2_HTTP_STATE_REQ_HEADERS_BEGIN,
  NGHTTP2_HTTP_STATE_REQ_HEADERS_END,
  NGHTTP2_HTTP_STATE_REQ_DATA_BEGIN,
  NGHTTP2_HTTP_STATE_REQ_DATA_END,
  NGHTTP2_HTTP_STATE_REQ_TRAILERS_BEGIN,
  NGHTTP2_HTTP_STATE_REQ_TRAILERS_END,
  NGHTTP2_HTTP_STATE_REQ_END,
  NGHTTP2_HTTP_STATE_RESP_INITIAL,
  NGHTTP2_HTTP_STATE_RESP_HEADERS_BEGIN,
  NGHTTP2_HTTP_STATE_RESP_HEADERS_END,
  NGHTTP2_HTTP_STATE_RESP_DATA_BEGIN,
  NGHTTP2_HTTP_STATE_RESP_DATA_END,
  NGHTTP2_HTTP_STATE_RESP_TRAILERS_BEGIN,
  NGHTTP2_HTTP_STATE_RESP_TRAILERS_END,
  NGHTTP2_HTTP_STATE_RESP_END,
} nghttp2_stream_http_state;

typedef enum nghttp2_stream_http_event {
  NGHTTP2_HTTP_EVENT_DATA_BEGIN,
  NGHTTP2_HTTP_EVENT_DATA_END,
  NGHTTP2_HTTP_EVENT_HEADERS_BEGIN,
  NGHTTP2_HTTP_EVENT_HEADERS_END,
  NGHTTP2_HTTP_EVENT_MSG_END,
} nghttp2_stream_http_event;

typedef struct nghttp2_http_state {
  /* content_length is the value of received content-length header
     field. */
  int64_t content_length;
  /* recv_content_length is the number of body bytes received so
     far. */
  int64_t recv_content_length;
  nghttp2_pri pri;
  /* status_code is HTTP status code received.  This field is used
     if connection is initialized as client. */
  int32_t status_code;
  uint32_t flags;
} nghttp2_http_state;

typedef struct nghttp2_stream_callbacks {
  nghttp2_write_stream_data_offset write_stream_data_offset;
} nghttp2_stream_callbacks;

typedef struct nghttp2_stream {
  const nghttp2_mem *mem;
  int64_t stream_id;
  nghttp2_stream **strmq_prev;
  nghttp2_stream *strmq_next;

  struct {
    nghttp2_stream_http_state hstate;
    nghttp2_http_state http;
    /* offset is the offset of stream data received for this stream so
       far. */
    uint64_t offset;
    /* max_offset is the maximum offset that remote endpoint can send
       to this stream. */
    uint64_t max_offset;
    /* unsent_max_offset is the maximum offset that remote endpoint
       can send to this stream, and it is not notified to the remote
       endpoint.  unsent_max_offset could be "negative" when window
       size is reduced by SETTINGS.  It is negative if
       unsent_max_offset - max_offset > NGHTTP2_MAX_WINDOW_SIZE. */
    uint64_t unsent_max_offset;
  } rx;

  struct {
    nghttp2_http_writer hw;

    struct {
      /* client_pri contains the value of priority field (RFC 9218) to
         send in PRIORITY_UPDATE frame. */
      nghttp2_vec client_pri;
    } priority;

    /* offset is the next offset of new outgoing data.  In other
       words, it is the number of bytes sent in this stream without
       duplication. */
    uint64_t offset;
    /* max_tx_offset is the maximum offset that local endpoint can
       send for this stream. */
    uint64_t max_offset;
  } tx;

  struct {
    /* pe must be a first field of shced. */
    nghttp2_pq_entry pe;
    uint64_t cycle;
    nghttp2_pri pri;
    size_t unscheduled_nwrite;
  } sched;

  void *user_data;
  uint32_t error_code;
  uint32_t flags;
} nghttp2_stream;

void nghttp2_stream_init(nghttp2_stream *stream, int64_t stream_id,
                         const nghttp2_stream_callbacks *callbacks,
                         uint32_t flags, uint64_t max_rx_offset,
                         uint64_t max_tx_offset, void *user_data,
                         const nghttp2_mem *mem);

void nghttp2_stream_free(nghttp2_stream *stream);

int nghttp2_stream_transit_rx_http_state(nghttp2_stream *stream,
                                         nghttp2_stream_http_event event);

int nghttp2_stream_empty_headers_allowed(const nghttp2_stream *stream);

void nghttp2_stream_set_error_code(nghttp2_stream *stream, uint32_t error_code);

int nghttp2_stream_require_strmq(const nghttp2_stream *stream);

int nghttp2_stream_require_schedule(const nghttp2_stream *stream);

int nghttp2_stream_schedule(nghttp2_stream *stream, nghttp2_pq *pq,
                            uint64_t nwrite);

void nghttp2_stream_unschedule(nghttp2_stream *stream, nghttp2_pq *pq);

int nghttp2_stream_add_tx_max_offset(nghttp2_stream *stream, uint64_t delta);

void nghttp2_stream_free_client_pri(nghttp2_stream *stream);

#endif /* !defined(NGHTTP2_STREAM_H) */
