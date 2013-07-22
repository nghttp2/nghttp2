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
#ifndef NGHTTP2_STREAM_H
#define NGHTTP2_STREAM_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <nghttp2/nghttp2.h>
#include "nghttp2_outbound_item.h"
#include "nghttp2_map.h"

/*
 * If local peer is stream initiator:
 * NGHTTP2_STREAM_OPENING : upon sending SYN_STREAM
 * NGHTTP2_STREAM_OPENED : upon receiving SYN_REPLY
 * NGHTTP2_STREAM_CLOSING : upon queuing RST_STREAM
 *
 * If remote peer is stream initiator:
 * NGHTTP2_STREAM_OPENING : upon receiving SYN_STREAM
 * NGHTTP2_STREAM_OPENED : upon sending SYN_REPLY
 * NGHTTP2_STREAM_CLOSING : upon queuing RST_STREAM
 */
typedef enum {
  /* Initial state */
  NGHTTP2_STREAM_INITIAL,
  /* For stream initiator: SYN_STREAM has been sent, but SYN_REPLY is
     not received yet.  For receiver: SYN_STREAM has been received,
     but it does not send SYN_REPLY yet. */
  NGHTTP2_STREAM_OPENING,
  /* For stream initiator: SYN_REPLY is received. For receiver:
     SYN_REPLY is sent. */
  NGHTTP2_STREAM_OPENED,
  /* RST_STREAM is received, but somehow we need to keep stream in
     memory. */
  NGHTTP2_STREAM_CLOSING
} nghttp2_stream_state;

typedef enum {
  NGHTTP2_SHUT_NONE = 0,
  /* Indicates further receptions will be disallowed. */
  NGHTTP2_SHUT_RD = 0x01,
  /* Indicates further transmissions will be disallowed. */
  NGHTTP2_SHUT_WR = 0x02,
  /* Indicates both further receptions and transmissions will be
     disallowed. */
  NGHTTP2_SHUT_RDWR = NGHTTP2_SHUT_RD | NGHTTP2_SHUT_WR
} nghttp2_shut_flag;

typedef enum {
  NGHTTP2_DEFERRED_NONE = 0,
  /* Indicates the DATA is deferred due to flow control. */
  NGHTTP2_DEFERRED_FLOW_CONTROL = 0x01
} nghttp2_deferred_flag;

typedef struct {
  /* Intrusive Map */
  nghttp2_map_entry map_entry;
  /* stream ID */
  int32_t stream_id;
  nghttp2_stream_state state;
  /* Use same value in SYN_STREAM frame */
  uint8_t flags;
  /* Use same value in SYN_STREAM frame */
  int32_t pri;
  /* Bitwise OR of zero or more nghttp2_shut_flag values */
  uint8_t shut_flags;
  /* The arbitrary data provided by user for this stream. */
  void *stream_user_data;
  /* Deferred DATA frame */
  nghttp2_outbound_item *deferred_data;
  /* The flags for defered DATA. Bitwise OR of zero or more
     nghttp2_deferred_flag values */
  uint8_t deferred_flags;
  /* Flag to indicate whether the remote side has flow control
     enabled. If it is enabled, we have to enforces flow control to
     send data to the other side. This could be disabled when
     receiving SETTINGS with flow control options off or receiving
     WINDOW_UPDATE with END_FLOW_CONTROL bit set. */
  uint8_t remote_flow_control;
  /* Flag to indicate whether the local side has flow control
     enabled. If it is enabled, the received data are subject to the
     flow control. This could be disabled by sending SETTINGS with
     flow control options off or sending WINDOW_UPDATE with
     END_FLOW_CONTROL bit set. */
  uint8_t local_flow_control;
  /* Current sender window size. This value is computed against the
     current initial window size of remote endpoint. */
  int32_t window_size;
  /* Keep track of the number of bytes received without
     WINDOW_UPDATE. */
  int32_t recv_window_size;
} nghttp2_stream;

void nghttp2_stream_init(nghttp2_stream *stream, int32_t stream_id,
                         uint8_t flags, int32_t pri,
                         nghttp2_stream_state initial_state,
                         uint8_t remote_flow_control,
                         uint8_t local_flow_control,
                         int32_t initial_window_size,
                         void *stream_user_data);

void nghttp2_stream_free(nghttp2_stream *stream);

/*
 * Disallow either further receptions or transmissions, or both.
 * |flag| is bitwise OR of one or more of nghttp2_shut_flag.
 */
void nghttp2_stream_shutdown(nghttp2_stream *stream, nghttp2_shut_flag flag);

/*
 * Defer DATA frame |data|. We won't call this function in the
 * situation where stream->deferred_data != NULL.  If |flags| is
 * bitwise OR of zero or more nghttp2_deferred_flag values.
 */
void nghttp2_stream_defer_data(nghttp2_stream *stream,
                               nghttp2_outbound_item *data,
                               uint8_t flags);

/*
 * Detaches deferred data from this stream. This function does not
 * free deferred data.
 */
void nghttp2_stream_detach_deferred_data(nghttp2_stream *stream);

/*
 * Updates the initial window size with the new value
 * |new_initial_window_size|. The |old_initial_window_size| is used to
 * calculate the current window size.
 */
void nghttp2_stream_update_initial_window_size(nghttp2_stream *stream,
                                               int32_t new_initial_window_size,
                                               int32_t old_initial_window_size);

#endif /* NGHTTP2_STREAM */
