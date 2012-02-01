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
#ifndef SPDYLAY_STREAM_H
#define SPDYLAY_STREAM_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <spdylay/spdylay.h>

/*
 * If local peer is stream initiator:
 * SPDYLAY_STREAM_OPENING : upon sending SYN_STREAM
 * SPDYLAY_STREAM_OPENED : upon receiving SYN_REPLY
 * SPDYLAY_STREAM_CLOSING : upon queuing RST_STREAM
 *
 * If remote peer is stream initiator:
 * SPDYLAY_STREAM_OPENING : upon receiving SYN_STREAM
 * SPDYLAY_STREAM_OPENED : upon sending SYN_REPLY
 * SPDYLAY_STREAM_CLOSING : upon queuing RST_STREAM
 */
typedef enum {
  /* Initial state */
  SPDYLAY_STREAM_INITIAL,
  /* For stream initiator: SYN_STREAM has been sent, but SYN_REPLY is
     not received yet.  For receiver: SYN_STREAM has been received,
     but it does not send SYN_REPLY yet. */
  SPDYLAY_STREAM_OPENING,
  /* For stream initiator: SYN_REPLY is received. For receiver:
     SYN_REPLY is sent. */
  SPDYLAY_STREAM_OPENED,
  /* RST_STREAM is received, but somehow we need to keep stream in
     memory. */
  SPDYLAY_STREAM_CLOSING
} spdylay_stream_state;

typedef enum {
  SPDYLAY_SHUT_NONE = 0,
  /* Indicates further receptions will be disallowed. */
  SPDYLAY_SHUT_RD = 0x01,
  /* Indicates further transmissions will be disallowed. */
  SPDYLAY_SHUT_WR = 0x02,
  /* Indicates both further receptions and transmissions will be
     disallowed. */
  SPDYLAY_SHUT_RDWR = SPDYLAY_SHUT_RD | SPDYLAY_SHUT_WR
} spdylay_shut_flag;

typedef struct {
  int32_t stream_id;
  spdylay_stream_state state;
  /* Use same value in SYN_STREAM frame */
  uint8_t flags;
  /* Use same scheme in SYN_STREAM frame */
  uint8_t pri;
  /* Bitwise OR of zero or more spdylay_shut_flag values */
  uint8_t shut_flags;
  /* TODO spdylay_stream should remember pushed stream ID, so that if
     RST_STREAM with CANCEL (mandatory?) is sent, we can close all of
     them. */
} spdylay_stream;

void spdylay_stream_init(spdylay_stream *stream, int32_t stream_id,
                         uint8_t flags, uint8_t pri,
                         spdylay_stream_state initial_state);

void spdylay_stream_free(spdylay_stream *stream);

/*
 * Disallow either further receptions or transmissions, or both.
 * |flag| is bitwise OR of one or more of spdylay_shut_flag.
 */
void spdylay_stream_shutdown(spdylay_stream *stream, spdylay_shut_flag flag);

#endif /* SPDYLAY_STREAM */
