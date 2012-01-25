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
#ifndef SPDYLAY_SESSION_H
#define SPDYLAY_SESSION_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <spdylay/spdylay.h>
#include "spdylay_pq.h"
#include "spdylay_map.h"
#include "spdylay_frame.h"
#include "spdylay_zlib.h"
#include "spdylay_stream.h"

typedef struct {
  spdylay_frame_type frame_type;
  spdylay_frame *frame;
  int pri;
} spdylay_outbound_item;

typedef struct {
  spdylay_outbound_item *item;
  uint8_t *framebuf;
  size_t framebuflen;
  size_t framebufoff;
} spdylay_active_outbound_item;

typedef struct {
  uint8_t buf[4096];
  uint8_t *mark;
  uint8_t *limit;
} spdylay_inbound_buffer;

typedef enum {
  SPDYLAY_RECV_HEAD,
  SPDYLAY_RECV_PAYLOAD
} spdylay_inbound_state;

#define SPDYLAY_HEAD_LEN 8

typedef struct {
  spdylay_inbound_state state;
  uint8_t headbuf[SPDYLAY_HEAD_LEN];
  /* NULL if inbound frame is data frame */
  uint8_t *buf;
  /* length in Length field */
  size_t len;
  size_t off;
  uint8_t ign;
} spdylay_inbound_frame;

typedef struct spdylay_session {
  uint8_t server;
  int32_t next_stream_id;
  int32_t last_recv_stream_id;
  
  spdylay_map /* <spdylay_stream*> */ streams;
  spdylay_pq /* <spdylay_outbound_item*> */ ob_pq;

  spdylay_active_outbound_item aob;

  spdylay_inbound_buffer ibuf;
  spdylay_inbound_frame iframe;

  spdylay_zlib hd_deflater;
  spdylay_zlib hd_inflater;

  spdylay_session_callbacks callbacks;
  void *user_data;
} spdylay_session;

/* TODO stream timeout etc */

int spdylay_session_add_frame(spdylay_session *session,
                              spdylay_frame_type frame_type,
                              spdylay_frame *frame);

int spdylay_session_add_rst_stream(spdylay_session *session,
                                   int32_t stream_id, uint32_t status_code);

/*
 * Creates new stream in |session| with stream ID |stream_id|,
 * priority |pri| and flags |flags|. Currently, |flags| &
 * SPDYLAY_FLAG_UNIDIRECTIONAL is non-zero, this stream is
 * unidirectional. |flags| & SPDYLAY_FLAG_FIN is non-zero, the sender
 * of SYN_STREAM will not send any further data in this stream.
 * The state of stream is set to |initial_state|.
 */
int spdylay_session_open_stream(spdylay_session *session, int32_t stream_id,
                                uint8_t flags, uint8_t pri,
                                spdylay_stream_state initial_state);

/*
 * Closes stream whose stream ID is |stream_id|. This function returns
 * 0 if it succeeds, or negative error code.  The possible error code
 * is SPDYLAY_ERR_INVALID_ARGUMENT, which is used when stream
 * |stream_id| does not exist. So the caller may ignore this error.
 */
int spdylay_session_close_stream(spdylay_session *session, int32_t stream_id);

/*
 * Called when SYN_STREAM is received. Received frame is |frame|.
 * This function does first
 * validate received frame and then open stream and call callback
 * functions.
 */
int spdylay_session_on_syn_stream_received(spdylay_session *session,
                                           spdylay_frame *frame);

/*
 * Called when SYN_STREAM is received. Received frame is |frame|.
 * This function does first validate received frame and then open
 * stream and call callback functions.
 */
int spdylay_session_on_syn_reply_received(spdylay_session *session,
                                          spdylay_frame *frame);


/*
 * Returns spdylay_stream* object whose stream ID is |stream_id|.  It
 * could be NULL if such stream does not exist.
 */
spdylay_stream* spdylay_session_get_stream(spdylay_session *session,
                                           int32_t stream_id);

#endif /* SPDYLAY_SESSION_H */
