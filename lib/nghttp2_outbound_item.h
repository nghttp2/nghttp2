/*
 * nghttp2 - HTTP/2 C Library
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
#ifndef NGHTTP2_OUTBOUND_ITEM_H
#define NGHTTP2_OUTBOUND_ITEM_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <nghttp2/nghttp2.h>
#include "nghttp2_frame.h"
#include "nghttp2_mem.h"

/* A bit higher priority for non-DATA frames */
#define NGHTTP2_OB_EX_CYCLE 2
/* Even more higher priority for SETTINGS frame */
#define NGHTTP2_OB_SETTINGS_CYCLE 1
/* Highest priority for PING frame */
#define NGHTTP2_OB_PING_CYCLE 0

/* struct used for HEADERS and PUSH_PROMISE frame */
typedef struct {
  nghttp2_data_provider data_prd;
  void *stream_user_data;
  /* error code when request HEADERS is canceled by RST_STREAM while
     it is in queue. */
  uint32_t error_code;
  /* nonzero if request HEADERS is canceled.  The error code is stored
     in |error_code|. */
  uint8_t canceled;
  /* nonzero if this item should be attached to stream object to make
     it under priority control */
  uint8_t attach_stream;
} nghttp2_headers_aux_data;

/* struct used for DATA frame */
typedef struct {
  /**
   * The data to be sent for this DATA frame.
   */
  nghttp2_data_provider data_prd;
  /**
   * The flags of DATA frame.  We use separate flags here and
   * nghttp2_data frame.  The latter contains flags actually sent to
   * peer.  This |flags| may contain NGHTTP2_FLAG_END_STREAM and only
   * when |eof| becomes nonzero, flags in nghttp2_data has
   * NGHTTP2_FLAG_END_STREAM set.
   */
  uint8_t flags;
  /**
   * The flag to indicate whether EOF was reached or not. Initially
   * |eof| is 0. It becomes 1 after all data were read.
   */
  uint8_t eof;
  /**
   * The flag to indicate that NGHTTP2_DATA_FLAG_NO_COPY is used.
   */
  uint8_t no_copy;
} nghttp2_data_aux_data;

typedef enum {
  NGHTTP2_GOAWAY_AUX_NONE = 0x0,
  /* indicates that session should be terminated after the
     transmission of this frame. */
  NGHTTP2_GOAWAY_AUX_TERM_ON_SEND = 0x1,
  /* indicates that this GOAWAY is just a notification for graceful
     shutdown.  No nghttp2_session.goaway_flags should be updated on
     the reaction to this frame. */
  NGHTTP2_GOAWAY_AUX_SHUTDOWN_NOTICE = 0x2,
} nghttp2_goaway_aux_flag;

/* struct used for GOAWAY frame */
typedef struct {
  /* bitwise-OR of one or more of nghttp2_goaway_aux_flag. */
  uint8_t flags;
} nghttp2_goaway_aux_data;

/* Additional data which cannot be stored in nghttp2_frame struct */
typedef union {
  nghttp2_data_aux_data data;
  nghttp2_headers_aux_data headers;
  nghttp2_goaway_aux_data goaway;
} nghttp2_aux_data;

typedef struct {
  nghttp2_frame frame;
  nghttp2_aux_data aux_data;
  int64_t seq;
  /* The priority used in priority comparion.  Smaller is served
     ealier.  For PING, SETTINGS and non-DATA frames (excluding
     response HEADERS frame) have dedicated cycle value defined above.
     For DATA frame, cycle is computed by taking into account of
     effective weight and frame payload length previously sent, so
     that the amount of transmission is distributed across streams
     proportional to effective weight (inside a tree). */
  uint64_t cycle;
  /* nonzero if this object is queued. */
  uint8_t queued;
} nghttp2_outbound_item;

/*
 * Deallocates resource for |item|. If |item| is NULL, this function
 * does nothing.
 */
void nghttp2_outbound_item_free(nghttp2_outbound_item *item, nghttp2_mem *mem);

#endif /* NGHTTP2_OUTBOUND_ITEM_H */
