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
#ifndef NGHTTP2_OUTBOUND_ITEM_H
#define NGHTTP2_OUTBOUND_ITEM_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <nghttp2/nghttp2.h>
#include "nghttp2_frame.h"

/* Priority for PING */
#define NGHTTP2_OB_PRI_PING -10
/* Priority for CREDENTIAL */
#define NGHTTP2_OB_PRI_CREDENTIAL -2
/* Priority for the frame which must be sent after CREDENTIAL */
#define NGHTTP2_OB_PRI_AFTER_CREDENTIAL -1

typedef struct {
  nghttp2_data_provider *data_prd;
  void *stream_user_data;
} nghttp2_syn_stream_aux_data;

typedef struct {
  /* Type of |frame|. NGHTTP2_CTRL: nghttp2_frame*, NGHTTP2_DATA:
     nghttp2_data* */
  nghttp2_frame_category frame_cat;
  void *frame;
  void *aux_data;
  /* Initial priority of this item */
  int inipri;
  /* The current priority of this item. Initially, pri equals to
     inipri. The item is chosen from the queue based on pri and
     seq. For control frames, they consist of just 1 frame and pri
     does not change. For DATA frame, they could split up to several
     frames. After sending a frame, the pri is increased by 1. If it
     becomes more than lowest priority, then it returns back to inipri
     and do the same sequence again and again. By doing this, the
     higher priority long DATA frames don't starve the lower
     prioritized streams. */
  int pri;
  int64_t seq;
} nghttp2_outbound_item;

/*
 * Deallocates resource for |item|. If |item| is NULL, this function
 * does nothing.
 */
void nghttp2_outbound_item_free(nghttp2_outbound_item *item);

/* Macros to cast nghttp2_outbound_item.frame to the proper type. */
#define nghttp2_outbound_item_get_ctrl_frame(ITEM) ((nghttp2_frame*)ITEM->frame)
#define nghttp2_outbound_item_get_ctrl_frame_type(ITEM) \
  (((nghttp2_frame*)ITEM->frame)->ctrl.hd.type)
#define nghttp2_outbound_item_get_data_frame(ITEM) ((nghttp2_data*)ITEM->frame)

#endif /* NGHTTP2_OUTBOUND_ITEM_H */
