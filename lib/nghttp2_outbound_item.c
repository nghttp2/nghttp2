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
#include "nghttp2_outbound_item.h"

#include <assert.h>

void nghttp2_outbound_item_free(nghttp2_outbound_item *item)
{
  if(item == NULL) {
    return;
  }
  if(item->frame_cat == NGHTTP2_CTRL) {
    nghttp2_frame_type frame_type;
    nghttp2_frame *frame;
    frame_type = nghttp2_outbound_item_get_ctrl_frame_type(item);
    frame = nghttp2_outbound_item_get_ctrl_frame(item);
    switch(frame_type) {
    case NGHTTP2_SYN_STREAM:
      nghttp2_frame_syn_stream_free(&frame->syn_stream);
      free(((nghttp2_syn_stream_aux_data*)item->aux_data)->data_prd);
      break;
    case NGHTTP2_SYN_REPLY:
      nghttp2_frame_syn_reply_free(&frame->syn_reply);
      break;
    case NGHTTP2_RST_STREAM:
      nghttp2_frame_rst_stream_free(&frame->rst_stream);
      break;
    case NGHTTP2_SETTINGS:
      nghttp2_frame_settings_free(&frame->settings);
      break;
    case NGHTTP2_NOOP:
      /* We don't have any public API to add NOOP, so here is
         unreachable. */
      assert(0);
    case NGHTTP2_PING:
      nghttp2_frame_ping_free(&frame->ping);
      break;
    case NGHTTP2_GOAWAY:
      nghttp2_frame_goaway_free(&frame->goaway);
      break;
    case NGHTTP2_HEADERS:
      nghttp2_frame_headers_free(&frame->headers);
      break;
    case NGHTTP2_WINDOW_UPDATE:
      nghttp2_frame_window_update_free(&frame->window_update);
      break;
    case NGHTTP2_CREDENTIAL:
      nghttp2_frame_credential_free(&frame->credential);
      break;
    }
  } else if(item->frame_cat == NGHTTP2_DATA) {
    nghttp2_data *data_frame;
    data_frame = nghttp2_outbound_item_get_data_frame(item);
    nghttp2_frame_data_free(data_frame);
  } else {
    /* Unreachable */
    assert(0);
  }
  free(item->frame);
  free(item->aux_data);
}
