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
#include "spdylay_outbound_item.h"

void spdylay_outbound_item_free(spdylay_outbound_item *item)
{
  if(item == NULL) {
    return;
  }
  switch(item->frame_type) {
  case SPDYLAY_SYN_STREAM:
    spdylay_frame_syn_stream_free(&item->frame->syn_stream);
    free(((spdylay_syn_stream_aux_data*)item->aux_data)->data_prd);
    break;
  case SPDYLAY_SYN_REPLY:
    spdylay_frame_syn_reply_free(&item->frame->syn_reply);
    break;
  case SPDYLAY_RST_STREAM:
    spdylay_frame_rst_stream_free(&item->frame->rst_stream);
    break;
  case SPDYLAY_SETTINGS:
    spdylay_frame_settings_free(&item->frame->settings);
    break;
  case SPDYLAY_NOOP:
    /* We don't have any public API to add NOOP, so here is
       unreachable. */
    abort();
  case SPDYLAY_PING:
    spdylay_frame_ping_free(&item->frame->ping);
    break;
  case SPDYLAY_GOAWAY:
    spdylay_frame_goaway_free(&item->frame->goaway);
    break;
  case SPDYLAY_HEADERS:
    spdylay_frame_headers_free(&item->frame->headers);
    break;
  case SPDYLAY_WINDOW_UPDATE:
    spdylay_frame_window_update_free(&item->frame->window_update);
    break;
  case SPDYLAY_DATA:
    spdylay_frame_data_free(&item->frame->data);
    break;
  }
  free(item->frame);
  free(item->aux_data);
}
