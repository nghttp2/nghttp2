/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
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
#include "nghttp2_option.h"

int nghttp2_option_new(nghttp2_option **option_ptr)
{
  *option_ptr = (nghttp2_option *)calloc(1, sizeof(nghttp2_option));

  if(*option_ptr == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  return 0;
}

void nghttp2_option_del(nghttp2_option *option)
{
  free(option);
}

void nghttp2_option_set_no_auto_stream_window_update(nghttp2_option *option,
                                                     int val)
{
  option->opt_set_mask |= NGHTTP2_OPT_NO_AUTO_STREAM_WINDOW_UPDATE;
  option->no_auto_stream_window_update = val;
}

void nghttp2_option_set_no_auto_connection_window_update
(nghttp2_option *option, int val)
{
  option->opt_set_mask |= NGHTTP2_OPT_NO_AUTO_CONNECTION_WINDOW_UPDATE;
  option->no_auto_connection_window_update = val;
}

void nghttp2_option_set_peer_max_concurrent_streams(nghttp2_option *option,
                                                    uint32_t val)
{
  option->opt_set_mask |= NGHTTP2_OPT_PEER_MAX_CONCURRENT_STREAMS;
  option->peer_max_concurrent_streams = val;
}
