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
#include "nghttp2_stream.h"

#include <assert.h>

void nghttp2_stream_init(nghttp2_stream *stream, int32_t stream_id,
                         uint8_t flags, int32_t pri,
                         nghttp2_stream_state initial_state,
                         uint8_t remote_flow_control,
                         uint8_t local_flow_control,
                         int32_t initial_window_size,
                         void *stream_user_data)
{
  nghttp2_map_entry_init(&stream->map_entry, stream_id);
  stream->stream_id = stream_id;
  stream->flags = flags;
  stream->pri = pri;
  stream->state = initial_state;
  stream->shut_flags = NGHTTP2_SHUT_NONE;
  stream->stream_user_data = stream_user_data;
  stream->deferred_data = NULL;
  stream->deferred_flags = NGHTTP2_DEFERRED_NONE;
  stream->remote_flow_control = remote_flow_control;
  stream->local_flow_control = local_flow_control;
  stream->window_size = initial_window_size;
  stream->recv_window_size = 0;
}

void nghttp2_stream_free(nghttp2_stream *stream)
{
  nghttp2_outbound_item_free(stream->deferred_data);
  free(stream->deferred_data);
}

void nghttp2_stream_shutdown(nghttp2_stream *stream, nghttp2_shut_flag flag)
{
  stream->shut_flags |= flag;
}

void nghttp2_stream_defer_data(nghttp2_stream *stream,
                               nghttp2_outbound_item *data,
                               uint8_t flags)
{
  assert(stream->deferred_data == NULL);
  stream->deferred_data = data;
  stream->deferred_flags = flags;
}

void nghttp2_stream_detach_deferred_data(nghttp2_stream *stream)
{
  stream->deferred_data = NULL;
  stream->deferred_flags = NGHTTP2_DEFERRED_NONE;
}

void nghttp2_stream_update_initial_window_size(nghttp2_stream *stream,
                                               int32_t new_initial_window_size,
                                               int32_t old_initial_window_size)
{
  stream->window_size =
    new_initial_window_size-(old_initial_window_size-stream->window_size);
}

void nghttp2_stream_promise_fulfilled(nghttp2_stream *stream)
{
  stream->state = NGHTTP2_STREAM_OPENED;
}
