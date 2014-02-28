/*
 * nghttp2 - HTTP/2.0 C Library
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
#include "h2load_http2_session.h"

#include "h2load.h"

namespace h2load {

Http2Session::Http2Session(Client *client)
  : client_(client),
    session_(nullptr)
{}

Http2Session::~Http2Session()
{
  nghttp2_session_del(session_);
}

namespace {
int before_frame_send_callback
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
  auto client = static_cast<Client*>(user_data);
  if(frame->hd.type == NGHTTP2_HEADERS &&
     frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
    client->on_request(frame->hd.stream_id);
  }
  return 0;
}
} // namespace

namespace {
int on_header_callback(nghttp2_session *session,
                       const nghttp2_frame *frame,
                       const uint8_t *name, size_t namelen,
                       const uint8_t *value, size_t valuelen,
                       void *user_data)
{
  auto client = static_cast<Client*>(user_data);
  if(frame->hd.type != NGHTTP2_HEADERS ||
     frame->headers.cat != NGHTTP2_HCAT_RESPONSE) {
    return 0;
  }
  client->on_header(frame->hd.stream_id, name, namelen, value, valuelen);
  return 0;
}
} // namespace

namespace {
int on_frame_recv_callback(nghttp2_session *session,
                           const nghttp2_frame *frame,
                           void *user_data)
{
  auto client = static_cast<Client*>(user_data);
  if(frame->hd.type != NGHTTP2_HEADERS ||
     frame->headers.cat != NGHTTP2_HCAT_RESPONSE) {
    return 0;
  }
  client->worker->stats.bytes_head += frame->hd.length;
  return 0;
}
} // namespace

namespace {
int on_data_chunk_recv_callback
(nghttp2_session *session, uint8_t flags, int32_t stream_id,
 const uint8_t *data, size_t len, void *user_data)
{
  auto client = static_cast<Client*>(user_data);
  client->worker->stats.bytes_body += len;
  return 0;
}
} // namespace

namespace {
int on_stream_close_callback
(nghttp2_session *session, int32_t stream_id, nghttp2_error_code error_code,
 void *user_data)
{
  auto client = static_cast<Client*>(user_data);
  client->on_stream_close(stream_id, error_code == NGHTTP2_NO_ERROR);
  return 0;
}
} // namespace

void Http2Session::on_connect()
{
  nghttp2_session_callbacks callbacks = {0};
  callbacks.before_frame_send_callback = before_frame_send_callback;
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks.on_stream_close_callback = on_stream_close_callback;
  callbacks.on_header_callback = on_header_callback;

  nghttp2_session_client_new(&session_, &callbacks, client_);

  nghttp2_settings_entry iv[2];
  iv[0].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
  iv[0].value = 0;
  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = (1 << client_->worker->config->window_bits) - 1;
  nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, iv,
                          sizeof(iv) / sizeof(iv[0]));

  auto extra_connection_window =
    (1 << client_->worker->config->connection_window_bits) - 1
    - NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE;
  if(extra_connection_window != 0) {
    nghttp2_submit_window_update(session_, NGHTTP2_FLAG_NONE, 0,
                                 extra_connection_window);
  }

  bufferevent_write(client_->bev, NGHTTP2_CLIENT_CONNECTION_HEADER,
                    NGHTTP2_CLIENT_CONNECTION_HEADER_LEN);
}

void Http2Session::submit_request()
{
  nghttp2_submit_request(session_, 0,
                         client_->worker->config->nva.data(),
                         client_->worker->config->nva.size(),
                         nullptr, nullptr);
}

ssize_t Http2Session::on_read()
{
  int rv;
  auto input = bufferevent_get_input(client_->bev);
  auto inputlen = evbuffer_get_length(input);
  auto mem = evbuffer_pullup(input, -1);

  rv = nghttp2_session_mem_recv(session_, mem, inputlen);
  if(rv < 0) {
    return -1;
  }
  evbuffer_drain(input, rv);
  return rv;
}

int Http2Session::on_write()
{
  int rv;
  auto output = bufferevent_get_output(client_->bev);
  for(;;) {
    const uint8_t *data;
    auto datalen = nghttp2_session_mem_send(session_, &data);

    if(datalen < 0) {
      return -1;
    }
    if(datalen == 0) {
      break;
    }
    rv = evbuffer_add(output, data, datalen);
    if(rv == -1) {
      return -1;
    }
  }
  if(nghttp2_session_want_read(session_) == 0 &&
     nghttp2_session_want_write(session_) == 0 &&
     evbuffer_get_length(output) == 0) {
    return -1;
  }
  return 0;
}

void Http2Session::terminate()
{
  nghttp2_session_terminate_session(session_, NGHTTP2_NO_ERROR);
}

} // namespace h2load
