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
#include "h2load_spdy_session.h"

#include "h2load.h"

namespace h2load {

SpdySession::SpdySession(Client *client, uint16_t spdy_version)
  : client_(client),
    session_(nullptr),
    spdy_version_(spdy_version)
{}

SpdySession::~SpdySession()
{
  spdylay_session_del(session_);
}

namespace {
void before_ctrl_send_callback
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  auto client = static_cast<Client*>(user_data);
  if(type != SPDYLAY_SYN_STREAM) {
    return;
  }
  client->on_request(frame->syn_stream.stream_id);
}
} // namespace

namespace {
void on_ctrl_recv_callback(spdylay_session *session,
                           spdylay_frame_type type,
                           spdylay_frame *frame,
                           void *user_data)
{
  auto client = static_cast<Client*>(user_data);
  if(type != SPDYLAY_SYN_REPLY) {
    return;
  }
  for(auto p = frame->syn_reply.nv; *p; p += 2) {
    auto name = *p;
    auto value = *(p + 1);
    client->on_header(frame->syn_reply.stream_id,
                      reinterpret_cast<const uint8_t*>(name),
                      strlen(name),
                      reinterpret_cast<const uint8_t*>(value),
                      strlen(value));
  }
  client->worker->stats.bytes_head += frame->syn_reply.hd.length;
}
} // namespace

namespace {
void on_data_chunk_recv_callback
(spdylay_session *session, uint8_t flags, int32_t stream_id,
 const uint8_t *data, size_t len, void *user_data)
{
  auto client = static_cast<Client*>(user_data);
  client->worker->stats.bytes_body += len;

  auto spdy_session = static_cast<SpdySession*>(client->session.get());

  spdy_session->handle_window_update(stream_id, len);
}
} // namespace

namespace {
void on_stream_close_callback
(spdylay_session *session, int32_t stream_id, spdylay_status_code status_code,
 void *user_data)
{
  auto client = static_cast<Client*>(user_data);
  client->on_stream_close(stream_id, status_code == SPDYLAY_OK);
}
} // namespace

namespace {
ssize_t send_callback(spdylay_session *session,
                      const uint8_t *data, size_t length, int flags,
                      void *user_data)
{
  auto client = static_cast<Client*>(user_data);
  auto spdy_session = static_cast<SpdySession*>(client->session.get());
  int rv;

  rv = spdy_session->sendbuf.add(data, length);
  if(rv != 0) {
    return SPDYLAY_ERR_CALLBACK_FAILURE;
  }
  return length;
}
} //namespace

void SpdySession::on_connect()
{
  spdylay_session_callbacks callbacks = {0};
  callbacks.send_callback = send_callback;
  callbacks.before_ctrl_send_callback = before_ctrl_send_callback;
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks.on_stream_close_callback = on_stream_close_callback;
  callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback;

  spdylay_session_client_new(&session_, spdy_version_, &callbacks, client_);

  int val = 1;
  spdylay_session_set_option(session_, SPDYLAY_OPT_NO_AUTO_WINDOW_UPDATE,
                             &val, sizeof(val));

  spdylay_settings_entry iv[1];
  iv[0].settings_id = SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[0].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;
  iv[0].value = (1 << client_->worker->config->window_bits);
  spdylay_submit_settings(session_, SPDYLAY_FLAG_SETTINGS_NONE, iv,
                          sizeof(iv) / sizeof(iv[0]));

  auto config = client_->worker->config;

  if(spdy_version_ >= SPDYLAY_PROTO_SPDY3_1 &&
     config->connection_window_bits > 16) {
    auto delta = (1 << config->connection_window_bits)
      - SPDYLAY_INITIAL_WINDOW_SIZE;
    spdylay_submit_window_update(session_, 0, delta);
  }
}

void SpdySession::submit_request()
{
  spdylay_submit_request(session_, 0, client_->worker->config->nv.data(),
                         nullptr, nullptr);
}

ssize_t SpdySession::on_read()
{
  int rv;
  auto input = bufferevent_get_input(client_->bev);
  auto inputlen = evbuffer_get_length(input);
  auto mem = evbuffer_pullup(input, -1);

  rv = spdylay_session_mem_recv(session_, mem, inputlen);
  if(rv < 0) {
    return -1;
  }
  evbuffer_drain(input, rv);
  return rv;
}

int SpdySession::on_write()
{
  int rv;
  uint8_t buf[4096];

  sendbuf.reset(bufferevent_get_output(client_->bev), buf, sizeof(buf));

  rv = spdylay_session_send(session_);
  if(rv != 0) {
    return -1;
  }

  rv = sendbuf.flush();
  if(rv != 0) {
    return -1;
  }

  if(spdylay_session_want_read(session_) == 0 &&
     spdylay_session_want_write(session_) == 0 &&
     evbuffer_get_length(bufferevent_get_output(client_->bev)) == 0) {
    return -1;
  }
  return 0;
}

void SpdySession::terminate()
{
  spdylay_session_fail_session(session_, SPDYLAY_OK);
}

namespace {
int32_t determine_window_update_transmission(spdylay_session *session,
                                             int32_t stream_id,
                                             size_t window_bits)
{
  int32_t recv_length;

  if(stream_id == 0) {
    recv_length = spdylay_session_get_recv_data_length(session);
  } else {
    recv_length = spdylay_session_get_stream_recv_data_length
      (session, stream_id);
  }

  auto window_size = 1 << window_bits;

  if(recv_length != -1 && recv_length >= window_size / 2) {
    return recv_length;
  }

  return -1;
}
} // namespace

void SpdySession::handle_window_update(int32_t stream_id, size_t recvlen)
{
  auto config = client_->worker->config;
  size_t connection_window_bits;

  if(config->connection_window_bits > 16) {
    connection_window_bits = config->connection_window_bits;
  } else {
    connection_window_bits = 16;
  }

  auto delta = determine_window_update_transmission
    (session_, 0, connection_window_bits);
  if(delta > 0) {
    spdylay_submit_window_update(session_, 0, delta);
  }

  delta = determine_window_update_transmission
    (session_, stream_id, config->window_bits);
  if(delta > 0) {
    spdylay_submit_window_update(session_, stream_id, delta);
  }
}

} // namespace h2load
