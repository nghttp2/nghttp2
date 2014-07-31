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
#include "shrpx_spdy_upstream.h"

#include <netinet/tcp.h>
#include <assert.h>
#include <cerrno>
#include <sstream>

#include <nghttp2/nghttp2.h>

#include "shrpx_client_handler.h"
#include "shrpx_downstream.h"
#include "shrpx_downstream_connection.h"
#include "shrpx_config.h"
#include "shrpx_http.h"
#include "shrpx_worker_config.h"
#include "http2.h"
#include "util.h"

using namespace nghttp2;

namespace shrpx {

namespace {
const size_t OUTBUF_MAX_THRES = 16*1024;
const size_t INBUF_MAX_THRES = 16*1024;
} // namespace

namespace {
ssize_t send_callback(spdylay_session *session,
                      const uint8_t *data, size_t len, int flags,
                      void *user_data)
{
  int rv;
  auto upstream = static_cast<SpdyUpstream*>(user_data);
  auto handler = upstream->get_client_handler();

  // Check buffer length and return WOULDBLOCK if it is large enough.
  if(handler->get_outbuf_length() + upstream->sendbuf.get_buflen() >=
     OUTBUF_MAX_THRES) {
    return SPDYLAY_ERR_WOULDBLOCK;
  }

  rv = upstream->sendbuf.add(data, len);
  if(rv != 0) {
    ULOG(FATAL, upstream) << "evbuffer_add() failed";
    return SPDYLAY_ERR_CALLBACK_FAILURE;
  }
  return len;
}
} // namespace

namespace {
ssize_t recv_callback(spdylay_session *session,
                      uint8_t *data, size_t len, int flags, void *user_data)
{
  auto upstream = static_cast<SpdyUpstream*>(user_data);
  auto handler = upstream->get_client_handler();
  auto bev = handler->get_bev();
  auto input = bufferevent_get_input(bev);
  int nread = evbuffer_remove(input, data, len);
  if(nread == -1) {
    return SPDYLAY_ERR_CALLBACK_FAILURE;
  } else if(nread == 0) {
    return SPDYLAY_ERR_WOULDBLOCK;
  } else {
    return nread;
  }
}
} // namespace

namespace {
void on_stream_close_callback
(spdylay_session *session, int32_t stream_id, spdylay_status_code status_code,
 void *user_data)
{
  auto upstream = static_cast<SpdyUpstream*>(user_data);
  if(LOG_ENABLED(INFO)) {
    ULOG(INFO, upstream) << "Stream stream_id=" << stream_id
                         << " is being closed";
  }
  auto downstream = upstream->find_downstream(stream_id);
  if(!downstream) {
    return;
  }

  if(downstream->get_request_state() == Downstream::CONNECT_FAIL) {
    upstream->remove_downstream(downstream);
    delete downstream;
    return;
  }

  downstream->set_request_state(Downstream::STREAM_CLOSED);
  if(downstream->get_response_state() == Downstream::MSG_COMPLETE) {
    // At this point, downstream response was read
    if(!downstream->get_upgraded() &&
       !downstream->get_response_connection_close()) {
      // Keep-alive
      auto dconn = downstream->get_downstream_connection();
      if(dconn) {
        dconn->detach_downstream(downstream);
      }
    }
    upstream->remove_downstream(downstream);
    delete downstream;
    return;
  }

  // At this point, downstream read may be paused.

  // If shrpx_downstream::push_request_headers() failed, the
  // error is handled here.
  upstream->remove_downstream(downstream);
  delete downstream;
  // How to test this case? Request sufficient large download
  // and make client send RST_STREAM after it gets first DATA
  // frame chunk.
}
} // namespace

namespace {
void on_ctrl_recv_callback
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  auto upstream = static_cast<SpdyUpstream*>(user_data);
  switch(type) {
  case SPDYLAY_SYN_STREAM: {
    if(LOG_ENABLED(INFO)) {
      ULOG(INFO, upstream) << "Received upstream SYN_STREAM stream_id="
                           << frame->syn_stream.stream_id;
    }
    auto downstream = new Downstream(upstream,
                                     frame->syn_stream.stream_id,
                                     frame->syn_stream.pri);
    upstream->add_downstream(downstream);
    downstream->init_response_body_buf();

    auto nv = frame->syn_stream.nv;
    const char *path = nullptr;
    const char *scheme = nullptr;
    const char *host = nullptr;
    const char *method = nullptr;
    const char *content_length = nullptr;
    const char *user_agent = nullptr;

    for(size_t i = 0; nv[i]; i += 2) {
      if(strcmp(nv[i], ":path") == 0) {
        path = nv[i+1];
      } else if(strcmp(nv[i], ":scheme") == 0) {
        scheme = nv[i+1];
      } else if(strcmp(nv[i], ":method") == 0) {
        method = nv[i+1];
      } else if(strcmp(nv[i], ":host") == 0) {
        host = nv[i+1];
      } else if(nv[i][0] != ':') {
        if(strcmp(nv[i], "content-length") == 0) {
          content_length = nv[i+1];
        } else if(strcmp(nv[i], "user-agent") == 0) {
          user_agent = nv[i+1];
        }
        downstream->add_request_header(nv[i], nv[i+1]);
      }
    }
    bool is_connect = method && strcmp("CONNECT", method) == 0;
    if(!path || !host || !method ||
       http2::lws(host) || http2::lws(path) || http2::lws(method) ||
       (!is_connect && (!scheme || http2::lws(scheme)))) {
      upstream->rst_stream(downstream, SPDYLAY_INTERNAL_ERROR);
      return;
    }
    // Require content-length if FIN flag is not set.
    if(!is_connect && !content_length &&
       (frame->syn_stream.hd.flags & SPDYLAY_CTRL_FLAG_FIN) == 0) {
      upstream->rst_stream(downstream, SPDYLAY_PROTOCOL_ERROR);
      return;
    }

    downstream->set_request_method(method);
    if(is_connect) {
      downstream->set_request_http2_authority(path);
    } else {
      downstream->set_request_http2_scheme(scheme);
      downstream->set_request_http2_authority(host);
      downstream->set_request_path(path);
    }

    if(user_agent) {
      downstream->set_request_user_agent(user_agent);
    }

    if(!(frame->syn_stream.hd.flags & SPDYLAY_CTRL_FLAG_FIN)) {
      downstream->set_request_http2_expect_body(true);
    }

    downstream->inspect_http2_request();

    if(LOG_ENABLED(INFO)) {
      std::stringstream ss;
      for(size_t i = 0; nv[i]; i += 2) {
        ss << TTY_HTTP_HD << nv[i] << TTY_RST << ": " << nv[i+1] << "\n";
      }
      ULOG(INFO, upstream) << "HTTP request headers. stream_id="
                           << downstream->get_stream_id()
                           << "\n" << ss.str();
    }

    auto dconn = upstream->get_client_handler()->get_downstream_connection();
    int rv = dconn->attach_downstream(downstream);
    if(rv != 0) {
      // If downstream connection fails, issue RST_STREAM.
      upstream->rst_stream(downstream, SPDYLAY_INTERNAL_ERROR);
      downstream->set_request_state(Downstream::CONNECT_FAIL);
      return;
    }
    rv = downstream->push_request_headers();
    if(rv != 0) {
      upstream->rst_stream(downstream, SPDYLAY_INTERNAL_ERROR);
      return;
    }
    downstream->set_request_state(Downstream::HEADER_COMPLETE);
    if(frame->syn_stream.hd.flags & SPDYLAY_CTRL_FLAG_FIN) {
      downstream->set_request_state(Downstream::MSG_COMPLETE);
    }
    break;
  }
  default:
    break;
  }
}
} // namespace

namespace {
void on_data_chunk_recv_callback(spdylay_session *session,
                                 uint8_t flags, int32_t stream_id,
                                 const uint8_t *data, size_t len,
                                 void *user_data)
{
  auto upstream = static_cast<SpdyUpstream*>(user_data);
  auto downstream = upstream->find_downstream(stream_id);

  if(!downstream) {
    upstream->handle_ign_data_chunk(len);
    return;
  }

  if(downstream->push_upload_data_chunk(data, len) != 0) {
    upstream->rst_stream(downstream, SPDYLAY_INTERNAL_ERROR);
    upstream->handle_ign_data_chunk(len);
    return;
  }

  if(!upstream->get_flow_control()) {
    return;
  }

  // If connection-level window control is not enabled (e.g,
  // spdy/3), spdylay_session_get_recv_data_length() is always
  // returns 0.
  if(spdylay_session_get_recv_data_length(session) >
     std::max(SPDYLAY_INITIAL_WINDOW_SIZE,
              1 << get_config()->http2_upstream_connection_window_bits)) {
    if(LOG_ENABLED(INFO)) {
      ULOG(INFO, upstream)
        << "Flow control error on connection: "
        << "recv_window_size="
        << spdylay_session_get_recv_data_length(session)
        << ", window_size="
        << (1 << get_config()->http2_upstream_connection_window_bits);
    }
    spdylay_session_fail_session(session, SPDYLAY_GOAWAY_PROTOCOL_ERROR);
    return;
  }
  if(spdylay_session_get_stream_recv_data_length(session, stream_id) >
     std::max(SPDYLAY_INITIAL_WINDOW_SIZE,
              1 << get_config()->http2_upstream_window_bits)) {
    if(LOG_ENABLED(INFO)) {
      ULOG(INFO, upstream)
        << "Flow control error: recv_window_size="
        << spdylay_session_get_stream_recv_data_length(session, stream_id)
        << ", initial_window_size="
        << (1 << get_config()->http2_upstream_window_bits);
    }
    upstream->rst_stream(downstream, SPDYLAY_FLOW_CONTROL_ERROR);
    return;
  }
}
} // namespace

namespace {
void on_data_recv_callback(spdylay_session *session, uint8_t flags,
                           int32_t stream_id, int32_t length, void *user_data)
{
  auto upstream = static_cast<SpdyUpstream*>(user_data);
  auto downstream = upstream->find_downstream(stream_id);
  if(downstream && (flags & SPDYLAY_DATA_FLAG_FIN)) {
    downstream->end_upload_data();
    downstream->set_request_state(Downstream::MSG_COMPLETE);
  }
}
} // namespace

namespace {
void on_ctrl_not_send_callback(spdylay_session *session,
                               spdylay_frame_type type,
                               spdylay_frame *frame,
                               int error_code, void *user_data)
{
  auto upstream = static_cast<SpdyUpstream*>(user_data);
  ULOG(WARNING, upstream) << "Failed to send control frame type=" << type
                          << ", error_code=" << error_code << ":"
                          << spdylay_strerror(error_code);
  if(type == SPDYLAY_SYN_REPLY) {
    // To avoid stream hanging around, issue RST_STREAM.
    auto stream_id = frame->syn_reply.stream_id;
    auto downstream = upstream->find_downstream(stream_id);
    if(downstream) {
      upstream->rst_stream(downstream, SPDYLAY_INTERNAL_ERROR);
    }
  }
}
} // namespace

namespace {
void on_ctrl_recv_parse_error_callback(spdylay_session *session,
                                       spdylay_frame_type type,
                                       const uint8_t *head, size_t headlen,
                                       const uint8_t *payload,
                                       size_t payloadlen, int error_code,
                                       void *user_data)
{
  auto upstream = static_cast<SpdyUpstream*>(user_data);
  if(LOG_ENABLED(INFO)) {
    ULOG(INFO, upstream) << "Failed to parse received control frame. type="
                         << type
                         << ", error_code=" << error_code << ":"
                         << spdylay_strerror(error_code);
  }
}
} // namespace

namespace {
void on_unknown_ctrl_recv_callback(spdylay_session *session,
                                   const uint8_t *head, size_t headlen,
                                   const uint8_t *payload, size_t payloadlen,
                                   void *user_data)
{
  auto upstream = static_cast<SpdyUpstream*>(user_data);
  if(LOG_ENABLED(INFO)) {
    ULOG(INFO, upstream) << "Received unknown control frame.";
  }
}
} // namespace

namespace {
// Infer upstream RST_STREAM status code from downstream HTTP/2
// error code.
uint32_t infer_upstream_rst_stream_status_code
(nghttp2_error_code downstream_error_code)
{
  // Only propagate *_REFUSED_STREAM so that upstream client can
  // resend request.
  if(downstream_error_code == NGHTTP2_REFUSED_STREAM) {
    return SPDYLAY_REFUSED_STREAM;
  } else {
    return SPDYLAY_INTERNAL_ERROR;
  }
}
} // namespace

SpdyUpstream::SpdyUpstream(uint16_t version, ClientHandler *handler)
  : handler_(handler),
    session_(nullptr),
    recv_ign_window_size_(0)
{
  //handler->set_bev_cb(spdy_readcb, 0, spdy_eventcb);
  handler->set_upstream_timeouts(&get_config()->http2_upstream_read_timeout,
                                 &get_config()->upstream_write_timeout);

  spdylay_session_callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = send_callback;
  callbacks.recv_callback = recv_callback;
  callbacks.on_stream_close_callback = on_stream_close_callback;
  callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback;
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks.on_data_recv_callback = on_data_recv_callback;
  callbacks.on_ctrl_not_send_callback = on_ctrl_not_send_callback;
  callbacks.on_ctrl_recv_parse_error_callback =
    on_ctrl_recv_parse_error_callback;
  callbacks.on_unknown_ctrl_recv_callback = on_unknown_ctrl_recv_callback;

  int rv;
  rv = spdylay_session_server_new(&session_, version, &callbacks, this);
  assert(rv == 0);

  if(version >= SPDYLAY_PROTO_SPDY3) {
    int val = 1;
    flow_control_ = true;
    initial_window_size_ = 1 << get_config()->http2_upstream_window_bits;
    rv = spdylay_session_set_option(session_,
                                    SPDYLAY_OPT_NO_AUTO_WINDOW_UPDATE, &val,
                                    sizeof(val));
    assert(rv == 0);
  } else {
    flow_control_ = false;
    initial_window_size_ = 0;
  }
  // TODO Maybe call from outside?
  spdylay_settings_entry entry[2];
  entry[0].settings_id = SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS;
  entry[0].value = get_config()->http2_max_concurrent_streams;
  entry[0].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;

  entry[1].settings_id = SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE;
  entry[1].value = initial_window_size_;
  entry[1].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;

  rv = spdylay_submit_settings
    (session_, SPDYLAY_FLAG_SETTINGS_NONE,
     entry, sizeof(entry)/sizeof(spdylay_settings_entry));
  assert(rv == 0);

  if(version >= SPDYLAY_PROTO_SPDY3_1 &&
     get_config()->http2_upstream_connection_window_bits > 16) {
    int32_t delta = (1 << get_config()->http2_upstream_connection_window_bits)
      - SPDYLAY_INITIAL_WINDOW_SIZE;
    rv = spdylay_submit_window_update(session_, 0, delta);
    assert(rv == 0);
  }

  // TODO Maybe call from outside?
  send();
}

SpdyUpstream::~SpdyUpstream()
{
  spdylay_session_del(session_);
}

int SpdyUpstream::on_read()
{
  int rv = 0;

  rv = spdylay_session_recv(session_);
  if(rv < 0) {
    if(rv != SPDYLAY_ERR_EOF) {
      ULOG(ERROR, this) << "spdylay_session_recv() returned error: "
                        << spdylay_strerror(rv);
    }
    return rv;
  }
  return send();
}

int SpdyUpstream::on_write()
{
  return send();
}

// After this function call, downstream may be deleted.
int SpdyUpstream::send()
{
  int rv = 0;
  uint8_t buf[16384];

  sendbuf.reset(bufferevent_get_output(handler_->get_bev()), buf, sizeof(buf));

  rv = spdylay_session_send(session_);
  if(rv != 0) {
    ULOG(ERROR, this) << "spdylay_session_send() returned error: "
                      << spdylay_strerror(rv);
    return rv;
  }

  rv = sendbuf.flush();
  if(rv != 0) {
    ULOG(FATAL, this) << "evbuffer_add() failed";
    return -1;
  }

  if(spdylay_session_want_read(session_) == 0 &&
     spdylay_session_want_write(session_) == 0 &&
     handler_->get_outbuf_length() == 0) {
    if(LOG_ENABLED(INFO)) {
      ULOG(INFO, this) << "No more read/write for this SPDY session";
    }
    return -1;
  }
  return 0;
}

int SpdyUpstream::on_event()
{
  return 0;
}

ClientHandler* SpdyUpstream::get_client_handler() const
{
  return handler_;
}

namespace {
void spdy_downstream_readcb(bufferevent *bev, void *ptr)
{
  auto dconn = static_cast<DownstreamConnection*>(ptr);
  auto downstream = dconn->get_downstream();
  auto upstream = static_cast<SpdyUpstream*>(downstream->get_upstream());
  if(downstream->get_request_state() == Downstream::STREAM_CLOSED) {
    // If upstream SPDY stream was closed, we just close downstream,
    // because there is no consumer now. Downstream connection is also
    // closed in this case.
    upstream->remove_downstream(downstream);
    delete downstream;
    return;
  }

  if(downstream->get_response_state() == Downstream::MSG_RESET) {
    // The downstream stream was reset (canceled). In this case,
    // RST_STREAM to the upstream and delete downstream connection
    // here. Deleting downstream will be taken place at
    // on_stream_close_callback.
    upstream->rst_stream(downstream, infer_upstream_rst_stream_status_code
                         (downstream->get_response_rst_stream_error_code()));
    downstream->set_downstream_connection(nullptr);
    delete dconn;
    dconn = nullptr;
  } else {
    auto rv = downstream->on_read();
    if(rv != 0) {
      if(LOG_ENABLED(INFO)) {
        DCLOG(INFO, dconn) << "HTTP parser failure";
      }
      if(downstream->get_response_state() == Downstream::HEADER_COMPLETE) {
        upstream->rst_stream(downstream, SPDYLAY_INTERNAL_ERROR);
      } else if(downstream->get_response_state() != Downstream::MSG_COMPLETE) {
        // If response was completed, then don't issue RST_STREAM
        if(upstream->error_reply(downstream, 502) != 0) {
          delete upstream->get_client_handler();
          return;
        }
      }
      downstream->set_response_state(Downstream::MSG_COMPLETE);
      // Clearly, we have to close downstream connection on http parser
      // failure.
      downstream->set_downstream_connection(nullptr);
      delete dconn;
      dconn = nullptr;
    }
  }
  if(upstream->send() != 0) {
    delete upstream->get_client_handler();
    return;
  }
  // At this point, downstream may be deleted.
}
} // namespace

namespace {
void spdy_downstream_writecb(bufferevent *bev, void *ptr)
{
  if(evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
    return;
  }
  auto dconn = static_cast<DownstreamConnection*>(ptr);
  auto downstream = dconn->get_downstream();
  auto upstream = static_cast<SpdyUpstream*>(downstream->get_upstream());
  upstream->resume_read(SHRPX_NO_BUFFER, downstream);
}
} // namespace

namespace {
void spdy_downstream_eventcb(bufferevent *bev, short events, void *ptr)
{
  auto dconn = static_cast<DownstreamConnection*>(ptr);
  auto downstream = dconn->get_downstream();
  auto upstream = static_cast<SpdyUpstream*>(downstream->get_upstream());

  if(events & BEV_EVENT_CONNECTED) {
    if(LOG_ENABLED(INFO)) {
      DCLOG(INFO, dconn) << "Connection established. stream_id="
                         << downstream->get_stream_id();
    }
    int fd = bufferevent_getfd(bev);
    int val = 1;
    if(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                  reinterpret_cast<char *>(&val), sizeof(val)) == -1) {
      DCLOG(WARNING, dconn) << "Setting option TCP_NODELAY failed: errno="
                            << errno;
    }
    return;
  }

  if(events & BEV_EVENT_EOF) {
    if(LOG_ENABLED(INFO)) {
      DCLOG(INFO, dconn) << "EOF. stream_id=" << downstream->get_stream_id();
    }
    if(downstream->get_request_state() == Downstream::STREAM_CLOSED) {
      // If stream was closed already, we don't need to send reply at
      // the first place. We can delete downstream.
      upstream->remove_downstream(downstream);
      delete downstream;
      return;
    }

    // Delete downstream connection. If we don't delete it here, it
    // will be pooled in on_stream_close_callback.
    downstream->set_downstream_connection(nullptr);
    delete dconn;
    dconn = nullptr;
    // downstream wil be deleted in on_stream_close_callback.
    if(downstream->get_response_state() == Downstream::HEADER_COMPLETE) {
      // Server may indicate the end of the request by EOF
      if(LOG_ENABLED(INFO)) {
        ULOG(INFO, upstream) << "Downstream body was ended by EOF";
      }
      downstream->set_response_state(Downstream::MSG_COMPLETE);

      // For tunneled connection, MSG_COMPLETE signals
      // spdy_data_read_callback to send RST_STREAM after pending
      // response body is sent. This is needed to ensure that
      // RST_STREAM is sent after all pending data are sent.
      upstream->on_downstream_body_complete(downstream);
    } else if(downstream->get_response_state() != Downstream::MSG_COMPLETE) {
      // If stream was not closed, then we set MSG_COMPLETE and let
      // on_stream_close_callback delete downstream.
      if(upstream->error_reply(downstream, 502) != 0) {
        delete upstream->get_client_handler();
        return;
      }
      downstream->set_response_state(Downstream::MSG_COMPLETE);
    }
    if(upstream->send() != 0) {
      delete upstream->get_client_handler();
      return;
    }
    // At this point, downstream may be deleted.

    return;
  }

  if(events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
    if(LOG_ENABLED(INFO)) {
      if(events & BEV_EVENT_ERROR) {
        DCLOG(INFO, dconn) << "Downstream network error: "
                           << evutil_socket_error_to_string
          (EVUTIL_SOCKET_ERROR());
      } else {
        DCLOG(INFO, dconn) << "Timeout";
      }
      if(downstream->get_upgraded()) {
        DCLOG(INFO, dconn) << "Note: this is tunnel connection";
      }
    }
    if(downstream->get_request_state() == Downstream::STREAM_CLOSED) {
      upstream->remove_downstream(downstream);
      delete downstream;
      return;
    }

    // Delete downstream connection. If we don't delete it here, it
    // will be pooled in on_stream_close_callback.
    downstream->set_downstream_connection(nullptr);
    delete dconn;
    dconn = nullptr;

    if(downstream->get_response_state() == Downstream::MSG_COMPLETE) {
      // For SSL tunneling, we issue RST_STREAM. For other types of
      // stream, we don't have to do anything since response was
      // complete.
      if(downstream->get_upgraded()) {
        upstream->rst_stream(downstream, SPDYLAY_INTERNAL_ERROR);
      }
    } else {
      if(downstream->get_response_state() == Downstream::HEADER_COMPLETE) {
        upstream->rst_stream(downstream, SPDYLAY_INTERNAL_ERROR);
      } else {
        unsigned int status;
        if(events & BEV_EVENT_TIMEOUT) {
          status = 504;
        } else {
          status = 502;
        }
        if(upstream->error_reply(downstream, status) != 0) {
          delete upstream->get_client_handler();
          return;
        }
      }
      downstream->set_response_state(Downstream::MSG_COMPLETE);
    }
    if(upstream->send() != 0) {
      delete upstream->get_client_handler();
      return;
    }
    // At this point, downstream may be deleted.
    return;
  }
}
} // namespace

int SpdyUpstream::rst_stream(Downstream *downstream, int status_code)
{
  if(LOG_ENABLED(INFO)) {
    ULOG(INFO, this) << "RST_STREAM stream_id="
                     << downstream->get_stream_id();
  }
  int rv;
  rv = spdylay_submit_rst_stream(session_, downstream->get_stream_id(),
                                 status_code);
  if(rv < SPDYLAY_ERR_FATAL) {
    ULOG(FATAL, this) << "spdylay_submit_rst_stream() failed: "
                      << spdylay_strerror(rv);
    DIE();
  }
  return 0;
}

int SpdyUpstream::window_update(Downstream *downstream, int32_t delta)
{
  int rv;
  int32_t stream_id;

  if(downstream) {
    stream_id = downstream->get_stream_id();
  } else {
    stream_id = 0;
    recv_ign_window_size_ = 0;
  }

  rv = spdylay_submit_window_update(session_, stream_id, delta);

  if(rv < SPDYLAY_ERR_FATAL) {
    ULOG(FATAL, this) << "spdylay_submit_window_update() failed: "
                      << spdylay_strerror(rv);
    DIE();
  }
  return 0;
}

namespace {
ssize_t spdy_data_read_callback(spdylay_session *session,
                                int32_t stream_id,
                                uint8_t *buf, size_t length,
                                int *eof,
                                spdylay_data_source *source,
                                void *user_data)
{
  auto downstream = static_cast<Downstream*>(source->ptr);
  auto upstream = static_cast<SpdyUpstream*>(downstream->get_upstream());
  auto body = downstream->get_response_body_buf();
  assert(body);
  int nread = evbuffer_remove(body, buf, length);
  if(nread == -1) {
    ULOG(FATAL, upstream) << "evbuffer_remove() failed";
    return SPDYLAY_ERR_CALLBACK_FAILURE;
  }
  if(nread == 0 &&
     downstream->get_response_state() == Downstream::MSG_COMPLETE) {
    if(!downstream->get_upgraded()) {
      *eof = 1;

      upstream_accesslog(upstream->get_client_handler()->get_ipaddr(),
                         downstream->get_response_http_status(), downstream);
    } else {
      // For tunneling, issue RST_STREAM to finish the stream.
      if(LOG_ENABLED(INFO)) {
        ULOG(INFO, upstream) << "RST_STREAM to tunneled stream stream_id="
                             << stream_id;
      }
      upstream->rst_stream(downstream, infer_upstream_rst_stream_status_code
                           (downstream->get_response_rst_stream_error_code()));
    }
  }

  if(nread == 0 && *eof != 1) {
    if(downstream->resume_read(SHRPX_NO_BUFFER) != 0) {
      return SPDYLAY_ERR_CALLBACK_FAILURE;
    }

    return SPDYLAY_ERR_DEFERRED;
  }

  return nread;
}
} // namespace

int SpdyUpstream::error_reply(Downstream *downstream, unsigned int status_code)
{
  int rv;
  auto html = http::create_error_html(status_code);
  downstream->set_response_http_status(status_code);
  downstream->init_response_body_buf();
  auto body = downstream->get_response_body_buf();
  rv = evbuffer_add(body, html.c_str(), html.size());
  if(rv == -1) {
    ULOG(FATAL, this) << "evbuffer_add() failed";
    return -1;
  }
  downstream->set_response_state(Downstream::MSG_COMPLETE);

  spdylay_data_provider data_prd;
  data_prd.source.ptr = downstream;
  data_prd.read_callback = spdy_data_read_callback;

  std::string content_length = util::utos(html.size());
  std::string status_string = http2::get_status_string(status_code);
  const char *nv[] = {
    ":status", status_string.c_str(),
    ":version", "http/1.1",
    "content-type", "text/html; charset=UTF-8",
    "server", get_config()->server_name,
    "content-length", content_length.c_str(),
    nullptr
  };

  rv = spdylay_submit_response(session_, downstream->get_stream_id(), nv,
                               &data_prd);
  if(rv < SPDYLAY_ERR_FATAL) {
    ULOG(FATAL, this) << "spdylay_submit_response() failed: "
                      << spdylay_strerror(rv);
    DIE();
  }

  return 0;
}

bufferevent_data_cb SpdyUpstream::get_downstream_readcb()
{
  return spdy_downstream_readcb;
}

bufferevent_data_cb SpdyUpstream::get_downstream_writecb()
{
  return spdy_downstream_writecb;
}

bufferevent_event_cb SpdyUpstream::get_downstream_eventcb()
{
  return spdy_downstream_eventcb;
}

void SpdyUpstream::add_downstream(Downstream *downstream)
{
  downstream_queue_.add(downstream);
}

void SpdyUpstream::remove_downstream(Downstream *downstream)
{
  downstream_queue_.remove(downstream);
}

Downstream* SpdyUpstream::find_downstream(int32_t stream_id)
{
  return downstream_queue_.find(stream_id);
}

spdylay_session* SpdyUpstream::get_http2_session()
{
  return session_;
}

// WARNING: Never call directly or indirectly spdylay_session_send or
// spdylay_session_recv. These calls may delete downstream.
int SpdyUpstream::on_downstream_header_complete(Downstream *downstream)
{
  if(downstream->get_non_final_response()) {
    // SPDY does not support non-final response.  We could send it
    // with HEADERS and final response in SYN_REPLY, but it is not
    // official way.
    downstream->clear_response_headers();

    return 0;
  }

  if(LOG_ENABLED(INFO)) {
    DLOG(INFO, downstream) << "HTTP response header completed";
  }
  downstream->normalize_response_headers();
  if(!get_config()->http2_proxy && !get_config()->client_proxy) {
    downstream->rewrite_norm_location_response_header
      (get_client_handler()->get_upstream_scheme(), get_config()->port);
  }
  size_t nheader = downstream->get_response_headers().size();
  // 6 means :status, :version and possible via header field.
  auto nv = util::make_unique<const char*[]>
    (nheader * 2 + 6 + get_config()->add_response_headers.size() * 2 + 1);

  size_t hdidx = 0;
  std::string via_value;
  std::string status_string = http2::get_status_string
    (downstream->get_response_http_status());
  nv[hdidx++] = ":status";
  nv[hdidx++] = status_string.c_str();
  nv[hdidx++] = ":version";
  nv[hdidx++] = "HTTP/1.1";
  for(auto& hd : downstream->get_response_headers()) {
    if(hd.name.empty() || hd.name.c_str()[0] == ':' ||
       util::strieq(hd.name.c_str(), "transfer-encoding") ||
       util::strieq(hd.name.c_str(), "keep-alive") || // HTTP/1.0?
       util::strieq(hd.name.c_str(), "connection") ||
       util::strieq(hd.name.c_str(), "proxy-connection")) {
      // These are ignored
    } else if(!get_config()->no_via &&
              util::strieq(hd.name.c_str(), "via")) {
      via_value = hd.value;
    } else {
      nv[hdidx++] = hd.name.c_str();
      nv[hdidx++] = hd.value.c_str();
    }
  }
  if(!get_config()->no_via) {
    if(!via_value.empty()) {
      via_value += ", ";
    }
    via_value += http::create_via_header_value
      (downstream->get_response_major(), downstream->get_response_minor());
    nv[hdidx++] = "via";
    nv[hdidx++] = via_value.c_str();
  }

  for(auto& p : get_config()->add_response_headers) {
    nv[hdidx++] = p.first.c_str();
    nv[hdidx++] = p.second.c_str();
  }

  nv[hdidx++] = 0;
  if(LOG_ENABLED(INFO)) {
    std::stringstream ss;
    for(size_t i = 0; nv[i]; i += 2) {
      ss << TTY_HTTP_HD << nv[i] << TTY_RST << ": " << nv[i+1] << "\n";
    }
    ULOG(INFO, this) << "HTTP response headers. stream_id="
                     << downstream->get_stream_id() << "\n"
                     << ss.str();
  }
  spdylay_data_provider data_prd;
  data_prd.source.ptr = downstream;
  data_prd.read_callback = spdy_data_read_callback;

  int rv;
  rv = spdylay_submit_response(session_, downstream->get_stream_id(), nv.get(),
                               &data_prd);
  if(rv != 0) {
    ULOG(FATAL, this) << "spdylay_submit_response() failed";
    return -1;
  }

  if(downstream->get_upgraded()) {
    upstream_accesslog(get_client_handler()->get_ipaddr(),
                       downstream->get_response_http_status(), downstream);
  }

  downstream->clear_response_headers();

  return 0;
}

// WARNING: Never call directly or indirectly spdylay_session_send or
// spdylay_session_recv. These calls may delete downstream.
int SpdyUpstream::on_downstream_body(Downstream *downstream,
                                     const uint8_t *data, size_t len,
                                     bool flush)
{
  auto body = downstream->get_response_body_buf();
  int rv = evbuffer_add(body, data, len);
  if(rv != 0) {
    ULOG(FATAL, this) << "evbuffer_add() failed";
    return -1;
  }

  if(flush) {
    spdylay_session_resume_data(session_, downstream->get_stream_id());
  }

  if(evbuffer_get_length(body) >= INBUF_MAX_THRES) {
    if(!flush) {
      spdylay_session_resume_data(session_, downstream->get_stream_id());
    }

    downstream->pause_read(SHRPX_NO_BUFFER);
  }

  return 0;
}

// WARNING: Never call directly or indirectly spdylay_session_send or
// spdylay_session_recv. These calls may delete downstream.
int SpdyUpstream::on_downstream_body_complete(Downstream *downstream)
{
  if(LOG_ENABLED(INFO)) {
    DLOG(INFO, downstream) << "HTTP response completed";
  }
  spdylay_session_resume_data(session_, downstream->get_stream_id());
  return 0;
}

bool SpdyUpstream::get_flow_control() const
{
  return flow_control_;
}

void SpdyUpstream::pause_read(IOCtrlReason reason)
{}

namespace {
int32_t determine_window_update_transmission(spdylay_session *session,
                                             int32_t stream_id)
{
  int32_t recv_length, window_size;
  if(stream_id == 0) {
    recv_length = spdylay_session_get_recv_data_length(session);
    window_size = 1 << get_config()->http2_upstream_connection_window_bits;
  } else {
    recv_length = spdylay_session_get_stream_recv_data_length
      (session, stream_id);
    window_size = 1 << get_config()->http2_upstream_window_bits;
  }
  if(recv_length != -1 && recv_length >= window_size / 2) {
    return recv_length;
  }
  return -1;
}
} // namespace

int SpdyUpstream::resume_read(IOCtrlReason reason, Downstream *downstream)
{
  if(get_flow_control()) {
    int32_t delta;
    delta = determine_window_update_transmission(session_, 0);
    if(delta != -1) {
      window_update(0, delta);
    }
    delta = determine_window_update_transmission
      (session_, downstream->get_stream_id());
    if(delta != -1) {
      window_update(downstream, delta);
    }
  }
  return send();
}

int SpdyUpstream::on_downstream_abort_request(Downstream *downstream,
                                              unsigned int status_code)
{
  int rv;

  rv = error_reply(downstream, status_code);

  if(rv != 0) {
    return -1;
  }

  return send();
}

int SpdyUpstream::handle_ign_data_chunk(size_t len)
{
  int32_t window_size;

  if(spdylay_session_get_recv_data_length(session_) == -1) {
    // No connection flow control
    return 0;
  }

  window_size = 1 << get_config()->http2_upstream_connection_window_bits;

  if(recv_ign_window_size_ >= window_size / 2) {
    window_update(0, recv_ign_window_size_);
  }

  return 0;
}

} // namespace shrpx
