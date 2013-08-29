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
#include "shrpx_http2_upstream.h"

#include <netinet/tcp.h>
#include <assert.h>
#include <cerrno>
#include <sstream>

#include "shrpx_client_handler.h"
#include "shrpx_https_upstream.h"
#include "shrpx_downstream.h"
#include "shrpx_downstream_connection.h"
#include "shrpx_config.h"
#include "shrpx_http.h"
#include "shrpx_accesslog.h"
#include "http2.h"
#include "util.h"
#include "base64.h"

using namespace nghttp2;

namespace shrpx {

namespace {
const size_t SHRPX_SPDY_UPSTREAM_OUTPUT_UPPER_THRES = 64*1024;
} // namespace

namespace {
ssize_t send_callback(nghttp2_session *session,
                      const uint8_t *data, size_t len, int flags,
                      void *user_data)
{
  int rv;
  Http2Upstream *upstream = reinterpret_cast<Http2Upstream*>(user_data);
  ClientHandler *handler = upstream->get_client_handler();
  bufferevent *bev = handler->get_bev();
  evbuffer *output = bufferevent_get_output(bev);
  // Check buffer length and return WOULDBLOCK if it is large enough.
  if(evbuffer_get_length(output) > SHRPX_SPDY_UPSTREAM_OUTPUT_UPPER_THRES) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }

  rv = evbuffer_add(output, data, len);
  if(rv == -1) {
    ULOG(FATAL, upstream) << "evbuffer_add() failed";
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  } else {
    return len;
  }
}
} // namespace

namespace {
ssize_t recv_callback(nghttp2_session *session,
                      uint8_t *data, size_t len, int flags, void *user_data)
{
  Http2Upstream *upstream = reinterpret_cast<Http2Upstream*>(user_data);
  ClientHandler *handler = upstream->get_client_handler();
  bufferevent *bev = handler->get_bev();
  evbuffer *input = bufferevent_get_input(bev);
  int nread = evbuffer_remove(input, data, len);
  if(nread == -1) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  } else if(nread == 0) {
    return NGHTTP2_ERR_WOULDBLOCK;
  } else {
    return nread;
  }
}
} // namespace

namespace {
void on_stream_close_callback
(nghttp2_session *session, int32_t stream_id, nghttp2_error_code error_code,
 void *user_data)
{
  Http2Upstream *upstream = reinterpret_cast<Http2Upstream*>(user_data);
  if(LOG_ENABLED(INFO)) {
    ULOG(INFO, upstream) << "Stream stream_id=" << stream_id
                         << " is being closed";
  }
  Downstream *downstream = upstream->find_downstream(stream_id);
  if(downstream) {
    if(downstream->get_request_state() == Downstream::CONNECT_FAIL) {
      upstream->remove_downstream(downstream);
      delete downstream;
    } else {
      downstream->set_request_state(Downstream::STREAM_CLOSED);
      if(downstream->get_response_state() == Downstream::MSG_COMPLETE) {
        // At this point, downstream response was read
        if(!downstream->get_upgraded() &&
           !downstream->get_response_connection_close()) {
          // Keep-alive
          DownstreamConnection *dconn;
          dconn = downstream->get_downstream_connection();
          if(dconn) {
            dconn->detach_downstream(downstream);
          }
        }
        upstream->remove_downstream(downstream);
        delete downstream;
      } else {
        // At this point, downstream read may be paused.

        // If shrpx_downstream::push_request_headers() failed, the
        // error is handled here.
        upstream->remove_downstream(downstream);
        delete downstream;
        // How to test this case? Request sufficient large download
        // and make client send RST_STREAM after it gets first DATA
        // frame chunk.
      }
    }
  }
}
} // namespace

int Http2Upstream::upgrade_upstream(HttpsUpstream *http)
{
  int rv;
  std::string settings_payload;
  auto downstream = http->get_downstream();
  for(auto& hd : downstream->get_request_headers()) {
    if(util::strieq(hd.first.c_str(), "http2-settings")) {
      auto val = hd.second;
      util::to_base64(val);
      settings_payload = base64::decode(std::begin(val), std::end(val));
      break;
    }
  }
  rv = nghttp2_session_upgrade
    (session_,
     reinterpret_cast<const uint8_t*>(settings_payload.c_str()),
     settings_payload.size(),
     nullptr);
  if(rv != 0) {
    ULOG(WARNING, this) << "nghttp2_session_upgrade() returned error: "
                        << nghttp2_strerror(rv);
    return -1;
  }
  pre_upstream_ = http;
  http->pop_downstream();
  downstream->reset_upstream(this);
  add_downstream(downstream);
  downstream->init_response_body_buf();
  downstream->set_stream_id(1);
  downstream->set_priority(0);

  return 0;
}

namespace {
int on_frame_recv_callback
(nghttp2_session *session, nghttp2_frame *frame, void *user_data)
{
  auto upstream = reinterpret_cast<Http2Upstream*>(user_data);
  switch(frame->hd.type) {
  case NGHTTP2_HEADERS: {
    if(frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
      break;
    }
    if(LOG_ENABLED(INFO)) {
      ULOG(INFO, upstream) << "Received upstream request HEADERS stream_id="
                           << frame->hd.stream_id;
    }
    auto downstream = new Downstream(upstream,
                                     frame->hd.stream_id,
                                     frame->headers.pri);
    upstream->add_downstream(downstream);
    downstream->init_response_body_buf();

    auto nva = frame->headers.nva;
    auto nvlen = frame->headers.nvlen;

    if(LOG_ENABLED(INFO)) {
      std::stringstream ss;
      for(size_t i = 0; i < frame->headers.nvlen; ++i) {
        ss << TTY_HTTP_HD;
        ss.write(reinterpret_cast<char*>(nva[i].name), nva[i].namelen);
        ss << TTY_RST << ": ";
        ss.write(reinterpret_cast<char*>(nva[i].value), nva[i].valuelen);
        ss << "\n";
      }
      ULOG(INFO, upstream) << "HTTP request headers. stream_id="
                           << downstream->get_stream_id()
                           << "\n" << ss.str();
    }

    // Assuming that nva is sorted by name.
    if(!http2::check_http2_headers(nva, nvlen)) {
      upstream->rst_stream(downstream, NGHTTP2_PROTOCOL_ERROR);
      return 0;
    }

    for(size_t i = 0; i < nvlen; ++i) {
      if(nva[i].namelen > 0 && nva[i].name[0] != ':') {
        downstream->add_request_header(http2::name_to_str(&nva[i]),
                                       http2::value_to_str(&nva[i]));
      }
    }

    auto host = http2::get_unique_header(nva, nvlen, ":host");
    auto path = http2::get_unique_header(nva, nvlen, ":path");
    auto method = http2::get_unique_header(nva, nvlen, ":method");
    auto scheme = http2::get_unique_header(nva, nvlen, ":scheme");
    bool is_connect = method &&
      util::streq("CONNECT", method->value, method->valuelen);
    if(!host || !path || !method ||
       http2::value_lws(host) || http2::value_lws(path) ||
       http2::value_lws(method) ||
       (!is_connect && (!scheme || http2::value_lws(scheme)))) {
      upstream->rst_stream(downstream, NGHTTP2_PROTOCOL_ERROR);
      return 0;
    }
    if(!is_connect &&
       (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == 0) {
      auto content_length = http2::get_header(nva, nvlen, "content-length");
      if(!content_length || http2::value_lws(content_length)) {
        // If content-length is missing,
        // Downstream::push_upload_data_chunk will fail and
        upstream->rst_stream(downstream, NGHTTP2_PROTOCOL_ERROR);
        return 0;
      }
    }

    downstream->set_request_method(http2::value_to_str(method));

    // SpdyDownstreamConnection examines request path to find
    // scheme. We construct abs URI for spdy_bridge mode as well as
    // spdy_proxy mode.
    if((get_config()->spdy_proxy || get_config()->spdy_bridge) &&
       scheme && path->value[0] == '/') {
      std::string reqpath(http2::value_to_str(scheme));
      reqpath += "://";
      reqpath += http2::value_to_str(host);
      reqpath += http2::value_to_str(path);
      downstream->set_request_path(reqpath);
    } else {
      downstream->set_request_path(http2::value_to_str(path));
    }
    downstream->add_request_header("host", http2::value_to_str(host));
    downstream->check_upgrade_request();

    auto dconn = upstream->get_client_handler()->get_downstream_connection();
    int rv = dconn->attach_downstream(downstream);
    if(rv != 0) {
      // If downstream connection fails, issue RST_STREAM.
      upstream->rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
      downstream->set_request_state(Downstream::CONNECT_FAIL);
      return 0;
    }
    rv = downstream->push_request_headers();
    if(rv != 0) {
      upstream->rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
      return 0;
    }
    downstream->set_request_state(Downstream::HEADER_COMPLETE);
    if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      downstream->set_request_state(Downstream::MSG_COMPLETE);
    }
    break;
  }
  default:
    break;
  }
  return 0;
}
} // namespace

namespace {
int on_data_chunk_recv_callback(nghttp2_session *session,
                                uint8_t flags, int32_t stream_id,
                                const uint8_t *data, size_t len,
                                void *user_data)
{
  Http2Upstream *upstream = reinterpret_cast<Http2Upstream*>(user_data);
  Downstream *downstream = upstream->find_downstream(stream_id);
  if(downstream) {
    if(downstream->push_upload_data_chunk(data, len) != 0) {
      upstream->rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
      return 0;
    }
    if(upstream->get_flow_control()) {
      downstream->inc_recv_window_size(len);
      // In case that user specified initial window size is smaller
      // than default one and avoid stream tear down for the first
      // request due to race condition, we allow at least default
      // initial window size.
      if(downstream->get_recv_window_size() >
         std::max(NGHTTP2_INITIAL_WINDOW_SIZE,
                  upstream->get_initial_window_size())) {
        if(LOG_ENABLED(INFO)) {
          ULOG(INFO, upstream) << "Flow control error: recv_window_size="
                               << downstream->get_recv_window_size()
                               << ", initial_window_size="
                               << upstream->get_initial_window_size();
        }
        upstream->rst_stream(downstream, NGHTTP2_FLOW_CONTROL_ERROR);
        return 0;
      }
    }
    if(flags & NGHTTP2_FLAG_END_STREAM) {
      downstream->set_request_state(Downstream::MSG_COMPLETE);
    }
  }
  return 0;
}
} // namespace

namespace {
int on_frame_not_send_callback(nghttp2_session *session,
                               nghttp2_frame *frame,
                               int lib_error_code, void *user_data)
{
  auto upstream = reinterpret_cast<Http2Upstream*>(user_data);
  ULOG(WARNING, upstream) << "Failed to send control frame type="
                          << static_cast<uint32_t>(frame->hd.type)
                          << ", lib_error_code=" << lib_error_code << ":"
                          << nghttp2_strerror(lib_error_code);
  if(frame->hd.type == NGHTTP2_HEADERS &&
     frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
    // To avoid stream hanging around, issue RST_STREAM.
    auto downstream = upstream->find_downstream(frame->hd.stream_id);
    if(downstream) {
      upstream->rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
    }
  }
  return 0;
}
} // namespace

namespace {
void on_frame_recv_parse_error_callback(nghttp2_session *session,
                                        nghttp2_frame_type type,
                                        const uint8_t *head, size_t headlen,
                                        const uint8_t *payload,
                                        size_t payloadlen, int lib_error_code,
                                        void *user_data)
{
  auto upstream = reinterpret_cast<Http2Upstream*>(user_data);
  if(LOG_ENABLED(INFO)) {
    ULOG(INFO, upstream) << "Failed to parse received control frame. type="
                         << type
                         << ", error_code=" << lib_error_code << ":"
                         << nghttp2_strerror(lib_error_code);
  }
}
} // namespace

namespace {
void on_unknown_frame_recv_callback(nghttp2_session *session,
                                    const uint8_t *head, size_t headlen,
                                    const uint8_t *payload, size_t payloadlen,
                                    void *user_data)
{
  auto upstream = reinterpret_cast<Http2Upstream*>(user_data);
  if(LOG_ENABLED(INFO)) {
    ULOG(INFO, upstream) << "Received unknown control frame.";
  }
}
} // namespace

namespace {
nghttp2_error_code infer_upstream_rst_stream_error_code
(nghttp2_error_code downstream_error_code)
{
  // Only propagate NGHTTP2_REFUSED_STREAM so that upstream client
  // can resend request.
  if(downstream_error_code != NGHTTP2_REFUSED_STREAM) {
    return NGHTTP2_INTERNAL_ERROR;
  } else {
    return downstream_error_code;
  }
}
} // namespace

Http2Upstream::Http2Upstream(ClientHandler *handler)
  : handler_(handler),
    session_(nullptr),
    pre_upstream_(nullptr)
{
  //handler->set_bev_cb(spdy_readcb, 0, spdy_eventcb);
  handler->set_upstream_timeouts(&get_config()->spdy_upstream_read_timeout,
                                 &get_config()->upstream_write_timeout);

  nghttp2_session_callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = send_callback;
  callbacks.recv_callback = recv_callback;
  callbacks.on_stream_close_callback = on_stream_close_callback;
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks.on_frame_not_send_callback = on_frame_not_send_callback;
  callbacks.on_frame_recv_parse_error_callback =
    on_frame_recv_parse_error_callback;
  callbacks.on_unknown_frame_recv_callback = on_unknown_frame_recv_callback;

  int rv;
  rv = nghttp2_session_server_new(&session_, &callbacks, this);
  assert(rv == 0);

  int val = 1;
  flow_control_ = true;
  initial_window_size_ = (1 << get_config()->spdy_upstream_window_bits) - 1;
  rv = nghttp2_session_set_option(session_,
                                  NGHTTP2_OPT_NO_AUTO_STREAM_WINDOW_UPDATE,
                                  &val, sizeof(val));
  assert(rv == 0);

  // TODO Maybe call from outside?
  nghttp2_settings_entry entry[2];
  entry[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  entry[0].value = get_config()->spdy_max_concurrent_streams;

  entry[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  entry[1].value = initial_window_size_;

  rv = nghttp2_submit_settings
    (session_, entry, sizeof(entry)/sizeof(nghttp2_settings_entry));
  assert(rv == 0);
  // Set large connection-level window size to effectively disable
  // connection-level flow control.
  rv = nghttp2_submit_window_update(session_, NGHTTP2_FLAG_NONE,
                                    0, 1000000007);
  assert(rv == 0);
}

Http2Upstream::~Http2Upstream()
{
  nghttp2_session_del(session_);
  delete pre_upstream_;
}

int Http2Upstream::on_read()
{
  int rv = 0;
  if((rv = nghttp2_session_recv(session_)) < 0) {
    if(rv != NGHTTP2_ERR_EOF) {
      ULOG(ERROR, this) << "nghttp2_session_recv() returned error: "
                        << nghttp2_strerror(rv);
    }
  } else if((rv = nghttp2_session_send(session_)) < 0) {
    ULOG(ERROR, this) << "nghttp2_session_send() returned error: "
                      << nghttp2_strerror(rv);
  }
  if(rv == 0) {
    if(nghttp2_session_want_read(session_) == 0 &&
       nghttp2_session_want_write(session_) == 0 &&
       evbuffer_get_length(bufferevent_get_output(handler_->get_bev())) == 0) {
      if(LOG_ENABLED(INFO)) {
        ULOG(INFO, this) << "No more read/write for this SPDY session";
      }
      rv = -1;
    }
  }
  return rv;
}

int Http2Upstream::on_write()
{
  return send();
}

// After this function call, downstream may be deleted.
int Http2Upstream::send()
{
  int rv = 0;
  if((rv = nghttp2_session_send(session_)) < 0) {
    ULOG(ERROR, this) << "nghttp2_session_send() returned error: "
                      << nghttp2_strerror(rv);
  }
  if(rv == 0) {
    if(nghttp2_session_want_read(session_) == 0 &&
       nghttp2_session_want_write(session_) == 0 &&
       evbuffer_get_length(bufferevent_get_output(handler_->get_bev())) == 0) {
      if(LOG_ENABLED(INFO)) {
        ULOG(INFO, this) << "No more read/write for this SPDY session";
      }
      rv = -1;
    }
  }
  return rv;
}

int Http2Upstream::on_event()
{
  return 0;
}

ClientHandler* Http2Upstream::get_client_handler() const
{
  return handler_;
}

namespace {
void spdy_downstream_readcb(bufferevent *bev, void *ptr)
{
  DownstreamConnection *dconn = reinterpret_cast<DownstreamConnection*>(ptr);
  Downstream *downstream = dconn->get_downstream();
  Http2Upstream *upstream;
  upstream = static_cast<Http2Upstream*>(downstream->get_upstream());
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
    upstream->rst_stream(downstream, infer_upstream_rst_stream_error_code
                         (downstream->get_response_rst_stream_error_code()));
    downstream->set_downstream_connection(0);
    delete dconn;
    dconn = 0;
  } else {
    int rv = downstream->on_read();
    if(rv != 0) {
      if(LOG_ENABLED(INFO)) {
        DCLOG(INFO, dconn) << "HTTP parser failure";
      }
      if(downstream->get_response_state() == Downstream::HEADER_COMPLETE) {
        upstream->rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
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
      downstream->set_downstream_connection(0);
      delete dconn;
      dconn = 0;
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
  DownstreamConnection *dconn = reinterpret_cast<DownstreamConnection*>(ptr);
  Downstream *downstream = dconn->get_downstream();
  Http2Upstream *upstream;
  upstream = static_cast<Http2Upstream*>(downstream->get_upstream());
  upstream->resume_read(SHRPX_NO_BUFFER, downstream);
}
} // namespace

namespace {
void spdy_downstream_eventcb(bufferevent *bev, short events, void *ptr)
{
  DownstreamConnection *dconn = reinterpret_cast<DownstreamConnection*>(ptr);
  Downstream *downstream = dconn->get_downstream();
  Http2Upstream *upstream;
  upstream = static_cast<Http2Upstream*>(downstream->get_upstream());
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
  } else if(events & BEV_EVENT_EOF) {
    if(LOG_ENABLED(INFO)) {
      DCLOG(INFO, dconn) << "EOF. stream_id=" << downstream->get_stream_id();
    }
    if(downstream->get_request_state() == Downstream::STREAM_CLOSED) {
      // If stream was closed already, we don't need to send reply at
      // the first place. We can delete downstream.
      upstream->remove_downstream(downstream);
      delete downstream;
    } else {
      // Delete downstream connection. If we don't delete it here, it
      // will be pooled in on_stream_close_callback.
      downstream->set_downstream_connection(0);
      delete dconn;
      dconn = 0;
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
    }
  } else if(events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
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
    } else {
      // Delete downstream connection. If we don't delete it here, it
      // will be pooled in on_stream_close_callback.
      downstream->set_downstream_connection(0);
      delete dconn;
      dconn = 0;
      if(downstream->get_response_state() == Downstream::MSG_COMPLETE) {
        // For SSL tunneling, we issue RST_STREAM. For other types of
        // stream, we don't have to do anything since response was
        // complete.
        if(downstream->get_upgraded()) {
          upstream->rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
        }
      } else {
        if(downstream->get_response_state() == Downstream::HEADER_COMPLETE) {
          upstream->rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
        } else {
          int status;
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
    }
  }
}
} // namespace

int Http2Upstream::rst_stream(Downstream *downstream,
                              nghttp2_error_code error_code)
{
  if(LOG_ENABLED(INFO)) {
    ULOG(INFO, this) << "RST_STREAM stream_id="
                     << downstream->get_stream_id();
  }
  int rv;
  rv = nghttp2_submit_rst_stream(session_, downstream->get_stream_id(),
                                 error_code);
  if(rv < NGHTTP2_ERR_FATAL) {
    ULOG(FATAL, this) << "nghttp2_submit_rst_stream() failed: "
                      << nghttp2_strerror(rv);
    DIE();
  }
  return 0;
}

int Http2Upstream::window_update(Downstream *downstream)
{
  int rv;
  rv = nghttp2_submit_window_update(session_, NGHTTP2_FLAG_NONE,
                                    downstream->get_stream_id(),
                                    downstream->get_recv_window_size());
  downstream->set_recv_window_size(0);
  if(rv < NGHTTP2_ERR_FATAL) {
    ULOG(FATAL, this) << "nghttp2_submit_window_update() failed: "
                      << nghttp2_strerror(rv);
    DIE();
  }
  return 0;
}

namespace {
ssize_t spdy_data_read_callback(nghttp2_session *session,
                                int32_t stream_id,
                                uint8_t *buf, size_t length,
                                int *eof,
                                nghttp2_data_source *source,
                                void *user_data)
{
  Downstream *downstream = reinterpret_cast<Downstream*>(source->ptr);
  evbuffer *body = downstream->get_response_body_buf();
  assert(body);
  int nread = evbuffer_remove(body, buf, length);
  if(nread == 0 &&
     downstream->get_response_state() == Downstream::MSG_COMPLETE) {
    if(!downstream->get_upgraded()) {
      *eof = 1;
    } else {
      // For tunneling, issue RST_STREAM to finish the stream.
      Http2Upstream *upstream;
      upstream = reinterpret_cast<Http2Upstream*>(downstream->get_upstream());
      if(LOG_ENABLED(INFO)) {
        ULOG(INFO, upstream) << "RST_STREAM to tunneled stream stream_id="
                             << stream_id;
      }
      upstream->rst_stream(downstream, infer_upstream_rst_stream_error_code
                           (downstream->get_response_rst_stream_error_code()));
    }
  }
  if(nread == 0 && *eof != 1) {
    return NGHTTP2_ERR_DEFERRED;
  }
  return nread;
}
} // namespace

int Http2Upstream::error_reply(Downstream *downstream, int status_code)
{
  int rv;
  std::string html = http::create_error_html(status_code);
  downstream->init_response_body_buf();
  evbuffer *body = downstream->get_response_body_buf();
  rv = evbuffer_add(body, html.c_str(), html.size());
  if(rv == -1) {
    ULOG(FATAL, this) << "evbuffer_add() failed";
    return -1;
  }
  downstream->set_response_state(Downstream::MSG_COMPLETE);

  nghttp2_data_provider data_prd;
  data_prd.source.ptr = downstream;
  data_prd.read_callback = spdy_data_read_callback;

  std::string content_length = util::utos(html.size());
  std::string status_code_str = std::to_string(status_code);
  const char *nv[] = {
    ":status", status_code_str.c_str(),
    "content-type", "text/html; charset=UTF-8",
    "server", get_config()->server_name,
    "content-length", content_length.c_str(),
    0
  };

  rv = nghttp2_submit_response(session_, downstream->get_stream_id(), nv,
                               &data_prd);
  if(rv < NGHTTP2_ERR_FATAL) {
    ULOG(FATAL, this) << "nghttp2_submit_response() failed: "
                      << nghttp2_strerror(rv);
    DIE();
  }
  if(get_config()->accesslog) {
    upstream_response(get_client_handler()->get_ipaddr(),
                      status_code, downstream);
  }
  return 0;
}

bufferevent_data_cb Http2Upstream::get_downstream_readcb()
{
  return spdy_downstream_readcb;
}

bufferevent_data_cb Http2Upstream::get_downstream_writecb()
{
  return spdy_downstream_writecb;
}

bufferevent_event_cb Http2Upstream::get_downstream_eventcb()
{
  return spdy_downstream_eventcb;
}

void Http2Upstream::add_downstream(Downstream *downstream)
{
  downstream_queue_.add(downstream);
}

void Http2Upstream::remove_downstream(Downstream *downstream)
{
  downstream_queue_.remove(downstream);
}

Downstream* Http2Upstream::find_downstream(int32_t stream_id)
{
  return downstream_queue_.find(stream_id);
}

nghttp2_session* Http2Upstream::get_spdy_session()
{
  return session_;
}

// WARNING: Never call directly or indirectly nghttp2_session_send or
// nghttp2_session_recv. These calls may delete downstream.
int Http2Upstream::on_downstream_header_complete(Downstream *downstream)
{
  if(LOG_ENABLED(INFO)) {
    DLOG(INFO, downstream) << "HTTP response header completed";
  }
  downstream->normalize_response_headers();
  auto end_headers = std::end(downstream->get_response_headers());
  size_t nheader = downstream->get_response_headers().size();
  // 4 means :status and possible via header field.
  const char **nv = new const char*[nheader * 2 + 4 + 1];
  size_t hdidx = 0;
  std::string via_value;
  std::string response_status =
    std::to_string(downstream->get_response_http_status());
  nv[hdidx++] = ":status";
  nv[hdidx++] = response_status.c_str();

  hdidx += http2::copy_norm_headers_to_nv(&nv[hdidx],
                                          downstream->get_response_headers());
  auto via = downstream->get_norm_response_header("via");
  if(get_config()->no_via) {
    if(via != end_headers) {
      nv[hdidx++] = "via";
      nv[hdidx++] = (*via).second.c_str();
    }
  } else {
    if(via != end_headers) {
      via_value = (*via).second;
      via_value += ", ";
    }
    via_value += http::create_via_header_value
      (downstream->get_response_major(), downstream->get_response_minor());
    nv[hdidx++] = "via";
    nv[hdidx++] = via_value.c_str();
  }
  nv[hdidx++] = nullptr;
  if(LOG_ENABLED(INFO)) {
    std::stringstream ss;
    for(size_t i = 0; nv[i]; i += 2) {
      ss << TTY_HTTP_HD << nv[i] << TTY_RST << ": " << nv[i+1] << "\n";
    }
    ULOG(INFO, this) << "HTTP response headers. stream_id="
                     << downstream->get_stream_id() << "\n"
                     << ss.str();
  }
  nghttp2_data_provider data_prd;
  data_prd.source.ptr = downstream;
  data_prd.read_callback = spdy_data_read_callback;

  int rv;
  rv = nghttp2_submit_response(session_, downstream->get_stream_id(), nv,
                               &data_prd);
  delete [] nv;
  if(rv != 0) {
    ULOG(FATAL, this) << "nghttp2_submit_response() failed";
    return -1;
  }
  if(get_config()->accesslog) {
    upstream_response(get_client_handler()->get_ipaddr(),
                      downstream->get_response_http_status(),
                      downstream);
  }
  return 0;
}

// WARNING: Never call directly or indirectly nghttp2_session_send or
// nghttp2_session_recv. These calls may delete downstream.
int Http2Upstream::on_downstream_body(Downstream *downstream,
                                      const uint8_t *data, size_t len)
{
  evbuffer *body = downstream->get_response_body_buf();
  int rv = evbuffer_add(body, data, len);
  if(rv != 0) {
    ULOG(FATAL, this) << "evbuffer_add() failed";
    return -1;
  }
  nghttp2_session_resume_data(session_, downstream->get_stream_id());

  size_t bodylen = evbuffer_get_length(body);
  if(bodylen > SHRPX_SPDY_UPSTREAM_OUTPUT_UPPER_THRES) {
    downstream->pause_read(SHRPX_NO_BUFFER);
  }

  return 0;
}

// WARNING: Never call directly or indirectly nghttp2_session_send or
// nghttp2_session_recv. These calls may delete downstream.
int Http2Upstream::on_downstream_body_complete(Downstream *downstream)
{
  if(LOG_ENABLED(INFO)) {
    DLOG(INFO, downstream) << "HTTP response completed";
  }
  nghttp2_session_resume_data(session_, downstream->get_stream_id());
  return 0;
}

bool Http2Upstream::get_flow_control() const
{
  return flow_control_;
}

int32_t Http2Upstream::get_initial_window_size() const
{
  return initial_window_size_;
}

void Http2Upstream::pause_read(IOCtrlReason reason)
{}

int Http2Upstream::resume_read(IOCtrlReason reason, Downstream *downstream)
{
  if(get_flow_control()) {
    if(downstream->get_recv_window_size() >= get_initial_window_size()/2) {
      window_update(downstream);
    }
  }
  return send();
}

} // namespace shrpx
