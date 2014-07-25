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
#include "shrpx_http2_session.h"

#include <netinet/tcp.h>
#include <unistd.h>
#include <vector>

#include <openssl/err.h>

#include <event2/bufferevent_ssl.h>

#include "shrpx_upstream.h"
#include "shrpx_downstream.h"
#include "shrpx_config.h"
#include "shrpx_error.h"
#include "shrpx_http2_downstream_connection.h"
#include "shrpx_client_handler.h"
#include "shrpx_ssl.h"
#include "shrpx_http.h"
#include "shrpx_worker_config.h"
#include "http2.h"
#include "util.h"
#include "base64.h"

using namespace nghttp2;

namespace shrpx {

Http2Session::Http2Session(event_base *evbase, SSL_CTX *ssl_ctx)
  : evbase_(evbase),
    ssl_ctx_(ssl_ctx),
    ssl_(nullptr),
    session_(nullptr),
    bev_(nullptr),
    wrbev_(nullptr),
    rdbev_(nullptr),
    settings_timerev_(nullptr),
    fd_(-1),
    state_(DISCONNECTED),
    notified_(false),
    flow_control_(false)
{}

Http2Session::~Http2Session()
{
  disconnect();
}

int Http2Session::disconnect()
{
  if(LOG_ENABLED(INFO)) {
    SSLOG(INFO, this) << "Disconnecting";
  }
  nghttp2_session_del(session_);
  session_ = nullptr;

  if(settings_timerev_) {
    event_free(settings_timerev_);
    settings_timerev_ = nullptr;
  }

  if(ssl_) {
    SSL_set_shutdown(ssl_, SSL_RECEIVED_SHUTDOWN);
    SSL_shutdown(ssl_);
  }
  if(bev_) {
    int fd = bufferevent_getfd(bev_);
    bufferevent_disable(bev_, EV_READ | EV_WRITE);
    bufferevent_free(bev_);
    bev_ = nullptr;
    if(fd != -1) {
      if(fd_ == -1) {
        fd_ = fd;
      } else if(fd != fd_) {
        SSLOG(WARNING, this) << "fd in bev_ != fd_";
        shutdown(fd, SHUT_WR);
        close(fd);
      }
    }
  }
  if(ssl_) {
    SSL_free(ssl_);
  }
  ssl_ = nullptr;

  if(fd_ != -1) {
    if(LOG_ENABLED(INFO)) {
      SSLOG(INFO, this) << "Closing fd=" << fd_;
    }
    shutdown(fd_, SHUT_WR);
    close(fd_);
    fd_ = -1;
  }

  if(proxy_htp_) {
    proxy_htp_.reset();
  }

  notified_ = false;
  state_ = DISCONNECTED;

  // Delete all client handler associated to Downstream. When deleting
  // Http2DownstreamConnection, it calls this object's
  // remove_downstream_connection(). The multiple
  // Http2DownstreamConnection objects belong to the same ClientHandler
  // object. So first dump ClientHandler objects and delete them once
  // and for all.
  std::vector<Http2DownstreamConnection*> vec(std::begin(dconns_),
                                              std::end(dconns_));
  std::set<ClientHandler*> handlers;
  for(auto dc : vec) {
    handlers.insert(dc->get_client_handler());
  }
  for(auto& h : handlers) {
    delete h;
  }

  dconns_.clear();
  for(auto& s : streams_) {
    delete s;
  }
  streams_.clear();
  return 0;
}

namespace {
void notify_readcb(bufferevent *bev, void *arg)
{
  int rv;
  auto http2session = static_cast<Http2Session*>(arg);
  http2session->clear_notify();
  switch(http2session->get_state()) {
  case Http2Session::DISCONNECTED:
    rv = http2session->initiate_connection();
    if(rv != 0) {
      SSLOG(FATAL, http2session)
        << "Could not initiate backend connection";
      http2session->disconnect();
    }
    break;
  case Http2Session::CONNECTED:
    rv = http2session->send();
    if(rv != 0) {
      http2session->disconnect();
    }
    break;
  }
}
} // namespace

namespace {
void notify_eventcb(bufferevent *bev, short events, void *arg)
{
  auto http2session = static_cast<Http2Session*>(arg);
  // TODO should DIE()?
  if(events & BEV_EVENT_EOF) {
    SSLOG(ERROR, http2session) << "Notification connection lost: EOF";
  }
  if(events & BEV_EVENT_TIMEOUT) {
    SSLOG(ERROR, http2session) << "Notification connection lost: timeout";
  }
  if(events & BEV_EVENT_ERROR) {
    SSLOG(ERROR, http2session) << "Notification connection lost: network error";
  }
}
} // namespace

int Http2Session::init_notification()
{
  int rv;
  int sockpair[2];
  rv = socketpair(AF_UNIX, SOCK_STREAM, 0, sockpair);
  if(rv == -1) {
    SSLOG(FATAL, this) << "socketpair() failed: errno=" << errno;
    return -1;
  }
  evutil_make_socket_nonblocking(sockpair[0]);
  evutil_make_socket_nonblocking(sockpair[1]);
  wrbev_ = bufferevent_socket_new(evbase_, sockpair[0],
                                  BEV_OPT_CLOSE_ON_FREE|
                                  BEV_OPT_DEFER_CALLBACKS);
  if(!wrbev_) {
    SSLOG(FATAL, this) << "bufferevent_socket_new() failed";
    for(int i = 0; i < 2; ++i) {
      close(sockpair[i]);
    }
    return -1;
  }
  rdbev_ = bufferevent_socket_new(evbase_, sockpair[1],
                                  BEV_OPT_CLOSE_ON_FREE|
                                  BEV_OPT_DEFER_CALLBACKS);
  if(!rdbev_) {
    SSLOG(FATAL, this) << "bufferevent_socket_new() failed";
    close(sockpair[1]);
    return -1;
  }
  bufferevent_enable(rdbev_, EV_READ);
  bufferevent_setcb(rdbev_, notify_readcb, nullptr, notify_eventcb, this);
  return 0;
}

namespace {
void readcb(bufferevent *bev, void *ptr)
{
  int rv;
  auto http2session = static_cast<Http2Session*>(ptr);
  rv = http2session->on_read();
  if(rv != 0) {
    http2session->disconnect();
  }
}
} // namespace

namespace {
void writecb(bufferevent *bev, void *ptr)
{
  if(evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
    return;
  }
  int rv;
  auto http2session = static_cast<Http2Session*>(ptr);
  rv = http2session->on_write();
  if(rv != 0) {
    http2session->disconnect();
  }
}
} // namespace

namespace {
void eventcb(bufferevent *bev, short events, void *ptr)
{
  auto http2session = static_cast<Http2Session*>(ptr);
  if(events & BEV_EVENT_CONNECTED) {
    if(LOG_ENABLED(INFO)) {
      SSLOG(INFO, http2session) << "Connection established";
    }
    http2session->set_state(Http2Session::CONNECTED);
    if(!get_config()->downstream_no_tls &&
       !get_config()->insecure &&
       http2session->check_cert() != 0) {

      http2session->disconnect();

      return;
    }

    if(http2session->on_connect() != 0) {
      http2session->disconnect();
      return;
    }

    auto fd = bufferevent_getfd(bev);
    int val = 1;
    if(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                  reinterpret_cast<char*>(&val), sizeof(val)) == -1) {
      SSLOG(WARNING, http2session)
        << "Setting option TCP_NODELAY failed: errno=" << errno;
    }
    return;
  }

  if(events & BEV_EVENT_EOF) {
    if(LOG_ENABLED(INFO)) {
      SSLOG(INFO, http2session) << "EOF";
    }
    http2session->disconnect();
    return;
  }

  if(events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
    if(LOG_ENABLED(INFO)) {
      if(events & BEV_EVENT_ERROR) {
        SSLOG(INFO, http2session) << "Network error";
      } else {
        SSLOG(INFO, http2session) << "Timeout";
      }
    }
    http2session->disconnect();
    return;
  }
}
} // namespace

namespace {
void proxy_readcb(bufferevent *bev, void *ptr)
{
  auto http2session = static_cast<Http2Session*>(ptr);
  if(http2session->on_read_proxy() == 0) {
    switch(http2session->get_state()) {
    case Http2Session::PROXY_CONNECTED:
      // The current bufferevent is no longer necessary, so delete it
      // here. But we keep fd_ inside it.
      http2session->unwrap_free_bev();
      // Initiate SSL/TLS handshake through established tunnel.
      if(http2session->initiate_connection() != 0) {
        http2session->disconnect();
      }
      break;
    case Http2Session::PROXY_FAILED:
      http2session->disconnect();
      break;
    }
  } else {
    http2session->disconnect();
  }
}
} // namespace

namespace {
void proxy_eventcb(bufferevent *bev, short events, void *ptr)
{
  auto http2session = static_cast<Http2Session*>(ptr);
  if(events & BEV_EVENT_CONNECTED) {
    if(LOG_ENABLED(INFO)) {
      SSLOG(INFO, http2session) << "Connected to the proxy";
    }
    std::string req = "CONNECT ";
    req += get_config()->downstream_hostport.get();
    req += " HTTP/1.1\r\nHost: ";
    req += get_config()->downstream_host.get();
    req += "\r\n";
    if(get_config()->downstream_http_proxy_userinfo) {
      req += "Proxy-Authorization: Basic ";
      size_t len = strlen(get_config()->downstream_http_proxy_userinfo.get());
      req += base64::encode
        (get_config()->downstream_http_proxy_userinfo.get(),
         get_config()->downstream_http_proxy_userinfo.get() + len);
      req += "\r\n";
    }
    req += "\r\n";
    if(LOG_ENABLED(INFO)) {
      SSLOG(INFO, http2session) << "HTTP proxy request headers\n" << req;
    }
    if(bufferevent_write(bev, req.c_str(), req.size()) != 0) {
      SSLOG(ERROR, http2session) << "bufferevent_write() failed";
      http2session->disconnect();
    }
    return;
  }

  if(events & BEV_EVENT_EOF) {
    if(LOG_ENABLED(INFO)) {
      SSLOG(INFO, http2session) << "Proxy EOF";
    }
    http2session->disconnect();
    return;
  }

  if(events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
    if(LOG_ENABLED(INFO)) {
      if(events & BEV_EVENT_ERROR) {
        SSLOG(INFO, http2session) << "Network error";
      } else {
        SSLOG(INFO, http2session) << "Timeout";
      }
    }
    http2session->disconnect();
    return;
  }
}
} // namespace

int Http2Session::check_cert()
{
  return ssl::check_cert(ssl_);
}

int Http2Session::initiate_connection()
{
  int rv = 0;
  if(get_config()->downstream_http_proxy_host && state_ == DISCONNECTED) {
    if(LOG_ENABLED(INFO)) {
      SSLOG(INFO, this) << "Connecting to the proxy "
                        << get_config()->downstream_http_proxy_host.get()
                        << ":"
                        << get_config()->downstream_http_proxy_port;
    }
    bev_ = bufferevent_socket_new(evbase_, -1, BEV_OPT_DEFER_CALLBACKS);
    if(!bev_) {
      SSLOG(ERROR, this) << "bufferevent_socket_new() failed";
      return SHRPX_ERR_NETWORK;
    }
    bufferevent_enable(bev_, EV_READ);
    bufferevent_set_timeouts(bev_, &get_config()->downstream_read_timeout,
                             &get_config()->downstream_write_timeout);

    // No need to set writecb because we write the request when
    // connected at once.
    bufferevent_setcb(bev_, proxy_readcb, nullptr, proxy_eventcb, this);
    rv = bufferevent_socket_connect
      (bev_,
       const_cast<sockaddr*>(&get_config()->downstream_http_proxy_addr.sa),
       get_config()->downstream_http_proxy_addrlen);
    if(rv != 0) {
      SSLOG(ERROR, this) << "Failed to connect to the proxy "
                         << get_config()->downstream_http_proxy_host.get()
                         << ":"
                         << get_config()->downstream_http_proxy_port;
      return SHRPX_ERR_NETWORK;
    }
    proxy_htp_ = util::make_unique<http_parser>();
    http_parser_init(proxy_htp_.get(), HTTP_RESPONSE);
    proxy_htp_->data = this;

    state_ = PROXY_CONNECTING;

    return 0;
  }

  if(state_ == DISCONNECTED || state_ == PROXY_CONNECTED) {
    if(LOG_ENABLED(INFO)) {
      SSLOG(INFO, this) << "Connecting to downstream server";
    }
    if(ssl_ctx_) {
      // We are establishing TLS connection.
      ssl_ = SSL_new(ssl_ctx_);
      if(!ssl_) {
        SSLOG(ERROR, this) << "SSL_new() failed: "
                           << ERR_error_string(ERR_get_error(), NULL);
        return -1;
      }

      const char *sni_name = nullptr;
      if ( get_config()->backend_tls_sni_name ) {
        sni_name = get_config()->backend_tls_sni_name.get();
      }
      else {
        sni_name = get_config()->downstream_host.get();
      }

      if(sni_name && !util::numeric_host(sni_name)) {
        // TLS extensions: SNI. There is no documentation about the return
        // code for this function (actually this is macro wrapping SSL_ctrl
        // at the time of this writing).
        SSL_set_tlsext_host_name(ssl_, sni_name);
      }
      // If state_ == PROXY_CONNECTED, we has connected to the proxy
      // using fd_ and tunnel has been established.
      bev_ = bufferevent_openssl_socket_new(evbase_, fd_, ssl_,
                                            BUFFEREVENT_SSL_CONNECTING,
                                            BEV_OPT_DEFER_CALLBACKS);
      if(!bev_) {
        SSLOG(ERROR, this) << "bufferevent_socket_new() failed";
        return SHRPX_ERR_NETWORK;
      }
      rv = bufferevent_socket_connect
        (bev_,
         // TODO maybe not thread-safe?
         const_cast<sockaddr*>(&get_config()->downstream_addr.sa),
         get_config()->downstream_addrlen);
    } else if(state_ == DISCONNECTED) {
      // Without TLS and proxy.
      bev_ = bufferevent_socket_new(evbase_, -1, BEV_OPT_DEFER_CALLBACKS);
      if(!bev_) {
        SSLOG(ERROR, this) << "bufferevent_socket_new() failed";
        return SHRPX_ERR_NETWORK;
      }
      rv = bufferevent_socket_connect
        (bev_,
         const_cast<sockaddr*>(&get_config()->downstream_addr.sa),
         get_config()->downstream_addrlen);
    } else {
      assert(state_ == PROXY_CONNECTED);
      // Without TLS but with proxy.
      bev_ = bufferevent_socket_new(evbase_, fd_, BEV_OPT_DEFER_CALLBACKS);
      if(!bev_) {
        SSLOG(ERROR, this) << "bufferevent_socket_new() failed";
        return SHRPX_ERR_NETWORK;
      }
      // Connection already established.
      eventcb(bev_, BEV_EVENT_CONNECTED, this);
      // eventcb() has no return value. Check state_ to whether it was
      // failed or not.
      if(state_ == DISCONNECTED) {
        return -1;
      }
    }
    if(rv != 0) {
      return SHRPX_ERR_NETWORK;
    }

    bufferevent_setwatermark(bev_, EV_READ, 0, SHRPX_READ_WATERMARK);
    bufferevent_enable(bev_, EV_READ);
    bufferevent_setcb(bev_, readcb, writecb, eventcb, this);
    // Set timeout for HTTP2 session
    bufferevent_set_timeouts(bev_, &get_config()->downstream_read_timeout,
                             &get_config()->downstream_write_timeout);

    // We have been already connected when no TLS and proxy is used.
    if(state_ != CONNECTED) {
      state_ = CONNECTING;
    }

    return 0;
  }

  // Unreachable
  DIE();
  return 0;
}

void Http2Session::unwrap_free_bev()
{
  assert(fd_ == -1);
  fd_ = bufferevent_getfd(bev_);
  bufferevent_free(bev_);
  bev_ = nullptr;
}

namespace {
int htp_hdrs_completecb(http_parser *htp)
{
  auto http2session = static_cast<Http2Session*>(htp->data);
  // We just check status code here
  if(htp->status_code == 200) {
    if(LOG_ENABLED(INFO)) {
      SSLOG(INFO, http2session) << "Tunneling success";
    }
    http2session->set_state(Http2Session::PROXY_CONNECTED);

    return 0;
  }

  SSLOG(WARNING, http2session) << "Tunneling failed";
  http2session->set_state(Http2Session::PROXY_FAILED);

  return 0;
}
} // namespace

namespace {
http_parser_settings htp_hooks = {
  nullptr, // http_cb      on_message_begin;
  nullptr, // http_data_cb on_url;
  nullptr, // http_data_cb on_status;
  nullptr, // http_data_cb on_header_field;
  nullptr, // http_data_cb on_header_value;
  htp_hdrs_completecb, // http_cb      on_headers_complete;
  nullptr, // http_data_cb on_body;
  nullptr  // http_cb      on_message_complete;
};
} // namespace

int Http2Session::on_read_proxy()
{
  auto input = bufferevent_get_input(bev_);

  for(;;) {
    auto inputlen = evbuffer_get_contiguous_space(input);

    if(inputlen == 0) {
      assert(evbuffer_get_length(input) == 0);

      return 0;
    }

    auto mem = evbuffer_pullup(input, inputlen);

    size_t nread = http_parser_execute(proxy_htp_.get(), &htp_hooks,
                                       reinterpret_cast<const char*>(mem),
                                       inputlen);

    if(evbuffer_drain(input, nread) != 0) {
      SSLOG(FATAL, this) << "evbuffer_drain() failed";
      return -1;
    }

    auto htperr = HTTP_PARSER_ERRNO(proxy_htp_.get());

    if(htperr != HPE_OK) {
      return -1;
    }
  }
}

void Http2Session::add_downstream_connection(Http2DownstreamConnection *dconn)
{
  dconns_.insert(dconn);
}

void Http2Session::remove_downstream_connection
(Http2DownstreamConnection *dconn)
{
  dconns_.erase(dconn);
  dconn->detach_stream_data();
}

void Http2Session::remove_stream_data(StreamData *sd)
{
  streams_.erase(sd);
  if(sd->dconn) {
    sd->dconn->detach_stream_data();
  }
  delete sd;
}

int Http2Session::submit_request(Http2DownstreamConnection *dconn,
                                 int32_t pri,
                                 const nghttp2_nv *nva, size_t nvlen,
                                 const nghttp2_data_provider *data_prd)
{
  assert(state_ == CONNECTED);
  auto sd = util::make_unique<StreamData>();
  // TODO Specify nullptr to pri_spec for now
  auto stream_id = nghttp2_submit_request(session_, nullptr, nva, nvlen,
                                          data_prd, sd.get());
  if(stream_id < 0) {
    SSLOG(FATAL, this) << "nghttp2_submit_request() failed: "
                       << nghttp2_strerror(stream_id);
    return -1;
  }

  dconn->attach_stream_data(sd.get());
  dconn->get_downstream()->set_downstream_stream_id(stream_id);
  streams_.insert(sd.release());

  return 0;
}

int Http2Session::submit_rst_stream(int32_t stream_id,
                                   nghttp2_error_code error_code)
{
  assert(state_ == CONNECTED);
  if(LOG_ENABLED(INFO)) {
    SSLOG(INFO, this) << "RST_STREAM stream_id="
                      << stream_id
                      << " with error_code="
                      << error_code;
  }
  int rv = nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE,
                                     stream_id, error_code);
  if(rv != 0) {
    SSLOG(FATAL, this) << "nghttp2_submit_rst_stream() failed: "
                       << nghttp2_strerror(rv);
    return -1;
  }
  return 0;
}

int Http2Session::submit_priority(Http2DownstreamConnection *dconn,
                                  int32_t pri)
{
  assert(state_ == CONNECTED);
  if(!dconn) {
    return 0;
  }
  int rv;

  // TODO Disabled temporarily

  // rv = nghttp2_submit_priority(session_, NGHTTP2_FLAG_NONE,
  //                              dconn->get_downstream()->
  //                              get_downstream_stream_id(), pri);

  rv = 0;

  if(rv < NGHTTP2_ERR_FATAL) {
    SSLOG(FATAL, this) << "nghttp2_submit_priority() failed: "
                       << nghttp2_strerror(rv);
    return -1;
  }
  return 0;
}

nghttp2_session* Http2Session::get_session() const
{
  return session_;
}

bool Http2Session::get_flow_control() const
{
  return flow_control_;
}

int Http2Session::resume_data(Http2DownstreamConnection *dconn)
{
  assert(state_ == CONNECTED);
  auto downstream = dconn->get_downstream();
  int rv = nghttp2_session_resume_data(session_,
                                       downstream->get_downstream_stream_id());
  switch(rv) {
  case 0:
  case NGHTTP2_ERR_INVALID_ARGUMENT:
    return 0;
  default:
    SSLOG(FATAL, this) << "nghttp2_resume_session() failed: "
                       << nghttp2_strerror(rv);
    return -1;
  }
}

namespace {
void call_downstream_readcb(Http2Session *http2session, Downstream *downstream)
{
  auto upstream = downstream->get_upstream();
  if(upstream) {
    (upstream->get_downstream_readcb())
      (http2session->get_bev(),
       downstream->get_downstream_connection());
  }
}
} // namespace

namespace {
int on_stream_close_callback
(nghttp2_session *session, int32_t stream_id, nghttp2_error_code error_code,
 void *user_data)
{
  auto http2session = static_cast<Http2Session*>(user_data);
  if(LOG_ENABLED(INFO)) {
    SSLOG(INFO, http2session) << "Stream stream_id=" << stream_id
                              << " is being closed";
  }
  auto sd = static_cast<StreamData*>
    (nghttp2_session_get_stream_user_data(session, stream_id));
  if(sd == 0) {
    // We might get this close callback when pushed streams are
    // closed.
    return 0;
  }
  auto dconn = sd->dconn;
  if(dconn) {
    auto downstream = dconn->get_downstream();
    if(downstream && downstream->get_downstream_stream_id() == stream_id) {

      http2session->consume(downstream->get_downstream_stream_id(),
                            downstream->get_response_datalen());

      downstream->reset_response_datalen();

      if(error_code == NGHTTP2_NO_ERROR) {
        if(downstream->get_response_state() != Downstream::MSG_COMPLETE) {
          downstream->set_response_state(Downstream::MSG_RESET);
        }
      } else {
        downstream->set_response_state(Downstream::MSG_RESET);
      }
      call_downstream_readcb(http2session, downstream);
      // dconn may be deleted
    }
  }
  // The life time of StreamData ends here
  http2session->remove_stream_data(sd);
  return 0;
}
} // namespace

namespace {
void settings_timeout_cb(evutil_socket_t fd, short what, void *arg)
{
  auto http2session = static_cast<Http2Session*>(arg);
  SSLOG(INFO, http2session) << "SETTINGS timeout";
  if(http2session->terminate_session(NGHTTP2_SETTINGS_TIMEOUT) != 0) {
    http2session->disconnect();
    return;
  }
  if(http2session->send() != 0) {
    http2session->disconnect();
  }
}
} // namespace

int Http2Session::start_settings_timer()
{
  int rv;
  // We submit SETTINGS only once
  if(settings_timerev_) {
    return 0;
  }
  settings_timerev_ = evtimer_new(evbase_, settings_timeout_cb, this);
  if(settings_timerev_ == nullptr) {
    return -1;
  }
  // SETTINGS ACK timeout is 10 seconds for now
  timeval settings_timeout = { 10, 0 };
  rv = evtimer_add(settings_timerev_, &settings_timeout);
  if(rv == -1) {
    return -1;
  }
  return 0;
}

void Http2Session::stop_settings_timer()
{
  if(settings_timerev_ == nullptr) {
    return;
  }
  event_free(settings_timerev_);
  settings_timerev_ = nullptr;
}

namespace {
int on_header_callback(nghttp2_session *session,
                       const nghttp2_frame *frame,
                       const uint8_t *name, size_t namelen,
                       const uint8_t *value, size_t valuelen,
                       uint8_t flags,
                       void *user_data)
{
  auto sd = static_cast<StreamData*>
    (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
  if(!sd || !sd->dconn) {
    return 0;
  }
  auto downstream = sd->dconn->get_downstream();
  if(!downstream) {
    return 0;
  }

  if(frame->hd.type != NGHTTP2_HEADERS ||
     (frame->headers.cat != NGHTTP2_HCAT_RESPONSE &&
      !downstream->get_expect_final_response())) {
    return 0;
  }

  if(downstream->get_response_headers_sum() > Downstream::MAX_HEADERS_SUM) {
    if(LOG_ENABLED(INFO)) {
      DLOG(INFO, downstream) << "Too large header block size="
                             << downstream->get_response_headers_sum();
    }
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }
  if(!http2::check_nv(name, namelen, value, valuelen)) {
    return 0;
  }
  downstream->split_add_response_header(name, namelen, value, valuelen,
                                        flags & NGHTTP2_NV_FLAG_NO_INDEX);
  return 0;
}
} // namespace

namespace {
int on_begin_headers_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              void *user_data)
{
  auto http2session = static_cast<Http2Session*>(user_data);
  if(frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
    // server sends request HEADERS
    http2session->submit_rst_stream(frame->hd.stream_id,
                                    NGHTTP2_REFUSED_STREAM);
    return 0;
  }
  if(frame->headers.cat != NGHTTP2_HCAT_RESPONSE) {
    return 0;
  }
  auto sd = static_cast<StreamData*>
    (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
  if(!sd || !sd->dconn) {
    http2session->submit_rst_stream(frame->hd.stream_id,
                                    NGHTTP2_INTERNAL_ERROR);
    return 0;
  }
  auto downstream = sd->dconn->get_downstream();
  if(!downstream ||
     downstream->get_downstream_stream_id() != frame->hd.stream_id) {
    http2session->submit_rst_stream(frame->hd.stream_id,
                                    NGHTTP2_INTERNAL_ERROR);
    return 0;
  }
  return 0;
}
} // namespace

namespace {
int on_response_headers(Http2Session *http2session,
                        Downstream *downstream,
                        nghttp2_session *session,
                        const nghttp2_frame *frame)
{
  int rv;

  auto upstream = downstream->get_upstream();

  downstream->normalize_response_headers();
  auto& nva = downstream->get_response_headers();

  if(!http2::check_http2_headers(nva)) {
    http2session->submit_rst_stream(frame->hd.stream_id,
                                    NGHTTP2_PROTOCOL_ERROR);
    downstream->set_response_state(Downstream::MSG_RESET);
    call_downstream_readcb(http2session, downstream);
    return 0;
  }

  auto status = http2::get_unique_header(nva, ":status");
  if(!status || http2::value_lws(status)) {
    http2session->submit_rst_stream(frame->hd.stream_id,
                                    NGHTTP2_PROTOCOL_ERROR);
    downstream->set_response_state(Downstream::MSG_RESET);
    call_downstream_readcb(http2session, downstream);

    return 0;
  }

  downstream->set_response_http_status(strtoul(status->value.c_str(),
                                               nullptr, 10));
  downstream->set_response_major(2);
  downstream->set_response_minor(0);

  if(downstream->get_non_final_response()) {

    if(LOG_ENABLED(INFO)) {
      SSLOG(INFO, http2session) << "HTTP non-final response. stream_id="
                                << frame->hd.stream_id;
    }

    downstream->set_expect_final_response(true);
    rv = upstream->on_downstream_header_complete(downstream);

    // Now Dowstream's response headers are erased.

    if(rv != 0) {
      http2session->submit_rst_stream(frame->hd.stream_id,
                                      NGHTTP2_PROTOCOL_ERROR);
      downstream->set_response_state(Downstream::MSG_RESET);
    }

    return 0;
  }

  downstream->set_expect_final_response(false);

  if(LOG_ENABLED(INFO)) {
    std::stringstream ss;
    for(auto& nv : nva) {
      ss << TTY_HTTP_HD << nv.name << TTY_RST << ": " << nv.value << "\n";
    }
    SSLOG(INFO, http2session) << "HTTP response headers. stream_id="
                              << frame->hd.stream_id
                              << "\n" << ss.str();
  }

  auto content_length = http2::get_header(nva, "content-length");
  if(!content_length && downstream->get_request_method() != "HEAD" &&
     downstream->get_request_method() != "CONNECT") {
    unsigned int status;
    status = downstream->get_response_http_status();
    if(!((100 <= status && status <= 199) || status == 204 ||
         status == 304)) {
      // Here we have response body but Content-Length is not known
      // in advance.
      if(downstream->get_request_major() <= 0 ||
         downstream->get_request_minor() <= 0) {
        // We simply close connection for pre-HTTP/1.1 in this case.
        downstream->set_response_connection_close(true);
      } else {
        // Otherwise, use chunked encoding to keep upstream
        // connection open.  In HTTP2, we are supporsed not to
        // receive transfer-encoding.
        downstream->add_response_header("transfer-encoding", "chunked");
        downstream->set_chunked_response(true);
      }
    }
  }

  downstream->set_response_state(Downstream::HEADER_COMPLETE);
  downstream->check_upgrade_fulfilled();
  if(downstream->get_upgraded()) {
    downstream->set_response_connection_close(true);
    // On upgrade sucess, both ends can send data
    if(upstream->resume_read(SHRPX_MSG_BLOCK, downstream) != 0) {
      // If resume_read fails, just drop connection. Not ideal.
      delete upstream->get_client_handler();
      return 0;
    }
    downstream->set_request_state(Downstream::HEADER_COMPLETE);
    if(LOG_ENABLED(INFO)) {
      SSLOG(INFO, http2session) << "HTTP upgrade success. stream_id="
                                << frame->hd.stream_id;
    }
  } else if(downstream->get_request_method() == "CONNECT") {
    // If request is CONNECT, terminate request body to avoid for
    // stream to stall.
    downstream->end_upload_data();
  }
  rv = upstream->on_downstream_header_complete(downstream);
  if(rv != 0) {
    http2session->submit_rst_stream(frame->hd.stream_id,
                                    NGHTTP2_PROTOCOL_ERROR);
    downstream->set_response_state(Downstream::MSG_RESET);
  }
  call_downstream_readcb(http2session, downstream);
  return 0;
}
} // namespace

namespace {
int on_frame_recv_callback
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
  int rv;
  auto http2session = static_cast<Http2Session*>(user_data);

  switch(frame->hd.type) {
  case NGHTTP2_DATA: {
    auto sd = static_cast<StreamData*>
      (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
    if(!sd || !sd->dconn) {
      break;
    }
    auto downstream = sd->dconn->get_downstream();
    if(!downstream ||
       downstream->get_downstream_stream_id() != frame->hd.stream_id) {
      break;
    }

    auto upstream = downstream->get_upstream();
    rv = upstream->on_downstream_body(downstream, nullptr, 0, true);
    if(rv != 0) {
      http2session->submit_rst_stream(frame->hd.stream_id,
                                      NGHTTP2_INTERNAL_ERROR);
      downstream->set_response_state(Downstream::MSG_RESET);

    } else if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {

      if(downstream->get_response_state() != Downstream::MSG_RESET) {

        downstream->set_response_state(Downstream::MSG_COMPLETE);

        rv = upstream->on_downstream_body_complete(downstream);

        if(rv != 0) {
          downstream->set_response_state(Downstream::MSG_RESET);
        }
      }
    }

    call_downstream_readcb(http2session, downstream);
    break;
  }
  case NGHTTP2_HEADERS: {
    auto sd = static_cast<StreamData*>
      (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
    if(!sd || !sd->dconn) {
      break;
    }
    auto downstream = sd->dconn->get_downstream();

    if(!downstream) {
      return 0;
    }

    if(frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      rv = on_response_headers(http2session, downstream, session, frame);

      if(rv != 0) {
        return rv;
      }
    }

    if(frame->headers.cat == NGHTTP2_HCAT_HEADERS &&
       downstream->get_expect_final_response()) {

      rv = on_response_headers(http2session, downstream, session, frame);

      if(rv != 0) {
        return rv;
      }
    }

    if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      if(downstream->get_response_state() != Downstream::MSG_RESET) {
        downstream->set_response_state(Downstream::MSG_COMPLETE);

        auto upstream = downstream->get_upstream();

        rv = upstream->on_downstream_body_complete(downstream);

        if(rv != 0) {
          downstream->set_response_state(Downstream::MSG_RESET);
        }
      }
    }
    break;
  }
  case NGHTTP2_RST_STREAM: {
    auto sd = static_cast<StreamData*>
      (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
    if(sd && sd->dconn) {
      auto downstream = sd->dconn->get_downstream();
      if(downstream &&
         downstream->get_downstream_stream_id() == frame->hd.stream_id) {
        if(downstream->get_upgraded() &&
           downstream->get_response_state() == Downstream::HEADER_COMPLETE) {
          // For tunneled connection, we have to submit RST_STREAM to
          // upstream *after* whole response body is sent. We just set
          // MSG_COMPLETE here. Upstream will take care of that.
          if(LOG_ENABLED(INFO)) {
            SSLOG(INFO, http2session) << "RST_STREAM against tunneled stream "
                                      << "stream_id="
                                      << frame->hd.stream_id;
          }
          downstream->get_upstream()->on_downstream_body_complete(downstream);
          downstream->set_response_state(Downstream::MSG_COMPLETE);
        } else {
          // If we got RST_STREAM, just flag MSG_RESET to indicate
          // upstream connection must be terminated.
          downstream->set_response_state(Downstream::MSG_RESET);
        }
        downstream->set_response_rst_stream_error_code
          (frame->rst_stream.error_code);
        call_downstream_readcb(http2session, downstream);
      }
    }
    break;
  }
  case NGHTTP2_SETTINGS:
    if((frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) {
      break;
    }
    http2session->stop_settings_timer();
    break;
  case NGHTTP2_PUSH_PROMISE:
    if(LOG_ENABLED(INFO)) {
      SSLOG(INFO, http2session)
        << "Received downstream PUSH_PROMISE stream_id=" << frame->hd.stream_id
        << ", promised_stream_id=" << frame->push_promise.promised_stream_id;
    }
    // We just respond with RST_STREAM.
    http2session->submit_rst_stream(frame->push_promise.promised_stream_id,
                                    NGHTTP2_REFUSED_STREAM);
    break;
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
  int rv;
  auto http2session = static_cast<Http2Session*>(user_data);
  auto sd = static_cast<StreamData*>
    (nghttp2_session_get_stream_user_data(session, stream_id));
  if(!sd || !sd->dconn) {
    http2session->submit_rst_stream(stream_id, NGHTTP2_INTERNAL_ERROR);

    if(http2session->consume(stream_id, len) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
  }
  auto downstream = sd->dconn->get_downstream();
  if(!downstream || downstream->get_downstream_stream_id() != stream_id ||
     !downstream->expect_response_body()) {

    http2session->submit_rst_stream(stream_id, NGHTTP2_INTERNAL_ERROR);

    if(http2session->consume(stream_id, len) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
  }

  // We don't want DATA after non-final response, which is illegal in
  // HTTP.
  if(downstream->get_non_final_response()) {
    http2session->submit_rst_stream(stream_id, NGHTTP2_PROTOCOL_ERROR);

    if(http2session->consume(stream_id, len) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
  }

  downstream->add_response_bodylen(len);

  auto upstream = downstream->get_upstream();
  rv = upstream->on_downstream_body(downstream, data, len, false);
  if(rv != 0) {
    http2session->submit_rst_stream(stream_id, NGHTTP2_INTERNAL_ERROR);

    if(http2session->consume(stream_id, len) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    downstream->set_response_state(Downstream::MSG_RESET);
  }

  downstream->add_response_datalen(len);

  call_downstream_readcb(http2session, downstream);
  return 0;
}
} // namespace

namespace {
int on_frame_send_callback(nghttp2_session* session,
                           const nghttp2_frame *frame, void *user_data)
{
  auto http2session = static_cast<Http2Session*>(user_data);
  if(frame->hd.type == NGHTTP2_SETTINGS &&
     (frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) {
    if(http2session->start_settings_timer() != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}
} // namespace

namespace {
int on_frame_not_send_callback(nghttp2_session *session,
                               const nghttp2_frame *frame,
                               int lib_error_code, void *user_data)
{
  auto http2session = static_cast<Http2Session*>(user_data);
  SSLOG(WARNING, http2session) << "Failed to send control frame type="
                               << static_cast<uint32_t>(frame->hd.type)
                               << "lib_error_code=" << lib_error_code << ":"
                               << nghttp2_strerror(lib_error_code);
  if(frame->hd.type == NGHTTP2_HEADERS &&
     frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
    // To avoid stream hanging around, flag Downstream::MSG_RESET and
    // terminate the upstream and downstream connections.
    auto sd = static_cast<StreamData*>
      (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
    if(!sd) {
      return 0;
    }
    if(sd->dconn) {
      auto downstream = sd->dconn->get_downstream();
      if(!downstream ||
         downstream->get_downstream_stream_id() != frame->hd.stream_id) {
        return 0;
      }
      downstream->set_response_state(Downstream::MSG_RESET);
      call_downstream_readcb(http2session, downstream);
    }
    http2session->remove_stream_data(sd);
  }
  return 0;
}
} // namespace

namespace {
int on_unknown_frame_recv_callback(nghttp2_session *session,
                                   const uint8_t *head, size_t headlen,
                                   const uint8_t *payload, size_t payloadlen,
                                   void *user_data)
{
  auto http2session = static_cast<Http2Session*>(user_data);
  if(LOG_ENABLED(INFO)) {
    SSLOG(INFO, http2session) << "Received unknown control frame";
  }
  return 0;
}
} // namespace

int Http2Session::on_connect()
{
  int rv;
  if(ssl_ctx_) {
    const unsigned char *next_proto = nullptr;
    unsigned int next_proto_len;
    SSL_get0_next_proto_negotiated(ssl_, &next_proto, &next_proto_len);
    for(int i = 0; i < 2; ++i) {
      if(next_proto) {
        if(LOG_ENABLED(INFO)) {
          std::string proto(next_proto, next_proto+next_proto_len);
          SSLOG(INFO, this) << "Negotiated next protocol: " << proto;
        }
        if(next_proto_len != NGHTTP2_PROTO_VERSION_ID_LEN ||
           memcmp(NGHTTP2_PROTO_VERSION_ID, next_proto,
                  NGHTTP2_PROTO_VERSION_ID_LEN) != 0) {
          return -1;
        }
        break;
      }
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
      SSL_get0_alpn_selected(ssl_, &next_proto, &next_proto_len);
#else // OPENSSL_VERSION_NUMBER < 0x10002000L
      break;
#endif // OPENSSL_VERSION_NUMBER < 0x10002000L
    }
    if(!next_proto) {
      return -1;
    }
  }
  nghttp2_session_callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.on_stream_close_callback = on_stream_close_callback;
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.on_frame_not_send_callback = on_frame_not_send_callback;
  callbacks.on_unknown_frame_recv_callback = on_unknown_frame_recv_callback;
  callbacks.on_header_callback = on_header_callback;
  callbacks.on_begin_headers_callback = on_begin_headers_callback;
  if(get_config()->padding) {
    callbacks.select_padding_callback = http::select_padding_callback;
  }

  rv = nghttp2_session_client_new2(&session_, &callbacks, this,
                                   get_config()->http2_option);

  if(rv != 0) {
    return -1;
  }

  flow_control_ = true;

  nghttp2_settings_entry entry[3];
  entry[0].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
  entry[0].value = 0;
  entry[1].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  entry[1].value = get_config()->http2_max_concurrent_streams;

  entry[2].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  entry[2].value = (1 << get_config()->http2_downstream_window_bits) - 1;

  rv = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, entry,
                               sizeof(entry)/sizeof(nghttp2_settings_entry));
  if(rv != 0) {
    return -1;
  }

  if(get_config()->http2_downstream_connection_window_bits > 16) {
    int32_t delta =
      (1 << get_config()->http2_downstream_connection_window_bits) - 1
      - NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE;
    rv = nghttp2_submit_window_update(session_, NGHTTP2_FLAG_NONE, 0, delta);
    if(rv != 0) {
      return -1;
    }
  }

  rv = bufferevent_write(bev_, NGHTTP2_CLIENT_CONNECTION_PREFACE,
                         NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN);
  if(rv != 0) {
    SSLOG(FATAL, this) << "bufferevent_write() failed";
    return -1;
  }

  if(!get_config()->downstream_no_tls &&
     !ssl::check_http2_requirement(ssl_)) {

    rv = terminate_session(NGHTTP2_INADEQUATE_SECURITY);

    if(rv != 0) {
      return -1;
    }
  }

  rv = send();
  if(rv != 0) {
    return -1;
  }

  if(!get_config()->downstream_no_tls &&
     !ssl::check_http2_requirement(ssl_)) {

    return 0;
  }

  // submit pending request
  for(auto dconn : dconns_) {
    if(dconn->push_request_headers() == 0) {
      continue;
    }

    if(LOG_ENABLED(INFO)) {
      SSLOG(INFO, this) << "backend request failed";
    }

    auto downstream = dconn->get_downstream();

    if(!downstream) {
      continue;
    }

    auto upstream = downstream->get_upstream();

    upstream->on_downstream_abort_request(downstream, 400);
  }
  return 0;
}

int Http2Session::on_read()
{
  ssize_t rv = 0;
  auto input = bufferevent_get_input(bev_);

  for(;;) {
    auto inputlen = evbuffer_get_contiguous_space(input);

    if(inputlen == 0) {
      assert(evbuffer_get_length(input) == 0);

      return send();
    }

    auto mem = evbuffer_pullup(input, inputlen);

    rv = nghttp2_session_mem_recv(session_, mem, inputlen);

    if(rv < 0) {
      SSLOG(ERROR, this) << "nghttp2_session_recv() returned error: "
                         << nghttp2_strerror(rv);
      return -1;
    }

    if(evbuffer_drain(input, rv) != 0) {
      SSLOG(FATAL, this) << "evbuffer_drain() faild";
      return -1;
    }
  }
}

int Http2Session::on_write()
{
  return send();
}

int Http2Session::send()
{
  int rv;
  uint8_t buf[16384];
  auto output = bufferevent_get_output(bev_);
  util::EvbufferBuffer evbbuf(output, buf, sizeof(buf));
  for(;;) {
    // Check buffer length and return WOULDBLOCK if it is large enough.
    if(evbuffer_get_length(output) + evbbuf.get_buflen() >
       Http2Session::OUTBUF_MAX_THRES) {
      return NGHTTP2_ERR_WOULDBLOCK;
    }

    const uint8_t *data;
    auto datalen = nghttp2_session_mem_send(session_, &data);

    if(datalen < 0) {
      SSLOG(ERROR, this) << "nghttp2_session_mem_send() returned error: "
                         << nghttp2_strerror(datalen);
      break;
    }
    if(datalen == 0) {
      break;
    }
    rv = evbbuf.add(data, datalen);
    if(rv != 0) {
      SSLOG(FATAL, this) << "evbuffer_add() failed";
      return -1;
    }
  }

  rv = evbbuf.flush();
  if(rv != 0) {
    SSLOG(FATAL, this) << "evbuffer_add() failed";
    return -1;
  }

  if(nghttp2_session_want_read(session_) == 0 &&
     nghttp2_session_want_write(session_) == 0 &&
     evbuffer_get_length(output) == 0) {
    if(LOG_ENABLED(INFO)) {
      SSLOG(INFO, this) << "No more read/write for this session";
    }
    return -1;
  }
  return 0;
}

void Http2Session::clear_notify()
{
  auto input = bufferevent_get_output(rdbev_);
  if(evbuffer_drain(input, evbuffer_get_length(input)) != 0) {
    SSLOG(FATAL, this) << "evbuffer_drain() failed";
  }
  notified_ = false;
}

void Http2Session::notify()
{
  if(!notified_) {
    if(bufferevent_write(wrbev_, "1", 1) != 0) {
      SSLOG(FATAL, this) << "bufferevent_write failed";
    }
    notified_ = true;
  }
}

bufferevent* Http2Session::get_bev() const
{
  return bev_;
}

int Http2Session::get_state() const
{
  return state_;
}

void Http2Session::set_state(int state)
{
  state_ = state;
}

int Http2Session::terminate_session(nghttp2_error_code error_code)
{
  int rv;
  rv = nghttp2_session_terminate_session(session_, error_code);
  if(rv != 0) {
    return -1;
  }
  return 0;
}

size_t Http2Session::get_outbuf_length() const
{
  if(bev_) {
    return evbuffer_get_length(bufferevent_get_output(bev_));
  } else {
    return OUTBUF_MAX_THRES;
  }
}

SSL* Http2Session::get_ssl() const
{
  return ssl_;
}

int Http2Session::consume(int32_t stream_id, size_t len)
{
  int rv;

  rv = nghttp2_session_consume(session_, stream_id, len);

  if(rv != 0) {
    SSLOG(WARNING, this) << "nghttp2_session_consume() returned error: "
                         << nghttp2_strerror(rv);

    return -1;
  }

  return 0;
}

} // namespace shrpx
