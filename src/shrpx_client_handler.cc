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
#include "shrpx_client_handler.h"

#include <unistd.h>
#include <cerrno>

#include "shrpx_upstream.h"
#include "shrpx_http2_upstream.h"
#include "shrpx_https_upstream.h"
#include "shrpx_config.h"
#include "shrpx_http_downstream_connection.h"
#include "shrpx_http2_downstream_connection.h"
#include "shrpx_ssl.h"
#include "shrpx_worker.h"
#include "shrpx_worker_config.h"
#include "shrpx_downstream_connection_pool.h"
#ifdef HAVE_SPDYLAY
#include "shrpx_spdy_upstream.h"
#endif // HAVE_SPDYLAY
#include "util.h"
#include "libevent_util.h"

using namespace nghttp2;

namespace shrpx {

namespace {
void upstream_readcb(bufferevent *bev, void *arg)
{
  auto handler = static_cast<ClientHandler*>(arg);
  auto upstream = handler->get_upstream();
  if(upstream) {
    upstream->reset_timeouts();
  }
  int rv = handler->on_read();
  if(rv != 0) {
    delete handler;
  }
}
} // namespace

namespace {
void upstream_writecb(bufferevent *bev, void *arg)
{
  auto handler = static_cast<ClientHandler*>(arg);
  auto upstream = handler->get_upstream();
  if(upstream) {
    upstream->reset_timeouts();
  }

  handler->update_last_write_time();

  // We actually depend on write low-water mark == 0.
  if(handler->get_outbuf_length() > 0) {
    // Possibly because of deferred callback, we may get this callback
    // when the output buffer is not empty.
    return;
  }
  if(handler->get_should_close_after_write()) {
    delete handler;
    return;
  }

  if(!upstream) {
    return;
  }
  int rv = upstream->on_write();
  if(rv != 0) {
    delete handler;
  }
}
} // namespace

namespace {
void upstream_eventcb(bufferevent *bev, short events, void *arg)
{
  auto handler = static_cast<ClientHandler*>(arg);
  bool finish = false;
  if(events & BEV_EVENT_EOF) {
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, handler) << "EOF";
    }
    finish = true;
  }
  if(events & BEV_EVENT_ERROR) {
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, handler) << "Network error: "
                          << evutil_socket_error_to_string
        (EVUTIL_SOCKET_ERROR());
    }
    finish = true;
  }
  if(events & BEV_EVENT_TIMEOUT) {
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, handler) << "Time out";
    }
    finish = true;
  }
  if(finish) {
    delete handler;
  } else {
    if(events & BEV_EVENT_CONNECTED) {
      handler->set_tls_handshake(true);
      if(LOG_ENABLED(INFO)) {
        CLOG(INFO, handler) << "SSL/TLS handshake completed";
      }
      if(handler->validate_next_proto() != 0) {
        delete handler;
        return;
      }
      if(LOG_ENABLED(INFO)) {
        if(SSL_session_reused(handler->get_ssl())) {
          CLOG(INFO, handler) << "SSL/TLS session reused";
        }
      }
    }
  }
}
} // namespace

namespace {
void upstream_http2_connhd_readcb(bufferevent *bev, void *arg)
{
  // This callback assumes upstream is Http2Upstream.
  auto handler = static_cast<ClientHandler*>(arg);
  if(handler->on_http2_connhd_read() != 0) {
    delete handler;
  }
}
} // namespace

namespace {
void upstream_http1_connhd_readcb(bufferevent *bev, void *arg)
{
  // This callback assumes upstream is HttpsUpstream.
  auto handler = static_cast<ClientHandler*>(arg);
  if(handler->on_http1_connhd_read() != 0) {
    delete handler;
  }
}
} // namespace

ClientHandler::ClientHandler(bufferevent *bev,
                             bufferevent_rate_limit_group *rate_limit_group,
                             int fd, SSL *ssl,
                             const char *ipaddr,
                             WorkerStat *worker_stat,
                             DownstreamConnectionPool *dconn_pool)
  : ipaddr_(ipaddr),
    dconn_pool_(dconn_pool),
    bev_(bev),
    http2session_(nullptr),
    ssl_(ssl),
    reneg_shutdown_timerev_(nullptr),
    worker_stat_(worker_stat),
    last_write_time_(0),
    warmup_writelen_(0),
    left_connhd_len_(NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN),
    fd_(fd),
    should_close_after_write_(false),
    tls_handshake_(false),
    tls_renegotiation_(false)
{
  int rv;

  ++worker_stat->num_connections;

  rv = bufferevent_set_rate_limit(bev_, get_config()->rate_limit_cfg);
  if(rv == -1) {
    CLOG(FATAL, this) << "bufferevent_set_rate_limit() failed";
  }

  rv = bufferevent_add_to_rate_limit_group(bev_, rate_limit_group);
  if(rv == -1) {
    CLOG(FATAL, this) << "bufferevent_add_to_rate_limit_group() failed";
  }

  util::bev_enable_unless(bev_, EV_READ | EV_WRITE);
  bufferevent_setwatermark(bev_, EV_READ, 0, SHRPX_READ_WATERMARK);
  set_upstream_timeouts(&get_config()->upstream_read_timeout,
                        &get_config()->upstream_write_timeout);
  if(ssl_) {
    SSL_set_app_data(ssl_, reinterpret_cast<char*>(this));
    set_bev_cb(nullptr, upstream_writecb, upstream_eventcb);
  } else {
    // For non-TLS version, first create HttpsUpstream. It may be
    // upgraded to HTTP/2 through HTTP Upgrade or direct HTTP/2
    // connection.
    upstream_ = util::make_unique<HttpsUpstream>(this);
    set_bev_cb(upstream_http1_connhd_readcb, nullptr, upstream_eventcb);
  }
}

ClientHandler::~ClientHandler()
{
  if(LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Deleting";
  }

  --worker_stat_->num_connections;

  // TODO If backend is http/2, and it is in CONNECTED state, signal
  // it and make it loopbreak when output is zero.
  if(worker_config->graceful_shutdown && worker_stat_->num_connections == 0) {
    event_base_loopbreak(get_evbase());
  }

  if(reneg_shutdown_timerev_) {
    event_free(reneg_shutdown_timerev_);
  }

  if(ssl_) {
    SSL_set_app_data(ssl_, nullptr);
    SSL_set_shutdown(ssl_, SSL_RECEIVED_SHUTDOWN);
    SSL_shutdown(ssl_);
  }

  bufferevent_remove_from_rate_limit_group(bev_);

  util::bev_disable_unless(bev_, EV_READ | EV_WRITE);
  bufferevent_free(bev_);

  if(ssl_) {
    SSL_free(ssl_);
  }

  shutdown(fd_, SHUT_WR);
  close(fd_);
  if(LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Deleted";
  }
}

Upstream* ClientHandler::get_upstream()
{
  return upstream_.get();
}

bufferevent* ClientHandler::get_bev() const
{
  return bev_;
}

event_base* ClientHandler::get_evbase() const
{
  return bufferevent_get_base(bev_);
}

void ClientHandler::set_bev_cb
(bufferevent_data_cb readcb, bufferevent_data_cb writecb,
 bufferevent_event_cb eventcb)
{
  bufferevent_setcb(bev_, readcb, writecb, eventcb, this);
}

void ClientHandler::set_upstream_timeouts(const timeval *read_timeout,
                                          const timeval *write_timeout)
{
  bufferevent_set_timeouts(bev_, read_timeout, write_timeout);
}

int ClientHandler::validate_next_proto()
{
  const unsigned char *next_proto = nullptr;
  unsigned int next_proto_len;
  int rv;

  // First set callback for catch all cases
  set_bev_cb(upstream_readcb, upstream_writecb, upstream_eventcb);
  SSL_get0_next_proto_negotiated(ssl_, &next_proto, &next_proto_len);
  for(int i = 0; i < 2; ++i) {
    if(next_proto) {
      if(LOG_ENABLED(INFO)) {
        std::string proto(next_proto, next_proto+next_proto_len);
        CLOG(INFO, this) << "The negotiated next protocol: " << proto;
      }
      if(!ssl::in_proto_list(get_config()->npn_list,
                             next_proto, next_proto_len)) {
        break;
      }
      if(util::check_h2_is_selected(next_proto, next_proto_len)) {

        set_bev_cb(upstream_http2_connhd_readcb, upstream_writecb,
                   upstream_eventcb);

        auto http2_upstream = util::make_unique<Http2Upstream>(this);

        if(!ssl::check_http2_requirement(ssl_)) {
          rv = http2_upstream->terminate_session(NGHTTP2_INADEQUATE_SECURITY);

          if(rv != 0) {
            return -1;
          }
        }

        upstream_ = std::move(http2_upstream);

        // At this point, input buffer is already filled with some
        // bytes.  The read callback is not called until new data
        // come. So consume input buffer here.
        if(on_http2_connhd_read() != 0) {
          return -1;
        }

        return 0;
      } else {
#ifdef HAVE_SPDYLAY
        uint16_t version = spdylay_npn_get_version(next_proto, next_proto_len);
        if(version) {
          upstream_ = util::make_unique<SpdyUpstream>(version, this);

          // At this point, input buffer is already filled with some
          // bytes.  The read callback is not called until new data
          // come. So consume input buffer here.
          if(upstream_->on_read() != 0) {
            return -1;
          }

          return 0;
        }
#endif // HAVE_SPDYLAY
        if(next_proto_len == 8 && memcmp("http/1.1", next_proto, 8) == 0) {
          upstream_ = util::make_unique<HttpsUpstream>(this);

          // At this point, input buffer is already filled with some
          // bytes.  The read callback is not called until new data
          // come. So consume input buffer here.
          if(upstream_->on_read() != 0) {
            return -1;
          }

          return 0;
        }
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
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "No protocol negotiated. Fallback to HTTP/1.1";
    }
    upstream_ = util::make_unique<HttpsUpstream>(this);

    // At this point, input buffer is already filled with some bytes.
    // The read callback is not called until new data come. So consume
    // input buffer here.
    if(upstream_->on_read() != 0) {
      return -1;
    }

    return 0;
  }
  if(LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "The negotiated protocol is not supported";
  }
  return -1;
}

int ClientHandler::on_read()
{
  return upstream_->on_read();
}

int ClientHandler::on_event()
{
  return upstream_->on_event();
}

int ClientHandler::on_http2_connhd_read()
{
  // This callback assumes upstream is Http2Upstream.
  uint8_t data[NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN];
  auto input = bufferevent_get_input(bev_);
  auto readlen = evbuffer_remove(input, data, left_connhd_len_);

  if(readlen == -1) {
    return -1;
  }

  if(memcmp(NGHTTP2_CLIENT_CONNECTION_PREFACE +
            NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN - left_connhd_len_,
            data, readlen) != 0) {
    // There is no downgrade path here. Just drop the connection.
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "invalid client connection header";
    }

    return -1;
  }

  left_connhd_len_ -= readlen;

  if(left_connhd_len_ > 0) {
    return 0;
  }

  set_bev_cb(upstream_readcb, upstream_writecb, upstream_eventcb);

  // Run on_read to process data left in buffer since they are not
  // notified further
  if(on_read() != 0) {
    return -1;
  }

  return 0;
}

int ClientHandler::on_http1_connhd_read()
{
  uint8_t data[NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN];
  auto input = bufferevent_get_input(bev_);
  auto readlen = evbuffer_copyout(input, data, left_connhd_len_);

  if(readlen == -1) {
    return -1;
  }

  if(memcmp(NGHTTP2_CLIENT_CONNECTION_PREFACE +
            NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN - left_connhd_len_,
            data, readlen) != 0) {
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "This is HTTP/1.1 connection, "
                       << "but may be upgraded to HTTP/2 later.";
    }

    // Reset header length for later HTTP/2 upgrade
    left_connhd_len_ = NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN;
    set_bev_cb(upstream_readcb, upstream_writecb, upstream_eventcb);

    if(on_read() != 0) {
      return -1;
    }

    return 0;
  }

  if(evbuffer_drain(input, readlen) == -1) {
    return -1;
  }

  left_connhd_len_ -= readlen;

  if(left_connhd_len_ > 0) {
    return 0;
  }

  if(LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "direct HTTP/2 connection";
  }

  direct_http2_upgrade();
  set_bev_cb(upstream_readcb, upstream_writecb, upstream_eventcb);

  // Run on_read to process data left in buffer since they are not
  // notified further
  if(on_read() != 0) {
    return -1;
  }

  return 0;
}

const std::string& ClientHandler::get_ipaddr() const
{
  return ipaddr_;
}

bool ClientHandler::get_should_close_after_write() const
{
  return should_close_after_write_;
}

void ClientHandler::set_should_close_after_write(bool f)
{
  should_close_after_write_ = f;
}

void ClientHandler::pool_downstream_connection
(std::unique_ptr<DownstreamConnection> dconn)
{
  if(LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Pooling downstream connection DCONN:" << dconn.get();
  }
  dconn->set_client_handler(nullptr);
  dconn_pool_->add_downstream_connection(std::move(dconn));
}

void ClientHandler::remove_downstream_connection(DownstreamConnection *dconn)
{
  if(LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Removing downstream connection DCONN:" << dconn
                     << " from pool";
  }
  dconn_pool_->remove_downstream_connection(dconn);
}

std::unique_ptr<DownstreamConnection>
ClientHandler::get_downstream_connection()
{
  auto dconn = dconn_pool_->pop_downstream_connection();

  if(!dconn) {
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "Downstream connection pool is empty."
                       << " Create new one";
    }

    if(http2session_) {
      dconn = util::make_unique<Http2DownstreamConnection>
        (dconn_pool_, http2session_);
    } else {
      dconn = util::make_unique<HttpDownstreamConnection>(dconn_pool_);
    }
    dconn->set_client_handler(this);
    return dconn;
  }

  dconn->set_client_handler(this);

  if(LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Reuse downstream connection DCONN:" << dconn.get()
                     << " from pool";
  }

  return dconn;
}

size_t ClientHandler::get_outbuf_length()
{
  return evbuffer_get_length(bufferevent_get_output(bev_));
}

SSL* ClientHandler::get_ssl() const
{
  return ssl_;
}

void ClientHandler::set_http2_session(Http2Session *http2session)
{
  http2session_ = http2session;
}

Http2Session* ClientHandler::get_http2_session() const
{
  return http2session_;
}

void ClientHandler::set_http1_connect_blocker
(ConnectBlocker *http1_connect_blocker)
{
  http1_connect_blocker_ = http1_connect_blocker;
}

ConnectBlocker* ClientHandler::get_http1_connect_blocker() const
{
  return http1_connect_blocker_;
}

void ClientHandler::direct_http2_upgrade()
{
  upstream_= util::make_unique<Http2Upstream>(this);
  set_bev_cb(upstream_readcb, upstream_writecb, upstream_eventcb);
}

int ClientHandler::perform_http2_upgrade(HttpsUpstream *http)
{
  int rv;
  auto upstream = util::make_unique<Http2Upstream>(this);
  if(upstream->upgrade_upstream(http) != 0) {
    return -1;
  }
  // http pointer is now owned by upstream.
  upstream_.release();
  upstream_ = std::move(upstream);
  set_bev_cb(upstream_http2_connhd_readcb, upstream_writecb, upstream_eventcb);
  static char res[] = "HTTP/1.1 101 Switching Protocols\r\n"
    "Connection: Upgrade\r\n"
    "Upgrade: " NGHTTP2_CLEARTEXT_PROTO_VERSION_ID "\r\n"
    "\r\n";
  rv = bufferevent_write(bev_, res, sizeof(res) - 1);
  if(rv != 0) {
    CLOG(FATAL, this) << "bufferevent_write() faild";
    return -1;
  }
  return 0;
}

bool ClientHandler::get_http2_upgrade_allowed() const
{
  return !ssl_;
}

std::string ClientHandler::get_upstream_scheme() const
{
  if(ssl_) {
    return "https";
  } else {
    return "http";
  }
}

void ClientHandler::set_tls_handshake(bool f)
{
  tls_handshake_ = f;
}

bool ClientHandler::get_tls_handshake() const
{
  return tls_handshake_;
}

namespace {
void shutdown_cb(evutil_socket_t fd, short what, void *arg)
{
  auto handler = static_cast<ClientHandler*>(arg);

  if(LOG_ENABLED(INFO)) {
    CLOG(INFO, handler) << "Close connection due to TLS renegotiation";
  }

  delete handler;
}
} // namespace

void ClientHandler::set_tls_renegotiation(bool f)
{
  if(tls_renegotiation_ == false) {
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "TLS renegotiation detected. "
                       << "Start shutdown timer now.";
    }

    reneg_shutdown_timerev_ = evtimer_new(get_evbase(), shutdown_cb, this);
    event_priority_set(reneg_shutdown_timerev_, 0);

    timeval timeout = {0, 0};

    // TODO What to do if this failed?
    evtimer_add(reneg_shutdown_timerev_, &timeout);
  }
  tls_renegotiation_ = f;
}

bool ClientHandler::get_tls_renegotiation() const
{
  return tls_renegotiation_;
}

namespace {
const size_t SHRPX_SMALL_WRITE_LIMIT = 1300;
const size_t SHRPX_WARMUP_THRESHOLD = 1 << 20;
} // namespace

ssize_t ClientHandler::get_write_limit()
{
  if(!ssl_) {
    return -1;
  }

  timeval tv;
  if(event_base_gettimeofday_cached(get_evbase(), &tv) == 0) {
    auto now = util::to_time64(tv);
    if(now - last_write_time_ > 1000000) {
      // Time out, use small record size
      warmup_writelen_ = 0;
      return SHRPX_SMALL_WRITE_LIMIT;
    }
  }

  // If event_base_gettimeofday_cached() failed, we just skip timer
  // checking.  Don't know how to treat this.

  if(warmup_writelen_ >= SHRPX_WARMUP_THRESHOLD) {
    return -1;
  }

  return SHRPX_SMALL_WRITE_LIMIT;
}

void ClientHandler::update_warmup_writelen(size_t n)
{
  if(warmup_writelen_ < SHRPX_WARMUP_THRESHOLD) {
    warmup_writelen_ += n;
  }
}

void ClientHandler::update_last_write_time()
{
  timeval tv;
  if(event_base_gettimeofday_cached(get_evbase(), &tv) == 0) {
    last_write_time_ = util::to_time64(tv);
  }
}

} // namespace shrpx
