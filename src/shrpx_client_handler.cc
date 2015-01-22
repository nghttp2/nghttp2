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
#include "shrpx_downstream.h"
#ifdef HAVE_SPDYLAY
#include "shrpx_spdy_upstream.h"
#endif // HAVE_SPDYLAY
#include "util.h"

using namespace nghttp2;

namespace shrpx {

namespace {
void timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto handler = static_cast<ClientHandler *>(w->data);

  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, handler) << "Time out";
  }

  delete handler;
}
} // namespace

namespace {
void shutdowncb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto handler = static_cast<ClientHandler *>(w->data);

  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, handler) << "Close connection due to TLS renegotiation";
  }

  delete handler;
}
} // namespace

namespace {
void readcb(struct ev_loop *loop, ev_io *w, int revents) {
  auto handler = static_cast<ClientHandler *>(w->data);

  if (handler->do_read() != 0) {
    delete handler;
    return;
  }
}
} // namespace

namespace {
void writecb(struct ev_loop *loop, ev_io *w, int revents) {
  auto handler = static_cast<ClientHandler *>(w->data);

  if (handler->do_write() != 0) {
    delete handler;
    return;
  }
}
} // namespace

int ClientHandler::read_clear() {
  ev_timer_again(loop_, &rt_);

  for (;;) {
    // we should process buffered data first before we read EOF.
    if (rb_.rleft() && on_read() != 0) {
      return -1;
    }
    if (rb_.rleft()) {
      return 0;
    }
    rb_.reset();
    struct iovec iov[2];
    auto iovcnt = rb_.wiovec(iov);
    iovcnt = limit_iovec(iov, iovcnt, rlimit_.avail());
    if (iovcnt == 0) {
      break;
    }

    ssize_t nread;
    while ((nread = readv(fd_, iov, iovcnt)) == -1 && errno == EINTR)
      ;
    if (nread == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      return -1;
    }

    if (nread == 0) {
      return -1;
    }

    rb_.write(nread);
    rlimit_.drain(nread);
  }

  return 0;
}

int ClientHandler::write_clear() {
  ev_timer_again(loop_, &rt_);

  for (;;) {
    if (wb_.rleft() > 0) {
      struct iovec iov[2];
      auto iovcnt = wb_.riovec(iov);
      iovcnt = limit_iovec(iov, iovcnt, wlimit_.avail());
      if (iovcnt == 0) {
        return 0;
      }

      ssize_t nwrite;
      while ((nwrite = writev(fd_, iov, iovcnt)) == -1 && errno == EINTR)
        ;
      if (nwrite == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          wlimit_.startw();
          ev_timer_again(loop_, &wt_);
          return 0;
        }
        return -1;
      }
      wb_.drain(nwrite);
      wlimit_.drain(nwrite);
      continue;
    }
    wb_.reset();
    if (on_write() != 0) {
      return -1;
    }
    if (wb_.rleft() == 0) {
      break;
    }
  }

  wlimit_.stopw();
  ev_timer_stop(loop_, &wt_);

  return 0;
}

int ClientHandler::tls_handshake() {
  ev_timer_again(loop_, &rt_);

  ERR_clear_error();

  auto rv = SSL_do_handshake(ssl_);

  if (rv == 0) {
    return -1;
  }

  if (rv < 0) {
    auto err = SSL_get_error(ssl_, rv);
    switch (err) {
    case SSL_ERROR_WANT_READ:
      wlimit_.stopw();
      ev_timer_stop(loop_, &wt_);
      return 0;
    case SSL_ERROR_WANT_WRITE:
      wlimit_.startw();
      ev_timer_again(loop_, &wt_);
      return 0;
    default:
      return -1;
    }
  }

  wlimit_.stopw();
  ev_timer_stop(loop_, &wt_);

  set_tls_handshake(true);
  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "SSL/TLS handshake completed";
  }
  if (validate_next_proto() != 0) {
    return -1;
  }
  if (LOG_ENABLED(INFO)) {
    if (SSL_session_reused(ssl_)) {
      CLOG(INFO, this) << "SSL/TLS session reused";
    }
  }

  read_ = &ClientHandler::read_tls;
  write_ = &ClientHandler::write_tls;

  return 0;
}

int ClientHandler::read_tls() {
  ev_timer_again(loop_, &rt_);

  ERR_clear_error();

  for (;;) {
    // we should process buffered data first before we read EOF.
    if (rb_.rleft() && on_read() != 0) {
      return -1;
    }
    if (rb_.rleft()) {
      return 0;
    }
    rb_.reset();
    struct iovec iov[2];
    auto iovcnt = rb_.wiovec(iov);
    // SSL_read requires the same arguments (buf pointer and its
    // length) on SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.
    // rlimit_.avail() or rlimit_.avail() may return different length
    // than the length previously passed to SSL_read, which violates
    // OpenSSL assumption.  To avoid this, we keep last legnth passed
    // to SSL_read to tls_last_readlen_ if SSL_read indicated I/O
    // blocking.
    if (tls_last_readlen_ == 0) {
      iovcnt = limit_iovec(iov, iovcnt, rlimit_.avail());
      if (iovcnt == 0) {
        return 0;
      }
    } else {
      assert(iov[0].iov_len == tls_last_readlen_);
      tls_last_readlen_ = 0;
    }

    auto rv = SSL_read(ssl_, iov[0].iov_base, iov[0].iov_len);

    if (rv == 0) {
      return -1;
    }

    if (rv < 0) {
      auto err = SSL_get_error(ssl_, rv);
      switch (err) {
      case SSL_ERROR_WANT_READ:
        tls_last_readlen_ = iov[0].iov_len;
        return 0;
      case SSL_ERROR_WANT_WRITE:
        if (LOG_ENABLED(INFO)) {
          CLOG(INFO, this) << "Close connection due to TLS renegotiation";
        }
        return -1;
      default:
        if (LOG_ENABLED(INFO)) {
          CLOG(INFO, this) << "SSL_read: SSL_get_error returned " << err;
        }
        return -1;
      }
    }

    rb_.write(rv);
    rlimit_.drain(rv);
  }
}

int ClientHandler::write_tls() {
  ev_timer_again(loop_, &rt_);

  ERR_clear_error();

  for (;;) {
    if (wb_.rleft() > 0) {
      const void *p;
      size_t len;
      std::tie(p, len) = wb_.get();

      // SSL_write requires the same arguments (buf pointer and its
      // length) on SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.
      // get_write_limit() may return smaller length than previously
      // passed to SSL_write, which violates OpenSSL assumption.  To
      // avoid this, we keep last legnth passed to SSL_write to
      // tls_last_writelen_ if SSL_write indicated I/O blocking.
      if (tls_last_writelen_ == 0) {
        len = std::min(len, wlimit_.avail());
        if (len == 0) {
          return 0;
        }

        auto limit = get_write_limit();
        if (limit != -1) {
          len = std::min(len, static_cast<size_t>(limit));
        }
      } else {
        assert(len >= tls_last_writelen_);

        len = tls_last_writelen_;
        tls_last_writelen_ = 0;
      }

      auto rv = SSL_write(ssl_, p, len);

      if (rv == 0) {
        return -1;
      }

      update_last_write_time();

      if (rv < 0) {
        auto err = SSL_get_error(ssl_, rv);
        switch (err) {
        case SSL_ERROR_WANT_READ:
          if (LOG_ENABLED(INFO)) {
            CLOG(INFO, this) << "Close connection due to TLS renegotiation";
          }
          return -1;
        case SSL_ERROR_WANT_WRITE:
          tls_last_writelen_ = len;
          wlimit_.startw();
          ev_timer_again(loop_, &wt_);
          return 0;
        default:
          if (LOG_ENABLED(INFO)) {
            CLOG(INFO, this) << "SSL_write: SSL_get_error returned " << err;
          }
          return -1;
        }
      }

      wb_.drain(rv);
      wlimit_.drain(rv);

      update_warmup_writelen(rv);

      continue;
    }
    wb_.reset();
    if (on_write() != 0) {
      return -1;
    }
    if (wb_.rleft() == 0) {
      break;
    }
  }

  wlimit_.stopw();
  ev_timer_stop(loop_, &wt_);

  return 0;
}

int ClientHandler::upstream_noop() { return 0; }

int ClientHandler::upstream_read() {
  assert(upstream_);
  if (upstream_->on_read() != 0) {
    return -1;
  }
  return 0;
}

int ClientHandler::upstream_write() {
  assert(upstream_);
  if (upstream_->on_write() != 0) {
    return -1;
  }

  if (get_should_close_after_write() && wb_.rleft() == 0) {
    return -1;
  }

  return 0;
}

int ClientHandler::upstream_http2_connhd_read() {
  struct iovec iov[2];
  auto iovcnt = rb_.riovec(iov);
  for (int i = 0; i < iovcnt; ++i) {
    auto nread =
        std::min(left_connhd_len_, static_cast<size_t>(iov[i].iov_len));
    if (memcmp(NGHTTP2_CLIENT_CONNECTION_PREFACE +
                   NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN - left_connhd_len_,
               iov[i].iov_base, nread) != 0) {
      // There is no downgrade path here. Just drop the connection.
      if (LOG_ENABLED(INFO)) {
        CLOG(INFO, this) << "invalid client connection header";
      }

      return -1;
    }

    left_connhd_len_ -= nread;
    rb_.drain(nread);

    if (left_connhd_len_ == 0) {
      on_read_ = &ClientHandler::upstream_read;
      // Run on_read to process data left in buffer since they are not
      // notified further
      if (on_read() != 0) {
        return -1;
      }
      return 0;
    }
  }

  return 0;
}

int ClientHandler::upstream_http1_connhd_read() {
  struct iovec iov[2];
  auto iovcnt = rb_.riovec(iov);
  for (int i = 0; i < iovcnt; ++i) {
    auto nread =
        std::min(left_connhd_len_, static_cast<size_t>(iov[i].iov_len));
    if (memcmp(NGHTTP2_CLIENT_CONNECTION_PREFACE +
                   NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN - left_connhd_len_,
               iov[i].iov_base, nread) != 0) {
      if (LOG_ENABLED(INFO)) {
        CLOG(INFO, this) << "This is HTTP/1.1 connection, "
                         << "but may be upgraded to HTTP/2 later.";
      }

      // Reset header length for later HTTP/2 upgrade
      left_connhd_len_ = NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN;
      on_read_ = &ClientHandler::upstream_read;
      on_write_ = &ClientHandler::upstream_write;

      if (on_read() != 0) {
        return -1;
      }

      return 0;
    }

    left_connhd_len_ -= nread;
    rb_.drain(nread);

    if (left_connhd_len_ == 0) {
      if (LOG_ENABLED(INFO)) {
        CLOG(INFO, this) << "direct HTTP/2 connection";
      }

      direct_http2_upgrade();
      on_read_ = &ClientHandler::upstream_read;
      on_write_ = &ClientHandler::upstream_write;

      // Run on_read to process data left in buffer since they are not
      // notified further
      if (on_read() != 0) {
        return -1;
      }

      return 0;
    }
  }

  return 0;
}

ClientHandler::ClientHandler(struct ev_loop *loop, int fd, SSL *ssl,
                             const char *ipaddr, const char *port,
                             WorkerStat *worker_stat,
                             DownstreamConnectionPool *dconn_pool)
    : ipaddr_(ipaddr), port_(port),
      wlimit_(loop, &wev_, get_config()->write_rate, get_config()->write_burst),
      rlimit_(loop, &rev_, get_config()->read_rate, get_config()->read_burst),
      loop_(loop), dconn_pool_(dconn_pool), http2session_(nullptr),
      http1_connect_blocker_(nullptr), ssl_(ssl), worker_stat_(worker_stat),
      last_write_time_(0.), warmup_writelen_(0),
      left_connhd_len_(NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN),
      tls_last_writelen_(0), tls_last_readlen_(0), fd_(fd),
      should_close_after_write_(false), tls_handshake_(false),
      tls_renegotiation_(false) {

  ++worker_stat->num_connections;

  ev_io_init(&wev_, writecb, fd_, EV_WRITE);
  ev_io_init(&rev_, readcb, fd_, EV_READ);

  wev_.data = this;
  rev_.data = this;

  ev_timer_init(&wt_, timeoutcb, 0., get_config()->upstream_write_timeout);
  ev_timer_init(&rt_, timeoutcb, 0., get_config()->upstream_read_timeout);

  wt_.data = this;
  rt_.data = this;

  ev_timer_init(&reneg_shutdown_timer_, shutdowncb, 0., 0.);

  reneg_shutdown_timer_.data = this;

  rlimit_.startw();
  ev_timer_again(loop_, &rt_);

  if (ssl_) {
    SSL_set_app_data(ssl_, reinterpret_cast<char *>(this));
    read_ = write_ = &ClientHandler::tls_handshake;
    on_read_ = &ClientHandler::upstream_noop;
    on_write_ = &ClientHandler::upstream_write;
  } else {
    // For non-TLS version, first create HttpsUpstream. It may be
    // upgraded to HTTP/2 through HTTP Upgrade or direct HTTP/2
    // connection.
    upstream_ = util::make_unique<HttpsUpstream>(this);
    alpn_ = "http/1.1";
    read_ = &ClientHandler::read_clear;
    write_ = &ClientHandler::write_clear;
    on_read_ = &ClientHandler::upstream_http1_connhd_read;
    on_write_ = &ClientHandler::upstream_noop;
  }
}

ClientHandler::~ClientHandler() {
  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Deleting";
  }

  if (upstream_) {
    upstream_->on_handler_delete();
  }

  --worker_stat_->num_connections;

  ev_timer_stop(loop_, &reneg_shutdown_timer_);

  ev_timer_stop(loop_, &rt_);
  ev_timer_stop(loop_, &wt_);

  ev_io_stop(loop_, &rev_);
  ev_io_stop(loop_, &wev_);

  // TODO If backend is http/2, and it is in CONNECTED state, signal
  // it and make it loopbreak when output is zero.
  if (worker_config->graceful_shutdown && worker_stat_->num_connections == 0) {
    ev_break(loop_);
  }

  if (ssl_) {
    SSL_set_app_data(ssl_, nullptr);
    SSL_set_shutdown(ssl_, SSL_RECEIVED_SHUTDOWN);
    ERR_clear_error();
    SSL_shutdown(ssl_);
  }

  if (ssl_) {
    SSL_free(ssl_);
  }

  shutdown(fd_, SHUT_WR);
  close(fd_);
  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Deleted";
  }
}

Upstream *ClientHandler::get_upstream() { return upstream_.get(); }

struct ev_loop *ClientHandler::get_loop() const {
  return loop_;
}

void ClientHandler::reset_upstream_read_timeout(ev_tstamp t) {
  rt_.repeat = t;
  if (ev_is_active(&rt_)) {
    ev_timer_again(loop_, &rt_);
  }
}

void ClientHandler::reset_upstream_write_timeout(ev_tstamp t) {
  wt_.repeat = t;
  if (ev_is_active(&wt_)) {
    ev_timer_again(loop_, &wt_);
  }
}

int ClientHandler::validate_next_proto() {
  const unsigned char *next_proto = nullptr;
  unsigned int next_proto_len;
  int rv;

  // First set callback for catch all cases
  on_read_ = &ClientHandler::upstream_read;

  SSL_get0_next_proto_negotiated(ssl_, &next_proto, &next_proto_len);
  for (int i = 0; i < 2; ++i) {
    if (next_proto) {
      if (LOG_ENABLED(INFO)) {
        std::string proto(next_proto, next_proto + next_proto_len);
        CLOG(INFO, this) << "The negotiated next protocol: " << proto;
      }
      if (!ssl::in_proto_list(get_config()->npn_list, next_proto,
                              next_proto_len)) {
        break;
      }
      if (util::check_h2_is_selected(next_proto, next_proto_len) ||
          (next_proto_len == sizeof("h2-16") - 1 &&
           memcmp("h2-16", next_proto, next_proto_len) == 0)) {

        on_read_ = &ClientHandler::upstream_http2_connhd_read;

        auto http2_upstream = util::make_unique<Http2Upstream>(this);

        if (!ssl::check_http2_requirement(ssl_)) {
          rv = http2_upstream->terminate_session(NGHTTP2_INADEQUATE_SECURITY);

          if (rv != 0) {
            return -1;
          }
        }

        upstream_ = std::move(http2_upstream);
        alpn_.assign(next_proto, next_proto + next_proto_len);

        // At this point, input buffer is already filled with some
        // bytes.  The read callback is not called until new data
        // come. So consume input buffer here.
        if (on_read() != 0) {
          return -1;
        }

        return 0;
      } else {
#ifdef HAVE_SPDYLAY
        uint16_t version = spdylay_npn_get_version(next_proto, next_proto_len);
        if (version) {
          upstream_ = util::make_unique<SpdyUpstream>(version, this);

          switch (version) {
          case SPDYLAY_PROTO_SPDY2:
            alpn_ = "spdy/2";
            break;
          case SPDYLAY_PROTO_SPDY3:
            alpn_ = "spdy/3";
            break;
          case SPDYLAY_PROTO_SPDY3_1:
            alpn_ = "spdy/3.1";
            break;
          default:
            alpn_ = "spdy/unknown";
          }

          // At this point, input buffer is already filled with some
          // bytes.  The read callback is not called until new data
          // come. So consume input buffer here.
          if (on_read() != 0) {
            return -1;
          }

          return 0;
        }
#endif // HAVE_SPDYLAY
        if (next_proto_len == 8 && memcmp("http/1.1", next_proto, 8) == 0) {
          upstream_ = util::make_unique<HttpsUpstream>(this);
          alpn_ = "http/1.1";

          // At this point, input buffer is already filled with some
          // bytes.  The read callback is not called until new data
          // come. So consume input buffer here.
          if (on_read() != 0) {
            return -1;
          }

          return 0;
        }
      }
      break;
    }
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    SSL_get0_alpn_selected(ssl_, &next_proto, &next_proto_len);
#else  // OPENSSL_VERSION_NUMBER < 0x10002000L
    break;
#endif // OPENSSL_VERSION_NUMBER < 0x10002000L
  }
  if (!next_proto) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "No protocol negotiated. Fallback to HTTP/1.1";
    }
    upstream_ = util::make_unique<HttpsUpstream>(this);
    alpn_ = "http/1.1";

    // At this point, input buffer is already filled with some bytes.
    // The read callback is not called until new data come. So consume
    // input buffer here.
    if (on_read() != 0) {
      return -1;
    }

    return 0;
  }
  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "The negotiated protocol is not supported";
  }
  return -1;
}

int ClientHandler::do_read() { return read_(*this); }
int ClientHandler::do_write() { return write_(*this); }

int ClientHandler::on_read() { return on_read_(*this); }
int ClientHandler::on_write() { return on_write_(*this); }

const std::string &ClientHandler::get_ipaddr() const { return ipaddr_; }

bool ClientHandler::get_should_close_after_write() const {
  return should_close_after_write_;
}

void ClientHandler::set_should_close_after_write(bool f) {
  should_close_after_write_ = f;
}

void ClientHandler::pool_downstream_connection(
    std::unique_ptr<DownstreamConnection> dconn) {
  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Pooling downstream connection DCONN:" << dconn.get();
  }
  dconn->set_client_handler(nullptr);
  dconn_pool_->add_downstream_connection(std::move(dconn));
}

void ClientHandler::remove_downstream_connection(DownstreamConnection *dconn) {
  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Removing downstream connection DCONN:" << dconn
                     << " from pool";
  }
  dconn_pool_->remove_downstream_connection(dconn);
}

std::unique_ptr<DownstreamConnection>
ClientHandler::get_downstream_connection() {
  auto dconn = dconn_pool_->pop_downstream_connection();

  if (!dconn) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "Downstream connection pool is empty."
                       << " Create new one";
    }

    if (http2session_) {
      dconn = util::make_unique<Http2DownstreamConnection>(dconn_pool_,
                                                           http2session_);
    } else {
      dconn = util::make_unique<HttpDownstreamConnection>(dconn_pool_, loop_);
    }
    dconn->set_client_handler(this);
    return dconn;
  }

  dconn->set_client_handler(this);

  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Reuse downstream connection DCONN:" << dconn.get()
                     << " from pool";
  }

  return dconn;
}

SSL *ClientHandler::get_ssl() const { return ssl_; }

void ClientHandler::set_http2_session(Http2Session *http2session) {
  http2session_ = http2session;
}

Http2Session *ClientHandler::get_http2_session() const { return http2session_; }

void ClientHandler::set_http1_connect_blocker(
    ConnectBlocker *http1_connect_blocker) {
  http1_connect_blocker_ = http1_connect_blocker;
}

ConnectBlocker *ClientHandler::get_http1_connect_blocker() const {
  return http1_connect_blocker_;
}

void ClientHandler::direct_http2_upgrade() {
  upstream_ = util::make_unique<Http2Upstream>(this);
  // TODO We don't know exact h2 draft version in direct upgrade.  We
  // just use library default for now.
  alpn_ = NGHTTP2_CLEARTEXT_PROTO_VERSION_ID;
  on_read_ = &ClientHandler::upstream_read;
}

int ClientHandler::perform_http2_upgrade(HttpsUpstream *http) {
  auto upstream = util::make_unique<Http2Upstream>(this);
  if (upstream->upgrade_upstream(http) != 0) {
    return -1;
  }
  // http pointer is now owned by upstream.
  upstream_.release();
  upstream_ = std::move(upstream);
  // TODO We might get other version id in HTTP2-settings, if we
  // support aliasing for h2, but we just use library default for now.
  alpn_ = NGHTTP2_CLEARTEXT_PROTO_VERSION_ID;
  on_read_ = &ClientHandler::upstream_http2_connhd_read;

  static char res[] = "HTTP/1.1 101 Switching Protocols\r\n"
                      "Connection: Upgrade\r\n"
                      "Upgrade: " NGHTTP2_CLEARTEXT_PROTO_VERSION_ID "\r\n"
                      "\r\n";
  wb_.write(res, sizeof(res) - 1);
  return 0;
}

bool ClientHandler::get_http2_upgrade_allowed() const { return !ssl_; }

std::string ClientHandler::get_upstream_scheme() const {
  if (ssl_) {
    return "https";
  } else {
    return "http";
  }
}

void ClientHandler::set_tls_handshake(bool f) { tls_handshake_ = f; }

bool ClientHandler::get_tls_handshake() const { return tls_handshake_; }

void ClientHandler::set_tls_renegotiation(bool f) {
  if (tls_renegotiation_ == false) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "TLS renegotiation detected. "
                       << "Start shutdown timer now.";
    }

    ev_timer_start(loop_, &reneg_shutdown_timer_);
  }
  tls_renegotiation_ = f;
}

bool ClientHandler::get_tls_renegotiation() const { return tls_renegotiation_; }

namespace {
const size_t SHRPX_SMALL_WRITE_LIMIT = 1300;
const size_t SHRPX_WARMUP_THRESHOLD = 1 << 20;
} // namespace

ssize_t ClientHandler::get_write_limit() {
  if (!ssl_) {
    return -1;
  }

  auto t = ev_now(loop_);

  if (t - last_write_time_ > 1.0) {
    // Time out, use small record size
    warmup_writelen_ = 0;
    return SHRPX_SMALL_WRITE_LIMIT;
  }

  // If event_base_gettimeofday_cached() failed, we just skip timer
  // checking.  Don't know how to treat this.

  if (warmup_writelen_ >= SHRPX_WARMUP_THRESHOLD) {
    return -1;
  }

  return SHRPX_SMALL_WRITE_LIMIT;
}

void ClientHandler::update_warmup_writelen(size_t n) {
  if (warmup_writelen_ < SHRPX_WARMUP_THRESHOLD) {
    warmup_writelen_ += n;
  }
}

void ClientHandler::update_last_write_time() {
  last_write_time_ = ev_now(loop_);
}

void ClientHandler::write_accesslog(Downstream *downstream) {
  LogSpec lgsp = {
      downstream, ipaddr_.c_str(), downstream->get_request_method().c_str(),

      downstream->get_request_path().empty()
          ? downstream->get_request_http2_authority().c_str()
          : downstream->get_request_path().c_str(),

      alpn_.c_str(),

      std::chrono::system_clock::now(),          // time_now
      downstream->get_request_start_time(),      // request_start_time
      std::chrono::high_resolution_clock::now(), // request_end_time

      downstream->get_request_major(), downstream->get_request_minor(),
      downstream->get_response_http_status(),
      downstream->get_response_sent_bodylen(), port_.c_str(),
      get_config()->port, get_config()->pid,
  };

  upstream_accesslog(get_config()->accesslog_format, &lgsp);
}

void ClientHandler::write_accesslog(int major, int minor, unsigned int status,
                                    int64_t body_bytes_sent) {
  auto time_now = std::chrono::system_clock::now();
  auto highres_now = std::chrono::high_resolution_clock::now();

  LogSpec lgsp = {
      nullptr,            ipaddr_.c_str(),
      "-", // method
      "-", // path,
      alpn_.c_str(),      time_now,
      highres_now,               // request_start_time TODO is
                                 // there a better value?
      highres_now,               // request_end_time
      major,              minor, // major, minor
      status,             body_bytes_sent,   port_.c_str(),
      get_config()->port, get_config()->pid,
  };

  upstream_accesslog(get_config()->accesslog_format, &lgsp);
}

WorkerStat *ClientHandler::get_worker_stat() const { return worker_stat_; }

ClientHandler::WriteBuf *ClientHandler::get_wb() { return &wb_; }

ClientHandler::ReadBuf *ClientHandler::get_rb() { return &rb_; }

void ClientHandler::signal_write() { wlimit_.startw(); }

RateLimit *ClientHandler::get_rlimit() { return &rlimit_; }
RateLimit *ClientHandler::get_wlimit() { return &wlimit_; }

} // namespace shrpx
