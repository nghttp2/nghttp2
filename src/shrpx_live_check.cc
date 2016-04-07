/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2016 Tatsuhiro Tsujikawa
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
#include "shrpx_live_check.h"
#include "shrpx_worker.h"
#include "shrpx_connect_blocker.h"
#include "shrpx_ssl.h"

namespace shrpx {

namespace {
void readcb(struct ev_loop *loop, ev_io *w, int revents) {
  int rv;
  auto conn = static_cast<Connection *>(w->data);
  auto live_check = static_cast<LiveCheck *>(conn->data);

  rv = live_check->do_read();
  if (rv != 0) {
    live_check->on_failure();
    return;
  }
}
} // namespace

namespace {
void writecb(struct ev_loop *loop, ev_io *w, int revents) {
  int rv;
  auto conn = static_cast<Connection *>(w->data);
  auto live_check = static_cast<LiveCheck *>(conn->data);

  rv = live_check->do_write();
  if (rv != 0) {
    live_check->on_failure();
    return;
  }
}
} // namespace

namespace {
void timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto conn = static_cast<Connection *>(w->data);
  auto live_check = static_cast<LiveCheck *>(conn->data);

  live_check->on_failure();
}
} // namespace

namespace {
void backoff_timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  int rv;
  auto live_check = static_cast<LiveCheck *>(w->data);

  rv = live_check->initiate_connection();
  if (rv != 0) {
    live_check->on_failure();
    return;
  }
}
} // namespace

LiveCheck::LiveCheck(struct ev_loop *loop, SSL_CTX *ssl_ctx, Worker *worker,
                     DownstreamAddrGroup *group, DownstreamAddr *addr)
    : conn_(loop, -1, nullptr, worker->get_mcpool(),
            get_config()->conn.downstream.timeout.write,
            get_config()->conn.downstream.timeout.read, {}, {}, writecb, readcb,
            timeoutcb, this, get_config()->tls.dyn_rec.warmup_threshold,
            get_config()->tls.dyn_rec.idle_timeout, PROTO_NONE),
      read_(&LiveCheck::noop),
      write_(&LiveCheck::noop),
      worker_(worker),
      ssl_ctx_(ssl_ctx),
      group_(group),
      addr_(addr),
      success_count_(0),
      fail_count_(0) {
  ev_timer_init(&backoff_timer_, backoff_timeoutcb, 0., 0.);
  backoff_timer_.data = this;
}

LiveCheck::~LiveCheck() {
  disconnect();

  ev_timer_stop(conn_.loop, &backoff_timer_);
}

void LiveCheck::disconnect() {
  conn_.rlimit.stopw();
  conn_.wlimit.stopw();

  read_ = write_ = &LiveCheck::noop;

  conn_.disconnect();
}

void LiveCheck::schedule() {
  // TODO use exponential backoff based on fail_count_.
  ev_timer_set(&backoff_timer_, 1.6, 0.);
  ev_timer_start(conn_.loop, &backoff_timer_);
}

int LiveCheck::do_read() { return read_(*this); }

int LiveCheck::do_write() { return write_(*this); }

int LiveCheck::initiate_connection() {
  int rv;

  const auto &shared_addr = group_->shared_addr;

  auto worker_blocker = worker_->get_connect_blocker();
  if (worker_blocker->blocked()) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Worker wide backend connection was blocked temporarily";
    }
    return -1;
  }

  if (ssl_ctx_) {
    auto ssl = ssl::create_ssl(ssl_ctx_);
    if (!ssl) {
      return -1;
    }

    switch (shared_addr->proto) {
    case PROTO_HTTP1:
      ssl::setup_downstream_http1_alpn(ssl);
      break;
    case PROTO_HTTP2:
      ssl::setup_downstream_http2_alpn(ssl);
      break;
    default:
      assert(0);
    }

    conn_.set_ssl(ssl);
  }

  conn_.fd = util::create_nonblock_socket(addr_->addr.su.storage.ss_family);

  if (conn_.fd == -1) {
    auto error = errno;
    LOG(WARN) << "socket() failed; addr=" << util::to_numeric_addr(&addr_->addr)
              << ", errno=" << error;
    return -1;
  }

  rv = connect(conn_.fd, &addr_->addr.su.sa, addr_->addr.len);
  if (rv != 0 && errno != EINPROGRESS) {
    auto error = errno;
    LOG(WARN) << "connect() failed; addr="
              << util::to_numeric_addr(&addr_->addr) << ", errno=" << error;
    LOG(WARN) << strerror(error);

    close(conn_.fd);
    conn_.fd = -1;

    return -1;
  }

  if (ssl_ctx_) {
    auto sni_name = !get_config()->tls.backend_sni_name.empty()
                        ? StringRef(get_config()->tls.backend_sni_name)
                        : StringRef(addr_->host);
    if (!util::numeric_host(sni_name.c_str())) {
      SSL_set_tlsext_host_name(conn_.tls.ssl, sni_name.c_str());
    }

    auto session = ssl::reuse_tls_session(addr_);
    if (session) {
      SSL_set_session(conn_.tls.ssl, session);
      SSL_SESSION_free(session);
    }

    conn_.prepare_client_handshake();
  }

  write_ = &LiveCheck::connected;

  ev_io_set(&conn_.wev, conn_.fd, EV_WRITE);
  ev_io_set(&conn_.rev, conn_.fd, EV_READ);

  conn_.wlimit.startw();

  // TODO we should have timeout for connection establishment
  ev_timer_again(conn_.loop, &conn_.wt);

  return 0;
}

int LiveCheck::connected() {
  if (!util::check_socket_connected(conn_.fd)) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Backend connect failed; addr="
                << util::to_numeric_addr(&addr_->addr);
    }

    return -1;
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Connection established";
  }

  conn_.rlimit.startw();

  if (conn_.tls.ssl) {
    read_ = &LiveCheck::tls_handshake;
    write_ = &LiveCheck::tls_handshake;

    return do_write();
  }

  on_success();
  disconnect();

  return 0;
}

int LiveCheck::tls_handshake() {
  ev_timer_again(conn_.loop, &conn_.rt);

  ERR_clear_error();

  auto rv = conn_.tls_handshake();

  if (rv == SHRPX_ERR_INPROGRESS) {
    return 0;
  }

  if (rv < 0) {
    return rv;
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "SSL/TLS handshake completed";
  }

  if (!get_config()->tls.insecure &&
      ssl::check_cert(conn_.tls.ssl, addr_) != 0) {
    return -1;
  }

  if (!SSL_session_reused(conn_.tls.ssl)) {
    auto tls_session = SSL_get0_session(conn_.tls.ssl);
    if (tls_session) {
      ssl::try_cache_tls_session(addr_, tls_session, ev_now(conn_.loop));
    }
  }

  on_success();
  disconnect();

  // TODO Check ALPN identifier here

  return 0;
}

void LiveCheck::on_failure() {
  ++fail_count_;

  LOG(WARN) << "Liveness check for " << util::to_numeric_addr(&addr_->addr)
            << " failed " << fail_count_ << " time(s) in a row";

  disconnect();

  schedule();
}

void LiveCheck::on_success() {
  ++success_count_;
  fail_count_ = 0;

  LOG(WARN) << "Liveness check for " << util::to_numeric_addr(&addr_->addr)
            << " succeeded " << success_count_ << " time(s) in a row";

  if (success_count_ < 3) {
    disconnect();

    schedule();

    return;
  }

  LOG(NOTICE) << util::to_numeric_addr(&addr_->addr) << " is considered online";

  addr_->connect_blocker->online();

  success_count_ = 0;
  fail_count_ = 0;

  disconnect();
}

int LiveCheck::noop() { return 0; }

} // namespace shrpx
