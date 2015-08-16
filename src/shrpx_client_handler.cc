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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif // HAVE_UNISTD_H
#include <cerrno>

#include "shrpx_upstream.h"
#include "shrpx_http2_upstream.h"
#include "shrpx_https_upstream.h"
#include "shrpx_config.h"
#include "shrpx_http_downstream_connection.h"
#include "shrpx_http2_downstream_connection.h"
#include "shrpx_ssl.h"
#include "shrpx_worker.h"
#include "shrpx_downstream_connection_pool.h"
#include "shrpx_downstream.h"
#include "shrpx_http2_session.h"
#ifdef HAVE_SPDYLAY
#include "shrpx_spdy_upstream.h"
#endif // HAVE_SPDYLAY
#include "util.h"
#include "template.h"

using namespace nghttp2;

namespace shrpx {

namespace {
void timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto conn = static_cast<Connection *>(w->data);
  auto handler = static_cast<ClientHandler *>(conn->data);

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
  auto conn = static_cast<Connection *>(w->data);
  auto handler = static_cast<ClientHandler *>(conn->data);

  if (handler->do_read() != 0) {
    delete handler;
    return;
  }
  if (handler->do_write() != 0) {
    delete handler;
    return;
  }
}
} // namespace

namespace {
void writecb(struct ev_loop *loop, ev_io *w, int revents) {
  auto conn = static_cast<Connection *>(w->data);
  auto handler = static_cast<ClientHandler *>(conn->data);

  if (handler->do_write() != 0) {
    delete handler;
    return;
  }
}
} // namespace

int ClientHandler::read_clear() {
  ev_timer_again(conn_.loop, &conn_.rt);

  for (;;) {
    if (rb_.rleft() && on_read() != 0) {
      return -1;
    }
    if (rb_.rleft() == 0) {
      rb_.reset();
    } else if (rb_.wleft() == 0) {
      conn_.rlimit.stopw();
      return 0;
    }

    auto nread = conn_.read_clear(rb_.last, rb_.wleft());

    if (nread == 0) {
      return 0;
    }

    if (nread < 0) {
      return -1;
    }

    rb_.write(nread);
  }
}

int ClientHandler::write_clear() {
  ev_timer_again(conn_.loop, &conn_.rt);

  for (;;) {
    if (wb_.rleft() > 0) {
      auto nwrite = conn_.write_clear(wb_.pos, wb_.rleft());
      if (nwrite == 0) {
        return 0;
      }
      if (nwrite < 0) {
        return -1;
      }
      wb_.drain(nwrite);
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

  conn_.wlimit.stopw();
  ev_timer_stop(conn_.loop, &conn_.wt);

  return 0;
}

int ClientHandler::tls_handshake() {
  ev_timer_again(conn_.loop, &conn_.rt);

  ERR_clear_error();

  auto rv = conn_.tls_handshake();

  if (rv == SHRPX_ERR_INPROGRESS) {
    return 0;
  }

  if (rv < 0) {
    return -1;
  }

  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "SSL/TLS handshake completed";
  }

  if (validate_next_proto() != 0) {
    return -1;
  }

  read_ = &ClientHandler::read_tls;
  write_ = &ClientHandler::write_tls;

  return 0;
}

int ClientHandler::read_tls() {
  ev_timer_again(conn_.loop, &conn_.rt);

  ERR_clear_error();

  for (;;) {
    // we should process buffered data first before we read EOF.
    if (rb_.rleft() && on_read() != 0) {
      return -1;
    }
    if (rb_.rleft() == 0) {
      rb_.reset();
    } else if (rb_.wleft() == 0) {
      conn_.rlimit.stopw();
      return 0;
    }

    auto nread = conn_.read_tls(rb_.last, rb_.wleft());

    if (nread == 0) {
      return 0;
    }

    if (nread < 0) {
      return -1;
    }

    rb_.write(nread);
  }
}

int ClientHandler::write_tls() {
  ev_timer_again(conn_.loop, &conn_.rt);

  ERR_clear_error();

  for (;;) {
    if (wb_.rleft() > 0) {
      auto nwrite = conn_.write_tls(wb_.pos, wb_.rleft());

      if (nwrite == 0) {
        return 0;
      }

      if (nwrite < 0) {
        return -1;
      }

      wb_.drain(nwrite);

      continue;
    }
    wb_.reset();
    if (on_write() != 0) {
      return -1;
    }
    if (wb_.rleft() == 0) {
      conn_.start_tls_write_idle();
      break;
    }
  }

  conn_.wlimit.stopw();
  ev_timer_stop(conn_.loop, &conn_.wt);

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
  auto nread = std::min(left_connhd_len_, rb_.rleft());
  if (memcmp(NGHTTP2_CLIENT_MAGIC + NGHTTP2_CLIENT_MAGIC_LEN - left_connhd_len_,
             rb_.pos, nread) != 0) {
    // There is no downgrade path here. Just drop the connection.
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "invalid client connection header";
    }

    return -1;
  }

  left_connhd_len_ -= nread;
  rb_.drain(nread);
  conn_.rlimit.startw();

  if (left_connhd_len_ == 0) {
    on_read_ = &ClientHandler::upstream_read;
    // Run on_read to process data left in buffer since they are not
    // notified further
    if (on_read() != 0) {
      return -1;
    }
    return 0;
  }

  return 0;
}

int ClientHandler::upstream_http1_connhd_read() {
  auto nread = std::min(left_connhd_len_, rb_.rleft());
  if (memcmp(NGHTTP2_CLIENT_MAGIC + NGHTTP2_CLIENT_MAGIC_LEN - left_connhd_len_,
             rb_.pos, nread) != 0) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "This is HTTP/1.1 connection, "
                       << "but may be upgraded to HTTP/2 later.";
    }

    // Reset header length for later HTTP/2 upgrade
    left_connhd_len_ = NGHTTP2_CLIENT_MAGIC_LEN;
    on_read_ = &ClientHandler::upstream_read;
    on_write_ = &ClientHandler::upstream_write;

    if (on_read() != 0) {
      return -1;
    }

    return 0;
  }

  left_connhd_len_ -= nread;
  rb_.drain(nread);
  conn_.rlimit.startw();

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

  return 0;
}

ClientHandler::ClientHandler(Worker *worker, int fd, SSL *ssl,
                             const char *ipaddr, const char *port)
    : conn_(worker->get_loop(), fd, ssl, worker->get_mcpool(),
            get_config()->upstream_write_timeout,
            get_config()->upstream_read_timeout, get_config()->write_rate,
            get_config()->write_burst, get_config()->read_rate,
            get_config()->read_burst, writecb, readcb, timeoutcb, this),
      pinned_http2sessions_(
          get_config()->downstream_proto == PROTO_HTTP2
              ? make_unique<std::vector<ssize_t>>(
                    get_config()->downstream_addr_groups.size(), -1)
              : nullptr),
      ipaddr_(ipaddr), port_(port), worker_(worker),
      left_connhd_len_(NGHTTP2_CLIENT_MAGIC_LEN),
      should_close_after_write_(false) {

  ++worker_->get_worker_stat()->num_connections;

  ev_timer_init(&reneg_shutdown_timer_, shutdowncb, 0., 0.);

  reneg_shutdown_timer_.data = this;

  conn_.rlimit.startw();
  ev_timer_again(conn_.loop, &conn_.rt);

  if (conn_.tls.ssl) {
    conn_.prepare_server_handshake();
    read_ = write_ = &ClientHandler::tls_handshake;
    on_read_ = &ClientHandler::upstream_noop;
    on_write_ = &ClientHandler::upstream_write;
  } else {
    // For non-TLS version, first create HttpsUpstream. It may be
    // upgraded to HTTP/2 through HTTP Upgrade or direct HTTP/2
    // connection.
    upstream_ = make_unique<HttpsUpstream>(this);
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

  auto worker_stat = worker_->get_worker_stat();
  --worker_stat->num_connections;

  if (worker_stat->num_connections == 0) {
    worker_->schedule_clear_mcpool();
  }

  ev_timer_stop(conn_.loop, &reneg_shutdown_timer_);

  // TODO If backend is http/2, and it is in CONNECTED state, signal
  // it and make it loopbreak when output is zero.
  if (worker_->get_graceful_shutdown() && worker_stat->num_connections == 0) {
    ev_break(conn_.loop);
  }

  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Deleted";
  }
}

Upstream *ClientHandler::get_upstream() { return upstream_.get(); }

struct ev_loop *ClientHandler::get_loop() const {
  return conn_.loop;
}

void ClientHandler::reset_upstream_read_timeout(ev_tstamp t) {
  conn_.rt.repeat = t;
  if (ev_is_active(&conn_.rt)) {
    ev_timer_again(conn_.loop, &conn_.rt);
  }
}

void ClientHandler::reset_upstream_write_timeout(ev_tstamp t) {
  conn_.wt.repeat = t;
  if (ev_is_active(&conn_.wt)) {
    ev_timer_again(conn_.loop, &conn_.wt);
  }
}

int ClientHandler::validate_next_proto() {
  const unsigned char *next_proto = nullptr;
  unsigned int next_proto_len;
  int rv;

  // First set callback for catch all cases
  on_read_ = &ClientHandler::upstream_read;

  SSL_get0_next_proto_negotiated(conn_.tls.ssl, &next_proto, &next_proto_len);
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
      if (util::check_h2_is_selected(next_proto, next_proto_len)) {

        on_read_ = &ClientHandler::upstream_http2_connhd_read;

        auto http2_upstream = make_unique<Http2Upstream>(this);

        if (!ssl::check_http2_requirement(conn_.tls.ssl)) {
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
          upstream_ = make_unique<SpdyUpstream>(version, this);

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
          upstream_ = make_unique<HttpsUpstream>(this);
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
    SSL_get0_alpn_selected(conn_.tls.ssl, &next_proto, &next_proto_len);
#else  // OPENSSL_VERSION_NUMBER < 0x10002000L
    break;
#endif // OPENSSL_VERSION_NUMBER < 0x10002000L
  }
  if (!next_proto) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "No protocol negotiated. Fallback to HTTP/1.1";
    }
    upstream_ = make_unique<HttpsUpstream>(this);
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

int ClientHandler::on_read() {
  auto rv = on_read_(*this);
  if (rv != 0) {
    return rv;
  }
  conn_.handle_tls_pending_read();
  return 0;
}
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
  if (!dconn->poolable()) {
    return;
  }
  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Pooling downstream connection DCONN:" << dconn.get()
                     << " in group " << dconn->get_group();
  }
  dconn->set_client_handler(nullptr);
  auto dconn_pool = worker_->get_dconn_pool();
  dconn_pool->add_downstream_connection(std::move(dconn));
}

void ClientHandler::remove_downstream_connection(DownstreamConnection *dconn) {
  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Removing downstream connection DCONN:" << dconn
                     << " from pool";
  }
  auto dconn_pool = worker_->get_dconn_pool();
  dconn_pool->remove_downstream_connection(dconn);
}

std::unique_ptr<DownstreamConnection>
ClientHandler::get_downstream_connection(Downstream *downstream) {
  size_t group;
  auto &groups = get_config()->downstream_addr_groups;
  auto catch_all = get_config()->downstream_addr_group_catch_all;

  // Fast path.  If we have one group, it must be catch-all group.
  // HTTP/2 and client proxy modes fall in this case.
  if (groups.size() == 1) {
    group = 0;
  } else if (downstream->get_request_method() == HTTP_CONNECT) {
    //  We don't know how to treat CONNECT request in host-path
    //  mapping.  It most likely appears in proxy scenario.  Since we
    //  have dealt with proxy case already, just use catch-all group.
    group = catch_all;
  } else {
    if (!downstream->get_request_http2_authority().empty()) {
      group = match_downstream_addr_group(
          downstream->get_request_http2_authority(),
          downstream->get_request_path(), groups, catch_all);
    } else {
      auto h = downstream->get_request_header(http2::HD_HOST);
      if (h) {
        group = match_downstream_addr_group(
            h->value, downstream->get_request_path(), groups, catch_all);
      } else {
        group = match_downstream_addr_group("", downstream->get_request_path(),
                                            groups, catch_all);
      }
    }
  }

  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Downstream address group: " << group;
  }

  auto dconn_pool = worker_->get_dconn_pool();
  auto dconn = dconn_pool->pop_downstream_connection(group);

  if (!dconn) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "Downstream connection pool is empty."
                       << " Create new one";
    }

    auto dconn_pool = worker_->get_dconn_pool();

    if (get_config()->downstream_proto == PROTO_HTTP2) {
      Http2Session *http2session;
      auto &pinned = (*pinned_http2sessions_)[group];
      if (pinned == -1) {
        http2session = worker_->next_http2_session(group);
        pinned = http2session->get_index();
      } else {
        auto dgrp = worker_->get_dgrp(group);
        http2session = dgrp->http2sessions[pinned].get();
      }
      dconn = make_unique<Http2DownstreamConnection>(dconn_pool, http2session);
    } else {
      dconn =
          make_unique<HttpDownstreamConnection>(dconn_pool, group, conn_.loop);
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

MemchunkPool *ClientHandler::get_mcpool() { return worker_->get_mcpool(); }

SSL *ClientHandler::get_ssl() const { return conn_.tls.ssl; }

ConnectBlocker *ClientHandler::get_connect_blocker() const {
  return worker_->get_connect_blocker();
}

void ClientHandler::direct_http2_upgrade() {
  upstream_ = make_unique<Http2Upstream>(this);
  alpn_ = NGHTTP2_CLEARTEXT_PROTO_VERSION_ID;
  on_read_ = &ClientHandler::upstream_read;
}

int ClientHandler::perform_http2_upgrade(HttpsUpstream *http) {
  auto upstream = make_unique<Http2Upstream>(this);
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
  signal_write();
  return 0;
}

bool ClientHandler::get_http2_upgrade_allowed() const { return !conn_.tls.ssl; }

std::string ClientHandler::get_upstream_scheme() const {
  if (conn_.tls.ssl) {
    return "https";
  } else {
    return "http";
  }
}

void ClientHandler::start_immediate_shutdown() {
  ev_timer_start(conn_.loop, &reneg_shutdown_timer_);
}

namespace {
// Construct absolute request URI from |downstream|, mainly to log
// request URI for proxy request (HTTP/2 proxy or client proxy).  This
// is mostly same routine found in
// HttpDownstreamConnection::push_request_headers(), but vastly
// simplified since we only care about absolute URI.
std::string construct_absolute_request_uri(Downstream *downstream) {
  const char *authority = nullptr, *host = nullptr;
  if (!downstream->get_request_http2_authority().empty()) {
    authority = downstream->get_request_http2_authority().c_str();
  }
  auto h = downstream->get_request_header(http2::HD_HOST);
  if (h) {
    host = h->value.c_str();
  }
  if (!authority && !host) {
    return downstream->get_request_path();
  }
  std::string uri;
  if (downstream->get_request_http2_scheme().empty()) {
    // We may have to log the request which lacks scheme (e.g.,
    // http/1.1 with origin form).
    uri += "http://";
  } else {
    uri += downstream->get_request_http2_scheme();
    uri += "://";
  }
  if (authority) {
    uri += authority;
  } else {
    uri += host;
  }

  // Server-wide OPTIONS takes following form in proxy request:
  //
  // OPTIONS http://example.org HTTP/1.1
  //
  // Notice that no slash after authority. See
  // http://tools.ietf.org/html/rfc7230#section-5.3.4
  if (downstream->get_request_path() != "*") {
    uri += downstream->get_request_path();
  }
  return uri;
}
} // namespace

void ClientHandler::write_accesslog(Downstream *downstream) {
  nghttp2::ssl::TLSSessionInfo tls_info;

  upstream_accesslog(
      get_config()->accesslog_format,
      LogSpec{
          downstream, ipaddr_.c_str(),
          http2::to_method_string(downstream->get_request_method()),

          (downstream->get_request_method() != HTTP_CONNECT &&
           (get_config()->http2_proxy || get_config()->client_proxy))
              ? construct_absolute_request_uri(downstream).c_str()
              : downstream->get_request_path().empty()
                    ? downstream->get_request_http2_authority().c_str()
                    : downstream->get_request_path().c_str(),

          alpn_.c_str(),
          nghttp2::ssl::get_tls_session_info(&tls_info, conn_.tls.ssl),

          std::chrono::system_clock::now(),          // time_now
          downstream->get_request_start_time(),      // request_start_time
          std::chrono::high_resolution_clock::now(), // request_end_time

          downstream->get_request_major(), downstream->get_request_minor(),
          downstream->get_response_http_status(),
          downstream->get_response_sent_bodylen(), port_.c_str(),
          get_config()->port, get_config()->pid,
      });
}

void ClientHandler::write_accesslog(int major, int minor, unsigned int status,
                                    int64_t body_bytes_sent) {
  auto time_now = std::chrono::system_clock::now();
  auto highres_now = std::chrono::high_resolution_clock::now();
  nghttp2::ssl::TLSSessionInfo tls_info;

  upstream_accesslog(get_config()->accesslog_format,
                     LogSpec{
                         nullptr, ipaddr_.c_str(),
                         "-", // method
                         "-", // path,
                         alpn_.c_str(), nghttp2::ssl::get_tls_session_info(
                                            &tls_info, conn_.tls.ssl),
                         time_now,
                         highres_now,  // request_start_time TODO is
                                       // there a better value?
                         highres_now,  // request_end_time
                         major, minor, // major, minor
                         status, body_bytes_sent, port_.c_str(),
                         get_config()->port, get_config()->pid,
                     });
}

ClientHandler::WriteBuf *ClientHandler::get_wb() { return &wb_; }

ClientHandler::ReadBuf *ClientHandler::get_rb() { return &rb_; }

void ClientHandler::signal_write() { conn_.wlimit.startw(); }

RateLimit *ClientHandler::get_rlimit() { return &conn_.rlimit; }
RateLimit *ClientHandler::get_wlimit() { return &conn_.wlimit; }

ev_io *ClientHandler::get_wev() { return &conn_.wev; }

Worker *ClientHandler::get_worker() const { return worker_; }

} // namespace shrpx
