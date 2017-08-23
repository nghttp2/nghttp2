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
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif // HAVE_SYS_SOCKET_H
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif // HAVE_NETDB_H

#include <cerrno>

#include "shrpx_upstream.h"
#include "shrpx_http2_upstream.h"
#include "shrpx_https_upstream.h"
#include "shrpx_config.h"
#include "shrpx_http_downstream_connection.h"
#include "shrpx_http2_downstream_connection.h"
#include "shrpx_tls.h"
#include "shrpx_worker.h"
#include "shrpx_downstream_connection_pool.h"
#include "shrpx_downstream.h"
#include "shrpx_http2_session.h"
#include "shrpx_connect_blocker.h"
#include "shrpx_api_downstream_connection.h"
#include "shrpx_health_monitor_downstream_connection.h"
#include "shrpx_log.h"
#ifdef HAVE_SPDYLAY
#include "shrpx_spdy_upstream.h"
#endif // HAVE_SPDYLAY
#include "util.h"
#include "template.h"
#include "tls.h"

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

int ClientHandler::noop() { return 0; }

int ClientHandler::read_clear() {
  rb_.ensure_chunk();
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

    if (!ev_is_active(&conn_.rev)) {
      return 0;
    }

    auto nread = conn_.read_clear(rb_.last(), rb_.wleft());

    if (nread == 0) {
      if (rb_.rleft() == 0) {
        rb_.release_chunk();
      }
      return 0;
    }

    if (nread < 0) {
      return -1;
    }

    rb_.write(nread);
  }
}

int ClientHandler::write_clear() {
  std::array<iovec, 2> iov;

  for (;;) {
    if (on_write() != 0) {
      return -1;
    }

    auto iovcnt = upstream_->response_riovec(iov.data(), iov.size());
    if (iovcnt == 0) {
      break;
    }

    auto nwrite = conn_.writev_clear(iov.data(), iovcnt);
    if (nwrite < 0) {
      return -1;
    }

    if (nwrite == 0) {
      return 0;
    }

    upstream_->response_drain(nwrite);
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
  ERR_clear_error();

  rb_.ensure_chunk();

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

    if (!ev_is_active(&conn_.rev)) {
      return 0;
    }

    auto nread = conn_.read_tls(rb_.last(), rb_.wleft());

    if (nread == 0) {
      if (rb_.rleft() == 0) {
        rb_.release_chunk();
      }
      return 0;
    }

    if (nread < 0) {
      return -1;
    }

    rb_.write(nread);
  }
}

int ClientHandler::write_tls() {
  struct iovec iov;

  ERR_clear_error();

  if (on_write() != 0) {
    return -1;
  }

  auto iovcnt = upstream_->response_riovec(&iov, 1);
  if (iovcnt == 0) {
    conn_.start_tls_write_idle();

    conn_.wlimit.stopw();
    ev_timer_stop(conn_.loop, &conn_.wt);

    return 0;
  }

  for (;;) {
    auto nwrite = conn_.write_tls(iov.iov_base, iov.iov_len);
    if (nwrite < 0) {
      return -1;
    }

    if (nwrite == 0) {
      return 0;
    }

    upstream_->response_drain(nwrite);

    iovcnt = upstream_->response_riovec(&iov, 1);
    if (iovcnt == 0) {
      return 0;
    }
  }
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

  if (get_should_close_after_write() && upstream_->response_empty()) {
    return -1;
  }

  return 0;
}

int ClientHandler::upstream_http2_connhd_read() {
  auto nread = (std::min)(left_connhd_len_, rb_.rleft());
  if (memcmp(NGHTTP2_CLIENT_MAGIC + NGHTTP2_CLIENT_MAGIC_LEN - left_connhd_len_,
             rb_.pos(), nread) != 0) {
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
  auto nread = (std::min)(left_connhd_len_, rb_.rleft());
  if (memcmp(NGHTTP2_CLIENT_MAGIC + NGHTTP2_CLIENT_MAGIC_LEN - left_connhd_len_,
             rb_.pos(), nread) != 0) {
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
                             const StringRef &ipaddr, const StringRef &port,
                             int family, const UpstreamAddr *faddr)
    : // We use balloc_ for TLS session ID (64), ipaddr (IPv6) (39),
      // port (5), forwarded-for (IPv6) (41), alpn (5), proxyproto
      // ipaddr (15), proxyproto port (5), sni (32, estimated).  we
      // need terminal NULL byte for each.  We also require 8 bytes
      // header for each allocation.  We align at 16 bytes boundary,
      // so the required space is 64 + 48 + 16 + 48 + 16 + 16 + 16 +
      // 32 + 8 + 8 * 8 = 328.
      balloc_(512, 512),
      rb_(worker->get_mcpool()),
      conn_(worker->get_loop(), fd, ssl, worker->get_mcpool(),
            get_config()->conn.upstream.timeout.write,
            get_config()->conn.upstream.timeout.read,
            get_config()->conn.upstream.ratelimit.write,
            get_config()->conn.upstream.ratelimit.read, writecb, readcb,
            timeoutcb, this, get_config()->tls.dyn_rec.warmup_threshold,
            get_config()->tls.dyn_rec.idle_timeout, PROTO_NONE),
      ipaddr_(make_string_ref(balloc_, ipaddr)),
      port_(make_string_ref(balloc_, port)),
      faddr_(faddr),
      worker_(worker),
      left_connhd_len_(NGHTTP2_CLIENT_MAGIC_LEN),
      affinity_hash_(0),
      should_close_after_write_(false),
      affinity_hash_computed_(false) {

  ++worker_->get_worker_stat()->num_connections;

  ev_timer_init(&reneg_shutdown_timer_, shutdowncb, 0., 0.);

  reneg_shutdown_timer_.data = this;

  conn_.rlimit.startw();
  ev_timer_again(conn_.loop, &conn_.rt);

  auto config = get_config();

  if (faddr_->accept_proxy_protocol ||
      config->conn.upstream.accept_proxy_protocol) {
    read_ = &ClientHandler::read_clear;
    write_ = &ClientHandler::noop;
    on_read_ = &ClientHandler::proxy_protocol_read;
    on_write_ = &ClientHandler::upstream_noop;
  } else {
    setup_upstream_io_callback();
  }

  auto &fwdconf = config->http.forwarded;

  if (fwdconf.params & FORWARDED_FOR) {
    if (fwdconf.for_node_type == FORWARDED_NODE_OBFUSCATED) {
      // 1 for '_'
      auto len = SHRPX_OBFUSCATED_NODE_LENGTH + 1;
      // 1 for terminating NUL.
      auto buf = make_byte_ref(balloc_, len + 1);
      auto p = buf.base;
      *p++ = '_';
      p = util::random_alpha_digit(p, p + SHRPX_OBFUSCATED_NODE_LENGTH,
                                   worker_->get_randgen());
      *p = '\0';

      forwarded_for_ = StringRef{buf.base, p};
    } else if (!faddr_->accept_proxy_protocol &&
               !config->conn.upstream.accept_proxy_protocol) {
      init_forwarded_for(family, ipaddr_);
    }
  }
}

void ClientHandler::init_forwarded_for(int family, const StringRef &ipaddr) {
  if (family == AF_INET6) {
    // 2 for '[' and ']'
    auto len = 2 + ipaddr.size();
    // 1 for terminating NUL.
    auto buf = make_byte_ref(balloc_, len + 1);
    auto p = buf.base;
    *p++ = '[';
    p = std::copy(std::begin(ipaddr), std::end(ipaddr), p);
    *p++ = ']';
    *p = '\0';

    forwarded_for_ = StringRef{buf.base, p};
  } else {
    // family == AF_INET or family == AF_UNIX
    forwarded_for_ = ipaddr;
  }
}

void ClientHandler::setup_upstream_io_callback() {
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
    alpn_ = StringRef::from_lit("http/1.1");
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

void ClientHandler::repeat_read_timer() {
  ev_timer_again(conn_.loop, &conn_.rt);
}

void ClientHandler::stop_read_timer() { ev_timer_stop(conn_.loop, &conn_.rt); }

int ClientHandler::validate_next_proto() {
  const unsigned char *next_proto = nullptr;
  unsigned int next_proto_len = 0;

  // First set callback for catch all cases
  on_read_ = &ClientHandler::upstream_read;

  SSL_get0_next_proto_negotiated(conn_.tls.ssl, &next_proto, &next_proto_len);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  if (next_proto == nullptr) {
    SSL_get0_alpn_selected(conn_.tls.ssl, &next_proto, &next_proto_len);
  }
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

  if (next_proto == nullptr) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "No protocol negotiated. Fallback to HTTP/1.1";
    }

    upstream_ = make_unique<HttpsUpstream>(this);
    alpn_ = StringRef::from_lit("http/1.1");

    // At this point, input buffer is already filled with some bytes.
    // The read callback is not called until new data come. So consume
    // input buffer here.
    if (on_read() != 0) {
      return -1;
    }

    return 0;
  }

  auto proto = StringRef{next_proto, next_proto_len};

  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "The negotiated next protocol: " << proto;
  }

  if (!tls::in_proto_list(get_config()->tls.npn_list, proto)) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "The negotiated protocol is not supported: " << proto;
    }
    return -1;
  }

  if (util::check_h2_is_selected(proto)) {
    on_read_ = &ClientHandler::upstream_http2_connhd_read;

    auto http2_upstream = make_unique<Http2Upstream>(this);

    upstream_ = std::move(http2_upstream);
    alpn_ = make_string_ref(balloc_, proto);

    // At this point, input buffer is already filled with some bytes.
    // The read callback is not called until new data come. So consume
    // input buffer here.
    if (on_read() != 0) {
      return -1;
    }

    return 0;
  }

#ifdef HAVE_SPDYLAY
  auto spdy_version = spdylay_npn_get_version(proto.byte(), proto.size());
  if (spdy_version) {
    upstream_ = make_unique<SpdyUpstream>(spdy_version, this);

    switch (spdy_version) {
    case SPDYLAY_PROTO_SPDY2:
      alpn_ = StringRef::from_lit("spdy/2");
      break;
    case SPDYLAY_PROTO_SPDY3:
      alpn_ = StringRef::from_lit("spdy/3");
      break;
    case SPDYLAY_PROTO_SPDY3_1:
      alpn_ = StringRef::from_lit("spdy/3.1");
      break;
    default:
      alpn_ = StringRef::from_lit("spdy/unknown");
    }

    // At this point, input buffer is already filled with some bytes.
    // The read callback is not called until new data come. So consume
    // input buffer here.
    if (on_read() != 0) {
      return -1;
    }

    return 0;
  }
#endif // HAVE_SPDYLAY

  if (proto == StringRef::from_lit("http/1.1")) {
    upstream_ = make_unique<HttpsUpstream>(this);
    alpn_ = StringRef::from_lit("http/1.1");

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
  if (rb_.chunk_avail()) {
    auto rv = on_read_(*this);
    if (rv != 0) {
      return rv;
    }
  }
  conn_.handle_tls_pending_read();
  return 0;
}
int ClientHandler::on_write() { return on_write_(*this); }

const StringRef &ClientHandler::get_ipaddr() const { return ipaddr_; }

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

  dconn->set_client_handler(nullptr);

  auto &group = dconn->get_downstream_addr_group();

  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Pooling downstream connection DCONN:" << dconn.get()
                     << " in group " << group;
  }

  auto &shared_addr = group->shared_addr;

  if (shared_addr->affinity == AFFINITY_NONE) {
    auto &dconn_pool = group->shared_addr->dconn_pool;
    dconn_pool.add_downstream_connection(std::move(dconn));

    return;
  }

  auto addr = dconn->get_addr();
  auto &dconn_pool = addr->dconn_pool;
  dconn_pool->add_downstream_connection(std::move(dconn));
}

void ClientHandler::remove_downstream_connection(DownstreamConnection *dconn) {
  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Removing downstream connection DCONN:" << dconn
                     << " from pool";
  }
  auto &dconn_pool =
      dconn->get_downstream_addr_group()->shared_addr->dconn_pool;
  dconn_pool.remove_downstream_connection(dconn);
}

namespace {
// Computes 32bits hash for session affinity for IP address |ip|.
uint32_t compute_affinity_from_ip(const StringRef &ip) {
  int rv;
  std::array<uint8_t, 32> buf;

  rv = util::sha256(buf.data(), ip);
  if (rv != 0) {
    // Not sure when sha256 failed.  Just fall back to another
    // function.
    return util::hash32(ip);
  }

  return (static_cast<uint32_t>(buf[0]) << 24) |
         (static_cast<uint32_t>(buf[1]) << 16) |
         (static_cast<uint32_t>(buf[2]) << 8) | static_cast<uint32_t>(buf[3]);
}
} // namespace

Http2Session *ClientHandler::select_http2_session_with_affinity(
    const std::shared_ptr<DownstreamAddrGroup> &group, DownstreamAddr *addr) {
  auto &shared_addr = group->shared_addr;

  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Selected DownstreamAddr=" << addr
                     << ", index=" << (addr - shared_addr->addrs.data());
  }

  for (auto session = addr->http2_extra_freelist.head; session;) {
    auto next = session->dlnext;

    if (session->max_concurrency_reached(0)) {
      if (LOG_ENABLED(INFO)) {
        CLOG(INFO, this)
            << "Maximum streams have been reached for Http2Session(" << session
            << ").  Skip it";
      }

      session->remove_from_freelist();
      session = next;

      continue;
    }

    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "Use Http2Session " << session
                       << " from http2_extra_freelist";
    }

    if (session->max_concurrency_reached(1)) {
      if (LOG_ENABLED(INFO)) {
        CLOG(INFO, this) << "Maximum streams are reached for Http2Session("
                         << session << ").";
      }

      session->remove_from_freelist();
    }
    return session;
  }

  auto session = new Http2Session(conn_.loop, worker_->get_cl_ssl_ctx(),
                                  worker_, group, addr);

  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Create new Http2Session " << session;
  }

  session->add_to_extra_freelist();

  return session;
}

namespace {
// Returns true if load of |lhs| is lighter than that of |rhs|.
// Currently, we assume that lesser streams means lesser load.
bool load_lighter(const DownstreamAddr *lhs, const DownstreamAddr *rhs) {
  return lhs->num_dconn < rhs->num_dconn;
}
} // namespace

Http2Session *ClientHandler::select_http2_session(
    const std::shared_ptr<DownstreamAddrGroup> &group) {
  auto &shared_addr = group->shared_addr;

  // First count the working backend addresses.
  size_t min = 0;
  for (const auto &addr : shared_addr->addrs) {
    if (addr.proto != PROTO_HTTP2 || addr.connect_blocker->blocked()) {
      continue;
    }

    ++min;
  }

  if (min == 0) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "No working backend address found";
    }

    return nullptr;
  }

  auto &http2_avail_freelist = shared_addr->http2_avail_freelist;

  if (http2_avail_freelist.size() >= min) {
    for (auto session = http2_avail_freelist.head; session;) {
      auto next = session->dlnext;

      session->remove_from_freelist();

      // session may be in graceful shutdown period now.
      if (session->max_concurrency_reached(0)) {
        if (LOG_ENABLED(INFO)) {
          CLOG(INFO, this)
              << "Maximum streams have been reached for Http2Session("
              << session << ").  Skip it";
        }

        session = next;

        continue;
      }

      if (LOG_ENABLED(INFO)) {
        CLOG(INFO, this) << "Use Http2Session " << session
                         << " from http2_avail_freelist";
      }

      if (session->max_concurrency_reached(1)) {
        if (LOG_ENABLED(INFO)) {
          CLOG(INFO, this) << "Maximum streams are reached for Http2Session("
                           << session << ").";
        }
      } else {
        session->add_to_avail_freelist();
      }
      return session;
    }
  }

  DownstreamAddr *selected_addr = nullptr;

  for (auto &addr : shared_addr->addrs) {
    if (addr.in_avail || addr.proto != PROTO_HTTP2 ||
        (addr.http2_extra_freelist.size() == 0 &&
         addr.connect_blocker->blocked())) {
      continue;
    }

    for (auto session = addr.http2_extra_freelist.head; session;) {
      auto next = session->dlnext;

      // session may be in graceful shutdown period now.
      if (session->max_concurrency_reached(0)) {
        if (LOG_ENABLED(INFO)) {
          CLOG(INFO, this)
              << "Maximum streams have been reached for Http2Session("
              << session << ").  Skip it";
        }

        session->remove_from_freelist();

        session = next;

        continue;
      }

      break;
    }

    if (addr.http2_extra_freelist.size() == 0 &&
        addr.connect_blocker->blocked()) {
      continue;
    }

    if (selected_addr == nullptr || load_lighter(&addr, selected_addr)) {
      selected_addr = &addr;
    }
  }

  assert(selected_addr);

  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Selected DownstreamAddr=" << selected_addr
                     << ", index="
                     << (selected_addr - shared_addr->addrs.data());
  }

  if (selected_addr->http2_extra_freelist.size()) {
    auto session = selected_addr->http2_extra_freelist.head;
    session->remove_from_freelist();

    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "Use Http2Session " << session
                       << " from http2_extra_freelist";
    }

    if (session->max_concurrency_reached(1)) {
      if (LOG_ENABLED(INFO)) {
        CLOG(INFO, this) << "Maximum streams are reached for Http2Session("
                         << session << ").";
      }
    } else {
      session->add_to_avail_freelist();
    }
    return session;
  }

  auto session = new Http2Session(conn_.loop, worker_->get_cl_ssl_ctx(),
                                  worker_, group, selected_addr);

  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Create new Http2Session " << session;
  }

  session->add_to_avail_freelist();

  return session;
}

namespace {
// The chosen value is small enough for uint32_t, and large enough for
// the number of backend.
constexpr uint32_t WEIGHT_MAX = 65536;
} // namespace

namespace {
bool pri_less(const WeightedPri &lhs, const WeightedPri &rhs) {
  if (lhs.cycle < rhs.cycle) {
    return rhs.cycle - lhs.cycle <= WEIGHT_MAX;
  }

  return lhs.cycle - rhs.cycle > WEIGHT_MAX;
}
} // namespace

namespace {
uint32_t next_cycle(const WeightedPri &pri) {
  return pri.cycle + WEIGHT_MAX / (std::min)(WEIGHT_MAX, pri.weight);
}
} // namespace

std::unique_ptr<DownstreamConnection>
ClientHandler::get_downstream_connection(int &err, Downstream *downstream) {
  size_t group_idx;
  auto &downstreamconf = *worker_->get_downstream_config();
  auto &routerconf = downstreamconf.router;

  auto catch_all = downstreamconf.addr_group_catch_all;
  auto &groups = worker_->get_downstream_addr_groups();

  const auto &req = downstream->request();

  err = 0;

  switch (faddr_->alt_mode) {
  case ALTMODE_API:
    return make_unique<APIDownstreamConnection>(worker_);
  case ALTMODE_HEALTHMON:
    return make_unique<HealthMonitorDownstreamConnection>();
  }

  auto &balloc = downstream->get_block_allocator();

  // Fast path.  If we have one group, it must be catch-all group.
  if (groups.size() == 1) {
    group_idx = 0;
  } else {
    StringRef authority;
    if (faddr_->sni_fwd) {
      authority = sni_;
    } else if (!req.authority.empty()) {
      authority = req.authority;
    } else {
      auto h = req.fs.header(http2::HD_HOST);
      if (h) {
        authority = h->value;
      }
    }

    StringRef path;
    // CONNECT method does not have path.  But we requires path in
    // host-path mapping.  As workaround, we assume that path is "/".
    if (req.method != HTTP_CONNECT) {
      path = req.path;
    }

    group_idx = match_downstream_addr_group(routerconf, authority, path, groups,
                                            catch_all, balloc);
  }

  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Downstream address group_idx: " << group_idx;
  }

  if (groups[group_idx]->shared_addr->redirect_if_not_tls && !conn_.tls.ssl) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "Downstream address group " << group_idx
                       << " requires frontend TLS connection.";
    }
    err = SHRPX_ERR_TLS_REQUIRED;
    return nullptr;
  }

  auto &group = groups[group_idx];
  auto &shared_addr = group->shared_addr;

  if (shared_addr->affinity == AFFINITY_IP) {
    if (!affinity_hash_computed_) {
      affinity_hash_ = compute_affinity_from_ip(ipaddr_);
      affinity_hash_computed_ = true;
    }

    const auto &affinity_hash = shared_addr->affinity_hash;

    auto it = std::lower_bound(
        std::begin(affinity_hash), std::end(affinity_hash), affinity_hash_,
        [](const AffinityHash &lhs, uint32_t rhs) { return lhs.hash < rhs; });

    if (it == std::end(affinity_hash)) {
      it = std::begin(affinity_hash);
    }

    auto idx = (*it).idx;

    auto &addr = shared_addr->addrs[idx];
    if (addr.proto == PROTO_HTTP2) {
      auto http2session = select_http2_session_with_affinity(group, &addr);

      auto dconn = make_unique<Http2DownstreamConnection>(http2session);

      dconn->set_client_handler(this);

      return std::move(dconn);
    }

    auto &dconn_pool = addr.dconn_pool;
    auto dconn = dconn_pool->pop_downstream_connection();

    if (!dconn) {
      dconn = make_unique<HttpDownstreamConnection>(group, idx, conn_.loop,
                                                    worker_);
    }

    dconn->set_client_handler(this);

    return dconn;
  }

  auto http1_weight = shared_addr->http1_pri.weight;
  auto http2_weight = shared_addr->http2_pri.weight;

  auto proto = PROTO_NONE;

  if (http1_weight > 0 && http2_weight > 0) {
    // We only advance cycle if both weight has nonzero to keep its
    // distance under WEIGHT_MAX.
    if (pri_less(shared_addr->http1_pri, shared_addr->http2_pri)) {
      proto = PROTO_HTTP1;
      shared_addr->http1_pri.cycle = next_cycle(shared_addr->http1_pri);
    } else {
      proto = PROTO_HTTP2;
      shared_addr->http2_pri.cycle = next_cycle(shared_addr->http2_pri);
    }
  } else if (http1_weight > 0) {
    proto = PROTO_HTTP1;
  } else if (http2_weight > 0) {
    proto = PROTO_HTTP2;
  }

  if (proto == PROTO_NONE) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "No working downstream address found";
    }

    err = -1;
    return nullptr;
  }

  if (proto == PROTO_HTTP2) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "Downstream connection pool is empty."
                       << " Create new one";
    }

    auto http2session = select_http2_session(group);

    if (http2session == nullptr) {
      err = -1;
      return nullptr;
    }

    auto dconn = make_unique<Http2DownstreamConnection>(http2session);

    dconn->set_client_handler(this);

    return std::move(dconn);
  }

  auto &dconn_pool = shared_addr->dconn_pool;

  // pool connection must be HTTP/1.1 connection
  auto dconn = dconn_pool.pop_downstream_connection();

  if (dconn) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "Reuse downstream connection DCONN:" << dconn.get()
                       << " from pool";
    }
  } else {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "Downstream connection pool is empty."
                       << " Create new one";
    }

    dconn =
        make_unique<HttpDownstreamConnection>(group, -1, conn_.loop, worker_);
  }

  dconn->set_client_handler(this);

  return dconn;
}

MemchunkPool *ClientHandler::get_mcpool() { return worker_->get_mcpool(); }

SSL *ClientHandler::get_ssl() const { return conn_.tls.ssl; }

void ClientHandler::direct_http2_upgrade() {
  upstream_ = make_unique<Http2Upstream>(this);
  alpn_ = StringRef::from_lit(NGHTTP2_CLEARTEXT_PROTO_VERSION_ID);
  on_read_ = &ClientHandler::upstream_read;
  write_ = &ClientHandler::write_clear;
}

int ClientHandler::perform_http2_upgrade(HttpsUpstream *http) {
  auto upstream = make_unique<Http2Upstream>(this);

  auto output = upstream->get_response_buf();

  // We might have written non-final header in response_buf, in this
  // case, response_state is still INITIAL.  If this non-final header
  // and upgrade header fit in output buffer, do upgrade.  Otherwise,
  // to avoid to send this non-final header as response body in HTTP/2
  // upstream, fail upgrade.
  auto downstream = http->get_downstream();
  auto input = downstream->get_response_buf();

  if (upstream->upgrade_upstream(http) != 0) {
    return -1;
  }
  // http pointer is now owned by upstream.
  upstream_.release();
  // TODO We might get other version id in HTTP2-settings, if we
  // support aliasing for h2, but we just use library default for now.
  alpn_ = StringRef::from_lit(NGHTTP2_CLEARTEXT_PROTO_VERSION_ID);
  on_read_ = &ClientHandler::upstream_http2_connhd_read;
  write_ = &ClientHandler::write_clear;

  input->remove(*output, input->rleft());

  constexpr auto res =
      StringRef::from_lit("HTTP/1.1 101 Switching Protocols\r\n"
                          "Connection: Upgrade\r\n"
                          "Upgrade: " NGHTTP2_CLEARTEXT_PROTO_VERSION_ID "\r\n"
                          "\r\n");

  output->append(res);
  upstream_ = std::move(upstream);

  signal_write();
  return 0;
}

bool ClientHandler::get_http2_upgrade_allowed() const { return !conn_.tls.ssl; }

StringRef ClientHandler::get_upstream_scheme() const {
  if (conn_.tls.ssl) {
    return StringRef::from_lit("https");
  } else {
    return StringRef::from_lit("http");
  }
}

void ClientHandler::start_immediate_shutdown() {
  ev_timer_start(conn_.loop, &reneg_shutdown_timer_);
}

void ClientHandler::write_accesslog(Downstream *downstream) {
  nghttp2::tls::TLSSessionInfo tls_info;
  auto &req = downstream->request();

  auto config = get_config();

  if (!req.tstamp) {
    auto lgconf = log_config();
    lgconf->update_tstamp(std::chrono::system_clock::now());
    req.tstamp = lgconf->tstamp;
  }

  upstream_accesslog(
      config->logging.access.format,
      LogSpec{
          downstream, ipaddr_, alpn_, sni_,
          nghttp2::tls::get_tls_session_info(&tls_info, conn_.tls.ssl),
          std::chrono::high_resolution_clock::now(), // request_end_time
          port_, faddr_->port, config->pid,
      });
}

ClientHandler::ReadBuf *ClientHandler::get_rb() { return &rb_; }

void ClientHandler::signal_write() { conn_.wlimit.startw(); }

RateLimit *ClientHandler::get_rlimit() { return &conn_.rlimit; }
RateLimit *ClientHandler::get_wlimit() { return &conn_.wlimit; }

ev_io *ClientHandler::get_wev() { return &conn_.wev; }

Worker *ClientHandler::get_worker() const { return worker_; }

namespace {
ssize_t parse_proxy_line_port(const uint8_t *first, const uint8_t *last) {
  auto p = first;
  int32_t port = 0;

  if (p == last) {
    return -1;
  }

  if (*p == '0') {
    if (p + 1 != last && util::is_digit(*(p + 1))) {
      return -1;
    }
    return 1;
  }

  for (; p != last && util::is_digit(*p); ++p) {
    port *= 10;
    port += *p - '0';

    if (port > 65535) {
      return -1;
    }
  }

  return p - first;
}
} // namespace

int ClientHandler::on_proxy_protocol_finish() {
  if (conn_.tls.ssl) {
    conn_.tls.rbuf.append(rb_.pos(), rb_.rleft());
    rb_.reset();
  }

  setup_upstream_io_callback();

  // Run on_read to process data left in buffer since they are not
  // notified further
  if (on_read() != 0) {
    return -1;
  }

  return 0;
}

// http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt
int ClientHandler::proxy_protocol_read() {
  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "PROXY-protocol: Started";
  }

  auto first = rb_.pos();

  // NULL character really destroys functions which expects NULL
  // terminated string.  We won't expect it in PROXY protocol line, so
  // find it here.
  auto chrs = std::array<char, 2>{{'\n', '\0'}};

  constexpr size_t MAX_PROXY_LINELEN = 107;

  auto bufend = rb_.pos() + (std::min)(MAX_PROXY_LINELEN, rb_.rleft());

  auto end =
      std::find_first_of(rb_.pos(), bufend, std::begin(chrs), std::end(chrs));

  if (end == bufend || *end == '\0' || end == rb_.pos() || *(end - 1) != '\r') {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "PROXY-protocol-v1: No ending CR LF sequence found";
    }
    return -1;
  }

  --end;

  constexpr auto HEADER = StringRef::from_lit("PROXY ");

  if (static_cast<size_t>(end - rb_.pos()) < HEADER.size()) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "PROXY-protocol-v1: PROXY version 1 ID not found";
    }
    return -1;
  }

  if (!util::streq(HEADER, StringRef{rb_.pos(), HEADER.size()})) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "PROXY-protocol-v1: Bad PROXY protocol version 1 ID";
    }
    return -1;
  }

  rb_.drain(HEADER.size());

  int family;

  if (rb_.pos()[0] == 'T') {
    if (end - rb_.pos() < 5) {
      if (LOG_ENABLED(INFO)) {
        CLOG(INFO, this) << "PROXY-protocol-v1: INET protocol family not found";
      }
      return -1;
    }

    if (rb_.pos()[1] != 'C' || rb_.pos()[2] != 'P') {
      if (LOG_ENABLED(INFO)) {
        CLOG(INFO, this) << "PROXY-protocol-v1: Unknown INET protocol family";
      }
      return -1;
    }

    switch (rb_.pos()[3]) {
    case '4':
      family = AF_INET;
      break;
    case '6':
      family = AF_INET6;
      break;
    default:
      if (LOG_ENABLED(INFO)) {
        CLOG(INFO, this) << "PROXY-protocol-v1: Unknown INET protocol family";
      }
      return -1;
    }

    rb_.drain(5);
  } else {
    if (end - rb_.pos() < 7) {
      if (LOG_ENABLED(INFO)) {
        CLOG(INFO, this) << "PROXY-protocol-v1: INET protocol family not found";
      }
      return -1;
    }
    if (!util::streq_l("UNKNOWN", rb_.pos(), 7)) {
      if (LOG_ENABLED(INFO)) {
        CLOG(INFO, this) << "PROXY-protocol-v1: Unknown INET protocol family";
      }
      return -1;
    }

    rb_.drain(end + 2 - rb_.pos());

    return on_proxy_protocol_finish();
  }

  // source address
  auto token_end = std::find(rb_.pos(), end, ' ');
  if (token_end == end) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "PROXY-protocol-v1: Source address not found";
    }
    return -1;
  }

  *token_end = '\0';
  if (!util::numeric_host(reinterpret_cast<const char *>(rb_.pos()), family)) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "PROXY-protocol-v1: Invalid source address";
    }
    return -1;
  }

  auto src_addr = rb_.pos();
  auto src_addrlen = token_end - rb_.pos();

  rb_.drain(token_end - rb_.pos() + 1);

  // destination address
  token_end = std::find(rb_.pos(), end, ' ');
  if (token_end == end) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "PROXY-protocol-v1: Destination address not found";
    }
    return -1;
  }

  *token_end = '\0';
  if (!util::numeric_host(reinterpret_cast<const char *>(rb_.pos()), family)) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "PROXY-protocol-v1: Invalid destination address";
    }
    return -1;
  }

  // Currently we don't use destination address

  rb_.drain(token_end - rb_.pos() + 1);

  // source port
  auto n = parse_proxy_line_port(rb_.pos(), end);
  if (n <= 0 || *(rb_.pos() + n) != ' ') {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "PROXY-protocol-v1: Invalid source port";
    }
    return -1;
  }

  rb_.pos()[n] = '\0';
  auto src_port = rb_.pos();
  auto src_portlen = n;

  rb_.drain(n + 1);

  // destination  port
  n = parse_proxy_line_port(rb_.pos(), end);
  if (n <= 0 || rb_.pos() + n != end) {
    if (LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "PROXY-protocol-v1: Invalid destination port";
    }
    return -1;
  }

  // Currently we don't use destination port

  rb_.drain(end + 2 - rb_.pos());

  ipaddr_ =
      make_string_ref(balloc_, StringRef{src_addr, src_addr + src_addrlen});
  port_ = make_string_ref(balloc_, StringRef{src_port, src_port + src_portlen});

  if (LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "PROXY-protocol-v1: Finished, " << (rb_.pos() - first)
                     << " bytes read";
  }

  auto config = get_config();
  auto &fwdconf = config->http.forwarded;

  if ((fwdconf.params & FORWARDED_FOR) &&
      fwdconf.for_node_type == FORWARDED_NODE_IP) {
    init_forwarded_for(family, ipaddr_);
  }

  return on_proxy_protocol_finish();
}

StringRef ClientHandler::get_forwarded_by() const {
  auto &fwdconf = get_config()->http.forwarded;

  if (fwdconf.by_node_type == FORWARDED_NODE_OBFUSCATED) {
    return fwdconf.by_obfuscated;
  }

  return faddr_->hostport;
}

StringRef ClientHandler::get_forwarded_for() const { return forwarded_for_; }

const UpstreamAddr *ClientHandler::get_upstream_addr() const { return faddr_; }

Connection *ClientHandler::get_connection() { return &conn_; };

void ClientHandler::set_tls_sni(const StringRef &sni) {
  sni_ = make_string_ref(balloc_, sni);
}

StringRef ClientHandler::get_tls_sni() const { return sni_; }

BlockAllocator &ClientHandler::get_block_allocator() { return balloc_; }

} // namespace shrpx
