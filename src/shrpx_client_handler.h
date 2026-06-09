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
#ifndef SHRPX_CLIENT_HANDLER_H
#define SHRPX_CLIENT_HANDLER_H

#include "shrpx.h"

#include <memory>
#include <expected>

#include <ev.h>

#include "ssl_compat.h"

#ifdef NGHTTP2_OPENSSL_IS_WOLFSSL
#  include <wolfssl/options.h>
#  include <wolfssl/openssl/ssl.h>
#else // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)
#  include <openssl/ssl.h>
#endif // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)

#include "shrpx_rate_limit.h"
#include "shrpx_connection.h"
#include "buffer.h"
#include "memchunk.h"
#include "allocator.h"
#include "errors.h"

using namespace nghttp2;

namespace shrpx {

class Upstream;
class DownstreamConnection;
class HttpsUpstream;
class ConnectBlocker;
class DownstreamConnectionPool;
class Worker;
class Downstream;
struct WorkerStat;
struct DownstreamAddrGroup;
struct SharedDownstreamAddr;
struct DownstreamAddr;
#ifdef ENABLE_HTTP3
class Http3Upstream;
#endif // defined(ENABLE_HTTP3)

class ClientHandler {
public:
  ClientHandler(Worker *worker, int fd, SSL *ssl, std::string_view ipaddr,
                std::string_view port, int family, const UpstreamAddr *faddr);
  ~ClientHandler();

  std::expected<void, Error> noop() { return {}; }
  // Performs clear text I/O
  std::expected<void, Error> read_clear();
  std::expected<void, Error> write_clear();
  // Specialized for PROXY-protocol use; peek data from socket.
  std::expected<void, Error> proxy_protocol_peek_clear();
  // Performs TLS handshake
  std::expected<void, Error> tls_handshake();
  // Performs TLS I/O
  std::expected<void, Error> read_tls();
  std::expected<void, Error> write_tls();

  std::expected<void, Error> upstream_noop() { return {}; }
  std::expected<void, Error> upstream_read();
  std::expected<void, Error> upstream_http2_connhd_read();
  std::expected<void, Error> upstream_http1_connhd_read();
  std::expected<void, Error> upstream_write();

  std::expected<void, Error> proxy_protocol_read();
  std::expected<void, Error> proxy_protocol_v2_read();
  std::expected<void, Error> on_proxy_protocol_finish();

  // Performs I/O operation.  Internally calls on_read()/on_write().
  std::expected<void, Error> do_read();
  std::expected<void, Error> do_write();

  // Processes buffers.  No underlying I/O operation will be done.
  std::expected<void, Error> on_read();
  std::expected<void, Error> on_write();

  struct ev_loop *get_loop() const;
  void reset_upstream_read_timeout(ev_tstamp t);
  void reset_upstream_write_timeout(ev_tstamp t);

  std::expected<void, Error> validate_next_proto();
  std::string_view get_ipaddr() const;
  bool get_should_close_after_write() const;
  void set_should_close_after_write(bool f);
  Upstream *get_upstream();

  void pool_downstream_connection(std::unique_ptr<DownstreamConnection> dconn);
  void remove_downstream_connection(DownstreamConnection *dconn);
  std::expected<DownstreamAddr *, Error>
  get_downstream_addr(DownstreamAddrGroup *group, Downstream *downstream);
  // Returns DownstreamConnection object based on request path.
  std::expected<std::unique_ptr<DownstreamConnection>, Error>
  get_downstream_connection(Downstream *downstream);
  MemchunkPool *get_mcpool();
  SSL *get_ssl() const;
  // Call this function when HTTP/2 connection header is received at
  // the start of the connection.
  void direct_http2_upgrade();
  // Performs HTTP/2 Upgrade from the connection managed by |http|. If
  // this function fails, the connection must be terminated.
  std::expected<void, Error> perform_http2_upgrade(HttpsUpstream *http);
  bool get_http2_upgrade_allowed() const;
  // Returns upstream scheme, either "http" or "https"
  std::string_view get_upstream_scheme() const;
  void start_immediate_shutdown();

  // Writes upstream accesslog using |downstream|.  The |downstream|
  // must not be nullptr.
  void write_accesslog(Downstream *downstream);

  Worker *get_worker() const;

  // Initializes forwarded_for_.
  void init_forwarded_for(int family, std::string_view ipaddr);

  using ReadBuf = DefaultMemchunkBuffer;

  ReadBuf *get_rb();

  RateLimit *get_rlimit();
  RateLimit *get_wlimit();

  void signal_write();
  ev_io *get_wev();

  void setup_upstream_io_callback();

#ifdef ENABLE_HTTP3
  void setup_http3_upstream(std::unique_ptr<Http3Upstream> &&upstream);
  std::expected<void, Error> read_quic(const UpstreamAddr *faddr,
                                       const Address &remote_addr,
                                       const Address &local_addr,
                                       const ngtcp2_pkt_info &pi,
                                       std::span<const uint8_t> data);
  std::expected<void, Error> write_quic();
#endif // defined(ENABLE_HTTP3)

  // Returns string suitable for use in "by" parameter of Forwarded
  // header field.
  std::string_view get_forwarded_by() const;
  // Returns string suitable for use in "for" parameter of Forwarded
  // header field.
  std::string_view get_forwarded_for() const;

  Http2Session *
  get_http2_session(const std::shared_ptr<DownstreamAddrGroup> &group,
                    DownstreamAddr *addr);

  // Returns an affinity cookie value for |downstream|.  |cookie_name|
  // is used to inspect cookie header field in request header fields.
  uint32_t get_affinity_cookie(Downstream *downstream,
                               std::string_view cookie_name);

  std::expected<DownstreamAddr *, Error> get_downstream_addr_strict_affinity(
    const std::shared_ptr<SharedDownstreamAddr> &shared_addr,
    Downstream *downstream);

  const UpstreamAddr *get_upstream_addr() const;

  void repeat_read_timer();
  void stop_read_timer();

  Connection *get_connection();

  // Stores |sni| which is TLS SNI extension value client sent in this
  // connection.
  void set_tls_sni(std::string_view sni);
  // Returns TLS SNI extension value client sent in this connection.
  std::string_view get_tls_sni() const;

  // Returns ALPN negotiated in this connection.
  std::string_view get_alpn() const;

  BlockAllocator &get_block_allocator();

  void set_alpn_from_conn();

  void set_local_hostport(const sockaddr *addr, socklen_t addrlen);

  void register_write_rate_timer(Downstream *downstream);
  void unregister_write_rate_timer(Downstream *downstream);
  void extend_write_rate_timer(size_t nwrite);
  std::expected<void, Error> on_write_rate_timeout();

private:
  // Allocator to allocate memory for connection-wide objects.  Make
  // sure that the allocations must be bounded, and not proportional
  // to the number of requests.
  //
  // We use balloc_ for TLS session ID (64), ipaddr (IPv6) (39), port
  // (5), forwarded-for (IPv6) (41), alpn (5), proxyproto ipaddr (15),
  // proxyproto port (5), sni (32, estimated).  we need terminal NULL
  // byte for each.  We also require 8 bytes header for each
  // allocation.  We align at 16 bytes boundary, so the required space
  // is 64 + 48 + 16 + 48 + 16 + 16 + 16 + 32 + 8 + 8 * 8 = 328.
  BlockAllocator balloc_{512, 512};
  DefaultMemchunkBuffer rb_;
  Connection conn_;
  ev_timer reneg_shutdown_timer_;
  ev_timer write_rate_timer_;
  std::unique_ptr<Upstream> upstream_;
  // IP address of client.  If UNIX domain socket is used, this is
  // "localhost".
  std::string_view ipaddr_;
  std::string_view port_;
  // The ALPN identifier negotiated for this connection.
  std::string_view alpn_;
  // The client address used in "for" parameter of Forwarded header
  // field.
  std::string_view forwarded_for_;
  // lowercased TLS SNI which client sent.
  std::string_view sni_;
  // The host and port of local address where the connection is
  // accepted.  For QUIC connection, the local address may change due
  // to client address migration, but this value stays the same for
  // now.
  std::string_view local_hostport_;
  std::function<std::expected<void, Error>(ClientHandler &)> read_, write_;
  std::function<std::expected<void, Error>(ClientHandler &)> on_read_,
    on_write_;
  // Address of frontend listening socket
  const UpstreamAddr *faddr_;
  Worker *worker_;
  // The number of bytes of HTTP/2 client connection header to read
  size_t left_connhd_len_{NGHTTP2_CLIENT_MAGIC_LEN};
  // hash for session affinity using client IP
  uint32_t affinity_hash_{};
  bool should_close_after_write_{};
  // true if affinity_hash_ is computed
  bool affinity_hash_computed_{};
  // the number of Downstreams participating to the write rate group.
  size_t write_rate_member_count_{};
};

} // namespace shrpx

#endif // !defined(SHRPX_CLIENT_HANDLER_H)
