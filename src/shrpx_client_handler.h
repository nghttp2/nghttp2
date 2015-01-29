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

#include <ev.h>

#include <openssl/ssl.h>

#include "shrpx_rate_limit.h"
#include "buffer.h"

using namespace nghttp2;

namespace shrpx {

class Upstream;
class DownstreamConnection;
class Http2Session;
class HttpsUpstream;
class ConnectBlocker;
class DownstreamConnectionPool;
struct WorkerStat;

class ClientHandler {
public:
  ClientHandler(struct ev_loop *loop, int fd, SSL *ssl, const char *ipaddr,
                const char *port, WorkerStat *worker_stat,
                DownstreamConnectionPool *dconn_pool);
  ~ClientHandler();

  // Performs clear text I/O
  int read_clear();
  int write_clear();
  // Performs TLS handshake
  int tls_handshake();
  // Performs TLS I/O
  int read_tls();
  int write_tls();

  int upstream_noop();
  int upstream_read();
  int upstream_http2_connhd_read();
  int upstream_http1_connhd_read();
  int upstream_write();

  // Performs I/O operation.  Internally calls on_read()/on_write().
  int do_read();
  int do_write();

  // Processes buffers.  No underlying I/O operation will be done.
  int on_read();
  int on_write();

  struct ev_loop *get_loop() const;
  void reset_upstream_read_timeout(ev_tstamp t);
  void reset_upstream_write_timeout(ev_tstamp t);
  int validate_next_proto();
  const std::string &get_ipaddr() const;
  const std::string &get_port() const;
  bool get_should_close_after_write() const;
  void set_should_close_after_write(bool f);
  Upstream *get_upstream();

  void pool_downstream_connection(std::unique_ptr<DownstreamConnection> dconn);
  void remove_downstream_connection(DownstreamConnection *dconn);
  std::unique_ptr<DownstreamConnection> get_downstream_connection();
  SSL *get_ssl() const;
  void set_http2_session(Http2Session *http2session);
  Http2Session *get_http2_session() const;
  void set_http1_connect_blocker(ConnectBlocker *http1_connect_blocker);
  ConnectBlocker *get_http1_connect_blocker() const;
  // Call this function when HTTP/2 connection header is received at
  // the start of the connection.
  void direct_http2_upgrade();
  // Performs HTTP/2 Upgrade from the connection managed by
  // |http|. If this function fails, the connection must be
  // terminated. This function returns 0 if it succeeds, or -1.
  int perform_http2_upgrade(HttpsUpstream *http);
  bool get_http2_upgrade_allowed() const;
  // Returns upstream scheme, either "http" or "https"
  std::string get_upstream_scheme() const;
  void set_tls_handshake(bool f);
  bool get_tls_handshake() const;
  void set_tls_renegotiation(bool f);
  bool get_tls_renegotiation() const;
  // Returns maximum chunk size for one evbuffer_add().  The intention
  // of this chunk size is control the TLS record size.  The actual
  // SSL_write() call is done under libevent control.  In
  // libevent-2.0.21, libevent calls SSL_write() for each chunk inside
  // evbuffer.  This means that we can control TLS record size by
  // adjusting the chunk size to evbuffer_add().
  //
  // This function returns -1, if TLS is not enabled or no limitation
  // is required.
  ssize_t get_write_limit();
  // Updates the number of bytes written in warm up period.
  void update_warmup_writelen(size_t n);
  // Updates the time when last write was done.
  void update_last_write_time();

  // Writes upstream accesslog using |downstream|.  The |downstream|
  // must not be nullptr.
  void write_accesslog(Downstream *downstream);

  // Writes upstream accesslog.  This function is used if
  // corresponding Downstream object is not available.
  void write_accesslog(int major, int minor, unsigned int status,
                       int64_t body_bytes_sent);
  WorkerStat *get_worker_stat() const;

  using WriteBuf = Buffer<65536>;
  using ReadBuf = Buffer<8192>;

  WriteBuf *get_wb();
  ReadBuf *get_rb();

  RateLimit *get_rlimit();
  RateLimit *get_wlimit();

  void signal_write();

private:
  ev_io wev_;
  ev_io rev_;
  ev_timer wt_;
  ev_timer rt_;
  ev_timer reneg_shutdown_timer_;
  std::unique_ptr<Upstream> upstream_;
  std::string ipaddr_;
  std::string port_;
  // The ALPN identifier negotiated for this connection.
  std::string alpn_;
  std::function<int(ClientHandler &)> read_, write_;
  std::function<int(ClientHandler &)> on_read_, on_write_;
  RateLimit wlimit_;
  RateLimit rlimit_;
  struct ev_loop *loop_;
  DownstreamConnectionPool *dconn_pool_;
  // Shared HTTP2 session for each thread. NULL if backend is not
  // HTTP2. Not deleted by this object.
  Http2Session *http2session_;
  ConnectBlocker *http1_connect_blocker_;
  SSL *ssl_;
  WorkerStat *worker_stat_;
  double last_write_time_;
  size_t warmup_writelen_;
  // The number of bytes of HTTP/2 client connection header to read
  size_t left_connhd_len_;
  size_t tls_last_writelen_;
  size_t tls_last_readlen_;
  int fd_;
  bool should_close_after_write_;
  bool tls_handshake_;
  bool tls_renegotiation_;
  WriteBuf wb_;
  ReadBuf rb_;
};

} // namespace shrpx

#endif // SHRPX_CLIENT_HANDLER_H
