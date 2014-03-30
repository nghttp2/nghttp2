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

#include <set>
#include <memory>

#include <event.h>
#include <event2/bufferevent.h>

#include <openssl/ssl.h>

namespace shrpx {

class Upstream;
class DownstreamConnection;
class Http2Session;
class HttpsUpstream;

class ClientHandler {
public:
  ClientHandler(bufferevent *bev,
                bufferevent_rate_limit_group *rate_limit_group,
                int fd, SSL *ssl, const char *ipaddr);
  ~ClientHandler();
  int on_read();
  int on_event();
  bufferevent* get_bev() const;
  event_base* get_evbase() const;
  void set_bev_cb(bufferevent_data_cb readcb, bufferevent_data_cb writecb,
                  bufferevent_event_cb eventcb);
  void set_upstream_timeouts(const timeval *read_timeout,
                             const timeval *write_timeout);
  int validate_next_proto();
  const std::string& get_ipaddr() const;
  bool get_should_close_after_write() const;
  void set_should_close_after_write(bool f);
  Upstream* get_upstream();

  void pool_downstream_connection(DownstreamConnection *dconn);
  void remove_downstream_connection(DownstreamConnection *dconn);
  DownstreamConnection* get_downstream_connection();
  size_t get_outbuf_length();
  SSL* get_ssl() const;
  void set_http2_session(Http2Session *http2session);
  Http2Session* get_http2_session() const;
  size_t get_left_connhd_len() const;
  void set_left_connhd_len(size_t left);
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
private:
  std::set<DownstreamConnection*> dconn_pool_;
  std::unique_ptr<Upstream> upstream_;
  std::string ipaddr_;
  bufferevent *bev_;
  // Shared HTTP2 session for each thread. NULL if backend is not
  // HTTP2. Not deleted by this object.
  Http2Session *http2session_;
  SSL *ssl_;
  // The number of bytes of HTTP/2 client connection header to read
  size_t left_connhd_len_;
  int fd_;
  bool should_close_after_write_;
  bool tls_handshake_;
  bool tls_renegotiation_;
};

} // namespace shrpx

#endif // SHRPX_CLIENT_HANDLER_H
