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
#ifndef SHRPX_LIVE_CHECK_H
#define SHRPX_LIVE_CHECK_H

#include "shrpx.h"

#include <functional>
#include <random>

#include <openssl/ssl.h>

#include <ev.h>

#include "shrpx_connection.h"

namespace shrpx {

class Worker;
struct DownstreamAddrGroup;
struct DownstreamAddr;

class LiveCheck {
public:
  LiveCheck(struct ev_loop *loop, SSL_CTX *ssl_ctx, Worker *worker,
            DownstreamAddrGroup *group, DownstreamAddr *addr,
            std::mt19937 &gen);
  ~LiveCheck();

  void disconnect();

  void on_success();
  void on_failure();

  int initiate_connection();

  // Schedules next connection attempt
  void schedule();

  // Low level I/O operation callback; they are called from do_read()
  // or do_write().
  int noop();
  int connected();
  int tls_handshake();

  int do_read();
  int do_write();

private:
  Connection conn_;
  std::mt19937 &gen_;
  ev_timer backoff_timer_;
  std::function<int(LiveCheck &)> read_, write_;
  Worker *worker_;
  // nullptr if no TLS is configured
  SSL_CTX *ssl_ctx_;
  DownstreamAddrGroup *group_;
  // Address of remote endpoint
  DownstreamAddr *addr_;
  // The number of successful connect attempt in a row.
  size_t success_count_;
  // The number of unsuccessful connect attempt in a row.
  size_t fail_count_;
};

} // namespace shrpx

#endif // SHRPX_LIVE_CHECK_H
