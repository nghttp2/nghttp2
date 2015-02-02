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
#ifndef SHRPX_WORKER_H
#define SHRPX_WORKER_H

#include "shrpx.h"

#include <mutex>
#include <deque>
#include <thread>
#ifndef NOTHREADS
#include <future>
#endif // NOTHREADS

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <ev.h>

#include "shrpx_config.h"
#include "shrpx_downstream_connection_pool.h"

namespace shrpx {

class Http2Session;
class ConnectBlocker;

namespace ssl {
class CertLookupTree;
} // namespace ssl

struct WorkerStat {
  WorkerStat() : num_connections(0), next_downstream(0) {}

  size_t num_connections;
  // Next downstream index in Config::downstream_addrs.  For HTTP/2
  // downstream connections, this is always 0.  For HTTP/1, this is
  // used as load balancing.
  size_t next_downstream;
};

enum WorkerEventType {
  NEW_CONNECTION = 0x01,
  REOPEN_LOG = 0x02,
  GRACEFUL_SHUTDOWN = 0x03,
  RENEW_TICKET_KEYS = 0x04,
};

struct WorkerEvent {
  WorkerEventType type;
  struct {
    sockaddr_union client_addr;
    size_t client_addrlen;
    int client_fd;
  };
  std::shared_ptr<TicketKeys> ticket_keys;
};

class Worker {
public:
  Worker(SSL_CTX *sv_ssl_ctx, SSL_CTX *cl_ssl_ctx,
         ssl::CertLookupTree *cert_tree,
         const std::shared_ptr<TicketKeys> &ticket_keys);
  ~Worker();
  void wait();
  void process_events();
  void send(const WorkerEvent &event);

private:
#ifndef NOTHREADS
  std::future<void> fut_;
#endif // NOTHREADS
  std::mutex m_;
  std::deque<WorkerEvent> q_;
  ev_async w_;
  DownstreamConnectionPool dconn_pool_;
  struct ev_loop *loop_;
  SSL_CTX *sv_ssl_ctx_;
  SSL_CTX *cl_ssl_ctx_;
  std::unique_ptr<Http2Session> http2session_;
  std::unique_ptr<ConnectBlocker> http1_connect_blocker_;
  std::unique_ptr<WorkerStat> worker_stat_;
};

} // namespace shrpx

#endif // SHRPX_WORKER_H
