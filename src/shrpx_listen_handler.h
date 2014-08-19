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
#ifndef SHRPX_LISTEN_HANDLER_H
#define SHRPX_LISTEN_HANDLER_H

#include "shrpx.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <memory>
#include <vector>
#ifndef NOTHREADS
#include <future>
#endif // NOTHREADS

#include <openssl/ssl.h>

#include <event.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

namespace shrpx {

struct WorkerInfo {
#ifndef NOTHREADS
  std::future<void> fut;
#endif // NOTHREADS
  SSL_CTX *sv_ssl_ctx;
  SSL_CTX *cl_ssl_ctx;
  bufferevent *bev;
  int sv[2];
};

class Http2Session;
class ConnectBlocker;
struct WorkerStat;

class ListenHandler {
public:
  ListenHandler(event_base *evbase, SSL_CTX *sv_ssl_ctx, SSL_CTX *cl_ssl_ctx);
  ~ListenHandler();
  int accept_connection(evutil_socket_t fd, sockaddr *addr, int addrlen);
  void create_worker_thread(size_t num);
  void worker_reopen_log_files();
  event_base* get_evbase() const;
  int create_http2_session();
  int create_http1_connect_blocker();
  const WorkerStat* get_worker_stat() const;
  void set_evlistener4(evconnlistener *evlistener4);
  evconnlistener* get_evlistener4() const;
  void set_evlistener6(evconnlistener *evlistener6);
  evconnlistener* get_evlistener6() const;
  void disable_evlistener();
  void accept_pending_connection();
  void graceful_shutdown_worker();
  void join_worker();
  void notify_worker_shutdown();
private:
  std::vector<std::unique_ptr<WorkerInfo>> workers_;
  event_base *evbase_;
  // The frontend server SSL_CTX
  SSL_CTX *sv_ssl_ctx_;
  // The backend server SSL_CTX
  SSL_CTX *cl_ssl_ctx_;
  // Shared backend HTTP2 session. NULL if multi-threaded. In
  // multi-threaded case, see shrpx_worker.cc.
  std::unique_ptr<Http2Session> http2session_;
  std::unique_ptr<ConnectBlocker> http1_connect_blocker_;
  bufferevent_rate_limit_group *rate_limit_group_;
  evconnlistener *evlistener4_;
  evconnlistener *evlistener6_;
  std::unique_ptr<WorkerStat> worker_stat_;
  unsigned int worker_round_robin_cnt_;
  int num_worker_shutdown_;
};

} // namespace shrpx

#endif // SHRPX_LISTEN_HANDLER_H
