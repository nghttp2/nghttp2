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

#include <openssl/ssl.h>

#include <event.h>
#include <event2/bufferevent.h>

namespace shrpx {

struct WorkerInfo {
  SSL_CTX *sv_ssl_ctx;
  SSL_CTX *cl_ssl_ctx;
  bufferevent *bev;
  int sv[2];
};

class Http2Session;
struct WorkerStat;

class ListenHandler {
public:
  ListenHandler(event_base *evbase, SSL_CTX *sv_ssl_ctx, SSL_CTX *cl_ssl_ctx);
  ~ListenHandler();
  int accept_connection(evutil_socket_t fd, sockaddr *addr, int addrlen);
  void create_worker_thread(size_t num);
  event_base* get_evbase() const;
  int create_http2_session();
private:
  std::vector<WorkerInfo> workers_;
  event_base *evbase_;
  // The frontend server SSL_CTX
  SSL_CTX *sv_ssl_ctx_;
  // The backend server SSL_CTX
  SSL_CTX *cl_ssl_ctx_;
  // Shared backend HTTP2 session. NULL if multi-threaded. In
  // multi-threaded case, see shrpx_worker.cc.
  Http2Session *http2session_;
  bufferevent_rate_limit_group *rate_limit_group_;
  std::unique_ptr<WorkerStat> worker_stat_;
  size_t num_worker_;
  unsigned int worker_round_robin_cnt_;
};

} // namespace shrpx

#endif // SHRPX_LISTEN_HANDLER_H
