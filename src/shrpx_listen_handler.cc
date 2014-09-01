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
#include "shrpx_listen_handler.h"

#include <unistd.h>

#include <cerrno>
#include <thread>

#include <event2/bufferevent_ssl.h>

#include "shrpx_client_handler.h"
#include "shrpx_thread_event_receiver.h"
#include "shrpx_ssl.h"
#include "shrpx_worker.h"
#include "shrpx_worker_config.h"
#include "shrpx_config.h"
#include "shrpx_http2_session.h"
#include "shrpx_connect_blocker.h"
#include "util.h"

using namespace nghttp2;

namespace shrpx {

namespace {
void evlistener_disable_cb(evutil_socket_t fd, short events, void *arg)
{
  auto listener_handler = static_cast<ListenHandler*>(arg);

  // If we are in graceful shutdown period, we must not enable
  // evlisteners again.
  if(worker_config->graceful_shutdown) {
    return;
  }

  listener_handler->enable_evlistener();
}
} // namespace

ListenHandler::ListenHandler(event_base *evbase, SSL_CTX *sv_ssl_ctx,
                             SSL_CTX *cl_ssl_ctx)
  : evbase_(evbase),
    sv_ssl_ctx_(sv_ssl_ctx),
    cl_ssl_ctx_(cl_ssl_ctx),
    rate_limit_group_(bufferevent_rate_limit_group_new
                      (evbase, get_config()->worker_rate_limit_cfg)),
    evlistener4_(nullptr),
    evlistener6_(nullptr),
    evlistener_disable_timerev_(evtimer_new(evbase,
                                            evlistener_disable_cb, this)),
    worker_stat_(util::make_unique<WorkerStat>()),
    num_worker_shutdown_(0),
    worker_round_robin_cnt_(0)
{}

ListenHandler::~ListenHandler()
{
  bufferevent_rate_limit_group_free(rate_limit_group_);
}

void ListenHandler::worker_reopen_log_files()
{
  WorkerEvent wev;

  memset(&wev, 0, sizeof(wev));
  wev.type = REOPEN_LOG;

  for(auto& info : workers_) {
    bufferevent_write(info->bev, &wev, sizeof(wev));
  }
}

#ifndef NOTHREADS
namespace {
void worker_writecb(bufferevent *bev, void *ptr)
{
  auto listener_handler = static_cast<ListenHandler*>(ptr);
  auto output = bufferevent_get_output(bev);

  if(!worker_config->graceful_shutdown ||
     evbuffer_get_length(output) != 0) {
    return;
  }

  // If graceful_shutdown is true and nothing left to send, we sent
  // graceful shutdown event to worker successfully.  The worker is
  // now doing shutdown.
  listener_handler->notify_worker_shutdown();

  // Disable bev so that this won' be called accidentally in the
  // future.
  bufferevent_disable(bev, EV_READ | EV_WRITE);
}
} // namespace
#endif // NOTHREADS

void ListenHandler::create_worker_thread(size_t num)
{
#ifndef NOTHREADS
  workers_.resize(0);
  for(size_t i = 0; i < num; ++i) {
    int rv;
    auto info = util::make_unique<WorkerInfo>();
    rv = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0,
                    info->sv);
    if(rv == -1) {
      auto error = errno;
      LLOG(ERROR, this) << "socketpair() failed: errno=" << error;
      continue;
    }

    info->sv_ssl_ctx = sv_ssl_ctx_;
    info->cl_ssl_ctx = cl_ssl_ctx_;

    info->fut = std::async(std::launch::async, start_threaded_worker,
                           info.get());

    auto bev = bufferevent_socket_new(evbase_, info->sv[0],
                                      BEV_OPT_DEFER_CALLBACKS);
    if(!bev) {
      LLOG(ERROR, this) << "bufferevent_socket_new() failed";
      for(size_t j = 0; j < 2; ++j) {
        close(info->sv[j]);
      }
      continue;
    }

    bufferevent_setcb(bev, nullptr, worker_writecb, nullptr, this);

    info->bev = bev;

    workers_.push_back(std::move(info));

    if(LOG_ENABLED(INFO)) {
      LLOG(INFO, this) << "Created thread #" << workers_.size() - 1;
    }
  }
#endif // NOTHREADS
}

void ListenHandler::join_worker()
{
#ifndef NOTHREADS
  int n = 0;

  if(LOG_ENABLED(INFO)) {
    LLOG(INFO, this) << "Waiting for worker thread to join: n="
                     << workers_.size();
  }

  for(auto& worker : workers_) {
    worker->fut.get();
    if(LOG_ENABLED(INFO)) {
      LLOG(INFO, this) << "Thread #" << n << " joined";
    }
    ++n;
  }
#endif // NOTHREADS
}

void ListenHandler::graceful_shutdown_worker()
{
  if(get_config()->num_worker == 1) {
    return;
  }

  for(auto& worker : workers_) {
    WorkerEvent wev;
    memset(&wev, 0, sizeof(wev));
    wev.type = GRACEFUL_SHUTDOWN;

    if(LOG_ENABLED(INFO)) {
      LLOG(INFO, this) << "Sending graceful shutdown signal to worker";
    }

    auto output = bufferevent_get_output(worker->bev);

    if(evbuffer_add(output, &wev, sizeof(wev)) != 0) {
      LLOG(FATAL, this) << "evbuffer_add() failed";
    }
  }
}

int ListenHandler::accept_connection(evutil_socket_t fd,
                                     sockaddr *addr, int addrlen)
{
  if(LOG_ENABLED(INFO)) {
    LLOG(INFO, this) << "Accepted connection. fd=" << fd;
  }

  evutil_make_socket_closeonexec(fd);

  if(get_config()->num_worker == 1) {

    if(worker_stat_->num_connections >=
       get_config()->worker_frontend_connections) {

      if(LOG_ENABLED(INFO)) {
        TLOG(INFO, this) << "Too many connections >="
                         << get_config()->worker_frontend_connections;
      }

      close(fd);
      return -1;
    }

    auto client = ssl::accept_connection(evbase_, rate_limit_group_,
                                         sv_ssl_ctx_, fd, addr, addrlen,
                                         worker_stat_.get());
    if(!client) {
      LLOG(ERROR, this) << "ClientHandler creation failed";

      close(fd);
      return -1;
    }

    client->set_http2_session(http2session_.get());
    client->set_http1_connect_blocker(http1_connect_blocker_.get());

    return 0;
  }
  size_t idx = worker_round_robin_cnt_ % workers_.size();
  ++worker_round_robin_cnt_;
  WorkerEvent wev;
  memset(&wev, 0, sizeof(wev));
  wev.type = NEW_CONNECTION;
  wev.client_fd = fd;
  memcpy(&wev.client_addr, addr, addrlen);
  wev.client_addrlen = addrlen;
  auto output = bufferevent_get_output(workers_[idx]->bev);
  if(evbuffer_add(output, &wev, sizeof(wev)) != 0) {
    LLOG(FATAL, this) << "evbuffer_add() failed";
    close(fd);
    return -1;
  }

  return 0;
}

event_base* ListenHandler::get_evbase() const
{
  return evbase_;
}

int ListenHandler::create_http2_session()
{
  int rv;
  http2session_ = util::make_unique<Http2Session>(evbase_, cl_ssl_ctx_);
  rv = http2session_->init_notification();
  return rv;
}

int ListenHandler::create_http1_connect_blocker()
{
  int rv;
  http1_connect_blocker_ = util::make_unique<ConnectBlocker>();

  rv = http1_connect_blocker_->init(evbase_);

  if(rv != 0) {
    return -1;
  }

  return 0;
}

const WorkerStat* ListenHandler::get_worker_stat() const
{
  return worker_stat_.get();
}

void ListenHandler::set_evlistener4(evconnlistener *evlistener4)
{
  evlistener4_ = evlistener4;
}

evconnlistener* ListenHandler::get_evlistener4() const
{
  return evlistener4_;
}

void ListenHandler::set_evlistener6(evconnlistener *evlistener6)
{
  evlistener6_ = evlistener6;
}

evconnlistener* ListenHandler::get_evlistener6() const
{
  return evlistener6_;
}

void ListenHandler::enable_evlistener()
{
  if(evlistener4_) {
    evconnlistener_enable(evlistener4_);
  }

  if(evlistener6_) {
    evconnlistener_enable(evlistener6_);
  }
}

void ListenHandler::disable_evlistener()
{
  if(evlistener4_) {
    evconnlistener_disable(evlistener4_);
  }

  if(evlistener6_) {
    evconnlistener_disable(evlistener6_);
  }
}

void ListenHandler::disable_evlistener_temporary(const timeval *timeout)
{
  int rv;

  if(timeout->tv_sec == 0 ||
     evtimer_pending(evlistener_disable_timerev_, nullptr)) {
    return;
  }

  disable_evlistener();

  rv = evtimer_add(evlistener_disable_timerev_, timeout);

  if(rv < 0) {
    LOG(ERROR) << "evtimer_add for evlistener_disable_timerev_ failed";
  }
}

namespace {
void perform_accept_pending_connection(ListenHandler *listener_handler,
                                       evconnlistener *listener)
{
  if(!listener) {
    return;
  }

  auto server_fd = evconnlistener_get_fd(listener);

  for(;;) {
    sockaddr_union sockaddr;
    socklen_t addrlen = sizeof(sockaddr);

    auto fd = accept(server_fd, &sockaddr.sa, &addrlen);

    if(fd == -1) {
      if(errno == EINTR ||
         errno == ENETDOWN ||
         errno == EPROTO ||
         errno == ENOPROTOOPT ||
         errno == EHOSTDOWN ||
#ifdef ENONET
         errno == ENONET ||
#endif // ENONET
         errno == EHOSTUNREACH ||
         errno == EOPNOTSUPP ||
         errno == ENETUNREACH) {
        continue;
      }

      return;
    }

    evutil_make_socket_nonblocking(fd);

    listener_handler->accept_connection(fd, &sockaddr.sa, addrlen);
  }
}
} // namespace

void ListenHandler::accept_pending_connection()
{
  perform_accept_pending_connection(this, evlistener4_);
  perform_accept_pending_connection(this, evlistener6_);
}

void ListenHandler::notify_worker_shutdown()
{
  if(++num_worker_shutdown_ == workers_.size()) {
    event_base_loopbreak(evbase_);
  }
}

} // namespace shrpx
