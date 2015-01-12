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
#include "shrpx_connection_handler.h"

#include <unistd.h>

#include <cerrno>
#include <thread>

#include "shrpx_client_handler.h"
#include "shrpx_ssl.h"
#include "shrpx_worker.h"
#include "shrpx_worker_config.h"
#include "shrpx_config.h"
#include "shrpx_http2_session.h"
#include "shrpx_connect_blocker.h"
#include "shrpx_downstream_connection.h"
#include "shrpx_accept_handler.h"
#include "util.h"

using namespace nghttp2;

namespace shrpx {

namespace {
void acceptor_disable_cb(struct ev_loop *loop, ev_timer *w, int revent) {
  auto h = static_cast<ConnectionHandler *>(w->data);

  // If we are in graceful shutdown period, we must not enable
  // acceptors again.
  if (worker_config->graceful_shutdown) {
    return;
  }

  h->enable_acceptor();
}
} // namespace

ConnectionHandler::ConnectionHandler(struct ev_loop *loop)
    : loop_(loop), sv_ssl_ctx_(nullptr), cl_ssl_ctx_(nullptr),
      // rate_limit_group_(bufferevent_rate_limit_group_new(
      //     evbase, get_config()->worker_rate_limit_cfg)),
      worker_stat_(util::make_unique<WorkerStat>()),
      worker_round_robin_cnt_(0) {
  ev_timer_init(&disable_acceptor_timer_, acceptor_disable_cb, 0., 0.);
  disable_acceptor_timer_.data = this;
}

ConnectionHandler::~ConnectionHandler() {
  //  bufferevent_rate_limit_group_free(rate_limit_group_);
  ev_timer_stop(loop_, &disable_acceptor_timer_);
}

void ConnectionHandler::create_ssl_context() {
  sv_ssl_ctx_ = ssl::setup_server_ssl_context();
  cl_ssl_ctx_ = ssl::setup_client_ssl_context();
}

void ConnectionHandler::worker_reopen_log_files() {
  WorkerEvent wev;

  memset(&wev, 0, sizeof(wev));
  wev.type = REOPEN_LOG;

  for (auto &worker : workers_) {
    worker->send(wev);
  }
}

void ConnectionHandler::worker_renew_ticket_keys(
    const std::shared_ptr<TicketKeys> &ticket_keys) {
  WorkerEvent wev;

  memset(&wev, 0, sizeof(wev));
  wev.type = RENEW_TICKET_KEYS;
  wev.ticket_keys = ticket_keys;

  for (auto &worker : workers_) {
    worker->send(wev);
  }
}

void ConnectionHandler::create_worker_thread(size_t num) {
#ifndef NOTHREADS
  assert(workers_.size() == 0);

  for (size_t i = 0; i < num; ++i) {
    workers_.push_back(util::make_unique<Worker>(sv_ssl_ctx_, cl_ssl_ctx_,
                                                 worker_config->cert_tree,
                                                 worker_config->ticket_keys));

    if (LOG_ENABLED(INFO)) {
      LLOG(INFO, this) << "Created thread #" << workers_.size() - 1;
    }
  }
#endif // NOTHREADS
}

void ConnectionHandler::join_worker() {
#ifndef NOTHREADS
  int n = 0;

  if (LOG_ENABLED(INFO)) {
    LLOG(INFO, this) << "Waiting for worker thread to join: n="
                     << workers_.size();
  }

  for (auto &worker : workers_) {
    worker->wait();
    if (LOG_ENABLED(INFO)) {
      LLOG(INFO, this) << "Thread #" << n << " joined";
    }
    ++n;
  }
#endif // NOTHREADS
}

void ConnectionHandler::graceful_shutdown_worker() {
  if (get_config()->num_worker == 1) {
    return;
  }

  WorkerEvent wev;
  memset(&wev, 0, sizeof(wev));
  wev.type = GRACEFUL_SHUTDOWN;

  if (LOG_ENABLED(INFO)) {
    LLOG(INFO, this) << "Sending graceful shutdown signal to worker";
  }

  for (auto &worker : workers_) {

    worker->send(wev);
  }
}

int ConnectionHandler::handle_connection(int fd, sockaddr *addr, int addrlen) {
  if (LOG_ENABLED(INFO)) {
    LLOG(INFO, this) << "Accepted connection. fd=" << fd;
  }

  if (get_config()->num_worker == 1) {

    if (worker_stat_->num_connections >=
        get_config()->worker_frontend_connections) {

      if (LOG_ENABLED(INFO)) {
        LLOG(INFO, this) << "Too many connections >="
                         << get_config()->worker_frontend_connections;
      }

      close(fd);
      return -1;
    }

    auto client = ssl::accept_connection(loop_, sv_ssl_ctx_, fd, addr, addrlen,
                                         worker_stat_.get(), &dconn_pool_);
    if (!client) {
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

  workers_[idx]->send(wev);

  return 0;
}

struct ev_loop *ConnectionHandler::get_loop() const {
  return loop_;
}

void ConnectionHandler::create_http2_session() {
  http2session_ = util::make_unique<Http2Session>(loop_, cl_ssl_ctx_);
}

void ConnectionHandler::create_http1_connect_blocker() {
  http1_connect_blocker_ = util::make_unique<ConnectBlocker>(loop_);
}

const WorkerStat *ConnectionHandler::get_worker_stat() const {
  return worker_stat_.get();
}

void ConnectionHandler::set_acceptor4(std::unique_ptr<AcceptHandler> h) {
  acceptor4_ = std::move(h);
}

AcceptHandler *ConnectionHandler::get_acceptor4() const {
  return acceptor4_.get();
}

void ConnectionHandler::set_acceptor6(std::unique_ptr<AcceptHandler> h) {
  acceptor6_ = std::move(h);
}

AcceptHandler *ConnectionHandler::get_acceptor6() const {
  return acceptor6_.get();
}

void ConnectionHandler::enable_acceptor() {
  if (acceptor4_) {
    acceptor4_->enable();
  }

  if (acceptor6_) {
    acceptor6_->enable();
  }
}

void ConnectionHandler::disable_acceptor() {
  if (acceptor4_) {
    acceptor4_->disable();
  }

  if (acceptor6_) {
    acceptor6_->disable();
  }
}

void ConnectionHandler::disable_acceptor_temporary(ev_tstamp t) {
  if (t == 0. || ev_is_active(&disable_acceptor_timer_)) {
    return;
  }

  disable_acceptor();

  ev_timer_set(&disable_acceptor_timer_, t, 0.);
  ev_timer_start(loop_, &disable_acceptor_timer_);
}

void ConnectionHandler::accept_pending_connection() {
  if (acceptor4_) {
    acceptor4_->accept_connection();
  }
  if (acceptor6_) {
    acceptor6_->accept_connection();
  }
}

} // namespace shrpx
