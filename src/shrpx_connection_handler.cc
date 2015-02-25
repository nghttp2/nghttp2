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
#include "shrpx_config.h"
#include "shrpx_http2_session.h"
#include "shrpx_connect_blocker.h"
#include "shrpx_downstream_connection.h"
#include "shrpx_accept_handler.h"
#include "util.h"
#include "template.h"

using namespace nghttp2;

namespace shrpx {

namespace {
void acceptor_disable_cb(struct ev_loop *loop, ev_timer *w, int revent) {
  auto h = static_cast<ConnectionHandler *>(w->data);

  // If we are in graceful shutdown period, we must not enable
  // acceptors again.
  if (h->get_graceful_shutdown()) {
    return;
  }

  h->enable_acceptor();
}
} // namespace

ConnectionHandler::ConnectionHandler(struct ev_loop *loop)
    : single_worker_(nullptr), loop_(loop), worker_round_robin_cnt_(0),
      graceful_shutdown_(false) {
  ev_timer_init(&disable_acceptor_timer_, acceptor_disable_cb, 0., 0.);
  disable_acceptor_timer_.data = this;
}

ConnectionHandler::~ConnectionHandler() {
  ev_timer_stop(loop_, &disable_acceptor_timer_);
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

void ConnectionHandler::create_single_worker() {
  auto cert_tree = ssl::create_cert_lookup_tree();
  auto sv_ssl_ctx = ssl::setup_server_ssl_context(cert_tree);
  auto cl_ssl_ctx = ssl::setup_client_ssl_context();

  single_worker_ = make_unique<Worker>(loop_, sv_ssl_ctx, cl_ssl_ctx, cert_tree,
                                       ticket_keys_);
}

void ConnectionHandler::create_worker_thread(size_t num) {
#ifndef NOTHREADS
  assert(workers_.size() == 0);

  SSL_CTX *sv_ssl_ctx = nullptr, *cl_ssl_ctx = nullptr;
  ssl::CertLookupTree *cert_tree = nullptr;

  if (!get_config()->tls_ctx_per_worker) {
    cert_tree = ssl::create_cert_lookup_tree();
    sv_ssl_ctx = ssl::setup_server_ssl_context(cert_tree);
    cl_ssl_ctx = ssl::setup_client_ssl_context();
  }

  for (size_t i = 0; i < num; ++i) {
    auto loop = ev_loop_new(0);

    if (get_config()->tls_ctx_per_worker) {
      cert_tree = ssl::create_cert_lookup_tree();
      sv_ssl_ctx = ssl::setup_server_ssl_context(cert_tree);
      cl_ssl_ctx = ssl::setup_client_ssl_context();
    }

    auto worker = make_unique<Worker>(loop, sv_ssl_ctx, cl_ssl_ctx, cert_tree,
                                      ticket_keys_);
    worker->run_async();
    workers_.push_back(std::move(worker));

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

    if (single_worker_->get_worker_stat()->num_connections >=
        get_config()->worker_frontend_connections) {

      if (LOG_ENABLED(INFO)) {
        LLOG(INFO, this) << "Too many connections >="
                         << get_config()->worker_frontend_connections;
      }

      close(fd);
      return -1;
    }

    auto client =
        ssl::accept_connection(single_worker_.get(), fd, addr, addrlen);
    if (!client) {
      LLOG(ERROR, this) << "ClientHandler creation failed";

      close(fd);
      return -1;
    }

    return 0;
  }

  size_t idx = worker_round_robin_cnt_ % workers_.size();
  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Dispatch connection to worker #" << idx;
  }
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

Worker *ConnectionHandler::get_single_worker() const {
  return single_worker_.get();
}

void ConnectionHandler::set_acceptor(std::unique_ptr<AcceptHandler> h) {
  acceptor_ = std::move(h);
}

AcceptHandler *ConnectionHandler::get_acceptor() const {
  return acceptor_.get();
}

void ConnectionHandler::set_acceptor6(std::unique_ptr<AcceptHandler> h) {
  acceptor6_ = std::move(h);
}

AcceptHandler *ConnectionHandler::get_acceptor6() const {
  return acceptor6_.get();
}

void ConnectionHandler::enable_acceptor() {
  if (acceptor_) {
    acceptor_->enable();
  }

  if (acceptor6_) {
    acceptor6_->enable();
  }
}

void ConnectionHandler::disable_acceptor() {
  if (acceptor_) {
    acceptor_->disable();
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
  if (acceptor_) {
    acceptor_->accept_connection();
  }
  if (acceptor6_) {
    acceptor6_->accept_connection();
  }
}

void
ConnectionHandler::set_ticket_keys(std::shared_ptr<TicketKeys> ticket_keys) {
  ticket_keys_ = std::move(ticket_keys);
  if (single_worker_) {
    single_worker_->set_ticket_keys(ticket_keys_);
  }
}

const std::shared_ptr<TicketKeys> &ConnectionHandler::get_ticket_keys() const {
  return ticket_keys_;
}

void ConnectionHandler::set_graceful_shutdown(bool f) {
  graceful_shutdown_ = f;
  if (single_worker_) {
    single_worker_->set_graceful_shutdown(f);
  }
}

bool ConnectionHandler::get_graceful_shutdown() const {
  return graceful_shutdown_;
}

} // namespace shrpx
