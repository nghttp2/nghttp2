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
#include "shrpx_worker.h"

#include <unistd.h>

#include <memory>

#include "shrpx_ssl.h"
#include "shrpx_log.h"
#include "shrpx_client_handler.h"
#include "shrpx_http2_session.h"
#include "shrpx_worker_config.h"
#include "shrpx_connect_blocker.h"
#include "util.h"
#include "template.h"

using namespace nghttp2;

namespace shrpx {

namespace {
void eventcb(struct ev_loop *loop, ev_async *w, int revents) {
  auto worker = static_cast<Worker *>(w->data);
  worker->process_events();
}
} // namespace

Worker::Worker(SSL_CTX *sv_ssl_ctx, SSL_CTX *cl_ssl_ctx,
               ssl::CertLookupTree *cert_tree,
               const std::shared_ptr<TicketKeys> &ticket_keys)
    : loop_(ev_loop_new(0)), sv_ssl_ctx_(sv_ssl_ctx), cl_ssl_ctx_(cl_ssl_ctx),
      worker_stat_(make_unique<WorkerStat>()) {
  ev_async_init(&w_, eventcb);
  w_.data = this;
  ev_async_start(loop_, &w_);

#ifndef NOTHREADS
  fut_ = std::async(std::launch::async, [this, cert_tree, &ticket_keys] {
    if (get_config()->tls_ctx_per_worker) {
      sv_ssl_ctx_ = ssl::setup_server_ssl_context();
      cl_ssl_ctx_ = ssl::setup_client_ssl_context();
    } else {
      worker_config->cert_tree = cert_tree;
    }

    if (get_config()->downstream_proto == PROTO_HTTP2) {
      http2session_ = make_unique<Http2Session>(loop_, cl_ssl_ctx_);
    } else {
      http1_connect_blocker_ = make_unique<ConnectBlocker>(loop_);
    }

    worker_config->ticket_keys = ticket_keys;
    (void)reopen_log_files();
    ev_run(loop_);
  });
#endif // !NOTHREADS
}

Worker::~Worker() { ev_async_stop(loop_, &w_); }

void Worker::wait() {
#ifndef NOTHREADS
  fut_.get();
#endif // !NOTHREADS
}

void Worker::send(const WorkerEvent &event) {
  {
    std::lock_guard<std::mutex> g(m_);

    q_.push_back(event);
  }

  ev_async_send(loop_, &w_);
}

void Worker::process_events() {
  std::deque<WorkerEvent> q;
  {
    std::lock_guard<std::mutex> g(m_);
    q.swap(q_);
  }
  for (auto &wev : q) {
    switch (wev.type) {
    case NEW_CONNECTION: {
      if (LOG_ENABLED(INFO)) {
        WLOG(INFO, this) << "WorkerEvent: client_fd=" << wev.client_fd
                         << ", addrlen=" << wev.client_addrlen;
      }

      if (worker_stat_->num_connections >=
          get_config()->worker_frontend_connections) {

        if (LOG_ENABLED(INFO)) {
          WLOG(INFO, this) << "Too many connections >= "
                           << get_config()->worker_frontend_connections;
        }

        close(wev.client_fd);

        break;
      }

      auto client_handler = ssl::accept_connection(
          loop_, sv_ssl_ctx_, wev.client_fd, &wev.client_addr.sa,
          wev.client_addrlen, worker_stat_.get(), &dconn_pool_);
      if (!client_handler) {
        if (LOG_ENABLED(INFO)) {
          WLOG(ERROR, this) << "ClientHandler creation failed";
        }
        close(wev.client_fd);
        break;
      }

      client_handler->set_http2_session(http2session_.get());
      client_handler->set_http1_connect_blocker(http1_connect_blocker_.get());

      if (LOG_ENABLED(INFO)) {
        WLOG(INFO, this) << "CLIENT_HANDLER:" << client_handler << " created ";
      }

      break;
    }
    case RENEW_TICKET_KEYS:
      if (LOG_ENABLED(INFO)) {
        WLOG(INFO, this) << "Renew ticket keys: worker_info(" << worker_config
                         << ")";
      }

      worker_config->ticket_keys = wev.ticket_keys;

      break;
    case REOPEN_LOG:
      if (LOG_ENABLED(INFO)) {
        WLOG(INFO, this) << "Reopening log files: worker_info(" << worker_config
                         << ")";
      }

      reopen_log_files();

      break;
    case GRACEFUL_SHUTDOWN:
      WLOG(NOTICE, this) << "Graceful shutdown commencing";

      worker_config->graceful_shutdown = true;

      if (worker_stat_->num_connections == 0) {
        ev_break(loop_);

        return;
      }

      break;
    default:
      if (LOG_ENABLED(INFO)) {
        WLOG(INFO, this) << "unknown event type " << wev.type;
      }
    }
  }
}

} // namespace shrpx
