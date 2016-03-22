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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif // HAVE_UNISTD_H

#include <memory>

#include "shrpx_ssl.h"
#include "shrpx_log.h"
#include "shrpx_client_handler.h"
#include "shrpx_http2_session.h"
#include "shrpx_log_config.h"
#include "shrpx_connect_blocker.h"
#include "shrpx_memcached_dispatcher.h"
#ifdef HAVE_MRUBY
#include "shrpx_mruby.h"
#endif // HAVE_MRUBY
#include "util.h"
#include "template.h"

namespace shrpx {

namespace {
void eventcb(struct ev_loop *loop, ev_async *w, int revents) {
  auto worker = static_cast<Worker *>(w->data);
  worker->process_events();
}
} // namespace

namespace {
void mcpool_clear_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto worker = static_cast<Worker *>(w->data);
  if (worker->get_worker_stat()->num_connections != 0) {
    return;
  }
  worker->get_mcpool()->clear();
}
} // namespace

namespace {
std::random_device rd;
} // namespace

Worker::Worker(struct ev_loop *loop, SSL_CTX *sv_ssl_ctx, SSL_CTX *cl_ssl_ctx,
               SSL_CTX *tls_session_cache_memcached_ssl_ctx,
               ssl::CertLookupTree *cert_tree,
               const std::shared_ptr<TicketKeys> &ticket_keys)
    : randgen_(rd()),
      worker_stat_{},
      loop_(loop),
      sv_ssl_ctx_(sv_ssl_ctx),
      cl_ssl_ctx_(cl_ssl_ctx),
      cert_tree_(cert_tree),
      ticket_keys_(ticket_keys),
      downstream_addr_groups_(get_config()->conn.downstream.addr_groups.size()),
      connect_blocker_(make_unique<ConnectBlocker>(randgen_, loop_)),
      graceful_shutdown_(false) {
  ev_async_init(&w_, eventcb);
  w_.data = this;
  ev_async_start(loop_, &w_);

  ev_timer_init(&mcpool_clear_timer_, mcpool_clear_cb, 0., 0.);
  mcpool_clear_timer_.data = this;

  auto &session_cacheconf = get_config()->tls.session_cache;

  if (!session_cacheconf.memcached.host.empty()) {
    session_cache_memcached_dispatcher_ = make_unique<MemcachedDispatcher>(
        &session_cacheconf.memcached.addr, loop,
        tls_session_cache_memcached_ssl_ctx,
        StringRef{session_cacheconf.memcached.host}, &mcpool_);
  }

  auto &downstreamconf = get_config()->conn.downstream;

  for (size_t i = 0; i < downstreamconf.addr_groups.size(); ++i) {
    auto &src = downstreamconf.addr_groups[i];
    auto &dst = downstream_addr_groups_[i];

    dst.pattern = src.pattern;
    dst.addrs.resize(src.addrs.size());
    dst.proto = src.proto;

    for (size_t j = 0; j < src.addrs.size(); ++j) {
      auto &src_addr = src.addrs[j];
      auto &dst_addr = dst.addrs[j];

      dst_addr.addr = src_addr.addr;
      dst_addr.host = src_addr.host;
      dst_addr.hostport = src_addr.hostport;
      dst_addr.port = src_addr.port;
      dst_addr.host_unix = src_addr.host_unix;

      dst_addr.connect_blocker = make_unique<ConnectBlocker>(randgen_, loop_);
    }
  }
}

Worker::~Worker() {
  ev_async_stop(loop_, &w_);
  ev_timer_stop(loop_, &mcpool_clear_timer_);
}

void Worker::schedule_clear_mcpool() {
  // libev manual says: "If the watcher is already active nothing will
  // happen."  Since we don't change any timeout here, we don't have
  // to worry about querying ev_is_active.
  ev_timer_start(loop_, &mcpool_clear_timer_);
}

void Worker::wait() {
#ifndef NOTHREADS
  fut_.get();
#endif // !NOTHREADS
}

void Worker::run_async() {
#ifndef NOTHREADS
  fut_ = std::async(std::launch::async, [this] {
    (void)reopen_log_files();
    ev_run(loop_);
    delete log_config();
  });
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
  std::vector<WorkerEvent> q;
  {
    std::lock_guard<std::mutex> g(m_);
    q.swap(q_);
  }

  auto worker_connections = get_config()->conn.upstream.worker_connections;

  for (auto &wev : q) {
    switch (wev.type) {
    case NEW_CONNECTION: {
      if (LOG_ENABLED(INFO)) {
        WLOG(INFO, this) << "WorkerEvent: client_fd=" << wev.client_fd
                         << ", addrlen=" << wev.client_addrlen;
      }

      if (worker_stat_.num_connections >= worker_connections) {

        if (LOG_ENABLED(INFO)) {
          WLOG(INFO, this) << "Too many connections >= " << worker_connections;
        }

        close(wev.client_fd);

        break;
      }

      auto client_handler =
          ssl::accept_connection(this, wev.client_fd, &wev.client_addr.sa,
                                 wev.client_addrlen, wev.faddr);
      if (!client_handler) {
        if (LOG_ENABLED(INFO)) {
          WLOG(ERROR, this) << "ClientHandler creation failed";
        }
        close(wev.client_fd);
        break;
      }

      if (LOG_ENABLED(INFO)) {
        WLOG(INFO, this) << "CLIENT_HANDLER:" << client_handler << " created ";
      }

      break;
    }
    case REOPEN_LOG:
      WLOG(NOTICE, this) << "Reopening log files: worker process (thread "
                         << this << ")";

      reopen_log_files();

      break;
    case GRACEFUL_SHUTDOWN:
      WLOG(NOTICE, this) << "Graceful shutdown commencing";

      graceful_shutdown_ = true;

      if (worker_stat_.num_connections == 0) {
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

ssl::CertLookupTree *Worker::get_cert_lookup_tree() const { return cert_tree_; }

std::shared_ptr<TicketKeys> Worker::get_ticket_keys() {
  std::lock_guard<std::mutex> g(m_);
  return ticket_keys_;
}

void Worker::set_ticket_keys(std::shared_ptr<TicketKeys> ticket_keys) {
  std::lock_guard<std::mutex> g(m_);
  ticket_keys_ = std::move(ticket_keys);
}

WorkerStat *Worker::get_worker_stat() { return &worker_stat_; }

struct ev_loop *Worker::get_loop() const {
  return loop_;
}

SSL_CTX *Worker::get_sv_ssl_ctx() const { return sv_ssl_ctx_; }

SSL_CTX *Worker::get_cl_ssl_ctx() const { return cl_ssl_ctx_; }

void Worker::set_graceful_shutdown(bool f) { graceful_shutdown_ = f; }

bool Worker::get_graceful_shutdown() const { return graceful_shutdown_; }

MemchunkPool *Worker::get_mcpool() { return &mcpool_; }

MemcachedDispatcher *Worker::get_session_cache_memcached_dispatcher() {
  return session_cache_memcached_dispatcher_.get();
}

std::mt19937 &Worker::get_randgen() { return randgen_; }

#ifdef HAVE_MRUBY
int Worker::create_mruby_context() {
  mruby_ctx_ = mruby::create_mruby_context(StringRef{get_config()->mruby_file});
  if (!mruby_ctx_) {
    return -1;
  }

  return 0;
}

mruby::MRubyContext *Worker::get_mruby_context() const {
  return mruby_ctx_.get();
}
#endif // HAVE_MRUBY

std::vector<DownstreamAddrGroup> &Worker::get_downstream_addr_groups() {
  return downstream_addr_groups_;
}

ConnectBlocker *Worker::get_connect_blocker() const {
  return connect_blocker_.get();
}

namespace {
size_t match_downstream_addr_group_host(
    const Router &router, const std::vector<WildcardPattern> &wildcard_patterns,
    const StringRef &host, const StringRef &path,
    const std::vector<DownstreamAddrGroup> &groups, size_t catch_all) {
  if (path.empty() || path[0] != '/') {
    auto group = router.match(host, StringRef::from_lit("/"));
    if (group != -1) {
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "Found pattern with query " << host
                  << ", matched pattern=" << groups[group].pattern;
      }
      return group;
    }
    return catch_all;
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Perform mapping selection, using host=" << host
              << ", path=" << path;
  }

  auto group = router.match(host, path);
  if (group != -1) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Found pattern with query " << host << path
                << ", matched pattern=" << groups[group].pattern;
    }
    return group;
  }

  for (auto it = std::begin(wildcard_patterns);
       it != std::end(wildcard_patterns); ++it) {
    /* left most '*' must match at least one character */
    if (host.size() <= (*it).host.size() ||
        !util::ends_with(std::begin(host), std::end(host),
                         std::begin((*it).host), std::end((*it).host))) {
      continue;
    }
    auto group = (*it).router.match(StringRef{}, path);
    if (group != -1) {
      // We sorted wildcard_patterns in a way that first match is the
      // longest host pattern.
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "Found wildcard pattern with query " << host << path
                  << ", matched pattern=" << groups[group].pattern;
      }
      return group;
    }
  }

  group = router.match(StringRef::from_lit(""), path);
  if (group != -1) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Found pattern with query " << path
                << ", matched pattern=" << groups[group].pattern;
    }
    return group;
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "None match.  Use catch-all pattern";
  }
  return catch_all;
}
} // namespace

size_t match_downstream_addr_group(
    const Router &router, const std::vector<WildcardPattern> &wildcard_patterns,
    const StringRef &hostport, const StringRef &raw_path,
    const std::vector<DownstreamAddrGroup> &groups, size_t catch_all) {
  if (std::find(std::begin(hostport), std::end(hostport), '/') !=
      std::end(hostport)) {
    // We use '/' specially, and if '/' is included in host, it breaks
    // our code.  Select catch-all case.
    return catch_all;
  }

  auto fragment = std::find(std::begin(raw_path), std::end(raw_path), '#');
  auto query = std::find(std::begin(raw_path), fragment, '?');
  auto path = StringRef{std::begin(raw_path), query};

  if (hostport.empty()) {
    return match_downstream_addr_group_host(router, wildcard_patterns, hostport,
                                            path, groups, catch_all);
  }

  StringRef host;
  if (hostport[0] == '[') {
    // assume this is IPv6 numeric address
    auto p = std::find(std::begin(hostport), std::end(hostport), ']');
    if (p == std::end(hostport)) {
      return catch_all;
    }
    if (p + 1 < std::end(hostport) && *(p + 1) != ':') {
      return catch_all;
    }
    host = StringRef{std::begin(hostport), p + 1};
  } else {
    auto p = std::find(std::begin(hostport), std::end(hostport), ':');
    if (p == std::begin(hostport)) {
      return catch_all;
    }
    host = StringRef{std::begin(hostport), p};
  }

  std::string low_host;
  if (std::find_if(std::begin(host), std::end(host), [](char c) {
        return 'A' <= c || c <= 'Z';
      }) != std::end(host)) {
    low_host = host.str();
    util::inp_strlower(low_host);
    host = StringRef{low_host};
  }
  return match_downstream_addr_group_host(router, wildcard_patterns, host, path,
                                          groups, catch_all);
}

} // namespace shrpx
