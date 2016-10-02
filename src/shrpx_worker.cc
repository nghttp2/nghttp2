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
void proc_wev_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto worker = static_cast<Worker *>(w->data);
  worker->process_events();
}
} // namespace

namespace {
bool match_shared_downstream_addr(
    const std::shared_ptr<SharedDownstreamAddr> &lhs,
    const std::shared_ptr<SharedDownstreamAddr> &rhs) {
  if (lhs->addrs.size() != rhs->addrs.size()) {
    return false;
  }

  if (lhs->affinity != rhs->affinity) {
    return false;
  }

  auto used = std::vector<bool>(lhs->addrs.size());

  for (auto &a : lhs->addrs) {
    size_t i;
    for (i = 0; i < rhs->addrs.size(); ++i) {
      if (used[i]) {
        continue;
      }

      auto &b = rhs->addrs[i];
      if (a.host == b.host && a.port == b.port && a.host_unix == b.host_unix &&
          a.proto == b.proto && a.tls == b.tls && a.sni == b.sni &&
          a.fall == b.fall && a.rise == b.rise) {
        break;
      }
    }

    if (i == rhs->addrs.size()) {
      return false;
    }

    used[i] = true;
  }

  return true;
}
} // namespace

namespace {
std::random_device rd;
} // namespace

Worker::Worker(struct ev_loop *loop, SSL_CTX *sv_ssl_ctx, SSL_CTX *cl_ssl_ctx,
               SSL_CTX *tls_session_cache_memcached_ssl_ctx,
               ssl::CertLookupTree *cert_tree,
               const std::shared_ptr<TicketKeys> &ticket_keys,
               ConnectionHandler *conn_handler,
               std::shared_ptr<DownstreamConfig> downstreamconf)
    : randgen_(rd()),
      worker_stat_{},
      loop_(loop),
      sv_ssl_ctx_(sv_ssl_ctx),
      cl_ssl_ctx_(cl_ssl_ctx),
      cert_tree_(cert_tree),
      conn_handler_(conn_handler),
      ticket_keys_(ticket_keys),
      connect_blocker_(
          make_unique<ConnectBlocker>(randgen_, loop_, []() {}, []() {})),
      graceful_shutdown_(false) {
  ev_async_init(&w_, eventcb);
  w_.data = this;
  ev_async_start(loop_, &w_);

  ev_timer_init(&mcpool_clear_timer_, mcpool_clear_cb, 0., 0.);
  mcpool_clear_timer_.data = this;

  ev_timer_init(&proc_wev_timer_, proc_wev_cb, 0., 0.);
  proc_wev_timer_.data = this;

  auto &session_cacheconf = get_config()->tls.session_cache;

  if (!session_cacheconf.memcached.host.empty()) {
    session_cache_memcached_dispatcher_ = make_unique<MemcachedDispatcher>(
        &session_cacheconf.memcached.addr, loop,
        tls_session_cache_memcached_ssl_ctx,
        StringRef{session_cacheconf.memcached.host}, &mcpool_, randgen_);
  }

  replace_downstream_config(std::move(downstreamconf));
}

void Worker::replace_downstream_config(
    std::shared_ptr<DownstreamConfig> downstreamconf) {
  for (auto &g : downstream_addr_groups_) {
    g->retired = true;

    auto &shared_addr = g->shared_addr;

    if (shared_addr->affinity == AFFINITY_NONE) {
      shared_addr->dconn_pool.remove_all();
      continue;
    }

    for (auto &addr : shared_addr->addrs) {
      addr.dconn_pool->remove_all();
    }
  }

  downstreamconf_ = downstreamconf;

  // Making a copy is much faster with multiple thread on
  // backendconfig API call.
  auto groups = downstreamconf->addr_groups;

  downstream_addr_groups_ =
      std::vector<std::shared_ptr<DownstreamAddrGroup>>(groups.size());

  for (size_t i = 0; i < groups.size(); ++i) {
    auto &src = groups[i];
    auto &dst = downstream_addr_groups_[i];

    dst = std::make_shared<DownstreamAddrGroup>();
    dst->pattern =
        ImmutableString{std::begin(src.pattern), std::end(src.pattern)};

    auto shared_addr = std::make_shared<SharedDownstreamAddr>();

    shared_addr->addrs.resize(src.addrs.size());
    shared_addr->affinity = src.affinity;
    shared_addr->affinity_hash = src.affinity_hash;

    size_t num_http1 = 0;
    size_t num_http2 = 0;

    for (size_t j = 0; j < src.addrs.size(); ++j) {
      auto &src_addr = src.addrs[j];
      auto &dst_addr = shared_addr->addrs[j];

      dst_addr.addr = src_addr.addr;
      dst_addr.host = make_string_ref(shared_addr->balloc, src_addr.host);
      dst_addr.hostport =
          make_string_ref(shared_addr->balloc, src_addr.hostport);
      dst_addr.port = src_addr.port;
      dst_addr.host_unix = src_addr.host_unix;
      dst_addr.proto = src_addr.proto;
      dst_addr.tls = src_addr.tls;
      dst_addr.sni = make_string_ref(shared_addr->balloc, src_addr.sni);
      dst_addr.fall = src_addr.fall;
      dst_addr.rise = src_addr.rise;

      auto shared_addr_ptr = shared_addr.get();

      dst_addr.connect_blocker =
          make_unique<ConnectBlocker>(randgen_, loop_,
                                      [shared_addr_ptr, &dst_addr]() {
                                        switch (dst_addr.proto) {
                                        case PROTO_HTTP1:
                                          --shared_addr_ptr->http1_pri.weight;
                                          break;
                                        case PROTO_HTTP2:
                                          --shared_addr_ptr->http2_pri.weight;
                                          break;
                                        default:
                                          assert(0);
                                        }
                                      },
                                      [shared_addr_ptr, &dst_addr]() {
                                        switch (dst_addr.proto) {
                                        case PROTO_HTTP1:
                                          ++shared_addr_ptr->http1_pri.weight;
                                          break;
                                        case PROTO_HTTP2:
                                          ++shared_addr_ptr->http2_pri.weight;
                                          break;
                                        default:
                                          assert(0);
                                        }
                                      });

      dst_addr.live_check =
          make_unique<LiveCheck>(loop_, cl_ssl_ctx_, this, &dst_addr, randgen_);

      if (dst_addr.proto == PROTO_HTTP2) {
        ++num_http2;
      } else {
        assert(dst_addr.proto == PROTO_HTTP1);
        ++num_http1;
      }
    }

    // share the connection if patterns have the same set of backend
    // addresses.
    auto end = std::begin(downstream_addr_groups_) + i;
    auto it = std::find_if(
        std::begin(downstream_addr_groups_), end,
        [&shared_addr](const std::shared_ptr<DownstreamAddrGroup> &group) {
          return match_shared_downstream_addr(group->shared_addr, shared_addr);
        });

    if (it == end) {
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "number of http/1.1 backend: " << num_http1
                  << ", number of h2 backend: " << num_http2;
      }

      shared_addr->http1_pri.weight = num_http1;
      shared_addr->http2_pri.weight = num_http2;

      if (shared_addr->affinity != AFFINITY_NONE) {
        for (auto &addr : shared_addr->addrs) {
          addr.dconn_pool = make_unique<DownstreamConnectionPool>();
        }
      }

      dst->shared_addr = shared_addr;
    } else {
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << dst->pattern << " shares the same backend group with "
                  << (*it)->pattern;
      }
      dst->shared_addr = (*it)->shared_addr;
    }
  }
}

Worker::~Worker() {
  ev_async_stop(loop_, &w_);
  ev_timer_stop(loop_, &mcpool_clear_timer_);
  ev_timer_stop(loop_, &proc_wev_timer_);
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
  WorkerEvent wev;
  {
    std::lock_guard<std::mutex> g(m_);

    // Process event one at a time.  This is important for
    // NEW_CONNECTION event since accepting large number of new
    // connections at once may delay time to 1st byte for existing
    // connections.

    if (q_.empty()) {
      ev_timer_stop(loop_, &proc_wev_timer_);
      return;
    }

    wev = q_.front();
    q_.pop_front();
  }

  ev_timer_start(loop_, &proc_wev_timer_);

  auto worker_connections = get_config()->conn.upstream.worker_connections;

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
    WLOG(NOTICE, this) << "Reopening log files: worker process (thread " << this
                       << ")";

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
  case REPLACE_DOWNSTREAM:
    WLOG(NOTICE, this) << "Replace downstream";

    replace_downstream_config(wev.downstreamconf);

    break;
  default:
    if (LOG_ENABLED(INFO)) {
      WLOG(INFO, this) << "unknown event type " << wev.type;
    }
  }
}

ssl::CertLookupTree *Worker::get_cert_lookup_tree() const { return cert_tree_; }

std::shared_ptr<TicketKeys> Worker::get_ticket_keys() {
#ifdef HAVE_ATOMIC_STD_SHARED_PTR
  return std::atomic_load_explicit(&ticket_keys_, std::memory_order_acquire);
#else  // !HAVE_ATOMIC_STD_SHARED_PTR
  std::lock_guard<std::mutex> g(ticket_keys_m_);
  return ticket_keys_;
#endif // !HAVE_ATOMIC_STD_SHARED_PTR
}

void Worker::set_ticket_keys(std::shared_ptr<TicketKeys> ticket_keys) {
#ifdef HAVE_ATOMIC_STD_SHARED_PTR
  // This is single writer
  std::atomic_store_explicit(&ticket_keys_, std::move(ticket_keys),
                             std::memory_order_release);
#else  // !HAVE_ATOMIC_STD_SHARED_PTR
  std::lock_guard<std::mutex> g(ticket_keys_m_);
  ticket_keys_ = std::move(ticket_keys);
#endif // !HAVE_ATOMIC_STD_SHARED_PTR
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

std::vector<std::shared_ptr<DownstreamAddrGroup>> &
Worker::get_downstream_addr_groups() {
  return downstream_addr_groups_;
}

ConnectBlocker *Worker::get_connect_blocker() const {
  return connect_blocker_.get();
}

const DownstreamConfig *Worker::get_downstream_config() const {
  return downstreamconf_.get();
}

ConnectionHandler *Worker::get_connection_handler() const {
  return conn_handler_;
}

namespace {
size_t match_downstream_addr_group_host(
    const RouterConfig &routerconf, const StringRef &host,
    const StringRef &path,
    const std::vector<std::shared_ptr<DownstreamAddrGroup>> &groups,
    size_t catch_all, BlockAllocator &balloc) {

  const auto &router = routerconf.router;
  const auto &rev_wildcard_router = routerconf.rev_wildcard_router;
  const auto &wildcard_patterns = routerconf.wildcard_patterns;

  if (path.empty() || path[0] != '/') {
    auto group = router.match(host, StringRef::from_lit("/"));
    if (group != -1) {
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "Found pattern with query " << host
                  << ", matched pattern=" << groups[group]->pattern;
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
                << ", matched pattern=" << groups[group]->pattern;
    }
    return group;
  }

  if (!wildcard_patterns.empty() && !host.empty()) {
    auto rev_host_src = make_byte_ref(balloc, host.size() - 1);
    auto ep =
        std::copy(std::begin(host) + 1, std::end(host), rev_host_src.base);
    std::reverse(rev_host_src.base, ep);
    auto rev_host = StringRef{rev_host_src.base, ep};

    ssize_t best_group = -1;
    const RNode *last_node = nullptr;

    for (;;) {
      size_t nread = 0;
      auto wcidx =
          rev_wildcard_router.match_prefix(&nread, &last_node, rev_host);
      if (wcidx == -1) {
        break;
      }

      rev_host = StringRef{std::begin(rev_host) + nread, std::end(rev_host)};

      auto &wc = wildcard_patterns[wcidx];
      auto group = wc.router.match(StringRef{}, path);
      if (group != -1) {
        // We sorted wildcard_patterns in a way that first match is the
        // longest host pattern.
        if (LOG_ENABLED(INFO)) {
          LOG(INFO) << "Found wildcard pattern with query " << host << path
                    << ", matched pattern=" << groups[group]->pattern;
        }

        best_group = group;
      }
    }

    if (best_group != -1) {
      return best_group;
    }
  }

  group = router.match(StringRef::from_lit(""), path);
  if (group != -1) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Found pattern with query " << path
                << ", matched pattern=" << groups[group]->pattern;
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
    const RouterConfig &routerconf, const StringRef &hostport,
    const StringRef &raw_path,
    const std::vector<std::shared_ptr<DownstreamAddrGroup>> &groups,
    size_t catch_all, BlockAllocator &balloc) {
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
    return match_downstream_addr_group_host(routerconf, hostport, path, groups,
                                            catch_all, balloc);
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

  if (std::find_if(std::begin(host), std::end(host), [](char c) {
        return 'A' <= c || c <= 'Z';
      }) != std::end(host)) {
    auto low_host = make_byte_ref(balloc, host.size() + 1);
    auto ep = std::copy(std::begin(host), std::end(host), low_host.base);
    *ep = '\0';
    util::inp_strlower(low_host.base, ep);
    host = StringRef{low_host.base, ep};
  }
  return match_downstream_addr_group_host(routerconf, host, path, groups,
                                          catch_all, balloc);
}

void downstream_failure(DownstreamAddr *addr) {
  const auto &connect_blocker = addr->connect_blocker;

  if (connect_blocker->in_offline()) {
    return;
  }

  connect_blocker->on_failure();

  if (addr->fall == 0) {
    return;
  }

  auto fail_count = connect_blocker->get_fail_count();

  if (fail_count >= addr->fall) {
    LOG(WARN) << "Could not connect to " << util::to_numeric_addr(&addr->addr)
              << " " << fail_count << " times in a row; considered as offline";

    connect_blocker->offline();

    if (addr->rise) {
      addr->live_check->schedule();
    }
  }
}

} // namespace shrpx
