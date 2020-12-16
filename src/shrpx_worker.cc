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
#  include <unistd.h>
#endif // HAVE_UNISTD_H

#include <memory>

#include "shrpx_tls.h"
#include "shrpx_log.h"
#include "shrpx_client_handler.h"
#include "shrpx_http2_session.h"
#include "shrpx_log_config.h"
#include "shrpx_memcached_dispatcher.h"
#ifdef HAVE_MRUBY
#  include "shrpx_mruby.h"
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
  auto mcpool = worker->get_mcpool();
  if (mcpool->freelistsize == mcpool->poolsize) {
    worker->get_mcpool()->clear();
  }
}
} // namespace

namespace {
void proc_wev_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto worker = static_cast<Worker *>(w->data);
  worker->process_events();
}
} // namespace

DownstreamAddrGroup::DownstreamAddrGroup() : retired{false} {}

DownstreamAddrGroup::~DownstreamAddrGroup() {}

// DownstreamKey is used to index SharedDownstreamAddr in order to
// find the same configuration.
using DownstreamKey =
    std::tuple<std::vector<std::tuple<StringRef, StringRef, StringRef, size_t,
                                      size_t, Proto, uint32_t, uint32_t,
                                      uint32_t, bool, bool, bool, bool>>,
               bool, SessionAffinity, StringRef, StringRef,
               SessionAffinityCookieSecure, int64_t, int64_t, StringRef>;

namespace {
DownstreamKey
create_downstream_key(const std::shared_ptr<SharedDownstreamAddr> &shared_addr,
                      const StringRef &mruby_file) {
  DownstreamKey dkey;

  auto &addrs = std::get<0>(dkey);
  addrs.resize(shared_addr->addrs.size());
  auto p = std::begin(addrs);
  for (auto &a : shared_addr->addrs) {
    std::get<0>(*p) = a.host;
    std::get<1>(*p) = a.sni;
    std::get<2>(*p) = a.group;
    std::get<3>(*p) = a.fall;
    std::get<4>(*p) = a.rise;
    std::get<5>(*p) = a.proto;
    std::get<6>(*p) = a.port;
    std::get<7>(*p) = a.weight;
    std::get<8>(*p) = a.group_weight;
    std::get<9>(*p) = a.host_unix;
    std::get<10>(*p) = a.tls;
    std::get<11>(*p) = a.dns;
    std::get<12>(*p) = a.upgrade_scheme;
    ++p;
  }
  std::sort(std::begin(addrs), std::end(addrs));

  std::get<1>(dkey) = shared_addr->redirect_if_not_tls;

  auto &affinity = shared_addr->affinity;
  std::get<2>(dkey) = affinity.type;
  std::get<3>(dkey) = affinity.cookie.name;
  std::get<4>(dkey) = affinity.cookie.path;
  std::get<5>(dkey) = affinity.cookie.secure;
  auto &timeout = shared_addr->timeout;
  std::get<6>(dkey) = timeout.read;
  std::get<7>(dkey) = timeout.write;
  std::get<8>(dkey) = mruby_file;

  return dkey;
}
} // namespace

Worker::Worker(struct ev_loop *loop, SSL_CTX *sv_ssl_ctx, SSL_CTX *cl_ssl_ctx,
               SSL_CTX *tls_session_cache_memcached_ssl_ctx,
               tls::CertLookupTree *cert_tree,
               const std::shared_ptr<TicketKeys> &ticket_keys,
               ConnectionHandler *conn_handler,
               std::shared_ptr<DownstreamConfig> downstreamconf)
    : randgen_(util::make_mt19937()),
      worker_stat_{},
      dns_tracker_(loop),
      loop_(loop),
      sv_ssl_ctx_(sv_ssl_ctx),
      cl_ssl_ctx_(cl_ssl_ctx),
      cert_tree_(cert_tree),
      conn_handler_(conn_handler),
      ticket_keys_(ticket_keys),
      connect_blocker_(
          std::make_unique<ConnectBlocker>(randgen_, loop_, nullptr, nullptr)),
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
    session_cache_memcached_dispatcher_ = std::make_unique<MemcachedDispatcher>(
        &session_cacheconf.memcached.addr, loop,
        tls_session_cache_memcached_ssl_ctx,
        StringRef{session_cacheconf.memcached.host}, &mcpool_, randgen_);
  }

  replace_downstream_config(std::move(downstreamconf));
}

namespace {
void ensure_enqueue_addr(
    std::priority_queue<WeightGroupEntry, std::vector<WeightGroupEntry>,
                        WeightGroupEntryGreater> &wgpq,
    WeightGroup *wg, DownstreamAddr *addr) {
  uint32_t cycle;
  if (!wg->pq.empty()) {
    auto &top = wg->pq.top();
    cycle = top.cycle;
  } else {
    cycle = 0;
  }

  addr->cycle = cycle;
  addr->pending_penalty = 0;
  wg->pq.push(DownstreamAddrEntry{addr, addr->seq, addr->cycle});
  addr->queued = true;

  if (!wg->queued) {
    if (!wgpq.empty()) {
      auto &top = wgpq.top();
      cycle = top.cycle;
    } else {
      cycle = 0;
    }

    wg->cycle = cycle;
    wg->pending_penalty = 0;
    wgpq.push(WeightGroupEntry{wg, wg->seq, wg->cycle});
    wg->queued = true;
  }
}
} // namespace

void Worker::replace_downstream_config(
    std::shared_ptr<DownstreamConfig> downstreamconf) {
  for (auto &g : downstream_addr_groups_) {
    g->retired = true;

    auto &shared_addr = g->shared_addr;
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

  std::map<DownstreamKey, size_t> addr_groups_indexer;
#ifdef HAVE_MRUBY
  // TODO It is a bit less efficient because
  // mruby::create_mruby_context returns std::unique_ptr and we cannot
  // use std::make_shared.
  std::map<StringRef, std::shared_ptr<mruby::MRubyContext>> shared_mruby_ctxs;
#endif // HAVE_MRUBY

  for (size_t i = 0; i < groups.size(); ++i) {
    auto &src = groups[i];
    auto &dst = downstream_addr_groups_[i];

    dst = std::make_shared<DownstreamAddrGroup>();
    dst->pattern =
        ImmutableString{std::begin(src.pattern), std::end(src.pattern)};

    auto shared_addr = std::make_shared<SharedDownstreamAddr>();

    shared_addr->addrs.resize(src.addrs.size());
    shared_addr->affinity.type = src.affinity.type;
    if (src.affinity.type == SessionAffinity::COOKIE) {
      shared_addr->affinity.cookie.name =
          make_string_ref(shared_addr->balloc, src.affinity.cookie.name);
      if (!src.affinity.cookie.path.empty()) {
        shared_addr->affinity.cookie.path =
            make_string_ref(shared_addr->balloc, src.affinity.cookie.path);
      }
      shared_addr->affinity.cookie.secure = src.affinity.cookie.secure;
    }
    shared_addr->affinity_hash = src.affinity_hash;
    shared_addr->redirect_if_not_tls = src.redirect_if_not_tls;
    shared_addr->timeout.read = src.timeout.read;
    shared_addr->timeout.write = src.timeout.write;

    for (size_t j = 0; j < src.addrs.size(); ++j) {
      auto &src_addr = src.addrs[j];
      auto &dst_addr = shared_addr->addrs[j];

      dst_addr.addr = src_addr.addr;
      dst_addr.host = make_string_ref(shared_addr->balloc, src_addr.host);
      dst_addr.hostport =
          make_string_ref(shared_addr->balloc, src_addr.hostport);
      dst_addr.port = src_addr.port;
      dst_addr.host_unix = src_addr.host_unix;
      dst_addr.weight = src_addr.weight;
      dst_addr.group = make_string_ref(shared_addr->balloc, src_addr.group);
      dst_addr.group_weight = src_addr.group_weight;
      dst_addr.proto = src_addr.proto;
      dst_addr.tls = src_addr.tls;
      dst_addr.sni = make_string_ref(shared_addr->balloc, src_addr.sni);
      dst_addr.fall = src_addr.fall;
      dst_addr.rise = src_addr.rise;
      dst_addr.dns = src_addr.dns;
      dst_addr.upgrade_scheme = src_addr.upgrade_scheme;

      auto shared_addr_ptr = shared_addr.get();

      dst_addr.connect_blocker = std::make_unique<ConnectBlocker>(
          randgen_, loop_, nullptr, [shared_addr_ptr, &dst_addr]() {
            if (!dst_addr.queued) {
              if (!dst_addr.wg) {
                return;
              }
              ensure_enqueue_addr(shared_addr_ptr->pq, dst_addr.wg, &dst_addr);
            }
          });

      dst_addr.live_check = std::make_unique<LiveCheck>(
          loop_, cl_ssl_ctx_, this, &dst_addr, randgen_);
    }

#ifdef HAVE_MRUBY
    auto mruby_ctx_it = shared_mruby_ctxs.find(src.mruby_file);
    if (mruby_ctx_it == std::end(shared_mruby_ctxs)) {
      shared_addr->mruby_ctx = mruby::create_mruby_context(src.mruby_file);
      assert(shared_addr->mruby_ctx);
      shared_mruby_ctxs.emplace(src.mruby_file, shared_addr->mruby_ctx);
    } else {
      shared_addr->mruby_ctx = (*mruby_ctx_it).second;
    }
#endif // HAVE_MRUBY

    // share the connection if patterns have the same set of backend
    // addresses.

    auto dkey = create_downstream_key(shared_addr, src.mruby_file);
    auto it = addr_groups_indexer.find(dkey);

    if (it == std::end(addr_groups_indexer)) {
      std::shuffle(std::begin(shared_addr->addrs), std::end(shared_addr->addrs),
                   randgen_);

      size_t seq = 0;
      for (auto &addr : shared_addr->addrs) {
        addr.dconn_pool = std::make_unique<DownstreamConnectionPool>();
        addr.seq = seq++;
      }

      if (shared_addr->affinity.type == SessionAffinity::NONE) {
        std::map<StringRef, WeightGroup *> wgs;
        size_t num_wgs = 0;
        for (auto &addr : shared_addr->addrs) {
          if (wgs.find(addr.group) == std::end(wgs)) {
            ++num_wgs;
            wgs.emplace(addr.group, nullptr);
          }
        }

        shared_addr->wgs = std::vector<WeightGroup>(num_wgs);

        for (auto &addr : shared_addr->addrs) {
          auto &wg = wgs[addr.group];
          if (wg == nullptr) {
            wg = &shared_addr->wgs[--num_wgs];
            wg->seq = num_wgs;
          }

          wg->weight = addr.group_weight;
          wg->pq.push(DownstreamAddrEntry{&addr, addr.seq, addr.cycle});
          addr.queued = true;
          addr.wg = wg;
        }

        assert(num_wgs == 0);

        for (auto &kv : wgs) {
          shared_addr->pq.push(
              WeightGroupEntry{kv.second, kv.second->seq, kv.second->cycle});
          kv.second->queued = true;
        }
      }

      dst->shared_addr = shared_addr;

      addr_groups_indexer.emplace(std::move(dkey), i);
    } else {
      auto &g = *(std::begin(downstream_addr_groups_) + (*it).second);
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << dst->pattern << " shares the same backend group with "
                  << g->pattern;
      }
      dst->shared_addr = g->shared_addr;
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
    (void)reopen_log_files(get_config()->logging);
    ev_run(loop_);
    delete_log_config();
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
    // WorkerEventType::NEW_CONNECTION event since accepting large
    // number of new connections at once may delay time to 1st byte
    // for existing connections.

    if (q_.empty()) {
      ev_timer_stop(loop_, &proc_wev_timer_);
      return;
    }

    wev = q_.front();
    q_.pop_front();
  }

  ev_timer_start(loop_, &proc_wev_timer_);

  auto config = get_config();

  auto worker_connections = config->conn.upstream.worker_connections;

  switch (wev.type) {
  case WorkerEventType::NEW_CONNECTION: {
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
        tls::accept_connection(this, wev.client_fd, &wev.client_addr.sa,
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
  case WorkerEventType::REOPEN_LOG:
    WLOG(NOTICE, this) << "Reopening log files: worker process (thread " << this
                       << ")";

    reopen_log_files(config->logging);

    break;
  case WorkerEventType::GRACEFUL_SHUTDOWN:
    WLOG(NOTICE, this) << "Graceful shutdown commencing";

    graceful_shutdown_ = true;

    if (worker_stat_.num_connections == 0) {
      ev_break(loop_);

      return;
    }

    break;
  case WorkerEventType::REPLACE_DOWNSTREAM:
    WLOG(NOTICE, this) << "Replace downstream";

    replace_downstream_config(wev.downstreamconf);

    break;
  default:
    if (LOG_ENABLED(INFO)) {
      WLOG(INFO, this) << "unknown event type " << static_cast<int>(wev.type);
    }
  }
}

tls::CertLookupTree *Worker::get_cert_lookup_tree() const { return cert_tree_; }

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

DNSTracker *Worker::get_dns_tracker() { return &dns_tracker_; }

namespace {
size_t match_downstream_addr_group_host(
    const RouterConfig &routerconf, const StringRef &host,
    const StringRef &path,
    const std::vector<std::shared_ptr<DownstreamAddrGroup>> &groups,
    size_t catch_all, BlockAllocator &balloc) {

  const auto &router = routerconf.router;
  const auto &rev_wildcard_router = routerconf.rev_wildcard_router;
  const auto &wildcard_patterns = routerconf.wildcard_patterns;

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

  if (path.empty() || path[0] != '/') {
    path = StringRef::from_lit("/");
  }

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

void downstream_failure(DownstreamAddr *addr, const Address *raddr) {
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
    if (raddr) {
      LOG(WARN) << "Could not connect to " << util::to_numeric_addr(raddr)
                << " " << fail_count
                << " times in a row; considered as offline";
    } else {
      LOG(WARN) << "Could not connect to " << addr->host << ":" << addr->port
                << " " << fail_count
                << " times in a row; considered as offline";
    }

    connect_blocker->offline();

    if (addr->rise) {
      addr->live_check->schedule();
    }
  }
}

} // namespace shrpx
