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
#endif // defined(HAVE_UNISTD_H)
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <cstdio>
#include <memory>
#include <map>

#include "ssl_compat.h"

#ifdef NGHTTP2_OPENSSL_IS_WOLFSSL
#  include <wolfssl/options.h>
#  include <wolfssl/openssl/rand.h>
#else // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)
#  include <openssl/rand.h>
#endif // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)

#ifdef HAVE_LIBBPF
#  include <bpf/bpf.h>
#  include <bpf/libbpf.h>
#endif // defined(HAVE_LIBBPF)

#include "shrpx_tls.h"
#include "shrpx_log.h"
#include "shrpx_client_handler.h"
#include "shrpx_http2_session.h"
#include "shrpx_log_config.h"
#ifdef HAVE_MRUBY
#  include "shrpx_mruby.h"
#endif // defined(HAVE_MRUBY)
#ifdef ENABLE_HTTP3
#  include "shrpx_quic_listener.h"
#endif // defined(ENABLE_HTTP3)
#include "shrpx_connection_handler.h"
#include "shrpx_accept_handler.h"
#include "util.h"
#include "template.h"
#include "xsi_strerror.h"

namespace shrpx {

#ifndef _KERNEL_FASTOPEN
#  define _KERNEL_FASTOPEN
// conditional define for TCP_FASTOPEN mostly on ubuntu
#  ifndef TCP_FASTOPEN
#    define TCP_FASTOPEN 23
#  endif // !defined(TCP_FASTOPEN)
#endif   // !defined(_KERNEL_FASTOPEN)

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

namespace {
void disable_listener_cb(struct ev_loop *loop, ev_timer *w, int revent) {
  auto worker = static_cast<Worker *>(w->data);

  // If we are in graceful shutdown period, we must not enable
  // acceptors again.
  if (worker->get_graceful_shutdown()) {
    return;
  }

  worker->enable_listener();
}
} // namespace

DownstreamAddrGroup::~DownstreamAddrGroup() {}

// DownstreamKey is used to index SharedDownstreamAddr in order to
// find the same configuration.
using DownstreamKey = std::tuple<
  std::vector<std::tuple<std::string_view, std::string_view, std::string_view,
                         size_t, size_t, Proto, uint32_t, uint32_t, uint32_t,
                         bool, bool, bool, bool>>,
  bool, SessionAffinity, std::string_view, std::string_view,
  SessionAffinityCookieSecure, SessionAffinityCookieStickiness, ev_tstamp,
  ev_tstamp, std::string_view, bool>;

namespace {
DownstreamKey
create_downstream_key(const std::shared_ptr<SharedDownstreamAddr> &shared_addr,
                      std::string_view mruby_file) {
  DownstreamKey dkey;

  auto &addrs = std::get<0>(dkey);
  addrs.resize(shared_addr->addrs.size());
  auto p = std::ranges::begin(addrs);
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
  std::ranges::sort(addrs);

  std::get<1>(dkey) = shared_addr->redirect_if_not_tls;

  auto &affinity = shared_addr->affinity;
  std::get<2>(dkey) = affinity.type;
  std::get<3>(dkey) = affinity.cookie.name;
  std::get<4>(dkey) = affinity.cookie.path;
  std::get<5>(dkey) = affinity.cookie.secure;
  std::get<6>(dkey) = affinity.cookie.stickiness;
  auto &timeout = shared_addr->timeout;
  std::get<7>(dkey) = timeout.read;
  std::get<8>(dkey) = timeout.write;
  std::get<9>(dkey) = mruby_file;
  std::get<10>(dkey) = shared_addr->dnf;

  return dkey;
}
} // namespace

Worker::Worker(struct ev_loop *loop, SSL_CTX *sv_ssl_ctx, SSL_CTX *cl_ssl_ctx,
               tls::CertLookupTree *cert_tree,
#ifdef ENABLE_HTTP3
               SSL_CTX *quic_sv_ssl_ctx, tls::CertLookupTree *quic_cert_tree,
               WorkerID wid,
#endif // defined(ENABLE_HTTP3)
               size_t index, const std::shared_ptr<TicketKeys> &ticket_keys,
               ConnectionHandler *conn_handler,
               std::shared_ptr<DownstreamConfig> downstreamconf)
  : index_{index},
    randgen_(util::make_mt19937()),
    worker_stat_{},
    dns_tracker_(loop, get_config()->conn.downstream->family),
    upstream_addrs_{get_config()->conn.listener.addrs},
#ifdef ENABLE_HTTP3
    worker_id_{std::move(wid)},
    quic_upstream_addrs_{get_config()->conn.quic_listener.addrs},
#endif // defined(ENABLE_HTTP3)
    loop_(loop),
    sv_ssl_ctx_(sv_ssl_ctx),
    cl_ssl_ctx_(cl_ssl_ctx),
    cert_tree_(cert_tree),
    conn_handler_(conn_handler),
#ifdef ENABLE_HTTP3
    quic_sv_ssl_ctx_{quic_sv_ssl_ctx},
    quic_cert_tree_{quic_cert_tree},
    quic_conn_handler_{this},
#endif // defined(ENABLE_HTTP3)
    ticket_keys_(ticket_keys),
    connect_blocker_(
      std::make_unique<ConnectBlocker>(randgen_, loop_, nullptr, nullptr)) {
  ev_async_init(&w_, eventcb);
  w_.data = this;
  ev_async_start(loop_, &w_);

  ev_timer_init(&mcpool_clear_timer_, mcpool_clear_cb, 0., 0.);
  mcpool_clear_timer_.data = this;

  ev_timer_init(&proc_wev_timer_, proc_wev_cb, 0., 0.);
  proc_wev_timer_.data = this;

  ev_timer_init(&disable_listener_timer_, disable_listener_cb, 0., 0.);
  disable_listener_timer_.data = this;

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

  auto old_addr_groups = std::exchange(
    downstream_addr_groups_,
    std::vector<std::shared_ptr<DownstreamAddrGroup>>(groups.size()));

  std::map<DownstreamKey, size_t> addr_groups_indexer;
#ifdef HAVE_MRUBY
  // TODO It is a bit less efficient because
  // mruby::create_mruby_context returns std::unique_ptr and we cannot
  // use std::make_shared.
  std::unordered_map<std::string_view, std::shared_ptr<mruby::MRubyContext>>
    shared_mruby_ctxs;
#endif // defined(HAVE_MRUBY)

  auto old_addr_group_it = std::ranges::begin(old_addr_groups);

  for (size_t i = 0; i < groups.size(); ++i) {
    auto &src = groups[i];
    auto &dst = downstream_addr_groups_[i];

    dst = std::make_shared<DownstreamAddrGroup>();
    dst->pattern = ImmutableString{src.pattern};

    for (; old_addr_group_it != std::ranges::end(old_addr_groups) &&
           (*old_addr_group_it)->pattern < dst->pattern;
         ++old_addr_group_it)
      ;

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
      shared_addr->affinity.cookie.stickiness = src.affinity.cookie.stickiness;
    }
    shared_addr->affinity_hash = src.affinity_hash;
    shared_addr->affinity_hash_map = src.affinity_hash_map;
    shared_addr->redirect_if_not_tls = src.redirect_if_not_tls;
    shared_addr->dnf = src.dnf;
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
      dst_addr.affinity_hash = src_addr.affinity_hash;
      dst_addr.proto = src_addr.proto;
      dst_addr.tls = src_addr.tls;
      dst_addr.sni = make_string_ref(shared_addr->balloc, src_addr.sni);
      dst_addr.fall = src_addr.fall;
      dst_addr.rise = src_addr.rise;
      dst_addr.dns = src_addr.dns;
      dst_addr.upgrade_scheme = src_addr.upgrade_scheme;
    }

#ifdef HAVE_MRUBY
    auto mruby_ctx_it = shared_mruby_ctxs.find(src.mruby_file);
    if (mruby_ctx_it == std::ranges::end(shared_mruby_ctxs)) {
      auto maybe_mruby_ctx = mruby::create_mruby_context(src.mruby_file);
      assert(maybe_mruby_ctx);
      shared_addr->mruby_ctx = std::move(*maybe_mruby_ctx);
      assert(shared_addr->mruby_ctx);
      shared_mruby_ctxs.emplace(src.mruby_file, shared_addr->mruby_ctx);
    } else {
      shared_addr->mruby_ctx = (*mruby_ctx_it).second;
    }
#endif // defined(HAVE_MRUBY)

    // share the connection if patterns have the same set of backend
    // addresses.

    auto dkey = create_downstream_key(shared_addr, src.mruby_file);
    auto it = addr_groups_indexer.find(dkey);

    if (it == std::ranges::end(addr_groups_indexer)) {
      auto shared_addr_ptr = shared_addr.get();

      for (auto &addr : shared_addr->addrs) {
        addr.connect_blocker = std::make_unique<ConnectBlocker>(
          randgen_, loop_, nullptr, [shared_addr_ptr, &addr] {
            if (!addr.queued) {
              if (!addr.wg) {
                return;
              }
              ensure_enqueue_addr(shared_addr_ptr->pq, addr.wg, &addr);
            }
          });

        addr.live_check = std::make_unique<LiveCheck>(loop_, cl_ssl_ctx_, this,
                                                      &addr, randgen_);
      }

      size_t seq = 0;
      for (auto &addr : shared_addr->addrs) {
        addr.dconn_pool = std::make_unique<DownstreamConnectionPool>();
        addr.seq = seq++;
      }

      util::shuffle(shared_addr->addrs, randgen_,
                    [](auto i, auto j) { std::swap((*i).seq, (*j).seq); });

      if (shared_addr->affinity.type == SessionAffinity::NONE) {
        std::unordered_map<std::string_view, WeightGroup *> wgs;
        size_t num_wgs = 0;
        for (auto &addr : shared_addr->addrs) {
          if (!wgs.contains(addr.group)) {
            ++num_wgs;
            wgs.emplace(addr.group, nullptr);
          }
        }

        shared_addr->wgs = std::vector<WeightGroup>(num_wgs);

        for (auto &addr : shared_addr->addrs) {
          auto &wg = wgs[addr.group];
          if (wg == nullptr) {
            wg = &shared_addr->wgs[--num_wgs];
            wg->name = addr.group;
            wg->seq = num_wgs;
          }

          wg->weight = addr.group_weight;
          wg->pq.push(DownstreamAddrEntry{&addr, addr.seq, addr.cycle});
          addr.queued = true;
          addr.wg = wg;
        }

        assert(num_wgs == 0);

        auto copy_cycle =
          old_addr_group_it != std::ranges::end(old_addr_groups) &&
          (*old_addr_group_it)->pattern == dst->pattern &&
          (*old_addr_group_it)->shared_addr->affinity.type ==
            SessionAffinity::NONE &&
          std::ranges::equal(shared_addr->wgs,
                             (*old_addr_group_it)->shared_addr->wgs,
                             [](const auto &a, const auto &b) {
                               return a.name == b.name && a.weight == b.weight;
                             });

        for (size_t i = 0; i < shared_addr->wgs.size(); ++i) {
          auto &wg = shared_addr->wgs[i];

          if (copy_cycle) {
            wg.cycle = (*old_addr_group_it)->shared_addr->wgs[i].cycle;
          }

          shared_addr->pq.push(WeightGroupEntry{&wg, wg.seq, wg.cycle});
          wg.queued = true;
        }
      }

      dst->shared_addr = std::move(shared_addr);

      addr_groups_indexer.emplace(std::move(dkey), i);
    } else {
      auto &g = *(std::ranges::begin(downstream_addr_groups_) +
                  as_signed((*it).second));
      if (log_enabled(INFO)) {
        Log{INFO} << dst->pattern << " shares the same backend group with "
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
  ev_timer_stop(loop_, &disable_listener_timer_);
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
#endif // !defined(NOTHREADS)
}

void Worker::run_async() {
#ifndef NOTHREADS
  fut_ = std::async(std::launch::async, [this] {
    (void)reopen_log_files(get_config()->logging);
    ev_run(loop_);

#  ifdef NGHTTP2_OPENSSL_IS_WOLFSSL
    wc_ecc_fp_free();
#  endif // defined(NGHTTP2_OPENSSL_IS_WOLFSSL)
  });
#endif // !defined(NOTHREADS)
}

void Worker::send(WorkerEvent event) {
  {
    std::lock_guard<std::mutex> g(m_);

    q_.emplace_back(std::move(event));
  }

  ev_async_send(loop_, &w_);
}

void Worker::process_events() {
  WorkerEvent wev;
  {
    std::lock_guard<std::mutex> g(m_);

    // Process event one at a time.

    if (q_.empty()) {
      ev_timer_stop(loop_, &proc_wev_timer_);
      return;
    }

    wev = std::move(q_.front());
    q_.pop_front();
  }

  ev_timer_start(loop_, &proc_wev_timer_);

  auto config = get_config();

  switch (wev.type) {
  case WorkerEventType::REOPEN_LOG:
    Log{NOTICE, this} << "Reopening log files: worker process (thread " << this
                      << ")";

    (void)reopen_log_files(config->logging);

    break;
  case WorkerEventType::GRACEFUL_SHUTDOWN:
    Log{NOTICE, this} << "Graceful shutdown commencing";

    graceful_shutdown_ = true;

    drain_and_delete_listener();

    if (worker_stat_.num_connections == 0 &&
        worker_stat_.num_close_waits == 0) {
      ev_break(loop_);

      return;
    }

    break;
  case WorkerEventType::REPLACE_DOWNSTREAM:
    Log{NOTICE, this} << "Replace downstream";

    replace_downstream_config(wev.downstreamconf);

    break;
#ifdef ENABLE_HTTP3
  case WorkerEventType::QUIC_PKT_FORWARD: {
    const UpstreamAddr *faddr;

    if (wev.quic_pkt->upstream_addr_index == static_cast<size_t>(-1)) {
      auto maybe_faddr = find_quic_upstream_addr(wev.quic_pkt->local_addr);
      if (!maybe_faddr) {
        Log{ERROR} << "No suitable upstream address found";

        break;
      }

      faddr = *maybe_faddr;
    } else if (quic_upstream_addrs_.size() <=
               wev.quic_pkt->upstream_addr_index) {
      Log{ERROR} << "upstream_addr_index is too large";

      break;
    } else {
      faddr = &quic_upstream_addrs_[wev.quic_pkt->upstream_addr_index];
    }

    quic_conn_handler_.handle_packet(faddr, wev.quic_pkt->remote_addr,
                                     wev.quic_pkt->local_addr, wev.quic_pkt->pi,
                                     wev.quic_pkt->data);

    break;
  }
#endif // defined(ENABLE_HTTP3)
  default:
    if (log_enabled(INFO)) {
      Log{INFO, this} << "unknown event type " << static_cast<int>(wev.type);
    }
  }
}

void Worker::enable_listener() {
  if (log_enabled(INFO)) {
    Log{INFO, this} << "Enable listeners";
  }

  for (auto &a : listeners_) {
    a->enable();
  }
}

void Worker::disable_listener() {
  if (log_enabled(INFO)) {
    Log{INFO, this} << "Disable listeners";
  }

  for (auto &a : listeners_) {
    a->disable();
  }
}

void Worker::sleep_listener(ev_tstamp t) {
  if (t == 0. || ev_is_active(&disable_listener_timer_)) {
    return;
  }

  disable_listener();

  ev_timer_set(&disable_listener_timer_, t, 0.);
  ev_timer_start(loop_, &disable_listener_timer_);
}

tls::CertLookupTree *Worker::get_cert_lookup_tree() const { return cert_tree_; }

#ifdef ENABLE_HTTP3
tls::CertLookupTree *Worker::get_quic_cert_lookup_tree() const {
  return quic_cert_tree_;
}
#endif // defined(ENABLE_HTTP3)

std::shared_ptr<TicketKeys> Worker::get_ticket_keys() {
#ifdef HAVE_ATOMIC_STD_SHARED_PTR
  return ticket_keys_.load(std::memory_order_acquire);
#else  // !defined(HAVE_ATOMIC_STD_SHARED_PTR)
  std::lock_guard<std::mutex> g(ticket_keys_m_);
  return ticket_keys_;
#endif // !defined(HAVE_ATOMIC_STD_SHARED_PTR)
}

void Worker::set_ticket_keys(std::shared_ptr<TicketKeys> ticket_keys) {
#ifdef HAVE_ATOMIC_STD_SHARED_PTR
  // This is single writer
  ticket_keys_.store(std::move(ticket_keys), std::memory_order_release);
#else  // !defined(HAVE_ATOMIC_STD_SHARED_PTR)
  std::lock_guard<std::mutex> g(ticket_keys_m_);
  ticket_keys_ = std::move(ticket_keys);
#endif // !defined(HAVE_ATOMIC_STD_SHARED_PTR)
}

WorkerStat *Worker::get_worker_stat() { return &worker_stat_; }

struct ev_loop *Worker::get_loop() const { return loop_; }

SSL_CTX *Worker::get_sv_ssl_ctx() const { return sv_ssl_ctx_; }

SSL_CTX *Worker::get_cl_ssl_ctx() const { return cl_ssl_ctx_; }

#ifdef ENABLE_HTTP3
SSL_CTX *Worker::get_quic_sv_ssl_ctx() const { return quic_sv_ssl_ctx_; }
#endif // defined(ENABLE_HTTP3)

void Worker::set_graceful_shutdown(bool f) { graceful_shutdown_ = f; }

bool Worker::get_graceful_shutdown() const { return graceful_shutdown_; }

MemchunkPool *Worker::get_mcpool() { return &mcpool_; }

std::mt19937 &Worker::get_randgen() { return randgen_; }

#ifdef HAVE_MRUBY
std::expected<void, Error> Worker::create_mruby_context() {
  auto maybe_mruby_ctx = mruby::create_mruby_context(get_config()->mruby_file);
  if (!maybe_mruby_ctx) {
    return std::unexpected{maybe_mruby_ctx.error()};
  }

  mruby_ctx_ = std::move(*maybe_mruby_ctx);

  return {};
}

mruby::MRubyContext *Worker::get_mruby_context() const {
  return mruby_ctx_.get();
}
#endif // defined(HAVE_MRUBY)

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

std::expected<void, Error> Worker::setup_server_socket() {
  auto config = get_config();
  auto &apiconf = config->api;
  auto api_isolation = apiconf.enabled && !config->single_thread;

  for (auto &addr : upstream_addrs_) {
    if (api_isolation) {
      if (addr.alt_mode == UpstreamAltMode::API) {
        if (index_ != 0) {
          continue;
        }
      } else if (index_ == 0) {
        continue;
      }
    }

    if (addr.host_unix) {
      // Copy file descriptor because AcceptHandler destructor closes
      // addr.fd.
      addr.fd = dup(addr.fd);
      if (addr.fd == -1) {
        return std::unexpected{Error::SYSCALL};
      }

      util::make_socket_closeonexec(addr.fd);
    } else if (auto rv = create_tcp_server_socket(addr); !rv) {
      return rv;
    }

    listeners_.emplace_back(std::make_unique<AcceptHandler>(this, &addr));
  }

  return {};
}

void Worker::drain_and_delete_listener() {
  for (auto &l : listeners_) {
    l->drain_connection();
    l.reset(nullptr);
  }

  listeners_.clear();
}

std::expected<void, Error>
Worker::create_tcp_server_socket(UpstreamAddr &faddr) {
  std::array<char, STRERROR_BUFSIZE> errbuf;
  int fd = -1;
  int rv;

  auto &listenerconf = get_config()->conn.listener;

  auto service = util::utos(faddr.port);
  addrinfo hints{
    .ai_flags = AI_PASSIVE
#ifdef AI_ADDRCONFIG
                | AI_ADDRCONFIG
#endif // defined(AI_ADDRCONFIG)
    ,
    .ai_family = faddr.family,
    .ai_socktype = SOCK_STREAM,
  };

  auto node = faddr.host == "*"sv ? nullptr : faddr.host.data();

  addrinfo *res, *rp;
  rv = getaddrinfo(node, service.c_str(), &hints, &res);
#ifdef AI_ADDRCONFIG
  if (rv != 0) {
    // Retry without AI_ADDRCONFIG
    hints.ai_flags &= ~AI_ADDRCONFIG;
    rv = getaddrinfo(node, service.c_str(), &hints, &res);
  }
#endif // defined(AI_ADDRCONFIG)
  if (rv != 0) {
    Log{FATAL} << "Unable to get IPv" << (faddr.family == AF_INET ? "4" : "6")
               << " address for " << faddr.host << ", port " << faddr.port
               << ": " << gai_strerror(rv);
    return std::unexpected{Error::LIBC};
  }

  auto res_d = defer([res] { freeaddrinfo(res); });

  std::array<char, NI_MAXHOST> host;

  for (rp = res; rp; rp = rp->ai_next) {
    rv = getnameinfo(rp->ai_addr, rp->ai_addrlen, host.data(), host.size(),
                     nullptr, 0, NI_NUMERICHOST);

    if (rv != 0) {
      Log{WARN} << "getnameinfo() failed: " << gai_strerror(rv);
      continue;
    }

#ifdef SOCK_NONBLOCK
    fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
                rp->ai_protocol);
    if (fd == -1) {
      auto error = errno;
      Log{WARN} << "socket() syscall failed: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      continue;
    }
#else  // !defined(SOCK_NONBLOCK)
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      auto error = errno;
      Log{WARN} << "socket() syscall failed: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      continue;
    }
    util::make_socket_nonblocking(fd);
    util::make_socket_closeonexec(fd);
#endif // !defined(SOCK_NONBLOCK)
    const int val = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      auto error = errno;
      Log{WARN} << "Failed to set SO_REUSEADDR option to listener socket: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      auto error = errno;
      Log{WARN} << "Failed to set SO_REUSEPORT option to listener socket: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }

#ifdef IPV6_V6ONLY
    if (faddr.family == AF_INET6) {
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        Log{WARN} << "Failed to set IPV6_V6ONLY option to listener socket: "
                  << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }
    }
#endif // defined(IPV6_V6ONLY)

#ifdef TCP_DEFER_ACCEPT
    if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      auto error = errno;
      Log{WARN} << "Failed to set TCP_DEFER_ACCEPT option to listener socket: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
    }
#endif // defined(TCP_DEFER_ACCEPT)

    // When we are executing new binary, and the old binary did not
    // bind privileged port (< 1024) for some reason, binding to those
    // ports will fail with permission denied error.
    if (bind(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
      auto error = errno;
      Log{WARN} << "bind() syscall failed: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }

    if (listenerconf.fastopen > 0) {
      const int val = listenerconf.fastopen;
      if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        Log{WARN} << "Failed to set TCP_FASTOPEN option to listener socket: "
                  << xsi_strerror(error, errbuf.data(), errbuf.size());
      }
    }

    if (listen(fd, listenerconf.backlog) == -1) {
      auto error = errno;
      Log{WARN} << "listen() syscall failed: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }

    break;
  }

  if (!rp) {
    Log{FATAL} << "Listening " << (faddr.family == AF_INET ? "IPv4" : "IPv6")
               << " socket failed";

    return std::unexpected{Error::SYSCALL};
  }

  faddr.fd = fd;
  faddr.hostport = util::make_http_hostport(
    mod_config()->balloc, std::string_view{host.data()}, faddr.port);

  Log{NOTICE} << "Listening on " << faddr.hostport
              << (faddr.tls ? ", tls" : "");

  return {};
}

#ifdef ENABLE_HTTP3
QUICConnectionHandler *Worker::get_quic_connection_handler() {
  return &quic_conn_handler_;
}
#endif // defined(ENABLE_HTTP3)

DNSTracker *Worker::get_dns_tracker() { return &dns_tracker_; }

#ifdef ENABLE_HTTP3
#  ifdef HAVE_LIBBPF
bool Worker::should_attach_bpf() const {
  auto config = get_config();
  auto &quicconf = config->quic;
  auto &apiconf = config->api;

  if (quicconf.bpf.disabled) {
    return false;
  }

  if (!config->single_thread && apiconf.enabled) {
    return index_ == 1;
  }

  return index_ == 0;
}

bool Worker::should_update_bpf_map() const {
  auto config = get_config();
  auto &quicconf = config->quic;

  return !quicconf.bpf.disabled;
}

uint32_t Worker::compute_sk_index() const {
  auto config = get_config();
  auto &apiconf = config->api;

  if (!config->single_thread && apiconf.enabled) {
    return static_cast<uint32_t>(index_ - 1);
  }

  return static_cast<uint32_t>(index_);
}
#  endif // defined(HAVE_LIBBPF)

std::expected<void, Error> Worker::setup_quic_server_socket() {
  size_t n = 0;

  for (auto &addr : quic_upstream_addrs_) {
    assert(!addr.host_unix);
    if (auto rv = create_quic_server_socket(addr); !rv) {
      return rv;
    }

    // Make sure that each endpoint has a unique address.
    for (size_t i = 0; i < n; ++i) {
      const auto &a = quic_upstream_addrs_[i];

      if (addr.hostport == a.hostport) {
        Log{FATAL}
          << "QUIC frontend endpoint must be unique: a duplicate found for "
          << addr.hostport;

        return std::unexpected{Error::INTERNAL};
      }
    }

    ++n;

    quic_listeners_.emplace_back(std::make_unique<QUICListener>(&addr, this));
  }

  return {};
}

#  ifdef HAVE_LIBBPF
namespace {
// https://github.com/kokke/tiny-AES-c
//
// License is Public Domain.
// Commit hash: 12e7744b4919e9d55de75b7ab566326a1c8e7a67

// The number of columns comprising a state in AES. This is a constant
// in AES. Value=4
#    define Nb 4

#    define Nk 4  // The number of 32 bit words in a key.
#    define Nr 10 // The number of rounds in AES Cipher.

// The lookup-tables are marked const so they can be placed in
// read-only storage instead of RAM The numbers below can be computed
// dynamically trading ROM for RAM - This can be useful in (embedded)
// bootloader applications, where ROM is often limited.
constexpr uint8_t sbox[256] = {
  // 0 1 2 3 4 5 6 7 8 9 A B C D E F
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE,
  0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4,
  0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7,
  0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3,
  0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09,
  0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3,
  0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE,
  0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
  0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92,
  0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C,
  0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19,
  0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
  0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2,
  0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5,
  0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25,
  0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86,
  0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E,
  0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42,
  0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

#    define getSBoxValue(num) (sbox[(num)])

// The round constant word array, Rcon[i], contains the values given
// by x to the power (i-1) being powers of x (x is denoted as {02}) in
// the field GF(2^8)
constexpr uint8_t Rcon[11] = {
  0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
};

// This function produces Nb(Nr+1) round keys. The round keys are used
// in each round to decrypt the states.
void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key) {
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i) {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i) {
    {
      k = (i - 1) * 4;
      tempa[0] = RoundKey[k + 0];
      tempa[1] = RoundKey[k + 1];
      tempa[2] = RoundKey[k + 2];
      tempa[3] = RoundKey[k + 3];
    }

    if (i % Nk == 0) {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an
      // output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i / Nk];
    }
    j = i * 4;
    k = (i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}
} // namespace
#  endif // defined(HAVE_LIBBPF)

std::expected<void, Error>
Worker::create_quic_server_socket(UpstreamAddr &faddr) {
  std::array<char, STRERROR_BUFSIZE> errbuf;
  int fd = -1;
  int rv;

  auto service = util::utos(faddr.port);
  addrinfo hints{
    .ai_flags = AI_PASSIVE
#  ifdef AI_ADDRCONFIG
                | AI_ADDRCONFIG
#  endif // defined(AI_ADDRCONFIG)
    ,
    .ai_family = faddr.family,
    .ai_socktype = SOCK_DGRAM,
  };

  auto node = faddr.host == "*"sv ? nullptr : faddr.host.data();

  addrinfo *res, *rp;
  rv = getaddrinfo(node, service.c_str(), &hints, &res);
#  ifdef AI_ADDRCONFIG
  if (rv != 0) {
    // Retry without AI_ADDRCONFIG
    hints.ai_flags &= ~AI_ADDRCONFIG;
    rv = getaddrinfo(node, service.c_str(), &hints, &res);
  }
#  endif // defined(AI_ADDRCONFIG)
  if (rv != 0) {
    Log{FATAL} << "Unable to get IPv" << (faddr.family == AF_INET ? "4" : "6")
               << " address for " << faddr.host << ", port " << faddr.port
               << ": " << gai_strerror(rv);
    return std::unexpected{Error::LIBC};
  }

  auto res_d = defer([res] { freeaddrinfo(res); });

  std::array<char, NI_MAXHOST> host;

  for (rp = res; rp; rp = rp->ai_next) {
    rv = getnameinfo(rp->ai_addr, rp->ai_addrlen, host.data(), host.size(),
                     nullptr, 0, NI_NUMERICHOST);
    if (rv != 0) {
      Log{WARN} << "getnameinfo() failed: " << gai_strerror(rv);
      continue;
    }

#  ifdef SOCK_NONBLOCK
    fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
                rp->ai_protocol);
    if (fd == -1) {
      auto error = errno;
      Log{WARN} << "socket() syscall failed: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      continue;
    }
#  else  // !defined(SOCK_NONBLOCK)
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      auto error = errno;
      Log{WARN} << "socket() syscall failed: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      continue;
    }
    util::make_socket_nonblocking(fd);
    util::make_socket_closeonexec(fd);
#  endif // !defined(SOCK_NONBLOCK)

    int val = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      auto error = errno;
      Log{WARN} << "Failed to set SO_REUSEADDR option to listener socket: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      auto error = errno;
      Log{WARN} << "Failed to set SO_REUSEPORT option to listener socket: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }

    if (faddr.family == AF_INET6) {
#  ifdef IPV6_V6ONLY
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        Log{WARN} << "Failed to set IPV6_V6ONLY option to listener socket: "
                  << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }
#  endif // defined(IPV6_V6ONLY)

      if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        Log{WARN}
          << "Failed to set IPV6_RECVPKTINFO option to listener socket: "
          << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }

      if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        Log{WARN} << "Failed to set IPV6_RECVTCLASS option to listener socket: "
                  << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }

#  if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_PROBE)
      int mtu_disc = IPV6_PMTUDISC_PROBE;
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &mtu_disc,
                     static_cast<socklen_t>(sizeof(mtu_disc))) == -1) {
        auto error = errno;
        Log{WARN}
          << "Failed to set IPV6_MTU_DISCOVER option to listener socket: "
          << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }
#  endif // defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_PROBE)
    } else {
      if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        Log{WARN} << "Failed to set IP_PKTINFO option to listener socket: "
                  << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }

      if (setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        Log{WARN} << "Failed to set IP_RECVTOS option to listener socket: "
                  << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }

#  if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_PROBE)
      int mtu_disc = IP_PMTUDISC_PROBE;
      if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mtu_disc,
                     static_cast<socklen_t>(sizeof(mtu_disc))) == -1) {
        auto error = errno;
        Log{WARN} << "Failed to set IP_MTU_DISCOVER option to listener socket: "
                  << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }
#  endif // defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_PROBE)
    }

#  ifdef UDP_GRO
    if (setsockopt(fd, IPPROTO_UDP, UDP_GRO, &val, sizeof(val)) == -1) {
      auto error = errno;
      Log{WARN} << "Failed to set UDP_GRO option to listener socket: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }
#  endif // defined(UDP_GRO)

    if (bind(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
      auto error = errno;
      Log{WARN} << "bind() syscall failed: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }

#  ifdef HAVE_LIBBPF
    auto config = get_config();

    auto &quic_bpf_refs = conn_handler_->get_quic_bpf_refs();

    if (should_attach_bpf()) {
      auto &bpfconf = config->quic.bpf;

      auto obj = bpf_object__open_file(bpfconf.prog_file.data(), nullptr);
      if (!obj) {
        auto error = errno;
        Log{FATAL} << "Failed to open bpf object file: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return std::unexpected{Error::BPF};
      }

      rv = bpf_object__load(obj);
      if (rv != 0) {
        auto error = errno;
        Log{FATAL} << "Failed to load bpf object file: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return std::unexpected{Error::BPF};
      }

      auto prog = bpf_object__find_program_by_name(obj, "select_reuseport");
      if (!prog) {
        auto error = errno;
        Log{FATAL} << "Failed to find sk_reuseport program: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return std::unexpected{Error::BPF};
      }

      auto &ref = quic_bpf_refs[faddr.index];

      ref.obj = obj;

      ref.reuseport_array =
        bpf_object__find_map_by_name(obj, "reuseport_array");
      if (!ref.reuseport_array) {
        auto error = errno;
        Log{FATAL} << "Failed to get reuseport_array: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return std::unexpected{Error::BPF};
      }

      ref.worker_id_map = bpf_object__find_map_by_name(obj, "worker_id_map");
      if (!ref.worker_id_map) {
        auto error = errno;
        Log{FATAL} << "Failed to get worker_id_map: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return std::unexpected{Error::BPF};
      }

      auto sk_info = bpf_object__find_map_by_name(obj, "sk_info");
      if (!sk_info) {
        auto error = errno;
        Log{FATAL} << "Failed to get sk_info: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return std::unexpected{Error::BPF};
      }

      constexpr uint32_t zero = 0;
      uint64_t num_socks = config->num_worker;

      rv = bpf_map__update_elem(sk_info, &zero, sizeof(zero), &num_socks,
                                sizeof(num_socks), BPF_ANY);
      if (rv != 0) {
        auto error = errno;
        Log{FATAL} << "Failed to update sk_info: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return std::unexpected{Error::BPF};
      }

      assert(quic_keying_materials_);
      auto &qkm = quic_keying_materials_->keying_materials.front();

      auto aes_key = bpf_object__find_map_by_name(obj, "aes_key");
      if (!aes_key) {
        auto error = errno;
        Log{FATAL} << "Failed to get aes_key: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return std::unexpected{Error::BPF};
      }

      constexpr size_t expanded_aes_keylen = 176;
      std::array<uint8_t, expanded_aes_keylen> aes_exp_key;

      KeyExpansion(aes_exp_key.data(), qkm.cid_encryption_key.data());

      rv =
        bpf_map__update_elem(aes_key, &zero, sizeof(zero), aes_exp_key.data(),
                             aes_exp_key.size(), BPF_ANY);
      if (rv != 0) {
        auto error = errno;
        Log{FATAL} << "Failed to update aes_key: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return std::unexpected{Error::BPF};
      }

      auto prog_fd = bpf_program__fd(prog);

      if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd,
                     static_cast<socklen_t>(sizeof(prog_fd))) == -1) {
        Log{FATAL} << "Failed to attach bpf program: "
                   << xsi_strerror(errno, errbuf.data(), errbuf.size());
        close(fd);
        return std::unexpected{Error::SYSCALL};
      }
    }

    if (should_update_bpf_map()) {
      const auto &ref = quic_bpf_refs[faddr.index];
      auto sk_index = compute_sk_index();

      rv = bpf_map__update_elem(ref.reuseport_array, &sk_index,
                                sizeof(sk_index), &fd, sizeof(fd), BPF_NOEXIST);
      if (rv != 0) {
        auto error = errno;
        Log{FATAL} << "Failed to update reuseport_array: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return std::unexpected{Error::BPF};
      }

      rv =
        bpf_map__update_elem(ref.worker_id_map, &worker_id_, sizeof(worker_id_),
                             &sk_index, sizeof(sk_index), BPF_NOEXIST);
      if (rv != 0) {
        auto error = errno;
        Log{FATAL} << "Failed to update worker_id_map: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return std::unexpected{Error::BPF};
      }
    }
#  endif // defined(HAVE_LIBBPF)

    break;
  }

  if (!rp) {
    Log{FATAL} << "Listening " << (faddr.family == AF_INET ? "IPv4" : "IPv6")
               << " socket failed";

    return std::unexpected{Error::SYSCALL};
  }

  faddr.fd = fd;
  faddr.hostport = util::make_http_hostport(
    mod_config()->balloc, std::string_view{host.data()}, faddr.port);
  faddr.sockaddr.set(rp->ai_addr);

  switch (faddr.family) {
  case AF_INET: {
    static constexpr auto inaddr_any = INADDR_ANY;

    const auto &inaddr = std::get<sockaddr_in>(faddr.sockaddr.skaddr);

    faddr.sockaddr_any =
      memcmp(&inaddr_any, &inaddr.sin_addr, sizeof(inaddr_any)) == 0;

    break;
  }
  case AF_INET6: {
    static constexpr in6_addr in6addr_any = IN6ADDR_ANY_INIT;

    const auto &in6addr = std::get<sockaddr_in6>(faddr.sockaddr.skaddr);

    faddr.sockaddr_any =
      memcmp(&in6addr_any, &in6addr.sin6_addr, sizeof(in6addr_any)) == 0;

    break;
  }
  default:
    assert(0);
  }

  Log{NOTICE} << "Listening on " << faddr.hostport << ", quic";

  return {};
}

const WorkerID &Worker::get_worker_id() const { return worker_id_; }

std::expected<const UpstreamAddr *, Error>
Worker::find_quic_upstream_addr(const Address &local_addr) {
  return std::visit(
    [&faddrs = quic_upstream_addrs_](
      auto &&arg) -> std::expected<const UpstreamAddr *, Error> {
      const UpstreamAddr *fallback_faddr = nullptr;

      using T = std::decay_t<decltype(arg)>;

      for (const auto &faddr : faddrs) {
        if constexpr (std::is_same_v<T, sockaddr_in>) {
          if (faddr.family != AF_INET) {
            continue;
          }

          const auto &addr = std::get<sockaddr_in>(faddr.sockaddr.skaddr);
          if (arg.sin_port != addr.sin_port) {
            continue;
          }

          if (memcmp(&arg.sin_addr, &addr.sin_addr, sizeof(addr.sin_addr)) ==
              0) {
            return &faddr;
          }
        }

        if constexpr (std::is_same_v<T, sockaddr_in6>) {
          if (faddr.family != AF_INET6) {
            continue;
          }

          const auto &addr = std::get<sockaddr_in6>(faddr.sockaddr.skaddr);
          if (arg.sin6_port != addr.sin6_port) {
            continue;
          }

          if (memcmp(&arg.sin6_addr, &addr.sin6_addr, sizeof(addr.sin6_addr)) ==
              0) {
            return &faddr;
          }
        }

        if (faddr.sockaddr_any) {
          fallback_faddr = &faddr;
        }
      }

      if (!fallback_faddr) {
        return std::unexpected{Error::ENTITY_NOT_FOUND};
      }

      return fallback_faddr;
    },
    local_addr.skaddr);
}

std::expected<void, Error> Worker::setup_quic_keying_materials(
  const std::unique_ptr<QUICKeyingMaterials> &qkms) {
  quic_keying_materials_ = std::make_unique<QUICKeyingMaterials>(*qkms);

  for (auto &qkm : quic_keying_materials_->keying_materials) {
    if (auto rv = qkm.init_ciphers(); !rv) {
      return rv;
    }
  }

  return {};
}
#endif // defined(ENABLE_HTTP3)

namespace {
size_t match_downstream_addr_group_host(
  const RouterConfig &routerconf, std::string_view host, std::string_view path,
  const std::vector<std::shared_ptr<DownstreamAddrGroup>> &groups,
  size_t catch_all, BlockAllocator &balloc) {
  const auto &router = routerconf.router;
  const auto &rev_wildcard_router = routerconf.rev_wildcard_router;
  const auto &wildcard_patterns = routerconf.wildcard_patterns;

  if (log_enabled(INFO)) {
    Log{INFO} << "Perform mapping selection, using host=" << host
              << ", path=" << path;
  }

  if (auto maybe_group = router.match(host, path); maybe_group) {
    auto group = *maybe_group;

    if (log_enabled(INFO)) {
      Log{INFO} << "Found pattern with query " << host << path
                << ", matched pattern=" << groups[group]->pattern;
    }
    return group;
  }

  if (!wildcard_patterns.empty() && !host.empty()) {
    auto rev_host_src = make_byte_ref(balloc, host.size() - 1);
    auto rev_host =
      as_string_view(std::ranges::begin(rev_host_src),
                     std::ranges::reverse_copy(std::ranges::begin(host) + 1,
                                               std::ranges::end(host),
                                               std::ranges::begin(rev_host_src))
                       .out);

    constexpr auto no_match = std::numeric_limits<size_t>::max();
    size_t best_group = no_match;
    const RNode *last_node = nullptr;

    for (;;) {
      size_t nread = 0;
      auto maybe_wcidx =
        rev_wildcard_router.match_prefix(&nread, &last_node, rev_host);
      if (!maybe_wcidx) {
        break;
      }

      auto wcidx = *maybe_wcidx;

      rev_host = std::string_view{std::ranges::begin(rev_host) + nread,
                                  std::ranges::end(rev_host)};

      auto &wc = wildcard_patterns[wcidx];
      if (auto maybe_group = wc.router.match(""sv, path); maybe_group) {
        best_group = *maybe_group;

        // We sorted wildcard_patterns in a way that first match is the
        // longest host pattern.
        if (log_enabled(INFO)) {
          Log{INFO} << "Found wildcard pattern with query " << host << path
                    << ", matched pattern=" << groups[best_group]->pattern;
        }
      }
    }

    if (best_group != no_match) {
      return best_group;
    }
  }

  if (auto maybe_group = router.match(""sv, path); maybe_group) {
    auto group = *maybe_group;

    if (log_enabled(INFO)) {
      Log{INFO} << "Found pattern with query " << path
                << ", matched pattern=" << groups[group]->pattern;
    }
    return group;
  }

  if (log_enabled(INFO)) {
    Log{INFO} << "None match.  Use catch-all pattern";
  }
  return catch_all;
}
} // namespace

size_t match_downstream_addr_group(
  const RouterConfig &routerconf, std::string_view hostport,
  std::string_view raw_path,
  const std::vector<std::shared_ptr<DownstreamAddrGroup>> &groups,
  size_t catch_all, BlockAllocator &balloc) {
  if (util::contains(hostport, '/')) {
    // We use '/' specially, and if '/' is included in host, it breaks
    // our code.  Select catch-all case.
    return catch_all;
  }

  auto fragment = std::ranges::find(raw_path, '#');
  auto query = std::ranges::find(std::ranges::begin(raw_path), fragment, '?');
  auto path = std::string_view{std::ranges::begin(raw_path), query};

  if (path.empty() || path[0] != '/') {
    path = "/"sv;
  }

  if (hostport.empty()) {
    return match_downstream_addr_group_host(routerconf, hostport, path, groups,
                                            catch_all, balloc);
  }

  std::string_view host;
  if (hostport[0] == '[') {
    // assume this is IPv6 numeric address
    auto p = std::ranges::find(hostport, ']');
    if (p == std::ranges::end(hostport)) {
      return catch_all;
    }
    if (p + 1 < std::ranges::end(hostport) && *(p + 1) != ':') {
      return catch_all;
    }
    host = std::string_view{std::ranges::begin(hostport), p + 1};
  } else {
    auto p = std::ranges::find(hostport, ':');
    if (p == std::ranges::begin(hostport)) {
      return catch_all;
    }
    host = std::string_view{std::ranges::begin(hostport), p};
  }

  if (std::ranges::find_if(host, [](char c) { return 'A' <= c && c <= 'Z'; }) !=
      std::ranges::end(host)) {
    auto low_host = make_byte_ref(balloc, host.size() + 1);
    auto ep = util::tolower(host, std::ranges::begin(low_host));
    *ep = '\0';
    host = as_string_view(std::ranges::begin(low_host), ep);
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
      Log{WARN} << "Could not connect to " << util::to_numeric_addr(raddr)
                << " " << fail_count
                << " times in a row; considered as offline";
    } else {
      Log{WARN} << "Could not connect to " << addr->host << ":" << addr->port
                << " " << fail_count
                << " times in a row; considered as offline";
    }

    connect_blocker->offline();

    if (addr->rise) {
      addr->live_check->schedule();
    }
  }
}

std::expected<void, Error>
Worker::handle_connection(int fd, const sockaddr *addr, socklen_t addrlen,
                          const UpstreamAddr *faddr) {
  if (log_enabled(INFO)) {
    Log{INFO, this} << "Accepted connection from "
                    << util::numeric_name(addr, addrlen) << ", fd=" << fd;
  }

  auto config = get_config();

  auto max_conns = config->conn.upstream.worker_connections;

  if (worker_stat_.num_connections >= max_conns) {
    if (log_enabled(INFO)) {
      Log{INFO, this} << "Too many connections >= " << max_conns;
    }

    close(fd);

    return std::unexpected{Error::INTERNAL};
  }

  auto maybe_handler = tls::accept_connection(this, fd, addr, addrlen, faddr);
  if (!maybe_handler) {
    if (log_enabled(INFO)) {
      Log{ERROR, this} << "ClientHandler creation failed";
    }

    close(fd);

    return std::unexpected{maybe_handler.error()};
  }

  auto client_handler = maybe_handler->release();

  if (log_enabled(INFO)) {
    Log{INFO, this} << "CLIENT_HANDLER:" << client_handler << " created";
  }

  return {};
}

} // namespace shrpx
