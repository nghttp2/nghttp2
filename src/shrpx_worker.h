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
#ifndef SHRPX_WORKER_H
#define SHRPX_WORKER_H

#include "shrpx.h"

#include <mutex>
#include <vector>
#include <random>
#include <unordered_map>
#include <deque>
#include <thread>
#ifndef NOTHREADS
#include <future>
#endif // NOTHREADS

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <ev.h>

#include "shrpx_config.h"
#include "shrpx_downstream_connection_pool.h"
#include "memchunk.h"
#include "shrpx_tls.h"
#include "shrpx_live_check.h"
#include "shrpx_connect_blocker.h"
#include "shrpx_dns_tracker.h"
#include "allocator.h"

using namespace nghttp2;

namespace shrpx {

class Http2Session;
class ConnectBlocker;
class MemcachedDispatcher;
struct UpstreamAddr;
class ConnectionHandler;

#ifdef HAVE_MRUBY
namespace mruby {

class MRubyContext;

} // namespace mruby
#endif // HAVE_MRUBY

namespace tls {
class CertLookupTree;
} // namespace tls

struct DownstreamAddr {
  Address addr;
  // backend address.  If |host_unix| is true, this is UNIX domain
  // socket path.
  StringRef host;
  StringRef hostport;
  // backend port.  0 if |host_unix| is true.
  uint16_t port;
  // true if |host| contains UNIX domain socket path.
  bool host_unix;

  // sni field to send remote server if TLS is enabled.
  StringRef sni;

  std::unique_ptr<ConnectBlocker> connect_blocker;
  std::unique_ptr<LiveCheck> live_check;
  // Connection pool for this particular address if session affinity
  // is enabled
  std::unique_ptr<DownstreamConnectionPool> dconn_pool;
  size_t fall;
  size_t rise;
  // Client side TLS session cache
  tls::TLSSessionCache tls_session_cache;
  // Http2Session object created for this address.  This list chains
  // all Http2Session objects that is not in group scope
  // http2_avail_freelist, and is not reached in maximum concurrency.
  //
  // If session affinity is enabled, http2_avail_freelist is not used,
  // and this list is solely used.
  DList<Http2Session> http2_extra_freelist;
  // true if Http2Session for this address is in group scope
  // SharedDownstreamAddr.http2_avail_freelist
  bool in_avail;
  // total number of streams created in HTTP/2 connections for this
  // address.
  size_t num_dconn;
  // Application protocol used in this backend
  shrpx_proto proto;
  // true if TLS is used in this backend
  bool tls;
  // true if dynamic DNS is enabled
  bool dns;
};

// Simplified weighted fair queuing.  Actually we don't use queue here
// since we have just 2 items.  This is the same algorithm used in
// stream priority, but ignores remainder.
struct WeightedPri {
  // current cycle of this item.  The lesser cycle has higher
  // priority.  This is unsigned 32 bit integer, so it may overflow.
  // But with the same theory described in stream priority, it is no
  // problem.
  uint32_t cycle;
  // weight, larger weight means more frequent use.
  uint32_t weight;
};

struct SharedDownstreamAddr {
  SharedDownstreamAddr()
      : balloc(1024, 1024),
        next{0},
        http1_pri{},
        http2_pri{},
        affinity{AFFINITY_NONE},
        redirect_if_not_tls{false} {}

  SharedDownstreamAddr(const SharedDownstreamAddr &) = delete;
  SharedDownstreamAddr(SharedDownstreamAddr &&) = delete;
  SharedDownstreamAddr &operator=(const SharedDownstreamAddr &) = delete;
  SharedDownstreamAddr &operator=(SharedDownstreamAddr &&) = delete;

  BlockAllocator balloc;
  std::vector<DownstreamAddr> addrs;
  // Bunch of session affinity hash.  Only used if affinity ==
  // AFFINITY_IP.
  std::vector<AffinityHash> affinity_hash;
  // List of Http2Session which is not fully utilized (i.e., the
  // server advertised maximum concurrency is not reached).  We will
  // coalesce as much stream as possible in one Http2Session to fully
  // utilize TCP connection.
  //
  // If session affinity is enabled, this list is not used.  Per
  // address http2_extra_freelist is used instead.
  //
  // TODO Verify that this approach performs better in performance
  // wise.
  DList<Http2Session> http2_avail_freelist;
  DownstreamConnectionPool dconn_pool;
  // Next http/1.1 downstream address index in addrs.
  size_t next;
  // http1_pri and http2_pri are used to which protocols are used
  // between HTTP/1.1 or HTTP/2 if they both are available in
  // backends.  They are choosed proportional to the number available
  // backend.  Usually, if http1_pri.cycle < http2_pri.cycle, choose
  // HTTP/1.1.  Otherwise, choose HTTP/2.
  WeightedPri http1_pri;
  WeightedPri http2_pri;
  // Session affinity
  shrpx_session_affinity affinity;
  // true if this group requires that client connection must be TLS,
  // and the request must be redirected to https URI.
  bool redirect_if_not_tls;
};

struct DownstreamAddrGroup {
  DownstreamAddrGroup() : retired{false} {};

  DownstreamAddrGroup(const DownstreamAddrGroup &) = delete;
  DownstreamAddrGroup(DownstreamAddrGroup &&) = delete;
  DownstreamAddrGroup &operator=(const DownstreamAddrGroup &) = delete;
  DownstreamAddrGroup &operator=(DownstreamAddrGroup &&) = delete;

  ImmutableString pattern;
  std::shared_ptr<SharedDownstreamAddr> shared_addr;
  // true if this group is no longer used for new request.  If this is
  // true, the connection made using one of address in shared_addr
  // must not be pooled.
  bool retired;
};

struct WorkerStat {
  size_t num_connections;
};

enum WorkerEventType {
  NEW_CONNECTION = 0x01,
  REOPEN_LOG = 0x02,
  GRACEFUL_SHUTDOWN = 0x03,
  REPLACE_DOWNSTREAM = 0x04,
};

struct WorkerEvent {
  WorkerEventType type;
  struct {
    sockaddr_union client_addr;
    size_t client_addrlen;
    int client_fd;
    const UpstreamAddr *faddr;
  };
  std::shared_ptr<TicketKeys> ticket_keys;
  std::shared_ptr<DownstreamConfig> downstreamconf;
};

class Worker {
public:
  Worker(struct ev_loop *loop, SSL_CTX *sv_ssl_ctx, SSL_CTX *cl_ssl_ctx,
         SSL_CTX *tls_session_cache_memcached_ssl_ctx,
         tls::CertLookupTree *cert_tree,
         const std::shared_ptr<TicketKeys> &ticket_keys,
         ConnectionHandler *conn_handler,
         std::shared_ptr<DownstreamConfig> downstreamconf);
  ~Worker();
  void run_async();
  void wait();
  void process_events();
  void send(const WorkerEvent &event);

  tls::CertLookupTree *get_cert_lookup_tree() const;

  // These 2 functions make a lock m_ to get/set ticket keys
  // atomically.
  std::shared_ptr<TicketKeys> get_ticket_keys();
  void set_ticket_keys(std::shared_ptr<TicketKeys> ticket_keys);

  WorkerStat *get_worker_stat();
  struct ev_loop *get_loop() const;
  SSL_CTX *get_sv_ssl_ctx() const;
  SSL_CTX *get_cl_ssl_ctx() const;

  void set_graceful_shutdown(bool f);
  bool get_graceful_shutdown() const;

  MemchunkPool *get_mcpool();
  void schedule_clear_mcpool();

  MemcachedDispatcher *get_session_cache_memcached_dispatcher();

  std::mt19937 &get_randgen();

#ifdef HAVE_MRUBY
  int create_mruby_context();

  mruby::MRubyContext *get_mruby_context() const;
#endif // HAVE_MRUBY

  std::vector<std::shared_ptr<DownstreamAddrGroup>> &
  get_downstream_addr_groups();

  ConnectBlocker *get_connect_blocker() const;

  const DownstreamConfig *get_downstream_config() const;

  void
  replace_downstream_config(std::shared_ptr<DownstreamConfig> downstreamconf);

  ConnectionHandler *get_connection_handler() const;

  DNSTracker *get_dns_tracker();

private:
#ifndef NOTHREADS
  std::future<void> fut_;
#endif // NOTHREADS
  std::mutex m_;
  std::deque<WorkerEvent> q_;
  std::mt19937 randgen_;
  ev_async w_;
  ev_timer mcpool_clear_timer_;
  ev_timer proc_wev_timer_;
  MemchunkPool mcpool_;
  WorkerStat worker_stat_;
  DNSTracker dns_tracker_;

  std::shared_ptr<DownstreamConfig> downstreamconf_;
  std::unique_ptr<MemcachedDispatcher> session_cache_memcached_dispatcher_;
#ifdef HAVE_MRUBY
  std::unique_ptr<mruby::MRubyContext> mruby_ctx_;
#endif // HAVE_MRUBY
  struct ev_loop *loop_;

  // Following fields are shared across threads if
  // get_config()->tls_ctx_per_worker == true.
  SSL_CTX *sv_ssl_ctx_;
  SSL_CTX *cl_ssl_ctx_;
  tls::CertLookupTree *cert_tree_;
  ConnectionHandler *conn_handler_;

#ifndef HAVE_ATOMIC_STD_SHARED_PTR
  std::mutex ticket_keys_m_;
#endif // !HAVE_ATOMIC_STD_SHARED_PTR
  std::shared_ptr<TicketKeys> ticket_keys_;
  std::vector<std::shared_ptr<DownstreamAddrGroup>> downstream_addr_groups_;
  // Worker level blocker for downstream connection.  For example,
  // this is used when file decriptor is exhausted.
  std::unique_ptr<ConnectBlocker> connect_blocker_;

  bool graceful_shutdown_;
};

// Selects group based on request's |hostport| and |path|.  |hostport|
// is the value taken from :authority or host header field, and may
// contain port.  The |path| may contain query part.  We require the
// catch-all pattern in place, so this function always selects one
// group.  The catch-all group index is given in |catch_all|.  All
// patterns are given in |groups|.
size_t match_downstream_addr_group(
    const RouterConfig &routerconfig, const StringRef &hostport,
    const StringRef &path,
    const std::vector<std::shared_ptr<DownstreamAddrGroup>> &groups,
    size_t catch_all, BlockAllocator &balloc);

// Calls this function if connecting to backend failed.  |raddr| is
// the actual address used to connect to backend, and it could be
// nullptr.  This function may schedule live check.
void downstream_failure(DownstreamAddr *addr, const Address *raddr);

} // namespace shrpx

#endif // SHRPX_WORKER_H
