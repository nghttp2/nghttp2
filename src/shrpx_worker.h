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

using namespace nghttp2;

namespace shrpx {

class Http2Session;
class ConnectBlocker;
class MemcachedDispatcher;
struct UpstreamAddr;

#ifdef HAVE_MRUBY
namespace mruby {

class MRubyContext;

} // namespace mruby
#endif // HAVE_MRUBY

namespace ssl {
class CertLookupTree;
} // namespace ssl

struct DownstreamAddr {
  Address addr;
  // backend address.  If |host_unix| is true, this is UNIX domain
  // socket path.
  ImmutableString host;
  ImmutableString hostport;
  // backend port.  0 if |host_unix| is true.
  uint16_t port;
  // true if |host| contains UNIX domain socket path.
  bool host_unix;

  std::unique_ptr<ConnectBlocker> connect_blocker;
  // Client side TLS session cache
  TLSSessionCache tls_session_cache;
};

struct SharedDownstreamAddr {
  std::vector<DownstreamAddr> addrs;
  // Application protocol used in this group
  shrpx_proto proto;
  // List of Http2Session which is not fully utilized (i.e., the
  // server advertized maximum concurrency is not reached).  We will
  // coalesce as much stream as possible in one Http2Session to fully
  // utilize TCP connection.
  //
  // TODO Verify that this approach performs better in performance
  // wise.
  DList<Http2Session> http2_freelist;
  DownstreamConnectionPool dconn_pool;
  // Next downstream address index in addrs.
  size_t next;
};

struct DownstreamAddrGroup {
  ImmutableString pattern;
  std::shared_ptr<SharedDownstreamAddr> shared_addr;
};

struct WorkerStat {
  size_t num_connections;
};

enum WorkerEventType {
  NEW_CONNECTION = 0x01,
  REOPEN_LOG = 0x02,
  GRACEFUL_SHUTDOWN = 0x03,
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
};

class Worker {
public:
  Worker(struct ev_loop *loop, SSL_CTX *sv_ssl_ctx, SSL_CTX *cl_ssl_ctx,
         SSL_CTX *tls_session_cache_memcached_ssl_ctx,
         ssl::CertLookupTree *cert_tree,
         const std::shared_ptr<TicketKeys> &ticket_keys);
  ~Worker();
  void run_async();
  void wait();
  void process_events();
  void send(const WorkerEvent &event);

  ssl::CertLookupTree *get_cert_lookup_tree() const;

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

  std::vector<DownstreamAddrGroup> &get_downstream_addr_groups();

  ConnectBlocker *get_connect_blocker() const;

private:
#ifndef NOTHREADS
  std::future<void> fut_;
#endif // NOTHREADS
  std::mutex m_;
  std::vector<WorkerEvent> q_;
  std::mt19937 randgen_;
  ev_async w_;
  ev_timer mcpool_clear_timer_;
  MemchunkPool mcpool_;
  WorkerStat worker_stat_;

  std::unique_ptr<MemcachedDispatcher> session_cache_memcached_dispatcher_;
#ifdef HAVE_MRUBY
  std::unique_ptr<mruby::MRubyContext> mruby_ctx_;
#endif // HAVE_MRUBY
  struct ev_loop *loop_;

  // Following fields are shared across threads if
  // get_config()->tls_ctx_per_worker == true.
  SSL_CTX *sv_ssl_ctx_;
  SSL_CTX *cl_ssl_ctx_;
  ssl::CertLookupTree *cert_tree_;

  std::shared_ptr<TicketKeys> ticket_keys_;
  std::vector<DownstreamAddrGroup> downstream_addr_groups_;
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
    const Router &router, const std::vector<WildcardPattern> &wildcard_patterns,
    const StringRef &hostport, const StringRef &path,
    const std::vector<DownstreamAddrGroup> &groups, size_t catch_all);

} // namespace shrpx

#endif // SHRPX_WORKER_H
