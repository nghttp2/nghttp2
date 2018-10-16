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
#ifndef SHRPX_CONNECTION_HANDLER_H
#define SHRPX_CONNECTION_HANDLER_H

#include "shrpx.h"

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif // HAVE_SYS_SOCKET_H

#include <mutex>
#include <memory>
#include <vector>
#include <random>
#ifndef NOTHREADS
#  include <future>
#endif // NOTHREADS

#include <openssl/ssl.h>

#include <ev.h>

#ifdef HAVE_NEVERBLEED
#  include <neverbleed.h>
#endif // HAVE_NEVERBLEED

#include "shrpx_downstream_connection_pool.h"
#include "shrpx_config.h"
#include "shrpx_exec.h"

namespace shrpx {

class Http2Session;
class ConnectBlocker;
class AcceptHandler;
class Worker;
struct WorkerStat;
struct TicketKeys;
class MemcachedDispatcher;
struct UpstreamAddr;

namespace tls {

class CertLookupTree;

} // namespace tls

struct OCSPUpdateContext {
  // ocsp response buffer
  std::vector<uint8_t> resp;
  // Process running fetch-ocsp-response script
  Process proc;
  // index to ConnectionHandler::all_ssl_ctx_, which points to next
  // SSL_CTX to update ocsp response cache.
  size_t next;
  ev_child chldev;
  ev_io rev;
  // errno encountered while processing response
  int error;
};

// SerialEvent is an event sent from Worker thread.
enum class SerialEventType {
  NONE,
  REPLACE_DOWNSTREAM,
};

struct SerialEvent {
  // ctor for event uses DownstreamConfig
  SerialEvent(SerialEventType type,
              const std::shared_ptr<DownstreamConfig> &downstreamconf)
      : type(type), downstreamconf(downstreamconf) {}

  SerialEventType type;
  std::shared_ptr<DownstreamConfig> downstreamconf;
};

class ConnectionHandler {
public:
  ConnectionHandler(struct ev_loop *loop, std::mt19937 &gen);
  ~ConnectionHandler();
  int handle_connection(int fd, sockaddr *addr, int addrlen,
                        const UpstreamAddr *faddr);
  // Creates Worker object for single threaded configuration.
  int create_single_worker();
  // Creates |num| Worker objects for multi threaded configuration.
  // The |num| must be strictly more than 1.
  int create_worker_thread(size_t num);
  void
  set_ticket_keys_to_worker(const std::shared_ptr<TicketKeys> &ticket_keys);
  void worker_reopen_log_files();
  void set_ticket_keys(std::shared_ptr<TicketKeys> ticket_keys);
  const std::shared_ptr<TicketKeys> &get_ticket_keys() const;
  struct ev_loop *get_loop() const;
  Worker *get_single_worker() const;
  void add_acceptor(std::unique_ptr<AcceptHandler> h);
  void delete_acceptor();
  void enable_acceptor();
  void disable_acceptor();
  void sleep_acceptor(ev_tstamp t);
  void accept_pending_connection();
  void graceful_shutdown_worker();
  void set_graceful_shutdown(bool f);
  bool get_graceful_shutdown() const;
  void join_worker();

  // Cancels ocsp update process
  void cancel_ocsp_update();
  // Starts ocsp update for certficate |cert_file|.
  int start_ocsp_update(const char *cert_file);
  // Reads incoming data from ocsp update process
  void read_ocsp_chunk();
  // Handles the completion of one ocsp update
  void handle_ocsp_complete();
  // Resets ocsp_;
  void reset_ocsp();
  // Proceeds to the next certificate's ocsp update.  If all
  // certificates' ocsp update has been done, schedule next ocsp
  // update.
  void proceed_next_cert_ocsp();

  void set_tls_ticket_key_memcached_dispatcher(
      std::unique_ptr<MemcachedDispatcher> dispatcher);

  MemcachedDispatcher *get_tls_ticket_key_memcached_dispatcher() const;
  void on_tls_ticket_key_network_error(ev_timer *w);
  void on_tls_ticket_key_not_found(ev_timer *w);
  void
  on_tls_ticket_key_get_success(const std::shared_ptr<TicketKeys> &ticket_keys,
                                ev_timer *w);
  void schedule_next_tls_ticket_key_memcached_get(ev_timer *w);
  SSL_CTX *create_tls_ticket_key_memcached_ssl_ctx();
  // Returns the SSL_CTX at all_ssl_ctx_[idx].  This does not perform
  // array bound checking.
  SSL_CTX *get_ssl_ctx(size_t idx) const;

  const std::vector<SSL_CTX *> &get_indexed_ssl_ctx(size_t idx) const;

#ifdef HAVE_NEVERBLEED
  void set_neverbleed(neverbleed_t *nb);
#endif // HAVE_NEVERBLEED

  // Send SerialEvent SerialEventType::REPLACE_DOWNSTREAM to this
  // object.
  void send_replace_downstream(
      const std::shared_ptr<DownstreamConfig> &downstreamconf);
  // Internal function to send |ev| to this object.
  void send_serial_event(SerialEvent ev);
  // Handles SerialEvents received.
  void handle_serial_event();
  // Sends WorkerEvent to make them replace downstream.
  void
  worker_replace_downstream(std::shared_ptr<DownstreamConfig> downstreamconf);

  void set_enable_acceptor_on_ocsp_completion(bool f);

private:
  // Stores all SSL_CTX objects.
  std::vector<SSL_CTX *> all_ssl_ctx_;
  // Stores all SSL_CTX objects in a way that its index is stored in
  // cert_tree.  The SSL_CTXs stored in the same index share the same
  // hostname, but could have different signature algorithm.  The
  // selection among them are performed by hostname presented by SNI,
  // and signature algorithm presented by client.
  std::vector<std::vector<SSL_CTX *>> indexed_ssl_ctx_;
  OCSPUpdateContext ocsp_;
  std::mt19937 &gen_;
  // ev_loop for each worker
  std::vector<struct ev_loop *> worker_loops_;
  // Worker instances when multi threaded mode (-nN, N >= 2) is used.
  // If at least one frontend enables API request, we allocate 1
  // additional worker dedicated to API request .
  std::vector<std::unique_ptr<Worker>> workers_;
  // mutex for serial event resive buffer handling
  std::mutex serial_event_mu_;
  // SerialEvent receive buffer
  std::vector<SerialEvent> serial_events_;
  // Worker instance used when single threaded mode (-n1) is used.
  // Otherwise, nullptr and workers_ has instances of Worker instead.
  std::unique_ptr<Worker> single_worker_;
  std::unique_ptr<tls::CertLookupTree> cert_tree_;
  std::unique_ptr<MemcachedDispatcher> tls_ticket_key_memcached_dispatcher_;
  // Current TLS session ticket keys.  Note that TLS connection does
  // not refer to this field directly.  They use TicketKeys object in
  // Worker object.
  std::shared_ptr<TicketKeys> ticket_keys_;
  struct ev_loop *loop_;
  std::vector<std::unique_ptr<AcceptHandler>> acceptors_;
#ifdef HAVE_NEVERBLEED
  neverbleed_t *nb_;
#endif // HAVE_NEVERBLEED
  ev_timer disable_acceptor_timer_;
  ev_timer ocsp_timer_;
  ev_async thread_join_asyncev_;
  ev_async serial_event_asyncev_;
#ifndef NOTHREADS
  std::future<void> thread_join_fut_;
#endif // NOTHREADS
  size_t tls_ticket_key_memcached_get_retry_count_;
  size_t tls_ticket_key_memcached_fail_count_;
  unsigned int worker_round_robin_cnt_;
  bool graceful_shutdown_;
  // true if acceptors should be enabled after the initial ocsp update
  // has finished.
  bool enable_acceptor_on_ocsp_completion_;
};

} // namespace shrpx

#endif // SHRPX_CONNECTION_HANDLER_H
