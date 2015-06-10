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
#include <sys/socket.h>
#endif // HAVE_SYS_SOCKET_H

#include <memory>
#include <vector>

#include <openssl/ssl.h>

#include <ev.h>

#include "shrpx_downstream_connection_pool.h"

namespace shrpx {

class Http2Session;
class ConnectBlocker;
class AcceptHandler;
class Worker;
struct WorkerStat;
struct TicketKeys;

struct OCSPUpdateContext {
  // ocsp response buffer
  std::vector<uint8_t> resp;
  // index to ConnectionHandler::all_ssl_ctx_, which points to next
  // SSL_CTX to update ocsp response cache.
  size_t next;
  ev_child chldev;
  ev_io rev;
  // fd to read response from fetch-ocsp-response script
  int fd;
  // errno encountered while processing response
  int error;
  // pid of forked fetch-ocsp-response script process
  pid_t pid;
};

class ConnectionHandler {
public:
  ConnectionHandler(struct ev_loop *loop);
  ~ConnectionHandler();
  int handle_connection(int fd, sockaddr *addr, int addrlen);
  // Creates Worker object for single threaded configuration.
  void create_single_worker();
  // Creates |num| Worker objects for multi threaded configuration.
  // The |num| must be strictly more than 1.
  void create_worker_thread(size_t num);
  void worker_reopen_log_files();
  void worker_renew_ticket_keys(const std::shared_ptr<TicketKeys> &ticket_keys);
  void set_ticket_keys(std::shared_ptr<TicketKeys> ticket_keys);
  const std::shared_ptr<TicketKeys> &get_ticket_keys() const;
  struct ev_loop *get_loop() const;
  Worker *get_single_worker() const;
  void set_acceptor(std::unique_ptr<AcceptHandler> h);
  AcceptHandler *get_acceptor() const;
  void set_acceptor6(std::unique_ptr<AcceptHandler> h);
  AcceptHandler *get_acceptor6() const;
  void enable_acceptor();
  void disable_acceptor();
  void disable_acceptor_temporary(ev_tstamp t);
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

private:
  // Stores all SSL_CTX objects.
  std::vector<SSL_CTX *> all_ssl_ctx_;
  OCSPUpdateContext ocsp_;
  // Worker instances when multi threaded mode (-nN, N >= 2) is used.
  std::vector<std::unique_ptr<Worker>> workers_;
  // Worker instance used when single threaded mode (-n1) is used.
  // Otherwise, nullptr and workers_ has instances of Worker instead.
  std::unique_ptr<Worker> single_worker_;
  // Current TLS session ticket keys.  Note that TLS connection does
  // not refer to this field directly.  They use TicketKeys object in
  // Worker object.
  std::shared_ptr<TicketKeys> ticket_keys_;
  struct ev_loop *loop_;
  // acceptor for IPv4 address or UNIX domain socket.
  std::unique_ptr<AcceptHandler> acceptor_;
  // acceptor for IPv6 address
  std::unique_ptr<AcceptHandler> acceptor6_;
  ev_timer disable_acceptor_timer_;
  ev_timer ocsp_timer_;
  unsigned int worker_round_robin_cnt_;
  bool graceful_shutdown_;
};

} // namespace shrpx

#endif // SHRPX_CONNECTION_HANDLER_H
