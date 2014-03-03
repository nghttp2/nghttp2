/*
 * nghttp2 - HTTP/2.0 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
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
#ifndef H2LOAD_H
#define H2LOAD_H

#include "nghttp2_config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <vector>
#include <string>
#include <unordered_map>
#include <memory>

#include <nghttp2/nghttp2.h>

#include <event.h>
#include <event2/event.h>

#include <openssl/ssl.h>

namespace h2load {

class Session;

struct Config {
  std::vector<nghttp2_nv> nva;
  std::vector<const char*> nv;
  std::string scheme;
  std::string host;
  std::string path;
  addrinfo *addrs;
  size_t nreqs;
  size_t nclients;
  size_t nthreads;
  // The maximum number of concurrent streams per session.
  size_t max_concurrent_streams;
  size_t window_bits;
  size_t connection_window_bits;
  uint16_t port;
  bool verbose;

  Config();
  ~Config();
};

struct Stats {
  // The total number of requests
  size_t req_todo;
  // The number of requests issued so far
  size_t req_started;
  // The number of requests finished
  size_t req_done;
  // The number of requests marked as success. This is subset of
  // req_done.
  size_t req_success;
  // The number of requests failed. This is subset of req_done.
  size_t req_failed;
  // The number of requests failed due to network errors. This is
  // subset of req_failed.
  size_t req_error;
  // The number of bytes received on the "wire". If SSL/TLS is used,
  // this is the number of decrypted bytes the application received.
  int64_t bytes_total;
  // The number of bytes received in HEADERS frame payload.
  int64_t bytes_head;
  // The number of bytes received in DATA frame.
  int64_t bytes_body;
  // The number of each HTTP status category, status[i] is status code
  // in the range [i*100, (i+1)*100).
  size_t status[6];
};

enum ClientState {
  CLIENT_IDLE,
  CLIENT_CONNECTED
};

struct Client;

struct Worker {
  std::vector<std::unique_ptr<Client>> clients;
  Stats stats;
  event_base *evbase;
  SSL_CTX *ssl_ctx;
  Config *config;
  size_t progress_interval;
  uint32_t id;
  bool term_timer_started;

  Worker(uint32_t id, SSL_CTX *ssl_ctx, size_t nreq_todo, size_t nclients,
         Config *config);
  ~Worker();
  void run();
  void schedule_terminate();
  void terminate_session();
};

struct Stream {
  int status_success;
  Stream();
};

struct Client {
  std::unordered_map<int32_t, Stream> streams;
  std::unique_ptr<Session> session;
  Worker *worker;
  SSL *ssl;
  bufferevent *bev;
  addrinfo *next_addr;
  ClientState state;

  Client(Worker *worker);
  ~Client();
  int connect();
  void disconnect();
  void submit_request();
  void process_abandoned_streams();
  void report_progress();
  void terminate_session();
  int on_connect();
  int on_read();
  int on_write();
  void on_request(int32_t stream_id);
  void on_header(int32_t stream_id,
                 const uint8_t *name, size_t namelen,
                 const uint8_t *value, size_t valuelen);
  void on_stream_close(int32_t stream_id, bool success);
};

} // namespace h2load

#endif // H2LOAD_H
