/*
 * nghttp2 - HTTP/2 C Library
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
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif // HAVE_SYS_SOCKET_H
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif // HAVE_NETDB_H

#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <array>

#include <nghttp2/nghttp2.h>

#include <ev.h>

#include <openssl/ssl.h>

#include "http2.h"
#include "buffer.h"
#include "template.h"

using namespace nghttp2;

namespace h2load {

class Session;
struct Worker;

struct Config {
  std::vector<std::vector<nghttp2_nv>> nva;
  std::vector<std::vector<const char *>> nv;
  std::vector<std::string> h1reqs;
  std::vector<ev_tstamp> timings;
  nghttp2::Headers custom_headers;
  std::string scheme;
  std::string host;
  std::string ifile;
  std::string ciphers;
  // length of upload data
  int64_t data_length;
  addrinfo *addrs;
  size_t nreqs;
  size_t nclients;
  size_t nthreads;
  // The maximum number of concurrent streams per session.
  ssize_t max_concurrent_streams;
  size_t window_bits;
  size_t connection_window_bits;
  // rate at which connections should be made
  size_t rate;
  ev_tstamp rate_period;
  // amount of time to wait for activity on a given connection
  ev_tstamp conn_active_timeout;
  // amount of time to wait after the last request is made on a connection
  ev_tstamp conn_inactivity_timeout;
  enum {
    PROTO_HTTP2,
    PROTO_SPDY2,
    PROTO_SPDY3,
    PROTO_SPDY3_1,
    PROTO_HTTP1_1
  } no_tls_proto;
  // file descriptor for upload data
  int data_fd;
  uint16_t port;
  uint16_t default_port;
  bool verbose;
  bool timing_script;
  std::string base_uri;
  // list of supported NPN/ALPN protocol strings in the order of
  // preference.
  std::vector<std::string> npn_list;

  Config();
  ~Config();

  bool is_rate_mode() const;
  bool has_base_uri() const;
};

struct RequestStat {
  RequestStat();
  // time point when request was sent
  std::chrono::steady_clock::time_point request_time;
  // time point when stream was closed
  std::chrono::steady_clock::time_point stream_close_time;
  // upload data length sent so far
  int64_t data_offset;
  // true if stream was successfully closed.  This means stream was
  // not reset, but it does not mean HTTP level error (e.g., 404).
  bool completed;
};

template <typename Duration> struct TimeStat {
  // min, max, mean and sd (standard deviation)
  Duration min, max, mean, sd;
  // percentage of samples inside mean -/+ sd
  double within_sd;
};

struct TimeStats {
  // time for request
  TimeStat<std::chrono::microseconds> request;
  // time for connect
  TimeStat<std::chrono::microseconds> connect;
  // time to first byte (TTFB)
  TimeStat<std::chrono::microseconds> ttfb;
};

enum TimeStatType { STAT_REQUEST, STAT_CONNECT, STAT_FIRST_BYTE };

struct Stats {
  Stats(size_t req_todo);
  // The total number of requests
  size_t req_todo;
  // The number of requests issued so far
  size_t req_started;
  // The number of requests finished
  size_t req_done;
  // The number of requests completed successfull, but not necessarily
  // means successful HTTP status code.
  size_t req_success;
  // The number of requests marked as success.  HTTP status code is
  // also considered as success. This is subset of req_done.
  size_t req_status_success;
  // The number of requests failed. This is subset of req_done.
  size_t req_failed;
  // The number of requests failed due to network errors. This is
  // subset of req_failed.
  size_t req_error;
  // The number of requests that failed due to timeout.
  size_t req_timedout;
  // The number of bytes received on the "wire". If SSL/TLS is used,
  // this is the number of decrypted bytes the application received.
  int64_t bytes_total;
  // The number of bytes received for header fields.  This is
  // compressed version.
  int64_t bytes_head;
  // The number of bytes received for header fields after they are
  // decompressed.
  int64_t bytes_head_decomp;
  // The number of bytes received in DATA frame.
  int64_t bytes_body;
  // The number of each HTTP status category, status[i] is status code
  // in the range [i*100, (i+1)*100).
  std::array<size_t, 6> status;
  // The statistics per request
  std::vector<RequestStat> req_stats;
  // time connect starts
  std::vector<std::chrono::steady_clock::time_point> start_times;
  // time to connect
  std::vector<std::chrono::steady_clock::time_point> connect_times;
  // time to first byte (TTFB)
  std::vector<std::chrono::steady_clock::time_point> ttfbs;
};

enum ClientState { CLIENT_IDLE, CLIENT_CONNECTED };

struct Client;

struct Worker {
  std::vector<std::unique_ptr<Client>> clients;
  Stats stats;
  struct ev_loop *loop;
  SSL_CTX *ssl_ctx;
  Config *config;
  size_t progress_interval;
  uint32_t id;
  bool tls_info_report_done;
  bool app_info_report_done;
  size_t nconns_made;
  // number of clients this worker handles
  size_t nclients;
  // number of requests each client issues
  size_t nreqs_per_client;
  // at most nreqs_rem clients get an extra request
  size_t nreqs_rem;
  size_t rate;
  ev_timer timeout_watcher;

  Worker(uint32_t id, SSL_CTX *ssl_ctx, size_t nreq_todo, size_t nclients,
         size_t rate, Config *config);
  ~Worker();
  Worker(Worker &&o) = default;
  void run();
};

struct Stream {
  int status_success;
  Stream();
};

struct Client {
  std::unordered_map<int32_t, Stream> streams;
  std::unique_ptr<Session> session;
  ev_io wev;
  ev_io rev;
  std::function<int(Client &)> readfn, writefn;
  Worker *worker;
  SSL *ssl;
  ev_timer request_timeout_watcher;
  addrinfo *next_addr;
  // Address for the current address.  When try_new_connection() is
  // used and current_addr is not nullptr, it is used instead of
  // trying next address though next_addr.  To try new address, set
  // nullptr to current_addr before calling connect().
  addrinfo *current_addr;
  size_t reqidx;
  ClientState state;
  bool first_byte_received;
  // The number of requests this client has to issue.
  size_t req_todo;
  // The number of requests this client has issued so far.
  size_t req_started;
  // The number of requests this client has done so far.
  size_t req_done;
  int fd;
  Buffer<64_k> wb;
  ev_timer conn_active_watcher;
  ev_timer conn_inactivity_watcher;
  std::string selected_proto;
  bool new_connection_requested;

  enum { ERR_CONNECT_FAIL = -100 };

  Client(Worker *worker, size_t req_todo);
  ~Client();
  int make_socket(addrinfo *addr);
  int connect();
  void disconnect();
  void fail();
  void timeout();
  void restart_timeout();
  int submit_request();
  void process_request_failure();
  void process_timedout_streams();
  void process_abandoned_streams();
  void report_progress();
  void report_tls_info();
  void report_app_info();
  void terminate_session();
  // Asks client to create new connection, instead of just fail.
  void try_new_connection();

  int do_read();
  int do_write();

  // low-level I/O callback functions called by do_read/do_write
  int connected();
  int read_clear();
  int write_clear();
  int tls_handshake();
  int read_tls();
  int write_tls();

  int on_read(const uint8_t *data, size_t len);
  int on_write();

  int connection_made();

  void on_request(int32_t stream_id);
  void on_header(int32_t stream_id, const uint8_t *name, size_t namelen,
                 const uint8_t *value, size_t valuelen);
  void on_status_code(int32_t stream_id, uint16_t status);
  // |success| == true means that the request/response was exchanged
  // |successfully, but it does not mean response carried successful
  // |HTTP status code.
  void on_stream_close(int32_t stream_id, bool success, RequestStat *req_stat,
                       bool final = false);

  void record_request_time(RequestStat *req_stat);
  void record_start_time(Stats *stat);
  void record_connect_time(Stats *stat);
  void record_ttfb();

  void signal_write();
};

} // namespace h2load

#endif // H2LOAD_H
