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
#ifndef SHRPX_HTTP2_SESSION_H
#define SHRPX_HTTP2_SESSION_H

#include "shrpx.h"

#include <unordered_set>
#include <memory>

#include <openssl/ssl.h>

#include <ev.h>

#include <nghttp2/nghttp2.h>

#include "http-parser/http_parser.h"

#include "shrpx_connection.h"
#include "buffer.h"
#include "template.h"

using namespace nghttp2;

namespace shrpx {

class Http2DownstreamConnection;
class Worker;
struct DownstreamAddrGroup;
struct DownstreamAddr;

struct StreamData {
  StreamData *dlnext, *dlprev;
  Http2DownstreamConnection *dconn;
};

enum FreelistZone {
  // Http2Session object is not linked in any freelist.
  FREELIST_ZONE_NONE,
  // Http2Session object is linked in group scope
  // http2_avail_freelist.
  FREELIST_ZONE_AVAIL,
  // Http2Session object is linked in address scope
  // http2_extra_freelist.
  FREELIST_ZONE_EXTRA,
  // Http2Session object is about to be deleted, and it does not
  // belong to any linked list.
  FREELIST_ZONE_GONE
};

class Http2Session {
public:
  Http2Session(struct ev_loop *loop, SSL_CTX *ssl_ctx, Worker *worker,
               const std::shared_ptr<DownstreamAddrGroup> &group,
               DownstreamAddr *addr);
  ~Http2Session();

  // If hard is true, all pending requests are abandoned and
  // associated ClientHandlers will be deleted.
  int disconnect(bool hard = false);
  int initiate_connection();

  void add_downstream_connection(Http2DownstreamConnection *dconn);
  void remove_downstream_connection(Http2DownstreamConnection *dconn);

  void remove_stream_data(StreamData *sd);

  int submit_request(Http2DownstreamConnection *dconn, const nghttp2_nv *nva,
                     size_t nvlen, const nghttp2_data_provider *data_prd);

  int submit_rst_stream(int32_t stream_id, uint32_t error_code);

  int terminate_session(uint32_t error_code);

  nghttp2_session *get_session() const;

  int resume_data(Http2DownstreamConnection *dconn);

  int connection_made();

  int do_read();
  int do_write();

  int on_read(const uint8_t *data, size_t datalen);
  int on_write();

  int connected();
  int read_clear();
  int write_clear();
  int tls_handshake();
  int read_tls();
  int write_tls();

  int downstream_read_proxy(const uint8_t *data, size_t datalen);
  int downstream_connect_proxy();

  int downstream_read(const uint8_t *data, size_t datalen);
  int downstream_write();

  int noop();
  int read_noop(const uint8_t *data, size_t datalen);
  int write_noop();

  void signal_write();

  struct ev_loop *get_loop() const;

  ev_io *get_wev();

  int get_state() const;
  void set_state(int state);

  void start_settings_timer();
  void stop_settings_timer();

  SSL *get_ssl() const;

  int consume(int32_t stream_id, size_t len);

  // Returns true if request can be issued on downstream connection.
  bool can_push_request() const;
  // Initiates the connection checking if downstream connection has
  // been established and connection checking is required.
  void start_checking_connection();
  // Resets connection check timer to timeout |t|.  After timeout, we
  // require connection checking.  If connection checking is already
  // enabled, this timeout is for PING ACK timeout.
  void reset_connection_check_timer(ev_tstamp t);
  void reset_connection_check_timer_if_not_checking();
  // Signals that connection is alive.  Internally
  // reset_connection_check_timer() is called.
  void connection_alive();
  // Change connection check state.
  void set_connection_check_state(int state);
  int get_connection_check_state() const;

  bool should_hard_fail() const;

  void submit_pending_requests();

  DownstreamAddr *get_addr() const;

  const std::shared_ptr<DownstreamAddrGroup> &get_downstream_addr_group() const;

  int handle_downstream_push_promise(Downstream *downstream,
                                     int32_t promised_stream_id);
  int handle_downstream_push_promise_complete(Downstream *downstream,
                                              Downstream *promised_downstream);

  // Returns number of downstream connections, including pushed
  // streams.
  size_t get_num_dconns() const;

  // Adds to group scope http2_avail_freelist.
  void add_to_avail_freelist();
  // Adds to address scope http2_extra_freelist.
  void add_to_extra_freelist();

  // Removes this object from any freelist.  If this object is not
  // linked from any freelist, this function does nothing.
  void remove_from_freelist();

  // Removes this object form any freelist, and marks this object as
  // not schedulable.
  void exclude_from_scheduling();

  // Returns true if the maximum concurrency is reached.  In other
  // words, the number of currently participated streams in this
  // session is equal or greater than the max concurrent streams limit
  // advertised by server.  If |extra| is nonzero, it is added to the
  // number of current concurrent streams when comparing against
  // server initiated concurrency limit.
  bool max_concurrency_reached(size_t extra = 0) const;

  DefaultMemchunks *get_request_buf();

  void on_timeout();

  // This is called periodically using ev_prepare watcher, and if
  // group_ is retired (backend has been replaced), send GOAWAY to
  // shutdown the connection.
  void check_retire();

  void repeat_read_timer();
  void stop_read_timer();

  enum {
    // Disconnected
    DISCONNECTED,
    // Connecting proxy and making CONNECT request
    PROXY_CONNECTING,
    // Tunnel is established with proxy
    PROXY_CONNECTED,
    // Establishing tunnel is failed
    PROXY_FAILED,
    // Connecting to downstream and/or performing SSL/TLS handshake
    CONNECTING,
    // Connected to downstream
    CONNECTED,
    // Connection is started to fail
    CONNECT_FAILING,
  };

  enum {
    // Connection checking is not required
    CONNECTION_CHECK_NONE,
    // Connection checking is required
    CONNECTION_CHECK_REQUIRED,
    // Connection checking has been started
    CONNECTION_CHECK_STARTED
  };

  using ReadBuf = Buffer<8_k>;

  Http2Session *dlnext, *dlprev;

private:
  Connection conn_;
  DefaultMemchunks wb_;
  ev_timer settings_timer_;
  // This timer has 2 purpose: when it first timeout, set
  // connection_check_state_ = CONNECTION_CHECK_REQUIRED.  After
  // connection check has started, this timer is started again and
  // traps PING ACK timeout.
  ev_timer connchk_timer_;
  // timer to initiate connection.  usually, this fires immediately.
  ev_timer initiate_connection_timer_;
  ev_prepare prep_;
  DList<Http2DownstreamConnection> dconns_;
  DList<StreamData> streams_;
  std::function<int(Http2Session &)> read_, write_;
  std::function<int(Http2Session &, const uint8_t *, size_t)> on_read_;
  std::function<int(Http2Session &)> on_write_;
  // Used to parse the response from HTTP proxy
  std::unique_ptr<http_parser> proxy_htp_;
  Worker *worker_;
  // NULL if no TLS is configured
  SSL_CTX *ssl_ctx_;
  std::shared_ptr<DownstreamAddrGroup> group_;
  // Address of remote endpoint
  DownstreamAddr *addr_;
  nghttp2_session *session_;
  int state_;
  int connection_check_state_;
  int freelist_zone_;
};

nghttp2_session_callbacks *create_http2_downstream_callbacks();

} // namespace shrpx

#endif // SHRPX_HTTP2_SESSION_H
