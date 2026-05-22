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
#ifndef SHRPX_HTTP_DOWNSTREAM_CONNECTION_H
#define SHRPX_HTTP_DOWNSTREAM_CONNECTION_H

#include "shrpx.h"

#include "llhttp.h"

#include "shrpx_downstream_connection.h"
#include "shrpx_io_control.h"
#include "shrpx_connection.h"

namespace shrpx {

class DownstreamConnectionPool;
class Worker;
struct DownstreamAddrGroup;
struct DownstreamAddr;
struct DNSQuery;

class HttpDownstreamConnection : public DownstreamConnection {
public:
  HttpDownstreamConnection(const std::shared_ptr<DownstreamAddrGroup> &group,
                           DownstreamAddr *addr, struct ev_loop *loop,
                           Worker *worker);
  ~HttpDownstreamConnection() override;
  std::expected<void, Error> attach_downstream(Downstream *downstream) override;
  void detach_downstream(Downstream *downstream) override;

  std::expected<void, Error> push_request_headers() override;
  std::expected<void, Error>
  push_upload_data_chunk(std::span<const uint8_t> data) override;
  std::expected<void, Error> end_upload_data() override;
  void end_upload_data_chunk();

  void pause_read(IOCtrlReason reason) override;
  std::expected<void, Error> resume_read(IOCtrlReason reason,
                                         size_t consumed) override;
  void force_resume_read() override;

  std::expected<void, Error> on_read() override;
  std::expected<void, Error> on_write() override;

  void on_upstream_change(Upstream *upstream) override;

  bool poolable() const override;

  const std::shared_ptr<DownstreamAddrGroup> &
  get_downstream_addr_group() const override;
  DownstreamAddr *get_addr() const override;

  std::expected<void, Error> initiate_connection();

  std::expected<void, Error> write_first();
  std::expected<void, Error> read_clear();
  std::expected<void, Error> write_clear();
  std::expected<void, Error> read_tls();
  std::expected<void, Error> write_tls();

  std::expected<void, Error> process_input(std::span<const uint8_t> data);
  std::expected<void, Error> tls_handshake();

  std::expected<void, Error> connected();
  void signal_write();
  void actual_signal_write();

  // Returns address used to connect to backend.  Could be nullptr.
  const Address *get_raddr() const;

  std::expected<void, Error> noop() { return {}; }
  void void_noop() {}

  void process_blocked_request_buf();
  void process_blocked_request_buf_on_response();
  bool should_unblock_request_body_before_response() const;
  bool should_block_request_body() const;

private:
  Connection conn_;
  std::function<std::expected<void, Error>(HttpDownstreamConnection &)>
    on_read_{&HttpDownstreamConnection::noop},
    on_write_{&HttpDownstreamConnection::noop};
  std::function<void(HttpDownstreamConnection &)> signal_write_{
    &HttpDownstreamConnection::void_noop};
  Worker *worker_;
  // nullptr if TLS is not used.
  SSL_CTX *ssl_ctx_;
  std::shared_ptr<DownstreamAddrGroup> group_;
  // Address of remote endpoint
  DownstreamAddr *addr_;
  // Actual remote address used to contact backend.  This is initially
  // nullptr, and may point to either &addr_->addr, or
  // resolved_addr_.get().
  const Address *raddr_{};
  // Resolved IP address if dns parameter is used
  std::unique_ptr<Address> resolved_addr_;
  std::unique_ptr<DNSQuery> dns_query_;
  IOControl ioctrl_{&conn_.rlimit};
  llhttp_t response_htp_{};
  // true if first write succeeded.
  bool first_write_done_{};
  // true if this object can be reused
  bool reusable_{true};
  // true if request header is written to request buffer.
  bool request_header_written_{};
  // true if blocked request buffer has been processed.
  bool blocked_request_buf_processed_{};
};

} // namespace shrpx

#endif // !defined(SHRPX_HTTP_DOWNSTREAM_CONNECTION_H)
