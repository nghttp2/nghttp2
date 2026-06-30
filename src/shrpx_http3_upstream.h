/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2021 Tatsuhiro Tsujikawa
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
#ifndef SHRPX_HTTP3_UPSTREAM_H
#define SHRPX_HTTP3_UPSTREAM_H

#include "shrpx.h"

#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

#include "shrpx_upstream.h"
#include "shrpx_downstream_queue.h"
#include "network.h"
#include "ssl_compat.h"

#if defined(ENABLE_HTTP3) && OPENSSL_3_5_0_API
#  include <ngtcp2/ngtcp2_crypto_ossl.h>
#endif // defined(ENABLE_HTTP3) && OPENSSL_3_5_0_API

using namespace nghttp2;

namespace shrpx {

struct UpstreamAddr;

class Http3Upstream : public Upstream {
public:
  Http3Upstream(ClientHandler *handler);
  ~Http3Upstream() override;

  std::expected<void, Error> on_read() override { return {}; }
  std::expected<void, Error> on_write() override;
  std::expected<void, Error> on_timeout(Downstream *downstream) override;
  std::expected<void, Error>
  on_downstream_abort_request(Downstream *downstream,
                              unsigned int status_code) override;
  std::expected<void, Error> on_downstream_abort_request_with_https_redirect(
    Downstream *downstream) override;
  std::expected<void, Error>
  downstream_read(DownstreamConnection *dconn) override;
  std::expected<void, Error>
  downstream_write(DownstreamConnection *dconn) override;
  std::expected<void, Error>
  downstream_eof(DownstreamConnection *dconn) override;
  std::expected<void, Error> downstream_error(DownstreamConnection *dconn,
                                              int events) override;
  ClientHandler *get_client_handler() const override;

  std::expected<void, Error>
  on_downstream_header_complete(Downstream *downstream) override;
  std::expected<void, Error> on_downstream_body(Downstream *downstream,
                                                std::span<const uint8_t> data,
                                                bool flush) override;
  std::expected<void, Error>
  on_downstream_body_complete(Downstream *downstream) override;

  void on_handler_delete() override;
  std::expected<void, Error> on_downstream_reset(Downstream *downstream,
                                                 bool no_retry) override;

  void pause_read(IOCtrlReason reason) override;
  std::expected<void, Error> resume_read(IOCtrlReason reason,
                                         Downstream *downstream,
                                         size_t consumed) override;
  std::expected<void, Error> send_reply(Downstream *downstream,
                                        std::span<const uint8_t> body) override;

  std::expected<void, Error> initiate_push(Downstream *downstream,
                                           std::string_view uri) override {
    return {};
  }

  std::span<struct iovec>
  response_riovec(std::span<struct iovec> iov) const override;
  std::span<const uint8_t> response_peek() const override;
  void response_drain(size_t n) override;
  bool response_empty() const override;

  Downstream *on_downstream_push_promise(Downstream *downstream,
                                         int32_t promised_stream_id) override;
  std::expected<void, Error> on_downstream_push_promise_complete(
    Downstream *downstream, Downstream *promised_downstream) override {
    return {};
  }
  bool push_enabled() const override;
  void cancel_premature_downstream(Downstream *promised_downstream) override;

  std::expected<void, Error>
  init(const UpstreamAddr *faddr, const Address &remote_addr,
       const Address &local_addr, const ngtcp2_pkt_hd &initial_hd,
       const ngtcp2_cid *odcid, std::span<const uint8_t> token,
       ngtcp2_token_type token_type);

  std::expected<void, Error> on_read(const UpstreamAddr *faddr,
                                     const Address &remote_addr,
                                     const Address &local_addr,
                                     const ngtcp2_pkt_info &pi,
                                     std::span<const uint8_t> data);

  std::expected<void, Error> write_streams();
  ngtcp2_ssize write_pkt(ngtcp2_path *path, ngtcp2_pkt_info *pi, uint8_t *dest,
                         size_t destlen, ngtcp2_tstamp ts);

  std::expected<void, Error> handle_error();
  std::expected<void, Error> send_connection_close(const ngtcp2_ccerr &ccerr);

  std::expected<void, Error> handle_expiry();
  void reset_timer();

  std::expected<void, Error> setup_httpconn();
  void add_pending_downstream(std::unique_ptr<Downstream> downstream);
  std::expected<void, Error> recv_stream_data(uint32_t flags, int64_t stream_id,
                                              std::span<const uint8_t> data);
  std::expected<void, Error> acked_stream_data_offset(int64_t stream_id,
                                                      uint64_t datalen);
  std::expected<void, Error> extend_max_stream_data(int64_t stream_id);
  void extend_max_remote_streams_bidi(uint64_t max_streams);
  std::expected<void, Error> stream_close(int64_t stream_id,
                                          uint64_t app_error_code);
  std::expected<void, Error> http_shutdown_stream_read(int64_t stream_id);
  std::expected<void, Error> handshake_completed();
  std::expected<void, Error> error_reply(Downstream *downstream,
                                         unsigned int status_code);
  void http_begin_request_headers(int64_t stream_id);
  std::expected<void, Error>
  http_recv_request_header(Downstream *downstream, int32_t token,
                           nghttp3_rcbuf *name, nghttp3_rcbuf *value,
                           uint8_t flags, bool trailer);
  std::expected<void, Error> http_end_request_headers(Downstream *downstream,
                                                      int fin);
  std::expected<void, Error> http_end_stream(Downstream *downstream);
  std::expected<void, Error> http_stream_close(Downstream *downstream,
                                               uint64_t app_error_code);
  std::expected<void, Error> http_acked_stream_data(Downstream *downstream,
                                                    uint64_t datalen);
  std::expected<void, Error> http_reset_stream(int64_t stream_id,
                                               uint64_t app_error_code);
  std::expected<void, Error> http_stop_sending(int64_t stream_id,
                                               uint64_t app_error_code);
  std::expected<void, Error> http_recv_data(Downstream *downstream,
                                            std::span<const uint8_t> data);
  std::expected<void, Error> start_downstream(Downstream *downstream);
  std::expected<void, Error> initiate_downstream(Downstream *downstream);
  std::expected<void, Error> shutdown_stream(Downstream *downstream,
                                             uint64_t app_error_code);
  std::expected<void, Error> shutdown_stream_read(int64_t stream_id,
                                                  uint64_t app_error_code);
  void consume(int64_t stream_id, size_t nconsumed);
  std::expected<void, Error> remove_downstream(Downstream *downstream);
  void log_response_headers(Downstream *downstream,
                            const std::vector<nghttp3_nv> &nva) const;
  std::expected<void, Error> check_shutdown();
  std::expected<void, Error> start_graceful_shutdown();
  std::expected<void, Error> submit_goaway();
  // send_packet sends packet(s).  If send is blocked, this function
  // returns the packet(s) that are not yet sent.  This function
  // returns empty span if all packet(s) are sent.
  std::span<const uint8_t>
  send_packet(const UpstreamAddr *faddr, const sockaddr *remote_sa,
              socklen_t remote_salen, const sockaddr *local_sa,
              socklen_t local_salen, const ngtcp2_pkt_info &pi,
              std::span<const uint8_t> data, size_t gso_size);
  void send_packet(const ngtcp2_path &path, const ngtcp2_pkt_info &pi,
                   std::span<const uint8_t> data, size_t gso_size);

  void qlog_write(const void *data, size_t datalen, bool fin);
  std::expected<int, Error> open_qlog_file(std::string_view dir,
                                           const ngtcp2_cid &scid) const;

  void on_send_blocked(const ngtcp2_path &path, const ngtcp2_pkt_info &pi,
                       std::span<const uint8_t> data, size_t gso_size);
  void send_blocked_packet();
  void signal_write_upstream_addr(const UpstreamAddr *faddr);

  ngtcp2_conn *get_conn() const;

  std::expected<void, Error> send_new_token(const ngtcp2_addr *remote_addr);

  std::expected<size_t, Error> on_stream_write(int64_t stream_id,
                                               size_t datalen);

private:
  ClientHandler *handler_;
  ev_timer timer_;
  ev_timer shutdown_timer_;
  ev_prepare prep_;
  int qlog_fd_{-1};
  ngtcp2_cid hashed_scid_{};
  ngtcp2_conn *conn_{};
  ngtcp2_ccerr last_error_;
#if OPENSSL_3_5_0_API
  ngtcp2_crypto_ossl_ctx *ossl_ctx_{};
#endif // OPENSSL_3_5_0_API
  nghttp3_conn *httpconn_{};
  DownstreamQueue downstream_queue_;
  std::unique_ptr<uint8_t[]> conn_close_;
  size_t conn_closelen_{};

  struct {
    bool send_blocked;
    // blocked field is effective only when send_blocked is true.
    struct {
      const UpstreamAddr *faddr;
      Address local_addr;
      Address remote_addr;
      ngtcp2_pkt_info pi;
      std::span<const uint8_t> data;
      size_t gso_size;
    } blocked;
    bool no_gso{
#ifndef UDP_SEGMENT
      true
#endif // !defined(UDP_SEGMENT)
    };
  } tx_{};
  std::array<uint8_t, 64_k> txbuf_;
};

} // namespace shrpx

#endif // SHRPX_HTTP3_UPSTREAM_H
