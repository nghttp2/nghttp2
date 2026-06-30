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
#ifndef SHRPX_HTTP2_UPSTREAM_H
#define SHRPX_HTTP2_UPSTREAM_H

#include "shrpx.h"

#include <memory>

#include <ev.h>

#include <nghttp2/nghttp2.h>

#include "shrpx_upstream.h"
#include "shrpx_downstream_queue.h"
#include "memchunk.h"
#include "buffer.h"

using namespace nghttp2;

namespace shrpx {

class ClientHandler;
class HttpsUpstream;

inline constexpr size_t SHRPX_HTTP2_MAX_BUFFER_SIZE = 32_k;

class Http2Upstream : public Upstream {
public:
  Http2Upstream(ClientHandler *handler);
  ~Http2Upstream() override;
  std::expected<void, Error> on_read() override;
  std::expected<void, Error> on_write() override;
  std::expected<void, Error> on_timeout(Downstream *downstream) override;
  std::expected<void, Error>
  on_downstream_abort_request(Downstream *downstream,
                              unsigned int status_code) override;
  std::expected<void, Error> on_downstream_abort_request_with_https_redirect(
    Downstream *downstream) override;
  ClientHandler *get_client_handler() const override;

  std::expected<void, Error>
  downstream_read(DownstreamConnection *dconn) override;
  std::expected<void, Error>
  downstream_write(DownstreamConnection *dconn) override;
  std::expected<void, Error>
  downstream_eof(DownstreamConnection *dconn) override;
  std::expected<void, Error> downstream_error(DownstreamConnection *dconn,
                                              int events) override;

  void add_pending_downstream(std::unique_ptr<Downstream> downstream);
  std::expected<void, Error> remove_downstream(Downstream *downstream);

  std::expected<void, Error> rst_stream(Downstream *downstream,
                                        uint32_t error_code);
  std::expected<void, Error> terminate_session(uint32_t error_code);
  std::expected<void, Error> error_reply(Downstream *downstream,
                                         unsigned int status_code);

  void pause_read(IOCtrlReason reason) override;
  std::expected<void, Error> resume_read(IOCtrlReason reason,
                                         Downstream *downstream,
                                         size_t consumed) override;

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
  std::expected<void, Error> send_reply(Downstream *downstream,
                                        std::span<const uint8_t> body) override;
  std::expected<void, Error> initiate_push(Downstream *downstream,
                                           std::string_view uri) override;
  std::span<struct iovec>
  response_riovec(std::span<struct iovec> iov) const override;
  std::span<const uint8_t> response_peek() const override;
  void response_drain(size_t n) override;
  bool response_empty() const override;

  Downstream *on_downstream_push_promise(Downstream *downstream,
                                         int32_t promised_stream_id) override;
  std::expected<void, Error>
  on_downstream_push_promise_complete(Downstream *downstream,
                                      Downstream *promised_downstream) override;
  bool push_enabled() const override;
  void cancel_premature_downstream(Downstream *promised_downstream) override;

  bool get_flow_control() const;
  // Perform HTTP/2 upgrade from |upstream|. On success, this object
  // takes ownership of the |upstream|.
  std::expected<void, Error> upgrade_upstream(HttpsUpstream *upstream);
  void start_settings_timer();
  void stop_settings_timer();
  std::expected<void, Error> consume(int32_t stream_id, size_t len);
  void log_response_headers(Downstream *downstream,
                            const std::vector<nghttp2_nv> &nva) const;
  std::expected<void, Error> start_downstream(Downstream *downstream);
  std::expected<void, Error> initiate_downstream(Downstream *downstream);

  void submit_goaway();
  void check_shutdown();
  // Starts graceful shutdown period.
  void start_graceful_shutdown();

  std::expected<void, Error> prepare_push_promise(Downstream *downstream);
  std::expected<void, Error> submit_push_promise(std::string_view scheme,
                                                 std::string_view authority,
                                                 std::string_view path,
                                                 Downstream *downstream);

  // Called when new request has started.
  void on_start_request(const nghttp2_frame *frame);
  std::expected<void, Error> on_request_headers(Downstream *downstream,
                                                const nghttp2_frame *frame);

  DefaultMemchunks *get_response_buf();

  size_t get_max_buffer_size() const;

  std::expected<void, Error> redirect_to_https(Downstream *downstream);

private:
  DefaultMemchunks wb_;
  std::unique_ptr<HttpsUpstream> pre_upstream_;
  DownstreamQueue downstream_queue_;
  ev_timer settings_timer_;
  ev_timer shutdown_timer_;
  ev_prepare prep_;
  ClientHandler *handler_;
  nghttp2_session *session_{};
  size_t max_buffer_size_{SHRPX_HTTP2_MAX_BUFFER_SIZE};
  // The number of requests seen so far.
  size_t num_requests_{};
  bool flow_control_{true};
};

nghttp2_session_callbacks *create_http2_upstream_callbacks();

} // namespace shrpx

#endif // !defined(SHRPX_HTTP2_UPSTREAM_H)
