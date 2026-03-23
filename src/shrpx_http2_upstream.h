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

class Http2Upstream : public Upstream {
public:
  Http2Upstream(ClientHandler *handler);
  ~Http2Upstream() override;
  int on_read() override;
  int on_write() override;
  int on_timeout(Downstream *downstream) override;
  int on_downstream_abort_request(Downstream *downstream,
                                  unsigned int status_code) override;
  int on_downstream_abort_request_with_https_redirect(
    Downstream *downstream) override;
  ClientHandler *get_client_handler() const override;

  int downstream_read(DownstreamConnection *dconn) override;
  int downstream_write(DownstreamConnection *dconn) override;
  int downstream_eof(DownstreamConnection *dconn) override;
  int downstream_error(DownstreamConnection *dconn, int events) override;

  void add_pending_downstream(std::unique_ptr<Downstream> downstream);
  void remove_downstream(Downstream *downstream);

  int rst_stream(Downstream *downstream, uint32_t error_code);
  int terminate_session(uint32_t error_code);
  int error_reply(Downstream *downstream, unsigned int status_code);

  void pause_read(IOCtrlReason reason) override;
  int resume_read(IOCtrlReason reason, Downstream *downstream,
                  size_t consumed) override;

  int on_downstream_header_complete(Downstream *downstream) override;
  int on_downstream_body(Downstream *downstream, std::span<const uint8_t> data,
                         bool flush) override;
  int on_downstream_body_complete(Downstream *downstream) override;

  void on_handler_delete() override;
  int on_downstream_reset(Downstream *downstream, bool no_retry) override;
  int send_reply(Downstream *downstream,
                 std::span<const uint8_t> body) override;
  int initiate_push(Downstream *downstream, std::string_view uri) override;
  int response_riovec(struct iovec *iov, int iovcnt) const override;
  void response_drain(size_t n) override;
  bool response_empty() const override;

  Downstream *on_downstream_push_promise(Downstream *downstream,
                                         int32_t promised_stream_id) override;
  int on_downstream_push_promise_complete(
    Downstream *downstream, Downstream *promised_downstream) override;
  bool push_enabled() const override;
  void cancel_premature_downstream(Downstream *promised_downstream) override;

  bool get_flow_control() const;
  // Perform HTTP/2 upgrade from |upstream|. On success, this object
  // takes ownership of the |upstream|. This function returns 0 if it
  // succeeds, or -1.
  int upgrade_upstream(HttpsUpstream *upstream);
  void start_settings_timer();
  void stop_settings_timer();
  int consume(int32_t stream_id, size_t len);
  void log_response_headers(Downstream *downstream,
                            const std::vector<nghttp2_nv> &nva) const;
  void start_downstream(Downstream *downstream);
  void initiate_downstream(Downstream *downstream);

  void submit_goaway();
  void check_shutdown();
  // Starts graceful shutdown period.
  void start_graceful_shutdown();

  int prepare_push_promise(Downstream *downstream);
  int submit_push_promise(std::string_view scheme, std::string_view authority,
                          std::string_view path, Downstream *downstream);

  // Called when new request has started.
  void on_start_request(const nghttp2_frame *frame);
  int on_request_headers(Downstream *downstream, const nghttp2_frame *frame);

  DefaultMemchunks *get_response_buf();

  size_t get_max_buffer_size() const;

  int redirect_to_https(Downstream *downstream);

private:
  DefaultMemchunks wb_;
  std::unique_ptr<HttpsUpstream> pre_upstream_;
  DownstreamQueue downstream_queue_;
  ev_timer settings_timer_;
  ev_timer shutdown_timer_;
  ev_prepare prep_;
  ClientHandler *handler_;
  nghttp2_session *session_;
  size_t max_buffer_size_;
  // The number of requests seen so far.
  size_t num_requests_;
  bool flow_control_;
};

nghttp2_session_callbacks *create_http2_upstream_callbacks();

} // namespace shrpx

#endif // !defined(SHRPX_HTTP2_UPSTREAM_H)
