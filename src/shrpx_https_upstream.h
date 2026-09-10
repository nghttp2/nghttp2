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
#ifndef SHRPX_HTTPS_UPSTREAM_H
#define SHRPX_HTTPS_UPSTREAM_H

#include "shrpx.h"

#include <cinttypes>
#include <memory>

#include "llhttp.h"

#include "shrpx_upstream.h"
#include "memchunk.h"

using namespace nghttp2;

namespace shrpx {

class ClientHandler;

class HttpsUpstream : public Upstream {
public:
  HttpsUpstream(ClientHandler *handler);
  ~HttpsUpstream() override;
  std::expected<void, Error> on_read() override;
  std::expected<void, Error> on_write() override;
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

  void attach_downstream(std::unique_ptr<Downstream> downstream);
  void delete_downstream();
  Downstream *get_downstream() const;
  std::unique_ptr<Downstream> pop_downstream();
  void error_reply(unsigned int status_code);

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
  std::span<struct iovec>
  response_riovec(std::span<struct iovec> iov) const override;
  std::span<const uint8_t> response_peek() const override;
  void response_drain(size_t n) override;
  bool response_empty() const override;

  void reset_current_header_length();
  void log_response_headers(DefaultMemchunks *buf) const;
  std::expected<void, Error> redirect_to_https(Downstream *downstream);

  // Called when new request has started.
  void on_start_request();

private:
  ClientHandler *handler_;
  llhttp_t htp_;
  size_t current_header_length_{};
  std::unique_ptr<Downstream> downstream_;
  IOControl ioctrl_;
  // The number of requests seen so far.
  size_t num_requests_{};
};

} // namespace shrpx

#endif // !defined(SHRPX_HTTPS_UPSTREAM_H)
