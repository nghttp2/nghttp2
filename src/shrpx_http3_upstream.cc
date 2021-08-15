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
#include "shrpx_http3_upstream.h"
#include "shrpx_client_handler.h"
#include "shrpx_downstream.h"
#include "shrpx_downstream_connection.h"
#include "shrpx_log.h"

namespace shrpx {

Http3Upstream::Http3Upstream(ClientHandler *handler)
    : handler_{handler}, tls_alert_{0} {}

Http3Upstream::~Http3Upstream() {}

int Http3Upstream::on_read() { return 0; }

int Http3Upstream::on_write() { return 0; }

int Http3Upstream::on_timeout(Downstream *downstream) { return 0; }

int Http3Upstream::on_downstream_abort_request(Downstream *downstream,
                                               unsigned int status_code) {
  return 0;
}

int Http3Upstream::on_downstream_abort_request_with_https_redirect(
    Downstream *downstream) {
  return 0;
}

int Http3Upstream::downstream_read(DownstreamConnection *dconn) { return 0; }

int Http3Upstream::downstream_write(DownstreamConnection *dconn) { return 0; }

int Http3Upstream::downstream_eof(DownstreamConnection *dconn) { return 0; }

int Http3Upstream::downstream_error(DownstreamConnection *dconn, int events) {
  return 0;
}

ClientHandler *Http3Upstream::get_client_handler() const { return handler_; }

int Http3Upstream::on_downstream_header_complete(Downstream *downstream) {
  return 0;
}

int Http3Upstream::on_downstream_body(Downstream *downstream,
                                      const uint8_t *data, size_t len,
                                      bool flush) {
  return 0;
}

int Http3Upstream::on_downstream_body_complete(Downstream *downstream) {
  return 0;
}

void Http3Upstream::on_handler_delete() {}

int Http3Upstream::on_downstream_reset(Downstream *downstream, bool no_retry) {
  return 0;
}

void Http3Upstream::pause_read(IOCtrlReason reason) {}

int Http3Upstream::resume_read(IOCtrlReason reason, Downstream *downstream,
                               size_t consumed) {
  return 0;
}

int Http3Upstream::send_reply(Downstream *downstream, const uint8_t *body,
                              size_t bodylen) {
  return 0;
}

int Http3Upstream::initiate_push(Downstream *downstream, const StringRef &uri) {
  return 0;
}

int Http3Upstream::response_riovec(struct iovec *iov, int iovcnt) const {
  return 0;
}

void Http3Upstream::response_drain(size_t n) {}

bool Http3Upstream::response_empty() const { return false; }

Downstream *
Http3Upstream::on_downstream_push_promise(Downstream *downstream,
                                          int32_t promised_stream_id) {
  return nullptr;
}

int Http3Upstream::on_downstream_push_promise_complete(
    Downstream *downstream, Downstream *promised_downstream) {
  return 0;
}

bool Http3Upstream::push_enabled() const { return false; }

void Http3Upstream::cancel_premature_downstream(
    Downstream *promised_downstream) {}

int Http3Upstream::on_read(const UpstreamAddr *faddr,
                           const Address &remote_addr,
                           const Address &local_addr, const uint8_t *data,
                           size_t datalen) {
  return 0;
}

int Http3Upstream::on_rx_secret(ngtcp2_crypto_level level,
                                const uint8_t *secret, size_t secretlen) {
  return 0;
}

int Http3Upstream::on_tx_secret(ngtcp2_crypto_level level,
                                const uint8_t *secret, size_t secretlen) {
  return 0;
}

int Http3Upstream::add_crypto_data(ngtcp2_crypto_level level,
                                   const uint8_t *data, size_t datalen) {
  return 0;
}

void Http3Upstream::set_tls_alert(uint8_t alert) { tls_alert_ = alert; }

} // namespace shrpx
