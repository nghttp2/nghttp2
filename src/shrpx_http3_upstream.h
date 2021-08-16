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

#include "shrpx_upstream.h"
#include "quic.h"
#include "network.h"

using namespace nghttp2;

namespace shrpx {

struct UpstreamAddr;

class Http3Upstream : public Upstream {
public:
  Http3Upstream(ClientHandler *handler);
  virtual ~Http3Upstream();

  virtual int on_read();
  virtual int on_write();
  virtual int on_timeout(Downstream *downstream);
  virtual int on_downstream_abort_request(Downstream *downstream,
                                          unsigned int status_code);
  virtual int
  on_downstream_abort_request_with_https_redirect(Downstream *downstream);
  virtual int downstream_read(DownstreamConnection *dconn);
  virtual int downstream_write(DownstreamConnection *dconn);
  virtual int downstream_eof(DownstreamConnection *dconn);
  virtual int downstream_error(DownstreamConnection *dconn, int events);
  virtual ClientHandler *get_client_handler() const;

  virtual int on_downstream_header_complete(Downstream *downstream);
  virtual int on_downstream_body(Downstream *downstream, const uint8_t *data,
                                 size_t len, bool flush);
  virtual int on_downstream_body_complete(Downstream *downstream);

  virtual void on_handler_delete();
  virtual int on_downstream_reset(Downstream *downstream, bool no_retry);

  virtual void pause_read(IOCtrlReason reason);
  virtual int resume_read(IOCtrlReason reason, Downstream *downstream,
                          size_t consumed);
  virtual int send_reply(Downstream *downstream, const uint8_t *body,
                         size_t bodylen);

  virtual int initiate_push(Downstream *downstream, const StringRef &uri);

  virtual int response_riovec(struct iovec *iov, int iovcnt) const;
  virtual void response_drain(size_t n);
  virtual bool response_empty() const;

  virtual Downstream *on_downstream_push_promise(Downstream *downstream,
                                                 int32_t promised_stream_id);
  virtual int
  on_downstream_push_promise_complete(Downstream *downstream,
                                      Downstream *promised_downstream);
  virtual bool push_enabled() const;
  virtual void cancel_premature_downstream(Downstream *promised_downstream);

  int init(const UpstreamAddr *faddr, const Address &remote_addr,
           const Address &local_addr, const ngtcp2_pkt_hd &initial_hd);

  int on_read(const UpstreamAddr *faddr, const Address &remote_addr,
              const Address &local_addr, const uint8_t *data, size_t datalen);

  int on_rx_secret(ngtcp2_crypto_level level, const uint8_t *secret,
                   size_t secretlen);
  int on_tx_secret(ngtcp2_crypto_level level, const uint8_t *secret,
                   size_t secretlen);

  int add_crypto_data(ngtcp2_crypto_level level, const uint8_t *data,
                      size_t datalen);

  void set_tls_alert(uint8_t alert);

  int handle_error();

private:
  ClientHandler *handler_;
  ngtcp2_cid initial_client_dcid_;
  ngtcp2_conn *conn_;
  quic::Error last_error_;
  uint8_t tls_alert_;
};

} // namespace shrpx

#endif // SHRPX_HTTP3_UPSTREAM_H
