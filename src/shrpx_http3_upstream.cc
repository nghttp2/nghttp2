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

#include <stdio.h>

#include <ngtcp2/ngtcp2_crypto.h>

#include "shrpx_client_handler.h"
#include "shrpx_downstream.h"
#include "shrpx_downstream_connection.h"
#include "shrpx_log.h"
#include "shrpx_quic.h"
#include "shrpx_worker.h"
#include "util.h"

namespace shrpx {

Http3Upstream::Http3Upstream(ClientHandler *handler)
    : handler_{handler}, conn_{nullptr}, tls_alert_{0} {}

Http3Upstream::~Http3Upstream() {
  if (conn_) {
    auto worker = handler_->get_worker();
    auto quic_client_handler = worker->get_quic_connection_handler();

    quic_client_handler->remove_connection_id(&initial_client_dcid_);

    std::vector<ngtcp2_cid> scids(ngtcp2_conn_get_num_scid(conn_));
    ngtcp2_conn_get_scid(conn_, scids.data());

    for (auto &cid : scids) {
      quic_client_handler->remove_connection_id(&cid);
    }

    ngtcp2_conn_del(conn_);
  }
}

namespace {
void log_printf(void *user_data, const char *fmt, ...) {
  va_list ap;
  std::array<char, 4096> buf;

  va_start(ap, fmt);
  auto nwrite = vsnprintf(buf.data(), buf.size(), fmt, ap);
  va_end(ap);

  if (nwrite >= buf.size()) {
    nwrite = buf.size() - 1;
  }

  buf[nwrite++] = '\n';

  write(fileno(stderr), buf.data(), nwrite);
}
} // namespace

namespace {
void rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
  util::random_bytes(dest, dest + destlen,
                     *static_cast<std::mt19937 *>(rand_ctx->native_handle));
}
} // namespace

namespace {
int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                          size_t cidlen, void *user_data) {
  if (generate_quic_connection_id(cid, cidlen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  auto config = get_config();
  auto &quicconf = config->quic;
  auto &secret = quicconf.stateless_reset.secret;

  if (generate_quic_stateless_reset_token(token, cid, secret.data(),
                                          secret.size()) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid,
                         void *user_data) {
  auto upstream = static_cast<Http3Upstream *>(user_data);
  auto handler = upstream->get_client_handler();
  auto worker = handler->get_worker();
  auto quic_conn_handler = worker->get_quic_connection_handler();

  quic_conn_handler->remove_connection_id(cid);

  return 0;
}
} // namespace

int Http3Upstream::init(const UpstreamAddr *faddr, const Address &remote_addr,
                        const Address &local_addr,
                        const ngtcp2_pkt_hd &initial_hd) {
  int rv;

  auto worker = handler_->get_worker();

  auto callbacks = ngtcp2_callbacks{
      nullptr, // client_initial
      ngtcp2_crypto_recv_client_initial_cb,
      ngtcp2_crypto_recv_crypto_data_cb,
      nullptr, // handshake_completed
      nullptr, // recv_version_negotiation
      ngtcp2_crypto_encrypt_cb,
      ngtcp2_crypto_decrypt_cb,
      ngtcp2_crypto_hp_mask_cb,
      nullptr, // recv_stream_data
      nullptr, // acked_stream_data_offset
      nullptr, // stream_open
      nullptr, // stream_close
      nullptr, // recv_stateless_reset
      nullptr, // recv_retry
      nullptr, // extend_max_local_streams_bidi
      nullptr, // extend_max_local_streams_uni
      rand,
      get_new_connection_id,
      remove_connection_id,
      ngtcp2_crypto_update_key_cb,
      nullptr, // path_validation
      nullptr, // select_preferred_addr
      nullptr, // stream_reset
      nullptr, // extend_max_remote_streams_bidi
      nullptr, // extend_max_remote_streams_uni
      nullptr, // extend_max_stream_data
      nullptr, // dcid_status
      nullptr, // handshake_confirmed
      nullptr, // recv_new_token
      ngtcp2_crypto_delete_crypto_aead_ctx_cb,
      ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
      nullptr, // recv_datagram
      nullptr, // ack_datagram
      nullptr, // lost_datagram
      ngtcp2_crypto_get_path_challenge_data_cb,
      nullptr, // stream_stop_sending
  };

  initial_client_dcid_ = initial_hd.dcid;

  ngtcp2_cid scid;

  if (generate_quic_connection_id(&scid, SHRPX_QUIC_SCIDLEN) != 0) {
    return -1;
  }

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.log_printf = log_printf;
  settings.initial_ts = quic_timestamp();
  settings.cc_algo = NGTCP2_CC_ALGO_BBR;
  settings.max_window = 6_m;
  settings.max_stream_window = 6_m;
  settings.max_udp_payload_size = SHRPX_MAX_UDP_PAYLOAD_SIZE;
  settings.rand_ctx = {&worker->get_randgen()};

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default(&params);
  params.initial_max_data = 1_m;
  params.initial_max_stream_data_bidi_remote = 256_k;
  params.initial_max_stream_data_uni = 256_k;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  params.original_dcid = initial_hd.dcid;

  auto path = ngtcp2_path{
      {local_addr.len, const_cast<sockaddr *>(&local_addr.su.sa)},
      {remote_addr.len, const_cast<sockaddr *>(&remote_addr.su.sa)},
      const_cast<UpstreamAddr *>(faddr),
  };

  rv = ngtcp2_conn_server_new(&conn_, &initial_hd.scid, &scid, &path,
                              initial_hd.version, &callbacks, &settings,
                              &params, nullptr, this);
  if (rv != 0) {
    LOG(ERROR) << "ngtcp2_conn_server_new: " << ngtcp2_strerror(rv);
    return -1;
  }

  ngtcp2_conn_set_tls_native_handle(conn_, handler_->get_ssl());

  auto quic_connection_handler = worker->get_quic_connection_handler();

  quic_connection_handler->add_connection_id(&initial_client_dcid_, handler_);
  quic_connection_handler->add_connection_id(&scid, handler_);

  return 0;
}

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
  int rv;
  ngtcp2_pkt_info pi{};

  auto path = ngtcp2_path{
      {
          local_addr.len,
          const_cast<sockaddr *>(&local_addr.su.sa),
      },
      {
          remote_addr.len,
          const_cast<sockaddr *>(&remote_addr.su.sa),
      },
      const_cast<UpstreamAddr *>(faddr),
  };

  rv = ngtcp2_conn_read_pkt(conn_, &path, &pi, data, datalen, quic_timestamp());
  if (rv != 0) {
    LOG(ERROR) << "ngtcp2_conn_read_pkt: " << ngtcp2_strerror(rv);

    switch (rv) {
    case NGTCP2_ERR_DRAINING:
      // TODO Start drain period
      return -1;
    case NGTCP2_ERR_RETRY:
      // TODO Send Retry packet
      return -1;
    case NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM:
    case NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM:
    case NGTCP2_ERR_TRANSPORT_PARAM:
      // If rv indicates transport_parameters related error, we should
      // send TRANSPORT_PARAMETER_ERROR even if last_error_.code is
      // already set.  This is because OpenSSL might set Alert.
      last_error_ = quic::err_transport(rv);
      break;
    case NGTCP2_ERR_DROP_CONN:
      return -1;
    default:
      if (!last_error_.code) {
        last_error_ = quic::err_transport(rv);
      }
    }

    // TODO Send connection close
    return handle_error();
  }

  return 0;
}

int Http3Upstream::handle_error() { return -1; }

int Http3Upstream::on_rx_secret(ngtcp2_crypto_level level,
                                const uint8_t *secret, size_t secretlen) {
  if (ngtcp2_crypto_derive_and_install_rx_key(conn_, nullptr, nullptr, nullptr,
                                              level, secret, secretlen) != 0) {
    LOG(ERROR) << "ngtcp2_crypto_derive_and_install_rx_key failed";
    return -1;
  }

  return 0;
}

int Http3Upstream::on_tx_secret(ngtcp2_crypto_level level,
                                const uint8_t *secret, size_t secretlen) {
  if (ngtcp2_crypto_derive_and_install_tx_key(conn_, nullptr, nullptr, nullptr,
                                              level, secret, secretlen) != 0) {
    LOG(ERROR) << "ngtcp2_crypto_derive_and_install_tx_key failed";
    return -1;
  }

  return 0;
}

int Http3Upstream::add_crypto_data(ngtcp2_crypto_level level,
                                   const uint8_t *data, size_t datalen) {
  return 0;
}

void Http3Upstream::set_tls_alert(uint8_t alert) { tls_alert_ = alert; }

} // namespace shrpx
