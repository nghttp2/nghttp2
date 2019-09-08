/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2019 nghttp2 contributors
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
#include "h2load_quic.h"

#include <iostream>

#include <openssl/err.h>

#include "h2load_http3_session.h"

namespace h2load {

namespace {
auto randgen = util::make_mt19937();
} // namespace

namespace {
int client_initial(ngtcp2_conn *conn, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->quic_recv_crypto_data(NGTCP2_CRYPTO_LEVEL_INITIAL, nullptr, 0) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int recv_crypto_data(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->quic_recv_crypto_data(crypto_level, data, datalen) != 0) {
    return NGTCP2_ERR_CRYPTO;
  }

  return 0;
}
} // namespace

int Client::quic_recv_crypto_data(ngtcp2_crypto_level crypto_level,
                                  const uint8_t *data, size_t datalen) {
  return ngtcp2_crypto_read_write_crypto_data(quic.conn, ssl, crypto_level,
                                              data, datalen);
}

namespace {
int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->quic_handshake_completed() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

int Client::quic_handshake_completed() { return connection_made(); }

namespace {
int recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
               const ngtcp2_pkt_retry *retry, void *user_data) {
  // Re-generate handshake secrets here because connection ID might
  // change.
  auto c = static_cast<Client *>(user_data);

  if (c->quic_setup_initial_crypto() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int recv_stream_data(ngtcp2_conn *conn, int64_t stream_id, int fin,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  if (c->quic_recv_stream_data(stream_id, fin, data, datalen) != 0) {
    // TODO Better to do this gracefully rather than
    // NGTCP2_ERR_CALLBACK_FAILURE.  Perhaps, call
    // ngtcp2_conn_write_application_close() ?
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

int Client::quic_recv_stream_data(int64_t stream_id, int fin,
                                  const uint8_t *data, size_t datalen) {
  auto s = static_cast<Http3Session *>(session.get());
  auto nconsumed = s->read_stream(stream_id, data, datalen, fin);
  if (nconsumed == -1) {
    return -1;
  }

  ngtcp2_conn_extend_max_stream_offset(quic.conn, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(quic.conn, nconsumed);

  return 0;
}

namespace {
int acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                             uint64_t offset, size_t datalen, void *user_data,
                             void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  if (c->quic_acked_stream_data_offset(stream_id, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

int Client::quic_acked_stream_data_offset(int64_t stream_id, size_t datalen) {
  auto s = static_cast<Http3Session *>(session.get());
  if (s->add_ack_offset(stream_id, datalen) != 0) {
    return -1;
  }
  return 0;
}

namespace {
int stream_close(ngtcp2_conn *conn, int64_t stream_id, uint64_t app_error_code,
                 void *user_data, void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  if (c->quic_stream_close(stream_id, app_error_code) != 0) {
    return -1;
  }
  return 0;
}
} // namespace

int Client::quic_stream_close(int64_t stream_id, uint64_t app_error_code) {
  auto s = static_cast<Http3Session *>(session.get());
  if (s->close_stream(stream_id, app_error_code) != 0) {
    return -1;
  }
  return 0;
}

namespace {
int stream_reset(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                 uint64_t app_error_code, void *user_data,
                 void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  if (c->quic_stream_reset(stream_id, app_error_code) != 0) {
    return -1;
  }
  return 0;
}
} // namespace

int Client::quic_stream_reset(int64_t stream_id, uint64_t app_error_code) {
  auto s = static_cast<Http3Session *>(session.get());
  if (s->reset_stream(stream_id) != 0) {
    return -1;
  }
  return 0;
}

namespace {
int extend_max_local_streams_bidi(ngtcp2_conn *conn, uint64_t max_streams,
                                  void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->quic_extend_max_local_streams() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

int Client::quic_extend_max_local_streams() {
  auto s = static_cast<Http3Session *>(session.get());
  if (s->extend_max_local_streams() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

namespace {
int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                          size_t cidlen, void *user_data) {
  auto dis = std::uniform_int_distribution<uint8_t>(
      0, std::numeric_limits<uint8_t>::max());
  auto f = [&dis]() { return dis(randgen); };

  std::generate_n(cid->data, cidlen, f);
  cid->datalen = cidlen;
  std::generate_n(token, NGTCP2_STATELESS_RESET_TOKENLEN, f);

  return 0;
}
} // namespace

namespace {
void debug_log_printf(void *user_data, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  fprintf(stderr, "\n");
}
} // namespace

namespace {
void generate_cid(ngtcp2_cid &dest) {
  auto dis = std::uniform_int_distribution<uint8_t>(
      0, std::numeric_limits<uint8_t>::max());
  dest.datalen = 8;
  std::generate_n(dest.data, dest.datalen, [&dis]() { return dis(randgen); });
}
} // namespace

namespace {
int select_preferred_addr(ngtcp2_conn *conn, ngtcp2_addr *dest,
                          const ngtcp2_preferred_addr *paddr, void *user_data) {
  return 0;
}
} // namespace

namespace {
ngtcp2_tstamp timestamp(struct ev_loop *loop) {
  return ev_now(loop) * NGTCP2_SECONDS;
}
} // namespace

namespace {
ngtcp2_crypto_level from_ossl_level(OSSL_ENCRYPTION_LEVEL ossl_level) {
  switch (ossl_level) {
  case ssl_encryption_initial:
    return NGTCP2_CRYPTO_LEVEL_INITIAL;
  case ssl_encryption_early_data:
    return NGTCP2_CRYPTO_LEVEL_EARLY;
  case ssl_encryption_handshake:
    return NGTCP2_CRYPTO_LEVEL_HANDSHAKE;
  case ssl_encryption_application:
    return NGTCP2_CRYPTO_LEVEL_APP;
  default:
    assert(0);
  }
}
} // namespace

namespace {
int set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                           const uint8_t *rx_secret, const uint8_t *tx_secret,
                           size_t secret_len) {
  auto c = static_cast<Client *>(SSL_get_app_data(ssl));

  if (c->quic_on_key(from_ossl_level(ossl_level), rx_secret, tx_secret,
                     secret_len) != 0) {
    return 0;
  }

  return 1;
}
} // namespace

namespace {
int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                       const uint8_t *data, size_t len) {
  auto c = static_cast<Client *>(SSL_get_app_data(ssl));
  c->quic_write_client_handshake(from_ossl_level(ossl_level), data, len);
  return 1;
}
} // namespace

namespace {
int flush_flight(SSL *ssl) { return 1; }
} // namespace

namespace {
int send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert) {
  auto c = static_cast<Client *>(SSL_get_app_data(ssl));
  c->quic_set_tls_alert(alert);
  return 1;
}
} // namespace

namespace {
auto quic_method = SSL_QUIC_METHOD{
    set_encryption_secrets,
    add_handshake_data,
    flush_flight,
    send_alert,
};
} // namespace

int Client::quic_init(const sockaddr *local_addr, socklen_t local_addrlen,
                      const sockaddr *remote_addr, socklen_t remote_addrlen) {
  int rv;

  if (!ssl) {
    ssl = SSL_new(worker->ssl_ctx);

    SSL_set_app_data(ssl, this);
    SSL_set_connect_state(ssl);
    SSL_set_quic_method(ssl, &quic_method);
  }

  switch (remote_addr->sa_family) {
  case AF_INET:
    quic.max_pktlen = NGTCP2_MAX_PKTLEN_IPV4;
    break;
  case AF_INET6:
    quic.max_pktlen = NGTCP2_MAX_PKTLEN_IPV6;
    break;
  default:
    return -1;
  }

  auto callbacks = ngtcp2_conn_callbacks{
      h2load::client_initial,
      nullptr, // recv_client_initial
      h2load::recv_crypto_data,
      h2load::handshake_completed,
      nullptr, // recv_version_negotiation
      ngtcp2_crypto_encrypt_cb,
      ngtcp2_crypto_decrypt_cb,
      ngtcp2_crypto_hp_mask_cb,
      h2load::recv_stream_data,
      nullptr, // acked_crypto_offset
      h2load::acked_stream_data_offset,
      nullptr, // stream_open
      h2load::stream_close,
      nullptr, // recv_stateless_reset
      h2load::recv_retry,
      h2load::extend_max_local_streams_bidi,
      nullptr, // extend_max_local_streams_uni
      nullptr, // rand
      get_new_connection_id,
      nullptr, // remove_connection_id
      nullptr, // update_key
      nullptr, // path_validation
      select_preferred_addr,
      h2load::stream_reset,
      nullptr, // extend_max_remote_streams_bidi
      nullptr, // extend_max_remote_streams_uni
      nullptr, // extend_max_stream_data
  };

  ngtcp2_cid scid, dcid;
  generate_cid(scid);
  generate_cid(dcid);

  auto config = worker->config;

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  if (config->verbose) {
    settings.log_printf = debug_log_printf;
  }
  settings.initial_ts = timestamp(worker->loop);
  settings.max_stream_data_bidi_local = (1 << config->window_bits) - 1;
  settings.max_stream_data_uni = (1 << config->window_bits) - 1;
  settings.max_data = (1 << config->connection_window_bits) - 1;
  settings.max_streams_bidi = 0;
  settings.max_streams_uni = 100;
  settings.idle_timeout = 30 * NGTCP2_SECONDS;

  auto path = ngtcp2_path{
      {local_addrlen,
       const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(local_addr))},
      {remote_addrlen,
       const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(remote_addr))},
  };

  rv = ngtcp2_conn_client_new(&quic.conn, &dcid, &scid, &path, NGTCP2_PROTO_VER,
                              &callbacks, &settings, nullptr, this);
  if (rv != 0) {
    return -1;
  }

  ngtcp2_transport_params params;
  ngtcp2_conn_get_local_transport_params(quic.conn, &params);

  std::array<uint8_t, 64> buf;

  auto nwrite = ngtcp2_encode_transport_params(
      buf.data(), buf.size(), NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,
      &params);
  if (nwrite < 0) {
    std::cerr << "ngtcp2_encode_transport_params: " << ngtcp2_strerror(nwrite)
              << std::endl;
    return -1;
  }

  if (SSL_set_quic_transport_params(ssl, buf.data(), nwrite) != 1) {
    std::cerr << "SSL_set_quic_transport_params failed" << std::endl;
    return -1;
  }

  rv = quic_setup_initial_crypto();
  if (rv != 0) {
    ngtcp2_conn_del(quic.conn);
    quic.conn = nullptr;
    return -1;
  }

  return 0;
}

void Client::quic_free() { ngtcp2_conn_del(quic.conn); }

void Client::quic_close_connection() {
  if (!quic.conn) {
    return;
  }

  std::array<uint8_t, 1500> buf;
  ssize_t nwrite;
  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);

  switch (quic.last_error.type) {
  case quic::ErrorType::TransportVersionNegotiation:
    return;
  case quic::ErrorType::Transport:
    nwrite = ngtcp2_conn_write_connection_close(
        quic.conn, &ps.path, buf.data(), quic.max_pktlen, quic.last_error.code,
        timestamp(worker->loop));
    break;
  case quic::ErrorType::Application:
    nwrite = ngtcp2_conn_write_application_close(
        quic.conn, &ps.path, buf.data(), quic.max_pktlen, quic.last_error.code,
        timestamp(worker->loop));
    break;
  default:
    assert(0);
  }

  if (nwrite < 0) {
    return;
  }

  write_udp(reinterpret_cast<sockaddr *>(ps.path.remote.addr),
            ps.path.remote.addrlen, buf.data(), nwrite);
}

int Client::quic_setup_initial_crypto() {
  auto dcid = ngtcp2_conn_get_dcid(quic.conn);

  if (ngtcp2_crypto_derive_and_install_initial_key(
          quic.conn, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
          nullptr, nullptr, nullptr, dcid, NGTCP2_CRYPTO_SIDE_CLIENT) != 0) {
    std::cerr << "ngtcp2_crypto_derive_and_install_initial_key() failed"
              << std::endl;
    return -1;
  }

  return 0;
}

int Client::quic_on_key(ngtcp2_crypto_level level, const uint8_t *rx_secret,
                        const uint8_t *tx_secret, size_t secretlen) {
  if (ngtcp2_crypto_derive_and_install_key(
          quic.conn, ssl, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
          level, rx_secret, tx_secret, secretlen,
          NGTCP2_CRYPTO_SIDE_CLIENT) != 0) {
    std::cerr << "ngtcp2_crypto_derive_and_install_key() failed" << std::endl;
    return -1;
  }

  if (level == NGTCP2_CRYPTO_LEVEL_APP) {
    auto s = std::make_unique<Http3Session>(this);
    if (s->init_conn() == -1) {
      return -1;
    }
    session = std::move(s);
  }

  return 0;
}

void Client::quic_set_tls_alert(uint8_t alert) {
  quic.last_error = quic::err_transport_tls(alert);
}

void Client::quic_write_client_handshake(ngtcp2_crypto_level level,
                                         const uint8_t *data, size_t datalen) {
  assert(level < 2);
  auto &crypto = quic.crypto[level];
  assert(crypto.data.size() >= crypto.datalen + datalen);

  auto p = std::begin(crypto.data) + crypto.datalen;
  std::copy_n(data, datalen, p);
  crypto.datalen += datalen;

  ngtcp2_conn_submit_crypto_data(quic.conn, level, p, datalen);
}

void quic_pkt_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto c = static_cast<Client *>(w->data);

  if (c->quic_pkt_timeout() != 0) {
    c->fail();
    c->worker->free_client(c);
    delete c;
    return;
  }
}

int Client::quic_pkt_timeout() {
  int rv;
  auto now = timestamp(worker->loop);

  if (ngtcp2_conn_loss_detection_expiry(quic.conn) <= now) {
    rv = ngtcp2_conn_on_loss_detection_timer(quic.conn, now);
    if (rv != 0) {
      quic.last_error = quic::err_transport(NGTCP2_ERR_INTERNAL);
      return -1;
    }
  }
  if (ngtcp2_conn_ack_delay_expiry(quic.conn) <= now) {
    ngtcp2_conn_cancel_expired_ack_delay_timer(quic.conn, now);
  }

  return write_quic();
}

void Client::quic_restart_pkt_timer() {
  auto expiry = ngtcp2_conn_get_expiry(quic.conn);
  auto now = timestamp(worker->loop);
  auto t = expiry > now ? static_cast<ev_tstamp>(expiry - now) / NGTCP2_SECONDS
                        : 1e-9;
  quic.pkt_timer.repeat = t;
  ev_timer_again(worker->loop, &quic.pkt_timer);
}

int Client::read_quic() {
  std::array<uint8_t, 1500> buf;
  sockaddr_union su;
  socklen_t addrlen = sizeof(su);
  int rv;

  auto nread =
      recvfrom(fd, buf.data(), buf.size(), MSG_DONTWAIT, &su.sa, &addrlen);
  if (nread == -1) {
    return 0;
  }

  assert(quic.conn);

  auto path = ngtcp2_path{
      {local_addr.len, reinterpret_cast<uint8_t *>(&local_addr.su.sa)},
      {addrlen, reinterpret_cast<uint8_t *>(&su.sa)},
  };

  rv = ngtcp2_conn_read_pkt(quic.conn, &path, buf.data(), nread,
                            timestamp(worker->loop));
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_read_pkt: " << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  if (worker->current_phase == Phase::MAIN_DURATION) {
    worker->stats.bytes_total += nread;
  }

  return 0;
}

int Client::write_quic() {
  if (quic.close_requested) {
    return -1;
  }

  std::array<nghttp3_vec, 16> vec;
  std::array<uint8_t, 1500> buf;
  ngtcp2_path_storage ps;

  ngtcp2_path_storage_zero(&ps);

  auto s = static_cast<Http3Session *>(session.get());

  for (;;) {
    int64_t stream_id = -1;
    int fin = 0;
    ssize_t sveccnt = 0;

    if (session && ngtcp2_conn_get_max_data_left(quic.conn)) {
      sveccnt = s->write_stream(stream_id, fin, vec.data(), vec.size());
      if (sveccnt == -1) {
        return -1;
      }
    }

    ssize_t ndatalen;
    auto v = vec.data();
    auto vcnt = static_cast<size_t>(sveccnt);

    auto nwrite = ngtcp2_conn_writev_stream(
        quic.conn, &ps.path, buf.data(), quic.max_pktlen, &ndatalen,
        NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id, fin,
        reinterpret_cast<const ngtcp2_vec *>(v), vcnt, timestamp(worker->loop));
    if (nwrite < 0) {
      switch (nwrite) {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
      case NGTCP2_ERR_STREAM_SHUT_WR:
        if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED &&
            ngtcp2_conn_get_max_data_left(quic.conn) == 0) {
          return 0;
        }

        if (s->block_stream(stream_id) != 0) {
          return -1;
        }
        continue;
      case NGTCP2_ERR_WRITE_STREAM_MORE:
        assert(ndatalen > 0);
        if (s->add_write_offset(stream_id, ndatalen) != 0) {
          return -1;
        }
        continue;
      }

      quic.last_error = quic::err_transport(nwrite);
      return -1;
    }

    quic_restart_pkt_timer();

    if (nwrite == 0) {
      return 0;
    }

    if (ndatalen >= 0) {
      if (s->add_write_offset(stream_id, ndatalen) != 0) {
        return -1;
      }
    }

    write_udp(reinterpret_cast<sockaddr *>(ps.path.remote.addr),
              ps.path.remote.addrlen, buf.data(), nwrite);
  }
}

} // namespace h2load
