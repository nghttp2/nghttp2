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

#include <netinet/udp.h>

#include <iostream>

#ifdef HAVE_LIBNGTCP2_CRYPTO_OPENSSL
#  include <ngtcp2/ngtcp2_crypto_openssl.h>
#endif // HAVE_LIBNGTCP2_CRYPTO_OPENSSL
#ifdef HAVE_LIBNGTCP2_CRYPTO_BORINGSSL
#  include <ngtcp2/ngtcp2_crypto_boringssl.h>
#endif // HAVE_LIBNGTCP2_CRYPTO_BORINGSSL

#include <openssl/err.h>

#include "h2load_http3_session.h"

namespace h2load {

namespace {
auto randgen = util::make_mt19937();
} // namespace

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
int recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  if (c->quic_recv_stream_data(flags, stream_id, data, datalen) != 0) {
    // TODO Better to do this gracefully rather than
    // NGTCP2_ERR_CALLBACK_FAILURE.  Perhaps, call
    // ngtcp2_conn_write_application_close() ?
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

int Client::quic_recv_stream_data(uint32_t flags, int64_t stream_id,
                                  const uint8_t *data, size_t datalen) {
  if (worker->current_phase == Phase::MAIN_DURATION) {
    worker->stats.bytes_total += datalen;
  }

  auto s = static_cast<Http3Session *>(session.get());
  auto nconsumed = s->read_stream(flags, stream_id, data, datalen);
  if (nconsumed == -1) {
    return -1;
  }

  ngtcp2_conn_extend_max_stream_offset(quic.conn, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(quic.conn, nconsumed);

  return 0;
}

namespace {
int acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                             uint64_t offset, uint64_t datalen, void *user_data,
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
int stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                 uint64_t app_error_code, void *user_data,
                 void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);

  if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) {
    app_error_code = NGHTTP3_H3_NO_ERROR;
  }

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
  if (s->shutdown_stream_read(stream_id) != 0) {
    return -1;
  }
  return 0;
}

namespace {
int stream_stop_sending(ngtcp2_conn *conn, int64_t stream_id,
                        uint64_t app_error_code, void *user_data,
                        void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  if (c->quic_stream_stop_sending(stream_id, app_error_code) != 0) {
    return -1;
  }
  return 0;
}
} // namespace

int Client::quic_stream_stop_sending(int64_t stream_id,
                                     uint64_t app_error_code) {
  auto s = static_cast<Http3Session *>(session.get());
  if (s->shutdown_stream_read(stream_id) != 0) {
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
ngtcp2_tstamp timestamp(struct ev_loop *loop) {
  return ev_now(loop) * NGTCP2_SECONDS;
}
} // namespace

#ifdef HAVE_LIBNGTCP2_CRYPTO_OPENSSL
namespace {
int set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                           const uint8_t *rx_secret, const uint8_t *tx_secret,
                           size_t secret_len) {
  auto c = static_cast<Client *>(SSL_get_app_data(ssl));
  auto level = ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

  if (c->quic_on_rx_secret(level, rx_secret, secret_len) != 0) {
    return 0;
  }

  if (c->quic_on_tx_secret(level, tx_secret, secret_len) != 0) {
    return 0;
  }

  return 1;
}
} // namespace

namespace {
int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                       const uint8_t *data, size_t len) {
  auto c = static_cast<Client *>(SSL_get_app_data(ssl));
  c->quic_write_client_handshake(
      ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level), data, len);
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
#endif // HAVE_LIBNGTCP2_CRYPTO_OPENSSL

#ifdef HAVE_LIBNGTCP2_CRYPTO_BORINGSSL
namespace {
int set_read_secret(SSL *ssl, ssl_encryption_level_t ssl_level,
                    const SSL_CIPHER *cipher, const uint8_t *secret,
                    size_t secretlen) {
  auto c = static_cast<Client *>(SSL_get_app_data(ssl));

  if (c->quic_on_rx_secret(
          ngtcp2_crypto_boringssl_from_ssl_encryption_level(ssl_level), secret,
          secretlen) != 0) {
    return 0;
  }

  return 1;
}
} // namespace

namespace {
int set_write_secret(SSL *ssl, ssl_encryption_level_t ssl_level,
                     const SSL_CIPHER *cipher, const uint8_t *secret,
                     size_t secretlen) {
  auto c = static_cast<Client *>(SSL_get_app_data(ssl));

  if (c->quic_on_tx_secret(
          ngtcp2_crypto_boringssl_from_ssl_encryption_level(ssl_level), secret,
          secretlen) != 0) {
    return 0;
  }

  return 1;
}
} // namespace

namespace {
int add_handshake_data(SSL *ssl, ssl_encryption_level_t ssl_level,
                       const uint8_t *data, size_t len) {
  auto c = static_cast<Client *>(SSL_get_app_data(ssl));
  c->quic_write_client_handshake(
      ngtcp2_crypto_boringssl_from_ssl_encryption_level(ssl_level), data, len);
  return 1;
}
} // namespace

namespace {
int flush_flight(SSL *ssl) { return 1; }
} // namespace

namespace {
int send_alert(SSL *ssl, ssl_encryption_level_t level, uint8_t alert) {
  auto c = static_cast<Client *>(SSL_get_app_data(ssl));
  c->quic_set_tls_alert(alert);
  return 1;
}
} // namespace

namespace {
auto quic_method = SSL_QUIC_METHOD{
    set_read_secret, set_write_secret, add_handshake_data,
    flush_flight,    send_alert,
};
} // namespace
#endif // HAVE_LIBNGTCP2_CRYPTO_BORINGSSL

// qlog write callback -- excerpted from ngtcp2/examples/client_base.cc
namespace {
void qlog_write_cb(void *user_data, uint32_t flags, const void *data,
                   size_t datalen) {
  auto c = static_cast<Client *>(user_data);
  c->quic_write_qlog(data, datalen);
}
} // namespace

void Client::quic_write_qlog(const void *data, size_t datalen) {
  assert(quic.qlog_file != nullptr);
  fwrite(data, 1, datalen, quic.qlog_file);
}

int Client::quic_init(const sockaddr *local_addr, socklen_t local_addrlen,
                      const sockaddr *remote_addr, socklen_t remote_addrlen) {
  int rv;

  if (!ssl) {
    ssl = SSL_new(worker->ssl_ctx);

    SSL_set_app_data(ssl, this);
    SSL_set_connect_state(ssl);
    SSL_set_quic_method(ssl, &quic_method);
    SSL_set_quic_use_legacy_codepoint(ssl, 0);
  }

  auto callbacks = ngtcp2_callbacks{
      ngtcp2_crypto_client_initial_cb,
      nullptr, // recv_client_initial
      ngtcp2_crypto_recv_crypto_data_cb,
      h2load::handshake_completed,
      nullptr, // recv_version_negotiation
      ngtcp2_crypto_encrypt_cb,
      ngtcp2_crypto_decrypt_cb,
      ngtcp2_crypto_hp_mask_cb,
      h2load::recv_stream_data,
      h2load::acked_stream_data_offset,
      nullptr, // stream_open
      h2load::stream_close,
      nullptr, // recv_stateless_reset
      ngtcp2_crypto_recv_retry_cb,
      h2load::extend_max_local_streams_bidi,
      nullptr, // extend_max_local_streams_uni
      nullptr, // rand
      get_new_connection_id,
      nullptr, // remove_connection_id
      ngtcp2_crypto_update_key_cb,
      nullptr, // path_validation
      nullptr, // select_preferred_addr
      h2load::stream_reset,
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
      nullptr, // get_path_challenge_data
      h2load::stream_stop_sending,
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
  if (!config->qlog_file_base.empty()) {
    assert(quic.qlog_file == nullptr);
    auto path = config->qlog_file_base;
    path += '.';
    path += util::utos(worker->id);
    path += '.';
    path += util::utos(id);
    path += ".qlog";
    quic.qlog_file = fopen(path.c_str(), "w");
    if (quic.qlog_file == nullptr) {
      std::cerr << "Failed to open a qlog file: " << path << std::endl;
      return -1;
    }
    settings.qlog.write = qlog_write_cb;
  }
  if (config->max_udp_payload_size) {
    settings.max_udp_payload_size = config->max_udp_payload_size;
    settings.no_udp_payload_size_shaping = 1;
  }

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default(&params);
  auto max_stream_data =
      std::min((1 << 26) - 1, (1 << config->window_bits) - 1);
  params.initial_max_stream_data_bidi_local = max_stream_data;
  params.initial_max_stream_data_uni = max_stream_data;
  params.initial_max_data = (1 << config->connection_window_bits) - 1;
  params.initial_max_streams_bidi = 0;
  params.initial_max_streams_uni = 100;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;

  auto path = ngtcp2_path{
      {local_addrlen, const_cast<sockaddr *>(local_addr)},
      {remote_addrlen, const_cast<sockaddr *>(remote_addr)},
  };

  assert(config->npn_list.size());

  uint32_t quic_version;

  if (config->npn_list[0] == NGHTTP3_ALPN_H3) {
    quic_version = NGTCP2_PROTO_VER_V1;
  } else {
    quic_version = NGTCP2_PROTO_VER_MIN;
  }

  rv = ngtcp2_conn_client_new(&quic.conn, &dcid, &scid, &path, quic_version,
                              &callbacks, &settings, &params, nullptr, this);
  if (rv != 0) {
    return -1;
  }

  ngtcp2_conn_set_tls_native_handle(quic.conn, ssl);

  return 0;
}

void Client::quic_free() {
  ngtcp2_conn_del(quic.conn);
  if (quic.qlog_file != nullptr) {
    fclose(quic.qlog_file);
    quic.qlog_file = nullptr;
  }
}

void Client::quic_close_connection() {
  if (!quic.conn) {
    return;
  }

  std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> buf;
  ngtcp2_ssize nwrite;
  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);

  switch (quic.last_error.type) {
  case quic::ErrorType::TransportVersionNegotiation:
    return;
  case quic::ErrorType::Transport:
    nwrite = ngtcp2_conn_write_connection_close(
        quic.conn, &ps.path, nullptr, buf.data(), buf.size(),
        quic.last_error.code, timestamp(worker->loop));
    break;
  case quic::ErrorType::Application:
    nwrite = ngtcp2_conn_write_application_close(
        quic.conn, &ps.path, nullptr, buf.data(), buf.size(),
        quic.last_error.code, timestamp(worker->loop));
    break;
  default:
    assert(0);
    abort();
  }

  if (nwrite < 0) {
    return;
  }

  write_udp(reinterpret_cast<sockaddr *>(ps.path.remote.addr),
            ps.path.remote.addrlen, buf.data(), nwrite, 0);
}

int Client::quic_on_rx_secret(ngtcp2_crypto_level level, const uint8_t *secret,
                              size_t secretlen) {
  if (ngtcp2_crypto_derive_and_install_rx_key(quic.conn, nullptr, nullptr,
                                              nullptr, level, secret,
                                              secretlen) != 0) {
    std::cerr << "ngtcp2_crypto_derive_and_install_rx_key() failed"
              << std::endl;
    return -1;
  }

  if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION) {
    auto s = std::make_unique<Http3Session>(this);
    if (s->init_conn() == -1) {
      return -1;
    }
    session = std::move(s);
  }

  return 0;
}

int Client::quic_on_tx_secret(ngtcp2_crypto_level level, const uint8_t *secret,
                              size_t secretlen) {
  if (ngtcp2_crypto_derive_and_install_tx_key(quic.conn, nullptr, nullptr,
                                              nullptr, level, secret,
                                              secretlen) != 0) {
    std::cerr << "ngtcp2_crypto_derive_and_install_tx_key() failed"
              << std::endl;
    return -1;
  }

  return 0;
}

void Client::quic_set_tls_alert(uint8_t alert) {
  quic.last_error = quic::err_transport_tls(alert);
}

void Client::quic_write_client_handshake(ngtcp2_crypto_level level,
                                         const uint8_t *data, size_t datalen) {
  assert(level < 2);

  ngtcp2_conn_submit_crypto_data(quic.conn, level, data, datalen);
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

  rv = ngtcp2_conn_handle_expiry(quic.conn, now);
  if (rv != 0) {
    quic.last_error = quic::err_transport(NGTCP2_ERR_INTERNAL);
    return -1;
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
  std::array<uint8_t, 65536> buf;
  sockaddr_union su;
  socklen_t addrlen = sizeof(su);
  int rv;
  size_t pktcnt = 0;
  ngtcp2_pkt_info pi{};

  for (;;) {
    auto nread =
        recvfrom(fd, buf.data(), buf.size(), MSG_DONTWAIT, &su.sa, &addrlen);
    if (nread == -1) {
      return 0;
    }

    assert(quic.conn);

    ++worker->stats.udp_dgram_recv;

    auto path = ngtcp2_path{
        {local_addr.len, &local_addr.su.sa},
        {addrlen, &su.sa},
    };

    rv = ngtcp2_conn_read_pkt(quic.conn, &path, &pi, buf.data(), nread,
                              timestamp(worker->loop));
    if (rv != 0) {
      std::cerr << "ngtcp2_conn_read_pkt: " << ngtcp2_strerror(rv) << std::endl;
      return -1;
    }

    if (++pktcnt == 100) {
      break;
    }
  }

  return 0;
}

int Client::write_quic() {
  ev_io_stop(worker->loop, &wev);

  if (quic.close_requested) {
    return -1;
  }

  std::array<nghttp3_vec, 16> vec;
  size_t pktcnt = 0;
  auto max_udp_payload_size =
      ngtcp2_conn_get_path_max_udp_payload_size(quic.conn);
  size_t max_pktcnt =
#ifdef UDP_SEGMENT
      worker->config->no_udp_gso
          ? 1
          : std::min(static_cast<size_t>(10),
                     static_cast<size_t>(64_k / max_udp_payload_size));
#else  // !UDP_SEGMENT
      1;
#endif // !UDP_SEGMENT
  std::array<uint8_t, 64_k> buf;
  uint8_t *bufpos = buf.data();
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

    ngtcp2_ssize ndatalen;
    auto v = vec.data();
    auto vcnt = static_cast<size_t>(sveccnt);

    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin) {
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    auto nwrite = ngtcp2_conn_writev_stream(
        quic.conn, &ps.path, nullptr, bufpos, max_udp_payload_size, &ndatalen,
        flags, stream_id, reinterpret_cast<const ngtcp2_vec *>(v), vcnt,
        timestamp(worker->loop));
    if (nwrite < 0) {
      switch (nwrite) {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
        assert(ndatalen == -1);
        if (s->block_stream(stream_id) != 0) {
          return -1;
        }
        continue;
      case NGTCP2_ERR_STREAM_SHUT_WR:
        assert(ndatalen == -1);
        if (s->shutdown_stream_write(stream_id) != 0) {
          return -1;
        }
        continue;
      case NGTCP2_ERR_WRITE_MORE:
        assert(ndatalen >= 0);
        if (s->add_write_offset(stream_id, ndatalen) != 0) {
          return -1;
        }
        continue;
      }

      quic.last_error = quic::err_transport(nwrite);
      return -1;
    } else if (ndatalen >= 0 && s->add_write_offset(stream_id, ndatalen) != 0) {
      return -1;
    }

    quic_restart_pkt_timer();

    if (nwrite == 0) {
      if (bufpos - buf.data()) {
        write_udp(ps.path.remote.addr, ps.path.remote.addrlen, buf.data(),
                  bufpos - buf.data(), max_udp_payload_size);
      }
      return 0;
    }

    bufpos += nwrite;

    // Assume that the path does not change.
    if (++pktcnt == max_pktcnt ||
        static_cast<size_t>(nwrite) < max_udp_payload_size) {
      write_udp(ps.path.remote.addr, ps.path.remote.addrlen, buf.data(),
                bufpos - buf.data(), max_udp_payload_size);
      signal_write();
      return 0;
    }
  }
}

} // namespace h2load
