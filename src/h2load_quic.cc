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
#include <openssl/bio.h>

#include "h2load_http3_session.h"

namespace h2load {

namespace {
auto randgen = util::make_mt19937();
} // namespace

ngtcp2_crypto_ctx in_crypto_ctx;

namespace {
int client_initial(ngtcp2_conn *conn, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->quic_client_initial() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

int Client::quic_client_initial() {
  if (quic_tls_handshake(true) != 0) {
    return -1;
  }
  return 0;
}

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
  if (quic_write_server_handshake(crypto_level, data, datalen) != 0) {
    return -1;
  }

  if (!ngtcp2_conn_get_handshake_completed(quic.conn)) {
    if (quic_tls_handshake() != 0) {
      return -1;
    }
    return 0;
  }

  // SSL_do_handshake() might not consume all data (e.g.,
  // NewSessionTicket).
  return quic_read_tls();
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

int Client::quic_handshake_completed() {
  quic.tx_crypto_level = NGTCP2_CRYPTO_LEVEL_APP;

  // TODO Create Http3Session here.
  return connection_made();
}

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
int in_encrypt(ngtcp2_conn *conn, uint8_t *dest, const uint8_t *plaintext,
               size_t plaintextlen, const uint8_t *key, const uint8_t *nonce,
               size_t noncelen, const uint8_t *ad, size_t adlen,
               void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->quic_in_encrypt(dest, plaintext, plaintextlen, key, nonce, noncelen,
                         ad, adlen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

int Client::quic_in_encrypt(uint8_t *dest, const uint8_t *plaintext,
                            size_t plaintextlen, const uint8_t *key,
                            const uint8_t *nonce, size_t noncelen,
                            const uint8_t *ad, size_t adlen) {
  return ngtcp2_crypto_encrypt(dest, &in_crypto_ctx.aead, plaintext,
                               plaintextlen, key, nonce, noncelen, ad, adlen);
}

namespace {
int in_decrypt(ngtcp2_conn *conn, uint8_t *dest, const uint8_t *ciphertext,
               size_t ciphertextlen, const uint8_t *key, const uint8_t *nonce,
               size_t noncelen, const uint8_t *ad, size_t adlen,
               void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->quic_in_decrypt(dest, ciphertext, ciphertextlen, key, nonce, noncelen,
                         ad, adlen) != 0) {
    return NGTCP2_ERR_TLS_DECRYPT;
  }

  return 0;
}
} // namespace

int Client::quic_in_decrypt(uint8_t *dest, const uint8_t *ciphertext,
                            size_t ciphertextlen, const uint8_t *key,
                            const uint8_t *nonce, size_t noncelen,
                            const uint8_t *ad, size_t adlen) {
  return ngtcp2_crypto_decrypt(dest, &in_crypto_ctx.aead, ciphertext,
                               ciphertextlen, key, nonce, noncelen, ad, adlen);
}

namespace {
int encrypt(ngtcp2_conn *conn, uint8_t *dest, const uint8_t *plaintext,
            size_t plaintextlen, const uint8_t *key, const uint8_t *nonce,
            size_t noncelen, const uint8_t *ad, size_t adlen, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->quic_encrypt(dest, plaintext, plaintextlen, key, nonce, noncelen, ad,
                      adlen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

int Client::quic_encrypt(uint8_t *dest, const uint8_t *plaintext,
                         size_t plaintextlen, const uint8_t *key,
                         const uint8_t *nonce, size_t noncelen,
                         const uint8_t *ad, size_t adlen) {
  return ngtcp2_crypto_encrypt(dest, &quic.crypto_ctx.aead, plaintext,
                               plaintextlen, key, nonce, noncelen, ad, adlen);
}

namespace {
int decrypt(ngtcp2_conn *conn, uint8_t *dest, const uint8_t *ciphertext,
            size_t ciphertextlen, const uint8_t *key, const uint8_t *nonce,
            size_t noncelen, const uint8_t *ad, size_t adlen, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->quic_decrypt(dest, ciphertext, ciphertextlen, key, nonce, noncelen, ad,
                      adlen) != 0) {
    return NGTCP2_ERR_TLS_DECRYPT;
  }

  return 0;
}
} // namespace

int Client::quic_decrypt(uint8_t *dest, const uint8_t *ciphertext,
                         size_t ciphertextlen, const uint8_t *key,
                         const uint8_t *nonce, size_t noncelen,
                         const uint8_t *ad, size_t adlen) {
  return ngtcp2_crypto_decrypt(dest, &quic.crypto_ctx.aead, ciphertext,
                               ciphertextlen, key, nonce, noncelen, ad, adlen);
}

namespace {
int in_hp_mask(ngtcp2_conn *conn, uint8_t *dest, const uint8_t *key,
               const uint8_t *sample, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->quic_in_hp_mask(dest, key, sample) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

int Client::quic_in_hp_mask(uint8_t *dest, const uint8_t *key,
                            const uint8_t *sample) {
  return ngtcp2_crypto_hp_mask(dest, &in_crypto_ctx.hp, key, sample);
}

namespace {
int hp_mask(ngtcp2_conn *conn, uint8_t *dest, const uint8_t *key,
            const uint8_t *sample, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->quic_hp_mask(dest, key, sample) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

int Client::quic_hp_mask(uint8_t *dest, const uint8_t *key,
                         const uint8_t *sample) {
  return ngtcp2_crypto_hp_mask(dest, &quic.crypto_ctx.hp, key, sample);
}

namespace {
int recv_stream_data(ngtcp2_conn *conn, int64_t stream_id, int fin,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  if (c->quic_recv_stream_data(stream_id, fin, data, datalen) != 0) {
    // TODO Better to do this gracefully rather than
    // NGTCP2_ERR_CALLBACK_FAILURE.  Perhaps, call
    // ngtcp2_conn_write_application_close() ?
    return -1;
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
int bio_write(BIO *b, const char *buf, int len) {
  assert(0);
  return -1;
}
} // namespace

namespace {
int bio_read(BIO *b, char *buf, int len) {
  BIO_clear_retry_flags(b);

  auto c = static_cast<Client *>(BIO_get_data(b));

  len = c->quic_read_server_handshake(reinterpret_cast<uint8_t *>(buf), len);
  if (len == 0) {
    BIO_set_retry_read(b);
    return -1;
  }

  return len;
}
} // namespace

namespace {
int bio_puts(BIO *b, const char *str) { return bio_write(b, str, strlen(str)); }
} // namespace

namespace {
int bio_gets(BIO *b, char *buf, int len) { return -1; }
} // namespace

namespace {
long bio_ctrl(BIO *b, int cmd, long num, void *ptr) {
  switch (cmd) {
  case BIO_CTRL_FLUSH:
    return 1;
  }

  return 0;
}
} // namespace

namespace {
int bio_create(BIO *b) {
  BIO_set_init(b, 1);
  return 1;
}
} // namespace

namespace {
int bio_destroy(BIO *b) {
  if (b == nullptr) {
    return 0;
  }

  return 1;
}
} // namespace

namespace {
BIO_METHOD *create_bio_method() {
  static auto meth = BIO_meth_new(BIO_TYPE_FD, "bio");
  BIO_meth_set_write(meth, bio_write);
  BIO_meth_set_read(meth, bio_read);
  BIO_meth_set_puts(meth, bio_puts);
  BIO_meth_set_gets(meth, bio_gets);
  BIO_meth_set_ctrl(meth, bio_ctrl);
  BIO_meth_set_create(meth, bio_create);
  BIO_meth_set_destroy(meth, bio_destroy);
  return meth;
}
} // namespace

namespace {
int key_cb(SSL *ssl, int name, const unsigned char *secret, size_t secretlen,
           void *arg) {
  auto c = static_cast<Client *>(arg);

  if (c->quic_on_key(name, secret, secretlen) != 0) {
    return 0;
  }

  return 1;
}
} // namespace

namespace {
void msg_cb(int write_p, int version, int content_type, const void *buf,
            size_t len, SSL *ssl, void *arg) {
  if (!write_p) {
    return;
  }

  auto c = static_cast<Client *>(arg);
  auto msg = reinterpret_cast<const uint8_t *>(buf);

  switch (content_type) {
  case SSL3_RT_HANDSHAKE:
    break;
  case SSL3_RT_ALERT:
    assert(len == 2);
    if (msg[0] != 2 /* FATAL */) {
      return;
    }
    c->quic_set_tls_alert(msg[1]);
    return;
  default:
    return;
  }

  c->quic_write_client_handshake(reinterpret_cast<const uint8_t *>(buf), len);
}
} // namespace

int Client::quic_init(const sockaddr *local_addr, socklen_t local_addrlen,
                      const sockaddr *remote_addr, socklen_t remote_addrlen) {
  int rv;

  if (!ssl) {
    ssl = SSL_new(worker->ssl_ctx);

    auto bio = BIO_new(create_bio_method());
    BIO_set_data(bio, this);

    SSL_set_bio(ssl, bio, bio);
    SSL_set_app_data(ssl, this);
    SSL_set_connect_state(ssl);
    SSL_set_msg_callback(ssl, msg_cb);
    SSL_set_msg_callback_arg(ssl, this);
    SSL_set_key_callback(ssl, key_cb, this);
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
      h2load::in_encrypt,
      h2load::in_decrypt,
      h2load::encrypt,
      h2load::decrypt,
      h2load::in_hp_mask,
      h2load::hp_mask,
      h2load::recv_stream_data,
      nullptr, // acked_crypto_offset
      nullptr, // acked_stream_data_offset
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
  std::array<uint8_t, 32> tx_secret, rx_secret;
  auto dcid = ngtcp2_conn_get_dcid(quic.conn);
  if (ngtcp2_crypto_derive_initial_secrets(rx_secret.data(), tx_secret.data(),
                                           nullptr, dcid,
                                           NGTCP2_CRYPTO_SIDE_CLIENT) != 0) {
    std::cerr << "ngtcp2_crypto_derive_initial_secrets() failed" << std::endl;
    return -1;
  }

  auto aead = &in_crypto_ctx.aead;
  auto md = &in_crypto_ctx.md;

  std::array<uint8_t, 16> key, iv, hp;
  auto keylen = ngtcp2_crypto_aead_keylen(aead);
  auto ivlen = ngtcp2_crypto_packet_protection_ivlen(aead);
  auto hplen = keylen;

  if (ngtcp2_crypto_derive_packet_protection_key(key.data(), iv.data(), aead,
                                                 md, tx_secret.data(),
                                                 tx_secret.size()) != 0) {
    return -1;
  }

  if (ngtcp2_crypto_derive_header_protection_key(
          hp.data(), aead, md, tx_secret.data(), tx_secret.size()) != 0) {
    return -1;
  }

  ngtcp2_conn_install_initial_tx_keys(quic.conn, key.data(), keylen, iv.data(),
                                      ivlen, hp.data(), hplen);

  if (ngtcp2_crypto_derive_packet_protection_key(key.data(), iv.data(), aead,
                                                 md, rx_secret.data(),
                                                 rx_secret.size()) != 0) {
    return -1;
  }

  if (ngtcp2_crypto_derive_header_protection_key(
          hp.data(), aead, md, rx_secret.data(), rx_secret.size()) != 0) {
    return -1;
  }

  ngtcp2_conn_install_initial_rx_keys(quic.conn, key.data(), keylen, iv.data(),
                                      ivlen, hp.data(), hplen);

  return 0;
}

int Client::quic_on_key(int name, const uint8_t *secret, size_t secretlen) {
  switch (name) {
  case SSL_KEY_CLIENT_EARLY_TRAFFIC:
  case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
  case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
  case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
  case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
    break;
  default:
    return 0;
  }

  if (quic.crypto_ctx.aead.native_handle == nullptr) {
    ngtcp2_crypto_ctx_tls(&quic.crypto_ctx, ssl);
    ngtcp2_conn_set_aead_overhead(
        quic.conn, ngtcp2_crypto_aead_taglen(&quic.crypto_ctx.aead));
  }

  auto aead = &quic.crypto_ctx.aead;
  auto md = &quic.crypto_ctx.md;

  std::array<uint8_t, 64> key, iv, hp;
  auto keylen = ngtcp2_crypto_aead_keylen(aead);
  auto ivlen = ngtcp2_crypto_packet_protection_ivlen(aead);
  auto hplen = keylen;

  if (ngtcp2_crypto_derive_packet_protection_key(key.data(), iv.data(), aead,
                                                 md, secret, secretlen) != 0) {
    return -1;
  }

  if (ngtcp2_crypto_derive_header_protection_key(hp.data(), aead, md, secret,
                                                 secretlen) != 0) {
    return -1;
  }

  switch (name) {
  case SSL_KEY_CLIENT_EARLY_TRAFFIC:
    ngtcp2_conn_install_early_keys(quic.conn, key.data(), keylen, iv.data(),
                                   ivlen, hp.data(), hplen);
    break;
  case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
    ngtcp2_conn_install_handshake_tx_keys(quic.conn, key.data(), keylen,
                                          iv.data(), ivlen, hp.data(), hplen);
    quic.tx_crypto_level = NGTCP2_CRYPTO_LEVEL_HANDSHAKE;
    break;
  case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
    ngtcp2_conn_install_tx_keys(quic.conn, key.data(), keylen, iv.data(), ivlen,
                                hp.data(), hplen);
    break;
  case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
    ngtcp2_conn_install_handshake_rx_keys(quic.conn, key.data(), keylen,
                                          iv.data(), ivlen, hp.data(), hplen);
    quic.rx_crypto_level = NGTCP2_CRYPTO_LEVEL_HANDSHAKE;
    break;
  case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
    ngtcp2_conn_install_rx_keys(quic.conn, key.data(), keylen, iv.data(), ivlen,
                                hp.data(), hplen);
    quic.rx_crypto_level = NGTCP2_CRYPTO_LEVEL_APP;
    break;
  }

  return 0;
}

int Client::quic_tls_handshake(bool initial) {
  ERR_clear_error();

  int rv;

  rv = SSL_do_handshake(ssl);
  if (rv <= 0) {
    auto err = SSL_get_error(ssl, rv);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return 0;
    case SSL_ERROR_SSL:
      std::cerr << "TLS handshake error: "
                << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
      return -1;
    default:
      std::cerr << "TLS handshake error: " << err << std::endl;
      return -1;
    }
  }

  ngtcp2_conn_handshake_completed(quic.conn);

  if (quic_read_tls() != 0) {
    return -1;
  }

  return 0;
}

int Client::quic_read_tls() {
  ERR_clear_error();

  std::array<uint8_t, 4096> buf;
  size_t nread;

  for (;;) {
    auto rv = SSL_read_ex(ssl, buf.data(), buf.size(), &nread);
    if (rv == 1) {
      continue;
    }
    auto err = SSL_get_error(ssl, 0);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return 0;
    case SSL_ERROR_SSL:
    case SSL_ERROR_ZERO_RETURN:
      std::cerr << "TLS read error: "
                << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
      return NGTCP2_ERR_CRYPTO;
    default:
      std::cerr << "TLS read error: " << err << std::endl;
      return NGTCP2_ERR_CRYPTO;
    }
  }
}

void Client::quic_set_tls_alert(uint8_t alert) {
  quic.last_error = quic::err_transport_tls(alert);
}

size_t Client::quic_read_server_handshake(uint8_t *buf, size_t buflen) {
  auto n = std::min(buflen,
                    quic.server_handshake.size() - quic.server_handshake_nread);
  std::copy_n(std::begin(quic.server_handshake) + quic.server_handshake_nread,
              n, buf);
  quic.server_handshake_nread += n;
  return n;
}

int Client::quic_write_server_handshake(ngtcp2_crypto_level crypto_level,
                                        const uint8_t *data, size_t datalen) {
  if (quic.rx_crypto_level != crypto_level) {
    std::cerr << "Got crypto level "
              << ", want " << quic.rx_crypto_level << std::endl;
    return -1;
  }
  std::copy_n(data, datalen, std::back_inserter(quic.server_handshake));
  return 0;
}

void Client::quic_write_client_handshake(const uint8_t *data, size_t datalen) {
  assert(quic.tx_crypto_level < 2);
  quic_write_client_handshake(quic.crypto[quic.tx_crypto_level], data, datalen);
}

void Client::quic_write_client_handshake(Crypto &crypto, const uint8_t *data,
                                         size_t datalen) {
  assert(crypto.data.size() >= crypto.datalen + datalen);

  auto p = std::begin(crypto.data) + crypto.datalen;
  std::copy_n(data, datalen, p);
  crypto.datalen += datalen;

  ngtcp2_conn_submit_crypto_data(quic.conn, quic.tx_crypto_level, p, datalen);
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
  auto t = expiry < now ? 1e-9
                        : static_cast<ev_tstamp>(expiry - now) / NGTCP2_SECONDS;
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

  if (!session) {
    auto nwrite =
        ngtcp2_conn_write_pkt(quic.conn, &ps.path, buf.data(), quic.max_pktlen,
                              timestamp(worker->loop));
    if (nwrite < 0) {
      quic.last_error = quic::err_transport(nwrite);
      return -1;
    }

    quic_restart_pkt_timer();

    if (nwrite) {
      write_udp(reinterpret_cast<sockaddr *>(ps.path.remote.addr),
                ps.path.remote.addrlen, buf.data(), nwrite);

      ev_io_start(worker->loop, &wev);
      return 0;
    }

    // session might be initialized during ngtcp2_conn_write_pkt.
    if (!session) {
      ev_io_stop(worker->loop, &wev);
      return 0;
    }
  }

  auto s = static_cast<Http3Session *>(session.get());

  for (;;) {
    int64_t stream_id;
    int fin;
    ssize_t sveccnt = 0;

    if (ngtcp2_conn_get_max_data_left(quic.conn)) {
      sveccnt = s->write_stream(stream_id, fin, vec.data(), vec.size());
      if (sveccnt == -1) {
        return -1;
      }
    }

    ssize_t ndatalen;
    if (sveccnt == 0) {
      auto nwrite =
          ngtcp2_conn_write_pkt(quic.conn, &ps.path, buf.data(),
                                quic.max_pktlen, timestamp(worker->loop));
      if (nwrite < 0) {
        quic.last_error = quic::err_transport(nwrite);
        return -1;
      }

      quic_restart_pkt_timer();

      if (nwrite == 0) {
        ev_io_stop(worker->loop, &wev);
        return 0;
      }

      write_udp(reinterpret_cast<sockaddr *>(ps.path.remote.addr),
                ps.path.remote.addrlen, buf.data(), nwrite);

      ev_io_start(worker->loop, &wev);

      return 0;
    }

    auto v = vec.data();
    auto vcnt = static_cast<size_t>(sveccnt);
    for (;;) {
      auto nwrite = ngtcp2_conn_writev_stream(
          quic.conn, &ps.path, buf.data(), quic.max_pktlen, &ndatalen,
          NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id, fin,
          reinterpret_cast<const ngtcp2_vec *>(v), vcnt,
          timestamp(worker->loop));
      if (nwrite < 0) {
        auto should_break = false;
        switch (nwrite) {
        case NGTCP2_ERR_STREAM_DATA_BLOCKED:
          if (ngtcp2_conn_get_max_data_left(quic.conn) == 0) {
            return 0;
          }

          if (s->block_stream(stream_id) != 0) {
            return -1;
          }
          should_break = true;
          break;
        case NGTCP2_ERR_EARLY_DATA_REJECTED:
        case NGTCP2_ERR_STREAM_SHUT_WR:
        case NGTCP2_ERR_STREAM_NOT_FOUND: // This means that stream is
                                          // closed.
          assert(0);
          // TODO Perhaps, close stream or this should not happen?
          break;
        case NGTCP2_ERR_WRITE_STREAM_MORE:
          assert(ndatalen > 0);
          if (s->add_write_offset(stream_id, ndatalen) != 0) {
            return -1;
          }
          should_break = true;
          break;
        }

        if (should_break) {
          break;
        }

        quic.last_error = quic::err_transport(nwrite);
        return -1;
      }

      quic_restart_pkt_timer();

      if (nwrite == 0) {
        ev_io_stop(worker->loop, &wev);
        return 0;
      }

      if (ndatalen > 0) {
        if (s->add_write_offset(stream_id, ndatalen) != 0) {
          return -1;
        }
      }

      write_udp(reinterpret_cast<sockaddr *>(ps.path.remote.addr),
                ps.path.remote.addrlen, buf.data(), nwrite);

      ev_io_start(worker->loop, &wev);

      return 0;
    }
  }
}

} // namespace h2load
