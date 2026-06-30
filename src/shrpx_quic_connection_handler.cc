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
#include "shrpx_quic_connection_handler.h"

#include "ssl_compat.h"

#ifdef NGHTTP2_OPENSSL_IS_WOLFSSL
#  include <wolfssl/options.h>
#  include <wolfssl/openssl/rand.h>
#else // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)
#  include <openssl/rand.h>
#endif // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include "shrpx_worker.h"
#include "shrpx_client_handler.h"
#include "shrpx_log.h"
#include "shrpx_http3_upstream.h"
#include "shrpx_connection_handler.h"

namespace shrpx {

namespace {
void stateless_reset_bucket_regen_timercb(struct ev_loop *loop, ev_timer *w,
                                          int revents) {
  auto quic_conn_handler = static_cast<QUICConnectionHandler *>(w->data);

  quic_conn_handler->on_stateless_reset_bucket_regen();
}
} // namespace

QUICConnectionHandler::QUICConnectionHandler(Worker *worker) : worker_{worker} {
  ev_timer_init(&stateless_reset_bucket_regen_timer_,
                stateless_reset_bucket_regen_timercb, 0., 1.);
  stateless_reset_bucket_regen_timer_.data = this;
}

QUICConnectionHandler::~QUICConnectionHandler() {
  ev_timer_stop(worker_->get_loop(), &stateless_reset_bucket_regen_timer_);
}

void QUICConnectionHandler::handle_packet(const UpstreamAddr *faddr,
                                          const Address &remote_addr,
                                          const Address &local_addr,
                                          const ngtcp2_pkt_info &pi,
                                          std::span<const uint8_t> data) {
  int rv;
  ngtcp2_version_cid vc;

  rv = ngtcp2_pkt_decode_version_cid(&vc, data.data(), data.size(),
                                     SHRPX_QUIC_SCIDLEN);
  if (rv != 0) {
    if (rv == NGTCP2_ERR_VERSION_NEGOTIATION) {
      (void)send_version_negotiation(faddr, vc.version, {vc.dcid, vc.dcidlen},
                                     {vc.scid, vc.scidlen}, remote_addr,
                                     local_addr);

      return;
    }

    return;
  }

  auto config = get_config();

  ngtcp2_cid dcid_key;
  ngtcp2_cid_init(&dcid_key, vc.dcid, vc.dcidlen);

  auto conn_handler = worker_->get_connection_handler();

  ClientHandler *handler;

  auto &quicconf = config->quic;

  auto it = connections_.find(dcid_key);
  if (it == std::ranges::end(connections_)) {
    auto cwit = close_waits_.find(dcid_key);
    if (cwit != std::ranges::end(close_waits_)) {
      auto cw = (*cwit).second;

      cw->handle_packet(faddr, remote_addr, local_addr, pi, data);

      return;
    }

    if (data[0] & 0x80) {
      if (!generate_quic_hashed_connection_id(dcid_key, remote_addr, local_addr,
                                              dcid_key)) {
        return;
      }

      it = connections_.find(dcid_key);
      if (it == std::ranges::end(connections_)) {
        auto cwit = close_waits_.find(dcid_key);
        if (cwit != std::ranges::end(close_waits_)) {
          auto cw = (*cwit).second;

          cw->handle_packet(faddr, remote_addr, local_addr, pi, data);

          return;
        }
      }
    }
  }

  if (it == std::ranges::end(connections_)) {
    ConnectionID decrypted_dcid;

    auto &qkms = worker_->get_quic_keying_materials();
    const QUICKeyingMaterial *qkm = nullptr;

    if (vc.dcidlen == SHRPX_QUIC_SCIDLEN) {
      qkm = select_quic_keying_material(
        *qkms.get(), vc.dcid[0] & SHRPX_QUIC_DCID_KM_ID_MASK);

      if (!decrypt_quic_connection_id(decrypted_dcid,
                                      std::span{vc.dcid, vc.dcidlen}.subspan(
                                        SHRPX_QUIC_CID_WORKER_ID_OFFSET),
                                      qkm->cid_decryption_ctx)) {
        return;
      }

      if (qkm != &qkms->keying_materials.front() ||
          decrypted_dcid.worker != worker_->get_worker_id()) {
        auto maybe_quic_lwp =
          conn_handler->match_quic_lingering_worker_process_worker_id(
            decrypted_dcid.worker);
        if (maybe_quic_lwp) {
          (void)conn_handler->forward_quic_packet_to_lingering_worker_process(
            *maybe_quic_lwp, remote_addr, local_addr, pi, data);

          return;
        }
      }
    }

    // new connection

    auto &upstreamconf = config->conn.upstream;
    if (worker_->get_worker_stat()->num_connections >=
        upstreamconf.worker_connections) {
      if (log_enabled(INFO)) {
        Log{INFO} << "Too many connections >="
                  << upstreamconf.worker_connections;
      }

      return;
    }

    ngtcp2_pkt_hd hd;
    ngtcp2_cid odcid, *podcid = nullptr;
    std::span<const uint8_t> token;
    ngtcp2_token_type token_type = NGTCP2_TOKEN_TYPE_UNKNOWN;

    switch (ngtcp2_accept(&hd, data.data(), data.size())) {
    case 0: {
      // If we get Initial and it has the Worker ID of this worker, it
      // is likely that client is intentionally use the prefix.  Just
      // drop it.
      if (vc.dcidlen == SHRPX_QUIC_SCIDLEN) {
        if (qkm != &qkms->keying_materials.front()) {
          qkm = &qkms->keying_materials.front();

          if (!decrypt_quic_connection_id(
                decrypted_dcid,
                std::span{vc.dcid, vc.dcidlen}.subspan(
                  SHRPX_QUIC_CID_WORKER_ID_OFFSET),
                qkm->cid_decryption_ctx)) {
            return;
          }
        }

        if (decrypted_dcid.worker == worker_->get_worker_id()) {
          return;
        }
      }

      if (worker_->get_graceful_shutdown()) {
        (void)send_connection_close(faddr, hd.version, hd.dcid, hd.scid,
                                    remote_addr, local_addr,
                                    NGTCP2_CONNECTION_REFUSED, data.size() * 3);
        return;
      }

      if (hd.tokenlen == 0) {
        if (quicconf.upstream.require_token) {
          (void)send_retry(faddr, vc.version, {vc.dcid, vc.dcidlen},
                           {vc.scid, vc.scidlen}, remote_addr, local_addr,
                           data.size() * 3);

          return;
        }

        break;
      }

      switch (hd.token[0]) {
      case NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2: {
        if (vc.dcidlen != SHRPX_QUIC_SCIDLEN) {
          // Initial packets with Retry token must have DCID chosen by
          // server.
          return;
        }

        auto qkm = select_quic_keying_material(
          *qkms.get(), vc.dcid[0] & SHRPX_QUIC_DCID_KM_ID_MASK);

        if (auto rv = verify_retry_token(
              odcid, {hd.token, hd.tokenlen}, hd.version, hd.dcid,
              remote_addr.as_sockaddr(), remote_addr.size(), qkm->secret);
            !rv) {
          if (log_enabled(INFO)) {
            Log{INFO} << "Failed to validate Retry token from remote="
                      << util::to_numeric_addr(&remote_addr);
          }

          if (rv.error() != Error::QUIC_UNREADABLE_TOKEN ||
              quicconf.upstream.require_token) {
            // 2nd Retry packet is not allowed, so send
            // CONNECTION_CLOSE with INVALID_TOKEN.
            (void)send_connection_close(faddr, hd.version, hd.dcid, hd.scid,
                                        remote_addr, local_addr,
                                        NGTCP2_INVALID_TOKEN, data.size() * 3);
            return;
          }

          // Ignore unreadable token.

          break;
        }

        if (log_enabled(INFO)) {
          Log{INFO} << "Successfully validated Retry token from remote="
                    << util::to_numeric_addr(&remote_addr);
        }

        podcid = &odcid;
        token = {hd.token, hd.tokenlen};
        token_type = NGTCP2_TOKEN_TYPE_RETRY;

        break;
      }
      case NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR: {
        // If a token is a regular token, it must be at least
        // NGTCP2_MIN_INITIAL_DCIDLEN bytes long.
        if (vc.dcidlen < NGTCP2_MIN_INITIAL_DCIDLEN) {
          return;
        }

        if (hd.tokenlen != NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN + 1) {
          if (log_enabled(INFO)) {
            Log{INFO} << "Failed to validate token from remote="
                      << util::to_numeric_addr(&remote_addr);
          }

          if (quicconf.upstream.require_token) {
            (void)send_retry(faddr, vc.version, {vc.dcid, vc.dcidlen},
                             {vc.scid, vc.scidlen}, remote_addr, local_addr,
                             data.size() * 3);

            return;
          }

          break;
        }

        auto qkm = select_quic_keying_material(
          *qkms.get(), hd.token[NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN]);

        if (!verify_token({hd.token, hd.tokenlen}, remote_addr.as_sockaddr(),
                          remote_addr.size(), qkm->secret)) {
          if (log_enabled(INFO)) {
            Log{INFO} << "Failed to validate token from remote="
                      << util::to_numeric_addr(&remote_addr);
          }

          if (quicconf.upstream.require_token) {
            (void)send_retry(faddr, vc.version, {vc.dcid, vc.dcidlen},
                             {vc.scid, vc.scidlen}, remote_addr, local_addr,
                             data.size() * 3);

            return;
          }

          break;
        }

        if (log_enabled(INFO)) {
          Log{INFO} << "Successfully validated token from remote="
                    << util::to_numeric_addr(&remote_addr);
        }

        token = {hd.token, hd.tokenlen};
        token_type = NGTCP2_TOKEN_TYPE_NEW_TOKEN;

        break;
      }
      default:
        if (quicconf.upstream.require_token) {
          (void)send_retry(faddr, vc.version, {vc.dcid, vc.dcidlen},
                           {vc.scid, vc.scidlen}, remote_addr, local_addr,
                           data.size() * 3);

          return;
        }

        break;
      }

      break;
    }
    default:
      if (!(data[0] & 0x80) && vc.dcidlen == SHRPX_QUIC_SCIDLEN &&
          decrypted_dcid.worker != worker_->get_worker_id()) {
        if (!config->single_thread && conn_handler->forward_quic_packet(
                                        faddr, remote_addr, local_addr, pi,
                                        decrypted_dcid.worker, data)) {
          return;
        }

        if (data.size() >= SHRPX_QUIC_SCIDLEN + 21) {
          (void)send_stateless_reset(faddr, data.size(), {vc.dcid, vc.dcidlen},
                                     remote_addr, local_addr);
        }
      }

      return;
    }

    auto maybe_handler = handle_new_connection(faddr, remote_addr, local_addr,
                                               hd, podcid, token, token_type);
    if (!maybe_handler) {
      return;
    }

    handler = maybe_handler->release();
  } else {
    handler = (*it).second;
  }

  if (!handler->read_quic(faddr, remote_addr, local_addr, pi, data)) {
    delete handler;
    return;
  }

  handler->signal_write();
}

std::expected<std::unique_ptr<ClientHandler>, Error>
QUICConnectionHandler::handle_new_connection(
  const UpstreamAddr *faddr, const Address &remote_addr,
  const Address &local_addr, const ngtcp2_pkt_hd &hd, const ngtcp2_cid *odcid,
  std::span<const uint8_t> token, ngtcp2_token_type token_type) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> service;
  int rv;

  rv = getnameinfo(remote_addr.as_sockaddr(), remote_addr.size(), host.data(),
                   host.size(), service.data(), service.size(),
                   NI_NUMERICHOST | NI_NUMERICSERV);
  if (rv != 0) {
    Log{ERROR} << "getnameinfo() failed: " << gai_strerror(rv);

    return std::unexpected{Error::LIBC};
  }

  auto ssl_ctx = worker_->get_quic_sv_ssl_ctx();

  assert(ssl_ctx);

  auto maybe_ssl = tls::create_ssl(ssl_ctx);
  if (!maybe_ssl) {
    return std::unexpected{maybe_ssl.error()};
  }

  auto ssl = *maybe_ssl;

#if !OPENSSL_3_5_0_API &&                                                      \
  (defined(NGHTTP2_GENUINE_OPENSSL) || defined(NGHTTP2_OPENSSL_IS_WOLFSSL))
  assert(SSL_is_quic(ssl));
#endif // !OPENSSL_3_5_0_API && (defined(NGHTTP2_GENUINE_OPENSSL) ||
       // defined(NGHTTP2_OPENSSL_IS_WOLFSSL))

  SSL_set_accept_state(ssl);

  auto config = get_config();
  auto &quicconf = config->quic;

  if (quicconf.upstream.early_data) {
#if OPENSSL_3_5_0_API
    SSL_set_quic_tls_early_data_enabled(ssl, 1);
#elif defined(NGHTTP2_GENUINE_OPENSSL) ||                                      \
  (defined(NGHTTP2_OPENSSL_IS_WOLFSSL) && defined(WOLFSSL_EARLY_DATA))
    SSL_set_quic_early_data_enabled(ssl, 1);
#elif defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
    SSL_set_early_data_enabled(ssl, 1);
#endif // defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
  }

  // Disable TLS session ticket if we don't have working ticket
  // keys.
  if (!worker_->get_ticket_keys()) {
    SSL_set_options(ssl, SSL_OP_NO_TICKET);
  }

  auto handler = std::make_unique<ClientHandler>(
    worker_, faddr->fd, ssl, std::string_view{host.data()},
    std::string_view{service.data()}, remote_addr.family(), faddr);

  auto &fwdconf = config->http.forwarded;

  if (fwdconf.params & FORWARDED_BY) {
    handler->set_local_hostport(local_addr.as_sockaddr(), local_addr.size());
  }

  auto upstream = std::make_unique<Http3Upstream>(handler.get());
  if (auto rv = upstream->init(faddr, remote_addr, local_addr, hd, odcid, token,
                               token_type);
      !rv) {
    return std::unexpected{rv.error()};
  }

  handler->setup_http3_upstream(std::move(upstream));

  return handler;
}

namespace {
uint32_t generate_reserved_version(const Address &addr, uint32_t version) {
  uint32_t h = 0x811C9DC5u;
  const uint8_t *p = reinterpret_cast<const uint8_t *>(addr.as_sockaddr());
  const uint8_t *ep = p + addr.size();

  for (; p != ep; ++p) {
    h ^= *p;
    h *= 0x01000193U;
  }

  version = htonl(version);
  p = (const uint8_t *)&version;
  ep = p + sizeof(version);

  for (; p != ep; ++p) {
    h ^= *p;
    h *= 0x01000193U;
  }

  h &= 0xF0F0F0F0U;
  h |= 0x0A0A0A0AU;

  return h;
}
} // namespace

std::expected<void, Error> QUICConnectionHandler::send_retry(
  const UpstreamAddr *faddr, uint32_t version,
  std::span<const uint8_t> ini_dcid, std::span<const uint8_t> ini_scid,
  const Address &remote_addr, const Address &local_addr, size_t max_pktlen) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> port;

  const auto &remote_sockaddr = remote_addr.as_sockaddr();
  auto remote_sockaddrlen = remote_addr.size();

  if (getnameinfo(remote_sockaddr, remote_sockaddrlen, host.data(), host.size(),
                  port.data(), port.size(),
                  NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
    return std::unexpected{Error::LIBC};
  }

  auto config = get_config();
  auto &quicconf = config->quic;

  auto &qkms = worker_->get_quic_keying_materials();
  auto &qkm = qkms->keying_materials.front();

  ngtcp2_cid retry_scid;

  if (auto rv = generate_quic_retry_connection_id(
        retry_scid, quicconf.server_id, qkm.id, qkm.cid_encryption_ctx);
      !rv) {
    return rv;
  }

  ngtcp2_cid idcid, iscid;
  ngtcp2_cid_init(&idcid, ini_dcid.data(), ini_dcid.size());
  ngtcp2_cid_init(&iscid, ini_scid.data(), ini_scid.size());

  std::array<uint8_t, NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2> tokenbuf;

  auto maybe_token =
    generate_retry_token(tokenbuf, version, remote_sockaddr, remote_sockaddrlen,
                         retry_scid, idcid, qkm.secret);
  if (!maybe_token) {
    return std::unexpected{maybe_token.error()};
  }

  std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> buf;
  auto buflen = std::min(max_pktlen, buf.size());
  auto token = *maybe_token;

  auto nwrite =
    ngtcp2_crypto_write_retry(buf.data(), buflen, version, &iscid, &retry_scid,
                              &idcid, token.data(), token.size());
  if (nwrite < 0) {
    Log{ERROR} << "ngtcp2_crypto_write_retry: "
               << ngtcp2_strerror(static_cast<int>(nwrite));
    return std::unexpected{Error::QUIC};
  }

  assert(nwrite);

  auto retrylen = as_unsigned(nwrite);
  auto retry = std::make_unique_for_overwrite<uint8_t[]>(retrylen);

  std::ranges::copy_n(std::ranges::begin(buf), as_signed(retrylen),
                      retry.get());

  (void)quic_send_packet(faddr, remote_addr, local_addr,
                         {retry.get(), retrylen});

  if (auto rv = generate_quic_hashed_connection_id(idcid, remote_addr,
                                                   local_addr, idcid);
      !rv) {
    return rv;
  }

  auto d =
    static_cast<ev_tstamp>(NGTCP2_DEFAULT_INITIAL_RTT * 3) / NGTCP2_SECONDS;

  if (log_enabled(INFO)) {
    Log{INFO} << "Enter close-wait period " << d << "s with " << retrylen
              << " bytes sentinel packet";
  }

  auto cw = std::make_unique<CloseWait>(worker_, std::vector<ngtcp2_cid>{idcid},
                                        std::move(retry), retrylen, d);

  add_close_wait(cw.release());

  return {};
}

std::expected<void, Error> QUICConnectionHandler::send_version_negotiation(
  const UpstreamAddr *faddr, uint32_t version,
  std::span<const uint8_t> ini_dcid, std::span<const uint8_t> ini_scid,
  const Address &remote_addr, const Address &local_addr) {
  auto sv = std::to_array({
    generate_reserved_version(remote_addr, version),
    NGTCP2_PROTO_VER_V1,
  });

  std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> buf;

  uint8_t rand_byte;
  util::random_bytes(&rand_byte, &rand_byte + 1, worker_->get_randgen());

  auto nwrite = ngtcp2_pkt_write_version_negotiation(
    buf.data(), buf.size(), rand_byte, ini_scid.data(), ini_scid.size(),
    ini_dcid.data(), ini_dcid.size(), sv.data(), sv.size());
  if (nwrite < 0) {
    Log{ERROR} << "ngtcp2_pkt_write_version_negotiation: "
               << ngtcp2_strerror(static_cast<int>(nwrite));
    return std::unexpected{Error::QUIC};
  }

  auto pkt = std::span{buf}.first(as_unsigned(nwrite));
  return quic_send_packet(faddr, remote_addr, local_addr, pkt);
}

std::expected<void, Error> QUICConnectionHandler::send_stateless_reset(
  const UpstreamAddr *faddr, size_t pktlen, std::span<const uint8_t> dcid,
  const Address &remote_addr, const Address &local_addr) {
  if (stateless_reset_bucket_ == 0) {
    if (log_enabled(INFO)) {
      Log{INFO} << "Stateless Reset bucket has been depleted";
    }

    return {};
  }

  --stateless_reset_bucket_;

  if (!ev_is_active(&stateless_reset_bucket_regen_timer_)) {
    ev_timer_again(worker_->get_loop(), &stateless_reset_bucket_regen_timer_);
  }

  ngtcp2_stateless_reset_token token;
  ngtcp2_cid cid;

  ngtcp2_cid_init(&cid, dcid.data(), dcid.size());

  auto &qkms = worker_->get_quic_keying_materials();
  auto &qkm = qkms->keying_materials.front();

  if (auto rv =
        generate_quic_stateless_reset_token(token.data, cid, qkm.secret);
      !rv) {
    return rv;
  }

  // SCID + minimum expansion - NGTCP2_STATELESS_RESET_TOKENLEN
  constexpr size_t max_rand_byteslen =
    NGTCP2_MAX_CIDLEN + 22 - NGTCP2_STATELESS_RESET_TOKENLEN;

  size_t rand_byteslen;

  if (pktlen <= 43) {
    // As per
    // https://datatracker.ietf.org/doc/html/rfc9000#section-10.3
    rand_byteslen = pktlen - NGTCP2_STATELESS_RESET_TOKENLEN - 1;
  } else {
    rand_byteslen = max_rand_byteslen;
  }

  std::array<uint8_t, max_rand_byteslen> rand_bytes;

  if (RAND_bytes(rand_bytes.data(), static_cast<nghttp2_ssl_rand_length_type>(
                                      rand_byteslen)) != 1) {
    return std::unexpected{Error::CRYPTO};
  }

  std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> buf;

  auto nwrite = ngtcp2_pkt_write_stateless_reset2(
    buf.data(), buf.size(), &token, rand_bytes.data(), rand_byteslen);
  if (nwrite < 0) {
    Log{ERROR} << "ngtcp2_pkt_write_stateless_reset: "
               << ngtcp2_strerror(static_cast<int>(nwrite));
    return std::unexpected{Error::QUIC};
  }

  if (log_enabled(INFO)) {
    Log{INFO} << "Send stateless_reset to remote="
              << util::to_numeric_addr(&remote_addr)
              << " dcid=" << util::format_hex(dcid);
  }

  auto pkt = std::span{buf}.first(as_unsigned(nwrite));
  return quic_send_packet(faddr, remote_addr, local_addr, pkt);
}

std::expected<void, Error> QUICConnectionHandler::send_connection_close(
  const UpstreamAddr *faddr, uint32_t version, const ngtcp2_cid &ini_dcid,
  const ngtcp2_cid &ini_scid, const Address &remote_addr,
  const Address &local_addr, uint64_t error_code, size_t max_pktlen) {
  std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> buf;

  max_pktlen = std::min(max_pktlen, buf.size());

  auto nwrite = ngtcp2_crypto_write_connection_close(
    buf.data(), max_pktlen, version, &ini_scid, &ini_dcid, error_code, nullptr,
    0);
  if (nwrite < 0) {
    Log{ERROR} << "ngtcp2_crypto_write_connection_close failed";
    return std::unexpected{Error::QUIC};
  }

  if (log_enabled(INFO)) {
    Log{INFO} << "Send Initial CONNECTION_CLOSE with error_code=" << log::hex
              << error_code << log::dec
              << " to remote=" << util::to_numeric_addr(&remote_addr)
              << " dcid="
              << util::format_hex(std::span{ini_scid.data, ini_scid.datalen})
              << " scid="
              << util::format_hex(std::span{ini_dcid.data, ini_dcid.datalen});
  }

  auto pkt = std::span{buf}.first(as_unsigned(nwrite));
  return quic_send_packet(faddr, remote_addr, local_addr, pkt);
}

void QUICConnectionHandler::add_connection_id(const ngtcp2_cid &cid,
                                              ClientHandler *handler) {
  connections_.emplace(cid, handler);
}

void QUICConnectionHandler::remove_connection_id(const ngtcp2_cid &cid) {
  connections_.erase(cid);
}

void QUICConnectionHandler::add_close_wait(CloseWait *cw) {
  for (auto &cid : cw->scids) {
    close_waits_.emplace(cid, cw);
  }
}

void QUICConnectionHandler::remove_close_wait(const CloseWait *cw) {
  for (auto &cid : cw->scids) {
    close_waits_.erase(cid);
  }
}

void QUICConnectionHandler::on_stateless_reset_bucket_regen() {
  assert(stateless_reset_bucket_ < SHRPX_QUIC_STATELESS_RESET_BURST);

  if (++stateless_reset_bucket_ == SHRPX_QUIC_STATELESS_RESET_BURST) {
    ev_timer_stop(worker_->get_loop(), &stateless_reset_bucket_regen_timer_);
  }
}

static void close_wait_timeoutcb(struct ev_loop *loop, ev_timer *w,
                                 int revents) {
  auto cw = static_cast<CloseWait *>(w->data);

  if (log_enabled(INFO)) {
    Log{INFO} << "close-wait period finished";
  }

  auto quic_conn_handler = cw->worker->get_quic_connection_handler();
  quic_conn_handler->remove_close_wait(cw);

  delete cw;
}

CloseWait::CloseWait(Worker *worker, std::vector<ngtcp2_cid> scids,
                     std::unique_ptr<uint8_t[]> pkt, size_t pktlen,
                     ev_tstamp period)
  : worker{worker},
    scids{std::move(scids)},
    pkt{std::move(pkt)},
    pktlen{pktlen},
    bytes_recv{0},
    bytes_sent{0},
    num_pkts_recv{0},
    next_pkts_recv{1} {
  ++worker->get_worker_stat()->num_close_waits;

  ev_timer_init(&timer, close_wait_timeoutcb, period, 0.);
  timer.data = this;

  ev_timer_start(worker->get_loop(), &timer);
}

CloseWait::~CloseWait() {
  auto loop = worker->get_loop();

  ev_timer_stop(loop, &timer);

  auto worker_stat = worker->get_worker_stat();
  --worker_stat->num_close_waits;

  if (worker->get_graceful_shutdown() && worker_stat->num_connections == 0 &&
      worker_stat->num_close_waits == 0) {
    ev_break(loop);
  }
}

void CloseWait::handle_packet(const UpstreamAddr *faddr,
                              const Address &remote_addr,
                              const Address &local_addr,
                              const ngtcp2_pkt_info &pi,
                              std::span<const uint8_t> data) {
  if (pktlen == 0) {
    return;
  }

  ++num_pkts_recv;
  bytes_recv += data.size();

  if (bytes_sent + pktlen > 3 * bytes_recv || next_pkts_recv > num_pkts_recv) {
    return;
  }

  if (!quic_send_packet(faddr, remote_addr, local_addr, {pkt.get(), pktlen})) {
    return;
  }

  next_pkts_recv *= 2;
  bytes_sent += pktlen;
}

} // namespace shrpx
