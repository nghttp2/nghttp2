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

#include <ngtcp2/ngtcp2.h>

#include "shrpx_worker.h"
#include "shrpx_client_handler.h"
#include "shrpx_log.h"
#include "shrpx_quic.h"
#include "shrpx_http3_upstream.h"

namespace shrpx {

QUICConnectionHandler::QUICConnectionHandler(Worker *worker)
    : worker_{worker} {}

QUICConnectionHandler::~QUICConnectionHandler() {}

namespace {
std::string make_cid_key(const uint8_t *dcid, size_t dcidlen) {
  return std::string{dcid, dcid + dcidlen};
}
} // namespace

namespace {
std::string make_cid_key(const ngtcp2_cid *cid) {
  return make_cid_key(cid->data, cid->datalen);
}
} // namespace

int QUICConnectionHandler::handle_packet(const UpstreamAddr *faddr,
                                         const Address &remote_addr,
                                         const Address &local_addr,
                                         const uint8_t *data, size_t datalen) {
  int rv;
  uint32_t version;
  const uint8_t *dcid, *scid;
  size_t dcidlen, scidlen;

  rv = ngtcp2_pkt_decode_version_cid(&version, &dcid, &dcidlen, &scid, &scidlen,
                                     data, datalen, SHRPX_QUIC_SCIDLEN);
  if (rv != 0) {
    if (rv == 1) {
      send_version_negotiation(faddr, version, scid, scidlen, dcid, dcidlen,
                               remote_addr, local_addr);
    }

    return 0;
  }

  auto dcid_key = make_cid_key(dcid, dcidlen);

  ClientHandler *handler;

  auto it = connections_.find(dcid_key);
  if (it == std::end(connections_)) {
    // new connection

    ngtcp2_pkt_hd hd;

    switch (ngtcp2_accept(&hd, data, datalen)) {
    case 0:
      break;
    case NGTCP2_ERR_RETRY:
      // TODO Send retry
      return 0;
    case NGTCP2_ERR_VERSION_NEGOTIATION:
      send_version_negotiation(faddr, version, scid, scidlen, dcid, dcidlen,
                               remote_addr, local_addr);
      return 0;
    default:
      // TODO Must be rate limited
      send_stateless_reset(faddr, dcid, dcidlen, remote_addr, local_addr);
      return 0;
    }

    handler = handle_new_connection(faddr, remote_addr, local_addr, hd);
    if (handler == nullptr) {
      return 0;
    }
  } else {
    handler = (*it).second;
  }

  if (handler->read_quic(faddr, remote_addr, local_addr, data, datalen) != 0) {
    delete handler;
    return 0;
  }

  handler->signal_write();

  return 0;
}

ClientHandler *QUICConnectionHandler::handle_new_connection(
    const UpstreamAddr *faddr, const Address &remote_addr,
    const Address &local_addr, const ngtcp2_pkt_hd &hd) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> service;
  int rv;

  rv = getnameinfo(&remote_addr.su.sa, remote_addr.len, host.data(),
                   host.size(), service.data(), service.size(),
                   NI_NUMERICHOST | NI_NUMERICSERV);
  if (rv != 0) {
    LOG(ERROR) << "getnameinfo() failed: " << gai_strerror(rv);

    return nullptr;
  }

  auto ssl_ctx = worker_->get_quic_sv_ssl_ctx();

  assert(ssl_ctx);

  auto ssl = tls::create_ssl(ssl_ctx);
  if (ssl == nullptr) {
    return nullptr;
  }

  assert(SSL_is_quic(ssl));

  SSL_set_accept_state(ssl);

  // Disable TLS session ticket if we don't have working ticket
  // keys.
  if (!worker_->get_ticket_keys()) {
    SSL_set_options(ssl, SSL_OP_NO_TICKET);
  }

  auto handler = std::make_unique<ClientHandler>(
      worker_, faddr->fd, ssl, StringRef{host.data()},
      StringRef{service.data()}, remote_addr.su.sa.sa_family, faddr);

  auto upstream = std::make_unique<Http3Upstream>(handler.get());
  if (upstream->init(faddr, remote_addr, local_addr, hd) != 0) {
    return nullptr;
  }

  handler->setup_http3_upstream(std::move(upstream));

  return handler.release();
}

namespace {
uint32_t generate_reserved_version(const Address &addr, uint32_t version) {
  uint32_t h = 0x811C9DC5u;
  const uint8_t *p = reinterpret_cast<const uint8_t *>(&addr.su.sa);
  const uint8_t *ep = p + addr.len;

  for (; p != ep; ++p) {
    h ^= *p;
    h *= 0x01000193u;
  }

  version = htonl(version);
  p = (const uint8_t *)&version;
  ep = p + sizeof(version);

  for (; p != ep; ++p) {
    h ^= *p;
    h *= 0x01000193u;
  }

  h &= 0xf0f0f0f0u;
  h |= 0x0a0a0a0au;

  return h;
}
} // namespace

int QUICConnectionHandler::send_version_negotiation(
    const UpstreamAddr *faddr, uint32_t version, const uint8_t *dcid,
    size_t dcidlen, const uint8_t *scid, size_t scidlen,
    const Address &remote_addr, const Address &local_addr) {
  std::array<uint32_t, 2> sv;

  sv[0] = generate_reserved_version(remote_addr, version);
  sv[1] = NGTCP2_PROTO_VER_V1;

  std::array<uint8_t, 1280> buf;

  uint8_t rand_byte;
  util::random_bytes(&rand_byte, &rand_byte + 1, worker_->get_randgen());

  auto nwrite = ngtcp2_pkt_write_version_negotiation(
      buf.data(), buf.size(), rand_byte, dcid, dcidlen, scid, scidlen,
      sv.data(), sv.size());
  if (nwrite < 0) {
    LOG(ERROR) << "ngtcp2_pkt_write_version_negotiation: "
               << ngtcp2_strerror(nwrite);
    return -1;
  }

  return quic_send_packet(faddr, &remote_addr.su.sa, remote_addr.len,
                          &local_addr.su.sa, local_addr.len, buf.data(), nwrite,
                          0);
}

int QUICConnectionHandler::send_stateless_reset(const UpstreamAddr *faddr,
                                                const uint8_t *dcid,
                                                size_t dcidlen,
                                                const Address &remote_addr,
                                                const Address &local_addr) {
  int rv;
  std::array<uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> token;
  ngtcp2_cid cid;

  ngtcp2_cid_init(&cid, dcid, dcidlen);

  auto config = get_config();
  auto &quicconf = config->quic;
  auto &stateless_resetconf = quicconf.stateless_reset;

  rv = generate_quic_stateless_reset_token(token.data(), &cid,
                                           stateless_resetconf.secret.data(),
                                           stateless_resetconf.secret.size());
  if (rv != 0) {
    return -1;
  }

  std::array<uint8_t, NGTCP2_MIN_STATELESS_RESET_RANDLEN> rand_bytes;

  if (RAND_bytes(rand_bytes.data(), rand_bytes.size()) != 1) {
    return -1;
  }

  std::array<uint8_t, 1280> buf;

  auto nwrite =
      ngtcp2_pkt_write_stateless_reset(buf.data(), buf.size(), token.data(),
                                       rand_bytes.data(), rand_bytes.size());
  if (nwrite < 0) {
    LOG(ERROR) << "ngtcp2_pkt_write_stateless_reset: "
               << ngtcp2_strerror(nwrite);
    return -1;
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Send stateless_reset to remote="
              << util::to_numeric_addr(&remote_addr)
              << " dcid=" << util::format_hex(dcid, dcidlen);
  }

  return quic_send_packet(faddr, &remote_addr.su.sa, remote_addr.len,
                          &local_addr.su.sa, local_addr.len, buf.data(), nwrite,
                          0);
}

void QUICConnectionHandler::add_connection_id(const ngtcp2_cid *cid,
                                              ClientHandler *handler) {
  auto key = make_cid_key(cid);
  connections_.emplace(key, handler);
}

void QUICConnectionHandler::remove_connection_id(const ngtcp2_cid *cid) {
  auto key = make_cid_key(cid);
  connections_.erase(key);
}

} // namespace shrpx
