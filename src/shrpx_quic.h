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
#ifndef SHRPX_QUIC_H
#define SHRPX_QUIC_H

#include "shrpx.h"

#include <stdint.h>

#include <functional>

#include <ngtcp2/ngtcp2.h>

#include "network.h"

using namespace nghttp2;

namespace std {
template <> struct hash<ngtcp2_cid> {
  std::size_t operator()(const ngtcp2_cid &cid) const noexcept {
    // FNV-1a 64bits variant
    constexpr uint64_t basis = 0xCBF29CE484222325ULL;
    const uint8_t *p = cid.data, *end = cid.data + cid.datalen;
    uint64_t h = basis;

    for (; p != end;) {
      h ^= *p++;
      h *= basis;
    }

    return static_cast<size_t>(h);
  }
};
} // namespace std

bool operator==(const ngtcp2_cid &lhs, const ngtcp2_cid &rhs);

namespace shrpx {

struct UpstreamAddr;

constexpr size_t SHRPX_QUIC_SCIDLEN = 20;
constexpr size_t SHRPX_QUIC_CID_PREFIXLEN = 8;
constexpr size_t SHRPX_QUIC_DECRYPTED_DCIDLEN = 16;
constexpr size_t SHRPX_QUIC_CID_ENCRYPTION_KEYLEN = 16;
constexpr size_t SHRPX_QUIC_MAX_UDP_PAYLOAD_SIZE = 1472;
constexpr size_t SHRPX_QUIC_STATELESS_RESET_SECRETLEN = 32;
constexpr size_t SHRPX_QUIC_TOKEN_SECRETLEN = 32;
constexpr size_t SHRPX_QUIC_CONN_CLOSE_PKTLEN = 256;
constexpr size_t SHRPX_QUIC_STATELESS_RESET_BURST = 100;

ngtcp2_tstamp quic_timestamp();

int quic_send_packet(const UpstreamAddr *faddr, const sockaddr *remote_sa,
                     size_t remote_salen, const sockaddr *local_sa,
                     size_t local_salen, const uint8_t *data, size_t datalen,
                     size_t gso_size);

int generate_quic_connection_id(ngtcp2_cid &cid, size_t cidlen);

int generate_encrypted_quic_connection_id(ngtcp2_cid &cid, size_t cidlen,
                                          const uint8_t *cid_prefix,
                                          const uint8_t *key);

int encrypt_quic_connection_id(uint8_t *dest, const uint8_t *src,
                               const uint8_t *key);

int decrypt_quic_connection_id(uint8_t *dest, const uint8_t *src,
                               const uint8_t *key);

int generate_quic_hashed_connection_id(ngtcp2_cid &dest,
                                       const Address &remote_addr,
                                       const Address &local_addr,
                                       const ngtcp2_cid &cid);

int generate_quic_stateless_reset_token(uint8_t *token, const ngtcp2_cid &cid,
                                        const uint8_t *secret,
                                        size_t secretlen);

int generate_quic_stateless_reset_secret(uint8_t *secret);

int generate_quic_token_secret(uint8_t *secret);

int generate_retry_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa,
                         socklen_t salen, const ngtcp2_cid &retry_scid,
                         const ngtcp2_cid &odcid, const uint8_t *token_secret);

int verify_retry_token(ngtcp2_cid &odcid, const uint8_t *token, size_t tokenlen,
                       const ngtcp2_cid &dcid, const sockaddr *sa,
                       socklen_t salen, const uint8_t *token_secret);

int generate_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa,
                   size_t salen, const uint8_t *token_secret);

int verify_token(const uint8_t *token, size_t tokenlen, const sockaddr *sa,
                 socklen_t salen, const uint8_t *token_secret);

} // namespace shrpx

#endif // SHRPX_QUIC_H
