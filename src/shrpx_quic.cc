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
#include "shrpx_quic.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/udp.h>

#include <array>
#include <chrono>

#include <ngtcp2/ngtcp2_crypto.h>

#include <nghttp3/nghttp3.h>

#include <openssl/rand.h>

#include "shrpx_config.h"
#include "shrpx_log.h"
#include "util.h"
#include "xsi_strerror.h"

using namespace nghttp2;

namespace shrpx {

ngtcp2_tstamp quic_timestamp() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

int quic_send_packet(const UpstreamAddr *faddr, const sockaddr *remote_sa,
                     size_t remote_salen, const sockaddr *local_sa,
                     size_t local_salen, const uint8_t *data, size_t datalen,
                     size_t gso_size) {
  iovec msg_iov = {const_cast<uint8_t *>(data), datalen};
  msghdr msg{};
  msg.msg_name = const_cast<sockaddr *>(remote_sa);
  msg.msg_namelen = remote_salen;
  msg.msg_iov = &msg_iov;
  msg.msg_iovlen = 1;

  uint8_t msg_ctrl[
#ifdef UDP_SEGMENT
      CMSG_SPACE(sizeof(uint16_t)) +
#endif // UDP_SEGMENT
      CMSG_SPACE(sizeof(in6_pktinfo))];

  memset(msg_ctrl, 0, sizeof(msg_ctrl));

  msg.msg_control = msg_ctrl;
  msg.msg_controllen = sizeof(msg_ctrl);

  size_t controllen = 0;

  auto cm = CMSG_FIRSTHDR(&msg);

  switch (local_sa->sa_family) {
  case AF_INET: {
    controllen += CMSG_SPACE(sizeof(in_pktinfo));
    cm->cmsg_level = IPPROTO_IP;
    cm->cmsg_type = IP_PKTINFO;
    cm->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
    auto pktinfo = reinterpret_cast<in_pktinfo *>(CMSG_DATA(cm));
    memset(pktinfo, 0, sizeof(in_pktinfo));
    auto addrin =
        reinterpret_cast<sockaddr_in *>(const_cast<sockaddr *>(local_sa));
    pktinfo->ipi_spec_dst = addrin->sin_addr;
    break;
  }
  case AF_INET6: {
    controllen += CMSG_SPACE(sizeof(in6_pktinfo));
    cm->cmsg_level = IPPROTO_IPV6;
    cm->cmsg_type = IPV6_PKTINFO;
    cm->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
    auto pktinfo = reinterpret_cast<in6_pktinfo *>(CMSG_DATA(cm));
    memset(pktinfo, 0, sizeof(in6_pktinfo));
    auto addrin =
        reinterpret_cast<sockaddr_in6 *>(const_cast<sockaddr *>(local_sa));
    pktinfo->ipi6_addr = addrin->sin6_addr;
    break;
  }
  default:
    assert(0);
  }

#ifdef UDP_SEGMENT
  if (gso_size && datalen > gso_size) {
    controllen += CMSG_SPACE(sizeof(uint16_t));
    cm = CMSG_NXTHDR(&msg, cm);
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    *(reinterpret_cast<uint16_t *>(CMSG_DATA(cm))) = gso_size;
  }
#endif // UDP_SEGMENT

  msg.msg_controllen = controllen;

  ssize_t nwrite;

  do {
    nwrite = sendmsg(faddr->fd, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1) {
    return -1;
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "QUIC sent packet: local="
              << util::to_numeric_addr(local_sa, local_salen)
              << " remote=" << util::to_numeric_addr(remote_sa, remote_salen)
              << " " << nwrite << " bytes";
  }

  return 0;
}

int generate_quic_connection_id(ngtcp2_cid *cid, size_t cidlen) {
  if (RAND_bytes(cid->data, cidlen) != 1) {
    return -1;
  }

  cid->datalen = cidlen;

  return 0;
}

int generate_quic_connection_id(ngtcp2_cid *cid, size_t cidlen,
                                const uint8_t *cid_prefix) {
  assert(cidlen > SHRPX_QUIC_CID_PREFIXLEN);

  auto p = std::copy_n(cid_prefix, SHRPX_QUIC_CID_PREFIXLEN, cid->data);

  if (RAND_bytes(p, cidlen - SHRPX_QUIC_CID_PREFIXLEN) != 1) {
    return -1;
  }

  cid->datalen = cidlen;

  return 0;
}

int generate_quic_stateless_reset_token(uint8_t *token, const ngtcp2_cid *cid,
                                        const uint8_t *secret,
                                        size_t secretlen) {
  ngtcp2_crypto_md md;
  ngtcp2_crypto_md_init(&md, const_cast<EVP_MD *>(EVP_sha256()));

  if (ngtcp2_crypto_generate_stateless_reset_token(token, &md, secret,
                                                   secretlen, cid) != 0) {
    return -1;
  }

  return 0;
}

int generate_quic_stateless_reset_secret(uint8_t *secret) {
  if (RAND_bytes(secret, SHRPX_QUIC_STATELESS_RESET_SECRETLEN) != 1) {
    return -1;
  }

  return 0;
}

int generate_quic_token_secret(uint8_t *secret) {
  if (RAND_bytes(secret, SHRPX_QUIC_TOKEN_SECRETLEN) != 1) {
    return -1;
  }

  return 0;
}

namespace {
int derive_token_key(uint8_t *key, size_t &keylen, uint8_t *iv, size_t &ivlen,
                     const uint8_t *token_secret, const uint8_t *rand_data,
                     size_t rand_datalen, const ngtcp2_crypto_aead *aead,
                     const ngtcp2_crypto_md *md) {
  std::array<uint8_t, 32> secret;

  if (ngtcp2_crypto_hkdf_extract(secret.data(), md, token_secret,
                                 SHRPX_QUIC_TOKEN_SECRETLEN, rand_data,
                                 rand_datalen) != 0) {
    return -1;
  }

  auto aead_keylen = ngtcp2_crypto_aead_keylen(aead);
  if (keylen < aead_keylen) {
    return -1;
  }

  keylen = aead_keylen;

  auto aead_ivlen = ngtcp2_crypto_packet_protection_ivlen(aead);
  if (ivlen < aead_ivlen) {
    return -1;
  }

  ivlen = aead_ivlen;

  if (ngtcp2_crypto_derive_packet_protection_key(
          key, iv, nullptr, aead, md, secret.data(), secret.size()) != 0) {
    return -1;
  }

  return 0;
}
} // namespace

namespace {
size_t generate_retry_token_aad(uint8_t *dest, size_t destlen,
                                const sockaddr *sa, socklen_t salen,
                                const ngtcp2_cid *retry_scid) {
  assert(destlen >= salen + retry_scid->datalen);

  auto p = std::copy_n(reinterpret_cast<const uint8_t *>(sa), salen, dest);
  p = std::copy_n(retry_scid->data, retry_scid->datalen, p);

  return p - dest;
}
} // namespace

int generate_retry_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa,
                         socklen_t salen, const ngtcp2_cid *retry_scid,
                         const ngtcp2_cid *odcid, const uint8_t *token_secret) {
  std::array<uint8_t, 4096> plaintext;

  uint64_t t = std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  auto p = std::begin(plaintext);
  // Host byte order
  p = std::copy_n(reinterpret_cast<uint8_t *>(&t), sizeof(t), p);
  p = std::copy_n(odcid->data, odcid->datalen, p);

  std::array<uint8_t, SHRPX_QUIC_TOKEN_RAND_DATALEN> rand_data;
  std::array<uint8_t, 32> key, iv;
  auto keylen = key.size();
  auto ivlen = iv.size();

  if (RAND_bytes(rand_data.data(), rand_data.size()) != 1) {
    return -1;
  }

  ngtcp2_crypto_aead aead;
  ngtcp2_crypto_aead_init(&aead, const_cast<EVP_CIPHER *>(EVP_aes_128_gcm()));

  ngtcp2_crypto_md md;
  ngtcp2_crypto_md_init(&md, const_cast<EVP_MD *>(EVP_sha256()));

  if (derive_token_key(key.data(), keylen, iv.data(), ivlen, token_secret,
                       rand_data.data(), rand_data.size(), &aead, &md) != 0) {
    return -1;
  }

  auto plaintextlen = std::distance(std::begin(plaintext), p);

  std::array<uint8_t, 256> aad;
  auto aadlen =
      generate_retry_token_aad(aad.data(), aad.size(), sa, salen, retry_scid);

  token[0] = SHRPX_QUIC_RETRY_TOKEN_MAGIC;

  ngtcp2_crypto_aead_ctx aead_ctx;
  if (ngtcp2_crypto_aead_ctx_encrypt_init(&aead_ctx, &aead, key.data(),
                                          ivlen) != 0) {
    return -1;
  }

  auto rv =
      ngtcp2_crypto_encrypt(token + 1, &aead, &aead_ctx, plaintext.data(),
                            plaintextlen, iv.data(), ivlen, aad.data(), aadlen);

  ngtcp2_crypto_aead_ctx_free(&aead_ctx);

  if (rv != 0) {
    return -1;
  }

  /* 1 for magic byte */
  tokenlen = 1 + plaintextlen + aead.max_overhead;
  memcpy(token + tokenlen, rand_data.data(), rand_data.size());
  tokenlen += rand_data.size();

  return 0;
}

int verify_retry_token(ngtcp2_cid *odcid, const uint8_t *token, size_t tokenlen,
                       const ngtcp2_cid *dcid, const sockaddr *sa,
                       socklen_t salen, const uint8_t *token_secret) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> port;

  if (getnameinfo(sa, salen, host.data(), host.size(), port.data(), port.size(),
                  NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
    return -1;
  }

  /* 1 for SHRPX_QUIC_RETRY_TOKEN_MAGIC */
  if (tokenlen < SHRPX_QUIC_TOKEN_RAND_DATALEN + 1) {
    return -1;
  }
  if (tokenlen > SHRPX_QUIC_MAX_RETRY_TOKENLEN) {
    return -1;
  }

  assert(token[0] == SHRPX_QUIC_RETRY_TOKEN_MAGIC);

  auto rand_data = token + tokenlen - SHRPX_QUIC_TOKEN_RAND_DATALEN;
  auto ciphertext = token + 1;
  auto ciphertextlen = tokenlen - SHRPX_QUIC_TOKEN_RAND_DATALEN - 1;

  std::array<uint8_t, 32> key, iv;
  auto keylen = key.size();
  auto ivlen = iv.size();

  ngtcp2_crypto_aead aead;
  ngtcp2_crypto_aead_init(&aead, const_cast<EVP_CIPHER *>(EVP_aes_128_gcm()));

  ngtcp2_crypto_md md;
  ngtcp2_crypto_md_init(&md, const_cast<EVP_MD *>(EVP_sha256()));

  if (derive_token_key(key.data(), keylen, iv.data(), ivlen, token_secret,
                       rand_data, SHRPX_QUIC_TOKEN_RAND_DATALEN, &aead,
                       &md) != 0) {
    return -1;
  }

  std::array<uint8_t, 256> aad;
  auto aadlen =
      generate_retry_token_aad(aad.data(), aad.size(), sa, salen, dcid);

  ngtcp2_crypto_aead_ctx aead_ctx;
  if (ngtcp2_crypto_aead_ctx_decrypt_init(&aead_ctx, &aead, key.data(),
                                          ivlen) != 0) {
    return -1;
  }

  std::array<uint8_t, SHRPX_QUIC_MAX_RETRY_TOKENLEN> plaintext;

  auto rv = ngtcp2_crypto_decrypt(plaintext.data(), &aead, &aead_ctx,
                                  ciphertext, ciphertextlen, iv.data(), ivlen,
                                  aad.data(), aadlen);

  ngtcp2_crypto_aead_ctx_free(&aead_ctx);

  if (rv != 0) {
    return -1;
  }

  assert(ciphertextlen >= aead.max_overhead);

  auto plaintextlen = ciphertextlen - aead.max_overhead;
  if (plaintextlen < sizeof(uint64_t)) {
    return -1;
  }

  auto cil = plaintextlen - sizeof(uint64_t);
  if (cil != 0 && (cil < NGTCP2_MIN_CIDLEN || cil > NGTCP2_MAX_CIDLEN)) {
    return -1;
  }

  uint64_t t;
  memcpy(&t, plaintext.data(), sizeof(uint64_t));

  uint64_t now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();

  // Allow 10 seconds window
  if (t + 10ULL * NGTCP2_SECONDS < now) {
    return -1;
  }

  ngtcp2_cid_init(odcid, plaintext.data() + sizeof(uint64_t), cil);

  return 0;
}

namespace {
size_t generate_token_aad(uint8_t *dest, size_t destlen, const sockaddr *sa,
                          size_t salen) {
  const uint8_t *addr;
  size_t addrlen;

  switch (sa->sa_family) {
  case AF_INET:
    addr = reinterpret_cast<const uint8_t *>(
        &reinterpret_cast<const sockaddr_in *>(sa)->sin_addr);
    addrlen = sizeof(reinterpret_cast<const sockaddr_in *>(sa)->sin_addr);
    break;
  case AF_INET6:
    addr = reinterpret_cast<const uint8_t *>(
        &reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_addr);
    addrlen = sizeof(reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_addr);
    break;
  default:
    return 0;
  }

  assert(destlen >= addrlen);

  return std::copy_n(addr, addrlen, dest) - dest;
}
} // namespace

int generate_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa,
                   size_t salen, const uint8_t *token_secret) {
  std::array<uint8_t, 8> plaintext;

  uint64_t t = std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  std::array<uint8_t, 256> aad;
  auto aadlen = generate_token_aad(aad.data(), aad.size(), sa, salen);
  if (aadlen == 0) {
    return -1;
  }

  auto p = std::begin(plaintext);
  // Host byte order
  p = std::copy_n(reinterpret_cast<uint8_t *>(&t), sizeof(t), p);

  std::array<uint8_t, SHRPX_QUIC_TOKEN_RAND_DATALEN> rand_data;
  std::array<uint8_t, 32> key, iv;
  auto keylen = key.size();
  auto ivlen = iv.size();

  if (RAND_bytes(rand_data.data(), rand_data.size()) != 1) {
    return -1;
  }

  ngtcp2_crypto_aead aead;
  ngtcp2_crypto_aead_init(&aead, const_cast<EVP_CIPHER *>(EVP_aes_128_gcm()));

  ngtcp2_crypto_md md;
  ngtcp2_crypto_md_init(&md, const_cast<EVP_MD *>(EVP_sha256()));

  if (derive_token_key(key.data(), keylen, iv.data(), ivlen, token_secret,
                       rand_data.data(), rand_data.size(), &aead, &md) != 0) {
    return -1;
  }

  auto plaintextlen = std::distance(std::begin(plaintext), p);

  ngtcp2_crypto_aead_ctx aead_ctx;
  if (ngtcp2_crypto_aead_ctx_encrypt_init(&aead_ctx, &aead, key.data(),
                                          ivlen) != 0) {
    return -1;
  }

  token[0] = SHRPX_QUIC_TOKEN_MAGIC;
  auto rv =
      ngtcp2_crypto_encrypt(token + 1, &aead, &aead_ctx, plaintext.data(),
                            plaintextlen, iv.data(), ivlen, aad.data(), aadlen);

  ngtcp2_crypto_aead_ctx_free(&aead_ctx);

  if (rv != 0) {
    return -1;
  }

  /* 1 for magic byte */
  tokenlen = 1 + plaintextlen + aead.max_overhead;
  memcpy(token + tokenlen, rand_data.data(), rand_data.size());
  tokenlen += rand_data.size();

  return 0;
}

int verify_token(const uint8_t *token, size_t tokenlen, const sockaddr *sa,
                 socklen_t salen, const uint8_t *token_secret) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> port;

  if (getnameinfo(sa, salen, host.data(), host.size(), port.data(), port.size(),
                  NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
    return -1;
  }

  /* 1 for TOKEN_MAGIC */
  if (tokenlen < SHRPX_QUIC_TOKEN_RAND_DATALEN + 1) {
    return -1;
  }
  if (tokenlen > SHRPX_QUIC_MAX_TOKENLEN) {
    return -1;
  }

  assert(token[0] == SHRPX_QUIC_TOKEN_MAGIC);

  std::array<uint8_t, 256> aad;
  auto aadlen = generate_token_aad(aad.data(), aad.size(), sa, salen);
  if (aadlen == 0) {
    return -1;
  }

  auto rand_data = token + tokenlen - SHRPX_QUIC_TOKEN_RAND_DATALEN;
  auto ciphertext = token + 1;
  auto ciphertextlen = tokenlen - SHRPX_QUIC_TOKEN_RAND_DATALEN - 1;

  std::array<uint8_t, 32> key, iv;
  auto keylen = key.size();
  auto ivlen = iv.size();

  ngtcp2_crypto_aead aead;
  ngtcp2_crypto_aead_init(&aead, const_cast<EVP_CIPHER *>(EVP_aes_128_gcm()));

  ngtcp2_crypto_md md;
  ngtcp2_crypto_md_init(&md, const_cast<EVP_MD *>(EVP_sha256()));

  if (derive_token_key(key.data(), keylen, iv.data(), ivlen, token_secret,
                       rand_data, SHRPX_QUIC_TOKEN_RAND_DATALEN, &aead,
                       &md) != 0) {
    return -1;
  }

  ngtcp2_crypto_aead_ctx aead_ctx;
  if (ngtcp2_crypto_aead_ctx_decrypt_init(&aead_ctx, &aead, key.data(),
                                          ivlen) != 0) {
    return -1;
  }

  std::array<uint8_t, SHRPX_QUIC_MAX_TOKENLEN> plaintext;

  auto rv = ngtcp2_crypto_decrypt(plaintext.data(), &aead, &aead_ctx,
                                  ciphertext, ciphertextlen, iv.data(), ivlen,
                                  aad.data(), aadlen);

  ngtcp2_crypto_aead_ctx_free(&aead_ctx);

  if (rv != 0) {
    return -1;
  }

  assert(ciphertextlen >= aead.max_overhead);

  auto plaintextlen = ciphertextlen - aead.max_overhead;
  if (plaintextlen != sizeof(uint64_t)) {
    return -1;
  }

  uint64_t t;
  memcpy(&t, plaintext.data(), sizeof(uint64_t));

  uint64_t now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();

  // Allow 1 hour window
  if (t + 3600ULL * NGTCP2_SECONDS < now) {
    return -1;
  }

  return 0;
}

} // namespace shrpx
