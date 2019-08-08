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
#include "quic.h"

#include <cassert>

#include <openssl/kdf.h>

#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

#include "template.h"

using namespace nghttp2;

namespace quic {

const EVP_CIPHER *aead(SSL *ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case 0x03001301u: // TLS_AES_128_GCM_SHA256
    return EVP_aes_128_gcm();
  case 0x03001302u: // TLS_AES_256_GCM_SHA384
    return EVP_aes_256_gcm();
  case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
    return EVP_chacha20_poly1305();
  case 0x03001304u: // TLS_AES_128_CCM_SHA256
    return EVP_aes_128_ccm();
  default:
    assert(0);
  }
}

const EVP_CIPHER *hp(SSL *ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case 0x03001301u: // TLS_AES_128_GCM_SHA256
  case 0x03001304u: // TLS_AES_128_CCM_SHA256
    return EVP_aes_128_ctr();
  case 0x03001302u: // TLS_AES_256_GCM_SHA384
    return EVP_aes_256_ctr();
  case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
    return EVP_chacha20();
  default:
    assert(0);
  }
}

const EVP_MD *prf(SSL *ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case 0x03001301u: // TLS_AES_128_GCM_SHA256
  case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
  case 0x03001304u: // TLS_AES_128_CCM_SHA256
    return EVP_sha256();
  case 0x03001302u: // TLS_AES_256_GCM_SHA384
    return EVP_sha384();
  default:
    assert(0);
  }
}

namespace {
size_t aead_key_length(const EVP_CIPHER *aead) {
  return EVP_CIPHER_key_length(aead);
}
} // namespace

namespace {
size_t aead_nonce_length(const EVP_CIPHER *aead) {
  return EVP_CIPHER_iv_length(aead);
}
} // namespace

namespace {
size_t aead_tag_length(const EVP_CIPHER *aead) {
  if (aead == EVP_aes_128_gcm() || aead == EVP_aes_256_gcm()) {
    return EVP_GCM_TLS_TAG_LEN;
  }
  if (aead == EVP_chacha20_poly1305()) {
    return EVP_CHACHAPOLY_TLS_TAG_LEN;
  }
  if (aead == EVP_aes_128_ccm()) {
    return EVP_CCM_TLS_TAG_LEN;
  }
  assert(0);
}
} // namespace

size_t aead_max_overhead(const EVP_CIPHER *aead) {
  return aead_tag_length(aead);
}

int hkdf_extract(uint8_t *dest, size_t destlen, const uint8_t *secret,
                 size_t secretlen, const uint8_t *salt, size_t saltlen,
                 const EVP_MD *prf) {
  auto pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (pctx == nullptr) {
    return -1;
  }

  auto pctx_d = defer(EVP_PKEY_CTX_free, pctx);

  if (EVP_PKEY_derive_init(pctx) != 1 ||
      EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1 ||
      EVP_PKEY_CTX_set_hkdf_md(pctx, prf) != 1 ||
      EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) != 1 ||
      EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != 1 ||
      EVP_PKEY_derive(pctx, dest, &destlen) != 1) {
    return -1;
  }

  return 0;
}

int hkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret,
                size_t secretlen, const uint8_t *info, size_t infolen,
                const EVP_MD *prf) {
  auto pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (pctx == nullptr) {
    return -1;
  }

  auto pctx_d = defer(EVP_PKEY_CTX_free, pctx);

  if (EVP_PKEY_derive_init(pctx) != 1 ||
      EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1 ||
      EVP_PKEY_CTX_set_hkdf_md(pctx, prf) != 1 ||
      EVP_PKEY_CTX_set1_hkdf_salt(pctx, "", 0) != 1 ||
      EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != 1 ||
      EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) != 1 ||
      EVP_PKEY_derive(pctx, dest, &destlen) != 1) {
    return -1;
  }

  return 0;
}

int hkdf_expand_label(uint8_t *dest, size_t destlen, const uint8_t *secret,
                      size_t secretlen, const uint8_t *label, size_t labellen,
                      const EVP_MD *prf) {
  std::array<uint8_t, 256> info;
  static constexpr const uint8_t LABEL[] = "tls13 ";

  auto p = std::begin(info);
  *p++ = destlen / 256;
  *p++ = destlen % 256;
  *p++ = str_size(LABEL) + labellen;
  p = std::copy_n(LABEL, str_size(LABEL), p);
  p = std::copy_n(label, labellen, p);
  *p++ = 0;

  return hkdf_expand(dest, destlen, secret, secretlen, info.data(),
                     p - std::begin(info), prf);
}

int derive_initial_secret(uint8_t *dest, size_t destlen, const uint8_t *secret,
                          size_t secretlen, const uint8_t *salt,
                          size_t saltlen) {
  return hkdf_extract(dest, destlen, secret, secretlen, salt, saltlen,
                      EVP_sha256());
}

int derive_client_initial_secret(uint8_t *dest, size_t destlen,
                                 const uint8_t *secret, size_t secretlen) {
  static constexpr uint8_t LABEL[] = "client in";
  return hkdf_expand_label(dest, destlen, secret, secretlen, LABEL,
                           str_size(LABEL), EVP_sha256());
}

int derive_server_initial_secret(uint8_t *dest, size_t destlen,
                                 const uint8_t *secret, size_t secretlen) {
  static constexpr uint8_t LABEL[] = "server in";
  return hkdf_expand_label(dest, destlen, secret, secretlen, LABEL,
                           str_size(LABEL), EVP_sha256());
}

int derive_packet_protection_key(uint8_t *key, size_t &keylen, uint8_t *iv,
                                 size_t &ivlen, const uint8_t *secret,
                                 size_t secretlen, const EVP_CIPHER *aead,
                                 const EVP_MD *prf) {
  int rv;
  static constexpr uint8_t KEY_LABEL[] = "quic key";
  static constexpr uint8_t IV_LABEL[] = "quic iv";

  auto req_keylen = aead_key_length(aead);
  if (req_keylen > keylen) {
    return -1;
  }

  keylen = req_keylen;
  rv = hkdf_expand_label(key, keylen, secret, secretlen, KEY_LABEL,
                         str_size(KEY_LABEL), prf);
  if (rv != 0) {
    return -1;
  }

  auto req_ivlen = std::max(static_cast<size_t>(8), aead_nonce_length(aead));
  if (req_ivlen > ivlen) {
    return -1;
  }

  ivlen = req_ivlen;
  rv = hkdf_expand_label(iv, ivlen, secret, secretlen, IV_LABEL,
                         str_size(IV_LABEL), prf);
  if (rv != 0) {
    return -1;
  }

  return 0;
}

int derive_header_protection_key(uint8_t *key, size_t &keylen,
                                 const uint8_t *secret, size_t secretlen,
                                 const EVP_CIPHER *aead, const EVP_MD *prf) {
  int rv;
  static constexpr uint8_t LABEL[] = "quic hp";

  auto req_keylen = aead_key_length(aead);
  if (req_keylen > keylen) {
    return -1;
  }

  keylen = req_keylen;
  rv = hkdf_expand_label(key, keylen, secret, secretlen, LABEL, str_size(LABEL),
                         prf);
  if (rv != 0) {
    return -1;
  }

  return 0;
}

ssize_t encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
                size_t plaintextlen, const uint8_t *key, size_t keylen,
                const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
                size_t adlen, const EVP_CIPHER *aead) {
  auto taglen = aead_tag_length(aead);

  if (destlen < plaintextlen + taglen) {
    return -1;
  }

  auto actx = EVP_CIPHER_CTX_new();
  if (actx == nullptr) {
    return -1;
  }

  auto actx_d = defer(EVP_CIPHER_CTX_free, actx);

  if (EVP_EncryptInit_ex(actx, aead, nullptr, nullptr, nullptr) != 1) {
    return -1;
  }

  if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, nullptr) !=
      1) {
    return -1;
  }

  if (aead == EVP_aes_128_ccm() &&
      EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, taglen, nullptr) != 1) {
    return -1;
  }

  if (EVP_EncryptInit_ex(actx, nullptr, nullptr, key, nonce) != 1) {
    return -1;
  }

  size_t outlen = 0;
  int len;

  if (aead == EVP_aes_128_ccm() &&
      EVP_EncryptUpdate(actx, nullptr, &len, nullptr, plaintextlen) != 1) {
    return -1;
  }

  if (EVP_EncryptUpdate(actx, nullptr, &len, ad, adlen) != 1) {
    return -1;
  }

  if (EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen) != 1) {
    return -1;
  }

  outlen = len;

  if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1) {
    return -1;
  }

  outlen += len;

  assert(outlen + taglen <= destlen);

  if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_GET_TAG, taglen, dest + outlen) !=
      1) {
    return -1;
  }

  outlen += taglen;

  return outlen;
}

ssize_t decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
                size_t ciphertextlen, const uint8_t *key, size_t keylen,
                const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
                size_t adlen, const EVP_CIPHER *aead) {
  auto taglen = aead_tag_length(aead);

  if (taglen > ciphertextlen || destlen + taglen < ciphertextlen) {
    return -1;
  }

  ciphertextlen -= taglen;
  auto tag = ciphertext + ciphertextlen;

  auto actx = EVP_CIPHER_CTX_new();
  if (actx == nullptr) {
    return -1;
  }

  auto actx_d = defer(EVP_CIPHER_CTX_free, actx);

  if (EVP_DecryptInit_ex(actx, aead, nullptr, nullptr, nullptr) != 1) {
    return -1;
  }

  if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, nullptr) !=
      1) {
    return -1;
  }

  if (aead == EVP_aes_128_ccm() &&
      EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, taglen,
                          const_cast<uint8_t *>(tag)) != 1) {
    return -1;
  }

  if (EVP_DecryptInit_ex(actx, nullptr, nullptr, key, nonce) != 1) {
    return -1;
  }

  size_t outlen;
  int len;

  if (aead == EVP_aes_128_ccm() &&
      EVP_DecryptUpdate(actx, nullptr, &len, nullptr, ciphertextlen) != 1) {
    return -1;
  }

  if (EVP_DecryptUpdate(actx, nullptr, &len, ad, adlen) != 1) {
    return -1;
  }

  if (EVP_DecryptUpdate(actx, dest, &len, ciphertext, ciphertextlen) != 1) {
    return -1;
  }

  outlen = len;

  if (aead == EVP_aes_128_ccm()) {
    return outlen;
  }

  if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, taglen,
                          const_cast<uint8_t *>(tag)) != 1) {
    return -1;
  }

  if (EVP_DecryptFinal_ex(actx, dest + outlen, &len) != 1) {
    return -1;
  }

  outlen += len;

  return outlen;
}

ssize_t hp_mask(uint8_t *dest, size_t destlen, const uint8_t *key,
                size_t keylen, const uint8_t *sample, size_t samplelen,
                const EVP_CIPHER *cipher) {
  static constexpr uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";

  auto actx = EVP_CIPHER_CTX_new();
  if (actx == nullptr) {
    return -1;
  }

  auto actx_d = defer(EVP_CIPHER_CTX_free, actx);

  if (EVP_EncryptInit_ex(actx, cipher, nullptr, key, sample) != 1) {
    return -1;
  }

  size_t outlen = 0;
  int len;

  if (EVP_EncryptUpdate(actx, dest, &len, PLAINTEXT, str_size(PLAINTEXT)) !=
      1) {
    return -1;
  }

  assert(len == 5);

  outlen = len;

  if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1) {
    return -1;
  }

  assert(len == 0);

  return outlen;
}

Error err_transport(int liberr) {
  if (liberr == NGTCP2_ERR_RECV_VERSION_NEGOTIATION) {
    return {ErrorType::TransportVersionNegotiation, 0};
  }
  return {ErrorType::Transport,
          ngtcp2_err_infer_quic_transport_error_code(liberr)};
}

Error err_transport_tls(int alert) {
  return {ErrorType::Transport, ngtcp2_err_infer_quic_transport_error_code(
                                    NGTCP2_CRYPTO_ERROR | alert)};
}

Error err_application(int liberr) {
  return {ErrorType::Application,
          nghttp3_err_infer_quic_app_error_code(liberr)};
}

} // namespace quic
