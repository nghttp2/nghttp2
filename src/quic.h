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
#ifndef QUIC_H
#define QUIC_H

#include "nghttp2_config.h"

#include <openssl/ssl.h>

namespace quic {

const EVP_CIPHER *aead(SSL *ssl);
const EVP_CIPHER *hp(SSL *ssl);
const EVP_MD *prf(SSL *ssl);
size_t aead_max_overhead(const EVP_CIPHER *aead);

int hkdf_extract(uint8_t *dest, size_t destlen, const uint8_t *secret,
                 size_t secretlen, const uint8_t *salt, size_t saltlen,
                 const EVP_MD *prf);

int hkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret,
                size_t secretlen, const uint8_t *info, size_t infolen,
                const EVP_MD *prf);

int hkdf_expand_label(uint8_t *dest, size_t destlen, const uint8_t *secret,
                      size_t secretlen, const uint8_t *label, size_t labellen,
                      const EVP_MD *prf);

int derive_initial_secret(uint8_t *dest, size_t destlen, const uint8_t *secret,
                          size_t secretlen, const uint8_t *salt,
                          size_t saltlen);

int derive_client_initial_secret(uint8_t *dest, size_t destlen,
                                 const uint8_t *secret, size_t secretlen);

int derive_server_initial_secret(uint8_t *dest, size_t destlen,
                                 const uint8_t *secret, size_t secretlen);

int derive_packet_protection_key(uint8_t *key, size_t &keylen, uint8_t *iv,
                                 size_t &ivlen, const uint8_t *secret,
                                 size_t secretlen, const EVP_CIPHER *aead,
                                 const EVP_MD *prf);

int derive_header_protection_key(uint8_t *key, size_t &keylen,
                                 const uint8_t *secret, size_t secretlen,
                                 const EVP_CIPHER *aead, const EVP_MD *prf);

ssize_t encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
                size_t plaintextlen, const uint8_t *key, size_t keylen,
                const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
                size_t adlen, const EVP_CIPHER *aead);

ssize_t decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
                size_t ciphertextlen, const uint8_t *key, size_t keylen,
                const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
                size_t adlen, const EVP_CIPHER *aead);

ssize_t hp_mask(uint8_t *dest, size_t destlen, const uint8_t *key,
                size_t keylen, const uint8_t *sample, size_t samplelen,
                const EVP_CIPHER *cipher);

enum class ErrorType {
  Transport,
  TransportVersionNegotiation,
  Application,
};

struct Error {
  Error(ErrorType type, uint16_t code) : type(type), code(code) {}
  Error() : type(ErrorType::Transport), code(0) {}

  ErrorType type;
  uint16_t code;
};

Error err_transport(int liberr);
Error err_transport_tls(int alert);
Error err_application(int liberr);

} // namespace quic

#endif // QUIC_H
