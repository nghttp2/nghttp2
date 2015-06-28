/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
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
#include "ssl.h"

#include <cassert>
#include <vector>
#include <mutex>
#include <iostream>

#include <openssl/crypto.h>

namespace nghttp2 {

namespace ssl {

// Recommended general purpose "Non-Backward Compatible" cipher by
// mozilla.
//
// https://wiki.mozilla.org/Security/Server_Side_TLS
const char *const DEFAULT_CIPHER_LIST =
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-"
    "AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:"
    "DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-"
    "AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-"
    "AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-"
    "AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:"
    "DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:"
    "!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";

namespace {
std::vector<std::mutex> ssl_global_locks;
} // namespace

namespace {
void ssl_locking_cb(int mode, int type, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    ssl_global_locks[type].lock();
  } else {
    ssl_global_locks[type].unlock();
  }
}
} // namespace

LibsslGlobalLock::LibsslGlobalLock() {
  if (!ssl_global_locks.empty()) {
    std::cerr << "OpenSSL global lock has been already set" << std::endl;
    assert(0);
  }
  ssl_global_locks = std::vector<std::mutex>(CRYPTO_num_locks());
  // CRYPTO_set_id_callback(ssl_thread_id); OpenSSL manual says that
  // if threadid_func is not specified using
  // CRYPTO_THREADID_set_callback(), then default implementation is
  // used. We use this default one.
  CRYPTO_set_locking_callback(ssl_locking_cb);
}

LibsslGlobalLock::~LibsslGlobalLock() { ssl_global_locks.clear(); }

const char *get_tls_protocol(SSL *ssl) {
  auto session = SSL_get_session(ssl);
  if (!session) {
    return "unknown";
  }

  switch (session->ssl_version) {
  case SSL2_VERSION:
    return "SSLv2";
  case SSL3_VERSION:
    return "SSLv3";
  case TLS1_2_VERSION:
    return "TLSv1.2";
  case TLS1_1_VERSION:
    return "TLSv1.1";
  case TLS1_VERSION:
    return "TLSv1";
  default:
    return "unknown";
  }
}

TLSSessionInfo *get_tls_session_info(TLSSessionInfo *tls_info, SSL *ssl) {
  if (!ssl) {
    return nullptr;
  }

  auto session = SSL_get_session(ssl);
  if (!session) {
    return nullptr;
  }

  tls_info->cipher = SSL_get_cipher_name(ssl);
  tls_info->protocol = get_tls_protocol(ssl);
  tls_info->session_id = session->session_id;
  tls_info->session_id_length = session->session_id_length;
  tls_info->session_reused = SSL_session_reused(ssl);

  return tls_info;
}

} // namespace ssl

} // namespace nghttp2
