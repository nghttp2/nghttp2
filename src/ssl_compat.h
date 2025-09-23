/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2016 Tatsuhiro Tsujikawa
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
#ifndef SSL_COMPAT_H
#define SSL_COMPAT_H

#include "nghttp2_config.h"

#include <cstdint>

#ifdef HAVE_WOLFSSL
#  include <wolfssl/options.h>
#  include <wolfssl/openssl/ssl.h>

#  define NGHTTP2_OPENSSL_IS_WOLFSSL

using nghttp2_ssl_op_type = long;
using nghttp2_ssl_proto_version_type = int;
using nghttp2_ssl_key_length_type = int;
using nghttp2_ssl_stack_index_type = int;
using nghttp2_ssl_timeout_type = uint32_t;
using nghttp2_ssl_rand_length_type = int;
using nghttp2_ssl_verify_host_length_type = unsigned int;

inline constexpr auto NGHTTP2_CERT_TYPE_ECDSA = ECDSAk;
inline constexpr auto NGHTTP2_CERT_TYPE_ML_DSA_44 = ML_DSA_LEVEL2k;
inline constexpr auto NGHTTP2_CERT_TYPE_ML_DSA_65 = ML_DSA_LEVEL3k;
inline constexpr auto NGHTTP2_CERT_TYPE_ML_DSA_87 = ML_DSA_LEVEL5k;
#else // !defined(HAVE_WOLFSSL)
#  include <openssl/ssl.h>

#  ifdef LIBRESSL_VERSION_NUMBER
#    define NGHTTP2_OPENSSL_IS_LIBRESSL
using nghttp2_ssl_op_type = long;
using nghttp2_ssl_proto_version_type = uint16_t;
using nghttp2_ssl_key_length_type = int;
using nghttp2_ssl_stack_index_type = int;
using nghttp2_ssl_timeout_type = long;
using nghttp2_ssl_rand_length_type = int;
using nghttp2_ssl_verify_host_length_type = size_t;
#  endif // !defined(LIBRESSL_VERSION_NUMBER)

#  if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
#    define NGHTTP2_OPENSSL_IS_BORINGSSL
using nghttp2_ssl_op_type = uint32_t;
using nghttp2_ssl_proto_version_type = uint16_t;
using nghttp2_ssl_key_length_type = size_t;
using nghttp2_ssl_stack_index_type = size_t;
using nghttp2_ssl_timeout_type = uint32_t;
using nghttp2_ssl_rand_length_type = size_t;
using nghttp2_ssl_verify_host_length_type = size_t;
#  endif // defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)

#  if !defined(NGHTTP2_OPENSSL_IS_BORINGSSL) &&                                \
    !defined(NGHTTP2_OPENSSL_IS_LIBRESSL)
#    define NGHTTP2_GENUINE_OPENSSL
#  endif // !defined(NGHTTP2_OPENSSL_IS_BORINGSSL) &&
         // !defined(NGHTTP2_OPENSSL_IS_LIBRESSL)

#  ifdef NGHTTP2_GENUINE_OPENSSL
#    define OPENSSL_3_0_0_API (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#    define OPENSSL_3_5_0_API (OPENSSL_VERSION_NUMBER >= 0x30500000L)
#    if OPENSSL_VERSION_NUMBER >= 0x30000000L
using nghttp2_ssl_op_type = uint64_t;
#    else  // OPENSSL_VERSION_NUMBER < 0x30000000L
using nghttp2_ssl_op_type = unsigned long;
#    endif // OPENSSL_VERSION_NUMBER < 0x30000000L
using nghttp2_ssl_proto_version_type = long;
using nghttp2_ssl_key_length_type = int;
using nghttp2_ssl_stack_index_type = int;
using nghttp2_ssl_timeout_type = long;
using nghttp2_ssl_rand_length_type = int;
using nghttp2_ssl_verify_host_length_type = size_t;
#  else    // !defined(NGHTTP2_GENUINE_OPENSSL)
#    define OPENSSL_3_0_0_API 0
#    define OPENSSL_3_5_0_API 0
#  endif // !defined(NGHTTP2_GENUINE_OPENSSL)

inline constexpr auto NGHTTP2_CERT_TYPE_ECDSA = EVP_PKEY_EC;
#  if OPENSSL_3_5_0_API
inline constexpr auto NGHTTP2_CERT_TYPE_ML_DSA_44 = EVP_PKEY_ML_DSA_44;
inline constexpr auto NGHTTP2_CERT_TYPE_ML_DSA_65 = EVP_PKEY_ML_DSA_65;
inline constexpr auto NGHTTP2_CERT_TYPE_ML_DSA_87 = EVP_PKEY_ML_DSA_87;
#  endif // OPENSSL_3_5_0_API
#endif   // !defined(HAVE_WOLFSSL)

#endif // !defined(SSL_COMPAT_H)
