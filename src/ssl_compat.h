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
#ifndef OPENSSL_COMPAT_H
#define OPENSSL_COMPAT_H

#include "nghttp2_config.h"

#include <cstdint>

#ifdef HAVE_WOLFSSL
#  define NGHTTP2_OPENSSL_IS_WOLFSSL
using nghttp2_ssl_op_type = long;
using nghttp2_ssl_proto_version_type = int;
using nghttp2_ssl_key_length_type = int;
using nghttp2_ssl_stack_index_type = int;
using nghttp2_ssl_timeout_type = uint32_t;
using nghttp2_ssl_rand_length_type = int;
using nghttp2_ssl_verify_host_length_type = unsigned int;
#else // !HAVE_WOLFSSL
#  include <openssl/opensslv.h>

#  ifdef LIBRESSL_VERSION_NUMBER
#    define NGHTTP2_OPENSSL_IS_LIBRESSL
using nghttp2_ssl_op_type = long;
using nghttp2_ssl_proto_version_type = uint16_t;
using nghttp2_ssl_key_length_type = int;
using nghttp2_ssl_stack_index_type = int;
using nghttp2_ssl_timeout_type = long;
using nghttp2_ssl_rand_length_type = int;
using nghttp2_ssl_verify_host_length_type = size_t;
#  endif // !LIBRESSL_VERSION_NUMBER

#  if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
#    define NGHTTP2_OPENSSL_IS_BORINGSSL
using nghttp2_ssl_op_type = uint32_t;
using nghttp2_ssl_proto_version_type = uint16_t;
using nghttp2_ssl_key_length_type = size_t;
using nghttp2_ssl_stack_index_type = size_t;
using nghttp2_ssl_timeout_type = uint32_t;
using nghttp2_ssl_rand_length_type = size_t;
using nghttp2_ssl_verify_host_length_type = size_t;
#  endif // OPENSSL_IS_BORINGSSL || OPENSSL_IS_AWSLC

#  if !defined(NGHTTP2_OPENSSL_IS_BORINGSSL) &&                                \
    !defined(NGHTTP2_OPENSSL_IS_LIBRESSL)
#    define NGHTTP2_GENUINE_OPENSSL
#  endif // !NGHTTP2_OPENSSL_IS_BORINGSSL && !NGHTTP2_OPENSSL_IS_LIBRESSL

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
#  else    // !NGHTTP2_GENUINE_OPENSSL
#    define OPENSSL_3_0_0_API 0
#    define OPENSSL_3_5_0_API 0
#  endif // !NGHTTP2_GENUINE_OPENSSL
#endif   // !HAVE_WOLFSSL

#endif // OPENSSL_COMPAT_H
