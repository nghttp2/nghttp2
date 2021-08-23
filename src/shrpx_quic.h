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

#include <ngtcp2/ngtcp2.h>

namespace shrpx {

struct UpstreamAddr;

constexpr size_t SHRPX_QUIC_SCIDLEN = 20;
constexpr size_t SHRPX_QUIC_CID_PREFIXLEN = 8;
constexpr size_t SHRPX_MAX_UDP_PAYLOAD_SIZE = 1280;

ngtcp2_tstamp quic_timestamp();

int create_quic_server_socket(UpstreamAddr &addr);

int quic_send_packet(const UpstreamAddr *faddr, const sockaddr *remote_sa,
                     size_t remote_salen, const sockaddr *local_sa,
                     size_t local_salen, const uint8_t *data, size_t datalen,
                     size_t gso_size);

int generate_quic_connection_id(ngtcp2_cid *cid, size_t cidlen);

int generate_quic_connection_id(ngtcp2_cid *cid, size_t cidlen,
                                const uint8_t *cid_prefix);

int generate_quic_stateless_reset_token(uint8_t *token, const ngtcp2_cid *cid,
                                        const uint8_t *secret,
                                        size_t secretlen);

} // namespace shrpx

#endif // SHRPX_QUIC_H
