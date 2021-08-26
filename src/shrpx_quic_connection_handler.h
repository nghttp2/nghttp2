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
#ifndef SHRPX_QUIC_CONNECTION_HANDLER_H
#define SHRPX_QUIC_CONNECTION_HANDLER_H

#include "shrpx.h"

#include <memory>
#include <unordered_map>
#include <string>

#include <ngtcp2/ngtcp2.h>

#include "network.h"

using namespace nghttp2;

namespace shrpx {

struct UpstreamAddr;
class ClientHandler;
class Worker;

class QUICConnectionHandler {
public:
  QUICConnectionHandler(Worker *worker);
  ~QUICConnectionHandler();
  int handle_packet(const UpstreamAddr *faddr, const Address &remote_addr,
                    const Address &local_addr, const uint8_t *data,
                    size_t datalen);
  // Send Retry packet.  |ini_dcid| is the destination Connection ID
  // which appeared in Client Initial packet and its length is
  // |dcidlen|.  |ini_scid| is the source Connection ID which appeared
  // in Client Initial packet and its length is |scidlen|.
  int send_retry(const UpstreamAddr *faddr, uint32_t version,
                 const uint8_t *ini_dcid, size_t ini_dcidlen,
                 const uint8_t *ini_scid, size_t ini_scidlen,
                 const Address &remote_addr, const Address &local_addr);
  // Send Version Negotiation packet.  |ini_dcid| is the destination
  // Connection ID which appeared in Client Initial packet and its
  // length is |dcidlen|.  |ini_scid| is the source Connection ID
  // which appeared in Client Initial packet and its length is
  // |scidlen|.
  int send_version_negotiation(const UpstreamAddr *faddr, uint32_t version,
                               const uint8_t *ini_dcid, size_t ini_dcidlen,
                               const uint8_t *ini_scid, size_t ini_scidlen,
                               const Address &remote_addr,
                               const Address &local_addr);
  int send_stateless_reset(const UpstreamAddr *faddr, const uint8_t *dcid,
                           size_t dcidlen, const Address &remote_addr,
                           const Address &local_addr);
  ClientHandler *handle_new_connection(const UpstreamAddr *faddr,
                                       const Address &remote_addr,
                                       const Address &local_addr,
                                       const ngtcp2_pkt_hd &hd,
                                       const ngtcp2_cid *odcid);
  void add_connection_id(const ngtcp2_cid *cid, ClientHandler *handler);
  void remove_connection_id(const ngtcp2_cid *cid);

private:
  Worker *worker_;
  std::unordered_map<std::string, ClientHandler *> connections_;
};

} // namespace shrpx

#endif // SHRPX_QUIC_CONNECTION_HANDLER_H
