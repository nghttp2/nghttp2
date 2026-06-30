/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
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
#ifndef SHRPX_HTTP2_DOWNSTREAM_CONNECTION_H
#define SHRPX_HTTP2_DOWNSTREAM_CONNECTION_H

#include "shrpx.h"

#include "ssl_compat.h"

#ifdef NGHTTP2_OPENSSL_IS_WOLFSSL
#  include <wolfssl/options.h>
#  include <wolfssl/openssl/ssl.h>
#else // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)
#  include <openssl/ssl.h>
#endif // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)

#include <nghttp2/nghttp2.h>

#include "shrpx_downstream_connection.h"

namespace shrpx {

struct StreamData;
class Http2Session;
class DownstreamConnectionPool;

class Http2DownstreamConnection : public DownstreamConnection {
public:
  Http2DownstreamConnection(Http2Session *http2session);
  ~Http2DownstreamConnection() override;
  std::expected<void, Error> attach_downstream(Downstream *downstream) override;
  std::expected<void, Error> detach_downstream(Downstream *downstream) override;

  std::expected<void, Error> push_request_headers() override;
  std::expected<void, Error>
  push_upload_data_chunk(std::span<const uint8_t> data) override;
  std::expected<void, Error> end_upload_data() override;

  void pause_read(IOCtrlReason reason) override {}
  std::expected<void, Error> resume_read(IOCtrlReason reason,
                                         size_t consumed) override;
  void force_resume_read() override {}

  std::expected<void, Error> on_read() override { return {}; }
  std::expected<void, Error> on_write() override { return {}; }
  std::expected<void, Error> on_timeout() override;

  void on_upstream_change(Upstream *upstream) override {}

  // This object is not poolable because we don't have facility to
  // migrate to another Http2Session object.
  bool poolable() const override { return false; }

  const std::shared_ptr<DownstreamAddrGroup> &
  get_downstream_addr_group() const override;
  DownstreamAddr *get_addr() const override;

  void attach_stream_data(StreamData *sd);
  StreamData *detach_stream_data();

  std::expected<void, Error>
  submit_rst_stream(Downstream *downstream,
                    uint32_t error_code = NGHTTP2_INTERNAL_ERROR);

  Http2DownstreamConnection *dlnext{}, *dlprev{};

private:
  Http2Session *http2session_;
  StreamData *sd_{};
};

} // namespace shrpx

#endif // !defined(SHRPX_HTTP2_DOWNSTREAM_CONNECTION_H)
