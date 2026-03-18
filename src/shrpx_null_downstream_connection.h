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
#ifndef SHRPX_NULL_DOWNSTREAM_CONNECTION_H
#define SHRPX_NULL_DOWNSTREAM_CONNECTION_H

#include "shrpx_downstream_connection.h"
#include "template.h"

using namespace nghttp2;

namespace shrpx {

class NullDownstreamConnection : public DownstreamConnection {
public:
  NullDownstreamConnection(const std::shared_ptr<DownstreamAddrGroup> &group);
  ~NullDownstreamConnection() override;
  int attach_downstream(Downstream *downstream) override;
  void detach_downstream(Downstream *downstream) override;

  int push_request_headers() override;
  int push_upload_data_chunk(const uint8_t *data, size_t datalen) override;
  int end_upload_data() override;

  void pause_read(IOCtrlReason reason) override;
  int resume_read(IOCtrlReason reason, size_t consumed) override;
  void force_resume_read() override;

  int on_read() override;
  int on_write() override;

  void on_upstream_change(Upstream *upstream) override;

  // true if this object is poolable.
  bool poolable() const override;

  const std::shared_ptr<DownstreamAddrGroup> &
  get_downstream_addr_group() const override;
  DownstreamAddr *get_addr() const override;

private:
  std::shared_ptr<DownstreamAddrGroup> group_;
};

} // namespace shrpx

#endif // !defined(SHRPX_NULL_DOWNSTREAM_CONNECTION_H)
