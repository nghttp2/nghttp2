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
#ifndef SHRPX_HEALTH_MONITOR_DOWNSTREAM_CONNECTION_H
#define SHRPX_HEALTH_MONITOR_DOWNSTREAM_CONNECTION_H

#include "shrpx_downstream_connection.h"

namespace shrpx {

class Worker;

class HealthMonitorDownstreamConnection : public DownstreamConnection {
public:
  HealthMonitorDownstreamConnection();
  ~HealthMonitorDownstreamConnection() override;
  std::expected<void, Error> attach_downstream(Downstream *downstream) override;
  std::expected<void, Error> detach_downstream(Downstream *downstream) override;

  std::expected<void, Error> push_request_headers() override;
  std::expected<void, Error>
  push_upload_data_chunk(std::span<const uint8_t> data) override {
    return {};
  }
  std::expected<void, Error> end_upload_data() override;

  void pause_read(IOCtrlReason reason) override;
  std::expected<void, Error> resume_read(IOCtrlReason reason,
                                         size_t consumed) override {
    return {};
  }
  void force_resume_read() override;

  std::expected<void, Error> on_read() override { return {}; }
  std::expected<void, Error> on_write() override { return {}; }

  void on_upstream_change(Upstream *upstream) override;

  // true if this object is poolable.
  bool poolable() const override;

  const std::shared_ptr<DownstreamAddrGroup> &
  get_downstream_addr_group() const override;
  DownstreamAddr *get_addr() const override;
};

} // namespace shrpx

#endif // !defined(SHRPX_HEALTH_MONITOR_DOWNSTREAM_CONNECTION_H)
