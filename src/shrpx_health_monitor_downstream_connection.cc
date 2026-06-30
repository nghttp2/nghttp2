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
#include "shrpx_health_monitor_downstream_connection.h"

#include "shrpx_client_handler.h"
#include "shrpx_upstream.h"
#include "shrpx_downstream.h"
#include "shrpx_log.h"

namespace shrpx {

HealthMonitorDownstreamConnection::HealthMonitorDownstreamConnection() {}

HealthMonitorDownstreamConnection::~HealthMonitorDownstreamConnection() {}

std::expected<void, Error>
HealthMonitorDownstreamConnection::attach_downstream(Downstream *downstream) {
  if (log_enabled(INFO)) {
    Log{INFO, this} << "Attaching to DOWNSTREAM:" << downstream;
  }

  downstream_ = downstream;

  return {};
}

std::expected<void, Error>
HealthMonitorDownstreamConnection::detach_downstream(Downstream *downstream) {
  if (log_enabled(INFO)) {
    Log{INFO, this} << "Detaching from DOWNSTREAM:" << downstream;
  }
  downstream_ = nullptr;

  return {};
}

std::expected<void, Error>
HealthMonitorDownstreamConnection::push_request_headers() {
  downstream_->set_request_header_sent(true);
  auto src = downstream_->get_blocked_request_buf();
  auto dest = downstream_->get_request_buf();
  src->remove(*dest);

  return {};
}

std::expected<void, Error>
HealthMonitorDownstreamConnection::end_upload_data() {
  auto upstream = downstream_->get_upstream();
  auto &resp = downstream_->response();

  resp.http_status = 200;

  resp.fs.add_header_token("content-length"sv, "0"sv, false,
                           http2::HD_CONTENT_LENGTH);

  if (auto rv = upstream->send_reply(downstream_, {}); !rv) {
    return rv;
  }

  return {};
}

void HealthMonitorDownstreamConnection::pause_read(IOCtrlReason reason) {}

void HealthMonitorDownstreamConnection::force_resume_read() {}

void HealthMonitorDownstreamConnection::on_upstream_change(Upstream *upstream) {
}

bool HealthMonitorDownstreamConnection::poolable() const { return false; }

const std::shared_ptr<DownstreamAddrGroup> &
HealthMonitorDownstreamConnection::get_downstream_addr_group() const {
  static std::shared_ptr<DownstreamAddrGroup> s;
  return s;
}

DownstreamAddr *HealthMonitorDownstreamConnection::get_addr() const {
  return nullptr;
}

} // namespace shrpx
