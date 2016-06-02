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
#include "shrpx_api_downstream_connection.h"

#include "shrpx_client_handler.h"
#include "shrpx_upstream.h"
#include "shrpx_downstream.h"
#include "shrpx_worker.h"

namespace shrpx {

APIDownstreamConnection::APIDownstreamConnection(Worker *worker)
    : worker_(worker) {}

APIDownstreamConnection::~APIDownstreamConnection() {}

int APIDownstreamConnection::attach_downstream(Downstream *downstream) {
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Attaching to DOWNSTREAM:" << downstream;
  }

  auto &req = downstream->request();

  if (req.path != StringRef::from_lit("/api/v1/dynamicconfig")) {
    // TODO this will return 503 error, which is not nice.  We'd like
    // to use 404 in this case.
    return -1;
  }

  downstream_ = downstream;

  return 0;
}

void APIDownstreamConnection::detach_downstream(Downstream *downstream) {
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Detaching from DOWNSTREAM:" << downstream;
  }
  downstream_ = nullptr;
}

int APIDownstreamConnection::push_request_headers() { return 0; }

int APIDownstreamConnection::push_upload_data_chunk(const uint8_t *data,
                                                    size_t datalen) {
  auto output = downstream_->get_request_buf();

  // TODO limit the maximum payload size
  output->append(data, datalen);

  // We don't have to call Upstream::resume_read() here, because
  // request buffer is effectively unlimited.  Actually, we cannot
  // call it here since it could recursively call this function again.

  return 0;
}

int APIDownstreamConnection::end_upload_data() {
  // TODO process request payload here
  (void)worker_;
  return 0;
}

void APIDownstreamConnection::pause_read(IOCtrlReason reason) {}

int APIDownstreamConnection::resume_read(IOCtrlReason reason, size_t consumed) {
  return 0;
}

void APIDownstreamConnection::force_resume_read() {}

int APIDownstreamConnection::on_read() { return 0; }

int APIDownstreamConnection::on_write() { return 0; }

void APIDownstreamConnection::on_upstream_change(Upstream *uptream) {}

bool APIDownstreamConnection::poolable() const { return false; }

DownstreamAddrGroup *
APIDownstreamConnection::get_downstream_addr_group() const {
  return nullptr;
}

} // namespace shrpx
