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
#ifndef SHRPX_API_DOWNSTREAM_CONNECTION_H
#define SHRPX_API_DOWNSTREAM_CONNECTION_H

#include "shrpx_downstream_connection.h"
#include "template.h"

using namespace nghttp2;
using namespace std::literals;

namespace shrpx {

class Worker;

// If new method is added, don't forget to update API_METHOD_STRING as
// well.
enum APIMethod {
  API_METHOD_GET,
  API_METHOD_POST,
  API_METHOD_PUT,
  API_METHOD_MAX,
};

// API status code, which is independent from HTTP status code.  But
// generally, 2xx code for SUCCESS, and otherwise FAILURE.
enum class APIStatusCode {
  SUCCESS,
  FAILURE,
};

class APIDownstreamConnection;

struct APIEndpoint {
  // Endpoint path.  It must start with "/api/".
  std::string_view path;
  // true if we evaluate request body.
  bool require_body;
  // Allowed methods.  This is bitwise OR of one or more of (1 <<
  // APIMethod value).
  uint8_t allowed_methods;
  std::function<std::expected<void, Error>(APIDownstreamConnection &)> handler;
};

class APIDownstreamConnection : public DownstreamConnection {
public:
  APIDownstreamConnection(Worker *worker);
  ~APIDownstreamConnection() override;
  std::expected<void, Error> attach_downstream(Downstream *downstream) override;
  std::expected<void, Error> detach_downstream(Downstream *downstream) override;

  std::expected<void, Error> push_request_headers() override;
  std::expected<void, Error>
  push_upload_data_chunk(std::span<const uint8_t> data) override;
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

  std::expected<void, Error> send_reply(unsigned int http_status,
                                        APIStatusCode api_status,
                                        std::string_view data = ""sv);
  std::expected<void, Error> error_method_not_allowed();

  // Handles backendconfig API request.
  std::expected<void, Error> handle_backendconfig();
  // Handles configrevision API request.
  std::expected<void, Error> handle_configrevision();

private:
  Worker *worker_;
  // This points to the requested APIEndpoint struct.
  const APIEndpoint *api_{};
  // The file descriptor for temporary file to store request body.
  int fd_{-1};
  // true if we stop reading request body.
  bool shutdown_read_{};
};

} // namespace shrpx

#endif // !defined(SHRPX_API_DOWNSTREAM_CONNECTION_H)
