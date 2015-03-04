/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2015 Tatsuhiro Tsujikawa
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
#ifndef ASIO_HTTP2_CLIENT_H
#define ASIO_HTTP2_CLIENT_H

#include <nghttp2/asio_http2.h>

namespace nghttp2 {

namespace asio_http2 {

namespace client {

class response_impl;

class response {
public:
  response();
  ~response();

  void on_data(data_cb cb) const;

  int status_code() const;

  int64_t content_length() const;

  const header_map &header() const;

  response_impl &impl() const;

private:
  std::unique_ptr<response_impl> impl_;
};

class request;

using response_cb = std::function<void(const response &)>;
using request_cb = std::function<void(const request &)>;
using connect_cb =
    std::function<void(boost::asio::ip::tcp::resolver::iterator)>;

class request_impl;

class request {
public:
  request();
  ~request();

  void on_response(response_cb cb) const;
  void on_push(request_cb cb) const;
  void on_close(close_cb cb) const;

  void cancel(uint32_t error_code = NGHTTP2_INTERNAL_ERROR) const;

  const std::string &method() const;

  const uri_ref &uri() const;

  const header_map &header() const;

  request_impl &impl() const;

private:
  std::unique_ptr<request_impl> impl_;
};

class session_impl;

class session {
public:
  session(boost::asio::io_service &io_service, const std::string &host,
          const std::string &service);
  session(boost::asio::io_service &io_service,
          boost::asio::ssl::context &tls_context, const std::string &host,
          const std::string &service);
  ~session();

  void on_connect(connect_cb cb) const;
  void on_error(error_cb cb) const;

  void shutdown() const;

  boost::asio::io_service &io_service() const;

  const request *submit(boost::system::error_code &ec,
                        const std::string &method, const std::string &uri,
                        header_map h = {}) const;
  const request *submit(boost::system::error_code &ec,
                        const std::string &method, const std::string &uri,
                        std::string data, header_map h = {}) const;
  const request *submit(boost::system::error_code &ec,
                        const std::string &method, const std::string &uri,
                        read_cb cb, header_map h = {}) const;

private:
  std::unique_ptr<session_impl> impl_;
};

// configure |tls_ctx| for client use.  Currently, we just set NPN
// callback for HTTP/2.
void configure_tls_context(boost::asio::ssl::context &tls_ctx);

} // namespace client

} // namespace asio_http2

} // namespace nghttp2

#endif // ASIO_HTTP2_CLIENT_H
