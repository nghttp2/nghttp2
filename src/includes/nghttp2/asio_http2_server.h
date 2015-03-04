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
#ifndef ASIO_HTTP2_SERVER_H
#define ASIO_HTTP2_SERVER_H

#include <nghttp2/asio_http2.h>

namespace nghttp2 {

namespace asio_http2 {

namespace server {

class request_impl;
class response_impl;

class request {
public:
  // Application must not call this directly.
  request();

  // Returns request headers.  The pusedo headers, which start with
  // colon (:), are exluced from this list.
  const header_map &header() const;

  // Returns method (e.g., GET).
  const std::string &method() const;

  // Returns request URI, split into components.
  const uri_ref &uri() const;

  // Sets callback when chunk of request body is received.
  void on_data(data_cb cb) const;

  // Application must not call this directly.
  request_impl &impl() const;

private:
  std::unique_ptr<request_impl> impl_;
};

class response {
public:
  // Application must not call this directly.
  response();

  // Write response header using |status_code| (e.g., 200) and
  // additional headers in |h|.
  void write_head(unsigned int status_code, header_map h = {}) const;

  // Sends |data| as request body.  No further call of end() is
  // allowed.
  void end(std::string data = "") const;

  // Sets callback |cb| as a generator of the response body.  No
  // further call of end() is allowed.
  void end(read_cb cb) const;

  void on_close(close_cb cb) const;

  void cancel(uint32_t error_code = NGHTTP2_INTERNAL_ERROR) const;

  // Resumes deferred response.
  void resume() const;

  // Pushes resource denoted by |raw_path_query| using |method|.  The
  // additional headers can be given in |h|.  This function returns
  // pointer to response object for promised stream, otherwise nullptr
  // and error code is filled in |ec|.
  const response *push(boost::system::error_code &ec, std::string method,
                       std::string raw_path_query, header_map h = {}) const;

  // Returns status code.
  unsigned int status_code() const;

  // Returns true if response has been started.
  bool started() const;

  // Returns boost::asio::io_service this response is running on.
  boost::asio::io_service &io_service() const;

  // Application must not call this directly.
  response_impl &impl() const;

private:
  std::unique_ptr<response_impl> impl_;
};

// This is so called request callback.  Called every time request is
// received.
typedef std::function<void(const request &, const response &)> request_cb;

class http2_impl;

class http2 {
public:
  http2();
  ~http2();

  // Starts listening connection on given address and port and serves
  // incoming requests.
  void listen(const std::string &address, uint16_t port);

  // Registers request handler |cb| with path pattern |pattern|.  This
  // function will fail and returns false if same pattern has been
  // already registered.  Otherwise returns true.
  bool handle(std::string pattern, request_cb cb);

  // Sets number of native threads to handle incoming HTTP request.
  // It defaults to 1.
  void num_threads(size_t num_threads);

  // Sets TLS private key file and certificate file.  Both files must
  // be in PEM format.
  void tls(std::string private_key_file, std::string certificate_file);

  // Sets the maximum length to which the queue of pending
  // connections.
  void backlog(int backlog);

private:
  std::unique_ptr<http2_impl> impl_;
};

} // namespace server

} // namespace asio_http2

} // namespace nghttp2

#endif // ASIO_HTTP2_SERVER_H
