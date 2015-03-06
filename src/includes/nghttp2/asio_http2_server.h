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
  ~request();

  // Returns request header fields.  The pusedo header fields, which
  // start with colon (:), are exluced from this list.
  const header_map &header() const;

  // Returns method (e.g., GET).
  const std::string &method() const;

  // Returns request URI, split into components.
  const uri_ref &uri() const;

  // Sets callback which is invoked when chunk of request body is
  // received.
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
  ~response();

  // Write response header using |status_code| (e.g., 200) and
  // additional header fields in |h|.
  void write_head(unsigned int status_code, header_map h = {}) const;

  // Sends |data| as request body.  No further call of end() is
  // allowed.
  void end(std::string data = "") const;

  // Sets callback as a generator of the response body.  No further
  // call of end() is allowed.
  void end(generator_cb cb) const;

  // Sets callback which is invoked when this request and response are
  // finished.  After the invocation of this callback, the application
  // must not access request and response object.
  void on_close(close_cb cb) const;

  // Cancels this request and response with given error code.
  void cancel(uint32_t error_code = NGHTTP2_INTERNAL_ERROR) const;

  // Resumes deferred response.
  void resume() const;

  // Pushes resource denoted by |raw_path_query| using |method|.  The
  // additional header fields can be given in |h|.  This function
  // returns pointer to response object for promised stream, otherwise
  // nullptr and error code is filled in |ec|.  Be aware that the
  // header field name given in |h| must be lower-cased.
  const response *push(boost::system::error_code &ec, std::string method,
                       std::string raw_path_query, header_map h = {}) const;

  // Returns status code.
  unsigned int status_code() const;

  // Returns boost::asio::io_service this response is running on.
  boost::asio::io_service &io_service() const;

  // Application must not call this directly.
  response_impl &impl() const;

private:
  std::unique_ptr<response_impl> impl_;
};

// This is so called request callback.  Called every time request is
// received.  The life time of |request| and |response| objects end
// when callback set by response::on_close() is called.  After that,
// the application must not access to those objects.
typedef std::function<void(const request &, const response &)> request_cb;

class http2_impl;

class http2 {
public:
  http2();
  ~http2();

  // Starts listening connection on given address and port and serves
  // incoming requests in cleartext TCP connection.
  boost::system::error_code listen_and_serve(boost::system::error_code &ec,
                                             const std::string &address,
                                             const std::string &port);

  // Starts listening connection on given address and port and serves
  // incoming requests in SSL/TLS encrypted connection.
  boost::system::error_code
  listen_and_serve(boost::system::error_code &ec,
                   boost::asio::ssl::context &tls_context,
                   const std::string &address, const std::string &port);

  // Registers request handler |cb| with path pattern |pattern|.  This
  // function will fail and returns false if same pattern has been
  // already registered or |pattern| is empty string.  Otherwise
  // returns true.  The pattern match rule is the same as
  // net/http/ServeMux in golang.
  bool handle(std::string pattern, request_cb cb);

  // Sets number of native threads to handle incoming HTTP request.
  // It defaults to 1.
  void num_threads(size_t num_threads);

  // Sets the maximum length to which the queue of pending
  // connections.
  void backlog(int backlog);

private:
  std::unique_ptr<http2_impl> impl_;
};

// Configures |tls_context| for server use.  This function sets couple
// of OpenSSL options (disables SSLv2 and SSLv3 and compression) and
// enables ECDHE ciphers.  NPN callback is also configured.
boost::system::error_code
configure_tls_context_easy(boost::system::error_code &ec,
                           boost::asio::ssl::context &tls_context);

// Returns request handler to do redirect to |uri| using
// |status_code|.  The |uri| appears in "location" header field as is.
request_cb redirect_handler(int status_code, std::string uri);

// Returns request handler to reply with given |status_code| and HTML
// including message about status code.
request_cb status_handler(int status_code);

} // namespace server

} // namespace asio_http2

} // namespace nghttp2

#endif // ASIO_HTTP2_SERVER_H
