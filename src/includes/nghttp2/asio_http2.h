/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
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
#ifndef ASIO_HTTP2_H
#define ASIO_HTTP2_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <functional>

namespace nghttp2 {

namespace asio_http2 {

struct header {
  std::string name;
  std::string value;
};

namespace server {

class request_impl;
class response_impl;

typedef std::function<void(const uint8_t*, std::size_t)> data_cb;
typedef std::function<void(void)> void_cb;

// Callback function to generate response body.  The implementation of
// this callback must fill at most |len| bytes data to |buf|.  The
// return value is pair of written bytes and bool value indicating
// that this is the end of the body.  If the end of the body was
// reached, return true.  If there is error and application wants to
// terminate stream, return std::make_pair(-1, false).  Currently,
// returning std::make_pair(0, false) is reserved for future use.
typedef std::function<std::pair<ssize_t, bool>
                      (uint8_t *buf, std::size_t len)> read_cb;

class request {
public:
  // Application must not call this directly.
  request();

  // Returns request headers.  The pusedo headers, which start with
  // colon (;), are exluced from this list.
  const std::vector<header>& headers() const;

  // Returns method (e.g., GET).
  const std::string& method() const;

  // Returns scheme (e.g., https).
  const std::string& scheme() const;

  // Returns authority (e.g., example.org).  This could be empty
  // string.  In this case, check host().

  const std::string& authority() const;
  // Returns host (e.g., example.org).  If host header field is not
  // present, this value is copied from authority().

  const std::string& host() const;

  // Returns path (e.g., /index.html).
  const std::string& path() const;

  // Sets callback when chunk of request body is received.
  void on_data(data_cb cb);

  // Sets callback when request was completed.
  void on_end(void_cb cb);

  // Pushes resource denoted by |path| using |method|.  The additional
  // headers can be given in |headers|.  request_cb will be called for
  // pushed resource later on.  This function returns true if it
  // succeeds, or false.
  bool push(std::string method, std::string path,
            std::vector<header> headers = {});

  // Returns true if this is pushed request.
  bool pushed() const;

  // Returns true if stream has been closed.
  bool closed() const;

  // Application must not call this directly.
  request_impl& impl();
private:
  std::unique_ptr<request_impl> impl_;
};

class response {
public:
  // Application must not call this directly.
  response();

  // Write response header using |status_code| (e.g., 200) and
  // additional headers in |headers|.
  void write_head(unsigned int status_code, std::vector<header> headers = {});

  // Sends |data| as request body.  No further call of end() is
  // allowed.
  void end(std::string data = "");

  // Sets callback |cb| as a generator of the response body.  No
  // further call of end() is allowed.
  void end(read_cb cb);

  // Resumes deferred response.  Not implemented yet.
  void resume();

  // Returns status code.
  unsigned int status_code() const;

  // Returns true if response has been started.
  bool started() const;

  // Application must not call this directly.
  response_impl& impl();
private:
  std::unique_ptr<response_impl> impl_;
};

typedef std::function<void(std::shared_ptr<request>,
                           std::shared_ptr<response>)> request_cb;

class http2_impl;

class http2 {
public:
  http2();
  ~http2();

  // Starts listening connection on given address and port.  The
  // incoming requests are handled by given callback |cb|.
  void listen(const std::string& address, uint16_t port,
              request_cb cb);

  // Sets number of native threads.
  void num_threads(size_t num_threads);

  // Sets TLS private key file and certificate file.  Both files must
  // be in PEM format.
  void tls(std::string private_key_file, std::string certificate_file);
private:
  std::unique_ptr<http2_impl> impl_;
};

// Convenient function to create function to read file denoted by
// |path|.  This can be passed to response::end().
read_cb file_reader(const std::string& path);

// Like file_reader(const std::string&), but it takes opened file
// descriptor.  The passed descriptor will be closed when returned
// function object is destroyed.
read_cb file_reader_from_fd(int fd);

// Validates path so that it does not contain directory traversal
// vector.  Returns true if path is safe.  The |path| must start with
// "/" otherwise returns false.  This function should be called after
// percent-decode was performed.
bool check_path(const std::string& path);

// Performs percent-decode against string |s|.
std::string percent_decode(const std::string& s);

// Returns HTTP date representation of current posix time |t|.
std::string http_date(time_t t);

} // namespace server

} // namespace asio_http2

} // namespace nghttp2

#endif // ASIO_HTTP2_H
