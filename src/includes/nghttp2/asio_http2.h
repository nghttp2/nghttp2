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
#include <map>

#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <nghttp2/nghttp2.h>

namespace boost {
namespace system {

template <> struct is_error_code_enum<nghttp2_error> {
  BOOST_STATIC_CONSTANT(bool, value = true);
};

} // namespace system
} // namespace boost

namespace nghttp2 {

namespace asio_http2 {

struct header_value {
  std::string value;
  bool sensitive;
};

using header_map = std::multimap<std::string, header_value>;

const boost::system::error_category &nghttp2_category() noexcept;

struct uri_ref {
  std::string scheme;
  std::string host;
  // percent-decoded form
  std::string path;
  std::string raw_path;
  std::string raw_query;
  std::string fragment;
};

typedef std::function<void(const uint8_t *, std::size_t)> data_cb;
typedef std::function<void(void)> void_cb;
typedef std::function<void(const boost::system::error_code &ec)> error_cb;
typedef std::function<void(uint32_t)> close_cb;

// Callback function to generate response body.  TBD
typedef std::function<
    ssize_t(uint8_t *buf, std::size_t len, uint32_t *data_flags)> read_cb;

// Convenient function to create function to read file denoted by
// |path|.  This can be passed to response::end().
read_cb file_reader(const std::string &path);

// Like file_reader(const std::string&), but it takes opened file
// descriptor.  The passed descriptor will be closed when returned
// function object is destroyed.
read_cb file_reader_from_fd(int fd);

// Validates path so that it does not contain directory traversal
// vector.  Returns true if path is safe.  The |path| must start with
// "/" otherwise returns false.  This function should be called after
// percent-decode was performed.
bool check_path(const std::string &path);

// Performs percent-decode against string |s|.
std::string percent_decode(const std::string &s);

// Returns HTTP date representation of current posix time |t|.
std::string http_date(int64_t t);

} // namespace asio_http2

} // namespace nghttp2

#endif // ASIO_HTTP2_H
