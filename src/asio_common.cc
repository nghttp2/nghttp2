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
#include "asio_common.h"

#include <memory>

#include "util.h"

namespace nghttp2 {
namespace asio_http2 {

class nghttp2_category_impl : public boost::system::error_category {
public:
  const char *name() const noexcept { return "nghttp2"; }
  std::string message(int ev) const { return nghttp2_strerror(ev); }
};

const boost::system::error_category &nghttp2_category() noexcept {
  static nghttp2_category_impl cat;
  return cat;
}

boost::system::error_code make_error_code(nghttp2_error ev) {
  return boost::system::error_code(static_cast<int>(ev), nghttp2_category());
}

read_cb string_reader(std::string data) {
  auto strio = std::make_shared<std::pair<std::string, size_t>>(std::move(data),
                                                                data.size());
  return [strio](uint8_t *buf, size_t len) {
    auto n = std::min(len, strio->second);
    std::copy_n(strio->first.c_str(), n, buf);
    strio->second -= n;
    return std::make_pair(n, strio->second == 0);
  };
}

uri_ref make_uri_ref(std::string scheme, std::string host, std::string raw_path,
                     std::string raw_query) {
  return uri_ref{
      std::move(scheme), std::move(host), percent_decode(raw_path),
      std::move(raw_path),
  };
}

uri_ref make_uri_ref(std::string scheme, std::string host,
                     const std::string &raw_path_query) {
  auto path_end = raw_path_query.find('?');
  std::size_t query_pos;
  if (path_end == std::string::npos) {
    query_pos = path_end = raw_path_query.size();
  } else {
    query_pos = path_end + 1;
  }
  return uri_ref{std::move(scheme), std::move(host),
                 util::percentDecode(std::begin(raw_path_query),
                                     std::begin(raw_path_query) + path_end),
                 raw_path_query.substr(query_pos)};
}

} // namespace asio_http2
} // namespace nghttp2
