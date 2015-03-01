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

http_header::http_header() {}

http_header::http_header(
    std::initializer_list<std::pair<std::string, header_value>> ilist) {
  for (auto &kv : ilist) {
    auto name = kv.first;
    util::inp_strlower(name);
    items_.emplace(std::move(name), kv.second);
  }
}

http_header &http_header::
operator=(std::initializer_list<std::pair<std::string, header_value>> ilist) {
  items_.clear();
  for (auto &kv : ilist) {
    auto name = kv.first;
    util::inp_strlower(name);
    items_.emplace(std::move(name), kv.second);
  }
  return *this;
}

const header_map &http_header::items() const { return items_; }

void http_header::add(std::string name, std::string value, bool sensitive) {
  util::inp_strlower(name);
  items_.emplace(name, header_value(value, sensitive));
}

const header_value *http_header::get(const std::string &name) const {
  auto it = items_.find(name);
  if (it == std::end(items_)) {
    return nullptr;
  }
  return &(*it).second;
}

std::size_t http_header::size() const { return items_.size(); }

bool http_header::empty() const { return items_.empty(); }

} // namespace asio_http2
} // namespace nghttp2
