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
#include "asio_server_response_impl.h"

#include "asio_server_stream.h"
#include "asio_server_http2_handler.h"
#include "asio_common.h"

namespace nghttp2 {
namespace asio_http2 {
namespace server {

response_impl::response_impl()
    : strm_(nullptr), status_code_(200), started_(false), pushed_(false),
      push_promise_sent_(false) {}

unsigned int response_impl::status_code() const { return status_code_; }

void response_impl::write_head(unsigned int status_code, header_map h) {
  status_code_ = status_code;
  header_ = std::move(h);
}

void response_impl::end(std::string data) {
  if (started_) {
    return;
  }

  end(string_reader(std::move(data)));
}

void response_impl::end(read_cb cb) {
  if (started_) {
    return;
  }

  read_cb_ = std::move(cb);
  started_ = true;

  start_response();
}

void response_impl::on_close(close_cb cb) { close_cb_ = std::move(cb); }

void response_impl::call_on_close(uint32_t error_code) {
  if (close_cb_) {
    close_cb_(error_code);
  }
}

void response_impl::cancel(uint32_t error_code) {
  auto handler = strm_->handler();
  handler->stream_error(strm_->get_stream_id(), error_code);
}

void response_impl::start_response() {
  if (!started_ || (pushed_ && !push_promise_sent_)) {
    return;
  }

  auto handler = strm_->handler();

  if (handler->start_response(*strm_) != 0) {
    handler->stream_error(strm_->get_stream_id(), NGHTTP2_INTERNAL_ERROR);
    return;
  }
}

response *response_impl::push(boost::system::error_code &ec, std::string method,
                              std::string raw_path_query, header_map h) const {
  auto handler = strm_->handler();
  return handler->push_promise(ec, *strm_, std::move(method),
                               std::move(raw_path_query), std::move(h));
}

void response_impl::resume() {
  auto handler = strm_->handler();
  handler->resume(*strm_);
}

boost::asio::io_service &response_impl::io_service() {
  return strm_->handler()->io_service();
}

bool response_impl::started() const { return started_; }

void response_impl::pushed(bool f) { pushed_ = f; }

void response_impl::push_promise_sent(bool f) { push_promise_sent_ = f; }

const header_map &response_impl::header() const { return header_; }

void response_impl::stream(class stream *s) { strm_ = s; }

read_cb::result_type response_impl::call_read(uint8_t *data, std::size_t len,
                                              uint32_t *data_flags) {
  if (read_cb_) {
    return read_cb_(data, len, data_flags);
  }

  *data_flags |= NGHTTP2_DATA_FLAG_EOF;

  return 0;
}

} // namespace server
} // namespace asio_http2
} // namespace nghttp2
