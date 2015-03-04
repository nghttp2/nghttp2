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
#ifndef HTTP2_HANDLER_H
#define HTTP2_HANDLER_H

#include "nghttp2_config.h"

#include <map>
#include <vector>
#include <functional>
#include <string>

#include <boost/array.hpp>

#include <nghttp2/asio_http2_server.h>

namespace nghttp2 {
namespace asio_http2 {
namespace server {

class http2_handler;
class http2_stream;
class serve_mux;

class request_impl {
public:
  request_impl();

  void header(header_map h);
  const header_map &header() const;
  header_map &header();

  void method(std::string method);
  const std::string &method() const;

  const uri_ref &uri() const;
  uri_ref &uri();

  void on_data(data_cb cb);

  void stream(http2_stream *s);
  void call_on_data(const uint8_t *data, std::size_t len);

private:
  http2_stream *stream_;
  header_map header_;
  std::string method_;
  uri_ref uri_;
  data_cb on_data_cb_;
};

class response_impl {
public:
  response_impl();
  void write_head(unsigned int status_code, header_map h = {});
  void end(std::string data = "");
  void end(read_cb cb);
  void on_close(close_cb cb);
  void resume();

  void cancel(uint32_t error_code);

  response *push(boost::system::error_code &ec, std::string method,
                 std::string raw_path_query, header_map h = {}) const;

  boost::asio::io_service &io_service();

  void start_response();

  unsigned int status_code() const;
  const header_map &header() const;
  bool started() const;
  void pushed(bool f);
  void push_promise_sent(bool f);
  void stream(http2_stream *s);
  read_cb::result_type call_read(uint8_t *data, std::size_t len,
                                 uint32_t *data_flags);
  void call_on_close(uint32_t error_code);

private:
  http2_stream *stream_;
  header_map header_;
  read_cb read_cb_;
  close_cb close_cb_;
  unsigned int status_code_;
  // true if response started (end() is called)
  bool started_;
  // true if this is pushed stream's response
  bool pushed_;
  // true if PUSH_PROMISE is sent if this is response of a pushed
  // stream
  bool push_promise_sent_;
};

class http2_stream {
public:
  http2_stream(http2_handler *h, int32_t stream_id);

  int32_t get_stream_id() const;
  request &request();
  response &response();

  http2_handler *handler() const;

private:
  http2_handler *handler_;
  class request request_;
  class response response_;
  int32_t stream_id_;
};

struct callback_guard {
  callback_guard(http2_handler &h);
  ~callback_guard();
  http2_handler &handler;
};

typedef std::function<void(void)> connection_write;

class http2_handler : public std::enable_shared_from_this<http2_handler> {
public:
  http2_handler(boost::asio::io_service &io_service, connection_write writefun,
                serve_mux &mux);

  ~http2_handler();

  int start();

  http2_stream *create_stream(int32_t stream_id);
  void close_stream(int32_t stream_id);
  http2_stream *find_stream(int32_t stream_id);

  void call_on_request(http2_stream &stream);

  bool should_stop() const;

  int start_response(http2_stream &stream);

  void stream_error(int32_t stream_id, uint32_t error_code);

  void initiate_write();

  void enter_callback();
  void leave_callback();
  bool inside_callback() const;

  void resume(http2_stream &stream);

  response *push_promise(boost::system::error_code &ec, http2_stream &stream,
                         std::string method, std::string raw_path_query,
                         header_map h);

  boost::asio::io_service &io_service();

  template <size_t N>
  int on_read(const boost::array<uint8_t, N> &buffer, std::size_t len) {
    callback_guard cg(*this);

    int rv;

    rv = nghttp2_session_mem_recv(session_, buffer.data(), len);

    if (rv < 0) {
      return -1;
    }

    return 0;
  }

  template <size_t N>
  int on_write(boost::array<uint8_t, N> &buffer, std::size_t &len) {
    callback_guard cg(*this);

    len = 0;

    if (buf_) {
      std::copy_n(buf_, buflen_, std::begin(buffer));

      len += buflen_;

      buf_ = nullptr;
      buflen_ = 0;
    }

    for (;;) {
      const uint8_t *data;
      auto nread = nghttp2_session_mem_send(session_, &data);
      if (nread < 0) {
        return -1;
      }

      if (nread == 0) {
        break;
      }

      if (len + nread > buffer.size()) {
        buf_ = data;
        buflen_ = nread;

        break;
      }

      std::copy_n(data, nread, std::begin(buffer) + len);

      len += nread;
    }

    return 0;
  }

private:
  std::map<int32_t, std::shared_ptr<http2_stream>> streams_;
  connection_write writefun_;
  serve_mux &mux_;
  boost::asio::io_service &io_service_;
  nghttp2_session *session_;
  const uint8_t *buf_;
  std::size_t buflen_;
  bool inside_callback_;
};

} // namespace server
} // namespace asio_http2
} // namespace nghttp

#endif // HTTP2_HANDLER_H
