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
// We wrote this code based on the original code which has the
// following license:
//
// server.hpp
// ~~~~~~~~~~
//
// Copyright (c) 2003-2013 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef HTTP_SERVER2_SERVER_HPP
#define HTTP_SERVER2_SERVER_HPP

#include "nghttp2_config.h"

#include <string>
#include <vector>
#include <memory>

#include <boost/noncopyable.hpp>

#include <nghttp2/asio_http2_server.h>

#include "asio_connection.h"
#include "asio_io_service_pool.h"

namespace nghttp2 {

namespace asio_http2 {

namespace server {

class serve_mux;

/// The top-level class of the HTTP server.
class server : private boost::noncopyable {
public:
  /// Construct the server to listen on the specified TCP address and port, and
  /// serve up files from the given directory.
  explicit server(const std::string &address, uint16_t port,
                  std::size_t io_service_pool_size, serve_mux &mux_,
                  std::unique_ptr<boost::asio::ssl::context> ssl_ctx,
                  int backlog = -1);

  /// Run the server's io_service loop.
  void run();

private:
  /// Initiate an asynchronous accept operation.
  void start_accept(boost::asio::ip::tcp::acceptor &acceptor);

  void start_timer();

  /// The pool of io_service objects used to perform asynchronous operations.
  io_service_pool io_service_pool_;

  /// The signal_set is used to register for process termination notifications.
  boost::asio::signal_set signals_;

  boost::asio::deadline_timer tick_timer_;

  /// Acceptor used to listen for incoming connections.
  std::vector<boost::asio::ip::tcp::acceptor> acceptors_;

  std::unique_ptr<boost::asio::ssl::context> ssl_ctx_;

  serve_mux &mux_;
};

} // namespace server

} // namespace asio_http2

} // namespace nghttp2

#endif // HTTP_SERVER2_SERVER_HPP
