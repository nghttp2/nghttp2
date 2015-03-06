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
// server.cpp
// ~~~~~~~~~~
//
// Copyright (c) 2003-2013 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "asio_server.h"

#include <boost/date_time/posix_time/posix_time.hpp>

#include "asio_server_connection.h"
#include "util.h"

namespace nghttp2 {
namespace asio_http2 {
namespace server {

server::server(std::size_t io_service_pool_size)
    : io_service_pool_(io_service_pool_size),
      signals_(io_service_pool_.get_io_service()),
      tick_timer_(io_service_pool_.get_io_service(),
                  boost::posix_time::seconds(1)) {
  // Register to handle the signals that indicate when the server should exit.
  // It is safe to register for the same signal multiple times in a program,
  // provided all registration for the specified signal is made through Asio.
  signals_.add(SIGINT);
  signals_.add(SIGTERM);
#if defined(SIGQUIT)
  signals_.add(SIGQUIT);
#endif // defined(SIGQUIT)
  signals_.async_wait([this](const boost::system::error_code &error,
                             int signal_number) { io_service_pool_.stop(); });
}

boost::system::error_code
server::listen_and_serve(boost::system::error_code &ec,
                         boost::asio::ssl::context *tls_context,
                         const std::string &address, const std::string &port,
                         int backlog, serve_mux &mux) {
  ec.clear();

  if (bind_and_listen(ec, address, port, backlog)) {
    return ec;
  }

  for (auto &acceptor : acceptors_) {
    if (tls_context) {
      start_accept(*tls_context, acceptor, mux);
    } else {
      start_accept(acceptor, mux);
    }
  }

  start_timer();

  io_service_pool_.run();

  return ec;
}

boost::system::error_code server::bind_and_listen(boost::system::error_code &ec,
                                                  const std::string &address,
                                                  const std::string &port,
                                                  int backlog) {
  // Open the acceptor with the option to reuse the address (i.e.
  // SO_REUSEADDR).
  tcp::resolver resolver(io_service_pool_.get_io_service());
  tcp::resolver::query query(address, port);
  auto it = resolver.resolve(query, ec);
  if (ec) {
    return ec;
  }

  for (; it != tcp::resolver::iterator(); ++it) {
    tcp::endpoint endpoint = *it;
    auto acceptor = tcp::acceptor(io_service_pool_.get_io_service());

    if (acceptor.open(endpoint.protocol(), ec)) {
      continue;
    }

    acceptor.set_option(tcp::acceptor::reuse_address(true));

    if (acceptor.bind(endpoint, ec)) {
      continue;
    }

    if (acceptor.listen(
            backlog == -1 ? boost::asio::socket_base::max_connections : backlog,
            ec)) {
      continue;
    }

    acceptors_.push_back(std::move(acceptor));
  }

  if (acceptors_.empty()) {
    return ec;
  }

  // ec could have some errors since we may have failed to bind some
  // interfaces.
  ec.clear();

  return ec;
}

std::shared_ptr<std::string> cached_date;

void server::start_timer() {
  cached_date = std::make_shared<std::string>(util::http_date(time(nullptr)));

  tick_timer_.async_wait([this](const boost::system::error_code &e) {
    tick_timer_.expires_at(tick_timer_.expires_at() +
                           boost::posix_time::seconds(1));
    start_timer();
  });
}

void server::start_accept(boost::asio::ssl::context &tls_context,
                          tcp::acceptor &acceptor, serve_mux &mux) {
  auto new_connection = std::make_shared<connection<ssl_socket>>(
      mux, io_service_pool_.get_io_service(), tls_context);

  acceptor.async_accept(new_connection->socket().lowest_layer(),
                        [this, &tls_context, &acceptor, &mux, new_connection](
                            const boost::system::error_code &e) {
    if (!e) {
      new_connection->socket().lowest_layer().set_option(tcp::no_delay(true));
      new_connection->socket().async_handshake(
          boost::asio::ssl::stream_base::server,
          [new_connection](const boost::system::error_code &e) {
            if (!e) {
              new_connection->start();
            }
          });
    }

    start_accept(tls_context, acceptor, mux);
  });
}

void server::start_accept(tcp::acceptor &acceptor, serve_mux &mux) {
  auto new_connection = std::make_shared<connection<tcp::socket>>(
      mux, io_service_pool_.get_io_service());

  acceptor.async_accept(new_connection->socket(),
                        [this, &acceptor, &mux, new_connection](
                            const boost::system::error_code &e) {
    if (!e) {
      new_connection->socket().set_option(tcp::no_delay(true));
      new_connection->start();
    }

    start_accept(acceptor, mux);
  });
}

} // namespace server
} // namespace asio_http2
} // namespace nghttp2
