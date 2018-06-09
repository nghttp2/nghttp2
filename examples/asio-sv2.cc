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
// main.cpp
// ~~~~~~~~
//
// Copyright (c) 2003-2013 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif // HAVE_UNISTD_H
#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif // HAVE_FCNTL_H
#include <iostream>
#include <string>

#include <nghttp2/asio_http2_server.h>

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;

int main(int argc, char *argv[]) {
  try {
    // Check command line arguments.
    if (argc < 5) {
      std::cerr << "Usage: asio-sv2 <address> <port> <threads> <doc-root> "
                << "[<private-key-file> <cert-file>]\n";
      return 1;
    }

    boost::system::error_code ec;

    std::string addr = argv[1];
    std::string port = argv[2];
    std::size_t num_threads = std::stoi(argv[3]);
    std::string docroot = argv[4];

    http2 server;

    server.num_threads(num_threads);

    server.handle("/", [&docroot](const request &req, const response &res) {
      auto path = percent_decode(req.uri().path);
      if (!check_path(path)) {
        res.write_head(404);
        res.end();
        return;
      }

      if (path == "/") {
        path = "/index.html";
      }

      path = docroot + path;
      auto fd = open(path.c_str(), O_RDONLY);
      if (fd == -1) {
        res.write_head(404);
        res.end();
        return;
      }

      auto header = header_map();

      struct stat stbuf;
      if (stat(path.c_str(), &stbuf) == 0) {
        header.emplace("content-length",
                       header_value{std::to_string(stbuf.st_size)});
        header.emplace("last-modified",
                       header_value{http_date(stbuf.st_mtime)});
      }
      res.write_head(200, std::move(header));
      res.end(file_generator_from_fd(fd));
    });

    if (argc >= 7) {
      boost::asio::ssl::context tls(boost::asio::ssl::context::sslv23);
      tls.use_private_key_file(argv[5], boost::asio::ssl::context::pem);
      tls.use_certificate_chain_file(argv[6]);

      configure_tls_context_easy(ec, tls);

      if (server.listen_and_serve(ec, tls, addr, port)) {
        std::cerr << "error: " << ec.message() << std::endl;
      }
    } else {
      if (server.listen_and_serve(ec, addr, port)) {
        std::cerr << "error: " << ec.message() << std::endl;
      }
    }
  } catch (std::exception &e) {
    std::cerr << "exception: " << e.what() << "\n";
  }

  return 0;
}
