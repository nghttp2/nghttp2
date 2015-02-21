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
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <string>

#include <nghttp2/asio_http2.h>

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;

int main(int argc, char *argv[]) {
  try {
    // Check command line arguments.
    if (argc < 4) {
      std::cerr << "Usage: asio-sv2 <port> <threads> <doc-root> "
                << "<private-key-file> <cert-file>\n";
      return 1;
    }

    uint16_t port = std::stoi(argv[1]);
    std::size_t num_threads = std::stoi(argv[2]);
    std::string docroot = argv[3];

    http2 server;

    server.num_threads(num_threads);

    if (argc >= 6) {
      server.tls(argv[4], argv[5]);
    }

    server.listen("*", port, [&docroot](const std::shared_ptr<request> &req,
                                        const std::shared_ptr<response> &res) {
      auto path = percent_decode(req->path());
      if (!check_path(path)) {
        res->write_head(404);
        res->end();
        return;
      }

      if (path == "/") {
        path = "/index.html";
      }

      path = docroot + path;
      auto fd = open(path.c_str(), O_RDONLY);
      if (fd == -1) {
        res->write_head(404);
        res->end();
        return;
      }

      auto headers = std::vector<header>();

      struct stat stbuf;
      if (stat(path.c_str(), &stbuf) == 0) {
        headers.push_back(
            header{"content-length", std::to_string(stbuf.st_size)});
        headers.push_back(header{"last-modified", http_date(stbuf.st_mtime)});
      }
      res->write_head(200, std::move(headers));
      res->end(file_reader_from_fd(fd));
    });
  } catch (std::exception &e) {
    std::cerr << "exception: " << e.what() << "\n";
  }

  return 0;
}
