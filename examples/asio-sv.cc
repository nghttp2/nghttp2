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

#include <iostream>
#include <string>

#include <nghttp2/asio_http2_server.h>

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;

int main(int argc, char *argv[]) {
  try {
    // Check command line arguments.
    if (argc < 4) {
      std::cerr
          << "Usage: asio-sv <address> <port> <threads> [<private-key-file> "
          << "<cert-file>]\n";
      return 1;
    }

    boost::system::error_code ec;

    std::string addr = argv[1];
    std::string port = argv[2];
    std::size_t num_threads = std::stoi(argv[3]);

    http2 server;

    server.num_threads(num_threads);

    server.handle("/", [](const request &req, const response &res) {
      res.write_head(200, {{"foo", {"bar"}}});
      res.end("hello, world\n");
    });
    server.handle("/secret/", [](const request &req, const response &res) {
      res.write_head(200);
      res.end("under construction!\n");
    });
    server.handle("/push", [](const request &req, const response &res) {
      boost::system::error_code ec;
      auto push = res.push(ec, "GET", "/push/1");
      if (!ec) {
        push->write_head(200);
        push->end("server push FTW!\n");
      }

      res.write_head(200);
      res.end("you'll receive server push!\n");
    });
    server.handle("/delay", [](const request &req, const response &res) {
      res.write_head(200);

      auto timer = std::make_shared<boost::asio::deadline_timer>(
          res.io_service(), boost::posix_time::seconds(3));
      auto closed = std::make_shared<bool>();

      res.on_close([timer, closed](uint32_t error_code) {
        timer->cancel();
        *closed = true;
      });

      timer->async_wait([&res, closed](const boost::system::error_code &ec) {
        if (ec || *closed) {
          return;
        }

        res.end("finally!\n");
      });
    });
    server.handle("/trailer", [](const request &req, const response &res) {
      // send trailer part.
      res.write_head(200, {{"trailers", {"digest"}}});

      std::string body = "nghttp2 FTW!\n";
      auto left = std::make_shared<size_t>(body.size());

      res.end([&res, body, left](uint8_t *dst, std::size_t len,
                                 uint32_t *data_flags) {
        auto n = std::min(len, *left);
        std::copy_n(body.c_str() + (body.size() - *left), n, dst);
        *left -= n;
        if (*left == 0) {
          *data_flags |=
              NGHTTP2_DATA_FLAG_EOF | NGHTTP2_DATA_FLAG_NO_END_STREAM;
          // RFC 3230 Instance Digests in HTTP.  The digest value is
          // SHA-256 message digest of body.
          res.write_trailer(
              {{"digest",
                {"SHA-256=qqXqskW7F3ueBSvmZRCiSwl2ym4HRO0M/pvQCBlSDis="}}});
        }
        return n;
      });
    });

    if (argc >= 6) {
      boost::asio::ssl::context tls(boost::asio::ssl::context::sslv23);
      tls.use_private_key_file(argv[4], boost::asio::ssl::context::pem);
      tls.use_certificate_chain_file(argv[5]);

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
