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

#include <iostream>

#include <nghttp2/asio_http2_client.h>

using boost::asio::ip::tcp;

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::client;

int main(int argc, char *argv[]) {
  try {
    boost::system::error_code ec;
    boost::asio::io_service io_service;

    boost::asio::ssl::context tls_ctx(boost::asio::ssl::context::sslv23);
    tls_ctx.set_default_verify_paths();
    // disabled to make development easier...
    // tls_ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    configure_tls_context(ec, tls_ctx);

    session sess(io_service, tls_ctx, "localhost", "3000");
    sess.on_connect([&sess](tcp::resolver::iterator endpoint_it) {
      boost::system::error_code ec;
      auto req = sess.submit(ec, "GET", "https://localhost:3000/");

      if (ec) {
        std::cerr << "error: " << ec.message() << std::endl;
        return;
      }

      req->on_response([&sess, req](const response &res) {
        std::cerr << "HTTP/2 " << res.status_code() << std::endl;
        for (auto &kv : res.header()) {
          std::cerr << kv.first << ": " << kv.second.value << "\n";
        }
        std::cerr << std::endl;

        res.on_data([&sess](const uint8_t *data, std::size_t len) {
          if (len == 0) {
            // eof
            sess.shutdown();
            return;
          }
          std::cerr.write(reinterpret_cast<const char *>(data), len);
          std::cerr << std::endl;
        });
      });
    });

    sess.on_error([](const boost::system::error_code &ec) {
      std::cerr << "error: " << ec.message() << std::endl;
    });

    io_service.run();
  } catch (std::exception &e) {
    std::cerr << "exception: " << e.what() << "\n";
  }

  return 0;
}
