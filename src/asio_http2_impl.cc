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
#include "asio_http2_impl.h"

#include <boost/asio/ssl.hpp>

#include <openssl/ssl.h>

#include <nghttp2/nghttp2.h>

#include "asio_server.h"
#include "util.h"
#include "ssl.h"
#include "template.h"

namespace nghttp2 {

namespace asio_http2 {

namespace server {

http2::http2() : impl_(make_unique<http2_impl>()) {}

http2::~http2() {}

void http2::listen(const std::string &address, uint16_t port, request_cb cb) {
  impl_->listen(address, port, std::move(cb));
}

void http2::num_threads(size_t num_threads) { impl_->num_threads(num_threads); }

void http2::tls(std::string private_key_file, std::string certificate_file) {
  impl_->tls(std::move(private_key_file), std::move(certificate_file));
}

void http2::backlog(int backlog) { impl_->backlog(backlog); }

http2_impl::http2_impl() : num_threads_(1), backlog_(-1) {}

namespace {
std::vector<unsigned char> &get_alpn_token() {
  static auto alpn_token = util::get_default_alpn();
  return alpn_token;
}
} // namespace

void http2_impl::listen(const std::string &address, uint16_t port,
                        request_cb cb) {
  std::unique_ptr<boost::asio::ssl::context> ssl_ctx;

  if (!private_key_file_.empty() && !certificate_file_.empty()) {
    ssl_ctx = make_unique<boost::asio::ssl::context>(
        boost::asio::ssl::context::sslv23);

    ssl_ctx->use_private_key_file(private_key_file_,
                                  boost::asio::ssl::context::pem);
    ssl_ctx->use_certificate_chain_file(certificate_file_);

    auto ctx = ssl_ctx->native_handle();

    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                                 SSL_OP_NO_COMPRESSION |
                                 SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
                                 SSL_OP_SINGLE_ECDH_USE | SSL_OP_NO_TICKET |
                                 SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

    SSL_CTX_set_cipher_list(ctx, ssl::DEFAULT_CIPHER_LIST);

    auto ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ecdh) {
      SSL_CTX_set_tmp_ecdh(ctx, ecdh);
      EC_KEY_free(ecdh);
    }

    SSL_CTX_set_next_protos_advertised_cb(
        ctx,
        [](SSL *s, const unsigned char **data, unsigned int *len, void *arg) {
          auto &token = get_alpn_token();

          *data = token.data();
          *len = token.size();

          return SSL_TLSEXT_ERR_OK;
        },
        nullptr);
  }

  server(address, port, num_threads_, std::move(cb), std::move(ssl_ctx),
         backlog_).run();
}

void http2_impl::num_threads(size_t num_threads) { num_threads_ = num_threads; }

void http2_impl::tls(std::string private_key_file,
                     std::string certificate_file) {
  private_key_file_ = std::move(private_key_file);
  certificate_file_ = std::move(certificate_file);
}

void http2_impl::backlog(int backlog) { backlog_ = backlog; }

} // namespace server

template <typename F, typename... T>
std::shared_ptr<Defer<F, T...>> defer_shared(F &&f, T &&... t) {
  return std::make_shared<Defer<F, T...>>(std::forward<F>(f),
                                          std::forward<T>(t)...);
}

read_cb file_reader(const std::string &path) {
  auto fd = open(path.c_str(), O_RDONLY);
  if (fd == -1) {
    return read_cb();
  }

  return file_reader_from_fd(fd);
}

read_cb file_reader_from_fd(int fd) {
  auto d = defer_shared(close, fd);

  return [fd, d](uint8_t *buf, size_t len) -> read_cb::result_type {
    int rv;
    while ((rv = read(fd, buf, len)) == -1 && errno == EINTR)
      ;

    if (rv == -1) {
      return std::make_pair(-1, false);
    }

    if (rv == 0) {
      return std::make_pair(rv, true);
    }

    return std::make_pair(rv, false);
  };
}

bool check_path(const std::string &path) { return util::check_path(path); }

std::string percent_decode(const std::string &s) {
  return util::percentDecode(std::begin(s), std::end(s));
}

std::string http_date(int64_t t) { return util::http_date(t); }

} // namespace asio_http2

} // namespace nghttp2
