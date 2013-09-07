/*
 * nghttp2 - HTTP/2.0 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
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
#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include "nghttp2_config.h"

#include <stdint.h>
#include <sys/types.h>

#include <cstdlib>

#include <string>
#include <vector>
#include <map>
#include <memory>

#include <openssl/ssl.h>

#include <event2/bufferevent.h>

#include <nghttp2/nghttp2.h>

namespace nghttp2 {

struct Config {
  std::string htdocs;
  bool verbose;
  bool daemon;
  std::string host;
  uint16_t port;
  std::string private_key_file;
  std::string cert_file;
  nghttp2_on_request_recv_callback on_request_recv_callback;
  void *data_ptr;
  bool verify_client;
  bool no_tls;
  bool no_flow_control;
  size_t output_upper_thres;
  Config();
};

class Sessions;

struct Request {
  int32_t stream_id;
  std::vector<std::pair<std::string, std::string>> headers;
  int file;
  std::pair<std::string, size_t> response_body;
  Request(int32_t stream_id);
  ~Request();
};

class Sessions;

class Http2Handler {
public:
  Http2Handler(Sessions *sessions, int fd, SSL *ssl, int64_t session_id);
  ~Http2Handler();

  void remove_self();
  int setup_bev();
  int on_read();
  int on_write();
  int on_connect();
  int verify_npn_result();
  int sendcb(const uint8_t *data, size_t len);
  int recvcb(uint8_t *buf, size_t len);

  int submit_file_response(const std::string& status,
                           int32_t stream_id,
                           time_t last_modified,
                           off_t file_length,
                           nghttp2_data_provider *data_prd);

  int submit_response(const std::string& status,
                      int32_t stream_id,
                      nghttp2_data_provider *data_prd);

  int submit_response
  (const std::string& status,
   int32_t stream_id,
   const std::vector<std::pair<std::string, std::string>>& headers,
   nghttp2_data_provider *data_prd);

  void add_stream(int32_t stream_id, std::unique_ptr<Request> req);
  void remove_stream(int32_t stream_id);
  Request* get_stream(int32_t stream_id);
  int64_t session_id() const;
  Sessions* get_sessions() const;
  const Config* get_config() const;
  size_t get_left_connhd_len() const;
  void set_left_connhd_len(size_t left);
private:
  nghttp2_session *session_;
  Sessions *sessions_;
  bufferevent *bev_;
  int fd_;
  SSL* ssl_;
  int64_t session_id_;
  std::map<int32_t, std::unique_ptr<Request>> id2req_;
  size_t left_connhd_len_;
};

class HttpServer {
public:
  HttpServer(const Config* config);
  int listen();
  int run();
private:
  const Config *config_;
};

int htdocs_on_request_recv_callback
(nghttp2_session *session, int32_t stream_id, void *user_data);

ssize_t file_read_callback
(nghttp2_session *session, int32_t stream_id,
 uint8_t *buf, size_t length, int *eof,
 nghttp2_data_source *source, void *user_data);

} // namespace nghttp2

#endif // HTTP_SERVER_H
