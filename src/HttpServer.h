/*
 * nghttp2 - HTTP/2 C Library
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

#include <sys/types.h>

#include <cinttypes>
#include <cstdlib>

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <string_view>
#include <span>
#include <expected>

#include "ssl_compat.h"

#ifdef NGHTTP2_OPENSSL_IS_WOLFSSL
#  include <wolfssl/options.h>
#  include <wolfssl/openssl/ssl.h>
#else // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)
#  include <openssl/ssl.h>
#endif // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)

#include <ev.h>

#define NGHTTP2_NO_SSIZE_T
#include <nghttp2v2/nghttp2.h>

#include "http2.h"
#include "buffer.h"
#include "template.h"
#include "allocator.h"
#include "errors.h"

namespace nghttp2 {

struct Config {
  std::unordered_map<std::string, std::vector<std::string>> push;
  std::unordered_map<std::string, std::string> mime_types;
  Headers trailer;
  std::string trailer_names;
  std::string htdocs;
  std::string host;
  std::string private_key_file;
  std::string cert_file;
  std::string dh_param_file;
  std::string address;
  std::string mime_types_file{"/etc/mime.types"};
  std::string_view groups{"X25519:P-256:P-384:P-521"};
  ev_tstamp stream_read_timeout{1_min};
  ev_tstamp stream_write_timeout{1_min};
  void *data_ptr{};
  size_t padding{};
  size_t num_worker{1};
  size_t max_concurrent_streams{100};
  ssize_t header_table_size{-1};
  ssize_t encoder_header_table_size{-1};
  int window_bits{-1};
  int connection_window_bits{-1};
  uint16_t port{};
  bool verbose{};
  bool daemon{};
  bool verify_client{};
  bool no_tls{};
  bool error_gzip{};
  bool early_response{};
  bool hexdump{};
  bool echo_upload{};
  bool no_content_length{};
  bool ktls{};
  Config() noexcept = default;
  ~Config();
};

class Http2Handler;

struct FileEntry {
  FileEntry(std::string path, int64_t length, int64_t mtime, int fd,
            const std::string *content_type,
            std::chrono::steady_clock::time_point last_valid,
            bool stale = false)
    : path(std::move(path)),
      length(length),
      mtime(mtime),
      last_valid(last_valid),
      content_type(content_type),
      fd(fd),
      stale(stale) {}
  void map_file();
  std::string path;
  std::unordered_multimap<std::string, std::unique_ptr<FileEntry>>::iterator it;
  void *map{};
  int64_t length;
  int64_t mtime;
  std::chrono::steady_clock::time_point last_valid;
  const std::string *content_type;
  FileEntry *dlnext{}, *dlprev{};
  int fd;
  int usecount{1};
  bool stale;
};

struct RequestHeader {
  std::string_view method;
  std::string_view scheme;
  std::string_view authority;
  std::string_view host;
  std::string_view path;
  std::string_view ims;
  std::string_view expect;

  struct {
    nghttp2_rcbuf *method;
    nghttp2_rcbuf *scheme;
    nghttp2_rcbuf *authority;
    nghttp2_rcbuf *host;
    nghttp2_rcbuf *path;
    nghttp2_rcbuf *ims;
    nghttp2_rcbuf *expect;
  } rcbuf;
};

struct Stream {
  BlockAllocator balloc{1024, 1024};
  RequestHeader header{};
  Http2Handler *handler;
  FileEntry *file_ent{};
  bool static_file_ent{};
  ev_timer rtimer;
  ev_timer wtimer;
  int64_t body_length{};
  int64_t body_offset{};
  // Total amount of bytes (sum of name and value length) used in
  // headers.
  size_t header_buffer_size{};
  int64_t stream_id;
  bool echo_upload{};
  Stream(Http2Handler *handler, int64_t stream_id);
  ~Stream();
};

class Sessions;

class Http2Handler {
public:
  Http2Handler(Sessions *sessions, int fd, SSL *ssl, int64_t session_id);
  ~Http2Handler();

  void remove_self();
  void start_settings_timer();
  std::expected<void, Error> on_read();
  std::expected<void, Error> on_write();
  std::expected<void, Error> connection_made();
  std::expected<void, Error> verify_alpn_result();

  std::expected<void, Error>
  submit_file_response(std::string_view status, Stream *stream,
                       time_t last_modified, off_t file_length,
                       const std::string *content_type,
                       const nghttp2_data_reader *dr);

  std::expected<void, Error> submit_response(std::string_view status,
                                             int64_t stream_id,
                                             const nghttp2_data_reader *dr);

  std::expected<void, Error> submit_response(std::string_view status,
                                             int64_t stream_id,
                                             const HeaderRefs &headers,
                                             const nghttp2_data_reader *dr);

  std::expected<void, Error>
  submit_non_final_response(const std::string &status, int64_t stream_id);

  std::expected<void, Error> submit_push_promise(Stream *stream,
                                                 std::string_view push_path);

  std::expected<void, Error> submit_rst_stream(Stream *stream,
                                               uint32_t error_code);

  void add_stream(int64_t stream_id, std::unique_ptr<Stream> stream);
  void remove_stream(int64_t stream_id);
  Stream *get_stream(int64_t stream_id);
  int64_t session_id() const;
  Sessions *get_sessions() const;
  const Config *get_config() const;
  void remove_settings_timer();
  void terminate_session(uint32_t error_code);
  void set_timeout();
  std::expected<void, Error> on_timeout();

  std::expected<void, Error> fill_wb(nghttp2_tstamp ts);

  std::expected<void, Error> read_clear();
  std::expected<void, Error> write_clear();
  std::expected<void, Error> tls_handshake();
  std::expected<void, Error> read_tls();
  std::expected<void, Error> write_tls();

  struct ev_loop *get_loop() const;

  using WriteBuf = Buffer<64_k>;

private:
  ev_io wev_;
  ev_io rev_;
  ev_timer settings_timerev_;
  std::unordered_map<int64_t, std::unique_ptr<Stream>> id2stream_;
  std::function<std::expected<void, Error>(Http2Handler &)> read_, write_;
  int64_t session_id_;
  nghttp2_conn *conn_{};
  Sessions *sessions_;
  SSL *ssl_;
  std::span<const uint8_t> data_pending_;
  int fd_;
  struct {
    std::span<const uint8_t> data;
  } tx_{};
  std::array<uint8_t, 16_k> txbuf_;
};

struct StatusPage {
  std::string status;
  FileEntry file_ent;
};

class HttpServer {
public:
  HttpServer(const Config *config);
  std::expected<void, Error> run();
  const Config *get_config() const;
  const StatusPage *get_status_page(int status) const;

private:
  std::vector<StatusPage> status_pages_;
  const Config *config_;
};

nghttp2_ssize file_read_callback(nghttp2_conn *conn, int64_t stream_id,
                                 nghttp2_vec *vec, size_t veccnt,
                                 uint32_t *pflags, void *conn_user_data,
                                 void *stream_user_data);

} // namespace nghttp2

#endif // !defined(HTTP_SERVER_H)
