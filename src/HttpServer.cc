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
#include "HttpServer.h"

#include <sys/stat.h>
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif // defined(HAVE_SYS_SOCKET_H)
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif // defined(HAVE_NETDB_H)
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif // defined(HAVE_UNISTD_H)
#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif // defined(HAVE_FCNTL_H)
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif // defined(HAVE_NETINET_IN_H)
#include <netinet/tcp.h>
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif // defined(HAVE_ARPA_INET_H)
#include <sys/mman.h>

#include <cassert>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <deque>
#include <print>

#include "ssl_compat.h"

#ifdef NGHTTP2_OPENSSL_IS_WOLFSSL
#  include <wolfssl/options.h>
#  include <wolfssl/openssl/err.h>
#  include <wolfssl/openssl/dh.h>
#else // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)
#  include <openssl/err.h>
#  include <openssl/dh.h>
#  if OPENSSL_3_0_0_API
#    include <openssl/decoder.h>
#  endif // OPENSSL_3_0_0_API
#endif   // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)

#include <zlib.h>

#include "app_helper.h"
#include "http2.h"
#include "util.h"
#include "tls.h"
#include "template.h"

#ifndef O_BINARY
#  define O_BINARY (0)
#endif // !defined(O_BINARY)

using namespace std::chrono_literals;
using namespace std::string_literals;

namespace nghttp2 {

constexpr auto DEFAULT_HTML = "index.html"sv;
constexpr auto NGHTTPD_SERVER = "nghttpd nghttp2/" NGHTTP2_VERSION ""sv;

namespace {
void delete_handler(Http2Handler *handler) {
  handler->remove_self();
  delete handler;
}
} // namespace

namespace {
void print_session_id(int64_t id) { std::print("[id={}] ", id); }
} // namespace

Config::~Config() {}

void FileEntry::map_file() {
  map = mmap(NULL, static_cast<size_t>(length), PROT_READ, MAP_PRIVATE, fd, 0);
  assert(map != MAP_FAILED);
}

namespace {
void stream_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto stream = static_cast<Stream *>(w->data);
  auto hd = stream->handler;
  auto config = hd->get_config();

  ev_timer_stop(hd->get_loop(), &stream->rtimer);
  ev_timer_stop(hd->get_loop(), &stream->wtimer);

  if (config->verbose) {
    print_session_id(hd->session_id());
    print_timer();
    std::println(" timeout stream_id={}", stream->stream_id);
  }

  if (!hd->submit_rst_stream(stream, NGHTTP2_INTERNAL_ERROR) ||
      !hd->on_write()) {
    delete_handler(hd);
  }
}
} // namespace

namespace {
void add_stream_read_timeout(Stream *stream) {
  auto hd = stream->handler;
  ev_timer_again(hd->get_loop(), &stream->rtimer);
}
} // namespace

namespace {
void remove_stream_read_timeout(Stream *stream) {
  auto hd = stream->handler;
  ev_timer_stop(hd->get_loop(), &stream->rtimer);
}
} // namespace

namespace {
void remove_stream_write_timeout(Stream *stream) {
  auto hd = stream->handler;
  ev_timer_stop(hd->get_loop(), &stream->wtimer);
}
} // namespace

constexpr ev_tstamp RELEASE_FD_TIMEOUT = 2.;

namespace {
void release_fd_cb(struct ev_loop *loop, ev_timer *w, int revents);
} // namespace

constexpr auto FILE_ENTRY_MAX_AGE = 10s;

constexpr size_t FILE_ENTRY_EVICT_THRES = 2048;

namespace {
bool need_validation_file_entry(const FileEntry *ent,
                                std::chrono::steady_clock::time_point now) {
  return ent->last_valid + FILE_ENTRY_MAX_AGE < now;
}
} // namespace

namespace {
bool validate_file_entry(FileEntry *ent,
                         std::chrono::steady_clock::time_point now) {
  struct stat stbuf;
  int rv;

  rv = fstat(ent->fd, &stbuf);
  if (rv != 0) {
    ent->stale = true;
    return false;
  }

  if (stbuf.st_nlink == 0 || ent->mtime != stbuf.st_mtime) {
    ent->stale = true;
    return false;
  }

  ent->mtime = stbuf.st_mtime;
  ent->last_valid = now;

  return true;
}
} // namespace

class Sessions {
public:
  Sessions(HttpServer *sv, struct ev_loop *loop, const Config *config,
           SSL_CTX *ssl_ctx)
    : sv_(sv),
      loop_(loop),
      config_(config),
      ssl_ctx_(ssl_ctx),
      tstamp_cached_(ev_now(loop)),
      cached_date_(
        util::format_http_date(std::chrono::system_clock::from_time_t(
          static_cast<time_t>(tstamp_cached_)))) {
    ev_timer_init(&release_fd_timer_, release_fd_cb, 0., RELEASE_FD_TIMEOUT);
    release_fd_timer_.data = this;
  }
  ~Sessions() {
    ev_timer_stop(loop_, &release_fd_timer_);
    for (auto handler : handlers_) {
      delete handler;
    }
  }
  void add_handler(Http2Handler *handler) { handlers_.insert(handler); }
  void remove_handler(Http2Handler *handler) {
    handlers_.erase(handler);
    if (handlers_.empty() && !fd_cache_.empty()) {
      ev_timer_again(loop_, &release_fd_timer_);
    }
  }
  SSL_CTX *get_ssl_ctx() const { return ssl_ctx_; }
  SSL *ssl_session_new(int fd) {
    SSL *ssl = SSL_new(ssl_ctx_);
    if (!ssl) {
      std::println(stderr, "SSL_new() failed");
      return nullptr;
    }
    if (SSL_set_fd(ssl, fd) == 0) {
      std::println(stderr, "SSL_set_fd() failed");
      SSL_free(ssl);
      return nullptr;
    }
    return ssl;
  }
  const Config *get_config() const { return config_; }
  struct ev_loop *get_loop() const { return loop_; }
  int64_t get_next_session_id() {
    auto session_id = next_session_id_;
    if (next_session_id_ == std::numeric_limits<int64_t>::max()) {
      next_session_id_ = 1;
    } else {
      ++next_session_id_;
    }
    return session_id;
  }
  void accept_connection(int fd) {
    util::make_socket_nodelay(fd);
    SSL *ssl = nullptr;
    if (ssl_ctx_) {
      ssl = ssl_session_new(fd);
      if (!ssl) {
        close(fd);
        return;
      }
    }
    auto handler =
      std::make_unique<Http2Handler>(this, fd, ssl, get_next_session_id());
    if (!ssl && !handler->connection_made()) {
      return;
    }
    add_handler(handler.release());
  }
  void update_cached_date() {
    cached_date_ =
      util::format_http_date(std::chrono::system_clock::from_time_t(
        static_cast<time_t>(tstamp_cached_)));
  }
  const std::string &get_cached_date() {
    auto t = ev_now(loop_);
    if (t != tstamp_cached_) {
      tstamp_cached_ = t;
      update_cached_date();
    }
    return cached_date_;
  }
  FileEntry *get_cached_fd(const std::string &path) {
    auto range = fd_cache_.equal_range(path);
    if (range.first == range.second) {
      return nullptr;
    }

    auto now = std::chrono::steady_clock::now();

    for (auto it = range.first; it != range.second;) {
      auto &ent = (*it).second;
      if (ent->stale) {
        ++it;
        continue;
      }
      if (need_validation_file_entry(ent.get(), now) &&
          !validate_file_entry(ent.get(), now)) {
        if (ent->usecount == 0) {
          fd_cache_lru_.remove(ent.get());
          munmap(ent->map, static_cast<size_t>(ent->length));
          close(ent->fd);
          it = fd_cache_.erase(it);
          continue;
        }
        ++it;
        continue;
      }

      fd_cache_lru_.remove(ent.get());
      fd_cache_lru_.append(ent.get());

      ++ent->usecount;
      return ent.get();
    }
    return nullptr;
  }
  FileEntry *cache_fd(const std::string &path, const FileEntry &ent) {
    auto rv = fd_cache_.emplace(path, std::make_unique<FileEntry>(ent));
    auto &res = (*rv).second;
    res->it = rv;
    fd_cache_lru_.append(res.get());

    while (fd_cache_.size() > FILE_ENTRY_EVICT_THRES) {
      auto ent = fd_cache_lru_.head;
      if (ent->usecount) {
        break;
      }
      fd_cache_lru_.remove(ent);
      munmap(ent->map, static_cast<size_t>(ent->length));
      close(ent->fd);
      fd_cache_.erase(ent->it);
    }

    return res.get();
  }
  void release_fd(FileEntry *target) {
    --target->usecount;

    if (target->usecount == 0 && target->stale) {
      fd_cache_lru_.remove(target);
      munmap(target->map, static_cast<size_t>(target->length));
      close(target->fd);
      fd_cache_.erase(target->it);
      return;
    }

    // We use timer to close file descriptor and delete the entry from
    // cache.  The timer will be started when there is no handler.
  }
  void release_unused_fd() {
    for (auto i = std::ranges::begin(fd_cache_);
         i != std::ranges::end(fd_cache_);) {
      auto &ent = (*i).second;
      if (ent->usecount != 0) {
        ++i;
        continue;
      }

      fd_cache_lru_.remove(ent.get());
      munmap(ent->map, static_cast<size_t>(ent->length));
      close(ent->fd);
      i = fd_cache_.erase(i);
    }
  }
  const HttpServer *get_server() const { return sv_; }
  bool handlers_empty() const { return handlers_.empty(); }

private:
  std::unordered_set<Http2Handler *> handlers_;
  // cache for file descriptors to read file.
  std::unordered_multimap<std::string, std::unique_ptr<FileEntry>> fd_cache_;
  DList<FileEntry> fd_cache_lru_;
  HttpServer *sv_;
  struct ev_loop *loop_;
  const Config *config_;
  SSL_CTX *ssl_ctx_;
  ev_timer release_fd_timer_;
  int64_t next_session_id_{1};
  ev_tstamp tstamp_cached_;
  std::string cached_date_;
};

namespace {
bool prepare_upload_temp_store(Stream *stream, Http2Handler *hd) {
  auto sessions = hd->get_sessions();

  char tempfn[] = "/tmp/nghttpd.temp.XXXXXX";
  auto fd = mkstemp(tempfn);
  if (fd == -1) {
    return false;
  }
  unlink(tempfn);
  // Ordinary request never start with "echo:".  The length is 0 for
  // now.  We will update it when we get whole request body.
  auto path = std::string("echo:") + tempfn;
  stream->file_ent =
    sessions->cache_fd(path, FileEntry(path, 0, 0, fd, nullptr, {}, true));
  stream->echo_upload = true;
  return true;
}
} // namespace

namespace {
int begin_headers(nghttp2_conn *conn, int64_t stream_id, void *user_data,
                  void *stream_user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);

  auto stream = std::make_unique<Stream>(hd, stream_id);

  add_stream_read_timeout(stream.get());
  hd->add_stream(stream_id, std::move(stream));

  return 0;
}
} // namespace

namespace {
int recv_header(nghttp2_conn *conn, int64_t stream_id, int32_t token,
                nghttp2_rcbuf *name, nghttp2_rcbuf *value, uint8_t flags,
                void *user_data, void *stream_user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);

  auto namebuf = nghttp2_rcbuf_get_buf(name);
  auto valuebuf = nghttp2_rcbuf_get_buf(value);
  auto stream = hd->get_stream(stream_id);
  if (!stream) {
    return 0;
  }

  if (stream->header_buffer_size + namebuf.len + valuebuf.len > 64_k) {
    if (!hd->submit_rst_stream(stream, NGHTTP2_INTERNAL_ERROR)) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
  }

  stream->header_buffer_size += namebuf.len + valuebuf.len;

  auto &header = stream->header;

  switch (token) {
  case NGHTTP2_HPACK_TOKEN__METHOD:
    header.method = as_string_view(valuebuf.base, valuebuf.len);
    header.rcbuf.method = value;
    nghttp2_rcbuf_incref(value);
    break;
  case NGHTTP2_HPACK_TOKEN__SCHEME:
    header.scheme = as_string_view(valuebuf.base, valuebuf.len);
    header.rcbuf.scheme = value;
    nghttp2_rcbuf_incref(value);
    break;
  case NGHTTP2_HPACK_TOKEN__AUTHORITY:
    header.authority = as_string_view(valuebuf.base, valuebuf.len);
    header.rcbuf.authority = value;
    nghttp2_rcbuf_incref(value);
    break;
  case NGHTTP2_HPACK_TOKEN_HOST:
    header.host = as_string_view(valuebuf.base, valuebuf.len);
    header.rcbuf.host = value;
    nghttp2_rcbuf_incref(value);
    break;
  case NGHTTP2_HPACK_TOKEN__PATH:
    header.path = as_string_view(valuebuf.base, valuebuf.len);
    header.rcbuf.path = value;
    nghttp2_rcbuf_incref(value);
    break;
  case NGHTTP2_HPACK_TOKEN_IF_MODIFIED_SINCE:
    header.ims = as_string_view(valuebuf.base, valuebuf.len);
    header.rcbuf.ims = value;
    nghttp2_rcbuf_incref(value);
    break;
  case NGHTTP2_HPACK_TOKEN_EXPECT:
    header.expect = as_string_view(valuebuf.base, valuebuf.len);
    header.rcbuf.expect = value;
    nghttp2_rcbuf_incref(value);
    break;
  default:
    break;
  }

  return 0;
}
} // namespace

namespace {
std::expected<void, Error> prepare_response(Stream *stream, Http2Handler *hd);
} // namespace

namespace {
int end_headers(nghttp2_conn *conn, int64_t stream_id, int fin, void *user_data,
                void *stream_user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);

  auto stream = hd->get_stream(stream_id);
  if (!stream) {
    return 0;
  }

  auto expect100 = stream->header.expect;

  if (util::strieq("100-continue"sv, expect100) &&
      !hd->submit_non_final_response("100", stream_id)) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  auto method = stream->header.method;
  if (hd->get_config()->echo_upload &&
      (method == "POST"sv || method == "PUT"sv)) {
    if (!prepare_upload_temp_store(stream, hd)) {
      if (!hd->submit_rst_stream(stream, NGHTTP2_INTERNAL_ERROR)) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }

      return 0;
    }
  } else if (hd->get_config()->early_response &&
             !prepare_response(stream, hd)) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  if (!fin) {
    add_stream_read_timeout(stream);
  }

  return 0;
}
} // namespace

namespace {
int recv_data(nghttp2_conn *conn, int64_t stream_id, const uint8_t *data,
              size_t datalen, void *user_data, void *stream_user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);

  auto stream = hd->get_stream(stream_id);
  if (!stream) {
    return 0;
  }

  if (stream->echo_upload) {
    assert(stream->file_ent);

    while (datalen) {
      ssize_t n;

      while ((n = write(stream->file_ent->fd, data, datalen)) == -1 &&
             errno == EINTR)
        ;
      if (n == -1) {
        if (!hd->submit_rst_stream(stream, NGHTTP2_INTERNAL_ERROR)) {
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }

        return 0;
      }
      datalen -= as_unsigned(n);
      data += n;
    }
  }

  // TODO Handle POST

  add_stream_read_timeout(stream);

  return 0;
}
} // namespace

namespace {
int end_stream(nghttp2_conn *conn, int64_t stream_id, void *user_data,
               void *stream_user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);

  auto stream = hd->get_stream(stream_id);
  if (!stream) {
    return 0;
  }

  remove_stream_read_timeout(stream);

  if ((stream->echo_upload || !hd->get_config()->early_response) &&
      !prepare_response(stream, hd)) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int stream_close(nghttp2_conn *conn, uint32_t flags, int64_t stream_id,
                 uint32_t error_code, void *user_data, void *stream_user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);
  hd->remove_stream(stream_id);
  if (hd->get_config()->verbose) {
    print_session_id(hd->session_id());
    print_timer();
    std::println(" stream_id={} closed", stream_id);
    fflush(stdout);
  }
  return 0;
}
} // namespace

namespace {
void release_fd_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto sessions = static_cast<Sessions *>(w->data);

  ev_timer_stop(loop, w);

  if (!sessions->handlers_empty()) {
    return;
  }

  sessions->release_unused_fd();
}
} // namespace

Stream::Stream(Http2Handler *handler, int64_t stream_id)
  : handler(handler), stream_id(stream_id) {
  auto config = handler->get_config();
  ev_timer_init(&rtimer, stream_timeout_cb, 0., config->stream_read_timeout);
  ev_timer_init(&wtimer, stream_timeout_cb, 0., config->stream_write_timeout);
  rtimer.data = this;
  wtimer.data = this;
}

Stream::~Stream() {
  if (file_ent != nullptr && !static_file_ent) {
    auto sessions = handler->get_sessions();
    sessions->release_fd(file_ent);
  }

  auto &rcbuf = header.rcbuf;
  nghttp2_rcbuf_decref(rcbuf.method);
  nghttp2_rcbuf_decref(rcbuf.scheme);
  nghttp2_rcbuf_decref(rcbuf.authority);
  nghttp2_rcbuf_decref(rcbuf.host);
  nghttp2_rcbuf_decref(rcbuf.path);
  nghttp2_rcbuf_decref(rcbuf.ims);
  nghttp2_rcbuf_decref(rcbuf.expect);

  auto loop = handler->get_loop();
  ev_timer_stop(loop, &rtimer);
  ev_timer_stop(loop, &wtimer);
}

namespace {
void on_session_closed(Http2Handler *hd, int64_t session_id) {
  if (hd->get_config()->verbose) {
    print_session_id(session_id);
    print_timer();
    std::println(" closed");
  }
}
} // namespace

namespace {
void settings_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto hd = static_cast<Http2Handler *>(w->data);

  if (!hd->on_timeout()) {
    delete_handler(hd);
  }
}
} // namespace

namespace {
void readcb(struct ev_loop *loop, ev_io *w, int revents) {
  auto handler = static_cast<Http2Handler *>(w->data);

  if (!handler->on_read()) {
    delete_handler(handler);
  }
}
} // namespace

namespace {
void writecb(struct ev_loop *loop, ev_io *w, int revents) {
  auto handler = static_cast<Http2Handler *>(w->data);

  if (!handler->on_write()) {
    delete_handler(handler);
  }
}
} // namespace

Http2Handler::Http2Handler(Sessions *sessions, int fd, SSL *ssl,
                           int64_t session_id)
  : session_id_(session_id), sessions_(sessions), ssl_(ssl), fd_(fd) {
  ev_timer_init(&settings_timerev_, settings_timeout_cb, 0., 0.);
  ev_io_init(&wev_, writecb, fd, EV_WRITE);
  ev_io_init(&rev_, readcb, fd, EV_READ);

  settings_timerev_.data = this;
  wev_.data = this;
  rev_.data = this;

  auto loop = sessions_->get_loop();
  ev_io_start(loop, &rev_);

  if (ssl) {
    SSL_set_accept_state(ssl);
    read_ = &Http2Handler::tls_handshake;
    write_ = &Http2Handler::tls_handshake;
  } else {
    read_ = &Http2Handler::read_clear;
    write_ = &Http2Handler::write_clear;
  }
}

Http2Handler::~Http2Handler() {
  on_session_closed(this, session_id_);
  nghttp2_conn_del(conn_);
  if (ssl_) {
    SSL_set_shutdown(ssl_, SSL_get_shutdown(ssl_) | SSL_RECEIVED_SHUTDOWN);
    ERR_clear_error();
    SSL_shutdown(ssl_);
  }
  auto loop = sessions_->get_loop();
  ev_timer_stop(loop, &settings_timerev_);
  ev_io_stop(loop, &rev_);
  ev_io_stop(loop, &wev_);
  if (ssl_) {
    SSL_free(ssl_);
  }
  shutdown(fd_, SHUT_WR);
  close(fd_);
}

void Http2Handler::remove_self() { sessions_->remove_handler(this); }

struct ev_loop *Http2Handler::get_loop() const { return sessions_->get_loop(); }

void Http2Handler::start_settings_timer() {
  ev_timer_start(sessions_->get_loop(), &settings_timerev_);
}

std::expected<void, Error> Http2Handler::fill_wb(nghttp2_tstamp ts) {
  auto buf = std::span{txbuf_};

  auto nwrite = nghttp2_conn_write(conn_, buf.data(), buf.size(), ts);
  if (nwrite < 0) {
    std::println(stderr, "nghttp2_conn_write: {}",
                 nghttp2_strerror(static_cast<int>(nwrite)));

    return std::unexpected{Error::HTTP2};
  }

  tx_.data = buf.first(as_unsigned(nwrite));

  return {};
}

std::expected<void, Error> Http2Handler::read_clear() {
  std::array<uint8_t, 16_k> buf;
  auto ts = util::timestamp();

  ssize_t nread;
  while ((nread = read(fd_, buf.data(), buf.size())) == -1 && errno == EINTR)
    ;
  if (nread == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return on_write();
    }
    return std::unexpected{Error::SYSCALL};
  }
  if (nread == 0) {
    return std::unexpected{Error::RECV_EOF};
  }

  if (get_config()->hexdump) {
    (void)util::hexdump(stdout, buf.data(), as_unsigned(nread));
  }

  if (auto rv = nghttp2_conn_read(conn_, buf.data(), as_unsigned(nread), ts);
      rv != 0) {
    std::println(stderr, "nghttp2_conn_read: {}", nghttp2_strerror(rv));

    return std::unexpected{Error::HTTP2};
  }

  return on_write();
}

std::expected<void, Error> Http2Handler::write_clear() {
  auto loop = sessions_->get_loop();
  auto ts = util::timestamp();

  for (;;) {
    if (tx_.data.empty()) {
      if (auto rv = fill_wb(ts); !rv) {
        return rv;
      }

      if (tx_.data.empty()) {
        break;
      }
    }

    ssize_t nwrite;
    while ((nwrite = write(fd_, tx_.data.data(), tx_.data.size())) == -1 &&
           errno == EINTR)
      ;
    if (nwrite == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        ev_io_start(loop, &wev_);
        return {};
      }

      return std::unexpected{Error::SYSCALL};
    }

    tx_.data = tx_.data.subspan(as_unsigned(nwrite));
  }

  ev_io_stop(loop, &wev_);

  return {};
}

std::expected<void, Error> Http2Handler::tls_handshake() {
  ev_io_stop(sessions_->get_loop(), &wev_);

  ERR_clear_error();

  auto rv = SSL_do_handshake(ssl_);

  if (rv <= 0) {
    auto err = SSL_get_error(ssl_, rv);
    switch (err) {
    case SSL_ERROR_WANT_READ:
      return {};
    case SSL_ERROR_WANT_WRITE:
      ev_io_start(sessions_->get_loop(), &wev_);
      return {};
    default:
      return std::unexpected{Error::CRYPTO};
    }
  }

  if (sessions_->get_config()->verbose) {
    std::println(stderr, "SSL/TLS handshake completed");
  }

  if (auto rv = verify_alpn_result(); !rv) {
    return rv;
  }

  read_ = &Http2Handler::read_tls;
  write_ = &Http2Handler::write_tls;

  if (auto rv = connection_made(); !rv) {
    return rv;
  }

  if (sessions_->get_config()->verbose) {
    if (SSL_session_reused(ssl_)) {
      std::println(stderr, "SSL/TLS session reused");
    }
  }

  return {};
}

std::expected<void, Error> Http2Handler::read_tls() {
  std::array<uint8_t, 16_k> buf;
  auto ts = util::timestamp();

  ERR_clear_error();

  for (;;) {
    auto rv = SSL_read(ssl_, buf.data(), buf.size());

    if (rv <= 0) {
      auto err = SSL_get_error(ssl_, rv);
      switch (err) {
      case SSL_ERROR_WANT_READ:
        return on_write();
      case SSL_ERROR_WANT_WRITE:
        // renegotiation started
      default:
        return std::unexpected{Error::CRYPTO};
      }
    }

    auto nread = static_cast<size_t>(rv);

    if (get_config()->hexdump) {
      (void)util::hexdump(stdout, buf.data(), nread);
    }

    if (auto rv = nghttp2_conn_read(conn_, buf.data(), nread, ts); rv != 0) {
      std::println(stderr, "nghttp2_conn_read: {}({})", nghttp2_strerror(rv),
                   rv);

      return std::unexpected{Error::HTTP2};
    }

    if (SSL_pending(ssl_) == 0) {
      break;
    }
  }

  return on_write();
}

std::expected<void, Error> Http2Handler::write_tls() {
  auto loop = sessions_->get_loop();
  auto ts = util::timestamp();

  ERR_clear_error();

  for (;;) {
    if (tx_.data.empty()) {
      if (auto rv = fill_wb(ts); !rv) {
        return rv;
      }

      if (tx_.data.empty()) {
        break;
      }
    }

    auto nwrite =
      SSL_write(ssl_, tx_.data.data(), static_cast<int>(tx_.data.size()));

    if (nwrite <= 0) {
      auto err = SSL_get_error(ssl_, nwrite);
      switch (err) {
      case SSL_ERROR_WANT_WRITE:
        ev_io_start(sessions_->get_loop(), &wev_);
        return {};
      case SSL_ERROR_WANT_READ:
        // renegotiation started
      default:
        return std::unexpected{Error::CRYPTO};
      }
    }

    tx_.data = tx_.data.subspan(as_unsigned(nwrite));
  }

  ev_io_stop(loop, &wev_);

  return {};
}

std::expected<void, Error> Http2Handler::on_read() { return read_(*this); }

std::expected<void, Error> Http2Handler::on_write() {
  if (auto rv = write_(*this); !rv) {
    return rv;
  }

  set_timeout();

  return {};
}

void Http2Handler::set_timeout() {
  if (!conn_) {
    return;
  }

  auto loop = sessions_->get_loop();

  auto expiry = nghttp2_conn_get_expiry(conn_);
  if (expiry == UINT64_MAX) {
    if (ev_is_active(&settings_timerev_)) {
      ev_timer_stop(loop, &settings_timerev_);
    }

    return;
  }

  auto now = util::timestamp();
  auto config = sessions_->get_config();

  if (expiry <= now) {
    if (config->verbose) {
      auto t = static_cast<ev_tstamp>(now - expiry) / NGHTTP2_SECONDS;
      std::println(stderr, "Timer has already expired: {:.9f}s", t);
    }

    ev_feed_event(loop, &settings_timerev_, EV_TIMER);

    return;
  }

  auto t = static_cast<ev_tstamp>(expiry - now) / NGHTTP2_SECONDS;
  if (config->verbose) {
    std::println(stderr, "Set timer={:.9f}s", t);
  }

  settings_timerev_.repeat = t;
  ev_timer_again(loop, &settings_timerev_);
}

std::expected<void, Error> Http2Handler::on_timeout() {
  auto rv = nghttp2_conn_handle_expiry(conn_, util::timestamp());
  if (rv != 0) {
    return std::unexpected{Error::HTTP2};
  }

  auto loop = sessions_->get_loop();

  ev_io_start(loop, &wev_);

  return {};
}

namespace {
void log_write(void *user_data, char *msg, size_t len) {
  msg[len++] = '\n';

  while (write(fileno(stderr), msg, len) == -1 && errno == EINTR)
    ;
}
} // namespace

std::expected<void, Error> Http2Handler::connection_made() {
  int rv;

  static const auto callbacks = nghttp2_callbacks{
    .rand = util::secure_random,
    .stream_close = nghttp2::stream_close,
    .begin_headers = nghttp2::begin_headers,
    .recv_header = nghttp2::recv_header,
    .end_headers = nghttp2::end_headers,
    .recv_data = nghttp2::recv_data,
    .end_stream = nghttp2::end_stream,
  };

  auto config = sessions_->get_config();

  nghttp2_settings settings;

  nghttp2_settings_default(&settings);
  settings.initial_ts = util::timestamp();

  util::secure_random(reinterpret_cast<uint8_t *>(&settings.conn_id),
                      sizeof(settings.conn_id));

  if (config->verbose) {
    settings.log_write = log_write;
  }

  settings.max_concurrent_streams_remote =
    (uint32_t)config->max_concurrent_streams;

  if (config->header_table_size != -1) {
    settings.hpack_max_dtable_capacity = (uint32_t)config->header_table_size;
  }

  if (config->window_bits != -1) {
    settings.initial_max_stream_data = (1 << config->window_bits) - 1;
  }

  if (config->connection_window_bits != -1) {
    settings.initial_max_data = (1 << config->connection_window_bits) - 1;
  }

  if (config->encoder_header_table_size != -1) {
    settings.hpack_encoder_max_dtable_capacity =
      as_unsigned(config->encoder_header_table_size);
  }

  rv = nghttp2_conn_server_new(&conn_, &callbacks, &settings, NULL, this);
  if (rv != 0) {
    std::println(stderr, "nghttp2_conn_server_new: {}", nghttp2_strerror(rv));
    return std::unexpected{Error::HTTP2};
  }

  if (ssl_ && !nghttp2::tls::check_http2_requirement(ssl_)) {
    terminate_session(NGHTTP2_INADEQUATE_SECURITY);
  }

  return on_write();
}

std::expected<void, Error> Http2Handler::verify_alpn_result() {
  const unsigned char *next_proto = nullptr;
  unsigned int next_proto_len;
  // Check the negotiated protocol in ALPN
  SSL_get0_alpn_selected(ssl_, &next_proto, &next_proto_len);
  if (next_proto) {
    auto proto = as_string_view(next_proto, next_proto_len);
    if (sessions_->get_config()->verbose) {
      std::println("The negotiated protocol: {}", proto);
    }
    if (util::check_h2_is_selected(proto)) {
      return {};
    }
  }
  if (sessions_->get_config()->verbose) {
    std::println(stderr, "Client did not advertise HTTP/2 protocol. (nghttp2 "
                         "expects h2");
  }
  return std::unexpected{Error::ALPN};
}

std::expected<void, Error>
Http2Handler::submit_file_response(std::string_view status, Stream *stream,
                                   time_t last_modified, off_t file_length,
                                   const std::string *content_type,
                                   const nghttp2_data_reader *dr) {
  std::string last_modified_str;
  auto nva = std::to_array({
    http2::make_field(":status"sv, status),
    http2::make_field("server"sv, NGHTTPD_SERVER),
    http2::make_field("cache-control"sv, "max-age=3600"sv),
    http2::make_field_v("date"sv, sessions_->get_cached_date()),
    {},
    {},
    {},
    {},
  });
  size_t nvlen = 4;
  if (!get_config()->no_content_length) {
    nva[nvlen++] = http2::make_field(
      "content-length"sv,
      util::make_string_ref_uint(stream->balloc, as_unsigned(file_length)));
  }
  if (last_modified != 0) {
    last_modified_str = util::format_http_date(
      std::chrono::system_clock::from_time_t(last_modified));
    nva[nvlen++] = http2::make_field_v("last-modified"sv, last_modified_str);
  }
  if (content_type) {
    nva[nvlen++] = http2::make_field_v("content-type"sv, *content_type);
  }
  auto &trailer_names = get_config()->trailer_names;
  if (!trailer_names.empty()) {
    nva[nvlen++] = http2::make_field("trailer"sv, trailer_names);
  }

  if (auto rv = nghttp2_conn_submit_response(conn_, stream->stream_id,
                                             nva.data(), nvlen, dr);
      rv != 0) {
    std::println(stderr, "nghttp2_conn_submit_response: {}",
                 nghttp2_strerror(rv));

    return std::unexpected{Error::HTTP2};
  }

  return {};
}

std::expected<void, Error>
Http2Handler::submit_response(std::string_view status, int64_t stream_id,
                              const HeaderRefs &headers,
                              const nghttp2_data_reader *dr) {
  auto nva = std::vector<nghttp2_nv>();
  nva.reserve(4 + headers.size());
  nva.push_back(http2::make_field(":status"sv, status));
  nva.push_back(http2::make_field("server"sv, NGHTTPD_SERVER));
  nva.push_back(http2::make_field_v("date"sv, sessions_->get_cached_date()));

  if (dr) {
    auto &trailer_names = get_config()->trailer_names;
    if (!trailer_names.empty()) {
      nva.push_back(http2::make_field("trailer"sv, trailer_names));
    }
  }

  for (auto &nv : headers) {
    nva.push_back(
      http2::make_field(nv.name, nv.value, http2::never_index(nv.never_index)));
  }
  if (auto rv = nghttp2_conn_submit_response(conn_, stream_id, nva.data(),
                                             nva.size(), dr);
      rv != 0) {
    std::println(stderr, "nghttp2_conn_submit_response: {}",
                 nghttp2_strerror(rv));

    return std::unexpected{Error::HTTP2};
  }

  return {};
}

std::expected<void, Error>
Http2Handler::submit_response(std::string_view status, int64_t stream_id,
                              const nghttp2_data_reader *dr) {
  auto nva = std::to_array({
    http2::make_field(":status"sv, status),
    http2::make_field("server"sv, NGHTTPD_SERVER),
    http2::make_field_v("date"sv, sessions_->get_cached_date()),
    {},
  });
  size_t nvlen = 3;

  if (dr) {
    auto &trailer_names = get_config()->trailer_names;
    if (!trailer_names.empty()) {
      nva[nvlen++] = http2::make_field("trailer"sv, trailer_names);
    }
  }

  if (nghttp2_conn_submit_response(conn_, stream_id, nva.data(), nvlen, dr) !=
      0) {
    return std::unexpected{Error::HTTP2};
  }

  return {};
}

std::expected<void, Error>
Http2Handler::submit_non_final_response(const std::string &status,
                                        int64_t stream_id) {
  auto nva = std::to_array({http2::make_field_v(":status"sv, status)});

  auto rv = nghttp2_conn_submit_info(conn_, stream_id, nva.data(), nva.size());
  if (rv != 0) {
    return std::unexpected{Error::HTTP2};
  }

  return {};
}

std::expected<void, Error>
Http2Handler::submit_rst_stream(Stream *stream, uint32_t error_code) {
  remove_stream_read_timeout(stream);
  remove_stream_write_timeout(stream);

  nghttp2_conn_shutdown_stream(conn_, 0x00, stream->stream_id, error_code);

  return {};
}

void Http2Handler::add_stream(int64_t stream_id,
                              std::unique_ptr<Stream> stream) {
  id2stream_[stream_id] = std::move(stream);
}

void Http2Handler::remove_stream(int64_t stream_id) {
  id2stream_.erase(stream_id);
}

Stream *Http2Handler::get_stream(int64_t stream_id) {
  auto itr = id2stream_.find(stream_id);
  if (itr == std::ranges::end(id2stream_)) {
    return nullptr;
  } else {
    return (*itr).second.get();
  }
}

int64_t Http2Handler::session_id() const { return session_id_; }

Sessions *Http2Handler::get_sessions() const { return sessions_; }

const Config *Http2Handler::get_config() const {
  return sessions_->get_config();
}

void Http2Handler::remove_settings_timer() {
  ev_timer_stop(sessions_->get_loop(), &settings_timerev_);
}

void Http2Handler::terminate_session(uint32_t error_code) {
  nghttp2_conn_terminate(conn_, error_code);
}

nghttp2_ssize file_read_callback(nghttp2_conn *conn, int64_t stream_id,
                                 nghttp2_vec *vec, size_t veccnt,
                                 uint32_t *pflags, void *user_data,
                                 void *stream_user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);
  auto stream = hd->get_stream(stream_id);

  vec[0] = {
    .base = reinterpret_cast<uint8_t *>(stream->file_ent->map),
    .len = static_cast<size_t>(stream->file_ent->length),
  };

  stream->body_offset = stream->file_ent->length;

  *pflags |= NGHTTP2_READ_DATA_FLAG_EOF;

  return 1;
}

namespace {
std::expected<void, Error>
prepare_status_response(Stream *stream, Http2Handler *hd, int status) {
  auto sessions = hd->get_sessions();
  auto status_page = sessions->get_server()->get_status_page(status);
  auto file_ent = &status_page->file_ent;

  // we don't set stream->file_ent since we don't want to expire it.
  stream->static_file_ent = true;
  stream->file_ent = const_cast<FileEntry *>(file_ent);
  stream->body_length = file_ent->length;

  static constexpr nghttp2_data_reader dr{
    .read_data = file_read_callback,
  };

  HeaderRefs headers;
  headers.reserve(2);
  headers.emplace_back("content-type"sv, "text/html; charset=UTF-8"sv);
  headers.emplace_back(
    "content-length"sv,
    util::make_string_ref_uint(stream->balloc, as_unsigned(file_ent->length)));
  return hd->submit_response(status_page->status, stream->stream_id, headers,
                             &dr);
}
} // namespace

namespace {
std::expected<void, Error> prepare_echo_response(Stream *stream,
                                                 Http2Handler *hd) {
  auto length = lseek(stream->file_ent->fd, 0, SEEK_END);
  if (length == -1) {
    return hd->submit_rst_stream(stream, NGHTTP2_INTERNAL_ERROR);
  }
  stream->body_length = length;
  if (lseek(stream->file_ent->fd, 0, SEEK_SET) == -1) {
    return hd->submit_rst_stream(stream, NGHTTP2_INTERNAL_ERROR);
  }

  static constexpr nghttp2_data_reader dr{
    .read_data = file_read_callback,
  };

  HeaderRefs headers;
  headers.emplace_back("nghttpd-response"sv, "echo"sv);
  if (!hd->get_config()->no_content_length) {
    headers.emplace_back(
      "content-length"sv,
      util::make_string_ref_uint(stream->balloc, as_unsigned(length)));
  }

  return hd->submit_response("200"sv, stream->stream_id, headers, &dr);
}
} // namespace

namespace {
std::expected<void, Error> prepare_redirect_response(Stream *stream,
                                                     Http2Handler *hd,
                                                     std::string_view path,
                                                     int status) {
  auto scheme = stream->header.scheme;

  auto authority = stream->header.authority;
  if (authority.empty()) {
    authority = stream->header.host;
  }

  auto location =
    concat_string_ref(stream->balloc, scheme, "://"sv, authority, path);

  auto headers = HeaderRefs{{"location"sv, location}};

  auto sessions = hd->get_sessions();
  auto status_page = sessions->get_server()->get_status_page(status);

  return hd->submit_response(status_page->status, stream->stream_id, headers,
                             nullptr);
}
} // namespace

namespace {
std::expected<void, Error> prepare_response(Stream *stream, Http2Handler *hd) {
  auto reqpath = stream->header.path;
  if (reqpath.empty()) {
    return prepare_status_response(stream, hd, 405);
  }

  auto ims = stream->header.ims;

  time_t last_mod = 0;
  bool last_mod_found = false;
  if (!ims.empty()) {
    auto maybe_last_mod = util::parse_http_date(ims);
    if (maybe_last_mod) {
      last_mod_found = true;
      last_mod = *maybe_last_mod;
    }
  }

  std::string_view raw_path, raw_query;
  auto query_pos = std::ranges::find(reqpath, '?');
  if (query_pos != std::ranges::end(reqpath)) {
    // Do not response to this request to allow clients to test timeouts.
    if ("nghttpd_do_not_respond_to_req=yes"sv ==
        std::string_view{query_pos, std::ranges::end(reqpath)}) {
      return {};
    }
    raw_path = std::string_view{std::ranges::begin(reqpath), query_pos};
    raw_query = std::string_view{query_pos, std::ranges::end(reqpath)};
  } else {
    raw_path = reqpath;
  }

  auto sessions = hd->get_sessions();

  std::string_view path;
  if (util::contains(raw_path, '%')) {
    path = util::percent_decode(stream->balloc, raw_path);
  } else {
    path = raw_path;
  }

  path = http2::path_join(stream->balloc, ""sv, ""sv, path, ""sv);

  if (util::contains(path, '\\')) {
    if (stream->file_ent) {
      sessions->release_fd(stream->file_ent);
      stream->file_ent = nullptr;
    }
    return prepare_status_response(stream, hd, 404);
  }

  std::string file_path;
  {
    auto len = hd->get_config()->htdocs.size() + path.size();

    auto trailing_slash = path[path.size() - 1] == '/';
    if (trailing_slash) {
      len += DEFAULT_HTML.size();
    }

    file_path.resize_and_overwrite(
      len, [hd, path, trailing_slash](auto p, auto len) {
        auto first = p;
        auto &htdocs = hd->get_config()->htdocs;
        p = std::ranges::copy(htdocs, p).out;
        p = std::ranges::copy(path, p).out;
        if (trailing_slash) {
          p = std::ranges::copy(DEFAULT_HTML, p).out;
        }

        return std::ranges::distance(first, p);
      });
  }

  if (stream->echo_upload) {
    assert(stream->file_ent);
    return prepare_echo_response(stream, hd);
  }

  auto file_ent = sessions->get_cached_fd(file_path);

  if (file_ent == nullptr) {
    int file = open(file_path.c_str(), O_RDONLY | O_BINARY);
    if (file == -1) {
      return prepare_status_response(stream, hd, 404);
    }

    struct stat buf;

    if (fstat(file, &buf) == -1) {
      close(file);
      return prepare_status_response(stream, hd, 404);
    }

    if (buf.st_mode & S_IFDIR) {
      close(file);

      auto reqpath =
        concat_string_ref(stream->balloc, raw_path, "/"sv, raw_query);

      return prepare_redirect_response(stream, hd, reqpath, 301);
    }

    const std::string *content_type = nullptr;

    auto ext = file_path.c_str() + file_path.size() - 1;
    for (; file_path.c_str() < ext && *ext != '.' && *ext != '/'; --ext)
      ;
    if (*ext == '.') {
      ++ext;

      const auto &mime_types = hd->get_config()->mime_types;
      auto content_type_itr = mime_types.find(ext);
      if (content_type_itr != std::ranges::end(mime_types)) {
        content_type = &(*content_type_itr).second;
      }
    }

    file_ent = sessions->cache_fd(
      file_path, FileEntry(file_path, buf.st_size, buf.st_mtime, file,
                           content_type, std::chrono::steady_clock::now()));
    file_ent->map_file();
  }

  stream->file_ent = file_ent;

  if (last_mod_found && file_ent->mtime <= last_mod) {
    return hd->submit_response("304"sv, stream->stream_id, nullptr);
  }

  auto method = stream->header.method;
  if (method == "HEAD"sv) {
    return hd->submit_file_response("200"sv, stream, file_ent->mtime,
                                    file_ent->length, file_ent->content_type,
                                    nullptr);
  }

  stream->body_length = file_ent->length;

  static constexpr nghttp2_data_reader dr{
    .read_data = file_read_callback,
  };

  return hd->submit_file_response("200"sv, stream, file_ent->mtime,
                                  file_ent->length, file_ent->content_type,
                                  &dr);
}
} // namespace

struct ClientInfo {
  int fd;
};

struct Worker {
  std::unique_ptr<Sessions> sessions;
  ev_async w;
  // protects q
  std::mutex m;
  std::deque<ClientInfo> q;
};

namespace {
void worker_acceptcb(struct ev_loop *loop, ev_async *w, int revents) {
  auto worker = static_cast<Worker *>(w->data);
  auto &sessions = worker->sessions;

  std::deque<ClientInfo> q;
  {
    std::lock_guard<std::mutex> lock(worker->m);
    q.swap(worker->q);
  }

  for (const auto &c : q) {
    sessions->accept_connection(c.fd);
  }
}
} // namespace

namespace {
void run_worker(Worker *worker) {
  auto loop = worker->sessions->get_loop();

  ev_run(loop, 0);

#ifdef NGHTTP2_OPENSSL_IS_WOLFSSL
  wc_ecc_fp_free();
#endif // defined(NGHTTP2_OPENSSL_IS_WOLFSSL)
}
} // namespace

namespace {
unsigned int get_ev_loop_flags() {
  if (ev_supported_backends() & ~ev_recommended_backends() & EVBACKEND_KQUEUE) {
    return ev_recommended_backends() | EVBACKEND_KQUEUE;
  }

  return 0;
}
} // namespace

class AcceptHandler {
public:
  AcceptHandler(HttpServer *sv, Sessions *sessions, const Config *config)
    : sessions_(sessions), config_(config), next_worker_(0) {
    if (config_->num_worker == 1) {
      return;
    }
    for (size_t i = 0; i < config_->num_worker; ++i) {
      if (config_->verbose) {
        std::println(stderr, "spawning thread #{}", i);
      }
      auto worker = std::make_unique<Worker>();
      auto loop = ev_loop_new(get_ev_loop_flags());
      worker->sessions =
        std::make_unique<Sessions>(sv, loop, config_, sessions_->get_ssl_ctx());
      ev_async_init(&worker->w, worker_acceptcb);
      worker->w.data = worker.get();
      ev_async_start(loop, &worker->w);

      auto t = std::thread(run_worker, worker.get());
      t.detach();
      workers_.push_back(std::move(worker));
    }
  }
  void accept_connection(int fd) {
    if (config_->num_worker == 1) {
      sessions_->accept_connection(fd);
      return;
    }

    // Dispatch client to the one of the worker threads, in a round
    // robin manner.
    auto &worker = workers_[next_worker_];
    if (next_worker_ == config_->num_worker - 1) {
      next_worker_ = 0;
    } else {
      ++next_worker_;
    }
    {
      std::lock_guard<std::mutex> lock(worker->m);
      worker->q.push_back({fd});
    }
    ev_async_send(worker->sessions->get_loop(), &worker->w);
  }

private:
  std::vector<std::unique_ptr<Worker>> workers_;
  Sessions *sessions_;
  const Config *config_;
  // In multi threading mode, this points to the next thread that
  // client will be dispatched.
  size_t next_worker_;
};

namespace {
void acceptcb(struct ev_loop *loop, ev_io *w, int revents);
} // namespace

class ListenEventHandler {
public:
  ListenEventHandler(Sessions *sessions, int fd,
                     std::shared_ptr<AcceptHandler> acceptor)
    : acceptor_(std::move(acceptor)), sessions_(sessions), fd_(fd) {
    ev_io_init(&w_, acceptcb, fd, EV_READ);
    w_.data = this;
    ev_io_start(sessions_->get_loop(), &w_);
  }
  void accept_connection() {
    constexpr size_t max_num_accept = 10;

    for (size_t i = 0; i < max_num_accept; ++i) {
#ifdef HAVE_ACCEPT4
      auto fd = accept4(fd_, nullptr, nullptr, SOCK_NONBLOCK);
#else  // !defined(HAVE_ACCEPT4)
      auto fd = accept(fd_, nullptr, nullptr);
#endif // !defined(HAVE_ACCEPT4)
      if (fd == -1) {
        break;
      }
#ifndef HAVE_ACCEPT4
      util::make_socket_nonblocking(fd);
#endif // !defined(HAVE_ACCEPT4)
      acceptor_->accept_connection(fd);
    }
  }

private:
  ev_io w_;
  std::shared_ptr<AcceptHandler> acceptor_;
  Sessions *sessions_;
  int fd_;
};

namespace {
void acceptcb(struct ev_loop *loop, ev_io *w, int revents) {
  auto handler = static_cast<ListenEventHandler *>(w->data);
  handler->accept_connection();
}
} // namespace

namespace {
FileEntry make_status_body(uint32_t status, uint16_t port) {
  BlockAllocator balloc(1024, 1024);

  auto status_string = http2::stringify_status(balloc, status);
  auto reason_pharase = http2::get_reason_phrase(status);

  std::string body;
  body = "<html><head><title>";
  body += status_string;
  body += ' ';
  body += reason_pharase;
  body += "</title></head><body><h1>";
  body += status_string;
  body += ' ';
  body += reason_pharase;
  body += "</h1><hr><address>";
  body += NGHTTPD_SERVER;
  body += " at port ";
  body += util::utos(port);
  body += "</address>";
  body += "</body></html>";

  char tempfn[] = "/tmp/nghttpd.temp.XXXXXX";
  int fd = mkstemp(tempfn);
  if (fd == -1) {
    auto error = errno;
    std::println(stderr, "Could not open status response body file: errno={}",
                 error);
    assert(0);
  }
  unlink(tempfn);
  ssize_t nwrite;
  while ((nwrite = write(fd, body.c_str(), body.size())) == -1 &&
         errno == EINTR)
    ;
  if (nwrite == -1) {
    auto error = errno;
    std::println(stderr,
                 "Could not write status response body into file: errno={}",
                 error);
    assert(0);
  }

  auto ent = FileEntry(util::utos(status), nwrite, 0, fd, nullptr, {});
  ent.map_file();

  return ent;
}
} // namespace

// index into HttpServer::status_pages_
enum {
  IDX_200,
  IDX_301,
  IDX_400,
  IDX_404,
  IDX_405,
};

HttpServer::HttpServer(const Config *config) : config_(config) {
  status_pages_ = std::vector<StatusPage>{
    {"200", make_status_body(200, config_->port)},
    {"301", make_status_body(301, config_->port)},
    {"400", make_status_body(400, config_->port)},
    {"404", make_status_body(404, config_->port)},
    {"405", make_status_body(405, config_->port)},
  };
}

namespace {
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
  // We don't verify the client certificate. Just request it for the
  // testing purpose.
  return 1;
}
} // namespace

namespace {
std::expected<void, Error> start_listen(HttpServer *sv, struct ev_loop *loop,
                                        Sessions *sessions,
                                        const Config *config) {
  int r;
  bool ok = false;
  const char *addr = nullptr;

  std::shared_ptr<AcceptHandler> acceptor;
  auto service = util::utos(config->port);

  addrinfo hints{
    .ai_flags = AI_PASSIVE
#ifdef AI_ADDRCONFIG
                | AI_ADDRCONFIG
#endif // defined(AI_ADDRCONFIG)
    ,
    .ai_family = AF_UNSPEC,
    .ai_socktype = SOCK_STREAM,
  };

  if (!config->address.empty()) {
    addr = config->address.c_str();
  }

  addrinfo *res, *rp;
  r = getaddrinfo(addr, service.c_str(), &hints, &res);
  if (r != 0) {
    std::println(stderr, "getaddrinfo() failed: {}", gai_strerror(r));
    return std::unexpected{Error::LIBC};
  }

  for (rp = res; rp; rp = rp->ai_next) {
    int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      continue;
    }
    int val = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      close(fd);
      continue;
    }
    (void)util::make_socket_nonblocking(fd);
#ifdef IPV6_V6ONLY
    if (rp->ai_family == AF_INET6) {
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        close(fd);
        continue;
      }
    }
#endif // defined(IPV6_V6ONLY)
    if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0 && listen(fd, 1000) == 0) {
      if (!acceptor) {
        acceptor = std::make_shared<AcceptHandler>(sv, sessions, config);
      }
      new ListenEventHandler(sessions, fd, acceptor);

      if (config->verbose) {
        std::string s = util::numeric_name(rp->ai_addr, rp->ai_addrlen);
        std::println("{}: listen {}:{}",
                     rp->ai_family == AF_INET ? "IPv4" : "IPv6", s,
                     config->port);
      }
      ok = true;
      continue;
    } else {
      std::println(stderr, "{}", strerror(errno));
    }
    close(fd);
  }
  freeaddrinfo(res);

  if (!ok) {
    return std::unexpected{Error::SYSCALL};
  }
  return {};
}
} // namespace

namespace {
int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                         unsigned char *outlen, const unsigned char *in,
                         unsigned int inlen, void *arg) {
  auto config = static_cast<HttpServer *>(arg)->get_config();
  if (config->verbose) {
    std::println("[ALPN] client offers:");

    for (unsigned int i = 0; i < inlen; i += in[i] + 1) {
      std::println(" * {}", as_string_view(&in[i + 1], in[i]));
    }
  }
  if (!util::select_h2(out, outlen, in, inlen)) {
    return SSL_TLSEXT_ERR_NOACK;
  }
  return SSL_TLSEXT_ERR_OK;
}
} // namespace

std::expected<void, Error> HttpServer::run() {
  SSL_CTX *ssl_ctx = nullptr;

  if (!config_->no_tls) {
    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
      std::println(stderr, "{}", ERR_error_string(ERR_get_error(), nullptr));
      return std::unexpected{Error::CRYPTO};
    }

    auto ssl_opts = static_cast<nghttp2_ssl_op_type>(
      (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) | SSL_OP_NO_SSLv2 |
      SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION |
      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION | SSL_OP_SINGLE_ECDH_USE |
      SSL_OP_NO_TICKET | SSL_OP_CIPHER_SERVER_PREFERENCE);

#ifdef SSL_OP_ENABLE_KTLS
    if (config_->ktls) {
      ssl_opts |= SSL_OP_ENABLE_KTLS;
    }
#endif // defined(SSL_OP_ENABLE_KTLS)

    SSL_CTX_set_options(ssl_ctx, ssl_opts);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

    if (auto rv = nghttp2::tls::ssl_ctx_set_proto_versions(
          ssl_ctx, nghttp2::tls::NGHTTP2_TLS_MIN_VERSION,
          nghttp2::tls::NGHTTP2_TLS_MAX_VERSION);
        !rv) {
      std::println(stderr, "Could not set TLS versions");
      return rv;
    }

    if (SSL_CTX_set_cipher_list(ssl_ctx, tls::DEFAULT_CIPHER_LIST.data()) ==
        0) {
      std::println(stderr, "{}", ERR_error_string(ERR_get_error(), nullptr));
      return std::unexpected{Error::CRYPTO};
    }

#ifdef NGHTTP2_OPENSSL_IS_WOLFSSL
    if (SSL_CTX_set_ciphersuites(ssl_ctx,
                                 tls::DEFAULT_TLS13_CIPHER_LIST.data()) == 0) {
      std::println(stderr, "{}", ERR_error_string(ERR_get_error(), nullptr));
      return std::unexpected{Error::CRYPTO};
    }
#endif // defined(NGHTTP2_OPENSSL_IS_WOLFSSL)

    const unsigned char sid_ctx[] = "nghttpd";
    SSL_CTX_set_session_id_context(ssl_ctx, sid_ctx, sizeof(sid_ctx) - 1);
    SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER);

    if (SSL_CTX_set1_groups_list(ssl_ctx, config_->groups.data()) != 1) {
      std::println(stderr, "SSL_CTX_set1_groups_list failed: {}",
                   ERR_error_string(ERR_get_error(), nullptr));
      return std::unexpected{Error::CRYPTO};
    }

    if (!config_->dh_param_file.empty()) {
      // Read DH parameters from file
      auto bio = BIO_new_file(config_->dh_param_file.c_str(), "rb");
      if (bio == nullptr) {
        std::println(stderr, "BIO_new_file() failed: {}",
                     ERR_error_string(ERR_get_error(), nullptr));
        return std::unexpected{Error::IO};
      }

#if OPENSSL_3_0_0_API
      EVP_PKEY *dh = nullptr;
      auto dctx = OSSL_DECODER_CTX_new_for_pkey(
        &dh, "PEM", nullptr, "DH", OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
        nullptr, nullptr);

      if (!OSSL_DECODER_from_bio(dctx, bio)) {
        std::println(stderr, "OSSL_DECODER_from_bio() failed: {}",
                     ERR_error_string(ERR_get_error(), nullptr));
        return std::unexpected{Error::CRYPTO};
      }

      if (SSL_CTX_set0_tmp_dh_pkey(ssl_ctx, dh) != 1) {
        std::println(stderr, "SSL_CTX_set0_tmp_dh_pkey failed: {}",
                     ERR_error_string(ERR_get_error(), nullptr));
        return std::unexpected{Error::CRYPTO};
      }
#else  // !OPENSSL_3_0_0_API
      auto dh = PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr);

      if (dh == nullptr) {
        std::println(stderr, "PEM_read_bio_DHparams() failed: {}",
                     ERR_error_string(ERR_get_error(), nullptr));
        return std::unexpected{Error::CRYPTO};
      }

      SSL_CTX_set_tmp_dh(ssl_ctx, dh);
      DH_free(dh);
#endif // !OPENSSL_3_0_0_API
      BIO_free(bio);
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, config_->private_key_file.c_str(),
                                    SSL_FILETYPE_PEM) != 1) {
      std::println(stderr, "SSL_CTX_use_PrivateKey_file failed.");
      return std::unexpected{Error::CRYPTO};
    }
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx,
                                           config_->cert_file.c_str()) != 1) {
      std::println(stderr, "SSL_CTX_use_certificate_file failed.");
      return std::unexpected{Error::CRYPTO};
    }
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
      std::println(stderr, "SSL_CTX_check_private_key failed.");
      return std::unexpected{Error::CRYPTO};
    }
    if (config_->verify_client) {
      SSL_CTX_set_verify(ssl_ctx,
                         SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |
                           SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                         verify_callback);
    }

    // ALPN selection callback
    SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, this);

#if defined(NGHTTP2_OPENSSL_IS_BORINGSSL) && defined(HAVE_LIBBROTLI)
    if (!SSL_CTX_add_cert_compression_alg(
          ssl_ctx, nghttp2::tls::CERTIFICATE_COMPRESSION_ALGO_BROTLI,
          nghttp2::tls::cert_compress, nghttp2::tls::cert_decompress)) {
      std::println(stderr, "SSL_CTX_add_cert_compression_alg failed.");
      return std::unexpected{Error::CRYPTO};
    }
#endif // defined(NGHTTP2_OPENSSL_IS_BORINGSSL) &&
       // defined(HAVE_LIBBROTLI)

    if (auto rv = tls::setup_keylog_callback(ssl_ctx); !rv) {
      std::println(stderr, "Failed to setup keylog");
      return rv;
    }
  }

  auto loop = EV_DEFAULT;

  Sessions sessions(this, loop, config_, ssl_ctx);
  if (auto rv = start_listen(this, loop, &sessions, config_); !rv) {
    std::println(stderr, "Could not listen");
    if (ssl_ctx) {
      SSL_CTX_free(ssl_ctx);
    }
    return rv;
  }

  ev_run(loop, 0);

  SSL_CTX_free(ssl_ctx);

  return {};
}

const Config *HttpServer::get_config() const { return config_; }

const StatusPage *HttpServer::get_status_page(int status) const {
  switch (status) {
  case 200:
    return &status_pages_[IDX_200];
  case 301:
    return &status_pages_[IDX_301];
  case 400:
    return &status_pages_[IDX_400];
  case 404:
    return &status_pages_[IDX_404];
  case 405:
    return &status_pages_[IDX_405];
  default:
    assert(0);
  }
  return nullptr;
}

} // namespace nghttp2
