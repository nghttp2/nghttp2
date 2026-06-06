/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
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
#include "shrpx_log.h"

#ifdef HAVE_SYSLOG_H
#  include <syslog.h>
#endif // defined(HAVE_SYSLOG_H)
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif // defined(HAVE_UNISTD_H)
#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#endif // defined(HAVE_INTTYPES_H)
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif // defined(HAVE_FCNTL_H)
#include <sys/wait.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <print>

#include "shrpx_config.h"
#include "shrpx_downstream.h"
#include "shrpx_worker.h"
#include "util.h"
#include "template.h"

using namespace nghttp2;

namespace shrpx {

constexpr std::string_view SEVERITY_STR[] = {"INFO"sv, "NOTICE"sv, "WARN"sv,
                                             "ERROR"sv, "FATAL"sv};

constexpr std::string_view SEVERITY_COLOR[] = {
  "\033[1;32m"sv, // INFO
  "\033[1;36m"sv, // NOTICE
  "\033[1;33m"sv, // WARN
  "\033[1;31m"sv, // ERROR
  "\033[1;35m"sv, // FATAL
};

namespace {
LogBuffer *get_logbuf() {
  static thread_local LogBuffer logbuf;

  return &logbuf;
}
} // namespace

int Log::severity_thres_ = NOTICE;

void Log::set_severity_level(int severity) { severity_thres_ = severity; }

std::expected<int, Error>
Log::get_severity_level_by_name(std::string_view name) {
  for (size_t i = 0, max = array_size(SEVERITY_STR); i < max; ++i) {
    if (name == SEVERITY_STR[i]) {
      return static_cast<int>(i);
    }
  }
  return std::unexpected{Error::INVALID_ARGUMENT};
}

int severity_to_syslog_level(int severity) {
  switch (severity) {
  case (INFO):
    return LOG_INFO;
  case (NOTICE):
    return LOG_NOTICE;
  case (WARN):
    return LOG_WARNING;
  case (ERROR):
    return LOG_ERR;
  case (FATAL):
    return LOG_CRIT;
  default:
    return -1;
  }
}

Log::Log(int severity, const std::source_location loc)
  : buf_(*get_logbuf()),
    begin_(buf_.data()),
    end_(begin_ + buf_.size()),
    last_(begin_),
    filename_(loc.file_name()),
    severity_(severity),
    linenum_(loc.line()) {
  auto config = get_config();

  if (!config) {
    full_ = true;
    return;
  }

  auto lgconf = log_config();

  auto &errorconf = config->logging.error;

  if (!log_enabled(severity_) ||
      (lgconf->errorlog_fd == -1 && !errorconf.syslog)) {
    full_ = true;
    return;
  }

  if (errorconf.syslog) {
    *last_++ = '[';
    last_ = std::ranges::copy(SEVERITY_STR[severity_], last_).out;
    last_ = std::ranges::copy("] "sv, last_).out;

    return;
  }

  auto tty = lgconf->errorlog_tty;

  lgconf->update_tstamp_millis(std::chrono::system_clock::now());

  // Error log format: <datetime> <main-pid> <current-pid>
  // <thread-id> <level> (<filename>:<line>) <msg>
  last_ = std::ranges::copy(lgconf->tstamp->time_iso8601, last_).out;
  *last_++ = ' ';
  last_ = util::utos(as_unsigned(config->pid), last_);
  *last_++ = ' ';
  last_ = util::utos(as_unsigned(lgconf->pid), last_);
  *last_++ = ' ';
  last_ = std::ranges::copy(lgconf->thread_id, last_).out;
  *last_++ = ' ';

  if (tty) {
    last_ = std::ranges::copy(SEVERITY_COLOR[severity_], last_).out;
  }

  last_ = std::ranges::copy(SEVERITY_STR[severity_], last_).out;

  if (tty) {
    last_ = std::ranges::copy("\033[0m"sv, last_).out;
  }

  last_ = std::ranges::copy(" ("sv, last_).out;
  last_ = std::ranges::copy(filename_, last_).out;
  *last_++ = ':';
  last_ = util::utos(as_unsigned(linenum_), last_);
  last_ = std::ranges::copy(") "sv, last_).out;
}

Log::~Log() {
  if (last_ == begin_) {
    return;
  }

  auto config = get_config();
  auto &errorconf = config->logging.error;

  if (errorconf.syslog) {
    if (severity_ != NOTICE &&
        wleft() >= " ("sv.size() + filename_.size() + /* : */ 1 +
                     std::numeric_limits<decltype(linenum_)>::digits10 + 1 +
                     /* ) */ 1) {
      last_ = std::ranges::copy(" ("sv, last_).out;
      last_ = std::ranges::copy(filename_, last_).out;
      *last_++ = ':';
      last_ = util::utos(as_unsigned(linenum_), last_);
      *last_++ = ')';
    }

    *last_ = '\0';

    syslog(severity_to_syslog_level(severity_), "%s", begin_);

    return;
  }

  auto lgconf = log_config();

  *last_++ = '\n';

  while (write(lgconf->errorlog_fd, begin_, rleft()) == -1 && errno == EINTR)
    ;
}

Log &Log::operator<<(const std::string &s) {
  write_seq(s);
  return *this;
}

Log &Log::operator<<(std::string_view s) {
  write_seq(s);
  return *this;
}

Log &Log::operator<<(const char *s) {
  write_seq(std::string_view{s});
  return *this;
}

Log &Log::operator<<(const ImmutableString &s) {
  write_seq(s);
  return *this;
}

Log &Log::operator<<(bool n) {
  if (full_) {
    return *this;
  }

  *last_++ = n ? '1' : '0';
  update_full();

  return *this;
}

Log &Log::operator<<(const void *p) {
  if (full_) {
    return *this;
  }

  write_hex(reinterpret_cast<uintptr_t>(p));

  return *this;
}

namespace log {
void hex(Log &log) { log.set_flags(Log::fmt_hex); }

void dec(Log &log) { log.set_flags(Log::fmt_dec); }
} // namespace log

namespace {
template <std::ranges::sized_range R>
requires(!std::is_array_v<std::remove_cvref_t<R>>)
std::span<char> copy(R &&src, std::span<char> dest) {
  auto nwrite = std::min(std::ranges::size(src), std::ranges::size(dest));
  std::ranges::copy(std::views::take(src, as_signed(nwrite)),
                    std::ranges::begin(dest));
  return dest.subspan(nwrite);
}
} // namespace

namespace {
std::span<char> copy(const char *src, std::span<char> dest) {
  return copy(std::string_view{src}, dest);
}
} // namespace

namespace {
std::span<char> copy(char c, std::span<char> dest) {
  if (dest.empty()) {
    return dest;
  }

  dest[0] = c;

  return dest.subspan(1);
}
} // namespace

namespace {
std::span<char> copy_hex_low(std::span<const uint8_t> src,
                             std::span<char> dest) {
  auto n = std::min(dest.size(), src.size() * 2) / 2;
  auto d = util::format_hex(src.first(n), std::ranges::begin(dest));

  if (n < src.size()) {
    return {d, d};
  }

  return {d, std::ranges::end(dest)};
}
} // namespace

namespace {
template <std::unsigned_integral T>
std::span<char> copy(T n, std::span<char> dest) {
  if (dest.size() < std::numeric_limits<T>::digits10 + 1) {
    return dest.first(0);
  }

  return {util::utos(n, std::ranges::begin(dest)), std::ranges::end(dest)};
}
} // namespace

// true means that character must be escaped as "\xNN", where NN is
// ascii code of the character in hex notation.
constexpr auto ESCAPE_TBL = [] {
  std::array<bool, 256> tbl{};

  for (auto i = 0UZ; i < 256; ++i) {
    tbl[i] = i < 0x20 || i == '"' || i == '\\' || i >= 0x7F;
  }

  return tbl;
}();

namespace {
std::span<char> copy_escape(std::string_view src, std::span<char> dest) {
  auto safe_first = std::ranges::begin(src);
  for (auto p = safe_first; p != std::ranges::end(src) && !dest.empty(); ++p) {
    auto c = as_unsigned(*p);
    if (!ESCAPE_TBL[c]) {
      continue;
    }

    auto n = std::min(std::ranges::size(dest),
                      as_unsigned(std::ranges::distance(safe_first, p)));
    std::ranges::copy_n(safe_first, as_signed(n), std::ranges::begin(dest));
    dest = dest.subspan(n);

    if (dest.size() < 4) {
      return dest.first(0);
    }

    dest[0] = '\\';
    dest[1] = 'x';
    util::format_hex(c, std::ranges::begin(dest) + 2);
    dest = dest.subspan(4);

    safe_first = p + 1;
  }

  auto n = std::min(
    std::ranges::size(dest),
    as_unsigned(std::ranges::distance(safe_first, std::ranges::end(src))));
  std::ranges::copy_n(safe_first, as_signed(n), std::ranges::begin(dest));

  return dest.subspan(n);
}
} // namespace

namespace {
// Construct absolute request URI from |Request|, mainly to log
// request URI for proxy request (HTTP/2 proxy or client proxy).  This
// is mostly same routine found in
// HttpDownstreamConnection::push_request_headers(), but vastly
// simplified since we only care about absolute URI.
std::string_view construct_absolute_request_uri(BlockAllocator &balloc,
                                                const Request &req) {
  if (req.authority.empty()) {
    return req.path;
  }

  auto len = req.authority.size() + req.path.size();
  if (req.scheme.empty()) {
    len += str_size("http://");
  } else {
    len += req.scheme.size() + str_size("://");
  }

  auto iov = make_byte_ref(balloc, len + 1);
  auto p = std::ranges::begin(iov);

  if (req.scheme.empty()) {
    // We may have to log the request which lacks scheme (e.g.,
    // http/1.1 with origin form).
    p = std::ranges::copy("http://"sv, p).out;
  } else {
    p = std::ranges::copy(req.scheme, p).out;
    p = std::ranges::copy("://"sv, p).out;
  }
  p = std::ranges::copy(req.authority, p).out;
  p = std::ranges::copy(req.path, p).out;
  *p = '\0';

  return as_string_view(std::ranges::begin(iov), p);
}
} // namespace

void upstream_accesslog(const std::vector<LogFragment> &lfv,
                        const LogSpec &lgsp) {
  auto config = get_config();
  auto lgconf = log_config();
  auto &accessconf = get_config()->logging.access;

  if (lgconf->accesslog_fd == -1 && !accessconf.syslog) {
    return;
  }

  std::array<char, 4_k> buf;

  auto downstream = lgsp.downstream;

  const auto &req = downstream->request();
  const auto &resp = downstream->response();
  const auto &tstamp = req.tstamp;
  auto &balloc = downstream->get_block_allocator();

  auto downstream_addr = downstream->get_addr();
  auto method =
    req.method == -1 ? "<unknown>"sv : http2::to_method_string(req.method);
  auto path = req.method == HTTP_CONNECT ? req.authority
              : config->http2_proxy
                ? construct_absolute_request_uri(balloc, req)
              : req.path.empty() ? req.method == HTTP_OPTIONS ? "*"sv : "-"sv
                                 : req.path;
  auto path_without_query = req.method == HTTP_CONNECT
                              ? path
                              : std::string_view{std::ranges::begin(path),
                                                 std::ranges::find(path, '?')};

  auto p = std::span{buf}.first(buf.size() - 2);

  for (auto &lf : lfv) {
    switch (lf.type) {
    case LogFragmentType::LITERAL:
      p = copy(lf.value, p);
      break;
    case LogFragmentType::REMOTE_ADDR:
      p = copy(lgsp.remote_addr, p);
      break;
    case LogFragmentType::TIME_LOCAL:
      p = copy(tstamp->time_local, p);
      break;
    case LogFragmentType::TIME_ISO8601:
      p = copy(tstamp->time_iso8601, p);
      break;
    case LogFragmentType::REQUEST:
      p = copy(method, p);
      p = copy(' ', p);
      p = copy_escape(path, p);
      p = copy(" HTTP/"sv, p);
      p = copy(as_unsigned(req.http_major), p);
      if (req.http_major < 2) {
        p = copy('.', p);
        p = copy(as_unsigned(req.http_minor), p);
      }
      break;
    case LogFragmentType::METHOD:
      p = copy(method, p);
      break;
    case LogFragmentType::PATH:
      p = copy_escape(path, p);
      break;
    case LogFragmentType::PATH_WITHOUT_QUERY:
      p = copy_escape(path_without_query, p);
      break;
    case LogFragmentType::PROTOCOL_VERSION:
      p = copy("HTTP/"sv, p);
      p = copy(as_unsigned(req.http_major), p);
      if (req.http_major < 2) {
        p = copy('.', p);
        p = copy(as_unsigned(req.http_minor), p);
      }
      break;
    case LogFragmentType::STATUS:
      p = copy(resp.http_status, p);
      break;
    case LogFragmentType::BODY_BYTES_SENT:
      p = copy(as_unsigned(downstream->response_sent_body_length), p);
      break;
    case LogFragmentType::HTTP: {
      auto hd = req.fs.header(lf.value);
      if (hd) {
        p = copy_escape((*hd).value, p);
        break;
      }

      p = copy('-', p);

      break;
    }
    case LogFragmentType::AUTHORITY:
      if (!req.authority.empty()) {
        p = copy(req.authority, p);
        break;
      }

      p = copy('-', p);

      break;
    case LogFragmentType::REMOTE_PORT:
      p = copy(lgsp.remote_port, p);
      break;
    case LogFragmentType::SERVER_PORT:
      p = copy(lgsp.server_port, p);
      break;
    case LogFragmentType::REQUEST_TIME: {
      auto t = std::chrono::duration_cast<std::chrono::milliseconds>(
                 lgsp.request_end_time - downstream->get_request_start_time())
                 .count();
      p = copy(as_unsigned(t / 1000), p);
      p = copy('.', p);
      auto frac = t % 1000;
      if (frac < 100) {
        auto n = static_cast<size_t>(frac < 10 ? 2 : 1);
        p = copy(std::string_view{"000", n}, p);
      }
      p = copy(as_unsigned(frac), p);
      break;
    }
    case LogFragmentType::PID:
      p = copy(as_unsigned(lgsp.pid), p);
      break;
    case LogFragmentType::ALPN:
      p = copy_escape(lgsp.alpn, p);
      break;
    case LogFragmentType::TLS_CIPHER:
      if (!lgsp.ssl) {
        p = copy('-', p);
        break;
      }
      p = copy(SSL_get_cipher_name(lgsp.ssl), p);
      break;
    case LogFragmentType::TLS_PROTOCOL:
      if (!lgsp.ssl) {
        p = copy('-', p);
        break;
      }
      p = copy(nghttp2::tls::get_tls_protocol(lgsp.ssl), p);
      break;
    case LogFragmentType::TLS_SESSION_ID: {
      auto session = SSL_get_session(lgsp.ssl);
      if (!session) {
        p = copy('-', p);
        break;
      }
      unsigned int session_id_length = 0;
      auto session_id = SSL_SESSION_get_id(session, &session_id_length);
      if (session_id_length == 0) {
        p = copy('-', p);
        break;
      }
      p = copy_hex_low({session_id, session_id_length}, p);
      break;
    }
    case LogFragmentType::TLS_SESSION_REUSED:
      if (!lgsp.ssl) {
        p = copy('-', p);
        break;
      }
      p = copy(SSL_session_reused(lgsp.ssl) ? 'r' : '.', p);
      break;
    case LogFragmentType::TLS_SNI:
      if (lgsp.sni.empty()) {
        p = copy('-', p);
        break;
      }
      p = copy_escape(lgsp.sni, p);
      break;
    case LogFragmentType::TLS_CLIENT_FINGERPRINT_SHA1:
    case LogFragmentType::TLS_CLIENT_FINGERPRINT_SHA256: {
      if (!lgsp.ssl) {
        p = copy('-', p);
        break;
      }
#if OPENSSL_3_0_0_API
      auto x = SSL_get0_peer_certificate(lgsp.ssl);
#else  // !OPENSSL_3_0_0_API
      auto x = SSL_get_peer_certificate(lgsp.ssl);
#endif // !OPENSSL_3_0_0_API
      if (!x) {
        p = copy('-', p);
        break;
      }
      std::array<uint8_t, 32> buf;
      auto maybe_fp = tls::get_x509_fingerprint(
        buf, x,
        lf.type == LogFragmentType::TLS_CLIENT_FINGERPRINT_SHA256
          ? nghttp2::tls::sha256()
          : nghttp2::tls::sha1());
#if !OPENSSL_3_0_0_API
      X509_free(x);
#endif // !OPENSSL_3_0_0_API
      if (!maybe_fp) {
        p = copy('-', p);
        break;
      }
      p = copy_hex_low(*maybe_fp, p);
      break;
    }
    case LogFragmentType::TLS_CLIENT_ISSUER_NAME:
    case LogFragmentType::TLS_CLIENT_SUBJECT_NAME: {
      if (!lgsp.ssl) {
        p = copy('-', p);
        break;
      }
#if OPENSSL_3_0_0_API
      auto x = SSL_get0_peer_certificate(lgsp.ssl);
#else  // !OPENSSL_3_0_0_API
      auto x = SSL_get_peer_certificate(lgsp.ssl);
#endif // !OPENSSL_3_0_0_API
      if (!x) {
        p = copy('-', p);
        break;
      }
      auto name = lf.type == LogFragmentType::TLS_CLIENT_ISSUER_NAME
                    ? tls::get_x509_issuer_name(balloc, x)
                    : tls::get_x509_subject_name(balloc, x);
#if !OPENSSL_3_0_0_API
      X509_free(x);
#endif // !OPENSSL_3_0_0_API
      if (name.empty()) {
        p = copy('-', p);
        break;
      }
      p = copy(name, p);
      break;
    }
    case LogFragmentType::TLS_CLIENT_SERIAL: {
      if (!lgsp.ssl) {
        p = copy('-', p);
        break;
      }
#if OPENSSL_3_0_0_API
      auto x = SSL_get0_peer_certificate(lgsp.ssl);
#else  // !OPENSSL_3_0_0_API
      auto x = SSL_get_peer_certificate(lgsp.ssl);
#endif // !OPENSSL_3_0_0_API
      if (!x) {
        p = copy('-', p);
        break;
      }
      auto sn = tls::get_x509_serial(balloc, x);
#if !OPENSSL_3_0_0_API
      X509_free(x);
#endif // !OPENSSL_3_0_0_API
      if (sn.empty()) {
        p = copy('-', p);
        break;
      }
      p = copy(sn, p);
      break;
    }
    case LogFragmentType::BACKEND_HOST:
      if (!downstream_addr) {
        p = copy('-', p);
        break;
      }
      p = copy(downstream_addr->host, p);
      break;
    case LogFragmentType::BACKEND_PORT:
      if (!downstream_addr) {
        p = copy('-', p);
        break;
      }
      p = copy(downstream_addr->port, p);
      break;
    case LogFragmentType::TLS_ECH_ACCEPTED:
      if (!lgsp.ssl) {
        p = copy('-', p);
        break;
      }
      p = copy(tls::is_ech_accepted(lgsp.ssl) ? 'e' : '.', p);
      break;
    case LogFragmentType::NONE:
      break;
    default:
      break;
    }
  }

  if (accessconf.syslog) {
    p[0] = '\0';

    syslog(LOG_INFO, "%s", buf.data());

    return;
  }

  p[0] = '\n';
  p = p.subspan(1);

  auto nwrite = as_unsigned(std::ranges::distance(
    std::ranges::begin(std::span<char>{buf}), std::ranges::begin(p)));
  while (write(lgconf->accesslog_fd, buf.data(), nwrite) == -1 &&
         errno == EINTR)
    ;
}

std::expected<void, Error> reopen_log_files(const LoggingConfig &loggingconf) {
  std::expected<void, Error> res;
  int new_accesslog_fd = -1;
  int new_errorlog_fd = -1;

  auto lgconf = log_config();
  auto &accessconf = loggingconf.access;
  auto &errorconf = loggingconf.error;

  if (!accessconf.syslog && !accessconf.file.empty()) {
    auto maybe_new_accesslog_fd = open_log_file(accessconf.file.data());
    if (!maybe_new_accesslog_fd) {
      Log{ERROR} << "Failed to open accesslog file " << accessconf.file;
      res = std::unexpected{maybe_new_accesslog_fd.error()};
    } else {
      new_accesslog_fd = *maybe_new_accesslog_fd;
    }
  }

  if (!errorconf.syslog && !errorconf.file.empty()) {
    auto maybe_new_errorlog_fd = open_log_file(errorconf.file.data());
    if (!maybe_new_errorlog_fd) {
      if (lgconf->errorlog_fd != -1) {
        Log{ERROR} << "Failed to open errorlog file " << errorconf.file;
      } else {
        std::println(stderr, "Failed to open errorlog file {}", errorconf.file);
      }

      res = std::unexpected{maybe_new_errorlog_fd.error()};
    } else {
      new_errorlog_fd = *maybe_new_errorlog_fd;
    }
  }

  close_log_file(lgconf->accesslog_fd);
  close_log_file(lgconf->errorlog_fd);

  lgconf->accesslog_fd = new_accesslog_fd;
  lgconf->errorlog_fd = new_errorlog_fd;
  lgconf->errorlog_tty =
    (new_errorlog_fd == -1) ? false : isatty(new_errorlog_fd);

  return res;
}

void log_chld(pid_t pid, int rstatus, const char *msg) {
  std::string signalstr;
  if (WIFSIGNALED(rstatus)) {
    signalstr += "; signal ";
    auto sig = WTERMSIG(rstatus);
    auto s = strsignal(sig);
    if (s) {
      signalstr += s;
      signalstr += '(';
    } else {
      signalstr += "UNKNOWN(";
    }
    signalstr += util::utos(as_unsigned(sig));
    signalstr += ')';
  }

  Log{NOTICE} << msg << ": [" << pid << "] exited "
              << (WIFEXITED(rstatus) ? "normally" : "abnormally")
              << " with status " << log::hex << rstatus << log::dec
              << "; exit status "
              << (WIFEXITED(rstatus) ? WEXITSTATUS(rstatus) : 0)
              << (signalstr.empty() ? "" : signalstr.c_str());
}

void redirect_stderr_to_errorlog(const LoggingConfig &loggingconf) {
  auto lgconf = log_config();
  auto &errorconf = loggingconf.error;

  if (errorconf.syslog || lgconf->errorlog_fd == -1) {
    return;
  }

  dup2(lgconf->errorlog_fd, STDERR_FILENO);
}

namespace {
int STDERR_COPY = -1;
int STDOUT_COPY = -1;
} // namespace

void store_original_fds() {
  // consider dup'ing stdout too
  STDERR_COPY = dup(STDERR_FILENO);
  STDOUT_COPY = STDOUT_FILENO;
  // no race here, since it is called early
  util::make_socket_closeonexec(STDERR_COPY);
}

void restore_original_fds() { dup2(STDERR_COPY, STDERR_FILENO); }

void close_log_file(int &fd) {
  if (fd != STDERR_COPY && fd != STDOUT_COPY && fd != -1) {
    close(fd);
  }
  fd = -1;
}

std::expected<int, Error> open_log_file(const char *path) {
  if (strcmp(path, "/dev/stdout") == 0 ||
      strcmp(path, "/proc/self/fd/1") == 0) {
    return STDOUT_COPY;
  }

  if (strcmp(path, "/dev/stderr") == 0 ||
      strcmp(path, "/proc/self/fd/2") == 0) {
    return STDERR_COPY;
  }
#ifdef O_CLOEXEC

  auto fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC,
                 S_IRUSR | S_IWUSR | S_IRGRP);
#else // !defined(O_CLOEXEC)

  auto fd =
    open(path, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);

  // We get race condition if execve is called at the same time.
  if (fd != -1) {
    util::make_socket_closeonexec(fd);
  }

#endif // !defined(O_CLOEXEC)

  if (fd == -1) {
    return std::unexpected{Error::SYSCALL};
  }

  return fd;
}

} // namespace shrpx
