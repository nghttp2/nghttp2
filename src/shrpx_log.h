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
#ifndef SHRPX_LOG_H
#define SHRPX_LOG_H

#include "shrpx.h"

#include <sys/types.h>

#include <memory>
#include <vector>
#include <chrono>
#include <algorithm>
#include <ranges>

#include "shrpx_log_config.h"
#include "tls.h"
#include "template.h"
#include "util.h"

using namespace nghttp2;

#define ENABLE_LOG 1

#define LOG_ENABLED(SEVERITY) (ENABLE_LOG && shrpx::Log::log_enabled(SEVERITY))

#ifdef __FILE_NAME__
#  define NGHTTP2_FILE_NAME __FILE_NAME__
#else // !__FILE_NAME__
#  define NGHTTP2_FILE_NAME __FILE__
#endif // !__FILE_NAME__

#define LOG(SEVERITY) shrpx::Log(SEVERITY, NGHTTP2_FILE_NAME, __LINE__)

// Listener log
#define LLOG(SEVERITY, LISTEN)                                                 \
  (shrpx::Log(SEVERITY, NGHTTP2_FILE_NAME, __LINE__)                           \
   << "[LISTEN:" << LISTEN << "] ")

// Worker log
#define WLOG(SEVERITY, WORKER)                                                 \
  (shrpx::Log(SEVERITY, NGHTTP2_FILE_NAME, __LINE__)                           \
   << "[WORKER:" << WORKER << "] ")

// ClientHandler log
#define CLOG(SEVERITY, CLIENT_HANDLER)                                         \
  (shrpx::Log(SEVERITY, NGHTTP2_FILE_NAME, __LINE__)                           \
   << "[CLIENT_HANDLER:" << CLIENT_HANDLER << "] ")

// Upstream log
#define ULOG(SEVERITY, UPSTREAM)                                               \
  (shrpx::Log(SEVERITY, NGHTTP2_FILE_NAME, __LINE__)                           \
   << "[UPSTREAM:" << UPSTREAM << "] ")

// Downstream log
#define DLOG(SEVERITY, DOWNSTREAM)                                             \
  (shrpx::Log(SEVERITY, NGHTTP2_FILE_NAME, __LINE__)                           \
   << "[DOWNSTREAM:" << DOWNSTREAM << "] ")

// Downstream connection log
#define DCLOG(SEVERITY, DCONN)                                                 \
  (shrpx::Log(SEVERITY, NGHTTP2_FILE_NAME, __LINE__)                           \
   << "[DCONN:" << DCONN << "] ")

// Downstream HTTP2 session log
#define SSLOG(SEVERITY, HTTP2)                                                 \
  (shrpx::Log(SEVERITY, NGHTTP2_FILE_NAME, __LINE__)                           \
   << "[DHTTP2:" << HTTP2 << "] ")

// Memcached connection log
#define MCLOG(SEVERITY, MCONN)                                                 \
  (shrpx::Log(SEVERITY, NGHTTP2_FILE_NAME, __LINE__)                           \
   << "[MCONN:" << MCONN << "] ")

namespace shrpx {

class Downstream;
struct DownstreamAddr;
struct LoggingConfig;

enum SeverityLevel { INFO, NOTICE, WARN, ERROR, FATAL };

using LogBuffer = std::array<uint8_t, 4_k>;

class Log {
public:
  Log(int severity, const char *filename, int linenum);
  ~Log();
  Log &operator<<(const std::string &s);
  Log &operator<<(const std::string_view &s);
  Log &operator<<(const char *s);
  Log &operator<<(const ImmutableString &s);
  template <std::signed_integral T> Log &operator<<(T n) {
    if (full_) {
      return *this;
    }

    if (n >= 0) {
      return *this << as_unsigned(n);
    }

    if (flags_ & fmt_hex) {
      write_hex(as_unsigned(n));
      return *this;
    }

    if (wleft() < std::numeric_limits<T>::digits10 + 1 + /* sign */ 1) {
      full_ = true;
      return *this;
    }

    *last_++ = '-';

    last_ = util::utos(
      static_cast<std::make_unsigned_t<T>>(0u - as_unsigned(n)), last_);
    update_full();

    return *this;
  }
  template <std::unsigned_integral T> Log &operator<<(T n) {
    if (full_) {
      return *this;
    }

    if (flags_ & fmt_hex) {
      write_hex(n);
      return *this;
    }

    if (wleft() < std::numeric_limits<T>::digits10 + 1) {
      full_ = true;
      return *this;
    }

    last_ = util::utos(n, last_);
    update_full();

    return *this;
  }
  Log &operator<<(float n) { return *this << static_cast<double>(n); }
  Log &operator<<(double n);
  Log &operator<<(long double n);
  Log &operator<<(bool n);
  Log &operator<<(const void *p);
  template <typename T> Log &operator<<(const std::shared_ptr<T> &ptr) {
    return *this << ptr.get();
  }
  Log &operator<<(void (*func)(Log &log)) {
    func(*this);
    return *this;
  }
  template <std::ranges::input_range R>
  requires(!std::is_array_v<std::remove_cvref_t<R>>)
  void write_seq(R &&r) {
    if (full_) {
      return;
    }

    auto n = std::min(wleft(), static_cast<size_t>(std::ranges::distance(r)));
    last_ = std::ranges::copy(std::views::take(r, as_signed(n)), last_).out;
    update_full();
  }

  template <std::unsigned_integral T> void write_hex(T n) {
    if (full_) {
      return;
    }

    if (wleft() < "0x"sv.size() + sizeof(T) * 2) {
      full_ = true;
      return;
    }

    *last_++ = '0';
    *last_++ = 'x';

    last_ = util::format_hex(n, last_);
    update_full();
  }
  static void set_severity_level(int severity);
  // Returns the severity level by |name|.  Returns -1 if |name| is
  // unknown.
  static int get_severity_level_by_name(const std::string_view &name);
  static bool log_enabled(int severity) { return severity >= severity_thres_; }

  enum {
    fmt_dec = 0x00,
    fmt_hex = 0x01,
  };

  void set_flags(uint32_t flags) { flags_ = flags; }

private:
  size_t rleft() { return as_unsigned(last_ - begin_); }
  size_t wleft() {
    return as_unsigned(end_ - last_ - /* terminal NUL or LF */ 1);
  }
  void update_full() { full_ = wleft() == 0; }

  LogBuffer &buf_;
  uint8_t *begin_;
  uint8_t *end_;
  uint8_t *last_;
  std::string_view filename_;
  uint32_t flags_;
  int severity_;
  int linenum_;
  bool full_;
  static int severity_thres_;
};

namespace log {
void hex(Log &log);
void dec(Log &log);
} // namespace log

#define TTY_HTTP_HD (log_config()->errorlog_tty ? "\033[1;34m" : "")
#define TTY_RST (log_config()->errorlog_tty ? "\033[0m" : "")

enum class LogFragmentType {
  NONE,
  LITERAL,
  REMOTE_ADDR,
  TIME_LOCAL,
  TIME_ISO8601,
  REQUEST,
  STATUS,
  BODY_BYTES_SENT,
  HTTP,
  AUTHORITY,
  REMOTE_PORT,
  SERVER_PORT,
  REQUEST_TIME,
  PID,
  ALPN,
  TLS_CIPHER,
  SSL_CIPHER = TLS_CIPHER,
  TLS_PROTOCOL,
  SSL_PROTOCOL = TLS_PROTOCOL,
  TLS_SESSION_ID,
  SSL_SESSION_ID = TLS_SESSION_ID,
  TLS_SESSION_REUSED,
  SSL_SESSION_REUSED = TLS_SESSION_REUSED,
  TLS_SNI,
  TLS_CLIENT_FINGERPRINT_SHA1,
  TLS_CLIENT_FINGERPRINT_SHA256,
  TLS_CLIENT_ISSUER_NAME,
  TLS_CLIENT_SERIAL,
  TLS_CLIENT_SUBJECT_NAME,
  BACKEND_HOST,
  BACKEND_PORT,
  METHOD,
  PATH,
  PATH_WITHOUT_QUERY,
  PROTOCOL_VERSION,
};

struct LogFragment {
  LogFragment(LogFragmentType type, std::string_view value = ""sv)
    : type(type), value(std::move(value)) {}
  LogFragmentType type;
  std::string_view value;
};

struct LogSpec {
  Downstream *downstream;
  std::string_view remote_addr;
  std::string_view alpn;
  std::string_view sni;
  SSL *ssl;
  std::chrono::high_resolution_clock::time_point request_end_time;
  std::string_view remote_port;
  uint16_t server_port;
  pid_t pid;
};

void upstream_accesslog(const std::vector<LogFragment> &lf,
                        const LogSpec &lgsp);

int reopen_log_files(const LoggingConfig &loggingconf);

// Logs message when process whose pid is |pid| and exist status is
// |rstatus| exited.  The |msg| is prepended to the log message.
void log_chld(pid_t pid, int rstatus, const char *msg);

void redirect_stderr_to_errorlog(const LoggingConfig &loggingconf);

// Makes internal copy of stderr (and possibly stdout in the future),
// which is then used as pointer to /dev/stderr or /proc/self/fd/2
void store_original_fds();

// Restores the original stderr that was stored with copy_original_fds
// Used just before execv
void restore_original_fds();

// Closes |fd| which was returned by open_log_file (see below)
// and sets it to -1. In the case that |fd| points to stdout or
// stderr, or is -1, the descriptor is not closed (but still set to -1).
void close_log_file(int &fd);

// Opens |path| with O_APPEND enabled.  If file does not exist, it is
// created first.  This function returns file descriptor referring the
// opened file if it succeeds, or -1.
int open_log_file(const char *path);

} // namespace shrpx

#endif // SHRPX_LOG_H
