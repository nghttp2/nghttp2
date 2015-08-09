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

#include <sstream>
#include <memory>
#include <vector>
#include <chrono>

#include "shrpx_log_config.h"
#include "ssl.h"

namespace shrpx {

class Downstream;

#define ENABLE_LOG 1

#define LOG_ENABLED(SEVERITY) (ENABLE_LOG && Log::log_enabled(SEVERITY))

#define LOG(SEVERITY) Log(SEVERITY, __FILE__, __LINE__)

// Listener log
#define LLOG(SEVERITY, LISTEN)                                                 \
  (Log(SEVERITY, __FILE__, __LINE__) << "[LISTEN:" << LISTEN << "] ")

// Worker log
#define WLOG(SEVERITY, WORKER)                                                 \
  (Log(SEVERITY, __FILE__, __LINE__) << "[WORKER:" << WORKER << "] ")

// ClientHandler log
#define CLOG(SEVERITY, CLIENT_HANDLER)                                         \
  (Log(SEVERITY, __FILE__, __LINE__) << "[CLIENT_HANDLER:" << CLIENT_HANDLER   \
                                     << "] ")

// Upstream log
#define ULOG(SEVERITY, UPSTREAM)                                               \
  (Log(SEVERITY, __FILE__, __LINE__) << "[UPSTREAM:" << UPSTREAM << "] ")

// Downstream log
#define DLOG(SEVERITY, DOWNSTREAM)                                             \
  (Log(SEVERITY, __FILE__, __LINE__) << "[DOWNSTREAM:" << DOWNSTREAM << "] ")

// Downstream connection log
#define DCLOG(SEVERITY, DCONN)                                                 \
  (Log(SEVERITY, __FILE__, __LINE__) << "[DCONN:" << DCONN << "] ")

// Downstream HTTP2 session log
#define SSLOG(SEVERITY, HTTP2)                                                 \
  (Log(SEVERITY, __FILE__, __LINE__) << "[DHTTP2:" << HTTP2 << "] ")

// Memcached connection log
#define MCLOG(SEVERITY, MCONN)                                                 \
  (Log(SEVERITY, __FILE__, __LINE__) << "[MCONN:" << MCONN << "] ")

enum SeverityLevel { INFO, NOTICE, WARN, ERROR, FATAL };

class Log {
public:
  Log(int severity, const char *filename, int linenum);
  ~Log();
  template <typename Type> Log &operator<<(Type s) {
    stream_ << s;
    return *this;
  }
  static void set_severity_level(int severity);
  static int set_severity_level_by_name(const char *name);
  static bool log_enabled(int severity) { return severity >= severity_thres_; }

private:
  std::stringstream stream_;
  const char *filename_;
  int severity_;
  int linenum_;
  static int severity_thres_;
};

#define TTY_HTTP_HD (log_config()->errorlog_tty ? "\033[1;34m" : "")
#define TTY_RST (log_config()->errorlog_tty ? "\033[0m" : "")

enum LogFragmentType {
  SHRPX_LOGF_NONE,
  SHRPX_LOGF_LITERAL,
  SHRPX_LOGF_REMOTE_ADDR,
  SHRPX_LOGF_TIME_LOCAL,
  SHRPX_LOGF_TIME_ISO8601,
  SHRPX_LOGF_REQUEST,
  SHRPX_LOGF_STATUS,
  SHRPX_LOGF_BODY_BYTES_SENT,
  SHRPX_LOGF_HTTP,
  SHRPX_LOGF_REMOTE_PORT,
  SHRPX_LOGF_SERVER_PORT,
  SHRPX_LOGF_REQUEST_TIME,
  SHRPX_LOGF_PID,
  SHRPX_LOGF_ALPN,
  SHRPX_LOGF_SSL_CIPHER,
  SHRPX_LOGF_SSL_PROTOCOL,
  SHRPX_LOGF_SSL_SESSION_ID,
  SHRPX_LOGF_SSL_SESSION_REUSED,
};

struct LogFragment {
  LogFragment(LogFragmentType type, std::unique_ptr<char[]> value = nullptr)
      : type(type), value(std::move(value)) {}
  LogFragmentType type;
  std::unique_ptr<char[]> value;
};

struct LogSpec {
  Downstream *downstream;
  const char *remote_addr;
  const char *method;
  const char *path;
  const char *alpn;
  const nghttp2::ssl::TLSSessionInfo *tls_info;
  std::chrono::system_clock::time_point time_now;
  std::chrono::high_resolution_clock::time_point request_start_time;
  std::chrono::high_resolution_clock::time_point request_end_time;
  int major, minor;
  unsigned int status;
  int64_t body_bytes_sent;
  const char *remote_port;
  uint16_t server_port;
  pid_t pid;
};

void upstream_accesslog(const std::vector<LogFragment> &lf,
                        const LogSpec &lgsp);

int reopen_log_files();

void redirect_stderr_to_errorlog();

} // namespace shrpx

#endif // SHRPX_LOG_H
