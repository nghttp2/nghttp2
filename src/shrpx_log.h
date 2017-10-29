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

#include "shrpx_config.h"
#include "shrpx_log_config.h"
#include "tls.h"
#include "template.h"

using namespace nghttp2;

#define ENABLE_LOG 1

#define LOG_ENABLED(SEVERITY) (ENABLE_LOG && shrpx::Log::log_enabled(SEVERITY))

#define LOG(SEVERITY) shrpx::Log(SEVERITY, __FILE__, __LINE__)

// Listener log
#define LLOG(SEVERITY, LISTEN)                                                 \
  (shrpx::Log(SEVERITY, __FILE__, __LINE__) << "[LISTEN:" << LISTEN << "] ")

// Worker log
#define WLOG(SEVERITY, WORKER)                                                 \
  (shrpx::Log(SEVERITY, __FILE__, __LINE__) << "[WORKER:" << WORKER << "] ")

// ClientHandler log
#define CLOG(SEVERITY, CLIENT_HANDLER)                                         \
  (shrpx::Log(SEVERITY, __FILE__, __LINE__)                                    \
   << "[CLIENT_HANDLER:" << CLIENT_HANDLER << "] ")

// Upstream log
#define ULOG(SEVERITY, UPSTREAM)                                               \
  (shrpx::Log(SEVERITY, __FILE__, __LINE__)                                    \
   << "[UPSTREAM:" << UPSTREAM << "]"                                          \
                                  " ")

// Downstream log
#define DLOG(SEVERITY, DOWNSTREAM)                                             \
  (shrpx::Log(SEVERITY, __FILE__, __LINE__)                                    \
   << "[DOWNSTREAM:" << DOWNSTREAM << "] ")

// Downstream connection log
#define DCLOG(SEVERITY, DCONN)                                                 \
  (shrpx::Log(SEVERITY, __FILE__, __LINE__) << "[DCONN:" << DCONN << "] ")

// Downstream HTTP2 session log
#define SSLOG(SEVERITY, HTTP2)                                                 \
  (shrpx::Log(SEVERITY, __FILE__, __LINE__) << "[DHTTP2:" << HTTP2 << "] ")

// Memcached connection log
#define MCLOG(SEVERITY, MCONN)                                                 \
  (shrpx::Log(SEVERITY, __FILE__, __LINE__) << "[MCONN:" << MCONN << "] ")

namespace shrpx {

class Downstream;
struct DownstreamAddr;

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
  static int set_severity_level_by_name(const StringRef &name);
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
  SHRPX_LOGF_AUTHORITY,
  SHRPX_LOGF_REMOTE_PORT,
  SHRPX_LOGF_SERVER_PORT,
  SHRPX_LOGF_REQUEST_TIME,
  SHRPX_LOGF_PID,
  SHRPX_LOGF_ALPN,
  SHRPX_LOGF_TLS_CIPHER,
  SHRPX_LOGF_SSL_CIPHER = SHRPX_LOGF_TLS_CIPHER,
  SHRPX_LOGF_TLS_PROTOCOL,
  SHRPX_LOGF_SSL_PROTOCOL = SHRPX_LOGF_TLS_PROTOCOL,
  SHRPX_LOGF_TLS_SESSION_ID,
  SHRPX_LOGF_SSL_SESSION_ID = SHRPX_LOGF_TLS_SESSION_ID,
  SHRPX_LOGF_TLS_SESSION_REUSED,
  SHRPX_LOGF_SSL_SESSION_REUSED = SHRPX_LOGF_TLS_SESSION_REUSED,
  SHRPX_LOGF_TLS_SNI,
  SHRPX_LOGF_TLS_CLIENT_FINGERPRINT,
  SHRPX_LOGF_TLS_CLIENT_SUBJECT_NAME,
  SHRPX_LOGF_BACKEND_HOST,
  SHRPX_LOGF_BACKEND_PORT,
};

struct LogFragment {
  LogFragment(LogFragmentType type, StringRef value = StringRef::from_lit(""))
      : type(type), value(std::move(value)) {}
  LogFragmentType type;
  StringRef value;
};

struct LogSpec {
  Downstream *downstream;
  StringRef remote_addr;
  StringRef alpn;
  StringRef sni;
  SSL *ssl;
  std::chrono::high_resolution_clock::time_point request_end_time;
  StringRef remote_port;
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
