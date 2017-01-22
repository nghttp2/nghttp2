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
#include <syslog.h>
#endif // HAVE_SYSLOG_H
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif // HAVE_UNISTD_H
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif // HAVE_INTTYPES_H
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif // HAVE_FCNTL_H
#include <sys/wait.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <iomanip>

#include "shrpx_config.h"
#include "shrpx_downstream.h"
#include "shrpx_worker.h"
#include "util.h"
#include "template.h"

using namespace nghttp2;

namespace shrpx {

namespace {
constexpr StringRef SEVERITY_STR[] = {
    StringRef::from_lit("INFO"), StringRef::from_lit("NOTICE"),
    StringRef::from_lit("WARN"), StringRef::from_lit("ERROR"),
    StringRef::from_lit("FATAL")};
} // namespace

namespace {
constexpr const char *SEVERITY_COLOR[] = {
    "\033[1;32m", // INFO
    "\033[1;36m", // NOTICE
    "\033[1;33m", // WARN
    "\033[1;31m", // ERROR
    "\033[1;35m", // FATAL
};
} // namespace

int Log::severity_thres_ = NOTICE;

void Log::set_severity_level(int severity) { severity_thres_ = severity; }

int Log::set_severity_level_by_name(const StringRef &name) {
  for (size_t i = 0, max = array_size(SEVERITY_STR); i < max; ++i) {
    if (name == SEVERITY_STR[i]) {
      severity_thres_ = i;
      return 0;
    }
  }
  return -1;
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

Log::Log(int severity, const char *filename, int linenum)
    : filename_(filename), severity_(severity), linenum_(linenum) {}

Log::~Log() {
  int rv;
  auto config = get_config();

  if (!config) {
    return;
  }

  auto lgconf = log_config();

  auto &errorconf = config->logging.error;

  if (!log_enabled(severity_) ||
      (lgconf->errorlog_fd == -1 && !errorconf.syslog)) {
    return;
  }

  if (errorconf.syslog) {
    if (severity_ == NOTICE) {
      syslog(severity_to_syslog_level(severity_), "[%s] %s",
             SEVERITY_STR[severity_].c_str(), stream_.str().c_str());
    } else {
      syslog(severity_to_syslog_level(severity_), "[%s] %s (%s:%d)",
             SEVERITY_STR[severity_].c_str(), stream_.str().c_str(), filename_,
             linenum_);
    }

    return;
  }

  char buf[4_k];
  auto tty = lgconf->errorlog_tty;

  lgconf->update_tstamp(std::chrono::system_clock::now());

  // Error log format: <datetime> <master-pid> <current-pid>
  // <thread-id> <level> (<filename>:<line>) <msg>
  rv = snprintf(buf, sizeof(buf), "%s %d %d %s %s%s%s (%s:%d) %s\n",
                lgconf->tstamp->time_iso8601.c_str(), config->pid, lgconf->pid,
                lgconf->thread_id.c_str(), tty ? SEVERITY_COLOR[severity_] : "",
                SEVERITY_STR[severity_].c_str(), tty ? "\033[0m" : "",
                filename_, linenum_, stream_.str().c_str());

  if (rv < 0) {
    return;
  }

  auto nwrite = std::min(static_cast<size_t>(rv), sizeof(buf) - 1);

  while (write(lgconf->errorlog_fd, buf, nwrite) == -1 && errno == EINTR)
    ;
}

namespace {
template <typename OutputIterator>
std::pair<OutputIterator, OutputIterator> copy(const char *src, size_t srclen,
                                               OutputIterator d_first,
                                               OutputIterator d_last) {
  auto nwrite =
      std::min(static_cast<size_t>(std::distance(d_first, d_last)), srclen);
  return std::make_pair(std::copy_n(src, nwrite, d_first), d_last);
}
} // namespace

namespace {
template <typename OutputIterator>
std::pair<OutputIterator, OutputIterator>
copy(const char *src, OutputIterator d_first, OutputIterator d_last) {
  return copy(src, strlen(src), d_first, d_last);
}
} // namespace

namespace {
template <typename OutputIterator>
std::pair<OutputIterator, OutputIterator>
copy(const StringRef &src, OutputIterator d_first, OutputIterator d_last) {
  return copy(src.c_str(), src.size(), d_first, d_last);
}
} // namespace

namespace {
template <size_t N, typename OutputIterator>
std::pair<OutputIterator, OutputIterator>
copy_l(const char (&src)[N], OutputIterator d_first, OutputIterator d_last) {
  return copy(src, N - 1, d_first, d_last);
}
} // namespace

namespace {
template <typename OutputIterator>
std::pair<OutputIterator, OutputIterator> copy(char c, OutputIterator d_first,
                                               OutputIterator d_last) {
  if (d_first == d_last) {
    return std::make_pair(d_last, d_last);
  }
  *d_first++ = c;
  return std::make_pair(d_first, d_last);
}
} // namespace

namespace {
constexpr char LOWER_XDIGITS[] = "0123456789abcdef";
} // namespace

namespace {
template <typename OutputIterator>
std::pair<OutputIterator, OutputIterator>
copy_hex_low(const uint8_t *src, size_t srclen, OutputIterator d_first,
             OutputIterator d_last) {
  auto nwrite = std::min(static_cast<size_t>(std::distance(d_first, d_last)),
                         srclen * 2) /
                2;
  for (size_t i = 0; i < nwrite; ++i) {
    *d_first++ = LOWER_XDIGITS[src[i] >> 4];
    *d_first++ = LOWER_XDIGITS[src[i] & 0xf];
  }
  return std::make_pair(d_first, d_last);
}
} // namespace

namespace {
template <typename OutputIterator, typename T>
std::pair<OutputIterator, OutputIterator> copy(T n, OutputIterator d_first,
                                               OutputIterator d_last) {
  if (static_cast<size_t>(std::distance(d_first, d_last)) <
      NGHTTP2_MAX_UINT64_DIGITS) {
    return std::make_pair(d_last, d_last);
  }
  return std::make_pair(util::utos(d_first, n), d_last);
}
} // namespace

namespace {
// Construct absolute request URI from |Request|, mainly to log
// request URI for proxy request (HTTP/2 proxy or client proxy).  This
// is mostly same routine found in
// HttpDownstreamConnection::push_request_headers(), but vastly
// simplified since we only care about absolute URI.
StringRef construct_absolute_request_uri(BlockAllocator &balloc,
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
  auto p = iov.base;

  if (req.scheme.empty()) {
    // We may have to log the request which lacks scheme (e.g.,
    // http/1.1 with origin form).
    p = util::copy_lit(p, "http://");
  } else {
    p = std::copy(std::begin(req.scheme), std::end(req.scheme), p);
    p = util::copy_lit(p, "://");
  }
  p = std::copy(std::begin(req.authority), std::end(req.authority), p);
  p = std::copy(std::begin(req.path), std::end(req.path), p);
  *p = '\0';

  return StringRef{iov.base, p};
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
  auto method = http2::to_method_string(req.method);
  auto path = req.method == HTTP_CONNECT
                  ? req.authority
                  : config->http2_proxy
                        ? construct_absolute_request_uri(balloc, req)
                        : req.path.empty()
                              ? req.method == HTTP_OPTIONS
                                    ? StringRef::from_lit("*")
                                    : StringRef::from_lit("-")
                              : req.path;

  auto p = std::begin(buf);
  auto last = std::end(buf) - 2;

  for (auto &lf : lfv) {
    switch (lf.type) {
    case SHRPX_LOGF_LITERAL:
      std::tie(p, last) = copy(lf.value, p, last);
      break;
    case SHRPX_LOGF_REMOTE_ADDR:
      std::tie(p, last) = copy(lgsp.remote_addr, p, last);
      break;
    case SHRPX_LOGF_TIME_LOCAL:
      std::tie(p, last) = copy(tstamp->time_local, p, last);
      break;
    case SHRPX_LOGF_TIME_ISO8601:
      std::tie(p, last) = copy(tstamp->time_iso8601, p, last);
      break;
    case SHRPX_LOGF_REQUEST:
      std::tie(p, last) = copy(method, p, last);
      std::tie(p, last) = copy(' ', p, last);
      std::tie(p, last) = copy(path, p, last);
      std::tie(p, last) = copy_l(" HTTP/", p, last);
      std::tie(p, last) = copy(req.http_major, p, last);
      if (req.http_major < 2) {
        std::tie(p, last) = copy('.', p, last);
        std::tie(p, last) = copy(req.http_minor, p, last);
      }
      break;
    case SHRPX_LOGF_STATUS:
      std::tie(p, last) = copy(resp.http_status, p, last);
      break;
    case SHRPX_LOGF_BODY_BYTES_SENT:
      std::tie(p, last) = copy(downstream->response_sent_body_length, p, last);
      break;
    case SHRPX_LOGF_HTTP: {
      auto hd = req.fs.header(lf.value);
      if (hd) {
        std::tie(p, last) = copy((*hd).value, p, last);
        break;
      }

      std::tie(p, last) = copy('-', p, last);

      break;
    }
    case SHRPX_LOGF_AUTHORITY:
      if (!req.authority.empty()) {
        std::tie(p, last) = copy(req.authority, p, last);
        break;
      }

      std::tie(p, last) = copy('-', p, last);

      break;
    case SHRPX_LOGF_REMOTE_PORT:
      std::tie(p, last) = copy(lgsp.remote_port, p, last);
      break;
    case SHRPX_LOGF_SERVER_PORT:
      std::tie(p, last) = copy(lgsp.server_port, p, last);
      break;
    case SHRPX_LOGF_REQUEST_TIME: {
      auto t = std::chrono::duration_cast<std::chrono::milliseconds>(
                   lgsp.request_end_time - downstream->get_request_start_time())
                   .count();
      std::tie(p, last) = copy(t / 1000, p, last);
      std::tie(p, last) = copy('.', p, last);
      auto frac = t % 1000;
      if (frac < 100) {
        auto n = frac < 10 ? 2 : 1;
        std::tie(p, last) = copy("000", n, p, last);
      }
      std::tie(p, last) = copy(frac, p, last);
      break;
    }
    case SHRPX_LOGF_PID:
      std::tie(p, last) = copy(lgsp.pid, p, last);
      break;
    case SHRPX_LOGF_ALPN:
      std::tie(p, last) = copy(lgsp.alpn, p, last);
      break;
    case SHRPX_LOGF_SSL_CIPHER:
      if (!lgsp.tls_info) {
        std::tie(p, last) = copy('-', p, last);
        break;
      }
      std::tie(p, last) = copy(lgsp.tls_info->cipher, p, last);
      break;
    case SHRPX_LOGF_SSL_PROTOCOL:
      if (!lgsp.tls_info) {
        std::tie(p, last) = copy('-', p, last);
        break;
      }
      std::tie(p, last) = copy(lgsp.tls_info->protocol, p, last);
      break;
    case SHRPX_LOGF_SSL_SESSION_ID:
      if (!lgsp.tls_info || lgsp.tls_info->session_id_length == 0) {
        std::tie(p, last) = copy('-', p, last);
        break;
      }
      std::tie(p, last) = copy_hex_low(
          lgsp.tls_info->session_id, lgsp.tls_info->session_id_length, p, last);
      break;
    case SHRPX_LOGF_SSL_SESSION_REUSED:
      if (!lgsp.tls_info) {
        std::tie(p, last) = copy('-', p, last);
        break;
      }
      std::tie(p, last) =
          copy(lgsp.tls_info->session_reused ? 'r' : '.', p, last);
      break;
    case SHRPX_LOGF_BACKEND_HOST:
      if (!downstream_addr) {
        std::tie(p, last) = copy('-', p, last);
        break;
      }
      std::tie(p, last) = copy(downstream_addr->host, p, last);
      break;
    case SHRPX_LOGF_BACKEND_PORT:
      if (!downstream_addr) {
        std::tie(p, last) = copy('-', p, last);
        break;
      }
      std::tie(p, last) = copy(downstream_addr->port, p, last);
      break;
    case SHRPX_LOGF_NONE:
      break;
    default:
      break;
    }
  }

  *p = '\0';

  if (accessconf.syslog) {
    syslog(LOG_INFO, "%s", buf.data());

    return;
  }

  *p++ = '\n';

  auto nwrite = std::distance(std::begin(buf), p);
  while (write(lgconf->accesslog_fd, buf.data(), nwrite) == -1 &&
         errno == EINTR)
    ;
}

int reopen_log_files() {
  int res = 0;
  int new_accesslog_fd = -1;
  int new_errorlog_fd = -1;

  auto lgconf = log_config();
  auto config = get_config();
  auto &accessconf = config->logging.access;
  auto &errorconf = config->logging.error;

  if (!accessconf.syslog && !accessconf.file.empty()) {
    new_accesslog_fd = open_log_file(accessconf.file.c_str());

    if (new_accesslog_fd == -1) {
      LOG(ERROR) << "Failed to open accesslog file " << accessconf.file;
      res = -1;
    }
  }

  if (!errorconf.syslog && !errorconf.file.empty()) {
    new_errorlog_fd = open_log_file(errorconf.file.c_str());

    if (new_errorlog_fd == -1) {
      if (lgconf->errorlog_fd != -1) {
        LOG(ERROR) << "Failed to open errorlog file " << errorconf.file;
      } else {
        std::cerr << "Failed to open errorlog file " << errorconf.file
                  << std::endl;
      }

      res = -1;
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
    signalstr += util::utos(sig);
    signalstr += ')';
  }

  LOG(NOTICE) << msg << ": [" << pid << "] exited "
              << (WIFEXITED(rstatus) ? "normally" : "abnormally")
              << " with status " << std::hex << rstatus << std::oct
              << "; exit status " << WEXITSTATUS(rstatus)
              << (signalstr.empty() ? "" : signalstr.c_str());
}

void redirect_stderr_to_errorlog() {
  auto lgconf = log_config();
  auto &errorconf = get_config()->logging.error;

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

int open_log_file(const char *path) {

  if (strcmp(path, "/dev/stdout") == 0 ||
      strcmp(path, "/proc/self/fd/1") == 0) {
    return STDOUT_COPY;
  }

  if (strcmp(path, "/dev/stderr") == 0 ||
      strcmp(path, "/proc/self/fd/2") == 0) {
    return STDERR_COPY;
  }
#if defined O_CLOEXEC

  auto fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC,
                 S_IRUSR | S_IWUSR | S_IRGRP);
#else // !O_CLOEXEC

  auto fd =
      open(path, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);

  // We get race condition if execve is called at the same time.
  if (fd != -1) {
    util::make_socket_closeonexec(fd);
  }

#endif // !O_CLOEXEC

  if (fd == -1) {
    return -1;
  }

  return fd;
}

} // namespace shrpx
