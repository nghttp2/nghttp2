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

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <iomanip>

#include "shrpx_config.h"
#include "shrpx_downstream.h"
#include "util.h"
#include "template.h"

using namespace nghttp2;

namespace shrpx {

namespace {
const char *SEVERITY_STR[] = {"INFO", "NOTICE", "WARN", "ERROR", "FATAL"};
} // namespace

namespace {
const char *SEVERITY_COLOR[] = {
    "\033[1;32m", // INFO
    "\033[1;36m", // NOTICE
    "\033[1;33m", // WARN
    "\033[1;31m", // ERROR
    "\033[1;35m", // FATAL
};
} // namespace

int Log::severity_thres_ = NOTICE;

void Log::set_severity_level(int severity) { severity_thres_ = severity; }

int Log::set_severity_level_by_name(const char *name) {
  for (size_t i = 0, max = array_size(SEVERITY_STR); i < max; ++i) {
    if (strcmp(SEVERITY_STR[i], name) == 0) {
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

  if (!get_config()) {
    return;
  }

  auto lgconf = log_config();

  if (!log_enabled(severity_) ||
      (lgconf->errorlog_fd == -1 && !get_config()->errorlog_syslog)) {
    return;
  }

  if (get_config()->errorlog_syslog) {
    if (severity_ == NOTICE) {
      syslog(severity_to_syslog_level(severity_), "[%s] %s",
             SEVERITY_STR[severity_], stream_.str().c_str());
    } else {
      syslog(severity_to_syslog_level(severity_), "[%s] %s (%s:%d)",
             SEVERITY_STR[severity_], stream_.str().c_str(), filename_,
             linenum_);
    }

    return;
  }

  char buf[4096];
  auto tty = lgconf->errorlog_tty;

  lgconf->update_tstamp(std::chrono::system_clock::now());
  auto &time_local = lgconf->time_local_str;

  if (severity_ == NOTICE) {
    rv = snprintf(buf, sizeof(buf), "%s PID%d [%s%s%s] %s\n",
                  time_local.c_str(), get_config()->pid,
                  tty ? SEVERITY_COLOR[severity_] : "", SEVERITY_STR[severity_],
                  tty ? "\033[0m" : "", stream_.str().c_str());
  } else {
    rv = snprintf(buf, sizeof(buf), "%s PID%d [%s%s%s] %s%s:%d%s %s\n",
                  time_local.c_str(), get_config()->pid,
                  tty ? SEVERITY_COLOR[severity_] : "", SEVERITY_STR[severity_],
                  tty ? "\033[0m" : "", tty ? "\033[1;30m" : "", filename_,
                  linenum_, tty ? "\033[0m" : "", stream_.str().c_str());
  }

  if (rv < 0) {
    return;
  }

  auto nwrite = std::min(static_cast<size_t>(rv), sizeof(buf) - 1);

  while (write(lgconf->errorlog_fd, buf, nwrite) == -1 && errno == EINTR)
    ;
}

namespace {
template <typename OutputIterator>
std::pair<OutputIterator, size_t> copy(const char *src, size_t avail,
                                       OutputIterator oitr) {
  auto nwrite = std::min(strlen(src), avail);
  auto noitr = std::copy_n(src, nwrite, oitr);
  return std::make_pair(noitr, avail - nwrite);
}
} // namespace

void upstream_accesslog(const std::vector<LogFragment> &lfv,
                        const LogSpec &lgsp) {
  auto lgconf = log_config();

  if (lgconf->accesslog_fd == -1 && !get_config()->accesslog_syslog) {
    return;
  }

  char buf[4096];

  auto downstream = lgsp.downstream;

  auto p = buf;
  auto avail = sizeof(buf) - 2;

  lgconf->update_tstamp(lgsp.time_now);
  auto &time_local = lgconf->time_local_str;
  auto &time_iso8601 = lgconf->time_iso8601_str;

  for (auto &lf : lfv) {
    switch (lf.type) {
    case SHRPX_LOGF_LITERAL:
      std::tie(p, avail) = copy(lf.value.get(), avail, p);
      break;
    case SHRPX_LOGF_REMOTE_ADDR:
      std::tie(p, avail) = copy(lgsp.remote_addr, avail, p);
      break;
    case SHRPX_LOGF_TIME_LOCAL:
      std::tie(p, avail) = copy(time_local.c_str(), avail, p);
      break;
    case SHRPX_LOGF_TIME_ISO8601:
      std::tie(p, avail) = copy(time_iso8601.c_str(), avail, p);
      break;
    case SHRPX_LOGF_REQUEST:
      std::tie(p, avail) = copy(lgsp.method, avail, p);
      std::tie(p, avail) = copy(" ", avail, p);
      std::tie(p, avail) = copy(lgsp.path, avail, p);
      std::tie(p, avail) = copy(" HTTP/", avail, p);
      std::tie(p, avail) = copy(util::utos(lgsp.major).c_str(), avail, p);
      if (lgsp.major < 2) {
        std::tie(p, avail) = copy(".", avail, p);
        std::tie(p, avail) = copy(util::utos(lgsp.minor).c_str(), avail, p);
      }
      break;
    case SHRPX_LOGF_STATUS:
      std::tie(p, avail) = copy(util::utos(lgsp.status).c_str(), avail, p);
      break;
    case SHRPX_LOGF_BODY_BYTES_SENT:
      std::tie(p, avail) =
          copy(util::utos(lgsp.body_bytes_sent).c_str(), avail, p);
      break;
    case SHRPX_LOGF_HTTP:
      if (downstream) {
        auto hd = downstream->get_request_header(lf.value.get());
        if (hd) {
          std::tie(p, avail) = copy((*hd).value.c_str(), avail, p);
          break;
        }
      }

      std::tie(p, avail) = copy("-", avail, p);

      break;
    case SHRPX_LOGF_REMOTE_PORT:
      std::tie(p, avail) = copy(lgsp.remote_port, avail, p);
      break;
    case SHRPX_LOGF_SERVER_PORT:
      std::tie(p, avail) = copy(util::utos(lgsp.server_port).c_str(), avail, p);
      break;
    case SHRPX_LOGF_REQUEST_TIME: {
      auto t = std::chrono::duration_cast<std::chrono::milliseconds>(
                   lgsp.request_end_time - lgsp.request_start_time).count();

      auto frac = util::utos(t % 1000);
      auto sec = util::utos(t / 1000);
      if (frac.size() < 3) {
        frac = std::string(3 - frac.size(), '0') + frac;
      }
      sec += ".";
      sec += frac;

      std::tie(p, avail) = copy(sec.c_str(), avail, p);
    } break;
    case SHRPX_LOGF_PID:
      std::tie(p, avail) = copy(util::utos(lgsp.pid).c_str(), avail, p);
      break;
    case SHRPX_LOGF_ALPN:
      std::tie(p, avail) = copy(lgsp.alpn, avail, p);
      break;
    case SHRPX_LOGF_NONE:
      break;
    default:
      break;
    }
  }

  *p = '\0';

  if (get_config()->accesslog_syslog) {
    syslog(LOG_INFO, "%s", buf);

    return;
  }

  *p++ = '\n';

  auto nwrite = p - buf;
  while (write(lgconf->accesslog_fd, buf, nwrite) == -1 && errno == EINTR)
    ;
}

int reopen_log_files() {
  int res = 0;

  auto lgconf = log_config();

  if (lgconf->accesslog_fd != -1) {
    close(lgconf->accesslog_fd);
    lgconf->accesslog_fd = -1;
  }

  if (!get_config()->accesslog_syslog && get_config()->accesslog_file) {

    lgconf->accesslog_fd =
        util::reopen_log_file(get_config()->accesslog_file.get());

    if (lgconf->accesslog_fd == -1) {
      LOG(ERROR) << "Failed to open accesslog file "
                 << get_config()->accesslog_file.get();
      res = -1;
    }
  }

  int new_errorlog_fd = -1;

  if (!get_config()->errorlog_syslog && get_config()->errorlog_file) {

    new_errorlog_fd = util::reopen_log_file(get_config()->errorlog_file.get());

    if (new_errorlog_fd == -1) {
      if (lgconf->errorlog_fd != -1) {
        LOG(ERROR) << "Failed to open errorlog file "
                   << get_config()->errorlog_file.get();
      } else {
        std::cerr << "Failed to open errorlog file "
                  << get_config()->errorlog_file.get() << std::endl;
      }

      res = -1;
    }
  }

  if (lgconf->errorlog_fd != -1) {
    close(lgconf->errorlog_fd);
    lgconf->errorlog_fd = -1;
    lgconf->errorlog_tty = false;
  }

  if (new_errorlog_fd != -1) {
    lgconf->errorlog_fd = new_errorlog_fd;
    lgconf->errorlog_tty = isatty(lgconf->errorlog_fd);
  }

  return res;
}

void redirect_stderr_to_errorlog() {
  auto lgconf = log_config();

  if (get_config()->errorlog_syslog || lgconf->errorlog_fd == -1) {
    return;
  }

  dup2(lgconf->errorlog_fd, STDERR_FILENO);
}

} // namespace shrpx
