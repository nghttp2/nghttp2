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

#include <syslog.h>
#include <unistd.h>
#include <inttypes.h>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>

#include "shrpx_config.h"
#include "shrpx_downstream.h"
#include "shrpx_worker_config.h"
#include "util.h"

using namespace nghttp2;

namespace shrpx {

namespace {
const char *SEVERITY_STR[] = {
  "INFO", "WARN", "ERROR", "FATAL"
};
} // namespace

namespace {
const char *SEVERITY_COLOR[] = {
  "\033[1;32m", // INFO
  "\033[1;33m", // WARN
  "\033[1;31m", // ERROR
  "\033[1;35m", // FATAL
};
} // namespace

int Log::severity_thres_ = WARNING;

void Log::set_severity_level(int severity)
{
  severity_thres_ = severity;
}

int Log::set_severity_level_by_name(const char *name)
{
  for(size_t i = 0, max = sizeof(SEVERITY_STR)/sizeof(char*); i < max;  ++i) {
    if(strcmp(SEVERITY_STR[i], name) == 0) {
      severity_thres_ = i;
      return 0;
    }
  }
  return -1;
}

int severity_to_syslog_level(int severity)
{
  switch(severity) {
  case(INFO):
    return LOG_INFO;
  case(WARNING):
    return LOG_WARNING;
  case(ERROR):
    return LOG_ERR;
  case(FATAL):
    return LOG_CRIT;
  default:
    return -1;
  }
}

Log::Log(int severity, const char *filename, int linenum)
  : filename_(filename),
    severity_(severity),
    linenum_(linenum)
{}

Log::~Log()
{
  int rv;

  if(!log_enabled(severity_) ||
     (worker_config.errorlog_fd == -1 && !get_config()->errorlog_syslog)) {
    return;
  }

  if(get_config()->errorlog_syslog) {
    syslog(severity_to_syslog_level(severity_), "[%s] %s (%s:%d)",
           SEVERITY_STR[severity_], stream_.str().c_str(),
           filename_, linenum_);

    return;
  }

  char buf[4096];
  auto tty = worker_config.errorlog_tty;

  auto cached_time = get_config()->cached_time;

  rv = snprintf(buf, sizeof(buf),
                "%s PID%d [%s%s%s] %s%s:%d%s %s\n",
                cached_time->c_str(),
                getpid(),
                tty ? SEVERITY_COLOR[severity_] : "",
                SEVERITY_STR[severity_],
                tty ? "\033[0m" : "",
                tty ? "\033[1;30m" : "",
                filename_, linenum_,
                tty ? "\033[0m" : "",
                stream_.str().c_str());

  if(rv < 0) {
    return;
  }

  auto nwrite = std::min(static_cast<size_t>(rv), sizeof(buf) - 1);

  write(worker_config.errorlog_fd, buf, nwrite);
}

void upstream_accesslog(const std::string& client_ip, unsigned int status_code,
                        Downstream *downstream)
{
  if(worker_config.accesslog_fd == -1 && !get_config()->accesslog_syslog) {
    return;
  }

  char buf[1024];
  int rv;

  const char *path;
  const char *method;
  unsigned int major, minor;
  const char *user_agent;
  int64_t response_bodylen;

  if(!downstream) {
    path = "-";
    method = "-";
    major = 1;
    minor = 0;
    user_agent = "-";
    response_bodylen = 0;
  } else {
    if(downstream->get_request_path().empty()) {
      path = downstream->get_request_http2_authority().c_str();
    } else {
      path = downstream->get_request_path().c_str();
    }

    method = downstream->get_request_method().c_str();
    major = downstream->get_request_major();
    minor = downstream->get_request_minor();
    user_agent = downstream->get_request_user_agent().c_str();
    if(!user_agent[0]) {
      user_agent = "-";
    }
    response_bodylen = downstream->get_response_bodylen();
  }

  static const char fmt[] =
    "%s - - [%s] \"%s %s HTTP/%u.%u\" %u %lld \"-\" \"%s\"\n";

  auto cached_time = get_config()->cached_time;

  rv = snprintf(buf, sizeof(buf), fmt,
                client_ip.c_str(),
                cached_time->c_str(),
                method,
                path,
                major,
                minor,
                status_code,
                (long long int)response_bodylen,
                user_agent);

  if(rv < 0) {
    return;
  }

  auto nwrite = std::min(static_cast<size_t>(rv), sizeof(buf) - 1);

  if(get_config()->accesslog_syslog) {
    syslog(LOG_INFO, "%s", buf);

    return;
  }

  write(worker_config.accesslog_fd, buf, nwrite);
}

int reopen_log_files()
{
  int res = 0;

  if(worker_config.accesslog_fd != -1) {
    close(worker_config.accesslog_fd);
    worker_config.accesslog_fd = -1;
  }

  if(!get_config()->accesslog_syslog && get_config()->accesslog_file) {

    worker_config.accesslog_fd =
      util::reopen_log_file(get_config()->accesslog_file.get());

    if(worker_config.accesslog_fd == -1) {
      LOG(ERROR) << "Failed to open accesslog file "
                 << get_config()->accesslog_file.get();
      res = -1;
    }
  }

  int new_errorlog_fd = -1;

  if(!get_config()->errorlog_syslog && get_config()->errorlog_file) {

    new_errorlog_fd = util::reopen_log_file(get_config()->errorlog_file.get());

    if(new_errorlog_fd == -1) {
      if(worker_config.errorlog_fd != -1) {
        LOG(ERROR) << "Failed to open errorlog file "
                   << get_config()->errorlog_file.get();
      } else {
        std::cerr << "Failed to open errorlog file "
                  << get_config()->errorlog_file.get()
                  << std::endl;
      }

      res = -1;
    }
  }

  if(worker_config.errorlog_fd != -1) {
    close(worker_config.errorlog_fd);
    worker_config.errorlog_fd = -1;
    worker_config.errorlog_tty = false;
  }

  if(new_errorlog_fd != -1) {
    worker_config.errorlog_fd = new_errorlog_fd;
    worker_config.errorlog_tty = isatty(worker_config.errorlog_fd);
  }

  return res;
}

} // namespace shrpx
