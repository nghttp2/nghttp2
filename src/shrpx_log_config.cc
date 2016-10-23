/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
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
#include "shrpx_log_config.h"
#include "util.h"

using namespace nghttp2;

namespace shrpx {

LogConfig::LogConfig()
    : accesslog_fd(-1), errorlog_fd(-1), errorlog_tty(false) {}

#ifndef NOTHREADS
#ifdef HAVE_THREAD_LOCAL
namespace {
thread_local std::unique_ptr<LogConfig> config = make_unique<LogConfig>();
} // namespace

LogConfig *log_config() { return config.get(); }
void delete_log_config() {}
#else  // !HAVE_THREAD_LOCAL
namespace {
pthread_key_t lckey;
pthread_once_t lckey_once = PTHREAD_ONCE_INIT;
} // namespace

namespace {
void make_key() { pthread_key_create(&lckey, NULL); }
} // namespace

LogConfig *log_config() {
  pthread_once(&lckey_once, make_key);
  LogConfig *config = (LogConfig *)pthread_getspecific(lckey);
  if (!config) {
    config = new LogConfig();
    pthread_setspecific(lckey, config);
  }
  return config;
}

void delete_log_config() { delete log_config(); }
#endif // !HAVE_THREAD_LOCAL
#else  // NOTHREADS
namespace {
std::unique_ptr<LogConfig> config = make_unique<LogConfig>();
} // namespace

LogConfig *log_config() { return config.get(); }

void delete_log_config() {}
#endif // NOTHREADS

void LogConfig::update_tstamp(
    const std::chrono::system_clock::time_point &now) {
  auto t0 = std::chrono::system_clock::to_time_t(time_str_updated_);
  auto t1 = std::chrono::system_clock::to_time_t(now);
  if (t0 == t1) {
    return;
  }

  time_str_updated_ = now;

  time_local = util::format_common_log(time_local_buf.data(), now);
  time_iso8601 = util::format_iso8601(time_iso8601_buf.data(), now);
  time_http = util::format_http_date(time_http_buf.data(), now);
}

} // namespace shrpx
