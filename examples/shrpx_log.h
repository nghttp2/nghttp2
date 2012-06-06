/*
 * Spdylay - SPDY Library
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

#include <sstream>

namespace shrpx {

#define ENABLE_LOG 1

#define LOG(SEVERITY) Log(SEVERITY, __FILE__, __LINE__)

enum SeverityLevel {
  INFO, WARNING, ERROR, FATAL
};

class Log {
public:
  Log(int severity, const char *filename, int linenum);
  ~Log();
  template<typename Type> Log& operator<<(Type s)
  {
    stream_ << s;
    return *this;
  }
  static void set_severity_level(int severity);
  static int set_severity_level_by_name(const char *name);
private:
  int severity_;
  const char *filename_;
  int linenum_;
  std::stringstream stream_;
  static int severity_thres_;
};

} // namespace shrpx

#endif // SHRPX_LOG_H
