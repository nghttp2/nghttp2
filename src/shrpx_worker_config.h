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
#ifndef SHRPX_WORKER_CONFIG_H
#define SHRPX_WORKER_CONFIG_H

#include "shrpx.h"

namespace shrpx {

namespace ssl {
struct CertLookupTree;
} // namespace ssl

struct TicketKeys;

struct WorkerConfig {
  std::shared_ptr<TicketKeys> ticket_keys;
  ssl::CertLookupTree *cert_tree;
  int accesslog_fd;
  int errorlog_fd;
  // true if errorlog_fd is referring to a terminal.
  bool errorlog_tty;
  bool graceful_shutdown;

  WorkerConfig();
};

// We need WorkerConfig per thread
extern
#ifndef NOTHREADS
    thread_local
#endif // NOTHREADS
    WorkerConfig *worker_config;

} // namespace shrpx

#endif // SHRPX_WORKER_CONFIG_H
