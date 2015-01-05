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
#ifndef SHRPX_HTTP_DOWNSTREAM_CONNECTION_H
#define SHRPX_HTTP_DOWNSTREAM_CONNECTION_H

#include "shrpx.h"

#include "http-parser/http_parser.h"

#include "shrpx_downstream_connection.h"
#include "shrpx_io_control.h"

namespace shrpx {

class DownstreamConnectionPool;

class HttpDownstreamConnection : public DownstreamConnection {
public:
  HttpDownstreamConnection(DownstreamConnectionPool *dconn_pool,
                           struct ev_loop *loop);
  virtual ~HttpDownstreamConnection();
  virtual int attach_downstream(Downstream *downstream);
  virtual void detach_downstream(Downstream *downstream);

  virtual int push_request_headers();
  virtual int push_upload_data_chunk(const uint8_t *data, size_t datalen);
  virtual int end_upload_data();

  virtual void pause_read(IOCtrlReason reason);
  virtual int resume_read(IOCtrlReason reason, size_t consumed);
  virtual void force_resume_read();

  virtual int on_read();
  virtual int on_write();

  virtual void on_upstream_change(Upstream *upstream);
  virtual int on_priority_change(int32_t pri) { return 0; }

  int on_connect();
  void signal_write();

private:
  ev_io wev_;
  ev_io rev_;
  ev_timer wt_;
  ev_timer rt_;
  RateLimit rlimit_;
  IOControl ioctrl_;
  http_parser response_htp_;
  struct ev_loop *loop_;
  int fd_;
};

} // namespace shrpx

#endif // SHRPX_HTTP_DOWNSTREAM_CONNECTION_H
