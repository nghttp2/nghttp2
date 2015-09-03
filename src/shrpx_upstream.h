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
#ifndef SHRPX_UPSTREAM_H
#define SHRPX_UPSTREAM_H

#include "shrpx.h"
#include "shrpx_io_control.h"

namespace shrpx {

class ClientHandler;
class Downstream;
class DownstreamConnection;

class Upstream {
public:
  virtual ~Upstream() {}
  virtual int on_read() = 0;
  virtual int on_write() = 0;
  virtual int on_timeout(Downstream *downstream) { return 0; };
  virtual int on_downstream_abort_request(Downstream *downstream,
                                          unsigned int status_code) = 0;
  virtual int downstream_read(DownstreamConnection *dconn) = 0;
  virtual int downstream_write(DownstreamConnection *dconn) = 0;
  virtual int downstream_eof(DownstreamConnection *dconn) = 0;
  virtual int downstream_error(DownstreamConnection *dconn, int events) = 0;
  virtual ClientHandler *get_client_handler() const = 0;

  virtual int on_downstream_header_complete(Downstream *downstream) = 0;
  virtual int on_downstream_body(Downstream *downstream, const uint8_t *data,
                                 size_t len, bool flush) = 0;
  virtual int on_downstream_body_complete(Downstream *downstream) = 0;

  virtual void on_handler_delete() = 0;
  // Called when downstream connection is reset.  Currently this is
  // only used by Http2Session.  If |no_retry| is true, another
  // connection attempt using new DownstreamConnection is not allowed.
  virtual int on_downstream_reset(bool no_retry) = 0;

  virtual void pause_read(IOCtrlReason reason) = 0;
  virtual int resume_read(IOCtrlReason reason, Downstream *downstream,
                          size_t consumed) = 0;
  virtual int send_reply(Downstream *downstream, const uint8_t *body,
                         size_t bodylen) = 0;
};

} // namespace shrpx

#endif // SHRPX_UPSTREAM_H
