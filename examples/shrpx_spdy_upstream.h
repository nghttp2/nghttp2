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
#ifndef SHRPX_SPDY_UPSTREAM_H
#define SHRPX_SPDY_UPSTREAM_H

#include "shrpx.h"

#include <spdylay/spdylay.h>

#include "shrpx_upstream.h"
#include "shrpx_downstream_queue.h"

namespace shrpx {

class ClientHandler;

class SpdyUpstream : public Upstream {
public:
  SpdyUpstream(uint16_t version, ClientHandler *handler);
  virtual ~SpdyUpstream();
  virtual int on_read();
  virtual int on_event();
  int send();
  virtual ClientHandler* get_client_handler() const;
  virtual bufferevent_data_cb get_downstream_readcb();
  virtual bufferevent_data_cb get_downstream_writecb();
  virtual bufferevent_event_cb get_downstream_eventcb();
  void add_downstream(Downstream *downstream);
  void remove_downstream(Downstream *downstream);
  void start_downstream(Downstream *downstream);
  spdylay_session* get_spdy_session();
  DownstreamQueue* get_downstream_queue();

  int rst_stream(Downstream *downstream, int status_code);
  int error_reply(Downstream *downstream, int status_code);

  virtual int on_downstream_header_complete(Downstream *downstream);
  virtual int on_downstream_body(Downstream *downstream,
                                 const uint8_t *data, size_t len);
  virtual int on_downstream_body_complete(Downstream *downstream);
private:
  ClientHandler *handler_;
  spdylay_session *session_;
  DownstreamQueue downstream_queue_;
};

} // namespace shrpx

#endif // SHRPX_SPDY_UPSTREAM_H
