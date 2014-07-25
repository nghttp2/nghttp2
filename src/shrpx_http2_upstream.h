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
#ifndef SHRPX_HTTP2_UPSTREAM_H
#define SHRPX_HTTP2_UPSTREAM_H

#include "shrpx.h"

#include <memory>

#include <nghttp2/nghttp2.h>

#include "shrpx_upstream.h"
#include "shrpx_downstream_queue.h"

namespace shrpx {

class ClientHandler;
class HttpsUpstream;

class Http2Upstream : public Upstream {
public:
  Http2Upstream(ClientHandler *handler);
  virtual ~Http2Upstream();
  virtual int on_read();
  virtual int on_write();
  virtual int on_event();
  virtual int on_downstream_abort_request(Downstream *downstream,
                                          unsigned int status_code);
  int send();
  virtual ClientHandler* get_client_handler() const;
  virtual bufferevent_data_cb get_downstream_readcb();
  virtual bufferevent_data_cb get_downstream_writecb();
  virtual bufferevent_event_cb get_downstream_eventcb();
  void add_downstream(Downstream *downstream);
  void remove_downstream(Downstream *downstream);
  Downstream* find_downstream(int32_t stream_id);

  nghttp2_session* get_http2_session();

  int rst_stream(Downstream *downstream, nghttp2_error_code error_code);
  int terminate_session(nghttp2_error_code error_code);
  int error_reply(Downstream *downstream, unsigned int status_code);

  virtual void pause_read(IOCtrlReason reason);
  virtual int resume_read(IOCtrlReason reason, Downstream *downstream);

  virtual int on_downstream_header_complete(Downstream *downstream);
  virtual int on_downstream_body(Downstream *downstream,
                                 const uint8_t *data, size_t len, bool flush);
  virtual int on_downstream_body_complete(Downstream *downstream);

  bool get_flow_control() const;
  // Perform HTTP/2 upgrade from |upstream|. On success, this object
  // takes ownership of the |upstream|. This function returns 0 if it
  // succeeds, or -1.
  int upgrade_upstream(HttpsUpstream *upstream);
  int start_settings_timer();
  void stop_settings_timer();
  int consume(int32_t stream_id, size_t len);
private:
  DownstreamQueue downstream_queue_;
  std::unique_ptr<HttpsUpstream> pre_upstream_;
  ClientHandler *handler_;
  nghttp2_session *session_;
  event *settings_timerev_;
  bool flow_control_;
};

} // namespace shrpx

#endif // SHRPX_HTTP2_UPSTREAM_H
