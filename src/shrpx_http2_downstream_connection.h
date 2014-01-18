/*
 * nghttp2 - HTTP/2.0 C Library
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
#ifndef SHRPX_HTTP2_DOWNSTREAM_CONNECTION_H
#define SHRPX_HTTP2_DOWNSTREAM_CONNECTION_H

#include "shrpx.h"

#include <openssl/ssl.h>

#include <nghttp2/nghttp2.h>

#include "shrpx_downstream_connection.h"

namespace shrpx {

struct StreamData;
class Http2Session;

class Http2DownstreamConnection : public DownstreamConnection {
public:
  Http2DownstreamConnection(ClientHandler *client_handler);
  virtual ~Http2DownstreamConnection();
  virtual int attach_downstream(Downstream *downstream);
  virtual void detach_downstream(Downstream *downstream);

  virtual int push_request_headers();
  virtual int push_upload_data_chunk(const uint8_t *data, size_t datalen);
  virtual int end_upload_data();

  virtual void pause_read(IOCtrlReason reason) {}
  virtual int resume_read(IOCtrlReason reason);
  virtual void force_resume_read() {}

  virtual bool get_output_buffer_full();

  virtual int on_read();
  virtual int on_write();

  virtual void on_upstream_change(Upstream *upstream) {}
  virtual int on_priority_change(int32_t pri);

  int send();

  int init_request_body_buf();
  evbuffer* get_request_body_buf() const;

  void attach_stream_data(StreamData *sd);
  StreamData* detach_stream_data();

  int submit_rst_stream(Downstream *downstream);
private:
  Http2Session *http2session_;
  evbuffer *request_body_buf_;
  StreamData *sd_;
};

} // namespace shrpx

#endif // SHRPX_HTTP2_DOWNSTREAM_CONNECTION_H
