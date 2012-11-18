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
#ifndef SHRPX_SPDY_DOWNSTREAM_CONNECTION_H
#define SHRPX_SPDY_DOWNSTREAM_CONNECTION_H

#include "shrpx.h"

#include <openssl/ssl.h>

#include <spdylay/spdylay.h>

#include "shrpx_downstream_connection.h"

namespace shrpx {

class SpdyDownstreamConnection : public DownstreamConnection {
public:
  SpdyDownstreamConnection(ClientHandler *client_handler);
  virtual ~SpdyDownstreamConnection();
  virtual int attach_downstream(Downstream *downstream);

  virtual int push_request_headers();
  virtual int push_upload_data_chunk(const uint8_t *data, size_t datalen);
  virtual int end_upload_data();

  virtual int on_connect();

  int on_read();
  int on_write();
  int send();

  int init_request_body_buf();
  evbuffer* get_request_body_buf() const;
private:
  SSL *ssl_;
  spdylay_session *session_;
  evbuffer *request_body_buf_;
};

} // namespace shrpx

#endif // SHRPX_SPDY_DOWNSTREAM_CONNECTION_H
