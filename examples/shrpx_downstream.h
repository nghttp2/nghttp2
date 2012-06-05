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
#ifndef SHRPX_DOWNSTREAM_H
#define SHRPX_DOWNSTREAM_H

#include "shrpx.h"

#include <stdint.h>

#include <vector>
#include <string>

#include <event.h>
#include <event2/bufferevent.h>

extern "C" {
#include "htparse/htparse.h"
}

#include "shrpx_io_control.h"

namespace shrpx {

class Upstream;

typedef std::vector<std::pair<std::string, std::string> > Headers;

class Downstream {
public:
  Downstream(Upstream *upstream, int stream_id, int priority);
  ~Downstream();
  int start_connection();
  Upstream* get_upstream() const;
  int32_t get_stream_id() const;
  void pause_read(IOCtrlReason reason);
  bool resume_read(IOCtrlReason reason);
  // downstream request API
  const Headers& get_request_headers() const;
  void add_request_header(const std::string& name, const std::string& value);
  void set_last_request_header_value(const std::string& value);
  void set_request_method(const std::string& method);
  void set_request_path(const std::string& path);
  int push_request_headers();
  bool get_chunked_request() const;
  bool get_request_connection_close() const;
  void set_request_connection_close(bool f);
  int push_upload_data_chunk(const uint8_t *data, size_t datalen);
  int end_upload_data();
  enum {
    INITIAL,
    HEADER_COMPLETE,
    MSG_COMPLETE,
    STREAM_CLOSED,
    CONNECT_FAIL
  };
  void set_request_state(int state);
  int get_request_state() const;
  // downstream response API
  const Headers& get_response_headers() const;
  void add_response_header(const std::string& name, const std::string& value);
  void set_last_response_header_value(const std::string& value);
  unsigned int get_response_http_status() const;
  void set_response_http_status(unsigned int status);
  bool get_chunked_response() const;
  int parse_http_response();
  void set_response_state(int state);
  int get_response_state() const;
  int init_response_body_buf();
  evbuffer* get_response_body_buf();
private:
  Upstream *upstream_;
  bufferevent *bev_;
  int32_t stream_id_;
  int priority_;
  IOControl ioctrl_;
  int request_state_;
  std::string request_method_;
  std::string request_path_;
  bool chunked_request_;
  bool request_connection_close_;
  Headers request_headers_;

  int response_state_;
  unsigned int response_http_status_;
  bool chunked_response_;
  Headers response_headers_;
  htparser *response_htp_;
  // This buffer is used to temporarily store downstream response
  // body. Spdylay reads data from this in the callback.
  evbuffer *response_body_buf_;
};

} // namespace shrpx

#endif // SHRPX_DOWNSTREAM_H
