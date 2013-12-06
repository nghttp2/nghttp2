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
#ifndef SHRPX_DOWNSTREAM_H
#define SHRPX_DOWNSTREAM_H

#include "shrpx.h"

#include <stdint.h>

#include <vector>
#include <string>

#include <event.h>
#include <event2/bufferevent.h>

#include <nghttp2/nghttp2.h>

#include "shrpx_io_control.h"

namespace shrpx {

class Upstream;
class DownstreamConnection;

typedef std::vector<std::pair<std::string, std::string> > Headers;

class Downstream {
public:
  Downstream(Upstream *upstream, int stream_id, int priority);
  ~Downstream();
  void reset_upstream(Upstream *upstream);
  Upstream* get_upstream() const;
  void set_stream_id(int32_t stream_id);
  int32_t get_stream_id() const;
  void set_priority(int32_t pri);
  int32_t get_priorty() const;
  void pause_read(IOCtrlReason reason);
  int resume_read(IOCtrlReason reason);
  void force_resume_read();
  // Set stream ID for downstream HTTP2 connection.
  void set_downstream_stream_id(int32_t stream_id);
  int32_t get_downstream_stream_id() const;

  void set_downstream_connection(DownstreamConnection *dconn);
  DownstreamConnection* get_downstream_connection();
  // Returns true if output buffer is full. If underlying dconn_ is
  // NULL, this function always returns false.
  bool get_output_buffer_full();
  // Returns true if upgrade (HTTP Upgrade or CONNECT) is succeeded.
  void check_upgrade_fulfilled();
  // Checks request headers whether the request is upgrade request or
  // not.
  void check_upgrade_request();
  // Returns true if the request is upgrade.
  bool get_upgrade_request() const;
  // Returns true if the upgrade is succeded as a result of the call
  // check_upgrade_fulfilled().
  bool get_upgraded() const;
  // Returns true if the request is HTTP Upgrade for HTTP/2.0
  bool http2_upgrade_request() const;
  // downstream request API
  const Headers& get_request_headers() const;
  void crumble_request_cookie();
  void assemble_request_cookie();
  const std::string& get_assembled_request_cookie() const;
  // Makes key lowercase and sort headers by name using <
  void normalize_request_headers();
  // Returns iterator pointing to the request header with the name
  // |name|. If multiple header have |name| as name, return first
  // occurrence from the beginning. If no such header is found,
  // returns std::end(get_request_headers()). This function must be
  // called after calling normalize_request_headers().
  Headers::const_iterator get_norm_request_header
  (const std::string& name) const;
  void add_request_header(std::string name, std::string value);
  void set_last_request_header_value(std::string value);

  bool get_request_header_key_prev() const;
  void append_last_request_header_key(const char *data, size_t len);
  void append_last_request_header_value(const char *data, size_t len);

  void set_request_method(std::string method);
  const std::string& get_request_method() const;
  void set_request_path(std::string path);
  void append_request_path(const char *data, size_t len);
  // Returns request path. For HTTP/1.1, this is request-target. For
  // HTTP/2, this is :path header field value.
  const std::string& get_request_path() const;
  // Returns HTTP/2 :scheme header field value.
  const std::string& get_request_http2_scheme() const;
  void set_request_http2_scheme(std::string scheme);
  // Returns HTTP/2 :authority header field value.
  const std::string& get_request_http2_authority() const;
  void set_request_http2_authority(std::string authority);
  void set_request_major(int major);
  void set_request_minor(int minor);
  int get_request_major() const;
  int get_request_minor() const;
  int push_request_headers();
  bool get_chunked_request() const;
  bool get_request_connection_close() const;
  void set_request_connection_close(bool f);
  bool get_expect_100_continue() const;
  int push_upload_data_chunk(const uint8_t *data, size_t datalen);
  int end_upload_data();
  enum {
    INITIAL,
    HEADER_COMPLETE,
    MSG_COMPLETE,
    STREAM_CLOSED,
    CONNECT_FAIL,
    IDLE,
    MSG_RESET
  };
  void set_request_state(int state);
  int get_request_state() const;
  // downstream response API
  const Headers& get_response_headers() const;
  // Makes key lowercase and sort headers by name using <
  void normalize_response_headers();
  // Concatenates response header fields with same name by NULL as
  // delimiter. See http2::concat_norm_headers(). This function must
  // be called after calling normalize_response_headers().
  void concat_norm_response_headers();
  // Returns iterator pointing to the response header with the name
  // |name|. If multiple header have |name| as name, return first
  // occurrence from the beginning. If no such header is found,
  // returns std::end(get_response_headers()). This function must be
  // called after calling normalize_response_headers().
  Headers::const_iterator get_norm_response_header
  (const std::string& name) const;
  void add_response_header(std::string name, std::string value);
  void set_last_response_header_value(std::string value);

  bool get_response_header_key_prev() const;
  void append_last_response_header_key(const char *data, size_t len);
  void append_last_response_header_value(const char *data, size_t len);

  unsigned int get_response_http_status() const;
  void set_response_http_status(unsigned int status);
  void set_response_major(int major);
  void set_response_minor(int minor);
  int get_response_major() const;
  int get_response_minor() const;
  int get_response_version() const;
  bool get_chunked_response() const;
  void set_chunked_response(bool f);
  bool get_response_connection_close() const;
  void set_response_connection_close(bool f);
  void set_response_state(int state);
  int get_response_state() const;
  int init_response_body_buf();
  evbuffer* get_response_body_buf();
  nghttp2_error_code get_response_rst_stream_error_code() const;
  void set_response_rst_stream_error_code(nghttp2_error_code error_code);

  // Call this method when there is incoming data in downstream
  // connection.
  int on_read();

  static const size_t OUTPUT_UPPER_THRES = 64*1024;
private:
  Headers request_headers_;
  Headers response_headers_;

  std::string request_method_;
  std::string request_path_;
  std::string request_http2_scheme_;
  std::string request_http2_authority_;
  std::string assembled_request_cookie_;
  // the length of request body
  int64_t request_bodylen_;

  Upstream *upstream_;
  DownstreamConnection *dconn_;
  // This buffer is used to temporarily store downstream response
  // body. nghttp2 library reads data from this in the callback.
  evbuffer *response_body_buf_;

  int32_t stream_id_;
  int32_t priority_;
  // stream ID in backend connection
  int32_t downstream_stream_id_;

  // RST_STREAM error_code from downstream HTTP2 connection
  nghttp2_error_code response_rst_stream_error_code_;

  int request_state_;
  int request_major_;
  int request_minor_;

  int response_state_;
  unsigned int response_http_status_;
  int response_major_;
  int response_minor_;

  // true if the request contains upgrade token (HTTP Upgrade or
  // CONNECT)
  bool upgrade_request_;
  // true if the connection is upgraded (HTTP Upgrade or CONNECT)
  bool upgraded_;

  bool chunked_request_;
  bool request_connection_close_;
  bool request_expect_100_continue_;
  bool request_header_key_prev_;

  bool chunked_response_;
  bool response_connection_close_;
  bool response_header_key_prev_;
};

} // namespace shrpx

#endif // SHRPX_DOWNSTREAM_H
