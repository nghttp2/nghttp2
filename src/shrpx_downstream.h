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
#include "http2.h"

using namespace nghttp2;

namespace shrpx {

class Upstream;
class DownstreamConnection;

class Downstream {
public:
  Downstream(Upstream *upstream, int stream_id, int priority);
  ~Downstream();
  void reset_upstream(Upstream *upstream);
  Upstream* get_upstream() const;
  void set_stream_id(int32_t stream_id);
  int32_t get_stream_id() const;
  void set_priority(int32_t pri);
  int32_t get_priority() const;
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
  // Returns true if the request is upgrade.
  bool get_upgrade_request() const;
  // Returns true if the upgrade is succeded as a result of the call
  // check_upgrade_fulfilled().
  bool get_upgraded() const;
  // Inspects HTTP/2 request.
  void inspect_http2_request();
  // Inspects HTTP/1 request.  This checks whether the request is
  // upgrade request and tranfer-encoding etc.
  void inspect_http1_request();
  // Returns true if the request is HTTP Upgrade for HTTP/2
  bool get_http2_upgrade_request() const;
  // Returns the value of HTTP2-Settings request header field.
  const std::string& get_http2_settings() const;
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

  void split_add_request_header(const uint8_t *name, size_t namelen,
                                const uint8_t *value, size_t valuelen,
                                bool no_index);

  bool get_request_header_key_prev() const;
  void append_last_request_header_key(const char *data, size_t len);
  void append_last_request_header_value(const char *data, size_t len);
  // Empties request headers.
  void clear_request_headers();

  size_t get_request_headers_sum() const;

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
  void set_chunked_request(bool f);
  bool get_request_connection_close() const;
  void set_request_connection_close(bool f);
  void set_request_user_agent(std::string user_agent);
  const std::string& get_request_user_agent() const;
  bool get_request_http2_expect_body() const;
  void set_request_http2_expect_body(bool f);
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
  // Returns iterator pointing to the response header with the name
  // |name|. If multiple header have |name| as name, return first
  // occurrence from the beginning. If no such header is found,
  // returns std::end(get_response_headers()). This function must be
  // called after calling normalize_response_headers().
  Headers::const_iterator get_norm_response_header
  (const std::string& name) const;
  // Rewrites the location response header field. This function must
  // be called after calling normalize_response_headers() and
  // normalize_request_headers().
  void rewrite_norm_location_response_header
  (const std::string& upstream_scheme,
   uint16_t upstream_port);
  void add_response_header(std::string name, std::string value);
  void set_last_response_header_value(std::string value);

  void split_add_response_header(const uint8_t *name, size_t namelen,
                                 const uint8_t *value, size_t valuelen,
                                 bool no_index);

  bool get_response_header_key_prev() const;
  void append_last_response_header_key(const char *data, size_t len);
  void append_last_response_header_value(const char *data, size_t len);
  // Empties response headers.
  void clear_response_headers();

  size_t get_response_headers_sum() const;

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
  void add_response_bodylen(size_t amount);
  int64_t get_response_bodylen() const;
  nghttp2_error_code get_response_rst_stream_error_code() const;
  void set_response_rst_stream_error_code(nghttp2_error_code error_code);
  // Inspects HTTP/1 response.  This checks tranfer-encoding etc.
  void inspect_http1_response();
  // Clears some of member variables for response.
  void reset_response();
  bool get_non_final_response() const;
  void set_expect_final_response(bool f);
  bool get_expect_final_response() const;

  // Call this method when there is incoming data in downstream
  // connection.
  int on_read();

  // Change the priority of downstream
  int change_priority(int32_t pri);

  // Maximum buffer size for header name/value pairs.
  static const size_t MAX_HEADERS_SUM = 32768;

  bool get_rst_stream_after_end_stream() const;
  void set_rst_stream_after_end_stream(bool f);
private:
  Headers request_headers_;
  Headers response_headers_;

  std::string request_method_;
  std::string request_path_;
  std::string request_user_agent_;
  std::string request_http2_scheme_;
  std::string request_http2_authority_;
  std::string assembled_request_cookie_;
  std::string http2_settings_;

  // the length of request body
  int64_t request_bodylen_;
  // the length of response body
  int64_t response_bodylen_;

  Upstream *upstream_;
  DownstreamConnection *dconn_;
  // This buffer is used to temporarily store downstream response
  // body. nghttp2 library reads data from this in the callback.
  evbuffer *response_body_buf_;

  size_t request_headers_sum_;
  size_t response_headers_sum_;

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

  bool http2_upgrade_seen_;
  bool http2_settings_seen_;

  bool chunked_request_;
  bool request_connection_close_;
  bool request_header_key_prev_;
  bool request_http2_expect_body_;

  bool chunked_response_;
  bool response_connection_close_;
  bool response_header_key_prev_;
  bool expect_final_response_;
};

} // namespace shrpx

#endif // SHRPX_DOWNSTREAM_H
