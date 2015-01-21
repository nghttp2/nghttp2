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
#include <memory>
#include <chrono>

#include <ev.h>

#include <nghttp2/nghttp2.h>

#include "shrpx_io_control.h"
#include "http2.h"
#include "memchunk.h"

using namespace nghttp2;

namespace shrpx {

class Upstream;
class DownstreamConnection;

class Downstream {
public:
  Downstream(Upstream *upstream, int32_t stream_id, int32_t priority);
  ~Downstream();
  void reset_upstream(Upstream *upstream);
  Upstream *get_upstream() const;
  void set_stream_id(int32_t stream_id);
  int32_t get_stream_id() const;
  void set_priority(int32_t pri);
  int32_t get_priority() const;
  void pause_read(IOCtrlReason reason);
  int resume_read(IOCtrlReason reason, size_t consumed);
  void force_resume_read();
  // Set stream ID for downstream HTTP2 connection.
  void set_downstream_stream_id(int32_t stream_id);
  int32_t get_downstream_stream_id() const;

  int attach_downstream_connection(std::unique_ptr<DownstreamConnection> dconn);
  void detach_downstream_connection();
  // Releases dconn_, without freeing it.
  void release_downstream_connection();
  DownstreamConnection *get_downstream_connection();
  // Returns dconn_ and nullifies dconn_.
  std::unique_ptr<DownstreamConnection> pop_downstream_connection();

  // Returns true if output buffer is full. If underlying dconn_ is
  // NULL, this function always returns false.
  bool request_buf_full();
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
  const std::string &get_http2_settings() const;
  // downstream request API
  const Headers &get_request_headers() const;
  // Crumbles (split cookie by ";") in request_headers_ and returns
  // them.  Headers::no_index is inherited.
  Headers crumble_request_cookie();
  void assemble_request_cookie();
  const std::string &get_assembled_request_cookie() const;
  // Lower the request header field names and indexes request headers.
  // If there is any invalid headers (e.g., multiple Content-Length
  // having different values), returns -1.
  int index_request_headers();
  // Returns pointer to the request header with the name |name|.  If
  // multiple header have |name| as name, return last occurrence from
  // the beginning.  If no such header is found, returns nullptr.
  // This function must be called after headers are indexed
  const Headers::value_type *get_request_header(int token) const;
  // Returns pointer to the request header with the name |name|.  If
  // no such header is found, returns nullptr.
  const Headers::value_type *get_request_header(const std::string &name) const;
  void add_request_header(std::string name, std::string value);
  void set_last_request_header_value(std::string value);

  void add_request_header(const uint8_t *name, size_t namelen,
                          const uint8_t *value, size_t valuelen, bool no_index,
                          int token);

  bool get_request_header_key_prev() const;
  void append_last_request_header_key(const char *data, size_t len);
  void append_last_request_header_value(const char *data, size_t len);
  // Empties request headers.
  void clear_request_headers();

  size_t get_request_headers_sum() const;

  void set_request_method(std::string method);
  const std::string &get_request_method() const;
  void set_request_path(std::string path);
  void
  set_request_start_time(std::chrono::high_resolution_clock::time_point time);
  const std::chrono::high_resolution_clock::time_point &
  get_request_start_time() const;
  void append_request_path(const char *data, size_t len);
  // Returns request path. For HTTP/1.1, this is request-target. For
  // HTTP/2, this is :path header field value.
  const std::string &get_request_path() const;
  // Returns HTTP/2 :scheme header field value.
  const std::string &get_request_http2_scheme() const;
  void set_request_http2_scheme(std::string scheme);
  // Returns HTTP/2 :authority header field value.
  const std::string &get_request_http2_authority() const;
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
  bool get_request_http2_expect_body() const;
  void set_request_http2_expect_body(bool f);
  int push_upload_data_chunk(const uint8_t *data, size_t datalen);
  int end_upload_data();
  size_t get_request_datalen() const;
  void dec_request_datalen(size_t len);
  void reset_request_datalen();
  // Validates that received request body length and content-length
  // matches.
  bool validate_request_bodylen() const;
  int64_t get_request_content_length() const;
  void set_request_content_length(int64_t len);
  bool request_pseudo_header_allowed(int token) const;
  bool expect_response_body() const;
  enum {
    INITIAL,
    HEADER_COMPLETE,
    MSG_COMPLETE,
    STREAM_CLOSED,
    CONNECT_FAIL,
    IDLE,
    MSG_RESET,
    // header contains invalid header field.  We can safely send error
    // response (502) to a client.
    MSG_BAD_HEADER,
  };
  void set_request_state(int state);
  int get_request_state() const;
  DefaultMemchunks *get_request_buf();
  // downstream response API
  const Headers &get_response_headers() const;
  // Lower the response header field names and indexes response
  // headers.  If there are invalid headers (e.g., multiple
  // Content-Length with different values), returns -1.
  int index_response_headers();
  // Returns pointer to the response header with the name |name|.  If
  // multiple header have |name| as name, return last occurrence from
  // the beginning.  If no such header is found, returns nullptr.
  // This function must be called after response headers are indexed.
  const Headers::value_type *get_response_header(int token) const;
  // Rewrites the location response header field.
  void rewrite_location_response_header(const std::string &upstream_scheme,
                                        uint16_t upstream_port);
  void add_response_header(std::string name, std::string value);
  void set_last_response_header_value(std::string value);

  void add_response_header(const uint8_t *name, size_t namelen,
                           const uint8_t *value, size_t valuelen, bool no_index,
                           int token);

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
  DefaultMemchunks *get_response_buf();
  bool response_buf_full();
  void add_response_bodylen(size_t amount);
  int64_t get_response_bodylen() const;
  void add_response_sent_bodylen(size_t amount);
  int64_t get_response_sent_bodylen() const;
  int64_t get_response_content_length() const;
  void set_response_content_length(int64_t len);
  // Validates that received response body length and content-length
  // matches.
  bool validate_response_bodylen() const;
  uint32_t get_response_rst_stream_error_code() const;
  void set_response_rst_stream_error_code(uint32_t error_code);
  // Inspects HTTP/1 response.  This checks tranfer-encoding etc.
  void inspect_http1_response();
  // Clears some of member variables for response.
  void reset_response();
  bool get_non_final_response() const;
  void set_expect_final_response(bool f);
  bool get_expect_final_response() const;
  void add_response_datalen(size_t len);
  void dec_response_datalen(size_t len);
  size_t get_response_datalen() const;
  void reset_response_datalen();
  bool response_pseudo_header_allowed(int token) const;

  // Call this method when there is incoming data in downstream
  // connection.
  int on_read();

  // Change the priority of downstream
  int change_priority(int32_t pri);

  // Maximum buffer size for header name/value pairs.
  static const size_t MAX_HEADERS_SUM = 32768;

  bool get_rst_stream_after_end_stream() const;
  void set_rst_stream_after_end_stream(bool f);

  // Resets upstream read timer.  If it is active, timeout value is
  // reset.  If it is not active, timer will be started.
  void reset_upstream_rtimer();
  // Resets upstream write timer. If it is active, timeout value is
  // reset.  If it is not active, timer will be started.  This
  // function also resets read timer if it has been started.
  void reset_upstream_wtimer();
  // Makes sure that upstream write timer is started.  If it has been
  // started, do nothing.  Otherwise, write timer will be started.
  void ensure_upstream_wtimer();
  // Disables upstream read timer.
  void disable_upstream_rtimer();
  // Disables upstream write timer.
  void disable_upstream_wtimer();

  // Downstream timer functions.  They works in a similar way just
  // like the upstream timer function.
  void reset_downstream_rtimer();
  void reset_downstream_wtimer();
  void ensure_downstream_wtimer();
  void disable_downstream_rtimer();
  void disable_downstream_wtimer();

  // Returns true if accesslog can be written for this downstream.
  bool accesslog_ready() const;

  enum {
    EVENT_ERROR = 0x1,
    EVENT_TIMEOUT = 0x2,
  };

private:
  Headers request_headers_;
  Headers response_headers_;

  std::chrono::high_resolution_clock::time_point request_start_time_;

  std::string request_method_;
  std::string request_path_;
  std::string request_http2_scheme_;
  std::string request_http2_authority_;
  std::string assembled_request_cookie_;

  DefaultMemchunks request_buf_;
  DefaultMemchunks response_buf_;

  ev_timer upstream_rtimer_;
  ev_timer upstream_wtimer_;

  ev_timer downstream_rtimer_;
  ev_timer downstream_wtimer_;

  // the length of request body received so far
  int64_t request_bodylen_;
  // the length of response body received so far
  int64_t response_bodylen_;

  // the length of response body sent to upstream client
  int64_t response_sent_bodylen_;

  // content-length of request body, -1 if it is unknown.
  int64_t request_content_length_;
  // content-length of response body, -1 if it is unknown.
  int64_t response_content_length_;

  Upstream *upstream_;
  std::unique_ptr<DownstreamConnection> dconn_;

  size_t request_headers_sum_;
  size_t response_headers_sum_;

  // The number of bytes not consumed by the application yet.
  size_t request_datalen_;
  size_t response_datalen_;

  int32_t stream_id_;
  int32_t priority_;
  // stream ID in backend connection
  int32_t downstream_stream_id_;

  // RST_STREAM error_code from downstream HTTP2 connection
  uint32_t response_rst_stream_error_code_;

  int request_state_;
  int request_major_;
  int request_minor_;

  int response_state_;
  unsigned int response_http_status_;
  int response_major_;
  int response_minor_;

  int request_hdidx_[http2::HD_MAXIDX];
  int response_hdidx_[http2::HD_MAXIDX];

  // true if the request contains upgrade token (HTTP Upgrade or
  // CONNECT)
  bool upgrade_request_;
  // true if the connection is upgraded (HTTP Upgrade or CONNECT)
  bool upgraded_;

  bool http2_upgrade_seen_;

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
