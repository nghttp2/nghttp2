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
#include "shrpx_downstream.h"

#include <cassert>

#include "http-parser/http_parser.h"

#include "shrpx_upstream.h"
#include "shrpx_client_handler.h"
#include "shrpx_config.h"
#include "shrpx_error.h"
#include "shrpx_downstream_connection.h"
#include "util.h"
#include "http2.h"

namespace shrpx {

Downstream::Downstream(Upstream *upstream, int stream_id, int priority)
  : request_bodylen_(0),
    upstream_(upstream),
    dconn_(nullptr),
    response_body_buf_(nullptr),
    request_headers_sum_(0),
    response_headers_sum_(0),
    stream_id_(stream_id),
    priority_(priority),
    downstream_stream_id_(-1),
    response_rst_stream_error_code_(NGHTTP2_NO_ERROR),
    request_state_(INITIAL),
    request_major_(1),
    request_minor_(1),
    response_state_(INITIAL),
    response_http_status_(0),
    response_major_(1),
    response_minor_(1),
    upgrade_request_(false),
    upgraded_(false),
    chunked_request_(false),
    request_connection_close_(false),
    request_expect_100_continue_(false),
    request_header_key_prev_(false),
    chunked_response_(false),
    response_connection_close_(false),
    response_header_key_prev_(false)
{}

Downstream::~Downstream()
{
  if(LOG_ENABLED(INFO)) {
    DLOG(INFO, this) << "Deleting";
  }
  if(response_body_buf_) {
    // Passing NULL to evbuffer_free() causes segmentation fault.
    evbuffer_free(response_body_buf_);
  }
  if(dconn_) {
    delete dconn_;
  }
  if(LOG_ENABLED(INFO)) {
    DLOG(INFO, this) << "Deleted";
  }
}

void Downstream::set_downstream_connection(DownstreamConnection *dconn)
{
  dconn_ = dconn;
}

DownstreamConnection* Downstream::get_downstream_connection()
{
  return dconn_;
}

void Downstream::pause_read(IOCtrlReason reason)
{
  if(dconn_) {
    dconn_->pause_read(reason);
  }
}

int Downstream::resume_read(IOCtrlReason reason)
{
  if(dconn_) {
    return dconn_->resume_read(reason);
  } else {
    return 0;
  }
}

void Downstream::force_resume_read()
{
  if(dconn_) {
    dconn_->force_resume_read();
  }
}

namespace {
void check_header_field(bool *result, const Headers::value_type &item,
                        const char *name, const char *value)
{
  if(util::strieq(item.first.c_str(), name)) {
    if(util::strifind(item.second.c_str(), value)) {
      *result = true;
    }
  }
}
} // namespace

namespace {
void check_transfer_encoding_chunked(bool *chunked,
                                     const Headers::value_type &item)
{
  return check_header_field(chunked, item, "transfer-encoding", "chunked");
}
} // namespace

namespace {
void check_expect_100_continue(bool *res,
                               const Headers::value_type& item)
{
  return check_header_field(res, item, "expect", "100-continue");
}
} // namespace

namespace {
Headers::const_iterator get_norm_header(const Headers& headers,
                                        const std::string& name)
{
  auto i = std::lower_bound(std::begin(headers), std::end(headers),
                            std::make_pair(name, ""), http2::name_less);
  if(i != std::end(headers) && (*i).first == name) {
    return i;
  }
  return std::end(headers);
}
} // namespace

namespace {
Headers::iterator get_norm_header(Headers& headers, const std::string& name)
{
  auto i = std::lower_bound(std::begin(headers), std::end(headers),
                            std::make_pair(name, ""), http2::name_less);
  if(i != std::end(headers) && (*i).first == name) {
    return i;
  }
  return std::end(headers);
}
} // namespace

const Headers& Downstream::get_request_headers() const
{
  return request_headers_;
}

void Downstream::assemble_request_cookie()
{
  std::string& cookie = assembled_request_cookie_;
  cookie = "";
  for(auto& kv : request_headers_) {
    if(util::strieq("cookie", kv.first.c_str())) {
      auto end = kv.second.find_last_not_of(" ;");
      if(end == std::string::npos) {
        cookie += kv.second;
      } else {
        cookie.append(std::begin(kv.second), std::begin(kv.second) + end + 1);
      }
      cookie += "; ";
    }
  }
  if(cookie.size() >= 2) {
    cookie.erase(cookie.size() - 2);
  }
}

void Downstream::crumble_request_cookie()
{
  Headers cookie_hdrs;
  for(auto& kv : request_headers_) {
    if(util::strieq("cookie", kv.first.c_str())) {
      size_t last = kv.second.size();
      size_t num = 0;
      std::string rep_cookie;

      for(size_t j = 0; j < last;) {
        j = kv.second.find_first_not_of("\t ;", j);
        if(j == std::string::npos) {
          break;
        }
        auto first = j;

        j = kv.second.find(';', j);
        if(j == std::string::npos) {
          j = last;
        }

        if(num == 0) {
          if(first == 0 && j == last) {
            break;
          }
          rep_cookie = kv.second.substr(first, j - first);
        } else {
          cookie_hdrs.push_back
            (std::make_pair("cookie", kv.second.substr(first, j - first)));
        }
        ++num;
      }
      if(num > 0) {
        kv.second = std::move(rep_cookie);
      }
    }
  }
  request_headers_.insert(std::end(request_headers_),
                          std::begin(cookie_hdrs), std::end(cookie_hdrs));
}

const std::string& Downstream::get_assembled_request_cookie() const
{
  return assembled_request_cookie_;
}

void Downstream::normalize_request_headers()
{
  http2::normalize_headers(request_headers_);
}

Headers::const_iterator Downstream::get_norm_request_header
(const std::string& name) const
{
  return get_norm_header(request_headers_, name);
}

void Downstream::concat_norm_request_headers()
{
  request_headers_ = http2::concat_norm_headers(std::move(request_headers_));
}

void Downstream::add_request_header(std::string name, std::string value)
{
  request_header_key_prev_ = true;
  request_headers_sum_ += name.size() + value.size();
  request_headers_.emplace_back(std::move(name), std::move(value));
}

void Downstream::set_last_request_header_value(std::string value)
{
  request_header_key_prev_ = false;
  request_headers_sum_ += value.size();
  Headers::value_type &item = request_headers_.back();
  item.second = std::move(value);
  check_transfer_encoding_chunked(&chunked_request_, item);
  check_expect_100_continue(&request_expect_100_continue_, item);
}

void Downstream::split_add_request_header
(const uint8_t *name, size_t namelen,
 const uint8_t *value, size_t valuelen)
{
  request_headers_sum_ += namelen + valuelen;
  http2::split_add_header(request_headers_, name, namelen, value, valuelen);
}

bool Downstream::get_request_header_key_prev() const
{
  return request_header_key_prev_;
}

void Downstream::append_last_request_header_key(const char *data, size_t len)
{
  assert(request_header_key_prev_);
  request_headers_sum_ += len;
  auto& item = request_headers_.back();
  item.first.append(data, len);
}

void Downstream::append_last_request_header_value(const char *data, size_t len)
{
  assert(!request_header_key_prev_);
  request_headers_sum_ += len;
  auto& item = request_headers_.back();
  item.second.append(data, len);
}

size_t Downstream::get_request_headers_sum() const
{
  return request_headers_sum_;
}

void Downstream::set_request_method(std::string method)
{
  request_method_ = std::move(method);
}

const std::string& Downstream::get_request_method() const
{
  return request_method_;
}

void Downstream::set_request_path(std::string path)
{
  request_path_ = std::move(path);
}

void Downstream::append_request_path(const char *data, size_t len)
{
  request_path_.append(data, len);
}

const std::string& Downstream::get_request_path() const
{
  return request_path_;
}

const std::string& Downstream::get_request_http2_scheme() const
{
  return request_http2_scheme_;
}

void Downstream::set_request_http2_scheme(std::string scheme)
{
  request_http2_scheme_ = std::move(scheme);
}

const std::string& Downstream::get_request_http2_authority() const
{
  return request_http2_authority_;
}

void Downstream::set_request_http2_authority(std::string authority)
{
  request_http2_authority_ = std::move(authority);
}

void Downstream::set_request_major(int major)
{
  request_major_ = major;
}

void Downstream::set_request_minor(int minor)
{
  request_minor_ = minor;
}

int Downstream::get_request_major() const
{
  return request_major_;
}

int Downstream::get_request_minor() const
{
  return request_minor_;
}

void Downstream::reset_upstream(Upstream* upstream)
{
  upstream_ = upstream;
  if(dconn_) {
    dconn_->on_upstream_change(upstream);
  }
}

Upstream* Downstream::get_upstream() const
{
  return upstream_;
}

void Downstream::set_stream_id(int32_t stream_id)
{
  stream_id_ = stream_id;
}

int32_t Downstream::get_stream_id() const
{
  return stream_id_;
}

void Downstream::set_request_state(int state)
{
  request_state_ = state;
}

int Downstream::get_request_state() const
{
  return request_state_;
}

bool Downstream::get_chunked_request() const
{
  return chunked_request_;
}

bool Downstream::get_request_connection_close() const
{
  return request_connection_close_;
}

void Downstream::set_request_connection_close(bool f)
{
  request_connection_close_ = f;
}

bool Downstream::get_expect_100_continue() const
{
  return request_expect_100_continue_;
}

bool Downstream::get_output_buffer_full()
{
  if(dconn_) {
    return dconn_->get_output_buffer_full();
  } else {
    return false;
  }
}

// Call this function after this object is attached to
// Downstream. Otherwise, the program will crash.
int Downstream::push_request_headers()
{
  if(!dconn_) {
    DLOG(INFO, this) << "dconn_ is NULL";
    return -1;
  }
  return dconn_->push_request_headers();
}

int Downstream::push_upload_data_chunk(const uint8_t *data, size_t datalen)
{
  // Assumes that request headers have already been pushed to output
  // buffer using push_request_headers().
  if(!dconn_) {
    DLOG(INFO, this) << "dconn_ is NULL";
    return -1;
  }
  request_bodylen_ += datalen;
  return dconn_->push_upload_data_chunk(data, datalen);
}

int Downstream::end_upload_data()
{
  if(!dconn_) {
    DLOG(INFO, this) << "dconn_ is NULL";
    return -1;
  }
  return dconn_->end_upload_data();
}

const Headers& Downstream::get_response_headers() const
{
  return response_headers_;
}

void Downstream::normalize_response_headers()
{
  http2::normalize_headers(response_headers_);
}

void Downstream::concat_norm_response_headers()
{
  response_headers_ = http2::concat_norm_headers(std::move(response_headers_));
}

Headers::const_iterator Downstream::get_norm_response_header
(const std::string& name) const
{
  return get_norm_header(response_headers_, name);
}

void Downstream::rewrite_norm_location_response_header
(const std::string& upstream_scheme,
 uint16_t upstream_port)
{
  auto hd = get_norm_header(response_headers_, "location");
  if(hd == std::end(response_headers_)) {
    return;
  }
  http_parser_url u;
  memset(&u, 0, sizeof(u));
  int rv = http_parser_parse_url((*hd).second.c_str(), (*hd).second.size(),
                                 0, &u);
  if(rv != 0) {
    return;
  }
  std::string new_uri;
  if(!request_http2_authority_.empty()) {
    new_uri = http2::rewrite_location_uri((*hd).second, u,
                                          request_http2_authority_,
                                          upstream_scheme, upstream_port);
  }
  if(new_uri.empty()) {
    auto host = get_norm_request_header("host");
    if(host == std::end(request_headers_)) {
      return;
    }
    new_uri = http2::rewrite_location_uri((*hd).second, u, (*host).second,
                                          upstream_scheme, upstream_port);
  }
  if(!new_uri.empty()) {
    (*hd).second = std::move(new_uri);
  }
}

void Downstream::add_response_header(std::string name, std::string value)
{
  response_header_key_prev_ = true;
  response_headers_sum_ += name.size() + value.size();
  response_headers_.emplace_back(std::move(name), std::move(value));
  check_transfer_encoding_chunked(&chunked_response_,
                                  response_headers_.back());
}

void Downstream::set_last_response_header_value(std::string value)
{
  response_header_key_prev_ = false;
  response_headers_sum_ += value.size();
  auto& item = response_headers_.back();
  item.second = std::move(value);
  check_transfer_encoding_chunked(&chunked_response_, item);
}

void Downstream::split_add_response_header
(const uint8_t *name, size_t namelen,
 const uint8_t *value, size_t valuelen)
{
  response_headers_sum_ += namelen + valuelen;
  http2::split_add_header(response_headers_, name, namelen, value, valuelen);
}

bool Downstream::get_response_header_key_prev() const
{
  return response_header_key_prev_;
}

void Downstream::append_last_response_header_key(const char *data, size_t len)
{
  assert(response_header_key_prev_);
  response_headers_sum_ += len;
  auto& item = response_headers_.back();
  item.first.append(data, len);
}

void Downstream::append_last_response_header_value(const char *data,
                                                   size_t len)
{
  assert(!response_header_key_prev_);
  response_headers_sum_ += len;
  auto& item = response_headers_.back();
  item.second.append(data, len);
}

size_t Downstream::get_response_headers_sum() const
{
  return response_headers_sum_;
}

unsigned int Downstream::get_response_http_status() const
{
  return response_http_status_;
}

void Downstream::set_response_http_status(unsigned int status)
{
  response_http_status_ = status;
}

void Downstream::set_response_major(int major)
{
  response_major_ = major;
}

void Downstream::set_response_minor(int minor)
{
  response_minor_ = minor;
}

int Downstream::get_response_major() const
{
  return response_major_;
}

int Downstream::get_response_minor() const
{
  return response_minor_;
}

int Downstream::get_response_version() const
{
  return response_major_*100+response_minor_;
}

bool Downstream::get_chunked_response() const
{
  return chunked_response_;
}

void Downstream::set_chunked_response(bool f)
{
  chunked_response_ = f;
}

bool Downstream::get_response_connection_close() const
{
  return response_connection_close_;
}

void Downstream::set_response_connection_close(bool f)
{
  response_connection_close_ = f;
}

int Downstream::on_read()
{
  if(!dconn_) {
    DLOG(INFO, this) << "dconn_ is NULL";
    return -1;
  }
  return dconn_->on_read();
}

int Downstream::change_priority(int32_t pri)
{
  if(!dconn_) {
    DLOG(INFO, this) << "dconn_ is NULL";
    return -1;
  }
  return dconn_->on_priority_change(pri);
}

void Downstream::set_response_state(int state)
{
  response_state_ = state;
}

int Downstream::get_response_state() const
{
  return response_state_;
}

int Downstream::init_response_body_buf()
{
  if(!response_body_buf_) {
    response_body_buf_ = evbuffer_new();
    if(response_body_buf_ == nullptr) {
      DIE();
    }
  }
  return 0;
}

evbuffer* Downstream::get_response_body_buf()
{
  return response_body_buf_;
}

void Downstream::set_priority(int32_t pri)
{
  priority_ = pri;
}

int32_t Downstream::get_priority() const
{
  return priority_;
}

void Downstream::check_upgrade_fulfilled()
{
  if(request_method_ == "CONNECT") {
    upgraded_ = 200 <= response_http_status_ && response_http_status_ < 300;
  } else {
    // TODO Do more strict checking for upgrade headers
    if(response_http_status_ == 101) {
      for(auto& hd : request_headers_) {
        if(util::strieq("upgrade", hd.first.c_str())) {
          upgraded_ = true;
          break;
        }
      }
    }
  }
}

bool Downstream::get_upgraded() const
{
  return upgraded_;
}

void Downstream::check_upgrade_request()
{
  if(request_method_ == "CONNECT") {
    upgrade_request_ = true;
  } else {
    // TODO Do more strict checking for upgrade headers
    for(auto& hd : request_headers_) {
      if(util::strieq("upgrade", hd.first.c_str())) {
        upgrade_request_ = true;
        break;
      }
    }
  }
}

bool Downstream::get_upgrade_request() const
{
  return upgrade_request_;
}

bool Downstream::http2_upgrade_request() const
{
  if(request_bodylen_ != 0) {
    return false;
  }
  bool upgrade_seen = false;
  bool http2_settings_seen = false;
  for(auto& hd : request_headers_) {
    // For now just check NGHTTP2_CLEARTEXT_PROTO_VERSION_ID in
    // Upgrade header field and existence of HTTP2-Settings header
    // field.
    if(util::strieq(hd.first.c_str(), "upgrade")) {
       if(util::strieq(hd.second.c_str(),
                       NGHTTP2_CLEARTEXT_PROTO_VERSION_ID)) {
        upgrade_seen = true;
      }
    } else if(util::strieq(hd.first.c_str(), "http2-settings")) {
      http2_settings_seen = true;
    }
  }
  return upgrade_seen && http2_settings_seen;
}

void Downstream::set_downstream_stream_id(int32_t stream_id)
{
  downstream_stream_id_ = stream_id;
}

int32_t Downstream::get_downstream_stream_id() const
{
  return downstream_stream_id_;
}

nghttp2_error_code Downstream::get_response_rst_stream_error_code() const
{
  return response_rst_stream_error_code_;
}

void Downstream::set_response_rst_stream_error_code
(nghttp2_error_code error_code)
{
  response_rst_stream_error_code_ = error_code;
}

} // namespace shrpx
