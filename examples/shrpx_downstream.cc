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
#include "shrpx_downstream.h"

#include <cassert>

#include "shrpx_upstream.h"
#include "shrpx_client_handler.h"
#include "shrpx_config.h"
#include "shrpx_error.h"
#include "shrpx_http.h"
#include "shrpx_downstream_connection.h"
#include "util.h"

using namespace spdylay;

namespace shrpx {

Downstream::Downstream(Upstream *upstream, int stream_id, int priority)
  : upstream_(upstream),
    dconn_(0),
    stream_id_(stream_id),
    priority_(priority),
    ioctrl_(0),
    request_state_(INITIAL),
    request_major_(1),
    request_minor_(1),
    chunked_request_(false),
    request_connection_close_(false),
    request_expect_100_continue_(false),
    request_header_key_prev_(false),
    response_state_(INITIAL),
    response_http_status_(0),
    response_major_(1),
    response_minor_(1),
    chunked_response_(false),
    response_connection_close_(false),
    response_header_key_prev_(false),
    response_htp_(new http_parser()),
    response_body_buf_(0),
    recv_window_size_(0)
{
  http_parser_init(response_htp_, HTTP_RESPONSE);
  response_htp_->data = this;
}

Downstream::~Downstream()
{
  if(ENABLE_LOG) {
    LOG(INFO) << "Deleting downstream " << this;
  }
  if(response_body_buf_) {
    // Passing NULL to evbuffer_free() causes segmentation fault.
    evbuffer_free(response_body_buf_);
  }
  if(dconn_) {
    delete dconn_;
  }
  delete response_htp_;
  if(ENABLE_LOG) {
    LOG(INFO) << "Deleted";
  }
}

void Downstream::set_downstream_connection(DownstreamConnection *dconn)
{
  dconn_ = dconn;
  if(dconn_) {
    ioctrl_.set_bev(dconn_->get_bev());
  } else {
    ioctrl_.set_bev(0);
  }
}

DownstreamConnection* Downstream::get_downstream_connection()
{
  return dconn_;
}

void Downstream::pause_read(IOCtrlReason reason)
{
  ioctrl_.pause_read(reason);
}

bool Downstream::resume_read(IOCtrlReason reason)
{
  return ioctrl_.resume_read(reason);
}

void Downstream::force_resume_read()
{
  ioctrl_.force_resume_read();
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
void check_connection_close(bool *connection_close,
                            const Headers::value_type &item)
{
  if(util::strieq(item.first.c_str(), "connection")) {
    if(util::strifind(item.second.c_str(), "close")) {
      *connection_close = true;
    } else if(util::strifind(item.second.c_str(), "keep-alive")) {
      *connection_close = false;
    }
  }
}
} // namespace

void Downstream::add_request_header(const std::string& name,
                                    const std::string& value)
{
  request_header_key_prev_ = true;
  request_headers_.push_back(std::make_pair(name, value));
}

void Downstream::set_last_request_header_value(const std::string& value)
{
  request_header_key_prev_ = false;
  Headers::value_type &item = request_headers_.back();
  item.second = value;
  check_transfer_encoding_chunked(&chunked_request_, item);
  check_expect_100_continue(&request_expect_100_continue_, item);
  //check_connection_close(&request_connection_close_, item);
}

bool Downstream::get_request_header_key_prev() const
{
  return request_header_key_prev_;
}

void Downstream::append_last_request_header_key(const char *data, size_t len)
{
  assert(request_header_key_prev_);
  Headers::value_type &item = request_headers_.back();
  item.first.append(data, len);
}

void Downstream::append_last_request_header_value(const char *data, size_t len)
{
  assert(!request_header_key_prev_);
  Headers::value_type &item = request_headers_.back();
  item.second.append(data, len);
}

void Downstream::set_request_method(const std::string& method)
{
  request_method_ = method;
}

const std::string& Downstream::get_request_method() const
{
  return request_method_;
}

void Downstream::set_request_path(const std::string& path)
{
  request_path_ = path;
}

void Downstream::append_request_path(const char *data, size_t len)
{
  request_path_.append(data, len);
}

const std::string& Downstream::get_request_path() const
{
  return request_path_;
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

Upstream* Downstream::get_upstream() const
{
  return upstream_;
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

namespace {
const size_t DOWNSTREAM_OUTPUT_UPPER_THRES = 64*1024;
} // namespace

bool Downstream::get_output_buffer_full()
{
  if(dconn_) {
    bufferevent *bev = dconn_->get_bev();
    evbuffer *output = bufferevent_get_output(bev);
    return evbuffer_get_length(output) >= DOWNSTREAM_OUTPUT_UPPER_THRES;
  } else {
    return false;
  }
}

// Call this function after this object is attached to
// Downstream. Otherwise, the program will crash.
int Downstream::push_request_headers()
{
  std::string hdrs = request_method_;
  hdrs += " ";
  hdrs += request_path_;
  hdrs += " ";
  hdrs += "HTTP/1.1\r\n";
  std::string via_value;
  std::string xff_value;
  for(Headers::const_iterator i = request_headers_.begin();
      i != request_headers_.end(); ++i) {
    if(util::strieq((*i).first.c_str(), "X-Forwarded-Proto") ||
       util::strieq((*i).first.c_str(), "keep-alive") ||
       util::strieq((*i).first.c_str(), "connection") ||
       util::strieq((*i).first.c_str(), "proxy-connection")) {
      continue;
    }
    if(util::strieq((*i).first.c_str(), "via")) {
      via_value = (*i).second;
      continue;
    }
    if(util::strieq((*i).first.c_str(), "x-forwarded-for")) {
      xff_value = (*i).second;
      continue;
    }
    if(util::strieq((*i).first.c_str(), "expect") &&
       util::strifind((*i).second.c_str(), "100-continue")) {
      continue;
    }
    hdrs += (*i).first;
    hdrs += ": ";
    hdrs += (*i).second;
    hdrs += "\r\n";
  }
  if(request_connection_close_) {
    hdrs += "Connection: close\r\n";
  }
  if(get_config()->add_x_forwarded_for) {
    hdrs += "X-Forwarded-For: ";
    if(!xff_value.empty()) {
      hdrs += xff_value;
      hdrs += ", ";
    }
    hdrs += upstream_->get_client_handler()->get_ipaddr();
    hdrs += "\r\n";
  } else if(!xff_value.empty()) {
    hdrs += "X-Forwarded-For: ";
    hdrs += xff_value;
    hdrs += "\r\n";
  }
  if(request_method_ != "CONNECT") {
    hdrs += "X-Forwarded-Proto: ";
    if(util::istartsWith(request_path_, "http:")) {
      hdrs += "http";
    } else {
      hdrs += "https";
    }
    hdrs += "\r\n";
  }
  hdrs += "Via: ";
  hdrs += via_value;
  if(!via_value.empty()) {
    hdrs += ", ";
  }
  hdrs += http::create_via_header_value(request_major_, request_minor_);
  hdrs += "\r\n";

  hdrs += "\r\n";
  if(ENABLE_LOG) {
    LOG(INFO) << "Downstream request headers id="
              << stream_id_ << "\n" << hdrs;
  }
  bufferevent *bev = dconn_->get_bev();
  evbuffer *output = bufferevent_get_output(bev);
  int rv;
  rv = evbuffer_add(output, hdrs.c_str(), hdrs.size());
  if(rv != 0) {
    return -1;
  }

  dconn_->start_waiting_response();
  return 0;
}

int Downstream::push_upload_data_chunk(const uint8_t *data, size_t datalen)
{
  // Assumes that request headers have already been pushed to output
  // buffer using push_request_headers().
  if(!dconn_) {
    LOG(WARNING) << "dconn_ is NULL";
    return 0;
  }
  ssize_t res = 0;
  int rv;
  bufferevent *bev = dconn_->get_bev();
  evbuffer *output = bufferevent_get_output(bev);
  if(chunked_request_) {
    char chunk_size_hex[16];
    rv = snprintf(chunk_size_hex, sizeof(chunk_size_hex), "%X\r\n",
                  static_cast<unsigned int>(datalen));
    res += rv;
    rv = evbuffer_add(output, chunk_size_hex, rv);
    if(rv == -1) {
      LOG(FATAL) << "evbuffer_add() failed";
      return -1;
    }
  }
  rv = evbuffer_add(output, data, datalen);
  if(rv == -1) {
    LOG(FATAL) << "evbuffer_add() failed";
    return -1;
  }
  res += rv;
  if(chunked_request_) {
    rv = evbuffer_add(output, "\r\n", 2);
    if(rv == -1) {
      LOG(FATAL) << "evbuffer_add() failed";
      return -1;
    }
    res += 2;
  }
  return res;
}

int Downstream::end_upload_data()
{
  if(chunked_request_) {
    bufferevent *bev = dconn_->get_bev();
    evbuffer *output = bufferevent_get_output(bev);
    if(evbuffer_add(output, "0\r\n\r\n", 5) != 0) {
      LOG(FATAL) << "evbuffer_add() failed";
      return -1;
    }
  }
  return 0;
}

const Headers& Downstream::get_response_headers() const
{
  return response_headers_;
}

void Downstream::add_response_header(const std::string& name,
                                     const std::string& value)
{
  response_header_key_prev_ = true;
  response_headers_.push_back(std::make_pair(name, value));
}

void Downstream::set_last_response_header_value(const std::string& value)
{
  response_header_key_prev_ = false;
  Headers::value_type &item = response_headers_.back();
  item.second = value;
  check_transfer_encoding_chunked(&chunked_response_, item);
  //check_connection_close(&response_connection_close_, item);
}

bool Downstream::get_response_header_key_prev() const
{
  return response_header_key_prev_;
}

void Downstream::append_last_response_header_key(const char *data, size_t len)
{
  assert(response_header_key_prev_);
  Headers::value_type &item = response_headers_.back();
  item.first.append(data, len);
}

void Downstream::append_last_response_header_value(const char *data,
                                                   size_t len)
{
  assert(!response_header_key_prev_);
  Headers::value_type &item = response_headers_.back();
  item.second.append(data, len);
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

bool Downstream::get_response_connection_close() const
{
  return response_connection_close_;
}

void Downstream::set_response_connection_close(bool f)
{
  response_connection_close_ = f;
}

namespace {
int htp_hdrs_completecb(http_parser *htp)
{
  Downstream *downstream;
  downstream = reinterpret_cast<Downstream*>(htp->data);
  downstream->set_response_http_status(htp->status_code);
  downstream->set_response_major(htp->http_major);
  downstream->set_response_minor(htp->http_minor);
  downstream->set_response_connection_close(!http_should_keep_alive(htp));
  downstream->set_response_state(Downstream::HEADER_COMPLETE);
  if(downstream->get_upstream()->on_downstream_header_complete(downstream)
     != 0) {
    return -1;
  }
  unsigned int status = downstream->get_response_http_status();
  // Ignore the response body. HEAD response may contain
  // Content-Length or Transfer-Encoding: chunked.  Some server send
  // 304 status code with nonzero Content-Length, but without response
  // body. See
  // http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-20#section-3.3
  return downstream->get_request_method() == "HEAD" ||
    (100 <= status && status <= 199) || status == 204 ||
    status == 304 ? 1 : 0;
}
} // namespace

namespace {
int htp_hdr_keycb(http_parser *htp, const char *data, size_t len)
{
  Downstream *downstream;
  downstream = reinterpret_cast<Downstream*>(htp->data);
  if(downstream->get_response_header_key_prev()) {
    downstream->append_last_response_header_key(data, len);
  } else {
    downstream->add_response_header(std::string(data, len), "");
  }
  return 0;
}
} // namespace

namespace {
int htp_hdr_valcb(http_parser *htp, const char *data, size_t len)
{
  Downstream *downstream;
  downstream = reinterpret_cast<Downstream*>(htp->data);
  if(downstream->get_response_header_key_prev()) {
    downstream->set_last_response_header_value(std::string(data, len));
  } else {
    downstream->append_last_response_header_value(data, len);
  }
  return 0;
}
} // namespace

namespace {
int htp_bodycb(http_parser *htp, const char *data, size_t len)
{
  Downstream *downstream;
  downstream = reinterpret_cast<Downstream*>(htp->data);

  return downstream->get_upstream()->on_downstream_body
    (downstream, reinterpret_cast<const uint8_t*>(data), len);
}
} // namespace

namespace {
int htp_msg_completecb(http_parser *htp)
{
  Downstream *downstream;
  downstream = reinterpret_cast<Downstream*>(htp->data);

  downstream->set_response_state(Downstream::MSG_COMPLETE);
  return downstream->get_upstream()->on_downstream_body_complete(downstream);
}
} // namespace

namespace {
http_parser_settings htp_hooks = {
  0, /*http_cb      on_message_begin;*/
  0, /*http_data_cb on_url;*/
  htp_hdr_keycb, /*http_data_cb on_header_field;*/
  htp_hdr_valcb, /*http_data_cb on_header_value;*/
  htp_hdrs_completecb, /*http_cb      on_headers_complete;*/
  htp_bodycb, /*http_data_cb on_body;*/
  htp_msg_completecb /*http_cb      on_message_complete;*/
};
} // namespace

int Downstream::parse_http_response()
{
  bufferevent *bev = dconn_->get_bev();
  evbuffer *input = bufferevent_get_input(bev);
  unsigned char *mem = evbuffer_pullup(input, -1);

  size_t nread = http_parser_execute(response_htp_, &htp_hooks,
                                     reinterpret_cast<const char*>(mem),
                                     evbuffer_get_length(input));

  evbuffer_drain(input, nread);
  http_errno htperr = HTTP_PARSER_ERRNO(response_htp_);
  if(htperr == HPE_OK) {
    return 0;
  } else {
    if(ENABLE_LOG) {
      LOG(INFO) << "Downstream HTTP parser failure: "
                << "(" << http_errno_name(htperr) << ") "
                << http_errno_description(htperr);
    }
    return SHRPX_ERR_HTTP_PARSE;
  }
}

void Downstream::set_response_state(int state)
{
  response_state_ = state;
}

int Downstream::get_response_state() const
{
  return response_state_;
}

namespace {
void body_buf_cb(evbuffer *body, size_t oldlen, size_t newlen, void *arg)
{
  Downstream *downstream = reinterpret_cast<Downstream*>(arg);
  if(newlen == 0) {
    downstream->resume_read(SHRPX_NO_BUFFER);
  }
}
} // namespace

int Downstream::init_response_body_buf()
{
  if(!response_body_buf_) {
    response_body_buf_ = evbuffer_new();
    if(response_body_buf_ == 0) {
      DIE();
    }
    evbuffer_setcb(response_body_buf_, body_buf_cb, this);
  }
  return 0;
}

evbuffer* Downstream::get_response_body_buf()
{
  return response_body_buf_;
}

void Downstream::set_priority(int pri)
{
  priority_ = pri;
}

int32_t Downstream::get_recv_window_size() const
{
  return recv_window_size_;
}

void Downstream::inc_recv_window_size(int32_t amount)
{
  recv_window_size_ += amount;
}

void Downstream::set_recv_window_size(int32_t new_size)
{
  recv_window_size_ = new_size;
}

bool Downstream::tunnel_established() const
{
  return request_method_ == "CONNECT" &&
    200 <= response_http_status_ && response_http_status_ < 300;
}

} // namespace shrpx
