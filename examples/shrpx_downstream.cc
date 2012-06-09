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
    response_state_(INITIAL),
    response_http_status_(0),
    response_major_(1),
    response_minor_(1),
    chunked_response_(false),
    response_connection_close_(false),
    response_htp_(htparser_new()),
    response_body_buf_(0)
{
  htparser_init(response_htp_, htp_type_response);
  htparser_set_userdata(response_htp_, this);
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
  free(response_htp_);
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
void check_transfer_encoding_chunked(bool *chunked,
                                     const Headers::value_type &item)
{
  if(util::strieq(item.first.c_str(), "transfer-encoding")) {
    if(util::strifind(item.second.c_str(), "chunked")) {
      *chunked = true;
    }
  }
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
  request_headers_.push_back(std::make_pair(name, value));
}

void Downstream::set_last_request_header_value(const std::string& value)
{
  Headers::value_type &item = request_headers_.back();
  item.second = value;
  check_transfer_encoding_chunked(&chunked_request_, item);
  check_connection_close(&request_connection_close_, item);
}

void Downstream::set_request_method(const std::string& method)
{
  request_method_ = method;
}

void Downstream::set_request_path(const std::string& path)
{
  request_path_ = path;
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

int Downstream::push_request_headers()
{
  bool xff_found = false;
  std::string hdrs = request_method_;
  hdrs += " ";
  hdrs += request_path_;
  hdrs += " ";
  hdrs += "HTTP/1.1\r\n";
  hdrs += "Host: ";
  hdrs += get_config()->downstream_hostport;
  hdrs += "\r\n";
  std::string via_value;
  for(Headers::const_iterator i = request_headers_.begin();
      i != request_headers_.end(); ++i) {
    if(util::strieq((*i).first.c_str(), "X-Forwarded-Proto")) {
      continue;
    }
    if(util::strieq((*i).first.c_str(), "via")) {
      via_value = (*i).second;
      continue;
    }
    if(util::strieq((*i).first.c_str(), "host")) {
      continue;
    }
    hdrs += (*i).first;
    hdrs += ": ";
    hdrs += (*i).second;
    if(!xff_found && util::strieq((*i).first.c_str(), "X-Forwarded-For")) {
      xff_found = true;
      hdrs += ", ";
      hdrs += upstream_->get_client_handler()->get_ipaddr();
    }
    hdrs += "\r\n";
  }
  if(request_connection_close_) {
    hdrs += "Connection: close\r\n";
  }
  if(!xff_found) {
    hdrs += "X-Forwarded-For: ";
    hdrs += upstream_->get_client_handler()->get_ipaddr();
    hdrs += "\r\n";
  }
  hdrs += "X-Forwarded-Proto: https\r\n";

  hdrs += "Via: ";
  hdrs += via_value;
  if(!via_value.empty()) {
    hdrs += ", ";
  }
  hdrs += http::create_via_header_value(request_major_, request_minor_);
  hdrs += "\r\n";

  hdrs += "\r\n";
  if(ENABLE_LOG) {
    LOG(INFO) << "Downstream request headers\n" << hdrs;
  }
  bufferevent *bev = dconn_->get_bev();
  evbuffer *output = bufferevent_get_output(bev);
  evbuffer_add(output, hdrs.c_str(), hdrs.size());
  return 0;
}

int Downstream::push_upload_data_chunk(const uint8_t *data, size_t datalen)
{
  // Assumes that request headers have already been pushed to output
  // buffer using push_request_headers().
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
      return -1;
    }
  }
  rv = evbuffer_add(output, data, datalen);
  if(rv == -1) {
    return -1;
  }
  res += rv;
  return res;
}

int Downstream::end_upload_data()
{
  if(chunked_request_) {
    bufferevent *bev = dconn_->get_bev();
    evbuffer *output = bufferevent_get_output(bev);
    evbuffer_add(output, "0\r\n\r\n", 5);
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
  response_headers_.push_back(std::make_pair(name, value));
}

void Downstream::set_last_response_header_value(const std::string& value)
{
  Headers::value_type &item = response_headers_.back();
  item.second = value;
  check_transfer_encoding_chunked(&chunked_response_, item);
  check_connection_close(&response_connection_close_, item);
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

bool Downstream::get_chunked_response() const
{
  return chunked_response_;
}

bool Downstream::get_response_connection_close() const
{
  return response_connection_close_;
}

namespace {
int htp_hdrs_completecb(htparser *htp)
{
  Downstream *downstream;
  downstream = reinterpret_cast<Downstream*>(htparser_get_userdata(htp));
  downstream->set_response_http_status(htparser_get_status(htp));
  downstream->set_response_major(htparser_get_major(htp));
  downstream->set_response_minor(htparser_get_minor(htp));
  downstream->set_response_state(Downstream::HEADER_COMPLETE);
  downstream->get_upstream()->on_downstream_header_complete(downstream);
  return 0;
}
} // namespace

namespace {
int htp_hdr_keycb(htparser *htp, const char *data, size_t len)
{
  Downstream *downstream;
  downstream = reinterpret_cast<Downstream*>(htparser_get_userdata(htp));
  downstream->add_response_header(std::string(data, len), "");
  return 0;
}
} // namespace

namespace {
int htp_hdr_valcb(htparser *htp, const char *data, size_t len)
{
  Downstream *downstream;
  downstream = reinterpret_cast<Downstream*>(htparser_get_userdata(htp));
  downstream->set_last_response_header_value(std::string(data, len));
  return 0;
}
} // namespace

namespace {
int htp_bodycb(htparser *htp, const char *data, size_t len)
{
  Downstream *downstream;
  downstream = reinterpret_cast<Downstream*>(htparser_get_userdata(htp));
  downstream->get_upstream()->on_downstream_body
    (downstream, reinterpret_cast<const uint8_t*>(data), len);
  return 0;
}
} // namespace

namespace {
int htp_body_completecb(htparser *htp)
{
  Downstream *downstream;
  downstream = reinterpret_cast<Downstream*>(htparser_get_userdata(htp));
  downstream->set_response_state(Downstream::MSG_COMPLETE);
  downstream->get_upstream()->on_downstream_body_complete(downstream);
  return 0;
}
} // namespace

namespace {
htparse_hooks htp_hooks = {
  0, /*htparse_hook      on_msg_begin;*/
  0, /*htparse_data_hook method;*/
  0, /* htparse_data_hook scheme;*/
  0, /* htparse_data_hook host; */
  0, /* htparse_data_hook port; */
  0, /* htparse_data_hook path; */
  0, /* htparse_data_hook args; */
  0, /* htparse_data_hook uri; */
  0, /* htparse_hook      on_hdrs_begin; */
  htp_hdr_keycb, /* htparse_data_hook hdr_key; */
  htp_hdr_valcb, /* htparse_data_hook hdr_val; */
  htp_hdrs_completecb, /* htparse_hook      on_hdrs_complete; */
  0, /*htparse_hook      on_new_chunk;*/
  0, /*htparse_hook      on_chunk_complete;*/
  0, /*htparse_hook      on_chunks_complete;*/
  htp_bodycb, /* htparse_data_hook body; */
  htp_body_completecb /* htparse_hook      on_msg_complete;*/
};
} // namespace

int Downstream::parse_http_response()
{
  bufferevent *bev = dconn_->get_bev();
  evbuffer *input = bufferevent_get_input(bev);
  unsigned char *mem = evbuffer_pullup(input, -1);
  size_t nread = htparser_run(response_htp_, &htp_hooks,
                              reinterpret_cast<const char*>(mem),
                              evbuffer_get_length(input));
  evbuffer_drain(input, nread);
  if(htparser_get_error(response_htp_) == htparse_error_none) {
    return 0;
  } else {
    if(ENABLE_LOG) {
      LOG(INFO) << "Downstream HTTP parser failure: "
                << htparser_get_strerror(response_htp_);
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

} // namespace shrpx
