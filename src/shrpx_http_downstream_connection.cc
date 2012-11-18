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
#include "shrpx_http_downstream_connection.h"

#include "shrpx_client_handler.h"
#include "shrpx_upstream.h"
#include "shrpx_downstream.h"
#include "shrpx_config.h"
#include "shrpx_error.h"
#include "shrpx_http.h"
#include "util.h"

using namespace spdylay;

namespace shrpx {

// Workaround for the inability for Bufferevent to remove timeout from
// bufferevent. Specify this long timeout instead of removing.
namespace {
timeval max_timeout = { 86400, 0 };
} // namespace

HttpDownstreamConnection::HttpDownstreamConnection
(ClientHandler *client_handler)
  : DownstreamConnection(client_handler)
{}

HttpDownstreamConnection::~HttpDownstreamConnection()
{}

int HttpDownstreamConnection::attach_downstream(Downstream *downstream)
{
  if(ENABLE_LOG) {
    LOG(INFO) << "Attaching downstream connection " << this << " to "
              << "downstream " << downstream;
  }
  Upstream *upstream = downstream->get_upstream();
  if(!bev_) {
    event_base *evbase = client_handler_->get_evbase();
    bev_ = bufferevent_socket_new
      (evbase, -1,
       BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    int rv = bufferevent_socket_connect
      (bev_,
       // TODO maybe not thread-safe?
       const_cast<sockaddr*>(&get_config()->downstream_addr.sa),
       get_config()->downstream_addrlen);
    if(rv != 0) {
      bufferevent_free(bev_);
      bev_ = 0;
      return SHRPX_ERR_NETWORK;
    }
    if(ENABLE_LOG) {
      LOG(INFO) << "Connecting to downstream server " << this;
    }
  }
  downstream->set_downstream_connection(this);
  downstream_ = downstream;
  bufferevent_setwatermark(bev_, EV_READ, 0, SHRPX_READ_WARTER_MARK);
  bufferevent_enable(bev_, EV_READ);
  bufferevent_setcb(bev_,
                    upstream->get_downstream_readcb(),
                    upstream->get_downstream_writecb(),
                    upstream->get_downstream_eventcb(), this);
  // HTTP request/response model, we first issue request to downstream
  // server, so just enable write timeout here.
  bufferevent_set_timeouts(bev_,
                           &max_timeout,
                           &get_config()->downstream_write_timeout);
  return 0;
}

int HttpDownstreamConnection::push_request_headers()
{
  std::string hdrs = downstream_->get_request_method();
  hdrs += " ";
  hdrs += downstream_->get_request_path();
  hdrs += " ";
  hdrs += "HTTP/1.1\r\n";
  std::string via_value;
  std::string xff_value;
  const Headers& request_headers = downstream_->get_request_headers();
  for(Headers::const_iterator i = request_headers.begin();
      i != request_headers.end(); ++i) {
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
  if(downstream_->get_request_connection_close()) {
    hdrs += "Connection: close\r\n";
  }
  if(get_config()->add_x_forwarded_for) {
    hdrs += "X-Forwarded-For: ";
    if(!xff_value.empty()) {
      hdrs += xff_value;
      hdrs += ", ";
    }
    hdrs += downstream_->get_upstream()->get_client_handler()->get_ipaddr();
    hdrs += "\r\n";
  } else if(!xff_value.empty()) {
    hdrs += "X-Forwarded-For: ";
    hdrs += xff_value;
    hdrs += "\r\n";
  }
  if(downstream_->get_request_method() != "CONNECT") {
    hdrs += "X-Forwarded-Proto: ";
    if(util::istartsWith(downstream_->get_request_path(), "http:")) {
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
  hdrs += http::create_via_header_value(downstream_->get_request_major(),
                                        downstream_->get_request_minor());
  hdrs += "\r\n";

  hdrs += "\r\n";
  if(ENABLE_LOG) {
    LOG(INFO) << "Downstream request headers id="
              << downstream_->get_stream_id() << "\n" << hdrs;
  }
  evbuffer *output = bufferevent_get_output(bev_);
  int rv;
  rv = evbuffer_add(output, hdrs.c_str(), hdrs.size());
  if(rv != 0) {
    return -1;
  }
  start_waiting_response();
  return 0;
}

int HttpDownstreamConnection::push_upload_data_chunk
(const uint8_t *data, size_t datalen)
{
  ssize_t res = 0;
  int rv;
  int chunked = downstream_->get_chunked_request();
  evbuffer *output = bufferevent_get_output(bev_);
  if(chunked) {
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
  if(chunked) {
    rv = evbuffer_add(output, "\r\n", 2);
    if(rv == -1) {
      LOG(FATAL) << "evbuffer_add() failed";
      return -1;
    }
    res += 2;
  }
  return res;
}

int HttpDownstreamConnection::end_upload_data()
{
  if(downstream_->get_chunked_request()) {
    evbuffer *output = bufferevent_get_output(bev_);
    if(evbuffer_add(output, "0\r\n\r\n", 5) != 0) {
      LOG(FATAL) << "evbuffer_add() failed";
      return -1;
    }
  }
  return 0;
}

int HttpDownstreamConnection::on_connect()
{
  return 0;
}

} // namespace shrpx
