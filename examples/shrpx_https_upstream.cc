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
#include "shrpx_https_upstream.h"

#include <cassert>
#include <set>

#include "shrpx_client_handler.h"
#include "shrpx_downstream.h"
#include "shrpx_downstream_connection.h"
#include "shrpx_http.h"
#include "shrpx_config.h"
#include "shrpx_error.h"
#include "util.h"

using namespace spdylay;

namespace shrpx {

namespace {
const size_t SHRPX_HTTPS_UPSTREAM_OUTPUT_UPPER_THRES = 64*1024;
const size_t SHRPX_HTTPS_MAX_HEADER_LENGTH = 64*1024;
} // namespace

HttpsUpstream::HttpsUpstream(ClientHandler *handler)
  : handler_(handler),
    htp_(htparser_new()),
    current_header_length_(0),
    ioctrl_(handler->get_bev())
{
  htparser_init(htp_, htp_type_request);
  htparser_set_userdata(htp_, this);
}

HttpsUpstream::~HttpsUpstream()
{
  free(htp_);
  for(std::deque<Downstream*>::iterator i = downstream_queue_.begin();
      i != downstream_queue_.end(); ++i) {
    delete *i;
  }
}

void HttpsUpstream::reset_current_header_length()
{
  current_header_length_ = 0;
}

namespace {
int htp_msg_begin(htparser *htp)
{
  if(ENABLE_LOG) {
    LOG(INFO) << "Upstream https request start";
  }
  HttpsUpstream *upstream;
  upstream = reinterpret_cast<HttpsUpstream*>(htparser_get_userdata(htp));
  upstream->reset_current_header_length();
  Downstream *downstream = new Downstream(upstream, 0, 0);
  upstream->add_downstream(downstream);
  return 0;
}
} // namespace

namespace {
int htp_methodcb(htparser *htp, const char *data, size_t len)
{
  HttpsUpstream *upstream;
  upstream = reinterpret_cast<HttpsUpstream*>(htparser_get_userdata(htp));
  Downstream *downstream = upstream->get_last_downstream();
  downstream->set_request_method(std::string(data, len));
  return 0;
}
} // namespace

namespace {
int htp_uricb(htparser *htp, const char *data, size_t len)
{
  HttpsUpstream *upstream;
  upstream = reinterpret_cast<HttpsUpstream*>(htparser_get_userdata(htp));
  Downstream *downstream = upstream->get_last_downstream();
  downstream->set_request_path(std::string(data, len));
  return 0;
}
} // namespace

namespace {
int htp_hdrs_begincb(htparser *htp)
{
  if(ENABLE_LOG) {
    LOG(INFO) << "Upstream https request headers start";
  }
  HttpsUpstream *upstream;
  upstream = reinterpret_cast<HttpsUpstream*>(htparser_get_userdata(htp));
  Downstream *downstream = upstream->get_last_downstream();

  int version = htparser_get_major(htp)*100 + htparser_get_minor(htp);
  if(version < 101) {
    downstream->set_request_connection_close(true);
  }
  return 0;
}
} // namespace

namespace {
int htp_hdr_keycb(htparser *htp, const char *data, size_t len)
{
  HttpsUpstream *upstream;
  upstream = reinterpret_cast<HttpsUpstream*>(htparser_get_userdata(htp));
  Downstream *downstream = upstream->get_last_downstream();
  downstream->add_request_header(std::string(data, len), "");
  return 0;
}
} // namespace

namespace {
int htp_hdr_valcb(htparser *htp, const char *data, size_t len)
{
  HttpsUpstream *upstream;
  upstream = reinterpret_cast<HttpsUpstream*>(htparser_get_userdata(htp));
  Downstream *downstream = upstream->get_last_downstream();
  downstream->set_last_request_header_value(std::string(data, len));
  return 0;
}
} // namespace

namespace {
int htp_hdrs_completecb(htparser *htp)
{
  if(ENABLE_LOG) {
    LOG(INFO) << "Upstream https request headers complete";
  }
  HttpsUpstream *upstream;
  upstream = reinterpret_cast<HttpsUpstream*>(htparser_get_userdata(htp));
  Downstream *downstream = upstream->get_last_downstream();

  downstream->set_request_major(htparser_get_major(htp));
  downstream->set_request_minor(htparser_get_minor(htp));

  DownstreamConnection *dconn;
  dconn = upstream->get_client_handler()->get_downstream_connection();

  int rv =  dconn->attach_downstream(downstream);
  if(rv != 0) {
    downstream->set_request_state(Downstream::CONNECT_FAIL);
    downstream->set_downstream_connection(0);
    delete dconn;
    return 1;
  } else {
    downstream->push_request_headers();
    downstream->set_request_state(Downstream::HEADER_COMPLETE);
    return 0;
  }
}
} // namespace

namespace {
int htp_bodycb(htparser *htp, const char *data, size_t len)
{
  HttpsUpstream *upstream;
  upstream = reinterpret_cast<HttpsUpstream*>(htparser_get_userdata(htp));
  Downstream *downstream = upstream->get_last_downstream();
  downstream->push_upload_data_chunk(reinterpret_cast<const uint8_t*>(data),
                                     len);
  return 0;
}
} // namespace

namespace {
int htp_msg_completecb(htparser *htp)
{
  if(ENABLE_LOG) {
    LOG(INFO) << "Upstream https request complete";
  }
  HttpsUpstream *upstream;
  upstream = reinterpret_cast<HttpsUpstream*>(htparser_get_userdata(htp));
  Downstream *downstream = upstream->get_last_downstream();
  downstream->end_upload_data();
  downstream->set_request_state(Downstream::MSG_COMPLETE);
  // Stop further processing to complete this request
  return 1;
}
} // namespace

namespace {
htparse_hooks htp_hooks = {
  htp_msg_begin, /*htparse_hook      on_msg_begin;*/
  htp_methodcb, /*htparse_data_hook method;*/
  0, /* htparse_data_hook scheme;*/
  0, /* htparse_data_hook host; */
  0, /* htparse_data_hook port; */
  0, /* htparse_data_hook path; */
  0, /* htparse_data_hook args; */
  htp_uricb, /* htparse_data_hook uri; */
  htp_hdrs_begincb, /* htparse_hook      on_hdrs_begin; */
  htp_hdr_keycb, /* htparse_data_hook hdr_key; */
  htp_hdr_valcb, /* htparse_data_hook hdr_val; */
  htp_hdrs_completecb, /* htparse_hook      on_hdrs_complete; */
  0, /*htparse_hook      on_new_chunk;*/
  0, /*htparse_hook      on_chunk_complete;*/
  0, /*htparse_hook      on_chunks_complete;*/
  htp_bodycb, /* htparse_data_hook body; */
  htp_msg_completecb /* htparse_hook      on_msg_complete;*/
};
} // namespace

// on_read() does not consume all available data in input buffer if
// one http request is fully received.
int HttpsUpstream::on_read()
{
  bufferevent *bev = handler_->get_bev();
  evbuffer *input = bufferevent_get_input(bev);
  unsigned char *mem = evbuffer_pullup(input, -1);
  int nread = htparser_run(htp_, &htp_hooks,
                           reinterpret_cast<const char*>(mem),
                           evbuffer_get_length(input));
  evbuffer_drain(input, nread);
  // Well, actually header length + some body bytes
  current_header_length_ += nread;
  htpparse_error htperr = htparser_get_error(htp_);
  Downstream *downstream = get_top_downstream();
  if(htperr == htparse_error_user) {
    if(downstream->get_request_state() == Downstream::CONNECT_FAIL) {
      get_client_handler()->set_should_close_after_write(true);
      error_reply(503);
      // Downstream gets deleted after response body is read.
    } else {
      assert(downstream->get_request_state() == Downstream::MSG_COMPLETE);
      if(downstream->get_downstream_connection() == 0) {
        // Error response already be sent
        assert(downstream->get_response_state() == Downstream::MSG_COMPLETE);
        pop_downstream();
        delete downstream;
      } else {
        pause_read(SHRPX_MSG_BLOCK);
      }
    }
  } else if(htperr == htparse_error_none) {
    // downstream can be NULL here.
    if(downstream) {
      if(downstream->get_request_state() == Downstream::INITIAL &&
         current_header_length_ > SHRPX_HTTPS_MAX_HEADER_LENGTH) {
        LOG(WARNING) << "Request Header too long:" << current_header_length_
                     << " bytes";
        get_client_handler()->set_should_close_after_write(true);
        error_reply(400);
      } else if(downstream->get_output_buffer_full()) {
        if(ENABLE_LOG) {
          LOG(INFO) << "Downstream output buffer is full";
        }
        pause_read(SHRPX_NO_BUFFER);
      }
    }
  } else {
    if(ENABLE_LOG) {
      LOG(INFO) << "Upstream http parse failure: "
                << htparser_get_strerror(htp_);
    }
    get_client_handler()->set_should_close_after_write(true);
    error_reply(400);
  }
  return 0;
}

namespace {
void https_downstream_readcb(bufferevent *bev, void *ptr);
} // namespace

int HttpsUpstream::on_write()
{
  Downstream *downstream = get_top_downstream();
  if(downstream) {
    downstream->resume_read(SHRPX_NO_BUFFER);
  }
  return 0;
}

int HttpsUpstream::on_event()
{
  return 0;
}

ClientHandler* HttpsUpstream::get_client_handler() const
{
  return handler_;
}

void HttpsUpstream::pause_read(IOCtrlReason reason)
{
  ioctrl_.pause_read(reason);
}

void HttpsUpstream::resume_read(IOCtrlReason reason)
{
  if(ioctrl_.resume_read(reason)) {
    // Process remaining data in input buffer here because these bytes
    // are not notified by readcb until new data arrive.
    on_read();
  }
}

namespace {
void https_downstream_readcb(bufferevent *bev, void *ptr)
{
  DownstreamConnection *dconn = reinterpret_cast<DownstreamConnection*>(ptr);
  Downstream *downstream = dconn->get_downstream();
  HttpsUpstream *upstream;
  upstream = static_cast<HttpsUpstream*>(downstream->get_upstream());
  int rv = downstream->parse_http_response();
  if(rv == 0) {
    if(downstream->get_response_state() == Downstream::MSG_COMPLETE) {
      if(downstream->get_response_connection_close()) {
        // Connection close
        downstream->set_downstream_connection(0);
        delete dconn;
        dconn = 0;
      } else {
        // Keep-alive
        dconn->detach_downstream(downstream);
      }
      if(downstream->get_request_state() == Downstream::MSG_COMPLETE) {
        upstream->pop_downstream();
        delete downstream;
        // Process next HTTP request
        upstream->resume_read(SHRPX_MSG_BLOCK);
      }
    } else {
      ClientHandler *handler = upstream->get_client_handler();
      bufferevent *bev = handler->get_bev();
      size_t outputlen = evbuffer_get_length(bufferevent_get_output(bev));
      if(outputlen > SHRPX_HTTPS_UPSTREAM_OUTPUT_UPPER_THRES) {
        downstream->pause_read(SHRPX_NO_BUFFER);
      }
    }
  } else {
    if(downstream->get_response_state() == Downstream::HEADER_COMPLETE) {
      // We already sent HTTP response headers to upstream
      // client. Just close the upstream connection.
      delete upstream->get_client_handler();
    } else {
      // We did not sent any HTTP response, so sent error
      // response. Cannot reuse downstream connection in this case.
      upstream->error_reply(502);
      if(downstream->get_request_state() == Downstream::MSG_COMPLETE) {
        upstream->pop_downstream();
        delete downstream;
        // Process next HTTP request
        upstream->resume_read(SHRPX_MSG_BLOCK);
      }
    }
  }
}
} // namespace

namespace {
void https_downstream_writecb(bufferevent *bev, void *ptr)
{
  DownstreamConnection *dconn = reinterpret_cast<DownstreamConnection*>(ptr);
  Downstream *downstream = dconn->get_downstream();
  HttpsUpstream *upstream;
  upstream = static_cast<HttpsUpstream*>(downstream->get_upstream());
  upstream->resume_read(SHRPX_NO_BUFFER);
}
} // namespace

namespace {
void https_downstream_eventcb(bufferevent *bev, short events, void *ptr)
{
  DownstreamConnection *dconn = reinterpret_cast<DownstreamConnection*>(ptr);
  Downstream *downstream = dconn->get_downstream();
  HttpsUpstream *upstream;
  upstream = static_cast<HttpsUpstream*>(downstream->get_upstream());
  if(events & BEV_EVENT_CONNECTED) {
    if(ENABLE_LOG) {
      LOG(INFO) << "Downstream connection established. downstream "
                << downstream;
    }
  } else if(events & BEV_EVENT_EOF) {
    if(ENABLE_LOG) {
      LOG(INFO) << "Downstream EOF. stream_id="
                << downstream->get_stream_id();
    }
    if(downstream->get_response_state() == Downstream::HEADER_COMPLETE) {
      // Server may indicate the end of the request by EOF
      if(ENABLE_LOG) {
        LOG(INFO) << "Assuming downstream content-length is 0 byte";
      }
      upstream->on_downstream_body_complete(downstream);
      //downstream->set_response_state(Downstream::MSG_COMPLETE);
    } else if(downstream->get_response_state() == Downstream::MSG_COMPLETE) {
      // Nothing to do
    } else {
      // error
      if(ENABLE_LOG) {
        LOG(INFO) << "Treated as downstream error";
      }
      upstream->error_reply(502);
    }
    if(downstream->get_request_state() == Downstream::MSG_COMPLETE) {
      upstream->pop_downstream();
      delete downstream;
      upstream->resume_read(SHRPX_MSG_BLOCK);
    }
  } else if(events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
    if(ENABLE_LOG) {
      LOG(INFO) << "Downstream error/timeout. " << downstream;
    }
    if(downstream->get_response_state() == Downstream::INITIAL) {
      int status;
      if(events & BEV_EVENT_TIMEOUT) {
        status = 504;
      } else {
        status = 502;
      }
      upstream->error_reply(status);
    }
    if(downstream->get_request_state() == Downstream::MSG_COMPLETE) {
      upstream->pop_downstream();
      delete downstream;
      upstream->resume_read(SHRPX_MSG_BLOCK);
    }
  }
}
} // namespace

void HttpsUpstream::error_reply(int status_code)
{
  std::string html = http::create_error_html(status_code);
  std::stringstream ss;
  ss << "HTTP/1.1 " << http::get_status_string(status_code) << "\r\n"
     << "Server: " << get_config()->server_name << "\r\n"
     << "Content-Length: " << html.size() << "\r\n"
     << "Content-Type: " << "text/html; charset=UTF-8\r\n";
  if(get_client_handler()->get_should_close_after_write()) {
    ss << "Connection: close\r\n";
  }
  ss << "\r\n";
  std::string header = ss.str();
  evbuffer *output = bufferevent_get_output(handler_->get_bev());
  evbuffer_add(output, header.c_str(), header.size());
  evbuffer_add(output, html.c_str(), html.size());
  Downstream *downstream = get_top_downstream();
  if(downstream) {
    downstream->set_response_state(Downstream::MSG_COMPLETE);
  }
}

bufferevent_data_cb HttpsUpstream::get_downstream_readcb()
{
  return https_downstream_readcb;
}

bufferevent_data_cb HttpsUpstream::get_downstream_writecb()
{
  return https_downstream_writecb;
}

bufferevent_event_cb HttpsUpstream::get_downstream_eventcb()
{
  return https_downstream_eventcb;
}

void HttpsUpstream::add_downstream(Downstream *downstream)
{
  downstream_queue_.push_back(downstream);
}

void HttpsUpstream::pop_downstream()
{
  downstream_queue_.pop_front();
}

Downstream* HttpsUpstream::get_top_downstream()
{
  if(downstream_queue_.empty()) {
    return 0;
  } else {
    return downstream_queue_.front();
  }
}

Downstream* HttpsUpstream::get_last_downstream()
{
  if(downstream_queue_.empty()) {
    return 0;
  } else {
    return downstream_queue_.back();
  }
}

int HttpsUpstream::on_downstream_header_complete(Downstream *downstream)
{
  if(ENABLE_LOG) {
    LOG(INFO) << "Downstream on_downstream_header_complete";
  }
  std::string via_value;
  std::string hdrs = "HTTP/1.1 ";
  hdrs += http::get_status_string(downstream->get_response_http_status());
  hdrs += "\r\n";
  for(Headers::const_iterator i = downstream->get_response_headers().begin();
      i != downstream->get_response_headers().end(); ++i) {
    if(util::strieq((*i).first.c_str(), "keep-alive") || // HTTP/1.0?
       util::strieq((*i).first.c_str(), "connection") ||
       util:: strieq((*i).first.c_str(), "proxy-connection")) {
      // These are ignored
    } else if(util::strieq((*i).first.c_str(), "via")) {
      via_value = (*i).second;
    } else {
      hdrs += (*i).first;
      hdrs += ": ";
      hdrs += (*i).second;
      hdrs += "\r\n";
    }
  }
  if(get_client_handler()->get_should_close_after_write()) {
    hdrs += "Connection: close\r\n";
  } else if(downstream->get_request_major() == 1 &&
            downstream->get_request_minor() == 0) {
    hdrs += "Connection: Keep-Alive\r\n";
  }
  hdrs += "Via: ";
  hdrs += via_value;
  if(!via_value.empty()) {
    hdrs += ", ";
  }
  hdrs += http::create_via_header_value
    (downstream->get_response_major(), downstream->get_response_minor());
  hdrs += "\r\n";
  hdrs += "\r\n";
  if(ENABLE_LOG) {
    LOG(INFO) << "Upstream https response headers\n" << hdrs;
  }
  evbuffer *output = bufferevent_get_output(handler_->get_bev());
  evbuffer_add(output, hdrs.c_str(), hdrs.size());
  return 0;
}

int HttpsUpstream::on_downstream_body(Downstream *downstream,
                                      const uint8_t *data, size_t len)
{
  int rv;
  evbuffer *output = bufferevent_get_output(handler_->get_bev());
  if(downstream->get_chunked_response()) {
    char chunk_size_hex[16];
    rv = snprintf(chunk_size_hex, sizeof(chunk_size_hex), "%X\r\n",
                  static_cast<unsigned int>(len));
    evbuffer_add(output, chunk_size_hex, rv);
  }
  evbuffer_add(output, data, len);
  return 0;
}

int HttpsUpstream::on_downstream_body_complete(Downstream *downstream)
{
  if(downstream->get_chunked_response()) {
    evbuffer *output = bufferevent_get_output(handler_->get_bev());
    evbuffer_add(output, "0\r\n\r\n", 5);
  }
  if(ENABLE_LOG) {
    LOG(INFO) << "Downstream on_downstream_body_complete";
  }
  if(downstream->get_request_connection_close()) {
    ClientHandler *handler = downstream->get_upstream()->get_client_handler();
    handler->set_should_close_after_write(true);
  }
  return 0;
}

} // namespace shrpx
