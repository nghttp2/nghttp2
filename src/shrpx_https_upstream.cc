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
#include "shrpx_https_upstream.h"

#include <cassert>
#include <set>
#include <sstream>

#include "shrpx_client_handler.h"
#include "shrpx_downstream.h"
#include "shrpx_downstream_connection.h"
#include "shrpx_http2_downstream_connection.h"
#include "shrpx_http.h"
#include "shrpx_config.h"
#include "shrpx_error.h"
#include "shrpx_worker_config.h"
#include "http2.h"
#include "util.h"

using namespace nghttp2;

namespace shrpx {

namespace {
const size_t OUTBUF_MAX_THRES = 16*1024;
} // namespace

HttpsUpstream::HttpsUpstream(ClientHandler *handler)
  : handler_(handler),
    current_header_length_(0),
    downstream_(nullptr),
    ioctrl_(handler->get_bev())
{
  http_parser_init(&htp_, HTTP_REQUEST);
  htp_.data = this;
}

HttpsUpstream::~HttpsUpstream()
{
  delete downstream_;
}

void HttpsUpstream::reset_current_header_length()
{
  current_header_length_ = 0;
}

namespace {
int htp_msg_begin(http_parser *htp)
{
  auto upstream = static_cast<HttpsUpstream*>(htp->data);
  if(LOG_ENABLED(INFO)) {
    ULOG(INFO, upstream) << "HTTP request started";
  }
  upstream->reset_current_header_length();
  // TODO specify 0 as priority for now
  auto downstream = new Downstream(upstream, 0, 0);
  upstream->attach_downstream(downstream);
  return 0;
}
} // namespace

namespace {
int htp_uricb(http_parser *htp, const char *data, size_t len)
{
  auto upstream = static_cast<HttpsUpstream*>(htp->data);
  auto downstream = upstream->get_downstream();
  downstream->append_request_path(data, len);
  return 0;
}
} // namespace

namespace {
int htp_hdr_keycb(http_parser *htp, const char *data, size_t len)
{
  auto upstream = static_cast<HttpsUpstream*>(htp->data);
  auto downstream = upstream->get_downstream();
  if(downstream->get_request_header_key_prev()) {
    downstream->append_last_request_header_key(data, len);
  } else {
    downstream->add_request_header(std::string(data, len), "");
  }
  if(downstream->get_request_headers_sum() > Downstream::MAX_HEADERS_SUM) {
    if(LOG_ENABLED(INFO)) {
      ULOG(INFO, upstream) << "Too large header block size="
                           << downstream->get_request_headers_sum();
    }
    return -1;
  }
  return 0;
}
} // namespace

namespace {
int htp_hdr_valcb(http_parser *htp, const char *data, size_t len)
{
  auto upstream = static_cast<HttpsUpstream*>(htp->data);
  auto downstream = upstream->get_downstream();
  if(downstream->get_request_header_key_prev()) {
    downstream->set_last_request_header_value(std::string(data, len));
  } else {
    downstream->append_last_request_header_value(data, len);
  }
  if(downstream->get_request_headers_sum() > Downstream::MAX_HEADERS_SUM) {
    if(LOG_ENABLED(INFO)) {
      ULOG(INFO, upstream) << "Too large header block size="
                           << downstream->get_request_headers_sum();
    }
    return -1;
  }
  return 0;
}
} // namespace

namespace {
int htp_hdrs_completecb(http_parser *htp)
{
  int rv;
  auto upstream = static_cast<HttpsUpstream*>(htp->data);
  if(LOG_ENABLED(INFO)) {
    ULOG(INFO, upstream) << "HTTP request headers completed";
  }
  auto downstream = upstream->get_downstream();

  downstream->set_request_method(http_method_str((enum http_method)htp->method));
  downstream->set_request_major(htp->http_major);
  downstream->set_request_minor(htp->http_minor);

  downstream->set_request_connection_close(!http_should_keep_alive(htp));

  if(LOG_ENABLED(INFO)) {
    std::stringstream ss;
    ss << downstream->get_request_method() << " "
       << downstream->get_request_path() << " "
       << "HTTP/" << downstream->get_request_major() << "."
       << downstream->get_request_minor() << "\n";
    const auto& headers = downstream->get_request_headers();
    for(size_t i = 0; i < headers.size(); ++i) {
      ss << TTY_HTTP_HD << headers[i].name << TTY_RST << ": "
         << headers[i].value << "\n";
    }
    ULOG(INFO, upstream) << "HTTP request headers\n" << ss.str();
  }

  downstream->normalize_request_headers();
  auto& nva = downstream->get_request_headers();

  auto user_agent = http2::get_header(nva, "user-agent");

  downstream->set_request_user_agent(http2::value_to_str(user_agent));

  downstream->inspect_http1_request();

  if(get_config()->client_proxy &&
     downstream->get_request_method() != "CONNECT") {
    // Make sure that request path is an absolute URI.
    http_parser_url u;
    auto url = downstream->get_request_path().c_str();
    memset(&u, 0, sizeof(u));
    rv = http_parser_parse_url(url,
                               downstream->get_request_path().size(),
                               0, &u);
    if(rv != 0 || !(u.field_set & (1 << UF_SCHEMA))) {
      // Expect to respond with 400 bad request
      return -1;
    }
  }

  auto dconn = upstream->get_client_handler()->get_downstream_connection();

  rv =  dconn->attach_downstream(downstream);

  if(rv != 0) {
    downstream->set_request_state(Downstream::CONNECT_FAIL);
    downstream->set_downstream_connection(nullptr);
    delete dconn;
    return -1;
  }

  rv = downstream->push_request_headers();

  if(rv != 0) {
    return -1;
  }

  downstream->set_request_state(Downstream::HEADER_COMPLETE);

  return 0;
}
} // namespace

namespace {
int htp_bodycb(http_parser *htp, const char *data, size_t len)
{
  int rv;
  auto upstream = static_cast<HttpsUpstream*>(htp->data);
  auto downstream = upstream->get_downstream();
  rv = downstream->push_upload_data_chunk
    (reinterpret_cast<const uint8_t*>(data), len);
  if(rv != 0) {
    return -1;
  }
  return 0;
}
} // namespace

namespace {
int htp_msg_completecb(http_parser *htp)
{
  int rv;
  auto upstream = static_cast<HttpsUpstream*>(htp->data);
  if(LOG_ENABLED(INFO)) {
    ULOG(INFO, upstream) << "HTTP request completed";
  }
  auto downstream = upstream->get_downstream();
  downstream->set_request_state(Downstream::MSG_COMPLETE);
  rv = downstream->end_upload_data();
  if(rv != 0) {
    return -1;
  }
  // Stop further processing to complete this request
  http_parser_pause(htp, 1);
  return 0;
}
} // namespace

namespace {
http_parser_settings htp_hooks = {
  htp_msg_begin, // http_cb      on_message_begin;
  htp_uricb, // http_data_cb on_url;
  nullptr, // http_data_cb on_status;
  htp_hdr_keycb, // http_data_cb on_header_field;
  htp_hdr_valcb, // http_data_cb on_header_value;
  htp_hdrs_completecb, // http_cb      on_headers_complete;
  htp_bodycb, // http_data_cb on_body;
  htp_msg_completecb // http_cb      on_message_complete;
};
} // namespace


// on_read() does not consume all available data in input buffer if
// one http request is fully received.
int HttpsUpstream::on_read()
{
  auto bev = handler_->get_bev();
  auto input = bufferevent_get_input(bev);
  auto downstream = get_downstream();

  // downstream can be nullptr here, because it is initialized in the
  // callback chain called by http_parser_execute()
  if(downstream && downstream->get_upgraded()) {
    for(;;) {
      auto inputlen = evbuffer_get_contiguous_space(input);

      if(inputlen == 0) {
        return 0;
      }

      auto mem = evbuffer_pullup(input, inputlen);

      auto rv = downstream->push_upload_data_chunk
        (reinterpret_cast<const uint8_t*>(mem), inputlen);

      if(rv != 0) {
        return -1;
      }

      if(evbuffer_drain(input, inputlen) != 0) {
        ULOG(FATAL, this) << "evbuffer_drain() failed";
        return -1;
      }

      if(downstream->get_output_buffer_full()) {
        if(LOG_ENABLED(INFO)) {
          ULOG(INFO, this) << "Downstream output buffer is full";
        }
        pause_read(SHRPX_NO_BUFFER);

        return 0;
      }
    }
  }

  for(;;) {
    auto inputlen = evbuffer_get_contiguous_space(input);

    if(inputlen == 0) {
      return 0;
    }

    auto mem = evbuffer_pullup(input, inputlen);

    auto nread = http_parser_execute(&htp_, &htp_hooks,
                                     reinterpret_cast<const char*>(mem),
                                     inputlen);

    if(evbuffer_drain(input, nread) != 0) {
      ULOG(FATAL, this) << "evbuffer_drain() failed";
      return -1;
    }

    // Well, actually header length + some body bytes
    current_header_length_ += nread;

    // Get downstream again because it may be initialized in http parser
    // execution
    downstream = get_downstream();

    auto handler = get_client_handler();
    auto htperr = HTTP_PARSER_ERRNO(&htp_);

    if(htperr == HPE_PAUSED) {

      assert(downstream);

      if(downstream->get_request_state() == Downstream::CONNECT_FAIL) {
        handler->set_should_close_after_write(true);
        // Following paues_read is needed to avoid reading next data.
        pause_read(SHRPX_MSG_BLOCK);
        if(error_reply(503) != 0) {
          return -1;
        }
        // Downstream gets deleted after response body is read.
        return 0;
      }

      assert(downstream->get_request_state() == Downstream::MSG_COMPLETE);

      if(downstream->get_downstream_connection() == nullptr) {
        // Error response has already be sent
        assert(downstream->get_response_state() == Downstream::MSG_COMPLETE);
        delete_downstream();

        return 0;
      }

      if(handler->get_http2_upgrade_allowed() &&
         downstream->get_http2_upgrade_request()) {

        if(handler->perform_http2_upgrade(this) != 0) {
          return -1;
        }

        return 0;
      }

      pause_read(SHRPX_MSG_BLOCK);

      return 0;
    }

    if(htperr != HPE_OK) {
      if(LOG_ENABLED(INFO)) {
        ULOG(INFO, this) << "HTTP parse failure: "
                         << "(" << http_errno_name(htperr) << ") "
                         << http_errno_description(htperr);
      }

      handler->set_should_close_after_write(true);
      pause_read(SHRPX_MSG_BLOCK);

      if(error_reply(400) != 0) {
        return -1;
      }

      return 0;
    }

    // downstream can be NULL here.
    if(downstream && downstream->get_output_buffer_full()) {
      if(LOG_ENABLED(INFO)) {
        ULOG(INFO, this) << "Downstream output buffer is full";
      }

      pause_read(SHRPX_NO_BUFFER);

      return 0;
    }
  }
}

int HttpsUpstream::on_write()
{
  int rv = 0;
  auto downstream = get_downstream();
  if(downstream) {
    rv = downstream->resume_read(SHRPX_NO_BUFFER);
  }
  return rv;
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

int HttpsUpstream::resume_read(IOCtrlReason reason, Downstream *downstream)
{
  if(ioctrl_.resume_read(reason)) {
    // Process remaining data in input buffer here because these bytes
    // are not notified by readcb until new data arrive.
    http_parser_pause(&htp_, 0);
    return on_read();
  }

  return 0;
}

namespace {
void https_downstream_readcb(bufferevent *bev, void *ptr)
{
  auto dconn = static_cast<DownstreamConnection*>(ptr);
  auto downstream = dconn->get_downstream();
  auto upstream = static_cast<HttpsUpstream*>(downstream->get_upstream());
  int rv;

  rv = downstream->on_read();

  if(downstream->get_response_state() == Downstream::MSG_RESET) {
    delete upstream->get_client_handler();

    return;
  }

  if(rv != 0) {
    if(downstream->get_response_state() == Downstream::HEADER_COMPLETE) {
      // We already sent HTTP response headers to upstream
      // client. Just close the upstream connection.
      delete upstream->get_client_handler();

      return;
    }

    // We did not sent any HTTP response, so sent error
    // response. Cannot reuse downstream connection in this case.
    if(upstream->error_reply(502) != 0) {
      delete upstream->get_client_handler();

      return;
    }

    if(downstream->get_request_state() == Downstream::MSG_COMPLETE) {
      upstream->delete_downstream();

      // Process next HTTP request
      if(upstream->resume_read(SHRPX_MSG_BLOCK, 0) == -1) {
        return;
      }
    }

    return;
  }

  auto handler = upstream->get_client_handler();

  if(downstream->get_response_state() != Downstream::MSG_COMPLETE) {
    if(handler->get_outbuf_length() >= OUTBUF_MAX_THRES) {
      downstream->pause_read(SHRPX_NO_BUFFER);
    }

    return;
  }


  if(downstream->get_response_connection_close()) {
    // Connection close
    downstream->set_downstream_connection(nullptr);

    delete dconn;

    dconn = nullptr;
  } else {
    // Keep-alive
    dconn->detach_downstream(downstream);
  }

  if(downstream->get_request_state() == Downstream::MSG_COMPLETE) {
    if(handler->get_should_close_after_write() &&
       handler->get_outbuf_length() == 0) {
      // If all upstream response body has already written out to
      // the peer, we cannot use writecb for ClientHandler. In
      // this case, we just delete handler here.
      delete handler;

      return;
    }

    upstream->delete_downstream();

    // Process next HTTP request
    if(upstream->resume_read(SHRPX_MSG_BLOCK, 0) == -1) {
      return;
    }

    return;
  }

  if(downstream->get_upgraded()) {
    // This path is effectively only taken for HTTP2 downstream
    // because only HTTP2 downstream sets response_state to
    // MSG_COMPLETE and this function. For HTTP downstream, EOF
    // from tunnel connection is handled on
    // https_downstream_eventcb.
    //
    // Tunneled connection always indicates connection close.
    if(handler->get_outbuf_length() == 0) {
      // For tunneled connection, if there is no pending data,
      // delete handler because on_write will not be called.
      delete handler;

      return;
    }

    if(LOG_ENABLED(INFO)) {
      DLOG(INFO, downstream) << "Tunneled connection has pending data";
    }

    return;
  }
}
} // namespace

namespace {
void https_downstream_writecb(bufferevent *bev, void *ptr)
{
  if(evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
    return;
  }
  auto dconn = static_cast<DownstreamConnection*>(ptr);
  auto downstream = dconn->get_downstream();
  auto upstream = static_cast<HttpsUpstream*>(downstream->get_upstream());
  // May return -1
  upstream->resume_read(SHRPX_NO_BUFFER, downstream);
}
} // namespace

namespace {
void https_downstream_eventcb(bufferevent *bev, short events, void *ptr)
{
  auto dconn = static_cast<DownstreamConnection*>(ptr);
  auto downstream = dconn->get_downstream();
  auto upstream = static_cast<HttpsUpstream*>(downstream->get_upstream());
  if(events & BEV_EVENT_CONNECTED) {
    if(LOG_ENABLED(INFO)) {
      DCLOG(INFO, dconn) << "Connection established";
    }

    return;
  }

  if(events & BEV_EVENT_EOF) {
    if(LOG_ENABLED(INFO)) {
      DCLOG(INFO, dconn) << "EOF";
    }
    if(downstream->get_response_state() == Downstream::HEADER_COMPLETE) {
      // Server may indicate the end of the request by EOF
      if(LOG_ENABLED(INFO)) {
        DCLOG(INFO, dconn) << "The end of the response body was indicated by "
                           << "EOF";
      }
      upstream->on_downstream_body_complete(downstream);
      downstream->set_response_state(Downstream::MSG_COMPLETE);

      auto handler = upstream->get_client_handler();
      if(handler->get_should_close_after_write() &&
         handler->get_outbuf_length() == 0) {
        // If all upstream response body has already written out to
        // the peer, we cannot use writecb for ClientHandler. In this
        // case, we just delete handler here.
        delete handler;
        return;
      }
    } else if(downstream->get_response_state() != Downstream::MSG_COMPLETE) {
      // error
      if(LOG_ENABLED(INFO)) {
        DCLOG(INFO, dconn) << "Treated as error";
      }
      if(upstream->error_reply(502) != 0) {
        delete upstream->get_client_handler();
        return;
      }
    }
    if(downstream->get_request_state() == Downstream::MSG_COMPLETE) {
      upstream->delete_downstream();
      if(upstream->resume_read(SHRPX_MSG_BLOCK, 0) == -1) {
        return;
      }
    }

    return;
  }

  if(events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
    if(LOG_ENABLED(INFO)) {
      if(events & BEV_EVENT_ERROR) {
        DCLOG(INFO, dconn) << "Network error";
      } else {
        DCLOG(INFO, dconn) << "Timeout";
      }
    }
    if(downstream->get_response_state() == Downstream::INITIAL) {
      unsigned int status;
      if(events & BEV_EVENT_TIMEOUT) {
        status = 504;
      } else {
        status = 502;
      }
      if(upstream->error_reply(status) != 0) {
        delete upstream->get_client_handler();
        return;
      }
    }
    if(downstream->get_request_state() == Downstream::MSG_COMPLETE) {
      upstream->delete_downstream();
      if(upstream->resume_read(SHRPX_MSG_BLOCK, 0) == -1) {
        return;
      }
    }
  }
}
} // namespace

int HttpsUpstream::error_reply(unsigned int status_code)
{
  auto html = http::create_error_html(status_code);
  auto downstream = get_downstream();

  if(downstream) {
    downstream->set_response_http_status(status_code);
  }

  std::string header;
  header.reserve(512);
  header += "HTTP/1.1 ";
  header += http2::get_status_string(status_code);
  header += "\r\nServer: ";
  header += get_config()->server_name;
  header += "\r\nContent-Length: ";
  header += util::utos(html.size());
  header += "\r\nContent-Type: text/html; charset=UTF-8\r\n";
  if(get_client_handler()->get_should_close_after_write()) {
    header += "Connection: close\r\n";
  }
  header += "\r\n";
  auto output = bufferevent_get_output(handler_->get_bev());
  if(evbuffer_add(output, header.c_str(), header.size()) != 0 ||
     evbuffer_add(output, html.c_str(), html.size()) != 0) {
    ULOG(FATAL, this) << "evbuffer_add() failed";
    return -1;
  }

  if(downstream) {
    downstream->set_response_state(Downstream::MSG_COMPLETE);
  }

  return 0;
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

void HttpsUpstream::attach_downstream(Downstream *downstream)
{
  assert(!downstream_);
  downstream_ = downstream;
}

void HttpsUpstream::delete_downstream()
{
  delete downstream_;
  downstream_ = 0;
}

Downstream* HttpsUpstream::get_downstream() const
{
  return downstream_;
}

Downstream* HttpsUpstream::pop_downstream()
{
  auto downstream = downstream_;
  downstream_ = nullptr;
  return downstream;
}

int HttpsUpstream::on_downstream_header_complete(Downstream *downstream)
{
  if(LOG_ENABLED(INFO)) {
    if(downstream->get_non_final_response()) {
      DLOG(INFO, downstream) << "HTTP non-final response header";
    } else {
      DLOG(INFO, downstream) << "HTTP response header completed";
    }
  }

  std::string hdrs = "HTTP/";
  hdrs += util::utos(downstream->get_request_major());
  hdrs += ".";
  hdrs += util::utos(downstream->get_request_minor());
  hdrs += " ";
  hdrs += http2::get_status_string(downstream->get_response_http_status());
  hdrs += "\r\n";
  downstream->normalize_response_headers();
  if(!get_config()->http2_proxy && !get_config()->client_proxy) {
    downstream->rewrite_norm_location_response_header
      (get_client_handler()->get_upstream_scheme(), get_config()->port);
  }
  auto end_headers = std::end(downstream->get_response_headers());
  http2::build_http1_headers_from_norm_headers
    (hdrs, downstream->get_response_headers());

  if(downstream->get_non_final_response()) {
    hdrs += "\r\n";

    auto output = bufferevent_get_output(handler_->get_bev());
    if(evbuffer_add(output, hdrs.c_str(), hdrs.size()) != 0) {
      ULOG(FATAL, this) << "evbuffer_add() failed";
      return -1;
    }

    downstream->clear_response_headers();

    return 0;
  }

  // We check downstream->get_response_connection_close() in case when
  // the Content-Length is not available.
  if(!downstream->get_request_connection_close() &&
     !downstream->get_response_connection_close()) {
    if(downstream->get_request_major() <= 0 ||
       downstream->get_request_minor() <= 0) {
      // We add this header for HTTP/1.0 or HTTP/0.9 clients
      hdrs += "Connection: Keep-Alive\r\n";
    }
  } else if(!downstream->get_upgraded() ||
            downstream->get_request_method() != "CONNECT") {
    hdrs += "Connection: close\r\n";
  }

  if(downstream->get_norm_response_header("alt-svc") == end_headers) {
    // We won't change or alter alt-svc from backend at the moment.
    if(!get_config()->altsvcs.empty()) {
      hdrs += "Alt-Svc: ";

      for(auto& altsvc : get_config()->altsvcs) {
        hdrs += util::percent_encode_token(altsvc.protocol_id);
        hdrs += "=";
        hdrs += util::utos(altsvc.port);
        hdrs += ", ";
      }

      hdrs[hdrs.size() - 2] = '\r';
      hdrs[hdrs.size() - 1] = '\n';
    }
  }

  auto via = downstream->get_norm_response_header("via");
  if(get_config()->no_via) {
    if(via != end_headers) {
      hdrs += "Via: ";
      hdrs += (*via).value;
      http2::sanitize_header_value(hdrs, hdrs.size() - (*via).value.size());
      hdrs += "\r\n";
    }
  } else {
    hdrs += "Via: ";
    if(via != end_headers) {
      hdrs += (*via).value;
      http2::sanitize_header_value(hdrs, hdrs.size() - (*via).value.size());
      hdrs += ", ";
    }
    hdrs += http::create_via_header_value
      (downstream->get_response_major(), downstream->get_response_minor());
    hdrs += "\r\n";
  }

  for(auto& p : get_config()->add_response_headers) {
    hdrs += p.first;
    hdrs += ": ";
    hdrs += p.second;
    hdrs += "\r\n";
  }

  hdrs += "\r\n";
  if(LOG_ENABLED(INFO)) {
    const char *hdrp;
    std::string nhdrs;
    if(worker_config.errorlog_tty) {
      nhdrs = http::colorizeHeaders(hdrs.c_str());
      hdrp = nhdrs.c_str();
    } else {
      hdrp = hdrs.c_str();
    }
    ULOG(INFO, this) << "HTTP response headers\n" << hdrp;
  }
  auto output = bufferevent_get_output(handler_->get_bev());
  if(evbuffer_add(output, hdrs.c_str(), hdrs.size()) != 0) {
    ULOG(FATAL, this) << "evbuffer_add() failed";
    return -1;
  }

  if(downstream->get_upgraded()) {
    upstream_accesslog(this->get_client_handler()->get_ipaddr(),
                       downstream->get_response_http_status(), downstream);
  }

  downstream->clear_response_headers();

  return 0;
}

int HttpsUpstream::on_downstream_body(Downstream *downstream,
                                      const uint8_t *data, size_t len,
                                      bool flush)
{
  int rv;
  if(len == 0) {
    return 0;
  }
  auto output = bufferevent_get_output(handler_->get_bev());
  if(downstream->get_chunked_response()) {
    auto chunk_size_hex = util::utox(len);
    chunk_size_hex += "\r\n";

    rv = evbuffer_add(output, chunk_size_hex.c_str(), chunk_size_hex.size());

    if(rv != 0) {
      ULOG(FATAL, this) << "evbuffer_add() failed";
      return -1;
    }
  }
  if(evbuffer_add(output, data, len) != 0) {
    ULOG(FATAL, this) << "evbuffer_add() failed";
    return -1;
  }
  if(downstream->get_chunked_response()) {
    if(evbuffer_add(output, "\r\n", 2) != 0) {
      ULOG(FATAL, this) << "evbuffer_add() failed";
      return -1;
    }
  }
  return 0;
}

int HttpsUpstream::on_downstream_body_complete(Downstream *downstream)
{
  if(downstream->get_chunked_response()) {
    auto output = bufferevent_get_output(handler_->get_bev());
    if(evbuffer_add(output, "0\r\n\r\n", 5) != 0) {
      ULOG(FATAL, this) << "evbuffer_add() failed";
      return -1;
    }
  }
  if(LOG_ENABLED(INFO)) {
    DLOG(INFO, downstream) << "HTTP response completed";
  }

  if(!downstream->get_upgraded()) {
    upstream_accesslog(get_client_handler()->get_ipaddr(),
                       downstream->get_response_http_status(),
                       downstream);
  }

  if(downstream->get_request_connection_close() ||
     downstream->get_response_connection_close()) {
    auto handler = get_client_handler();
    handler->set_should_close_after_write(true);
  }
  return 0;
}

int HttpsUpstream::on_downstream_abort_request(Downstream *downstream,
                                               unsigned int status_code)
{
  return error_reply(status_code);
}

} // namespace shrpx
