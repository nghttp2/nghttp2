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
#include "shrpx_http_downstream_connection.h"

#include "shrpx_client_handler.h"
#include "shrpx_upstream.h"
#include "shrpx_downstream.h"
#include "shrpx_config.h"
#include "shrpx_error.h"
#include "shrpx_http.h"
#include "shrpx_worker_config.h"
#include "http2.h"
#include "util.h"

using namespace nghttp2;

namespace shrpx {

namespace {
const size_t OUTBUF_MAX_THRES = 64*1024;
} // namespace

// Workaround for the inability for Bufferevent to remove timeout from
// bufferevent. Specify this long timeout instead of removing.
namespace {
timeval max_timeout = { 86400, 0 };
} // namespace

HttpDownstreamConnection::HttpDownstreamConnection
(ClientHandler *client_handler)
  : DownstreamConnection(client_handler),
    bev_(nullptr),
    ioctrl_(nullptr),
    response_htp_{0}
{}

HttpDownstreamConnection::~HttpDownstreamConnection()
{
  if(bev_) {
    bufferevent_disable(bev_, EV_READ | EV_WRITE);
    bufferevent_free(bev_);
  }
  // Downstream and DownstreamConnection may be deleted
  // asynchronously.
  if(downstream_) {
    downstream_->set_downstream_connection(nullptr);
  }
}

int HttpDownstreamConnection::attach_downstream(Downstream *downstream)
{
  if(LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Attaching to DOWNSTREAM:" << downstream;
  }
  auto upstream = downstream->get_upstream();
  if(!bev_) {
    auto evbase = client_handler_->get_evbase();
    bev_ = bufferevent_socket_new
      (evbase, -1,
       BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    if(!bev_) {
      DCLOG(INFO, this) << "bufferevent_socket_new() failed";
      return SHRPX_ERR_NETWORK;
    }
    int rv = bufferevent_socket_connect
      (bev_,
       // TODO maybe not thread-safe?
       const_cast<sockaddr*>(&get_config()->downstream_addr.sa),
       get_config()->downstream_addrlen);
    if(rv != 0) {
      bufferevent_free(bev_);
      bev_ = nullptr;
      return SHRPX_ERR_NETWORK;
    }
    if(LOG_ENABLED(INFO)) {
      DCLOG(INFO, this) << "Connecting to downstream server";
    }
  }
  downstream->set_downstream_connection(this);
  downstream_ = downstream;

  ioctrl_.set_bev(bev_);

  http_parser_init(&response_htp_, HTTP_RESPONSE);
  response_htp_.data = downstream_;

  bufferevent_setwatermark(bev_, EV_READ, 0, SHRPX_READ_WATERMARK);
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
  downstream_->assemble_request_cookie();
  downstream_->normalize_request_headers();
  auto end_headers = std::end(downstream_->get_request_headers());
  // Assume that method and request path do not contain \r\n.
  std::string hdrs = downstream_->get_request_method();
  hdrs += " ";
  if(downstream_->get_request_method() == "CONNECT") {
    if(!downstream_->get_request_http2_authority().empty()) {
      hdrs += downstream_->get_request_http2_authority();
    } else {
      hdrs += downstream_->get_request_path();
    }
  } else if(get_config()->http2_proxy &&
            !downstream_->get_request_http2_scheme().empty() &&
            !downstream_->get_request_http2_authority().empty() &&
            (downstream_->get_request_path().c_str()[0] == '/' ||
             downstream_->get_request_path() == "*")) {
    // Construct absolute-form request target because we are going to
    // send a request to a HTTP/1 proxy.
    hdrs += downstream_->get_request_http2_scheme();
    hdrs += "://";
    hdrs += downstream_->get_request_http2_authority();

    // Server-wide OPTIONS takes following form in proxy request:
    //
    // OPTIONS http://example.org HTTP/1.1
    //
    // Notice that no slash after authority. See
    // http://tools.ietf.org/html/rfc7230#section-5.3.4
    if(downstream_->get_request_path() != "*") {
      hdrs += downstream_->get_request_path();
    }
  } else {
    // No proxy case. get_request_path() may be absolute-form but we
    // don't care.
    hdrs += downstream_->get_request_path();
  }
  hdrs += " HTTP/1.1\r\n";
  if(downstream_->get_norm_request_header("host") == end_headers &&
     !downstream_->get_request_http2_authority().empty()) {
    hdrs += "Host: ";
    hdrs += downstream_->get_request_http2_authority();
    hdrs += "\r\n";
  }
  http2::build_http1_headers_from_norm_headers
    (hdrs, downstream_->get_request_headers());

  if(!downstream_->get_assembled_request_cookie().empty()) {
    hdrs += "Cookie: ";
    hdrs += downstream_->get_assembled_request_cookie();
    hdrs += "\r\n";
  }

  if(downstream_->get_request_method() != "CONNECT" &&
     downstream_->get_request_http2_expect_body() &&
     downstream_->get_norm_request_header("content-length") == end_headers) {

    downstream_->set_chunked_request(true);
    hdrs += "Transfer-Encoding: chunked\r\n";
  }

  if(downstream_->get_request_connection_close()) {
    hdrs += "Connection: close\r\n";
  }
  auto xff = downstream_->get_norm_request_header("x-forwarded-for");
  if(get_config()->add_x_forwarded_for) {
    hdrs += "X-Forwarded-For: ";
    if(xff != end_headers) {
      hdrs += (*xff).value;
      http2::sanitize_header_value(hdrs, hdrs.size() - (*xff).value.size());
      hdrs += ", ";
    }
    hdrs += client_handler_->get_ipaddr();
    hdrs += "\r\n";
  } else if(xff != end_headers) {
    hdrs += "X-Forwarded-For: ";
    hdrs += (*xff).value;
    http2::sanitize_header_value(hdrs, hdrs.size() - (*xff).value.size());
    hdrs += "\r\n";
  }
  if(downstream_->get_request_method() != "CONNECT") {
    hdrs += "X-Forwarded-Proto: ";
    if(!downstream_->get_request_http2_scheme().empty()) {
      hdrs += downstream_->get_request_http2_scheme();
      hdrs += "\r\n";
    } else if(client_handler_->get_ssl()) {
      hdrs += "https\r\n";
    } else {
      hdrs += "http\r\n";
    }
  }
  auto expect = downstream_->get_norm_request_header("expect");
  if(expect != end_headers &&
     !util::strifind((*expect).value.c_str(), "100-continue")) {
    hdrs += "Expect: ";
    hdrs += (*expect).value;
    http2::sanitize_header_value(hdrs, hdrs.size() - (*expect).value.size());
    hdrs += "\r\n";
  }
  auto via = downstream_->get_norm_request_header("via");
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
    hdrs += http::create_via_header_value(downstream_->get_request_major(),
                                          downstream_->get_request_minor());
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
    DCLOG(INFO, this) << "HTTP request headers. stream_id="
                      << downstream_->get_stream_id() << "\n" << hdrp;
  }
  auto output = bufferevent_get_output(bev_);
  int rv;
  rv = evbuffer_add(output, hdrs.c_str(), hdrs.size());
  if(rv != 0) {
    return -1;
  }

  // When downstream request is issued, set read timeout. We don't
  // know when the request is completely received by the downstream
  // server. This function may be called before that happens. Overall
  // it does not cause problem for most of the time.  If the
  // downstream server is too slow to recv/send, the connection will
  // be dropped by read timeout.
  bufferevent_set_timeouts(bev_,
                           &get_config()->downstream_read_timeout,
                           &get_config()->downstream_write_timeout);

  downstream_->clear_request_headers();

  return 0;
}

int HttpDownstreamConnection::push_upload_data_chunk
(const uint8_t *data, size_t datalen)
{
  int rv;
  int chunked = downstream_->get_chunked_request();
  auto output = bufferevent_get_output(bev_);

  if(chunked) {
    auto chunk_size_hex = util::utox(datalen);
    chunk_size_hex += "\r\n";

    rv = evbuffer_add(output, chunk_size_hex.c_str(), chunk_size_hex.size());
    if(rv == -1) {
      DCLOG(FATAL, this) << "evbuffer_add() failed";
      return -1;
    }
  }

  rv = evbuffer_add(output, data, datalen);

  if(rv == -1) {
    DCLOG(FATAL, this) << "evbuffer_add() failed";
    return -1;
  }

  if(chunked) {
    rv = evbuffer_add(output, "\r\n", 2);
    if(rv == -1) {
      DCLOG(FATAL, this) << "evbuffer_add() failed";
      return -1;
    }
  }

  return 0;
}

int HttpDownstreamConnection::end_upload_data()
{
  if(downstream_->get_chunked_request()) {
    auto output = bufferevent_get_output(bev_);
    if(evbuffer_add(output, "0\r\n\r\n", 5) != 0) {
      DCLOG(FATAL, this) << "evbuffer_add() failed";
      return -1;
    }
  }
  return 0;
}

namespace {
// Gets called when DownstreamConnection is pooled in ClientHandler.
void idle_eventcb(bufferevent *bev, short events, void *arg)
{
  auto dconn = static_cast<HttpDownstreamConnection*>(arg);
  if(events & BEV_EVENT_CONNECTED) {
    // Downstream was detached before connection established?
    // This may be safe to be left.
    if(LOG_ENABLED(INFO)) {
      DCLOG(INFO, dconn) << "Idle connection connected?";
    }
    return;
  }
  if(events & BEV_EVENT_EOF) {
    if(LOG_ENABLED(INFO)) {
      DCLOG(INFO, dconn) << "Idle connection EOF";
    }
  } else if(events & BEV_EVENT_TIMEOUT) {
    if(LOG_ENABLED(INFO)) {
      DCLOG(INFO, dconn) << "Idle connection timeout";
    }
  } else if(events & BEV_EVENT_ERROR) {
    if(LOG_ENABLED(INFO)) {
      DCLOG(INFO, dconn) << "Idle connection network error";
    }
  }
  auto client_handler = dconn->get_client_handler();
  client_handler->remove_downstream_connection(dconn);
  delete dconn;
}
} // namespace

void HttpDownstreamConnection::detach_downstream(Downstream *downstream)
{
  if(LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Detaching from DOWNSTREAM:" << downstream;
  }
  downstream->set_downstream_connection(0);
  downstream_ = 0;
  ioctrl_.force_resume_read();
  bufferevent_enable(bev_, EV_READ);
  bufferevent_setcb(bev_, 0, 0, idle_eventcb, this);
  // On idle state, just enable read timeout. Normally idle downstream
  // connection will get EOF from the downstream server and closed.
  bufferevent_set_timeouts(bev_,
                           &get_config()->downstream_idle_read_timeout,
                           &get_config()->downstream_write_timeout);
  client_handler_->pool_downstream_connection(this);
}

bufferevent* HttpDownstreamConnection::get_bev()
{
  return bev_;
}

void HttpDownstreamConnection::pause_read(IOCtrlReason reason)
{
  ioctrl_.pause_read(reason);
}

int HttpDownstreamConnection::resume_read(IOCtrlReason reason)
{
  ioctrl_.resume_read(reason);
  return 0;
}

void HttpDownstreamConnection::force_resume_read()
{
  ioctrl_.force_resume_read();
}

bool HttpDownstreamConnection::get_output_buffer_full()
{
  auto output = bufferevent_get_output(bev_);
  return evbuffer_get_length(output) >= OUTBUF_MAX_THRES;
}

namespace {
int htp_msg_begincb(http_parser *htp)
{
  auto downstream = static_cast<Downstream*>(htp->data);

  if(downstream->get_response_state() != Downstream::INITIAL) {
    return -1;
  }

  return 0;
}
} // namespace

namespace {
int htp_hdrs_completecb(http_parser *htp)
{
  auto downstream = static_cast<Downstream*>(htp->data);
  auto upstream = downstream->get_upstream();
  int rv;

  downstream->set_response_http_status(htp->status_code);
  downstream->set_response_major(htp->http_major);
  downstream->set_response_minor(htp->http_minor);

  if(downstream->get_non_final_response()) {
    // For non-final response code, we just call
    // on_downstream_header_complete() without changing response
    // state.
    rv = upstream->on_downstream_header_complete(downstream);

    if(rv != 0) {
      return -1;
    }

    return 0;
  }

  downstream->set_response_connection_close(!http_should_keep_alive(htp));
  downstream->set_response_state(Downstream::HEADER_COMPLETE);
  downstream->inspect_http1_response();
  downstream->check_upgrade_fulfilled();
  if(downstream->get_upgraded()) {
    downstream->set_response_connection_close(true);
  }
  if(upstream->on_downstream_header_complete(downstream) != 0) {
    return -1;
  }

  if(downstream->get_upgraded()) {
    // Upgrade complete, read until EOF in both ends
    if(upstream->resume_read(SHRPX_MSG_BLOCK, downstream) != 0) {
      return -1;
    }
    downstream->set_request_state(Downstream::HEADER_COMPLETE);
    if(LOG_ENABLED(INFO)) {
      LOG(INFO) << "HTTP upgrade success. stream_id="
                << downstream->get_stream_id();
    }
  }


  unsigned int status = downstream->get_response_http_status();
  // Ignore the response body. HEAD response may contain
  // Content-Length or Transfer-Encoding: chunked.  Some server send
  // 304 status code with nonzero Content-Length, but without response
  // body. See
  // http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-20#section-3.3

  // TODO It seems that the cases other than HEAD are handled by
  // http-parser.  Need test.
  return downstream->get_request_method() == "HEAD" ||
    (100 <= status && status <= 199) || status == 204 ||
    status == 304 ? 1 : 0;
}
} // namespace

namespace {
int htp_hdr_keycb(http_parser *htp, const char *data, size_t len)
{
  auto downstream = static_cast<Downstream*>(htp->data);
  if(downstream->get_response_header_key_prev()) {
    downstream->append_last_response_header_key(data, len);
  } else {
    downstream->add_response_header(std::string(data, len), "");
  }
  if(downstream->get_response_headers_sum() > Downstream::MAX_HEADERS_SUM) {
    if(LOG_ENABLED(INFO)) {
      DLOG(INFO, downstream) << "Too large header block size="
                             << downstream->get_response_headers_sum();
    }
    return -1;
  }
  return 0;
}
} // namespace

namespace {
int htp_hdr_valcb(http_parser *htp, const char *data, size_t len)
{
  auto downstream = static_cast<Downstream*>(htp->data);
  if(downstream->get_response_header_key_prev()) {
    downstream->set_last_response_header_value(std::string(data, len));
  } else {
    downstream->append_last_response_header_value(data, len);
  }
  if(downstream->get_response_headers_sum() > Downstream::MAX_HEADERS_SUM) {
    if(LOG_ENABLED(INFO)) {
      DLOG(INFO, downstream) << "Too large header block size="
                             << downstream->get_response_headers_sum();
    }
    return -1;
  }
  return 0;
}
} // namespace

namespace {
int htp_bodycb(http_parser *htp, const char *data, size_t len)
{
  auto downstream = static_cast<Downstream*>(htp->data);

  downstream->add_response_bodylen(len);

  return downstream->get_upstream()->on_downstream_body
    (downstream, reinterpret_cast<const uint8_t*>(data), len, true);
}
} // namespace

namespace {
int htp_msg_completecb(http_parser *htp)
{
  auto downstream = static_cast<Downstream*>(htp->data);

  if(downstream->get_non_final_response()) {
    downstream->reset_response();

    return 0;
  }

  downstream->set_response_state(Downstream::MSG_COMPLETE);
  // Block reading another response message from (broken?)
  // server. This callback is not called if the connection is
  // tunneled.
  downstream->pause_read(SHRPX_MSG_BLOCK);
  return downstream->get_upstream()->on_downstream_body_complete(downstream);
}
} // namespace

namespace {
http_parser_settings htp_hooks = {
  htp_msg_begincb, // http_cb on_message_begin;
  nullptr, // http_data_cb on_url;
  nullptr, // http_data_cb on_status;
  htp_hdr_keycb, // http_data_cb on_header_field;
  htp_hdr_valcb, // http_data_cb on_header_value;
  htp_hdrs_completecb, // http_cb      on_headers_complete;
  htp_bodycb, // http_data_cb on_body;
  htp_msg_completecb // http_cb      on_message_complete;
};
} // namespace

int HttpDownstreamConnection::on_read()
{
  auto input = bufferevent_get_input(bev_);

  if(downstream_->get_upgraded()) {
    // For upgraded connection, just pass data to the upstream.
    for(;;) {
      auto inputlen = evbuffer_get_contiguous_space(input);

      if(inputlen == 0) {
        assert(evbuffer_get_length(input) == 0);

        return 0;
      }

      auto mem = evbuffer_pullup(input, inputlen);

      int rv;
      rv = downstream_->get_upstream()->on_downstream_body
        (downstream_, reinterpret_cast<const uint8_t*>(mem), inputlen, true);
      if(rv != 0) {
        return rv;
      }
      if(evbuffer_drain(input, inputlen) != 0) {
        DCLOG(FATAL, this) << "evbuffer_drain() failed";
        return -1;
      }
    }
  }


  for(;;) {
    auto inputlen = evbuffer_get_contiguous_space(input);

    if(inputlen == 0) {
      assert(evbuffer_get_length(input) == 0);
      return 0;
    }

    auto mem = evbuffer_pullup(input, inputlen);

    auto nread = http_parser_execute(&response_htp_, &htp_hooks,
                                     reinterpret_cast<const char*>(mem),
                                     inputlen);

    if(evbuffer_drain(input, nread) != 0) {
      DCLOG(FATAL, this) << "evbuffer_drain() failed";
      return -1;
    }

    auto htperr = HTTP_PARSER_ERRNO(&response_htp_);

    if(htperr != HPE_OK) {
      if(LOG_ENABLED(INFO)) {
        DCLOG(INFO, this) << "HTTP parser failure: "
                          << "(" << http_errno_name(htperr) << ") "
                          << http_errno_description(htperr);
      }

      return SHRPX_ERR_HTTP_PARSE;
    }
  }
}

int HttpDownstreamConnection::on_write()
{
  return 0;
}

void HttpDownstreamConnection::on_upstream_change(Upstream *upstream)
{
  bufferevent_setcb(bev_,
                    upstream->get_downstream_readcb(),
                    upstream->get_downstream_writecb(),
                    upstream->get_downstream_eventcb(), this);
}

} // namespace shrpx
