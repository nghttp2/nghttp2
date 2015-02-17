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
#include "shrpx_http.h"
#include "shrpx_config.h"
#include "shrpx_error.h"
#include "shrpx_worker_config.h"
#include "http2.h"
#include "util.h"
#include "template.h"

using namespace nghttp2;

namespace shrpx {

HttpsUpstream::HttpsUpstream(ClientHandler *handler)
    : handler_(handler), current_header_length_(0),
      ioctrl_(handler->get_rlimit()) {
  http_parser_init(&htp_, HTTP_REQUEST);
  htp_.data = this;
}

HttpsUpstream::~HttpsUpstream() {}

void HttpsUpstream::reset_current_header_length() {
  current_header_length_ = 0;
}

namespace {
int htp_msg_begin(http_parser *htp) {
  auto upstream = static_cast<HttpsUpstream *>(htp->data);
  if (LOG_ENABLED(INFO)) {
    ULOG(INFO, upstream) << "HTTP request started";
  }
  upstream->reset_current_header_length();
  // TODO specify 0 as priority for now
  upstream->attach_downstream(make_unique<Downstream>(upstream, 0, 0));
  return 0;
}
} // namespace

namespace {
int htp_uricb(http_parser *htp, const char *data, size_t len) {
  auto upstream = static_cast<HttpsUpstream *>(htp->data);
  auto downstream = upstream->get_downstream();
  downstream->append_request_path(data, len);
  return 0;
}
} // namespace

namespace {
int htp_hdr_keycb(http_parser *htp, const char *data, size_t len) {
  auto upstream = static_cast<HttpsUpstream *>(htp->data);
  auto downstream = upstream->get_downstream();
  if (downstream->get_request_state() != Downstream::INITIAL) {
    // ignore trailers
    return 0;
  }
  if (downstream->get_request_header_key_prev()) {
    downstream->append_last_request_header_key(data, len);
  } else {
    downstream->add_request_header(std::string(data, len), "");
  }
  if (downstream->get_request_headers_sum() > Downstream::MAX_HEADERS_SUM) {
    if (LOG_ENABLED(INFO)) {
      ULOG(INFO, upstream) << "Too large header block size="
                           << downstream->get_request_headers_sum();
    }
    return -1;
  }
  return 0;
}
} // namespace

namespace {
int htp_hdr_valcb(http_parser *htp, const char *data, size_t len) {
  auto upstream = static_cast<HttpsUpstream *>(htp->data);
  auto downstream = upstream->get_downstream();
  if (downstream->get_request_state() != Downstream::INITIAL) {
    // ignore trailers
    return 0;
  }
  if (downstream->get_request_header_key_prev()) {
    downstream->set_last_request_header_value(std::string(data, len));
  } else {
    downstream->append_last_request_header_value(data, len);
  }
  if (downstream->get_request_headers_sum() > Downstream::MAX_HEADERS_SUM) {
    if (LOG_ENABLED(INFO)) {
      ULOG(INFO, upstream) << "Too large header block size="
                           << downstream->get_request_headers_sum();
    }
    return -1;
  }
  return 0;
}
} // namespace

namespace {
int htp_hdrs_completecb(http_parser *htp) {
  int rv;
  auto upstream = static_cast<HttpsUpstream *>(htp->data);
  if (LOG_ENABLED(INFO)) {
    ULOG(INFO, upstream) << "HTTP request headers completed";
  }
  auto downstream = upstream->get_downstream();

  downstream->set_request_method(
      http_method_str((enum http_method)htp->method));
  downstream->set_request_major(htp->http_major);
  downstream->set_request_minor(htp->http_minor);

  downstream->set_request_connection_close(!http_should_keep_alive(htp));

  if (LOG_ENABLED(INFO)) {
    std::stringstream ss;
    ss << downstream->get_request_method() << " "
       << downstream->get_request_path() << " "
       << "HTTP/" << downstream->get_request_major() << "."
       << downstream->get_request_minor() << "\n";
    const auto &headers = downstream->get_request_headers();
    for (size_t i = 0; i < headers.size(); ++i) {
      ss << TTY_HTTP_HD << headers[i].name << TTY_RST << ": "
         << headers[i].value << "\n";
    }
    ULOG(INFO, upstream) << "HTTP request headers\n" << ss.str();
  }

  if (downstream->index_request_headers() != 0) {
    return -1;
  }

  if (downstream->get_request_major() == 1 &&
      downstream->get_request_minor() == 1 &&
      !downstream->get_request_header(http2::HD_HOST)) {
    return -1;
  }

  downstream->inspect_http1_request();

  if (get_config()->client_proxy &&
      downstream->get_request_method() != "CONNECT") {
    // Make sure that request path is an absolute URI.
    http_parser_url u;
    auto url = downstream->get_request_path().c_str();
    memset(&u, 0, sizeof(u));
    rv = http_parser_parse_url(url, downstream->get_request_path().size(), 0,
                               &u);
    if (rv != 0 || !(u.field_set & (1 << UF_SCHEMA))) {
      // Expect to respond with 400 bad request
      return -1;
    }
  }

  rv = downstream->attach_downstream_connection(
      upstream->get_client_handler()->get_downstream_connection());

  if (rv != 0) {
    downstream->set_request_state(Downstream::CONNECT_FAIL);

    return -1;
  }

  rv = downstream->push_request_headers();

  if (rv != 0) {
    return -1;
  }

  downstream->set_request_state(Downstream::HEADER_COMPLETE);

  return 0;
}
} // namespace

namespace {
int htp_bodycb(http_parser *htp, const char *data, size_t len) {
  int rv;
  auto upstream = static_cast<HttpsUpstream *>(htp->data);
  auto downstream = upstream->get_downstream();
  rv = downstream->push_upload_data_chunk(
      reinterpret_cast<const uint8_t *>(data), len);
  if (rv != 0) {
    return -1;
  }
  return 0;
}
} // namespace

namespace {
int htp_msg_completecb(http_parser *htp) {
  int rv;
  auto upstream = static_cast<HttpsUpstream *>(htp->data);
  if (LOG_ENABLED(INFO)) {
    ULOG(INFO, upstream) << "HTTP request completed";
  }
  auto downstream = upstream->get_downstream();
  downstream->set_request_state(Downstream::MSG_COMPLETE);
  rv = downstream->end_upload_data();
  if (rv != 0) {
    return -1;
  }
  // Stop further processing to complete this request
  http_parser_pause(htp, 1);
  return 0;
}
} // namespace

namespace {
http_parser_settings htp_hooks = {
    htp_msg_begin,       // http_cb      on_message_begin;
    htp_uricb,           // http_data_cb on_url;
    nullptr,             // http_data_cb on_status;
    htp_hdr_keycb,       // http_data_cb on_header_field;
    htp_hdr_valcb,       // http_data_cb on_header_value;
    htp_hdrs_completecb, // http_cb      on_headers_complete;
    htp_bodycb,          // http_data_cb on_body;
    htp_msg_completecb   // http_cb      on_message_complete;
};
} // namespace

// on_read() does not consume all available data in input buffer if
// one http request is fully received.
int HttpsUpstream::on_read() {
  auto rb = handler_->get_rb();
  auto rlimit = handler_->get_rlimit();
  auto downstream = get_downstream();

  if (rb->rleft() == 0) {
    return 0;
  }

  // downstream can be nullptr here, because it is initialized in the
  // callback chain called by http_parser_execute()
  if (downstream && downstream->get_upgraded()) {

    auto rv = downstream->push_upload_data_chunk(rb->pos, rb->rleft());

    if (rv != 0) {
      return -1;
    }

    rb->reset();
    rlimit->startw();

    if (downstream->request_buf_full()) {
      if (LOG_ENABLED(INFO)) {
        ULOG(INFO, this) << "Downstream request buf is full";
      }
      pause_read(SHRPX_NO_BUFFER);

      return 0;
    }

    return 0;
  }

  if (downstream) {
    // To avoid reading next pipelined request
    switch (downstream->get_request_state()) {
    case Downstream::INITIAL:
    case Downstream::HEADER_COMPLETE:
      break;
    default:
      return 0;
    }
  }

  auto nread = http_parser_execute(
      &htp_, &htp_hooks, reinterpret_cast<const char *>(rb->pos), rb->rleft());

  rb->drain(nread);
  rlimit->startw();

  // Well, actually header length + some body bytes
  current_header_length_ += nread;

  // Get downstream again because it may be initialized in http parser
  // execution
  downstream = get_downstream();

  auto handler = get_client_handler();
  auto htperr = HTTP_PARSER_ERRNO(&htp_);

  if (htperr == HPE_PAUSED) {

    assert(downstream);

    if (downstream->get_request_state() == Downstream::CONNECT_FAIL) {
      error_reply(503);
      handler_->signal_write();
      // Downstream gets deleted after response body is read.
      return 0;
    }

    assert(downstream->get_request_state() == Downstream::MSG_COMPLETE);

    if (downstream->get_downstream_connection() == nullptr) {
      // Error response has already be sent
      assert(downstream->get_response_state() == Downstream::MSG_COMPLETE);
      delete_downstream();

      return 0;
    }

    if (handler->get_http2_upgrade_allowed() &&
        downstream->get_http2_upgrade_request()) {

      if (handler->perform_http2_upgrade(this) != 0) {
        return -1;
      }

      handler_->signal_write();

      return 0;
    }

    return 0;
  }

  if (htperr != HPE_OK) {
    if (LOG_ENABLED(INFO)) {
      ULOG(INFO, this) << "HTTP parse failure: "
                       << "(" << http_errno_name(htperr) << ") "
                       << http_errno_description(htperr);
    }

    unsigned int status_code;

    if (downstream &&
        downstream->get_request_state() == Downstream::CONNECT_FAIL) {
      status_code = 503;
    } else {
      status_code = 400;
    }

    error_reply(status_code);

    handler_->signal_write();

    return 0;
  }

  // downstream can be NULL here.
  if (downstream && downstream->request_buf_full()) {
    if (LOG_ENABLED(INFO)) {
      ULOG(INFO, this) << "Downstream request buffer is full";
    }

    pause_read(SHRPX_NO_BUFFER);

    return 0;
  }

  return 0;
}

int HttpsUpstream::on_write() {
  auto downstream = get_downstream();
  if (!downstream) {
    return 0;
  }
  auto wb = handler_->get_wb();
  if (wb->wleft() == 0) {
    return 0;
  }

  auto dconn = downstream->get_downstream_connection();
  auto output = downstream->get_response_buf();

  if (output->rleft() == 0 && dconn &&
      downstream->get_response_state() != Downstream::MSG_COMPLETE) {
    if (downstream->resume_read(SHRPX_NO_BUFFER,
                                downstream->get_response_datalen()) != 0) {
      return -1;
    }

    if (downstream_read(dconn) != 0) {
      return -1;
    }
  }

  auto n = output->remove(wb->last, wb->wleft());
  wb->write(n);

  if (wb->rleft() > 0) {
    return 0;
  }

  // We need to postpone detachment until all data are sent so that
  // we can notify nghttp2 library all data consumed.
  if (downstream->get_response_state() == Downstream::MSG_COMPLETE) {
    if (downstream->get_response_connection_close()) {
      // Connection close
      downstream->pop_downstream_connection();
      // dconn was deleted
    } else {
      // Keep-alive
      downstream->detach_downstream_connection();
    }
    // We need this if response ends before request.
    if (downstream->get_request_state() == Downstream::MSG_COMPLETE) {
      delete_downstream();
      return resume_read(SHRPX_NO_BUFFER, nullptr, 0);
    }
  }

  return downstream->resume_read(SHRPX_NO_BUFFER,
                                 downstream->get_response_datalen());
}

int HttpsUpstream::on_event() { return 0; }

ClientHandler *HttpsUpstream::get_client_handler() const { return handler_; }

void HttpsUpstream::pause_read(IOCtrlReason reason) {
  ioctrl_.pause_read(reason);
}

int HttpsUpstream::resume_read(IOCtrlReason reason, Downstream *downstream,
                               size_t consumed) {
  // downstream could be nullptr
  if (downstream && downstream->request_buf_full()) {
    return 0;
  }
  if (ioctrl_.resume_read(reason)) {
    // Process remaining data in input buffer here because these bytes
    // are not notified by readcb until new data arrive.
    http_parser_pause(&htp_, 0);
    return on_read();
  }

  return 0;
}

int HttpsUpstream::downstream_read(DownstreamConnection *dconn) {
  auto downstream = dconn->get_downstream();
  int rv;

  rv = downstream->on_read();

  if (downstream->get_response_state() == Downstream::MSG_RESET) {
    return -1;
  }

  if (downstream->get_response_state() == Downstream::MSG_BAD_HEADER) {
    error_reply(502);
    downstream->pop_downstream_connection();
    goto end;
  }

  // Detach downstream connection early so that it could be reused
  // without hitting server's request timeout.
  if (downstream->get_response_state() == Downstream::MSG_COMPLETE &&
      !downstream->get_response_connection_close()) {
    // Keep-alive
    downstream->detach_downstream_connection();
  }

  if (rv == SHRPX_ERR_EOF) {
    return downstream_eof(dconn);
  }

  if (rv < 0) {
    return downstream_error(dconn, Downstream::EVENT_ERROR);
  }

end:
  handler_->signal_write();

  return 0;
}

int HttpsUpstream::downstream_write(DownstreamConnection *dconn) {
  int rv;
  rv = dconn->on_write();
  if (rv == SHRPX_ERR_NETWORK) {
    return downstream_error(dconn, Downstream::EVENT_ERROR);
  }

  if (rv != 0) {
    return -1;
  }

  return 0;
}

int HttpsUpstream::downstream_eof(DownstreamConnection *dconn) {
  auto downstream = dconn->get_downstream();

  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, dconn) << "EOF";
  }

  if (downstream->get_response_state() == Downstream::MSG_COMPLETE) {
    goto end;
  }

  if (downstream->get_response_state() == Downstream::HEADER_COMPLETE) {
    // Server may indicate the end of the request by EOF
    if (LOG_ENABLED(INFO)) {
      DCLOG(INFO, dconn) << "The end of the response body was indicated by "
                         << "EOF";
    }
    on_downstream_body_complete(downstream);
    downstream->set_response_state(Downstream::MSG_COMPLETE);
    downstream->pop_downstream_connection();
    goto end;
  }

  if (downstream->get_response_state() == Downstream::INITIAL) {
    // we did not send any response headers, so we can reply error
    // message.
    if (LOG_ENABLED(INFO)) {
      DCLOG(INFO, dconn) << "Return error reply";
    }
    error_reply(502);
    downstream->pop_downstream_connection();
    goto end;
  }

  // Otherwise, we don't know how to recover from this situation. Just
  // drop connection.
  return -1;
end:
  handler_->signal_write();

  return 0;
}

int HttpsUpstream::downstream_error(DownstreamConnection *dconn, int events) {
  auto downstream = dconn->get_downstream();
  if (LOG_ENABLED(INFO)) {
    if (events & Downstream::EVENT_ERROR) {
      DCLOG(INFO, dconn) << "Network error/general error";
    } else {
      DCLOG(INFO, dconn) << "Timeout";
    }
  }
  if (downstream->get_response_state() != Downstream::INITIAL) {
    return -1;
  }

  unsigned int status;
  if (events & Downstream::EVENT_TIMEOUT) {
    status = 504;
  } else {
    status = 502;
  }
  error_reply(status);

  downstream->pop_downstream_connection();

  handler_->signal_write();
  return 0;
}

void HttpsUpstream::error_reply(unsigned int status_code) {
  auto html = http::create_error_html(status_code);
  auto downstream = get_downstream();

  if (!downstream) {
    attach_downstream(make_unique<Downstream>(this, 1, 1));
    downstream = get_downstream();
  }

  downstream->set_response_http_status(status_code);
  // we are going to close connection for both frontend and backend in
  // error condition.  This is safest option.
  downstream->set_response_connection_close(true);
  handler_->set_should_close_after_write(true);

  auto output = downstream->get_response_buf();

  output->append("HTTP/1.1 ");
  auto status_str = http2::get_status_string(status_code);
  output->append(status_str.c_str(), status_str.size());
  output->append("\r\nServer: ");
  output->append(get_config()->server_name, strlen(get_config()->server_name));
  output->append("\r\nContent-Length: ");
  auto cl = util::utos(html.size());
  output->append(cl.c_str(), cl.size());
  output->append("\r\nContent-Type: text/html; "
                 "charset=UTF-8\r\nConnection: close\r\n\r\n");
  output->append(html.c_str(), html.size());

  downstream->add_response_sent_bodylen(html.size());
  downstream->set_response_state(Downstream::MSG_COMPLETE);
}

void HttpsUpstream::attach_downstream(std::unique_ptr<Downstream> downstream) {
  assert(!downstream_);
  downstream_ = std::move(downstream);
}

void HttpsUpstream::delete_downstream() {
  if (downstream_ && downstream_->accesslog_ready()) {
    handler_->write_accesslog(downstream_.get());
  }

  downstream_.reset();
}

Downstream *HttpsUpstream::get_downstream() const { return downstream_.get(); }

std::unique_ptr<Downstream> HttpsUpstream::pop_downstream() {
  return std::unique_ptr<Downstream>(downstream_.release());
}

int HttpsUpstream::on_downstream_header_complete(Downstream *downstream) {
  if (LOG_ENABLED(INFO)) {
    if (downstream->get_non_final_response()) {
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

  if (!get_config()->http2_proxy && !get_config()->client_proxy &&
      !get_config()->no_location_rewrite) {
    downstream->rewrite_location_response_header(
        get_client_handler()->get_upstream_scheme());
  }

  http2::build_http1_headers_from_headers(hdrs,
                                          downstream->get_response_headers());

  auto output = downstream->get_response_buf();

  if (downstream->get_non_final_response()) {
    hdrs += "\r\n";

    if (LOG_ENABLED(INFO)) {
      log_response_headers(hdrs);
    }

    output->append(hdrs.c_str(), hdrs.size());

    downstream->clear_response_headers();

    return 0;
  }

  // after graceful shutdown commenced, add connection: close header
  // field.
  if (worker_config->graceful_shutdown) {
    downstream->set_response_connection_close(true);
  }

  // We check downstream->get_response_connection_close() in case when
  // the Content-Length is not available.
  if (!downstream->get_request_connection_close() &&
      !downstream->get_response_connection_close()) {
    if (downstream->get_request_major() <= 0 ||
        downstream->get_request_minor() <= 0) {
      // We add this header for HTTP/1.0 or HTTP/0.9 clients
      hdrs += "Connection: Keep-Alive\r\n";
    }
  } else if (!downstream->get_upgraded() ||
             downstream->get_request_method() != "CONNECT") {
    hdrs += "Connection: close\r\n";
  }

  if (!downstream->get_response_header(http2::HD_ALT_SVC)) {
    // We won't change or alter alt-svc from backend for now
    if (!get_config()->altsvcs.empty()) {
      hdrs += "Alt-Svc: ";

      for (auto &altsvc : get_config()->altsvcs) {
        hdrs += util::percent_encode_token(altsvc.protocol_id);
        hdrs += "=\"";
        hdrs += util::quote_string(std::string(altsvc.host, altsvc.host_len));
        hdrs += ":";
        hdrs += util::utos(altsvc.port);
        hdrs += "\", ";
      }

      hdrs[hdrs.size() - 2] = '\r';
      hdrs[hdrs.size() - 1] = '\n';
    }
  }

  if (!get_config()->http2_proxy && !get_config()->client_proxy) {
    hdrs += "Server: ";
    hdrs += get_config()->server_name;
    hdrs += "\r\n";
  } else {
    auto server = downstream->get_response_header(http2::HD_SERVER);
    if (server) {
      hdrs += "Server: ";
      hdrs += (*server).value;
      hdrs += "\r\n";
    }
  }

  auto via = downstream->get_response_header(http2::HD_VIA);
  if (get_config()->no_via) {
    if (via) {
      hdrs += "Via: ";
      hdrs += (*via).value;
      hdrs += "\r\n";
    }
  } else {
    hdrs += "Via: ";
    if (via) {
      hdrs += (*via).value;
      hdrs += ", ";
    }
    hdrs += http::create_via_header_value(downstream->get_response_major(),
                                          downstream->get_response_minor());
    hdrs += "\r\n";
  }

  for (auto &p : get_config()->add_response_headers) {
    hdrs += p.first;
    hdrs += ": ";
    hdrs += p.second;
    hdrs += "\r\n";
  }

  hdrs += "\r\n";

  if (LOG_ENABLED(INFO)) {
    log_response_headers(hdrs);
  }

  output->append(hdrs.c_str(), hdrs.size());

  return 0;
}

int HttpsUpstream::on_downstream_body(Downstream *downstream,
                                      const uint8_t *data, size_t len,
                                      bool flush) {
  if (len == 0) {
    return 0;
  }
  auto output = downstream->get_response_buf();
  if (downstream->get_chunked_response()) {
    auto chunk_size_hex = util::utox(len);
    chunk_size_hex += "\r\n";

    output->append(chunk_size_hex.c_str(), chunk_size_hex.size());
  }
  output->append(data, len);

  downstream->add_response_sent_bodylen(len);

  if (downstream->get_chunked_response()) {
    output->append("\r\n");
  }
  return 0;
}

int HttpsUpstream::on_downstream_body_complete(Downstream *downstream) {
  if (downstream->get_chunked_response()) {
    auto output = downstream->get_response_buf();
    output->append("0\r\n\r\n");
  }
  if (LOG_ENABLED(INFO)) {
    DLOG(INFO, downstream) << "HTTP response completed";
  }

  if (!downstream->validate_response_bodylen()) {
    downstream->set_response_connection_close(true);
  }

  if (downstream->get_request_connection_close() ||
      downstream->get_response_connection_close()) {
    auto handler = get_client_handler();
    handler->set_should_close_after_write(true);
  }
  return 0;
}

int HttpsUpstream::on_downstream_abort_request(Downstream *downstream,
                                               unsigned int status_code) {
  error_reply(status_code);
  handler_->signal_write();
  return 0;
}

void HttpsUpstream::log_response_headers(const std::string &hdrs) const {
  const char *hdrp;
  std::string nhdrs;
  if (worker_config->errorlog_tty) {
    nhdrs = http::colorizeHeaders(hdrs.c_str());
    hdrp = nhdrs.c_str();
  } else {
    hdrp = hdrs.c_str();
  }
  ULOG(INFO, this) << "HTTP response headers\n" << hdrp;
}

void HttpsUpstream::on_handler_delete() {
  if (downstream_ && downstream_->accesslog_ready()) {
    handler_->write_accesslog(downstream_.get());
  }
}

int HttpsUpstream::on_downstream_reset(bool no_retry) {
  int rv;

  if (!downstream_->request_submission_ready()) {
    // Return error so that caller can delete handler
    return -1;
  }

  downstream_->pop_downstream_connection();

  downstream_->add_retry();

  if (no_retry || downstream_->no_more_retry()) {
    if (on_downstream_abort_request(downstream_.get(), 503) != 0) {
      return -1;
    }
    return 0;
  }

  rv = downstream_->attach_downstream_connection(
      handler_->get_downstream_connection());
  if (rv != 0) {
    return -1;
  }
  return 0;
}

MemchunkPool *HttpsUpstream::get_mcpool() { return &mcpool_; }

} // namespace shrpx
