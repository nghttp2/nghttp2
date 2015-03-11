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
#include "shrpx_http2_downstream_connection.h"

#include <unistd.h>

#include "http-parser/http_parser.h"

#include "shrpx_client_handler.h"
#include "shrpx_upstream.h"
#include "shrpx_downstream.h"
#include "shrpx_config.h"
#include "shrpx_error.h"
#include "shrpx_http.h"
#include "shrpx_http2_session.h"
#include "http2.h"
#include "util.h"

using namespace nghttp2;

namespace shrpx {

Http2DownstreamConnection::Http2DownstreamConnection(
    DownstreamConnectionPool *dconn_pool, Http2Session *http2session)
    : DownstreamConnection(dconn_pool), dlnext(nullptr), dlprev(nullptr),
      http2session_(http2session), sd_(nullptr) {}

Http2DownstreamConnection::~Http2DownstreamConnection() {
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Deleting";
  }
  if (downstream_) {
    downstream_->disable_downstream_rtimer();
    downstream_->disable_downstream_wtimer();

    uint32_t error_code;
    if (downstream_->get_request_state() == Downstream::STREAM_CLOSED &&
        downstream_->get_upgraded()) {
      // For upgraded connection, send NO_ERROR.  Should we consider
      // request states other than Downstream::STREAM_CLOSED ?
      error_code = NGHTTP2_NO_ERROR;
    } else {
      error_code = NGHTTP2_INTERNAL_ERROR;
    }

    if (downstream_->get_downstream_stream_id() != -1) {
      if (LOG_ENABLED(INFO)) {
        DCLOG(INFO, this) << "Submit RST_STREAM for DOWNSTREAM:" << downstream_
                          << ", stream_id="
                          << downstream_->get_downstream_stream_id()
                          << ", error_code=" << error_code;
      }

      submit_rst_stream(downstream_, error_code);

      http2session_->consume(downstream_->get_downstream_stream_id(),
                             downstream_->get_response_datalen());

      downstream_->reset_response_datalen();

      http2session_->signal_write();
    }
  }
  http2session_->remove_downstream_connection(this);
  // Downstream and DownstreamConnection may be deleted
  // asynchronously.
  if (downstream_) {
    downstream_->release_downstream_connection();
  }
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Deleted";
  }
}

int Http2DownstreamConnection::attach_downstream(Downstream *downstream) {
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Attaching to DOWNSTREAM:" << downstream;
  }
  http2session_->add_downstream_connection(this);
  if (http2session_->get_state() == Http2Session::DISCONNECTED) {
    http2session_->signal_write();
  }

  downstream_ = downstream;
  downstream_->reset_downstream_rtimer();

  return 0;
}

void Http2DownstreamConnection::detach_downstream(Downstream *downstream) {
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Detaching from DOWNSTREAM:" << downstream;
  }
  if (submit_rst_stream(downstream) == 0) {
    http2session_->signal_write();
  }

  if (downstream_->get_downstream_stream_id() != -1) {
    http2session_->consume(downstream_->get_downstream_stream_id(),
                           downstream_->get_response_datalen());

    downstream_->reset_response_datalen();

    http2session_->signal_write();
  }

  downstream->disable_downstream_rtimer();
  downstream->disable_downstream_wtimer();
  downstream_ = nullptr;
}

int Http2DownstreamConnection::submit_rst_stream(Downstream *downstream,
                                                 uint32_t error_code) {
  int rv = -1;
  if (http2session_->get_state() == Http2Session::CONNECTED &&
      downstream->get_downstream_stream_id() != -1) {
    switch (downstream->get_response_state()) {
    case Downstream::MSG_RESET:
    case Downstream::MSG_BAD_HEADER:
    case Downstream::MSG_COMPLETE:
      break;
    default:
      if (LOG_ENABLED(INFO)) {
        DCLOG(INFO, this) << "Submit RST_STREAM for DOWNSTREAM:" << downstream
                          << ", stream_id="
                          << downstream->get_downstream_stream_id();
      }
      rv = http2session_->submit_rst_stream(
          downstream->get_downstream_stream_id(), error_code);
    }
  }
  return rv;
}

namespace {
ssize_t http2_data_read_callback(nghttp2_session *session, int32_t stream_id,
                                 uint8_t *buf, size_t length,
                                 uint32_t *data_flags,
                                 nghttp2_data_source *source, void *user_data) {
  int rv;
  auto sd = static_cast<StreamData *>(
      nghttp2_session_get_stream_user_data(session, stream_id));
  if (!sd || !sd->dconn) {
    return NGHTTP2_ERR_DEFERRED;
  }
  auto dconn = static_cast<Http2DownstreamConnection *>(source->ptr);
  auto downstream = dconn->get_downstream();
  if (!downstream) {
    // In this case, RST_STREAM should have been issued. But depending
    // on the priority, DATA frame may come first.
    return NGHTTP2_ERR_DEFERRED;
  }
  auto input = downstream->get_request_buf();
  auto nread = input->remove(buf, length);
  auto input_empty = input->rleft() == 0;

  if (nread > 0) {
    // This is important because it will handle flow control
    // stuff.
    if (downstream->get_upstream()->resume_read(SHRPX_NO_BUFFER, downstream,
                                                nread) != 0) {
      // In this case, downstream may be deleted.
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    // Check dconn is still alive because Upstream::resume_read()
    // may delete downstream which will delete dconn.
    if (sd->dconn == nullptr) {
      return NGHTTP2_ERR_DEFERRED;
    }
  }

  if (input_empty &&
      downstream->get_request_state() == Downstream::MSG_COMPLETE &&
      // If connection is upgraded, don't set EOF flag, since HTTP/1
      // will set MSG_COMPLETE to request state after upgrade response
      // header is seen.
      (!downstream->get_upgrade_request() ||
       (downstream->get_response_state() == Downstream::HEADER_COMPLETE &&
        !downstream->get_upgraded()))) {

    *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    auto &trailers = downstream->get_request_trailers();
    if (!trailers.empty()) {
      std::vector<nghttp2_nv> nva;
      nva.reserve(trailers.size());
      http2::copy_headers_to_nva(nva, trailers);
      if (!nva.empty()) {
        rv = nghttp2_submit_trailer(session, stream_id, nva.data(), nva.size());
        if (rv != 0) {
          if (nghttp2_is_fatal(rv)) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
          }
        } else {
          *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
        }
      }
    }
  }

  if (!input_empty) {
    downstream->reset_downstream_wtimer();
  } else {
    downstream->disable_downstream_wtimer();
  }

  if (nread == 0 && (*data_flags & NGHTTP2_DATA_FLAG_EOF) == 0) {
    downstream->disable_downstream_wtimer();

    return NGHTTP2_ERR_DEFERRED;
  }

  return nread;
}
} // namespace

int Http2DownstreamConnection::push_request_headers() {
  int rv;
  if (!downstream_) {
    return 0;
  }
  if (!http2session_->can_push_request()) {
    // The HTTP2 session to the backend has not been established or
    // connection is now being checked.  This function will be called
    // again just after it is established.
    downstream_->set_request_pending(true);
    http2session_->start_checking_connection();
    return 0;
  }

  downstream_->set_request_pending(false);

  auto no_host_rewrite = get_config()->no_host_rewrite ||
                         get_config()->http2_proxy ||
                         get_config()->client_proxy ||
                         downstream_->get_request_method() == "CONNECT";

  // http2session_ has already in CONNECTED state, so we can get
  // addr_idx here.
  auto addr_idx = http2session_->get_addr_idx();
  auto &downstream_addr = get_config()->downstream_addrs[addr_idx];

  const char *authority = nullptr, *host = nullptr;
  if (!no_host_rewrite) {
    // HTTP/2 backend does not support multiple address, so we always
    // use index = 0.
    if (!downstream_->get_request_http2_authority().empty()) {
      authority = downstream_addr.hostport.get();
    }
    if (downstream_->get_request_header(http2::HD_HOST)) {
      host = downstream_addr.hostport.get();
    }
  } else {
    if (!downstream_->get_request_http2_authority().empty()) {
      authority = downstream_->get_request_http2_authority().c_str();
    }
    auto h = downstream_->get_request_header(http2::HD_HOST);
    if (h) {
      host = h->value.c_str();
    }
  }

  if (!authority && !host) {
    // upstream is HTTP/1.0.  We use backend server's host
    // nonetheless.
    host = downstream_addr.hostport.get();
  }

  if (authority) {
    downstream_->set_request_downstream_host(authority);
  } else {
    downstream_->set_request_downstream_host(host);
  }

  size_t nheader = downstream_->get_request_headers().size();

  Headers cookies;
  if (!get_config()->http2_no_cookie_crumbling) {
    cookies = downstream_->crumble_request_cookie();
  }

  // 9 means:
  // 1. :method
  // 2. :scheme
  // 3. :path
  // 4. :authority (at least either :authority or host exists)
  // 5. host
  // 6. via (optional)
  // 7. x-forwarded-for (optional)
  // 8. x-forwarded-proto (optional)
  // 9. te (optional)
  auto nva = std::vector<nghttp2_nv>();
  nva.reserve(nheader + 9 + cookies.size());

  std::string via_value;
  std::string xff_value;
  std::string scheme, uri_authority, path, query;

  // To reconstruct HTTP/1 status line and headers, proxy should
  // preserve host header field. See draft-09 section 8.1.3.1.
  if (downstream_->get_request_method() == "CONNECT") {
    // The upstream may be HTTP/2 or HTTP/1
    if (authority) {
      nva.push_back(http2::make_nv_lc(":authority", authority));
    } else {
      nva.push_back(
          http2::make_nv_ls(":authority", downstream_->get_request_path()));
    }
  } else if (!downstream_->get_request_http2_scheme().empty()) {
    // Here the upstream is HTTP/2
    nva.push_back(
        http2::make_nv_ls(":scheme", downstream_->get_request_http2_scheme()));
    nva.push_back(http2::make_nv_ls(":path", downstream_->get_request_path()));
    if (authority) {
      nva.push_back(http2::make_nv_lc(":authority", authority));
    }
  } else {
    // The upstream is HTTP/1
    http_parser_url u;
    const char *url = downstream_->get_request_path().c_str();
    memset(&u, 0, sizeof(u));
    rv = http_parser_parse_url(url, downstream_->get_request_path().size(), 0,
                               &u);
    if (rv == 0) {
      http2::copy_url_component(scheme, &u, UF_SCHEMA, url);
      http2::copy_url_component(uri_authority, &u, UF_HOST, url);
      http2::copy_url_component(path, &u, UF_PATH, url);
      http2::copy_url_component(query, &u, UF_QUERY, url);
      if (path.empty()) {
        if (!uri_authority.empty() &&
            downstream_->get_request_method() == "OPTIONS") {
          path = "*";
        } else {
          path = "/";
        }
      }
      if (!query.empty()) {
        path += "?";
        path += query;
      }
    }
    if (scheme.empty()) {
      if (client_handler_->get_ssl()) {
        nva.push_back(http2::make_nv_ll(":scheme", "https"));
      } else {
        nva.push_back(http2::make_nv_ll(":scheme", "http"));
      }
    } else {
      nva.push_back(http2::make_nv_ls(":scheme", scheme));
    }
    if (path.empty()) {
      nva.push_back(
          http2::make_nv_ls(":path", downstream_->get_request_path()));
    } else {
      nva.push_back(http2::make_nv_ls(":path", path));
    }

    if (!no_host_rewrite) {
      if (authority) {
        nva.push_back(http2::make_nv_lc(":authority", authority));
      }
    } else if (!uri_authority.empty()) {
      // TODO properly check IPv6 numeric address
      if (uri_authority.find(":") != std::string::npos) {
        uri_authority = "[" + uri_authority;
        uri_authority += "]";
      }
      if (u.field_set & (1 << UF_PORT)) {
        uri_authority += ":";
        uri_authority += util::utos(u.port);
      }
      nva.push_back(http2::make_nv_ls(":authority", uri_authority));
    }
  }

  nva.push_back(
      http2::make_nv_ls(":method", downstream_->get_request_method()));

  if (host) {
    nva.push_back(http2::make_nv_lc("host", host));
  }

  http2::copy_headers_to_nva(nva, downstream_->get_request_headers());

  bool chunked_encoding = false;
  auto transfer_encoding =
      downstream_->get_request_header(http2::HD_TRANSFER_ENCODING);
  if (transfer_encoding &&
      util::strieq_l("chunked", (*transfer_encoding).value)) {
    chunked_encoding = true;
  }

  for (auto &nv : cookies) {
    nva.push_back(http2::make_nv(nv.name, nv.value, nv.no_index));
  }

  auto xff = downstream_->get_request_header(http2::HD_X_FORWARDED_FOR);
  if (get_config()->add_x_forwarded_for) {
    if (xff && !get_config()->strip_incoming_x_forwarded_for) {
      xff_value = (*xff).value;
      xff_value += ", ";
    }
    xff_value +=
        downstream_->get_upstream()->get_client_handler()->get_ipaddr();
    nva.push_back(http2::make_nv_ls("x-forwarded-for", xff_value));
  } else if (xff && !get_config()->strip_incoming_x_forwarded_for) {
    nva.push_back(http2::make_nv_ls("x-forwarded-for", (*xff).value));
  }

  if (!get_config()->http2_proxy && !get_config()->client_proxy &&
      downstream_->get_request_method() != "CONNECT") {
    // We use same protocol with :scheme header field
    if (scheme.empty()) {
      if (client_handler_->get_ssl()) {
        nva.push_back(http2::make_nv_ll("x-forwarded-proto", "https"));
      } else {
        nva.push_back(http2::make_nv_ll("x-forwarded-proto", "http"));
      }
    } else {
      nva.push_back(http2::make_nv_ls("x-forwarded-proto", scheme));
    }
  }

  auto via = downstream_->get_request_header(http2::HD_VIA);
  if (get_config()->no_via) {
    if (via) {
      nva.push_back(http2::make_nv_ls("via", (*via).value));
    }
  } else {
    if (via) {
      via_value = (*via).value;
      via_value += ", ";
    }
    via_value += http::create_via_header_value(
        downstream_->get_request_major(), downstream_->get_request_minor());
    nva.push_back(http2::make_nv_ls("via", via_value));
  }

  auto te = downstream_->get_request_header(http2::HD_TE);
  if (te) {
    nva.push_back(http2::make_nv_ls("te", te->value));
  }

  if (LOG_ENABLED(INFO)) {
    std::stringstream ss;
    for (auto &nv : nva) {
      ss << TTY_HTTP_HD;
      ss.write(reinterpret_cast<const char *>(nv.name), nv.namelen);
      ss << TTY_RST << ": ";
      ss.write(reinterpret_cast<const char *>(nv.value), nv.valuelen);
      ss << "\n";
    }
    DCLOG(INFO, this) << "HTTP request headers\n" << ss.str();
  }

  auto content_length =
      downstream_->get_request_header(http2::HD_CONTENT_LENGTH);
  // TODO check content-length: 0 case

  if (downstream_->get_request_method() == "CONNECT" || chunked_encoding ||
      content_length || downstream_->get_request_http2_expect_body()) {
    // Request-body is expected.
    nghttp2_data_provider data_prd;
    data_prd.source.ptr = this;
    data_prd.read_callback = http2_data_read_callback;
    rv = http2session_->submit_request(this, downstream_->get_priority(),
                                       nva.data(), nva.size(), &data_prd);
  } else {
    rv = http2session_->submit_request(this, downstream_->get_priority(),
                                       nva.data(), nva.size(), nullptr);
  }
  if (rv != 0) {
    DCLOG(FATAL, this) << "nghttp2_submit_request() failed";
    return -1;
  }

  downstream_->reset_downstream_wtimer();

  http2session_->signal_write();
  return 0;
}

int Http2DownstreamConnection::push_upload_data_chunk(const uint8_t *data,
                                                      size_t datalen) {
  int rv;
  auto output = downstream_->get_request_buf();
  output->append(data, datalen);
  if (downstream_->get_downstream_stream_id() != -1) {
    rv = http2session_->resume_data(this);
    if (rv != 0) {
      return -1;
    }

    downstream_->ensure_downstream_wtimer();

    http2session_->signal_write();
  }
  return 0;
}

int Http2DownstreamConnection::end_upload_data() {
  int rv;
  if (downstream_->get_downstream_stream_id() != -1) {
    rv = http2session_->resume_data(this);
    if (rv != 0) {
      return -1;
    }

    downstream_->ensure_downstream_wtimer();

    http2session_->signal_write();
  }
  return 0;
}

int Http2DownstreamConnection::resume_read(IOCtrlReason reason,
                                           size_t consumed) {
  int rv;

  if (http2session_->get_state() != Http2Session::CONNECTED ||
      !http2session_->get_flow_control()) {
    return 0;
  }

  if (!downstream_ || downstream_->get_downstream_stream_id() == -1) {
    return 0;
  }

  if (consumed > 0) {
    assert(downstream_->get_response_datalen() >= consumed);

    rv = http2session_->consume(downstream_->get_downstream_stream_id(),
                                consumed);

    if (rv != 0) {
      return -1;
    }

    downstream_->dec_response_datalen(consumed);

    http2session_->signal_write();
  }

  return 0;
}

int Http2DownstreamConnection::on_read() { return 0; }

int Http2DownstreamConnection::on_write() { return 0; }

void Http2DownstreamConnection::attach_stream_data(StreamData *sd) {
  // It is possible sd->dconn is not NULL. sd is detached when
  // on_stream_close_callback. Before that, after MSG_COMPLETE is set
  // to Downstream::set_response_state(), upstream's readcb is called
  // and execution path eventually could reach here. Since the
  // response was already handled, we just detach sd.
  detach_stream_data();
  sd_ = sd;
  sd_->dconn = this;
}

StreamData *Http2DownstreamConnection::detach_stream_data() {
  if (sd_) {
    auto sd = sd_;
    sd_ = nullptr;
    sd->dconn = nullptr;
    return sd;
  }
  return nullptr;
}

int Http2DownstreamConnection::on_priority_change(int32_t pri) {
  int rv;
  if (downstream_->get_priority() == pri) {
    return 0;
  }
  downstream_->set_priority(pri);
  if (http2session_->get_state() != Http2Session::CONNECTED) {
    return 0;
  }
  rv = http2session_->submit_priority(this, pri);
  if (rv != 0) {
    DLOG(FATAL, this) << "nghttp2_submit_priority() failed";
    return -1;
  }
  http2session_->signal_write();
  return 0;
}

int Http2DownstreamConnection::on_timeout() {
  if (!downstream_) {
    return 0;
  }

  return submit_rst_stream(downstream_, NGHTTP2_NO_ERROR);
}

} // namespace shrpx
