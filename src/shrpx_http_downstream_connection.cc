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
#include "shrpx_log_config.h"
#include "shrpx_connect_blocker.h"
#include "shrpx_downstream_connection_pool.h"
#include "shrpx_worker.h"
#include "shrpx_http2_session.h"
#include "http2.h"
#include "util.h"

using namespace nghttp2;

namespace shrpx {

namespace {
void timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto conn = static_cast<Connection *>(w->data);
  auto dconn = static_cast<HttpDownstreamConnection *>(conn->data);

  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, dconn) << "Time out";
  }

  auto downstream = dconn->get_downstream();
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();

  // Do this so that dconn is not pooled
  downstream->set_response_connection_close(true);

  if (upstream->downstream_error(dconn, Downstream::EVENT_TIMEOUT) != 0) {
    delete handler;
  }
}
} // namespace

namespace {
void readcb(struct ev_loop *loop, ev_io *w, int revents) {
  auto conn = static_cast<Connection *>(w->data);
  auto dconn = static_cast<HttpDownstreamConnection *>(conn->data);
  auto downstream = dconn->get_downstream();
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();

  if (upstream->downstream_read(dconn) != 0) {
    delete handler;
  }
}
} // namespace

namespace {
void writecb(struct ev_loop *loop, ev_io *w, int revents) {
  auto conn = static_cast<Connection *>(w->data);
  auto dconn = static_cast<HttpDownstreamConnection *>(conn->data);
  auto downstream = dconn->get_downstream();
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();

  if (upstream->downstream_write(dconn) != 0) {
    delete handler;
  }
}
} // namespace

namespace {
void connectcb(struct ev_loop *loop, ev_io *w, int revents) {
  auto conn = static_cast<Connection *>(w->data);
  auto dconn = static_cast<HttpDownstreamConnection *>(conn->data);
  auto downstream = dconn->get_downstream();
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();
  if (dconn->on_connect() != 0) {
    if (upstream->on_downstream_abort_request(downstream, 503) != 0) {
      delete handler;
    }
    return;
  }
  writecb(loop, w, revents);
}
} // namespace

HttpDownstreamConnection::HttpDownstreamConnection(
    DownstreamConnectionPool *dconn_pool, size_t group, struct ev_loop *loop)
    : DownstreamConnection(dconn_pool),
      conn_(loop, -1, nullptr, nullptr, get_config()->downstream_write_timeout,
            get_config()->downstream_read_timeout, 0, 0, 0, 0, connectcb,
            readcb, timeoutcb, this),
      ioctrl_(&conn_.rlimit), response_htp_{0}, group_(group), addr_idx_(0),
      connected_(false) {}

HttpDownstreamConnection::~HttpDownstreamConnection() {}

int HttpDownstreamConnection::attach_downstream(Downstream *downstream) {
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Attaching to DOWNSTREAM:" << downstream;
  }

  if (conn_.fd == -1) {
    auto connect_blocker = client_handler_->get_connect_blocker();

    if (connect_blocker->blocked()) {
      if (LOG_ENABLED(INFO)) {
        DCLOG(INFO, this)
            << "Downstream connection was blocked by connect_blocker";
      }
      return -1;
    }

    auto worker = client_handler_->get_worker();
    auto &next_downstream = worker->get_dgrp(group_)->next;
    auto end = next_downstream;
    auto &addrs = get_config()->downstream_addr_groups[group_].addrs;
    for (;;) {
      auto &addr = addrs[next_downstream];
      auto i = next_downstream;
      if (++next_downstream >= addrs.size()) {
        next_downstream = 0;
      }

      conn_.fd = util::create_nonblock_socket(addr.addr.su.storage.ss_family);

      if (conn_.fd == -1) {
        auto error = errno;
        DCLOG(WARN, this) << "socket() failed; errno=" << error;

        connect_blocker->on_failure();

        return SHRPX_ERR_NETWORK;
      }

      int rv;
      rv = connect(conn_.fd, &addr.addr.su.sa, addr.addr.len);
      if (rv != 0 && errno != EINPROGRESS) {
        auto error = errno;
        DCLOG(WARN, this) << "connect() failed; errno=" << error;

        connect_blocker->on_failure();
        close(conn_.fd);
        conn_.fd = -1;

        if (end == next_downstream) {
          return SHRPX_ERR_NETWORK;
        }

        // Try again with the next downstream server
        continue;
      }

      if (LOG_ENABLED(INFO)) {
        DCLOG(INFO, this) << "Connecting to downstream server";
      }

      addr_idx_ = i;

      ev_io_set(&conn_.wev, conn_.fd, EV_WRITE);
      ev_io_set(&conn_.rev, conn_.fd, EV_READ);

      conn_.wlimit.startw();

      break;
    }

    // TODO we should have timeout for connection establishment
    ev_timer_again(conn_.loop, &conn_.wt);
  } else {
    // we may set read timer cb to idle_timeoutcb.  Reset again.
    conn_.rt.repeat = get_config()->downstream_read_timeout;
    ev_set_cb(&conn_.rt, timeoutcb);
    ev_timer_again(conn_.loop, &conn_.rt);
    ev_set_cb(&conn_.rev, readcb);
  }

  downstream_ = downstream;

  http_parser_init(&response_htp_, HTTP_RESPONSE);
  response_htp_.data = downstream_;

  return 0;
}

int HttpDownstreamConnection::push_request_headers() {
  const char *authority = nullptr, *host = nullptr;
  auto downstream_hostport = get_config()
                                 ->downstream_addr_groups[group_]
                                 .addrs[addr_idx_]
                                 .hostport.get();
  auto connect_method = downstream_->get_request_method() == HTTP_CONNECT;

  if (!get_config()->no_host_rewrite && !get_config()->http2_proxy &&
      !get_config()->client_proxy && !connect_method) {
    if (!downstream_->get_request_http2_authority().empty()) {
      authority = downstream_hostport;
    }
    if (downstream_->get_request_header(http2::HD_HOST)) {
      host = downstream_hostport;
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
    host = downstream_hostport;
  }

  if (authority) {
    downstream_->set_request_downstream_host(authority);
  } else {
    downstream_->set_request_downstream_host(host);
  }

  downstream_->assemble_request_cookie();

  // Assume that method and request path do not contain \r\n.
  std::string hdrs = http2::to_method_string(downstream_->get_request_method());
  hdrs += ' ';

  auto &scheme = downstream_->get_request_http2_scheme();

  if (connect_method) {
    if (authority) {
      hdrs += authority;
    } else {
      hdrs += downstream_->get_request_path();
    }
  } else if (get_config()->http2_proxy || get_config()->client_proxy) {
    // Construct absolute-form request target because we are going to
    // send a request to a HTTP/1 proxy.
    assert(!scheme.empty());
    hdrs += scheme;
    hdrs += "://";

    if (authority) {
      hdrs += authority;
    } else {
      hdrs += host;
    }

    // Server-wide OPTIONS takes following form in proxy request:
    //
    // OPTIONS http://example.org HTTP/1.1
    //
    // Notice that no slash after authority. See
    // http://tools.ietf.org/html/rfc7230#section-5.3.4
    if (downstream_->get_request_path() != "*") {
      hdrs += downstream_->get_request_path();
    }
  } else {
    // No proxy case.
    hdrs += downstream_->get_request_path();
  }
  hdrs += " HTTP/1.1\r\nHost: ";
  if (authority) {
    hdrs += authority;
  } else {
    hdrs += host;
  }
  hdrs += "\r\n";

  http2::build_http1_headers_from_headers(hdrs,
                                          downstream_->get_request_headers());

  if (!downstream_->get_assembled_request_cookie().empty()) {
    hdrs += "Cookie: ";
    hdrs += downstream_->get_assembled_request_cookie();
    hdrs += "\r\n";
  }

  if (!connect_method && downstream_->get_request_http2_expect_body() &&
      !downstream_->get_request_header(http2::HD_CONTENT_LENGTH)) {

    downstream_->set_chunked_request(true);
    hdrs += "Transfer-Encoding: chunked\r\n";
  }

  if (downstream_->get_request_connection_close()) {
    hdrs += "Connection: close\r\n";
  }

  if (!connect_method && downstream_->get_upgrade_request()) {
    auto connection = downstream_->get_request_header(http2::HD_CONNECTION);
    if (connection) {
      hdrs += "Connection: ";
      hdrs += (*connection).value;
      hdrs += "\r\n";
    }

    auto upgrade = downstream_->get_request_header(http2::HD_UPGRADE);
    if (upgrade) {
      hdrs += "Upgrade: ";
      hdrs += (*upgrade).value;
      hdrs += "\r\n";
    }
  }

  auto xff = downstream_->get_request_header(http2::HD_X_FORWARDED_FOR);
  if (get_config()->add_x_forwarded_for) {
    hdrs += "X-Forwarded-For: ";
    if (xff && !get_config()->strip_incoming_x_forwarded_for) {
      hdrs += (*xff).value;
      hdrs += ", ";
    }
    hdrs += client_handler_->get_ipaddr();
    hdrs += "\r\n";
  } else if (xff && !get_config()->strip_incoming_x_forwarded_for) {
    hdrs += "X-Forwarded-For: ";
    hdrs += (*xff).value;
    hdrs += "\r\n";
  }
  if (!get_config()->http2_proxy && !get_config()->client_proxy &&
      !connect_method) {
    hdrs += "X-Forwarded-Proto: ";
    assert(!scheme.empty());
    hdrs += scheme;
    hdrs += "\r\n";
  }
  auto via = downstream_->get_request_header(http2::HD_VIA);
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
    hdrs += http::create_via_header_value(downstream_->get_request_major(),
                                          downstream_->get_request_minor());
    hdrs += "\r\n";
  }

  for (auto &p : get_config()->add_request_headers) {
    hdrs += p.first;
    hdrs += ": ";
    hdrs += p.second;
    hdrs += "\r\n";
  }

  hdrs += "\r\n";
  if (LOG_ENABLED(INFO)) {
    const char *hdrp;
    std::string nhdrs;
    if (log_config()->errorlog_tty) {
      nhdrs = http::colorizeHeaders(hdrs.c_str());
      hdrp = nhdrs.c_str();
    } else {
      hdrp = hdrs.c_str();
    }
    DCLOG(INFO, this) << "HTTP request headers. stream_id="
                      << downstream_->get_stream_id() << "\n" << hdrp;
  }
  auto output = downstream_->get_request_buf();
  output->append(hdrs.c_str(), hdrs.size());

  signal_write();

  return 0;
}

int HttpDownstreamConnection::push_upload_data_chunk(const uint8_t *data,
                                                     size_t datalen) {
  auto chunked = downstream_->get_chunked_request();
  auto output = downstream_->get_request_buf();

  if (chunked) {
    auto chunk_size_hex = util::utox(datalen);
    output->append(chunk_size_hex.c_str(), chunk_size_hex.size());
    output->append("\r\n");
  }

  output->append(data, datalen);

  if (chunked) {
    output->append("\r\n");
  }

  signal_write();

  return 0;
}

int HttpDownstreamConnection::end_upload_data() {
  if (!downstream_->get_chunked_request()) {
    return 0;
  }

  auto output = downstream_->get_request_buf();
  auto &trailers = downstream_->get_request_trailers();
  if (trailers.empty()) {
    output->append("0\r\n\r\n");
  } else {
    output->append("0\r\n");
    std::string trailer_part;
    http2::build_http1_headers_from_headers(trailer_part, trailers);
    output->append(trailer_part.c_str(), trailer_part.size());
    output->append("\r\n");
  }

  signal_write();

  return 0;
}

namespace {
void idle_readcb(struct ev_loop *loop, ev_io *w, int revents) {
  auto conn = static_cast<Connection *>(w->data);
  auto dconn = static_cast<HttpDownstreamConnection *>(conn->data);
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, dconn) << "Idle connection EOF";
  }
  auto dconn_pool = dconn->get_dconn_pool();
  dconn_pool->remove_downstream_connection(dconn);
  // dconn was deleted
}
} // namespace

namespace {
void idle_timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto conn = static_cast<Connection *>(w->data);
  auto dconn = static_cast<HttpDownstreamConnection *>(conn->data);
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, dconn) << "Idle connection timeout";
  }
  auto dconn_pool = dconn->get_dconn_pool();
  dconn_pool->remove_downstream_connection(dconn);
  // dconn was deleted
}
} // namespace

void HttpDownstreamConnection::detach_downstream(Downstream *downstream) {
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Detaching from DOWNSTREAM:" << downstream;
  }
  downstream_ = nullptr;

  ev_set_cb(&conn_.rev, idle_readcb);
  ioctrl_.force_resume_read();

  conn_.rt.repeat = get_config()->downstream_idle_read_timeout;
  ev_set_cb(&conn_.rt, idle_timeoutcb);
  ev_timer_again(conn_.loop, &conn_.rt);

  conn_.wlimit.stopw();
  ev_timer_stop(conn_.loop, &conn_.wt);
}

void HttpDownstreamConnection::pause_read(IOCtrlReason reason) {
  ioctrl_.pause_read(reason);
}

int HttpDownstreamConnection::resume_read(IOCtrlReason reason,
                                          size_t consumed) {
  if (!downstream_->response_buf_full()) {
    ioctrl_.resume_read(reason);
  }

  return 0;
}

void HttpDownstreamConnection::force_resume_read() {
  ioctrl_.force_resume_read();
}

namespace {
int htp_msg_begincb(http_parser *htp) {
  auto downstream = static_cast<Downstream *>(htp->data);

  if (downstream->get_response_state() != Downstream::INITIAL) {
    return -1;
  }

  return 0;
}
} // namespace

namespace {
int htp_hdrs_completecb(http_parser *htp) {
  auto downstream = static_cast<Downstream *>(htp->data);
  auto upstream = downstream->get_upstream();
  int rv;

  downstream->set_response_http_status(htp->status_code);
  downstream->set_response_major(htp->http_major);
  downstream->set_response_minor(htp->http_minor);

  if (downstream->index_response_headers() != 0) {
    downstream->set_response_state(Downstream::MSG_BAD_HEADER);
    return -1;
  }

  // Check upgrade before processing non-final response, since if
  // upgrade succeeded, 101 response is treated as final in nghttpx.
  downstream->check_upgrade_fulfilled();

  if (downstream->get_non_final_response()) {
    // Reset content-length because we reuse same Downstream for the
    // next response.
    downstream->set_response_content_length(-1);
    // For non-final response code, we just call
    // on_downstream_header_complete() without changing response
    // state.
    rv = upstream->on_downstream_header_complete(downstream);

    if (rv != 0) {
      return -1;
    }

    // Ignore response body for non-final response.
    return 1;
  }

  downstream->set_response_connection_close(!http_should_keep_alive(htp));
  downstream->set_response_state(Downstream::HEADER_COMPLETE);
  downstream->inspect_http1_response();
  if (downstream->get_upgraded()) {
    // content-length must be ignored for upgraded connection.
    downstream->set_response_content_length(-1);
    downstream->set_response_connection_close(true);
    // transfer-encoding not applied to upgraded connection
    downstream->set_chunked_response(false);
  }
  if (upstream->on_downstream_header_complete(downstream) != 0) {
    return -1;
  }

  if (downstream->get_upgraded()) {
    // Upgrade complete, read until EOF in both ends
    if (upstream->resume_read(SHRPX_NO_BUFFER, downstream, 0) != 0) {
      return -1;
    }
    downstream->set_request_state(Downstream::HEADER_COMPLETE);
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "HTTP upgrade success. stream_id="
                << downstream->get_stream_id();
    }
  }

  unsigned int status = downstream->get_response_http_status();
  // Ignore the response body. HEAD response may contain
  // Content-Length or Transfer-Encoding: chunked.  Some server send
  // 304 status code with nonzero Content-Length, but without response
  // body. See
  // https://tools.ietf.org/html/rfc7230#section-3.3

  // TODO It seems that the cases other than HEAD are handled by
  // http-parser.  Need test.
  return downstream->get_request_method() == HTTP_HEAD ||
                 (100 <= status && status <= 199) || status == 204 ||
                 status == 304
             ? 1
             : 0;
}
} // namespace

namespace {
int htp_hdr_keycb(http_parser *htp, const char *data, size_t len) {
  auto downstream = static_cast<Downstream *>(htp->data);

  if (downstream->get_response_headers_sum() + len >
      get_config()->header_field_buffer) {
    if (LOG_ENABLED(INFO)) {
      DLOG(INFO, downstream) << "Too large header block size="
                             << downstream->get_response_headers_sum() + len;
    }
    return -1;
  }

  if (downstream->get_response_state() == Downstream::INITIAL) {
    if (downstream->get_response_header_key_prev()) {
      downstream->append_last_response_header_key(data, len);
    } else {
      if (downstream->get_response_headers().size() >=
          get_config()->max_header_fields) {
        if (LOG_ENABLED(INFO)) {
          DLOG(INFO, downstream)
              << "Too many header field num="
              << downstream->get_response_headers().size() + 1;
        }
        return -1;
      }
      downstream->add_response_header(std::string(data, len), "");
    }
  } else {
    // trailer part
    if (downstream->get_response_trailer_key_prev()) {
      downstream->append_last_response_trailer_key(data, len);
    } else {
      if (downstream->get_response_headers().size() >=
          get_config()->max_header_fields) {
        if (LOG_ENABLED(INFO)) {
          DLOG(INFO, downstream)
              << "Too many header field num="
              << downstream->get_response_headers().size() + 1;
        }
        return -1;
      }
      downstream->add_response_trailer(std::string(data, len), "");
    }
  }
  return 0;
}
} // namespace

namespace {
int htp_hdr_valcb(http_parser *htp, const char *data, size_t len) {
  auto downstream = static_cast<Downstream *>(htp->data);
  if (downstream->get_response_headers_sum() + len >
      get_config()->header_field_buffer) {
    if (LOG_ENABLED(INFO)) {
      DLOG(INFO, downstream) << "Too large header block size="
                             << downstream->get_response_headers_sum() + len;
    }
    return -1;
  }
  if (downstream->get_response_state() == Downstream::INITIAL) {
    if (downstream->get_response_header_key_prev()) {
      downstream->set_last_response_header_value(data, len);
    } else {
      downstream->append_last_response_header_value(data, len);
    }
  } else {
    if (downstream->get_response_trailer_key_prev()) {
      downstream->set_last_response_trailer_value(data, len);
    } else {
      downstream->append_last_response_trailer_value(data, len);
    }
  }
  return 0;
}
} // namespace

namespace {
int htp_bodycb(http_parser *htp, const char *data, size_t len) {
  auto downstream = static_cast<Downstream *>(htp->data);

  downstream->add_response_bodylen(len);

  return downstream->get_upstream()->on_downstream_body(
      downstream, reinterpret_cast<const uint8_t *>(data), len, true);
}
} // namespace

namespace {
int htp_msg_completecb(http_parser *htp) {
  auto downstream = static_cast<Downstream *>(htp->data);

  // http-parser does not treat "200 connection established" response
  // against CONNECT request, and in that case, this function is not
  // called.  But if HTTP Upgrade is made (e.g., WebSocket), this
  // function is called, and http_parser_execute() returns just after
  // that.
  if (downstream->get_upgraded()) {
    return 0;
  }

  if (downstream->get_non_final_response()) {
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
    htp_msg_begincb,     // http_cb on_message_begin;
    nullptr,             // http_data_cb on_url;
    nullptr,             // http_data_cb on_status;
    htp_hdr_keycb,       // http_data_cb on_header_field;
    htp_hdr_valcb,       // http_data_cb on_header_value;
    htp_hdrs_completecb, // http_cb      on_headers_complete;
    htp_bodycb,          // http_data_cb on_body;
    htp_msg_completecb   // http_cb      on_message_complete;
};
} // namespace

int HttpDownstreamConnection::on_read() {
  if (!connected_) {
    return 0;
  }

  ev_timer_again(conn_.loop, &conn_.rt);
  std::array<uint8_t, 8_k> buf;
  int rv;

  if (downstream_->get_upgraded()) {
    // For upgraded connection, just pass data to the upstream.
    for (;;) {
      auto nread = conn_.read_clear(buf.data(), buf.size());

      if (nread == 0) {
        return 0;
      }

      if (nread < 0) {
        return nread;
      }

      rv = downstream_->get_upstream()->on_downstream_body(
          downstream_, buf.data(), nread, true);
      if (rv != 0) {
        return rv;
      }

      if (downstream_->response_buf_full()) {
        downstream_->pause_read(SHRPX_NO_BUFFER);
        return 0;
      }
    }
  }

  for (;;) {
    auto nread = conn_.read_clear(buf.data(), buf.size());

    if (nread == 0) {
      return 0;
    }

    if (nread < 0) {
      return nread;
    }

    auto nproc =
        http_parser_execute(&response_htp_, &htp_hooks,
                            reinterpret_cast<char *>(buf.data()), nread);

    auto htperr = HTTP_PARSER_ERRNO(&response_htp_);

    if (htperr != HPE_OK) {
      if (LOG_ENABLED(INFO)) {
        DCLOG(INFO, this) << "HTTP parser failure: "
                          << "(" << http_errno_name(htperr) << ") "
                          << http_errno_description(htperr);
      }

      return -1;
    }

    if (downstream_->response_buf_full()) {
      downstream_->pause_read(SHRPX_NO_BUFFER);
      return 0;
    }

    if (downstream_->get_upgraded()) {
      if (nproc < static_cast<size_t>(nread)) {
        // Data from buf.data() + nproc are for upgraded protocol.
        rv = downstream_->get_upstream()->on_downstream_body(
            downstream_, buf.data() + nproc, nread - nproc, true);
        if (rv != 0) {
          return rv;
        }

        if (downstream_->response_buf_full()) {
          downstream_->pause_read(SHRPX_NO_BUFFER);
          return 0;
        }
      }
      // call on_read(), so that we can process data left in buffer as
      // upgrade.
      return on_read();
    }
  }
}

int HttpDownstreamConnection::on_write() {
  if (!connected_) {
    return 0;
  }

  ev_timer_again(conn_.loop, &conn_.rt);

  auto upstream = downstream_->get_upstream();
  auto input = downstream_->get_request_buf();

  std::array<struct iovec, MAX_WR_IOVCNT> iov;

  while (input->rleft() > 0) {
    auto iovcnt = input->riovec(iov.data(), iov.size());

    auto nwrite = conn_.writev_clear(iov.data(), iovcnt);

    if (nwrite == 0) {
      return 0;
    }

    if (nwrite < 0) {
      return nwrite;
    }

    input->drain(nwrite);
  }

  conn_.wlimit.stopw();
  ev_timer_stop(conn_.loop, &conn_.wt);

  if (input->rleft() == 0) {
    upstream->resume_read(SHRPX_NO_BUFFER, downstream_,
                          downstream_->get_request_datalen());
  }

  return 0;
}

int HttpDownstreamConnection::on_connect() {
  auto connect_blocker = client_handler_->get_connect_blocker();

  if (!util::check_socket_connected(conn_.fd)) {
    conn_.wlimit.stopw();

    if (LOG_ENABLED(INFO)) {
      DLOG(INFO, this) << "downstream connect failed";
    }

    downstream_->set_request_state(Downstream::CONNECT_FAIL);

    return -1;
  }

  connected_ = true;

  connect_blocker->on_success();

  conn_.rlimit.startw();
  ev_timer_again(conn_.loop, &conn_.rt);

  ev_set_cb(&conn_.wev, writecb);

  return 0;
}

void HttpDownstreamConnection::on_upstream_change(Upstream *upstream) {}

void HttpDownstreamConnection::signal_write() { conn_.wlimit.startw(); }

size_t HttpDownstreamConnection::get_group() const { return group_; }

} // namespace shrpx
