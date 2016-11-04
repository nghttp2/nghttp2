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
#include "shrpx_ssl.h"
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
  auto &resp = downstream->response();

  // Do this so that dconn is not pooled
  resp.connection_close = true;

  if (upstream->downstream_error(dconn, Downstream::EVENT_TIMEOUT) != 0) {
    delete handler;
  }
}
} // namespace

namespace {
void connect_timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto conn = static_cast<Connection *>(w->data);
  auto dconn = static_cast<HttpDownstreamConnection *>(conn->data);
  auto addr = dconn->get_addr();

  DCLOG(WARN, dconn) << "Connect time out; addr="
                     << util::to_numeric_addr(&addr->addr);

  downstream_failure(addr);

  auto downstream = dconn->get_downstream();
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();

  downstream->pop_downstream_connection();

  auto ndconn = handler->get_downstream_connection(downstream);
  if (ndconn) {
    if (downstream->attach_downstream_connection(std::move(ndconn)) == 0) {
      return;
    }
  }

  downstream->set_request_state(Downstream::CONNECT_FAIL);

  if (upstream->on_downstream_abort_request(downstream, 504) != 0) {
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
  if (dconn->connected() != 0) {
    downstream->pop_downstream_connection();

    auto ndconn = handler->get_downstream_connection(downstream);
    if (ndconn) {
      if (downstream->attach_downstream_connection(std::move(ndconn)) == 0) {
        return;
      }
    }

    downstream->set_request_state(Downstream::CONNECT_FAIL);

    if (upstream->on_downstream_abort_request(downstream, 503) != 0) {
      delete handler;
    }
    return;
  }
  writecb(loop, w, revents);
}
} // namespace

HttpDownstreamConnection::HttpDownstreamConnection(
    const std::shared_ptr<DownstreamAddrGroup> &group, ssize_t initial_addr_idx,
    struct ev_loop *loop, Worker *worker)
    : conn_(loop, -1, nullptr, worker->get_mcpool(),
            worker->get_downstream_config()->timeout.write,
            worker->get_downstream_config()->timeout.read, {}, {}, connectcb,
            readcb, connect_timeoutcb, this,
            get_config()->tls.dyn_rec.warmup_threshold,
            get_config()->tls.dyn_rec.idle_timeout, PROTO_HTTP1),
      do_read_(&HttpDownstreamConnection::noop),
      do_write_(&HttpDownstreamConnection::noop),
      do_signal_write_(&HttpDownstreamConnection::noop),
      worker_(worker),
      ssl_ctx_(worker->get_cl_ssl_ctx()),
      group_(group),
      addr_(nullptr),
      ioctrl_(&conn_.rlimit),
      response_htp_{0},
      initial_addr_idx_(initial_addr_idx) {}

HttpDownstreamConnection::~HttpDownstreamConnection() {
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Deleted";
  }
}

int HttpDownstreamConnection::attach_downstream(Downstream *downstream) {
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Attaching to DOWNSTREAM:" << downstream;
  }

  auto worker_blocker = worker_->get_connect_blocker();
  if (worker_blocker->blocked()) {
    if (LOG_ENABLED(INFO)) {
      DCLOG(INFO, this)
          << "Worker wide backend connection was blocked temporarily";
    }
    return SHRPX_ERR_NETWORK;
  }

  auto &downstreamconf = *worker_->get_downstream_config();

  if (conn_.fd == -1) {
    auto &shared_addr = group_->shared_addr;
    auto &addrs = shared_addr->addrs;

    // If session affinity is enabled, we always start with address at
    // initial_addr_idx_.
    size_t temp_idx = initial_addr_idx_;

    auto &next_downstream =
        shared_addr->affinity == AFFINITY_NONE ? shared_addr->next : temp_idx;
    auto end = next_downstream;
    for (;;) {
      auto &addr = addrs[next_downstream];

      if (++next_downstream >= addrs.size()) {
        next_downstream = 0;
      }

      if (addr.proto != PROTO_HTTP1) {
        if (end == next_downstream) {
          return SHRPX_ERR_NETWORK;
        }

        continue;
      }

      auto &connect_blocker = addr.connect_blocker;

      if (connect_blocker->blocked()) {
        if (LOG_ENABLED(INFO)) {
          DCLOG(INFO, this) << "Backend server "
                            << util::to_numeric_addr(&addr.addr)
                            << " was not available temporarily";
        }

        if (end == next_downstream) {
          return SHRPX_ERR_NETWORK;
        }

        continue;
      }

      conn_.fd = util::create_nonblock_socket(addr.addr.su.storage.ss_family);

      if (conn_.fd == -1) {
        auto error = errno;
        DCLOG(WARN, this) << "socket() failed; addr="
                          << util::to_numeric_addr(&addr.addr)
                          << ", errno=" << error;

        worker_blocker->on_failure();

        return SHRPX_ERR_NETWORK;
      }

      worker_blocker->on_success();

      int rv;
      rv = connect(conn_.fd, &addr.addr.su.sa, addr.addr.len);
      if (rv != 0 && errno != EINPROGRESS) {
        auto error = errno;
        DCLOG(WARN, this) << "connect() failed; addr="
                          << util::to_numeric_addr(&addr.addr)
                          << ", errno=" << error;

        downstream_failure(&addr);

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

      addr_ = &addr;

      if (addr_->tls) {
        assert(ssl_ctx_);

        auto ssl = ssl::create_ssl(ssl_ctx_);
        if (!ssl) {
          return -1;
        }

        ssl::setup_downstream_http1_alpn(ssl);

        conn_.set_ssl(ssl);

        auto sni_name =
            addr_->sni.empty() ? StringRef{addr_->host} : StringRef{addr_->sni};
        if (!util::numeric_host(sni_name.c_str())) {
          SSL_set_tlsext_host_name(conn_.tls.ssl, sni_name.c_str());
        }

        auto session = ssl::reuse_tls_session(addr_->tls_session_cache);
        if (session) {
          SSL_set_session(conn_.tls.ssl, session);
          SSL_SESSION_free(session);
        }

        conn_.prepare_client_handshake();
      }

      ev_io_set(&conn_.wev, conn_.fd, EV_WRITE);
      ev_io_set(&conn_.rev, conn_.fd, EV_READ);

      conn_.wlimit.startw();

      break;
    }

    conn_.wt.repeat = downstreamconf.timeout.connect;
    ev_timer_again(conn_.loop, &conn_.wt);
  } else {
    // we may set read timer cb to idle_timeoutcb.  Reset again.
    conn_.rt.repeat = downstreamconf.timeout.read;
    ev_set_cb(&conn_.rt, timeoutcb);
    ev_timer_stop(conn_.loop, &conn_.rt);

    ev_set_cb(&conn_.rev, readcb);
  }

  downstream_ = downstream;

  http_parser_init(&response_htp_, HTTP_RESPONSE);
  response_htp_.data = downstream_;

  return 0;
}

int HttpDownstreamConnection::push_request_headers() {
  const auto &downstream_hostport = addr_->hostport;
  const auto &req = downstream_->request();

  auto &balloc = downstream_->get_block_allocator();

  auto connect_method = req.method == HTTP_CONNECT;

  auto config = get_config();
  auto &httpconf = config->http;

  // Set request_sent to true because we write request into buffer
  // here.
  downstream_->set_request_header_sent(true);

  // For HTTP/1.0 request, there is no authority in request.  In that
  // case, we use backend server's host nonetheless.
  auto authority = StringRef(downstream_hostport);
  auto no_host_rewrite =
      httpconf.no_host_rewrite || config->http2_proxy || connect_method;

  if (no_host_rewrite && !req.authority.empty()) {
    authority = req.authority;
  }

  downstream_->set_request_downstream_host(authority);

  auto buf = downstream_->get_request_buf();

  // Assume that method and request path do not contain \r\n.
  auto meth = http2::to_method_string(req.method);
  buf->append(meth);
  buf->append(' ');

  if (connect_method) {
    buf->append(authority);
  } else if (config->http2_proxy) {
    // Construct absolute-form request target because we are going to
    // send a request to a HTTP/1 proxy.
    assert(!req.scheme.empty());
    buf->append(req.scheme);
    buf->append("://");
    buf->append(authority);
    buf->append(req.path);
  } else if (req.method == HTTP_OPTIONS && req.path.empty()) {
    // Server-wide OPTIONS
    buf->append("*");
  } else {
    buf->append(req.path);
  }
  buf->append(" HTTP/1.1\r\nHost: ");
  buf->append(authority);
  buf->append("\r\n");

  http2::build_http1_headers_from_headers(buf, req.fs.headers());

  auto cookie = downstream_->assemble_request_cookie();
  if (!cookie.empty()) {
    buf->append("Cookie: ");
    buf->append(cookie);
    buf->append("\r\n");
  }

  // set transfer-encoding only when content-length is unknown and
  // request body is expected.
  if (!connect_method && req.http2_expect_body && req.fs.content_length == -1) {
    downstream_->set_chunked_request(true);
    buf->append("Transfer-Encoding: chunked\r\n");
  }

  if (req.connection_close) {
    buf->append("Connection: close\r\n");
  }

  if (!connect_method && req.upgrade_request) {
    auto connection = req.fs.header(http2::HD_CONNECTION);
    if (connection) {
      buf->append("Connection: ");
      buf->append((*connection).value);
      buf->append("\r\n");
    }

    auto upgrade = req.fs.header(http2::HD_UPGRADE);
    if (upgrade) {
      buf->append("Upgrade: ");
      buf->append((*upgrade).value);
      buf->append("\r\n");
    }
  }

  auto upstream = downstream_->get_upstream();
  auto handler = upstream->get_client_handler();

  auto &fwdconf = httpconf.forwarded;

  auto fwd =
      fwdconf.strip_incoming ? nullptr : req.fs.header(http2::HD_FORWARDED);

  if (fwdconf.params) {
    auto params = fwdconf.params;

    if (config->http2_proxy || connect_method) {
      params &= ~FORWARDED_PROTO;
    }

    auto value = http::create_forwarded(
        balloc, params, handler->get_forwarded_by(),
        handler->get_forwarded_for(), req.authority, req.scheme);

    if (fwd || !value.empty()) {
      buf->append("Forwarded: ");
      if (fwd) {
        buf->append(fwd->value);

        if (!value.empty()) {
          buf->append(", ");
        }
      }
      buf->append(value);
      buf->append("\r\n");
    }
  } else if (fwd) {
    buf->append("Forwarded: ");
    buf->append(fwd->value);
    buf->append("\r\n");
  }

  auto &xffconf = httpconf.xff;

  auto xff = xffconf.strip_incoming ? nullptr
                                    : req.fs.header(http2::HD_X_FORWARDED_FOR);

  if (xffconf.add) {
    buf->append("X-Forwarded-For: ");
    if (xff) {
      buf->append((*xff).value);
      buf->append(", ");
    }
    buf->append(client_handler_->get_ipaddr());
    buf->append("\r\n");
  } else if (xff) {
    buf->append("X-Forwarded-For: ");
    buf->append((*xff).value);
    buf->append("\r\n");
  }
  if (!config->http2_proxy && !connect_method) {
    buf->append("X-Forwarded-Proto: ");
    assert(!req.scheme.empty());
    buf->append(req.scheme);
    buf->append("\r\n");
  }
  auto via = req.fs.header(http2::HD_VIA);
  if (httpconf.no_via) {
    if (via) {
      buf->append("Via: ");
      buf->append((*via).value);
      buf->append("\r\n");
    }
  } else {
    buf->append("Via: ");
    if (via) {
      buf->append((*via).value);
      buf->append(", ");
    }
    std::array<char, 16> viabuf;
    auto end = http::create_via_header_value(viabuf.data(), req.http_major,
                                             req.http_minor);
    buf->append(viabuf.data(), end - viabuf.data());
    buf->append("\r\n");
  }

  for (auto &p : httpconf.add_request_headers) {
    buf->append(p.name);
    buf->append(": ");
    buf->append(p.value);
    buf->append("\r\n");
  }

  buf->append("\r\n");

  if (LOG_ENABLED(INFO)) {
    std::string nhdrs;
    for (auto chunk = buf->head; chunk; chunk = chunk->next) {
      nhdrs.append(chunk->pos, chunk->last);
    }
    if (log_config()->errorlog_tty) {
      nhdrs = http::colorizeHeaders(nhdrs.c_str());
    }
    DCLOG(INFO, this) << "HTTP request headers. stream_id="
                      << downstream_->get_stream_id() << "\n"
                      << nhdrs;
  }

  // Don't call signal_write() if we anticipate request body.  We call
  // signal_write() when we received request body chunk, and it
  // enables us to send headers and data in one writev system call.
  if (connect_method ||
      (!req.http2_expect_body && req.fs.content_length == 0)) {
    signal_write();
  }

  return 0;
}

int HttpDownstreamConnection::push_upload_data_chunk(const uint8_t *data,
                                                     size_t datalen) {
  auto chunked = downstream_->get_chunked_request();
  auto output = downstream_->get_request_buf();

  if (chunked) {
    auto chunk_size_hex = util::utox(datalen);
    output->append(chunk_size_hex);
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

  const auto &req = downstream_->request();

  auto output = downstream_->get_request_buf();
  const auto &trailers = req.fs.trailers();
  if (trailers.empty()) {
    output->append("0\r\n\r\n");
  } else {
    output->append("0\r\n");
    http2::build_http1_headers_from_headers(output, trailers);
    output->append("\r\n");
  }

  signal_write();

  return 0;
}

namespace {
void remove_from_pool(HttpDownstreamConnection *dconn) {
  auto &group = dconn->get_downstream_addr_group();
  auto &shared_addr = group->shared_addr;

  if (shared_addr->affinity == AFFINITY_NONE) {
    auto &dconn_pool =
        dconn->get_downstream_addr_group()->shared_addr->dconn_pool;
    dconn_pool.remove_downstream_connection(dconn);
    return;
  }

  auto addr = dconn->get_addr();
  auto &dconn_pool = addr->dconn_pool;
  dconn_pool->remove_downstream_connection(dconn);
}
} // namespace

namespace {
void idle_readcb(struct ev_loop *loop, ev_io *w, int revents) {
  auto conn = static_cast<Connection *>(w->data);
  auto dconn = static_cast<HttpDownstreamConnection *>(conn->data);
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, dconn) << "Idle connection EOF";
  }

  remove_from_pool(dconn);
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

  remove_from_pool(dconn);
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

  auto &downstreamconf = *worker_->get_downstream_config();

  conn_.rt.repeat = downstreamconf.timeout.idle_read;
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
  auto &downstreamconf = *worker_->get_downstream_config();

  if (downstream_->get_response_buf()->rleft() <=
      downstreamconf.request_buffer_size / 2) {
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
  const auto &req = downstream->request();
  auto &resp = downstream->response();
  int rv;

  resp.http_status = htp->status_code;
  resp.http_major = htp->http_major;
  resp.http_minor = htp->http_minor;

  if (resp.http_major > 1) {
    // Normalize HTTP version, since we use http_major == 2 specially
    // in Downstream::expect_response_trailer().
    resp.http_major = 1;
    resp.http_minor = 1;
  }

  auto dconn = downstream->get_downstream_connection();

  downstream->set_downstream_addr_group(dconn->get_downstream_addr_group());
  downstream->set_addr(dconn->get_addr());

  // Server MUST NOT send Transfer-Encoding with a status code 1xx or
  // 204.  Also server MUST NOT send Transfer-Encoding with a status
  // code 200 to a CONNECT request.  Same holds true with
  // Content-Length.
  if (resp.http_status == 204 || resp.http_status / 100 == 1 ||
      (resp.http_status == 200 && req.method == HTTP_CONNECT)) {
    if (resp.fs.header(http2::HD_CONTENT_LENGTH) ||
        resp.fs.header(http2::HD_TRANSFER_ENCODING)) {
      return -1;
    }
  }

  if (resp.fs.parse_content_length() != 0) {
    downstream->set_response_state(Downstream::MSG_BAD_HEADER);
    return -1;
  }

  // Check upgrade before processing non-final response, since if
  // upgrade succeeded, 101 response is treated as final in nghttpx.
  downstream->check_upgrade_fulfilled();

  if (downstream->get_non_final_response()) {
    // Reset content-length because we reuse same Downstream for the
    // next response.
    resp.fs.content_length = -1;
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

  resp.connection_close = !http_should_keep_alive(htp);
  downstream->set_response_state(Downstream::HEADER_COMPLETE);
  downstream->inspect_http1_response();
  if (downstream->get_upgraded()) {
    // content-length must be ignored for upgraded connection.
    resp.fs.content_length = -1;
    resp.connection_close = true;
    // transfer-encoding not applied to upgraded connection
    downstream->set_chunked_response(false);
  } else if (!downstream->expect_response_body()) {
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

  // Ignore the response body. HEAD response may contain
  // Content-Length or Transfer-Encoding: chunked.  Some server send
  // 304 status code with nonzero Content-Length, but without response
  // body. See
  // https://tools.ietf.org/html/rfc7230#section-3.3

  // TODO It seems that the cases other than HEAD are handled by
  // http-parser.  Need test.
  return !http2::expect_response_body(req.method, resp.http_status);
}
} // namespace

namespace {
int ensure_header_field_buffer(const Downstream *downstream,
                               const HttpConfig &httpconf, size_t len) {
  auto &resp = downstream->response();

  if (resp.fs.buffer_size() + len > httpconf.response_header_field_buffer) {
    if (LOG_ENABLED(INFO)) {
      DLOG(INFO, downstream) << "Too large header header field size="
                             << resp.fs.buffer_size() + len;
    }
    return -1;
  }

  return 0;
}
} // namespace

namespace {
int ensure_max_header_fields(const Downstream *downstream,
                             const HttpConfig &httpconf) {
  auto &resp = downstream->response();

  if (resp.fs.num_fields() >= httpconf.max_response_header_fields) {
    if (LOG_ENABLED(INFO)) {
      DLOG(INFO, downstream) << "Too many header field num="
                             << resp.fs.num_fields() + 1;
    }
    return -1;
  }

  return 0;
}
} // namespace

namespace {
int htp_hdr_keycb(http_parser *htp, const char *data, size_t len) {
  auto downstream = static_cast<Downstream *>(htp->data);
  auto &resp = downstream->response();
  auto &httpconf = get_config()->http;
  auto &balloc = downstream->get_block_allocator();

  if (ensure_header_field_buffer(downstream, httpconf, len) != 0) {
    return -1;
  }

  if (downstream->get_response_state() == Downstream::INITIAL) {
    if (resp.fs.header_key_prev()) {
      resp.fs.append_last_header_key(data, len);
    } else {
      if (ensure_max_header_fields(downstream, httpconf) != 0) {
        return -1;
      }
      auto name = http2::copy_lower(balloc, StringRef{data, len});
      auto token = http2::lookup_token(name);
      resp.fs.add_header_token(name, StringRef{}, false, token);
    }
  } else {
    // trailer part
    if (resp.fs.trailer_key_prev()) {
      resp.fs.append_last_trailer_key(data, len);
    } else {
      if (ensure_max_header_fields(downstream, httpconf) != 0) {
        // Could not ignore this trailer field easily, since we may
        // get its value in htp_hdr_valcb, and it will be added to
        // wrong place or crash if trailer fields are currently empty.
        return -1;
      }
      auto name = http2::copy_lower(balloc, StringRef{data, len});
      auto token = http2::lookup_token(name);
      resp.fs.add_trailer_token(name, StringRef{}, false, token);
    }
  }
  return 0;
}
} // namespace

namespace {
int htp_hdr_valcb(http_parser *htp, const char *data, size_t len) {
  auto downstream = static_cast<Downstream *>(htp->data);
  auto &resp = downstream->response();
  auto &httpconf = get_config()->http;

  if (ensure_header_field_buffer(downstream, httpconf, len) != 0) {
    return -1;
  }

  if (downstream->get_response_state() == Downstream::INITIAL) {
    resp.fs.append_last_header_value(data, len);
  } else {
    resp.fs.append_last_trailer_value(data, len);
  }
  return 0;
}
} // namespace

namespace {
int htp_bodycb(http_parser *htp, const char *data, size_t len) {
  auto downstream = static_cast<Downstream *>(htp->data);
  auto &resp = downstream->response();

  resp.recv_body_length += len;

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

int HttpDownstreamConnection::read_clear() {
  std::array<uint8_t, 16_k> buf;
  int rv;

  for (;;) {
    auto nread = conn_.read_clear(buf.data(), buf.size());
    if (nread == 0) {
      return 0;
    }

    if (nread < 0) {
      return nread;
    }

    rv = process_input(buf.data(), nread);
    if (rv != 0) {
      return rv;
    }

    if (!ev_is_active(&conn_.rev)) {
      return 0;
    }
  }
}

int HttpDownstreamConnection::write_clear() {
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
    auto &req = downstream_->request();

    upstream->resume_read(SHRPX_NO_BUFFER, downstream_,
                          req.unconsumed_body_length);
  }

  return 0;
}

int HttpDownstreamConnection::tls_handshake() {
  ERR_clear_error();

  ev_timer_again(conn_.loop, &conn_.rt);

  auto rv = conn_.tls_handshake();
  if (rv == SHRPX_ERR_INPROGRESS) {
    return 0;
  }

  if (rv < 0) {
    downstream_failure(addr_);

    return rv;
  }

  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "SSL/TLS handshake completed";
  }

  if (!get_config()->tls.insecure &&
      ssl::check_cert(conn_.tls.ssl, addr_) != 0) {
    downstream_failure(addr_);

    return -1;
  }

  if (!SSL_session_reused(conn_.tls.ssl)) {
    auto session = SSL_get0_session(conn_.tls.ssl);
    if (session) {
      ssl::try_cache_tls_session(addr_->tls_session_cache, addr_->addr, session,
                                 ev_now(conn_.loop));
    }
  }

  auto &connect_blocker = addr_->connect_blocker;

  do_signal_write_ = &HttpDownstreamConnection::actual_signal_write;

  connect_blocker->on_success();

  ev_set_cb(&conn_.rt, timeoutcb);
  ev_set_cb(&conn_.wt, timeoutcb);

  do_read_ = &HttpDownstreamConnection::read_tls;
  do_write_ = &HttpDownstreamConnection::write_tls;

  // TODO Check negotiated ALPN

  return on_write();
}

int HttpDownstreamConnection::read_tls() {
  ERR_clear_error();

  std::array<uint8_t, 16_k> buf;
  int rv;

  for (;;) {
    auto nread = conn_.read_tls(buf.data(), buf.size());
    if (nread == 0) {
      return 0;
    }

    if (nread < 0) {
      return nread;
    }

    rv = process_input(buf.data(), nread);
    if (rv != 0) {
      return rv;
    }

    if (!ev_is_active(&conn_.rev)) {
      return 0;
    }
  }
}

int HttpDownstreamConnection::write_tls() {
  ERR_clear_error();

  auto upstream = downstream_->get_upstream();
  auto input = downstream_->get_request_buf();

  struct iovec iov;

  while (input->rleft() > 0) {
    auto iovcnt = input->riovec(&iov, 1);
    assert(iovcnt == 1);
    auto nwrite = conn_.write_tls(iov.iov_base, iov.iov_len);

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
    auto &req = downstream_->request();

    upstream->resume_read(SHRPX_NO_BUFFER, downstream_,
                          req.unconsumed_body_length);
  }

  return 0;
}

int HttpDownstreamConnection::process_input(const uint8_t *data,
                                            size_t datalen) {
  int rv;

  if (downstream_->get_upgraded()) {
    // For upgraded connection, just pass data to the upstream.
    rv = downstream_->get_upstream()->on_downstream_body(downstream_, data,
                                                         datalen, true);
    if (rv != 0) {
      return rv;
    }

    if (downstream_->response_buf_full()) {
      downstream_->pause_read(SHRPX_NO_BUFFER);
      return 0;
    }

    return 0;
  }

  auto nproc =
      http_parser_execute(&response_htp_, &htp_hooks,
                          reinterpret_cast<const char *>(data), datalen);

  auto htperr = HTTP_PARSER_ERRNO(&response_htp_);

  if (htperr != HPE_OK) {
    // Handling early return (in other words, response was hijacked by
    // mruby scripting).
    if (downstream_->get_response_state() == Downstream::MSG_COMPLETE) {
      return SHRPX_ERR_DCONN_CANCELED;
    }

    if (LOG_ENABLED(INFO)) {
      DCLOG(INFO, this) << "HTTP parser failure: "
                        << "(" << http_errno_name(htperr) << ") "
                        << http_errno_description(htperr);
    }

    return -1;
  }

  if (downstream_->get_upgraded()) {
    if (nproc < datalen) {
      // Data from data + nproc are for upgraded protocol.
      rv = downstream_->get_upstream()->on_downstream_body(
          downstream_, data + nproc, datalen - nproc, true);
      if (rv != 0) {
        return rv;
      }

      if (downstream_->response_buf_full()) {
        downstream_->pause_read(SHRPX_NO_BUFFER);
        return 0;
      }
    }
    return 0;
  }

  if (downstream_->response_buf_full()) {
    downstream_->pause_read(SHRPX_NO_BUFFER);
    return 0;
  }

  return 0;
}

int HttpDownstreamConnection::connected() {
  auto &connect_blocker = addr_->connect_blocker;

  auto sock_error = util::get_socket_error(conn_.fd);
  if (sock_error != 0) {
    conn_.wlimit.stopw();

    DCLOG(WARN, this) << "Backend connect failed; addr="
                      << util::to_numeric_addr(&addr_->addr)
                      << ": errno=" << sock_error;

    downstream_failure(addr_);

    return -1;
  }

  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Connected to downstream host";
  }

  auto &downstreamconf = *get_config()->conn.downstream;

  // Reset timeout for write.  Previously, we set timeout for connect.
  conn_.wt.repeat = downstreamconf.timeout.write;
  ev_timer_again(conn_.loop, &conn_.wt);

  conn_.rlimit.startw();

  ev_set_cb(&conn_.wev, writecb);

  if (conn_.tls.ssl) {
    do_read_ = &HttpDownstreamConnection::tls_handshake;
    do_write_ = &HttpDownstreamConnection::tls_handshake;

    return 0;
  }

  do_signal_write_ = &HttpDownstreamConnection::actual_signal_write;

  connect_blocker->on_success();

  ev_set_cb(&conn_.rt, timeoutcb);
  ev_set_cb(&conn_.wt, timeoutcb);

  do_read_ = &HttpDownstreamConnection::read_clear;
  do_write_ = &HttpDownstreamConnection::write_clear;

  return 0;
}

int HttpDownstreamConnection::on_read() { return do_read_(*this); }

int HttpDownstreamConnection::on_write() { return do_write_(*this); }

void HttpDownstreamConnection::on_upstream_change(Upstream *upstream) {}

void HttpDownstreamConnection::signal_write() { do_signal_write_(*this); }

int HttpDownstreamConnection::actual_signal_write() {
  ev_feed_event(conn_.loop, &conn_.wev, EV_WRITE);
  return 0;
}

int HttpDownstreamConnection::noop() { return 0; }

const std::shared_ptr<DownstreamAddrGroup> &
HttpDownstreamConnection::get_downstream_addr_group() const {
  return group_;
}

DownstreamAddr *HttpDownstreamConnection::get_addr() const { return addr_; }

bool HttpDownstreamConnection::poolable() const { return !group_->retired; }

} // namespace shrpx
