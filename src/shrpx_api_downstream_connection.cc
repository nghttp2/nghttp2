/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2016 Tatsuhiro Tsujikawa
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
#include "shrpx_api_downstream_connection.h"

#include "shrpx_client_handler.h"
#include "shrpx_upstream.h"
#include "shrpx_downstream.h"
#include "shrpx_worker.h"
#include "shrpx_connection_handler.h"

namespace shrpx {

APIDownstreamConnection::APIDownstreamConnection(Worker *worker)
    : worker_(worker), abandoned_(false) {}

APIDownstreamConnection::~APIDownstreamConnection() {}

int APIDownstreamConnection::attach_downstream(Downstream *downstream) {
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Attaching to DOWNSTREAM:" << downstream;
  }

  downstream_ = downstream;

  return 0;
}

void APIDownstreamConnection::detach_downstream(Downstream *downstream) {
  if (LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Detaching from DOWNSTREAM:" << downstream;
  }
  downstream_ = nullptr;
}

// API status, which is independent from HTTP status code.  But
// generally, 2xx code for API_SUCCESS, and otherwise API_FAILURE.
enum {
  API_SUCCESS,
  API_FAILURE,
};

int APIDownstreamConnection::send_reply(unsigned int http_status,
                                        int api_status) {
  abandoned_ = true;

  auto upstream = downstream_->get_upstream();

  auto &resp = downstream_->response();

  resp.http_status = http_status;

  auto &balloc = downstream_->get_block_allocator();

  StringRef api_status_str;

  switch (api_status) {
  case API_SUCCESS:
    api_status_str = StringRef::from_lit("Success");
    break;
  case API_FAILURE:
    api_status_str = StringRef::from_lit("Failure");
    break;
  default:
    assert(0);
  }

  constexpr auto M1 = StringRef::from_lit("{\"status\":\"");
  constexpr auto M2 = StringRef::from_lit("\",\"code\":");
  constexpr auto M3 = StringRef::from_lit("}");

  // 3 is the number of digits in http_status, assuming it is 3 digits
  // number.
  auto buflen = M1.size() + M2.size() + M3.size() + api_status_str.size() + 3;

  auto buf = make_byte_ref(balloc, buflen);
  auto p = buf.base;

  p = std::copy(std::begin(M1), std::end(M1), p);
  p = std::copy(std::begin(api_status_str), std::end(api_status_str), p);
  p = std::copy(std::begin(M2), std::end(M2), p);
  p = util::utos(p, http_status);
  p = std::copy(std::begin(M3), std::end(M3), p);

  buf.len = p - buf.base;

  auto content_length = util::make_string_ref_uint(balloc, buf.len);

  resp.fs.add_header_token(StringRef::from_lit("content-length"),
                           content_length, false, http2::HD_CONTENT_LENGTH);

  switch (http_status) {
  case 400:
  case 405:
  case 413:
    resp.fs.add_header_token(StringRef::from_lit("connection"),
                             StringRef::from_lit("close"), false,
                             http2::HD_CONNECTION);
    break;
  }

  if (upstream->send_reply(downstream_, buf.base, buf.len) != 0) {
    return -1;
  }

  return 0;
}

int APIDownstreamConnection::push_request_headers() {
  auto &req = downstream_->request();
  auto &resp = downstream_->response();

  auto path =
      StringRef{std::begin(req.path),
                std::find(std::begin(req.path), std::end(req.path), '?')};

  if (path != StringRef::from_lit("/api/v1beta1/backendconfig")) {
    send_reply(404, API_FAILURE);

    return 0;
  }

  if (req.method != HTTP_POST && req.method != HTTP_PUT) {
    resp.fs.add_header_token(StringRef::from_lit("allow"),
                             StringRef::from_lit("POST, PUT"), false, -1);
    send_reply(405, API_FAILURE);

    return 0;
  }

  // This works with req.fs.content_length == -1
  if (req.fs.content_length >
      static_cast<int64_t>(get_config()->api.max_request_body)) {
    send_reply(413, API_FAILURE);

    return 0;
  }

  return 0;
}

int APIDownstreamConnection::push_upload_data_chunk(const uint8_t *data,
                                                    size_t datalen) {
  if (abandoned_) {
    return 0;
  }

  auto output = downstream_->get_request_buf();

  auto &apiconf = get_config()->api;

  if (output->rleft() + datalen > apiconf.max_request_body) {
    send_reply(413, API_FAILURE);

    return 0;
  }

  output->append(data, datalen);

  // We don't have to call Upstream::resume_read() here, because
  // request buffer is effectively unlimited.  Actually, we cannot
  // call it here since it could recursively call this function again.

  return 0;
}

int APIDownstreamConnection::end_upload_data() {
  if (abandoned_) {
    return 0;
  }

  auto output = downstream_->get_request_buf();

  std::array<struct iovec, 2> iov;
  auto iovcnt = output->riovec(iov.data(), 2);

  if (iovcnt == 0) {
    send_reply(200, API_SUCCESS);

    return 0;
  }

  std::unique_ptr<uint8_t[]> large_buf;

  // If data spans in multiple chunks, pull them up into one
  // contiguous buffer.
  if (iovcnt > 1) {
    large_buf = make_unique<uint8_t[]>(output->rleft());
    auto len = output->rleft();
    output->remove(large_buf.get(), len);

    iov[0].iov_base = large_buf.get();
    iov[0].iov_len = len;
  }

  Config new_config{};
  new_config.conn.downstream = std::make_shared<DownstreamConfig>();
  const auto &downstreamconf = new_config.conn.downstream;

  auto config = get_config();
  auto &src = config->conn.downstream;

  downstreamconf->timeout = src->timeout;
  downstreamconf->connections_per_host = src->connections_per_host;
  downstreamconf->connections_per_frontend = src->connections_per_frontend;
  downstreamconf->request_buffer_size = src->request_buffer_size;
  downstreamconf->response_buffer_size = src->response_buffer_size;
  downstreamconf->family = src->family;

  std::set<StringRef> include_set;

  for (auto first = reinterpret_cast<const uint8_t *>(iov[0].iov_base),
            last = first + iov[0].iov_len;
       first != last;) {
    auto eol = std::find(first, last, '\n');
    if (eol == last) {
      break;
    }

    if (first == eol || *first == '#') {
      first = ++eol;
      continue;
    }

    auto eq = std::find(first, eol, '=');
    if (eq == eol) {
      send_reply(400, API_FAILURE);
      return 0;
    }

    auto opt = StringRef{first, eq};
    auto optval = StringRef{eq + 1, eol};

    auto optid = option_lookup_token(opt.c_str(), opt.size());

    switch (optid) {
    case SHRPX_OPTID_BACKEND:
      break;
    default:
      first = ++eol;
      continue;
    }

    if (parse_config(&new_config, optid, opt, optval, include_set) != 0) {
      send_reply(400, API_FAILURE);
      return 0;
    }

    first = ++eol;
  }

  auto &tlsconf = config->tls;
  if (configure_downstream_group(&new_config, config->http2_proxy, true,
                                 tlsconf) != 0) {
    send_reply(400, API_FAILURE);
    return 0;
  }

  auto conn_handler = worker_->get_connection_handler();

  conn_handler->send_replace_downstream(downstreamconf);

  send_reply(200, API_SUCCESS);

  return 0;
}

void APIDownstreamConnection::pause_read(IOCtrlReason reason) {}

int APIDownstreamConnection::resume_read(IOCtrlReason reason, size_t consumed) {
  return 0;
}

void APIDownstreamConnection::force_resume_read() {}

int APIDownstreamConnection::on_read() { return 0; }

int APIDownstreamConnection::on_write() { return 0; }

void APIDownstreamConnection::on_upstream_change(Upstream *uptream) {}

bool APIDownstreamConnection::poolable() const { return false; }

const std::shared_ptr<DownstreamAddrGroup> &
APIDownstreamConnection::get_downstream_addr_group() const {
  static std::shared_ptr<DownstreamAddrGroup> s;
  return s;
}

DownstreamAddr *APIDownstreamConnection::get_addr() const { return nullptr; }

} // namespace shrpx
