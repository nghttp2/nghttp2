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
#include "shrpx_downstream.h"

#include <cassert>

#include "http-parser/http_parser.h"

#include "shrpx_upstream.h"
#include "shrpx_client_handler.h"
#include "shrpx_config.h"
#include "shrpx_error.h"
#include "shrpx_downstream_connection.h"
#include "shrpx_downstream_queue.h"
#include "shrpx_worker.h"
#include "shrpx_http2_session.h"
#ifdef HAVE_MRUBY
#include "shrpx_mruby.h"
#endif // HAVE_MRUBY
#include "util.h"
#include "http2.h"

namespace shrpx {

namespace {
void upstream_timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto downstream = static_cast<Downstream *>(w->data);
  auto upstream = downstream->get_upstream();

  auto which = revents == EV_READ ? "read" : "write";

  if (LOG_ENABLED(INFO)) {
    DLOG(INFO, downstream) << "upstream timeout stream_id="
                           << downstream->get_stream_id() << " event=" << which;
  }

  downstream->disable_upstream_rtimer();
  downstream->disable_upstream_wtimer();

  upstream->on_timeout(downstream);
}
} // namespace

namespace {
void upstream_rtimeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  upstream_timeoutcb(loop, w, EV_READ);
}
} // namespace

namespace {
void upstream_wtimeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  upstream_timeoutcb(loop, w, EV_WRITE);
}
} // namespace

namespace {
void downstream_timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto downstream = static_cast<Downstream *>(w->data);

  auto which = revents == EV_READ ? "read" : "write";

  if (LOG_ENABLED(INFO)) {
    DLOG(INFO, downstream) << "downstream timeout stream_id="
                           << downstream->get_downstream_stream_id()
                           << " event=" << which;
  }

  downstream->disable_downstream_rtimer();
  downstream->disable_downstream_wtimer();

  auto dconn = downstream->get_downstream_connection();

  if (dconn) {
    dconn->on_timeout();
  }
}
} // namespace

namespace {
void downstream_rtimeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  downstream_timeoutcb(loop, w, EV_READ);
}
} // namespace

namespace {
void downstream_wtimeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  downstream_timeoutcb(loop, w, EV_WRITE);
}
} // namespace

// upstream could be nullptr for unittests
Downstream::Downstream(Upstream *upstream, MemchunkPool *mcpool,
                       int32_t stream_id, int32_t priority)
    : dlnext(nullptr), dlprev(nullptr),
      request_start_time_(std::chrono::high_resolution_clock::now()),
      request_buf_(mcpool), response_buf_(mcpool), request_bodylen_(0),
      response_bodylen_(0), response_sent_bodylen_(0),
      request_content_length_(-1), response_content_length_(-1),
      upstream_(upstream), blocked_link_(nullptr), request_headers_sum_(0),
      response_headers_sum_(0), request_datalen_(0), response_datalen_(0),
      num_retry_(0), stream_id_(stream_id), priority_(priority),
      downstream_stream_id_(-1),
      response_rst_stream_error_code_(NGHTTP2_NO_ERROR), request_method_(-1),
      request_state_(INITIAL), request_major_(1), request_minor_(1),
      response_state_(INITIAL), response_http_status_(0), response_major_(1),
      response_minor_(1), dispatch_state_(DISPATCH_NONE),
      upgrade_request_(false), upgraded_(false), http2_upgrade_seen_(false),
      chunked_request_(false), request_connection_close_(false),
      request_header_key_prev_(false), request_trailer_key_prev_(false),
      request_http2_expect_body_(false), chunked_response_(false),
      response_connection_close_(false), response_header_key_prev_(false),
      response_trailer_key_prev_(false), expect_final_response_(false),
      request_pending_(false) {

  ev_timer_init(&upstream_rtimer_, &upstream_rtimeoutcb, 0.,
                get_config()->stream_read_timeout);
  ev_timer_init(&upstream_wtimer_, &upstream_wtimeoutcb, 0.,
                get_config()->stream_write_timeout);
  ev_timer_init(&downstream_rtimer_, &downstream_rtimeoutcb, 0.,
                get_config()->stream_read_timeout);
  ev_timer_init(&downstream_wtimer_, &downstream_wtimeoutcb, 0.,
                get_config()->stream_write_timeout);

  upstream_rtimer_.data = this;
  upstream_wtimer_.data = this;
  downstream_rtimer_.data = this;
  downstream_wtimer_.data = this;

  http2::init_hdidx(request_hdidx_);
  http2::init_hdidx(response_hdidx_);

  request_headers_.reserve(16);
  response_headers_.reserve(32);
}

Downstream::~Downstream() {
  if (LOG_ENABLED(INFO)) {
    DLOG(INFO, this) << "Deleting";
  }

  // check nullptr for unittest
  if (upstream_) {
    auto loop = upstream_->get_client_handler()->get_loop();

    ev_timer_stop(loop, &upstream_rtimer_);
    ev_timer_stop(loop, &upstream_wtimer_);
    ev_timer_stop(loop, &downstream_rtimer_);
    ev_timer_stop(loop, &downstream_wtimer_);

#ifdef HAVE_MRUBY
    auto handler = upstream_->get_client_handler();
    auto worker = handler->get_worker();
    auto mruby_ctx = worker->get_mruby_context();

    mruby_ctx->delete_downstream(this);
#endif // HAVE_MRUBY
  }

  // DownstreamConnection may refer to this object.  Delete it now
  // explicitly.
  dconn_.reset();

  if (LOG_ENABLED(INFO)) {
    DLOG(INFO, this) << "Deleted";
  }
}

int Downstream::attach_downstream_connection(
    std::unique_ptr<DownstreamConnection> dconn) {
  if (dconn->attach_downstream(this) != 0) {
    return -1;
  }

  dconn_ = std::move(dconn);

  return 0;
}

void Downstream::detach_downstream_connection() {
  if (!dconn_) {
    return;
  }

  dconn_->detach_downstream(this);

  auto handler = dconn_->get_client_handler();

  handler->pool_downstream_connection(
      std::unique_ptr<DownstreamConnection>(dconn_.release()));
}

DownstreamConnection *Downstream::get_downstream_connection() {
  return dconn_.get();
}

std::unique_ptr<DownstreamConnection> Downstream::pop_downstream_connection() {
  return std::unique_ptr<DownstreamConnection>(dconn_.release());
}

void Downstream::pause_read(IOCtrlReason reason) {
  if (dconn_) {
    dconn_->pause_read(reason);
  }
}

int Downstream::resume_read(IOCtrlReason reason, size_t consumed) {
  if (dconn_) {
    return dconn_->resume_read(reason, consumed);
  }

  return 0;
}

void Downstream::force_resume_read() {
  if (dconn_) {
    dconn_->force_resume_read();
  }
}

namespace {
const Headers::value_type *get_header_linear(const Headers &headers,
                                             const std::string &name) {
  const Headers::value_type *res = nullptr;
  for (auto &kv : headers) {
    if (kv.name == name) {
      res = &kv;
    }
  }
  return res;
}
} // namespace

const Headers &Downstream::get_request_headers() const {
  return request_headers_;
}

Headers &Downstream::get_request_headers() { return request_headers_; }

void Downstream::assemble_request_cookie() {
  std::string &cookie = assembled_request_cookie_;
  cookie = "";
  for (auto &kv : request_headers_) {
    if (kv.name.size() != 6 || kv.name[5] != 'e' ||
        !util::streq_l("cooki", kv.name.c_str(), 5)) {
      continue;
    }

    auto end = kv.value.find_last_not_of(" ;");
    if (end == std::string::npos) {
      cookie += kv.value;
    } else {
      cookie.append(std::begin(kv.value), std::begin(kv.value) + end + 1);
    }
    cookie += "; ";
  }
  if (cookie.size() >= 2) {
    cookie.erase(cookie.size() - 2);
  }
}

size_t Downstream::count_crumble_request_cookie() {
  size_t n = 0;
  for (auto &kv : request_headers_) {
    if (kv.name.size() != 6 || kv.name[5] != 'e' ||
        !util::streq_l("cooki", kv.name.c_str(), 5)) {
      continue;
    }
    size_t last = kv.value.size();

    for (size_t j = 0; j < last;) {
      j = kv.value.find_first_not_of("\t ;", j);
      if (j == std::string::npos) {
        break;
      }

      j = kv.value.find(';', j);
      if (j == std::string::npos) {
        j = last;
      }

      ++n;
    }
  }
  return n;
}

void Downstream::crumble_request_cookie(std::vector<nghttp2_nv> &nva) {
  for (auto &kv : request_headers_) {
    if (kv.name.size() != 6 || kv.name[5] != 'e' ||
        !util::streq_l("cooki", kv.name.c_str(), 5)) {
      continue;
    }
    size_t last = kv.value.size();

    for (size_t j = 0; j < last;) {
      j = kv.value.find_first_not_of("\t ;", j);
      if (j == std::string::npos) {
        break;
      }
      auto first = j;

      j = kv.value.find(';', j);
      if (j == std::string::npos) {
        j = last;
      }

      nva.push_back({(uint8_t *)"cookie", (uint8_t *)kv.value.c_str() + first,
                     str_size("cookie"), j - first,
                     (uint8_t)(NGHTTP2_NV_FLAG_NO_COPY_NAME |
                               NGHTTP2_NV_FLAG_NO_COPY_VALUE |
                               (kv.no_index ? NGHTTP2_NV_FLAG_NO_INDEX : 0))});
    }
  }
}

const std::string &Downstream::get_assembled_request_cookie() const {
  return assembled_request_cookie_;
}

namespace {
void add_header(bool &key_prev, size_t &sum, Headers &headers, std::string name,
                std::string value) {
  key_prev = true;
  sum += name.size() + value.size();
  headers.emplace_back(std::move(name), std::move(value));
}
} // namespace

namespace {
void add_header(size_t &sum, Headers &headers, const uint8_t *name,
                size_t namelen, const uint8_t *value, size_t valuelen,
                bool no_index, int16_t token) {
  sum += namelen + valuelen;
  headers.emplace_back(
      std::string(reinterpret_cast<const char *>(name), namelen),
      std::string(reinterpret_cast<const char *>(value), valuelen), no_index,
      token);
}
} // namespace

namespace {
void append_last_header_key(bool key_prev, size_t &sum, Headers &headers,
                            const char *data, size_t len) {
  assert(key_prev);
  sum += len;
  auto &item = headers.back();
  item.name.append(data, len);
}
} // namespace

namespace {
void append_last_header_value(bool key_prev, size_t &sum, Headers &headers,
                              const char *data, size_t len) {
  assert(!key_prev);
  sum += len;
  auto &item = headers.back();
  item.value.append(data, len);
}
} // namespace

namespace {
void set_last_header_value(bool &key_prev, size_t &sum, Headers &headers,
                           const char *data, size_t len) {
  key_prev = false;
  sum += len;
  auto &item = headers.back();
  item.value.assign(data, len);
}
} // namespace

namespace {
int index_headers(http2::HeaderIndex &hdidx, Headers &headers,
                  int64_t &content_length) {
  http2::init_hdidx(hdidx);
  content_length = -1;

  for (size_t i = 0; i < headers.size(); ++i) {
    auto &kv = headers[i];
    util::inp_strlower(kv.name);

    auto token = http2::lookup_token(
        reinterpret_cast<const uint8_t *>(kv.name.c_str()), kv.name.size());
    if (token < 0) {
      continue;
    }

    kv.token = token;
    http2::index_header(hdidx, token, i);

    if (token == http2::HD_CONTENT_LENGTH) {
      auto len = util::parse_uint(kv.value);
      if (len == -1) {
        return -1;
      }
      if (content_length != -1) {
        return -1;
      }
      content_length = len;
    }
  }
  return 0;
}
} // namespace

int Downstream::index_request_headers() {
  return index_headers(request_hdidx_, request_headers_,
                       request_content_length_);
}

const Headers::value_type *Downstream::get_request_header(int16_t token) const {
  return http2::get_header(request_hdidx_, token, request_headers_);
}

const Headers::value_type *
Downstream::get_request_header(const std::string &name) const {
  return get_header_linear(request_headers_, name);
}

void Downstream::add_request_header(std::string name, std::string value) {
  add_header(request_header_key_prev_, request_headers_sum_, request_headers_,
             std::move(name), std::move(value));
}

void Downstream::set_last_request_header_value(const char *data, size_t len) {
  set_last_header_value(request_header_key_prev_, request_headers_sum_,
                        request_headers_, data, len);
}

void Downstream::add_request_header(std::string name, std::string value,
                                    int16_t token) {
  http2::index_header(request_hdidx_, token, request_headers_.size());
  request_headers_sum_ += name.size() + value.size();
  request_headers_.emplace_back(std::move(name), std::move(value), false,
                                token);
}

void Downstream::add_request_header(const uint8_t *name, size_t namelen,
                                    const uint8_t *value, size_t valuelen,
                                    bool no_index, int16_t token) {
  http2::index_header(request_hdidx_, token, request_headers_.size());
  add_header(request_headers_sum_, request_headers_, name, namelen, value,
             valuelen, no_index, token);
}

bool Downstream::get_request_header_key_prev() const {
  return request_header_key_prev_;
}

void Downstream::append_last_request_header_key(const char *data, size_t len) {
  append_last_header_key(request_header_key_prev_, request_headers_sum_,
                         request_headers_, data, len);
}

void Downstream::append_last_request_header_value(const char *data,
                                                  size_t len) {
  append_last_header_value(request_header_key_prev_, request_headers_sum_,
                           request_headers_, data, len);
}

void Downstream::clear_request_headers() {
  Headers().swap(request_headers_);
  http2::init_hdidx(request_hdidx_);
}

size_t Downstream::get_request_headers_sum() const {
  return request_headers_sum_;
}

void Downstream::add_request_trailer(const uint8_t *name, size_t namelen,
                                     const uint8_t *value, size_t valuelen,
                                     bool no_index, int16_t token) {
  // we never index trailer part.  Header size limit should be applied
  // to all request header fields combined.
  add_header(request_headers_sum_, request_trailers_, name, namelen, value,
             valuelen, no_index, -1);
}

const Headers &Downstream::get_request_trailers() const {
  return request_trailers_;
}

void Downstream::add_request_trailer(std::string name, std::string value) {
  add_header(request_trailer_key_prev_, request_headers_sum_, request_trailers_,
             std::move(name), std::move(value));
}

void Downstream::set_last_request_trailer_value(const char *data, size_t len) {
  set_last_header_value(request_trailer_key_prev_, request_headers_sum_,
                        request_trailers_, data, len);
}

bool Downstream::get_request_trailer_key_prev() const {
  return request_trailer_key_prev_;
}

void Downstream::append_last_request_trailer_key(const char *data, size_t len) {
  append_last_header_key(request_trailer_key_prev_, request_headers_sum_,
                         request_trailers_, data, len);
}

void Downstream::append_last_request_trailer_value(const char *data,
                                                   size_t len) {
  append_last_header_value(request_trailer_key_prev_, request_headers_sum_,
                           request_trailers_, data, len);
}

void Downstream::set_request_method(int method) { request_method_ = method; }

int Downstream::get_request_method() const { return request_method_; }

void Downstream::set_request_path(std::string path) {
  request_path_ = std::move(path);
}

void Downstream::append_request_path(const char *data, size_t len) {
  request_path_.append(data, len);
}

const std::string &Downstream::get_request_path() const {
  return request_path_;
}

void Downstream::set_request_start_time(
    std::chrono::high_resolution_clock::time_point time) {
  request_start_time_ = std::move(time);
}

const std::chrono::high_resolution_clock::time_point &
Downstream::get_request_start_time() const {
  return request_start_time_;
}

const std::string &Downstream::get_request_http2_scheme() const {
  return request_http2_scheme_;
}

void Downstream::set_request_http2_scheme(std::string scheme) {
  request_http2_scheme_ = std::move(scheme);
}

const std::string &Downstream::get_request_http2_authority() const {
  return request_http2_authority_;
}

void Downstream::set_request_http2_authority(std::string authority) {
  request_http2_authority_ = std::move(authority);
}

void Downstream::append_request_http2_authority(const char *data, size_t len) {
  request_http2_authority_.append(data, len);
}

void Downstream::set_request_major(int major) { request_major_ = major; }

void Downstream::set_request_minor(int minor) { request_minor_ = minor; }

int Downstream::get_request_major() const { return request_major_; }

int Downstream::get_request_minor() const { return request_minor_; }

void Downstream::reset_upstream(Upstream *upstream) {
  upstream_ = upstream;
  if (dconn_) {
    dconn_->on_upstream_change(upstream);
  }
}

Upstream *Downstream::get_upstream() const { return upstream_; }

void Downstream::set_stream_id(int32_t stream_id) { stream_id_ = stream_id; }

int32_t Downstream::get_stream_id() const { return stream_id_; }

void Downstream::set_request_state(int state) { request_state_ = state; }

int Downstream::get_request_state() const { return request_state_; }

bool Downstream::get_chunked_request() const { return chunked_request_; }

void Downstream::set_chunked_request(bool f) { chunked_request_ = f; }

bool Downstream::get_request_connection_close() const {
  return request_connection_close_;
}

void Downstream::set_request_connection_close(bool f) {
  request_connection_close_ = f;
}

bool Downstream::get_request_http2_expect_body() const {
  return request_http2_expect_body_;
}

void Downstream::set_request_http2_expect_body(bool f) {
  request_http2_expect_body_ = f;
}

bool Downstream::request_buf_full() {
  if (dconn_) {
    return request_buf_.rleft() >= get_config()->downstream_request_buffer_size;
  } else {
    return false;
  }
}

DefaultMemchunks *Downstream::get_request_buf() { return &request_buf_; }

// Call this function after this object is attached to
// Downstream. Otherwise, the program will crash.
int Downstream::push_request_headers() {
  if (!dconn_) {
    DLOG(INFO, this) << "dconn_ is NULL";
    return -1;
  }
  return dconn_->push_request_headers();
}

int Downstream::push_upload_data_chunk(const uint8_t *data, size_t datalen) {
  // Assumes that request headers have already been pushed to output
  // buffer using push_request_headers().
  if (!dconn_) {
    DLOG(INFO, this) << "dconn_ is NULL";
    return -1;
  }
  request_bodylen_ += datalen;
  if (dconn_->push_upload_data_chunk(data, datalen) != 0) {
    return -1;
  }

  request_datalen_ += datalen;

  return 0;
}

int Downstream::end_upload_data() {
  if (!dconn_) {
    DLOG(INFO, this) << "dconn_ is NULL";
    return -1;
  }
  return dconn_->end_upload_data();
}

const Headers &Downstream::get_response_headers() const {
  return response_headers_;
}

Headers &Downstream::get_response_headers() { return response_headers_; }

int Downstream::index_response_headers() {
  return index_headers(response_hdidx_, response_headers_,
                       response_content_length_);
}

const Headers::value_type *
Downstream::get_response_header(int16_t token) const {
  return http2::get_header(response_hdidx_, token, response_headers_);
}

Headers::value_type *Downstream::get_response_header(int16_t token) {
  return http2::get_header(response_hdidx_, token, response_headers_);
}

void Downstream::rewrite_location_response_header(
    const std::string &upstream_scheme) {
  auto hd =
      http2::get_header(response_hdidx_, http2::HD_LOCATION, response_headers_);
  if (!hd) {
    return;
  }
  http_parser_url u{};
  int rv =
      http_parser_parse_url((*hd).value.c_str(), (*hd).value.size(), 0, &u);
  if (rv != 0) {
    return;
  }
  std::string new_uri;
  if (get_config()->no_host_rewrite || request_method_ == HTTP_CONNECT) {
    if (!request_http2_authority_.empty()) {
      new_uri = http2::rewrite_location_uri(
          (*hd).value, u, request_http2_authority_, request_http2_authority_,
          upstream_scheme);
    }
    if (new_uri.empty()) {
      auto host = get_request_header(http2::HD_HOST);
      if (host) {
        new_uri = http2::rewrite_location_uri((*hd).value, u, (*host).value,
                                              (*host).value, upstream_scheme);
      } else if (!request_downstream_host_.empty()) {
        new_uri = http2::rewrite_location_uri(
            (*hd).value, u, request_downstream_host_, "", upstream_scheme);
      } else {
        return;
      }
    }
  } else {
    if (request_downstream_host_.empty()) {
      return;
    }
    if (!request_http2_authority_.empty()) {
      new_uri = http2::rewrite_location_uri(
          (*hd).value, u, request_downstream_host_, request_http2_authority_,
          upstream_scheme);
    } else {
      auto host = get_request_header(http2::HD_HOST);
      if (host) {
        new_uri = http2::rewrite_location_uri((*hd).value, u,
                                              request_downstream_host_,
                                              (*host).value, upstream_scheme);
      } else {
        new_uri = http2::rewrite_location_uri(
            (*hd).value, u, request_downstream_host_, "", upstream_scheme);
      }
    }
  }
  if (!new_uri.empty()) {
    auto idx = response_hdidx_[http2::HD_LOCATION];
    response_headers_[idx].value = std::move(new_uri);
  }
}

void Downstream::add_response_header(std::string name, std::string value) {
  add_header(response_header_key_prev_, response_headers_sum_,
             response_headers_, std::move(name), std::move(value));
}

void Downstream::set_last_response_header_value(const char *data, size_t len) {
  set_last_header_value(response_header_key_prev_, response_headers_sum_,
                        response_headers_, data, len);
}

void Downstream::add_response_header(std::string name, std::string value,
                                     int16_t token) {
  http2::index_header(response_hdidx_, token, response_headers_.size());
  response_headers_sum_ += name.size() + value.size();
  response_headers_.emplace_back(std::move(name), std::move(value), false,
                                 token);
}

void Downstream::add_response_header(const uint8_t *name, size_t namelen,
                                     const uint8_t *value, size_t valuelen,
                                     bool no_index, int16_t token) {
  http2::index_header(response_hdidx_, token, response_headers_.size());
  add_header(response_headers_sum_, response_headers_, name, namelen, value,
             valuelen, no_index, token);
}

bool Downstream::get_response_header_key_prev() const {
  return response_header_key_prev_;
}

void Downstream::append_last_response_header_key(const char *data, size_t len) {
  append_last_header_key(response_header_key_prev_, response_headers_sum_,
                         response_headers_, data, len);
}

void Downstream::append_last_response_header_value(const char *data,
                                                   size_t len) {
  append_last_header_value(response_header_key_prev_, response_headers_sum_,
                           response_headers_, data, len);
}

void Downstream::clear_response_headers() {
  Headers().swap(response_headers_);
  http2::init_hdidx(response_hdidx_);
}

size_t Downstream::get_response_headers_sum() const {
  return response_headers_sum_;
}

const Headers &Downstream::get_response_trailers() const {
  return response_trailers_;
}

void Downstream::add_response_trailer(const uint8_t *name, size_t namelen,
                                      const uint8_t *value, size_t valuelen,
                                      bool no_index, int16_t token) {
  add_header(response_headers_sum_, response_trailers_, name, namelen, value,
             valuelen, no_index, -1);
}

unsigned int Downstream::get_response_http_status() const {
  return response_http_status_;
}

void Downstream::add_response_trailer(std::string name, std::string value) {
  add_header(response_trailer_key_prev_, response_headers_sum_,
             response_trailers_, std::move(name), std::move(value));
}

void Downstream::set_last_response_trailer_value(const char *data, size_t len) {
  set_last_header_value(response_trailer_key_prev_, response_headers_sum_,
                        response_trailers_, data, len);
}

bool Downstream::get_response_trailer_key_prev() const {
  return response_trailer_key_prev_;
}

void Downstream::append_last_response_trailer_key(const char *data,
                                                  size_t len) {
  append_last_header_key(response_trailer_key_prev_, response_headers_sum_,
                         response_trailers_, data, len);
}

void Downstream::append_last_response_trailer_value(const char *data,
                                                    size_t len) {
  append_last_header_value(response_trailer_key_prev_, response_headers_sum_,
                           response_trailers_, data, len);
}

void Downstream::set_response_http_status(unsigned int status) {
  response_http_status_ = status;
}

void Downstream::set_response_major(int major) { response_major_ = major; }

void Downstream::set_response_minor(int minor) { response_minor_ = minor; }

int Downstream::get_response_major() const { return response_major_; }

int Downstream::get_response_minor() const { return response_minor_; }

int Downstream::get_response_version() const {
  return response_major_ * 100 + response_minor_;
}

bool Downstream::get_chunked_response() const { return chunked_response_; }

void Downstream::set_chunked_response(bool f) { chunked_response_ = f; }

bool Downstream::get_response_connection_close() const {
  return response_connection_close_;
}

void Downstream::set_response_connection_close(bool f) {
  response_connection_close_ = f;
}

int Downstream::on_read() {
  if (!dconn_) {
    DLOG(INFO, this) << "dconn_ is NULL";
    return -1;
  }
  return dconn_->on_read();
}

int Downstream::change_priority(int32_t pri) {
  if (!dconn_) {
    DLOG(INFO, this) << "dconn_ is NULL";
    return -1;
  }
  return dconn_->on_priority_change(pri);
}

void Downstream::set_response_state(int state) { response_state_ = state; }

int Downstream::get_response_state() const { return response_state_; }

DefaultMemchunks *Downstream::get_response_buf() { return &response_buf_; }

bool Downstream::response_buf_full() {
  if (dconn_) {
    return response_buf_.rleft() >=
           get_config()->downstream_response_buffer_size;
  } else {
    return false;
  }
}

void Downstream::add_response_bodylen(size_t amount) {
  response_bodylen_ += amount;
}

int64_t Downstream::get_response_bodylen() const { return response_bodylen_; }

void Downstream::add_response_sent_bodylen(size_t amount) {
  response_sent_bodylen_ += amount;
}

int64_t Downstream::get_response_sent_bodylen() const {
  return response_sent_bodylen_;
}

int64_t Downstream::get_response_content_length() const {
  return response_content_length_;
}

void Downstream::set_response_content_length(int64_t len) {
  response_content_length_ = len;
}

int64_t Downstream::get_request_content_length() const {
  return request_content_length_;
}

void Downstream::set_request_content_length(int64_t len) {
  request_content_length_ = len;
}

bool Downstream::validate_request_bodylen() const {
  if (request_content_length_ == -1) {
    return true;
  }

  if (request_content_length_ != request_bodylen_) {
    if (LOG_ENABLED(INFO)) {
      DLOG(INFO, this) << "request invalid bodylen: content-length="
                       << request_content_length_
                       << ", received=" << request_bodylen_;
    }
    return false;
  }

  return true;
}

bool Downstream::validate_response_bodylen() const {
  if (!expect_response_body() || response_content_length_ == -1) {
    return true;
  }

  if (response_content_length_ != response_bodylen_) {
    if (LOG_ENABLED(INFO)) {
      DLOG(INFO, this) << "response invalid bodylen: content-length="
                       << response_content_length_
                       << ", received=" << response_bodylen_;
    }
    return false;
  }

  return true;
}

void Downstream::set_priority(int32_t pri) { priority_ = pri; }

int32_t Downstream::get_priority() const { return priority_; }

void Downstream::check_upgrade_fulfilled() {
  if (request_method_ == HTTP_CONNECT) {
    upgraded_ = 200 <= response_http_status_ && response_http_status_ < 300;

    return;
  }

  if (response_http_status_ == 101) {
    // TODO Do more strict checking for upgrade headers
    upgraded_ = upgrade_request_;

    return;
  }
}

void Downstream::inspect_http2_request() {
  if (request_method_ == HTTP_CONNECT) {
    upgrade_request_ = true;
  }
}

void Downstream::inspect_http1_request() {
  if (request_method_ == HTTP_CONNECT) {
    upgrade_request_ = true;
  }

  if (!upgrade_request_) {
    auto idx = request_hdidx_[http2::HD_UPGRADE];
    if (idx != -1) {
      auto &val = request_headers_[idx].value;
      // TODO Perform more strict checking for upgrade headers
      if (util::streq_l(NGHTTP2_CLEARTEXT_PROTO_VERSION_ID, val.c_str(),
                        val.size())) {
        http2_upgrade_seen_ = true;
      } else {
        upgrade_request_ = true;
      }
    }
  }
  auto idx = request_hdidx_[http2::HD_TRANSFER_ENCODING];
  if (idx != -1) {
    request_content_length_ = -1;
    if (util::strifind(request_headers_[idx].value.c_str(), "chunked")) {
      chunked_request_ = true;
    }
  }
}

void Downstream::inspect_http1_response() {
  auto idx = response_hdidx_[http2::HD_TRANSFER_ENCODING];
  if (idx != -1) {
    response_content_length_ = -1;
    if (util::strifind(response_headers_[idx].value.c_str(), "chunked")) {
      chunked_response_ = true;
    }
  }
}

void Downstream::reset_response() {
  response_http_status_ = 0;
  response_major_ = 1;
  response_minor_ = 1;
}

bool Downstream::get_non_final_response() const {
  return !upgraded_ && response_http_status_ / 100 == 1;
}

bool Downstream::get_upgraded() const { return upgraded_; }

bool Downstream::get_upgrade_request() const { return upgrade_request_; }

bool Downstream::get_http2_upgrade_request() const {
  return http2_upgrade_seen_ &&
         request_hdidx_[http2::HD_HTTP2_SETTINGS] != -1 &&
         response_state_ == INITIAL;
}

namespace {
const std::string EMPTY;
} // namespace

const std::string &Downstream::get_http2_settings() const {
  auto idx = request_hdidx_[http2::HD_HTTP2_SETTINGS];
  if (idx == -1) {
    return EMPTY;
  }
  return request_headers_[idx].value;
}

void Downstream::set_downstream_stream_id(int32_t stream_id) {
  downstream_stream_id_ = stream_id;
}

int32_t Downstream::get_downstream_stream_id() const {
  return downstream_stream_id_;
}

uint32_t Downstream::get_response_rst_stream_error_code() const {
  return response_rst_stream_error_code_;
}

void Downstream::set_response_rst_stream_error_code(uint32_t error_code) {
  response_rst_stream_error_code_ = error_code;
}

void Downstream::set_expect_final_response(bool f) {
  expect_final_response_ = f;
}

bool Downstream::get_expect_final_response() const {
  return expect_final_response_;
}

size_t Downstream::get_request_datalen() const { return request_datalen_; }

void Downstream::dec_request_datalen(size_t len) {
  assert(request_datalen_ >= len);
  request_datalen_ -= len;
}

void Downstream::reset_request_datalen() { request_datalen_ = 0; }

void Downstream::add_response_datalen(size_t len) { response_datalen_ += len; }

void Downstream::dec_response_datalen(size_t len) {
  assert(response_datalen_ >= len);
  response_datalen_ -= len;
}

size_t Downstream::get_response_datalen() const { return response_datalen_; }

void Downstream::reset_response_datalen() { response_datalen_ = 0; }

bool Downstream::expect_response_body() const {
  return http2::expect_response_body(request_method_, response_http_status_);
}

namespace {
bool pseudo_header_allowed(const Headers &headers) {
  if (headers.empty()) {
    return true;
  }

  return headers.back().name.c_str()[0] == ':';
}
} // namespace

bool Downstream::request_pseudo_header_allowed(int16_t token) const {
  if (!pseudo_header_allowed(request_headers_)) {
    return false;
  }
  return http2::check_http2_request_pseudo_header(request_hdidx_, token);
}

bool Downstream::response_pseudo_header_allowed(int16_t token) const {
  if (!pseudo_header_allowed(response_headers_)) {
    return false;
  }
  return http2::check_http2_response_pseudo_header(response_hdidx_, token);
}

namespace {
void reset_timer(struct ev_loop *loop, ev_timer *w) { ev_timer_again(loop, w); }
} // namespace

namespace {
void try_reset_timer(struct ev_loop *loop, ev_timer *w) {
  if (!ev_is_active(w)) {
    return;
  }
  ev_timer_again(loop, w);
}
} // namespace

namespace {
void ensure_timer(struct ev_loop *loop, ev_timer *w) {
  if (ev_is_active(w)) {
    return;
  }
  ev_timer_again(loop, w);
}
} // namespace

namespace {
void disable_timer(struct ev_loop *loop, ev_timer *w) {
  ev_timer_stop(loop, w);
}
} // namespace

void Downstream::reset_upstream_rtimer() {
  if (get_config()->stream_read_timeout == 0.) {
    return;
  }
  auto loop = upstream_->get_client_handler()->get_loop();
  reset_timer(loop, &upstream_rtimer_);
}

void Downstream::reset_upstream_wtimer() {
  auto loop = upstream_->get_client_handler()->get_loop();
  if (get_config()->stream_write_timeout != 0.) {
    reset_timer(loop, &upstream_wtimer_);
  }
  if (get_config()->stream_read_timeout != 0.) {
    try_reset_timer(loop, &upstream_rtimer_);
  }
}

void Downstream::ensure_upstream_wtimer() {
  if (get_config()->stream_write_timeout == 0.) {
    return;
  }
  auto loop = upstream_->get_client_handler()->get_loop();
  ensure_timer(loop, &upstream_wtimer_);
}

void Downstream::disable_upstream_rtimer() {
  if (get_config()->stream_read_timeout == 0.) {
    return;
  }
  auto loop = upstream_->get_client_handler()->get_loop();
  disable_timer(loop, &upstream_rtimer_);
}

void Downstream::disable_upstream_wtimer() {
  if (get_config()->stream_write_timeout == 0.) {
    return;
  }
  auto loop = upstream_->get_client_handler()->get_loop();
  disable_timer(loop, &upstream_wtimer_);
}

void Downstream::reset_downstream_rtimer() {
  if (get_config()->stream_read_timeout == 0.) {
    return;
  }
  auto loop = upstream_->get_client_handler()->get_loop();
  reset_timer(loop, &downstream_rtimer_);
}

void Downstream::reset_downstream_wtimer() {
  auto loop = upstream_->get_client_handler()->get_loop();
  if (get_config()->stream_write_timeout != 0.) {
    reset_timer(loop, &downstream_wtimer_);
  }
  if (get_config()->stream_read_timeout != 0.) {
    try_reset_timer(loop, &downstream_rtimer_);
  }
}

void Downstream::ensure_downstream_wtimer() {
  if (get_config()->stream_write_timeout == 0.) {
    return;
  }
  auto loop = upstream_->get_client_handler()->get_loop();
  ensure_timer(loop, &downstream_wtimer_);
}

void Downstream::disable_downstream_rtimer() {
  if (get_config()->stream_read_timeout == 0.) {
    return;
  }
  auto loop = upstream_->get_client_handler()->get_loop();
  disable_timer(loop, &downstream_rtimer_);
}

void Downstream::disable_downstream_wtimer() {
  if (get_config()->stream_write_timeout == 0.) {
    return;
  }
  auto loop = upstream_->get_client_handler()->get_loop();
  disable_timer(loop, &downstream_wtimer_);
}

bool Downstream::accesslog_ready() const { return response_http_status_ > 0; }

void Downstream::add_retry() { ++num_retry_; }

bool Downstream::no_more_retry() const { return num_retry_ > 5; }

void Downstream::set_request_downstream_host(std::string host) {
  request_downstream_host_ = std::move(host);
}

void Downstream::set_request_pending(bool f) { request_pending_ = f; }

bool Downstream::get_request_pending() const { return request_pending_; }

bool Downstream::request_submission_ready() const {
  return (request_state_ == Downstream::HEADER_COMPLETE ||
          request_state_ == Downstream::MSG_COMPLETE) &&
         request_pending_ && response_state_ == Downstream::INITIAL;
}

int Downstream::get_dispatch_state() const { return dispatch_state_; }

void Downstream::set_dispatch_state(int s) { dispatch_state_ = s; }

void Downstream::attach_blocked_link(BlockedLink *l) {
  assert(!blocked_link_);

  l->downstream = this;
  blocked_link_ = l;
}

BlockedLink *Downstream::detach_blocked_link() {
  auto link = blocked_link_;
  blocked_link_ = nullptr;
  return link;
}

void Downstream::add_request_headers_sum(size_t amount) {
  request_headers_sum_ += amount;
}

bool Downstream::can_detach_downstream_connection() const {
  return dconn_ && response_state_ == Downstream::MSG_COMPLETE &&
         request_state_ == Downstream::MSG_COMPLETE && !upgraded_ &&
         !response_connection_close_;
}

DefaultMemchunks Downstream::pop_response_buf() {
  return std::move(response_buf_);
}

} // namespace shrpx
