/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
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
#include "asio_http2_handler.h"

#include <iostream>

#include "asio_common.h"
#include "http2.h"
#include "util.h"
#include "template.h"

namespace nghttp2 {

namespace asio_http2 {

namespace server {

extern std::shared_ptr<std::string> cached_date;

request::request() : impl_(make_unique<request_impl>()) {}

const header_map &request::header() const { return impl_->header(); }

const std::string &request::method() const { return impl_->method(); }

const uri_ref &request::uri() const { return impl_->uri(); }

void request::on_data(data_cb cb) const {
  return impl_->on_data(std::move(cb));
}

request_impl &request::impl() const { return *impl_; }

response::response() : impl_(make_unique<response_impl>()) {}

void response::write_head(unsigned int status_code, header_map h) const {
  impl_->write_head(status_code, std::move(h));
}

void response::end(std::string data) const { impl_->end(std::move(data)); }

void response::end(read_cb cb) const { impl_->end(std::move(cb)); }

void response::on_close(close_cb cb) const { impl_->on_close(std::move(cb)); }

void response::cancel() const { impl_->cancel(); }

const response *response::push(boost::system::error_code &ec,
                               std::string method, std::string path,
                               header_map h) const {
  return impl_->push(ec, std::move(method), std::move(path), std::move(h));
}

void response::resume() const { impl_->resume(); }

unsigned int response::status_code() const { return impl_->status_code(); }

bool response::started() const { return impl_->started(); }

response_impl &response::impl() const { return *impl_; }

request_impl::request_impl() : stream_(nullptr) {}

const header_map &request_impl::header() const { return header_; }

const std::string &request_impl::method() const { return method_; }

const uri_ref &request_impl::uri() const { return uri_; }

uri_ref &request_impl::uri() { return uri_; }

void request_impl::header(header_map h) { header_ = std::move(h); }

header_map &request_impl::header() { return header_; }

void request_impl::method(std::string arg) { method_ = std::move(arg); }

void request_impl::on_data(data_cb cb) { on_data_cb_ = std::move(cb); }

void request_impl::stream(http2_stream *s) { stream_ = s; }

void request_impl::call_on_data(const uint8_t *data, std::size_t len) {
  if (on_data_cb_) {
    on_data_cb_(data, len);
  }
}

response_impl::response_impl()
    : stream_(nullptr), status_code_(200), started_(false), pushed_(false),
      push_promise_sent_(false) {}

unsigned int response_impl::status_code() const { return status_code_; }

void response_impl::write_head(unsigned int status_code, header_map h) {
  status_code_ = status_code;
  header_ = std::move(h);
}

void response_impl::end(std::string data) {
  if (started_) {
    return;
  }

  end(string_reader(std::move(data)));
}

void response_impl::end(read_cb cb) {
  if (started_) {
    return;
  }

  read_cb_ = std::move(cb);
  started_ = true;

  start_response();
}

void response_impl::on_close(close_cb cb) { close_cb_ = std::move(cb); }

void response_impl::call_on_close(uint32_t error_code) {
  if (close_cb_) {
    close_cb_(error_code);
  }
}

void response_impl::cancel() {
  auto handler = stream_->handler();

  handler->stream_error(stream_->get_stream_id(), NGHTTP2_CANCEL);
}

void response_impl::start_response() {
  if (!started_ || (pushed_ && !push_promise_sent_)) {
    return;
  }

  auto handler = stream_->handler();

  if (handler->start_response(*stream_) != 0) {
    handler->stream_error(stream_->get_stream_id(), NGHTTP2_INTERNAL_ERROR);
    return;
  }

  if (!handler->inside_callback()) {
    handler->initiate_write();
  }
}

response *response_impl::push(boost::system::error_code &ec, std::string method,
                              std::string raw_path_query, header_map h) const {
  auto handler = stream_->handler();
  return handler->push_promise(ec, *stream_, std::move(method),
                               std::move(raw_path_query), std::move(h));
}

void response_impl::resume() {
  auto handler = stream_->handler();
  handler->resume(*stream_);

  if (!handler->inside_callback()) {
    handler->initiate_write();
  }
}

bool response_impl::started() const { return started_; }

void response_impl::pushed(bool f) { pushed_ = f; }

void response_impl::push_promise_sent(bool f) { push_promise_sent_ = f; }

const header_map &response_impl::header() const { return header_; }

void response_impl::stream(http2_stream *s) { stream_ = s; }

read_cb::result_type response_impl::call_read(uint8_t *data, std::size_t len,
                                              uint32_t *data_flags) {
  if (read_cb_) {
    return read_cb_(data, len, data_flags);
  }

  *data_flags |= NGHTTP2_DATA_FLAG_EOF;

  return 0;
}

http2_stream::http2_stream(http2_handler *h, int32_t stream_id)
    : handler_(h), stream_id_(stream_id) {
  request_.impl().stream(this);
  response_.impl().stream(this);
}

int32_t http2_stream::get_stream_id() const { return stream_id_; }

request &http2_stream::request() { return request_; }

response &http2_stream::response() { return response_; }

http2_handler *http2_stream::handler() const { return handler_; }

namespace {
int stream_error(nghttp2_session *session, int32_t stream_id,
                 uint32_t error_code) {
  return nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id,
                                   error_code);
}
} // namespace

namespace {
int on_begin_headers_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, void *user_data) {
  auto handler = static_cast<http2_handler *>(user_data);

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }

  handler->create_stream(frame->hd.stream_id);

  return 0;
}
} // namespace

namespace {
int on_header_callback(nghttp2_session *session, const nghttp2_frame *frame,
                       const uint8_t *name, size_t namelen,
                       const uint8_t *value, size_t valuelen, uint8_t flags,
                       void *user_data) {
  auto handler = static_cast<http2_handler *>(user_data);
  auto stream_id = frame->hd.stream_id;

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }

  auto stream = handler->find_stream(stream_id);
  if (!stream) {
    return 0;
  }

  auto &req = stream->request().impl();
  auto &uref = req.uri();

  switch (nghttp2::http2::lookup_token(name, namelen)) {
  case nghttp2::http2::HD__METHOD:
    req.method(std::string(value, value + valuelen));
    break;
  case nghttp2::http2::HD__SCHEME:
    uref.scheme.assign(value, value + valuelen);
    break;
  case nghttp2::http2::HD__AUTHORITY:
    uref.host.assign(value, value + valuelen);
    break;
  case nghttp2::http2::HD__PATH:
    split_path(uref, value, value + valuelen);
    break;
  case nghttp2::http2::HD_HOST:
    if (uref.host.empty()) {
      uref.host.assign(value, value + valuelen);
    }
  // fall through
  default:
    req.header().emplace(std::string(name, name + namelen),
                         header_value{std::string(value, value + valuelen),
                                      (flags & NGHTTP2_NV_FLAG_NO_INDEX) != 0});
  }

  return 0;
}
} // namespace

namespace {
int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame,
                           void *user_data) {
  auto handler = static_cast<http2_handler *>(user_data);
  auto stream = handler->find_stream(frame->hd.stream_id);

  switch (frame->hd.type) {
  case NGHTTP2_DATA:
    if (!stream) {
      break;
    }

    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      stream->request().impl().call_on_data(nullptr, 0);
    }

    break;
  case NGHTTP2_HEADERS: {
    if (!stream || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
      break;
    }

    handler->call_on_request(*stream);

    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      stream->request().impl().call_on_data(nullptr, 0);
    }

    break;
  }
  }

  return 0;
}
} // namespace

namespace {
int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                int32_t stream_id, const uint8_t *data,
                                size_t len, void *user_data) {
  auto handler = static_cast<http2_handler *>(user_data);
  auto stream = handler->find_stream(stream_id);

  if (!stream) {
    return 0;
  }

  stream->request().impl().call_on_data(data, len);

  return 0;
}

} // namespace

namespace {
int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                             uint32_t error_code, void *user_data) {
  auto handler = static_cast<http2_handler *>(user_data);

  auto stream = handler->find_stream(stream_id);
  if (!stream) {
    return 0;
  }

  stream->response().impl().call_on_close(error_code);

  handler->close_stream(stream_id);

  return 0;
}
} // namespace

namespace {
int on_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame,
                           void *user_data) {
  auto handler = static_cast<http2_handler *>(user_data);

  if (frame->hd.type != NGHTTP2_PUSH_PROMISE) {
    return 0;
  }

  auto stream = handler->find_stream(frame->push_promise.promised_stream_id);

  if (!stream) {
    return 0;
  }

  auto &res = stream->response().impl();
  res.push_promise_sent(true);
  res.start_response();

  return 0;
}
} // namespace

namespace {
int on_frame_not_send_callback(nghttp2_session *session,
                               const nghttp2_frame *frame, int lib_error_code,
                               void *user_data) {
  if (frame->hd.type != NGHTTP2_HEADERS) {
    return 0;
  }

  // Issue RST_STREAM so that stream does not hang around.
  nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, frame->hd.stream_id,
                            NGHTTP2_INTERNAL_ERROR);

  return 0;
}
} // namespace

http2_handler::http2_handler(boost::asio::io_service &io_service,
                             connection_write writefun, request_cb cb)
    : writefun_(writefun), request_cb_(std::move(cb)), io_service_(io_service),
      session_(nullptr), buf_(nullptr), buflen_(0), inside_callback_(false) {}

http2_handler::~http2_handler() { nghttp2_session_del(session_); }

int http2_handler::start() {
  int rv;

  nghttp2_session_callbacks *callbacks;
  rv = nghttp2_session_callbacks_new(&callbacks);
  if (rv != 0) {
    return -1;
  }

  auto cb_del = defer(nghttp2_session_callbacks_del, callbacks);

  nghttp2_session_callbacks_set_on_begin_headers_callback(
      callbacks, on_begin_headers_callback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                   on_header_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, on_stream_close_callback);
  nghttp2_session_callbacks_set_on_frame_send_callback(callbacks,
                                                       on_frame_send_callback);
  nghttp2_session_callbacks_set_on_frame_not_send_callback(
      callbacks, on_frame_not_send_callback);

  nghttp2_option *option;
  rv = nghttp2_option_new(&option);
  if (rv != 0) {
    return -1;
  }

  auto opt_del = defer(nghttp2_option_del, option);

  nghttp2_option_set_recv_client_preface(option, 1);

  rv = nghttp2_session_server_new2(&session_, callbacks, this, option);
  if (rv != 0) {
    return -1;
  }

  nghttp2_settings_entry ent{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100};
  nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, &ent, 1);

  return 0;
}

http2_stream *http2_handler::create_stream(int32_t stream_id) {
  auto p =
      streams_.emplace(stream_id, make_unique<http2_stream>(this, stream_id));
  assert(p.second);
  return (*p.first).second.get();
}

void http2_handler::close_stream(int32_t stream_id) {
  streams_.erase(stream_id);
}

http2_stream *http2_handler::find_stream(int32_t stream_id) {
  auto i = streams_.find(stream_id);
  if (i == std::end(streams_)) {
    return nullptr;
  }

  return (*i).second.get();
}

void http2_handler::call_on_request(http2_stream &stream) {
  request_cb_(stream.request(), stream.response());
}

bool http2_handler::should_stop() const {
  return !nghttp2_session_want_read(session_) &&
         !nghttp2_session_want_write(session_);
}

int http2_handler::start_response(http2_stream &stream) {
  int rv;

  auto &res = stream.response().impl();
  auto &header = res.header();
  auto nva = std::vector<nghttp2_nv>();
  nva.reserve(2 + header.size());
  auto status = util::utos(res.status_code());
  auto date = cached_date;
  nva.push_back(nghttp2::http2::make_nv_ls(":status", status));
  nva.push_back(nghttp2::http2::make_nv_ls("date", *date));
  for (auto &hd : header) {
    nva.push_back(nghttp2::http2::make_nv(hd.first, hd.second.value,
                                          hd.second.sensitive));
  }

  nghttp2_data_provider prd;
  prd.source.ptr = &stream;
  prd.read_callback =
      [](nghttp2_session *session, int32_t stream_id, uint8_t *buf,
         size_t length, uint32_t *data_flags, nghttp2_data_source *source,
         void *user_data) -> ssize_t {
    auto &stream = *static_cast<http2_stream *>(source->ptr);
    return stream.response().impl().call_read(buf, length, data_flags);
  };

  rv = nghttp2_submit_response(session_, stream.get_stream_id(), nva.data(),
                               nva.size(), &prd);

  if (rv != 0) {
    return -1;
  }

  return 0;
}

void http2_handler::enter_callback() {
  assert(!inside_callback_);
  inside_callback_ = true;
}

void http2_handler::leave_callback() {
  assert(inside_callback_);
  inside_callback_ = false;
}

bool http2_handler::inside_callback() const { return inside_callback_; }

void http2_handler::stream_error(int32_t stream_id, uint32_t error_code) {
  ::nghttp2::asio_http2::server::stream_error(session_, stream_id, error_code);
}

void http2_handler::initiate_write() { writefun_(); }

void http2_handler::resume(http2_stream &stream) {
  nghttp2_session_resume_data(session_, stream.get_stream_id());
}

response *http2_handler::push_promise(boost::system::error_code &ec,
                                      http2_stream &stream, std::string method,
                                      std::string raw_path_query,
                                      header_map h) {
  int rv;

  ec.clear();

  auto &req = stream.request().impl();

  auto nva = std::vector<nghttp2_nv>();
  nva.reserve(4 + h.size());
  nva.push_back(nghttp2::http2::make_nv_ls(":method", method));
  nva.push_back(nghttp2::http2::make_nv_ls(":scheme", req.uri().scheme));
  nva.push_back(nghttp2::http2::make_nv_ls(":authority", req.uri().host));
  nva.push_back(nghttp2::http2::make_nv_ls(":path", raw_path_query));

  for (auto &hd : h) {
    nva.push_back(nghttp2::http2::make_nv(hd.first, hd.second.value,
                                          hd.second.sensitive));
  }

  rv = nghttp2_submit_push_promise(session_, NGHTTP2_FLAG_NONE,
                                   stream.get_stream_id(), nva.data(),
                                   nva.size(), nullptr);

  if (rv < 0) {
    ec = make_error_code(static_cast<nghttp2_error>(rv));
    return nullptr;
  }

  auto promised_stream = create_stream(rv);
  auto &promised_req = promised_stream->request().impl();
  promised_req.header(std::move(h));
  promised_req.method(std::move(method));

  auto &uref = promised_req.uri();
  uref.scheme = req.uri().scheme;
  uref.host = req.uri().host;
  split_path(uref, std::begin(raw_path_query), std::end(raw_path_query));

  auto &promised_res = promised_stream->response().impl();
  promised_res.pushed(true);

  return &promised_stream->response();
}

boost::asio::io_service &http2_handler::io_service() { return io_service_; }

callback_guard::callback_guard(http2_handler &h) : handler(h) {
  handler.enter_callback();
}

callback_guard::~callback_guard() { handler.leave_callback(); }

} // namespace server

} // namespace asio_http2

} // namespace nghttp2
