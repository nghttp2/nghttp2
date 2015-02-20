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

#include "http2.h"
#include "util.h"
#include "template.h"

namespace nghttp2 {

namespace asio_http2 {

channel::channel() : impl_(make_unique<channel_impl>()) {}

void channel::post(void_cb cb) { impl_->post(std::move(cb)); }

channel_impl &channel::impl() { return *impl_; }

channel_impl::channel_impl() : strand_(nullptr) {}

void channel_impl::post(void_cb cb) { strand_->post(std::move(cb)); }

void channel_impl::strand(boost::asio::io_service::strand *strand) {
  strand_ = strand;
}

namespace server {

extern std::shared_ptr<std::string> cached_date;

request::request() : impl_(make_unique<request_impl>()) {}

const std::vector<header> &request::headers() const { return impl_->headers(); }

const std::string &request::method() const { return impl_->method(); }

const std::string &request::scheme() const { return impl_->scheme(); }

const std::string &request::authority() const { return impl_->authority(); }

const std::string &request::host() const { return impl_->host(); }

const std::string &request::path() const { return impl_->path(); }

bool request::push(std::string method, std::string path,
                   std::vector<header> headers) {
  return impl_->push(std::move(method), std::move(path), std::move(headers));
}

bool request::pushed() const { return impl_->pushed(); }

bool request::closed() const { return impl_->closed(); }

void request::on_data(data_cb cb) { return impl_->on_data(std::move(cb)); }

void request::on_end(void_cb cb) { return impl_->on_end(std::move(cb)); }

bool request::run_task(thread_cb start) {
  return impl_->run_task(std::move(start));
}

request_impl &request::impl() { return *impl_; }

response::response() : impl_(make_unique<response_impl>()) {}

void response::write_head(unsigned int status_code,
                          std::vector<header> headers) {
  impl_->write_head(status_code, std::move(headers));
}

void response::end(std::string data) { impl_->end(std::move(data)); }

void response::end(read_cb cb) { impl_->end(std::move(cb)); }

void response::resume() { impl_->resume(); }

unsigned int response::status_code() const { return impl_->status_code(); }

bool response::started() const { return impl_->started(); }

response_impl &response::impl() { return *impl_; }

request_impl::request_impl() : pushed_(false) {}

const std::vector<header> &request_impl::headers() const { return headers_; }

const std::string &request_impl::method() const { return method_; }

const std::string &request_impl::scheme() const { return scheme_; }

const std::string &request_impl::authority() const { return authority_; }

const std::string &request_impl::host() const { return host_; }

const std::string &request_impl::path() const { return path_; }

void request_impl::set_header(std::vector<header> headers) {
  headers_ = std::move(headers);
}

void request_impl::add_header(std::string name, std::string value) {
  headers_.push_back(header{std::move(name), std::move(value)});
}

void request_impl::method(std::string arg) { method_ = std::move(arg); }

void request_impl::scheme(std::string arg) { scheme_ = std::move(arg); }

void request_impl::authority(std::string arg) { authority_ = std::move(arg); }

void request_impl::host(std::string arg) { host_ = std::move(arg); }

void request_impl::path(std::string arg) { path_ = std::move(arg); }

bool request_impl::push(std::string method, std::string path,
                        std::vector<header> headers) {
  if (closed()) {
    return false;
  }

  auto handler = handler_.lock();
  auto stream = stream_.lock();
  auto rv = handler->push_promise(*stream, std::move(method), std::move(path),
                                  std::move(headers));
  return rv == 0;
}

bool request_impl::pushed() const { return pushed_; }

void request_impl::pushed(bool f) { pushed_ = f; }

bool request_impl::closed() const {
  return handler_.expired() || stream_.expired();
}

void request_impl::on_data(data_cb cb) { on_data_cb_ = std::move(cb); }

void request_impl::on_end(void_cb cb) { on_end_cb_ = std::move(cb); }

bool request_impl::run_task(thread_cb start) {
  if (closed()) {
    return false;
  }

  auto handler = handler_.lock();

  return handler->run_task(std::move(start));
}

void request_impl::handler(std::weak_ptr<http2_handler> h) {
  handler_ = std::move(h);
}

void request_impl::stream(std::weak_ptr<http2_stream> s) {
  stream_ = std::move(s);
}

void request_impl::call_on_data(const uint8_t *data, std::size_t len) {
  if (on_data_cb_) {
    on_data_cb_(data, len);
  }
}

void request_impl::call_on_end() {
  if (on_end_cb_) {
    on_end_cb_();
  }
}

response_impl::response_impl() : status_code_(200), started_(false) {}

unsigned int response_impl::status_code() const { return status_code_; }

void response_impl::write_head(unsigned int status_code,
                               std::vector<header> headers) {
  status_code_ = status_code;
  headers_ = std::move(headers);
}

void response_impl::end(std::string data) {
  if (started_) {
    return;
  }

  auto strio = std::make_shared<std::pair<std::string, size_t>>(std::move(data),
                                                                data.size());
  auto read_cb = [strio](uint8_t *buf, size_t len) {
    auto nread = std::min(len, strio->second);
    memcpy(buf, strio->first.c_str(), nread);
    strio->second -= nread;
    if (strio->second == 0) {
      return std::make_pair(nread, true);
    }

    return std::make_pair(nread, false);
  };

  end(std::move(read_cb));
}

void response_impl::end(read_cb cb) {
  if (started_ || closed()) {
    return;
  }

  read_cb_ = std::move(cb);
  started_ = true;

  auto handler = handler_.lock();
  auto stream = stream_.lock();

  if (handler->start_response(*stream) != 0) {
    handler->stream_error(stream->get_stream_id(), NGHTTP2_INTERNAL_ERROR);
    return;
  }

  if (!handler->inside_callback()) {
    handler->initiate_write();
  }
}

bool response_impl::closed() const {
  return handler_.expired() || stream_.expired();
}

void response_impl::resume() {
  if (closed()) {
    return;
  }

  auto handler = handler_.lock();
  auto stream = stream_.lock();
  handler->resume(*stream);

  if (!handler->inside_callback()) {
    handler->initiate_write();
  }
}

bool response_impl::started() const { return started_; }

const std::vector<header> &response_impl::headers() const { return headers_; }

void response_impl::handler(std::weak_ptr<http2_handler> h) {
  handler_ = std::move(h);
}

void response_impl::stream(std::weak_ptr<http2_stream> s) {
  stream_ = std::move(s);
}

std::pair<ssize_t, bool> response_impl::call_read(uint8_t *data,
                                                  std::size_t len) {
  if (read_cb_) {
    return read_cb_(data, len);
  }

  return std::make_pair(0, true);
}

http2_stream::http2_stream(int32_t stream_id)
    : request_(std::make_shared<request>()),
      response_(std::make_shared<response>()), stream_id_(stream_id) {}

int32_t http2_stream::get_stream_id() const { return stream_id_; }

const std::shared_ptr<request> &http2_stream::get_request() { return request_; }

const std::shared_ptr<response> &http2_stream::get_response() {
  return response_;
}

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

  if (!nghttp2_check_header_name(name, namelen) ||
      !nghttp2_check_header_value(value, valuelen)) {
    stream_error(session, stream_id, NGHTTP2_PROTOCOL_ERROR);

    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  auto &req = stream->get_request()->impl();

  if (name[0] == ':' && !req.headers().empty()) {
    stream_error(session, stream_id, NGHTTP2_PROTOCOL_ERROR);
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  if (util::streq_l(":method", name, namelen)) {
    if (!req.method().empty()) {
      stream_error(session, stream_id, NGHTTP2_PROTOCOL_ERROR);
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    req.method(std::string(value, value + valuelen));
  } else if (util::streq_l(":scheme", name, namelen)) {
    if (!req.scheme().empty()) {
      stream_error(session, stream_id, NGHTTP2_PROTOCOL_ERROR);
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    req.scheme(std::string(value, value + valuelen));
  } else if (util::streq_l(":authority", name, namelen)) {
    if (!req.authority().empty()) {
      stream_error(session, stream_id, NGHTTP2_PROTOCOL_ERROR);
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    req.authority(std::string(value, value + valuelen));
  } else if (util::streq_l(":path", name, namelen)) {
    if (!req.path().empty()) {
      stream_error(session, stream_id, NGHTTP2_PROTOCOL_ERROR);
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    req.path(std::string(value, value + valuelen));
  } else {
    if (name[0] == ':') {
      stream_error(session, stream_id, NGHTTP2_PROTOCOL_ERROR);
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    if (util::streq_l("host", name, namelen)) {
      req.host(std::string(value, value + valuelen));
    }

    req.add_header(std::string(name, name + namelen),
                   std::string(value, value + valuelen));
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
      stream->get_request()->impl().call_on_end();
    }

    break;
  case NGHTTP2_HEADERS: {
    if (!stream || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
      break;
    }

    auto &req = stream->get_request()->impl();

    if (req.method().empty() || req.scheme().empty() || req.path().empty() ||
        (req.authority().empty() && req.host().empty())) {
      stream_error(session, frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
      return 0;
    }

    if (req.host().empty()) {
      req.host(req.authority());
    }

    handler->call_on_request(*stream);

    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      stream->get_request()->impl().call_on_end();
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

  stream->get_request()->impl().call_on_data(data, len);

  return 0;
}

} // namespace

namespace {
int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                             uint32_t error_code, void *user_data) {
  auto handler = static_cast<http2_handler *>(user_data);

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

  handler->call_on_request(*stream);

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
                             boost::asio::io_service &task_io_service_,
                             connection_write writefun, request_cb cb)
    : writefun_(writefun), request_cb_(std::move(cb)), io_service_(io_service),
      task_io_service_(task_io_service_),
      strand_(std::make_shared<boost::asio::io_service::strand>(io_service_)),
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

std::shared_ptr<http2_stream> http2_handler::create_stream(int32_t stream_id) {
  auto stream = std::make_shared<http2_stream>(stream_id);
  streams_.emplace(stream_id, stream);

  auto self = shared_from_this();
  auto &req = stream->get_request()->impl();
  auto &res = stream->get_response()->impl();
  req.handler(self);
  req.stream(stream);
  res.handler(self);
  res.stream(stream);

  return stream;
}

void http2_handler::close_stream(int32_t stream_id) {
  streams_.erase(stream_id);
}

std::shared_ptr<http2_stream> http2_handler::find_stream(int32_t stream_id) {
  auto i = streams_.find(stream_id);
  if (i == std::end(streams_)) {
    return nullptr;
  }

  return (*i).second;
}

void http2_handler::call_on_request(http2_stream &stream) {
  request_cb_(stream.get_request(), stream.get_response());
}

bool http2_handler::should_stop() const {
  return !nghttp2_session_want_read(session_) &&
         !nghttp2_session_want_write(session_);
}

int http2_handler::start_response(http2_stream &stream) {
  int rv;

  auto &res = stream.get_response()->impl();
  auto &headers = res.headers();
  auto nva = std::vector<nghttp2_nv>();
  nva.reserve(2 + headers.size());
  auto status = util::utos(res.status_code());
  auto date = cached_date;
  nva.push_back(nghttp2::http2::make_nv_ls(":status", status));
  nva.push_back(nghttp2::http2::make_nv_ls("date", *date));
  for (auto &hd : headers) {
    nva.push_back(nghttp2::http2::make_nv(hd.name, hd.value));
  }

  nghttp2_data_provider prd;
  prd.source.ptr = &stream;
  prd.read_callback =
      [](nghttp2_session *session, int32_t stream_id, uint8_t *buf,
         size_t length, uint32_t *data_flags, nghttp2_data_source *source,
         void *user_data) -> ssize_t {
    auto &stream = *static_cast<http2_stream *>(source->ptr);
    auto rv = stream.get_response()->impl().call_read(buf, length);
    if (rv.first < 0) {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    if (rv.second) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    } else if (rv.first == 0) {
      return NGHTTP2_ERR_DEFERRED;
    }

    return rv.first;
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

int http2_handler::push_promise(http2_stream &stream, std::string method,
                                std::string path, std::vector<header> headers) {
  int rv;

  auto &req = stream.get_request()->impl();

  auto nva = std::vector<nghttp2_nv>();
  nva.reserve(5 + headers.size());
  nva.push_back(nghttp2::http2::make_nv_ls(":method", method));
  nva.push_back(nghttp2::http2::make_nv_ls(":scheme", req.scheme()));
  if (!req.authority().empty()) {
    nva.push_back(nghttp2::http2::make_nv_ls(":authority", req.authority()));
  }
  nva.push_back(nghttp2::http2::make_nv_ls(":path", path));
  if (!req.host().empty()) {
    nva.push_back(nghttp2::http2::make_nv_ls("host", req.host()));
  }

  for (auto &hd : headers) {
    nva.push_back(nghttp2::http2::make_nv(hd.name, hd.value));
  }

  rv = nghttp2_submit_push_promise(session_, NGHTTP2_FLAG_NONE,
                                   stream.get_stream_id(), nva.data(),
                                   nva.size(), nullptr);

  if (rv < 0) {
    return -1;
  }

  auto promised_stream = create_stream(rv);
  auto &promised_req = promised_stream->get_request()->impl();
  promised_req.pushed(true);
  promised_req.method(std::move(method));
  promised_req.scheme(req.scheme());
  promised_req.authority(req.authority());
  promised_req.path(std::move(path));
  promised_req.host(req.host());
  promised_req.set_header(std::move(headers));
  if (!req.host().empty()) {
    promised_req.add_header("host", req.host());
  }

  return 0;
}

bool http2_handler::run_task(thread_cb start) {
  auto strand = strand_;

  try {
    task_io_service_.post([start, strand]() {
      channel chan;
      chan.impl().strand(strand.get());

      start(chan);
    });

    return true;
  } catch (std::exception &ex) {
    return false;
  }
}

boost::asio::io_service &http2_handler::io_service() { return io_service_; }

callback_guard::callback_guard(http2_handler &h) : handler(h) {
  handler.enter_callback();
}

callback_guard::~callback_guard() { handler.leave_callback(); }

} // namespace server

} // namespace asio_http2

} // namespace nghttp2
