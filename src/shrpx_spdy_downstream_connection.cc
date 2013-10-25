/*
 * nghttp2 - HTTP/2.0 C Library
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
#include "shrpx_spdy_downstream_connection.h"

#include <unistd.h>

#include <openssl/err.h>

#include <event2/bufferevent_ssl.h>

#include "http-parser/http_parser.h"

#include "shrpx_client_handler.h"
#include "shrpx_upstream.h"
#include "shrpx_downstream.h"
#include "shrpx_config.h"
#include "shrpx_error.h"
#include "shrpx_http.h"
#include "shrpx_spdy_session.h"
#include "http2.h"
#include "util.h"

using namespace nghttp2;

namespace shrpx {

SpdyDownstreamConnection::SpdyDownstreamConnection
(ClientHandler *client_handler)
  : DownstreamConnection(client_handler),
    spdy_(client_handler->get_spdy_session()),
    request_body_buf_(0),
    sd_(0),
    recv_window_size_(0)
{}

SpdyDownstreamConnection::~SpdyDownstreamConnection()
{
  if(LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Deleting";
  }
  if(request_body_buf_) {
    evbuffer_free(request_body_buf_);
  }
  if(downstream_) {
    if(submit_rst_stream(downstream_) == 0) {
      spdy_->notify();
    }
  }
  spdy_->remove_downstream_connection(this);
  // Downstream and DownstreamConnection may be deleted
  // asynchronously.
  if(downstream_) {
    downstream_->set_downstream_connection(0);
  }
  if(LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Deleted";
  }
}

int SpdyDownstreamConnection::init_request_body_buf()
{
  int rv;
  if(request_body_buf_) {
    rv = evbuffer_drain(request_body_buf_,
                        evbuffer_get_length(request_body_buf_));
    if(rv != 0) {
      return -1;
    }
  } else {
    request_body_buf_ = evbuffer_new();
    if(request_body_buf_ == 0) {
      return -1;
    }
    evbuffer_setcb(request_body_buf_, 0, this);
  }
  return 0;
}

int SpdyDownstreamConnection::attach_downstream(Downstream *downstream)
{
  if(LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Attaching to DOWNSTREAM:" << downstream;
  }
  if(init_request_body_buf() == -1) {
    return -1;
  }
  spdy_->add_downstream_connection(this);
  if(spdy_->get_state() == SpdySession::DISCONNECTED) {
    spdy_->notify();
  }
  downstream->set_downstream_connection(this);
  downstream_ = downstream;
  recv_window_size_ = 0;
  return 0;
}

void SpdyDownstreamConnection::detach_downstream(Downstream *downstream)
{
  if(LOG_ENABLED(INFO)) {
    DCLOG(INFO, this) << "Detaching from DOWNSTREAM:" << downstream;
  }
  if(submit_rst_stream(downstream) == 0) {
    spdy_->notify();
  }
  downstream->set_downstream_connection(0);
  downstream_ = 0;

  client_handler_->pool_downstream_connection(this);
}

int SpdyDownstreamConnection::submit_rst_stream(Downstream *downstream)
{
  int rv = -1;
  if(spdy_->get_state() == SpdySession::CONNECTED &&
     downstream->get_downstream_stream_id() != -1) {
    switch(downstream->get_response_state()) {
    case Downstream::MSG_RESET:
    case Downstream::MSG_COMPLETE:
      break;
    default:
      if(LOG_ENABLED(INFO)) {
        DCLOG(INFO, this) << "Submit RST_STREAM for DOWNSTREAM:"
                          << downstream << ", stream_id="
                          << downstream->get_downstream_stream_id();
      }
      rv = spdy_->submit_rst_stream(downstream->get_downstream_stream_id(),
                                    NGHTTP2_INTERNAL_ERROR);
    }
  }
  return rv;
}

namespace {
ssize_t spdy_data_read_callback(nghttp2_session *session,
                                int32_t stream_id,
                                uint8_t *buf, size_t length,
                                int *eof,
                                nghttp2_data_source *source,
                                void *user_data)
{
  StreamData *sd;
  sd = reinterpret_cast<StreamData*>
    (nghttp2_session_get_stream_user_data(session, stream_id));
  if(!sd || !sd->dconn) {
    return NGHTTP2_ERR_DEFERRED;
  }
  SpdyDownstreamConnection *dconn;
  dconn = reinterpret_cast<SpdyDownstreamConnection*>(source->ptr);
  Downstream *downstream = dconn->get_downstream();
  if(!downstream) {
    // In this case, RST_STREAM should have been issued. But depending
    // on the priority, DATA frame may come first.
    return NGHTTP2_ERR_DEFERRED;
  }
  evbuffer *body = dconn->get_request_body_buf();
  int nread = 0;
  for(;;) {
    nread = evbuffer_remove(body, buf, length);
    if(nread == 0) {
      if(downstream->get_request_state() == Downstream::MSG_COMPLETE) {
        if(!downstream->get_upgrade_request() ||
           (downstream->get_response_state() == Downstream::HEADER_COMPLETE &&
            !downstream->get_upgraded())) {
          *eof = 1;
        } else {
          return NGHTTP2_ERR_DEFERRED;
        }
        break;
      } else {
        // This is important because it will handle flow control
        // stuff.
        if(downstream->get_upstream()->resume_read(SHRPX_NO_BUFFER,
                                                   downstream) == -1) {
          // In this case, downstream may be deleted.
          return NGHTTP2_ERR_DEFERRED;
        }
        // Check dconn is still alive because Upstream::resume_read()
        // may delete downstream which will delete dconn.
        if(sd->dconn == 0) {
          return NGHTTP2_ERR_DEFERRED;
        }
        if(evbuffer_get_length(body) == 0) {
          // Check get_request_state() == MSG_COMPLETE just in case
          if(downstream->get_request_state() == Downstream::MSG_COMPLETE) {
            *eof = 1;
            break;
          }
          return NGHTTP2_ERR_DEFERRED;
        }
      }
    } else {
      break;
    }
  }
  return nread;
}
} // namespace

int SpdyDownstreamConnection::push_request_headers()
{
  int rv;
  if(spdy_->get_state() != SpdySession::CONNECTED) {
    // The SPDY session to the backend has not been established.  This
    // function will be called again just after it is established.
    return 0;
  }
  if(!downstream_) {
    return 0;
  }
  size_t nheader = downstream_->get_request_headers().size();
  downstream_->normalize_request_headers();
  auto end_headers = std::end(downstream_->get_request_headers());
  // 12 means:
  // 1. :method
  // 2. :scheme
  // 3. :path
  // 4. :authority (optional)
  // 5. via (optional)
  // 6. x-forwarded-for (optional)
  auto nv = std::vector<const char*>();
  nv.reserve(nheader * 2 + 10 + 1);
  std::string via_value;
  std::string xff_value;
  std::string scheme, authority, path, query;
  if(downstream_->get_request_method() == "CONNECT") {
    // The upstream may be HTTP/2 or HTTP/1
    nv.push_back(":authority");
    if(!downstream_->get_request_http2_authority().empty()) {
      nv.push_back(downstream_->get_request_http2_authority().c_str());
    } else {
      nv.push_back(downstream_->get_request_path().c_str());
    }
  } else if(!downstream_->get_request_http2_scheme().empty()) {
    // Here the upstream is HTTP/2
    nv.push_back(":scheme");
    nv.push_back(downstream_->get_request_http2_scheme().c_str());
    nv.push_back(":path");
    nv.push_back(downstream_->get_request_path().c_str());
    if(!downstream_->get_request_http2_authority().empty()) {
      nv.push_back(":authority");
      nv.push_back(downstream_->get_request_http2_authority().c_str());
    } else if(downstream_->get_norm_request_header("host") == end_headers) {
      if(LOG_ENABLED(INFO)) {
        DCLOG(INFO, this) << "host header field missing";
      }
      return -1;
    }
  } else {
    // The upstream is HTTP/1
    http_parser_url u;
    const char *url = downstream_->get_request_path().c_str();
    memset(&u, 0, sizeof(u));
    rv = http_parser_parse_url(url,
                               downstream_->get_request_path().size(),
                               0, &u);
    if(rv == 0) {
      http2::copy_url_component(scheme, &u, UF_SCHEMA, url);
      http2::copy_url_component(authority, &u, UF_HOST, url);
      http2::copy_url_component(path, &u, UF_PATH, url);
      http2::copy_url_component(query, &u, UF_QUERY, url);
      if(path.empty()) {
        path = "/";
      }
      if(!query.empty()) {
        path += "?";
        path += query;
      }
    }
    nv.push_back(":scheme");
    if(scheme.empty()) {
      // The default scheme is http. For SPDY upstream, the path must
      // be absolute URI, so scheme should be provided.
      nv.push_back("http");
    } else {
      nv.push_back(scheme.c_str());
    }
    nv.push_back(":path");
    if(path.empty()) {
      nv.push_back(downstream_->get_request_path().c_str());
    } else {
      nv.push_back(path.c_str());
    }
    if(!authority.empty()) {
      // TODO properly check IPv6 numeric address
      if(authority.find(":") != std::string::npos) {
        authority = "[" + authority;
        authority += "]";
      }
      if(u.field_set & (1 << UF_PORT)) {
        authority += ":";
        authority += util::utos(u.port);
      }
      nv.push_back(":authority");
      nv.push_back(authority.c_str());
    } else if(downstream_->get_norm_request_header("host") == end_headers) {
      if(LOG_ENABLED(INFO)) {
        DCLOG(INFO, this) << "host header field missing";
      }
      return -1;
    }
  }

  nv.push_back(":method");
  nv.push_back(downstream_->get_request_method().c_str());

  http2::copy_norm_headers_to_nv(nv, downstream_->get_request_headers());

  bool content_length = false;
  if(downstream_->get_norm_request_header("content-length") != end_headers) {
    content_length = true;
  }

  auto expect = downstream_->get_norm_request_header("expect");
  if(expect != end_headers &&
     !util::strifind((*expect).second.c_str(), "100-continue")) {
    nv.push_back("expect");
    nv.push_back((*expect).second.c_str());
  }

  bool chunked_encoding = false;
  auto transfer_encoding =
    downstream_->get_norm_request_header("transfer-encoding");
  if(transfer_encoding != end_headers &&
     util::strieq((*transfer_encoding).second.c_str(), "chunked")) {
    chunked_encoding = true;
  }

  auto xff = downstream_->get_norm_request_header("x-forwarded-for");
  if(get_config()->add_x_forwarded_for) {
    nv.push_back("x-forwarded-for");
    if(xff != end_headers) {
      xff_value = (*xff).second;
      xff_value += ", ";
    }
    xff_value += downstream_->get_upstream()->get_client_handler()->
      get_ipaddr();
    nv.push_back(xff_value.c_str());
  } else if(xff != end_headers) {
    nv.push_back("x-forwarded-for");
    nv.push_back((*xff).second.c_str());
  }

  auto via = downstream_->get_norm_request_header("via");
  if(get_config()->no_via) {
    if(via != end_headers) {
      nv.push_back("via");
      nv.push_back((*via).second.c_str());
    }
  } else {
    if(via != end_headers) {
      via_value = (*via).second;
      via_value += ", ";
    }
    via_value += http::create_via_header_value
      (downstream_->get_request_major(), downstream_->get_request_minor());
    nv.push_back("via");
    nv.push_back(via_value.c_str());
  }
  nv.push_back(nullptr);

  if(LOG_ENABLED(INFO)) {
    std::stringstream ss;
    for(size_t i = 0; nv[i]; i += 2) {
      ss << TTY_HTTP_HD << nv[i] << TTY_RST << ": " << nv[i+1] << "\n";
    }
    DCLOG(INFO, this) << "HTTP request headers\n" << ss.str();
  }

  if(downstream_->get_request_method() == "CONNECT" ||
     chunked_encoding || content_length) {
    // Request-body is expected.
    nghttp2_data_provider data_prd;
    data_prd.source.ptr = this;
    data_prd.read_callback = spdy_data_read_callback;
    rv = spdy_->submit_request(this, 0, nv.data(), &data_prd);
  } else {
    rv = spdy_->submit_request(this, 0, nv.data(), nullptr);
  }
  if(rv != 0) {
    DCLOG(FATAL, this) << "nghttp2_submit_request() failed";
    return -1;
  }
  spdy_->notify();
  return 0;
}

int SpdyDownstreamConnection::push_upload_data_chunk(const uint8_t *data,
                                                     size_t datalen)
{
  int rv = evbuffer_add(request_body_buf_, data, datalen);
  if(rv != 0) {
    DCLOG(FATAL, this) << "evbuffer_add() failed";
    return -1;
  }
  if(downstream_->get_downstream_stream_id() != -1) {
    rv = spdy_->resume_data(this);
    if(rv != 0) {
      return -1;
    }
    spdy_->notify();
  }
  return 0;
}

int SpdyDownstreamConnection::end_upload_data()
{
  int rv;
  if(downstream_->get_downstream_stream_id() != -1) {
    rv = spdy_->resume_data(this);
    if(rv != 0) {
      return -1;
    }
    spdy_->notify();
  }
  return 0;
}

int SpdyDownstreamConnection::resume_read(IOCtrlReason reason)
{
  int rv;
  if(spdy_->get_state() == SpdySession::CONNECTED &&
     spdy_->get_flow_control() &&
     downstream_ && downstream_->get_downstream_stream_id() != -1 &&
     recv_window_size_ >= spdy_->get_initial_window_size()/2) {
    rv = spdy_->submit_window_update(this, recv_window_size_);
    if(rv == -1) {
      return -1;
    }
    spdy_->notify();
    recv_window_size_ = 0;
  }
  return 0;
}

int SpdyDownstreamConnection::on_read()
{
  return 0;
}

int SpdyDownstreamConnection::on_write()
{
  return 0;
}

evbuffer* SpdyDownstreamConnection::get_request_body_buf() const
{
  return request_body_buf_;
}

void SpdyDownstreamConnection::attach_stream_data(StreamData *sd)
{
  // It is possible sd->dconn is not NULL. sd is detached when
  // on_stream_close_callback. Before that, after MSG_COMPLETE is set
  // to Downstream::set_response_state(), upstream's readcb is called
  // and execution path eventually could reach here. Since the
  // response was already handled, we just detach sd.
  detach_stream_data();
  sd_ = sd;
  sd_->dconn = this;
}

StreamData* SpdyDownstreamConnection::detach_stream_data()
{
  if(sd_) {
    StreamData *sd = sd_;
    sd_ = 0;
    sd->dconn = 0;
    return sd;
  } else {
    return 0;
  }
}

bool SpdyDownstreamConnection::get_output_buffer_full()
{
  if(request_body_buf_) {
    return
      evbuffer_get_length(request_body_buf_) >= Downstream::OUTPUT_UPPER_THRES;
  } else {
    return false;
  }
}

int32_t SpdyDownstreamConnection::get_recv_window_size() const
{
  return recv_window_size_;
}

void SpdyDownstreamConnection::inc_recv_window_size(int32_t amount)
{
  recv_window_size_ += amount;
}

} // namespace shrpx
