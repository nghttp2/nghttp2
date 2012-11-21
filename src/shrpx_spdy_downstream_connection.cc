/*
 * Spdylay - SPDY Library
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

#include <http-parser/http_parser.h>

#include "shrpx_client_handler.h"
#include "shrpx_upstream.h"
#include "shrpx_downstream.h"
#include "shrpx_config.h"
#include "shrpx_error.h"
#include "shrpx_http.h"
#include "shrpx_spdy_session.h"
#include "util.h"

using namespace spdylay;

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
  if(request_body_buf_) {
    evbuffer_free(request_body_buf_);
  }
  // TODO need RST_STREAM?
  spdy_->remove_downstream_connection(this);
  // Downstream and DownstreamConnection may be deleted
  // asynchronously.
  if(downstream_) {
    downstream_->set_downstream_connection(0);
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
  if(ENABLE_LOG) {
    LOG(INFO) << "Attaching downstream connection " << this << " to "
              << "downstream " << downstream;
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
  if(ENABLE_LOG) {
    LOG(INFO) << "Detaching spdy downstream connection " << this << " from "
              << "downstream " << downstream;
  }
  downstream->set_downstream_connection(0);
  downstream_ = 0;

  // TODO do something to SpdySession? RST_STREAM?

  client_handler_->pool_downstream_connection(this);
}

namespace {
ssize_t spdy_data_read_callback(spdylay_session *session,
                                int32_t stream_id,
                                uint8_t *buf, size_t length,
                                int *eof,
                                spdylay_data_source *source,
                                void *user_data)
{
  StreamData *sd;
  sd = reinterpret_cast<StreamData*>
    (spdylay_session_get_stream_user_data(session, stream_id));
  if(!sd || !sd->dconn) {
    return SPDYLAY_ERR_DEFERRED;
  }
  SpdyDownstreamConnection *dconn;
  dconn = reinterpret_cast<SpdyDownstreamConnection*>(source->ptr);
  Downstream *downstream = dconn->get_downstream();
  if(!downstream) {
    // In this case, RST_STREAM should have been issued. But depending
    // on the priority, DATA frame may come first.
    return SPDYLAY_ERR_DEFERRED;
  }
  evbuffer *body = dconn->get_request_body_buf();
  int nread = 0;
  for(;;) {
    nread = evbuffer_remove(body, buf, length);
    if(nread == 0) {
      if(downstream->get_request_state() == Downstream::MSG_COMPLETE) {
        *eof = 1;
        break;
      } else {
        if(downstream->get_upstream()->resume_read(SHRPX_NO_BUFFER) == -1) {
          // In this case, downstream may be deleted.
          return SPDYLAY_ERR_DEFERRED;
        }
        if(evbuffer_get_length(body) == 0) {
          return SPDYLAY_ERR_DEFERRED;
        }
      }
    } else {
      break;
    }
  }
  return nread;
}
} // namespace

namespace {
void copy_url_component(std::string& dest, http_parser_url *u, int field,
                        const char* url)
{
  if(u->field_set & (1 << field)) {
    dest.assign(url+u->field_data[field].off, u->field_data[field].len);
  }
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
  // 14 means :method, :scheme, :path, :version and possible via,
  // x-forwarded-for and x-forwarded-proto header fields. We rename
  // host header field as :host.
  const char **nv = new const char*[nheader * 2 + 14 + 1];
  size_t hdidx = 0;
  std::string via_value;
  std::string xff_value;
  std::string scheme, path, query;
  if(downstream_->get_request_method() != "CONNECT") {
    http_parser_url u;
    const char *url = downstream_->get_request_path().c_str();
    memset(&u, 0, sizeof(u));
    rv = http_parser_parse_url(url,
                               downstream_->get_request_path().size(),
                               0, &u);
    if(rv == 0) {
      copy_url_component(scheme, &u, UF_SCHEMA, url);
      copy_url_component(path, &u, UF_PATH, url);
      copy_url_component(query, &u, UF_QUERY, url);
      if(!query.empty()) {
        path += "?";
        path += query;
      }
    }
  }

  nv[hdidx++] = ":method";
  nv[hdidx++] = downstream_->get_request_method().c_str();
  nv[hdidx++] = ":scheme";
  if(scheme.empty()) {
    // Currently, the user of this downstream connecion is HTTP
    // only.
    nv[hdidx++] = "http";
  } else {
    nv[hdidx++] = scheme.c_str();
  }
  nv[hdidx++] = ":path";
  if(downstream_->get_request_method() == "CONNECT" || path.empty()) {
    nv[hdidx++] = downstream_->get_request_path().c_str();
  } else {
    nv[hdidx++] = path.c_str();
  }
  nv[hdidx++] = ":version";
  nv[hdidx++] = "HTTP/1.1";
  bool chunked_encoding = false;
  bool content_length = false;
  for(Headers::const_iterator i = downstream_->get_request_headers().begin();
      i != downstream_->get_request_headers().end(); ++i) {
    if(util::strieq((*i).first.c_str(), "transfer-encoding")) {
      if(util::strieq((*i).second.c_str(), "chunked")) {
        chunked_encoding = true;
      }
      // Ignore transfer-encoding
    } else if(util::strieq((*i).first.c_str(), "x-forwarded-proto") ||
              util::strieq((*i).first.c_str(), "keep-alive") ||
              util::strieq((*i).first.c_str(), "connection") ||
              util:: strieq((*i).first.c_str(), "proxy-connection")) {
      // These are ignored
    } else if(util::strieq((*i).first.c_str(), "via")) {
      via_value = (*i).second;
    } else if(util::strieq((*i).first.c_str(), "x-forwarded-for")) {
      xff_value = (*i).second;
    } else if(util::strieq((*i).first.c_str(), "expect") &&
       util::strifind((*i).second.c_str(), "100-continue")) {
      // Ignore
    } else if(util::strieq((*i).first.c_str(), "host")) {
      nv[hdidx++] = ":host";
      nv[hdidx++] = (*i).second.c_str();
    } else {
      if(util::strieq((*i).first.c_str(), "content-length")) {
        content_length = true;
      }
      nv[hdidx++] = (*i).first.c_str();
      nv[hdidx++] = (*i).second.c_str();
    }
  }

  if(get_config()->add_x_forwarded_for) {
    nv[hdidx++] = "x-forwarded-for";
    if(!xff_value.empty()) {
      xff_value += ", ";
    }
    xff_value += downstream_->get_upstream()->get_client_handler()->
      get_ipaddr();
    nv[hdidx++] = xff_value.c_str();
  } else if(!xff_value.empty()) {
    nv[hdidx++] = "x-forwarded-for";
    nv[hdidx++] = xff_value.c_str();
  }
  if(downstream_->get_request_method() != "CONNECT") {
    // Currently, HTTP connection is used as upstream, so we just
    // specify it here.
    nv[hdidx++] = "x-forwarded-proto";
    nv[hdidx++] = "http";
  }

  if(!via_value.empty()) {
    via_value += ", ";
  }
  via_value += http::create_via_header_value(downstream_->get_request_major(),
                                             downstream_->get_request_minor());
  nv[hdidx++] = "via";
  nv[hdidx++] = via_value.c_str();
  nv[hdidx++] = 0;
  if(ENABLE_LOG) {
    std::stringstream ss;
    for(size_t i = 0; nv[i]; i += 2) {
      ss << nv[i] << ": " << nv[i+1] << "\n";
    }
    LOG(INFO) << "Downstream spdy request headers id="
              << downstream_->get_stream_id() << "\n"
              << ss.str();
  }

  if(downstream_->get_request_method() == "CONNECT" ||
     chunked_encoding || content_length) {
    // Request-body is expected.
    spdylay_data_provider data_prd;
    data_prd.source.ptr = this;
    data_prd.read_callback = spdy_data_read_callback;
    rv = spdy_->submit_request(this, 0, nv, &data_prd);
  } else {
    rv = spdy_->submit_request(this, 0, nv, 0);
  }
  delete [] nv;
  if(rv != 0) {
    LOG(FATAL) << "spdylay_submit_request() failed";
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
    LOG(FATAL) << "evbuffer_add() failed";
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

int SpdyDownstreamConnection::on_read()
{
  return 0;
}

int SpdyDownstreamConnection::on_write()
{
  return 0;
}

int SpdyDownstreamConnection::on_upstream_write()
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

evbuffer* SpdyDownstreamConnection::get_request_body_buf() const
{
  return request_body_buf_;
}

void SpdyDownstreamConnection::attach_stream_data(StreamData *sd)
{
  assert(sd_ == 0 && sd->dconn == 0);
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
