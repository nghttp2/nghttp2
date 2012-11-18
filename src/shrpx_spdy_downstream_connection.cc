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

#include "shrpx_client_handler.h"
#include "shrpx_upstream.h"
#include "shrpx_downstream.h"
#include "shrpx_config.h"
#include "shrpx_error.h"
#include "shrpx_http.h"
#include "util.h"

using namespace spdylay;

namespace shrpx {

SpdyDownstreamConnection::SpdyDownstreamConnection
(ClientHandler *client_handler)
  : DownstreamConnection(client_handler),
    ssl_(0),
    session_(0),
    request_body_buf_(0)
{}

SpdyDownstreamConnection::~SpdyDownstreamConnection()
{
  spdylay_session_del(session_);
  int fd = -1;
  if(ssl_) {
    fd = SSL_get_fd(ssl_);
    SSL_shutdown(ssl_);
  }
  if(bev_) {
    // We want to deallocate bev_ between SSL_shutdown and
    // SSL_free. This might not be necessary for recent libevent.
    bufferevent_disable(bev_, EV_READ | EV_WRITE);
    bufferevent_free(bev_);
    bev_ = 0;
  }
  if(ssl_) {
    SSL_free(ssl_);
  }
  if(fd != -1) {
    shutdown(fd, SHUT_WR);
    close(fd);
  }
  if(request_body_buf_) {
    evbuffer_free(request_body_buf_);
  }
}

namespace {
void body_buf_cb(evbuffer *body, size_t oldlen, size_t newlen, void *arg)
{
  SpdyDownstreamConnection *dconn;
  dconn = reinterpret_cast<SpdyDownstreamConnection*>(arg);
  if(newlen == 0) {
    Downstream *downstream = dconn->get_downstream();
    if(downstream) {
      downstream->get_upstream()->resume_read(SHRPX_NO_BUFFER);
    }
  }
}
} // namespace

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
    evbuffer_setcb(request_body_buf_, body_buf_cb, this);
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
  Upstream *upstream = downstream->get_upstream();
  if(!bev_) {
    event_base *evbase = client_handler_->get_evbase();
    ssl_ = SSL_new(client_handler_->get_ssl_client_ctx());
    if(!ssl_) {
      LOG(ERROR) << "SSL_new() failed: "
                 << ERR_error_string(ERR_get_error(), NULL);
      return -1;
    }
    bev_ = bufferevent_openssl_socket_new(evbase, -1, ssl_,
                                          BUFFEREVENT_SSL_CONNECTING,
                                          BEV_OPT_DEFER_CALLBACKS);
    int rv = bufferevent_socket_connect
      (bev_,
       // TODO maybe not thread-safe?
       const_cast<sockaddr*>(&get_config()->downstream_addr.sa),
       get_config()->downstream_addrlen);
    if(rv != 0) {
      bufferevent_free(bev_);
      bev_ = 0;
      return SHRPX_ERR_NETWORK;
    }
    if(ENABLE_LOG) {
      LOG(INFO) << "Connecting to downstream server " << this;
    }
  }
  downstream->set_downstream_connection(this);
  downstream_ = downstream;
  bufferevent_setwatermark(bev_, EV_READ, 0, SHRPX_READ_WARTER_MARK);
  bufferevent_enable(bev_, EV_READ);
  bufferevent_setcb(bev_,
                    upstream->get_downstream_readcb(),
                    upstream->get_downstream_writecb(),
                    upstream->get_downstream_eventcb(), this);

  bufferevent_set_timeouts(bev_,
                           &get_config()->downstream_read_timeout,
                           &get_config()->downstream_write_timeout);
  return 0;
}

namespace {
ssize_t spdy_data_read_callback(spdylay_session *session,
                                int32_t stream_id,
                                uint8_t *buf, size_t length,
                                int *eof,
                                spdylay_data_source *source,
                                void *user_data)
{
  SpdyDownstreamConnection *dconn;
  dconn = reinterpret_cast<SpdyDownstreamConnection*>(source->ptr);
  Downstream *downstream = dconn->get_downstream();
  if(!downstream) {
    // In this case, RST_STREAM should have been issued. But depending
    // on the priority, DATA frame may come first.
    return SPDYLAY_ERR_DEFERRED;
  }
  evbuffer *body = dconn->get_request_body_buf();
  int nread = evbuffer_remove(body, buf, length);
  if(nread == 0 &&
     downstream->get_request_state() == Downstream::MSG_COMPLETE) {
    *eof = 1;
  }
  if(nread == 0 && *eof != 1) {
    return SPDYLAY_ERR_DEFERRED;
  }
  return nread;
}
} // namespace

int SpdyDownstreamConnection::push_request_headers()
{
  int rv;
  if(!session_) {
    // If the connection to the backend has not been established,
    // session_ is not initialized. This function will be called again
    // just after SSL/TLS handshake is done.
    return 0;
  }
  if(!downstream_) {
    return 0;
  }
  size_t nheader = downstream_->get_request_headers().size();
  // 10 means :method, :scheme, :path, :version and possible via
  // header field. We rename host header field as :host.
  const char **nv = new const char*[nheader * 2 + 10 + 1];
  size_t hdidx = 0;
  std::string via_value;
  nv[hdidx++] = ":method";
  nv[hdidx++] = downstream_->get_request_method().c_str();
  nv[hdidx++] = ":scheme";
  nv[hdidx++] = "https";
  nv[hdidx++] = ":path";
  nv[hdidx++] = downstream_->get_request_path().c_str();
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
    } else if(util::strieq((*i).first.c_str(), "keep-alive") || // HTTP/1.0?
              util::strieq((*i).first.c_str(), "connection") ||
              util:: strieq((*i).first.c_str(), "proxy-connection")) {
      // These are ignored
    } else if(util::strieq((*i).first.c_str(), "via")) {
      via_value = (*i).second;
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

  if(chunked_encoding || content_length) {
    // Request-body is expected.
    spdylay_data_provider data_prd;
    data_prd.source.ptr = this;
    data_prd.read_callback = spdy_data_read_callback;
    rv = spdylay_submit_request(session_, 0, nv, &data_prd, 0);
  } else {
    rv = spdylay_submit_request(session_, 0, nv, 0, 0);
  }
  delete [] nv;
  if(rv != 0) {
    LOG(FATAL) << "spdylay_submit_request() failed";
    return -1;
  }
  return send();
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
    spdylay_session_resume_data(session_,
                                downstream_->get_downstream_stream_id());
  }
  size_t bodylen = evbuffer_get_length(request_body_buf_);
  if(bodylen > Downstream::DOWNSTREAM_OUTPUT_UPPER_THRES) {
    downstream_->get_upstream()->pause_read(SHRPX_NO_BUFFER);
  }
  return 0;
}

int SpdyDownstreamConnection::end_upload_data()
{
  if(downstream_->get_downstream_stream_id() != -1) {
    spdylay_session_resume_data(session_,
                                downstream_->get_downstream_stream_id());
  }
  return 0;
}

namespace {
ssize_t send_callback(spdylay_session *session,
                      const uint8_t *data, size_t len, int flags,
                      void *user_data)
{
  int rv;
  SpdyDownstreamConnection *dconn;
  dconn = reinterpret_cast<SpdyDownstreamConnection*>(user_data);

  bufferevent *bev = dconn->get_bev();
  evbuffer *output = bufferevent_get_output(bev);
  // Check buffer length and return WOULDBLOCK if it is large enough.
  if(evbuffer_get_length(output) > Downstream::DOWNSTREAM_OUTPUT_UPPER_THRES) {
    return SPDYLAY_ERR_WOULDBLOCK;
  }

  rv = evbuffer_add(output, data, len);
  if(rv == -1) {
    LOG(FATAL) << "evbuffer_add() failed";
    return SPDYLAY_ERR_CALLBACK_FAILURE;
  } else {
    return len;
  }
}
} // namespace

namespace {
ssize_t recv_callback(spdylay_session *session,
                      uint8_t *data, size_t len, int flags, void *user_data)
{
  SpdyDownstreamConnection *dconn;
  dconn = reinterpret_cast<SpdyDownstreamConnection*>(user_data);

  bufferevent *bev = dconn->get_bev();
  evbuffer *input = bufferevent_get_input(bev);
  int nread = evbuffer_remove(input, data, len);
  if(nread == -1) {
    return SPDYLAY_ERR_CALLBACK_FAILURE;
  } else if(nread == 0) {
    return SPDYLAY_ERR_WOULDBLOCK;
  } else {
    return nread;
  }
}
} // namespace

namespace {
void on_stream_close_callback
(spdylay_session *session, int32_t stream_id, spdylay_status_code status_code,
 void *user_data)
{
  int rv;
  if(ENABLE_LOG) {
    LOG(INFO) << "Downstream spdy Stream " << stream_id << " is being closed";
  }
  SpdyDownstreamConnection *dconn;
  dconn = reinterpret_cast<SpdyDownstreamConnection*>(user_data);
  Downstream *downstream = dconn->get_downstream();
  if(!downstream || downstream->get_downstream_stream_id() != stream_id) {
    // We might get this close callback when pushed streams are
    // closed.
    return;
  }
  downstream->set_response_state(Downstream::MSG_COMPLETE);
  rv = downstream->get_upstream()->on_downstream_body_complete(downstream);
  if(rv != 0) {
    downstream->set_response_state(Downstream::MSG_RESET);
    return;
  }
}
} // namespace

namespace {
void on_ctrl_recv_callback
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  int rv;
  SpdyDownstreamConnection *dconn;
  dconn = reinterpret_cast<SpdyDownstreamConnection*>(user_data);
  Downstream *downstream = dconn->get_downstream();
  switch(type) {
  case SPDYLAY_SYN_STREAM:
    if(ENABLE_LOG) {
      LOG(INFO) << "Downstream spdy received upstream SYN_STREAM stream_id="
                << frame->syn_stream.stream_id;
    }
    // We just respond pushed stream with RST_STREAM.
    spdylay_submit_rst_stream(session, frame->syn_stream.stream_id,
                              SPDYLAY_REFUSED_STREAM);
    break;
  case SPDYLAY_RST_STREAM:
    if(downstream &&
       downstream->get_downstream_stream_id() == frame->rst_stream.stream_id) {
      // If we got RST_STREAM, just flag MSG_RESET to indicate
      // upstream connection must be terminated.
      downstream->set_response_state(Downstream::MSG_RESET);
    }
    break;
  case SPDYLAY_SYN_REPLY: {
    if(!downstream ||
       downstream->get_downstream_stream_id() != frame->syn_reply.stream_id) {
      break;
    }
    char **nv = frame->syn_reply.nv;
    const char *status = 0;
    const char *version = 0;
    const char *content_length = 0;
    for(size_t i = 0; nv[i]; i += 2) {
      if(strcmp(nv[i], ":status") == 0) {
        unsigned int code = strtoul(nv[i+1], 0, 10);
        downstream->set_response_http_status(code);
        status = nv[i+1];
      } else if(strcmp(nv[i], ":version") == 0) {
        // We assume for now that most version is HTTP/1.1 from
        // SPDY. So just check if it is HTTP/1.0 and then set response
        // minor as so.
        downstream->set_response_major(1);
        if(util::strieq(nv[i+1], "HTTP/1.0")) {
          downstream->set_response_minor(0);
        } else {
          downstream->set_response_minor(1);
        }
        version = nv[i+1];
      } else if(nv[i][0] != ':') {
        if(strcmp(nv[i], "content-length") == 0) {
          content_length = nv[i+1];
        }
        downstream->add_response_header(nv[i], nv[i+1]);
      }
    }
    if(!status || !version) {
      spdylay_submit_rst_stream(session, frame->syn_reply.stream_id,
                                SPDYLAY_PROTOCOL_ERROR);
      downstream->set_response_state(Downstream::MSG_RESET);
      return;
    }

    if(!content_length && downstream->get_request_method() != "HEAD") {
      unsigned int status;
      status = downstream->get_response_http_status();
      if(!((100 <= status && status <= 199) || status == 204 ||
           status == 304)) {
        // In SPDY, we are supporsed not to receive
        // transfer-encoding.
        downstream->add_response_header("transfer-encoding", "chunked");
      }
    }

    if(ENABLE_LOG) {
      std::stringstream ss;
      for(size_t i = 0; nv[i]; i += 2) {
        ss << nv[i] << ": " << nv[i+1] << "\n";
      }
      LOG(INFO) << "Downstream spdy response headers id="
                << frame->syn_reply.stream_id
                << "\n" << ss.str();
    }

    Upstream *upstream = downstream->get_upstream();
    downstream->set_response_state(Downstream::HEADER_COMPLETE);
    rv = upstream->on_downstream_header_complete(downstream);
    if(rv != 0) {
      spdylay_submit_rst_stream(session, frame->syn_reply.stream_id,
                                SPDYLAY_PROTOCOL_ERROR);
      downstream->set_response_state(Downstream::MSG_RESET);
      return;
    }
    break;
  }
  default:
    break;
  }
}
} // namespace

namespace {
void on_data_chunk_recv_callback(spdylay_session *session,
                                 uint8_t flags, int32_t stream_id,
                                 const uint8_t *data, size_t len,
                                 void *user_data)
{
  int rv;
  SpdyDownstreamConnection *dconn;
  dconn = reinterpret_cast<SpdyDownstreamConnection*>(user_data);
  Downstream *downstream = dconn->get_downstream();
  if(!downstream || downstream->get_downstream_stream_id() != stream_id) {
    return;
  }
  // TODO No manual flow control at the moment.
  Upstream *upstream = downstream->get_upstream();
  rv = upstream->on_downstream_body(downstream, data, len);
  if(rv != 0) {
    spdylay_submit_rst_stream(session, stream_id, SPDYLAY_INTERNAL_ERROR);
    downstream->set_response_state(Downstream::MSG_RESET);
  }
}
} // namespace

namespace {
void before_ctrl_send_callback(spdylay_session *session,
                               spdylay_frame_type type,
                               spdylay_frame *frame,
                               void *user_data)
{
  if(type == SPDYLAY_SYN_STREAM) {
    SpdyDownstreamConnection *dconn;
    dconn = reinterpret_cast<SpdyDownstreamConnection*>(user_data);
    Downstream *downstream = dconn->get_downstream();
    if(downstream) {
      downstream->set_downstream_stream_id(frame->syn_stream.stream_id);
    }
  }
}
} // namespace

namespace {
void on_ctrl_not_send_callback(spdylay_session *session,
                               spdylay_frame_type type,
                               spdylay_frame *frame,
                               int error_code, void *user_data)
{
  LOG(WARNING) << "Failed to send control frame type=" << type << ", "
               << "error_code=" << error_code << ":"
               << spdylay_strerror(error_code);
  if(type == SPDYLAY_SYN_STREAM) {
    // To avoid stream hanging around, flag Downstream::MSG_RESET and
    // terminate the upstream and downstream connections.
    SpdyDownstreamConnection *dconn;
    dconn = reinterpret_cast<SpdyDownstreamConnection*>(user_data);
    Downstream *downstream = dconn->get_downstream();
    int32_t stream_id = frame->syn_stream.stream_id;
    if(!downstream || downstream->get_downstream_stream_id() != stream_id) {
      return;
    }
    downstream->set_response_state(Downstream::MSG_RESET);
  }
}
} // namespace

namespace {
void on_ctrl_recv_parse_error_callback(spdylay_session *session,
                                       spdylay_frame_type type,
                                       const uint8_t *head, size_t headlen,
                                       const uint8_t *payload,
                                       size_t payloadlen, int error_code,
                                       void *user_data)
{
  if(ENABLE_LOG) {
    LOG(INFO) << "Failed to parse received control frame. type=" << type
              << ", error_code=" << error_code << ":"
              << spdylay_strerror(error_code);
  }
}
} // namespace

namespace {
void on_unknown_ctrl_recv_callback(spdylay_session *session,
                                   const uint8_t *head, size_t headlen,
                                   const uint8_t *payload, size_t payloadlen,
                                   void *user_data)
{
  if(ENABLE_LOG) {
    LOG(INFO) << "Received unknown control frame.";
  }
}
} // namespace

int SpdyDownstreamConnection::on_connect()
{
  int rv;
  const unsigned char *next_proto = 0;
  unsigned int next_proto_len;
  SSL_get0_next_proto_negotiated(ssl_, &next_proto, &next_proto_len);

  if(ENABLE_LOG) {
    std::string proto(next_proto, next_proto+next_proto_len);
    LOG(INFO) << "Downstream negotiated next protocol: " << proto;
  }
  uint16_t version = spdylay_npn_get_version(next_proto, next_proto_len);
  if(!version) {
    return -1;
  }
  spdylay_session_callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = send_callback;
  callbacks.recv_callback = recv_callback;
  callbacks.on_stream_close_callback = on_stream_close_callback;
  callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback;
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks.before_ctrl_send_callback = before_ctrl_send_callback;
  callbacks.on_ctrl_not_send_callback = on_ctrl_not_send_callback;
  callbacks.on_ctrl_recv_parse_error_callback =
    on_ctrl_recv_parse_error_callback;
  callbacks.on_unknown_ctrl_recv_callback = on_unknown_ctrl_recv_callback;

  rv = spdylay_session_client_new(&session_, version, &callbacks, this);
  if(rv != 0) {
    return -1;
  }

  // TODO Send initial window size when manual flow control is
  // implemented.
  spdylay_settings_entry entry[1];
  entry[0].settings_id = SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS;
  entry[0].value = get_config()->spdy_max_concurrent_streams;
  entry[0].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;
  rv = spdylay_submit_settings
    (session_, SPDYLAY_FLAG_SETTINGS_NONE,
     entry, sizeof(entry)/sizeof(spdylay_settings_entry));
  if(rv != 0) {
    return -1;
  }
  rv = send();
  if(rv != 0) {
    return -1;
  }

  // We may have pending request
  push_request_headers();

  return 0;
}

int SpdyDownstreamConnection::on_read()
{
  int rv = 0;
  if((rv = spdylay_session_recv(session_)) < 0) {
    if(rv != SPDYLAY_ERR_EOF) {
      LOG(ERROR) << "spdylay_session_recv() returned error: "
                 << spdylay_strerror(rv);
    }
  } else if((rv = spdylay_session_send(session_)) < 0) {
    LOG(ERROR) << "spdylay_session_send() returned error: "
               << spdylay_strerror(rv);
  }
  // if(rv == 0) {
  //   if(spdylay_session_want_read(session_) == 0 &&
  //      spdylay_session_want_write(session_) == 0) {
  //     if(ENABLE_LOG) {
  //       LOG(INFO) << "No more read/write for this SPDY session";
  //     }
  //     rv = -1;
  //   }
  // }

  if(rv == SPDYLAY_ERR_EOF) {
    if(downstream_) {
      downstream_->set_response_connection_close(true);
    }
    rv = 0;
  } else if(rv != 0) {
    if(downstream_) {
      downstream_->set_response_state(Downstream::MSG_RESET);
    }
  }
  return rv;
}

int SpdyDownstreamConnection::on_write()
{
  return send();
}

int SpdyDownstreamConnection::send()
{
  int rv = 0;
  if((rv = spdylay_session_send(session_)) < 0) {
    LOG(ERROR) << "spdylay_session_send() returned error: "
               << spdylay_strerror(rv);
  }
  // if(rv == 0) {
  //   if(spdylay_session_want_read(session_) == 0 &&
  //      spdylay_session_want_write(session_) == 0) {
  //     if(ENABLE_LOG) {
  //       LOG(INFO) << "No more read/write for this SPDY session";
  //     }
  //     rv = -1;
  //   }
  // }
  return rv;
}

evbuffer* SpdyDownstreamConnection::get_request_body_buf() const
{
  return request_body_buf_;
}

} // namespace shrpx
