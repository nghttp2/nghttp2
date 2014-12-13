// Vivek Trehan
// Layer Inc.
// December 6, 2014


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
// We wrote this code based on the original code which has the
// following license:
//
// client.cpp
// ~~~~~~~~~~
//
// Copyright (c) 2003-2012 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <algorithm>

#include <cstdlib>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/deadline_timer.hpp>

#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include "http-parser/http_parser.h"
#include "util.h"
#include "ssl.h"

#include <nghttp2/nghttp2.h>
#include <nghttp2/asio_http2.h>
#include <asio-client.h>

using namespace nghttp2::asio_http2;
using namespace asio_http2_test_client;

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE, VALUELEN)                                         \
{                                                                            \
(uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN,            \
NGHTTP2_NV_FLAG_NONE                                                   \
}

/* nghttp2_send_callback. Here we transmit the |data|, |length| bytes,
 to the network. Because we are using libevent bufferevent, we just
 write those bytes into bufferevent buffer. */
static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                      size_t length, int flags, void *user_data)
{
  Http2Connection *connection = (Http2Connection *) user_data;
  connection->write(data, length);
  return length;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
 single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
                       const nghttp2_frame *frame, const uint8_t *name,
                       size_t namelen, const uint8_t *value,
                       size_t valuelen, uint8_t flags _U_,
                       void *user_data)
{
  Http2Connection *connection = (Http2Connection *) user_data;
  
  switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
      if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
          connection->stream()->stream_id() == frame->hd.stream_id) {
        /* Print response headers for the initiated request. */
        std::cerr << name << ": " << value << std::endl;
        break;
      }
  }
  return 0;
}

/* nghttp2_on_begin_headers_callback: Called when nghttp2 library gets
 started to receive header block. */
static int on_begin_headers_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              void *user_data)
{
  Http2Connection *connection = (Http2Connection *) user_data;
  switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
      if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
          connection->stream()->stream_id() == frame->hd.stream_id) {
        std::cerr << "Response headers for stream ID=%d:\n" << frame->hd.stream_id << std::endl;
      }
      break;
  }
  return 0;
}

/* nghttp2_on_frame_recv_callback: Called when nghttp2 library
 received a complete frame from the remote peer. */
static int on_frame_recv_callback(nghttp2_session *session _U_,
                           const nghttp2_frame *frame, void *user_data)
{
  Http2Connection *connection = (Http2Connection *) user_data;
  switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
      if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
          connection->stream()->stream_id() == frame->hd.stream_id) {
        std::cerr << "All headers received" << std::endl;
      }
      break;
  }
  return 0;
}

/* nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
 received from the remote peer. In this implementation, if the frame
 is meant to the stream we initiated, print the received data in
 stdout, so that the user can redirect its output to the file
 easily. */
static int on_data_chunk_recv_callback(nghttp2_session *session _U_,
                                uint8_t flags _U_, int32_t stream_id,
                                const uint8_t *data, size_t len,
                                void *user_data)
{
  Http2Connection *connection = (Http2Connection *) user_data;
  
  if (connection->stream()->stream_id() == stream_id) {
    std::cout.write((const char*)data, len);
  }
  
  return 0;
}

/* nghttp2_on_stream_close_callback: Called when a stream is about to
 closed. This example program only deals with 1 HTTP request (1
 stream), if it is closed, we send GOAWAY and tear down the
 session */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                             uint32_t error_code,
                             void *user_data)
{
  int rv;
  Http2Connection *connection = (Http2Connection *) user_data;
  
  if (connection->stream()->stream_id() == stream_id) {
    std::cerr << "Stream " << stream_id << " closed with error: " << error_code << std::endl;
    
    connection->nghttp2_stream_closed(stream_id);
    rv = nghttp2_session_terminate_session(connection->session(), NGHTTP2_NO_ERROR);
    if (rv != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}


namespace asio_http2_test_client {
  
//******************************************************************************************
void Http2Client::connect(std::string uri)
{
  connection_ = std::make_shared<Http2Connection>(shared_from_this(), uri);
}

void Http2Client::on_connect()
{
  connection_->send_request("GET");
}

//******************************************************************************************
Http2Stream::Http2Stream(const char *uri)
{
  uri_ = uri;
  stream_id_ = -1;
  
  struct http_parser_url u;
  int rv = http_parser_parse_url(uri_.c_str(), uri_.length(), 0, &u);
  if (rv != 0) {
    std::cerr << "Could not parse URI " << uri_ << std::endl;
    return;
  }
  
  authority_ = &uri[u.field_data[UF_HOST].off];
  authority_.resize(u.field_data[UF_HOST].len);
  
  host_ = authority_;
  
  if (u.field_set & (1 << UF_PORT)) {
    std::ostringstream oss;
    oss << u.port;
    port_ = oss.str();
    
    authority_.append(port_);
  }
  else {
    port_ = "443";
  }
  
  size_t pathlen = 0;
  path_ = "";
  if (u.field_set & (1 << UF_PATH)) {
    pathlen = u.field_data[UF_PATH].len;
  }
  if (u.field_set & (1 << UF_QUERY)) {
    // +1 for '?' character
    pathlen += u.field_data[UF_QUERY].len + 1;
  }
  
  if (pathlen > 0) {
    if (u.field_set & (1 << UF_PATH)) {
      path_ = &uri[u.field_data[UF_PATH].off];
      path_.resize(u.field_data[UF_PATH].len);
    }
    
    if (u.field_set & (1 << UF_QUERY)) {
      std::string query = &uri[u.field_data[UF_QUERY].off];
      query.resize(u.field_data[UF_QUERY].len);
      path_.append(query);
    }
  }
  
  scheme_ = &uri[u.field_data[UF_SCHEMA].off];
  scheme_.resize(u.field_data[UF_SCHEMA].len);
}

void Http2Stream::set_stream_id(int32_t stream_id)
{
  stream_id_ = stream_id;
}

//******************************************************************************************

Http2Connection::Http2Connection(std::shared_ptr<Http2Client> client, std::string uri):
client_(client),
strand_(*(client->io_service().get())),
read_timer_(*(client->io_service().get())),
outbox_(),
inbox_(),
state_(kConnectionStateNotConnected)
{
  socket_ = std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket> >(*(client->io_service().get()), *(client->ssl_ctx().get()));
  stream_ = std::make_shared<Http2Stream>(uri.c_str());
  session_ = NULL;
  inbox_.resize(1024);
  
  boost::asio::ip::tcp::resolver resolver(*(client->io_service().get()));
  boost::asio::ip::tcp::resolver::query query(stream_->host(), stream_->port());
  boost::asio::ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
  
  socket_->set_verify_mode(boost::asio::ssl::verify_peer);
  socket_->set_verify_callback(boost::bind(&Http2Connection::verify_certificate, this, _1, _2));
  
  boost::asio::async_connect(socket_->lowest_layer(), endpoint_iterator,
                             boost::bind(&Http2Connection::handle_connect, this,
                                         boost::asio::placeholders::error));
  
}

Http2Connection::~Http2Connection()
{
  if(state_ != kConnectionStateNotConnected) {
    end();
  }
}

void Http2Connection::send_request(std::string method_name)
{
  std::string uri = stream()->uri();
  
  nghttp2_nv hdrs[] = {
    MAKE_NV(":method", method_name.c_str(), method_name.length()),
    MAKE_NV(":scheme", stream()->scheme().c_str(), stream()->scheme().length()),
    MAKE_NV(":authority", stream()->authority().c_str(), stream()->authority().length()),
    MAKE_NV(":path", stream()->path().c_str(), stream()->path().length())};
  
  int32_t stream_id = nghttp2_submit_request(session(), NULL, hdrs,
                                             ARRLEN(hdrs), NULL, stream().get());
  if (stream_id < 0) {
    std::cerr << "Could not submit HTTP2 request: "<< nghttp2_strerror(stream_id) << std::endl;
  }
  
  stream()->set_stream_id(stream_id);
  
  int rv = nghttp2_session_send(session());
  if (rv != 0) {
    std::cerr << "Fatal error: " << nghttp2_strerror(rv) << std::endl;
    end();
  }
}

void Http2Connection::write(const uint8_t *data, size_t length)
{
  uint8_t *to_send = (uint8_t*)malloc(length);
  memcpy(to_send, data, length);
  strand_.post(boost::bind(&Http2Connection::queue_write, this,
                           to_send, length));
}

void Http2Connection::nghttp2_stream_closed(int32_t stream_id)
{
  state_ = kConnectionStateTerminationPending;
}

void Http2Connection::end()
{
  boost::system::error_code ec;
  socket_->shutdown(ec);
  
  if (ec)
  {
    std::cerr << "error closing socket " << ec.message() << std::endl;
  }
  state_ = kConnectionStateNotConnected;
  
  if(session_) {
    nghttp2_session_del(session_);
  }
}

bool Http2Connection::verify_certificate(bool preverified,
                        boost::asio::ssl::verify_context& ctx)
{
  std::cerr << "verify_certificate " << preverified << std::endl;
  // The verify callback can be used to check whether the certificate that is
  // being presented is valid for the peer. For example, RFC 2818 describes
  // the steps involved in doing this for HTTPS. Consult the OpenSSL
  // documentation for more details. Note that the callback is called once
  // for each certificate in the certificate chain, starting from the root
  // certificate authority.
  
  // In this example we will simply print the certificate's subject name.
  char subject_name[256];
  X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
  X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
  std::cerr << "Verifying " << subject_name << std::endl;

  return true;
}

void Http2Connection::handle_connect(const boost::system::error_code& error)
{
  if (!error)
  {
    state_ = kConnectionStateConnected;

    socket_->async_handshake(boost::asio::ssl::stream_base::client,
                             boost::bind(&Http2Connection::handle_handshake, this,
                                         boost::asio::placeholders::error));
    initialize_nghttp2_session();
  }
  else
  {
    std::cerr << "Connect failed: " << error.message() << std::endl;
  }
}

void Http2Connection::handle_handshake(const boost::system::error_code& error)
{
  if (!error)
  {
    boost::asio::ip::tcp::no_delay option(true);
    socket_->next_layer().set_option(option);
    
    write((const uint8_t *)NGHTTP2_CLIENT_CONNECTION_PREFACE, NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN);
    
    nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, iv,
                            ARRLEN(iv));
    
    client_->on_connect();
  }
  else
  {
    std::cerr << "Handshake failed: " << error.message() << std::endl;
  }
}

void Http2Connection::queue_write(uint8_t *to_send, size_t length)
{
  bool canWrite = outbox_.empty();
  
  std::copy(&to_send[0], &to_send[length], back_inserter(outbox_));
  free(to_send);
  
  if (canWrite) {
    perform_write();
  }
}

void Http2Connection::perform_write()
{
  boost::asio::async_write(*(socket_.get()),
                           boost::asio::buffer(&outbox_[0], outbox_.size()),
                           strand_.wrap(boost::bind(
                                                    &Http2Connection::handle_write,
                                                    this,
                                                    boost::asio::placeholders::error,
                                                    boost::asio::placeholders::bytes_transferred
                                                    )));
}

void Http2Connection::perform_read()
{
  if (!outbox_.empty()) {
    return;
  }
  
  socket()->async_read_some(boost::asio::buffer(&inbox_[0], inbox_.size()),
                            boost::bind(&Http2Connection::handle_read, this,
                                        boost::asio::placeholders::error,
                                        boost::asio::placeholders::bytes_transferred));

  read_timer_.expires_from_now(boost::posix_time::seconds(5));
  read_timer_.async_wait(boost::bind(&Http2Connection::handle_read_timeout, this, boost::asio::placeholders::error));
}

void Http2Connection::handle_write(const boost::system::error_code& error,
                  const size_t bytes_transferred)
{
  outbox_.erase(outbox_.begin(), outbox_.begin()+bytes_transferred);
  
  if (error) {
    std::cerr << "could not write: " << boost::system::system_error(error).what() << std::endl;
    return;
  }
  
  if (!outbox_.empty()) {
    // more messages to send
    perform_write();
  }
  else if (state_ == kConnectionStateTerminationPending) {
    end();
  }
  else {
    perform_read();
  }
}


void Http2Connection::handle_read(const boost::system::error_code& error,
                 size_t bytes_transferred)
{
  read_timer_.cancel();

  if (!error && bytes_transferred)
  {
    int64_t readlen = nghttp2_session_mem_recv(session(), &inbox_[0], bytes_transferred);
    if (readlen < 0) {
      std::cerr << "Fatal error: " <<  nghttp2_strerror((int)readlen) << std::endl;
      end();
      return;
    }
    
    int rv = nghttp2_session_send(session());
    if (rv != 0) {
      std::cerr << "Fatal error: " << nghttp2_strerror(rv) << std::endl;
      end();
      return;
    }
    
    strand_.post(boost::bind(&Http2Connection::perform_read, this));
    
  }
  
  if (error) {
    std::cerr << "Read failed: " << error.message() << std::endl;
    end();
  }
  
}


void Http2Connection::handle_read_timeout(const boost::system::error_code &error)
{
  if (error) {
    return;
  }

  std::cerr << "Read timer expired" << std::endl;
  end();
}
                         

void Http2Connection::initialize_nghttp2_session()
{
  nghttp2_session_callbacks *callbacks;
  
  nghttp2_session_callbacks_new(&callbacks);
  
  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers_callback);
  
  nghttp2_session_client_new(&session_, callbacks, this);
  
  nghttp2_session_callbacks_del(callbacks);
}

} // namespace asio_http2_test_client
//******************************************************************************************

/* NPN TLS extension client callback. We check that server advertised
 the HTTP/2 protocol the nghttp2 library supports. If not, exit
 the program. */
static int select_next_proto_cb(SSL *ssl, unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
  
  if (nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
    std::cerr << "Server did not advertise " << NGHTTP2_PROTO_VERSION_ID;
  }
  return SSL_TLSEXT_ERR_OK;
}

// Create SSL_CTX.
static std::shared_ptr<boost::asio::ssl::context> create_ssl_ctx(void)
{
  std::shared_ptr<boost::asio::ssl::context> ssl_ctx = std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::sslv23);
  
  if (!ssl_ctx) {
    std::cerr << "Could not create SSL/TLS context" << std::endl;
  }
  auto ctx = ssl_ctx->native_handle();
  SSL_CTX_set_options(ctx,
                      SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                      SSL_OP_NO_COMPRESSION |
                      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
  
  SSL_CTX_set_next_proto_select_cb(ctx, select_next_proto_cb, NULL);
  SSL_CTX_set_cipher_list(ctx, nghttp2::ssl::DEFAULT_CIPHER_LIST);
  return ssl_ctx;
}

static void run(const char *uri)
{
  std::shared_ptr<boost::asio::io_service> io_service = std::make_shared<boost::asio::io_service>();
  std::shared_ptr<boost::asio::ssl::context> ssl_ctx = create_ssl_ctx();
  
  
  std::shared_ptr<Http2Client> client = std::make_shared<Http2Client>(io_service, ssl_ctx);
  
  client->connect(uri);
  
  io_service->run();
}

int main(int argc, char *argv[])
{
  try {
    struct sigaction act;
    
    if (argc < 2) {
      std::cerr << "Usage: asio-client HTTPS_URI" << std::endl;
      exit(EXIT_FAILURE);
    }
    
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);
    
    run(argv[1]);
    
  } catch (std::exception &e) {
    std::cerr << "exception: " << e.what() << "\n";
  }
  
  return 0;
}

