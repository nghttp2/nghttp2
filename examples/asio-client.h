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

#ifndef NGHTTP2_ASIO_CLIENT_H
#define NGHTTP2_ASIO_CLIENT_H


namespace asio_http2_test_client {
  
class Http2Connection;
class Http2Client : public std::enable_shared_from_this<Http2Client>
{
public:
  Http2Client(std::shared_ptr<boost::asio::io_service> io_service,
              std::shared_ptr<boost::asio::ssl::context> context)
  : io_service_(io_service), ssl_ctx_(context)
  {}
  
  std::shared_ptr<boost::asio::io_service> io_service() { return io_service_; }
  std::shared_ptr<boost::asio::ssl::context> ssl_ctx() const { return ssl_ctx_; }
  
  void connect(std::string uri);
  void on_connect();
  
private:
  std::shared_ptr<Http2Connection> connection_;
  std::shared_ptr<boost::asio::io_service> io_service_;
  std::shared_ptr<boost::asio::ssl::context> ssl_ctx_;
};

  
class Http2Stream {
  
public:
  Http2Stream(const char *uri);
  std::string uri() const { return uri_; }
  std::string host() const { return host_; }
  std::string port() const { return port_; }
  
  std::string authority() const { return authority_; }
  std::string path() const { return path_; }
  std::string scheme() const { return scheme_; }
  int32_t stream_id() const { return stream_id_; }
  
  void set_stream_id(int32_t stream_id);
private:
  std::string uri_;
  std::string authority_;
  std::string path_;
  
  std::string host_;
  std::string port_;
  
  std::string scheme_;
  int32_t stream_id_;
};


class Http2Connection
{
public:
  enum ConnectionState {
    kConnectionStateNotConnected,
    kConnectionStateConnected,
    kConnectionStateTerminationPending
  };
  
public:
  Http2Connection(std::shared_ptr<Http2Client> client, std::string uri);
  ~Http2Connection();
  
  void send_request(std::string method_name);
  void write(const uint8_t *data, size_t length);
  
  
  std::shared_ptr<Http2Stream> stream() const { return stream_; }
  nghttp2_session *session() { return session_; }
  void nghttp2_stream_closed(int32_t stream_id);
  
private:
  void end();
  
  bool verify_certificate(bool preverified,
                          boost::asio::ssl::verify_context& ctx);
  void handle_connect(const boost::system::error_code& error);
  
  void handle_handshake(const boost::system::error_code& error);
  
  
  void queue_write(uint8_t *data, size_t length);
  void perform_write();
  void perform_read();
  
  void handle_write(const boost::system::error_code& error,
                    const size_t bytes_transferred);
  void handle_read(const boost::system::error_code& error,
                   size_t bytes_transferred);
  void handle_read_timeout(const boost::system::error_code &error);
  
  void initialize_nghttp2_session();
  std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket> > socket() { return socket_; }
  
  
  std::shared_ptr<Http2Client> client_;
  boost::asio::io_service::strand strand_;
  
  std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket> > socket_;
  std::shared_ptr<Http2Stream> stream_;
  boost::asio::deadline_timer read_timer_;
  
  std::vector<uint8_t> outbox_;
  std::vector<uint8_t> inbox_;
  nghttp2_session *session_;
  
  ConnectionState state_;
};
  
}// namespace asio_http2_test_client

#endif
