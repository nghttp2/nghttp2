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
#ifndef SPDY_H
#define SPDY_H

#include "spdylay_config.h"

#include <signal.h>

#include <vector>
#include <string>
#include <functional>

#include "spdylay_ssl.h"
#include "uri.h"
#include "util.h"
#include "SpdyServer.h"

using namespace spdylay;

namespace spdylay {

class request {
public:
  request(const std::vector<std::pair<std::string, std::string>>& headers)
    : headers_(headers)
  {}

  const std::vector<std::pair<std::string, std::string>>& headers()
  {
    return headers_;
  }
private:
  std::vector<std::pair<std::string, std::string>> headers_;
};

class response {
public:
  response()
    : status_code_(200)
  {}

  void set_status(int status_code)
  {
    status_code_ = status_code;
  }

  const char* get_status_string() const
  {
    switch(status_code_) {
    case 100: return "100 Continue";
    case 101: return "101 Switching Protocols";
    case 200: return "200 OK";
    case 201: return "201 Created";
    case 202: return "202 Accepted";
    case 203: return "203 Non-Authoritative Information";
    case 204: return "204 No Content";
    case 205: return "205 Reset Content";
    case 206: return "206 Partial Content";
    case 300: return "300 Multiple Choices";
    case 301: return "301 Moved Permanently";
    case 302: return "302 Found";
    case 303: return "303 See Other";
    case 304: return "304 Not Modified";
    case 305: return "305 Use Proxy";
      // case 306: return "306 (Unused)";
    case 307: return "307 Temporary Redirect";
    case 400: return "400 Bad Request";
    case 401: return "401 Unauthorized";
    case 402: return "402 Payment Required";
    case 403: return "403 Forbidden";
    case 404: return "404 Not Found";
    case 405: return "405 Method Not Allowed";
    case 406: return "406 Not Acceptable";
    case 407: return "407 Proxy Authentication Required";
    case 408: return "408 Request Timeout";
    case 409: return "409 Conflict";
    case 410: return "410 Gone";
    case 411: return "411 Length Required";
    case 412: return "412 Precondition Failed";
    case 413: return "413 Request Entity Too Large";
    case 414: return "414 Request-URI Too Long";
    case 415: return "415 Unsupported Media Type";
    case 416: return "416 Requested Range Not Satisfiable";
    case 417: return "417 Expectation Failed";
    case 500: return "500 Internal Server Error";
    case 501: return "501 Not Implemented";
    case 502: return "502 Bad Gateway";
    case 503: return "503 Service Unavailable";
    case 504: return "504 Gateway Timeout";
    case 505: return "505 HTTP Version Not Supported";
    default: return "";
    }
  }

  void set_header(const std::string& key, const std::string& value)
  {
    headers_.push_back(std::make_pair(key, value));
  }

  const std::vector<std::pair<std::string, std::string>>& get_headers()
  {
    return headers_;
  }

  void end(const std::string& body)
  {
    body_ = body;
  }

  const std::string& get_body() const
  {
    return body_;
  }
private:
  int status_code_;
  std::string body_;
  std::vector<std::pair<std::string, std::string>> headers_;
};

ssize_t string_read_callback
(spdylay_session *session, int32_t stream_id,
 uint8_t *buf, size_t length, int *eof,
 spdylay_data_source *source, void *user_data)
{
  std::pair<std::string, size_t>& body_pair =
    *reinterpret_cast<std::pair<std::string, size_t>*>(source->ptr);
  const std::string& body = body_pair.first;
  size_t off = body_pair.second;
  ssize_t readlen = std::min(body.size()-off, length);
  memcpy(buf, body.c_str()+off, readlen);
  off += readlen;
  if(off == body.size()) {
    *eof = 1;
  }
  return readlen;
}

void on_request_recv_callback
(spdylay_session *session, int32_t stream_id, void *user_data)
{
  SpdyEventHandler *hd = reinterpret_cast<SpdyEventHandler*>(user_data);
  Request *req = hd->get_stream(stream_id);
  request request_obj(req->headers);
  response response_obj;
  (*reinterpret_cast<std::function<void (request&, response&)>*>
   (hd->config()->data_ptr))(request_obj, response_obj);
  size_t body_length = response_obj.get_body().size();
  response_obj.set_header("content-length", util::to_str(body_length));
  req->response_body = std::make_pair(response_obj.get_body(), 0);

  spdylay_data_provider data_prd;
  data_prd.source.ptr = &req->response_body;
  data_prd.read_callback = string_read_callback;
  hd->submit_response(response_obj.get_status_string(), stream_id,
                      response_obj.get_headers(), &data_prd);
}

class spdy {
public:
  spdy() : server_(0) {}
  ~spdy()
  {
    delete server_;
  }
  bool listen(const std::string& host, uint16_t port,
              const std::string& private_key_file, const std::string& cert_file,
              std::function<void (request&, response&)> callback,
              bool verbose = false)
  {
    delete server_;
    callback_ = callback;
    config_.verbose = verbose;
    config_.host = host;
    config_.port = port;
    config_.private_key_file = private_key_file;
    config_.cert_file = cert_file;
    config_.on_request_recv_callback = on_request_recv_callback;
    config_.data_ptr = &callback_;
    server_ = new SpdyServer(&config_);
    return server_->listen() == 0;
  }

  int run()
  {
    return server_->run();
  }
private:
  Config config_;
  std::function<void (request&, response&)> callback_;
  SpdyServer *server_;
};

namespace reactor {

template<typename Server>
int run(Server& server)
{
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  SSL_library_init();
  reset_timer();
  int r = server.run();
  if(r == 0) {
    return EXIT_SUCCESS;
  } else {
    return EXIT_FAILURE;
  }
}

} // namespace reactor

} // namespace spdylay

#endif // SPDY_H
