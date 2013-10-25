/*
 * nghttp2 - HTTP/2.0 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
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
#include "HttpServer.h"

#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <cassert>
#include <set>
#include <iostream>

#include <openssl/err.h>

#include <zlib.h>

#include <event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#include "app_helper.h"
#include "http2.h"
#include "util.h"

#ifndef O_BINARY
# define O_BINARY (0)
#endif // O_BINARY

namespace nghttp2 {

namespace {
Config config;
const std::string STATUS_200 = "200";
const std::string STATUS_304 = "304";
const std::string STATUS_400 = "400";
const std::string STATUS_404 = "404";
const std::string DEFAULT_HTML = "index.html";
const std::string NGHTTPD_SERVER = "nghttpd nghttp2/" NGHTTP2_VERSION;
} // namespace

Config::Config()
  : verbose(false),
    daemon(false),
    port(0),
    on_request_recv_callback(nullptr),
    data_ptr(nullptr),
    verify_client(false),
    no_tls(false),
    no_flow_control(false),
    output_upper_thres(1024*1024)
{}

Request::Request(int32_t stream_id)
  : stream_id(stream_id),
    file(-1)
{}

Request::~Request()
{
  if(file != -1) {
    close(file);
  }
}

class Sessions {
public:
  Sessions(event_base *evbase, const Config *config, SSL_CTX *ssl_ctx)
    : evbase_(evbase),
      config_(config),
      ssl_ctx_(ssl_ctx)
  {}
  ~Sessions()
  {
    for(auto handler : handlers_) {
      delete handler;
    }
    SSL_CTX_free(ssl_ctx_);
  }
  void add_handler(Http2Handler *handler)
  {
    handlers_.insert(handler);
  }
  void remove_handler(Http2Handler *handler)
  {
    handlers_.erase(handler);
  }
  SSL_CTX* get_ssl_ctx() const
  {
    return ssl_ctx_;
  }
  SSL* ssl_session_new(int fd)
  {
    SSL *ssl = SSL_new(ssl_ctx_);
    if(!ssl) {
      std::cerr << "SSL_new() failed" << std::endl;
      return nullptr;
    }
    if(SSL_set_fd(ssl, fd) == 0) {
      std::cerr << "SSL_set_fd() failed" << std::endl;
      SSL_free(ssl);
      return nullptr;
    }
    return ssl;
  }
  const Config* get_config() const
  {
    return config_;
  }
  event_base* get_evbase() const
  {
    return evbase_;
  }
private:
  std::set<Http2Handler*> handlers_;
  event_base *evbase_;
  const Config *config_;
  SSL_CTX *ssl_ctx_;
};

namespace {
void delete_handler(Http2Handler *handler)
{
  handler->remove_self();
  delete handler;
}
} // namespace

namespace {
void print_session_id(int64_t id)
{
  std::cout << "[id=" << id << "] ";
}
} // namespace

namespace {
void on_session_closed(Http2Handler *hd, int64_t session_id)
{
  if(hd->get_config()->verbose) {
    print_session_id(session_id);
    print_timer();
    std::cout << " closed" << std::endl;
  }
}
} // namespace

namespace {
void fill_callback(nghttp2_session_callbacks& callbacks, const Config *config);
} // namespace

Http2Handler::Http2Handler(Sessions *sessions,
                           int fd, SSL *ssl, int64_t session_id)
  : session_(nullptr), sessions_(sessions), bev_(nullptr), fd_(fd), ssl_(ssl),
    session_id_(session_id),
    left_connhd_len_(NGHTTP2_CLIENT_CONNECTION_HEADER_LEN)
{}

Http2Handler::~Http2Handler()
{
  on_session_closed(this, session_id_);
  nghttp2_session_del(session_);
  if(ssl_) {
    SSL_shutdown(ssl_);
  }
  if(bev_) {
    bufferevent_free(bev_);
  }
  if(ssl_) {
    SSL_free(ssl_);
  }
  shutdown(fd_, SHUT_WR);
  close(fd_);
}

void Http2Handler::remove_self()
{
  sessions_->remove_handler(this);
}

namespace {
void readcb(bufferevent *bev, void *ptr)
{
  int rv;
  auto handler = reinterpret_cast<Http2Handler*>(ptr);
  rv = handler->on_read();
  if(rv != 0) {
    delete_handler(handler);
  }
}
} // namespace

namespace {
void writecb(bufferevent *bev, void *ptr)
{
  if(evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
    return;
  }
  int rv;
  auto handler = reinterpret_cast<Http2Handler*>(ptr);
  rv = handler->on_write();
  if(rv != 0) {
    delete_handler(handler);
  }
}
} // namespace

namespace {
void eventcb(bufferevent *bev, short events, void *ptr)
{
  auto handler = reinterpret_cast<Http2Handler*>(ptr);
  if(events & BEV_EVENT_CONNECTED) {
    // SSL/TLS handshake completed
    if(handler->verify_npn_result() != 0) {
      delete_handler(handler);
      return;
    }
    if(handler->on_connect() != 0) {
      delete_handler(handler);
      return;
    }
  } else if(events & BEV_EVENT_EOF) {
    delete_handler(handler);
    return;
  } else if(events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
    delete_handler(handler);
    return;
  }
}
} // namespace

namespace {
void connhd_readcb(bufferevent *bev, void *ptr)
{
  uint8_t data[24];
  auto handler = reinterpret_cast<Http2Handler*>(ptr);
  size_t leftlen = handler->get_left_connhd_len();
  auto input = bufferevent_get_input(bev);
  int readlen = evbuffer_remove(input, data, leftlen);
  if(readlen == -1) {
    delete_handler(handler);
    return;
  }
  const char *conhead = NGHTTP2_CLIENT_CONNECTION_HEADER;
  if(memcmp(conhead + NGHTTP2_CLIENT_CONNECTION_HEADER_LEN - leftlen,
            data, readlen) != 0) {
    delete_handler(handler);
    return;
  }
  leftlen -= readlen;
  handler->set_left_connhd_len(leftlen);
  if(leftlen == 0) {
    bufferevent_setcb(bev, readcb, writecb, eventcb, ptr);
    // Run on_read to process data left in buffer since they are not
    // notified further
    if(handler->on_read() != 0) {
      delete_handler(handler);
      return;
    }
  }
}
} // namespace

int Http2Handler::setup_bev()
{
  if(ssl_) {
    bev_ = bufferevent_openssl_socket_new
      (sessions_->get_evbase(), fd_, ssl_,
       BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_DEFER_CALLBACKS);
  } else {
    bev_ = bufferevent_socket_new(sessions_->get_evbase(), fd_,
                                  BEV_OPT_DEFER_CALLBACKS);
  }
  bufferevent_enable(bev_, EV_READ);
  bufferevent_setcb(bev_, connhd_readcb, writecb, eventcb, this);
  // TODO set up timeout here
  return 0;
}

int Http2Handler::on_read()
{
  int rv = 0;
  if((rv = nghttp2_session_recv(session_)) < 0) {
    if(rv != NGHTTP2_ERR_EOF) {
      std::cerr << "nghttp2_session_recv() returned error: "
                << nghttp2_strerror(rv) << std::endl;
    }
  } else if((rv = nghttp2_session_send(session_)) < 0) {
    std::cerr << "nghttp2_session_send() returned error: "
              << nghttp2_strerror(rv) << std::endl;
  }
  if(rv == 0) {
    if(nghttp2_session_want_read(session_) == 0 &&
       nghttp2_session_want_write(session_) == 0 &&
       evbuffer_get_length(bufferevent_get_output(bev_)) == 0) {
      rv = -1;
    }
  }
  return rv;
}

int Http2Handler::on_write()
{
  int rv = 0;
  if((rv = nghttp2_session_send(session_)) < 0) {
    std::cerr << "nghttp2_session_send() returned error: "
              << nghttp2_strerror(rv) << std::endl;
  }
  if(rv == 0) {
    if(nghttp2_session_want_read(session_) == 0 &&
       nghttp2_session_want_write(session_) == 0 &&
       evbuffer_get_length(bufferevent_get_output(bev_)) == 0) {
      rv = -1;
    }
  }
  return rv;
}

int Http2Handler::on_connect()
{
  int r;
  nghttp2_session_callbacks callbacks;
  fill_callback(callbacks, sessions_->get_config());
  r = nghttp2_session_server_new(&session_, &callbacks, this);
  if(r != 0) {
    return r;
  }
  nghttp2_settings_entry entry[2];
  size_t niv = 1;
  entry[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  entry[0].value = 100;
  if(sessions_->get_config()->no_flow_control) {
    entry[niv].settings_id = NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS;
    entry[niv].value = 1;
    ++niv;
  }
  r = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, entry, niv);
  if(r != 0) {
    return r;
  }
  return on_write();
}

int Http2Handler::verify_npn_result()
{
  const unsigned char *next_proto = nullptr;
  unsigned int next_proto_len;
  SSL_get0_next_proto_negotiated(ssl_, &next_proto, &next_proto_len);
  if(next_proto) {
    std::string proto(next_proto, next_proto+next_proto_len);
    if(sessions_->get_config()->verbose) {
      std::cout << "The negotiated next protocol: " << proto << std::endl;
    }
    if(proto == NGHTTP2_PROTO_VERSION_ID) {
      return 0;
    }
  }
  std::cerr << "The negotiated next protocol is not supported."
            << std::endl;
  return 0;
}

int Http2Handler::sendcb(const uint8_t *data, size_t len)
{
  int rv;
  auto output = bufferevent_get_output(bev_);
  // Check buffer length and return WOULDBLOCK if it is large enough.
  if(evbuffer_get_length(output) >
     sessions_->get_config()->output_upper_thres) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }

  rv = evbuffer_add(output, data, len);
  if(rv == -1) {
    std::cerr << "evbuffer_add() failed" << std::endl;
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  } else {
    return len;
  }
}

int Http2Handler::recvcb(uint8_t *buf, size_t len)
{
  auto input = bufferevent_get_input(bev_);
  int nread = evbuffer_remove(input, buf, len);
  if(nread == -1) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  } else if(nread == 0) {
    return NGHTTP2_ERR_WOULDBLOCK;
  } else {
    return nread;
  }
}

int Http2Handler::submit_file_response(const std::string& status,
                                       int32_t stream_id,
                                       time_t last_modified,
                                       off_t file_length,
                                       nghttp2_data_provider *data_prd)
{
  std::string date_str = util::http_date(time(0));
  std::string content_length = util::to_str(file_length);
  std::string last_modified_str;
  const char *nv[] = {
    ":status", status.c_str(),
    "server", NGHTTPD_SERVER.c_str(),
    "content-length", content_length.c_str(),
    "cache-control", "max-age=3600",
    "date", date_str.c_str(),
    nullptr, nullptr,
    nullptr
  };
  if(last_modified != 0) {
    last_modified_str = util::http_date(last_modified);
    nv[10] = "last-modified";
    nv[11] = last_modified_str.c_str();
  }
  return nghttp2_submit_response(session_, stream_id, nv, data_prd);
}

int Http2Handler::submit_response
(const std::string& status,
 int32_t stream_id,
 const std::vector<std::pair<std::string, std::string>>& headers,
 nghttp2_data_provider *data_prd)
{
  std::string date_str = util::http_date(time(0));
  const size_t static_size = 6;
  auto nv = std::vector<const char*>();
  nv.reserve(static_size + headers.size() * 2 + 1);
  nv.push_back(":status");
  nv.push_back(status.c_str());
  nv.push_back("server");
  nv.push_back(NGHTTPD_SERVER.c_str());
  nv.push_back("date");
  nv.push_back(date_str.c_str());
  for(size_t i = 0; i < headers.size(); ++i) {
    nv.push_back(headers[i].first.c_str());
    nv.push_back(headers[i].second.c_str());
  }
  nv.push_back(nullptr);
  int r = nghttp2_submit_response(session_, stream_id, nv.data(), data_prd);
  return r;
}

int Http2Handler::submit_response(const std::string& status,
                                  int32_t stream_id,
                                  nghttp2_data_provider *data_prd)
{
  const char *nv[] = {
    ":status", status.c_str(),
    "server", NGHTTPD_SERVER.c_str(),
    nullptr
  };
  return nghttp2_submit_response(session_, stream_id, nv, data_prd);
}

void Http2Handler::add_stream(int32_t stream_id, std::unique_ptr<Request> req)
{
  id2req_[stream_id] = std::move(req);
}

void Http2Handler::remove_stream(int32_t stream_id)
{
  id2req_.erase(stream_id);
}

Request* Http2Handler::get_stream(int32_t stream_id)
{
  auto itr = id2req_.find(stream_id);
  if(itr == std::end(id2req_)) {
    return nullptr;
  } else {
    return (*itr).second.get();
  }
}

int64_t Http2Handler::session_id() const
{
  return session_id_;
}

Sessions* Http2Handler::get_sessions() const
{
  return sessions_;
}

const Config* Http2Handler::get_config() const
{
  return sessions_->get_config();
}

size_t Http2Handler::get_left_connhd_len() const
{
  return left_connhd_len_;
}

void Http2Handler::set_left_connhd_len(size_t left)
{
  left_connhd_len_ = left;
}

namespace {
ssize_t hd_send_callback(nghttp2_session *session,
                         const uint8_t *data, size_t len, int flags,
                         void *user_data)
{
  auto hd = reinterpret_cast<Http2Handler*>(user_data);
  return hd->sendcb(data, len);
}
} // namespace

namespace {
ssize_t hd_recv_callback(nghttp2_session *session,
                         uint8_t *data, size_t len, int flags, void *user_data)
{
  auto hd = reinterpret_cast<Http2Handler*>(user_data);
  return hd->recvcb(data, len);
}
} // namespace

ssize_t file_read_callback
(nghttp2_session *session, int32_t stream_id,
 uint8_t *buf, size_t length, int *eof,
 nghttp2_data_source *source, void *user_data)
{
  int fd = source->fd;
  ssize_t r;
  while((r = read(fd, buf, length)) == -1 && errno == EINTR);
  if(r == -1) {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  } else {
    if(r == 0) {
      *eof = 1;
    }
    return r;
  }
}

namespace {
bool check_url(const std::string& url)
{
  // We don't like '\' in url.
  return !url.empty() && url[0] == '/' &&
    url.find('\\') == std::string::npos &&
    url.find("/../") == std::string::npos &&
    url.find("/./") == std::string::npos &&
    !util::endsWith(url, "/..") && !util::endsWith(url, "/.");
}
} // namespace

namespace {
void prepare_status_response(Request *req, Http2Handler *hd,
                             const std::string& status)
{
  int pipefd[2];
  if(status == STATUS_304 || pipe(pipefd) == -1) {
    hd->submit_response(status, req->stream_id, 0);
  } else {
    std::stringstream ss;
    ss << "<html><head><title>" << status << "</title></head><body>"
       << "<h1>" << status << "</h1>"
       << "<hr>"
       << "<address>" << NGHTTPD_SERVER
       << " at port " << hd->get_config()->port
       << "</address>"
       << "</body></html>";
    std::string body = ss.str();
    gzFile write_fd = gzdopen(pipefd[1], "w");
    gzwrite(write_fd, body.c_str(), body.size());
    gzclose(write_fd);
    close(pipefd[1]);

    req->file = pipefd[0];
    nghttp2_data_provider data_prd;
    data_prd.source.fd = pipefd[0];
    data_prd.read_callback = file_read_callback;
    std::vector<std::pair<std::string, std::string>> headers;
    headers.emplace_back("content-encoding", "gzip");
    headers.emplace_back("content-type", "text/html; charset=UTF-8");
    hd->submit_response(status, req->stream_id, headers, &data_prd);
  }
}
} // namespace

namespace {
void prepare_response(Request *req, Http2Handler *hd)
{
  auto url = (*std::lower_bound(std::begin(req->headers),
                                std::end(req->headers),
                                std::make_pair(std::string(":path"),
                                               std::string()))).second;
  auto ims = std::lower_bound(std::begin(req->headers),
                              std::end(req->headers),
                              std::make_pair(std::string("if-modified-since"),
                                             std::string()));
  time_t last_mod = 0;
  bool last_mod_found = false;
  if(ims != std::end(req->headers) &&
     (*ims).first == "if-modified-since") {
      last_mod_found = true;
      last_mod = util::parse_http_date((*ims).second);
  }
  auto query_pos = url.find("?");
  if(query_pos != std::string::npos) {
    // Do not response to this request to allow clients to test timeouts.
    if(url.find("nghttpd_do_not_respond_to_req=yes",
                query_pos) != std::string::npos) {
      return;
    }
    url = url.substr(0, query_pos);
  }
  url = util::percentDecode(url.begin(), url.end());
  if(!check_url(url)) {
    prepare_status_response(req, hd, STATUS_404);
    return;
  }
  std::string path = hd->get_config()->htdocs+url;
  if(path[path.size()-1] == '/') {
    path += DEFAULT_HTML;
  }
  int file = open(path.c_str(), O_RDONLY | O_BINARY);
  if(file == -1) {
    prepare_status_response(req, hd, STATUS_404);
  } else {
    struct stat buf;
    if(fstat(file, &buf) == -1) {
      close(file);
      prepare_status_response(req, hd, STATUS_404);
    } else {
      req->file = file;
      nghttp2_data_provider data_prd;
      data_prd.source.fd = file;
      data_prd.read_callback = file_read_callback;
      if(last_mod_found && buf.st_mtime <= last_mod) {
        prepare_status_response(req, hd, STATUS_304);
      } else {
        hd->submit_file_response(STATUS_200, req->stream_id, buf.st_mtime,
                                 buf.st_size, &data_prd);
      }
    }
  }
}
} // namespace

namespace {
void append_nv(Request *req, nghttp2_nv *nva, size_t nvlen)
{
  for(size_t i = 0; i < nvlen; ++i) {
    req->headers.push_back({
        std::string(nva[i].name, nva[i].name + nva[i].namelen),
          std::string(nva[i].value, nva[i].value + nva[i].valuelen)
          });
  }
}
} // namespace

namespace {
const char *REQUIRED_HEADERS[] = {
  ":host", ":method", ":path", ":scheme", nullptr
};
} // namespace

namespace {
int hd_on_frame_recv_callback
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
  auto hd = reinterpret_cast<Http2Handler*>(user_data);
  if(hd->get_config()->verbose) {
    print_session_id(hd->session_id());
    on_frame_recv_callback(session, frame, user_data);
  }
  switch(frame->hd.type) {
  case NGHTTP2_HEADERS:
    switch(frame->headers.cat) {
    case NGHTTP2_HCAT_REQUEST: {
      int32_t stream_id = frame->hd.stream_id;
      if(!http2::check_http2_headers(frame->headers.nva,
                                     frame->headers.nvlen)) {
        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id,
                                  NGHTTP2_PROTOCOL_ERROR);
        return 0;
      }
      for(size_t i = 0; REQUIRED_HEADERS[i]; ++i) {
        if(!http2::get_unique_header(frame->headers.nva,
                                     frame->headers.nvlen,
                                     REQUIRED_HEADERS[i])) {
          nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id,
                                    NGHTTP2_PROTOCOL_ERROR);
          return 0;
        }
      }
      auto req = util::make_unique<Request>(stream_id);
      append_nv(req.get(), frame->headers.nva, frame->headers.nvlen);
      hd->add_stream(stream_id, std::move(req));
      break;
    }
    default:
      break;
    }
    break;
  default:
    break;
  }
  return 0;
}
} // namespace

int htdocs_on_request_recv_callback
(nghttp2_session *session, int32_t stream_id, void *user_data)
{
  auto hd = reinterpret_cast<Http2Handler*>(user_data);
  auto stream = hd->get_stream(stream_id);
  if(stream) {
    prepare_response(hd->get_stream(stream_id), hd);
  }
  return 0;
}

namespace {
int hd_on_frame_send_callback
(nghttp2_session *session, const nghttp2_frame *frame,
 void *user_data)
{
  auto hd = reinterpret_cast<Http2Handler*>(user_data);
  if(hd->get_config()->verbose) {
    print_session_id(hd->session_id());
    on_frame_send_callback(session, frame, user_data);
  }
  return 0;
}
} // namespace

namespace {
int on_data_chunk_recv_callback
(nghttp2_session *session, uint8_t flags, int32_t stream_id,
 const uint8_t *data, size_t len, void *user_data)
{
  // TODO Handle POST
  return 0;
}
} // namespace

namespace {
int hd_on_data_recv_callback
(nghttp2_session *session, uint16_t length, uint8_t flags, int32_t stream_id,
 void *user_data)
{
  // TODO Handle POST
  auto hd = reinterpret_cast<Http2Handler*>(user_data);
  if(hd->get_config()->verbose) {
    print_session_id(hd->session_id());
    on_data_recv_callback(session, length, flags, stream_id, user_data);
  }
  return 0;
}
} // namespace

namespace {
int hd_on_data_send_callback
(nghttp2_session *session, uint16_t length,  uint8_t flags, int32_t stream_id,
 void *user_data)
{
  auto hd = reinterpret_cast<Http2Handler*>(user_data);
  if(hd->get_config()->verbose) {
    print_session_id(hd->session_id());
    on_data_send_callback(session, length, flags, stream_id, user_data);
  }
  return 0;
}
} // namespace

namespace {
int on_stream_close_callback
(nghttp2_session *session, int32_t stream_id, nghttp2_error_code error_code,
 void *user_data)
{
  auto hd = reinterpret_cast<Http2Handler*>(user_data);
  hd->remove_stream(stream_id);
  if(hd->get_config()->verbose) {
    print_session_id(hd->session_id());
    print_timer();
    printf(" stream_id=%d closed\n", stream_id);
    fflush(stdout);
  }
  return 0;
}
} // namespace

namespace {
void fill_callback(nghttp2_session_callbacks& callbacks, const Config *config)
{
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.send_callback = hd_send_callback;
  callbacks.recv_callback = hd_recv_callback;
  callbacks.on_stream_close_callback = on_stream_close_callback;
  callbacks.on_frame_recv_callback = hd_on_frame_recv_callback;
  callbacks.on_frame_send_callback = hd_on_frame_send_callback;
  callbacks.on_data_recv_callback = hd_on_data_recv_callback;
  callbacks.on_data_send_callback = hd_on_data_send_callback;
  if(config->verbose) {
    callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
    callbacks.on_frame_recv_parse_error_callback =
      on_frame_recv_parse_error_callback;
    callbacks.on_unknown_frame_recv_callback = on_unknown_frame_recv_callback;
  }
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks.on_request_recv_callback = config->on_request_recv_callback;
}
} // namespace

class ListenEventHandler {
public:
  ListenEventHandler(Sessions *sessions, int64_t *session_id_seed_ptr)
    : sessions_(sessions),
      session_id_seed_ptr_(session_id_seed_ptr)
  {}
  void accept_connection(int fd, sockaddr *addr, int addrlen)
  {
    int rv;
    int val = 1;
    SSL *ssl = nullptr;
    rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                    reinterpret_cast<char *>(&val), sizeof(val));
    if(rv == -1) {
      std::cerr << "Setting option TCP_NODELAY failed: errno="
                << errno << std::endl;
    }
    if(sessions_->get_ssl_ctx()) {
      ssl = sessions_->ssl_session_new(fd);
      if(!ssl) {
        return;
      }
    }
    int64_t session_id = ++(*session_id_seed_ptr_);
    auto handler = util::make_unique<Http2Handler>(sessions_, fd, ssl,
                                                   session_id);
    handler->setup_bev();
    if(!ssl) {
      if(handler->on_connect() != 0) {
        return;
      }
    }
    sessions_->add_handler(handler.release());
  }
private:
  Sessions *sessions_;
  int64_t *session_id_seed_ptr_;
};

HttpServer::HttpServer(const Config *config)
  : config_(config)
{}

namespace {
int next_proto_cb(SSL *s, const unsigned char **data, unsigned int *len,
                  void *arg)
{
  auto next_proto =
    reinterpret_cast<std::pair<unsigned char*, size_t>* >(arg);
  *data = next_proto->first;
  *len = next_proto->second;
  return SSL_TLSEXT_ERR_OK;
}
} // namespace

namespace {
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
  // We don't verify the client certificate. Just request it for the
  // testing purpose.
  return 1;
}
} // namespace

namespace {
void evlistener_acceptcb(evconnlistener *listener, int fd,
                         sockaddr *addr, int addrlen, void *arg)
{
  auto handler = reinterpret_cast<ListenEventHandler*>(arg);
  handler->accept_connection(fd, addr, addrlen);
}
} // namespace

namespace {
void evlistener_errorcb(evconnlistener *listener, void *ptr)
{
  std::cerr << "Accepting incoming connection failed" << std::endl;
}
} // namespace

namespace {
int start_listen(event_base *evbase, Sessions *sessions,
                 int64_t *session_id_seed_ptr)
{
  addrinfo hints;
  int r;
  char service[10];
  snprintf(service, sizeof(service), "%u", sessions->get_config()->port);
  memset(&hints, 0, sizeof(addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif // AI_ADDRCONFIG

  addrinfo *res, *rp;
  r = getaddrinfo(nullptr, service, &hints, &res);
  if(r != 0) {
    std::cerr << "getaddrinfo() failed: " << gai_strerror(r) << std::endl;
    return -1;
  }
  for(rp = res; rp; rp = rp->ai_next) {
    int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if(fd == -1) {
      continue;
    }
    int val = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                  static_cast<socklen_t>(sizeof(val))) == -1) {
      close(fd);
      continue;
    }
    evutil_make_socket_nonblocking(fd);
#ifdef IPV6_V6ONLY
    if(rp->ai_family == AF_INET6) {
      if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val,
                    static_cast<socklen_t>(sizeof(val))) == -1) {
        close(fd);
        continue;
      }
    }
#endif // IPV6_V6ONLY
    if(bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
      auto evlistener = evconnlistener_new
        (evbase,
         evlistener_acceptcb,
         new ListenEventHandler(sessions, session_id_seed_ptr),
         LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
         256,
         fd);
      evconnlistener_set_error_cb(evlistener, evlistener_errorcb);

      if(sessions->get_config()->verbose) {
        std::cout << (rp->ai_family == AF_INET ? "IPv4" : "IPv6")
                  << ": listen on port "
                  << sessions->get_config()->port << std::endl;
      }
      continue;
    } else {
      std::cerr << strerror(errno) << std::endl;

    }
    close(fd);
  }
  freeaddrinfo(res);
  return 0;
}
} // namespace

int HttpServer::run()
{
  SSL_CTX *ssl_ctx = nullptr;
  std::pair<unsigned char*, size_t> next_proto;
  unsigned char proto_list[255];
  if(!config_->no_tls) {
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if(!ssl_ctx) {
      std::cerr << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
      return -1;
    }
    SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    if(SSL_CTX_use_PrivateKey_file(ssl_ctx,
                                   config_->private_key_file.c_str(),
                                   SSL_FILETYPE_PEM) != 1) {
      std::cerr << "SSL_CTX_use_PrivateKey_file failed." << std::endl;
      return -1;
    }
    if(SSL_CTX_use_certificate_chain_file(ssl_ctx,
                                          config_->cert_file.c_str()) != 1) {
      std::cerr << "SSL_CTX_use_certificate_file failed." << std::endl;
      return -1;
    }
    if(SSL_CTX_check_private_key(ssl_ctx) != 1) {
      std::cerr << "SSL_CTX_check_private_key failed." << std::endl;
      return -1;
    }
    if(config_->verify_client) {
      SSL_CTX_set_verify(ssl_ctx,
                         SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |
                         SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                         verify_callback);
    }

    proto_list[0] = 17;
    memcpy(&proto_list[1], NGHTTP2_PROTO_VERSION_ID,
           NGHTTP2_PROTO_VERSION_ID_LEN);
    next_proto.first = proto_list;
    next_proto.second = 18;

    SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, &next_proto);
  }

  auto evbase = event_base_new();
  int64_t session_id_seed = 0;
  Sessions sessions(evbase, config_, ssl_ctx);
  if(start_listen(evbase, &sessions, &session_id_seed) != 0) {
    std::cerr << "Could not listen" << std::endl;
    return -1;
  }

  event_base_loop(evbase, 0);
  return 0;
}

} // namespace nghttp2
