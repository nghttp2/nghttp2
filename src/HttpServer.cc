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
#include <thread>

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
const std::string STATUS_200 = "200";
const std::string STATUS_304 = "304";
const std::string STATUS_400 = "400";
const std::string STATUS_404 = "404";
const std::string DEFAULT_HTML = "index.html";
const std::string NGHTTPD_SERVER = "nghttpd nghttp2/" NGHTTP2_VERSION;
} // namespace

Config::Config()
  : data_ptr(nullptr),
    output_upper_thres(1024*1024),
    padding(0),
    num_worker(1),
    header_table_size(-1),
    port(0),
    verbose(false),
    daemon(false),
    verify_client(false),
    no_tls(false)
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
      ssl_ctx_(ssl_ctx),
      next_session_id_(1)
  {}
  ~Sessions()
  {
    for(auto handler : handlers_) {
      delete handler;
    }
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
  int64_t get_next_session_id()
  {
    auto session_id = next_session_id_;
    if(next_session_id_ == INT64_MAX) {
      next_session_id_ = 1;
    }
    return session_id;
  }
  void accept_connection(int fd)
  {
    int val = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<char *>(&val), sizeof(val));
    SSL *ssl = nullptr;
    if(ssl_ctx_) {
      ssl = ssl_session_new(fd);
      if(!ssl) {
        close(fd);
        return;
      }
    }
    auto handler = util::make_unique<Http2Handler>(this, fd, ssl,
                                                   get_next_session_id());
    handler->setup_bev();
    if(!ssl) {
      if(handler->on_connect() != 0) {
        return;
      }
    }
    add_handler(handler.release());
  }
private:
  std::set<Http2Handler*> handlers_;
  event_base *evbase_;
  const Config *config_;
  SSL_CTX *ssl_ctx_;
  int64_t next_session_id_;
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
  : session_id_(session_id),
    session_(nullptr),
    sessions_(sessions),
    bev_(nullptr),
    ssl_(ssl),
    settings_timerev_(nullptr),
    left_connhd_len_(NGHTTP2_CLIENT_CONNECTION_HEADER_LEN),
    fd_(fd)
{}

Http2Handler::~Http2Handler()
{
  on_session_closed(this, session_id_);
  if(settings_timerev_) {
    event_free(settings_timerev_);
  }
  nghttp2_session_del(session_);
  if(ssl_) {
    SSL_set_shutdown(ssl_, SSL_RECEIVED_SHUTDOWN);
    SSL_shutdown(ssl_);
  }
  if(bev_) {
    bufferevent_disable(bev_, EV_READ | EV_WRITE);
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
  auto handler = static_cast<Http2Handler*>(ptr);
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
  auto handler = static_cast<Http2Handler*>(ptr);
  rv = handler->on_write();
  if(rv != 0) {
    delete_handler(handler);
  }
}
} // namespace

namespace {
void eventcb(bufferevent *bev, short events, void *ptr)
{
  auto handler = static_cast<Http2Handler*>(ptr);
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
  auto handler = static_cast<Http2Handler*>(ptr);
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
  int rv;
  auto input = bufferevent_get_input(bev_);
  auto inputlen = evbuffer_get_length(input);
  auto mem = evbuffer_pullup(input, -1);

  rv = nghttp2_session_mem_recv(session_, mem, inputlen);
  if(rv < 0) {
    std::cerr << "nghttp2_session_mem_recv() returned error: "
              << nghttp2_strerror(rv) << std::endl;
    return -1;
  }

  evbuffer_drain(input, rv);

  return on_write();
}

int Http2Handler::on_write()
{
  int rv;
  uint8_t buf[4096];
  size_t buflen = 0;
  auto output = bufferevent_get_output(bev_);

  for(;;) {
    if(evbuffer_get_length(output) + buflen >
       sessions_->get_config()->output_upper_thres) {
      break;
    }

    const uint8_t *data;
    auto datalen = nghttp2_session_mem_send(session_, &data);

    if(datalen < 0) {
      std::cerr << "nghttp2_session_mem_send() returned error: "
                << nghttp2_strerror(datalen) << std::endl;
      return -1;
    }
    if(datalen == 0) {
      break;
    }
    if(buflen + datalen > sizeof(buf)) {
      rv = evbuffer_add(output, buf, buflen);
      if(rv != 0) {
        std::cerr << "evbuffer_add() failed" << std::endl;
        return -1;
      }
      buflen = 0;
      if(datalen > static_cast<ssize_t>(sizeof(buf))) {
        rv = evbuffer_add(output, data, datalen);
        if(rv != 0) {
          std::cerr << "evbuffer_add() failed" << std::endl;
          return -1;
        }
        continue;
      }
    }
    memcpy(buf + buflen, data, datalen);
    buflen += datalen;
  }
  rv = evbuffer_add(output, buf, buflen);
  if(rv != 0) {
    std::cerr << "evbuffer_add() failed" << std::endl;
    return -1;
  }
  if(nghttp2_session_want_read(session_) == 0 &&
     nghttp2_session_want_write(session_) == 0 &&
     evbuffer_get_length(output) == 0) {
    return -1;
  }
  return 0;
}

namespace {
void settings_timeout_cb(evutil_socket_t fd, short what, void *arg)
{
  auto hd = static_cast<Http2Handler*>(arg);
  hd->terminate_session(NGHTTP2_SETTINGS_TIMEOUT);
  hd->on_write();
}
} // namespace

int Http2Handler::on_connect()
{
  int r;
  nghttp2_session_callbacks callbacks;
  fill_callback(callbacks, sessions_->get_config());
  r = nghttp2_session_server_new(&session_, &callbacks, this);
  if(r != 0) {
    return r;
  }
  nghttp2_settings_entry entry[4];
  size_t niv = 1;
  entry[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  entry[0].value = 100;
  if(sessions_->get_config()->header_table_size >= 0) {
    entry[niv].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
    entry[niv].value = sessions_->get_config()->header_table_size;
    ++niv;
  }
  r = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, entry, niv);
  if(r != 0) {
    return r;
  }
  assert(settings_timerev_ == nullptr);
  settings_timerev_ = evtimer_new(sessions_->get_evbase(), settings_timeout_cb,
                                  this);
  // SETTINGS ACK timeout is 10 seconds for now
  timeval settings_timeout = { 10, 0 };
  evtimer_add(settings_timerev_, &settings_timeout);

  return on_write();
}

int Http2Handler::verify_npn_result()
{
  const unsigned char *next_proto = nullptr;
  unsigned int next_proto_len;
  // Check the negotiated protocol in NPN or ALPN
  SSL_get0_next_proto_negotiated(ssl_, &next_proto, &next_proto_len);
  for(int i = 0; i < 2; ++i) {
    if(next_proto) {
      std::string proto(next_proto, next_proto+next_proto_len);
      if(sessions_->get_config()->verbose) {
        std::cout << "The negotiated protocol: " << proto << std::endl;
      }
      if(proto == NGHTTP2_PROTO_VERSION_ID) {
        return 0;
      }
      break;
    } else {
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
      SSL_get0_alpn_selected(ssl_, &next_proto, &next_proto_len);
#else // OPENSSL_VERSION_NUMBER < 0x10002000L
      break;
#endif // OPENSSL_VERSION_NUMBER < 0x10002000L
    }
  }
  if(sessions_->get_config()->verbose) {
    std::cerr << "Client did not advertise HTTP/2.0 protocol."
              << " (nghttp2 expects " << NGHTTP2_PROTO_VERSION_ID << ")"
              << std::endl;
  }
  return -1;
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
  auto nva = std::vector<nghttp2_nv>{
    http2::make_nv_ls(":status", status),
    http2::make_nv_ls("server", NGHTTPD_SERVER),
    http2::make_nv_ls("content-length", content_length),
    http2::make_nv_ll("cache-control", "max-age=3600"),
    http2::make_nv_ls("date", date_str),
  };
  if(last_modified != 0) {
    last_modified_str = util::http_date(last_modified);
    nva.push_back(http2::make_nv_ls("last-modified", last_modified_str));
  }
  return nghttp2_submit_response(session_, stream_id, nva.data(), nva.size(),
                                 data_prd);
}

int Http2Handler::submit_response
(const std::string& status,
 int32_t stream_id,
 const std::vector<std::pair<std::string, std::string>>& headers,
 nghttp2_data_provider *data_prd)
{
  std::string date_str = util::http_date(time(0));
  auto nva = std::vector<nghttp2_nv>{
    http2::make_nv_ls(":status", status),
    http2::make_nv_ls("server", NGHTTPD_SERVER),
    http2::make_nv_ls("date", date_str)
  };
  for(size_t i = 0; i < headers.size(); ++i) {
    nva.push_back(http2::make_nv(headers[i].first, headers[i].second));
  }
  int r = nghttp2_submit_response(session_, stream_id, nva.data(), nva.size(),
                                  data_prd);
  return r;
}

int Http2Handler::submit_response(const std::string& status,
                                  int32_t stream_id,
                                  nghttp2_data_provider *data_prd)
{
  auto nva = std::vector<nghttp2_nv>{
    http2::make_nv_ls(":status", status),
    http2::make_nv_ls("server", NGHTTPD_SERVER)
  };
  return nghttp2_submit_response(session_, stream_id, nva.data(), nva.size(),
                                 data_prd);
}

int Http2Handler::submit_push_promise(Request *req,
                                      const std::string& push_path)
{
  std::string authority;
  auto itr = std::lower_bound(std::begin(req->headers),
                              std::end(req->headers),
                              std::make_pair(std::string(":authority"),
                                             std::string("")));
  if(itr == std::end(req->headers) || (*itr).first != ":authority") {
    itr = std::lower_bound(std::begin(req->headers),
                           std::end(req->headers),
                           std::make_pair(std::string("host"),
                                          std::string("")));
  }
  auto nva = std::vector<nghttp2_nv>{
    http2::make_nv_ll(":method", "GET"),
    http2::make_nv_ls(":path", push_path),
    get_config()->no_tls ?
    http2::make_nv_ll(":scheme", "http") :
    http2::make_nv_ll(":scheme", "https"),
    http2::make_nv_ls(":authority", (*itr).second)
  };
  return nghttp2_submit_push_promise(session_, NGHTTP2_FLAG_END_HEADERS,
                                     req->stream_id, nva.data(), nva.size(),
                                     nullptr);
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

void Http2Handler::remove_settings_timer()
{
  if(settings_timerev_) {
    evtimer_del(settings_timerev_);
    event_free(settings_timerev_);
    settings_timerev_ = nullptr;
  }
}

void Http2Handler::terminate_session(nghttp2_error_code error_code)
{
  nghttp2_session_terminate_session(session_, error_code);
}

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
void prepare_response(Request *req, Http2Handler *hd, bool allow_push = true)
{
  int rv;
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
  auto push_itr = hd->get_config()->push.find(url);
  if(allow_push && push_itr != std::end(hd->get_config()->push)) {
    for(auto& push_path : (*push_itr).second) {
      rv = hd->submit_push_promise(req, push_path);
      if(rv != 0) {
        std::cerr << "nghttp2_submit_push_promise() returned error: "
                  << nghttp2_strerror(rv) << std::endl;
      }
    }
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
void append_nv(Request *req, const std::vector<nghttp2_nv>& nva)
{
  for(auto& nv : nva) {
    http2::split_add_header(req->headers,
                            nv.name, nv.namelen, nv.value, nv.valuelen);
  }
}
} // namespace

namespace {
const char *REQUIRED_HEADERS[] = {
  ":method", ":path", ":scheme", nullptr
};
} // namespace

namespace {
int on_header_callback(nghttp2_session *session,
                       const nghttp2_frame *frame,
                       const uint8_t *name, size_t namelen,
                       const uint8_t *value, size_t valuelen,
                       void *user_data)
{
  auto hd = static_cast<Http2Handler*>(user_data);
  if(hd->get_config()->verbose) {
    print_session_id(hd->session_id());
    verbose_on_header_callback(session, frame, name, namelen, value, valuelen,
                               user_data);
  }
  if(frame->hd.type != NGHTTP2_HEADERS ||
     frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }
  auto stream = hd->get_stream(frame->hd.stream_id);
  if(!stream) {
    return 0;
  }
  if(!http2::check_nv(name, namelen, value, valuelen)) {
    return 0;
  }
  http2::split_add_header(stream->headers, name, namelen, value, valuelen);
  return 0;
}
} // namespace

namespace {
int on_begin_headers_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              void *user_data)
{
  auto hd = static_cast<Http2Handler*>(user_data);
  if(frame->hd.type != NGHTTP2_HEADERS ||
     frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }
  auto stream = util::make_unique<Request>(frame->hd.stream_id);
  hd->add_stream(frame->hd.stream_id, std::move(stream));
  return 0;
}
} // namespace

namespace {
int hd_on_frame_recv_callback
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
  auto hd = static_cast<Http2Handler*>(user_data);
  if(hd->get_config()->verbose) {
    print_session_id(hd->session_id());
    verbose_on_frame_recv_callback(session, frame, user_data);
  }
  switch(frame->hd.type) {
  case NGHTTP2_DATA:
    // TODO Handle POST
    if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      auto stream = hd->get_stream(frame->hd.stream_id);
      if(!stream) {
        return 0;
      }
      prepare_response(stream, hd);
    }
    break;
  case NGHTTP2_HEADERS:
    switch(frame->headers.cat) {
    case NGHTTP2_HCAT_REQUEST: {
      auto stream = hd->get_stream(frame->hd.stream_id);
      if(!stream) {
        return 0;
      }
      http2::normalize_headers(stream->headers);
      if(!http2::check_http2_headers(stream->headers)) {
        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                  frame->hd.stream_id,
                                  NGHTTP2_PROTOCOL_ERROR);
        return 0;
      }
      for(size_t i = 0; REQUIRED_HEADERS[i]; ++i) {
        if(!http2::get_unique_header(stream->headers, REQUIRED_HEADERS[i])) {
          nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                    frame->hd.stream_id,
                                    NGHTTP2_PROTOCOL_ERROR);
          return 0;
        }
      }
      // intermediary translating from HTTP/1 request to HTTP/2 may
      // not produce :authority header field. In this case, it should
      // provide host HTTP/1.1 header field.
      if(!http2::get_unique_header(stream->headers, ":authority") &&
         !http2::get_unique_header(stream->headers, "host")) {
        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                  frame->hd.stream_id,
                                  NGHTTP2_PROTOCOL_ERROR);
        return 0;
      }
      if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
        prepare_response(stream, hd);
      }
      break;
    }
    default:
      break;
    }
    break;
  case NGHTTP2_SETTINGS:
    if(frame->hd.flags & NGHTTP2_FLAG_ACK) {
      hd->remove_settings_timer();
    }
    break;
  case NGHTTP2_PUSH_PROMISE:
    nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                              frame->push_promise.promised_stream_id,
                              NGHTTP2_REFUSED_STREAM);
    break;
  default:
    break;
  }
  return 0;
}
} // namespace

namespace {
int hd_before_frame_send_callback
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
  auto hd = static_cast<Http2Handler*>(user_data);
  if(frame->hd.type == NGHTTP2_PUSH_PROMISE) {
    auto stream_id = frame->push_promise.promised_stream_id;
    auto req = util::make_unique<Request>(stream_id);
    auto nva = http2::sort_nva(frame->push_promise.nva,
                               frame->push_promise.nvlen);
    append_nv(req.get(), nva);
    hd->add_stream(stream_id, std::move(req));
  }
  return 0;
}
} // namespace

namespace {
int hd_on_frame_send_callback
(nghttp2_session *session, const nghttp2_frame *frame,
 void *user_data)
{
  auto hd = static_cast<Http2Handler*>(user_data);
  if(frame->hd.type == NGHTTP2_PUSH_PROMISE) {
    auto stream = hd->get_stream(frame->push_promise.promised_stream_id);
    if(stream) {
      prepare_response(stream, hd, /*allow_push */ false);
    }
  }
  if(hd->get_config()->verbose) {
    print_session_id(hd->session_id());
    verbose_on_frame_send_callback(session, frame, user_data);
  }
  return 0;
}
} // namespace

namespace {
ssize_t select_padding_callback
(nghttp2_session *session, const nghttp2_frame *frame, size_t max_payload,
 void *user_data)
{
  auto hd = static_cast<Http2Handler*>(user_data);
  return std::min(max_payload, frame->hd.length + hd->get_config()->padding);
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
int on_stream_close_callback
(nghttp2_session *session, int32_t stream_id, nghttp2_error_code error_code,
 void *user_data)
{
  auto hd = static_cast<Http2Handler*>(user_data);
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
  callbacks.on_stream_close_callback = on_stream_close_callback;
  callbacks.on_frame_recv_callback = hd_on_frame_recv_callback;
  callbacks.before_frame_send_callback = hd_before_frame_send_callback;
  callbacks.on_frame_send_callback = hd_on_frame_send_callback;
  if(config->verbose) {
    callbacks.on_invalid_frame_recv_callback =
      verbose_on_invalid_frame_recv_callback;
    callbacks.on_unknown_frame_recv_callback =
      verbose_on_unknown_frame_recv_callback;
  }
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks.on_header_callback = on_header_callback;
  callbacks.on_begin_headers_callback = on_begin_headers_callback;
  if(config->padding) {
    callbacks.select_padding_callback = select_padding_callback;
  }
}
} // namespace

struct ClientInfo {
  int fd;
};

namespace {
void worker_readcb(bufferevent *bev, void *arg)
{
  auto sessions = static_cast<Sessions*>(arg);
  auto input = bufferevent_get_input(bev);
  while(evbuffer_get_length(input) >= sizeof(ClientInfo)) {
    ClientInfo client;
    evbuffer_remove(input, &client, sizeof(client));
    sessions->accept_connection(client.fd);
  }
}
} // namespace

namespace {
void run_worker(int thread_id, int fd, SSL_CTX *ssl_ctx, const Config *config)
{
  auto evbase = event_base_new();
  auto bev = bufferevent_socket_new(evbase, fd,
                                    BEV_OPT_DEFER_CALLBACKS |
                                    BEV_OPT_CLOSE_ON_FREE);
  auto sessions = Sessions(evbase, config, ssl_ctx);

  bufferevent_enable(bev, EV_READ);
  bufferevent_setcb(bev, worker_readcb, nullptr, nullptr, &sessions);
  event_base_loop(evbase, 0);
}
} // namespace

class ListenEventHandler {
public:
  ListenEventHandler(Sessions *sessions, const Config *config)
    : sessions_(sessions),
      config_(config),
      next_worker_(0)
  {
    int rv;
    if(config_->num_worker == 1) {
      return;
    }
    for(size_t i = 0; i < config_->num_worker; ++i) {
      if(config_->verbose) {
        std::cerr << "spawning thread #" << i << std::endl;
      }
      int socks[2];
      rv = socketpair(AF_UNIX, SOCK_STREAM, 0, socks);
      if(rv == -1) {
        std::cerr << "socketpair() failed: errno=" << errno << std::endl;
        assert(0);
      }
      evutil_make_socket_nonblocking(socks[0]);
      evutil_make_socket_nonblocking(socks[1]);
      auto bev = bufferevent_socket_new(sessions_->get_evbase(), socks[0],
                                        BEV_OPT_DEFER_CALLBACKS |
                                        BEV_OPT_CLOSE_ON_FREE);
      if(!bev) {
        std::cerr << "bufferevent_socket_new() failed" << std::endl;
        assert(0);
      }
      workers_.push_back(bev);
      auto t = std::thread(run_worker, i, socks[1], sessions_->get_ssl_ctx(),
                           config_);
      t.detach();
    }
  }
  void accept_connection(int fd, sockaddr *addr, int addrlen)
  {
    if(config_->num_worker == 1) {
      sessions_->accept_connection(fd);
      return;
    }
    // Dispatch client to the one of the worker threads, in a round
    // robin manner.
    auto client = ClientInfo{fd};
    bufferevent_write(workers_[next_worker_], &client, sizeof(client));
    if(next_worker_ == config_->num_worker - 1) {
      next_worker_ = 0;
    } else {
      ++next_worker_;
    }
  }
private:
  // In multi threading mode, this includes bufferevent to dispatch
  // client to the worker threads.
  std::vector<bufferevent*> workers_;
  Sessions *sessions_;
  const Config *config_;
  // In multi threading mode, this points to the next thread that
  // client will be dispatched.
  size_t next_worker_;
};

HttpServer::HttpServer(const Config *config)
  : config_(config)
{}

namespace {
int next_proto_cb(SSL *s, const unsigned char **data, unsigned int *len,
                  void *arg)
{
  auto next_proto = static_cast<std::pair<unsigned char*, size_t>* >(arg);
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
  auto handler = static_cast<ListenEventHandler*>(arg);
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
int start_listen(event_base *evbase, Sessions *sessions, const Config *config)
{
  addrinfo hints;
  int r;
  char service[10];
  snprintf(service, sizeof(service), "%u", config->port);
  memset(&hints, 0, sizeof(addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif // AI_ADDRCONFIG

  auto listen_handler = new ListenEventHandler(sessions, config);

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
        (evbase, evlistener_acceptcb, listen_handler,
         LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1, fd);
      evconnlistener_set_error_cb(evlistener, evlistener_errorcb);

      if(config->verbose) {
        std::cout << (rp->ai_family == AF_INET ? "IPv4" : "IPv6")
                  << ": listen on port "
                  << config->port << std::endl;
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

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
namespace {
int alpn_select_proto_cb(SSL* ssl,
                         const unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
  auto config = static_cast<HttpServer*>(arg)->get_config();
  if(config->verbose) {
    std::cout << "[ALPN] client offers:" << std::endl;
  }
  if(config->verbose) {
    for(unsigned int i = 0; i < inlen; i += in[i]+1) {
      std::cout << " * ";
      std::cout.write(reinterpret_cast<const char*>(&in[i+1]), in[i]);
      std::cout << std::endl;
    }
  }
  if(nghttp2_select_next_protocol(const_cast<unsigned char**>(out), outlen,
                                  in, inlen) <= 0) {
    return SSL_TLSEXT_ERR_NOACK;
  }
  return SSL_TLSEXT_ERR_OK;
}
} // namespace
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

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

    SSL_CTX_set_options(ssl_ctx,
                        SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION |
                        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
                        SSL_OP_SINGLE_ECDH_USE |
                        SSL_OP_NO_TICKET);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

    const unsigned char sid_ctx[] = "nghttpd";
    SSL_CTX_set_session_id_context(ssl_ctx, sid_ctx, sizeof(sid_ctx)-1);
    SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER);

#ifndef OPENSSL_NO_EC

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
#else // OPENSSL_VERSION_NUBMER < 0x10002000L
    // Use P-256, which is sufficiently secure at the time of this
    // writing.
    auto ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if(ecdh == nullptr) {
      std::cerr << "EC_KEY_new_by_curv_name failed: "
                << ERR_error_string(ERR_get_error(), nullptr);
      return -1;
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
    EC_KEY_free(ecdh);
#endif // OPENSSL_VERSION_NUBMER < 0x10002000L

#endif /* OPENSSL_NO_EC */

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

    proto_list[0] = NGHTTP2_PROTO_VERSION_ID_LEN;
    memcpy(&proto_list[1], NGHTTP2_PROTO_VERSION_ID,
           NGHTTP2_PROTO_VERSION_ID_LEN);
    next_proto.first = proto_list;
    next_proto.second = proto_list[0] + 1;

    SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, &next_proto);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    // ALPN selection callback
    SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, this);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
  }

  auto evbase = event_base_new();
  Sessions sessions(evbase, config_, ssl_ctx);
  if(start_listen(evbase, &sessions, config_) != 0) {
    std::cerr << "Could not listen" << std::endl;
    return -1;
  }
  event_base_loop(evbase, 0);
  return 0;
}

const Config* HttpServer::get_config() const
{
  return config_;
}

} // namespace nghttp2
