/*
 * nghttp2 - HTTP/2 C Library
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
#include "nghttp2_config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <getopt.h>

#include <cassert>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <string>
#include <set>
#include <iomanip>
#include <fstream>
#include <map>
#include <vector>
#include <sstream>
#include <tuple>
#include <chrono>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>

#include <nghttp2/nghttp2.h>

#include "http-parser/http_parser.h"

#include "app_helper.h"
#include "HtmlParser.h"
#include "util.h"
#include "base64.h"
#include "http2.h"
#include "nghttp2_gzip.h"

#ifndef O_BINARY
# define O_BINARY (0)
#endif // O_BINARY

namespace nghttp2 {

namespace {
struct Config {
  std::vector<std::pair<std::string, std::string>> headers;
  std::string certfile;
  std::string keyfile;
  std::string datafile;
  nghttp2_option *http2_option;
  size_t output_upper_thres;
  size_t padding;
  ssize_t peer_max_concurrent_streams;
  ssize_t header_table_size;
  int32_t weight;
  int multiply;
  // milliseconds
  int timeout;
  int window_bits;
  int connection_window_bits;
  bool null_out;
  bool remote_name;
  bool verbose;
  bool get_assets;
  bool stat;
  bool upgrade;
  bool continuation;
  bool no_content_length;

  Config()
    : output_upper_thres(1024*1024),
      padding(0),
      peer_max_concurrent_streams(NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS),
      header_table_size(-1),
      weight(NGHTTP2_DEFAULT_WEIGHT),
      multiply(1),
      timeout(-1),
      window_bits(-1),
      connection_window_bits(-1),
      null_out(false),
      remote_name(false),
      verbose(false),
      get_assets(false),
      stat(false),
      upgrade(false),
      continuation(false),
      no_content_length(false)
  {
    nghttp2_option_new(&http2_option);
    nghttp2_option_set_peer_max_concurrent_streams
      (http2_option,
       peer_max_concurrent_streams);
  }

  ~Config()
  {
    nghttp2_option_del(http2_option);
  }
};
} // namespace

enum StatStage {
  STAT_INITIAL,
  STAT_ON_REQUEST,
  STAT_ON_RESPONSE,
  STAT_ON_COMPLETE
};

namespace {
struct RequestStat {
  std::chrono::steady_clock::time_point on_request_time;
  std::chrono::steady_clock::time_point on_response_time;
  std::chrono::steady_clock::time_point on_complete_time;
  StatStage stage;
  RequestStat():stage(STAT_INITIAL) {}
};
} // namespace

namespace {
std::string strip_fragment(const char *raw_uri)
{
  const char *end;
  for(end = raw_uri; *end && *end != '#'; ++end);
  size_t len = end-raw_uri;
  return std::string(raw_uri, len);
}
} // namespace

namespace {
struct Request;
} // namespace

namespace {
struct Dependency {
  std::vector<std::vector<Request*>> deps;
};
} // namespace

namespace {
struct Request {
  Headers res_nva;
  Headers push_req_nva;
  // URI without fragment
  std::string uri;
  std::string status;
  http_parser_url u;
  std::shared_ptr<Dependency> dep;
  nghttp2_priority_spec pri_spec;
  RequestStat stat;
  int64_t data_length;
  int64_t data_offset;
  nghttp2_gzip *inflater;
  HtmlParser *html_parser;
  const nghttp2_data_provider *data_prd;
  int32_t stream_id;
  // Recursion level: 0: first entity, 1: entity linked from first entity
  int level;
  // RequestPriority value defined in HtmlParser.h
  int pri;

  // For pushed request, |uri| is empty and |u| is zero-cleared.
  Request(const std::string& uri, const http_parser_url &u,
          const nghttp2_data_provider *data_prd, int64_t data_length,
          const nghttp2_priority_spec& pri_spec,
          std::shared_ptr<Dependency> dep, int pri = 0, int level = 0)
    : uri(uri),
      u(u),
      dep(std::move(dep)),
      pri_spec(pri_spec),
      data_length(data_length),
      data_offset(0),
      inflater(nullptr),
      html_parser(nullptr),
      data_prd(data_prd),
      stream_id(-1),
      level(level),
      pri(pri)
  {}

  ~Request()
  {
    nghttp2_gzip_inflate_del(inflater);
    delete html_parser;
  }

  void init_inflater()
  {
    int rv;
    rv = nghttp2_gzip_inflate_new(&inflater);
    assert(rv == 0);
  }

  void init_html_parser()
  {
    html_parser = new HtmlParser(uri);
  }

  int update_html_parser(const uint8_t *data, size_t len, int fin)
  {
    if(!html_parser) {
      return 0;
    }
    int rv;
    rv = html_parser->parse_chunk(reinterpret_cast<const char*>(data), len,
                                  fin);
    return rv;
  }

  std::string make_reqpath() const
  {
    std::string path = util::has_uri_field(u, UF_PATH) ?
      util::get_uri_field(uri.c_str(), u, UF_PATH) : "/";
    if(util::has_uri_field(u, UF_QUERY)) {
      path += "?";
      path.append(uri.c_str()+u.field_data[UF_QUERY].off,
                  u.field_data[UF_QUERY].len);
    }
    return path;
  }

  int32_t find_dep_stream_id(int start)
  {
    for(auto i = start; i >= 0; --i) {
      for(auto req : dep->deps[i]) {
        return req->stream_id;
      }
    }
    return -1;
  }

  nghttp2_priority_spec resolve_dep(int32_t pri)
  {
    nghttp2_priority_spec pri_spec;
    int exclusive = 0;
    int32_t stream_id = -1;

    nghttp2_priority_spec_default_init(&pri_spec);

    if(pri == 0) {
      return pri_spec;
    }

    nghttp2_priority_spec_default_init(&pri_spec);

    auto start = std::min(pri, (int)dep->deps.size() - 1);

    for(auto i = start; i >= 0; --i) {
      if(dep->deps[i][0]->pri < pri) {
        stream_id = find_dep_stream_id(i);

        if(i != (int)dep->deps.size() - 1) {
          exclusive = 1;
        }

        break;
      } else if(dep->deps[i][0]->pri == pri) {
        stream_id = find_dep_stream_id(i - 1);

        break;
      }
    }

    if(stream_id == -1) {
      return pri_spec;
    }

    nghttp2_priority_spec_init(&pri_spec, stream_id, NGHTTP2_DEFAULT_WEIGHT,
                               exclusive);

    return pri_spec;
  }

  bool is_ipv6_literal_addr() const
  {
    if(util::has_uri_field(u, UF_HOST)) {
      return memchr(uri.c_str()+u.field_data[UF_HOST].off, ':',
                    u.field_data[UF_HOST].len);
    } else {
      return false;
    }
  }

  void record_request_time()
  {
    stat.stage = STAT_ON_REQUEST;
    stat.on_request_time = get_time();
  }

  void record_response_time()
  {
    stat.stage = STAT_ON_RESPONSE;
    stat.on_response_time = get_time();
  }

  void record_complete_time()
  {
    stat.stage = STAT_ON_COMPLETE;
    stat.on_complete_time = get_time();
  }
};
} // namespace

namespace {
struct SessionStat {
  std::chrono::steady_clock::time_point on_handshake_time;
};
} // namespace

namespace {
Config config;
} // namespace

namespace {
size_t populate_settings(nghttp2_settings_entry *iv)
{
  size_t niv = 2;

  iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = 100;

  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  if(config.window_bits != -1) {
    iv[1].value = (1 << config.window_bits) - 1;
  } else {
    iv[1].value = NGHTTP2_INITIAL_WINDOW_SIZE;
  }

  if(config.header_table_size >= 0) {
    iv[niv].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
    iv[niv].value = config.header_table_size;
    ++niv;
  }
  return niv;
}
} // namespace

namespace {
void eventcb(bufferevent *bev, short events, void *ptr);
} // namespace

namespace {
extern http_parser_settings htp_hooks;
} // namespace

namespace {
void upgrade_readcb(bufferevent *bev, void *ptr);
} // namespace

namespace {
void readcb(bufferevent *bev, void *ptr);
} // namespace

namespace {
void writecb(bufferevent *bev, void *ptr);
} // namespace

namespace {
struct HttpClient;
} // namespace

namespace {
int submit_request
(HttpClient *client,
 const std::vector<std::pair<std::string, std::string>>& headers,
 Request *req);
} // namespace

namespace {
void settings_timeout_cb(evutil_socket_t fd, short what, void *arg);
} // namespace

enum client_state {
  STATE_IDLE,
  STATE_CONNECTED
};

namespace {
struct HttpClient {
  std::vector<std::unique_ptr<Request>> reqvec;
  // Insert path already added in reqvec to prevent multiple request
  // for 1 resource.
  std::set<std::string> path_cache;
  std::string scheme;
  std::string host;
  std::string hostport;
  // Used for parse the HTTP upgrade response from server
  std::unique_ptr<http_parser> htp;
  SessionStat stat;
  nghttp2_session *session;
  const nghttp2_session_callbacks *callbacks;
  event_base *evbase;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  bufferevent *bev;
  event *settings_timerev;
  addrinfo *addrs;
  addrinfo *next_addr;
  // The number of completed requests, including failed ones.
  size_t complete;
  // The length of settings_payload
  size_t settings_payloadlen;
  client_state state;
  // The HTTP status code of the response message of HTTP Upgrade.
  unsigned int upgrade_response_status_code;
  // true if the response message of HTTP Upgrade request is fully
  // received. It is not relevant the upgrade succeeds, or not.
  bool upgrade_response_complete;
  // SETTINGS payload sent as token68 in HTTP Upgrade
  uint8_t settings_payload[128];

  HttpClient(const nghttp2_session_callbacks* callbacks,
             event_base *evbase, SSL_CTX *ssl_ctx)
    : session(nullptr),
      callbacks(callbacks),
      evbase(evbase),
      ssl_ctx(ssl_ctx),
      ssl(nullptr),
      bev(nullptr),
      settings_timerev(nullptr),
      addrs(nullptr),
      next_addr(nullptr),
      complete(0),
      settings_payloadlen(0),
      state(STATE_IDLE),
      upgrade_response_status_code(0),
      upgrade_response_complete(false)
  {}

  ~HttpClient()
  {
    disconnect();
    if(addrs) {
      freeaddrinfo(addrs);
      addrs = nullptr;
      next_addr = nullptr;
    }
  }

  bool need_upgrade() const
  {
    return config.upgrade && scheme == "http";
  }

  int resolve_host(const std::string& host, uint16_t port)
  {
    int rv;
    addrinfo hints;
    this->host = host;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_ADDRCONFIG;
    rv = getaddrinfo(host.c_str(), util::utos(port).c_str(), &hints, &addrs);
    if(rv != 0) {
      std::cerr << "getaddrinfo() failed: "
                << gai_strerror(rv) << std::endl;
      return -1;
    }
    if(addrs == nullptr) {
      std::cerr << "No address returned" << std::endl;
      return -1;
    }
    next_addr = addrs;
    return 0;
  }

  int initiate_connection()
  {
    int rv = 0;
    if(ssl_ctx) {
      // We are establishing TLS connection.
      ssl = SSL_new(ssl_ctx);
      if(!ssl) {
        std::cerr << "SSL_new() failed: "
                  << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return -1;
      }

      // If the user overrode the host header, use that value for the
      // SNI extension
      const char *host_string = nullptr;
      auto i = std::find_if(std::begin(config.headers),
                            std::end(config.headers),
                            [](const std::pair<std::string, std::string>& nv)
                            {
                              return util::strieq("host", nv.first.c_str());
                            });
      if ( i != std::end(config.headers) ) {
        host_string = (*i).second.c_str();
      } else {
        host_string = host.c_str();
      }

      if (!util::numeric_host(host_string)) {
        SSL_set_tlsext_host_name(ssl, host_string);
      }

      bev = bufferevent_openssl_socket_new(evbase, -1, ssl,
                                           BUFFEREVENT_SSL_CONNECTING,
                                           BEV_OPT_DEFER_CALLBACKS);
    } else {
      bev = bufferevent_socket_new(evbase, -1, BEV_OPT_DEFER_CALLBACKS);
    }
    rv = -1;
    while(next_addr) {
      rv = bufferevent_socket_connect
        (bev, next_addr->ai_addr, next_addr->ai_addrlen);
      next_addr = next_addr->ai_next;
      if(rv == 0) {
        break;
      }
    }
    if(rv != 0) {
      return -1;
    }
    bufferevent_enable(bev, EV_READ);
    if(need_upgrade()) {
      htp = util::make_unique<http_parser>();
      http_parser_init(htp.get(), HTTP_RESPONSE);
      htp->data = this;
      bufferevent_setcb(bev, upgrade_readcb, nullptr, eventcb, this);
    } else {
      bufferevent_setcb(bev, readcb, writecb, eventcb, this);
    }
    if(config.timeout != -1) {
      timeval tv = { config.timeout, 0 };
      bufferevent_set_timeouts(bev, &tv, &tv);
    }
    return 0;
  }

  void disconnect()
  {
    int fd = -1;
    state = STATE_IDLE;
    nghttp2_session_del(session);
    session = nullptr;
    if(ssl) {
      fd = SSL_get_fd(ssl);
      SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
      SSL_shutdown(ssl);
    }
    if(bev) {
      bufferevent_disable(bev, EV_READ | EV_WRITE);
      bufferevent_free(bev);
      bev = nullptr;
    }
    if(settings_timerev) {
      event_free(settings_timerev);
      settings_timerev = nullptr;
    }
    if(ssl) {
      SSL_free(ssl);
      ssl = nullptr;
    }
    if(fd != -1) {
      shutdown(fd, SHUT_WR);
      close(fd);
    }
  }

  int on_upgrade_connect()
  {
    ssize_t rv;
    record_handshake_time();
    assert(!reqvec.empty());
    nghttp2_settings_entry iv[32];
    size_t niv = populate_settings(iv);
    assert(sizeof(settings_payload) >= 8*niv);
    rv = nghttp2_pack_settings_payload(settings_payload,
                                       sizeof(settings_payload), iv, niv);
    if(rv < 0) {
      return -1;
    }
    settings_payloadlen = rv;
    auto token68 = base64::encode(&settings_payload[0],
                                  &settings_payload[settings_payloadlen]);
    util::to_token68(token68);
    std::string req;
    if(reqvec[0]->data_prd) {
      // If the request contains upload data, use OPTIONS * to upgrade
      req = "OPTIONS *";
    } else {
      req = "GET ";
      req += reqvec[0]->make_reqpath();
    }
    req += " HTTP/1.1\r\n"
      "Host: ";
    req += hostport;
    req += "\r\n"
      "Connection: Upgrade, HTTP2-Settings\r\n"
      "Upgrade: " NGHTTP2_CLEARTEXT_PROTO_VERSION_ID "\r\n"
      "HTTP2-Settings: ";
    req += token68;
    req += "\r\n"
      "Accept: */*\r\n"
      "User-Agent: nghttp2/" NGHTTP2_VERSION "\r\n"
      "\r\n";
    bufferevent_write(bev, req.c_str(), req.size());
    if(config.verbose) {
      print_timer();
      std::cout << " HTTP Upgrade request\n"
                << req << std::endl;
    }
    return 0;
  }

  int on_upgrade_read()
  {
    int rv;
    auto input = bufferevent_get_input(bev);

    for(;;) {
      auto inputlen = evbuffer_get_contiguous_space(input);

      if(inputlen == 0) {
        assert(evbuffer_get_length(input) == 0);

        return 0;
      }

      auto mem = evbuffer_pullup(input, inputlen);

      auto nread = http_parser_execute(htp.get(), &htp_hooks,
                                       reinterpret_cast<const char*>(mem),
                                       inputlen);

      if(config.verbose) {
        std::cout.write(reinterpret_cast<const char*>(mem), nread);
      }

      if(evbuffer_drain(input, nread) != 0) {
        return -1;
      }

      auto htperr = HTTP_PARSER_ERRNO(htp.get());

      if(htperr != HPE_OK) {
        std::cerr << "Failed to parse HTTP Upgrade response header: "
                  << "(" << http_errno_name(htperr) << ") "
                  << http_errno_description(htperr) << std::endl;
        return -1;
      }

      if(upgrade_response_complete) {

        if(config.verbose) {
          std::cout << std::endl;
        }

        if(upgrade_response_status_code == 101) {
          if(config.verbose) {
            print_timer();
            std::cout << " HTTP Upgrade success" << std::endl;
          }

          bufferevent_setcb(bev, readcb, writecb, eventcb, this);

          rv = on_connect();

          if(rv != 0) {
            return rv;
          }

          // Read remaining data in the buffer because it is not
          // notified callback anymore.
          rv = on_read();

          if(rv != 0) {
            return rv;
          }

          return 0;
        }

        std::cerr << "HTTP Upgrade failed" << std::endl;

        return -1;
      }
    }
  }

  int on_connect()
  {
    int rv;
    if(!need_upgrade()) {
      record_handshake_time();
    }

    rv = nghttp2_session_client_new2(&session, callbacks, this,
                                     config.http2_option);

    if(rv != 0) {
      return -1;
    }
    if(need_upgrade()) {
      // Adjust stream user-data depending on the existence of upload
      // data
      Request *stream_user_data = nullptr;
      if(!reqvec[0]->data_prd) {
        stream_user_data = reqvec[0].get();
      }
      rv = nghttp2_session_upgrade(session, settings_payload,
                                   settings_payloadlen, stream_user_data);
      if(rv != 0) {
        std::cerr << "nghttp2_session_upgrade() returned error: "
                  << nghttp2_strerror(rv) << std::endl;
        return -1;
      }
      if(stream_user_data) {
        stream_user_data->stream_id = 1;
        on_request(stream_user_data);
      }
    }
    // Send connection header here
    bufferevent_write(bev, NGHTTP2_CLIENT_CONNECTION_PREFACE,
                      NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN);
    // If upgrade succeeds, the SETTINGS value sent with
    // HTTP2-Settings header field has already been submitted to
    // session object.
    if(!need_upgrade()) {
      nghttp2_settings_entry iv[16];
      auto niv = populate_settings(iv);
      rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, niv);
      if(rv != 0) {
        return -1;
      }
    }
    assert(settings_timerev == nullptr);
    settings_timerev = evtimer_new(evbase, settings_timeout_cb, this);
    // SETTINGS ACK timeout is 10 seconds for now
    timeval settings_timeout = { 10, 0 };
    evtimer_add(settings_timerev, &settings_timeout);

    if(config.connection_window_bits != -1) {
      int32_t wininc = (1 << config.connection_window_bits) - 1
        - NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE;
      rv = nghttp2_submit_window_update
        (session, NGHTTP2_FLAG_NONE, 0, wininc);
      if(rv != 0) {
        return -1;
      }
    }
    // Adjust first request depending on the existence of the upload
    // data
    for(auto i = std::begin(reqvec)+(need_upgrade() && !reqvec[0]->data_prd);
        i != std::end(reqvec); ++i) {
      if(submit_request(this, config.headers, (*i).get()) != 0) {
        return -1;
      }
    }
    return on_write();
  }

  int on_read()
  {
    int rv;
    auto input = bufferevent_get_input(bev);

    for(;;) {
      auto inputlen = evbuffer_get_contiguous_space(input);

      if(inputlen == 0) {
        assert(evbuffer_get_length(input) == 0);

        return on_write();
      }

      auto mem = evbuffer_pullup(input, inputlen);

      rv = nghttp2_session_mem_recv(session, mem, inputlen);

      if(rv < 0) {
        std::cerr << "nghttp2_session_mem_recv() returned error: "
                  << nghttp2_strerror(rv) << std::endl;
        return -1;
      }

      if(evbuffer_drain(input, rv) != 0) {
        return -1;
      }
    }
  }

  int on_write()
  {
    int rv;
    uint8_t buf[4096];
    auto output = bufferevent_get_output(bev);
    util::EvbufferBuffer evbbuf(output, buf, sizeof(buf));
    for(;;) {
      if(evbuffer_get_length(output) + evbbuf.get_buflen() >
         config.output_upper_thres) {
        break;
      }

      const uint8_t *data;
      auto datalen = nghttp2_session_mem_send(session, &data);

      if(datalen < 0) {
        std::cerr << "nghttp2_session_mem_send() returned error: "
                  << nghttp2_strerror(datalen) << std::endl;
        return -1;
      }
      if(datalen == 0) {
        break;
      }
      rv = evbbuf.add(data, datalen);
      if(rv != 0) {
        std::cerr << "evbuffer_add() failed" << std::endl;
        return -1;
      }
    }
    rv = evbbuf.flush();
    if(rv != 0) {
      std::cerr << "evbuffer_add() failed" << std::endl;
      return -1;
    }
    if(nghttp2_session_want_read(session) == 0 &&
       nghttp2_session_want_write(session) == 0 &&
       evbuffer_get_length(output) == 0) {
      return -1;
    }
    return 0;
  }

  bool all_requests_processed() const
  {
    return complete == reqvec.size();
  }
  void update_hostport()
  {
    if(reqvec.empty()) {
      return;
    }
    scheme = util::get_uri_field(reqvec[0]->uri.c_str(), reqvec[0]->u,
                                 UF_SCHEMA);
    std::stringstream ss;
    if(reqvec[0]->is_ipv6_literal_addr()) {
      ss << "[";
      util::write_uri_field(ss, reqvec[0]->uri.c_str(), reqvec[0]->u, UF_HOST);
      ss << "]";
    } else {
      util::write_uri_field(ss, reqvec[0]->uri.c_str(), reqvec[0]->u, UF_HOST);
    }
    if(util::has_uri_field(reqvec[0]->u, UF_PORT) &&
       reqvec[0]->u.port != util::get_default_port(reqvec[0]->uri.c_str(),
                                                   reqvec[0]->u)) {
      ss << ":" << reqvec[0]->u.port;
    }
    hostport = ss.str();
  }
  bool add_request(const std::string& uri,
                   const nghttp2_data_provider *data_prd,
                   int64_t data_length,
                   const nghttp2_priority_spec& pri_spec,
                   std::shared_ptr<Dependency> dep,
                   int pri = 0, int level = 0)
  {
    http_parser_url u;
    memset(&u, 0, sizeof(u));
    if(http_parser_parse_url(uri.c_str(), uri.size(), 0, &u) != 0) {
      return false;
    }
    if(path_cache.count(uri)) {
      return false;
    }

    if(config.multiply == 1) {
      path_cache.insert(uri);
    }

    reqvec.push_back(util::make_unique<Request>(uri, u, data_prd,
                                                data_length,
                                                pri_spec, std::move(dep),
                                                pri, level));
    return true;
  }
  void record_handshake_time()
  {
    stat.on_handshake_time = get_time();
  }

  void on_request(Request *req)
  {
    req->record_request_time();

    if(req->pri == 0 && req->dep) {
      assert(req->dep->deps.empty());

      req->dep->deps.push_back(std::vector<Request*>{req});

      return;
    }

    if(req->stream_id % 2 == 0) {
      return;
    }

    auto itr = std::begin(req->dep->deps);
    for(; itr != std::end(req->dep->deps); ++itr) {
      if((*itr)[0]->pri == req->pri) {
        (*itr).push_back(req);

        break;
      }

      if((*itr)[0]->pri > req->pri) {
        auto v = std::vector<Request*>{req};
        req->dep->deps.insert(itr, std::move(v));

        break;
      }
    }

    if(itr == std::end(req->dep->deps)) {
      req->dep->deps.push_back(std::vector<Request*>{req});
    }
  }
};
} // namespace

namespace {
int htp_msg_begincb(http_parser *htp)
{
  if(config.verbose) {
    print_timer();
    std::cout << " HTTP Upgrade response" << std::endl;
  }
  return 0;
}
} // namespace

namespace {
int htp_statuscb(http_parser *htp, const char *at, size_t length)
{
  auto client = static_cast<HttpClient*>(htp->data);
  client->upgrade_response_status_code = htp->status_code;
  return 0;
}
} // namespace

namespace {
int htp_msg_completecb(http_parser *htp)
{
  auto client = static_cast<HttpClient*>(htp->data);
  client->upgrade_response_complete = true;
  return 0;
}
} // namespace

namespace {
http_parser_settings htp_hooks = {
  htp_msg_begincb, // http_cb      on_message_begin;
  nullptr, // http_data_cb on_url;
  htp_statuscb, // http_data_cb on_status;
  nullptr, // http_data_cb on_header_field;
  nullptr, // http_data_cb on_header_value;
  nullptr, // http_cb      on_headers_complete;
  nullptr, // http_data_cb on_body;
  htp_msg_completecb // http_cb      on_message_complete;
};
} // namespace

namespace {
int submit_request
(HttpClient *client,
 const std::vector<std::pair<std::string, std::string>>& headers,
 Request *req)
{
  auto path = req->make_reqpath();
  auto scheme = util::get_uri_field(req->uri.c_str(), req->u, UF_SCHEMA);
  auto build_headers = Headers
    {{":method", req->data_prd ? "POST" : "GET"},
     {":path", path},
     {":scheme", scheme},
     {":authority", client->hostport},
     {"accept", "*/*"},
     {"accept-encoding", "gzip, deflate"},
     {"user-agent", "nghttp2/" NGHTTP2_VERSION}};
  if(config.continuation) {
    for(size_t i = 0; i < 6; ++i) {
      build_headers.emplace_back("continuation-test-" + util::utos(i+1),
                                 std::string(4096, '-'));
    }
  }
  auto num_initial_headers = build_headers.size();
  if(!config.no_content_length && req->data_prd) {
    build_headers.emplace_back("content-length", util::utos(req->data_length));
  }
  for(auto& kv : headers) {
    size_t i;
    for(i = 0; i < num_initial_headers; ++i) {
      if(util::strieq(kv.first, build_headers[i].name)) {
        build_headers[i].value = kv.second;
        break;
      }
    }
    if(i < num_initial_headers) {
      continue;
    }

    // To test "never index" repr, don't index authorization header
    // field unconditionally.
    auto no_index = util::strieq(kv.first, "authorization");
    build_headers.emplace_back(kv.first, kv.second, no_index);
  }
  std::stable_sort(std::begin(build_headers), std::end(build_headers),
                   [](const Headers::value_type& lhs,
                      const Headers::value_type& rhs)
                   {
                     return lhs.name < rhs.name;
                   });

  auto nva = std::vector<nghttp2_nv>();
  nva.reserve(build_headers.size());

  for(auto& kv : build_headers) {
    nva.push_back(http2::make_nv(kv.name, kv.value, kv.no_index));
  }

  auto stream_id = nghttp2_submit_request(client->session, &req->pri_spec,
                                          nva.data(), nva.size(),
                                          req->data_prd, req);
  if(stream_id < 0) {
    std::cerr << "nghttp2_submit_request() returned error: "
              << nghttp2_strerror(stream_id) << std::endl;
    return -1;
  }

  req->stream_id = stream_id;
  client->on_request(req);

  return 0;
}
} // namespace

namespace {
void update_html_parser(HttpClient *client, Request *req,
                        const uint8_t *data, size_t len, int fin)
{
  if(!req->html_parser) {
    return;
  }
  req->update_html_parser(data, len, fin);

  for(auto& p : req->html_parser->get_links()) {
    auto uri = strip_fragment(p.first.c_str());
    auto pri = p.second;

    http_parser_url u;
    memset(&u, 0, sizeof(u));
    if(http_parser_parse_url(uri.c_str(), uri.size(), 0, &u) == 0 &&
       util::fieldeq(uri.c_str(), u, req->uri.c_str(), req->u, UF_SCHEMA) &&
       util::fieldeq(uri.c_str(), u, req->uri.c_str(), req->u, UF_HOST) &&
       util::porteq(uri.c_str(), u, req->uri.c_str(), req->u)) {
      // No POST data for assets
      auto pri_spec = req->resolve_dep(pri);

      if ( client->add_request(uri, nullptr, 0, pri_spec, req->dep,
                               pri, req->level+1) ) {

        submit_request(client, config.headers,
                       client->reqvec.back().get());
      }
    }
  }
  req->html_parser->clear_links();
}
} // namespace

namespace {
HttpClient* get_session(void *user_data)
{
  return static_cast<HttpClient*>(user_data);
}
} // namespace

namespace {
int on_data_chunk_recv_callback
(nghttp2_session *session, uint8_t flags, int32_t stream_id,
 const uint8_t *data, size_t len, void *user_data)
{
  auto client = get_session(user_data);
  auto req =
    (Request*)nghttp2_session_get_stream_user_data(session, stream_id);

  if(!req) {
    return 0;
  }

  if(req->inflater) {
    while(len > 0) {
      const size_t MAX_OUTLEN = 4096;
      uint8_t out[MAX_OUTLEN];
      size_t outlen = MAX_OUTLEN;
      size_t tlen = len;
      int rv = nghttp2_gzip_inflate(req->inflater, out, &outlen, data, &tlen);
      if(rv != 0) {
        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id,
                                  NGHTTP2_INTERNAL_ERROR);
        break;
      }
      if(!config.null_out) {
        std::cout.write(reinterpret_cast<const char*>(out), outlen);
      }
      update_html_parser(client, req, out, outlen, 0);
      data += tlen;
      len -= tlen;
    }

    return 0;
  }

  if(!config.null_out) {
    std::cout.write(reinterpret_cast<const char*>(data), len);
  }

  update_html_parser(client, req, data, len, 0);

  return 0;
}
} // namespace

namespace {
void settings_timeout_cb(evutil_socket_t fd, short what, void *arg)
{
  int rv;
  auto client = get_session(arg);
  nghttp2_session_terminate_session(client->session, NGHTTP2_SETTINGS_TIMEOUT);
  rv = client->on_write();
  if(rv != 0) {
    client->disconnect();
  }
}
} // namespace

namespace {
ssize_t select_padding_callback
(nghttp2_session *session, const nghttp2_frame *frame, size_t max_payload,
 void *user_data)
{
  return std::min(max_payload, frame->hd.length + config.padding);
}
} // namespace

namespace {
void check_response_header(nghttp2_session *session, Request* req)
{
  bool gzip = false;
  for(auto& nv : req->res_nva) {
    if("content-encoding" == nv.name) {
      gzip = util::strieq("gzip", nv.value) ||
        util::strieq("deflate", nv.value);
      continue;
    }
    if(":status" == nv.name) {
      req->status.assign(nv.value);
    }
  }
  if(gzip) {
    if(!req->inflater) {
      req->init_inflater();
    }
  }
  if(config.get_assets && req->level == 0) {
    if(!req->html_parser) {
      req->init_html_parser();
    }
  }
}
} // namespace

namespace {
int on_begin_headers_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              void *user_data)
{
  auto client = get_session(user_data);
  switch(frame->hd.type) {
  case NGHTTP2_PUSH_PROMISE: {
    auto stream_id = frame->push_promise.promised_stream_id;
    http_parser_url u;
    memset(&u, 0, sizeof(u));
    // TODO Set pri and level
    nghttp2_priority_spec pri_spec;

    nghttp2_priority_spec_default_init(&pri_spec);

    auto req = util::make_unique<Request>("", u, nullptr, 0, pri_spec,
                                          nullptr);
    req->stream_id = stream_id;

    nghttp2_session_set_stream_user_data(session, stream_id, req.get());

    client->on_request(req.get());
    client->reqvec.push_back(std::move(req));

    break;
  }
  }
  return 0;
}
} //namespace

namespace {
int on_header_callback(nghttp2_session *session,
                       const nghttp2_frame *frame,
                       const uint8_t *name, size_t namelen,
                       const uint8_t *value, size_t valuelen,
                       uint8_t flags,
                       void *user_data)
{
  if(config.verbose) {
    verbose_on_header_callback(session, frame, name, namelen, value, valuelen,
                               flags, user_data);
  }
  switch(frame->hd.type) {
  case NGHTTP2_HEADERS: {
    if(frame->headers.cat != NGHTTP2_HCAT_RESPONSE &&
       frame->headers.cat != NGHTTP2_HCAT_PUSH_RESPONSE) {
      break;
    }
    auto req = (Request*)nghttp2_session_get_stream_user_data
      (session, frame->hd.stream_id);
    if(!req) {
      break;
    }
    http2::add_header(req->res_nva, name, namelen, value, valuelen,
                      flags & NGHTTP2_NV_FLAG_NO_INDEX);
    break;
  }
  case NGHTTP2_PUSH_PROMISE: {
    auto req = (Request*)nghttp2_session_get_stream_user_data
      (session, frame->push_promise.promised_stream_id);
    if(!req) {
      break;
    }
    http2::add_header(req->push_req_nva, name, namelen, value, valuelen,
                      flags & NGHTTP2_NV_FLAG_NO_INDEX);
    break;
  }
  }
  return 0;
}
} // namespace

namespace {
int on_frame_recv_callback2
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
  int rv = 0;

  auto client = get_session(user_data);
  switch(frame->hd.type) {
  case NGHTTP2_HEADERS: {
    if(frame->headers.cat != NGHTTP2_HCAT_RESPONSE &&
       frame->headers.cat != NGHTTP2_HCAT_PUSH_RESPONSE) {
      break;
    }
    auto req = (Request*)nghttp2_session_get_stream_user_data
      (session, frame->hd.stream_id);
    // If this is the HTTP Upgrade with OPTIONS method to avoid POST,
    // req is nullptr.
    if(req) {
      req->record_response_time();
      check_response_header(session, req);
    }
    break;
  }
  case NGHTTP2_SETTINGS:
    if((frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) {
      break;
    }
    if(client->settings_timerev) {
      evtimer_del(client->settings_timerev);
      event_free(client->settings_timerev);
      client->settings_timerev = nullptr;
    }
    break;
  case NGHTTP2_PUSH_PROMISE: {
    auto req = (Request*)nghttp2_session_get_stream_user_data
      (session, frame->push_promise.promised_stream_id);
    if(!req) {
      break;
    }
    std::string scheme, authority, method, path;
    for(auto& nv : req->push_req_nva) {
      if(nv.name == ":scheme") {
        scheme = nv.value;
        continue;
      }
      if(nv.name == ":authority" || nv.name == "host") {
        authority = nv.value;
        continue;
      }
      if(nv.name == ":method") {
        method = nv.value;
        continue;
      }
      if(nv.name == ":path") {
        path = nv.value;
        continue;
      }
    }
    if(scheme.empty() || authority.empty() || method.empty() || path.empty() ||
       path[0] != '/') {
      nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                frame->push_promise.promised_stream_id,
                                NGHTTP2_PROTOCOL_ERROR);
      break;
    }
    std::string uri = scheme;
    uri += "://";
    uri += authority;
    uri += path;
    http_parser_url u;
    memset(&u, 0, sizeof(u));
    if(http_parser_parse_url(uri.c_str(), uri.size(), 0, &u) != 0) {
      nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                frame->push_promise.promised_stream_id,
                                NGHTTP2_PROTOCOL_ERROR);
      break;
    }
    req->uri = uri;
    req->u = u;
    break;
  }
  }
  if(config.verbose) {
    verbose_on_frame_recv_callback(session, frame, user_data);
  }
  return rv;
}
} // namespace

namespace {
int on_stream_close_callback
(nghttp2_session *session, int32_t stream_id, nghttp2_error_code error_code,
 void *user_data)
{
  auto client = get_session(user_data);
  auto req =
    (Request*)nghttp2_session_get_stream_user_data(session, stream_id);

  if(!req) {
    return 0;
  }

  update_html_parser(client, req, nullptr, 0, 1);
  req->record_complete_time();
  ++client->complete;

  if(client->all_requests_processed()) {
    nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
  }

  return 0;
}
} // namespace

namespace {
void print_stats(const HttpClient& client)
{
  std::cout << "***** Statistics *****" << std::endl;
  int i = 0;
  for(auto& req : client.reqvec) {
    std::cout << "#" << ++i << ": " << req->uri << std::endl;
    std::cout << "    Status: " << req->status << std::endl;
    std::cout << "    Delta (ms) from handshake(HEADERS):"
              << std::endl;
    if(req->stat.stage >= STAT_ON_RESPONSE) {
      std::cout << "        response HEADERS: "
                << time_delta(req->stat.on_response_time,
                              client.stat.on_handshake_time).count()
                << "("
                << time_delta(req->stat.on_response_time,
                              req->stat.on_request_time).count()
                << ")"
                << std::endl;
    }
    if(req->stat.stage >= STAT_ON_COMPLETE) {
      std::cout << "        Completed: "
                << time_delta(req->stat.on_complete_time,
                              client.stat.on_handshake_time).count()
                << "("
                << time_delta(req->stat.on_complete_time,
                              req->stat.on_request_time).count()
                << ")"
                << std::endl;
    }
    std::cout << std::endl;
  }
}
} // namespace

namespace {
void print_protocol_nego_error()
{
  std::cerr << "HTTP/2 protocol was not selected."
            << " (nghttp2 expects " << NGHTTP2_PROTO_VERSION_ID << ")"
            << std::endl;
}
} // namespace

namespace {
int client_select_next_proto_cb(SSL* ssl,
                                unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen,
                                void *arg)
{
  if(config.verbose) {
    print_timer();
    std::cout << "[NPN] server offers:" << std::endl;
  }
  for(unsigned int i = 0; i < inlen; i += in[i]+1) {
    if(config.verbose) {
      std::cout << "          * ";
      std::cout.write(reinterpret_cast<const char*>(&in[i+1]), in[i]);
      std::cout << std::endl;
    }
  }
  if(nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
    print_protocol_nego_error();
    return SSL_TLSEXT_ERR_NOACK;
  }
  return SSL_TLSEXT_ERR_OK;
}
} // namespace

namespace {
void upgrade_readcb(bufferevent *bev, void *ptr)
{
  int rv;
  auto client = static_cast<HttpClient*>(ptr);
  rv = client->on_upgrade_read();
  if(rv != 0) {
    client->disconnect();
  }
}
} // namespace

namespace {
void readcb(bufferevent *bev, void *ptr)
{
  int rv;
  auto client = static_cast<HttpClient*>(ptr);
  rv = client->on_read();
  if(rv != 0) {
    client->disconnect();
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
  auto client = static_cast<HttpClient*>(ptr);
  rv = client->on_write();
  if(rv != 0) {
    client->disconnect();
  }
}
} // namespace

namespace {
void eventcb(bufferevent *bev, short events, void *ptr)
{
  int rv;
  auto client = static_cast<HttpClient*>(ptr);
  if(events & BEV_EVENT_CONNECTED) {
    client->state = STATE_CONNECTED;
    int fd = bufferevent_getfd(bev);
    int val = 1;
    if(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                  reinterpret_cast<char *>(&val), sizeof(val)) == -1) {
      std::cerr << "Setting option TCP_NODELAY failed: errno="
                << errno << std::endl;
    }
    if(client->need_upgrade()) {
      rv = client->on_upgrade_connect();
    } else {
      if(client->ssl) {
        // Check NPN or ALPN result
        const unsigned char *next_proto = nullptr;
        unsigned int next_proto_len;
        SSL_get0_next_proto_negotiated(client->ssl,
                                       &next_proto, &next_proto_len);
        for(int i = 0; i < 2; ++i) {
          if(next_proto) {
            if(config.verbose) {
              std::cout << "The negotiated protocol: ";
              std::cout.write(reinterpret_cast<const char*>(next_proto),
                              next_proto_len);
              std::cout << std::endl;
            }
            if(NGHTTP2_PROTO_VERSION_ID_LEN != next_proto_len ||
               memcmp(NGHTTP2_PROTO_VERSION_ID, next_proto,
                      NGHTTP2_PROTO_VERSION_ID_LEN) != 0) {
              next_proto = nullptr;
            }
            break;
          }
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
          SSL_get0_alpn_selected(client->ssl, &next_proto, &next_proto_len);
#else // OPENSSL_VERSION_NUMBER < 0x10002000L
          break;
#endif // OPENSSL_VERSION_NUMBER < 0x10002000L
        }
        if(!next_proto) {
          print_protocol_nego_error();
          client->disconnect();
          return;
        }
      }
      rv = client->on_connect();
    }
    if(rv != 0) {
      client->disconnect();
      return;
    }
    return;
  }
  if(events & BEV_EVENT_EOF) {
    std::cerr << "EOF" << std::endl;
    auto state = client->state;
    client->disconnect();
    if(state == STATE_IDLE) {
      if(client->initiate_connection() == 0) {
        std::cerr << "Trying next address" << std::endl;
      }
    }
    return;
  }
  if(events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
    if(events & BEV_EVENT_ERROR) {
      if(client->state == STATE_IDLE) {
        std::cerr << "Could not connect to the host" << std::endl;
      } else {
        std::cerr << "Network error" << std::endl;
      }
    } else {
      std::cerr << "Timeout" << std::endl;
    }
    auto state = client->state;
    client->disconnect();
    if(state == STATE_IDLE) {
      if(client->initiate_connection() == 0) {
        std::cerr << "Trying next address" << std::endl;
      }
    }
    return;
  }
}
} // namespace

namespace {
int communicate(const std::string& scheme, const std::string& host,
                uint16_t port,
                std::vector<std::tuple<std::string,
                                       nghttp2_data_provider*,
                                       int64_t>> requests,
                const nghttp2_session_callbacks *callbacks)
{
  int result = 0;
  auto evbase = event_base_new();
  SSL_CTX *ssl_ctx = nullptr;
  if(scheme == "https") {
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if(!ssl_ctx) {
      std::cerr << "Failed to create SSL_CTX: "
                << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
      result = -1;
      goto fin;
    }
    SSL_CTX_set_options(ssl_ctx,
                        SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION |
                        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    if(!config.keyfile.empty()) {
      if(SSL_CTX_use_PrivateKey_file(ssl_ctx, config.keyfile.c_str(),
                                     SSL_FILETYPE_PEM) != 1) {
        std::cerr << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        result = -1;
        goto fin;
      }
    }
    if(!config.certfile.empty()) {
      if(SSL_CTX_use_certificate_chain_file(ssl_ctx,
                                            config.certfile.c_str()) != 1) {
        std::cerr << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        result = -1;
        goto fin;
      }
    }
    SSL_CTX_set_next_proto_select_cb(ssl_ctx,
                                     client_select_next_proto_cb, nullptr);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    unsigned char proto_list[255];
    proto_list[0] = NGHTTP2_PROTO_VERSION_ID_LEN;
    memcpy(&proto_list[1], NGHTTP2_PROTO_VERSION_ID,
           NGHTTP2_PROTO_VERSION_ID_LEN);
    SSL_CTX_set_alpn_protos(ssl_ctx, proto_list, proto_list[0] + 1);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
  }
  {
    HttpClient client{callbacks, evbase, ssl_ctx};

    nghttp2_priority_spec pri_spec;

    if(config.weight != NGHTTP2_DEFAULT_WEIGHT) {
      nghttp2_priority_spec_init(&pri_spec, 0, config.weight, 0);
    } else {
      nghttp2_priority_spec_default_init(&pri_spec);
    }

    for(auto req : requests) {
      for(int i = 0; i < config.multiply; ++i) {
        auto dep = std::make_shared<Dependency>();
        client.add_request(std::get<0>(req), std::get<1>(req),
                           std::get<2>(req), pri_spec, std::move(dep));
      }
    }
    client.update_hostport();
    if(client.resolve_host(host, port) != 0) {
      goto fin;
    }
    if(client.initiate_connection() != 0) {
      goto fin;
    }
    event_base_loop(evbase, 0);

    if(!client.all_requests_processed()) {
      std::cerr << "Some requests were not processed. total="
                << client.reqvec.size()
                << ", processed=" << client.complete << std::endl;
    }
    if(config.stat) {
      print_stats(client);
    }
  }
 fin:
  if(ssl_ctx) {
    SSL_CTX_free(ssl_ctx);
  }
  if(evbase) {
    event_base_free(evbase);
  }
  return result;
}
} // namespace

namespace {
ssize_t file_read_callback
(nghttp2_session *session, int32_t stream_id,
 uint8_t *buf, size_t length, uint32_t *data_flags,
 nghttp2_data_source *source, void *user_data)
{
  auto req = (Request*)nghttp2_session_get_stream_user_data
    (session, stream_id);
  assert(req);
  int fd = source->fd;
  ssize_t nread;

  while((nread = pread(fd, buf, length, req->data_offset)) == -1 &&
        errno == EINTR);

  if(nread == -1) {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  if(nread == 0) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  } else {
    req->data_offset += nread;
  }

  return nread;
}
} // namespace

namespace {
int run(char **uris, int n)
{
  nghttp2_session_callbacks callbacks;
  memset(&callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks.on_stream_close_callback = on_stream_close_callback;
  callbacks.on_frame_recv_callback = on_frame_recv_callback2;
  if(config.verbose) {
    callbacks.on_frame_send_callback = verbose_on_frame_send_callback;
    callbacks.on_invalid_frame_recv_callback =
      verbose_on_invalid_frame_recv_callback;
    callbacks.on_unknown_frame_recv_callback =
      verbose_on_unknown_frame_recv_callback;
  }
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks.on_begin_headers_callback = on_begin_headers_callback;
  callbacks.on_header_callback = on_header_callback;
  if(config.padding) {
    callbacks.select_padding_callback = select_padding_callback;
  }

  std::string prev_scheme;
  std::string prev_host;
  uint16_t prev_port = 0;
  int failures = 0;
  int data_fd = -1;
  nghttp2_data_provider data_prd;
  struct stat data_stat;

  if(!config.datafile.empty()) {
    data_fd = open(config.datafile.c_str(), O_RDONLY | O_BINARY);
    if(data_fd == -1) {
      std::cerr << "Could not open file " << config.datafile << std::endl;
      return 1;
    }
    if(fstat(data_fd, &data_stat) == -1) {
      close(data_fd);
      std::cerr << "Could not stat file " << config.datafile << std::endl;
      return 1;
    }
    data_prd.source.fd = data_fd;
    data_prd.read_callback = file_read_callback;
  }
  std::vector<std::tuple<std::string, nghttp2_data_provider*, int64_t>>
    requests;
  for(int i = 0; i < n; ++i) {
    http_parser_url u;
    memset(&u, 0, sizeof(u));
    auto uri = strip_fragment(uris[i]);
    if(http_parser_parse_url(uri.c_str(), uri.size(), 0, &u) == 0 &&
       util::has_uri_field(u, UF_SCHEMA)) {
      uint16_t port = util::has_uri_field(u, UF_PORT) ?
        u.port : util::get_default_port(uri.c_str(), u);
      if(!util::fieldeq(uri.c_str(), u, UF_SCHEMA, prev_scheme.c_str()) ||
         !util::fieldeq(uri.c_str(), u, UF_HOST, prev_host.c_str()) ||
         port != prev_port) {
        if(!requests.empty()) {
          if (communicate(prev_scheme, prev_host, prev_port,
                          std::move(requests), &callbacks) != 0) {
            ++failures;
          }
          requests.clear();
        }
        prev_scheme = util::get_uri_field(uri.c_str(), u, UF_SCHEMA);
        prev_host = util::get_uri_field(uri.c_str(), u, UF_HOST);
        prev_port = port;
      }
      requests.emplace_back(uri, data_fd == -1 ? nullptr : &data_prd,
                            data_stat.st_size);
    }
  }
  if(!requests.empty()) {
    if (communicate(prev_scheme, prev_host, prev_port, std::move(requests),
                    &callbacks) != 0) {
      ++failures;
    }
  }
  return failures;
}
} // namespace

namespace {
void print_version(std::ostream& out)
{
  out << "nghttp nghttp2/" NGHTTP2_VERSION << std::endl;
}
} // namespace

namespace {
void print_usage(std::ostream& out)
{
  out << R"(Usage: nghttp [OPTIONS]... <URI>...
HTTP/2 experimental client)" << std::endl;
}
} // namespace

namespace {
void print_help(std::ostream& out)
{
  print_usage(out);
  out << R"(
  <URI>              Specify URI to access.
Options:
  -v, --verbose      Print  debug information  such  as reception  and
                     transmission of frames and name/value pairs.
  -n, --null-out     Discard downloaded data.
  -O, --remote-name  Save download data in the current directory.  The
                     filename is dereived from  URI.  If URI ends with
                     '/',  'index.html' is  used as  a filename.   Not
                     implemented yet.
  -t, --timeout=<N>  Timeout each request after <N> seconds.
  -w, --window-bits=<N>
                     Sets  the stream  level  initial  window size  to
                     2**<N>-1.
  -W, --connection-window-bits=<N>
                     Sets the connection level  initial window size to
                     2**<N>-1.
  -a, --get-assets   Download assets  such as stylesheets,  images and
                     script files linked from the downloaded resource.
                     Only links  whose origins  are the same  with the
                     linking resource will be downloaded.
  -s, --stat         Print statistics.
  -H, --header       Add a header to the requests.
  --cert=<CERT>      Use the  specified client certificate  file.  The
                     file must be in PEM format.
  --key=<KEY>        Use the  client private key file.   The file must
                     be in PEM format.
  -d, --data=<FILE>  Post FILE to  server. If '-' is  given, data will
                     be read from stdin.
  -m, --multiply=<N> Request each URI <N> times.  By default, same URI
                     is not requested twice.   This option disables it
                     too.
  -u, --upgrade      Perform HTTP Upgrade for  HTTP/2.  This option is
                     ignored if the request  URI has https scheme.  If
                     -d is used, the HTTP upgrade request is performed
                     with OPTIONS method.
  -p, --weight=<WEIGHT>
                     Sets  priority  group  weight.  The  valid  value
                     range is [)"
      << NGHTTP2_MIN_WEIGHT << ", " << NGHTTP2_MAX_WEIGHT << R"(], inclusive.
                     Default: )"
      << NGHTTP2_DEFAULT_WEIGHT << R"(
  -M, --peer-max-concurrent-streams=<N>
                     Use <N>  as SETTINGS_MAX_CONCURRENT_STREAMS value
                     of  remote  endpoint  as  if it  is  received  in
                     SETTINGS frame.   The default is large  enough as
                     it is seen as unlimited.
  -c, --header-table-size=<N>
                     Specify decoder header table size.
  -b, --padding=<N>  Add  at most  <N>  bytes to  a  frame payload  as
                     padding.  Specify 0 to disable padding.
  --color            Force colored log output.
  --continuation     Send large header to test CONTINUATION.
  --no-content-length
                     Don't send content-length header field.
  --version          Display version information and exit.
  -h, --help         Display this help and exit.)"
      << std::endl;
}
} // namespace

int main(int argc, char **argv)
{
  bool color = false;
  while(1) {
    static int flag = 0;
    static option long_options[] = {
      {"verbose", no_argument, nullptr, 'v'},
      {"null-out", no_argument, nullptr, 'n'},
      {"remote-name", no_argument, nullptr, 'O'},
      {"timeout", required_argument, nullptr, 't'},
      {"window-bits", required_argument, nullptr, 'w'},
      {"connection-window-bits", required_argument, nullptr, 'W'},
      {"get-assets", no_argument, nullptr, 'a'},
      {"stat", no_argument, nullptr, 's'},
      {"help", no_argument, nullptr, 'h'},
      {"header", required_argument, nullptr, 'H'},
      {"data", required_argument, nullptr, 'd'},
      {"multiply", required_argument, nullptr, 'm'},
      {"upgrade", no_argument, nullptr, 'u'},
      {"weight", required_argument, nullptr, 'p'},
      {"peer-max-concurrent-streams", required_argument, nullptr, 'M'},
      {"header-table-size", required_argument, nullptr, 'c'},
      {"padding", required_argument, nullptr, 'b'},
      {"cert", required_argument, &flag, 1},
      {"key", required_argument, &flag, 2},
      {"color", no_argument, &flag, 3},
      {"continuation", no_argument, &flag, 4},
      {"version", no_argument, &flag, 5},
      {"no-content-length", no_argument, &flag, 6},
      {nullptr, 0, nullptr, 0 }
    };
    int option_index = 0;
    int c = getopt_long(argc, argv, "M:Oab:c:d:gm:np:hH:vst:uw:W:",
                        long_options, &option_index);
    char *end;
    if(c == -1) {
      break;
    }
    switch(c) {
    case 'M':
      // peer-max-concurrent-streams option
      config.peer_max_concurrent_streams = strtoul(optarg, nullptr, 10);
      break;
    case 'O':
      config.remote_name = true;
      break;
    case 'h':
      print_help(std::cout);
      exit(EXIT_SUCCESS);
    case 'b':
      config.padding = strtol(optarg, nullptr, 10);
      break;
    case 'n':
      config.null_out = true;
      break;
    case 'p': {
      errno = 0;
      auto n = strtoul(optarg, nullptr, 10);
      if(errno == 0 && NGHTTP2_MIN_WEIGHT <= n && n <= NGHTTP2_MAX_WEIGHT) {
        config.weight = n;
      } else {
        std::cerr << "-p: specify the integer in the range ["
                  << NGHTTP2_MIN_WEIGHT << ", "
                  << NGHTTP2_MAX_WEIGHT << "], inclusive"
                  << std::endl;
        exit(EXIT_FAILURE);
      }
      break;
    }
    case 'v':
      config.verbose = true;
      break;
    case 't':
      config.timeout = atoi(optarg) * 1000;
      break;
    case 'u':
      config.upgrade = true;
      break;
    case 'w':
    case 'W': {
      errno = 0;
      char *endptr = nullptr;
      unsigned long int n = strtoul(optarg, &endptr, 10);
      if(errno == 0 && *endptr == '\0' && n < 31) {
        if(c == 'w') {
          config.window_bits = n;
        } else {
          config.connection_window_bits = n;
        }
      } else {
        std::cerr << "-" << static_cast<char>(c)
                  << ": specify the integer in the range [0, 30], inclusive"
                  << std::endl;
        exit(EXIT_FAILURE);
      }
      break;
    }
    case 'H': {
      char *header = optarg;
      // Skip first possible ':' in the header name
      char *value = strchr( optarg + 1, ':' );
      if ( ! value || (header[0] == ':' && header + 1 == value)) {
        std::cerr << "-H: invalid header: " << optarg
                  << std::endl;
        exit(EXIT_FAILURE);
      }
      *value = 0;
      value++;
      while( isspace( *value ) ) { value++; }
      if ( *value == 0 ) {
        // This could also be a valid case for suppressing a header
        // similar to curl
        std::cerr << "-H: invalid header - value missing: " << optarg
                  << std::endl;
        exit(EXIT_FAILURE);
      }
      // Note that there is no processing currently to handle multiple
      // message-header fields with the same field name
      config.headers.emplace_back(header, value);
      util::inp_strlower(config.headers.back().first);
      break;
    }
    case 'a':
#ifdef HAVE_LIBXML2
      config.get_assets = true;
#else // !HAVE_LIBXML2
      std::cerr << "Warning: -a, --get-assets option cannot be used because\n"
                << "the binary was not compiled with libxml2."
                << std::endl;
#endif // !HAVE_LIBXML2
      break;
    case 's':
      config.stat = true;
      break;
    case 'd':
      config.datafile = strcmp("-", optarg) == 0 ? "/dev/stdin" : optarg;
      break;
    case 'm':
      config.multiply = strtoul(optarg, nullptr, 10);
      break;
    case 'c':
      errno = 0;
      config.header_table_size = strtol(optarg, &end, 10);
      if(errno == ERANGE || *end != '\0') {
        std::cerr << "-c: Bad option value: " << optarg << std::endl;
        exit(EXIT_FAILURE);
      }
      break;
    case '?':
      util::show_candidates(argv[optind - 1], long_options);
      exit(EXIT_FAILURE);
    case 0:
      switch(flag) {
      case 1:
        // cert option
        config.certfile = optarg;
        break;
      case 2:
        // key option
        config.keyfile = optarg;
        break;
      case 3:
        // color option
        color = true;
        break;
      case 4:
        // continuation option
        config.continuation = true;
        break;
      case 5:
        // version option
        print_version(std::cout);
        exit(EXIT_SUCCESS);
      case 6:
        // no-content-length option
        config.no_content_length = true;
        break;
      }
      break;
    default:
      break;
    }
  }

  set_color_output(color || isatty(fileno(stdout)));

  nghttp2_option_set_peer_max_concurrent_streams
    (config.http2_option, config.peer_max_concurrent_streams);

  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, nullptr);
  SSL_load_error_strings();
  SSL_library_init();
  reset_timer();
  return run(argv+optind, argc-optind);
}

} // namespace nghttp2

int main(int argc, char **argv)
{
  return nghttp2::main(argc, argv);
}
