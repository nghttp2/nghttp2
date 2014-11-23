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
#include "h2load.h"

#include <getopt.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <cstdio>
#include <cassert>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <future>

#ifdef HAVE_SPDYLAY
#include <spdylay/spdylay.h>
#endif // HAVE_SPDYLAY

#include <event2/bufferevent_ssl.h>

#include <openssl/err.h>
#include <openssl/conf.h>

#include "http-parser/http_parser.h"

#include "h2load_http2_session.h"
#ifdef HAVE_SPDYLAY
#include "h2load_spdy_session.h"
#endif // HAVE_SPDYLAY
#include "ssl.h"
#include "http2.h"
#include "util.h"

using namespace nghttp2;

namespace h2load {

Config::Config()
  : addrs(nullptr),
    nreqs(1),
    nclients(1),
    nthreads(1),
    max_concurrent_streams(-1),
    window_bits(16),
    connection_window_bits(16),
    no_tls_proto(PROTO_HTTP2),
    port(0),
    default_port(0),
    verbose(false)
{}

Config::~Config()
{
  freeaddrinfo(addrs);
}

Config config;

namespace {
void eventcb(bufferevent *bev, short events, void *ptr);
} // namespace

namespace {
void readcb(bufferevent *bev, void *ptr);
} // namespace

namespace {
void writecb(bufferevent *bev, void *ptr);
} // namespace

namespace {
void debug(const char *format, ...)
{
  if(config.verbose) {
    fprintf(stderr, "[DEBUG] ");
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
  }
}
} // namespace

Stream::Stream()
  : status_success(-1)
{}

Client::Client(Worker *worker, size_t req_todo)
  : worker(worker),
    ssl(nullptr),
    bev(nullptr),
    next_addr(config.addrs),
    reqidx(0),
    state(CLIENT_IDLE),
    req_todo(req_todo),
    req_started(0),
    req_done(0)
{}

Client::~Client()
{
  disconnect();
}

int Client::connect()
{
  if(config.scheme == "https") {
    ssl = SSL_new(worker->ssl_ctx);

    auto config = worker->config;

    if(!util::numeric_host(config->host.c_str())) {
      SSL_set_tlsext_host_name(ssl, config->host.c_str());
    }

    bev = bufferevent_openssl_socket_new(worker->evbase, -1, ssl,
                                         BUFFEREVENT_SSL_CONNECTING,
                                         BEV_OPT_DEFER_CALLBACKS);
  } else {
    bev = bufferevent_socket_new(worker->evbase, -1,
                                 BEV_OPT_DEFER_CALLBACKS);
  }

  int rv = -1;
  while(next_addr) {
    rv = bufferevent_socket_connect(bev, next_addr->ai_addr,
                                    next_addr->ai_addrlen);
    next_addr = next_addr->ai_next;
    if(rv == 0) {
      break;
    }
  }
  if(rv != 0) {
    return -1;
  }
  bufferevent_enable(bev, EV_READ);
  bufferevent_setcb(bev, readcb, writecb, eventcb, this);
  return 0;
}

void Client::fail()
{
  process_abandoned_streams();

  disconnect();
}

void Client::disconnect()
{
  int fd = -1;
  streams.clear();
  session.reset();
  state = CLIENT_IDLE;
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
  if(ssl) {
    SSL_free(ssl);
    ssl = nullptr;
  }
  if(fd != -1) {
    shutdown(fd, SHUT_WR);
    close(fd);
  }
}

void Client::submit_request()
{
  session->submit_request();
  ++worker->stats.req_started;
  ++req_started;
}

void Client::process_abandoned_streams()
{
  auto req_abandoned = req_todo - req_done;

  worker->stats.req_failed += req_abandoned;
  worker->stats.req_error += req_abandoned;
  worker->stats.req_done += req_abandoned;

  req_done = req_todo;
}

void Client::report_progress()
{
  if(worker->id == 0 &&
     worker->stats.req_done % worker->progress_interval == 0) {
    std::cout << "progress: "
              << worker->stats.req_done * 100 / worker->stats.req_todo
              << "% done"
              << std::endl;
  }
}

namespace {
const char* get_tls_protocol(SSL *ssl)
{
  auto session = SSL_get_session(ssl);

  switch(session->ssl_version) {
  case SSL2_VERSION:
    return "SSLv2";
  case SSL3_VERSION:
    return "SSLv3";
  case TLS1_2_VERSION:
    return "TLSv1.2";
  case TLS1_1_VERSION:
    return "TLSv1.1";
  case TLS1_VERSION:
    return "TLSv1";
  default:
    return "unknown";
  }
}
} // namespace

namespace {
void print_server_tmp_key(SSL *ssl)
{
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  EVP_PKEY *key;

  if(!SSL_get_server_tmp_key(ssl, &key)) {
    return;
  }

  auto key_del = util::defer(key, EVP_PKEY_free);

  std::cout << "Server Temp Key: ";

  switch(EVP_PKEY_id(key)) {
  case EVP_PKEY_RSA:
    std::cout << "RSA " << EVP_PKEY_bits(key) << " bits" << std::endl;
    break;
  case EVP_PKEY_DH:
    std::cout << "DH " << EVP_PKEY_bits(key) << " bits" << std::endl;
    break;
  case EVP_PKEY_EC: {
    auto ec = EVP_PKEY_get1_EC_KEY(key);
    auto ec_del = util::defer(ec, EC_KEY_free);
    auto nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
    auto cname = EC_curve_nid2nist(nid);
    if(!cname) {
      cname = OBJ_nid2sn(nid);
    }

    std::cout << "ECDH " << cname << " " << EVP_PKEY_bits(key)
              << " bits" << std::endl;
    break;
  }
  }
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
}
} // namespace

void Client::report_tls_info()
{
  if(worker->id == 0 && !worker->tls_info_report_done) {
    worker->tls_info_report_done = true;
    auto cipher = SSL_get_current_cipher(ssl);
    std::cout << "Protocol: " << get_tls_protocol(ssl) << "\n"
              << "Cipher: " << SSL_CIPHER_get_name(cipher) << std::endl;
    print_server_tmp_key(ssl);
  }
}

void Client::terminate_session()
{
  session->terminate();
}

void Client::on_request(int32_t stream_id)
{
  streams[stream_id] = Stream();
}

void Client::on_header(int32_t stream_id,
                       const uint8_t *name, size_t namelen,
                       const uint8_t *value, size_t valuelen)
{
  auto itr = streams.find(stream_id);
  if(itr == std::end(streams)) {
    return;
  }
  auto& stream = (*itr).second;
  if(stream.status_success == -1 &&
     namelen == 7 && util::streq(":status", 7, name, namelen)) {
    int status = 0;
    for(size_t i = 0; i < valuelen; ++i) {
      if('0' <= value[i] && value[i] <= '9') {
        status *= 10;
        status += value[i] - '0';
        if(status > 999) {
          stream.status_success = 0;
          return;
        }
      } else {
        break;
      }
    }

    if(status >= 200 && status < 300) {
      ++worker->stats.status[2];
      stream.status_success = 1;
    } else if(status < 400) {
      ++worker->stats.status[3];
      stream.status_success = 1;
    } else if(status < 600) {
      ++worker->stats.status[status / 100];
      stream.status_success = 0;
    } else {
      stream.status_success = 0;
    }
  }
}

void Client::on_stream_close(int32_t stream_id, bool success)
{
  ++worker->stats.req_done;
  ++req_done;
  if(success && streams[stream_id].status_success == 1) {
    ++worker->stats.req_success;
  } else {
    ++worker->stats.req_failed;
  }
  report_progress();
  streams.erase(stream_id);
  if(req_done == req_todo) {
    terminate_session();
    return;
  }

  if(req_started < req_todo) {
    submit_request();
    return;
  }
}

int Client::on_connect()
{
  session->on_connect();

  auto nreq = std::min(req_todo - req_started,
                       (size_t)config.max_concurrent_streams);

  for(; nreq > 0; --nreq) {
    submit_request();
  }
  return session->on_write();
}

int Client::on_read()
{
  ssize_t rv = session->on_read();
  if(rv < 0) {
    return -1;
  }
  worker->stats.bytes_total += rv;

  return on_write();
}

int Client::on_write()
{
  return session->on_write();
}

Worker::Worker(uint32_t id, SSL_CTX *ssl_ctx, size_t req_todo, size_t nclients,
               Config *config)
  : stats{0}, evbase(event_base_new()), ssl_ctx(ssl_ctx), config(config),
    id(id), tls_info_report_done(false)
{
  stats.req_todo = req_todo;
  progress_interval = std::max((size_t)1, req_todo / 10);

  auto nreqs_per_client = req_todo / nclients;
  auto nreqs_rem = req_todo % nclients;

  for(size_t i = 0; i < nclients; ++i) {
    auto req_todo = nreqs_per_client;
    if(nreqs_rem > 0) {
      ++req_todo;
      --nreqs_rem;
    }
    clients.push_back(util::make_unique<Client>(this, req_todo));
  }
}

Worker::~Worker()
{
  event_base_free(evbase);
}

void Worker::run()
{
  for(auto& client : clients) {
    if(client->connect() != 0) {
      std::cerr << "client could not connect to host" << std::endl;
      client->fail();
    }
  }
  event_base_loop(evbase, 0);
}

namespace {
void debug_nextproto_error()
{
#ifdef HAVE_SPDYLAY
  debug("no supported protocol was negotiated, expected: %s, "
        "spdy/2, spdy/3, spdy/3.1\n", NGHTTP2_PROTO_VERSION_ID);
#else // !HAVE_SPDYLAY
  debug("no supported protocol was negotiated, expected: %s\n",
        NGHTTP2_PROTO_VERSION_ID);
#endif // !HAVE_SPDYLAY
}
} // namespace

namespace {
void eventcb(bufferevent *bev, short events, void *ptr)
{
  int rv;
  auto client = static_cast<Client*>(ptr);
  if(events & BEV_EVENT_CONNECTED) {
    if(client->ssl) {
      client->report_tls_info();

      const unsigned char *next_proto = nullptr;
      unsigned int next_proto_len;
      SSL_get0_next_proto_negotiated(client->ssl,
                                     &next_proto, &next_proto_len);
      for(int i = 0; i < 2; ++i) {
        if(next_proto) {
          if(util::check_h2_is_selected(next_proto, next_proto_len)) {
            client->session = util::make_unique<Http2Session>(client);
          } else {
#ifdef HAVE_SPDYLAY
            auto spdy_version = spdylay_npn_get_version(next_proto,
                                                        next_proto_len);
            if(spdy_version) {
              client->session = util::make_unique<SpdySession>(client,
                                                               spdy_version);
            } else {
              debug_nextproto_error();
              client->fail();
              return;
            }
#else // !HAVE_SPDYLAY
            debug_nextproto_error();
            client->fail();
            return;
#endif // !HAVE_SPDYLAY
          }
        }

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        SSL_get0_alpn_selected(client->ssl, &next_proto, &next_proto_len);
#else // OPENSSL_VERSION_NUMBER < 0x10002000L
        break;
#endif // OPENSSL_VERSION_NUMBER < 0x10002000L
      }

      if(!next_proto) {
        debug_nextproto_error();
        client->fail();
        return;
      }
    } else {
      switch(config.no_tls_proto) {
      case Config::PROTO_HTTP2:
        client->session = util::make_unique<Http2Session>(client);
        break;
#ifdef HAVE_SPDYLAY
      case Config::PROTO_SPDY2:
        client->session = util::make_unique<SpdySession>
          (client, SPDYLAY_PROTO_SPDY2);
        break;
      case Config::PROTO_SPDY3:
        client->session = util::make_unique<SpdySession>
          (client, SPDYLAY_PROTO_SPDY3);
        break;
      case Config::PROTO_SPDY3_1:
        client->session = util::make_unique<SpdySession>
          (client, SPDYLAY_PROTO_SPDY3_1);
        break;
#endif // HAVE_SPDYLAY
      default:
        // unreachable
        assert(0);
      }
    }
    int fd = bufferevent_getfd(bev);
    int val = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<char *>(&val), sizeof(val));
    client->state = CLIENT_CONNECTED;
    client->on_connect();
    return;
  }
  if(events & BEV_EVENT_EOF) {
    client->fail();
    return;
  }
  if(events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
    if(client->state == CLIENT_IDLE) {
      client->disconnect();
      rv = client->connect();
      if(rv == 0) {
        return;
      }
    }
    debug("error/eof\n");
    client->fail();
    return;
  }
}
} // namespace

namespace {
void readcb(bufferevent *bev, void *ptr)
{
  int rv;
  auto client = static_cast<Client*>(ptr);
  rv = client->on_read();
  if(rv != 0) {
    client->fail();
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
  auto client = static_cast<Client*>(ptr);
  rv = client->on_write();
  if(rv != 0) {
    client->fail();
  }
}
} // namespace

namespace {
void resolve_host()
{
  int rv;
  addrinfo hints, *res;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_ADDRCONFIG;

  rv = getaddrinfo(config.host.c_str(), util::utos(config.port).c_str(),
                   &hints, &res);
  if(rv != 0) {
    std::cerr << "getaddrinfo() failed: "
              << gai_strerror(rv) << std::endl;
    exit(EXIT_FAILURE);
  }
  if(res == nullptr) {
    std::cerr << "No address returned" << std::endl;
    exit(EXIT_FAILURE);
  }
  config.addrs = res;
}
} // namespace

namespace {
std::string get_reqline(const char *uri, const http_parser_url& u)
{
  std::string reqline;

  if(util::has_uri_field(u, UF_PATH)) {
    reqline = util::get_uri_field(uri, u, UF_PATH);
  } else {
    reqline = "/";
  }

  if(util::has_uri_field(u, UF_QUERY)) {
    reqline += "?";
    reqline += util::get_uri_field(uri, u, UF_QUERY);
  }

  return reqline;
}
} // namespace

namespace {
int client_select_next_proto_cb(SSL* ssl,
                                unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen,
                                void *arg)
{
  if(nghttp2_select_next_protocol(out, outlen, in, inlen) > 0) {
    return SSL_TLSEXT_ERR_OK;
  }
#ifdef HAVE_SPDYLAY
  else if(spdylay_select_next_protocol(out, outlen, in, inlen) > 0) {
    return SSL_TLSEXT_ERR_OK;
  }
#endif
  return SSL_TLSEXT_ERR_NOACK;
}
} // namespace

namespace {
template<typename Iterator>
std::vector<std::string> parse_uris(Iterator first, Iterator last)
{
  std::vector<std::string> reqlines;

  // First URI is treated specially.  We use scheme, host and port of
  // this URI and ignore those in the remaining URIs if present.
  http_parser_url u;
  memset(&u, 0, sizeof(u));

  if(first == last) {
    std::cerr << "no URI available" << std::endl;
    exit(EXIT_FAILURE);
  }

  auto uri = (*first).c_str();
  ++first;

  if(http_parser_parse_url(uri, strlen(uri), 0, &u) != 0 ||
     !util::has_uri_field(u, UF_SCHEMA) || !util::has_uri_field(u, UF_HOST)) {
    std::cerr << "invalid URI: " << uri << std::endl;
    exit(EXIT_FAILURE);
  }

  config.scheme = util::get_uri_field(uri, u, UF_SCHEMA);
  config.host = util::get_uri_field(uri, u, UF_HOST);
  config.default_port = util::get_default_port(uri, u);
  if(util::has_uri_field(u, UF_PORT)) {
    config.port = u.port;
  } else {
    config.port = config.default_port;
  }

  reqlines.push_back(get_reqline(uri, u));

  for(; first != last; ++first) {
    http_parser_url u;
    memset(&u, 0, sizeof(u));

    auto uri = (*first).c_str();

    if(http_parser_parse_url(uri, strlen(uri), 0, &u) != 0) {
      std::cerr << "invalid URI: " << uri << std::endl;
      exit(EXIT_FAILURE);
    }

    reqlines.push_back(get_reqline(uri, u));
  }

  return reqlines;
}
} // namespace

namespace {
std::vector<std::string> read_uri_from_file(std::istream& infile)
{
  std::vector<std::string> uris;
  std::string line_uri;
  while(std::getline(infile, line_uri)) {
    uris.push_back(line_uri);
  }

  return uris;
}
} // namespace

namespace {
void print_version(std::ostream& out)
{
  out << "h2load nghttp2/" NGHTTP2_VERSION << std::endl;
}
} // namespace

namespace {
void print_usage(std::ostream& out)
{
  out << R"(
Usage: h2load [OPTIONS]... [URI]...
benchmarking tool for HTTP/2 and SPDY server)" << std::endl;
}
} // namespace

namespace {
void print_help(std::ostream& out)
{
  print_usage(out);

  out << R"(
  <URI>              Specify  URI to  access.   Multiple  URIs can  be
                     specified.  URIs are used  in this order for each
                     client.   All URIs  are used,  then first  URI is
                     used and  then 2nd URI,  and so on.   The scheme,
                     host and port in the subsequent URIs, if present,
                     are  ignored.  Those  in the  first URI  are used
                     solely.
Options:
  -n, --requests=<N> Number of requests. Default: )"
      << config.nreqs << R"(
  -c, --clients=<N>  Number of concurrent clients. Default: )"
      << config.nclients << R"(
  -t, --threads=<N>  Number of native threads. Default: )"
      << config.nthreads << R"(
  -i, --input-file=<FILE>
                     Path of  a file with multiple  URIs are seperated
                     by EOLs.   This option will disable  URIs getting
                     from command-line.   If '-'  is given  as <FILE>,
                     URIs will be  read from stdin.  URIs  are used in
                     this order  for each client.  All  URIs are used,
                     then first URI  is used and then 2nd  URI, and so
                     on.  The scheme, host  and port in the subsequent
                     URIs,  if present,  are  ignored.   Those in  the
                     first URI are used solely.
  -m, --max-concurrent-streams=(auto|<N>)
                     Max concurrent streams to  issue per session.  If
                     "auto"  is given,  the  number of  given URIs  is
                     used.  Default: auto
  -w, --window-bits=<N>
                     Sets  the stream  level  initial  window size  to
                     (2**<N>)-1.  For SPDY, 2**<N> is used instead.
  -W, --connection-window-bits=<N>
                     Sets the connection level  initial window size to
                     (2**<N>)-1.  For  SPDY, if  <N> is  strictly less
                     than  16,  this  option  is  ignored.   Otherwise
                     2**<N> is used for SPDY.
  -H, --header=<HEADER>
                     Add/Override a header to the requests.
  -p, --no-tls-proto=<PROTOID>
                     Specify  ALPN identifier  of the  protocol to  be
                     used  when accessing  http  URI without  SSL/TLS.)";
#ifdef HAVE_SPDYLAY
  out << R"(
                     Available protocols: spdy/2, spdy/3, spdy/3.1 and
                     )";
#else // !HAVE_SPDYLAY
  out << R"(
                     Available protocol: )";
#endif // !HAVE_SPDYLAY
  out << NGHTTP2_CLEARTEXT_PROTO_VERSION_ID << R"(
                     Default: )"
      << NGHTTP2_CLEARTEXT_PROTO_VERSION_ID << R"(
  -v, --verbose      Output debug information.
  --version          Display version information and exit.
  -h, --help         Display this help and exit.)"
      << std::endl;
}
} // namespace

int main(int argc, char **argv)
{
  while(1) {
    static int flag = 0;
    static option long_options[] = {
      {"requests", required_argument, nullptr, 'n'},
      {"clients", required_argument, nullptr, 'c'},
      {"threads", required_argument, nullptr, 't'},
      {"max-concurrent-streams", required_argument, nullptr, 'm'},
      {"window-bits", required_argument, nullptr, 'w'},
      {"connection-window-bits", required_argument, nullptr, 'W'},
      {"input-file", required_argument, nullptr, 'i'},
      {"header", required_argument, nullptr, 'H'},
      {"no-tls-proto", required_argument, nullptr, 'p'},
      {"verbose", no_argument, nullptr, 'v'},
      {"help", no_argument, nullptr, 'h'},
      {"version", no_argument, &flag, 1},
      {nullptr, 0, nullptr, 0 }
    };
    int option_index = 0;
    auto c = getopt_long(argc, argv, "hvW:c:m:n:p:t:w:H:i:", long_options,
                         &option_index);
    if(c == -1) {
      break;
    }
    switch(c) {
    case 'n':
      config.nreqs = strtoul(optarg, nullptr, 10);
      break;
    case 'c':
      config.nclients = strtoul(optarg, nullptr, 10);
      break;
    case 't':
#ifdef NOTHREADS
	  std::cerr << "-t: WARNING: Threading disabled at build time, " <<
		  "no threads created." << std::endl;
#else
      config.nthreads = strtoul(optarg, nullptr, 10);
#endif // NOTHREADS
      break;
    case 'm':
      if(util::strieq("auto", optarg)) {
        config.max_concurrent_streams = -1;
      } else {
        config.max_concurrent_streams = strtoul(optarg, nullptr, 10);
      }
      break;
    case 'w':
    case 'W': {
      errno = 0;
      char *endptr = nullptr;
      auto n = strtoul(optarg, &endptr, 10);
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
      config.custom_headers.emplace_back(header, value);
      util::inp_strlower(config.custom_headers.back().name);
      break;
    }
    case 'i': {
      config.ifile = std::string(optarg);
      break;
    }
    case 'p':
      if(util::strieq(NGHTTP2_CLEARTEXT_PROTO_VERSION_ID, optarg)) {
        config.no_tls_proto = Config::PROTO_HTTP2;
#ifdef HAVE_SPDYLAY
      } else if(util::strieq("spdy/2", optarg)) {
        config.no_tls_proto = Config::PROTO_SPDY2;
      } else if(util::strieq("spdy/3", optarg)) {
        config.no_tls_proto = Config::PROTO_SPDY3;
      } else if(util::strieq("spdy/3.1", optarg)) {
        config.no_tls_proto = Config::PROTO_SPDY3_1;
#endif // HAVE_SPDYLAY
      } else {
        std::cerr << "-p: unsupported protocol " << optarg << std::endl;
        exit(EXIT_FAILURE);
      }
      break;
    case 'v':
      config.verbose = true;
      break;
    case 'h':
      print_help(std::cout);
      exit(EXIT_SUCCESS);
    case '?':
      util::show_candidates(argv[optind - 1], long_options);
      exit(EXIT_FAILURE);
    case 0:
      switch(flag) {
      case 1:
        // version option
        print_version(std::cout);
        exit(EXIT_SUCCESS);
      }
      break;
    default:
      break;
    }
  }

  if(argc == optind) {
    if(config.ifile.empty()){
      std::cerr << "no URI or input file given" << std::endl;
      exit(EXIT_FAILURE);
    }
  }

  if(config.nreqs == 0) {
    std::cerr << "-n: the number of requests must be strictly greater than 0."
              << std::endl;
    exit(EXIT_FAILURE);
  }

  if(config.max_concurrent_streams == 0) {
    std::cerr << "-m: the max concurrent streams must be strictly greater "
              << "than 0."
              << std::endl;
    exit(EXIT_FAILURE);
  }

  if(config.nthreads == 0) {
    std::cerr << "-t: the number of threads must be strictly greater than 0."
              << std::endl;
    exit(EXIT_FAILURE);
  }

  if(config.nreqs < config.nclients) {
    std::cerr << "-n, -c: the number of requests must be greater than or "
              << "equal to the concurrent clients."
              << std::endl;
    exit(EXIT_FAILURE);
  }

  if(config.nthreads > std::thread::hardware_concurrency()) {
    std::cerr << "-t: warning: the number of threads is greater than hardware "
              << "cores."
              << std::endl;
  }

  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, nullptr);
  OPENSSL_config(nullptr);
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  SSL_library_init();

#ifndef NOTHREADS
  ssl::LibsslGlobalLock lock;
#endif // NOTHREADS

  auto ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if(!ssl_ctx) {
    std::cerr << "Failed to create SSL_CTX: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    exit(EXIT_FAILURE);
  }
  SSL_CTX_set_next_proto_select_cb(ssl_ctx,
                                   client_select_next_proto_cb, nullptr);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  auto proto_list = util::get_default_alpn();
#ifdef HAVE_SPDYLAY
  static const char spdy_proto_list[] = "\x8spdy/3.1\x6spdy/3\x6spdy/2";
  std::copy(spdy_proto_list, spdy_proto_list + sizeof(spdy_proto_list) - 1,
            std::back_inserter(proto_list));
#endif // HAVE_SPDYLAY
  SSL_CTX_set_alpn_protos(ssl_ctx, proto_list.data(), proto_list.size());
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

  std::vector<std::string> reqlines;

  if(config.ifile.empty()) {
    std::vector<std::string> uris;
    std::copy(&argv[optind], &argv[argc], std::back_inserter(uris));
    reqlines = parse_uris(std::begin(uris), std::end(uris));
  } else {
    std::vector<std::string> uris;
    if(config.ifile == "-") {
      uris = read_uri_from_file(std::cin);
    } else {
      std::ifstream infile(config.ifile);
      if(!infile) {
        std::cerr << "cannot read input file: " << config.ifile << std::endl;
        exit(EXIT_FAILURE);
      }

      uris = read_uri_from_file(infile);
    }

    reqlines = parse_uris(std::begin(uris), std::end(uris));
  }

  if(config.max_concurrent_streams == -1) {
    config.max_concurrent_streams = reqlines.size();
  }

  Headers shared_nva;
  shared_nva.emplace_back(":scheme", config.scheme);
  if(config.port != config.default_port) {
    shared_nva.emplace_back(":authority",
                            config.host + ":" + util::utos(config.port));
  } else {
    shared_nva.emplace_back(":authority", config.host);
  }
  shared_nva.emplace_back(":method", "GET");

  //list overridalbe headers
  auto override_hdrs = std::vector<std::string>{
    ":authority", ":host", ":method", ":scheme"
  };

  for(auto& kv : config.custom_headers) {
    if(std::find(std::begin(override_hdrs), std::end(override_hdrs), kv.name)
       != std::end(override_hdrs)) {
      // override header
      for(auto& nv : shared_nva) {
        if((nv.name == ":authority" && kv.name == ":host")
           || (nv.name == kv.name) ) {
          nv.value = kv.value;
        }
      }
    } else {
      // add additional headers
      shared_nva.push_back(kv);
    }
  }

  for(auto& req : reqlines) {
    // For nghttp2
    std::vector<nghttp2_nv> nva;

    nva.push_back(http2::make_nv_ls(":path", req));

    for(auto& nv : shared_nva) {
      nva.push_back(http2::make_nv(nv.name, nv.value, false));
    }

    config.nva.push_back(std::move(nva));

    // For spdylay
    std::vector<const char*> cva;

    cva.push_back(":path");
    cva.push_back(req.c_str());

    for(auto& nv : shared_nva) {
      if(nv.name == ":authority") {
        cva.push_back(":host");
      } else {
        cva.push_back(nv.name.c_str());
      }
      cva.push_back(nv.value.c_str());
    }
    cva.push_back(":version");
    cva.push_back("HTTP/1.1");
    cva.push_back(nullptr);

    config.nv.push_back(std::move(cva));
  }

  resolve_host();

  if(config.nclients == 1) {
    config.nthreads = 1;
  }

  size_t nreqs_per_thread = config.nreqs / config.nthreads;
  ssize_t nreqs_rem = config.nreqs % config.nthreads;

  size_t nclients_per_thread = config.nclients / config.nthreads;
  ssize_t nclients_rem = config.nclients % config.nthreads;

  std::cout << "starting benchmark..." << std::endl;

  auto start = std::chrono::steady_clock::now();

#ifndef NOTHREADS
  std::vector<std::future<Stats>> futures;
  for(size_t i = 0; i < config.nthreads - 1; ++i) {
    auto nreqs = nreqs_per_thread + (nreqs_rem-- > 0);
    auto nclients = nclients_per_thread + (nclients_rem-- > 0);
    std::cout << "spawning thread #" << i << ": "
              << nclients << " concurrent clients, "
              << nreqs << " total requests"
              << std::endl;
    auto worker = util::make_unique<Worker>(i, ssl_ctx, nreqs, nclients,
                                            &config);
    futures.push_back
      (std::async(std::launch::async,
                  [](std::unique_ptr<Worker> worker)
                  {
                    worker->run();

                    return worker->stats;
                  }, std::move(worker)));
  }
#endif // NOTHREADS

  auto nreqs_last = nreqs_per_thread + (nreqs_rem-- > 0);
  auto nclients_last = nclients_per_thread + (nclients_rem-- > 0);
  std::cout << "spawning thread #" << (config.nthreads - 1) << ": "
            << nclients_last << " concurrent clients, "
            << nreqs_last << " total requests"
            << std::endl;
  Worker worker(config.nthreads - 1, ssl_ctx, nreqs_last, nclients_last,
                &config);
  worker.run();

#ifndef NOTHREADS
  for(auto& fut : futures) {
    auto stats = fut.get();

    worker.stats.req_todo += stats.req_todo;
    worker.stats.req_started += stats.req_started;
    worker.stats.req_done += stats.req_done;
    worker.stats.req_success += stats.req_success;
    worker.stats.req_failed += stats.req_failed;
    worker.stats.req_error += stats.req_error;
    worker.stats.bytes_total += stats.bytes_total;
    worker.stats.bytes_head += stats.bytes_head;
    worker.stats.bytes_body += stats.bytes_body;

    for(size_t i = 0; i < util::array_size(stats.status); ++i) {
      worker.stats.status[i] += stats.status[i];
    }
  }
#endif // NOTHREADS

  auto end = std::chrono::steady_clock::now();
  auto duration =
    std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

  // Requests which have not been issued due to connection errors, are
  // counted towards req_failed and req_error.
  auto req_not_issued = worker.stats.req_todo
    - worker.stats.req_success - worker.stats.req_failed;
  worker.stats.req_failed += req_not_issued;
  worker.stats.req_error += req_not_issued;

  // UI is heavily inspired by weighttp
  // https://github.com/lighttpd/weighttp
  size_t rps;
  int64_t kbps;
  if(duration > 0) {
    auto secd = static_cast<double>(duration) / (1000 * 1000);
    rps = worker.stats.req_todo / secd;
    kbps = worker.stats.bytes_total / secd / 1024;
  } else {
    rps = 0;
    kbps = 0;
  }

  auto sec = duration / (1000 * 1000);
  auto millisec = (duration / 1000) % 1000;
  auto microsec = duration % 1000;

  std::cout << "\n"
            << "finished in "
            << sec << " sec, "
            << millisec << " millisec and "
            << microsec << " microsec, "
            << rps << " req/s, "
            << kbps << " kbytes/s\n"
            << "requests: "
            << worker.stats.req_todo << " total, "
            << worker.stats.req_started << " started, "
            << worker.stats.req_done << " done, "
            << worker.stats.req_success << " succeeded, "
            << worker.stats.req_failed << " failed, "
            << worker.stats.req_error << " errored\n"
            << "status codes: "
            << worker.stats.status[2] << " 2xx, "
            << worker.stats.status[3] << " 3xx, "
            << worker.stats.status[4] << " 4xx, "
            << worker.stats.status[5] << " 5xx\n"
            << "traffic: "
            << worker.stats.bytes_total << " bytes total, "
            << worker.stats.bytes_head << " bytes headers, "
            << worker.stats.bytes_body << " bytes data"
            << std::endl;

  SSL_CTX_free(ssl_ctx);

  return 0;
}

} // namespace h2load

int main(int argc, char **argv)
{
  return h2load::main(argc, argv);
}
