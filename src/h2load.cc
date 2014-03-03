/*
 * nghttp2 - HTTP/2.0 C Library
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
#include <chrono>
#include <thread>

#ifdef HAVE_SPDYLAY
#include <spdylay/spdylay.h>
#endif // HAVE_SPDYLAY

#include <event2/bufferevent_ssl.h>

#include <openssl/err.h>

#include "http-parser/http_parser.h"

#include "h2load_http2_session.h"
#ifdef HAVE_SPDYLAY
#include "h2load_spdy_session.h"
#endif // HAVE_SPDYLAY
#include "http2.h"
#include "util.h"

using namespace nghttp2;

namespace h2load {

Config::Config()
  : addrs(nullptr),
    nreqs(1),
    nclients(1),
    nthreads(1),
    max_concurrent_streams(1),
    window_bits(16),
    connection_window_bits(16),
    port(0),
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

Client::Client(Worker *worker)
  : worker(worker),
    ssl(nullptr),
    bev(nullptr),
    next_addr(config.addrs),
    state(CLIENT_IDLE)
{}

Client::~Client()
{
  disconnect();
}

int Client::connect()
{
  if(config.scheme == "https") {
    ssl = SSL_new(worker->ssl_ctx);
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

void Client::disconnect()
{
  process_abandoned_streams();
  if(worker->stats.req_done == worker->stats.req_todo) {
    worker->schedule_terminate();
  }
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
}

void Client::process_abandoned_streams()
{
  worker->stats.req_failed += streams.size();
  worker->stats.req_error += streams.size();
  worker->stats.req_done += streams.size();
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
  if(success && streams[stream_id].status_success == 1) {
    ++worker->stats.req_success;
  } else {
    ++worker->stats.req_failed;
  }
  report_progress();
  streams.erase(stream_id);
  if(worker->stats.req_done == worker->stats.req_todo) {
    worker->schedule_terminate();
    return;
  }

  if(worker->stats.req_started < worker->stats.req_todo) {
    submit_request();
    return;
  }
}

int Client::on_connect()
{
  session->on_connect();

  auto nreq = std::min(worker->stats.req_todo - worker->stats.req_started,
                       std::min(worker->stats.req_todo / worker->clients.size(),
                                config.max_concurrent_streams));
  for(; nreq > 0; --nreq) {
    submit_request();
  }
  return 0;
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
    id(id), term_timer_started(false)
{
  stats.req_todo = req_todo;
  progress_interval = std::max((size_t)1, req_todo / 10);
  for(size_t i = 0; i < nclients; ++i) {
    clients.push_back(util::make_unique<Client>(this));
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
      client->disconnect();
    }
  }
  event_base_loop(evbase, 0);
}

namespace {
void term_timeout_cb(evutil_socket_t fd, short what, void *arg)
{
  auto worker = static_cast<Worker*>(arg);
  worker->terminate_session();
}
} // namespace

void Worker::schedule_terminate()
{
  if(term_timer_started) {
    return;
  }
  term_timer_started = true;
  auto term_timer = evtimer_new(evbase, term_timeout_cb, this);
  timeval timeout = { 0, 0 };
  evtimer_add(term_timer, &timeout);
}

void Worker::terminate_session()
{
  for(auto& client : clients) {
    if(client->session == nullptr) {
      client->disconnect();
      continue;
    }
    client->terminate_session();
    if(client->on_write() != 0) {
      client->disconnect();
    }
  }
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
      const unsigned char *next_proto = nullptr;
      unsigned int next_proto_len;
      SSL_get0_next_proto_negotiated(client->ssl,
                                     &next_proto, &next_proto_len);

      if(!next_proto) {
        debug_nextproto_error();
        client->disconnect();
        return;
      }

      if(next_proto_len == NGHTTP2_PROTO_VERSION_ID_LEN &&
         memcmp(NGHTTP2_PROTO_VERSION_ID, next_proto, next_proto_len) == 0) {
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
          client->disconnect();
          return;
        }
#else // !HAVE_SPDYLAY
        debug_nextproto_error();
        client->disconnect();
        return;
#endif // !HAVE_SPDYLAY
      }
    } else {
      client->session = util::make_unique<Http2Session>(client);
    }
    int fd = bufferevent_getfd(bev);
    int val = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<char *>(&val), sizeof(val));
    client->state = CLIENT_CONNECTED;
    client->on_connect();
    return;
  }
  if(events & BEV_EVENT_EOF) {
    client->disconnect();
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
    client->disconnect();
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
  auto client = static_cast<Client*>(ptr);
  rv = client->on_write();
  if(rv != 0) {
    client->disconnect();
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
void print_version(std::ostream& out)
{
  out << "h2load nghttp2/" NGHTTP2_VERSION << std::endl;
}
} // namespace

namespace {
void print_usage(std::ostream& out)
{
  out << "Usage: h2load [OPTIONS]... <URI>\n"
      << "benchmarking tool for HTTP/2 and SPDY server" << std::endl;
}
} // namespace

namespace {
void print_help(std::ostream& out)
{
  print_usage(out);
  out << "\n"
      << "  <URI>              Specify URI to access.\n"
      << "Options:\n"
      << "  -n, --requests=<N> Number of requests. Default: "
      << config.nreqs << "\n"
      << "  -c, --clients=<N>  Number of concurrent clients. Default: "
      << config.nclients << "\n"
      << "  -t, --threads=<N>  Number of native threads. Default: "
      << config.nthreads << "\n"
      << "  -m, --max-concurrent-streams=<N>\n"
      << "                     Max concurrent streams to issue per session. \n"
      << "                     Default: "
      << config.max_concurrent_streams << "\n"
      << "  -w, --window-bits=<N>\n"
      << "                     Sets the stream level initial window size\n"
      << "                     to (2**<N>)-1. For SPDY, 2**<N> is used\n"
      << "                     instead.\n"
      << "  -W, --connection-window-bits=<N>\n"
      << "                     Sets the connection level initial window\n"
      << "                     size to 2**<N>-1. This option does not work\n"
      << "                     with SPDY.\n"
      << "                     instead.\n"
      << "  -v, --verbose      Output debug information.\n"
      << "  --version          Display version information and exit.\n"
      << "  -h, --help         Display this help and exit.\n"
      << std::endl;
}
} // namespace

int main(int argc, char **argv)
{
  while(1) {
    int flag = 0;
    static option long_options[] = {
      {"requests", required_argument, nullptr, 'n'},
      {"clients", required_argument, nullptr, 'c'},
      {"threads", required_argument, nullptr, 't'},
      {"max-concurrent-streams", required_argument, nullptr, 'm'},
      {"window-bits", required_argument, nullptr, 'w'},
      {"connection-window-bits", required_argument, nullptr, 'W'},
      {"verbose", no_argument, nullptr, 'v'},
      {"help", no_argument, nullptr, 'h'},
      {"version", no_argument, &flag, 1},
      {nullptr, 0, nullptr, 0 }
    };
    int option_index = 0;
    auto c = getopt_long(argc, argv, "hvW:c:m:n:t:w:", long_options,
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
      config.nthreads = strtoul(optarg, nullptr, 10);
      break;
    case 'm':
      config.max_concurrent_streams = strtoul(optarg, nullptr, 10);
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
    std::cerr << "no URI given" << std::endl;
    exit(EXIT_FAILURE);
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
  SSL_load_error_strings();
  SSL_library_init();

  http_parser_url u;
  memset(&u, 0, sizeof(u));
  auto uri = argv[optind];
  if(http_parser_parse_url(uri, strlen(uri), 0, &u) != 0 ||
     !util::has_uri_field(u, UF_SCHEMA) || !util::has_uri_field(u, UF_HOST)) {
    std::cerr << "invalid URI: " << uri << std::endl;
    exit(EXIT_FAILURE);
  }

  config.scheme = util::get_uri_field(uri, u, UF_SCHEMA);
  config.host = util::get_uri_field(uri, u, UF_HOST);
  if(util::has_uri_field(u, UF_PORT)) {
    config.port = u.port;
  } else {
    config.port = util::get_default_port(uri, u);
  }
  if(util::has_uri_field(u, UF_PATH)) {
    config.path = util::get_uri_field(uri, u, UF_PATH);
  } else {
    config.path = "/";
  }

  auto ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if(!ssl_ctx) {
    std::cerr << "Failed to create SSL_CTX: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    exit(EXIT_FAILURE);
  }
  SSL_CTX_set_next_proto_select_cb(ssl_ctx,
                                   client_select_next_proto_cb, nullptr);
  // For nghttp2
  Headers nva;
  nva.emplace_back(":scheme", config.scheme);
  if(config.port != util::get_default_port(uri, u)) {
    nva.emplace_back(":authority",
                     config.host + ":" + util::utos(config.port));
  } else {
    nva.emplace_back(":authority", config.host);
  }
  nva.emplace_back(":path", config.path);
  nva.emplace_back(":method", "GET");

  for(auto& nv : nva) {
    config.nva.push_back(http2::make_nv(nv.first, nv.second));
  }

  // For spdylay
  for(auto& nv : nva) {
    if(nv.first == ":authority") {
      config.nv.push_back(":host");
    } else {
      config.nv.push_back(nv.first.c_str());
    }
    config.nv.push_back(nv.second.c_str());
  }
  config.nv.push_back(":version");
  config.nv.push_back("HTTP/1.1");
  config.nv.push_back(nullptr);

  resolve_host();

  size_t nreqs_per_thread = config.nreqs / config.nthreads;
  ssize_t nreqs_rem = config.nreqs % config.nthreads;

  size_t nclients_per_thread = config.nclients / config.nthreads;
  ssize_t nclients_rem = config.nclients % config.nthreads;

  std::cout << "starting benchmark..." << std::endl;

  std::vector<std::thread> threads;
  auto start = std::chrono::steady_clock::now();

  std::vector<std::unique_ptr<Worker>> workers;
  for(size_t i = 0; i < config.nthreads - 1; ++i) {
    auto nreqs = nreqs_per_thread + (nreqs_rem-- > 0);
    auto nclients = nclients_per_thread + (nclients_rem-- > 0);
    std::cout << "spawning thread #" << i << ": "
              << nclients << " concurrent clients, "
              << nreqs << " total requests"
              << std::endl;
    workers.push_back(util::make_unique<Worker>(i, ssl_ctx, nreqs, nclients,
                                                &config));
    threads.emplace_back(&Worker::run, workers.back().get());
  }
  auto nreqs_last = nreqs_per_thread + (nreqs_rem-- > 0);
  auto nclients_last = nclients_per_thread + (nclients_rem-- > 0);
  std::cout << "spawning thread #" << (config.nthreads - 1) << ": "
            << nclients_last << " concurrent clients, "
            << nreqs_last << " total requests"
            << std::endl;
  Worker worker(config.nthreads - 1, ssl_ctx, nreqs_last, nclients_last,
                &config);
  worker.run();

  for(size_t i = 0; i < config.nthreads - 1; ++i) {
    threads[i].join();
    worker.stats.req_todo += workers[i]->stats.req_todo;
    worker.stats.req_started += workers[i]->stats.req_started;
    worker.stats.req_done += workers[i]->stats.req_done;
    worker.stats.req_success += workers[i]->stats.req_success;
    worker.stats.req_failed += workers[i]->stats.req_failed;
    worker.stats.req_error += workers[i]->stats.req_error;
    worker.stats.bytes_total += workers[i]->stats.bytes_total;
    worker.stats.bytes_head += workers[i]->stats.bytes_head;
    worker.stats.bytes_body += workers[i]->stats.bytes_body;
    for(size_t j = 0; j < 6; ++j) {
      worker.stats.status[j] += workers[i]->stats.status[j];
    }
  }

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
    kbps = (worker.stats.bytes_head + worker.stats.bytes_body) / secd / 1024;
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
  return 0;
}

} // namespace h2load

int main(int argc, char **argv)
{
  return h2load::main(argc, argv);
}
