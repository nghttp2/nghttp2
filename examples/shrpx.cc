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
#include "shrpx.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>

#include <limits>
#include <cstdlib>
#include <iostream>
#include <fstream>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <event2/listener.h>

#include <spdylay/spdylay.h>

#include "shrpx_config.h"
#include "shrpx_listen_handler.h"
#include "shrpx_ssl.h"

namespace shrpx {

namespace {
void ssl_acceptcb(evconnlistener *listener, int fd,
                  sockaddr *addr, int addrlen, void *arg)
{
  ListenHandler *handler = reinterpret_cast<ListenHandler*>(arg);
  handler->accept_connection(fd, addr, addrlen);
}
} // namespace

namespace {
bool is_ipv6_numeric_addr(const char *host)
{
  uint8_t dst[16];
  return inet_pton(AF_INET6, host, dst) == 1;
}
} // namespace

namespace {
int cache_downstream_host_address()
{
  addrinfo hints;
  int rv;
  char service[10];

  snprintf(service, sizeof(service), "%u", get_config()->downstream_port);
  memset(&hints, 0, sizeof(addrinfo));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif // AI_ADDRCONFIG
  addrinfo *res;

  rv = getaddrinfo(get_config()->downstream_host, service, &hints, &res);
  if(rv != 0) {
    LOG(FATAL) << "Unable to get downstream address: " << gai_strerror(rv);
    DIE();
  }

  char host[NI_MAXHOST];
  rv = getnameinfo(res->ai_addr, res->ai_addrlen, host, sizeof(host),
                  0, 0, NI_NUMERICHOST);
  if(rv == 0) {
    LOG(INFO) << "Using first returned address for downstream "
              << host
              << ", port "
              << get_config()->downstream_port;
  } else {
    LOG(FATAL) << gai_strerror(rv);
    DIE();
  }
  memcpy(&mod_config()->downstream_addr, res->ai_addr, res->ai_addrlen);
  mod_config()->downstream_addrlen = res->ai_addrlen;
  freeaddrinfo(res);
  return 0;
}
} // namespace

namespace {
void evlistener_errorcb(evconnlistener *listener, void *ptr)
{
  LOG(ERROR) << "Accepting incoming connection failed";
}
} // namespace

namespace {
evconnlistener* create_evlistener(ListenHandler *handler, int family)
{
  // TODO Listen both IPv4 and IPv6
  addrinfo hints;
  int fd = -1;
  int r;
  char service[10];
  snprintf(service, sizeof(service), "%u", get_config()->port);
  memset(&hints, 0, sizeof(addrinfo));
  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif // AI_ADDRCONFIG

  addrinfo *res, *rp;
  r = getaddrinfo(get_config()->host, service, &hints, &res);
  if(r != 0) {
    LOG(INFO) << "Unable to get address for " << get_config()->host << ": "
               << gai_strerror(r);
    return NULL;
  }
  for(rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
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
    if(family == AF_INET6) {
      if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val,
                    static_cast<socklen_t>(sizeof(val))) == -1) {
        close(fd);
        continue;
      }
    }
#endif // IPV6_V6ONLY
    if(bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
      break;
    }
    close(fd);
  }
  if(rp) {
    char host[NI_MAXHOST];
    r = getnameinfo(rp->ai_addr, rp->ai_addrlen, host, sizeof(host),
                        0, 0, NI_NUMERICHOST);
    if(r == 0) {
      LOG(INFO) << "Listening on " << host << ", port " << get_config()->port;
    } else {
      LOG(FATAL) << gai_strerror(r);
      DIE();
    }
  }
  freeaddrinfo(res);
  if(rp == 0) {
    if(ENABLE_LOG) {
      LOG(INFO) << "Listening " << (family == AF_INET ? "IPv4" : "IPv6")
                << " socket failed";
    }
    return 0;
  }

  evconnlistener *evlistener = evconnlistener_new
    (handler->get_evbase(),
     ssl_acceptcb,
     handler,
     LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
     512,
     fd);
  evconnlistener_set_error_cb(evlistener, evlistener_errorcb);
  return evlistener;
}
} // namespace

namespace {
int event_loop()
{
  event_base *evbase = event_base_new();

  ListenHandler *listener_handler = new ListenHandler(evbase);

  evconnlistener *evlistener6, *evlistener4;
  evlistener6 = create_evlistener(listener_handler, AF_INET6);
  evlistener4 = create_evlistener(listener_handler, AF_INET);
  if(!evlistener6 && !evlistener4) {
    LOG(FATAL) << "Failed to listen on address "
               << get_config()->host << ", port " << get_config()->port;
    exit(EXIT_FAILURE);
  }

  if(get_config()->num_worker > 1) {
    listener_handler->create_worker_thread(get_config()->num_worker);
  }

  if(ENABLE_LOG) {
    LOG(INFO) << "Entering event loop";
  }
  event_base_loop(evbase, 0);
  if(evlistener4) {
    evconnlistener_free(evlistener4);
  }
  if(evlistener6) {
    evconnlistener_free(evlistener6);
  }
  return 0;
}
} // namespace

namespace {
void save_pid()
{
  std::ofstream out(get_config()->pid_file, std::ios::binary);
  out << getpid() << "\n";
  out.close();
  if(!out) {
    LOG(ERROR) << "Could not save PID to file " << get_config()->pid_file;
    exit(EXIT_FAILURE);
  }
}
} // namespace

namespace {
void fill_default_config()
{
  mod_config()->daemon = false;

  mod_config()->server_name = "shrpx spdylay/"SPDYLAY_VERSION;
  mod_config()->host = "localhost";
  mod_config()->port = 3000;
  mod_config()->private_key_file = 0;
  mod_config()->cert_file = 0;

  // Read timeout for SPDY upstream connection
  mod_config()->spdy_upstream_read_timeout.tv_sec = 180;
  mod_config()->spdy_upstream_read_timeout.tv_usec = 0;

  // Read timeout for non-SPDY upstream connection
  mod_config()->upstream_read_timeout.tv_sec = 180;
  mod_config()->upstream_read_timeout.tv_usec = 0;

  // Write timeout for SPDY/non-SPDY upstream connection
  mod_config()->upstream_write_timeout.tv_sec = 60;
  mod_config()->upstream_write_timeout.tv_usec = 0;

  // Read/Write timeouts for downstream connection
  mod_config()->downstream_read_timeout.tv_sec = 900;
  mod_config()->downstream_read_timeout.tv_usec = 0;
  mod_config()->downstream_write_timeout.tv_sec = 60;
  mod_config()->downstream_write_timeout.tv_usec = 0;

  // Timeout for pooled (idle) connections
  mod_config()->downstream_idle_read_timeout.tv_sec = 60;

  // window bits for SPDY upstream connection
  // 2**16 = 64KiB, which is SPDY/3 default.
  mod_config()->spdy_upstream_window_bits = 16;

  mod_config()->downstream_host = "localhost";
  mod_config()->downstream_port = 80;

  mod_config()->num_worker = 1;

  mod_config()->spdy_max_concurrent_streams =
    SPDYLAY_INITIAL_MAX_CONCURRENT_STREAMS;
}
} // namespace

namespace {
int split_host_port(char *host, size_t hostlen, uint16_t *port_ptr,
                    const char *hostport)
{
  // host and port in |hostport| is separated by single ','.
  const char *p = strchr(hostport, ',');
  if(!p) {
    std::cerr << "Invalid host, port: " << hostport << std::endl;
    return -1;
  }
  size_t len = p-hostport;
  if(hostlen < len+1) {
    std::cerr << "Hostname too long: " << hostport << std::endl;
    return -1;
  }
  memcpy(host, hostport, len);
  host[len] = '\0';

  errno = 0;
  unsigned long d = strtoul(p+1, 0, 10);
  if(errno == 0 && 1 <= d && d <= std::numeric_limits<uint16_t>::max()) {
    *port_ptr = d;
    return 0;
  } else {
    std::cerr << "Port is invalid: " << p+1 << std::endl;
    return -1;
  }
}
} // namespace

namespace {
void print_usage(std::ostream& out)
{
  out << "Usage: shrpx [-Dhs] [-b <HOST,PORT>] [-f <HOST,PORT>] [-n <CORES>]\n"
      << "             [-c <NUM>] [-L <LEVEL>] [OPTIONS...]\n"
      << "             <PRIVATE_KEY> <CERT>\n"
      << "\n"
      << "A reverse proxy for SPDY/HTTPS.\n"
      << std::endl;
}
} // namespace

namespace {
void print_help(std::ostream& out)
{
  fill_default_config();
  print_usage(out);
  out << "\n"
      << "OPTIONS:\n"
      << "    -b, --backend=<HOST,PORT>\n"
      << "                       Set backend host and port.\n"
      << "                       Default: '"
      << get_config()->downstream_host << ","
      << get_config()->downstream_port << "'\n"
      << "    -f, --frontend=<HOST,PORT>\n"
      << "                       Set frontend host and port.\n"
      << "                       Default: '"
      << get_config()->host << "," << get_config()->port << "'\n"
      << "    -n, --workers=<CORES>\n"
      << "                       Set the number of worker threads.\n"
      << "                       Default: "
      << get_config()->num_worker << "\n"
      << "    -c, --spdy-max-concurrent-streams=<NUM>\n"
      << "                       Set the maximum number of the concurrent\n"
      << "                       streams in one SPDY session.\n"
      << "                       Default: "
      << get_config()->spdy_max_concurrent_streams << "\n"
      << "    -L, --log-level=<LEVEL>\n"
      << "                       Set the severity level of log output.\n"
      << "                       INFO, WARNING, ERROR and FATAL.\n"
      << "                       Default: WARNING\n"
      << "    -D, --daemon       Run in a background. If -D is used, the\n"
      << "                       current working directory is changed to '/'.\n"
      << "    -s, --spdy-proxy   SSL/SPDY proxy mode.\n"
      << "    --add-x-forwarded-for\n"
      << "                       Append X-Forwarded-For header field to the\n"
      << "                       downstream request.\n"
      << "    --frontend-spdy-read-timeout=<SEC>\n"
      << "                       Specify read timeout for SPDY frontend\n"
      << "                       connection. Default: "
      << get_config()->spdy_upstream_read_timeout.tv_sec << "\n"
      << "    --frontend-read-timeout=<SEC>\n"
      << "                       Specify read timeout for non-SPDY frontend\n"
      << "                       connection. Default: "
      << get_config()->upstream_read_timeout.tv_sec << "\n"
      << "    --frontend-write-timeout=<SEC>\n"
      << "                       Specify write timeout for both SPDY and\n"
      << "                       non-SPDY frontends.\n"
      << "                       connection. Default: "
      << get_config()->upstream_write_timeout.tv_sec << "\n"
      << "    --backend-read-timeout=<SEC>\n"
      << "                       Specify read timeout for backend connection.\n"
      << "                       Default: "
      << get_config()->downstream_read_timeout.tv_sec << "\n"
      << "    --backend-write-timeout=<SEC>\n"
      << "                       Specify write timeout for backend\n"
      << "                       connection. Default: "
      << get_config()->downstream_write_timeout.tv_sec << "\n"
      << "    --backend-keep-alive-timeout=<SEC>\n"
      << "                       Specify keep-alive timeout for backend\n"
      << "                       connection. Default: "
      << get_config()->downstream_idle_read_timeout.tv_sec << "\n"
      << "    --accesslog        Print simple accesslog to stderr.\n"
      << "    --frontend-spdy-window-bits=<N>\n"
      << "                       Sets the initial window size of SPDY\n"
      << "                       frontend connection to 2**<N>.\n"
      << "                       Default: "
      << get_config()->spdy_upstream_window_bits << "\n"
      << "    --pid-file=<PATH>  Set path to save PID of this program.\n"
      << "    --user=<USER>      Run this program as USER. This option is\n"
      << "                       intended to be used to drop root privileges.\n"
      << "    -h, --help         Print this help.\n"
      << std::endl;
}
} // namespace

int main(int argc, char **argv)
{
  Log::set_severity_level(WARNING);
  create_config();
  fill_default_config();

  char frontend_host[NI_MAXHOST];
  uint16_t frontend_port;
  char backend_host[NI_MAXHOST];
  uint16_t backend_port;

  while(1) {
    int flag;
    static option long_options[] = {
      {"backend", required_argument, 0, 'b' },
      {"frontend", required_argument, 0, 'f' },
      {"workers", required_argument, 0, 'n' },
      {"spdy-max-concurrent-streams", required_argument, 0, 'c' },
      {"log-level", required_argument, 0, 'L' },
      {"daemon", no_argument, 0, 'D' },
      {"spdy-proxy", no_argument, 0, 's' },
      {"add-x-forwarded-for", no_argument, &flag, 1 },
      {"frontend-spdy-read-timeout", required_argument, &flag, 2 },
      {"frontend-read-timeout", required_argument, &flag, 3 },
      {"frontend-write-timeout", required_argument, &flag, 4 },
      {"backend-read-timeout", required_argument, &flag, 5 },
      {"backend-write-timeout", required_argument, &flag, 6 },
      {"accesslog", no_argument, &flag, 7 },
      {"backend-keep-alive-timeout", required_argument, &flag, 8 },
      {"frontend-spdy-window-bits", required_argument, &flag, 9 },
      {"pid-file", required_argument, &flag, 10 },
      {"user", required_argument, &flag, 11 },
      {"help", no_argument, 0, 'h' },
      {0, 0, 0, 0 }
    };
    int option_index = 0;
    int c = getopt_long(argc, argv, "DL:sb:c:f:n:h", long_options,
                        &option_index);
    if(c == -1) {
      break;
    }
    switch(c) {
    case 'D':
      mod_config()->daemon = true;
      break;
    case 'h':
      print_help(std::cout);
      exit(EXIT_SUCCESS);
    case 'L':
      if(Log::set_severity_level_by_name(optarg) == -1) {
        std::cerr << "Invalid severity level: " << optarg << std::endl;
        exit(EXIT_SUCCESS);
      }
      break;
    case 'b':
      if(split_host_port(backend_host, sizeof(backend_host),
                         &backend_port, optarg) == -1) {
        exit(EXIT_FAILURE);
      } else {
        mod_config()->downstream_host = backend_host;
        mod_config()->downstream_port = backend_port;
      }
      break;
    case 'f':
      if(split_host_port(frontend_host, sizeof(frontend_host),
                         &frontend_port, optarg) == -1) {
        exit(EXIT_FAILURE);
      } else {
        mod_config()->host = frontend_host;
        mod_config()->port = frontend_port;
      }
      break;
    case 'n':
      mod_config()->num_worker = strtol(optarg, 0, 10);
      break;
    case 'c':
      mod_config()->spdy_max_concurrent_streams = strtol(optarg, 0, 10);
      break;
    case 's':
      mod_config()->spdy_proxy = true;
      break;
    case '?':
      exit(EXIT_FAILURE);
    case 0:
      switch(flag) {
      case 1:
        // --add-x-forwarded-for
        mod_config()->add_x_forwarded_for = true;
        break;
      case 2: {
        // --frontend-spdy-read-timeout
        timeval tv = {strtol(optarg, 0, 10), 0};
        mod_config()->spdy_upstream_read_timeout = tv;
        break;
      }
      case 3: {
        // --frontend-read-timeout
        timeval tv = {strtol(optarg, 0, 10), 0};
        mod_config()->upstream_read_timeout = tv;
        break;
      }
      case 4: {
        // --frontend-write-timeout
        timeval tv = {strtol(optarg, 0, 10), 0};
        mod_config()->upstream_write_timeout = tv;
        break;
      }
      case 5: {
        // --backend-read-timeout
        timeval tv = {strtol(optarg, 0, 10), 0};
        mod_config()->downstream_read_timeout = tv;
        break;
      }
      case 6: {
        // --backend-write-timeout
        timeval tv = {strtol(optarg, 0, 10), 0};
        mod_config()->downstream_write_timeout = tv;
        break;
      }
      case 7:
        mod_config()->accesslog = true;
        break;
      case 8: {
        // --backend-keep-alive-timeout
        timeval tv = {strtol(optarg, 0, 10), 0};
        mod_config()->downstream_idle_read_timeout = tv;
        break;
      }
      case 9: {
        // --frontend-spdy-window-bits
        errno = 0;
        unsigned long int n = strtoul(optarg, 0, 10);
        if(errno == 0 && n < 31) {
          mod_config()->spdy_upstream_window_bits = n;
        } else {
          std::cerr << "-w: specify the integer in the range [0, 30], inclusive"
                    << std::endl;
          exit(EXIT_FAILURE);
        }
        break;
      }
      case 10:
        mod_config()->pid_file = optarg;
        break;
      case 11: {
        passwd *pwd = getpwnam(optarg);
        if(pwd == 0) {
          std::cerr << "--user: failed to get uid from " << optarg
                    << ": " << strerror(errno) << std::endl;
          exit(EXIT_FAILURE);
        }
        mod_config()->uid = pwd->pw_uid;
        mod_config()->gid = pwd->pw_gid;
        break;
      }
      default:
        break;
      }
      break;
    default:
      break;
    }
  }

  if(argc-optind < 2) {
    print_usage(std::cerr);
    std::cerr << "Too few arguments" << std::endl;
    exit(EXIT_FAILURE);
  }

  mod_config()->private_key_file = argv[optind++];
  mod_config()->cert_file = argv[optind++];

  char hostport[NI_MAXHOST+16];
  bool downstream_ipv6_addr =
    is_ipv6_numeric_addr(get_config()->downstream_host);
  if(get_config()->downstream_port == 80) {
    snprintf(hostport, sizeof(hostport), "%s%s%s",
             downstream_ipv6_addr ? "[" : "",
             get_config()->downstream_host,
             downstream_ipv6_addr ? "]" : "");
  } else {
    snprintf(hostport, sizeof(hostport), "%s%s%s:%u",
             downstream_ipv6_addr ? "[" : "",
             get_config()->downstream_host,
             downstream_ipv6_addr ? "]" : "",
             get_config()->downstream_port);
  }
  mod_config()->downstream_hostport = hostport;

  if(cache_downstream_host_address() == -1) {
    exit(EXIT_FAILURE);
  }

  if(get_config()->daemon) {
    if(daemon(0, 0) == -1) {
      perror("daemon");
      exit(EXIT_FAILURE);
    }
  }
  if(get_config()->pid_file) {
    save_pid();
  }
  if(getuid() == 0 && get_config()->uid != 0) {
    if(setgid(get_config()->gid) != 0) {
      std::cerr << "Could not change gid: " << strerror(errno) << std::endl;
      exit(EXIT_FAILURE);
    }
    if(setuid(get_config()->uid) != 0) {
      std::cerr << "Could not change uid: " << strerror(errno) << std::endl;
      exit(EXIT_FAILURE);
    }
    if(setuid(0) != -1) {
      std::cerr << "FATAL: Still have root privileges?" << std::endl;
      exit(EXIT_FAILURE);
    }
  }

  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);

  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  SSL_library_init();
  ssl::setup_ssl_lock();

  event_loop();

  ssl::teardown_ssl_lock();

  return 0;
}

} // namespace shrpx

int main(int argc, char **argv)
{
  return shrpx::main(argc, argv);
}
