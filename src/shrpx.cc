/*
 * nghttp2 - HTTP/2 C Library
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#include <syslog.h>
#include <signal.h>

#include <limits>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <event2/listener.h>

#include <nghttp2/nghttp2.h>

#include "shrpx_config.h"
#include "shrpx_listen_handler.h"
#include "shrpx_ssl.h"
#include "shrpx_worker_config.h"
#include "util.h"
#include "app_helper.h"
#include "ssl.h"

using namespace nghttp2;

namespace shrpx {

namespace {
const int REOPEN_LOG_SIGNAL = SIGUSR1;
} // namespace

namespace {
void ssl_acceptcb(evconnlistener *listener, int fd,
                  sockaddr *addr, int addrlen, void *arg)
{
  auto handler = static_cast<ListenHandler*>(arg);
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
int resolve_hostname(sockaddr_union *addr, size_t *addrlen,
                     const char *hostname, uint16_t port, int family)
{
  addrinfo hints;
  int rv;

  auto service = util::utos(port);
  memset(&hints, 0, sizeof(addrinfo));

  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif // AI_ADDRCONFIG
  addrinfo *res;

  rv = getaddrinfo(hostname, service.c_str(), &hints, &res);
  if(rv != 0) {
    LOG(FATAL) << "Unable to resolve address for " << hostname
               << ": " << gai_strerror(rv);
    return -1;
  }

  char host[NI_MAXHOST];
  rv = getnameinfo(res->ai_addr, res->ai_addrlen, host, sizeof(host),
                  0, 0, NI_NUMERICHOST);
  if(rv != 0) {
    LOG(FATAL) << "Address resolution for " << hostname << " failed: "
               << gai_strerror(rv);

    freeaddrinfo(res);

    return -1;
  }

  if(LOG_ENABLED(INFO)) {
    LOG(INFO) << "Address resolution for " << hostname << " succeeded: "
              << host;
  }

  memcpy(addr, res->ai_addr, res->ai_addrlen);
  *addrlen = res->ai_addrlen;
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
  addrinfo hints;
  int fd = -1;
  int rv;

  auto service = util::utos(get_config()->port);
  memset(&hints, 0, sizeof(addrinfo));
  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif // AI_ADDRCONFIG

  auto node = strcmp("*", get_config()->host.get()) == 0 ?
    nullptr : get_config()->host.get();

  addrinfo *res, *rp;
  rv = getaddrinfo(node, service.c_str(), &hints, &res);
  if(rv != 0) {
    if(LOG_ENABLED(INFO)) {
      LOG(INFO) << "Unable to get IPv" << (family == AF_INET ? "4" : "6")
                << " address for " << get_config()->host.get() << ": "
                << gai_strerror(rv);
    }
    return nullptr;
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

  if(!rp) {
    LOG(WARNING) << "Listening " << (family == AF_INET ? "IPv4" : "IPv6")
                 << " socket failed";

    freeaddrinfo(res);

    return nullptr;
  }

  char host[NI_MAXHOST];
  rv = getnameinfo(rp->ai_addr, rp->ai_addrlen, host, sizeof(host),
                   nullptr, 0, NI_NUMERICHOST);

  freeaddrinfo(res);

  if(rv != 0) {
    LOG(WARNING) << gai_strerror(rv);

    close(fd);

    return nullptr;
  }

  if(LOG_ENABLED(INFO)) {
    LOG(INFO) << "Listening on " << host << ", port " << get_config()->port;
  }

  auto evlistener = evconnlistener_new
    (handler->get_evbase(),
     ssl_acceptcb,
     handler,
     LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
     get_config()->backlog,
     fd);
  evconnlistener_set_error_cb(evlistener, evlistener_errorcb);
  return evlistener;
}
} // namespace

namespace {
void drop_privileges()
{
  if(getuid() == 0 && get_config()->uid != 0) {
    if(setgid(get_config()->gid) != 0) {
      LOG(FATAL) << "Could not change gid: " << strerror(errno);
      exit(EXIT_FAILURE);
    }
    if(setuid(get_config()->uid) != 0) {
      LOG(FATAL) << "Could not change uid: " << strerror(errno);
      exit(EXIT_FAILURE);
    }
    if(setuid(0) != -1) {
      LOG(FATAL) << "Still have root privileges?";
      exit(EXIT_FAILURE);
    }
  }
}
} // namespace

namespace {
void save_pid()
{
  std::ofstream out(get_config()->pid_file.get(), std::ios::binary);
  out << getpid() << "\n";
  out.close();
  if(!out) {
    LOG(ERROR) << "Could not save PID to file "
               << get_config()->pid_file.get();
    exit(EXIT_FAILURE);
  }
}
} // namespace

namespace {
void reopen_log_signal_cb(evutil_socket_t sig, short events, void *arg)
{
  auto listener_handler = static_cast<ListenHandler*>(arg);

  if(LOG_ENABLED(INFO)) {
    LOG(INFO) << "Reopening log files: worker_info(" << &worker_config << ")";
  }

  (void)reopen_log_files();

  if(get_config()->num_worker > 1) {
    listener_handler->worker_reopen_log_files();
  }
}
} // namespace

namespace {
std::unique_ptr<std::string> generate_time()
{
  char buf[32];

  // Format data like this:
  // 03/Jul/2014:00:19:38 +0900
  struct tm tms;
  auto now = time(nullptr);

  if(localtime_r(&now, &tms) == nullptr) {
    return util::make_unique<std::string>("");
  }

  if(strftime(buf, sizeof(buf), "%d/%b/%Y:%T %z", &tms) == 0) {
    return util::make_unique<std::string>("");
  }

  return util::make_unique<std::string>(buf);
}
} // namespace

namespace {
void refresh_cb(evutil_socket_t sig, short events, void *arg)
{
  mod_config()->cached_time = generate_time();
}
} // namespace

namespace {
int event_loop()
{
  int rv;

  auto evbase = event_base_new();
  if(!evbase) {
    LOG(FATAL) << "event_base_new() failed";
    exit(EXIT_FAILURE);
  }
  SSL_CTX *sv_ssl_ctx, *cl_ssl_ctx;

  if(get_config()->client_mode) {
    sv_ssl_ctx = nullptr;
    cl_ssl_ctx = get_config()->downstream_no_tls ?
      nullptr : ssl::create_ssl_client_context();
  } else {
    sv_ssl_ctx = get_config()->upstream_no_tls ?
      nullptr : get_config()->default_ssl_ctx;
    cl_ssl_ctx = get_config()->http2_bridge &&
      !get_config()->downstream_no_tls ?
      ssl::create_ssl_client_context() : nullptr;
  }

  auto listener_handler = new ListenHandler(evbase, sv_ssl_ctx, cl_ssl_ctx);
  if(get_config()->daemon) {
    if(daemon(0, 0) == -1) {
      LOG(FATAL) << "Failed to daemonize: " << strerror(errno);
      exit(EXIT_FAILURE);
    }
  }

  if(get_config()->pid_file) {
    save_pid();
  }

  auto evlistener6 = create_evlistener(listener_handler, AF_INET6);
  auto evlistener4 = create_evlistener(listener_handler, AF_INET);
  if(!evlistener6 && !evlistener4) {
    LOG(FATAL) << "Failed to listen on address "
               << get_config()->host.get() << ", port " << get_config()->port;
    exit(EXIT_FAILURE);
  }

  // ListenHandler loads private key, and we listen on a priveleged port.
  // After that, we drop the root privileges if needed.
  drop_privileges();

#ifndef NOTHREADS
  sigset_t signals;
  sigemptyset(&signals);
  sigaddset(&signals, REOPEN_LOG_SIGNAL);

  rv = pthread_sigmask(SIG_BLOCK, &signals, nullptr);
  if(rv != 0) {
    LOG(ERROR) << "Blocking REOPEN_LOG_SIGNAL failed: " << strerror(rv);
  }
#endif // !NOTHREADS

  if(get_config()->num_worker > 1) {
    listener_handler->create_worker_thread(get_config()->num_worker);
  } else if(get_config()->downstream_proto == PROTO_HTTP2) {
    listener_handler->create_http2_session();
  }

#ifndef NOTHREADS
  rv = pthread_sigmask(SIG_UNBLOCK, &signals, nullptr);
  if(rv != 0) {
    LOG(ERROR) << "Unblocking REOPEN_LOG_SIGNAL failed: " << strerror(rv);
  }
#endif // !NOTHREADS

  auto reopen_log_signal_event = evsignal_new(evbase, REOPEN_LOG_SIGNAL,
                                              reopen_log_signal_cb,
                                              listener_handler);

  if(!reopen_log_signal_event) {
    LOG(ERROR) << "evsignal_new failed";
  } else {
    rv = event_add(reopen_log_signal_event, nullptr);
    if(rv < 0) {
      LOG(ERROR) << "event_add for reopen_log_signal_event failed";
    }
  }

  auto refresh_event = event_new(evbase, -1, EV_PERSIST, refresh_cb,
                                 nullptr);

  if(!refresh_event) {
    LOG(ERROR) << "event_new failed";

    exit(EXIT_FAILURE);
  }

  timeval refresh_timeout = { 1, 0 };
  rv = event_add(refresh_event, &refresh_timeout);

  if(rv == -1) {
    LOG(ERROR) << "Adding refresh_event failed";

    exit(EXIT_FAILURE);
  }

  if(LOG_ENABLED(INFO)) {
    LOG(INFO) << "Entering event loop";
  }
  event_base_loop(evbase, 0);

  if(refresh_event) {
    event_free(refresh_event);
  }
  if(reopen_log_signal_event) {
    event_free(reopen_log_signal_event);
  }
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
// Returns true if regular file or symbolic link |path| exists.
bool conf_exists(const char *path)
{
  struct stat buf;
  int rv = stat(path, &buf);
  return rv == 0 && (buf.st_mode & (S_IFREG | S_IFLNK));
}
} // namespace

namespace {
const char *DEFAULT_NPN_LIST = NGHTTP2_PROTO_VERSION_ID ","
#ifdef HAVE_SPDYLAY
  "spdy/3.1,spdy/3,spdy/2,"
#endif // HAVE_SPDYLAY
  "http/1.1";
} // namespace

namespace {
const char *DEFAULT_TLS_PROTO_LIST = "TLSv1.2,TLSv1.1";
} // namespace

namespace {
void fill_default_config()
{
  memset(mod_config(), 0, sizeof(*mod_config()));

  mod_config()->verbose = false;
  mod_config()->daemon = false;

  mod_config()->server_name = "nghttpx nghttp2/" NGHTTP2_VERSION;
  mod_config()->host = strcopy("*");
  mod_config()->port = 3000;
  mod_config()->private_key_file = nullptr;
  mod_config()->private_key_passwd = nullptr;
  mod_config()->cert_file = nullptr;

  // Read timeout for HTTP2 upstream connection
  mod_config()->http2_upstream_read_timeout.tv_sec = 180;
  mod_config()->http2_upstream_read_timeout.tv_usec = 0;

  // Read timeout for non-HTTP2 upstream connection
  mod_config()->upstream_read_timeout.tv_sec = 180;
  mod_config()->upstream_read_timeout.tv_usec = 0;

  // Write timeout for HTTP2/non-HTTP2 upstream connection
  mod_config()->upstream_write_timeout.tv_sec = 60;
  mod_config()->upstream_write_timeout.tv_usec = 0;

  // Read/Write timeouts for downstream connection
  mod_config()->downstream_read_timeout.tv_sec = 900;
  mod_config()->downstream_read_timeout.tv_usec = 0;
  mod_config()->downstream_write_timeout.tv_sec = 60;
  mod_config()->downstream_write_timeout.tv_usec = 0;

  // Timeout for pooled (idle) connections
  mod_config()->downstream_idle_read_timeout.tv_sec = 60;

  // window bits for HTTP/2 and SPDY upstream/downstream connection
  // per stream. 2**16-1 = 64KiB-1, which is HTTP/2 default. Please
  // note that SPDY/3 default is 64KiB.
  mod_config()->http2_upstream_window_bits = 16;
  mod_config()->http2_downstream_window_bits = 16;

  // HTTP/2 SPDY/3.1 has connection-level flow control. The default
  // window size for HTTP/2 is 64KiB - 1. SPDY/3's default is 64KiB
  mod_config()->http2_upstream_connection_window_bits = 16;
  mod_config()->http2_downstream_connection_window_bits = 16;

  mod_config()->upstream_no_tls = false;
  mod_config()->downstream_no_tls = false;

  mod_config()->downstream_host = strcopy("127.0.0.1");
  mod_config()->downstream_port = 80;
  mod_config()->downstream_hostport = nullptr;
  mod_config()->downstream_addrlen = 0;

  mod_config()->num_worker = 1;
  mod_config()->http2_max_concurrent_streams = 100;
  mod_config()->add_x_forwarded_for = false;
  mod_config()->no_via = false;
  mod_config()->accesslog_file = nullptr;
  mod_config()->accesslog_syslog = false;
  mod_config()->errorlog_file = strcopy("/dev/stderr");
  mod_config()->errorlog_syslog = false;
  mod_config()->conf_path = strcopy("/etc/nghttpx/nghttpx.conf");
  mod_config()->syslog_facility = LOG_DAEMON;
  // Default accept() backlog
  mod_config()->backlog = -1;
  mod_config()->ciphers = nullptr;
  mod_config()->http2_proxy = false;
  mod_config()->http2_bridge = false;
  mod_config()->client_proxy = false;
  mod_config()->client = false;
  mod_config()->client_mode = false;
  mod_config()->insecure = false;
  mod_config()->cacert = nullptr;
  mod_config()->pid_file = nullptr;
  mod_config()->uid = 0;
  mod_config()->gid = 0;
  mod_config()->backend_ipv4 = false;
  mod_config()->backend_ipv6 = false;
  mod_config()->cert_tree = nullptr;
  mod_config()->downstream_http_proxy_userinfo = nullptr;
  mod_config()->downstream_http_proxy_host = nullptr;
  mod_config()->downstream_http_proxy_port = 0;
  mod_config()->downstream_http_proxy_addrlen = 0;
  mod_config()->worker_read_rate = 0;
  mod_config()->worker_read_burst = 0;
  mod_config()->worker_write_rate = 0;
  mod_config()->worker_write_burst = 0;
  mod_config()->worker_rate_limit_cfg = nullptr;
  mod_config()->verify_client = false;
  mod_config()->verify_client_cacert = nullptr;
  mod_config()->client_private_key_file = nullptr;
  mod_config()->client_cert_file = nullptr;
  mod_config()->http2_upstream_dump_request_header = nullptr;
  mod_config()->http2_upstream_dump_response_header = nullptr;
  mod_config()->http2_no_cookie_crumbling = false;
  mod_config()->upstream_frame_debug = false;
  mod_config()->padding = 0;
  mod_config()->worker_frontend_connections = 0;

  nghttp2_option_new(&mod_config()->http2_option);

  nghttp2_option_set_no_auto_window_update
    (mod_config()->http2_option, 1);

  mod_config()->tls_proto_mask = 0;
  mod_config()->cached_time = generate_time();
}
} // namespace

namespace {
size_t get_rate_limit(size_t rate_limit)
{
  if(rate_limit == 0) {
    return EV_RATE_LIMIT_MAX;
  } else {
    return rate_limit;
  }
}
} // namespace

namespace {
void print_version(std::ostream& out)
{
  out << get_config()->server_name << std::endl;
}
} // namespace

namespace {
void print_usage(std::ostream& out)
{
  out << R"(Usage: nghttpx [OPTIONS]... [<PRIVATE_KEY> <CERT>]
A reverse proxy for HTTP/2, HTTP/1 and SPDY.)" << std::endl;
}
} // namespace

namespace {
void print_help(std::ostream& out)
{
  print_usage(out);
  out << R"(
  <PRIVATE_KEY>      Set  path  to  server's  private  key.   Required
                     unless  -p,  --client  or  --frontend-no-tls  are
                     given.
  <CERT>             Set  path  to   server's  certificate.   Required
                     unless  -p,  --client  or  --frontend-no-tls  are
                     given.
Options:
  The options are categorized into several groups.

Connections:
  -b, --backend=<HOST,PORT>
                     Set backend host and port.
                     Default: ')"
      << get_config()->downstream_host.get() << ","
      << get_config()->downstream_port << R"('
  -f, --frontend=<HOST,PORT>
                     Set frontend host and port.  If <HOST> is '*', it
                     assumes  all addresses  including  both IPv4  and
                     IPv6.
                     Default: ')"
      << get_config()->host.get() << "," << get_config()->port << R"('
  --backlog=<NUM>    Set  listen  backlog  size.    If  -1  is  given,
                     libevent will choose suitable value.
                     Default: )"
      << get_config()->backlog << R"(
  --backend-ipv4     Resolve backend hostname to IPv4 address only.
  --backend-ipv6     Resolve backend hostname to IPv6 address only.

Performance:
  -n, --workers=<CORES>
                     Set the number of worker threads.
                     Default: )"
      << get_config()->num_worker << R"(
  --worker-read-rate=<RATE>
                     Set  maximum   average  read  rate   on  frontend
                     connection per worker.  Setting  0 to this option
                     means read rate is unlimited.
                     Default: )"
      << get_config()->worker_read_rate << R"(
  --worker-read-burst=<SIZE>
                     Set   maximum  read   burst   size  on   frontend
                     connection per worker.  Setting  0 to this option
                     means read burst size is unlimited.
                     Default: )"
      << get_config()->worker_read_burst << R"(
  --worker-write-rate=<RATE>
                     Set  maximum  average   write  rate  on  frontend
                     connection per worker.  Setting  0 to this option
                     means write rate is unlimited.
                     Default: )"
      << get_config()->worker_write_rate << R"(
  --worker-write-burst=<SIZE>
                     Set   maximum  write   burst  size   on  frontend
                     connection per worker.  Setting  0 to this option
                     means write burst size is unlimited.
                     Default: )"
      << get_config()->worker_write_burst << R"(
  --worker-frontend-connections=<NUM>
                     Set  maximum number  of simultaneous  connections
                     frontend accepts.  Setting 0 means unlimited.
                     Default: 0

Timeout:
  --frontend-http2-read-timeout=<SEC>
                     Specify read timeout for HTTP/2 and SPDY frontend
                     connection.
                     Default: )"
      << get_config()->http2_upstream_read_timeout.tv_sec << R"(
  --frontend-read-timeout=<SEC>
                     Specify  read   timeout  for   HTTP/1.1  frontend
                     connection.
                     Default: )"
      << get_config()->upstream_read_timeout.tv_sec << R"(
  --frontend-write-timeout=<SEC>
                     Specify   write   timeout    for   all   frontend
                     connections.
                     Default: )"
      << get_config()->upstream_write_timeout.tv_sec << R"(
  --backend-read-timeout=<SEC>
                     Specify read timeout for backend connection.
                     Default: )"
      << get_config()->downstream_read_timeout.tv_sec << R"(
  --backend-write-timeout=<SEC>
                     Specify write timeout for backend connection.
                     Default: )"
      << get_config()->downstream_write_timeout.tv_sec << R"(
  --backend-keep-alive-timeout=<SEC>
                     Specify    keep-alive    timeout   for    backend
                     connection.
                     Default: )"
      << get_config()->downstream_idle_read_timeout.tv_sec << R"(
  --backend-http-proxy-uri=<URI>
                     Specify     proxy     URI     in     the     form
                     http://[<USER>:<PASS>@]<PROXY>:<PORT>.     If   a
                     proxy requires authentication, specify <USER> and
                     <PASS>.    Note  that   they  must   be  properly
                     percent-encoded.   This proxy  is  used when  the
                     backend  connection  is  HTTP/2.  First,  make  a
                     CONNECT request  to the proxy and  it connects to
                     the  backend on  behalf of  nghttpx.  This  forms
                     tunnel.   After  that, nghttpx  performs  SSL/TLS
                     handshake with the downstream through the tunnel.
                     The timeouts  when connecting and  making CONNECT
                     request       can      be       specified      by
                     --backend-read-timeout                        and
                     --backend-write-timeout options.

SSL/TLS:
  --ciphers=<SUITE>  Set  allowed  cipher  list.  The  format  of  the
                     string  is described  in OpenSSL  ciphers(1).
  -k, --insecure
                     Don't verify backend  server's certificate if -p,
                     --client   or   --http2-bridge  are   given   and
                     --backend-no-tls is not given.
  --cacert=<PATH>    Set path  to trusted  CA certificate file  if -p,
                     --client   or   --http2-bridge  are   given   and
                     --backend-no-tls is not given.   The file must be
                     in   PEM  format.    It   can  contain   multiple
                     certificates.    If   the   linked   OpenSSL   is
                     configured to load system wide certificates, they
                     are loaded at startup regardless of this option.
  --private-key-passwd-file=<FILEPATH>
                     Path  to  file  that contains  password  for  the
                     server's private  key.  If none is  given and the
                     private  key  is   password  protected  it'll  be
                     requested interactively.
  --subcert=<KEYPATH>:<CERTPATH>
                     Specify  additional certificate  and private  key
                     file.  nghttpx will  choose certificates based on
                     the hostname  indicated by  client using  TLS SNI
                     extension.   This  option  can be  used  multiple
                     times.
  --backend-tls-sni-field=<HOST>
                     Explicitly  set  the  content   of  the  TLS  SNI
                     extension.  This will default to the backend HOST
                     name.
  --dh-param-file=<PATH>
                     Path to  file that contains DH  parameters in PEM
                     format.  Without  this option, DHE  cipher suites
                     are not available.
  --npn-list=<LIST>  Comma delimited list  of ALPN protocol identifier
                     sorted in  the order  of preference.   That means
                     most  desirable protocol  comes  first.  This  is
                     used in both ALPN and NPN.  The parameter must be
                     delimited by  a single  comma only and  any white
                     spaces are treated as a part of protocol string.
                     Default: )" << DEFAULT_NPN_LIST << R"(
  --verify-client    Require and verify client certificate.
  --verify-client-cacert=<PATH>
                     Path  to file  that contains  CA certificates  to
                     verify client  certificate.  The file must  be in
                     PEM    format.    It    can   contain    multiple
                     certificates.
  --client-private-key-file=<PATH>
                     Path  to file  that contains  client private  key
                     used in backend client authentication.
  --client-cert-file=<PATH>
                     Path  to file  that  contains client  certificate
                     used in backend client authentication.
  --tls-proto-list=<LIST>
                     Comma delimited  list of  SSL/TLS protocol  to be
                     enabled.  The following  protocols are available:
                     TLSv1.2,  TLSv1.1, TLSv1.0  and SSLv3.   The name
                     matching is done in case-insensitive manner.  The
                     parameter  must be  delimited by  a single  comma
                     only and any  white spaces are treated  as a part
                     of protocol string.
                     Default: )" << DEFAULT_TLS_PROTO_LIST << R"(

HTTP/2 and SPDY:
  -c, --http2-max-concurrent-streams=<NUM>
                     Set the maximum number  of the concurrent streams
                     in one HTTP/2 and SPDY session.
                     Default: )"
      << get_config()->http2_max_concurrent_streams << R"(
  --frontend-http2-window-bits=<N>
                     Sets the per-stream initial window size of HTTP/2
                     SPDY frontend  connection.  For HTTP/2,  the size
                     is 2**<N>-1.  For SPDY, the size is 2**<N>.
                     Default: )"
      << get_config()->http2_upstream_window_bits << R"(
  --frontend-http2-connection-window-bits=<N>
                     Sets the per-connection window size of HTTP/2 and
                     SPDY frontend  connection.  For HTTP/2,  the size
                     is 2**<N>-1. For SPDY, the size is 2**<N>.
                     Default: )"
      << get_config()->http2_upstream_connection_window_bits << R"(
  --frontend-no-tls  Disable SSL/TLS on frontend connections.
  --backend-http2-window-bits=<N>
                     Sets the  initial window  size of  HTTP/2 backend
                     connection to 2**<N>-1.
                     Default: )"
      << get_config()->http2_downstream_window_bits << R"(
  --backend-http2-connection-window-bits=<N>
                     Sets  the per-connection  window  size of  HTTP/2
                     backend connection to 2**<N>-1.
                     Default: )"
      << get_config()->http2_downstream_connection_window_bits << R"(
  --backend-no-tls   Disable SSL/TLS on backend connections.
  --http2-no-cookie-crumbling
                     Don't crumble cookie header field.
  --padding=<N>      Add at most  <N> bytes to a  HTTP/2 frame payload
                     as padding.  Specify 0  to disable padding.  This
                     option  is meant  for debugging  purpose and  not
                     intended to enhance protocol security.

Mode:
  (default mode)     Accept  HTTP/2, SPDY  and HTTP/1.1  over SSL/TLS.
                     If --frontend-no-tls  is used, accept  HTTP/2 and
                     HTTP/1.1.  The  incoming HTTP/1.1  connection can
                     be upgraded to HTTP/2  through HTTP Upgrade.  The
                     protocol to the backend is HTTP/1.1.
  -s, --http2-proxy  Like default mode, but enable secure proxy mode.
  --http2-bridge     Like  default  mode,  but  communicate  with  the
                     backend  in   HTTP/2  over  SSL/TLS.    Thus  the
                     incoming all connections  are converted to HTTP/2
                     connection  and  relayed  to  the  backend.   See
                     --backend-http-proxy-uri option if you are behind
                     the  proxy and  want  to connect  to the  outside
                     HTTP/2 proxy.
  --client           Accept HTTP/2 and  HTTP/1.1 without SSL/TLS.  The
                     incoming HTTP/1.1  connection can be  upgraded to
                     HTTP/2  connection  through  HTTP  Upgrade.   The
                     protocol  to  the  backend  is  HTTP/2.   To  use
                     nghttpx  as  a  forward   proxy,  use  -p  option
                     instead.
  -p, --client-proxy
                     Like --client  option, but  it also  requires the
                     request path  from frontend  must be  an absolute
                     URI, suitable for use as a forward proxy.

Logging:
  -L, --log-level=<LEVEL>
                     Set the  severity level  of log  output.  <LEVEL>
                     must be one of INFO, WARNING, ERROR and FATAL.
                     Default: WARNING
  --accesslog-file=<PATH>
                     Set path  to write  access log.  To  reopen file,
                     send USR1 signal to nghttpx.
  --accesslog-syslog
                     Send  access log  to syslog.   If this  option is
                     used, --access-file option is ignored.
  --errorlog-file=<PATH>
                     Set  path to  write error  log.  To  reopen file,
                     send USR1 signal to nghttpx.
                     Default: )"
      << get_config()->errorlog_file.get() << R"(
  --errorlog-syslog  Send  error log  to  syslog.  If  this option  is
                     used, --errorlog-file option is ignored.
  --syslog-facility=<FACILITY>
                     Set syslog facility to <FACILITY>.
                     Default: )"
      << str_syslog_facility(get_config()->syslog_facility) << R"(

Misc:
  --add-x-forwarded-for
                     Append  X-Forwarded-For   header  field   to  the
                     downstream request.
  --no-via           Don't append to Via  header field.  If Via header
                     field is received, it is left unaltered.
  --altsvc=<PROTOID,PORT[,HOST,[ORIGIN]]>
                     Specify  protocol ID,  port, host  and origin  of
                     alternative  service.   <HOST> and  <ORIGIN>  are
                     optional.  They are  advertised in alt-svc header
                     field or HTTP/2 ALTSVC frame.  This option can be
                     used   multiple   times   to   specify   multiple
                     alternative services.  Example: --altsvc=h2,443
  --add-response-header=<HEADER>
                     Specify  additional   header  field  to   add  to
                     response  header set.   This option  just appends
                     header field  and won't replace  anything already
                     set.  This  option can  be used several  times to
                     specify multiple header fields.
                     Example: --add-response-header="foo: bar"
  --frontend-http2-dump-request-header=<PATH>
                     Dumps request headers received by HTTP/2 frontend
                     to  the file  denoted in  <PATH>.  The  output is
                     done  in  HTTP/1  header field  format  and  each
                     header block is followed  by an empty line.  This
                     option is  not thread safe  and MUST NOT  be used
                     with option -n<N>, where <N> >= 2.
  --frontend-http2-dump-response-header=<PATH>
                     Dumps response headers  sent from HTTP/2 frontend
                     to  the file  denoted in  <PATH>.  The  output is
                     done  in  HTTP/1  header field  format  and  each
                     header block is followed  by an empty line.  This
                     option is  not thread safe  and MUST NOT  be used
                     with option -n<N>, where <N> >= 2.
  -o, --frontend-frame-debug
                     Print HTTP/2 frames in  frontend to stderr.  This
                     option is  not thread safe  and MUST NOT  be used
                     with option -n=N, where N >= 2.
  -D, --daemon
                     Run in a background.  If  -D is used, the current
                     working directory is changed to '/'.
  --pid-file=<PATH>  Set path to save PID of this program.
  --user=<USER>      Run  this  program  as <USER>.   This  option  is
                     intended to be used to drop root privileges.
  --conf=<PATH>      Load configuration from <PATH>.
                     Default: )"
      << get_config()->conf_path.get() << R"(
  -v, --version      Print version and exit.
  -h, --help         Print this help and exit.)"
      << std::endl;
}
} // namespace

int main(int argc, char **argv)
{
  Log::set_severity_level(WARNING);
  create_config();
  fill_default_config();

  std::vector<std::pair<const char*, const char*> > cmdcfgs;
  while(1) {
    static int flag = 0;
    static option long_options[] = {
      {"daemon", no_argument, nullptr, 'D'},
      {"log-level", required_argument, nullptr, 'L'},
      {"backend", required_argument, nullptr, 'b'},
      {"http2-max-concurrent-streams", required_argument, nullptr, 'c'},
      {"frontend", required_argument, nullptr, 'f'},
      {"help", no_argument, nullptr, 'h'},
      {"insecure", no_argument, nullptr, 'k'},
      {"workers", required_argument, nullptr, 'n'},
      {"client-proxy", no_argument, nullptr, 'p'},
      {"http2-proxy", no_argument, nullptr, 's'},
      {"version", no_argument, nullptr, 'v'},
      {"frontend-frame-debug", no_argument, nullptr, 'o'},
      {"add-x-forwarded-for", no_argument, &flag, 1},
      {"frontend-http2-read-timeout", required_argument, &flag, 2},
      {"frontend-read-timeout", required_argument, &flag, 3},
      {"frontend-write-timeout", required_argument, &flag, 4},
      {"backend-read-timeout", required_argument, &flag, 5},
      {"backend-write-timeout", required_argument, &flag, 6},
      {"accesslog-file", required_argument, &flag, 7},
      {"backend-keep-alive-timeout", required_argument, &flag, 8},
      {"frontend-http2-window-bits", required_argument, &flag, 9},
      {"pid-file", required_argument, &flag, 10},
      {"user", required_argument, &flag, 11},
      {"conf", required_argument, &flag, 12},
      {"syslog-facility", required_argument, &flag, 14},
      {"backlog", required_argument, &flag, 15},
      {"ciphers", required_argument, &flag, 16},
      {"client", no_argument, &flag, 17},
      {"backend-http2-window-bits", required_argument, &flag, 18},
      {"cacert", required_argument, &flag, 19},
      {"backend-ipv4", no_argument, &flag, 20},
      {"backend-ipv6", no_argument, &flag, 21},
      {"private-key-passwd-file", required_argument, &flag, 22},
      {"no-via", no_argument, &flag, 23},
      {"subcert", required_argument, &flag, 24},
      {"http2-bridge", no_argument, &flag, 25},
      {"backend-http-proxy-uri", required_argument, &flag, 26},
      {"backend-no-tls", no_argument, &flag, 27},
      {"frontend-no-tls", no_argument, &flag, 29},
      {"backend-tls-sni-field", required_argument, &flag, 31},
      {"dh-param-file", required_argument, &flag, 33},
      {"npn-list", required_argument, &flag, 38},
      {"verify-client", no_argument, &flag, 39},
      {"verify-client-cacert", required_argument, &flag, 40},
      {"client-private-key-file", required_argument, &flag, 41},
      {"client-cert-file", required_argument, &flag, 42},
      {"frontend-http2-dump-request-header", required_argument, &flag, 43},
      {"frontend-http2-dump-response-header", required_argument, &flag, 44},
      {"http2-no-cookie-crumbling", no_argument, &flag, 45},
      {"frontend-http2-connection-window-bits", required_argument, &flag, 46},
      {"backend-http2-connection-window-bits", required_argument, &flag, 47},
      {"tls-proto-list", required_argument, &flag, 48},
      {"padding", required_argument, &flag, 49},
      {"worker-read-rate", required_argument, &flag, 50},
      {"worker-read-burst", required_argument, &flag, 51},
      {"worker-write-rate", required_argument, &flag, 52},
      {"worker-write-burst", required_argument, &flag, 53},
      {"altsvc", required_argument, &flag, 54},
      {"add-response-header", required_argument, &flag, 55},
      {"worker-frontend-connections", required_argument, &flag, 56},
      {"accesslog-syslog", no_argument, &flag, 57},
      {"errorlog-file", required_argument, &flag, 58},
      {"errorlog-syslog", no_argument, &flag, 59},
      {nullptr, 0, nullptr, 0 }
    };

    int option_index = 0;
    int c = getopt_long(argc, argv, "DL:b:c:f:hkn:opsv", long_options,
                        &option_index);
    if(c == -1) {
      break;
    }
    switch(c) {
    case 'D':
      cmdcfgs.emplace_back(SHRPX_OPT_DAEMON, "yes");
      break;
    case 'L':
      cmdcfgs.emplace_back(SHRPX_OPT_LOG_LEVEL, optarg);
      break;
    case 'b':
      cmdcfgs.emplace_back(SHRPX_OPT_BACKEND, optarg);
      break;
    case 'c':
      cmdcfgs.emplace_back(SHRPX_OPT_HTTP2_MAX_CONCURRENT_STREAMS, optarg);
      break;
    case 'f':
      cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND, optarg);
      break;
    case 'h':
      print_help(std::cout);
      exit(EXIT_SUCCESS);
    case 'k':
      cmdcfgs.emplace_back(SHRPX_OPT_INSECURE, "yes");
      break;
    case 'n':
#ifdef NOTHREADS
      LOG(WARNING) << "Threading disabled at build time, no threads created.";
#else
      cmdcfgs.emplace_back(SHRPX_OPT_WORKERS, optarg);
#endif // NOTHREADS
      break;
    case 'o':
      cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_FRAME_DEBUG, "yes");
      break;
    case 'p':
      cmdcfgs.emplace_back(SHRPX_OPT_CLIENT_PROXY, "yes");
      break;
    case 's':
      cmdcfgs.emplace_back(SHRPX_OPT_HTTP2_PROXY, "yes");
      break;
    case 'v':
      print_version(std::cout);
      exit(EXIT_SUCCESS);
    case '?':
      util::show_candidates(argv[optind - 1], long_options);
      exit(EXIT_FAILURE);
    case 0:
      switch(flag) {
      case 1:
        // --add-x-forwarded-for
        cmdcfgs.emplace_back(SHRPX_OPT_ADD_X_FORWARDED_FOR, "yes");
        break;
      case 2:
        // --frontend-http2-read-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_HTTP2_READ_TIMEOUT, optarg);
        break;
      case 3:
        // --frontend-read-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_READ_TIMEOUT, optarg);
        break;
      case 4:
        // --frontend-write-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_WRITE_TIMEOUT, optarg);
        break;
      case 5:
        // --backend-read-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_READ_TIMEOUT, optarg);
        break;
      case 6:
        // --backend-write-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_WRITE_TIMEOUT, optarg);
        break;
      case 7:
        cmdcfgs.emplace_back(SHRPX_OPT_ACCESSLOG_FILE, optarg);
        break;
      case 8:
        // --backend-keep-alive-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_KEEP_ALIVE_TIMEOUT, optarg);
        break;
      case 9:
        // --frontend-http2-window-bits
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_HTTP2_WINDOW_BITS, optarg);
        break;
      case 10:
        cmdcfgs.emplace_back(SHRPX_OPT_PID_FILE, optarg);
        break;
      case 11:
        cmdcfgs.emplace_back(SHRPX_OPT_USER, optarg);
        break;
      case 12:
        // --conf
        mod_config()->conf_path = strcopy(optarg);
        break;
      case 14:
        // --syslog-facility
        cmdcfgs.emplace_back(SHRPX_OPT_SYSLOG_FACILITY, optarg);
        break;
      case 15:
        // --backlog
        cmdcfgs.emplace_back(SHRPX_OPT_BACKLOG, optarg);
        break;
      case 16:
        // --ciphers
        cmdcfgs.emplace_back(SHRPX_OPT_CIPHERS, optarg);
        break;
      case 17:
        // --client
        cmdcfgs.emplace_back(SHRPX_OPT_CLIENT, "yes");
        break;
      case 18:
        // --backend-http2-window-bits
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_HTTP2_WINDOW_BITS, optarg);
        break;
      case 19:
        // --cacert
        cmdcfgs.emplace_back(SHRPX_OPT_CACERT, optarg);
        break;
      case 20:
        // --backend-ipv4
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_IPV4, "yes");
        break;
      case 21:
        // --backend-ipv6
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_IPV6, "yes");
        break;
      case 22:
        // --private-key-passwd-file
        cmdcfgs.emplace_back(SHRPX_OPT_PRIVATE_KEY_PASSWD_FILE, optarg);
        break;
      case 23:
        // --no-via
        cmdcfgs.emplace_back(SHRPX_OPT_NO_VIA, "yes");
        break;
      case 24:
        // --subcert
        cmdcfgs.emplace_back(SHRPX_OPT_SUBCERT, optarg);
        break;
      case 25:
        // --http2-bridge
        cmdcfgs.emplace_back(SHRPX_OPT_HTTP2_BRIDGE, "yes");
        break;
      case 26:
        // --backend-http-proxy-uri
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_HTTP_PROXY_URI, optarg);
        break;
      case 27:
        // --backend-no-tls
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_NO_TLS, "yes");
        break;
      case 29:
        // --frontend-no-tls
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_NO_TLS, "yes");
        break;
      case 31:
        // --backend-tls-sni-field
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_TLS_SNI_FIELD, optarg);
        break;
      case 33:
        // --dh-param-file
        cmdcfgs.emplace_back(SHRPX_OPT_DH_PARAM_FILE, optarg);
        break;
      case 38:
        // --npn-list
        cmdcfgs.emplace_back(SHRPX_OPT_NPN_LIST, optarg);
        break;
      case 39:
        // --verify-client
        cmdcfgs.emplace_back(SHRPX_OPT_VERIFY_CLIENT, "yes");
        break;
      case 40:
        // --verify-client-cacert
        cmdcfgs.emplace_back(SHRPX_OPT_VERIFY_CLIENT_CACERT, optarg);
        break;
      case 41:
        // --client-private-key-file
        cmdcfgs.emplace_back(SHRPX_OPT_CLIENT_PRIVATE_KEY_FILE, optarg);
        break;
      case 42:
        // --client-cert-file
        cmdcfgs.emplace_back(SHRPX_OPT_CLIENT_CERT_FILE, optarg);
        break;
      case 43:
        // --frontend-http2-dump-request-header
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_HTTP2_DUMP_REQUEST_HEADER,
                             optarg);
        break;
      case 44:
        // --frontend-http2-dump-response-header
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_HTTP2_DUMP_RESPONSE_HEADER,
                             optarg);
        break;
      case 45:
        // --http2-no-cookie-crumbling
        cmdcfgs.emplace_back(SHRPX_OPT_HTTP2_NO_COOKIE_CRUMBLING, "yes");
        break;
      case 46:
        // --frontend-http2-connection-window-bits
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_HTTP2_CONNECTION_WINDOW_BITS,
                             optarg);
        break;
      case 47:
        // --backend-http2-connection-window-bits
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_HTTP2_CONNECTION_WINDOW_BITS,
                             optarg);
        break;
      case 48:
        // --tls-proto-list
        cmdcfgs.emplace_back(SHRPX_OPT_TLS_PROTO_LIST, optarg);
        break;
      case 49:
        // --padding
        cmdcfgs.emplace_back(SHRPX_OPT_PADDING, optarg);
        break;
      case 50:
        // --worker-read-rate
        cmdcfgs.emplace_back(SHRPX_OPT_WORKER_READ_RATE, optarg);
        break;
      case 51:
        // --worker-read-burst
        cmdcfgs.emplace_back(SHRPX_OPT_WORKER_READ_BURST, optarg);
        break;
      case 52:
        // --worker-write-rate
        cmdcfgs.emplace_back(SHRPX_OPT_WORKER_WRITE_RATE, optarg);
        break;
      case 53:
        // --worker-write-burst
        cmdcfgs.emplace_back(SHRPX_OPT_WORKER_WRITE_BURST, optarg);
        break;
      case 54:
        // --altsvc
        cmdcfgs.emplace_back(SHRPX_OPT_ALTSVC, optarg);
        break;
      case 55:
        // --add-response-header
        cmdcfgs.emplace_back(SHRPX_OPT_ADD_RESPONSE_HEADER, optarg);
        break;
      case 56:
        // --worker-frontend-connections
        cmdcfgs.emplace_back(SHRPX_OPT_WORKER_FRONTEND_CONNECTIONS, optarg);
        break;
      case 57:
        // --accesslog-syslog
        cmdcfgs.emplace_back(SHRPX_OPT_ACCESSLOG_SYSLOG, "yes");
        break;
      case 58:
        // --errorlog-file
        cmdcfgs.emplace_back(SHRPX_OPT_ERRORLOG_FILE, optarg);
        break;
      case 59:
        // --errorlog-syslog
        cmdcfgs.emplace_back(SHRPX_OPT_ERRORLOG_SYSLOG, "yes");
        break;
      default:
        break;
      }
      break;
    default:
      break;
    }
  }

  // Initialize OpenSSL before parsing options because we create
  // SSL_CTX there.
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  SSL_library_init();
#ifndef NOTHREADS
  nghttp2::ssl::LibsslGlobalLock();
#endif // NOTHREADS

  if(conf_exists(get_config()->conf_path.get())) {
    if(load_config(get_config()->conf_path.get()) == -1) {
      LOG(FATAL) << "Failed to load configuration from "
                 << get_config()->conf_path.get();
      exit(EXIT_FAILURE);
    }
  }

  if(argc - optind >= 2) {
    cmdcfgs.emplace_back(SHRPX_OPT_PRIVATE_KEY_FILE, argv[optind++]);
    cmdcfgs.emplace_back(SHRPX_OPT_CERTIFICATE_FILE, argv[optind++]);
  }

  for(size_t i = 0, len = cmdcfgs.size(); i < len; ++i) {
    if(parse_config(cmdcfgs[i].first, cmdcfgs[i].second) == -1) {
      LOG(FATAL) << "Failed to parse command-line argument.";
      exit(EXIT_FAILURE);
    }
  }

  if(get_config()->accesslog_syslog || get_config()->errorlog_syslog) {
    openlog("nghttpx", LOG_NDELAY | LOG_NOWAIT | LOG_PID,
            get_config()->syslog_facility);
  }

  if(reopen_log_files() != 0) {
    LOG(FATAL) << "Failed to open log file";
    exit(EXIT_FAILURE);
  }

  if(get_config()->npn_list.empty()) {
    mod_config()->npn_list = parse_config_str_list(DEFAULT_NPN_LIST);
  }
  if(get_config()->tls_proto_list.empty()) {
    mod_config()->tls_proto_list = parse_config_str_list
      (DEFAULT_TLS_PROTO_LIST);
  }

  mod_config()->tls_proto_mask =
    ssl::create_tls_proto_mask(get_config()->tls_proto_list);

  mod_config()->alpn_prefs = ssl::set_alpn_prefs(get_config()->npn_list);

  if(!get_config()->subcerts.empty()) {
    mod_config()->cert_tree = ssl::cert_lookup_tree_new();
  }

  for(auto& keycert : get_config()->subcerts) {
    auto ssl_ctx = ssl::create_ssl_context(keycert.first.c_str(),
                                           keycert.second.c_str());
    if(ssl::cert_lookup_tree_add_cert_from_file
       (get_config()->cert_tree, ssl_ctx, keycert.second.c_str()) == -1) {
      LOG(FATAL) << "Failed to add sub certificate.";
      exit(EXIT_FAILURE);
    }
  }

  if(get_config()->cert_file && get_config()->private_key_file) {
    mod_config()->default_ssl_ctx =
      ssl::create_ssl_context(get_config()->private_key_file.get(),
                              get_config()->cert_file.get());
    if(get_config()->cert_tree) {
      if(ssl::cert_lookup_tree_add_cert_from_file
         (get_config()->cert_tree,
          get_config()->default_ssl_ctx,
          get_config()->cert_file.get()) == -1) {
        LOG(FATAL) << "Failed to parse command-line argument.";
        exit(EXIT_FAILURE);
      }
    }
  }

  if(get_config()->backend_ipv4 && get_config()->backend_ipv6) {
    LOG(FATAL) << "--backend-ipv4 and --backend-ipv6 cannot be used at the "
               << "same time.";
    exit(EXIT_FAILURE);
  }

  if(get_config()->worker_frontend_connections == 0) {
    mod_config()->worker_frontend_connections =
      std::numeric_limits<size_t>::max();
  }

  if(get_config()->http2_proxy + get_config()->http2_bridge +
     get_config()->client_proxy + get_config()->client > 1) {
    LOG(FATAL) << "--http2-proxy, --http2-bridge, --client-proxy and --client "
               << "cannot be used at the same time.";
    exit(EXIT_FAILURE);
  }

  if(get_config()->client || get_config()->client_proxy) {
    mod_config()->client_mode = true;
  }

  if(get_config()->client_mode || get_config()->http2_bridge) {
    mod_config()->downstream_proto = PROTO_HTTP2;
  } else {
    mod_config()->downstream_proto = PROTO_HTTP;
  }

  if(!get_config()->client_mode && !get_config()->upstream_no_tls) {
    if(!get_config()->private_key_file || !get_config()->cert_file) {
      print_usage(std::cerr);
      LOG(FATAL) << "Too few arguments";
      exit(EXIT_FAILURE);
    }
  }

  bool downstream_ipv6_addr =
    is_ipv6_numeric_addr(get_config()->downstream_host.get());

  {
    std::string hostport;

    if(downstream_ipv6_addr) {
      hostport += "[";
    }

    hostport += get_config()->downstream_host.get();

    if(downstream_ipv6_addr) {
      hostport += "]";
    }

    hostport += ":";
    hostport += util::utos(get_config()->downstream_port);

    mod_config()->downstream_hostport = strcopy(hostport);
  }

  if(LOG_ENABLED(INFO)) {
    LOG(INFO) << "Resolving backend address";
  }
  if(resolve_hostname(&mod_config()->downstream_addr,
                      &mod_config()->downstream_addrlen,
                      get_config()->downstream_host.get(),
                      get_config()->downstream_port,
                      get_config()->backend_ipv4 ? AF_INET :
                      (get_config()->backend_ipv6 ?
                       AF_INET6 : AF_UNSPEC)) == -1) {
    exit(EXIT_FAILURE);
  }

  if(get_config()->downstream_http_proxy_host) {
    if(LOG_ENABLED(INFO)) {
      LOG(INFO) << "Resolving backend http proxy address";
    }
    if(resolve_hostname(&mod_config()->downstream_http_proxy_addr,
                        &mod_config()->downstream_http_proxy_addrlen,
                        get_config()->downstream_http_proxy_host.get(),
                        get_config()->downstream_http_proxy_port,
                        AF_UNSPEC) == -1) {
      exit(EXIT_FAILURE);
    }
  }

  mod_config()->worker_rate_limit_cfg = ev_token_bucket_cfg_new
    (get_rate_limit(get_config()->worker_read_rate),
     get_rate_limit(get_config()->worker_read_burst),
     get_rate_limit(get_config()->worker_write_rate),
     get_rate_limit(get_config()->worker_write_burst),
     nullptr);

  if(get_config()->upstream_frame_debug) {
    // To make it sync to logging
    set_output(stderr);
    if(isatty(fileno(stdout))) {
      set_color_output(true);
    }
    reset_timer();
  }

  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);

  event_loop();

  return 0;
}

} // namespace shrpx

int main(int argc, char **argv)
{
  return shrpx::main(argc, argv);
}
