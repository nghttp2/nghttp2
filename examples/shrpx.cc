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

#include <cstdlib>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <event2/listener.h>

#include <spdylay/spdylay.h>

#include "shrpx_config.h"
#include "shrpx_listen_handler.h"

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
  LOG(INFO) << "Using first returned address for downstream "
            << get_config()->downstream_host
            << ", port "
            << get_config()->downstream_port;
  memcpy(&mod_config()->downstream_addr, res->ai_addr, res->ai_addrlen);
  mod_config()->downstream_addrlen = res->ai_addrlen;
  freeaddrinfo(res);
  return 0;
}
} // namespace

namespace {
evconnlistener* create_evlistener(ListenHandler *handler)
{
  // TODO Listen both IPv4 and IPv6
  addrinfo hints;
  int fd = -1;
  int r;
  char service[10];
  snprintf(service, sizeof(service), "%u", get_config()->port);
  memset(&hints, 0, sizeof(addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif // AI_ADDRCONFIG
  addrinfo *res, *rp;
  r = getaddrinfo(get_config()->host, service, &hints, &res);
  if(r != 0) {
    LOG(ERROR) << "getaddrinfo: " << gai_strerror(r);
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
    if(bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
      break;
    }
    close(fd);
  }
  freeaddrinfo(res);
  if(rp == 0) {
    LOG(ERROR) << "No valid address returned for host " << get_config()->host
               << ", port " << get_config()->port;
    return 0;
  }
  evconnlistener *evlistener = evconnlistener_new
    (handler->get_evbase(),
     ssl_acceptcb,
     handler,
     LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
     256,
     fd);
  return evlistener;
}
} // namespace

namespace {
int event_loop()
{
  event_base *evbase = event_base_new();
  ListenHandler *listener_handler = new ListenHandler(evbase);
  if(get_config()->num_worker > 1) {
    listener_handler->create_worker_thread(get_config()->num_worker);
  }
  evconnlistener *evlistener = create_evlistener(listener_handler);
  if(evlistener == NULL) {
    return -1;
  }
  if(ENABLE_LOG) {
    LOG(INFO) << "Entering event loop";
  }
  event_base_loop(evbase, 0);

  evconnlistener_free(evlistener);
  return 0;
}
} // namespace

int main(int argc, char **argv)
{
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);

  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  SSL_library_init();

  create_config();
  mod_config()->server_name = "shrpx spdylay/"SPDYLAY_VERSION;
  mod_config()->port = 3000;
  mod_config()->private_key_file = "server.key";
  mod_config()->cert_file = "server.crt";

  mod_config()->upstream_read_timeout.tv_sec = 30;
  mod_config()->upstream_read_timeout.tv_usec = 0;
  mod_config()->upstream_write_timeout.tv_sec = 60;
  mod_config()->upstream_write_timeout.tv_usec = 0;

  mod_config()->spdy_upstream_read_timeout.tv_sec = 600;
  mod_config()->spdy_upstream_read_timeout.tv_usec = 0;
  mod_config()->spdy_upstream_write_timeout.tv_sec = 30;
  mod_config()->spdy_upstream_write_timeout.tv_usec = 0;

  mod_config()->downstream_read_timeout.tv_sec = 30;
  mod_config()->downstream_read_timeout.tv_usec = 0;
  mod_config()->downstream_write_timeout.tv_sec = 30;
  mod_config()->downstream_write_timeout.tv_usec = 0;

  mod_config()->downstream_host = "localhost";
  mod_config()->downstream_port = 80;
  char hostport[256];
  if(get_config()->downstream_port == 80) {
    mod_config()->downstream_hostport = get_config()->downstream_host;
  } else {
    snprintf(hostport, sizeof(hostport), "%s:%u",
             get_config()->downstream_host, get_config()->downstream_port);
    mod_config()->downstream_hostport = hostport;
  }
  if(cache_downstream_host_address() == -1) {
    exit(EXIT_FAILURE);
  }

  mod_config()->num_worker = 4;

  event_loop();
  return 0;
}

} // namespace shrpx

int main(int argc, char **argv)
{
  return shrpx::main(argc, argv);
}
