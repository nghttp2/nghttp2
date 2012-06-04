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
#include <iostream>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <event2/listener.h>

#include <spdylay/spdylay.h>

#include "shrpx_config.h"
#include "shrpx_listen_handler.h"

namespace shrpx {

namespace {
std::pair<unsigned char*, size_t> next_proto;
unsigned char proto_list[23];
} // namespace

namespace {
int next_proto_cb(SSL *s, const unsigned char **data, unsigned int *len,
                  void *arg)
{
  std::pair<unsigned char*, size_t> *next_proto =
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
SSL_CTX* create_ssl_ctx()
{
  // TODO lock function
  SSL_CTX *ssl_ctx;
  ssl_ctx = SSL_CTX_new(SSLv23_server_method());
  if(!ssl_ctx) {
    std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
    return NULL;
  }
  SSL_CTX_set_options(ssl_ctx,
                      SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  if(SSL_CTX_use_PrivateKey_file(ssl_ctx,
                                 get_config()->private_key_file,
                                 SSL_FILETYPE_PEM) != 1) {
    std::cerr << "SSL_CTX_use_PrivateKey_file failed." << std::endl;
    return NULL;
  }
  if(SSL_CTX_use_certificate_file(ssl_ctx, get_config()->cert_file,
                                  SSL_FILETYPE_PEM) != 1) {
    std::cerr << "SSL_CTX_use_certificate_file failed." << std::endl;
    return NULL;
  }
  if(SSL_CTX_check_private_key(ssl_ctx) != 1) {
    std::cerr << "SSL_CTX_check_private_key failed." << std::endl;
    return NULL;
  }
  if(get_config()->verify_client) {
    SSL_CTX_set_verify(ssl_ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_callback);
  }
  // We speaks "http/1.1", "spdy/2" and "spdy/3".
  proto_list[0] = 6;
  memcpy(&proto_list[1], "spdy/3", 6);
  proto_list[7] = 6;
  memcpy(&proto_list[8], "spdy/2", 6);
  proto_list[14] = 8;
  memcpy(&proto_list[15], "http/1.1", 8);

  next_proto.first = proto_list;
  next_proto.second = sizeof(proto_list);
  SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, &next_proto);
  return ssl_ctx;
}
} // namespace

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
  addrinfo *res, *rp;
  rv = getaddrinfo(get_config()->downstream_host, service, &hints, &res);
  if(rv != 0) {
    LOG(ERROR) << "getaddrinfo: " << gai_strerror(rv);
    return -1;
  }
  for(rp = res; rp; rp = rp->ai_next) {
    int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if(fd == -1) {
      continue;
    }
    rv = connect(fd, rp->ai_addr, rp->ai_addrlen);
    close(fd);
    if(rv == -1) {
      continue;
    }
    break;
  }
  if(rp == 0 && res) {
    LOG(INFO) << "Using first returned address for downstream "
               << get_config()->downstream_host
               << ", port "
               << get_config()->downstream_port;
    rp = res;
  }
  if(rp != 0) {
    memcpy(&mod_config()->downstream_addr, rp->ai_addr, rp->ai_addrlen);
    mod_config()->downstream_addrlen = rp->ai_addrlen;
  }
  freeaddrinfo(res);
  if(rp == 0) {
    LOG(ERROR) << "No usable address found for downstream "
               << get_config()->downstream_host
               << ", port "
               << get_config()->downstream_port;
    return -1;
  } else {
    return 0;
  }
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
  SSL_CTX *ssl_ctx = create_ssl_ctx();
  if(ssl_ctx == NULL) {
    return -1;
  }
  event_base *evbase = event_base_new();
  ListenHandler *listener_handler = new ListenHandler(evbase, ssl_ctx);
  evconnlistener *evlistener = create_evlistener(listener_handler);
  if(evlistener == NULL) {
    return -1;
  }
  if(ENABLE_LOG) {
    LOG(INFO) << "Entering event loop";
  }
  event_base_loop(evbase, 0);

  evconnlistener_free(evlistener);
  SSL_CTX_free(ssl_ctx);
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
  mod_config()->upstream_write_timeout.tv_sec = 30;
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
  event_loop();
  return 0;
}

} // namespace shrpx

int main(int argc, char **argv)
{
  return shrpx::main(argc, argv);
}
