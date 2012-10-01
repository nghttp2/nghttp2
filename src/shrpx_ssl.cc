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
#include "shrpx_ssl.h"

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <pthread.h>

#include <openssl/crypto.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include "shrpx_log.h"
#include "shrpx_client_handler.h"
#include "shrpx_config.h"

namespace shrpx {

namespace ssl {

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
void set_npn_prefs(unsigned char *out, const char **protos, size_t len)
{
  unsigned char *ptr = out;
  for(size_t i = 0; i < len; ++i) {
    *ptr = strlen(protos[i]);
    memcpy(ptr+1, protos[i], *ptr);
    ptr += *ptr+1;
  }
}
} // namespace

SSL_CTX* create_ssl_context()
{
  SSL_CTX *ssl_ctx;
  ssl_ctx = SSL_CTX_new(SSLv23_server_method());
  if(!ssl_ctx) {
    LOG(FATAL) << ERR_error_string(ERR_get_error(), 0);
    DIE();
  }
  SSL_CTX_set_options(ssl_ctx,
                      SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION |
                      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

  const unsigned char sid_ctx[] = "shrpx";
  SSL_CTX_set_session_id_context(ssl_ctx, sid_ctx, sizeof(sid_ctx)-1);
  SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER);

  if(get_config()->ciphers) {
    if(SSL_CTX_set_cipher_list(ssl_ctx, get_config()->ciphers) == 0) {
      LOG(FATAL) << "SSL_CTX_set_cipher_list failed.";
      DIE();
    }
  }

  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  if(SSL_CTX_use_PrivateKey_file(ssl_ctx,
                                 get_config()->private_key_file,
                                 SSL_FILETYPE_PEM) != 1) {
    LOG(FATAL) << "SSL_CTX_use_PrivateKey_file failed.";
    DIE();
  }
  if(SSL_CTX_use_certificate_chain_file(ssl_ctx,
                                        get_config()->cert_file) != 1) {
    LOG(FATAL) << "SSL_CTX_use_certificate_file failed.";
    DIE();
  }
  if(SSL_CTX_check_private_key(ssl_ctx) != 1) {
    LOG(FATAL) << "SSL_CTX_check_private_key failed.";
    DIE();
  }
  if(get_config()->verify_client) {
    SSL_CTX_set_verify(ssl_ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_callback);
  }
  // We speak "http/1.1", "spdy/2" and "spdy/3".
  const char *protos[] = { "spdy/3", "spdy/2", "http/1.1" };
  set_npn_prefs(proto_list, protos, 3);

  next_proto.first = proto_list;
  next_proto.second = sizeof(proto_list);
  SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, &next_proto);
  return ssl_ctx;
}

ClientHandler* accept_ssl_connection(event_base *evbase, SSL_CTX *ssl_ctx,
                                     evutil_socket_t fd,
                                     sockaddr *addr, int addrlen)
{
  char host[NI_MAXHOST];
  int rv;
  rv = getnameinfo(addr, addrlen, host, sizeof(host), 0, 0, NI_NUMERICHOST);
  if(rv == 0) {
    SSL *ssl = SSL_new(ssl_ctx);
    if(!ssl) {
      LOG(ERROR) << "SSL_new() failed";
      return 0;
    }
    int val = 1;
    rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                    reinterpret_cast<char *>(&val), sizeof(val));
    if(rv == -1) {
      LOG(WARNING) << "Setting option TCP_NODELAY failed";
    }
    bufferevent *bev = bufferevent_openssl_socket_new
      (evbase, fd, ssl,
       BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_DEFER_CALLBACKS);

    ClientHandler *client_handler = new ClientHandler(bev, ssl, host);
    return client_handler;
  } else {
    LOG(ERROR) << "getnameinfo() failed: " << gai_strerror(rv);
    return 0;
  }
}

namespace {
pthread_mutex_t *ssl_locks;
} // namespace

namespace {
void ssl_locking_cb(int mode, int type, const char *file, int line)
{
  if(mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(ssl_locks[type]));
  } else {
    pthread_mutex_unlock(&(ssl_locks[type]));
  }
}
} // namespace

void setup_ssl_lock()
{
  ssl_locks = new pthread_mutex_t[CRYPTO_num_locks()];
  for(int i = 0; i < CRYPTO_num_locks(); ++i) {
    // Always returns 0
    pthread_mutex_init(&(ssl_locks[i]), 0);
  }
  //CRYPTO_set_id_callback(ssl_thread_id); OpenSSL manual says that if
  // threadid_func is not specified using
  // CRYPTO_THREADID_set_callback(), then default implementation is
  // used. We use this default one.
  CRYPTO_set_locking_callback(ssl_locking_cb);
}

void teardown_ssl_lock()
{
  for(int i = 0; i < CRYPTO_num_locks(); ++i) {
    pthread_mutex_destroy(&(ssl_locks[i]));
  }
  delete [] ssl_locks;
}

} // namespace ssl

} // namespace shrpx
