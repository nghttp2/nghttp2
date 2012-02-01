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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

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

#include "spdylay_ssl.h"

namespace spdylay {

bool ssl_debug = false;

Spdylay::Spdylay(int fd, SSL *ssl, const spdylay_session_callbacks *callbacks)
  : fd_(fd), ssl_(ssl), want_write_(false)
{
  spdylay_session_client_new(&session_, callbacks, this);
}

Spdylay::~Spdylay()
{
  spdylay_session_del(session_);
}

int Spdylay::recv()
{
  return spdylay_session_recv(session_);
}

int Spdylay::send()
{
  return spdylay_session_send(session_);
}

ssize_t Spdylay::send_data(const uint8_t *data, size_t len, int flags)
{
  ssize_t r;
  r = SSL_write(ssl_, data, len);
  return r;
}

ssize_t Spdylay::recv_data(uint8_t *data, size_t len, int flags)
{
  ssize_t r;
  want_write_ = false;
  r = SSL_read(ssl_, data, len);
  if(r < 0) {
    if(SSL_get_error(ssl_, r) == SSL_ERROR_WANT_WRITE) {
      want_write_ = true;
    }
  }
  return r;
}

bool Spdylay::want_read()
{
  return spdylay_session_want_read(session_);
}

bool Spdylay::want_write()
{
  return spdylay_session_want_write(session_) || want_write_;
}

int Spdylay::fd() const
{
  return fd_;
}

int Spdylay::submit_request(const std::string& hostport,
                            const std::string& path, uint8_t pri)
{
  const char *nv[] = {
    "host", hostport.c_str(),
    "method", "GET",
    "scheme", "https",
    "url", path.c_str(),
    "user-agent", "spdylay/0.0.0",
    "version", "HTTP/1.1",
    NULL
  };
  return spdylay_submit_request(session_, pri, nv, NULL);
}

bool Spdylay::would_block(int r)
{
  int e = SSL_get_error(ssl_, r);
  return e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ;
}

int connect_to(const std::string& host, uint16_t port)
{
  struct addrinfo hints;
  int fd = -1;
  int r;
  char service[10];
  snprintf(service, sizeof(service), "%u", port);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *res;
  r = getaddrinfo(host.c_str(), service, &hints, &res);
  if(r != 0) {
    std::cerr << "getaddrinfo: " << gai_strerror(r) << std::endl;
    return -1;
  }
  for(struct addrinfo *rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if(fd == -1) {
      continue;
    }
    while((r = connect(fd, rp->ai_addr, rp->ai_addrlen)) == -1 &&
          errno == EINTR);
    if(r == 0) {
      break;
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

int make_non_block(int fd)
{
  int flags, r;
  while((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR);
  if(flags == -1) {
    return -1;
  }
  while((r = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR);
  if(r == -1) {
    return -1;
  }
  return 0;
}

ssize_t send_callback(spdylay_session *session,
                      const uint8_t *data, size_t len, int flags,
                      void *user_data)
{
  Spdylay *sc = (Spdylay*)user_data;
  ssize_t r = sc->send_data(data, len, flags);
  if(r < 0) {
    if(sc->would_block(r)) {
      r = SPDYLAY_ERR_WOULDBLOCK;
    } else {
      r = SPDYLAY_ERR_CALLBACK_FAILURE;
    }
  }
  return r;
}

ssize_t recv_callback(spdylay_session *session,
                      uint8_t *data, size_t len, int flags, void *user_data)
{
  Spdylay *sc = (Spdylay*)user_data;
  ssize_t r = sc->recv_data(data, len, flags);
  if(r < 0) {
    if(sc->would_block(r)) {
      r = SPDYLAY_ERR_WOULDBLOCK;
    } else {
      r = SPDYLAY_ERR_CALLBACK_FAILURE;
    }
  } else if(r == 0) {
    r = SPDYLAY_ERR_CALLBACK_FAILURE;
  }
  return r;
}

namespace {
const char *ctrl_names[] = {
  "SYN_STREAM",
  "SYN_REPLY",
  "RST_STREAM",
  "SETTINGS",
  "NOOP",
  "PING",
  "GOAWAY",
  "HEADERS"
};
} // namespace

void print_nv(char **nv)
{
  int i;
  for(i = 0; nv[i]; i += 2) {
    printf("  %s: %s\n", nv[i], nv[i+1]);
  }
}

void print_timer()
{
  timeval tv;
  get_timer(&tv);
  printf("[%3ld.%03ld]", tv.tv_sec, tv.tv_usec/1000);
}

void print_frame(spdylay_frame_type type, spdylay_frame *frame)
{
  printf("%s frame ", ctrl_names[type-1]);
  switch(type) {
  case SPDYLAY_SYN_STREAM:
    printf("(stream_id=%d, assoc_stream_id=%d, flags=%u, length=%d, pri=%u)\n",
           frame->syn_stream.stream_id, frame->syn_stream.assoc_stream_id,
           frame->syn_stream.hd.flags,
           frame->syn_stream.hd.length, frame->syn_stream.pri);
    print_nv(frame->syn_stream.nv);
    break;
  case SPDYLAY_SYN_REPLY:
    printf("(stream_id=%d, flags=%u, length=%d)\n",
           frame->syn_reply.stream_id, frame->syn_reply.hd.flags,
           frame->syn_reply.hd.length);
    print_nv(frame->syn_reply.nv);
    break;
  case SPDYLAY_RST_STREAM:
    printf("(stream_id=%d, status_code=%u, flags=%u, length=%d)\n",
           frame->rst_stream.stream_id, frame->rst_stream.status_code,
           frame->rst_stream.hd.flags,
           frame->rst_stream.hd.length);
    break;
  case SPDYLAY_SETTINGS:
    printf("(flags=%u, length=%d, niv=%lu)\n",
           frame->settings.hd.flags, frame->settings.hd.length,
           static_cast<unsigned long>(frame->settings.niv));
    for(size_t i = 0; i < frame->settings.niv; ++i) {
      printf("  [%d(%u):%u]\n",
             frame->settings.iv[i].settings_id,
             frame->settings.iv[i].flags, frame->settings.iv[i].value);
    }
    break;
  case SPDYLAY_PING:
    printf("(unique_id=%d)\n", frame->ping.unique_id);
    break;
  case SPDYLAY_GOAWAY:
    printf("(last_good_stream_id=%d)\n", frame->goaway.last_good_stream_id);
    break;
  case SPDYLAY_HEADERS:
    printf("(stream_id=%d, flags=%u, length=%d)\n",
           frame->headers.stream_id, frame->headers.hd.flags,
           frame->headers.hd.length);
    print_nv(frame->headers.nv);
    break;
  default:
    printf("\n");
    break;
  }
}

void on_ctrl_recv_callback
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  print_timer();
  printf(" recv ");
  print_frame(type, frame);
  fflush(stdout);
}

void on_data_recv_callback
(spdylay_session *session, uint8_t flags, int32_t stream_id, int32_t length,
 void *user_data)
{
  print_timer();
  printf(" recv DATA frame (stream_id=%d, flags=%d, length=%d)\n",
         stream_id, flags, length);
  fflush(stdout);
}

void on_ctrl_send_callback
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  print_timer();
  printf(" send ");
  print_frame(type, frame);
  fflush(stdout);
}

void ctl_poll(pollfd *pollfd, Spdylay *sc)
{
  pollfd->events = 0;
  if(sc->want_read()) {
    pollfd->events |= POLLIN;
  }
  if(sc->want_write()) {
    pollfd->events |= POLLOUT;
  }
}

int select_next_proto_cb(SSL* ssl,
                         unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
  *out = (unsigned char*)in+1;
  *outlen = in[0];
  if(ssl_debug) {
    print_timer();
    std::cout << " NPN select next protocol: the remote server offers:"
              << std::endl;
  }
  for(unsigned int i = 0; i < inlen; i += in[i]+1) {
    if(ssl_debug) {
      std::cout << "  * ";
      std::cout.write(reinterpret_cast<const char*>(&in[i+1]), in[i]);
      std::cout << std::endl;
    }
    if(in[i] == 6 && memcmp(&in[i+1], "spdy/2", in[i]) == 0) {
      *out = (unsigned char*)in+i+1;
      *outlen = in[i];
    }
  }
  return SSL_TLSEXT_ERR_OK;
}

void setup_ssl_ctx(SSL_CTX *ssl_ctx)
{
  /* Disable SSLv2 and enable all workarounds for buggy servers */
  SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, 0);
}

int ssl_handshake(SSL *ssl, int fd)
{
  if(SSL_set_fd(ssl, fd) == 0) {
    std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
    return -1;
  }
  int r = SSL_connect(ssl);
  if(r <= 0) {
    std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
    return -1;
  }
  return 0;
}

namespace {
timeval base_tv;
} // namespace

void reset_timer()
{
  gettimeofday(&base_tv, 0);
}

void get_timer(timeval* tv)
{
  gettimeofday(tv, 0);
  tv->tv_usec -= base_tv.tv_usec;
  tv->tv_sec -= base_tv.tv_sec;
  if(tv->tv_usec < 0) {
    tv->tv_usec += 1000000;
    --tv->tv_sec;
  }
}

} // namespace spdylay
