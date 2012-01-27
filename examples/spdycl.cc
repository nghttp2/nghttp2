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
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>

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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <spdylay/spdylay.h>

int connect_to(const char *host, const char *service)
{
  struct addrinfo hints;
  int fd = -1;
  int r;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *res;
  r = getaddrinfo(host, service, &hints, &res);
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

class SpdylayClient {
public:
  SpdylayClient(int fd, SSL *ssl,
                const spdylay_session_callbacks *callbacks)
    : fd_(fd), ssl_(ssl), want_write_(false)
  {
    spdylay_session_client_new(&session_, callbacks, this);
  }
  ~SpdylayClient()
  {
    spdylay_session_del(session_);
    SSL_shutdown(ssl_);
    shutdown(fd_, SHUT_WR);
    close(fd_);
    SSL_free(ssl_);
  }
  int on_read_event()
  {
    return spdylay_session_recv(session_);
  }
  int on_write_event()
  {
    return spdylay_session_send(session_);
  }
  ssize_t send_data(const uint8_t *data, size_t len, int flags)
  {
    ssize_t r;
    r = SSL_write(ssl_, data, len);
    return r;
  }
  ssize_t recv_data(uint8_t *data, size_t len, int flags)
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
  bool want_read()
  {
    return spdylay_session_want_read(session_);
  }
  bool want_write()
  {
    return spdylay_session_want_write(session_) || want_write_;
  }
  int fd() const
  {
    return fd_;
  }
  int submit_request(const char *path)
  {
    const char *nv[] = {
      "method", "GET",
      "scheme", "https",
      "url", path,
      "version", "HTTP/1.1",
      NULL
    };
    return spdylay_submit_request(session_, 3, nv);
  }
  bool would_block(int r)
  {
    int e = SSL_get_error(ssl_, r);
    return e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ;
  }
private:
  int fd_;
  SSL *ssl_;
  spdylay_session *session_;
  bool want_write_;
};

ssize_t send_callback(spdylay_session *session,
                      const uint8_t *data, size_t len, int flags,
                      void *user_data)
{
  SpdylayClient *sc = (SpdylayClient*)user_data;
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
  SpdylayClient *sc = (SpdylayClient*)user_data;
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

void print_nv(char **nv)
{
  int i;
  for(i = 0; nv[i]; i += 2) {
    printf("  %s: %s\n", nv[i], nv[i+1]);
  }
}

static const char *ctrl_names[] = {
  "SYN_STREAM",
  "SYN_REPLY",
  "RST_STREAM",
  "SETTINGS",
  "NOOP",
  "PING",
  "GOAWAY",
  "HEADERS"
};

void on_ctrl_recv_callback
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  printf("recv %s frame ", ctrl_names[type-1]);
  switch(type) {
  case SPDYLAY_SYN_REPLY:
    printf("(stream_id=%d, flags=%d, length=%d)\n",
           frame->syn_reply.stream_id, frame->syn_reply.hd.flags,
           frame->syn_reply.hd.length);
    print_nv(frame->syn_reply.nv);
    break;
  default:
    break;
  }
}

void on_data_chunk_recv_callback
(spdylay_session *session, uint8_t flags, int32_t stream_id,
 const uint8_t *data, size_t len, void *user_data)
{}

void on_data_recv_callback
(spdylay_session *session, uint8_t flags, int32_t stream_id, int32_t length,
 void *user_data)
{
  printf("recv DATA frame (stream_id=%d, flags=%d, length=%d)\n",
         stream_id, flags, length);
}

void on_ctrl_send_callback
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  printf("send %s frame ", ctrl_names[type-1]);
  switch(type) {
  case SPDYLAY_SYN_STREAM:
    printf("(stream_id=%d, flags=%d, length=%d)\n",
           frame->syn_stream.stream_id, frame->syn_stream.hd.flags,
           frame->syn_stream.hd.length);
    print_nv(frame->syn_stream.nv);
    break;
  default:
    break;
  }
}

void ctl_epollev(int epollfd, int op, SpdylayClient& sc)
{
  epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  if(sc.want_read()) {
    ev.events |= EPOLLIN;
  }
  if(sc.want_write()) {
    ev.events |= EPOLLOUT;
  }
  if(epoll_ctl(epollfd, op, sc.fd(), &ev) == -1) {
    perror("epoll_ctl");
    exit(EXIT_FAILURE);
  }
}

int select_next_proto_cb(SSL* ssl,
                         unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
  *out = (unsigned char*)in+1;
  *outlen = in[0];
  std::cout << "NPN select next proto: server offers:" << std::endl;
  for(unsigned int i = 0; i < inlen; i += in[i]+1) {
    std::cout << "* " << std::string(&in[i+1], &in[i+1]+in[i]) << std::endl;
    if(in[i] == 6 && memcmp(&in[i+1], "spdy/2", in[i]) == 0) {
      *out = (unsigned char*)in+i+1;
      *outlen = in[i];
    }
  }
  return SSL_TLSEXT_ERR_OK;


  int status = SSL_select_next_proto(out, outlen, in, inlen,
                                     (const unsigned char*)"spdy/2", 6);
  switch(status) {
  case OPENSSL_NPN_UNSUPPORTED:
    std::cerr << "npn unsupported" << std::endl;
    break;
  case OPENSSL_NPN_NEGOTIATED:
    std::cout << "npn negotiated" << std::endl;
    break;
  case OPENSSL_NPN_NO_OVERLAP:
    std::cout << "npn no overlap" << std::endl;
    break;
  default:
    std::cout << "not reached?" << std::endl;
  }
  return SSL_TLSEXT_ERR_OK;
}

int communicate(const char *host, const char *service, const char *path,
                const spdylay_session_callbacks *callbacks)
{
  int r;
  int fd = connect_to(host, service);
  if(fd == -1) {
    std::cerr << "Could not connect to the host" << std::endl;
    return -1;
  }
  SSL_CTX *ssl_ctx;
  ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if(!ssl_ctx) {
    std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
    return -1;
  }
  /* Disable SSLv2 and enable all workarounds for buggy servers */
  SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, 0);

  SSL *ssl = SSL_new(ssl_ctx);
  if(!ssl) {
    std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
    return -1;
  }

  if(SSL_set_fd(ssl, fd) == 0) {
    std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
    return -1;
  }
  r = SSL_connect(ssl);
  if(r <= 0) {
    std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
    return -1;
  }

  make_non_block(fd);
  SpdylayClient sc(fd, ssl, callbacks);
  int epollfd = epoll_create(1);
  if(epollfd == -1) {
    perror("epoll_create");
    return -1;
  }

  sc.submit_request(path);

  ctl_epollev(epollfd, EPOLL_CTL_ADD, sc);
  static const size_t MAX_EVENTS = 1;
  epoll_event events[MAX_EVENTS];
  bool ok = true;
  while(1) {
    int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
    if(nfds == -1) {
      perror("epoll_wait");
      return -1;
    }
    for(int n = 0; n < nfds; ++n) {
      if(((events[n].events & EPOLLIN) && sc.on_read_event() != 0) ||
         ((events[n].events & EPOLLOUT) && sc.on_write_event() != 0)) {
        ok = false;
        std::cout << "Fatal" << std::endl;
        break;
      }
      if((events[n].events & EPOLLHUP) || (events[n].events & EPOLLERR)) {
        std::cout << "HUP" << std::endl;
        ok = false;
        break;
      }
    }
    if(!ok) {
      break;
    }
    ctl_epollev(epollfd, EPOLL_CTL_MOD, sc);
  }


  return ok ? 0 : -1;
}

int run(const char *host, const char *service, const char *path)
{
  spdylay_session_callbacks callbacks;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = send_callback;
  callbacks.recv_callback = recv_callback;
  callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback;
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks.on_data_recv_callback = on_data_recv_callback;
  callbacks.on_ctrl_send_callback = on_ctrl_send_callback;
  return communicate(host, service, path, &callbacks);
}

int main(int argc, char **argv)
{
  if(argc < 2) {
    std::cerr << "Usage: " << argv[0] << " HOST PORT PATH" << std::endl;
    exit(EXIT_FAILURE);
  }
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);
  const char *host = argv[1];
  const char *service = argv[2];
  const char *path = argv[3];
  SSL_load_error_strings();
  SSL_library_init();
  run(host, service, path);
  return 0;
}
