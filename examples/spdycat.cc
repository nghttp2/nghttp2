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

#include "spdylay_ssl.h"
#include "uri.h"

namespace spdylay {

std::string target_path;
int32_t target_stream_id;
bool debug = false;
extern bool ssl_debug;

void on_data_chunk_recv_callback
(spdylay_session *session, uint8_t flags, int32_t stream_id,
 const uint8_t *data, size_t len, void *user_data)
{
  if(!debug && stream_id == target_stream_id) {
    std::cout.write(reinterpret_cast<const char*>(data), len);
  }
}

void check_stream_id(spdylay_frame_type type, spdylay_frame *frame)
{
  if(type == SPDYLAY_SYN_STREAM) {
    for(int i = 0; frame->syn_stream.nv[i]; i += 2) {
      if(strcmp("url", frame->syn_stream.nv[i]) == 0) {
        if(target_path == frame->syn_stream.nv[i+1]) {
          target_stream_id = frame->syn_stream.stream_id;
        }
        break;
      }
    }
  }
}

void on_ctrl_send_callback2
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  check_stream_id(type, frame);
}

void on_ctrl_send_callback3
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  check_stream_id(type, frame);
  on_ctrl_send_callback(session, type, frame, user_data);
}

void on_stream_close_callback
(spdylay_session *session, int32_t stream_id, spdylay_status_code status_code,
 void *user_data)
{
  if(target_stream_id == stream_id) {
    spdylay_submit_goaway(session);
  }
}

int communicate(const std::string& host, uint16_t port,
                const std::string& path,
                const spdylay_session_callbacks *callbacks)
{
  target_path = path;
  ssl_debug = debug;
  int fd = connect_to(host, port);
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
  setup_ssl_ctx(ssl_ctx);
  SSL *ssl = SSL_new(ssl_ctx);
  if(!ssl) {
    std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
    return -1;
  }
  if(ssl_handshake(ssl, fd) == -1) {
    return -1;
  }
  make_non_block(fd);
  Spdylay sc(fd, ssl, callbacks);
  int epollfd = epoll_create(1);
  if(epollfd == -1) {
    perror("epoll_create");
    return -1;
  }
  sc.submit_request(path, 3);

  ctl_epollev(epollfd, EPOLL_CTL_ADD, &sc);
  static const size_t MAX_EVENTS = 1;
  epoll_event events[MAX_EVENTS];
  bool ok = true;
  while(sc.want_read() || sc.want_write()) {
    int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
    if(nfds == -1) {
      perror("epoll_wait");
      return -1;
    }
    for(int n = 0; n < nfds; ++n) {
      if(((events[n].events & EPOLLIN) && sc.recv() != 0) ||
         ((events[n].events & EPOLLOUT) && sc.send() != 0)) {
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
    ctl_epollev(epollfd, EPOLL_CTL_MOD, &sc);
  }

  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  shutdown(fd, SHUT_WR);
  close(fd);
  return ok ? 0 : -1;
}

int run(const std::string& host, uint16_t port, const std::string& path)
{
  spdylay_session_callbacks callbacks;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = send_callback;
  callbacks.recv_callback = recv_callback;
  callbacks.on_stream_close_callback = on_stream_close_callback;
  if(debug) {
    callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback;
    callbacks.on_data_recv_callback = on_data_recv_callback;
    callbacks.on_ctrl_send_callback = on_ctrl_send_callback3;
  } else {
    callbacks.on_ctrl_send_callback = on_ctrl_send_callback2;
    callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  }
  return communicate(host, port, path, &callbacks);
}

} // namespace spdylay

void print_usage(const char *prog)
{
  std::cerr << "Usage: " << prog << " [-d] URI" << std::endl;
  std::cerr << "   Get the resource identified by URI via spdy/2 protocol and\n"
            << "   output the resource.\n"
            << "\n"
            << "   -d: Output debug information instead of output the resource."
            << std::endl;
}

int main(int argc, char **argv)
{
  std::string uri;
  if(argc == 2) {
    spdylay::debug = false;
    uri = argv[1];
  } else if(argc == 3 && strcmp(argv[1], "-d") == 0) {
    spdylay::debug = true;
    uri = argv[2];
  } else {
    print_usage(basename(argv[0]));
    exit(EXIT_FAILURE);
  }
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);
  SSL_load_error_strings();
  SSL_library_init();
  spdylay::uri::UriStruct us;
  if(!spdylay::uri::parse(us, uri)) {
    std::cerr << "Could not parse URI" << std::endl;
    exit(EXIT_FAILURE);
  }
  spdylay::run(us.host, us.port, us.dir+us.file+us.query);
  return 0;
}
