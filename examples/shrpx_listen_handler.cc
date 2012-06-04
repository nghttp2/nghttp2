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
#include "shrpx_listen_handler.h"

#include <event2/bufferevent_ssl.h>

#include "shrpx_client_handler.h"

namespace shrpx {

ListenHandler::ListenHandler(event_base *evbase, SSL_CTX *ssl_ctx)
  : evbase_(evbase),
    ssl_ctx_(ssl_ctx)
{}

ListenHandler::~ListenHandler()
{}

int ListenHandler::accept_connection(evutil_socket_t fd,
                                     sockaddr *addr, int addrlen)
{
  if(ENABLE_LOG) {
    LOG(INFO) << "<listener> Accepted connection. fd=" << fd;
  }
  char host[NI_MAXHOST];
  int rv;
  rv = getnameinfo(addr, addrlen, host, sizeof(host), 0, 0, NI_NUMERICHOST);
  if(rv == 0) {
    SSL *ssl = SSL_new(ssl_ctx_);
    bufferevent *bev = bufferevent_openssl_socket_new
      (evbase_, fd, ssl,
       BUFFEREVENT_SSL_ACCEPTING,
       BEV_OPT_DEFER_CALLBACKS);
    if(bev == NULL) {
      if(ENABLE_LOG) {
        LOG(ERROR) << "<listener> bufferevent_openssl_socket_new failed";
      }
      close(fd);
    } else {
      /*ClientHandler *client_handler =*/ new ClientHandler(bev, ssl, host);
    }
  } else {
    if(ENABLE_LOG) {
      LOG(INFO) << "<listener> getnameinfo failed";
    }
    close(fd);
  }
  return 0;
}

event_base* ListenHandler::get_evbase() const
{
  return evbase_;
}

} // namespace shrpx
