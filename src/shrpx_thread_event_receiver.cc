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
#include "shrpx_thread_event_receiver.h"

#include <unistd.h>

#include "shrpx_ssl.h"
#include "shrpx_log.h"
#include "shrpx_client_handler.h"

namespace shrpx {

ThreadEventReceiver::ThreadEventReceiver(SSL_CTX *ssl_ctx)
  : ssl_ctx_(ssl_ctx)
{}

ThreadEventReceiver::~ThreadEventReceiver()
{}

void ThreadEventReceiver::on_read(bufferevent *bev)
{
  evbuffer *input = bufferevent_get_input(bev);
  while(evbuffer_get_length(input) >= sizeof(WorkerEvent)) {
    WorkerEvent wev;
    evbuffer_remove(input, &wev, sizeof(WorkerEvent));
    if(ENABLE_LOG) {
      LOG(INFO) << "WorkerEvent: client_fd=" << wev.client_fd
                << ", addrlen=" << wev.client_addrlen;
    }
    event_base *evbase = bufferevent_get_base(bev);
    ClientHandler *client_handler;
    client_handler = ssl::accept_ssl_connection(evbase, ssl_ctx_,
                                                wev.client_fd,
                                                &wev.client_addr.sa,
                                                wev.client_addrlen);
    if(client_handler) {
      if(ENABLE_LOG) {
        LOG(INFO) << "ClientHandler " << client_handler << " created";
      }
    } else {
      if(ENABLE_LOG) {
        LOG(ERROR) << "ClientHandler creation failed";
      }
      close(wev.client_fd);
    }
  }
}

} // namespace shrpx
