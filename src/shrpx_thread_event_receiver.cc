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
#include "shrpx_thread_event_receiver.h"

#include <unistd.h>

#include "shrpx_ssl.h"
#include "shrpx_log.h"
#include "shrpx_client_handler.h"
#include "shrpx_http2_session.h"
#include "shrpx_worker.h"
#include "util.h"

using namespace nghttp2;

namespace shrpx {

ThreadEventReceiver::ThreadEventReceiver(event_base *evbase,
                                         SSL_CTX *ssl_ctx,
                                         Http2Session *http2session)
  : evbase_(evbase),
    ssl_ctx_(ssl_ctx),
    http2session_(http2session),
    rate_limit_group_(bufferevent_rate_limit_group_new
                      (evbase_, get_config()->worker_rate_limit_cfg)),
    worker_stat_(util::make_unique<WorkerStat>())
{}

ThreadEventReceiver::~ThreadEventReceiver()
{
  bufferevent_rate_limit_group_free(rate_limit_group_);
}

void ThreadEventReceiver::on_read(bufferevent *bev)
{
  auto input = bufferevent_get_input(bev);
  while(evbuffer_get_length(input) >= sizeof(WorkerEvent)) {
    WorkerEvent wev;
    int nread = evbuffer_remove(input, &wev, sizeof(wev));
    if(nread == -1) {
      TLOG(FATAL, this) << "evbuffer_remove() failed";
      continue;
    }
    if(nread != sizeof(wev)) {
      TLOG(FATAL, this) << "evbuffer_remove() removed fewer bytes. Expected:"
                        << sizeof(wev) << " Actual:" << nread;
      continue;
    }
    if(LOG_ENABLED(INFO)) {
      TLOG(INFO, this) << "WorkerEvent: client_fd=" << wev.client_fd
                       << ", addrlen=" << wev.client_addrlen;
    }

    if(worker_stat_->num_connections >=
       get_config()->worker_frontend_connections) {

      if(LOG_ENABLED(INFO)) {
        TLOG(INFO, this) << "Too many connections >= "
                         << get_config()->worker_frontend_connections;
      }

      close(wev.client_fd);

      continue;
    }

    auto evbase = bufferevent_get_base(bev);
    auto client_handler = ssl::accept_connection(evbase, rate_limit_group_,
                                                 ssl_ctx_,
                                                 wev.client_fd,
                                                 &wev.client_addr.sa,
                                                 wev.client_addrlen,
                                                 worker_stat_.get());
    if(client_handler) {
      client_handler->set_http2_session(http2session_);

      if(LOG_ENABLED(INFO)) {
        TLOG(INFO, this) << "CLIENT_HANDLER:" << client_handler << " created";
      }
    } else {
      if(LOG_ENABLED(INFO)) {
        TLOG(ERROR, this) << "ClientHandler creation failed";
      }
      close(wev.client_fd);
    }
  }
}

} // namespace shrpx
