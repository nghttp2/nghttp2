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
#include "shrpx_worker.h"

#include <unistd.h>
#include <sys/socket.h>

#include <memory>

#include <event.h>
#include <event2/bufferevent.h>

#include "shrpx_ssl.h"
#include "shrpx_thread_event_receiver.h"
#include "shrpx_log.h"
#include "shrpx_http2_session.h"
#include "util.h"

using namespace nghttp2;

namespace shrpx {

Worker::Worker(WorkerInfo *info)
  : sv_ssl_ctx_(info->sv_ssl_ctx),
    cl_ssl_ctx_(info->cl_ssl_ctx),
    fd_(info->sv[1])
{}

Worker::~Worker()
{
  shutdown(fd_, SHUT_WR);
  close(fd_);
}

namespace {
void readcb(bufferevent *bev, void *arg)
{
  auto receiver = static_cast<ThreadEventReceiver*>(arg);
  receiver->on_read(bev);
}
} // namespace

namespace {
void eventcb(bufferevent *bev, short events, void *arg)
{
  if(events & BEV_EVENT_EOF) {
    LOG(ERROR) << "Connection to main thread lost: eof";
  }
  if(events & BEV_EVENT_ERROR) {
    LOG(ERROR) << "Connection to main thread lost: network error";
  }
}
} // namespace

void Worker::run()
{
  auto evbase = std::unique_ptr<event_base, decltype(&event_base_free)>
    (event_base_new(), event_base_free);
  if(!evbase) {
    LOG(ERROR) << "event_base_new() failed";
    return;
  }
  auto bev = std::unique_ptr<bufferevent, decltype(&bufferevent_free)>
    (bufferevent_socket_new(evbase.get(), fd_, BEV_OPT_DEFER_CALLBACKS),
     bufferevent_free);
  if(!bev) {
    LOG(ERROR) << "bufferevent_socket_new() failed";
    return;
  }
  std::unique_ptr<Http2Session> http2session;
  if(get_config()->downstream_proto == PROTO_HTTP2) {
    http2session = util::make_unique<Http2Session>(evbase.get(), cl_ssl_ctx_);
    if(http2session->init_notification() == -1) {
      DIE();
    }
  }
  auto receiver = util::make_unique<ThreadEventReceiver>(evbase.get(),
                                                         sv_ssl_ctx_,
                                                         http2session.get());
  bufferevent_enable(bev.get(), EV_READ);
  bufferevent_setcb(bev.get(), readcb, nullptr, eventcb, receiver.get());

  event_base_loop(evbase.get(), 0);
}

void start_threaded_worker(WorkerInfo *info)
{
  Worker worker(info);
  worker.run();
}

} // namespace shrpx
