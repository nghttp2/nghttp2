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
#include "shrpx_worker.h"

#include <unistd.h>
#include <sys/socket.h>

#include <event.h>
#include <event2/bufferevent.h>

#include "shrpx_ssl.h"
#include "shrpx_thread_event_receiver.h"
#include "shrpx_log.h"

namespace shrpx {

Worker::Worker(WorkerInfo *info)
  : fd_(info->sv[1]),
    ssl_ctx_(info->ssl_ctx)
{}

Worker::~Worker()
{
  shutdown(fd_, SHUT_WR);
  close(fd_);
}

namespace {
void readcb(bufferevent *bev, void *arg)
{
  ThreadEventReceiver *receiver = reinterpret_cast<ThreadEventReceiver*>(arg);
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
  event_base *evbase = event_base_new();
  bufferevent *bev = bufferevent_socket_new(evbase, fd_,
                                            BEV_OPT_DEFER_CALLBACKS);
  ThreadEventReceiver *receiver = new ThreadEventReceiver(ssl_ctx_);
  bufferevent_enable(bev, EV_READ);
  bufferevent_setcb(bev, readcb, 0, eventcb, receiver);

  event_base_loop(evbase, 0);

  delete receiver;
}

void* start_threaded_worker(void *arg)
{
  WorkerInfo *info = reinterpret_cast<WorkerInfo*>(arg);
  Worker worker(info);
  worker.run();
  return 0;
}

} // namespace shrpx
