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
#include "shrpx_downstream_connection.h"

#include "shrpx_client_handler.h"
#include "shrpx_upstream.h"
#include "shrpx_downstream.h"
#include "shrpx_config.h"
#include "shrpx_error.h"

namespace shrpx {

// Workaround for the inability for Bufferevent to remove timeout from
// bufferevent. Specify this long timeout instead of removing.
namespace {
timeval max_timeout = { 86400, 0 };
} // namespace

DownstreamConnection::DownstreamConnection(ClientHandler *client_handler)
  : client_handler_(client_handler),
    bev_(0),
    downstream_(0)
{

}

DownstreamConnection::~DownstreamConnection()
{
  if(bev_) {
    bufferevent_disable(bev_, EV_READ | EV_WRITE);
    bufferevent_free(bev_);
  }
  // Downstream and DownstreamConnection may be deleted
  // asynchronously.
  if(downstream_) {
    downstream_->set_downstream_connection(0);
  }
}

int DownstreamConnection::attach_downstream(Downstream *downstream)
{
  if(ENABLE_LOG) {
    LOG(INFO) << "Attaching downstream connection " << this << " to "
              << "downstream " << downstream;
  }
  Upstream *upstream = downstream->get_upstream();
  if(!bev_) {
    event_base *evbase = client_handler_->get_evbase();
    bev_ = bufferevent_socket_new
      (evbase, -1,
       BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    int rv = bufferevent_socket_connect
      (bev_,
       // TODO maybe not thread-safe?
       const_cast<sockaddr*>(&get_config()->downstream_addr.sa),
       get_config()->downstream_addrlen);
    if(rv != 0) {
      bufferevent_free(bev_);
      bev_ = 0;
      return SHRPX_ERR_NETWORK;
    }
    if(ENABLE_LOG) {
      LOG(INFO) << "Connecting to downstream server " << this;
    }
  }
  downstream->set_downstream_connection(this);
  downstream_ = downstream;
  bufferevent_setwatermark(bev_, EV_READ, 0, SHRPX_READ_WARTER_MARK);
  bufferevent_enable(bev_, EV_READ);
  bufferevent_setcb(bev_,
                    upstream->get_downstream_readcb(),
                    upstream->get_downstream_writecb(),
                    upstream->get_downstream_eventcb(), this);
  // HTTP request/response model, we first issue request to downstream
  // server, so just enable write timeout here.
  bufferevent_set_timeouts(bev_,
                           &max_timeout,
                           &get_config()->downstream_write_timeout);
  return 0;
}

// When downstream request is issued, call this function to set read
// timeout. We don't know when the request is completely received by
// the downstream server. This function may be called before that
// happens. Overall it does not cause problem for most of the time.
// If the downstream server is too slow to recv/send, the connection
// will be dropped by read timeout.
void DownstreamConnection::start_waiting_response()
{
  if(bev_) {
    bufferevent_set_timeouts(bev_,
                             &get_config()->downstream_read_timeout,
                             &get_config()->downstream_write_timeout);
  }
}

namespace {
// Gets called when DownstreamConnection is pooled in ClientHandler.
void idle_eventcb(bufferevent *bev, short events, void *arg)
{
  DownstreamConnection *dconn = reinterpret_cast<DownstreamConnection*>(arg);
  if(events & BEV_EVENT_CONNECTED) {
    // Downstream was detached before connection established?
    // This may be safe to be left.
    if(ENABLE_LOG) {
      LOG(INFO) << "Idle downstream connected?" << dconn;
    }
    return;
  }
  if(events & BEV_EVENT_EOF) {
    if(ENABLE_LOG) {
      LOG(INFO) << "Idle downstream connection EOF " << dconn;
    }
  } else if(events & BEV_EVENT_TIMEOUT) {
    if(ENABLE_LOG) {
      LOG(INFO) << "Idle downstream connection timeout " << dconn;
    }
  } else if(events & BEV_EVENT_ERROR) {
    if(ENABLE_LOG) {
      LOG(INFO) << "Idle downstream connection error " << dconn;
    }
  }
  ClientHandler *client_handler = dconn->get_client_handler();
  client_handler->remove_downstream_connection(dconn);
  delete dconn;
}
} // namespace

void DownstreamConnection::detach_downstream(Downstream *downstream)
{
  if(ENABLE_LOG) {
    LOG(INFO) << "Detaching downstream connection " << this << " from "
              << "downstream " << downstream;
  }
  downstream->set_downstream_connection(0);
  downstream_ = 0;
  bufferevent_enable(bev_, EV_READ);
  bufferevent_setcb(bev_, 0, 0, idle_eventcb, this);
  // On idle state, just enable read timeout. Normally idle downstream
  // connection will get EOF from the downstream server and closed.
  bufferevent_set_timeouts(bev_,
                           &get_config()->downstream_idle_read_timeout,
                           &get_config()->downstream_write_timeout);
  client_handler_->pool_downstream_connection(this);
}

ClientHandler* DownstreamConnection::get_client_handler()
{
  return client_handler_;
}

Downstream* DownstreamConnection::get_downstream()
{
  return downstream_;
}

bufferevent* DownstreamConnection::get_bev()
{
  return bev_;
}

} // namespace shrpx
