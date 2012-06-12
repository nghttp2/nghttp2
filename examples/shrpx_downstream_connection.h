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
#ifndef SHRPX_DOWNSTREAM_CONNECTION_H
#define SHRPX_DOWNSTREAM_CONNECTION_H

#include "shrpx.h"

#include <event.h>
#include <event2/bufferevent.h>

namespace shrpx {

class ClientHandler;
class Downstream;

class DownstreamConnection {
public:
  DownstreamConnection(ClientHandler *client_handler);
  ~DownstreamConnection();
  int attach_downstream(Downstream *downstream);
  void detach_downstream(Downstream *downstream);
  bufferevent* get_bev();
  int push_data(const void *data, size_t len);

  ClientHandler* get_client_handler();
  Downstream* get_downstream();
  void start_waiting_response();
private:
  ClientHandler *client_handler_;
  bufferevent *bev_;
  Downstream *downstream_;
};

} // namespace shrpx

#endif // SHRPX_DOWNSTREAM_CONNECTION_H
