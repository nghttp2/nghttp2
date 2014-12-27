/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2015 Tatsuhiro Tsujikawa
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
#ifndef SHRPX_RATE_LIMIT_H
#define SHRPX_RATE_LIMIT_H

#include "shrpx.h"

#include <ev.h>

namespace shrpx {

class RateLimit {
public:
  RateLimit(struct ev_loop *loop, ev_io *w, size_t rate, size_t burst);
  ~RateLimit();
  size_t avail() const;
  void drain(size_t n);
  void regen();
  void startw();
  void stopw();
private:
  ev_io *w_;
  ev_timer t_;
  struct ev_loop *loop_;
  size_t rate_;
  size_t burst_;
  size_t avail_;
  bool startw_req_;
};

} // namespace shrpx

#endif // SHRPX_RATE_LIMIT_H
