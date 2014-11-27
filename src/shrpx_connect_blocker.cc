/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
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
#include "shrpx_connect_blocker.h"

namespace shrpx {

namespace {
const int INITIAL_SLEEP = 2;
} // namespace

ConnectBlocker::ConnectBlocker() : timerev_(nullptr), sleep_(INITIAL_SLEEP) {}

ConnectBlocker::~ConnectBlocker() {
  if (timerev_) {
    event_free(timerev_);
  }
}

namespace {
void connect_blocker_cb(evutil_socket_t sig, short events, void *arg) {
  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "unblock downstream connection";
  }
}
} // namespace

int ConnectBlocker::init(event_base *evbase) {
  timerev_ = evtimer_new(evbase, connect_blocker_cb, this);

  if (timerev_ == nullptr) {
    return -1;
  }

  return 0;
}

bool ConnectBlocker::blocked() const {
  return evtimer_pending(timerev_, nullptr);
}

void ConnectBlocker::on_success() { sleep_ = INITIAL_SLEEP; }

void ConnectBlocker::on_failure() {
  int rv;

  sleep_ = std::min(128, sleep_ * 2);

  LOG(WARN) << "connect failure, start sleeping " << sleep_;

  timeval t = {sleep_, 0};

  rv = evtimer_add(timerev_, &t);

  if (rv == -1) {
    LOG(ERROR) << "evtimer_add for ConnectBlocker timerev_ failed";
  }
}

} // namespace shrpx
