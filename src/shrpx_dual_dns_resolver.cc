/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2016 Tatsuhiro Tsujikawa
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
#include "shrpx_dual_dns_resolver.h"

namespace shrpx {

DualDNSResolver::DualDNSResolver(struct ev_loop *loop)
    : resolv4_(loop), resolv6_(loop) {
  auto cb = [this](int, const Address *) {
    int rv;
    Address result;

    rv = this->get_status(&result);
    switch (rv) {
    case DNS_STATUS_ERROR:
    case DNS_STATUS_OK:
      break;
    default:
      return;
    }

    auto cb = this->get_complete_cb();
    cb(rv, &result);
  };

  resolv4_.set_complete_cb(cb);
  resolv6_.set_complete_cb(cb);
}

int DualDNSResolver::resolve(const StringRef &host) {
  int rv4, rv6;
  rv4 = resolv4_.resolve(host, AF_INET);
  rv6 = resolv6_.resolve(host, AF_INET6);

  if (rv4 != 0 && rv6 != 0) {
    return -1;
  }

  return 0;
}

CompleteCb DualDNSResolver::get_complete_cb() const { return complete_cb_; }

void DualDNSResolver::set_complete_cb(CompleteCb cb) { complete_cb_ = cb; }

int DualDNSResolver::get_status(Address *result) const {
  int rv4, rv6;
  rv6 = resolv6_.get_status(result);
  if (rv6 == DNS_STATUS_OK) {
    return DNS_STATUS_OK;
  }
  rv4 = resolv4_.get_status(result);
  if (rv4 == DNS_STATUS_OK) {
    return DNS_STATUS_OK;
  }
  if (rv4 == DNS_STATUS_RUNNING || rv6 == DNS_STATUS_RUNNING) {
    return DNS_STATUS_RUNNING;
  }
  if (rv4 == DNS_STATUS_ERROR || rv6 == DNS_STATUS_ERROR) {
    return DNS_STATUS_ERROR;
  }
  return DNS_STATUS_IDLE;
}

} // namespace shrpx
