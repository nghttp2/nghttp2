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
#include "shrpx_dns_tracker.h"
#include "shrpx_config.h"
#include "shrpx_log.h"
#include "util.h"

namespace shrpx {

namespace {
void gccb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto dns_tracker = static_cast<DNSTracker *>(w->data);
  dns_tracker->gc();
}
} // namespace

DNSTracker::DNSTracker(struct ev_loop *loop) : loop_(loop) {
  ev_timer_init(&gc_timer_, gccb, 0., 12_h);
  gc_timer_.data = this;
}

DNSTracker::~DNSTracker() {
  ev_timer_stop(loop_, &gc_timer_);

  for (auto &p : ents_) {
    auto &qlist = p.second.qlist;
    while (!qlist.empty()) {
      auto head = qlist.head;
      qlist.remove(head);
      head->status = DNS_STATUS_ERROR;
      head->in_qlist = false;
      // TODO Not sure we should call callback here, or it is even be
      // safe to do that.
    }
  }
}

ResolverEntry DNSTracker::make_entry(std::unique_ptr<DualDNSResolver> resolv,
                                     ImmutableString host, int status,
                                     const Address *result) {
  auto &dnsconf = get_config()->dns;

  auto ent = ResolverEntry{};
  ent.resolv = std::move(resolv);
  ent.host = std::move(host);
  ent.status = status;
  switch (status) {
  case DNS_STATUS_ERROR:
  case DNS_STATUS_OK:
    ent.expiry = ev_now(loop_) + dnsconf.timeout.cache;
    break;
  }
  if (result) {
    ent.result = *result;
  }
  return ent;
}

void DNSTracker::update_entry(ResolverEntry &ent,
                              std::unique_ptr<DualDNSResolver> resolv,
                              int status, const Address *result) {
  auto &dnsconf = get_config()->dns;

  ent.resolv = std::move(resolv);
  ent.status = status;
  switch (status) {
  case DNS_STATUS_ERROR:
  case DNS_STATUS_OK:
    ent.expiry = ev_now(loop_) + dnsconf.timeout.cache;
    break;
  }
  if (result) {
    ent.result = *result;
  }
}

int DNSTracker::resolve(Address *result, DNSQuery *dnsq) {
  int rv;

  auto it = ents_.find(dnsq->host);

  if (it == std::end(ents_)) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "DNS entry not found for " << dnsq->host;
    }

    auto resolv = make_unique<DualDNSResolver>(loop_);
    auto host_copy =
        ImmutableString{std::begin(dnsq->host), std::end(dnsq->host)};
    auto host = StringRef{host_copy};

    rv = resolv->resolve(host);
    if (rv != 0) {
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "Name lookup failed for " << host;
      }

      ents_.emplace(host, make_entry(nullptr, std::move(host_copy),
                                     DNS_STATUS_ERROR, nullptr));

      start_gc_timer();

      return DNS_STATUS_ERROR;
    }

    rv = resolv->get_status(result);
    switch (rv) {
    case DNS_STATUS_ERROR: {
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "Name lookup failed for " << host;
      }

      ents_.emplace(host, make_entry(nullptr, std::move(host_copy),
                                     DNS_STATUS_ERROR, nullptr));

      start_gc_timer();

      return DNS_STATUS_ERROR;
    }
    case DNS_STATUS_OK: {
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "Name lookup succeeded: " << host << " -> "
                  << util::numeric_name(&result->su.sa, result->len);
      }

      ents_.emplace(host, make_entry(nullptr, std::move(host_copy),
                                     DNS_STATUS_OK, result));

      start_gc_timer();

      return DNS_STATUS_OK;
    }
    case DNS_STATUS_RUNNING: {
      assert(rv == DNS_STATUS_RUNNING);

      auto p = ents_.emplace(host,
                             make_entry(std::move(resolv), std::move(host_copy),
                                        DNS_STATUS_RUNNING, nullptr));

      start_gc_timer();

      auto &ent = (*p.first).second;

      add_to_qlist(ent, dnsq);

      return DNS_STATUS_RUNNING;
    }
    default:
      assert(0);
    }
  }

  auto &ent = (*it).second;

  if (ent.status != DNS_STATUS_RUNNING && ent.expiry < ev_now(loop_)) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "DNS entry found for " << dnsq->host
                << ", but it has been expired";
    }

    auto resolv = make_unique<DualDNSResolver>(loop_);
    auto host = StringRef{ent.host};

    rv = resolv->resolve(host);
    if (rv != 0) {
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "Name lookup failed for " << host;
      }

      update_entry(ent, nullptr, DNS_STATUS_ERROR, nullptr);

      return DNS_STATUS_ERROR;
    }

    rv = resolv->get_status(result);
    switch (rv) {
    case DNS_STATUS_ERROR: {
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "Name lookup failed for " << host;
      }

      update_entry(ent, nullptr, DNS_STATUS_ERROR, nullptr);

      return DNS_STATUS_ERROR;
    }
    case DNS_STATUS_OK: {
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "Name lookup succeeded: " << host << " -> "
                  << util::numeric_name(&result->su.sa, result->len);
      }

      update_entry(ent, nullptr, DNS_STATUS_OK, result);

      return DNS_STATUS_OK;
    }
    case DNS_STATUS_RUNNING: {
      update_entry(ent, std::move(resolv), DNS_STATUS_RUNNING, nullptr);
      add_to_qlist(ent, dnsq);

      return DNS_STATUS_RUNNING;
    }
    default:
      assert(0);
    }
  }

  switch (ent.status) {
  case DNS_STATUS_RUNNING:
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Waiting for name lookup complete for " << dnsq->host;
    }
    ent.qlist.append(dnsq);
    dnsq->in_qlist = true;
    return DNS_STATUS_RUNNING;
  case DNS_STATUS_ERROR:
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Name lookup failed for " << dnsq->host << " (cached)";
    }
    return DNS_STATUS_ERROR;
  case DNS_STATUS_OK:
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Name lookup succeeded (cached): " << dnsq->host << " -> "
                << util::numeric_name(&ent.result.su.sa, ent.result.len);
    }
    if (result) {
      memcpy(result, &ent.result, sizeof(*result));
    }
    return DNS_STATUS_OK;
  default:
    assert(0);
    abort();
  }
}

void DNSTracker::add_to_qlist(ResolverEntry &ent, DNSQuery *dnsq) {
  auto loop = loop_;
  ent.resolv->set_complete_cb([&ent, loop](int status, const Address *result) {
    auto &qlist = ent.qlist;
    while (!qlist.empty()) {
      auto head = qlist.head;
      qlist.remove(head);
      head->status = status;
      head->in_qlist = false;
      auto cb = head->cb;
      cb(status, result);
    }

    auto &dnsconf = get_config()->dns;

    ent.resolv.reset();
    ent.status = status;
    ent.expiry = ev_now(loop) + dnsconf.timeout.cache;
    if (ent.status == DNS_STATUS_OK) {
      ent.result = *result;
    }
  });
  ent.qlist.append(dnsq);
  dnsq->in_qlist = true;
}

void DNSTracker::cancel(DNSQuery *dnsq) {
  if (!dnsq->in_qlist) {
    return;
  }

  auto it = ents_.find(dnsq->host);
  if (it == std::end(ents_)) {
    return;
  }

  auto &ent = (*it).second;
  ent.qlist.remove(dnsq);
  dnsq->in_qlist = false;
}

void DNSTracker::start_gc_timer() {
  if (ev_is_active(&gc_timer_)) {
    return;
  }

  ev_timer_again(loop_, &gc_timer_);
}

void DNSTracker::gc() {
  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Starting removing expired DNS cache entries";
  }

  auto now = ev_now(loop_);
  for (auto it = std::begin(ents_); it != std::end(ents_);) {
    auto &ent = (*it).second;
    if (ent.expiry >= now) {
      ++it;
      continue;
    }

    it = ents_.erase(it);
  }

  if (ents_.empty()) {
    ev_timer_stop(loop_, &gc_timer_);
  }
}

} // namespace shrpx
