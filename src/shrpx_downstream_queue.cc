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
#include "shrpx_downstream_queue.h"

#include <cassert>
#include <limits>

#include "shrpx_downstream.h"

namespace shrpx {

DownstreamQueue::HostEntry::HostEntry() : num_active(0) {}

DownstreamQueue::DownstreamQueue(size_t conn_max_per_host)
    : conn_max_per_host_(conn_max_per_host == 0
                             ? std::numeric_limits<size_t>::max()
                             : conn_max_per_host) {}

DownstreamQueue::~DownstreamQueue() {}

void DownstreamQueue::add_pending(std::unique_ptr<Downstream> downstream) {
  auto stream_id = downstream->get_stream_id();
  pending_downstreams_[stream_id] = std::move(downstream);
}

void DownstreamQueue::add_failure(std::unique_ptr<Downstream> downstream) {
  auto stream_id = downstream->get_stream_id();
  failure_downstreams_[stream_id] = std::move(downstream);
}

DownstreamQueue::HostEntry &
DownstreamQueue::find_host_entry(const std::string &host) {
  auto itr = host_entries_.find(host);
  if (itr == std::end(host_entries_)) {
    std::tie(itr, std::ignore) = host_entries_.emplace(host, HostEntry());
  }
  return (*itr).second;
}

void DownstreamQueue::add_active(std::unique_ptr<Downstream> downstream) {
  auto &ent = find_host_entry(downstream->get_request_http2_authority());
  ++ent.num_active;

  auto stream_id = downstream->get_stream_id();
  active_downstreams_[stream_id] = std::move(downstream);
}

void DownstreamQueue::add_blocked(std::unique_ptr<Downstream> downstream) {
  auto &ent = find_host_entry(downstream->get_request_http2_authority());
  auto stream_id = downstream->get_stream_id();
  ent.blocked.insert(stream_id);
  blocked_downstreams_[stream_id] = std::move(downstream);
}

bool DownstreamQueue::can_activate(const std::string &host) const {
  auto itr = host_entries_.find(host);
  if (itr == std::end(host_entries_)) {
    return true;
  }
  auto &ent = (*itr).second;
  return ent.num_active < conn_max_per_host_;
}

namespace {
std::unique_ptr<Downstream>
pop_downstream(DownstreamQueue::DownstreamMap::iterator i,
               DownstreamQueue::DownstreamMap &downstreams) {
  auto downstream = std::move((*i).second);
  downstreams.erase(i);
  return downstream;
}
} // namespace

namespace {
bool remove_host_entry_if_empty(const DownstreamQueue::HostEntry &ent,
                                DownstreamQueue::HostEntryMap &host_entries,
                                const std::string &host) {
  if (ent.blocked.empty() && ent.num_active == 0) {
    host_entries.erase(host);
    return true;
  }
  return false;
}
} // namespace

std::unique_ptr<Downstream> DownstreamQueue::pop_pending(int32_t stream_id) {
  auto itr = pending_downstreams_.find(stream_id);
  if (itr == std::end(pending_downstreams_)) {
    return nullptr;
  }
  return pop_downstream(itr, pending_downstreams_);
}

std::unique_ptr<Downstream>
DownstreamQueue::remove_and_pop_blocked(int32_t stream_id) {
  auto kv = active_downstreams_.find(stream_id);

  if (kv != std::end(active_downstreams_)) {
    auto downstream = pop_downstream(kv, active_downstreams_);
    auto &host = downstream->get_request_http2_authority();
    auto &ent = find_host_entry(host);
    --ent.num_active;

    if (remove_host_entry_if_empty(ent, host_entries_, host)) {
      return nullptr;
    }

    if (ent.blocked.empty() || ent.num_active >= conn_max_per_host_) {
      return nullptr;
    }

    auto next_stream_id = *std::begin(ent.blocked);
    ent.blocked.erase(std::begin(ent.blocked));

    auto itr = blocked_downstreams_.find(next_stream_id);
    assert(itr != std::end(blocked_downstreams_));

    auto next_downstream = pop_downstream(itr, blocked_downstreams_);

    remove_host_entry_if_empty(ent, host_entries_, host);

    return next_downstream;
  }

  kv = blocked_downstreams_.find(stream_id);

  if (kv != std::end(blocked_downstreams_)) {
    auto downstream = pop_downstream(kv, blocked_downstreams_);
    auto &host = downstream->get_request_http2_authority();
    auto &ent = find_host_entry(host);
    ent.blocked.erase(stream_id);

    remove_host_entry_if_empty(ent, host_entries_, host);

    return nullptr;
  }

  kv = pending_downstreams_.find(stream_id);

  if (kv != std::end(pending_downstreams_)) {
    pop_downstream(kv, pending_downstreams_);
    return nullptr;
  }

  kv = failure_downstreams_.find(stream_id);

  if (kv != std::end(failure_downstreams_)) {
    pop_downstream(kv, failure_downstreams_);
    return nullptr;
  }

  return nullptr;
}

Downstream *DownstreamQueue::find(int32_t stream_id) {
  auto kv = active_downstreams_.find(stream_id);

  if (kv != std::end(active_downstreams_)) {
    return (*kv).second.get();
  }

  kv = blocked_downstreams_.find(stream_id);

  if (kv != std::end(blocked_downstreams_)) {
    return (*kv).second.get();
  }

  kv = pending_downstreams_.find(stream_id);

  if (kv != std::end(pending_downstreams_)) {
    return (*kv).second.get();
  }

  kv = failure_downstreams_.find(stream_id);

  if (kv != std::end(failure_downstreams_)) {
    return (*kv).second.get();
  }

  return nullptr;
}

const DownstreamQueue::DownstreamMap &
DownstreamQueue::get_active_downstreams() const {
  return active_downstreams_;
}

} // namespace shrpx
