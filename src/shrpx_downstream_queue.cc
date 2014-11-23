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

#include "shrpx_downstream.h"

namespace shrpx {

DownstreamQueue::DownstreamQueue()
{}

DownstreamQueue::~DownstreamQueue()
{}

void DownstreamQueue::add_pending(std::unique_ptr<Downstream> downstream)
{
  auto stream_id = downstream->get_stream_id();
  pending_downstreams_[stream_id] = std::move(downstream);
}

void DownstreamQueue::add_failure(std::unique_ptr<Downstream> downstream)
{
  auto stream_id = downstream->get_stream_id();
  failure_downstreams_[stream_id] = std::move(downstream);
}

void DownstreamQueue::add_active(std::unique_ptr<Downstream> downstream)
{
  auto stream_id = downstream->get_stream_id();
  active_downstreams_[stream_id] = std::move(downstream);
}

std::unique_ptr<Downstream> DownstreamQueue::remove(int32_t stream_id)
{
  auto kv = pending_downstreams_.find(stream_id);

  if(kv != std::end(pending_downstreams_)) {
    auto downstream = std::move((*kv).second);
    pending_downstreams_.erase(kv);
    return downstream;
  }

  kv = active_downstreams_.find(stream_id);

  if(kv != std::end(active_downstreams_)) {
    auto downstream = std::move((*kv).second);
    active_downstreams_.erase(kv);
    return downstream;
  }

  kv = failure_downstreams_.find(stream_id);

  if(kv != std::end(failure_downstreams_)) {
    auto downstream = std::move((*kv).second);
    failure_downstreams_.erase(kv);
    return downstream;
  }

  return nullptr;
}

Downstream* DownstreamQueue::find(int32_t stream_id)
{
  auto kv = pending_downstreams_.find(stream_id);

  if(kv != std::end(pending_downstreams_)) {
    return (*kv).second.get();
  }

  kv = active_downstreams_.find(stream_id);

  if(kv != std::end(active_downstreams_)) {
    return (*kv).second.get();
  }

  kv = failure_downstreams_.find(stream_id);

  if(kv != std::end(failure_downstreams_)) {
    return (*kv).second.get();
  }

  return nullptr;
}

std::unique_ptr<Downstream> DownstreamQueue::pop_pending()
{
  auto i = std::begin(pending_downstreams_);

  if(i == std::end(pending_downstreams_)) {
    return nullptr;
  }

  auto downstream = std::move((*i).second);

  pending_downstreams_.erase(i);

  return downstream;
}

Downstream* DownstreamQueue::pending_top() const
{
  auto i = std::begin(pending_downstreams_);

  if(i == std::end(pending_downstreams_)) {
    return nullptr;
  }

  return (*i).second.get();
}

size_t DownstreamQueue::num_active() const
{
  return active_downstreams_.size();
}

bool DownstreamQueue::pending_empty() const
{
  return pending_downstreams_.empty();
}

const std::map<int32_t, std::unique_ptr<Downstream>>&
DownstreamQueue::get_active_downstreams() const
{
  return active_downstreams_;
}

} // namespace shrpx
