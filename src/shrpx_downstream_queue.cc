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
{
  for(auto& kv : pending_downstreams_) {
    delete kv.second;
  }

  for(auto& kv : active_downstreams_) {
    delete kv.second;
  }

  for(auto& kv : failure_downstreams_) {
    delete kv.second;
  }
}

void DownstreamQueue::add_pending(Downstream *downstream)
{
  pending_downstreams_[downstream->get_stream_id()] = downstream;
}

void DownstreamQueue::add_failure(Downstream *downstream)
{
  failure_downstreams_[downstream->get_stream_id()] = downstream;
}

void DownstreamQueue::add_active(Downstream *downstream)
{
  active_downstreams_[downstream->get_stream_id()] = downstream;
}

void DownstreamQueue::remove(Downstream *downstream)
{
  pending_downstreams_.erase(downstream->get_stream_id());
  active_downstreams_.erase(downstream->get_stream_id());
  failure_downstreams_.erase(downstream->get_stream_id());
}

Downstream* DownstreamQueue::find(int32_t stream_id)
{
  auto kv = pending_downstreams_.find(stream_id);

  if(kv != std::end(pending_downstreams_)) {
    return (*kv).second;
  }

  kv = active_downstreams_.find(stream_id);

  if(kv != std::end(active_downstreams_)) {
    return (*kv).second;
  }

  kv = failure_downstreams_.find(stream_id);

  if(kv != std::end(failure_downstreams_)) {
    return (*kv).second;
  }

  return nullptr;
}

Downstream* DownstreamQueue::pop_pending()
{
  auto i = std::begin(pending_downstreams_);

  if(i == std::end(pending_downstreams_)) {
    return nullptr;
  }

  auto downstream = (*i).second;

  pending_downstreams_.erase(i);

  return downstream;
}

size_t DownstreamQueue::num_active() const
{
  return active_downstreams_.size();
}

bool DownstreamQueue::pending_empty() const
{
  return pending_downstreams_.empty();
}

} // namespace shrpx
