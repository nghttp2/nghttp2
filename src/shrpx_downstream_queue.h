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
#ifndef SHRPX_DOWNSTREAM_QUEUE_H
#define SHRPX_DOWNSTREAM_QUEUE_H

#include "shrpx.h"

#include <stdint.h>

#include <map>
#include <memory>

namespace shrpx {

class Downstream;

class DownstreamQueue {
public:
  DownstreamQueue();
  ~DownstreamQueue();
  void add_pending(std::unique_ptr<Downstream> downstream);
  void add_failure(std::unique_ptr<Downstream> downstream);
  void add_active(std::unique_ptr<Downstream> downstream);
  // Removes |downstream| from either pending_downstreams_,
  // active_downstreams_ or failure_downstreams_ and returns it
  // wrapped in std::unique_ptr.
  std::unique_ptr<Downstream> remove(int32_t stream_id);
  // Finds Downstream object denoted by |stream_id| either in
  // pending_downstreams_, active_downstreams_ or
  // failure_downstreams_.
  Downstream* find(int32_t stream_id);
  // Returns the number of active Downstream objects.
  size_t num_active() const;
  // Returns true if pending_downstreams_ is empty.
  bool pending_empty() const;
  // Pops first Downstream object in pending_downstreams_ and returns
  // it.
  std::unique_ptr<Downstream> pop_pending();
private:
  // Downstream objects, not processed yet
  std::map<int32_t, std::unique_ptr<Downstream>> pending_downstreams_;
  // Downstream objects in use, consuming downstream concurrency limit
  std::map<int32_t, std::unique_ptr<Downstream>> active_downstreams_;
  // Downstream objects, failed to connect to downstream server
  std::map<int32_t, std::unique_ptr<Downstream>> failure_downstreams_;
};

} // namespace shrpx

#endif // SHRPX_DOWNSTREAM_QUEUE_H
