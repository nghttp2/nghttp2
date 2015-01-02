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
#include <set>
#include <memory>

namespace shrpx {

class Downstream;

class DownstreamQueue {
public:
  typedef std::map<int32_t, std::unique_ptr<Downstream>> DownstreamMap;

  struct HostEntry {
    // Set of stream ID that blocked by conn_max_per_host_.
    std::set<int32_t> blocked;
    // The number of connections currently made to this host.
    size_t num_active;
    HostEntry();
  };

  typedef std::map<std::string, HostEntry> HostEntryMap;

  // conn_max_per_host == 0 means no limit for downstream connection.
  DownstreamQueue(size_t conn_max_per_host = 0, bool unified_host = true);
  ~DownstreamQueue();
  void add_pending(std::unique_ptr<Downstream> downstream);
  void add_failure(std::unique_ptr<Downstream> downstream);
  // Adds |downstream| to active_downstreams_, which means that
  // downstream connection has been started.
  void add_active(std::unique_ptr<Downstream> downstream);
  // Adds |downstream| to blocked_downstreams_, which means that
  // download connection was blocked because conn_max_per_host_ limit.
  void add_blocked(std::unique_ptr<Downstream> downstream);
  // Returns true if we can make downstream connection to given
  // |host|.
  bool can_activate(const std::string &host) const;
  // Removes pending Downstream object whose stream ID is |stream_id|
  // from pending_downstreams_ and returns it.
  std::unique_ptr<Downstream> pop_pending(int32_t stream_id);
  // Removes Downstream object whose stream ID is |stream_id| from
  // either pending_downstreams_, active_downstreams_,
  // blocked_downstreams_ or failure_downstreams_.  If a Downstream
  // object is removed from active_downstreams_, this function may
  // return Downstream object with the same target host in
  // blocked_downstreams_ if its connection is now not blocked by
  // conn_max_per_host_ limit.
  std::unique_ptr<Downstream> remove_and_pop_blocked(int32_t stream_id);
  // Finds Downstream object denoted by |stream_id| either in
  // pending_downstreams_, active_downstreams_, blocked_downstreams_
  // or failure_downstreams_.
  Downstream *find(int32_t stream_id);
  const DownstreamMap &get_active_downstreams() const;
  HostEntry &find_host_entry(const std::string &host);
  const std::string &make_host_key(const std::string &host) const;
  const std::string &make_host_key(Downstream *downstream) const;

  // Maximum number of concurrent connections to the same host.
  size_t conn_max_per_host_;

private:
  // Per target host structure to keep track of the number of
  // connections to the same host.
  std::map<std::string, HostEntry> host_entries_;
  // Downstream objects, not processed yet
  DownstreamMap pending_downstreams_;
  // Downstream objects, failed to connect to downstream server
  DownstreamMap failure_downstreams_;
  // Downstream objects, downstream connection started
  DownstreamMap active_downstreams_;
  // Downstream objects, blocked by conn_max_per_host_
  DownstreamMap blocked_downstreams_;
  // true if downstream host is treated as the same.  Used for reverse
  // proxying.
  bool unified_host_;
};

} // namespace shrpx

#endif // SHRPX_DOWNSTREAM_QUEUE_H
