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
#ifndef SHRPX_ROUTER_H
#define SHRPX_ROUTER_H

#include "shrpx.h"

#include <vector>
#include <memory>
#include <expected>
#include <span>
#include <string_view>

#include "allocator.h"
#include "errors.h"

using namespace nghttp2;

namespace shrpx {

struct RNode {
  RNode() noexcept = default;
  RNode(std::span<const char> s, ssize_t index, ssize_t wildcard_index);
  RNode(RNode &&) noexcept = default;
  RNode(const RNode &) = delete;
  RNode &operator=(RNode &&) noexcept = default;
  RNode &operator=(const RNode &) = delete;

  // Next RNode, sorted by s[0].
  std::vector<std::unique_ptr<RNode>> next;
  // Stores pointer to the string this node represents.  Not
  // NULL-terminated.
  std::span<const char> s;
  // Index of pattern if match ends in this node.  Note that we don't
  // store duplicated pattern.
  ssize_t index{-1};
  // Index of wildcard pattern if query includes this node as prefix
  // and it still has suffix to match.  Note that we don't store
  // duplicated pattern.
  ssize_t wildcard_index{-1};
};

class Router {
public:
  Router() noexcept = default;
  ~Router();
  Router(Router &&) noexcept = default;
  Router(const Router &) = delete;
  Router &operator=(Router &&) noexcept = default;
  Router &operator=(const Router &) = delete;

  // Adds route |pattern| with its |index|.  If same pattern has
  // already been added, the existing index is returned.  If
  // |wildcard| is true, |pattern| is considered as wildcard pattern,
  // and all paths which have the |pattern| as prefix and are strictly
  // longer than |pattern| match.  The wildcard pattern only works
  // with match(std::string_view, std::string_view).
  size_t add_route(std::string_view pattern, size_t index,
                   bool wildcard = false);
  // Returns the matched index of pattern.
  std::expected<size_t, Error> match(std::string_view host,
                                     std::string_view path) const;
  // Returns the matched index of pattern |s|.
  std::expected<size_t, Error> match(std::string_view s) const;
  // Returns the matched RNode and the unmatched part of the |s| if
  // the matching pattern is a suffix of |s|.  If |start_node| is not
  // nullptr, it specifies the first node to start matching.  If it is
  // nullptr, match will start from scratch.  One can continue to
  // match the longer pattern using the returned RNode as |start_node|
  // to the another invocation of this function until it returns
  // error.
  std::expected<std::tuple<const RNode *, std::string_view>, Error>
  match_prefix(const RNode *start_node, std::string_view s) const;

  void dump() const;

private:
  void add_node(RNode *node, std::span<const char> pattern, ssize_t index,
                ssize_t wildcard_index);
  size_t add_route_internal(std::span<const char> pattern, size_t index,
                            bool wildcard = false);

  BlockAllocator balloc_{1024, 1024};
  // The root node of Patricia tree.  This is special node and its s
  // field is nulptr, and len field is 0.
  RNode root_{};
};

} // namespace shrpx

#endif // !defined(SHRPX_ROUTER_H)
