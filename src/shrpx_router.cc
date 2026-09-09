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
#include "shrpx_router.h"

#include <algorithm>
#include <print>

#include "shrpx_config.h"
#include "shrpx_log.h"

namespace shrpx {

RNode::RNode(std::span<const char> s, ssize_t index, ssize_t wildcard_index)
  : s{s}, index{index}, wildcard_index{wildcard_index} {}

Router::~Router() {}

namespace {
char first_byte(const std::unique_ptr<RNode> &node) { return node->s[0]; }
} // namespace

namespace {
RNode *find_next_node(const RNode *node, char c) {
  auto itr = std::ranges::lower_bound(node->next, c, {}, first_byte);
  if (itr == std::ranges::end(node->next) || (*itr)->s[0] != c) {
    return nullptr;
  }

  return (*itr).get();
}
} // namespace

namespace {
void add_next_node(RNode *node, std::unique_ptr<RNode> new_node) {
  auto itr =
    std::ranges::lower_bound(node->next, new_node->s[0], {}, first_byte);
  node->next.insert(itr, std::move(new_node));
}
} // namespace

void Router::add_node(RNode *node, std::span<const char> pattern, ssize_t index,
                      ssize_t wildcard_index) {
  auto pat = make_string_ref(balloc_, as_string_view(pattern));
  auto new_node = std::make_unique<RNode>(pat, index, wildcard_index);
  add_next_node(node, std::move(new_node));
}

size_t Router::add_route_internal(std::span<const char> pattern, size_t idx,
                                  bool wildcard) {
  ssize_t index = -1, wildcard_index = -1;
  if (wildcard) {
    wildcard_index = as_signed(idx);
  } else {
    index = as_signed(idx);
  }

  auto node = &root_;

  for (;;) {
    auto next_node = find_next_node(node, pattern[0]);
    if (!next_node) {
      add_node(node, pattern, index, wildcard_index);
      return idx;
    }

    node = next_node;

    auto n = std::min(node->s.size(), pattern.size());
    size_t i;
    for (i = 0; i < n && node->s[i] == pattern[i]; ++i)
      ;
    if (i == n) {
      // The common prefix was matched
      if (pattern.size() == node->s.size()) {
        // Complete match
        if (index != -1) {
          if (node->index != -1) {
            // Return the existing index for duplicates.
            return as_unsigned(node->index);
          }
          node->index = index;
          return idx;
        }

        assert(wildcard_index != -1);

        if (node->wildcard_index != -1) {
          return as_unsigned(node->wildcard_index);
        }
        node->wildcard_index = wildcard_index;
        return idx;
      }

      if (pattern.size() > node->s.size()) {
        // We still have pattern to add
        pattern = pattern.subspan(n);

        continue;
      }
    }

    pattern = pattern.subspan(i);

    if (node->s.size() > i) {
      // node must be split into 2 nodes.  new_node is now the child
      // of node.
      auto new_node = std::make_unique<RNode>(node->s.subspan(i), node->index,
                                              node->wildcard_index);
      std::swap(node->next, new_node->next);

      node->s = node->s.first(i);
      node->index = -1;
      node->wildcard_index = -1;

      add_next_node(node, std::move(new_node));

      if (pattern.empty()) {
        node->index = index;
        node->wildcard_index = wildcard_index;
        return idx;
      }
    }

    assert(!pattern.empty());

    add_node(node, pattern, index, wildcard_index);

    return idx;
  }
}

size_t Router::add_route(std::string_view pattern, size_t idx, bool wildcard) {
  return add_route_internal(pattern, idx, wildcard);
}

namespace {
std::expected<std::tuple<const RNode *, size_t>, Error>
match_complete(const RNode *node, std::span<const char> pattern) {
  if (pattern.empty()) {
    return std::make_tuple(node, 0);
  }

  for (;;) {
    node = find_next_node(node, pattern[0]);
    if (!node) {
      return std::unexpected{Error::ENTITY_NOT_FOUND};
    }

    auto n = std::min(node->s.size(), pattern.size());
    if (memcmp(node->s.data(), pattern.data(), n) != 0) {
      return std::unexpected{Error::ENTITY_NOT_FOUND};
    }

    pattern = pattern.subspan(n);
    if (pattern.empty()) {
      return std::make_tuple(node, n);
    }
  }
}
} // namespace

namespace {
std::expected<std::tuple<const RNode *, bool>, Error>
match_partial(const RNode *node, size_t offset, std::span<const char> pattern) {
  auto pattern_is_wildcard = false;

  if (pattern.empty()) {
    if (node->s.size() == offset) {
      return std::make_tuple(node, false);
    }
    return std::unexpected{Error::ENTITY_NOT_FOUND};
  }

  const RNode *found_node = nullptr;

  if (offset > 0) {
    auto n = std::min(node->s.size() - offset, pattern.size());
    if (memcmp(node->s.data() + offset, pattern.data(), n) != 0) {
      return std::unexpected{Error::ENTITY_NOT_FOUND};
    }

    pattern = pattern.subspan(n);

    if (pattern.empty()) {
      if (node->s.size() == offset + n) {
        if (node->index != -1) {
          return std::make_tuple(node, false);
        }

        // The last '/' handling, see below.
        node = find_next_node(node, '/');
        if (node && node->index != -1 && node->s.size() == 1) {
          return std::make_tuple(node, false);
        }

        return std::unexpected{Error::ENTITY_NOT_FOUND};
      }

      // The last '/' handling, see below.
      if (node->index != -1 && offset + n + 1 == node->s.size() &&
          node->s[node->s.size() - 1] == '/') {
        return std::make_tuple(node, false);
      }

      return std::unexpected{Error::ENTITY_NOT_FOUND};
    }

    if (node->wildcard_index != -1) {
      found_node = node;
      pattern_is_wildcard = true;
    } else if (node->index != -1 && node->s[node->s.size() - 1] == '/') {
      found_node = node;
      pattern_is_wildcard = false;
    }

    assert(node->s.size() == offset + n);
  }

  for (;;) {
    node = find_next_node(node, pattern[0]);
    if (!node) {
      return std::make_tuple(found_node, pattern_is_wildcard);
    }

    auto n = std::min(node->s.size(), pattern.size());
    if (memcmp(node->s.data(), pattern.data(), n) != 0) {
      return std::make_tuple(found_node, pattern_is_wildcard);
    }

    pattern = pattern.subspan(n);

    if (pattern.empty()) {
      if (node->s.size() == n) {
        // Complete match with this node
        if (node->index != -1) {
          return std::make_tuple(node, false);
        }

        // The last '/' handling, see below.
        node = find_next_node(node, '/');
        if (node && node->index != -1 && node->s.size() == 1) {
          return std::make_tuple(node, false);
        }

        return std::make_tuple(found_node, pattern_is_wildcard);
      }

      // We allow match without trailing "/" at the end of pattern.
      // So, if pattern ends with '/', and pattern and path matches
      // without that slash, we consider they match to deal with
      // request to the directory without trailing slash.  That is if
      // pattern is "/foo/" and path is "/foo", we consider they
      // match.
      if (node->index != -1 && n + 1 == node->s.size() && node->s[n] == '/') {
        return std::make_tuple(node, false);
      }

      return std::make_tuple(found_node, pattern_is_wildcard);
    }

    if (node->wildcard_index != -1) {
      found_node = node;
      pattern_is_wildcard = true;
    } else if (node->index != -1 && node->s[node->s.size() - 1] == '/') {
      // This is the case when pattern which ends with "/" is included
      // in query.
      found_node = node;
      pattern_is_wildcard = false;
    }

    assert(node->s.size() == n);
  }
}
} // namespace

std::expected<size_t, Error> Router::match(std::string_view host,
                                           std::string_view path) const {
  auto rv = match_complete(&root_, host);
  if (!rv) {
    return std::unexpected{rv.error()};
  }

  auto [node, offset] = *rv;

  auto prv = match_partial(node, offset, path);
  if (!prv) {
    return std::unexpected{prv.error()};
  }

  bool pattern_is_wildcard;
  std::tie(node, pattern_is_wildcard) = *prv;

  if (!node || node == &root_) {
    return std::unexpected{Error::ENTITY_NOT_FOUND};
  }

  auto idx = pattern_is_wildcard ? node->wildcard_index : node->index;
  if (idx == -1) {
    return std::unexpected{Error::ENTITY_NOT_FOUND};
  }

  return as_unsigned(idx);
}

std::expected<size_t, Error> Router::match(std::string_view s) const {
  auto rv = match_complete(&root_, s);
  if (!rv) {
    return std::unexpected{rv.error()};
  }

  auto [node, offset] = *rv;

  if (node->s.size() != offset || node->index == -1) {
    return std::unexpected{Error::ENTITY_NOT_FOUND};
  }

  return as_unsigned(node->index);
}

namespace {
std::expected<std::tuple<const RNode *, std::string_view>, Error>
match_prefix(const RNode *node, std::span<const char> pattern) {
  if (pattern.empty()) {
    return std::unexpected{Error::ENTITY_NOT_FOUND};
  }

  for (;;) {
    node = find_next_node(node, pattern[0]);
    if (!node || node->s.size() > pattern.size() ||
        memcmp(node->s.data(), pattern.data(), node->s.size()) != 0) {
      return std::unexpected{Error::ENTITY_NOT_FOUND};
    }

    pattern = pattern.subspan(node->s.size());

    if (node->index != -1) {
      return std::make_tuple(node, as_string_view(pattern));
    }

    if (pattern.empty()) {
      return std::unexpected{Error::ENTITY_NOT_FOUND};
    }
  }
}
} // namespace

std::expected<std::tuple<const RNode *, std::string_view>, Error>
Router::match_prefix(const RNode *start_node, std::string_view s) const {
  if (!start_node) {
    start_node = &root_;
  }

  return ::shrpx::match_prefix(start_node, s);
}

namespace {
void dump_node(const RNode *node, int depth) {
  std::println(stderr, "{:{}}s='{}', len={}, index={}", "", depth, node->s,
               node->s.size(), node->index);
  for (auto &nd : node->next) {
    dump_node(nd.get(), depth + 4);
  }
}
} // namespace

void Router::dump() const { dump_node(&root_, 0); }

} // namespace shrpx
