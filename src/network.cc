/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2025 nghttp2 contributors
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
#include "network.h"

#include <cassert>
#include <cstdlib>

namespace nghttp2 {

const sockaddr *as_sockaddr(const Sockaddr &skaddr) {
  return std::visit(
    [](auto &&arg) {
      if constexpr (std::is_same_v<std::decay_t<decltype(arg)>,
                                   std::monostate>) {
        assert(0);
        abort();
      }

      return reinterpret_cast<const sockaddr *>(&arg);
    },
    skaddr);
}

sockaddr *as_sockaddr(Sockaddr &skaddr) {
  return std::visit(
    [](auto &&arg) {
      if constexpr (std::is_same_v<std::decay_t<decltype(arg)>,
                                   std::monostate>) {
        assert(0);
        abort();
      }

      return reinterpret_cast<sockaddr *>(&arg);
    },
    skaddr);
}

int sockaddr_family(const Sockaddr &skaddr) {
  return as_sockaddr(skaddr)->sa_family;
}

uint16_t sockaddr_port(const Sockaddr &skaddr) {
  return std::visit(
    [](auto &&arg) -> uint16_t {
      using T = std::decay_t<decltype(arg)>;

      if constexpr (std::is_same_v<T, sockaddr_in>) {
        return ntohs(arg.sin_port);
      }

      if constexpr (std::is_same_v<T, sockaddr_in6>) {
        return ntohs(arg.sin6_port);
      }

#ifndef _WIN32
      // The existing codebase expects this.
      if constexpr (std::is_same_v<T, sockaddr_un>) {
        return 0;
      }
#endif // !defined(_WIN32)

      assert(0);
      abort();
    },
    skaddr);
}

void sockaddr_port(Sockaddr &skaddr, uint16_t port) {
  std::visit(
    [port](auto &&arg) {
      using T = std::decay_t<decltype(arg)>;

      if constexpr (std::is_same_v<T, sockaddr_in>) {
        arg.sin_port = htons(port);
        return;
      }

      if constexpr (std::is_same_v<T, sockaddr_in6>) {
        arg.sin6_port = htons(port);
        return;
      }

#ifndef _WIN32
      // The existing codebase expects this.
      if constexpr (std::is_same_v<T, sockaddr_un>) {
        return;
      }
#endif // !defined(_WIN32)

      assert(0);
      abort();
    },
    skaddr);
}

void sockaddr_set(Sockaddr &skaddr, const sockaddr *sa) {
  switch (sa->sa_family) {
  case AF_INET:
    skaddr.emplace<sockaddr_in>(*reinterpret_cast<const sockaddr_in *>(sa));
    return;
  case AF_INET6:
    skaddr.emplace<sockaddr_in6>(*reinterpret_cast<const sockaddr_in6 *>(sa));
    return;
#ifndef _WIN32
  case AF_UNIX:
    skaddr.emplace<sockaddr_un>(*reinterpret_cast<const sockaddr_un *>(sa));
    return;
#endif // !defined(_WIN32)
  default:
    assert(0);
    abort();
  }
}

socklen_t sockaddr_size(const Sockaddr &skaddr) {
  return std::visit(
    [](auto &&arg) { return static_cast<socklen_t>(sizeof(arg)); }, skaddr);
}

bool sockaddr_empty(const Sockaddr &skaddr) {
  return std::holds_alternative<std::monostate>(skaddr);
}

const sockaddr *Address::as_sockaddr() const {
  return nghttp2::as_sockaddr(skaddr);
}

sockaddr *Address::as_sockaddr() { return nghttp2::as_sockaddr(skaddr); }

int Address::family() const { return sockaddr_family(skaddr); }

uint16_t Address::port() const { return sockaddr_port(skaddr); }

void Address::port(uint16_t port) { sockaddr_port(skaddr, port); }

void Address::set(const sockaddr *sa) { sockaddr_set(skaddr, sa); }

socklen_t Address::size() const { return sockaddr_size(skaddr); }

bool Address::empty() const { return sockaddr_empty(skaddr); }

} // namespace nghttp2
