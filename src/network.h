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
#ifndef NETWORK_H
#define NETWORK_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // defined(HAVE_CONFIG_H)

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif // defined(HAVE_SYS_SOCKET_H)
#ifdef _WIN32
#  include <ws2tcpip.h>
#else // !defined(_WIN32)
#  include <sys/un.h>
#endif // !defined(_WIN32)
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif // defined(HAVE_NETINET_IN_H)
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif // defined(HAVE_ARPA_INET_H)

#include <variant>

#ifdef ENABLE_HTTP3
#  include <ngtcp2/ngtcp2.h>
#endif // defined(ENABLE_HTTP3)

namespace nghttp2 {

using Sockaddr = std::variant<std::monostate, sockaddr_in, sockaddr_in6
#ifndef _WIN32
                              ,
                              sockaddr_un
#endif // !defined(_WIN32)
                              >;

// as_sockaddr returns the pointer to the stored address casted to
// const sockaddr *.
[[nodiscard]] const sockaddr *as_sockaddr(const Sockaddr &skaddr);
[[nodiscard]] sockaddr *as_sockaddr(Sockaddr &skaddr);

// sockaddr_family returns the address family.
[[nodiscard]] int sockaddr_family(const Sockaddr &skaddr);

// sockaddr_port returns the port.
[[nodiscard]] uint16_t sockaddr_port(const Sockaddr &skaddr);

// sockaddr_port sets |port| to |skaddr|.
void sockaddr_port(Sockaddr &skaddr, uint16_t port);

// sockaddr_set stores |sa| to |skaddr|.  The address family is
// determined by |sa|->sa_family, and |sa| must point to the memory
// that contains valid object which is either sockaddr_in,
// sockaddr_in6, or sockaddr_un.
void sockaddr_set(Sockaddr &skaddr, const sockaddr *sa);

// sockaddr_size returns the size of the stored address.  If no
// meaningful address is set, the return value is implementation
// dependent.
[[nodiscard]] socklen_t sockaddr_size(const Sockaddr &skaddr);

// sockaddr_empty returns true if |skaddr| does not contain any
// meaningful address.
[[nodiscard]] bool sockaddr_empty(const Sockaddr &skaddr);

struct Address {
  // as_sockaddr returns the pointer to the stored address casted to
  // const sockaddr *.
  [[nodiscard]] const sockaddr *as_sockaddr() const;
  [[nodiscard]] sockaddr *as_sockaddr();
  // family returns the address family.
  [[nodiscard]] int family() const;
  // port returns the port.
  [[nodiscard]] uint16_t port() const;
  // port sets |port| to this address.
  void port(uint16_t port);
  // set stores |sa| to this address.  The address family is
  // determined by |sa|->sa_family, and |sa| must point to the memory
  // that contains valid object which is either sockaddr_in,
  // sockaddr_in6, or sockaddr_un.
  void set(const sockaddr *sa);
  // size returns the size of the stored address.  If no meaningful
  // address is set, the return value is implementation dependent.
  [[nodiscard]] socklen_t size() const;
  // empty returns true if this address does not contain any
  // meaningful address.
  [[nodiscard]] bool empty() const;

  Sockaddr skaddr;
};

#ifdef ENABLE_HTTP3
[[nodiscard]] inline ngtcp2_addr as_ngtcp2_addr(const Address &addr) {
  return {
    .addr = const_cast<sockaddr *>(addr.as_sockaddr()),
    .addrlen = addr.size(),
  };
}

[[nodiscard]] inline ngtcp2_addr as_ngtcp2_addr(Address &addr) {
  return {
    .addr = addr.as_sockaddr(),
    .addrlen = addr.size(),
  };
}
#endif // defined(ENABLE_HTTP3)

} // namespace nghttp2

#endif // !defined(NETWORK_H)
