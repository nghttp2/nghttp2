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
#include "network_test.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <cstring>
#include <iostream>

#include "munitxx.h"

#include <nghttp2/nghttp2.h>

#include "network.h"

using namespace std::literals;

namespace nghttp2 {

namespace {
const MunitTest tests[]{
  munit_void_test(test_network_address),
  munit_test_end(),
};
} // namespace

const MunitSuite network_suite{
  "/network", tests, nullptr, 1, MUNIT_SUITE_OPTION_NONE,
};

namespace {
Address parse_addr(const char *ipaddr, const char *port) {
  addrinfo hints{
    .ai_flags = AI_NUMERICHOST
#ifdef AI_NUMERICSERV
                | AI_NUMERICSERV
#endif // defined(AI_NUMERICSERV)
    ,
    .ai_family = AF_UNSPEC,
  };

  addrinfo *res = nullptr;

  auto rv = getaddrinfo(ipaddr, port, &hints, &res);

  assert_int(0, ==, rv);
  assert_not_null(res);

  Address addr;
  addr.set(res->ai_addr);

  freeaddrinfo(res);

  return addr;
}
} // namespace

void test_network_address(void) {
  // Not set
  {
    Address addr;

    assert_true(addr.empty());
  }

  // IPv4
  {
    constexpr auto ipaddr = "10.1.0.100";

    auto addr = parse_addr(ipaddr, "443");

    assert_ptr_equal(&std::get<sockaddr_in>(addr.skaddr), addr.as_sockaddr());
    assert_size(sizeof(sockaddr_in), ==, addr.size());
    assert_false(addr.empty());
    assert_int(AF_INET, ==, addr.family());
    assert_uint16(443, ==, addr.port());

    addr.port(8443);

    assert_uint16(8443, ==, addr.port());

    in_addr r;

    assert_int(1, ==, inet_pton(AF_INET, ipaddr, &r));

    const auto &inaddr = std::get<sockaddr_in>(addr.skaddr);

    assert_memory_equal(sizeof(in_addr), &r, &inaddr.sin_addr);
  }

  // IPv6
  {
    constexpr auto ipaddr = "2001:db8::1";

    auto addr = parse_addr(ipaddr, "443");

    assert_ptr_equal(&std::get<sockaddr_in6>(addr.skaddr), addr.as_sockaddr());
    assert_size(sizeof(sockaddr_in6), ==, addr.size());
    assert_false(addr.empty());
    assert_int(AF_INET6, ==, addr.family());
    assert_uint16(443, ==, addr.port());

    addr.port(8443);

    assert_uint16(8443, ==, addr.port());

    in6_addr r;

    assert_int(1, ==, inet_pton(AF_INET6, ipaddr, &r));

    const auto &inaddr = std::get<sockaddr_in6>(addr.skaddr);

    assert_memory_equal(sizeof(in6_addr), &r, &inaddr.sin6_addr);
  }

#ifndef _WIN32
  // UNIX
  {
    constexpr char path[] = "/unix.sock";

    Address addr;

    auto &unaddr = addr.skaddr.emplace<sockaddr_un>();
    unaddr.sun_family = AF_UNIX;
    memcpy(unaddr.sun_path, path, sizeof(path));

    assert_ptr_equal(&std::get<sockaddr_un>(addr.skaddr), addr.as_sockaddr());
    assert_size(sizeof(sockaddr_un), ==, addr.size());
    assert_false(addr.empty());
    assert_int(AF_UNIX, ==, addr.family());
    assert_uint16(0, ==, addr.port());

    addr.port(8443);

    assert_uint16(0, ==, addr.port());
  }
#endif // !defined(_WIN32)
}

} // namespace nghttp2
