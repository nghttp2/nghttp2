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
#include "shrpx_worker_test.h"

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif // HAVE_UNISTD_H

#include <cstdlib>

#include "munitxx.h"

#include "shrpx_worker.h"
#include "shrpx_connect_blocker.h"
#include "shrpx_log.h"

namespace shrpx {

namespace {
const MunitTest tests[]{
  munit_void_test(test_shrpx_worker_match_downstream_addr_group),
  munit_test_end(),
};
} // namespace

const MunitSuite worker_suite{
  "/worker", tests, nullptr, 1, MUNIT_SUITE_OPTION_NONE,
};

void test_shrpx_worker_match_downstream_addr_group(void) {
  auto groups = std::vector<std::shared_ptr<DownstreamAddrGroup>>();
  for (auto &s : {"nghttp2.org/", "nghttp2.org/alpha/bravo/",
                  "nghttp2.org/alpha/charlie", "nghttp2.org/delta%3A",
                  "www.nghttp2.org/", "[::1]/", "nghttp2.org/alpha/bravo/delta",
                  // Check that match is done in the single node
                  "example.com/alpha/bravo", "192.168.0.1/alpha/", "/golf/"}) {
    auto g = std::make_shared<DownstreamAddrGroup>();
    g->pattern = ImmutableString(s);
    groups.push_back(std::move(g));
  }

  BlockAllocator balloc(1024, 1024);
  RouterConfig routerconf;

  auto &router = routerconf.router;
  auto &wcrouter = routerconf.rev_wildcard_router;
  auto &wp = routerconf.wildcard_patterns;

  for (size_t i = 0; i < groups.size(); ++i) {
    auto &g = groups[i];
    router.add_route(std::string_view{g->pattern.begin(), g->pattern.end()}, i);
  }

  assert_size(0, ==,
              match_downstream_addr_group(routerconf, "nghttp2.org"sv, "/"sv,
                                          groups, 255, balloc));

  // port is removed
  assert_size(0, ==,
              match_downstream_addr_group(routerconf, "nghttp2.org:8080"sv,
                                          "/"sv, groups, 255, balloc));

  // host is case-insensitive
  assert_size(4, ==,
              match_downstream_addr_group(routerconf, "WWW.nghttp2.org"sv,
                                          "/alpha"sv, groups, 255, balloc));

  assert_size(1, ==,
              match_downstream_addr_group(routerconf, "nghttp2.org"sv,
                                          "/alpha/bravo/"sv, groups, 255,
                                          balloc));

  // /alpha/bravo also matches /alpha/bravo/
  assert_size(1, ==,
              match_downstream_addr_group(routerconf, "nghttp2.org"sv,
                                          "/alpha/bravo"sv, groups, 255,
                                          balloc));

  // path part is case-sensitive
  assert_size(0, ==,
              match_downstream_addr_group(routerconf, "nghttp2.org"sv,
                                          "/Alpha/bravo"sv, groups, 255,
                                          balloc));

  assert_size(1, ==,
              match_downstream_addr_group(routerconf, "nghttp2.org"sv,
                                          "/alpha/bravo/charlie"sv, groups, 255,
                                          balloc));

  assert_size(2, ==,
              match_downstream_addr_group(routerconf, "nghttp2.org"sv,
                                          "/alpha/charlie"sv, groups, 255,
                                          balloc));

  // pattern which does not end with '/' must match its entirely.  So
  // this matches to group 0, not group 2.
  assert_size(0, ==,
              match_downstream_addr_group(routerconf, "nghttp2.org"sv,
                                          "/alpha/charlie/"sv, groups, 255,
                                          balloc));

  assert_size(255, ==,
              match_downstream_addr_group(routerconf, "example.org"sv, "/"sv,
                                          groups, 255, balloc));

  assert_size(
    255, ==,
    match_downstream_addr_group(routerconf, ""sv, "/"sv, groups, 255, balloc));

  assert_size(255, ==,
              match_downstream_addr_group(routerconf, ""sv, "alpha"sv, groups,
                                          255, balloc));

  assert_size(255, ==,
              match_downstream_addr_group(routerconf, "foo/bar"sv, "/"sv,
                                          groups, 255, balloc));

  // If path is "*", only match with host + "/").
  assert_size(0, ==,
              match_downstream_addr_group(routerconf, "nghttp2.org"sv, "*"sv,
                                          groups, 255, balloc));

  assert_size(5, ==,
              match_downstream_addr_group(routerconf, "[::1]"sv, "/"sv, groups,
                                          255, balloc));
  assert_size(5, ==,
              match_downstream_addr_group(routerconf, "[::1]:8080"sv, "/"sv,
                                          groups, 255, balloc));
  assert_size(255, ==,
              match_downstream_addr_group(routerconf, "[::1"sv, "/"sv, groups,
                                          255, balloc));
  assert_size(255, ==,
              match_downstream_addr_group(routerconf, "[::1]8000"sv, "/"sv,
                                          groups, 255, balloc));

  // Check the case where adding route extends tree
  assert_size(6, ==,
              match_downstream_addr_group(routerconf, "nghttp2.org"sv,
                                          "/alpha/bravo/delta"sv, groups, 255,
                                          balloc));

  assert_size(1, ==,
              match_downstream_addr_group(routerconf, "nghttp2.org"sv,
                                          "/alpha/bravo/delta/"sv, groups, 255,
                                          balloc));

  // Check the case where query is done in a single node
  assert_size(7, ==,
              match_downstream_addr_group(routerconf, "example.com"sv,
                                          "/alpha/bravo"sv, groups, 255,
                                          balloc));

  assert_size(255, ==,
              match_downstream_addr_group(routerconf, "example.com"sv,
                                          "/alpha/bravo/"sv, groups, 255,
                                          balloc));

  assert_size(255, ==,
              match_downstream_addr_group(routerconf, "example.com"sv,
                                          "/alpha"sv, groups, 255, balloc));

  // Check the case where quey is done in a single node
  assert_size(8, ==,
              match_downstream_addr_group(routerconf, "192.168.0.1"sv,
                                          "/alpha"sv, groups, 255, balloc));

  assert_size(8, ==,
              match_downstream_addr_group(routerconf, "192.168.0.1"sv,
                                          "/alpha/"sv, groups, 255, balloc));

  assert_size(8, ==,
              match_downstream_addr_group(routerconf, "192.168.0.1"sv,
                                          "/alpha/bravo"sv, groups, 255,
                                          balloc));

  assert_size(255, ==,
              match_downstream_addr_group(routerconf, "192.168.0.1"sv,
                                          "/alph"sv, groups, 255, balloc));

  assert_size(255, ==,
              match_downstream_addr_group(routerconf, "192.168.0.1"sv, "/"sv,
                                          groups, 255, balloc));

  // Test for wildcard hosts
  auto g1 = std::make_shared<DownstreamAddrGroup>();
  g1->pattern = "git.nghttp2.org"_is;
  groups.push_back(std::move(g1));

  auto g2 = std::make_shared<DownstreamAddrGroup>();
  g2->pattern = ".nghttp2.org"_is;
  groups.push_back(std::move(g2));

  auto g3 = std::make_shared<DownstreamAddrGroup>();
  g3->pattern = ".local"_is;
  groups.push_back(std::move(g3));

  wp.emplace_back("git.nghttp2.org"sv);
  wcrouter.add_route("gro.2ptthgn.tig"sv, 0);
  wp.back().router.add_route("/echo/"sv, 10);

  wp.emplace_back(".nghttp2.org"sv);
  wcrouter.add_route("gro.2ptthgn."sv, 1);
  wp.back().router.add_route("/echo/"sv, 11);
  wp.back().router.add_route("/echo/foxtrot"sv, 12);

  wp.emplace_back(".local"sv);
  wcrouter.add_route("lacol."sv, 2);
  wp.back().router.add_route("/"sv, 13);

  assert_size(11, ==,
              match_downstream_addr_group(routerconf, "git.nghttp2.org"sv,
                                          "/echo"sv, groups, 255, balloc));

  assert_size(10, ==,
              match_downstream_addr_group(routerconf, "0git.nghttp2.org"sv,
                                          "/echo"sv, groups, 255, balloc));

  assert_size(11, ==,
              match_downstream_addr_group(routerconf, "it.nghttp2.org"sv,
                                          "/echo"sv, groups, 255, balloc));

  assert_size(255, ==,
              match_downstream_addr_group(routerconf, ".nghttp2.org"sv,
                                          "/echo/foxtrot"sv, groups, 255,
                                          balloc));

  assert_size(9, ==,
              match_downstream_addr_group(routerconf, "alpha.nghttp2.org"sv,
                                          "/golf"sv, groups, 255, balloc));

  assert_size(0, ==,
              match_downstream_addr_group(routerconf, "nghttp2.org"sv,
                                          "/echo"sv, groups, 255, balloc));

  assert_size(13, ==,
              match_downstream_addr_group(routerconf, "test.local"sv, ""sv,
                                          groups, 255, balloc));
}

} // namespace shrpx
