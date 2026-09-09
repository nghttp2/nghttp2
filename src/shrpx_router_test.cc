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
#include "shrpx_router_test.h"

#include "shrpx_router.h"

using namespace std::literals;

namespace shrpx {

namespace {
const MunitTest tests[]{
  munit_void_test(test_shrpx_router_match),
  munit_void_test(test_shrpx_router_match_wildcard),
  munit_void_test(test_shrpx_router_match_prefix),
  munit_test_end(),
};
} // namespace

const MunitSuite router_suite{
  .prefix = "/router",
  .tests = tests,
};

struct Pattern {
  std::string_view pattern;
  size_t idx;
  bool wildcard;
};

void test_shrpx_router_match(void) {
  static constexpr auto patterns = std::to_array<Pattern>({
    {"nghttp2.org/"sv, 0},
    {"nghttp2.org/alpha"sv, 1},
    {"nghttp2.org/alpha/"sv, 2},
    {"nghttp2.org/alpha/bravo/"sv, 3},
    {"www.nghttp2.org/alpha/"sv, 4},
    {"/alpha"sv, 5},
    {"example.com/alpha/"sv, 6},
    {"nghttp2.org/alpha/bravo2/"sv, 7},
    {"www2.nghttp2.org/alpha/"sv, 8},
    {"www2.nghttp2.org/alpha2/"sv, 9},
  });

  Router router;

  for (auto &p : patterns) {
    router.add_route(p.pattern, p.idx);
  }

  assert_ok_eq(0, router.match("nghttp2.org"sv, "/"sv));
  assert_ok_eq(1, router.match("nghttp2.org"sv, "/alpha"sv));
  assert_ok_eq(2, router.match("nghttp2.org"sv, "/alpha/"sv));
  assert_ok_eq(2, router.match("nghttp2.org"sv, "/alpha/charlie"sv));
  assert_ok_eq(3, router.match("nghttp2.org"sv, "/alpha/bravo/"sv));

  // matches pattern when last '/' is missing in path
  assert_ok_eq(3, router.match("nghttp2.org"sv, "/alpha/bravo"sv));
  assert_ok_eq(8, router.match("www2.nghttp2.org"sv, "/alpha"sv));
  assert_ok_eq(5, router.match(""sv, "/alpha"sv));

  assert_err(Error::ENTITY_NOT_FOUND, router.match("example.com", "/"sv));
  assert_err(Error::ENTITY_NOT_FOUND, router.match("www3.nghttp2.org", "/"sv));
}

void test_shrpx_router_match_wildcard(void) {
  constexpr auto patterns = std::to_array<Pattern>({
    {"nghttp2.org/"sv, 0},
    {"nghttp2.org/"sv, 1, true},
    {"nghttp2.org/alpha/"sv, 2},
    {"nghttp2.org/alpha/"sv, 3, true},
    {"nghttp2.org/bravo"sv, 4},
    {"nghttp2.org/bravo"sv, 5, true},
  });

  Router router;

  for (auto &p : patterns) {
    router.add_route(p.pattern, p.idx, p.wildcard);
  }

  assert_ok_eq(0, router.match("nghttp2.org"sv, "/"sv));
  assert_ok_eq(1, router.match("nghttp2.org"sv, "/a"sv));
  assert_ok_eq(1, router.match("nghttp2.org"sv, "/charlie"sv));
  assert_ok_eq(2, router.match("nghttp2.org"sv, "/alpha"sv));
  assert_ok_eq(2, router.match("nghttp2.org"sv, "/alpha/"sv));
  assert_ok_eq(3, router.match("nghttp2.org"sv, "/alpha/b"sv));
  assert_ok_eq(4, router.match("nghttp2.org"sv, "/bravo"sv));
  assert_ok_eq(5, router.match("nghttp2.org"sv, "/bravocharlie"sv));
  assert_ok_eq(5, router.match("nghttp2.org"sv, "/bravo/"sv));

  assert_err(Error::ENTITY_NOT_FOUND, router.match("www.nghttp2.org"sv, "/"sv));
}

void test_shrpx_router_match_prefix(void) {
  static constexpr auto patterns = std::to_array<Pattern>({
    {"gro.2ptthgn."sv, 0},
    {"gro.2ptthgn.www."sv, 1},
    {"gro.2ptthgn.gmi."sv, 2},
    {"gro.2ptthgn.gmi.ahpla."sv, 3},
  });

  Router router;

  for (auto &p : patterns) {
    router.add_route(p.pattern, p.idx);
  }

  const RNode *node = nullptr;

  assert_ok(router.match_prefix(node, "gro.2ptthgn.gmi.ahpla.ovarb"sv)
              .transform([&node](auto &&r) {
                auto [nd, rest] = r;
                node = nd;

                assert_eq(0, node->index);
                assert_eq("gmi.ahpla.ovarb"sv, rest);
              }));

  assert_ok(
    router.match_prefix(node, "gmi.ahpla.ovarb"sv).transform([&node](auto &&r) {
      auto [nd, rest] = r;
      node = nd;

      assert_eq(2, node->index);
      assert_eq("ahpla.ovarb"sv, rest);
    }));

  assert_ok(
    router.match_prefix(node, "ahpla.ovarb"sv).transform([&node](auto &&r) {
      auto [nd, rest] = r;
      node = nd;

      assert_eq(3, node->index);
      assert_eq("ovarb"sv, rest);
    }));

  assert_err(Error::ENTITY_NOT_FOUND, router.match_prefix(node, "c.b.c"sv));
}

} // namespace shrpx
