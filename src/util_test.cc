/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
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
#include "util_test.h"

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif // HAVE_SYS_SOCKET_H
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif // HAVE_NETDB_H

#include <cstring>
#include <iostream>
#include <random>

#include "munitxx.h"

#include <nghttp2/nghttp2.h>

#include "util.h"
#include "template.h"

using namespace nghttp2;
using namespace std::literals;

namespace shrpx {

namespace {
const MunitTest tests[]{
  munit_void_test(test_util_streq),
  munit_void_test(test_util_strieq),
  munit_void_test(test_util_tolower),
  munit_void_test(test_util_to_base64),
  munit_void_test(test_util_to_token68),
  munit_void_test(test_util_percent_encode_token),
  munit_void_test(test_util_percent_decode),
  munit_void_test(test_util_quote_string),
  munit_void_test(test_util_utox),
  munit_void_test(test_util_http_date),
  munit_void_test(test_util_select_h2),
  munit_void_test(test_util_ipv6_numeric_addr),
  munit_void_test(test_util_contains),
  munit_void_test(test_util_utos),
  munit_void_test(test_util_make_string_ref_uint),
  munit_void_test(test_util_utos_unit),
  munit_void_test(test_util_utos_funit),
  munit_void_test(test_util_parse_uint_with_unit),
  munit_void_test(test_util_parse_uint),
  munit_void_test(test_util_parse_duration_with_unit),
  munit_void_test(test_util_duration_str),
  munit_void_test(test_util_format_duration),
  munit_void_test(test_util_starts_with),
  munit_void_test(test_util_ends_with),
  munit_void_test(test_util_parse_http_date),
  munit_void_test(test_util_localtime_date),
  munit_void_test(test_util_get_uint64),
  munit_void_test(test_util_parse_config_str_list),
  munit_void_test(test_util_make_http_hostport),
  munit_void_test(test_util_make_hostport),
  munit_void_test(test_util_random_alpha_digit),
  munit_void_test(test_util_format_hex),
  munit_void_test(test_util_format_upper_hex),
  munit_void_test(test_util_is_hex_string),
  munit_void_test(test_util_decode_hex),
  munit_void_test(test_util_extract_host),
  munit_void_test(test_util_split_hostport),
  munit_void_test(test_util_split_str),
  munit_void_test(test_util_rstrip),
  munit_void_test(test_util_contains),
  munit_void_test(test_util_hex_to_uint),
  munit_void_test(test_util_is_alpha),
  munit_void_test(test_util_is_digit),
  munit_void_test(test_util_is_hex_digit),
  munit_void_test(test_util_in_rfc3986_unreserved_chars),
  munit_void_test(test_util_in_rfc3986_sub_delims),
  munit_void_test(test_util_in_token),
  munit_void_test(test_util_in_attr_char),
  munit_void_test(test_util_upcase),
  munit_void_test(test_util_to_numeric_addr),
  munit_test_end(),
};
} // namespace

const MunitSuite util_suite{
  "/util", tests, nullptr, 1, MUNIT_SUITE_OPTION_NONE,
};

void test_util_streq(void) {
  assert_true(util::streq("alpha"sv, "alpha"sv));
  assert_false(util::streq("alphabravo"sv, "alpha"sv));
  assert_false(util::streq("alpha"sv, "alphA"sv));
  assert_false(util::streq(""sv, "a"sv));
  assert_true(util::streq(""sv, ""sv));
  assert_false(util::streq("alpha"sv, ""sv));
}

void test_util_strieq(void) {
  assert_true(util::strieq("alpha"sv, "alpha"sv));
  assert_true(util::strieq("alpha"sv, "AlPhA"sv));
  assert_true(util::strieq(""sv, ""sv));
  assert_false(util::strieq("alpha"sv, "AlPhA "sv));
  assert_false(util::strieq(""sv, "AlPhA "sv));

  assert_true(util::strieq("alpha"sv, "alpha"sv));
  assert_true(util::strieq("alpha"sv, "AlPhA"sv));
  assert_true(util::strieq(""sv, ""sv));
  assert_false(util::strieq("alpha"sv, "AlPhA "sv));
  assert_false(util::strieq(""sv, "AlPhA "sv));
}

void test_util_tolower(void) {
  std::array<char, 16> buf;

  {
    assert_stdsv_equal(
      "alpha"sv,
      (std::string_view{std::ranges::begin(buf),
                        util::tolower("alPha"sv, std::ranges::begin(buf))}));
  }

  {
    auto s = "alPha"sv;

    assert_stdsv_equal(
      "alpha"sv, (std::string_view{std::ranges::begin(buf),
                                   util::tolower(std::ranges::begin(s),
                                                 std::ranges::end(s),
                                                 std::ranges::begin(buf))}));
  }

  {
    assert_stdsv_equal(
      ""sv, (std::string_view{std::ranges::begin(buf),
                              util::tolower(""sv, std::ranges::begin(buf))}));
  }

  {
    std::string s = "AlpHA\x00BraVO"s;

    util::tolower(s, std::ranges::begin(s));

    assert_stdstring_equal("alpha\x00bravo"s, s);
  }

  {
    std::string s = "\xbe\xef"s;

    util::tolower(s, std::ranges::begin(s));

    assert_stdstring_equal("\xbe\xef"s, s);
  }
}

void test_util_to_base64(void) {
  BlockAllocator balloc(4096, 4096);

  assert_stdsv_equal("AAA++B/="sv, util::to_base64(balloc, "AAA--B_"sv));
  assert_stdsv_equal("AAA++B/B"sv, util::to_base64(balloc, "AAA--B_B"sv));
}

void test_util_to_token68(void) {
  std::string x = "AAA++B/=";
  util::to_token68(x);
  assert_stdstring_equal("AAA--B_", x);

  x = "AAA++B/B";
  util::to_token68(x);
  assert_stdstring_equal("AAA--B_B", x);
}

void test_util_percent_encode_token(void) {
  std::array<char, 64> buf;

  assert_stdsv_equal(
    "h2"sv, as_string_view(buf.begin(),
                           util::percent_encode_token("h2"sv, buf.begin())));

  assert_size("h2"sv.size(), ==, util::percent_encode_tokenlen("h2"sv));

  assert_stdsv_equal(
    "h3~"sv, as_string_view(buf.begin(),
                            util::percent_encode_token("h3~"sv, buf.begin())));

  assert_size("h3~"sv.size(), ==, util::percent_encode_tokenlen("h3~"sv));

  assert_stdsv_equal("100%25"sv,
                     as_string_view(buf.begin(), util::percent_encode_token(
                                                   "100%"sv, buf.begin())));
  assert_size("100%25"sv.size(), ==, util::percent_encode_tokenlen("100%"sv));

  assert_stdsv_equal("http%202"sv,
                     as_string_view(buf.begin(), util::percent_encode_token(
                                                   "http 2"sv, buf.begin())));

  assert_size("http%202"sv.size(), ==,
              util::percent_encode_tokenlen("http 2"sv));
}

void test_util_percent_decode(void) {
  {
    std::string s = "%66%6F%6f%62%61%72";
    assert_stdstring_equal("foobar", util::percent_decode(std::ranges::begin(s),
                                                          std::ranges::end(s)));
  }
  {
    std::string s = "%66%6";
    assert_stdstring_equal("f%6", util::percent_decode(s));
  }
  {
    std::string s = "%66%";
    assert_stdstring_equal(
      "f%", util::percent_decode(std::ranges::begin(s), std::ranges::end(s)));
  }
  BlockAllocator balloc(1024, 1024);

  assert_stdsv_equal("foobar"sv,
                     util::percent_decode(balloc, "%66%6F%6f%62%61%72"sv));

  assert_stdsv_equal("f%6"sv, util::percent_decode(balloc, "%66%6"sv));

  assert_stdsv_equal("f%"sv, util::percent_decode(balloc, "%66%"sv));
}

void test_util_quote_string(void) {
  BlockAllocator balloc(4096, 4096);
  assert_stdsv_equal("alpha"sv, util::quote_string(balloc, "alpha"sv));
  assert_stdsv_equal(""sv, util::quote_string(balloc, ""sv));
  assert_stdsv_equal("\\\"alpha\\\""sv,
                     util::quote_string(balloc, "\"alpha\""sv));

  assert_size("\\\"alpha\\\""sv.size(), ==,
              util::quote_stringlen("\"alpha\""sv));
  assert_size(0, ==, util::quote_stringlen(""sv));
}

void test_util_utox(void) {
  std::array<char, 16> buf;

  assert_stdsv_equal(
    "0"sv, (std::string_view{buf.begin(), util::utox(0, buf.begin())}));
  assert_stdsv_equal(
    "1"sv, (std::string_view{buf.begin(), util::utox(1, buf.begin())}));
  assert_stdsv_equal(
    "F"sv, (std::string_view{buf.begin(), util::utox(15, buf.begin())}));
  assert_stdsv_equal(
    "10"sv, (std::string_view{buf.begin(), util::utox(16, buf.begin())}));
  assert_stdsv_equal(
    "3B9ACA07"sv,
    (std::string_view{buf.begin(), util::utox(1000000007, buf.begin())}));
  assert_stdsv_equal(
    "B5EA98F3663B14A"sv,
    (std::string_view{buf.begin(),
                      util::utox(819278614785929546, buf.begin())}));
  assert_stdsv_equal(
    "100000000"sv,
    (std::string_view{buf.begin(), util::utox(1LL << 32, buf.begin())}));
}

void test_util_http_date(void) {
  assert_stdstring_equal(
    "Thu, 01 Jan 1970 00:00:00 GMT"s,
    util::format_http_date(std::chrono::system_clock::time_point()));
  assert_stdstring_equal(
    "Wed, 29 Feb 2012 09:15:16 GMT"s,
    util::format_http_date(std::chrono::system_clock::from_time_t(1330506916)));

  std::array<char, 30> http_buf;

  assert_stdsv_equal(
    "Thu, 01 Jan 1970 00:00:00 GMT"sv,
    util::format_http_date(http_buf.data(),
                           std::chrono::system_clock::time_point()));
  assert_stdsv_equal(
    "Wed, 29 Feb 2012 09:15:16 GMT"sv,
    util::format_http_date(http_buf.data(),
                           std::chrono::system_clock::from_time_t(1330506916)));
}

void test_util_select_h2(void) {
  const unsigned char *out = nullptr;
  unsigned char outlen = 0;

  // Check single entry and select it.
  const unsigned char t1[] = "\x2h2";
  assert_true(util::select_h2(&out, &outlen, t1, sizeof(t1) - 1));
  assert_memory_equal(NGHTTP2_PROTO_VERSION_ID_LEN, NGHTTP2_PROTO_VERSION_ID,
                      out);
  assert_uchar(NGHTTP2_PROTO_VERSION_ID_LEN, ==, outlen);

  out = nullptr;
  outlen = 0;

  // Check the case where id is correct but length is invalid and too
  // long.
  const unsigned char t2[] = "\x3h2";
  assert_false(util::select_h2(&out, &outlen, t2, sizeof(t2) - 1));

  // Check the case where h2 is located after bogus ID.
  const unsigned char t3[] = "\x2h3\x2h2";
  assert_true(util::select_h2(&out, &outlen, t3, sizeof(t3) - 1));

  assert_memory_equal(NGHTTP2_PROTO_VERSION_ID_LEN, NGHTTP2_PROTO_VERSION_ID,
                      out);
  assert_uchar(NGHTTP2_PROTO_VERSION_ID_LEN, ==, outlen);

  out = nullptr;
  outlen = 0;

  // Check the case that last entry's length is invalid and too long.
  const unsigned char t4[] = "\x2h3\x6h2";
  assert_false(util::select_h2(&out, &outlen, t4, sizeof(t4) - 1));

  // Check the case that all entries are not supported.
  const unsigned char t5[] = "\x2h3\x2h4";
  assert_false(util::select_h2(&out, &outlen, t5, sizeof(t5) - 1));
}

void test_util_ipv6_numeric_addr(void) {
  assert_true(util::ipv6_numeric_addr("::1"));
  assert_true(
    util::ipv6_numeric_addr("2001:0db8:85a3:0042:1000:8a2e:0370:7334"));
  // IPv4
  assert_false(util::ipv6_numeric_addr("127.0.0.1"));
  // not numeric address
  assert_false(util::ipv6_numeric_addr("localhost"));
}

void test_util_count_digit(void) {
  assert_size(1, ==, util::count_digit(0u));
  assert_size(1, ==, util::count_digit(1u));
  assert_size(1, ==, util::count_digit(9u));
  assert_size(2, ==, util::count_digit(10u));
  assert_size(2, ==, util::count_digit(99u));
  assert_size(3, ==, util::count_digit(100u));
  assert_size(3, ==, util::count_digit(999u));
  assert_size(4, ==, util::count_digit(1'000u));
  assert_size(4, ==, util::count_digit(9'999u));
  assert_size(5, ==, util::count_digit(10'000u));
  assert_size(5, ==, util::count_digit(99'999u));
  assert_size(6, ==, util::count_digit(100'000u));
  assert_size(6, ==, util::count_digit(999'999u));
  assert_size(7, ==, util::count_digit(1'000'000u));
  assert_size(7, ==, util::count_digit(9'999'999u));
  assert_size(8, ==, util::count_digit(10'000'000u));
  assert_size(8, ==, util::count_digit(99'999'999u));
  assert_size(9, ==, util::count_digit(100'000'000u));
  assert_size(9, ==, util::count_digit(999'999'999u));
  assert_size(10, ==, util::count_digit(1'000'000'000u));
  assert_size(10, ==, util::count_digit(9'999'999'999u));
  assert_size(11, ==, util::count_digit(10'000'000'000u));
  assert_size(11, ==, util::count_digit(99'999'999'999u));
  assert_size(12, ==, util::count_digit(100'000'000'000u));
  assert_size(12, ==, util::count_digit(999'999'999'999u));
  assert_size(13, ==, util::count_digit(1'000'000'000'000u));
  assert_size(13, ==, util::count_digit(9'999'999'999'999u));
  assert_size(14, ==, util::count_digit(10'000'000'000'000u));
  assert_size(14, ==, util::count_digit(99'999'999'999'999u));
  assert_size(15, ==, util::count_digit(100'000'000'000'000u));
  assert_size(15, ==, util::count_digit(999'999'999'999'999u));
  assert_size(16, ==, util::count_digit(1'000'000'000'000'000u));
  assert_size(16, ==, util::count_digit(9'999'999'999'999'999u));
  assert_size(17, ==, util::count_digit(10'000'000'000'000'000u));
  assert_size(17, ==, util::count_digit(99'999'999'999'999'999u));
  assert_size(18, ==, util::count_digit(100'000'000'000'000'000u));
  assert_size(18, ==, util::count_digit(999'999'999'999'999'999u));
  assert_size(19, ==, util::count_digit(1'000'000'000'000'000'000u));
  assert_size(19, ==, util::count_digit(9'999'999'999'999'999'999u));
  assert_size(20, ==, util::count_digit(10'000'000'000'000'000'000u));
  assert_size(20, ==, util::count_digit(std::numeric_limits<uint64_t>::max()));
}

void test_util_utos(void) {
  char buf[32];

  assert_stdstring_equal("123"s, (std::string{buf, util::utos(123u, buf)}));

  assert_stdstring_equal("0"s, util::utos(0u));
  assert_stdstring_equal("123"s, util::utos(123u));
  assert_stdstring_equal("123"s, util::utos(static_cast<uint8_t>(123)));
  assert_stdstring_equal("123"s, util::utos(static_cast<uint16_t>(123)));
  assert_stdstring_equal("18446744073709551615"s,
                         util::utos(18'446'744'073'709'551'615u));

  assert_stdsv_equal("0"sv, (std::string_view{buf, util::utos(0u, buf)}));
  assert_stdsv_equal("1"sv, (std::string_view{buf, util::utos(1u, buf)}));
  assert_stdsv_equal("9"sv, (std::string_view{buf, util::utos(9u, buf)}));
  assert_stdsv_equal("10"sv, (std::string_view{buf, util::utos(10u, buf)}));
  assert_stdsv_equal("99"sv, (std::string_view{buf, util::utos(99u, buf)}));
  assert_stdsv_equal("100"sv, (std::string_view{buf, util::utos(100u, buf)}));
  assert_stdsv_equal("999"sv, (std::string_view{buf, util::utos(999u, buf)}));
  assert_stdsv_equal("1000"sv,
                     (std::string_view{buf, util::utos(1'000u, buf)}));
  assert_stdsv_equal("9999"sv,
                     (std::string_view{buf, util::utos(9'999u, buf)}));
  assert_stdsv_equal("10000"sv,
                     (std::string_view{buf, util::utos(10'000u, buf)}));
  assert_stdsv_equal("99999"sv,
                     (std::string_view{buf, util::utos(99'999u, buf)}));
  assert_stdsv_equal("100000"sv,
                     (std::string_view{buf, util::utos(100'000u, buf)}));
  assert_stdsv_equal("999999"sv,
                     (std::string_view{buf, util::utos(999'999u, buf)}));
  assert_stdsv_equal("1000000"sv,
                     (std::string_view{buf, util::utos(1'000'000u, buf)}));
  assert_stdsv_equal("9999999"sv,
                     (std::string_view{buf, util::utos(9'999'999u, buf)}));
  assert_stdsv_equal("10000000"sv,
                     (std::string_view{buf, util::utos(10'000'000u, buf)}));
  assert_stdsv_equal("99999999"sv,
                     (std::string_view{buf, util::utos(99'999'999u, buf)}));
  assert_stdsv_equal("100000000"sv,
                     (std::string_view{buf, util::utos(100'000'000u, buf)}));
  assert_stdsv_equal("999999999"sv,
                     (std::string_view{buf, util::utos(999'999'999u, buf)}));
  assert_stdsv_equal("1000000000"sv,
                     (std::string_view{buf, util::utos(1'000'000'000u, buf)}));
  assert_stdsv_equal("9999999999"sv,
                     (std::string_view{buf, util::utos(9'999'999'999u, buf)}));
  assert_stdsv_equal("10000000000"sv,
                     (std::string_view{buf, util::utos(10'000'000'000u, buf)}));
  assert_stdsv_equal("99999999999"sv,
                     (std::string_view{buf, util::utos(99'999'999'999u, buf)}));
  assert_stdsv_equal(
    "100000000000"sv,
    (std::string_view{buf, util::utos(100'000'000'000u, buf)}));
  assert_stdsv_equal(
    "999999999999"sv,
    (std::string_view{buf, util::utos(999'999'999'999u, buf)}));
  assert_stdsv_equal(
    "1000000000000"sv,
    (std::string_view{buf, util::utos(1'000'000'000'000u, buf)}));
  assert_stdsv_equal(
    "9999999999999"sv,
    (std::string_view{buf, util::utos(9'999'999'999'999u, buf)}));
  assert_stdsv_equal(
    "10000000000000"sv,
    (std::string_view{buf, util::utos(10'000'000'000'000u, buf)}));
  assert_stdsv_equal(
    "99999999999999"sv,
    (std::string_view{buf, util::utos(99'999'999'999'999u, buf)}));
  assert_stdsv_equal(
    "100000000000000"sv,
    (std::string_view{buf, util::utos(100'000'000'000'000u, buf)}));
  assert_stdsv_equal(
    "999999999999999"sv,
    (std::string_view{buf, util::utos(999'999'999'999'999u, buf)}));
  assert_stdsv_equal(
    "1000000000000000"sv,
    (std::string_view{buf, util::utos(1'000'000'000'000'000u, buf)}));
  assert_stdsv_equal(
    "9999999999999999"sv,
    (std::string_view{buf, util::utos(9'999'999'999'999'999u, buf)}));
  assert_stdsv_equal(
    "10000000000000000"sv,
    (std::string_view{buf, util::utos(10'000'000'000'000'000u, buf)}));
  assert_stdsv_equal(
    "99999999999999999"sv,
    (std::string_view{buf, util::utos(99'999'999'999'999'999u, buf)}));
  assert_stdsv_equal(
    "100000000000000000"sv,
    (std::string_view{buf, util::utos(100'000'000'000'000'000u, buf)}));
  assert_stdsv_equal(
    "999999999999999999"sv,
    (std::string_view{buf, util::utos(999'999'999'999'999'999u, buf)}));
  assert_stdsv_equal(
    "1000000000000000000"sv,
    (std::string_view{buf, util::utos(1'000'000'000'000'000'000u, buf)}));
  assert_stdsv_equal(
    "9999999999999999999"sv,
    (std::string_view{buf, util::utos(9'999'999'999'999'999'999u, buf)}));
  assert_stdsv_equal(
    "10000000000000000000"sv,
    (std::string_view{buf, util::utos(10'000'000'000'000'000'000u, buf)}));
  assert_stdsv_equal(
    "18446744073709551615"sv,
    (std::string_view{buf,
                      util::utos(std::numeric_limits<uint64_t>::max(), buf)}));
}

void test_util_make_string_ref_uint(void) {
  BlockAllocator balloc(1024, 1024);

  assert_stdsv_equal("0"sv, util::make_string_ref_uint(balloc, 0u));
  assert_stdsv_equal("123"sv, util::make_string_ref_uint(balloc, 123u));
  assert_stdsv_equal(
    "18446744073709551615"sv,
    util::make_string_ref_uint(balloc, 18446744073709551615ULL));
}

void test_util_utos_unit(void) {
  assert_stdstring_equal("0", util::utos_unit(0u));
  assert_stdstring_equal("1023", util::utos_unit(1023u));
  assert_stdstring_equal("1K", util::utos_unit(1024u));
  assert_stdstring_equal("1K", util::utos_unit(1025u));
  assert_stdstring_equal("1M", util::utos_unit(1u << 20));
  assert_stdstring_equal("1G", util::utos_unit(1u << 30));
  assert_stdstring_equal("1024G", util::utos_unit(1ULL << 40));
}

void test_util_utos_funit(void) {
  assert_stdstring_equal("0", util::utos_funit(0u));
  assert_stdstring_equal("1023", util::utos_funit(1023u));
  assert_stdstring_equal("1.00K", util::utos_funit(1024u));
  assert_stdstring_equal("1.00K", util::utos_funit(1025u));
  assert_stdstring_equal("1.09K", util::utos_funit(1119u));
  assert_stdstring_equal("1.27K", util::utos_funit(1300u));
  assert_stdstring_equal("1.00M", util::utos_funit(1u << 20));
  assert_stdstring_equal("1.18M", util::utos_funit(1234567u));
  assert_stdstring_equal("1.00G", util::utos_funit(1u << 30));
  assert_stdstring_equal("4492450797.23G",
                         util::utos_funit(4823732313248234343ULL));
  assert_stdstring_equal("1024.00G", util::utos_funit(1ULL << 40));
}

void test_util_parse_uint_with_unit(void) {
  assert_int64(0, ==, util::parse_uint_with_unit("0").value_or(-1));
  assert_int64(1023, ==, util::parse_uint_with_unit("1023").value_or(-1));
  assert_int64(1024, ==, util::parse_uint_with_unit("1k").value_or(-1));
  assert_int64(2048, ==, util::parse_uint_with_unit("2K").value_or(-1));
  assert_int64(1 << 20, ==, util::parse_uint_with_unit("1m").value_or(-1));
  assert_int64(1 << 21, ==, util::parse_uint_with_unit("2M").value_or(-1));
  assert_int64(1 << 30, ==, util::parse_uint_with_unit("1g").value_or(-1));
  assert_int64(1LL << 31, ==, util::parse_uint_with_unit("2G").value_or(-1));
  assert_int64(9223372036854775807LL, ==,
               util::parse_uint_with_unit("9223372036854775807").value_or(-1));
  // check overflow case
  assert_false(util::parse_uint_with_unit("9223372036854775808"));
  assert_false(util::parse_uint_with_unit("10000000000000000000"));
  assert_false(util::parse_uint_with_unit("9223372036854775807G"));
  // bad characters
  assert_false(util::parse_uint_with_unit("1.1"));
  assert_false(util::parse_uint_with_unit("1a"));
  assert_false(util::parse_uint_with_unit("a1"));
  assert_false(util::parse_uint_with_unit("1T"));
  assert_false(util::parse_uint_with_unit(""));
}

void test_util_parse_uint(void) {
  assert_int64(0, ==, util::parse_uint("0").value_or(-1));
  assert_int64(1023, ==, util::parse_uint("1023").value_or(-1));
  assert_false(util::parse_uint("1k"));
  assert_int64(9223372036854775807LL, ==,
               util::parse_uint("9223372036854775807").value_or(-1));
  // check overflow case
  assert_false(util::parse_uint("9223372036854775808"));
  assert_false(util::parse_uint("10000000000000000000"));
  // bad characters
  assert_false(util::parse_uint("1.1"));
  assert_false(util::parse_uint("1a"));
  assert_false(util::parse_uint("a1"));
  assert_false(util::parse_uint("1T"));
  assert_false(util::parse_uint(""));
}

void test_util_parse_duration_with_unit(void) {
  auto inf = std::numeric_limits<double>::infinity();

  assert_double(0., ==, util::parse_duration_with_unit("0").value_or(inf));
  assert_double(123., ==, util::parse_duration_with_unit("123").value_or(inf));
  assert_double(123., ==, util::parse_duration_with_unit("123s").value_or(inf));
  assert_double(0.500, ==,
                util::parse_duration_with_unit("500ms").value_or(inf));
  assert_double(123., ==, util::parse_duration_with_unit("123S").value_or(inf));
  assert_double(0.500, ==,
                util::parse_duration_with_unit("500MS").value_or(inf));
  assert_double(180, ==, util::parse_duration_with_unit("3m").value_or(inf));
  assert_double(3600 * 5, ==,
                util::parse_duration_with_unit("5h").value_or(inf));

  // check overflow case
  assert_false(util::parse_duration_with_unit("9223372036854775808"));
  // bad characters
  assert_false(util::parse_duration_with_unit("0u"));
  assert_false(util::parse_duration_with_unit("0xs"));
  assert_false(util::parse_duration_with_unit("0mt"));
  assert_false(util::parse_duration_with_unit("0mss"));
  assert_false(util::parse_duration_with_unit("s"));
  assert_false(util::parse_duration_with_unit("ms"));
}

void test_util_duration_str(void) {
  assert_stdstring_equal("0", util::duration_str(0.));
  assert_stdstring_equal("1s", util::duration_str(1.));
  assert_stdstring_equal("500ms", util::duration_str(0.5));
  assert_stdstring_equal("1500ms", util::duration_str(1.5));
  assert_stdstring_equal("2m", util::duration_str(120.));
  assert_stdstring_equal("121s", util::duration_str(121.));
  assert_stdstring_equal("1h", util::duration_str(3600.));
}

void test_util_format_duration(void) {
  assert_stdstring_equal("0us",
                         util::format_duration(std::chrono::microseconds(0)));
  assert_stdstring_equal("999us",
                         util::format_duration(std::chrono::microseconds(999)));
  assert_stdstring_equal(
    "1.00ms", util::format_duration(std::chrono::microseconds(1000)));
  assert_stdstring_equal(
    "1.09ms", util::format_duration(std::chrono::microseconds(1090)));
  assert_stdstring_equal(
    "1.01ms", util::format_duration(std::chrono::microseconds(1009)));
  assert_stdstring_equal(
    "999.99ms", util::format_duration(std::chrono::microseconds(999990)));
  assert_stdstring_equal(
    "1.00s", util::format_duration(std::chrono::microseconds(1000000)));
  assert_stdstring_equal(
    "1.05s", util::format_duration(std::chrono::microseconds(1050000)));

  assert_stdstring_equal("0us", util::format_duration(0.));
  assert_stdstring_equal("999us", util::format_duration(0.000999));
  assert_stdstring_equal("1.00ms", util::format_duration(0.001));
  assert_stdstring_equal("1.09ms", util::format_duration(0.00109));
  assert_stdstring_equal("1.01ms", util::format_duration(0.001009));
  assert_stdstring_equal("999.99ms", util::format_duration(0.99999));
  assert_stdstring_equal("1.00s", util::format_duration(1.));
  assert_stdstring_equal("1.05s", util::format_duration(1.05));
}

void test_util_starts_with(void) {
  assert_true(util::starts_with("foo"sv, "foo"sv));
  assert_true(util::starts_with("fooo"sv, "foo"sv));
  assert_true(util::starts_with("ofoo"sv, ""sv));
  assert_false(util::starts_with("ofoo"sv, "foo"sv));

  assert_true(util::istarts_with("FOO"sv, "fOO"sv));
  assert_true(util::istarts_with("ofoo"sv, ""sv));
  assert_true(util::istarts_with("fOOo"sv, "Foo"sv));
  assert_false(util::istarts_with("ofoo"sv, "foo"sv));
}

void test_util_ends_with(void) {
  assert_true(util::ends_with("foo"sv, "foo"sv));
  assert_true(util::ends_with("foo"sv, ""sv));
  assert_true(util::ends_with("ofoo"sv, "foo"sv));
  assert_false(util::ends_with("ofoo"sv, "fo"sv));

  assert_true(util::iends_with("fOo"sv, "Foo"sv));
  assert_true(util::iends_with("foo"sv, ""sv));
  assert_true(util::iends_with("oFoo"sv, "fOO"sv));
  assert_false(util::iends_with("ofoo"sv, "fo"sv));
}

void test_util_parse_http_date(void) {
  assert_int64(1001939696, ==,
               util::parse_http_date("Mon, 1 Oct 2001 12:34:56 GMT"sv));
}

void test_util_localtime_date(void) {
  std::array<char, 30> buf;

#ifdef HAVE_STD_CHRONO_TIME_ZONE
  assert_stdsv_equal(
    "2001-10-02T00:34:56.123+12:00"sv,
    util::format_iso8601(buf.data(),
                         std::chrono::system_clock::time_point(
                           std::chrono::milliseconds(1001939696123LL)),
                         std::chrono::locate_zone("Pacific/Auckland"sv)));

  assert_stdsv_equal(
    "20011002T003456.123+1200"sv,
    util::format_iso8601_basic(buf.data(),
                               std::chrono::system_clock::time_point(
                                 std::chrono::milliseconds(1001939696123LL)),
                               std::chrono::locate_zone("Pacific/Auckland"sv)));

  assert_stdsv_equal(
    "02/Oct/2001:00:34:56 +1200"sv,
    util::format_common_log(buf.data(),
                            std::chrono::system_clock::from_time_t(1001939696),
                            std::chrono::locate_zone("Pacific/Auckland"sv)));

  assert_stdsv_equal(
    "2001-10-01T12:34:56.123Z"sv,
    util::format_iso8601(buf.data(),
                         std::chrono::system_clock::time_point(
                           std::chrono::milliseconds(1001939696123LL)),
                         std::chrono::locate_zone("GMT"sv)));

  assert_stdsv_equal(
    "20011001T123456.123Z"sv,
    util::format_iso8601_basic(buf.data(),
                               std::chrono::system_clock::time_point(
                                 std::chrono::milliseconds(1001939696123LL)),
                               std::chrono::locate_zone("GMT"sv)));

  assert_stdsv_equal(
    "01/Oct/2001:12:34:56 +0000"sv,
    util::format_common_log(buf.data(),
                            std::chrono::system_clock::from_time_t(1001939696),
                            std::chrono::locate_zone("GMT"sv)));
#else // !defined(HAVE_STD_CHRONO_TIME_ZONE)
  auto tz = getenv("TZ");
  if (tz) {
    tz = strdup(tz);
  }
#  ifdef __linux__
  setenv("TZ", "NZST-12:00:00:00", 1);
#  else  // !__linux__
  setenv("TZ", ":Pacific/Auckland", 1);
#  endif // !__linux__
  tzset();

  assert_stdsv_equal(
    "2001-10-02T00:34:56.123+12:00"sv,
    util::format_iso8601(buf.data(),
                         std::chrono::system_clock::time_point(
                           std::chrono::milliseconds(1001939696123LL))));

  assert_stdsv_equal(
    "20011002T003456.123+1200"sv,
    util::format_iso8601_basic(buf.data(),
                               std::chrono::system_clock::time_point(
                                 std::chrono::milliseconds(1001939696123LL))));

  assert_stdsv_equal(
    "02/Oct/2001:00:34:56 +1200"sv,
    util::format_common_log(
      buf.data(), std::chrono::system_clock::from_time_t(1001939696)));

  if (tz) {
    setenv("TZ", tz, 1);
    free(tz);
  } else {
    unsetenv("TZ");
  }
  tzset();
#endif   // !defined(HAVE_STD_CHRONO_TIME_ZONE)
}

void test_util_get_uint64(void) {
  {
    auto v = std::to_array<unsigned char>(
      {0x01, 0x12, 0x34, 0x56, 0xff, 0x9a, 0xab, 0xbc});

    auto n = util::get_uint64(v.data());

    assert_uint64(0x01123456ff9aabbcULL, ==, n);
  }
  {
    auto v = std::to_array<unsigned char>(
      {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});

    auto n = util::get_uint64(v.data());

    assert_uint64(0xffffffffffffffffULL, ==, n);
  }
}

void test_util_parse_config_str_list(void) {
  auto res = util::parse_config_str_list("a"sv);
  assert_size(1, ==, res.size());
  assert_stdstring_equal("a", res[0]);

  res = util::parse_config_str_list("a,"sv);
  assert_size(2, ==, res.size());
  assert_stdstring_equal("a", res[0]);
  assert_stdstring_equal("", res[1]);

  res = util::parse_config_str_list(":a::"sv, ':');
  assert_size(4, ==, res.size());
  assert_stdstring_equal("", res[0]);
  assert_stdstring_equal("a", res[1]);
  assert_stdstring_equal("", res[2]);
  assert_stdstring_equal("", res[3]);

  res = util::parse_config_str_list(""sv);
  assert_size(1, ==, res.size());
  assert_stdstring_equal("", res[0]);

  res = util::parse_config_str_list("alpha,bravo,charlie"sv);
  assert_size(3, ==, res.size());
  assert_stdstring_equal("alpha", res[0]);
  assert_stdstring_equal("bravo", res[1]);
  assert_stdstring_equal("charlie", res[2]);
}

void test_util_make_http_hostport(void) {
  BlockAllocator balloc(4096, 4096);

  assert_stdsv_equal("localhost"sv,
                     util::make_http_hostport(balloc, "localhost"sv, 80));
  assert_stdsv_equal("[::1]"sv, util::make_http_hostport(balloc, "::1"sv, 443));
  assert_stdsv_equal("localhost:3000"sv,
                     util::make_http_hostport(balloc, "localhost"sv, 3000));
}

void test_util_make_hostport(void) {
  std::array<char, util::max_hostport> hostport_buf;
  assert_stdsv_equal(
    "localhost:80"sv,
    util::make_hostport("localhost"sv, 80, std::ranges::begin(hostport_buf)));
  assert_stdsv_equal(
    "[::1]:443"sv,
    util::make_hostport("::1"sv, 443, std::ranges::begin(hostport_buf)));

  BlockAllocator balloc(4096, 4096);
  assert_stdsv_equal("localhost:80"sv,
                     util::make_hostport(balloc, "localhost"sv, 80));
  assert_stdsv_equal("[::1]:443"sv, util::make_hostport(balloc, "::1"sv, 443));
}

void test_util_random_alpha_digit(void) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::array<uint8_t, 19> data;

  auto p = util::random_alpha_digit(std::ranges::begin(data),
                                    std::ranges::end(data), gen);

  assert_true(std::ranges::end(data) == p);

  for (auto b : data) {
    assert_true(('A' <= b && b <= 'Z') || ('a' <= b && b <= 'z') ||
                ('0' <= b && b <= '9'));
  }
}

void test_util_format_hex(void) {
  BlockAllocator balloc(4096, 4096);

  assert_stdsv_equal("0ff0"sv, util::format_hex(balloc, "\x0f\xf0"sv));
  assert_stdsv_equal(""sv, util::format_hex(balloc, ""sv));

  std::string o;
  o.resize(4);

  assert_true(std::ranges::end(o) ==
              util::format_hex("\xbe\xef"sv, std::ranges::begin(o)));
  assert_stdstring_equal("beef"s, o);
  assert_stdstring_equal("beef"s, util::format_hex("\xbe\xef"sv));

  std::array<char, 64> buf;

  assert_stdsv_equal(
    "00"sv,
    (std::string_view{
      buf.begin(), util::format_hex(static_cast<uint8_t>(0u), buf.begin())}));
  assert_stdsv_equal(
    "ec"sv,
    (std::string_view{buf.begin(), util::format_hex(static_cast<uint8_t>(0xecu),
                                                    buf.begin())}));
  assert_stdsv_equal(
    "00000000"sv,
    (std::string_view{buf.begin(), util::format_hex(0u, buf.begin())}));
  assert_stdsv_equal(
    "0000ab01"sv,
    (std::string_view{buf.begin(), util::format_hex(0xab01u, buf.begin())}));
  assert_stdsv_equal(
    "deadbeefbaadf00d"sv,
    (std::string_view{buf.begin(),
                      util::format_hex(0xdeadbeefbaadf00du, buf.begin())}));
  assert_stdsv_equal(
    "ffffffffffffffff"sv,
    (std::string_view{
      buf.begin(),
      util::format_hex(std::numeric_limits<uint64_t>::max(), buf.begin())}));
}

void test_util_format_upper_hex(void) {
  std::array<char, 64> buf;

  assert_stdsv_equal(
    "00"sv,
    (std::string_view{buf.begin(), util::format_upper_hex(0, buf.begin())}));
  assert_stdsv_equal(
    "0A"sv,
    (std::string_view{buf.begin(), util::format_upper_hex(0xa, buf.begin())}));
  assert_stdsv_equal(
    "7C"sv, (std::string_view{buf.begin(),
                              util::format_upper_hex(0x07c, buf.begin())}));
  assert_stdsv_equal(
    "EB"sv,
    (std::string_view{buf.begin(), util::format_upper_hex(0xeb, buf.begin())}));
  assert_stdsv_equal(
    "FF"sv,
    (std::string_view{buf.begin(), util::format_upper_hex(0xff, buf.begin())}));
}

void test_util_is_hex_string(void) {
  assert_true(util::is_hex_string(""sv));
  assert_true(util::is_hex_string("0123456789abcdef"sv));
  assert_true(util::is_hex_string("0123456789ABCDEF"sv));
  assert_false(util::is_hex_string("000"sv));
  assert_false(util::is_hex_string("XX"sv));
}

void test_util_decode_hex(void) {
  BlockAllocator balloc(4096, 4096);

  assert_stdsv_equal("\x0f\xf0"sv,
                     as_string_view(util::decode_hex(balloc, "0ff0"sv)));
  assert_stdsv_equal(""sv, as_string_view(util::decode_hex(balloc, ""sv)));
}

void test_util_extract_host(void) {
  assert_stdsv_equal("foo"sv, util::extract_host("foo"sv));
  assert_stdsv_equal("foo"sv, util::extract_host("foo:"sv));
  assert_stdsv_equal("foo"sv, util::extract_host("foo:0"sv));
  assert_stdsv_equal("[::1]"sv, util::extract_host("[::1]"sv));
  assert_stdsv_equal("[::1]"sv, util::extract_host("[::1]:"sv));

  assert_true(util::extract_host(":foo"sv).empty());
  assert_true(util::extract_host("[::1"sv).empty());
  assert_true(util::extract_host("[::1]0"sv).empty());
  assert_true(util::extract_host(""sv).empty());
}

void test_util_split_hostport(void) {
  assert_true(std::make_pair("foo"sv, ""sv) == util::split_hostport("foo"sv));
  assert_true(std::make_pair("foo"sv, "80"sv) ==
              util::split_hostport("foo:80"sv));
  assert_true(std::make_pair("::1"sv, "80"sv) ==
              util::split_hostport("[::1]:80"sv));
  assert_true(std::make_pair("::1"sv, ""sv) == util::split_hostport("[::1]"sv));

  assert_true(std::make_pair(""sv, ""sv) == util::split_hostport(""sv));
  assert_true(std::make_pair(""sv, ""sv) == util::split_hostport("[::1]:"sv));
  assert_true(std::make_pair(""sv, ""sv) == util::split_hostport("foo:"sv));
  assert_true(std::make_pair(""sv, ""sv) == util::split_hostport("[::1:"sv));
  assert_true(std::make_pair(""sv, ""sv) == util::split_hostport("[::1]80"sv));
}

void test_util_split_str(void) {
  assert_true(std::vector<std::string_view>{""sv} ==
              util::split_str(""sv, ','));
  assert_true(std::vector<std::string_view>{"alpha"sv} ==
              util::split_str("alpha"sv, ','));
  assert_true((std::vector<std::string_view>{"alpha"sv, ""sv}) ==
              util::split_str("alpha,"sv, ','));
  assert_true((std::vector<std::string_view>{"alpha"sv, "bravo"sv}) ==
              util::split_str("alpha,bravo"sv, ','));
  assert_true(
    (std::vector<std::string_view>{"alpha"sv, "bravo"sv, "charlie"sv}) ==
    util::split_str("alpha,bravo,charlie"sv, ','));
  assert_true(
    (std::vector<std::string_view>{"alpha"sv, "bravo"sv, "charlie"sv}) ==
    util::split_str("alpha,bravo,charlie"sv, ',', 0));
  assert_true(std::vector<std::string_view>{""sv} ==
              util::split_str(""sv, ',', 1));
  assert_true(std::vector<std::string_view>{""sv} ==
              util::split_str(""sv, ',', 2));
  assert_true((std::vector<std::string_view>{"alpha"sv, "bravo,charlie"sv}) ==
              util::split_str("alpha,bravo,charlie"sv, ',', 2));
  assert_true(std::vector<std::string_view>{"alpha"sv} ==
              util::split_str("alpha"sv, ',', 2));
  assert_true((std::vector<std::string_view>{"alpha"sv, ""sv}) ==
              util::split_str("alpha,"sv, ',', 2));
  assert_true(std::vector<std::string_view>{"alpha"sv} ==
              util::split_str("alpha"sv, ',', 0));
  assert_true(std::vector<std::string_view>{"alpha,bravo,charlie"sv} ==
              util::split_str("alpha,bravo,charlie"sv, ',', 1));
}

void test_util_rstrip(void) {
  BlockAllocator balloc(4096, 4096);

  assert_stdsv_equal("alpha"sv, util::rstrip(balloc, "alpha"sv));
  assert_stdsv_equal("alpha"sv, util::rstrip(balloc, "alpha "sv));
  assert_stdsv_equal("alpha"sv, util::rstrip(balloc, "alpha \t"sv));
  assert_stdsv_equal(""sv, util::rstrip(balloc, ""sv));
  assert_stdsv_equal(""sv, util::rstrip(balloc, "\t\t\t   "sv));
}

void test_util_contains(void) {
  assert_true(util::contains("alphabravo"sv, 'a'));
  assert_true(util::contains("alphabravo"sv, 'o'));
  assert_false(util::contains("alphabravo"sv, 'x'));
  assert_false(util::contains(""sv, ' '));
}

void test_util_hex_to_uint(void) {
  for (size_t i = 0; i < 256; ++i) {
    auto c = static_cast<char>(i);
    if (!util::is_hex_digit(c)) {
      assert_uint32(256, ==, util::hex_to_uint(c));
    }
  }

  for (uint32_t i = 0; i < 10; ++i) {
    assert_uint32(i, ==, util::hex_to_uint(static_cast<char>('0' + i)));
  }

  for (uint32_t i = 0; i < 6; ++i) {
    assert_uint32(i + 10, ==, util::hex_to_uint(static_cast<char>('A' + i)));
  }

  for (uint32_t i = 0; i < 6; ++i) {
    assert_uint32(i + 10, ==, util::hex_to_uint(static_cast<char>('a' + i)));
  }
}

void test_util_is_alpha(void) {
  for (size_t i = 0; i < 256; ++i) {
    auto c = static_cast<char>(i);
    if (('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z')) {
      assert_true(util::is_alpha(c));
    } else {
      assert_false(util::is_alpha(c));
    }
  }
}

void test_util_is_digit(void) {
  for (size_t i = 0; i < 256; ++i) {
    auto c = static_cast<char>(i);
    if ('0' <= c && c <= '9') {
      assert_true(util::is_digit(c));
    } else {
      assert_false(util::is_digit(c));
    }
  }
}

void test_util_is_hex_digit(void) {
  for (size_t i = 0; i < 256; ++i) {
    auto c = static_cast<char>(i);
    if (util::is_digit(c) || ('A' <= c && c <= 'F') || ('a' <= c && c <= 'f')) {
      assert_true(util::is_hex_digit(c));
    } else {
      assert_false(util::is_hex_digit(c));
    }
  }
}

void test_util_in_rfc3986_unreserved_chars(void) {
  for (size_t i = 0; i < 256; ++i) {
    auto c = static_cast<char>(i);
    switch (c) {
    case '-':
    case '.':
    case '_':
    case '~':
      assert_true(util::in_rfc3986_unreserved_chars(c));
      break;
    default:
      if (util::is_digit(c) || util::is_alpha(c)) {
        assert_true(util::in_rfc3986_unreserved_chars(c));
      } else {
        assert_false(util::in_rfc3986_unreserved_chars(c));
      }
    }
  }
}

void test_util_in_rfc3986_sub_delims(void) {
  for (size_t i = 0; i < 256; ++i) {
    auto c = static_cast<char>(i);
    switch (c) {
    case '!':
    case '$':
    case '&':
    case '\'':
    case '(':
    case ')':
    case '*':
    case '+':
    case ',':
    case ';':
    case '=':
      assert_true(util::in_rfc3986_sub_delims(c));
      break;
    default:
      assert_false(util::in_rfc3986_sub_delims(c));
    }
  }
}

void test_util_in_token(void) {
  for (size_t i = 0; i < 256; ++i) {
    auto c = static_cast<char>(i);
    switch (c) {
    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '.':
    case '^':
    case '_':
    case '`':
    case '|':
    case '~':
      assert_true(util::in_token(c));
      break;
    default:
      if (util::is_digit(c) || util::is_alpha(c)) {
        assert_true(util::in_token(c));
      } else {
        assert_false(util::in_token(c));
      }
    }
  }
}

void test_util_in_attr_char(void) {
  for (size_t i = 0; i < 256; ++i) {
    auto c = static_cast<char>(i);
    switch (c) {
    case '%':
    case '\'':
    case '*':
      assert_false(util::in_attr_char(c));
      break;
    default:
      if (util::in_token(c)) {
        assert_true(util::in_attr_char(c));
      } else {
        assert_false(util::in_attr_char(c));
      }
    }
  }
}

void test_util_upcase(void) {
  for (size_t i = 0; i < 256; ++i) {
    auto c = static_cast<char>(i);
    if ('a' <= c && c <= 'z') {
      assert_char(static_cast<char>(c - 'a' + 'A'), ==, util::upcase(c));
    } else {
      assert_char(c, ==, util::upcase(c));
    }
  }
}

void test_util_to_numeric_addr(void) {
  addrinfo hints{
    .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV,
    .ai_family = AF_UNSPEC,
  };

  addrinfo *res;

  auto rv = getaddrinfo("192.168.0.1", "443", &hints, &res);

  assert_int(0, ==, rv);

  assert_stdstring_equal("192.168.0.1:443"s,
                         util::to_numeric_addr(res->ai_addr, res->ai_addrlen));

  freeaddrinfo(res);

  rv = getaddrinfo("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "4443", &hints,
                   &res);

  assert_int(0, ==, rv);

  assert_stdstring_equal("[2001:db8:85a3::8a2e:370:7334]:4443"s,
                         util::to_numeric_addr(res->ai_addr, res->ai_addrlen));

  freeaddrinfo(res);
}

} // namespace shrpx
