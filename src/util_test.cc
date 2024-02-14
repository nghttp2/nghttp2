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

#include <cstring>
#include <iostream>
#include <random>

#include "munitxx.h"

#include <nghttp2/nghttp2.h>

#include "util.h"
#include "template.h"

using namespace nghttp2;

namespace shrpx {

namespace {
const MunitTest tests[]{
    munit_void_test(test_util_streq),
    munit_void_test(test_util_strieq),
    munit_void_test(test_util_inp_strlower),
    munit_void_test(test_util_to_base64),
    munit_void_test(test_util_to_token68),
    munit_void_test(test_util_percent_encode_token),
    munit_void_test(test_util_percent_decode),
    munit_void_test(test_util_quote_string),
    munit_void_test(test_util_utox),
    munit_void_test(test_util_http_date),
    munit_void_test(test_util_select_h2),
    munit_void_test(test_util_ipv6_numeric_addr),
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
    munit_void_test(test_util_strifind),
    munit_void_test(test_util_random_alpha_digit),
    munit_void_test(test_util_format_hex),
    munit_void_test(test_util_is_hex_string),
    munit_void_test(test_util_decode_hex),
    munit_void_test(test_util_extract_host),
    munit_void_test(test_util_split_hostport),
    munit_void_test(test_util_split_str),
    munit_void_test(test_util_rstrip),
    munit_test_end(),
};
} // namespace

const MunitSuite util_suite{
    "/util", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

void test_util_streq(void) {
  assert_true(
      util::streq(StringRef::from_lit("alpha"), StringRef::from_lit("alpha")));
  assert_false(util::streq(StringRef::from_lit("alpha"),
                           StringRef::from_lit("alphabravo")));
  assert_false(util::streq(StringRef::from_lit("alphabravo"),
                           StringRef::from_lit("alpha")));
  assert_false(
      util::streq(StringRef::from_lit("alpha"), StringRef::from_lit("alphA")));
  assert_false(util::streq(StringRef{}, StringRef::from_lit("a")));
  assert_true(util::streq(StringRef{}, StringRef{}));
  assert_false(util::streq(StringRef::from_lit("alpha"), StringRef{}));

  assert_false(
      util::streq(StringRef::from_lit("alph"), StringRef::from_lit("alpha")));
  assert_false(
      util::streq(StringRef::from_lit("alpha"), StringRef::from_lit("alph")));
  assert_false(
      util::streq(StringRef::from_lit("alpha"), StringRef::from_lit("alphA")));

  assert_true(util::streq_l("alpha", "alpha", 5));
  assert_true(util::streq_l("alpha", "alphabravo", 5));
  assert_false(util::streq_l("alpha", "alphabravo", 6));
  assert_false(util::streq_l("alphabravo", "alpha", 5));
  assert_false(util::streq_l("alpha", "alphA", 5));
  assert_false(util::streq_l("", "a", 1));
  assert_true(util::streq_l("", "", 0));
  assert_false(util::streq_l("alpha", "", 0));
}

void test_util_strieq(void) {
  assert_true(util::strieq(std::string("alpha"), std::string("alpha")));
  assert_true(util::strieq(std::string("alpha"), std::string("AlPhA")));
  assert_true(util::strieq(std::string(), std::string()));
  assert_false(util::strieq(std::string("alpha"), std::string("AlPhA ")));
  assert_false(util::strieq(std::string(), std::string("AlPhA ")));

  assert_true(
      util::strieq(StringRef::from_lit("alpha"), StringRef::from_lit("alpha")));
  assert_true(
      util::strieq(StringRef::from_lit("alpha"), StringRef::from_lit("AlPhA")));
  assert_true(util::strieq(StringRef{}, StringRef{}));
  assert_false(util::strieq(StringRef::from_lit("alpha"),
                            StringRef::from_lit("AlPhA ")));
  assert_false(
      util::strieq(StringRef::from_lit(""), StringRef::from_lit("AlPhA ")));

  assert_true(util::strieq_l("alpha", "alpha", 5));
  assert_true(util::strieq_l("alpha", "AlPhA", 5));
  assert_true(util::strieq_l("", static_cast<const char *>(nullptr), 0));
  assert_false(util::strieq_l("alpha", "AlPhA ", 6));
  assert_false(util::strieq_l("", "AlPhA ", 6));

  assert_true(util::strieq_l("alpha", StringRef::from_lit("alpha")));
  assert_true(util::strieq_l("alpha", StringRef::from_lit("AlPhA")));
  assert_true(util::strieq_l("", StringRef{}));
  assert_false(util::strieq_l("alpha", StringRef::from_lit("AlPhA ")));
  assert_false(util::strieq_l("", StringRef::from_lit("AlPhA ")));
}

void test_util_inp_strlower(void) {
  std::string a("alPha");
  util::inp_strlower(a);
  assert_stdstring_equal("alpha", a);

  a = "ALPHA123BRAVO";
  util::inp_strlower(a);
  assert_stdstring_equal("alpha123bravo", a);

  a = "";
  util::inp_strlower(a);
  assert_stdstring_equal("", a);
}

void test_util_to_base64(void) {
  BlockAllocator balloc(4096, 4096);

  assert_stdstring_equal(
      "AAA++B/=",
      util::to_base64(balloc, StringRef::from_lit("AAA--B_")).str());
  assert_stdstring_equal(
      "AAA++B/B",
      util::to_base64(balloc, StringRef::from_lit("AAA--B_B")).str());
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
  BlockAllocator balloc(4096, 4096);
  assert_stdstring_equal(
      "h2",
      util::percent_encode_token(balloc, StringRef::from_lit("h2")).str());
  assert_stdstring_equal(
      "h3~",
      util::percent_encode_token(balloc, StringRef::from_lit("h3~")).str());
  assert_stdstring_equal(
      "100%25",
      util::percent_encode_token(balloc, StringRef::from_lit("100%")).str());
  assert_stdstring_equal(
      "http%202",
      util::percent_encode_token(balloc, StringRef::from_lit("http 2")).str());
}

void test_util_percent_decode(void) {
  {
    std::string s = "%66%6F%6f%62%61%72";
    assert_stdstring_equal("foobar",
                           util::percent_decode(std::begin(s), std::end(s)));
  }
  {
    std::string s = "%66%6";
    assert_stdstring_equal("f%6",
                           util::percent_decode(std::begin(s), std::end(s)));
  }
  {
    std::string s = "%66%";
    assert_stdstring_equal("f%",
                           util::percent_decode(std::begin(s), std::end(s)));
  }
  BlockAllocator balloc(1024, 1024);

  assert_stdstring_equal(
      "foobar",
      util::percent_decode(balloc, StringRef::from_lit("%66%6F%6f%62%61%72"))
          .str());

  assert_stdstring_equal(
      "f%6", util::percent_decode(balloc, StringRef::from_lit("%66%6")).str());

  assert_stdstring_equal(
      "f%", util::percent_decode(balloc, StringRef::from_lit("%66%")).str());
}

void test_util_quote_string(void) {
  BlockAllocator balloc(4096, 4096);
  assert_stdstring_equal(
      "alpha", util::quote_string(balloc, StringRef::from_lit("alpha")).str());
  assert_stdstring_equal(
      "", util::quote_string(balloc, StringRef::from_lit("")).str());
  assert_stdstring_equal(
      "\\\"alpha\\\"",
      util::quote_string(balloc, StringRef::from_lit("\"alpha\"")).str());
}

void test_util_utox(void) {
  assert_stdstring_equal("0", util::utox(0));
  assert_stdstring_equal("1", util::utox(1));
  assert_stdstring_equal("F", util::utox(15));
  assert_stdstring_equal("10", util::utox(16));
  assert_stdstring_equal("3B9ACA07", util::utox(1000000007));
  assert_stdstring_equal("100000000", util::utox(1LL << 32));
}

void test_util_http_date(void) {
  assert_stdstring_equal("Thu, 01 Jan 1970 00:00:00 GMT", util::http_date(0));
  assert_stdstring_equal("Wed, 29 Feb 2012 09:15:16 GMT",
                         util::http_date(1330506916));

  std::array<char, 30> http_buf;

  assert_stdstring_equal(
      "Thu, 01 Jan 1970 00:00:00 GMT",
      util::format_http_date(http_buf.data(),
                             std::chrono::system_clock::time_point())
          .str());
  assert_stdstring_equal(
      "Wed, 29 Feb 2012 09:15:16 GMT",
      util::format_http_date(http_buf.data(),
                             std::chrono::system_clock::time_point(
                                 std::chrono::seconds(1330506916)))
          .str());
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
  const unsigned char t2[] = "\x6h2-14";
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
  const unsigned char t4[] = "\x2h3\x6h2-14";
  assert_false(util::select_h2(&out, &outlen, t4, sizeof(t4) - 1));

  // Check the case that all entries are not supported.
  const unsigned char t5[] = "\x2h3\x2h4";
  assert_false(util::select_h2(&out, &outlen, t5, sizeof(t5) - 1));

  // Check the case where 2 values are eligible, but last one is
  // picked up because it has precedence over the other.
  const unsigned char t6[] = "\x5h2-14\x5h2-16";
  assert_true(util::select_h2(&out, &outlen, t6, sizeof(t6) - 1));
  assert_true(util::streq(NGHTTP2_H2_16, StringRef{out, outlen}));
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

void test_util_utos(void) {
  uint8_t buf[32];

  assert_stdstring_equal("0", (std::string{buf, util::utos(buf, 0)}));
  assert_stdstring_equal("123", (std::string{buf, util::utos(buf, 123)}));
  assert_stdstring_equal(
      "18446744073709551615",
      (std::string{buf, util::utos(buf, 18446744073709551615ULL)}));
}

void test_util_make_string_ref_uint(void) {
  BlockAllocator balloc(1024, 1024);

  assert_stdstring_equal("0", util::make_string_ref_uint(balloc, 0).str());
  assert_stdstring_equal("123", util::make_string_ref_uint(balloc, 123).str());
  assert_stdstring_equal(
      "18446744073709551615",
      util::make_string_ref_uint(balloc, 18446744073709551615ULL).str());
}

void test_util_utos_unit(void) {
  assert_stdstring_equal("0", util::utos_unit(0));
  assert_stdstring_equal("1023", util::utos_unit(1023));
  assert_stdstring_equal("1K", util::utos_unit(1024));
  assert_stdstring_equal("1K", util::utos_unit(1025));
  assert_stdstring_equal("1M", util::utos_unit(1 << 20));
  assert_stdstring_equal("1G", util::utos_unit(1 << 30));
  assert_stdstring_equal("1024G", util::utos_unit(1LL << 40));
}

void test_util_utos_funit(void) {
  assert_stdstring_equal("0", util::utos_funit(0));
  assert_stdstring_equal("1023", util::utos_funit(1023));
  assert_stdstring_equal("1.00K", util::utos_funit(1024));
  assert_stdstring_equal("1.00K", util::utos_funit(1025));
  assert_stdstring_equal("1.09K", util::utos_funit(1119));
  assert_stdstring_equal("1.27K", util::utos_funit(1300));
  assert_stdstring_equal("1.00M", util::utos_funit(1 << 20));
  assert_stdstring_equal("1.18M", util::utos_funit(1234567));
  assert_stdstring_equal("1.00G", util::utos_funit(1 << 30));
  assert_stdstring_equal("4492450797.23G",
                         util::utos_funit(4823732313248234343LL));
  assert_stdstring_equal("1024.00G", util::utos_funit(1LL << 40));
}

void test_util_parse_uint_with_unit(void) {
  assert_int64(0, ==, util::parse_uint_with_unit("0"));
  assert_int64(1023, ==, util::parse_uint_with_unit("1023"));
  assert_int64(1024, ==, util::parse_uint_with_unit("1k"));
  assert_int64(2048, ==, util::parse_uint_with_unit("2K"));
  assert_int64(1 << 20, ==, util::parse_uint_with_unit("1m"));
  assert_int64(1 << 21, ==, util::parse_uint_with_unit("2M"));
  assert_int64(1 << 30, ==, util::parse_uint_with_unit("1g"));
  assert_int64(1LL << 31, ==, util::parse_uint_with_unit("2G"));
  assert_int64(9223372036854775807LL, ==,
               util::parse_uint_with_unit("9223372036854775807"));
  // check overflow case
  assert_int64(-1, ==, util::parse_uint_with_unit("9223372036854775808"));
  assert_int64(-1, ==, util::parse_uint_with_unit("10000000000000000000"));
  assert_int64(-1, ==, util::parse_uint_with_unit("9223372036854775807G"));
  // bad characters
  assert_int64(-1, ==, util::parse_uint_with_unit("1.1"));
  assert_int64(-1, ==, util::parse_uint_with_unit("1a"));
  assert_int64(-1, ==, util::parse_uint_with_unit("a1"));
  assert_int64(-1, ==, util::parse_uint_with_unit("1T"));
  assert_int64(-1, ==, util::parse_uint_with_unit(""));
}

void test_util_parse_uint(void) {
  assert_int64(0, ==, util::parse_uint("0"));
  assert_int64(1023, ==, util::parse_uint("1023"));
  assert_int64(-1, ==, util::parse_uint("1k"));
  assert_int64(9223372036854775807LL, ==,
               util::parse_uint("9223372036854775807"));
  // check overflow case
  assert_int64(-1, ==, util::parse_uint("9223372036854775808"));
  assert_int64(-1, ==, util::parse_uint("10000000000000000000"));
  // bad characters
  assert_int64(-1, ==, util::parse_uint("1.1"));
  assert_int64(-1, ==, util::parse_uint("1a"));
  assert_int64(-1, ==, util::parse_uint("a1"));
  assert_int64(-1, ==, util::parse_uint("1T"));
  assert_int64(-1, ==, util::parse_uint(""));
}

void test_util_parse_duration_with_unit(void) {
  assert_double(0., ==, util::parse_duration_with_unit("0"));
  assert_double(123., ==, util::parse_duration_with_unit("123"));
  assert_double(123., ==, util::parse_duration_with_unit("123s"));
  assert_double(0.500, ==, util::parse_duration_with_unit("500ms"));
  assert_double(123., ==, util::parse_duration_with_unit("123S"));
  assert_double(0.500, ==, util::parse_duration_with_unit("500MS"));
  assert_double(180, ==, util::parse_duration_with_unit("3m"));
  assert_double(3600 * 5, ==, util::parse_duration_with_unit("5h"));

  auto err = std::numeric_limits<double>::infinity();
  // check overflow case
  assert_double(err, ==, util::parse_duration_with_unit("9223372036854775808"));
  // bad characters
  assert_double(err, ==, util::parse_duration_with_unit("0u"));
  assert_double(err, ==, util::parse_duration_with_unit("0xs"));
  assert_double(err, ==, util::parse_duration_with_unit("0mt"));
  assert_double(err, ==, util::parse_duration_with_unit("0mss"));
  assert_double(err, ==, util::parse_duration_with_unit("s"));
  assert_double(err, ==, util::parse_duration_with_unit("ms"));
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
  assert_true(util::starts_with(StringRef::from_lit("foo"),
                                StringRef::from_lit("foo")));
  assert_true(util::starts_with(StringRef::from_lit("fooo"),
                                StringRef::from_lit("foo")));
  assert_true(util::starts_with(StringRef::from_lit("ofoo"), StringRef{}));
  assert_false(util::starts_with(StringRef::from_lit("ofoo"),
                                 StringRef::from_lit("foo")));

  assert_true(util::istarts_with(StringRef::from_lit("FOO"),
                                 StringRef::from_lit("fOO")));
  assert_true(util::istarts_with(StringRef::from_lit("ofoo"), StringRef{}));
  assert_true(util::istarts_with(StringRef::from_lit("fOOo"),
                                 StringRef::from_lit("Foo")));
  assert_false(util::istarts_with(StringRef::from_lit("ofoo"),
                                  StringRef::from_lit("foo")));

  assert_true(util::istarts_with_l(StringRef::from_lit("fOOo"), "Foo"));
  assert_false(util::istarts_with_l(StringRef::from_lit("ofoo"), "foo"));
}

void test_util_ends_with(void) {
  assert_true(
      util::ends_with(StringRef::from_lit("foo"), StringRef::from_lit("foo")));
  assert_true(util::ends_with(StringRef::from_lit("foo"), StringRef{}));
  assert_true(
      util::ends_with(StringRef::from_lit("ofoo"), StringRef::from_lit("foo")));
  assert_false(
      util::ends_with(StringRef::from_lit("ofoo"), StringRef::from_lit("fo")));

  assert_true(
      util::iends_with(StringRef::from_lit("fOo"), StringRef::from_lit("Foo")));
  assert_true(util::iends_with(StringRef::from_lit("foo"), StringRef{}));
  assert_true(util::iends_with(StringRef::from_lit("oFoo"),
                               StringRef::from_lit("fOO")));
  assert_false(
      util::iends_with(StringRef::from_lit("ofoo"), StringRef::from_lit("fo")));

  assert_true(util::iends_with_l(StringRef::from_lit("oFoo"), "fOO"));
  assert_false(util::iends_with_l(StringRef::from_lit("ofoo"), "fo"));
}

void test_util_parse_http_date(void) {
  assert_int64(1001939696, ==,
               util::parse_http_date(
                   StringRef::from_lit("Mon, 1 Oct 2001 12:34:56 GMT")));
}

void test_util_localtime_date(void) {
  auto tz = getenv("TZ");
  if (tz) {
    tz = strdup(tz);
  }
#ifdef __linux__
  setenv("TZ", "NZST-12:00:00:00", 1);
#else  // !__linux__
  setenv("TZ", ":Pacific/Auckland", 1);
#endif // !__linux__
  tzset();

  assert_stdstring_equal("02/Oct/2001:00:34:56 +1200",
                         util::common_log_date(1001939696));
  assert_stdstring_equal("2001-10-02T00:34:56.123+12:00",
                         util::iso8601_date(1001939696000LL + 123));

  std::array<char, 27> common_buf;

  assert_stdstring_equal(
      "02/Oct/2001:00:34:56 +1200",
      util::format_common_log(common_buf.data(),
                              std::chrono::system_clock::time_point(
                                  std::chrono::seconds(1001939696)))
          .str());

  std::array<char, 30> iso8601_buf;

  assert_stdstring_equal(
      "2001-10-02T00:34:56.123+12:00",
      util::format_iso8601(iso8601_buf.data(),
                           std::chrono::system_clock::time_point(
                               std::chrono::milliseconds(1001939696123LL)))
          .str());

  if (tz) {
    setenv("TZ", tz, 1);
    free(tz);
  } else {
    unsetenv("TZ");
  }
  tzset();
}

void test_util_get_uint64(void) {
  {
    auto v = std::array<unsigned char, 8>{
        {0x01, 0x12, 0x34, 0x56, 0xff, 0x9a, 0xab, 0xbc}};

    auto n = util::get_uint64(v.data());

    assert_uint64(0x01123456ff9aabbcULL, ==, n);
  }
  {
    auto v = std::array<unsigned char, 8>{
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

    auto n = util::get_uint64(v.data());

    assert_uint64(0xffffffffffffffffULL, ==, n);
  }
}

void test_util_parse_config_str_list(void) {
  auto res = util::parse_config_str_list(StringRef::from_lit("a"));
  assert_size(1, ==, res.size());
  assert_stdstring_equal("a", res[0]);

  res = util::parse_config_str_list(StringRef::from_lit("a,"));
  assert_size(2, ==, res.size());
  assert_stdstring_equal("a", res[0]);
  assert_stdstring_equal("", res[1]);

  res = util::parse_config_str_list(StringRef::from_lit(":a::"), ':');
  assert_size(4, ==, res.size());
  assert_stdstring_equal("", res[0]);
  assert_stdstring_equal("a", res[1]);
  assert_stdstring_equal("", res[2]);
  assert_stdstring_equal("", res[3]);

  res = util::parse_config_str_list(StringRef{});
  assert_size(1, ==, res.size());
  assert_stdstring_equal("", res[0]);

  res = util::parse_config_str_list(StringRef::from_lit("alpha,bravo,charlie"));
  assert_size(3, ==, res.size());
  assert_stdstring_equal("alpha", res[0]);
  assert_stdstring_equal("bravo", res[1]);
  assert_stdstring_equal("charlie", res[2]);
}

void test_util_make_http_hostport(void) {
  BlockAllocator balloc(4096, 4096);

  assert_stdstring_equal(
      "localhost",
      util::make_http_hostport(balloc, StringRef::from_lit("localhost"), 80)
          .str());
  assert_stdstring_equal(
      "[::1]",
      util::make_http_hostport(balloc, StringRef::from_lit("::1"), 443).str());
  assert_stdstring_equal(
      "localhost:3000",
      util::make_http_hostport(balloc, StringRef::from_lit("localhost"), 3000)
          .str());
}

void test_util_make_hostport(void) {
  std::array<char, util::max_hostport> hostport_buf;
  assert_stdstring_equal(
      "localhost:80", util::make_hostport(std::begin(hostport_buf),
                                          StringRef::from_lit("localhost"), 80)
                          .str());
  assert_stdstring_equal("[::1]:443",
                         util::make_hostport(std::begin(hostport_buf),
                                             StringRef::from_lit("::1"), 443)
                             .str());

  BlockAllocator balloc(4096, 4096);
  assert_stdstring_equal(
      "localhost:80",
      util::make_hostport(balloc, StringRef::from_lit("localhost"), 80).str());
  assert_stdstring_equal(
      "[::1]:443",
      util::make_hostport(balloc, StringRef::from_lit("::1"), 443).str());
}

void test_util_strifind(void) {
  assert_true(util::strifind(StringRef::from_lit("gzip, deflate, bzip2"),
                             StringRef::from_lit("gzip")));

  assert_true(util::strifind(StringRef::from_lit("gzip, deflate, bzip2"),
                             StringRef::from_lit("dEflate")));

  assert_true(util::strifind(StringRef::from_lit("gzip, deflate, bzip2"),
                             StringRef::from_lit("BZIP2")));

  assert_true(util::strifind(StringRef::from_lit("nghttp2"), StringRef{}));

  // Be aware this fact
  assert_false(util::strifind(StringRef{}, StringRef{}));

  assert_false(util::strifind(StringRef::from_lit("nghttp2"),
                              StringRef::from_lit("http1")));
}

void test_util_random_alpha_digit(void) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::array<uint8_t, 19> data;

  auto p = util::random_alpha_digit(std::begin(data), std::end(data), gen);

  assert_true(std::end(data) == p);

  for (auto b : data) {
    assert_true(('A' <= b && b <= 'Z') || ('a' <= b && b <= 'z') ||
                ('0' <= b && b <= '9'));
  }
}

void test_util_format_hex(void) {
  BlockAllocator balloc(4096, 4096);

  assert_stdstring_equal(
      "0ff0", util::format_hex(balloc, StringRef::from_lit("\x0f\xf0")).str());
  assert_stdstring_equal(
      "", util::format_hex(balloc, StringRef::from_lit("")).str());
}

void test_util_is_hex_string(void) {
  assert_true(util::is_hex_string(StringRef{}));
  assert_true(util::is_hex_string(StringRef::from_lit("0123456789abcdef")));
  assert_true(util::is_hex_string(StringRef::from_lit("0123456789ABCDEF")));
  assert_false(util::is_hex_string(StringRef::from_lit("000")));
  assert_false(util::is_hex_string(StringRef::from_lit("XX")));
}

void test_util_decode_hex(void) {
  BlockAllocator balloc(4096, 4096);

  assert_stdstring_equal(
      "\x0f\xf0", util::decode_hex(balloc, StringRef::from_lit("0ff0")).str());
  assert_stdstring_equal("", util::decode_hex(balloc, StringRef{}).str());
}

void test_util_extract_host(void) {
  assert_stdstring_equal("foo",
                         util::extract_host(StringRef::from_lit("foo")).str());
  assert_stdstring_equal("foo",
                         util::extract_host(StringRef::from_lit("foo:")).str());
  assert_stdstring_equal(
      "foo", util::extract_host(StringRef::from_lit("foo:0")).str());
  assert_stdstring_equal(
      "[::1]", util::extract_host(StringRef::from_lit("[::1]")).str());
  assert_stdstring_equal(
      "[::1]", util::extract_host(StringRef::from_lit("[::1]:")).str());

  assert_true(util::extract_host(StringRef::from_lit(":foo")).empty());
  assert_true(util::extract_host(StringRef::from_lit("[::1")).empty());
  assert_true(util::extract_host(StringRef::from_lit("[::1]0")).empty());
  assert_true(util::extract_host(StringRef{}).empty());
}

void test_util_split_hostport(void) {
  assert_true(std::make_pair(StringRef::from_lit("foo"), StringRef{}) ==
              util::split_hostport(StringRef::from_lit("foo")));
  assert_true(
      std::make_pair(StringRef::from_lit("foo"), StringRef::from_lit("80")) ==
      util::split_hostport(StringRef::from_lit("foo:80")));
  assert_true(
      std::make_pair(StringRef::from_lit("::1"), StringRef::from_lit("80")) ==
      util::split_hostport(StringRef::from_lit("[::1]:80")));
  assert_true(std::make_pair(StringRef::from_lit("::1"), StringRef{}) ==
              util::split_hostport(StringRef::from_lit("[::1]")));

  assert_true(std::make_pair(StringRef{}, StringRef{}) ==
              util::split_hostport(StringRef{}));
  assert_true(std::make_pair(StringRef{}, StringRef{}) ==
              util::split_hostport(StringRef::from_lit("[::1]:")));
  assert_true(std::make_pair(StringRef{}, StringRef{}) ==
              util::split_hostport(StringRef::from_lit("foo:")));
  assert_true(std::make_pair(StringRef{}, StringRef{}) ==
              util::split_hostport(StringRef::from_lit("[::1:")));
  assert_true(std::make_pair(StringRef{}, StringRef{}) ==
              util::split_hostport(StringRef::from_lit("[::1]80")));
}

void test_util_split_str(void) {
  assert_true(std::vector<StringRef>{StringRef::from_lit("")} ==
              util::split_str(StringRef::from_lit(""), ','));
  assert_true(std::vector<StringRef>{StringRef::from_lit("alpha")} ==
              util::split_str(StringRef::from_lit("alpha"), ','));
  assert_true((std::vector<StringRef>{StringRef::from_lit("alpha"),
                                      StringRef::from_lit("")}) ==
              util::split_str(StringRef::from_lit("alpha,"), ','));
  assert_true((std::vector<StringRef>{StringRef::from_lit("alpha"),
                                      StringRef::from_lit("bravo")}) ==
              util::split_str(StringRef::from_lit("alpha,bravo"), ','));
  assert_true((std::vector<StringRef>{StringRef::from_lit("alpha"),
                                      StringRef::from_lit("bravo"),
                                      StringRef::from_lit("charlie")}) ==
              util::split_str(StringRef::from_lit("alpha,bravo,charlie"), ','));
  assert_true(
      (std::vector<StringRef>{StringRef::from_lit("alpha"),
                              StringRef::from_lit("bravo"),
                              StringRef::from_lit("charlie")}) ==
      util::split_str(StringRef::from_lit("alpha,bravo,charlie"), ',', 0));
  assert_true(std::vector<StringRef>{StringRef::from_lit("")} ==
              util::split_str(StringRef::from_lit(""), ',', 1));
  assert_true(std::vector<StringRef>{StringRef::from_lit("")} ==
              util::split_str(StringRef::from_lit(""), ',', 2));
  assert_true(
      (std::vector<StringRef>{StringRef::from_lit("alpha"),
                              StringRef::from_lit("bravo,charlie")}) ==
      util::split_str(StringRef::from_lit("alpha,bravo,charlie"), ',', 2));
  assert_true(std::vector<StringRef>{StringRef::from_lit("alpha")} ==
              util::split_str(StringRef::from_lit("alpha"), ',', 2));
  assert_true((std::vector<StringRef>{StringRef::from_lit("alpha"),
                                      StringRef::from_lit("")}) ==
              util::split_str(StringRef::from_lit("alpha,"), ',', 2));
  assert_true(std::vector<StringRef>{StringRef::from_lit("alpha")} ==
              util::split_str(StringRef::from_lit("alpha"), ',', 0));
  assert_true(
      std::vector<StringRef>{StringRef::from_lit("alpha,bravo,charlie")} ==
      util::split_str(StringRef::from_lit("alpha,bravo,charlie"), ',', 1));
}

void test_util_rstrip(void) {
  BlockAllocator balloc(4096, 4096);

  assert_stdstring_equal(
      "alpha", util::rstrip(balloc, StringRef::from_lit("alpha")).str());
  assert_stdstring_equal(
      "alpha", util::rstrip(balloc, StringRef::from_lit("alpha ")).str());
  assert_stdstring_equal(
      "alpha", util::rstrip(balloc, StringRef::from_lit("alpha \t")).str());
  assert_stdstring_equal("",
                         util::rstrip(balloc, StringRef::from_lit("")).str());
  assert_stdstring_equal(
      "", util::rstrip(balloc, StringRef::from_lit("\t\t\t   ")).str());
}

} // namespace shrpx
