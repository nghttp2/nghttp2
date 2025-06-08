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
#include "util.h"

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif // HAVE_SYS_SOCKET_H
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif // HAVE_NETDB_H
#include <sys/stat.h>
#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif // HAVE_FCNTL_H
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif // HAVE_NETINET_IN_H
#ifdef HAVE_NETINET_IP_H
#  include <netinet/ip.h>
#endif // HAVE_NETINET_IP_H
#include <netinet/udp.h>
#ifdef _WIN32
#  include <ws2tcpip.h>
#else // !_WIN32
#  include <netinet/tcp.h>
#endif // !_WIN32
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif // HAVE_ARPA_INET_H

#include <cmath>
#include <cerrno>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <fstream>
#include <iomanip>

#include "ssl_compat.h"

#ifdef NGHTTP2_OPENSSL_IS_WOLFSSL
#  include <wolfssl/options.h>
#  include <wolfssl/openssl/evp.h>
#else // !NGHTTP2_OPENSSL_IS_WOLFSSL
#  include <openssl/evp.h>
#endif // !NGHTTP2_OPENSSL_IS_WOLFSSL

#include <nghttp2/nghttp2.h>

#include "timegm.h"

namespace nghttp2 {

namespace util {

#ifndef _WIN32
namespace {
int nghttp2_inet_pton(int af, const char *src, void *dst) {
  return inet_pton(af, src, dst);
}
} // namespace
#else // _WIN32
namespace {
// inet_pton-wrapper for Windows
int nghttp2_inet_pton(int af, const char *src, void *dst) {
#  if _WIN32_WINNT >= 0x0600
  return InetPtonA(af, src, dst);
#  else
  // the function takes a 'char*', so we need to make a copy
  char addr[INET6_ADDRSTRLEN + 1];
  strncpy(addr, src, sizeof(addr));
  addr[sizeof(addr) - 1] = 0;

  int size = sizeof(struct in6_addr);

  if (WSAStringToAddress(addr, af, nullptr, (LPSOCKADDR)dst, &size) == 0)
    return 1;
  return 0;
#  endif
}
} // namespace
#endif // _WIN32

namespace {
template <std::weakly_incrementable O>
requires(std::indirectly_writable<O, char>)
O cpydig2(uint32_t n, O result) {
  return std::ranges::copy_n(utos_digits.data() + n * 2, 2, result).out;
}
} // namespace

namespace {
template <std::weakly_incrementable O>
requires(std::indirectly_writable<O, char>)
O cpydig3(uint32_t n, O result) {
  *result++ = '0' + static_cast<char>((n / 100) % 10);
  return std::ranges::copy_n(utos_digits.data() + (n % 100) * 2, 2, result).out;
}
} // namespace

namespace {
template <std::weakly_incrementable O>
requires(std::indirectly_writable<O, char>)
O cpydig4(uint32_t n, O result) {
  result =
    std::ranges::copy_n(utos_digits.data() + (n / 100) * 2, 2, result).out;
  return std::ranges::copy_n(utos_digits.data() + (n % 100) * 2, 2, result).out;
}
} // namespace

namespace {
constinit const auto MONTH = std::to_array({
  "Jan"sv,
  "Feb"sv,
  "Mar"sv,
  "Apr"sv,
  "May"sv,
  "Jun"sv,
  "Jul"sv,
  "Aug"sv,
  "Sep"sv,
  "Oct"sv,
  "Nov"sv,
  "Dec"sv,
});

constinit const auto WEEKDAY = std::to_array({
  "Sun"sv,
  "Mon"sv,
  "Tue"sv,
  "Wed"sv,
  "Thu"sv,
  "Fri"sv,
  "Sat"sv,
});
} // namespace

std::string format_http_date(const std::chrono::system_clock::time_point &tp) {
  // Sat, 27 Sep 2014 06:31:15 GMT
  std::string res(29 + /* NUL */ 1, 0);

  auto s = format_http_date(res.data(), tp);

  res.resize(s.size());

  return res;
}

std::string format_iso8601(const std::chrono::system_clock::time_point &tp) {
  // 2014-11-15T12:58:24.741Z
  // 2014-11-15T12:58:24.741+09:00
  std::string res(29 + /* NUL */ 1, 0);

  auto s = format_iso8601(res.data(), tp);

  res.resize(s.size());

  return res;
}

#ifdef HAVE_STD_CHRONO_TIME_ZONE
namespace {
const std::chrono::time_zone *get_current_time_zone() {
  static auto tz = std::chrono::current_zone();
  return tz;
}
} // namespace

std::string_view
format_iso8601(char *out, const std::chrono::system_clock::time_point &tp) {
  return format_iso8601(out, tp, get_current_time_zone());
}

std::string_view format_iso8601(char *out,
                                const std::chrono::system_clock::time_point &tp,
                                const std::chrono::time_zone *tz) {
  auto t = std::chrono::floor<std::chrono::milliseconds>(tp);
  auto zt = std::chrono::zoned_time{tz, t};
  auto lt = zt.get_local_time();
  auto days = std::chrono::floor<std::chrono::days>(lt);
  auto ymd = std::chrono::year_month_day{days};

  auto p = out;

  p = cpydig4(as_unsigned(static_cast<int>(ymd.year())), p);
  *p++ = '-';
  p = cpydig2(static_cast<uint32_t>(ymd.month()), p);
  *p++ = '-';
  p = cpydig2(static_cast<uint32_t>(ymd.day()), p);
  *p++ = 'T';

  auto hms = std::chrono::hh_mm_ss{lt - days};

  p = cpydig2(static_cast<uint32_t>(hms.hours().count()), p);
  *p++ = ':';
  p = cpydig2(static_cast<uint32_t>(hms.minutes().count()), p);
  *p++ = ':';
  p = cpydig2(static_cast<uint32_t>(hms.seconds().count()), p);
  *p++ = '.';
  p = cpydig3(static_cast<uint32_t>(hms.subseconds().count()), p);

  auto sys_info = zt.get_info();
  auto gmtoff =
    std::chrono::floor<std::chrono::minutes>(sys_info.offset).count();
  if (gmtoff == 0) {
    *p++ = 'Z';
  } else {
    if (gmtoff > 0) {
      *p++ = '+';
    } else {
      *p++ = '-';
      gmtoff = -gmtoff;
    }
    p = cpydig2(static_cast<uint32_t>(gmtoff / 60), p);
    *p++ = ':';
    p = cpydig2(static_cast<uint32_t>(gmtoff % 60), p);
  }

  *p = '\0';

  return {out, p};
}

std::string_view
format_iso8601_basic(char *out,
                     const std::chrono::system_clock::time_point &tp) {
  return format_iso8601_basic(out, tp, get_current_time_zone());
}

std::string_view
format_iso8601_basic(char *out, const std::chrono::system_clock::time_point &tp,
                     const std::chrono::time_zone *tz) {
  auto t = std::chrono::floor<std::chrono::milliseconds>(tp);
  auto zt = std::chrono::zoned_time{tz, t};
  auto lt = zt.get_local_time();
  auto days = std::chrono::floor<std::chrono::days>(lt);
  auto ymd = std::chrono::year_month_day{days};

  auto p = out;

  p = cpydig4(as_unsigned(static_cast<int>(ymd.year())), p);
  p = cpydig2(static_cast<uint32_t>(ymd.month()), p);
  p = cpydig2(static_cast<uint32_t>(ymd.day()), p);
  *p++ = 'T';

  auto hms = std::chrono::hh_mm_ss{lt - days};

  p = cpydig2(static_cast<uint32_t>(hms.hours().count()), p);
  p = cpydig2(static_cast<uint32_t>(hms.minutes().count()), p);
  p = cpydig2(static_cast<uint32_t>(hms.seconds().count()), p);
  *p++ = '.';
  p = cpydig3(static_cast<uint32_t>(hms.subseconds().count()), p);

  auto sys_info = zt.get_info();
  auto gmtoff =
    std::chrono::floor<std::chrono::minutes>(sys_info.offset).count();
  if (gmtoff == 0) {
    *p++ = 'Z';
  } else {
    if (gmtoff > 0) {
      *p++ = '+';
    } else {
      *p++ = '-';
      gmtoff = -gmtoff;
    }
    p = cpydig2(static_cast<uint32_t>(gmtoff / 60), p);
    p = cpydig2(static_cast<uint32_t>(gmtoff % 60), p);
  }

  *p = '\0';

  return {out, p};
}

std::string_view
format_common_log(char *out, const std::chrono::system_clock::time_point &tp) {
  return format_common_log(out, tp, get_current_time_zone());
}

std::string_view
format_common_log(char *out, const std::chrono::system_clock::time_point &tp,
                  const std::chrono::time_zone *tz) {
  auto t = std::chrono::floor<std::chrono::milliseconds>(tp);
  auto zt = std::chrono::zoned_time{tz, t};
  auto lt = zt.get_local_time();
  auto days = std::chrono::floor<std::chrono::days>(lt);
  auto ymd = std::chrono::year_month_day{days};

  auto p = out;

  p = cpydig2(static_cast<uint32_t>(ymd.day()), p);
  *p++ = '/';
  p = std::ranges::copy(MONTH[static_cast<uint32_t>(ymd.month()) - 1], p).out;
  *p++ = '/';
  p = cpydig4(as_unsigned(static_cast<int>(ymd.year())), p);
  *p++ = ':';

  auto hms = std::chrono::hh_mm_ss{lt - days};

  p = cpydig2(static_cast<uint32_t>(hms.hours().count()), p);
  *p++ = ':';
  p = cpydig2(static_cast<uint32_t>(hms.minutes().count()), p);
  *p++ = ':';
  p = cpydig2(static_cast<uint32_t>(hms.seconds().count()), p);
  *p++ = ' ';

  auto sys_info = zt.get_info();
  auto gmtoff =
    std::chrono::floor<std::chrono::minutes>(sys_info.offset).count();
  if (gmtoff >= 0) {
    *p++ = '+';
  } else {
    *p++ = '-';
    gmtoff = -gmtoff;
  }

  p = cpydig2(static_cast<uint32_t>(gmtoff / 60), p);
  p = cpydig2(static_cast<uint32_t>(gmtoff % 60), p);

  *p = '\0';

  return {out, p};
}

std::string_view
format_http_date(char *out, const std::chrono::system_clock::time_point &tp) {
  auto t = std::chrono::floor<std::chrono::seconds>(tp);
  auto days = std::chrono::floor<std::chrono::days>(t);
  auto ymd = std::chrono::year_month_day{days};
  auto weekday = std::chrono::weekday{ymd};

  auto p = out;

  p = std::ranges::copy(WEEKDAY[weekday.c_encoding()], p).out;
  *p++ = ',';
  *p++ = ' ';
  p = cpydig2(static_cast<uint32_t>(ymd.day()), p);
  *p++ = ' ';
  p = std::ranges::copy(MONTH[static_cast<uint32_t>(ymd.month()) - 1], p).out;
  *p++ = ' ';
  p = cpydig4(as_unsigned(static_cast<int>(ymd.year())), p);
  *p++ = ' ';

  auto hms = std::chrono::hh_mm_ss{t - days};

  p = cpydig2(static_cast<uint32_t>(hms.hours().count()), p);
  *p++ = ':';
  p = cpydig2(static_cast<uint32_t>(hms.minutes().count()), p);
  *p++ = ':';
  p = cpydig2(static_cast<uint32_t>(hms.seconds().count()), p);
  p = std::ranges::copy(" GMT"sv, p).out;

  *p = '\0';

  return {out, p};
}
#else // !defined(HAVE_STD_CHRONO_TIME_ZONE)
namespace {
char *iso8601_date(char *out, const std::chrono::system_clock::time_point &tp) {
  auto ms = std::chrono::floor<std::chrono::milliseconds>(tp.time_since_epoch())
              .count();
  time_t sec = ms / 1000;

  tm tms;
  if (localtime_r(&sec, &tms) == nullptr) {
    return out;
  }

  auto p = out;

  p = cpydig4(static_cast<uint32_t>(tms.tm_year + 1900), p);
  *p++ = '-';
  p = cpydig2(static_cast<uint32_t>(tms.tm_mon + 1), p);
  *p++ = '-';
  p = cpydig2(static_cast<uint32_t>(tms.tm_mday), p);
  *p++ = 'T';
  p = cpydig2(static_cast<uint32_t>(tms.tm_hour), p);
  *p++ = ':';
  p = cpydig2(static_cast<uint32_t>(tms.tm_min), p);
  *p++ = ':';
  p = cpydig2(static_cast<uint32_t>(tms.tm_sec), p);
  *p++ = '.';
  p = cpydig3(static_cast<uint32_t>(ms % 1000), p);

#  ifdef HAVE_STRUCT_TM_TM_GMTOFF
  auto gmtoff = tms.tm_gmtoff;
#  else  // !HAVE_STRUCT_TM_TM_GMTOFF
  auto gmtoff = nghttp2_timegm(&tms) - sec;
#  endif // !HAVE_STRUCT_TM_TM_GMTOFF
  if (gmtoff == 0) {
    *p++ = 'Z';
  } else {
    if (gmtoff > 0) {
      *p++ = '+';
    } else {
      *p++ = '-';
      gmtoff = -gmtoff;
    }
    p = cpydig2(static_cast<uint32_t>(gmtoff / 3600), p);
    *p++ = ':';
    p = cpydig2(static_cast<uint32_t>((gmtoff % 3600) / 60), p);
  }

  return p;
}
} // namespace

std::string_view
format_iso8601(char *out, const std::chrono::system_clock::time_point &tp) {
  auto p = iso8601_date(out, tp);
  *p = '\0';
  return std::string_view{out, p};
}

namespace {
char *iso8601_basic_date(char *out,
                         const std::chrono::system_clock::time_point &tp) {
  auto ms = std::chrono::floor<std::chrono::milliseconds>(tp.time_since_epoch())
              .count();
  time_t sec = ms / 1000;

  tm tms;
  if (localtime_r(&sec, &tms) == nullptr) {
    return out;
  }

  auto p = out;

  p = cpydig4(static_cast<uint32_t>(tms.tm_year + 1900), p);
  p = cpydig2(static_cast<uint32_t>(tms.tm_mon + 1), p);
  p = cpydig2(static_cast<uint32_t>(tms.tm_mday), p);
  *p++ = 'T';
  p = cpydig2(static_cast<uint32_t>(tms.tm_hour), p);
  p = cpydig2(static_cast<uint32_t>(tms.tm_min), p);
  p = cpydig2(static_cast<uint32_t>(tms.tm_sec), p);
  *p++ = '.';
  p = cpydig3(static_cast<uint32_t>(ms % 1000), p);

#  ifdef HAVE_STRUCT_TM_TM_GMTOFF
  auto gmtoff = tms.tm_gmtoff;
#  else  // !HAVE_STRUCT_TM_TM_GMTOFF
  auto gmtoff = nghttp2_timegm(&tms) - sec;
#  endif // !HAVE_STRUCT_TM_TM_GMTOFF
  if (gmtoff == 0) {
    *p++ = 'Z';
  } else {
    if (gmtoff > 0) {
      *p++ = '+';
    } else {
      *p++ = '-';
      gmtoff = -gmtoff;
    }
    p = cpydig2(static_cast<uint32_t>(gmtoff / 3600), p);
    p = cpydig2(static_cast<uint32_t>((gmtoff % 3600) / 60), p);
  }

  return p;
}
} // namespace

std::string_view
format_iso8601_basic(char *out,
                     const std::chrono::system_clock::time_point &tp) {
  auto p = iso8601_basic_date(out, tp);
  *p = '\0';
  return {out, p};
}

namespace {
char *common_log_date(char *out,
                      const std::chrono::system_clock::time_point &tp) {
  time_t t =
    std::chrono::floor<std::chrono::seconds>(tp.time_since_epoch()).count();
  struct tm tms;

  if (localtime_r(&t, &tms) == nullptr) {
    return out;
  }

  auto p = out;

  p = cpydig2(static_cast<uint32_t>(tms.tm_mday), p);
  *p++ = '/';
  p = std::ranges::copy(MONTH[static_cast<size_t>(tms.tm_mon)], p).out;
  *p++ = '/';
  p = cpydig4(static_cast<uint32_t>(tms.tm_year + 1900), p);
  *p++ = ':';
  p = cpydig2(static_cast<uint32_t>(tms.tm_hour), p);
  *p++ = ':';
  p = cpydig2(static_cast<uint32_t>(tms.tm_min), p);
  *p++ = ':';
  p = cpydig2(static_cast<uint32_t>(tms.tm_sec), p);
  *p++ = ' ';

#  ifdef HAVE_STRUCT_TM_TM_GMTOFF
  auto gmtoff = tms.tm_gmtoff;
#  else  // !HAVE_STRUCT_TM_TM_GMTOFF
  auto gmtoff = nghttp2_timegm(&tms) - t;
#  endif // !HAVE_STRUCT_TM_TM_GMTOFF
  if (gmtoff >= 0) {
    *p++ = '+';
  } else {
    *p++ = '-';
    gmtoff = -gmtoff;
  }

  p = cpydig2(static_cast<uint32_t>(gmtoff / 3600), p);
  p = cpydig2(static_cast<uint32_t>((gmtoff % 3600) / 60), p);

  return p;
}
} // namespace

std::string_view
format_common_log(char *out, const std::chrono::system_clock::time_point &tp) {
  auto p = common_log_date(out, tp);
  *p = '\0';
  return {out, p};
}

namespace {
char *http_date(char *out, const std::chrono::system_clock::time_point &tp) {
  time_t t =
    std::chrono::floor<std::chrono::seconds>(tp.time_since_epoch()).count();
  struct tm tms;

  if (gmtime_r(&t, &tms) == nullptr) {
    return out;
  }

  auto p = out;

  p = std::ranges::copy(WEEKDAY[static_cast<size_t>(tms.tm_wday)], p).out;
  *p++ = ',';
  *p++ = ' ';
  p = cpydig2(static_cast<uint32_t>(tms.tm_mday), p);
  *p++ = ' ';
  p = std::ranges::copy(MONTH[static_cast<size_t>(tms.tm_mon)], p).out;
  *p++ = ' ';
  p = cpydig4(static_cast<uint32_t>(tms.tm_year + 1900), p);
  *p++ = ' ';
  p = cpydig2(static_cast<uint32_t>(tms.tm_hour), p);
  *p++ = ':';
  p = cpydig2(static_cast<uint32_t>(tms.tm_min), p);
  *p++ = ':';
  p = cpydig2(static_cast<uint32_t>(tms.tm_sec), p);
  p = std::ranges::copy(" GMT"sv, p).out;

  return p;
}
} // namespace

std::string_view
format_http_date(char *out, const std::chrono::system_clock::time_point &tp) {
  auto p = http_date(out, tp);
  *p = '\0';
  return {out, p};
}
#endif   // !defined(HAVE_STD_CHRONO_TIME_ZONE)

time_t parse_http_date(const std::string_view &s) {
  tm tm{};
#ifdef _WIN32
  // there is no strptime - use std::get_time
  std::stringstream sstr(s.data());
  sstr >> std::get_time(&tm, "%a, %d %b %Y %H:%M:%S GMT");
  if (sstr.fail()) {
    return 0;
  }
#else  // !_WIN32
  char *r = strptime(s.data(), "%a, %d %b %Y %H:%M:%S GMT", &tm);
  if (r == 0) {
    return 0;
  }
#endif // !_WIN32
  return nghttp2_timegm_without_yday(&tm);
}

time_t parse_openssl_asn1_time_print(const std::string_view &s) {
  tm tm{};
  auto r = strptime(s.data(), "%b %d %H:%M:%S %Y GMT", &tm);
  if (r == nullptr) {
    return 0;
  }
  return nghttp2_timegm_without_yday(&tm);
}

void to_token68(std::string &base64str) {
  for (auto it = base64str.begin(); it != base64str.end(); ++it) {
    switch (*it) {
    case '+':
      *it = '-';
      break;
    case '/':
      *it = '_';
      break;
    case '=':
      base64str.erase(it, base64str.end());
      return;
    }
  }
}

std::string_view to_base64(BlockAllocator &balloc,
                           const std::string_view &token68str) {
  // At most 3 padding '='
  auto len = token68str.size() + 3;
  auto iov = make_byte_ref(balloc, len + 1);

  auto p =
    std::ranges::transform(token68str, std::ranges::begin(iov), [](char c) {
      switch (c) {
      case '-':
        return '+';
      case '_':
        return '/';
      default:
        return c;
      }
    }).out;

  auto rem = token68str.size() & 0x3;
  if (rem) {
    p = std::ranges::fill_n(p, as_signed(4 - rem), '=');
  }

  *p = '\0';

  return as_string_view(std::ranges::begin(iov), p);
}

namespace {
// Calculates Damerau–Levenshtein distance between c-string a and b
// with given costs.  swapcost, subcost, addcost and delcost are cost
// to swap 2 adjacent characters, substitute characters, add character
// and delete character respectively.
uint32_t levenshtein(const std::string_view &a, const std::string_view &b,
                     uint32_t swapcost, uint32_t subcost, uint32_t addcost,
                     uint32_t delcost) {
  auto dp =
    std::vector<std::vector<uint32_t>>(3, std::vector<uint32_t>(b.size() + 1));
  for (uint32_t i = 0; i <= static_cast<uint32_t>(b.size()); ++i) {
    dp[1][i] = i * addcost;
  }
  for (uint32_t i = 1; i <= static_cast<uint32_t>(a.size()); ++i) {
    dp[0][0] = i * delcost;
    for (uint32_t j = 1; j <= static_cast<uint32_t>(b.size()); ++j) {
      dp[0][j] = dp[1][j - 1] + (a[i - 1] == b[j - 1] ? 0 : subcost);
      if (i >= 2 && j >= 2 && a[i - 1] != b[j - 1] && a[i - 2] == b[j - 1] &&
          a[i - 1] == b[j - 2]) {
        dp[0][j] = std::min(dp[0][j], dp[2][j - 2] + swapcost);
      }
      dp[0][j] = std::min(dp[0][j],
                          std::min(dp[1][j] + delcost, dp[0][j - 1] + addcost));
    }
    std::ranges::rotate(dp, std::ranges::begin(dp) + 2);
  }
  return dp[1][b.size()];
}
} // namespace

void show_candidates(const char *unkopt, const option *options) {
  for (; *unkopt == '-'; ++unkopt)
    ;
  if (*unkopt == '\0') {
    return;
  }
  auto unkoptend = unkopt;
  for (; *unkoptend && *unkoptend != '='; ++unkoptend)
    ;
  auto unkoptlen = unkoptend - unkopt;
  if (unkoptlen == 0) {
    return;
  }
  int prefix_match = 0;
  auto cands = std::vector<std::pair<uint32_t, std::string_view>>();
  for (size_t i = 0; options[i].name != nullptr; ++i) {
    auto opt = std::string_view{options[i].name};
    auto unk = std::string_view{unkopt, static_cast<size_t>(unkoptlen)};

    // Use cost 0 for prefix match
    if (istarts_with(opt, unk)) {
      if (opt.size() == unk.size()) {
        // Exact match, then we don't show any candidates.
        return;
      }
      ++prefix_match;
      cands.emplace_back(0, opt);
      continue;
    }
    // Use cost 0 for suffix match, but match at least 3 characters
    if (unk.size() >= 3 && iends_with(opt, unk)) {
      cands.emplace_back(0, options[i].name);
      continue;
    }
    // cost values are borrowed from git, help.c.
    auto sim = levenshtein(unk, opt, 0, 2, 1, 3);
    cands.emplace_back(sim, options[i].name);
  }
  if (prefix_match == 1 || cands.empty()) {
    return;
  }
  std::ranges::sort(cands);
  auto threshold = cands[0].first;
  // threshold value is a magic value.
  if (threshold > 6) {
    return;
  }
  std::cerr << "\nDid you mean:\n";
  for (auto &item : cands) {
    if (item.first > threshold) {
      break;
    }
    std::cerr << "\t--" << item.second << "\n";
  }
}

bool has_uri_field(const urlparse_url &u, urlparse_url_fields field) {
  return u.field_set & (1 << field);
}

bool fieldeq(const char *uri1, const urlparse_url &u1, const char *uri2,
             const urlparse_url &u2, urlparse_url_fields field) {
  if (!has_uri_field(u1, field)) {
    if (!has_uri_field(u2, field)) {
      return true;
    } else {
      return false;
    }
  } else if (!has_uri_field(u2, field)) {
    return false;
  }
  if (u1.field_data[field].len != u2.field_data[field].len) {
    return false;
  }
  return memcmp(uri1 + u1.field_data[field].off,
                uri2 + u2.field_data[field].off, u1.field_data[field].len) == 0;
}

bool fieldeq(const char *uri, const urlparse_url &u, urlparse_url_fields field,
             const char *t) {
  return fieldeq(uri, u, field, std::string_view{t});
}

bool fieldeq(const char *uri, const urlparse_url &u, urlparse_url_fields field,
             const std::string_view &t) {
  if (!has_uri_field(u, field)) {
    return t.empty();
  }
  auto &f = u.field_data[field];
  return std::string_view{uri + f.off, f.len} == t;
}

std::string_view get_uri_field(const char *uri, const urlparse_url &u,
                               urlparse_url_fields field) {
  if (!util::has_uri_field(u, field)) {
    return ""sv;
  }

  return std::string_view{uri + u.field_data[field].off,
                          u.field_data[field].len};
}

uint16_t get_default_port(const char *uri, const urlparse_url &u) {
  if (util::fieldeq(uri, u, URLPARSE_SCHEMA, "https")) {
    return 443;
  } else if (util::fieldeq(uri, u, URLPARSE_SCHEMA, "http")) {
    return 80;
  } else {
    return 443;
  }
}

bool porteq(const char *uri1, const urlparse_url &u1, const char *uri2,
            const urlparse_url &u2) {
  uint16_t port1, port2;
  port1 = util::has_uri_field(u1, URLPARSE_PORT) ? u1.port
                                                 : get_default_port(uri1, u1);
  port2 = util::has_uri_field(u2, URLPARSE_PORT) ? u2.port
                                                 : get_default_port(uri2, u2);
  return port1 == port2;
}

void write_uri_field(std::ostream &o, const char *uri, const urlparse_url &u,
                     urlparse_url_fields field) {
  if (util::has_uri_field(u, field)) {
    o.write(uri + u.field_data[field].off, u.field_data[field].len);
  }
}

bool numeric_host(const char *hostname) {
  return numeric_host(hostname, AF_INET) || numeric_host(hostname, AF_INET6);
}

bool numeric_host(const char *hostname, int family) {
  int rv;
  std::array<uint8_t, sizeof(struct in6_addr)> dst;

  rv = nghttp2_inet_pton(family, hostname, dst.data());

  return rv == 1;
}

std::string numeric_name(const struct sockaddr *sa, socklen_t salen) {
  std::array<char, NI_MAXHOST> host;
  auto rv = getnameinfo(sa, salen, host.data(), host.size(), nullptr, 0,
                        NI_NUMERICHOST);
  if (rv != 0) {
    return "unknown";
  }
  return host.data();
}

std::string to_numeric_addr(const Address *addr) {
  return to_numeric_addr(&addr->su.sa, addr->len);
}

std::string to_numeric_addr(const struct sockaddr *sa, socklen_t salen) {
  auto family = sa->sa_family;
#ifndef _WIN32
  if (family == AF_UNIX) {
    return reinterpret_cast<const sockaddr_un *>(sa)->sun_path;
  }
#endif // !_WIN32

  std::array<char, NI_MAXHOST> hostbuf;
  std::array<char, NI_MAXSERV> servbuf;

  auto rv =
    getnameinfo(sa, salen, hostbuf.data(), hostbuf.size(), servbuf.data(),
                servbuf.size(), NI_NUMERICHOST | NI_NUMERICSERV);
  if (rv != 0) {
    return "unknown";
  }

  auto host = std::string_view{hostbuf.data()};
  auto serv = std::string_view{servbuf.data()};

  std::string s;
  char *p;

  if (family == AF_INET6) {
    s.resize(host.size() + serv.size() + 2 + 1);
    p = &s[0];
    *p++ = '[';
    p = std::ranges::copy(host, p).out;
    *p++ = ']';
  } else {
    s.resize(host.size() + serv.size() + 1);
    p = &s[0];
    p = std::ranges::copy(host, p).out;
  }

  *p++ = ':';
  std::ranges::copy(serv, p);

  return s;
}

void set_port(Address &addr, uint16_t port) {
  switch (addr.su.storage.ss_family) {
  case AF_INET:
    addr.su.in.sin_port = htons(port);
    break;
  case AF_INET6:
    addr.su.in6.sin6_port = htons(port);
    break;
  }
}

uint16_t get_port(const sockaddr_union *su) {
  switch (su->storage.ss_family) {
  case AF_INET:
    return ntohs(su->in.sin_port);
  case AF_INET6:
    return ntohs(su->in6.sin6_port);
  default:
    return 0;
  }
}

bool quic_prohibited_port(uint16_t port) {
  switch (port) {
  case 1900:
  case 5353:
  case 11211:
  case 20800:
  case 27015:
    return true;
  default:
    return port < 1024;
  }
}

std::string ascii_dump(const uint8_t *data, size_t len) {
  std::string res;

  for (size_t i = 0; i < len; ++i) {
    auto c = data[i];

    if (c >= 0x20 && c < 0x7f) {
      res += as_signed(c);
    } else {
      res += '.';
    }
  }

  return res;
}

char *get_exec_path(size_t argc, char **const argv, const char *cwd) {
  if (argc == 0 || cwd == nullptr) {
    return nullptr;
  }

  auto argv0 = argv[0];
  auto len = strlen(argv0);

  char *path;

  if (argv0[0] == '/') {
    path = static_cast<char *>(malloc(len + 1));
    if (path == nullptr) {
      return nullptr;
    }
    memcpy(path, argv0, len + 1);
  } else {
    auto cwdlen = strlen(cwd);
    path = static_cast<char *>(malloc(len + 1 + cwdlen + 1));
    if (path == nullptr) {
      return nullptr;
    }
    memcpy(path, cwd, cwdlen);
    path[cwdlen] = '/';
    memcpy(path + cwdlen + 1, argv0, len + 1);
  }

  return path;
}

bool check_path(const std::string &path) {
  // We don't like '\' in path.
  return !path.empty() && path[0] == '/' &&
         path.find('\\') == std::string::npos &&
         path.find("/../") == std::string::npos &&
         path.find("/./") == std::string::npos &&
         !util::ends_with(path, "/.."sv) && !util::ends_with(path, "/."sv);
}

int64_t to_time64(const timeval &tv) {
  return tv.tv_sec * 1000000 + tv.tv_usec;
}

bool check_h2_is_selected(const std::string_view &proto) {
  return NGHTTP2_H2 == proto;
}

namespace {
bool select_proto(const unsigned char **out, unsigned char *outlen,
                  const unsigned char *in, unsigned int inlen,
                  const std::string_view &key) {
  for (auto p = in, end = in + inlen; p + key.size() <= end; p += *p + 1) {
    if (std::ranges::equal(key, as_string_view(p, key.size()))) {
      *out = p + 1;
      *outlen = *p;
      return true;
    }
  }
  return false;
}
} // namespace

bool select_h2(const unsigned char **out, unsigned char *outlen,
               const unsigned char *in, unsigned int inlen) {
  return select_proto(out, outlen, in, inlen, NGHTTP2_H2_ALPN);
}

bool select_protocol(const unsigned char **out, unsigned char *outlen,
                     const unsigned char *in, unsigned int inlen,
                     std::vector<std::string> proto_list) {
  for (const auto &proto : proto_list) {
    if (select_proto(out, outlen, in, inlen, proto)) {
      return true;
    }
  }

  return false;
}

std::vector<std::string_view> split_str(const std::string_view &s, char delim) {
  size_t len = 1;
  auto last = std::ranges::end(s);
  std::string_view::const_iterator d;
  for (auto first = std::ranges::begin(s);
       (d = std::ranges::find(first, last, delim)) != last;
       ++len, first = d + 1)
    ;

  auto list = std::vector<std::string_view>(len);

  len = 0;
  for (auto first = std::ranges::begin(s);; ++len) {
    auto stop = std::ranges::find(first, last, delim);
    list[len] = std::string_view{first, stop};
    if (stop == last) {
      break;
    }
    first = stop + 1;
  }
  return list;
}

std::vector<std::string_view> split_str(const std::string_view &s, char delim,
                                        size_t n) {
  if (n == 0) {
    return split_str(s, delim);
  }

  if (n == 1) {
    return {s};
  }

  size_t len = 1;
  auto last = std::ranges::end(s);
  std::string_view::const_iterator d;
  for (auto first = std::ranges::begin(s);
       len < n && (d = std::ranges::find(first, last, delim)) != last;
       ++len, first = d + 1)
    ;

  auto list = std::vector<std::string_view>(len);

  len = 0;
  for (auto first = std::ranges::begin(s);; ++len) {
    if (len == n - 1) {
      list[len] = std::string_view{first, last};
      break;
    }

    auto stop = std::ranges::find(first, last, delim);
    list[len] = std::string_view{first, stop};
    if (stop == last) {
      break;
    }
    first = stop + 1;
  }
  return list;
}

std::vector<std::string> parse_config_str_list(const std::string_view &s,
                                               char delim) {
  auto sublist = split_str(s, delim);
  auto res = std::vector<std::string>();
  res.reserve(sublist.size());
  for (const auto &s : sublist) {
    res.emplace_back(std::ranges::begin(s), std::ranges::end(s));
  }
  return res;
}

int make_socket_closeonexec(int fd) {
#ifdef _WIN32
  (void)fd;
  return 0;
#else  // !_WIN32
  int flags;
  int rv;
  while ((flags = fcntl(fd, F_GETFD)) == -1 && errno == EINTR)
    ;
  while ((rv = fcntl(fd, F_SETFD, flags | FD_CLOEXEC)) == -1 && errno == EINTR)
    ;
  return rv;
#endif // !_WIN32
}

int make_socket_nonblocking(int fd) {
  int rv;

#ifdef _WIN32
  u_long mode = 1;

  rv = ioctlsocket(fd, FIONBIO, &mode);
#else  // !_WIN32
  int flags;
  while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR)
    ;
  while ((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
    ;
#endif // !_WIN32

  return rv;
}

int make_socket_nodelay(int fd) {
  int val = 1;
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char *>(&val),
                 sizeof(val)) == -1) {
    return -1;
  }
  return 0;
}

int create_nonblock_socket(int family) {
#ifdef SOCK_NONBLOCK
  auto fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

  if (fd == -1) {
    return -1;
  }
#else  // !SOCK_NONBLOCK
  auto fd = socket(family, SOCK_STREAM, 0);

  if (fd == -1) {
    return -1;
  }

  make_socket_nonblocking(fd);
  make_socket_closeonexec(fd);
#endif // !SOCK_NONBLOCK

  if (family == AF_INET || family == AF_INET6) {
    make_socket_nodelay(fd);
  }

  return fd;
}

int create_nonblock_udp_socket(int family) {
#ifdef SOCK_NONBLOCK
  auto fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

  if (fd == -1) {
    return -1;
  }
#else  // !SOCK_NONBLOCK
  auto fd = socket(family, SOCK_DGRAM, 0);

  if (fd == -1) {
    return -1;
  }

  make_socket_nonblocking(fd);
  make_socket_closeonexec(fd);
#endif // !SOCK_NONBLOCK

  return fd;
}

int bind_any_addr_udp(int fd, int family) {
  addrinfo hints{};
  addrinfo *res, *rp;
  int rv;

  hints.ai_family = family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  rv = getaddrinfo(nullptr, "0", &hints, &res);
  if (rv != 0) {
    return -1;
  }

  for (rp = res; rp; rp = rp->ai_next) {
    if (bind(fd, rp->ai_addr, rp->ai_addrlen) != -1) {
      break;
    }
  }

  freeaddrinfo(res);

  if (!rp) {
    return -1;
  }

  return 0;
}

bool check_socket_connected(int fd) {
  int error;
  socklen_t len = sizeof(error);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len) != 0) {
    return false;
  }

  return error == 0;
}

int get_socket_error(int fd) {
  int error;
  socklen_t len = sizeof(error);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len) != 0) {
    return -1;
  }

  return error;
}

bool ipv6_numeric_addr(const char *host) {
  uint8_t dst[16];
  return nghttp2_inet_pton(AF_INET6, host, dst) == 1;
}

namespace {
std::optional<std::pair<int64_t, std::string_view>>
parse_uint_digits(const std::string_view &s) {
  if (s.empty()) {
    return {};
  }

  constexpr int64_t max = std::numeric_limits<int64_t>::max();

  int64_t n = 0;
  size_t i = 0;

  for (auto c : s) {
    if (!is_digit(c)) {
      break;
    }

    if (n > max / 10) {
      return {};
    }

    n *= 10;

    if (n > max - (c - '0')) {
      return {};
    }

    n += c - '0';

    ++i;
  }

  if (i == 0) {
    return {};
  }

  return std::pair{n, s.substr(i)};
}
} // namespace

std::optional<int64_t> parse_uint_with_unit(const std::string_view &s) {
  auto r = parse_uint_digits(s);
  if (!r) {
    return {};
  }

  auto [n, rest] = *r;

  if (rest.empty()) {
    return n;
  }

  if (rest.size() != 1) {
    return {};
  }

  int mul = 1;
  switch (rest[0]) {
  case 'K':
  case 'k':
    mul = 1 << 10;
    break;
  case 'M':
  case 'm':
    mul = 1 << 20;
    break;
  case 'G':
  case 'g':
    mul = 1 << 30;
    break;
  default:
    return {};
  }

  constexpr int64_t max = std::numeric_limits<int64_t>::max();
  if (n > max / mul) {
    return {};
  }

  return n * mul;
}

std::optional<int64_t> parse_uint(const std::string_view &s) {
  auto r = parse_uint_digits(s);
  if (!r || !(*r).second.empty()) {
    return {};
  }

  return (*r).first;
}

std::optional<double> parse_duration_with_unit(const std::string_view &s) {
  constexpr auto max = std::numeric_limits<int64_t>::max();

  auto r = parse_uint_digits(s);
  if (!r) {
    return {};
  }

  auto [n, rest] = *r;

  if (rest.empty()) {
    return static_cast<double>(n);
  }

  switch (rest[0]) {
  case 'S':
  case 's':
    // seconds
    if (rest.size() != 1) {
      return {};
    }

    return static_cast<double>(n);
  case 'M':
  case 'm':
    if (rest.size() == 1) {
      // minutes
      if (n > max / 60) {
        return {};
      }

      return static_cast<double>(n) * 60;
    }

    if (rest.size() != 2 || (rest[1] != 's' && rest[1] != 'S')) {
      return {};
    }

    // milliseconds
    return static_cast<double>(n) / 1000.;
  case 'H':
  case 'h':
    // hours
    if (rest.size() != 1) {
      return {};
    }

    if (n > max / 3600) {
      return {};
    }

    return static_cast<double>(n) * 3600;
  default:
    return {};
  }
}

std::string duration_str(double t) {
  if (t == 0.) {
    return "0";
  }
  auto frac = static_cast<uint64_t>(t * 1000) % 1000;
  if (frac > 0) {
    return utos(static_cast<uint64_t>(t * 1000)) + "ms";
  }
  auto v = static_cast<uint64_t>(t);
  if (v % 60) {
    return utos(v) + "s";
  }
  v /= 60;
  if (v % 60) {
    return utos(v) + "m";
  }
  v /= 60;
  return utos(v) + "h";
}

std::string format_duration(const std::chrono::microseconds &u) {
  auto unit = "us"sv;
  int d = 0;
  auto t = as_unsigned(u.count());
  if (t >= 1000000) {
    d = 1000000;
    unit = "s"sv;
  } else if (t >= 1000) {
    d = 1000;
    unit = "ms"sv;
  } else {
    return utos(t).append(unit);
  }
  return dtos(static_cast<double>(t) / d).append(unit);
}

std::string format_duration(double t) {
  auto unit = "us"sv;
  if (t >= 1.) {
    unit = "s"sv;
  } else if (t >= 0.001) {
    t *= 1000.;
    unit = "ms"sv;
  } else {
    t *= 1000000.;
    return utos(static_cast<uint64_t>(t)).append(unit);
  }
  return dtos(t).append(unit);
}

std::string dtos(double n) {
  auto m = as_unsigned(llround(100. * n));
  auto f = utos(m % 100);
  return utos(m / 100) + "." + (f.size() == 1 ? "0" : "") + f;
}

std::string_view make_http_hostport(BlockAllocator &balloc,
                                    const std::string_view &host,
                                    uint16_t port) {
  auto iov = make_byte_ref(balloc, host.size() + 2 + 1 + 5 + 1);
  return make_http_hostport(host, port, std::ranges::begin(iov));
}

std::string_view make_hostport(BlockAllocator &balloc,
                               const std::string_view &host, uint16_t port) {
  auto iov = make_byte_ref(balloc, host.size() + 2 + 1 + 5 + 1);
  return make_hostport(host, port, std::ranges::begin(iov));
}

namespace {
uint8_t *hexdump_addr(uint8_t *dest, size_t addr) {
  // Lower 32 bits are displayed.
  return format_hex(static_cast<uint32_t>(addr), dest);
}
} // namespace

namespace {
uint8_t *hexdump_ascii(uint8_t *dest, const uint8_t *data, size_t datalen) {
  *dest++ = '|';

  for (size_t i = 0; i < datalen; ++i) {
    if (0x20 <= data[i] && data[i] <= 0x7e) {
      *dest++ = data[i];
    } else {
      *dest++ = '.';
    }
  }

  *dest++ = '|';

  return dest;
}
} // namespace

namespace {
uint8_t *hexdump8(uint8_t *dest, const uint8_t *data, size_t datalen) {
  size_t i;

  for (i = 0; i < datalen; ++i) {
    dest = format_hex(data[i], dest);
    *dest++ = ' ';
  }

  for (; i < 8; ++i) {
    *dest++ = ' ';
    *dest++ = ' ';
    *dest++ = ' ';
  }

  return dest;
}
} // namespace

namespace {
uint8_t *hexdump16(uint8_t *dest, const uint8_t *data, size_t datalen) {
  if (datalen > 8) {
    dest = hexdump8(dest, data, 8);
    *dest++ = ' ';
    dest = hexdump8(dest, data + 8, datalen - 8);
    *dest++ = ' ';
  } else {
    dest = hexdump8(dest, data, datalen);
    *dest++ = ' ';
    dest = hexdump8(dest, nullptr, 0);
    *dest++ = ' ';
  }

  return dest;
}
} // namespace

namespace {
uint8_t *hexdump_line(uint8_t *dest, const uint8_t *data, size_t datalen,
                      size_t addr) {
  dest = hexdump_addr(dest, addr);
  *dest++ = ' ';
  *dest++ = ' ';

  dest = hexdump16(dest, data, datalen);

  return hexdump_ascii(dest, data, datalen);
}
} // namespace

namespace {
int hexdump_write(int fd, const uint8_t *data, size_t datalen) {
  ssize_t nwrite;

  for (; (nwrite = write(fd, data, datalen)) == -1 && errno == EINTR;)
    ;
  if (nwrite == -1) {
    return -1;
  }

  return 0;
}
} // namespace

int hexdump(FILE *out, const void *data, size_t datalen) {
  if (datalen == 0) {
    return 0;
  }

  // min_space is the additional minimum space that the buffer must
  // accept, which is the size of a single full line output + one
  // repeat line marker ("*\n").  If the remaining buffer size is less
  // than that, flush the buffer and reset.
  constexpr size_t min_space = 79 + 2;

  auto fd = fileno(out);
  std::array<uint8_t, 4096> buf;
  auto last = buf.data();
  auto in = reinterpret_cast<const uint8_t *>(data);
  auto repeated = false;

  for (size_t offset = 0; offset < datalen; offset += 16) {
    auto n = datalen - offset;
    auto s = in + offset;

    if (n >= 16) {
      n = 16;

      if (offset > 0) {
        if (std::ranges::equal(s - 16, s, s, s + 16)) {
          if (repeated) {
            continue;
          }

          repeated = true;

          *last++ = '*';
          *last++ = '\n';

          continue;
        }

        repeated = false;
      }
    }

    last = hexdump_line(last, s, n, offset);
    *last++ = '\n';

    auto len = static_cast<size_t>(last - buf.data());
    if (len + min_space > buf.size()) {
      if (hexdump_write(fd, buf.data(), len) != 0) {
        return -1;
      }

      last = buf.data();
    }
  }

  last = hexdump_addr(last, datalen);
  *last++ = '\n';

  auto len = static_cast<size_t>(last - buf.data());
  if (len) {
    return hexdump_write(fd, buf.data(), len);
  }

  return 0;
}

void put_uint16be(uint8_t *buf, uint16_t n) {
  uint16_t x = htons(n);
  memcpy(buf, &x, sizeof(uint16_t));
}

void put_uint32be(uint8_t *buf, uint32_t n) {
  uint32_t x = htonl(n);
  memcpy(buf, &x, sizeof(uint32_t));
}

uint16_t get_uint16(const uint8_t *data) {
  uint16_t n;
  memcpy(&n, data, sizeof(uint16_t));
  return ntohs(n);
}

uint32_t get_uint32(const uint8_t *data) {
  uint32_t n;
  memcpy(&n, data, sizeof(uint32_t));
  return ntohl(n);
}

uint64_t get_uint64(const uint8_t *data) {
  uint64_t n = 0;
  n += static_cast<uint64_t>(data[0]) << 56;
  n += static_cast<uint64_t>(data[1]) << 48;
  n += static_cast<uint64_t>(data[2]) << 40;
  n += static_cast<uint64_t>(data[3]) << 32;
  n += static_cast<uint64_t>(data[4]) << 24;
  n += static_cast<uint64_t>(data[5]) << 16;
  n += static_cast<uint64_t>(data[6]) << 8;
  n += data[7];
  return n;
}

int read_mime_types(std::unordered_map<std::string, std::string> &res,
                    const char *filename) {
  std::ifstream infile(filename);
  if (!infile) {
    return -1;
  }

  auto delim_pred = [](char c) { return c == ' ' || c == '\t'; };

  std::string line;
  while (std::getline(infile, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }

    auto type_end = std::ranges::find_if(line, delim_pred);
    if (type_end == std::ranges::begin(line)) {
      continue;
    }

    auto ext_end = type_end;
    for (;;) {
      auto ext_start =
        std::ranges::find_if_not(ext_end, std::ranges::end(line), delim_pred);
      if (ext_start == std::ranges::end(line)) {
        break;
      }
      ext_end =
        std::ranges::find_if(ext_start, std::ranges::end(line), delim_pred);
      res.emplace(std::string(ext_start, ext_end),
                  std::string(std::ranges::begin(line), type_end));
    }
  }

  return 0;
}

// Returns x**y
double int_pow(double x, size_t y) {
  auto res = 1.;
  for (; y; --y) {
    res *= x;
  }
  return res;
}

uint32_t hash32(const std::string_view &s) {
  /* 32 bit FNV-1a: http://isthe.com/chongo/tech/comp/fnv/ */
  uint32_t h = 2166136261u;
  size_t i;

  for (i = 0; i < s.size(); ++i) {
    h ^= static_cast<uint8_t>(s[i]);
    h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
  }

  return h;
}

namespace {
int message_digest(uint8_t *res, const EVP_MD *meth,
                   const std::string_view &s) {
  int rv;

  auto ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    return -1;
  }

  auto ctx_deleter = defer(EVP_MD_CTX_free, ctx);

  rv = EVP_DigestInit_ex(ctx, meth, nullptr);
  if (rv != 1) {
    return -1;
  }

  rv = EVP_DigestUpdate(ctx, s.data(), s.size());
  if (rv != 1) {
    return -1;
  }

  auto mdlen = static_cast<unsigned int>(EVP_MD_size(meth));

  rv = EVP_DigestFinal_ex(ctx, res, &mdlen);
  if (rv != 1) {
    return -1;
  }

  return 0;
}
} // namespace

int sha256(uint8_t *res, const std::string_view &s) {
  return message_digest(res, EVP_sha256(), s);
}

int sha1(uint8_t *res, const std::string_view &s) {
  return message_digest(res, EVP_sha1(), s);
}

std::string_view extract_host(const std::string_view &hostport) {
  if (hostport.empty()) {
    return ""sv;
  }

  if (hostport[0] == '[') {
    // assume this is IPv6 numeric address
    auto p = std::ranges::find(hostport, ']');
    if (p == std::ranges::end(hostport)) {
      return ""sv;
    }
    if (p + 1 < std::ranges::end(hostport) && *(p + 1) != ':') {
      return ""sv;
    }
    return std::string_view{std::ranges::begin(hostport), p + 1};
  }

  auto p = std::ranges::find(hostport, ':');
  if (p == std::ranges::begin(hostport)) {
    return ""sv;
  }
  return std::string_view{std::ranges::begin(hostport), p};
}

std::pair<std::string_view, std::string_view>
split_hostport(const std::string_view &hostport) {
  if (hostport.empty()) {
    return {};
  }
  if (hostport[0] == '[') {
    // assume this is IPv6 numeric address
    auto p = std::ranges::find(hostport, ']');
    if (p == std::ranges::end(hostport)) {
      return {};
    }
    if (p + 1 == std::ranges::end(hostport)) {
      return {std::string_view{std::ranges::begin(hostport) + 1, p}, {}};
    }
    if (*(p + 1) != ':' || p + 2 == std::ranges::end(hostport)) {
      return {};
    }
    return {std::string_view{std::ranges::begin(hostport) + 1, p},
            std::string_view{p + 2, std::ranges::end(hostport)}};
  }

  auto p = std::ranges::find(hostport, ':');
  if (p == std::ranges::begin(hostport)) {
    return {};
  }
  if (p == std::ranges::end(hostport)) {
    return {std::string_view{std::ranges::begin(hostport), p}, {}};
  }
  if (p + 1 == std::ranges::end(hostport)) {
    return {};
  }

  return {std::string_view{std::ranges::begin(hostport), p},
          std::string_view{p + 1, std::ranges::end(hostport)}};
}

std::mt19937 make_mt19937() {
  std::random_device rd;
  return std::mt19937(rd());
}

int daemonize(int nochdir, int noclose) {
#ifdef __APPLE__
  pid_t pid;
  pid = fork();
  if (pid == -1) {
    return -1;
  } else if (pid > 0) {
    _exit(EXIT_SUCCESS);
  }
  if (setsid() == -1) {
    return -1;
  }
  pid = fork();
  if (pid == -1) {
    return -1;
  } else if (pid > 0) {
    _exit(EXIT_SUCCESS);
  }
  if (nochdir == 0) {
    if (chdir("/") == -1) {
      return -1;
    }
  }
  if (noclose == 0) {
    if (freopen("/dev/null", "r", stdin) == nullptr) {
      return -1;
    }
    if (freopen("/dev/null", "w", stdout) == nullptr) {
      return -1;
    }
    if (freopen("/dev/null", "w", stderr) == nullptr) {
      return -1;
    }
  }
  return 0;
#else  // !__APPLE__
  return daemon(nochdir, noclose);
#endif // !__APPLE__
}

std::string_view rstrip(BlockAllocator &balloc, const std::string_view &s) {
  auto it = std::ranges::rbegin(s);
  for (; it != std::ranges::rend(s) && (*it == ' ' || *it == '\t'); ++it)
    ;

  auto len = as_unsigned(it - std::ranges::rbegin(s));
  if (len == 0) {
    return s;
  }

  return make_string_ref(balloc, std::string_view{s.data(), s.size() - len});
}

#ifdef ENABLE_HTTP3
int msghdr_get_local_addr(Address &dest, msghdr *msg, int family) {
  switch (family) {
  case AF_INET:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
        in_pktinfo pktinfo;
        memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));
        dest.len = sizeof(dest.su.in);
        auto &sa = dest.su.in;
        sa.sin_family = AF_INET;
        sa.sin_addr = pktinfo.ipi_addr;

        return 0;
      }
    }

    return -1;
  case AF_INET6:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
        in6_pktinfo pktinfo;
        memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));
        dest.len = sizeof(dest.su.in6);
        auto &sa = dest.su.in6;
        sa.sin6_family = AF_INET6;
        sa.sin6_addr = pktinfo.ipi6_addr;
        return 0;
      }
    }

    return -1;
  }

  return -1;
}

uint8_t msghdr_get_ecn(msghdr *msg, int family) {
  switch (family) {
  case AF_INET:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IP &&
#  ifdef __APPLE__
          cmsg->cmsg_type == IP_RECVTOS
#  else  // !__APPLE__
          cmsg->cmsg_type == IP_TOS
#  endif // !__APPLE__
          && cmsg->cmsg_len) {
        return *reinterpret_cast<uint8_t *>(CMSG_DATA(cmsg)) & IPTOS_ECN_MASK;
      }
    }

    return 0;
  case AF_INET6:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS &&
          cmsg->cmsg_len) {
        unsigned int tos;

        memcpy(&tos, CMSG_DATA(cmsg), sizeof(tos));

        return tos & IPTOS_ECN_MASK;
      }
    }

    return 0;
  }

  return 0;
}

size_t msghdr_get_udp_gro(msghdr *msg) {
  int gso_size = 0;

#  ifdef UDP_GRO
  for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
    if (cmsg->cmsg_level == SOL_UDP && cmsg->cmsg_type == UDP_GRO) {
      memcpy(&gso_size, CMSG_DATA(cmsg), sizeof(gso_size));

      break;
    }
  }
#  endif // UDP_GRO

  return static_cast<size_t>(gso_size);
}
#endif // ENABLE_HTTP3

} // namespace util

} // namespace nghttp2
