/*
 * nghttp2 - HTTP/2.0 C Library
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

#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>

#include "timegm.h"

namespace nghttp2 {

namespace util {

const char DEFAULT_STRIP_CHARSET[] = "\r\n\t ";

bool isAlpha(const char c)
{
  return ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z');
}

bool isDigit(const char c)
{
  return '0' <= c && c <= '9';
}

bool isHexDigit(const char c)
{
  return isDigit(c) || ('A' <= c && c <= 'F') || ('a' <= c && c <= 'f');
}

bool inRFC3986UnreservedChars(const char c)
{
  static const char unreserved[] = { '-', '.', '_', '~' };
  return isAlpha(c) || isDigit(c) ||
    std::find(&unreserved[0], &unreserved[4], c) != &unreserved[4];
}

std::string percentEncode(const unsigned char* target, size_t len)
{
  std::string dest;
  for(size_t i = 0; i < len; ++i) {
    if(inRFC3986UnreservedChars(target[i])) {
      dest += target[i];
    } else {
      char temp[4];
      snprintf(temp, sizeof(temp), "%%%02X", target[i]);
      dest.append(temp);
      //dest.append(fmt("%%%02X", target[i]));
    }
  }
  return dest;
}

std::string percentEncode(const std::string& target)
{
  return percentEncode(reinterpret_cast<const unsigned char*>(target.c_str()),
                       target.size());
}

std::string percentDecode
(std::string::const_iterator first, std::string::const_iterator last)
{
  std::string result;
  for(; first != last; ++first) {
    if(*first == '%') {
      if(first+1 != last && first+2 != last &&
         isHexDigit(*(first+1)) && isHexDigit(*(first+2))) {
        std::string numstr(first+1, first+3);
        result += strtol(numstr.c_str(), 0, 16);
        first += 2;
      } else {
        result += *first;
      }
    } else {
      result += *first;
    }
  }
  return result;
}

std::string http_date(time_t t)
{
  char buf[32];
  tm* tms = gmtime(&t); // returned struct is statically allocated.
  size_t r = strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", tms);
  return std::string(&buf[0], &buf[r]);
}

time_t parse_http_date(const std::string& s)
{
  tm tm;
  memset(&tm, 0, sizeof(tm));
  char* r = strptime(s.c_str(), "%a, %d %b %Y %H:%M:%S GMT", &tm);
  if(r == 0) {
    return 0;
  }
  return timegm(&tm);
}

bool startsWith(const std::string& a, const std::string& b)
{
  return startsWith(a.begin(), a.end(), b.begin(), b.end());
}

bool istartsWith(const std::string& a, const std::string& b)
{
  return istartsWith(a.begin(), a.end(), b.begin(), b.end());
}

namespace {
void streq_advance(const char **ap, const char **bp)
{
  for(; **ap && **bp && lowcase(**ap) == lowcase(**bp); ++*ap, ++*bp);
}
} // namespace

bool istartsWith(const char *a, const char* b)
{
  if(!a || !b) {
    return false;
  }
  streq_advance(&a, &b);
  return !*b;
}

bool endsWith(const std::string& a, const std::string& b)
{
  return endsWith(a.begin(), a.end(), b.begin(), b.end());
}

bool strieq(const std::string& a, const std::string& b)
{
  if(a.size() != b.size()) {
    return false;
  }
  for(size_t i = 0; i < a.size(); ++i) {
    if(lowcase(a[i]) != lowcase(b[i])) {
      return false;
    }
  }
  return true;
}

bool strieq(const char *a, const char *b)
{
  if(!a || !b) {
    return false;
  }
  for(; *a && *b && lowcase(*a) == lowcase(*b); ++a, ++b);
  return !*a && !*b;
}

bool strieq(const char *a, const uint8_t *b, size_t bn)
{
  if(!a || !b) {
    return false;
  }
  const uint8_t *blast = b + bn;
  for(; *a && b != blast && lowcase(*a) == lowcase(*b); ++a, ++b);
  return !*a && b == blast;
}

int strcompare(const char *a, const uint8_t *b, size_t bn)
{
  assert(a && b);
  const uint8_t *blast = b + bn;
  for(; *a && b != blast; ++a, ++b) {
    if(*a < *b) {
      return -1;
    } else if(*a > *b) {
      return 1;
    }
  }
  if(!*a && b == blast) {
    return 0;
  } else if(b == blast) {
    return 1;
  } else {
    return -1;
  }
}

bool strifind(const char *a, const char *b)
{
  if(!a || !b) {
    return false;
  }
  for(size_t i = 0; a[i]; ++i) {
    const char *ap = &a[i], *bp = b;
    for(; *ap && *bp && lowcase(*ap) == lowcase(*bp); ++ap, ++bp);
    if(!*bp) {
      return true;
    }
  }
  return false;
}

char upcase(char c)
{
  if('a' <= c && c <= 'z') {
    return c-'a'+'A';
  } else {
    return c;
  }
}

std::string format_hex(const unsigned char *s, size_t len)
{
  std::string res;
  for(size_t i = 0; i < len; ++i) {
    unsigned char c = s[i] >> 4;
    if(c > 9) {
      res += c - 10 + 'a';
    } else {
      res += c + '0';
    }
    c = s[i] & 0xf;
    if(c > 9) {
      res += c - 10 + 'a';
    } else {
      res += c + '0';
    }
  }
  return res;
}

void to_token68(std::string& base64str)
{
  for(auto i = std::begin(base64str); i != std::end(base64str); ++i) {
    switch(*i) {
    case '+':
      *i = '-';
      break;
    case '/':
      *i = '_';
      break;
    case '=':
      base64str.erase(i, std::end(base64str));
      return;
    }
  }
  return;
}

void to_base64(std::string& token68str)
{
  for(auto i = std::begin(token68str); i != std::end(token68str); ++i) {
    switch(*i) {
    case '-':
      *i = '+';
      break;
    case '_':
      *i = '/';
      break;
    }
  }
  if(token68str.size() & 0x3) {
    token68str.append(4 - (token68str.size() & 0x3), '=');
  }
  return;
}

void inp_strlower(std::string& s)
{
  for(auto i = std::begin(s); i != std::end(s); ++i) {
    if('A' <= *i && *i <= 'Z') {
      *i = (*i) - 'A' + 'a';
    }
  }
}

namespace {
// Calculates Damerau–Levenshtein distance between c-string a and b
// with given costs.  swapcost, subcost, addcost and delcost are cost
// to swap 2 adjacent characters, substitute characters, add character
// and delete character respectively.
int levenshtein
(const char* a,
 const char* b,
 int swapcost,
 int subcost,
 int addcost,
 int delcost)
{
  int alen = strlen(a);
  int blen = strlen(b);
  auto dp = std::vector<std::vector<int>>(3, std::vector<int>(blen+1));
  for(int i = 0; i <= blen; ++i) {
    dp[1][i] = i;
  }
  for(int i = 1; i <= alen; ++i) {
    dp[0][0] = i;
    for(int j = 1; j <= blen; ++j) {
      dp[0][j] = dp[1][j-1]+(a[i-1] == b[j-1] ? 0 : subcost);
      if(i >= 2 && j >= 2 && a[i-1] != b[j-1] &&
         a[i-2] == b[j-1] && a[i-1] == b[j-2]) {
        dp[0][j] = std::min(dp[0][j], dp[2][j-2]+swapcost);
      }
      dp[0][j] = std::min(dp[0][j],
                          std::min(dp[1][j]+delcost, dp[0][j-1]+addcost));
    }
    std::rotate(std::begin(dp), std::begin(dp)+2, std::end(dp));
  }
  return dp[1][blen];
}
} // namespace

void show_candidates(const char *unkopt, option *options)
{
  for(; *unkopt == '-'; ++unkopt);
  if(*unkopt == '\0') {
    return;
  }
  int prefix_match = 0;
  auto unkoptlen = strlen(unkopt);
  auto cands = std::vector<std::pair<int, const char*>>();
  for(size_t i = 0; options[i].name != nullptr; ++i) {
    auto optnamelen = strlen(options[i].name);
    // Use cost 0 for prefix match
    if(istartsWith(options[i].name, options[i].name + optnamelen,
                   unkopt, unkopt + unkoptlen)) {
      if(optnamelen == unkoptlen) {
        // Exact match, then we don't show any condidates.
        return ;
      }
      ++prefix_match;
      cands.emplace_back(0, options[i].name);
      continue;
    }
    // Use cost 0 for suffix match, but match at least 3 characters
    if(unkoptlen >= 3 &&
       iendsWith(options[i].name, options[i].name + optnamelen,
                 unkopt, unkopt + unkoptlen)) {
      cands.emplace_back(0, options[i].name);
      continue;
    }
    // cost values are borrowed from git, help.c.
    int sim = levenshtein(unkopt, options[i].name, 0, 2, 1, 3);
    cands.emplace_back(sim, options[i].name);
  }
  if(prefix_match == 1 || cands.empty()) {
    return;
  }
  std::sort(std::begin(cands), std::end(cands));
  int threshold = cands[0].first;
  // threshold value is a magic value.
  if(threshold > 6) {
    return;
  }
  std::cerr << "\nDid you mean:\n";
  for(auto& item : cands) {
    if(item.first > threshold) {
      break;
    }
    std::cerr << "\t--" << item.second << "\n";
  }
}

bool has_uri_field(const http_parser_url &u, http_parser_url_fields field)
{
  return u.field_set & (1 << field);
}

bool fieldeq(const char *uri1, const http_parser_url &u1,
             const char *uri2, const http_parser_url &u2,
             http_parser_url_fields field)
{
  if(!has_uri_field(u1, field)) {
    if(!has_uri_field(u2, field)) {
      return true;
    } else {
      return false;
    }
  } else if(!has_uri_field(u2, field)) {
    return false;
  }
  if(u1.field_data[field].len != u2.field_data[field].len) {
    return false;
  }
  return memcmp(uri1+u1.field_data[field].off,
                uri2+u2.field_data[field].off,
                u1.field_data[field].len) == 0;
}

bool fieldeq(const char *uri, const http_parser_url &u,
             http_parser_url_fields field,
             const char *t)
{
  if(!has_uri_field(u, field)) {
    if(!t[0]) {
      return true;
    } else {
      return false;
    }
  } else if(!t[0]) {
    return false;
  }
  int i, len = u.field_data[field].len;
  const char *p = uri+u.field_data[field].off;
  for(i = 0; i < len && t[i] && p[i] == t[i]; ++i);
  return i == len && !t[i];
}

std::string get_uri_field(const char *uri, const http_parser_url &u,
                          http_parser_url_fields field)
{
  if(util::has_uri_field(u, field)) {
    return std::string(uri+u.field_data[field].off,
                       u.field_data[field].len);
  } else {
    return "";
  }
}

uint16_t get_default_port(const char *uri, const http_parser_url &u)
{
  if(util::fieldeq(uri, u, UF_SCHEMA, "https")) {
    return 443;
  } else if(util::fieldeq(uri, u, UF_SCHEMA, "http")) {
    return 80;
  } else {
    return 443;
  }
}

bool porteq(const char *uri1, const http_parser_url &u1,
            const char *uri2, const http_parser_url &u2)
{
  uint16_t port1, port2;
  port1 = util::has_uri_field(u1, UF_PORT) ?
    u1.port : get_default_port(uri1, u1);
  port2 = util::has_uri_field(u2, UF_PORT) ?
    u2.port : get_default_port(uri2, u2);
  return port1 == port2;
}

void write_uri_field(std::ostream& o,
                     const char *uri, const http_parser_url &u,
                     http_parser_url_fields field)
{
  if(util::has_uri_field(u, field)) {
    o.write(uri+u.field_data[field].off, u.field_data[field].len);
  }
}

EvbufferBuffer::EvbufferBuffer()
  : evbuffer_(nullptr),
    buf_(nullptr),
    bufmax_(0),
    buflen_(0)
{}

EvbufferBuffer::EvbufferBuffer(evbuffer *evbuffer, uint8_t *buf, size_t bufmax)
  : evbuffer_(evbuffer),
    buf_(buf),
    bufmax_(bufmax),
    buflen_(0)
{}

void EvbufferBuffer::reset(evbuffer *evbuffer, uint8_t *buf, size_t bufmax)
{
  evbuffer_ = evbuffer;
  buf_ = buf;
  bufmax_ = bufmax;
  buflen_ = 0;
}

int EvbufferBuffer::flush()
{
  int rv;
  rv = evbuffer_add(evbuffer_, buf_, buflen_);
  if(rv == -1) {
    return -1;
  }
  buflen_ = 0;
  return 0;
}

int EvbufferBuffer::add(const uint8_t *data, size_t datalen)
{
  int rv;
  if(buflen_ + datalen > bufmax_) {
    rv = evbuffer_add(evbuffer_, buf_, buflen_);
    if(rv == -1) {
      return -1;
    }
    buflen_ = 0;
    if(datalen > bufmax_) {
      rv = evbuffer_add(evbuffer_, data, datalen);
      if(rv == -1) {
        return -1;
      }
      return 0;
    }
  }
  memcpy(buf_ + buflen_, data, datalen);
  buflen_ += datalen;
  return 0;
}

size_t EvbufferBuffer::get_buflen() const
{
  return buflen_;
}

bool numeric_host(const char *hostname)
{
  struct addrinfo hints;
  struct addrinfo* res;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_NUMERICHOST;
  if(getaddrinfo(hostname, nullptr, &hints, &res)) {
    return false;
  }
  freeaddrinfo(res);
  return true;
}

} // namespace util

} // namespace nghttp2
