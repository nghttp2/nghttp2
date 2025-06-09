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
#include "http2.h"

#include "llhttp.h"

#include "util.h"

using namespace std::literals;

namespace nghttp2 {

namespace http2 {

std::string_view get_reason_phrase(unsigned int status_code) {
  switch (status_code) {
  case 100:
    return "Continue"sv;
  case 101:
    return "Switching Protocols"sv;
  case 103:
    return "Early Hints"sv;
  case 200:
    return "OK"sv;
  case 201:
    return "Created"sv;
  case 202:
    return "Accepted"sv;
  case 203:
    return "Non-Authoritative Information"sv;
  case 204:
    return "No Content"sv;
  case 205:
    return "Reset Content"sv;
  case 206:
    return "Partial Content"sv;
  case 300:
    return "Multiple Choices"sv;
  case 301:
    return "Moved Permanently"sv;
  case 302:
    return "Found"sv;
  case 303:
    return "See Other"sv;
  case 304:
    return "Not Modified"sv;
  case 305:
    return "Use Proxy"sv;
  // case 306: return "(Unused)"sv;
  case 307:
    return "Temporary Redirect"sv;
  case 308:
    return "Permanent Redirect"sv;
  case 400:
    return "Bad Request"sv;
  case 401:
    return "Unauthorized"sv;
  case 402:
    return "Payment Required"sv;
  case 403:
    return "Forbidden"sv;
  case 404:
    return "Not Found"sv;
  case 405:
    return "Method Not Allowed"sv;
  case 406:
    return "Not Acceptable"sv;
  case 407:
    return "Proxy Authentication Required"sv;
  case 408:
    return "Request Timeout"sv;
  case 409:
    return "Conflict"sv;
  case 410:
    return "Gone"sv;
  case 411:
    return "Length Required"sv;
  case 412:
    return "Precondition Failed"sv;
  case 413:
    return "Payload Too Large"sv;
  case 414:
    return "URI Too Long"sv;
  case 415:
    return "Unsupported Media Type"sv;
  case 416:
    return "Requested Range Not Satisfiable"sv;
  case 417:
    return "Expectation Failed"sv;
  case 421:
    return "Misdirected Request"sv;
  case 425:
    // https://tools.ietf.org/html/rfc8470
    return "Too Early"sv;
  case 426:
    return "Upgrade Required"sv;
  case 428:
    return "Precondition Required"sv;
  case 429:
    return "Too Many Requests"sv;
  case 431:
    return "Request Header Fields Too Large"sv;
  case 451:
    return "Unavailable For Legal Reasons"sv;
  case 500:
    return "Internal Server Error"sv;
  case 501:
    return "Not Implemented"sv;
  case 502:
    return "Bad Gateway"sv;
  case 503:
    return "Service Unavailable"sv;
  case 504:
    return "Gateway Timeout"sv;
  case 505:
    return "HTTP Version Not Supported"sv;
  case 511:
    return "Network Authentication Required"sv;
  default:
    return ""sv;
  }
}

std::string_view stringify_status(BlockAllocator &balloc,
                                  unsigned int status_code) {
  switch (status_code) {
  case 100:
    return "100"sv;
  case 101:
    return "101"sv;
  case 103:
    return "103"sv;
  case 200:
    return "200"sv;
  case 201:
    return "201"sv;
  case 202:
    return "202"sv;
  case 203:
    return "203"sv;
  case 204:
    return "204"sv;
  case 205:
    return "205"sv;
  case 206:
    return "206"sv;
  case 300:
    return "300"sv;
  case 301:
    return "301"sv;
  case 302:
    return "302"sv;
  case 303:
    return "303"sv;
  case 304:
    return "304"sv;
  case 305:
    return "305"sv;
  // case 306: return "306"sv;
  case 307:
    return "307"sv;
  case 308:
    return "308"sv;
  case 400:
    return "400"sv;
  case 401:
    return "401"sv;
  case 402:
    return "402"sv;
  case 403:
    return "403"sv;
  case 404:
    return "404"sv;
  case 405:
    return "405"sv;
  case 406:
    return "406"sv;
  case 407:
    return "407"sv;
  case 408:
    return "408"sv;
  case 409:
    return "409"sv;
  case 410:
    return "410"sv;
  case 411:
    return "411"sv;
  case 412:
    return "412"sv;
  case 413:
    return "413"sv;
  case 414:
    return "414"sv;
  case 415:
    return "415"sv;
  case 416:
    return "416"sv;
  case 417:
    return "417"sv;
  case 421:
    return "421"sv;
  case 426:
    return "426"sv;
  case 428:
    return "428"sv;
  case 429:
    return "429"sv;
  case 431:
    return "431"sv;
  case 451:
    return "451"sv;
  case 500:
    return "500"sv;
  case 501:
    return "501"sv;
  case 502:
    return "502"sv;
  case 503:
    return "503"sv;
  case 504:
    return "504"sv;
  case 505:
    return "505"sv;
  case 511:
    return "511"sv;
  default:
    return util::make_string_ref_uint(balloc, status_code);
  }
}

struct Capitalizer {
  template <std::weakly_incrementable O>
  requires(std::indirectly_writable<O, char>)
  constexpr O operator()(const std::string_view &s, O result) noexcept {
    using result_type = std::iter_value_t<O>;

    *result++ = static_cast<result_type>(util::upcase(s[0]));

    for (size_t i = 1; i < s.size(); ++i) {
      if (s[i - 1] == '-') {
        *result++ = static_cast<result_type>(util::upcase(s[i]));
      } else {
        *result++ = static_cast<result_type>(s[i]);
      }
    }

    return result;
  }
};

namespace {
void capitalize_long(DefaultMemchunks *buf, const std::string_view &s) {
  buf->append(util::upcase(s[0]));

  auto it = s.begin() + 1;

  for (; it != s.end();) {
    auto p = std::ranges::find(it, s.end(), '-');
    p = std::ranges::find_if(p, s.end(), [](auto c) { return c != '-'; });

    buf->append(it, p);

    if (p == s.end()) {
      return;
    }

    buf->append(util::upcase(*p));

    it = p + 1;
  }
}
} // namespace

void capitalize(DefaultMemchunks *buf, const std::string_view &s) {
  assert(!s.empty());

  constexpr size_t max_namelen = 32;

  if (s.size() > max_namelen) {
    capitalize_long(buf, s);
    return;
  }

  buf->append(s.size(), std::bind_front(Capitalizer{}, s));
}

Headers::value_type to_header(const std::string_view &name,
                              const std::string_view &value, bool no_index,
                              int32_t token) {
  return Header(std::string{std::ranges::begin(name), std::ranges::end(name)},
                std::string{std::ranges::begin(value), std::ranges::end(value)},
                no_index, token);
}

void add_header(Headers &nva, const std::string_view &name,
                const std::string_view &value, bool no_index, int32_t token) {
  nva.push_back(to_header(name, value, no_index, token));
}

const Headers::value_type *get_header(const Headers &nva,
                                      const std::string_view &name) {
  const Headers::value_type *res = nullptr;
  for (auto &nv : nva) {
    if (nv.name == name) {
      res = &nv;
    }
  }
  return res;
}

bool non_empty_value(const HeaderRefs::value_type *nv) {
  return nv && !nv->value.empty();
}

namespace {
void copy_headers_to_nva_internal(std::vector<nghttp2_nv> &nva,
                                  const HeaderRefs &headers, uint8_t nv_flags,
                                  uint32_t flags) {
  auto it_forwarded = std::ranges::end(headers);
  auto it_xff = std::ranges::end(headers);
  auto it_xfp = std::ranges::end(headers);
  auto it_via = std::ranges::end(headers);

  for (auto it = std::ranges::begin(headers); it != std::ranges::end(headers);
       ++it) {
    auto kv = &(*it);
    if (kv->name.empty() || kv->name[0] == ':') {
      continue;
    }
    switch (kv->token) {
    case HD_COOKIE:
    case HD_CONNECTION:
    case HD_HOST:
    case HD_HTTP2_SETTINGS:
    case HD_KEEP_ALIVE:
    case HD_PROXY_CONNECTION:
    case HD_SERVER:
    case HD_TE:
    case HD_TRANSFER_ENCODING:
    case HD_UPGRADE:
      continue;
    case HD_EARLY_DATA:
      if (flags & HDOP_STRIP_EARLY_DATA) {
        continue;
      }
      break;
    case HD_SEC_WEBSOCKET_ACCEPT:
      if (flags & HDOP_STRIP_SEC_WEBSOCKET_ACCEPT) {
        continue;
      }
      break;
    case HD_SEC_WEBSOCKET_KEY:
      if (flags & HDOP_STRIP_SEC_WEBSOCKET_KEY) {
        continue;
      }
      break;
    case HD_FORWARDED:
      if (flags & HDOP_STRIP_FORWARDED) {
        continue;
      }

      if (it_forwarded == std::ranges::end(headers)) {
        it_forwarded = it;
        continue;
      }

      kv = &(*it_forwarded);
      it_forwarded = it;
      break;
    case HD_X_FORWARDED_FOR:
      if (flags & HDOP_STRIP_X_FORWARDED_FOR) {
        continue;
      }

      if (it_xff == std::ranges::end(headers)) {
        it_xff = it;
        continue;
      }

      kv = &(*it_xff);
      it_xff = it;
      break;
    case HD_X_FORWARDED_PROTO:
      if (flags & HDOP_STRIP_X_FORWARDED_PROTO) {
        continue;
      }

      if (it_xfp == std::ranges::end(headers)) {
        it_xfp = it;
        continue;
      }

      kv = &(*it_xfp);
      it_xfp = it;
      break;
    case HD_VIA:
      if (flags & HDOP_STRIP_VIA) {
        continue;
      }

      if (it_via == std::ranges::end(headers)) {
        it_via = it;
        continue;
      }

      kv = &(*it_via);
      it_via = it;
      break;
    }
    nva.push_back(
      make_field_flags(kv->name, kv->value, nv_flags | no_index(kv->no_index)));
  }
}
} // namespace

void copy_headers_to_nva(std::vector<nghttp2_nv> &nva,
                         const HeaderRefs &headers, uint32_t flags) {
  copy_headers_to_nva_internal(nva, headers, NGHTTP2_NV_FLAG_NONE, flags);
}

void copy_headers_to_nva_nocopy(std::vector<nghttp2_nv> &nva,
                                const HeaderRefs &headers, uint32_t flags) {
  copy_headers_to_nva_internal(
    nva, headers, NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE,
    flags);
}

void build_http1_headers_from_headers(DefaultMemchunks *buf,
                                      const HeaderRefs &headers,
                                      uint32_t flags) {
  auto it_forwarded = std::ranges::end(headers);
  auto it_xff = std::ranges::end(headers);
  auto it_xfp = std::ranges::end(headers);
  auto it_via = std::ranges::end(headers);

  for (auto it = std::ranges::begin(headers); it != std::ranges::end(headers);
       ++it) {
    auto kv = &(*it);
    if (kv->name.empty() || kv->name[0] == ':') {
      continue;
    }
    switch (kv->token) {
    case HD_CONNECTION:
    case HD_COOKIE:
    case HD_HOST:
    case HD_HTTP2_SETTINGS:
    case HD_KEEP_ALIVE:
    case HD_PROXY_CONNECTION:
    case HD_SERVER:
    case HD_UPGRADE:
      continue;
    case HD_EARLY_DATA:
      if (flags & HDOP_STRIP_EARLY_DATA) {
        continue;
      }
      break;
    case HD_TRANSFER_ENCODING:
      if (flags & HDOP_STRIP_TRANSFER_ENCODING) {
        continue;
      }
      break;
    case HD_FORWARDED:
      if (flags & HDOP_STRIP_FORWARDED) {
        continue;
      }

      if (it_forwarded == std::ranges::end(headers)) {
        it_forwarded = it;
        continue;
      }

      kv = &(*it_forwarded);
      it_forwarded = it;
      break;
    case HD_X_FORWARDED_FOR:
      if (flags & HDOP_STRIP_X_FORWARDED_FOR) {
        continue;
      }

      if (it_xff == std::ranges::end(headers)) {
        it_xff = it;
        continue;
      }

      kv = &(*it_xff);
      it_xff = it;
      break;
    case HD_X_FORWARDED_PROTO:
      if (flags & HDOP_STRIP_X_FORWARDED_PROTO) {
        continue;
      }

      if (it_xfp == std::ranges::end(headers)) {
        it_xfp = it;
        continue;
      }

      kv = &(*it_xfp);
      it_xfp = it;
      break;
    case HD_VIA:
      if (flags & HDOP_STRIP_VIA) {
        continue;
      }

      if (it_via == std::ranges::end(headers)) {
        it_via = it;
        continue;
      }

      kv = &(*it_via);
      it_via = it;
      break;
    }
    capitalize(buf, kv->name);
    buf->append(": "sv);
    buf->append(kv->value);
    buf->append("\r\n"sv);
  }
}

int32_t determine_window_update_transmission(nghttp2_session *session,
                                             int32_t stream_id) {
  int32_t recv_length, window_size;
  if (stream_id == 0) {
    recv_length = nghttp2_session_get_effective_recv_data_length(session);
    window_size = nghttp2_session_get_effective_local_window_size(session);
  } else {
    recv_length =
      nghttp2_session_get_stream_effective_recv_data_length(session, stream_id);
    window_size = nghttp2_session_get_stream_effective_local_window_size(
      session, stream_id);
  }
  if (recv_length != -1 && window_size != -1) {
    if (recv_length >= window_size / 2) {
      return recv_length;
    }
  }
  return -1;
}

void dump_nv(FILE *out, const nghttp2_nv *nva, size_t nvlen) {
  auto end = nva + nvlen;
  for (; nva != end; ++nva) {
    fprintf(out, "%s: %s\n", nva->name, nva->value);
  }
  fputc('\n', out);
  fflush(out);
}

void dump_nv(FILE *out, const HeaderRefs &nva) {
  for (auto &nv : nva) {
    fprintf(out, "%s: %s\n", nv.name.data(), nv.value.data());
  }
  fputc('\n', out);
  fflush(out);
}

void erase_header(HeaderRef *hd) {
  hd->name = ""sv;
  hd->token = -1;
}

std::string_view rewrite_location_uri(BlockAllocator &balloc,
                                      const std::string_view &uri,
                                      const urlparse_url &u,
                                      const std::string_view &match_host,
                                      const std::string_view &request_authority,
                                      const std::string_view &upstream_scheme) {
  // We just rewrite scheme and authority.
  if ((u.field_set & (1 << URLPARSE_HOST)) == 0) {
    return ""sv;
  }
  auto field = &u.field_data[URLPARSE_HOST];
  if (!util::starts_with(match_host,
                         std::string_view{&uri[field->off], field->len}) ||
      (match_host.size() != field->len && match_host[field->len] != ':')) {
    return ""sv;
  }

  size_t len = 0;
  if (!request_authority.empty()) {
    len += upstream_scheme.size() + str_size("://") + request_authority.size();
  }

  if (u.field_set & (1 << URLPARSE_PATH)) {
    field = &u.field_data[URLPARSE_PATH];
    len += field->len;
  }

  if (u.field_set & (1 << URLPARSE_QUERY)) {
    field = &u.field_data[URLPARSE_QUERY];
    len += 1 + field->len;
  }

  if (u.field_set & (1 << URLPARSE_FRAGMENT)) {
    field = &u.field_data[URLPARSE_FRAGMENT];
    len += 1 + field->len;
  }

  auto iov = make_byte_ref(balloc, len + 1);
  auto p = std::ranges::begin(iov);

  if (!request_authority.empty()) {
    p = std::ranges::copy(upstream_scheme, p).out;
    p = std::ranges::copy("://"sv, p).out;
    p = std::ranges::copy(request_authority, p).out;
  }
  if (u.field_set & (1 << URLPARSE_PATH)) {
    field = &u.field_data[URLPARSE_PATH];
    p = std::ranges::copy_n(&uri[field->off], field->len, p).out;
  }
  if (u.field_set & (1 << URLPARSE_QUERY)) {
    field = &u.field_data[URLPARSE_QUERY];
    *p++ = '?';
    p = std::ranges::copy_n(&uri[field->off], field->len, p).out;
  }
  if (u.field_set & (1 << URLPARSE_FRAGMENT)) {
    field = &u.field_data[URLPARSE_FRAGMENT];
    *p++ = '#';
    p = std::ranges::copy_n(&uri[field->off], field->len, p).out;
  }

  *p = '\0';

  return as_string_view(std::ranges::begin(iov), p);
}

int parse_http_status_code(const std::string_view &src) {
  if (src.size() != 3) {
    return -1;
  }

  int status = 0;
  for (auto c : src) {
    if (!isdigit(c)) {
      return -1;
    }
    status *= 10;
    status += c - '0';
  }

  if (status < 100) {
    return -1;
  }

  return status;
}

// This function was generated by genheaderfunc.py.  Inspired by h2o
// header lookup.  https://github.com/h2o/h2o
int lookup_token(const std::string_view &name) {
  switch (name.size()) {
  case 2:
    switch (name[1]) {
    case 'e':
      if (util::streq("t"sv, name.substr(0, 1))) {
        return HD_TE;
      }
      break;
    }
    break;
  case 3:
    switch (name[2]) {
    case 'a':
      if (util::streq("vi"sv, name.substr(0, 2))) {
        return HD_VIA;
      }
      break;
    }
    break;
  case 4:
    switch (name[3]) {
    case 'e':
      if (util::streq("dat"sv, name.substr(0, 3))) {
        return HD_DATE;
      }
      break;
    case 'k':
      if (util::streq("lin"sv, name.substr(0, 3))) {
        return HD_LINK;
      }
      break;
    case 't':
      if (util::streq("hos"sv, name.substr(0, 3))) {
        return HD_HOST;
      }
      break;
    }
    break;
  case 5:
    switch (name[4]) {
    case 'h':
      if (util::streq(":pat"sv, name.substr(0, 4))) {
        return HD__PATH;
      }
      break;
    case 't':
      if (util::streq(":hos"sv, name.substr(0, 4))) {
        return HD__HOST;
      }
      break;
    }
    break;
  case 6:
    switch (name[5]) {
    case 'e':
      if (util::streq("cooki"sv, name.substr(0, 5))) {
        return HD_COOKIE;
      }
      break;
    case 'r':
      if (util::streq("serve"sv, name.substr(0, 5))) {
        return HD_SERVER;
      }
      break;
    case 't':
      if (util::streq("expec"sv, name.substr(0, 5))) {
        return HD_EXPECT;
      }
      break;
    }
    break;
  case 7:
    switch (name[6]) {
    case 'c':
      if (util::streq("alt-sv"sv, name.substr(0, 6))) {
        return HD_ALT_SVC;
      }
      break;
    case 'd':
      if (util::streq(":metho"sv, name.substr(0, 6))) {
        return HD__METHOD;
      }
      break;
    case 'e':
      if (util::streq(":schem"sv, name.substr(0, 6))) {
        return HD__SCHEME;
      }
      if (util::streq("upgrad"sv, name.substr(0, 6))) {
        return HD_UPGRADE;
      }
      break;
    case 'r':
      if (util::streq("traile"sv, name.substr(0, 6))) {
        return HD_TRAILER;
      }
      break;
    case 's':
      if (util::streq(":statu"sv, name.substr(0, 6))) {
        return HD__STATUS;
      }
      break;
    }
    break;
  case 8:
    switch (name[7]) {
    case 'n':
      if (util::streq("locatio"sv, name.substr(0, 7))) {
        return HD_LOCATION;
      }
      break;
    case 'y':
      if (util::streq("priorit"sv, name.substr(0, 7))) {
        return HD_PRIORITY;
      }
      break;
    }
    break;
  case 9:
    switch (name[8]) {
    case 'd':
      if (util::streq("forwarde"sv, name.substr(0, 8))) {
        return HD_FORWARDED;
      }
      break;
    case 'l':
      if (util::streq(":protoco"sv, name.substr(0, 8))) {
        return HD__PROTOCOL;
      }
      break;
    }
    break;
  case 10:
    switch (name[9]) {
    case 'a':
      if (util::streq("early-dat"sv, name.substr(0, 9))) {
        return HD_EARLY_DATA;
      }
      break;
    case 'e':
      if (util::streq("keep-aliv"sv, name.substr(0, 9))) {
        return HD_KEEP_ALIVE;
      }
      break;
    case 'n':
      if (util::streq("connectio"sv, name.substr(0, 9))) {
        return HD_CONNECTION;
      }
      break;
    case 't':
      if (util::streq("user-agen"sv, name.substr(0, 9))) {
        return HD_USER_AGENT;
      }
      break;
    case 'y':
      if (util::streq(":authorit"sv, name.substr(0, 9))) {
        return HD__AUTHORITY;
      }
      break;
    }
    break;
  case 12:
    switch (name[11]) {
    case 'e':
      if (util::streq("content-typ"sv, name.substr(0, 11))) {
        return HD_CONTENT_TYPE;
      }
      break;
    }
    break;
  case 13:
    switch (name[12]) {
    case 'l':
      if (util::streq("cache-contro"sv, name.substr(0, 12))) {
        return HD_CACHE_CONTROL;
      }
      break;
    }
    break;
  case 14:
    switch (name[13]) {
    case 'h':
      if (util::streq("content-lengt"sv, name.substr(0, 13))) {
        return HD_CONTENT_LENGTH;
      }
      break;
    case 's':
      if (util::streq("http2-setting"sv, name.substr(0, 13))) {
        return HD_HTTP2_SETTINGS;
      }
      break;
    }
    break;
  case 15:
    switch (name[14]) {
    case 'e':
      if (util::streq("accept-languag"sv, name.substr(0, 14))) {
        return HD_ACCEPT_LANGUAGE;
      }
      break;
    case 'g':
      if (util::streq("accept-encodin"sv, name.substr(0, 14))) {
        return HD_ACCEPT_ENCODING;
      }
      break;
    case 'r':
      if (util::streq("x-forwarded-fo"sv, name.substr(0, 14))) {
        return HD_X_FORWARDED_FOR;
      }
      break;
    }
    break;
  case 16:
    switch (name[15]) {
    case 'n':
      if (util::streq("proxy-connectio"sv, name.substr(0, 15))) {
        return HD_PROXY_CONNECTION;
      }
      break;
    }
    break;
  case 17:
    switch (name[16]) {
    case 'e':
      if (util::streq("if-modified-sinc"sv, name.substr(0, 16))) {
        return HD_IF_MODIFIED_SINCE;
      }
      break;
    case 'g':
      if (util::streq("transfer-encodin"sv, name.substr(0, 16))) {
        return HD_TRANSFER_ENCODING;
      }
      break;
    case 'o':
      if (util::streq("x-forwarded-prot"sv, name.substr(0, 16))) {
        return HD_X_FORWARDED_PROTO;
      }
      break;
    case 'y':
      if (util::streq("sec-websocket-ke"sv, name.substr(0, 16))) {
        return HD_SEC_WEBSOCKET_KEY;
      }
      break;
    }
    break;
  case 20:
    switch (name[19]) {
    case 't':
      if (util::streq("sec-websocket-accep"sv, name.substr(0, 19))) {
        return HD_SEC_WEBSOCKET_ACCEPT;
      }
      break;
    }
    break;
  }
  return -1;
}

void init_hdidx(HeaderIndex &hdidx) { std::ranges::fill(hdidx, -1); }

void index_header(HeaderIndex &hdidx, int32_t token, size_t idx) {
  if (token == -1) {
    return;
  }
  assert(token < HD_MAXIDX);
  hdidx[static_cast<size_t>(token)] = static_cast<int16_t>(idx);
}

namespace {
template <typename InputIt> InputIt skip_lws(InputIt first, InputIt last) {
  for (; first != last; ++first) {
    switch (*first) {
    case ' ':
    case '\t':
      continue;
    default:
      return first;
    }
  }
  return first;
}
} // namespace

namespace {
template <typename InputIt>
InputIt skip_to_next_field(InputIt first, InputIt last) {
  for (; first != last; ++first) {
    switch (*first) {
    case ' ':
    case '\t':
    case ',':
      continue;
    default:
      return first;
    }
  }
  return first;
}
} // namespace

namespace {
// Skip to the right dquote ('"'), handling backslash escapes.
// Returns |last| if input is not terminated with '"'.
template <typename InputIt>
InputIt skip_to_right_dquote(InputIt first, InputIt last) {
  for (; first != last;) {
    switch (*first) {
    case '"':
      return first;
      // quoted-pair
    case '\\':
      ++first;
      if (first == last) {
        return first;
      }

      switch (*first) {
      case '\t':
      case ' ':
        break;
      default:
        if ((0x21 <= *first && *first <= 0x7e) /* VCHAR */ ||
            0x80 <= *first /* obs-text */) {
          break;
        }

        return last;
      }

      break;
      // qdtext
    case '\t':
    case ' ':
    case '!':
      break;
    default:
      if ((0x23 <= *first && *first <= 0x5b) ||
          (0x5d <= *first && *first <= 0x7e)) {
        break;
      }

      return last;
    }
    ++first;
  }
  return first;
}
} // namespace

namespace {
// Returns true if link-param does not match pattern |pat| of length
// |patlen| or it has empty value ("").  |pat| should be parmname
// followed by "=".
bool check_link_param_empty(const std::string_view &s,
                            const std::string_view &pat) {
  return s.size() < pat.size() ||
         !std::ranges::equal(s.substr(0, pat.size()), pat, util::CaseCmp()) ||
         (s.size() >= pat.size() + 2 &&
          // we only accept URI if pat is followed by ""
          // (e.g., loadpolicy="") here.
          s[pat.size()] == '"' && s[pat.size() + 1] == '"');
}
} // namespace

namespace {
// Returns true if link-param consists of only parmname, and it
// matches string [pat, pat + patlen).
bool check_link_param_without_value(const std::string_view &s,
                                    const std::string_view &pat) {
  if (s.size() < pat.size()) {
    return false;
  }

  if (s.size() == pat.size()) {
    return std::ranges::equal(s, pat, util::CaseCmp());
  }

  switch (s[pat.size()]) {
  case ';':
  case ',':
    return std::ranges::equal(s.substr(0, pat.size()), pat, util::CaseCmp());
  }

  return false;
}
} // namespace

namespace {
std::pair<LinkHeader, const char *>
parse_next_link_header_once(const char *first, const char *last) {
  first = skip_to_next_field(first, last);
  if (first == last || *first != '<') {
    return {{""sv}, last};
  }
  auto url_first = ++first;
  first = std::ranges::find(first, last, '>');
  if (first == last) {
    return {{""sv}, first};
  }
  auto url_last = first++;
  if (first == last) {
    return {{""sv}, first};
  }
  // we expect ';' or ',' here
  switch (*first) {
  case ',':
    return {{""sv}, ++first};
  case ';':
    ++first;
    break;
  default:
    return {{""sv}, last};
  }

  auto ok = false;
  auto ign = false;
  for (;;) {
    first = skip_lws(first, last);
    if (first == last) {
      return {{""sv}, first};
    }
    // we expect link-param

    if (!ign) {
      if (!ok) {
        // rel can take several relations using quoted form.
        static constexpr auto PLP = "rel=\""sv;
        static constexpr auto PLT = "preload"sv;

        if (first + PLP.size() < last && *(first + PLP.size() - 1) == '"' &&
            std::ranges::equal(PLP, std::string_view{first, PLP.size()},
                               util::CaseCmp())) {
          // we have to search preload in whitespace separated list:
          // rel="preload something http://example.org/foo"
          first += PLP.size();
          auto start = first;
          for (; first != last;) {
            if (*first != ' ' && *first != '"') {
              ++first;
              continue;
            }

            if (start == first) {
              return {{""sv}, last};
            }

            if (!ok && start + PLT.size() == first &&
                std::ranges::equal(PLT, std::string_view{start, PLT.size()},
                                   util::CaseCmp())) {
              ok = true;
            }

            if (*first == '"') {
              break;
            }
            first = skip_lws(first, last);
            start = first;
          }
          if (first == last) {
            return {{""sv}, last};
          }
          assert(*first == '"');
          ++first;
          if (first == last || *first == ',') {
            goto almost_done;
          }
          if (*first == ';') {
            ++first;
            // parse next link-param
            continue;
          }
          return {{""sv}, last};
        }
      }
      // we are only interested in rel=preload parameter.  Others are
      // simply skipped.
      static constexpr auto PL = "rel=preload"sv;
      if (first + PL.size() == last) {
        if (std::ranges::equal(PL, std::string_view{first, PL.size()},
                               util::CaseCmp())) {
          // ok = true;
          // this is the end of sequence
          return {{{url_first, url_last}}, last};
        }
      } else if (first + PL.size() + 1 <= last) {
        switch (*(first + PL.size())) {
        case ',':
          if (!std::ranges::equal(PL, std::string_view{first, PL.size()},
                                  util::CaseCmp())) {
            break;
          }
          // ok = true;
          // skip including ','
          first += PL.size() + 1;
          return {{{url_first, url_last}}, first};
        case ';':
          if (!std::ranges::equal(PL, std::string_view{first, PL.size()},
                                  util::CaseCmp())) {
            break;
          }
          ok = true;
          // skip including ';'
          first += PL.size() + 1;
          // continue parse next link-param
          continue;
        }
      }
      // we have to reject URI if we have nonempty anchor parameter.
      if (!ign && !check_link_param_empty({first, last}, "anchor="sv)) {
        ign = true;
      }

      // reject URI if we have non-empty loadpolicy.  This could be
      // tightened up to just pick up "next" or "insert".
      if (!ign && !check_link_param_empty({first, last}, "loadpolicy="sv)) {
        ign = true;
      }

      // reject URI if we have nopush attribute.
      if (!ign && check_link_param_without_value({first, last}, "nopush"sv)) {
        ign = true;
      }
    }

    auto param_first = first;
    for (; first != last;) {
      if (util::in_attr_char(*first)) {
        ++first;
        continue;
      }
      // '*' is only allowed at the end of parameter name and must be
      // followed by '='
      if (last - first >= 2 && first != param_first) {
        if (*first == '*' && *(first + 1) == '=') {
          ++first;
          break;
        }
      }
      if (*first == '=' || *first == ';' || *first == ',') {
        break;
      }
      return {{""sv}, last};
    }
    if (param_first == first) {
      // empty parmname
      return {{""sv}, last};
    }
    // link-param without value is acceptable (see link-extension) if
    // it is not followed by '='
    if (first == last || *first == ',') {
      goto almost_done;
    }
    if (*first == ';') {
      ++first;
      // parse next link-param
      continue;
    }
    // now parsing link-param value
    assert(*first == '=');
    ++first;
    if (first == last) {
      // empty value is not acceptable
      return {{""sv}, first};
    }
    if (*first == '"') {
      // quoted-string
      first = skip_to_right_dquote(first + 1, last);
      if (first == last) {
        return {{""sv}, first};
      }
      ++first;
      if (first == last || *first == ',') {
        goto almost_done;
      }
      if (*first == ';') {
        ++first;
        // parse next link-param
        continue;
      }
      return {{""sv}, last};
    }
    // not quoted-string, skip to next ',' or ';'
    if (*first == ',' || *first == ';') {
      // empty value
      return {{""sv}, last};
    }
    for (; first != last; ++first) {
      if (*first == ',' || *first == ';') {
        break;
      }
    }
    if (first == last || *first == ',') {
      goto almost_done;
    }
    assert(*first == ';');
    ++first;
    // parse next link-param
  }

almost_done:
  assert(first == last || *first == ',');

  if (first != last) {
    ++first;
  }
  if (ok && !ign) {
    return {{{url_first, url_last}}, first};
  }
  return {{""sv}, first};
}
} // namespace

std::vector<LinkHeader> parse_link_header(const std::string_view &src) {
  std::vector<LinkHeader> res;
  for (auto first = std::ranges::begin(src); first != std::ranges::end(src);) {
    auto rv = parse_next_link_header_once(first, std::ranges::end(src));
    first = rv.second;
    auto &link = rv.first;
    if (!link.uri.empty()) {
      res.push_back(link);
    }
  }
  return res;
}

std::string path_join(const std::string_view &base_path,
                      const std::string_view &base_query,
                      const std::string_view &rel_path,
                      const std::string_view &rel_query) {
  BlockAllocator balloc(1024, 1024);

  return std::string{
    path_join(balloc, base_path, base_query, rel_path, rel_query)};
}

bool expect_response_body(uint32_t status_code) {
  return status_code == 101 ||
         (status_code / 100 != 1 && status_code != 304 && status_code != 204);
}

bool expect_response_body(const std::string &method, uint32_t status_code) {
  return method != "HEAD" && expect_response_body(status_code);
}

bool expect_response_body(int method_token, uint32_t status_code) {
  return method_token != HTTP_HEAD && expect_response_body(status_code);
}

// This function was generated by genmethodfunc.py.
int lookup_method_token(const std::string_view &name) {
  switch (name.size()) {
  case 3:
    switch (name[2]) {
    case 'L':
      if (util::streq("AC"sv, name.substr(0, 2))) {
        return HTTP_ACL;
      }
      break;
    case 'T':
      if (util::streq("GE"sv, name.substr(0, 2))) {
        return HTTP_GET;
      }
      if (util::streq("PU"sv, name.substr(0, 2))) {
        return HTTP_PUT;
      }
      break;
    }
    break;
  case 4:
    switch (name[3]) {
    case 'D':
      if (util::streq("BIN"sv, name.substr(0, 3))) {
        return HTTP_BIND;
      }
      if (util::streq("HEA"sv, name.substr(0, 3))) {
        return HTTP_HEAD;
      }
      break;
    case 'E':
      if (util::streq("MOV"sv, name.substr(0, 3))) {
        return HTTP_MOVE;
      }
      break;
    case 'K':
      if (util::streq("LIN"sv, name.substr(0, 3))) {
        return HTTP_LINK;
      }
      if (util::streq("LOC"sv, name.substr(0, 3))) {
        return HTTP_LOCK;
      }
      break;
    case 'T':
      if (util::streq("POS"sv, name.substr(0, 3))) {
        return HTTP_POST;
      }
      break;
    case 'Y':
      if (util::streq("COP"sv, name.substr(0, 3))) {
        return HTTP_COPY;
      }
      break;
    }
    break;
  case 5:
    switch (name[4]) {
    case 'E':
      if (util::streq("MERG"sv, name.substr(0, 4))) {
        return HTTP_MERGE;
      }
      if (util::streq("PURG"sv, name.substr(0, 4))) {
        return HTTP_PURGE;
      }
      if (util::streq("TRAC"sv, name.substr(0, 4))) {
        return HTTP_TRACE;
      }
      break;
    case 'H':
      if (util::streq("PATC"sv, name.substr(0, 4))) {
        return HTTP_PATCH;
      }
      break;
    case 'L':
      if (util::streq("MKCO"sv, name.substr(0, 4))) {
        return HTTP_MKCOL;
      }
      break;
    }
    break;
  case 6:
    switch (name[5]) {
    case 'D':
      if (util::streq("REBIN"sv, name.substr(0, 5))) {
        return HTTP_REBIND;
      }
      if (util::streq("UNBIN"sv, name.substr(0, 5))) {
        return HTTP_UNBIND;
      }
      break;
    case 'E':
      if (util::streq("DELET"sv, name.substr(0, 5))) {
        return HTTP_DELETE;
      }
      if (util::streq("SOURC"sv, name.substr(0, 5))) {
        return HTTP_SOURCE;
      }
      break;
    case 'H':
      if (util::streq("SEARC"sv, name.substr(0, 5))) {
        return HTTP_SEARCH;
      }
      break;
    case 'K':
      if (util::streq("UNLIN"sv, name.substr(0, 5))) {
        return HTTP_UNLINK;
      }
      if (util::streq("UNLOC"sv, name.substr(0, 5))) {
        return HTTP_UNLOCK;
      }
      break;
    case 'T':
      if (util::streq("REPOR"sv, name.substr(0, 5))) {
        return HTTP_REPORT;
      }
      break;
    case 'Y':
      if (util::streq("NOTIF"sv, name.substr(0, 5))) {
        return HTTP_NOTIFY;
      }
      break;
    }
    break;
  case 7:
    switch (name[6]) {
    case 'H':
      if (util::streq("MSEARC"sv, name.substr(0, 6))) {
        return HTTP_MSEARCH;
      }
      break;
    case 'S':
      if (util::streq("OPTION"sv, name.substr(0, 6))) {
        return HTTP_OPTIONS;
      }
      break;
    case 'T':
      if (util::streq("CONNEC"sv, name.substr(0, 6))) {
        return HTTP_CONNECT;
      }
      break;
    }
    break;
  case 8:
    switch (name[7]) {
    case 'D':
      if (util::streq("PROPFIN"sv, name.substr(0, 7))) {
        return HTTP_PROPFIND;
      }
      break;
    case 'T':
      if (util::streq("CHECKOU"sv, name.substr(0, 7))) {
        return HTTP_CHECKOUT;
      }
      break;
    }
    break;
  case 9:
    switch (name[8]) {
    case 'E':
      if (util::streq("SUBSCRIB"sv, name.substr(0, 8))) {
        return HTTP_SUBSCRIBE;
      }
      break;
    case 'H':
      if (util::streq("PROPPATC"sv, name.substr(0, 8))) {
        return HTTP_PROPPATCH;
      }
      break;
    }
    break;
  case 10:
    switch (name[9]) {
    case 'R':
      if (util::streq("MKCALENDA"sv, name.substr(0, 9))) {
        return HTTP_MKCALENDAR;
      }
      break;
    case 'Y':
      if (util::streq("MKACTIVIT"sv, name.substr(0, 9))) {
        return HTTP_MKACTIVITY;
      }
      break;
    }
    break;
  case 11:
    switch (name[10]) {
    case 'E':
      if (util::streq("UNSUBSCRIB"sv, name.substr(0, 10))) {
        return HTTP_UNSUBSCRIBE;
      }
      break;
    }
    break;
  }
  return -1;
}

std::string_view to_method_string(int method_token) {
  // we happened to use same value for method with llhttp.
  return std::string_view{
    llhttp_method_name(static_cast<llhttp_method>(method_token))};
}

std::string_view get_pure_path_component(const std::string_view &uri) {
  int rv;

  urlparse_url u;
  rv = urlparse_parse_url(uri.data(), uri.size(), 0, &u);
  if (rv != 0) {
    return ""sv;
  }

  if (u.field_set & (1 << URLPARSE_PATH)) {
    auto &f = u.field_data[URLPARSE_PATH];
    return std::string_view{uri.data() + f.off, f.len};
  }

  return "/"sv;
}

int construct_push_component(BlockAllocator &balloc, std::string_view &scheme,
                             std::string_view &authority,
                             std::string_view &path,
                             const std::string_view &base,
                             const std::string_view &uri) {
  int rv;
  std::string_view rel, relq;

  if (uri.size() == 0) {
    return -1;
  }

  urlparse_url u;

  rv = urlparse_parse_url(uri.data(), uri.size(), 0, &u);

  if (rv != 0) {
    if (uri[0] == '/') {
      return -1;
    }

    // treat link_url as relative URI.
    auto end = std::ranges::find(uri, '#');
    auto q = std::ranges::find(std::ranges::begin(uri), end, '?');

    rel = std::string_view{std::ranges::begin(uri), q};
    if (q != end) {
      relq = std::string_view{q + 1, std::ranges::end(uri)};
    }
  } else {
    if (u.field_set & (1 << URLPARSE_SCHEMA)) {
      scheme = util::get_uri_field(uri.data(), u, URLPARSE_SCHEMA);
    }

    if (u.field_set & (1 << URLPARSE_HOST)) {
      auto auth = util::get_uri_field(uri.data(), u, URLPARSE_HOST);
      auto len = auth.size();
      auto port_exists = u.field_set & (1 << URLPARSE_PORT);
      if (port_exists) {
        len += 1 + str_size("65535");
      }
      auto iov = make_byte_ref(balloc, len + 1);
      auto p = std::ranges::begin(iov);
      p = std::ranges::copy(auth, p).out;
      if (port_exists) {
        *p++ = ':';
        p = util::utos(u.port, p);
      }
      *p = '\0';

      authority = as_string_view(std::ranges::begin(iov), p);
    }

    if (u.field_set & (1 << URLPARSE_PATH)) {
      auto &f = u.field_data[URLPARSE_PATH];
      rel = std::string_view{uri.data() + f.off, f.len};
    } else {
      rel = "/"sv;
    }

    if (u.field_set & (1 << URLPARSE_QUERY)) {
      auto &f = u.field_data[URLPARSE_QUERY];
      relq = std::string_view{uri.data() + f.off, f.len};
    }
  }

  path = path_join(balloc, base, ""sv, rel, relq);

  return 0;
}

namespace {
template <typename InputIt> InputIt eat_file(InputIt first, InputIt last) {
  if (first == last) {
    *first++ = '/';
    return first;
  }

  if (*(last - 1) == '/') {
    return last;
  }

  auto p = last;
  for (; p != first && *(p - 1) != '/'; --p)
    ;
  if (p == first) {
    // this should not happened in normal case, where we expect path
    // starts with '/'
    *first++ = '/';
    return first;
  }

  return p;
}
} // namespace

namespace {
template <typename InputIt> InputIt eat_dir(InputIt first, InputIt last) {
  auto p = eat_file(first, last);

  --p;

  assert(*p == '/');

  return eat_file(first, p);
}
} // namespace

std::string_view path_join(BlockAllocator &balloc,
                           const std::string_view &base_path,
                           const std::string_view &base_query,
                           const std::string_view &rel_path,
                           const std::string_view &rel_query) {
  auto res =
    make_byte_ref(balloc, std::max(static_cast<size_t>(1), base_path.size()) +
                            rel_path.size() + 1 +
                            std::max(base_query.size(), rel_query.size()) + 1);
  auto p = std::ranges::begin(res);

  if (rel_path.empty()) {
    if (base_path.empty()) {
      *p++ = '/';
    } else {
      p = std::ranges::copy(base_path, p).out;
    }
    if (rel_query.empty()) {
      if (!base_query.empty()) {
        *p++ = '?';
        p = std::ranges::copy(base_query, p).out;
      }
      *p = '\0';
      return as_string_view(std::ranges::begin(res), p);
    }
    *p++ = '?';
    p = std::ranges::copy(rel_query, p).out;
    *p = '\0';
    return as_string_view(std::ranges::begin(res), p);
  }

  auto first = std::ranges::begin(rel_path);
  auto last = std::ranges::end(rel_path);

  if (rel_path[0] == '/') {
    *p++ = '/';
    ++first;
    for (; first != last && *first == '/'; ++first)
      ;
  } else if (base_path.empty()) {
    *p++ = '/';
  } else {
    p = std::ranges::copy(base_path, p).out;
  }

  for (; first != last;) {
    if (*first == '.') {
      if (first + 1 == last) {
        if (*(p - 1) != '/') {
          p = eat_file(std::ranges::begin(res), p);
        }
        break;
      }
      if (*(first + 1) == '/') {
        if (*(p - 1) != '/') {
          p = eat_file(std::ranges::begin(res), p);
        }
        first += 2;
        continue;
      }
      if (*(first + 1) == '.') {
        if (first + 2 == last) {
          p = eat_dir(std::ranges::begin(res), p);
          break;
        }
        if (*(first + 2) == '/') {
          p = eat_dir(std::ranges::begin(res), p);
          first += 3;
          continue;
        }
      }
    }
    if (*(p - 1) != '/') {
      p = eat_file(std::ranges::begin(res), p);
    }
    auto slash = std::ranges::find(first, last, '/');
    if (slash == last) {
      p = std::ranges::copy(first, last, p).out;
      break;
    }
    p = std::ranges::copy(first, slash + 1, p).out;
    first = slash + 1;
    for (; first != last && *first == '/'; ++first)
      ;
  }
  if (!rel_query.empty()) {
    *p++ = '?';
    p = std::ranges::copy(rel_query, p).out;
  }
  *p = '\0';
  return as_string_view(std::ranges::begin(res), p);
}

std::string_view normalize_path(BlockAllocator &balloc,
                                const std::string_view &path,
                                const std::string_view &query) {
  // First, decode %XX for unreserved characters, then do
  // http2::path_join

  // We won't find %XX if length is less than 3.
  if (path.size() < 3 ||
      std::ranges::find(path, '%') == std::ranges::end(path)) {
    return path_join(balloc, ""sv, ""sv, path, query);
  }

  // includes last terminal NULL.
  auto result = make_byte_ref(balloc, path.size() + 1);
  auto p = std::ranges::begin(result);

  auto it = std::ranges::begin(path);
  for (; it + 2 < std::ranges::end(path);) {
    if (*it == '%') {
      if (util::is_hex_digit(*(it + 1)) && util::is_hex_digit(*(it + 2))) {
        auto c = static_cast<char>((util::hex_to_uint(*(it + 1)) << 4) +
                                   util::hex_to_uint(*(it + 2)));
        if (util::in_rfc3986_unreserved_chars(c)) {
          *p++ = as_unsigned(c);

          it += 3;

          continue;
        }
        *p++ = '%';
        *p++ = as_unsigned(util::upcase(*(it + 1)));
        *p++ = as_unsigned(util::upcase(*(it + 2)));

        it += 3;

        continue;
      }
    }
    *p++ = as_unsigned(*it++);
  }

  p = std::ranges::copy(it, std::ranges::end(path), p).out;
  *p = '\0';

  return path_join(balloc, ""sv, ""sv,
                   as_string_view(std::ranges::begin(result), p), query);
}

std::string_view normalize_path_colon(BlockAllocator &balloc,
                                      const std::string_view &path,
                                      const std::string_view &query) {
  // First, decode %XX for unreserved characters and ':', then do
  // http2::path_join

  // We won't find %XX if length is less than 3.
  if (path.size() < 3 ||
      std::ranges::find(path, '%') == std::ranges::end(path)) {
    return path_join(balloc, ""sv, ""sv, path, query);
  }

  // includes last terminal NULL.
  auto result = make_byte_ref(balloc, path.size() + 1);
  auto p = std::ranges::begin(result);

  auto it = std::ranges::begin(path);
  for (; it + 2 < std::ranges::end(path);) {
    if (*it == '%') {
      if (util::is_hex_digit(*(it + 1)) && util::is_hex_digit(*(it + 2))) {
        auto c = static_cast<char>((util::hex_to_uint(*(it + 1)) << 4) +
                                   util::hex_to_uint(*(it + 2)));
        if (util::in_rfc3986_unreserved_chars(c) || c == ':') {
          *p++ = as_unsigned(c);

          it += 3;

          continue;
        }
        *p++ = '%';
        *p++ = as_unsigned(util::upcase(*(it + 1)));
        *p++ = as_unsigned(util::upcase(*(it + 2)));

        it += 3;

        continue;
      }
    }
    *p++ = as_unsigned(*it++);
  }

  p = std::ranges::copy(it, std::ranges::end(path), p).out;
  *p = '\0';

  return path_join(balloc, ""sv, ""sv,
                   as_string_view(std::ranges::begin(result), p), query);
}

std::string normalize_path(const std::string_view &path,
                           const std::string_view &query) {
  BlockAllocator balloc(1024, 1024);

  return std::string{normalize_path(balloc, path, query)};
}

std::string_view rewrite_clean_path(BlockAllocator &balloc,
                                    const std::string_view &src) {
  if (src.empty() || src[0] != '/') {
    return src;
  }
  // probably, not necessary most of the case, but just in case.
  auto fragment = std::ranges::find(src, '#');
  auto raw_query = std::ranges::find(std::ranges::begin(src), fragment, '?');
  auto query = raw_query;
  if (query != fragment) {
    ++query;
  }
  return normalize_path(balloc,
                        std::string_view{std::ranges::begin(src), raw_query},
                        std::string_view{query, fragment});
}

bool contains_trailers(const std::string_view &s) {
  constexpr auto trailers = "trailers"sv;

  for (auto p = std::ranges::begin(s), end = std::ranges::end(s);; ++p) {
    p = std::ranges::find_if(p, end,
                             [](char c) { return c != ' ' && c != '\t'; });
    if (p == end || static_cast<size_t>(end - p) < trailers.size()) {
      return false;
    }
    if (util::strieq(trailers, std::string_view{p, p + trailers.size()})) {
      // Make sure that there is no character other than white spaces
      // before next "," or end of string.
      p = std::ranges::find_if(p + trailers.size(), end,
                               [](char c) { return c != ' ' && c != '\t'; });
      if (p == end || *p == ',') {
        return true;
      }
    }
    // Skip to next ",".
    p = std::ranges::find_if(p, end, [](char c) { return c == ','; });
    if (p == end) {
      return false;
    }
  }
}

std::string_view make_websocket_accept_token(uint8_t *dest,
                                             const std::string_view &key) {
  static constexpr auto magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"sv;
  std::array<char, base64::encode_length(16) + magic.size()> s;
  auto p = std::ranges::copy(key, std::ranges::begin(s)).out;
  std::ranges::copy(magic, p);

  std::array<uint8_t, 20> h;
  if (util::sha1(h.data(), as_string_view(s)) != 0) {
    return ""sv;
  }

  return as_string_view(dest, base64::encode(h, dest));
}

bool legacy_http1(int major, int minor) {
  return major <= 0 || (major == 1 && minor == 0);
}

bool check_transfer_encoding(const std::string_view &s) {
  if (s.empty()) {
    return false;
  }

  auto it = std::ranges::begin(s);

  for (;;) {
    // token
    if (!util::in_token(*it)) {
      return false;
    }

    ++it;

    for (; it != std::ranges::end(s) && util::in_token(*it); ++it)
      ;

    if (it == std::ranges::end(s)) {
      return true;
    }

    for (;;) {
      // OWS
      it = skip_lws(it, std::ranges::end(s));
      if (it == std::ranges::end(s)) {
        return false;
      }

      if (*it == ',') {
        ++it;

        it = skip_lws(it, std::ranges::end(s));
        if (it == std::ranges::end(s)) {
          return false;
        }

        break;
      }

      if (*it != ';') {
        return false;
      }

      ++it;

      // transfer-parameter follows

      // OWS
      it = skip_lws(it, std::ranges::end(s));
      if (it == std::ranges::end(s)) {
        return false;
      }

      // token
      if (!util::in_token(*it)) {
        return false;
      }

      ++it;

      for (; it != std::ranges::end(s) && util::in_token(*it); ++it)
        ;

      if (it == std::ranges::end(s)) {
        return false;
      }

      // No BWS allowed
      if (*it != '=') {
        return false;
      }

      ++it;

      if (util::in_token(*it)) {
        // token
        ++it;

        for (; it != std::ranges::end(s) && util::in_token(*it); ++it)
          ;
      } else if (*it == '"') {
        // quoted-string
        ++it;

        it = skip_to_right_dquote(it, std::ranges::end(s));
        if (it == std::ranges::end(s)) {
          return false;
        }

        ++it;
      } else {
        return false;
      }

      if (it == std::ranges::end(s)) {
        return true;
      }
    }
  }
}

std::string encode_extpri(const nghttp2_extpri &extpri) {
  std::string res = "u=";

  res += static_cast<char>(extpri.urgency) + '0';
  if (extpri.inc) {
    res += ",i";
  }

  return res;
}

} // namespace http2

} // namespace nghttp2
