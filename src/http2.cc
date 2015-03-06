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

#include "util.h"

namespace nghttp2 {

namespace http2 {

std::string get_status_string(unsigned int status_code) {
  switch (status_code) {
  case 100:
    return "100 Continue";
  case 101:
    return "101 Switching Protocols";
  case 200:
    return "200 OK";
  case 201:
    return "201 Created";
  case 202:
    return "202 Accepted";
  case 203:
    return "203 Non-Authoritative Information";
  case 204:
    return "204 No Content";
  case 205:
    return "205 Reset Content";
  case 206:
    return "206 Partial Content";
  case 300:
    return "300 Multiple Choices";
  case 301:
    return "301 Moved Permanently";
  case 302:
    return "302 Found";
  case 303:
    return "303 See Other";
  case 304:
    return "304 Not Modified";
  case 305:
    return "305 Use Proxy";
  // case 306: return "306 (Unused)";
  case 307:
    return "307 Temporary Redirect";
  case 308:
    return "308 Permanent Redirect";
  case 400:
    return "400 Bad Request";
  case 401:
    return "401 Unauthorized";
  case 402:
    return "402 Payment Required";
  case 403:
    return "403 Forbidden";
  case 404:
    return "404 Not Found";
  case 405:
    return "405 Method Not Allowed";
  case 406:
    return "406 Not Acceptable";
  case 407:
    return "407 Proxy Authentication Required";
  case 408:
    return "408 Request Timeout";
  case 409:
    return "409 Conflict";
  case 410:
    return "410 Gone";
  case 411:
    return "411 Length Required";
  case 412:
    return "412 Precondition Failed";
  case 413:
    return "413 Payload Too Large";
  case 414:
    return "414 URI Too Long";
  case 415:
    return "415 Unsupported Media Type";
  case 416:
    return "416 Requested Range Not Satisfiable";
  case 417:
    return "417 Expectation Failed";
  case 421:
    return "421 Misdirected Request";
  case 426:
    return "426 Upgrade Required";
  case 428:
    return "428 Precondition Required";
  case 429:
    return "429 Too Many Requests";
  case 431:
    return "431 Request Header Fields Too Large";
  case 500:
    return "500 Internal Server Error";
  case 501:
    return "501 Not Implemented";
  case 502:
    return "502 Bad Gateway";
  case 503:
    return "503 Service Unavailable";
  case 504:
    return "504 Gateway Timeout";
  case 505:
    return "505 HTTP Version Not Supported";
  case 511:
    return "511 Network Authentication Required";
  default:
    return util::utos(status_code);
  }
}

void capitalize(std::string &s, size_t offset) {
  s[offset] = util::upcase(s[offset]);
  for (size_t i = offset + 1, eoi = s.size(); i < eoi; ++i) {
    if (s[i - 1] == '-') {
      s[i] = util::upcase(s[i]);
    } else {
      s[i] = util::lowcase(s[i]);
    }
  }
}

bool lws(const char *value) {
  for (; *value; ++value) {
    switch (*value) {
    case '\t':
    case ' ':
      continue;
    default:
      return false;
    }
  }
  return true;
}

void copy_url_component(std::string &dest, const http_parser_url *u, int field,
                        const char *url) {
  if (u->field_set & (1 << field)) {
    dest.assign(url + u->field_data[field].off, u->field_data[field].len);
  }
}

Headers::value_type to_header(const uint8_t *name, size_t namelen,
                              const uint8_t *value, size_t valuelen,
                              bool no_index, int16_t token) {
  return Header(std::string(reinterpret_cast<const char *>(name), namelen),
                std::string(reinterpret_cast<const char *>(value), valuelen),
                no_index, token);
}

void add_header(Headers &nva, const uint8_t *name, size_t namelen,
                const uint8_t *value, size_t valuelen, bool no_index,
                int16_t token) {
  if (valuelen > 0) {
    size_t i, j;
    for (i = 0; i < valuelen && (value[i] == ' ' || value[i] == '\t'); ++i)
      ;
    for (j = valuelen - 1; j > i && (value[j] == ' ' || value[j] == '\t'); --j)
      ;
    value += i;
    valuelen -= i + (valuelen - j - 1);
  }
  nva.push_back(to_header(name, namelen, value, valuelen, no_index, token));
}

const Headers::value_type *get_header(const Headers &nva, const char *name) {
  const Headers::value_type *res = nullptr;
  for (auto &nv : nva) {
    if (nv.name == name) {
      res = &nv;
    }
  }
  return res;
}

std::string value_to_str(const Headers::value_type *nv) {
  if (nv) {
    return nv->value;
  }
  return "";
}

bool non_empty_value(const Headers::value_type *nv) {
  return nv && !nv->value.empty();
}

nghttp2_nv make_nv(const std::string &name, const std::string &value,
                   bool no_index) {
  uint8_t flags;

  flags = no_index ? NGHTTP2_NV_FLAG_NO_INDEX : NGHTTP2_NV_FLAG_NONE;

  return {(uint8_t *)name.c_str(), (uint8_t *)value.c_str(), name.size(),
          value.size(), flags};
}

void copy_headers_to_nva(std::vector<nghttp2_nv> &nva, const Headers &headers) {
  for (auto &kv : headers) {
    if (kv.name.empty() || kv.name[0] == ':') {
      continue;
    }
    switch (kv.token) {
    case HD_COOKIE:
    case HD_CONNECTION:
    case HD_HOST:
    case HD_HTTP2_SETTINGS:
    case HD_KEEP_ALIVE:
    case HD_PROXY_CONNECTION:
    case HD_SERVER:
    case HD_TRAILER:
    case HD_TRANSFER_ENCODING:
    case HD_UPGRADE:
    case HD_VIA:
    case HD_X_FORWARDED_FOR:
    case HD_X_FORWARDED_PROTO:
      continue;
    }
    nva.push_back(make_nv(kv.name, kv.value, kv.no_index));
  }
}

void build_http1_headers_from_headers(std::string &hdrs,
                                      const Headers &headers) {
  for (auto &kv : headers) {
    if (kv.name.empty() || kv.name[0] == ':') {
      continue;
    }
    switch (kv.token) {
    case HD_CONNECTION:
    case HD_COOKIE:
    case HD_HOST:
    case HD_HTTP2_SETTINGS:
    case HD_KEEP_ALIVE:
    case HD_PROXY_CONNECTION:
    case HD_SERVER:
    case HD_TRAILER:
    case HD_UPGRADE:
    case HD_VIA:
    case HD_X_FORWARDED_FOR:
    case HD_X_FORWARDED_PROTO:
      continue;
    }
    hdrs += kv.name;
    capitalize(hdrs, hdrs.size() - kv.name.size());
    hdrs += ": ";
    hdrs += kv.value;
    hdrs += "\r\n";
  }
}

int32_t determine_window_update_transmission(nghttp2_session *session,
                                             int32_t stream_id) {
  int32_t recv_length, window_size;
  if (stream_id == 0) {
    recv_length = nghttp2_session_get_effective_recv_data_length(session);
    window_size = nghttp2_session_get_effective_local_window_size(session);
  } else {
    recv_length = nghttp2_session_get_stream_effective_recv_data_length(
        session, stream_id);
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

void dump_nv(FILE *out, const char **nv) {
  for (size_t i = 0; nv[i]; i += 2) {
    fwrite(nv[i], strlen(nv[i]), 1, out);
    fwrite(": ", 2, 1, out);
    fwrite(nv[i + 1], strlen(nv[i + 1]), 1, out);
    fwrite("\n", 1, 1, out);
  }
  fwrite("\n", 1, 1, out);
  fflush(out);
}

void dump_nv(FILE *out, const nghttp2_nv *nva, size_t nvlen) {
  auto end = nva + nvlen;
  for (; nva != end; ++nva) {
    fwrite(nva->name, nva->namelen, 1, out);
    fwrite(": ", 2, 1, out);
    fwrite(nva->value, nva->valuelen, 1, out);
    fwrite("\n", 1, 1, out);
  }
  fwrite("\n", 1, 1, out);
  fflush(out);
}

void dump_nv(FILE *out, const Headers &nva) {
  for (auto &nv : nva) {
    fwrite(nv.name.c_str(), nv.name.size(), 1, out);
    fwrite(": ", 2, 1, out);
    fwrite(nv.value.c_str(), nv.value.size(), 1, out);
    fwrite("\n", 1, 1, out);
  }
  fwrite("\n", 1, 1, out);
  fflush(out);
}

std::string rewrite_location_uri(const std::string &uri,
                                 const http_parser_url &u,
                                 const std::string &match_host,
                                 const std::string &request_authority,
                                 const std::string &upstream_scheme) {
  // We just rewrite scheme and authority.
  if ((u.field_set & (1 << UF_HOST)) == 0) {
    return "";
  }
  auto field = &u.field_data[UF_HOST];
  if (!util::startsWith(std::begin(match_host), std::end(match_host),
                        &uri[field->off], &uri[field->off] + field->len) ||
      (match_host.size() != field->len && match_host[field->len] != ':')) {
    return "";
  }
  std::string res;
  if (!request_authority.empty()) {
    res += upstream_scheme;
    res += "://";
    res += request_authority;
  }
  if (u.field_set & (1 << UF_PATH)) {
    field = &u.field_data[UF_PATH];
    res.append(&uri[field->off], field->len);
  }
  if (u.field_set & (1 << UF_QUERY)) {
    field = &u.field_data[UF_QUERY];
    res += "?";
    res.append(&uri[field->off], field->len);
  }
  if (u.field_set & (1 << UF_FRAGMENT)) {
    field = &u.field_data[UF_FRAGMENT];
    res += "#";
    res.append(&uri[field->off], field->len);
  }
  return res;
}

int check_nv(const uint8_t *name, size_t namelen, const uint8_t *value,
             size_t valuelen) {
  if (!nghttp2_check_header_name(name, namelen)) {
    return 0;
  }
  if (!nghttp2_check_header_value(value, valuelen)) {
    return 0;
  }
  return 1;
}

int parse_http_status_code(const std::string &src) {
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

int lookup_token(const std::string &name) {
  return lookup_token(reinterpret_cast<const uint8_t *>(name.c_str()),
                      name.size());
}

// This function was generated by genheaderfunc.py.  Inspired by h2o
// header lookup.  https://github.com/h2o/h2o
int lookup_token(const uint8_t *name, size_t namelen) {
  switch (namelen) {
  case 2:
    switch (name[namelen - 1]) {
    case 'e':
      if (util::streq_l("t", name, 1)) {
        return HD_TE;
      }
      break;
    }
    break;
  case 3:
    switch (name[namelen - 1]) {
    case 'a':
      if (util::streq_l("vi", name, 2)) {
        return HD_VIA;
      }
      break;
    }
    break;
  case 4:
    switch (name[namelen - 1]) {
    case 'k':
      if (util::streq_l("lin", name, 3)) {
        return HD_LINK;
      }
      break;
    case 't':
      if (util::streq_l("hos", name, 3)) {
        return HD_HOST;
      }
      break;
    }
    break;
  case 5:
    switch (name[namelen - 1]) {
    case 'h':
      if (util::streq_l(":pat", name, 4)) {
        return HD__PATH;
      }
      break;
    case 't':
      if (util::streq_l(":hos", name, 4)) {
        return HD__HOST;
      }
      break;
    }
    break;
  case 6:
    switch (name[namelen - 1]) {
    case 'e':
      if (util::streq_l("cooki", name, 5)) {
        return HD_COOKIE;
      }
      break;
    case 'r':
      if (util::streq_l("serve", name, 5)) {
        return HD_SERVER;
      }
      break;
    case 't':
      if (util::streq_l("expec", name, 5)) {
        return HD_EXPECT;
      }
      break;
    }
    break;
  case 7:
    switch (name[namelen - 1]) {
    case 'c':
      if (util::streq_l("alt-sv", name, 6)) {
        return HD_ALT_SVC;
      }
      break;
    case 'd':
      if (util::streq_l(":metho", name, 6)) {
        return HD__METHOD;
      }
      break;
    case 'e':
      if (util::streq_l(":schem", name, 6)) {
        return HD__SCHEME;
      }
      if (util::streq_l("upgrad", name, 6)) {
        return HD_UPGRADE;
      }
      break;
    case 'r':
      if (util::streq_l("traile", name, 6)) {
        return HD_TRAILER;
      }
      break;
    case 's':
      if (util::streq_l(":statu", name, 6)) {
        return HD__STATUS;
      }
      break;
    }
    break;
  case 8:
    switch (name[namelen - 1]) {
    case 'n':
      if (util::streq_l("locatio", name, 7)) {
        return HD_LOCATION;
      }
      break;
    }
    break;
  case 10:
    switch (name[namelen - 1]) {
    case 'e':
      if (util::streq_l("keep-aliv", name, 9)) {
        return HD_KEEP_ALIVE;
      }
      break;
    case 'n':
      if (util::streq_l("connectio", name, 9)) {
        return HD_CONNECTION;
      }
      break;
    case 't':
      if (util::streq_l("user-agen", name, 9)) {
        return HD_USER_AGENT;
      }
      break;
    case 'y':
      if (util::streq_l(":authorit", name, 9)) {
        return HD__AUTHORITY;
      }
      break;
    }
    break;
  case 13:
    switch (name[namelen - 1]) {
    case 'l':
      if (util::streq_l("cache-contro", name, 12)) {
        return HD_CACHE_CONTROL;
      }
      break;
    }
    break;
  case 14:
    switch (name[namelen - 1]) {
    case 'h':
      if (util::streq_l("content-lengt", name, 13)) {
        return HD_CONTENT_LENGTH;
      }
      break;
    case 's':
      if (util::streq_l("http2-setting", name, 13)) {
        return HD_HTTP2_SETTINGS;
      }
      break;
    }
    break;
  case 15:
    switch (name[namelen - 1]) {
    case 'e':
      if (util::streq_l("accept-languag", name, 14)) {
        return HD_ACCEPT_LANGUAGE;
      }
      break;
    case 'g':
      if (util::streq_l("accept-encodin", name, 14)) {
        return HD_ACCEPT_ENCODING;
      }
      break;
    case 'r':
      if (util::streq_l("x-forwarded-fo", name, 14)) {
        return HD_X_FORWARDED_FOR;
      }
      break;
    }
    break;
  case 16:
    switch (name[namelen - 1]) {
    case 'n':
      if (util::streq_l("proxy-connectio", name, 15)) {
        return HD_PROXY_CONNECTION;
      }
      break;
    }
    break;
  case 17:
    switch (name[namelen - 1]) {
    case 'e':
      if (util::streq_l("if-modified-sinc", name, 16)) {
        return HD_IF_MODIFIED_SINCE;
      }
      break;
    case 'g':
      if (util::streq_l("transfer-encodin", name, 16)) {
        return HD_TRANSFER_ENCODING;
      }
      break;
    case 'o':
      if (util::streq_l("x-forwarded-prot", name, 16)) {
        return HD_X_FORWARDED_PROTO;
      }
      break;
    }
    break;
  }
  return -1;
}

void init_hdidx(HeaderIndex &hdidx) {
  std::fill(std::begin(hdidx), std::end(hdidx), -1);
}

void index_header(HeaderIndex &hdidx, int16_t token, size_t idx) {
  if (token == -1) {
    return;
  }
  assert(token < HD_MAXIDX);
  hdidx[token] = idx;
}

bool check_http2_request_pseudo_header(const HeaderIndex &hdidx,
                                       int16_t token) {
  switch (token) {
  case HD__AUTHORITY:
  case HD__METHOD:
  case HD__PATH:
  case HD__SCHEME:
    return hdidx[token] == -1;
  default:
    return false;
  }
}

bool check_http2_response_pseudo_header(const HeaderIndex &hdidx,
                                        int16_t token) {
  switch (token) {
  case HD__STATUS:
    return hdidx[token] == -1;
  default:
    return false;
  }
}

bool http2_header_allowed(int16_t token) {
  switch (token) {
  case HD_CONNECTION:
  case HD_KEEP_ALIVE:
  case HD_PROXY_CONNECTION:
  case HD_TRANSFER_ENCODING:
  case HD_UPGRADE:
    return false;
  default:
    return true;
  }
}

bool http2_mandatory_request_headers_presence(const HeaderIndex &hdidx) {
  if (hdidx[HD__METHOD] == -1 || hdidx[HD__PATH] == -1 ||
      hdidx[HD__SCHEME] == -1 ||
      (hdidx[HD__AUTHORITY] == -1 && hdidx[HD_HOST] == -1)) {
    return false;
  }
  return true;
}

const Headers::value_type *get_header(const HeaderIndex &hdidx, int16_t token,
                                      const Headers &nva) {
  auto i = hdidx[token];
  if (i == -1) {
    return nullptr;
  }
  return &nva[i];
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
    case '\\':
      ++first;
      if (first == last) {
        return first;
      }
      break;
    }
    ++first;
  }
  return first;
}
} // namespace

namespace {
std::pair<LinkHeader, const char *>
parse_next_link_header_once(const char *first, const char *last) {
  first = skip_to_next_field(first, last);
  if (first == last || *first != '<') {
    return {{{nullptr, nullptr}}, last};
  }
  auto url_first = ++first;
  first = std::find(first, last, '>');
  if (first == last) {
    return {{{nullptr, nullptr}}, first};
  }
  auto url_last = first++;
  if (first == last) {
    return {{{nullptr, nullptr}}, first};
  }
  // we expect ';' or ',' here
  switch (*first) {
  case ',':
    return {{{nullptr, nullptr}}, ++first};
  case ';':
    ++first;
    break;
  default:
    return {{{nullptr, nullptr}}, last};
  }

  auto ok = false;
  auto ign = false;
  for (;;) {
    first = skip_lws(first, last);
    if (first == last) {
      return {{{nullptr, nullptr}}, first};
    }
    // we expect link-param

    // rel can take several relations using quoted form.
    static const char PLP[] = "rel=\"";
    static const size_t PLPLEN = sizeof(PLP) - 1;

    static const char PLT[] = "preload";
    static const size_t PLTLEN = sizeof(PLT) - 1;
    if (first + PLPLEN < last && *(first + PLPLEN - 1) == '"' &&
        std::equal(PLP, PLP + PLPLEN, first, util::CaseCmp())) {
      // we have to search preload in whitespace separated list:
      // rel="preload something http://example.org/foo"
      first += PLPLEN;
      auto start = first;
      for (; first != last;) {
        if (*first != ' ' && *first != '"') {
          ++first;
          continue;
        }

        if (start == first) {
          return {{{nullptr, nullptr}}, last};
        }

        if (!ok && start + PLTLEN == first &&
            std::equal(PLT, PLT + PLTLEN, start, util::CaseCmp())) {
          ok = true;
        }

        if (*first == '"') {
          break;
        }
        first = skip_lws(first, last);
        start = first;
      }
      if (first == last) {
        return {{{nullptr, nullptr}}, first};
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
      return {{{nullptr, nullptr}}, last};
    }
    // we are only interested in rel=preload parameter.  Others are
    // simply skipped.
    static const char PL[] = "rel=preload";
    static const size_t PLLEN = sizeof(PL) - 1;
    if (first + PLLEN == last) {
      if (std::equal(PL, PL + PLLEN, first, util::CaseCmp())) {
        ok = true;
        // this is the end of sequence
        return {{{url_first, url_last}}, last};
      }
    } else if (first + PLLEN + 1 <= last) {
      switch (*(first + PLLEN)) {
      case ',':
        if (!std::equal(PL, PL + PLLEN, first, util::CaseCmp())) {
          break;
        }
        ok = true;
        // skip including ','
        first += PLLEN + 1;
        return {{{url_first, url_last}}, first};
      case ';':
        if (!std::equal(PL, PL + PLLEN, first, util::CaseCmp())) {
          break;
        }
        ok = true;
        // skip including ';'
        first += PLLEN + 1;
        // continue parse next link-param
        continue;
      }
    }
    // we have to reject URI if we have nonempty anchor parameter.
    static const char ANCHOR[] = "anchor=";
    static const size_t ANCHORLEN = sizeof(ANCHOR) - 1;
    if (!ign && first + ANCHORLEN <= last) {
      if (std::equal(ANCHOR, ANCHOR + ANCHORLEN, first, util::CaseCmp())) {
        // we only accept URI if anchor="" here.
        if (first + ANCHORLEN + 2 <= last) {
          if (*(first + ANCHORLEN) != '"' || *(first + ANCHORLEN + 1) != '"') {
            ign = true;
          }
        } else {
          // here we got invalid production (anchor=") or anchor=?
          ign = true;
        }
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
      return {{{nullptr, nullptr}}, last};
    }
    if (param_first == first) {
      // empty parmname
      return {{{nullptr, nullptr}}, last};
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
      return {{{nullptr, nullptr}}, first};
    }
    if (*first == '"') {
      // quoted-string
      first = skip_to_right_dquote(first + 1, last);
      if (first == last) {
        return {{{nullptr, nullptr}}, first};
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
      return {{{nullptr, nullptr}}, last};
    }
    // not quoted-string, skip to next ',' or ';'
    if (*first == ',' || *first == ';') {
      // empty value
      return {{{nullptr, nullptr}}, last};
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
  return {{{nullptr, nullptr}}, first};
}
} // namespace

std::vector<LinkHeader> parse_link_header(const char *src, size_t len) {
  auto first = src;
  auto last = src + len;
  std::vector<LinkHeader> res;
  for (; first != last;) {
    auto rv = parse_next_link_header_once(first, last);
    first = rv.second;
    if (rv.first.uri.first != nullptr && rv.first.uri.second != nullptr) {
      res.push_back(rv.first);
    }
  }
  return res;
}

namespace {
void eat_file(std::string &path) {
  if (path.empty()) {
    path = "/";
    return;
  }
  auto p = path.size() - 1;
  if (path[p] == '/') {
    return;
  }
  p = path.rfind('/', p);
  if (p == std::string::npos) {
    // this should not happend in normal case, where we expect path
    // starts with '/'
    path = "/";
    return;
  }
  path.erase(std::begin(path) + p + 1, std::end(path));
}
} // namespace

namespace {
void eat_dir(std::string &path) {
  if (path.empty()) {
    path = "/";
    return;
  }
  auto p = path.size() - 1;
  if (path[p] != '/') {
    p = path.rfind('/', p);
    if (p == std::string::npos) {
      // this should not happend in normal case, where we expect path
      // starts with '/'
      path = "/";
      return;
    }
  }
  if (path[p] == '/') {
    if (p == 0) {
      return;
    }
    --p;
  }
  p = path.rfind('/', p);
  if (p == std::string::npos) {
    // this should not happend in normal case, where we expect path
    // starts with '/'
    path = "/";
    return;
  }
  path.erase(std::begin(path) + p + 1, std::end(path));
}
} // namespace

std::string path_join(const char *base_path, size_t base_pathlen,
                      const char *base_query, size_t base_querylen,
                      const char *rel_path, size_t rel_pathlen,
                      const char *rel_query, size_t rel_querylen) {
  std::string res;
  if (rel_pathlen == 0) {
    if (base_pathlen == 0) {
      res = "/";
    } else {
      res.assign(base_path, base_pathlen);
    }
    if (rel_querylen == 0) {
      if (base_querylen) {
        res += "?";
        res.append(base_query, base_querylen);
      }
      return res;
    }
    res += "?";
    res.append(rel_query, rel_querylen);
    return res;
  }

  auto first = rel_path;
  auto last = rel_path + rel_pathlen;

  if (rel_path[0] == '/') {
    res = "/";
    ++first;
  } else if (base_pathlen == 0) {
    res = "/";
  } else {
    res.assign(base_path, base_pathlen);
  }

  for (; first != last;) {
    if (*first == '.') {
      if (first + 1 == last) {
        break;
      }
      if (*(first + 1) == '/') {
        first += 2;
        continue;
      }
      if (*(first + 1) == '.') {
        if (first + 2 == last) {
          eat_dir(res);
          break;
        }
        if (*(first + 2) == '/') {
          eat_dir(res);
          first += 3;
          continue;
        }
      }
    }
    if (res.back() != '/') {
      eat_file(res);
    }
    auto slash = std::find(first, last, '/');
    if (slash == last) {
      res.append(first, last);
      break;
    }
    res.append(first, slash + 1);
    first = slash + 1;
    for (; first != last && *first == '/'; ++first)
      ;
  }
  if (rel_querylen) {
    res += "?";
    res.append(rel_query, rel_querylen);
  }
  return res;
}

bool expect_response_body(int status_code) {
  return status_code / 100 != 1 && status_code != 304 && status_code != 204;
}

bool expect_response_body(const std::string &method, int status_code) {
  return method != "HEAD" && expect_response_body(status_code);
}

} // namespace http2

} // namespace nghttp2
