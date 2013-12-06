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
#include "http2.h"

#include "util.h"

namespace nghttp2 {

namespace http2 {

std::string get_status_string(unsigned int status_code)
{
  switch(status_code) {
  case 100: return "100 Continue";
  case 101: return "101 Switching Protocols";
  case 200: return "200 OK";
  case 201: return "201 Created";
  case 202: return "202 Accepted";
  case 203: return "203 Non-Authoritative Information";
  case 204: return "204 No Content";
  case 205: return "205 Reset Content";
  case 206: return "206 Partial Content";
  case 300: return "300 Multiple Choices";
  case 301: return "301 Moved Permanently";
  case 302: return "302 Found";
  case 303: return "303 See Other";
  case 304: return "304 Not Modified";
  case 305: return "305 Use Proxy";
    // case 306: return "306 (Unused)";
  case 307: return "307 Temporary Redirect";
  case 400: return "400 Bad Request";
  case 401: return "401 Unauthorized";
  case 402: return "402 Payment Required";
  case 403: return "403 Forbidden";
  case 404: return "404 Not Found";
  case 405: return "405 Method Not Allowed";
  case 406: return "406 Not Acceptable";
  case 407: return "407 Proxy Authentication Required";
  case 408: return "408 Request Timeout";
  case 409: return "409 Conflict";
  case 410: return "410 Gone";
  case 411: return "411 Length Required";
  case 412: return "412 Precondition Failed";
  case 413: return "413 Request Entity Too Large";
  case 414: return "414 Request-URI Too Long";
  case 415: return "415 Unsupported Media Type";
  case 416: return "416 Requested Range Not Satisfiable";
  case 417: return "417 Expectation Failed";
  case 500: return "500 Internal Server Error";
  case 501: return "501 Not Implemented";
  case 502: return "502 Bad Gateway";
  case 503: return "503 Service Unavailable";
  case 504: return "504 Gateway Timeout";
  case 505: return "505 HTTP Version Not Supported";
  default: return util::utos(status_code);
  }
}

void capitalize(std::string& s, size_t offset)
{
  s[offset] = util::upcase(s[offset]);
  for(size_t i = offset+1, eoi = s.size(); i < eoi; ++i) {
    if(s[i-1] == '-') {
      s[i] = util::upcase(s[i]);
    } else {
      s[i] = util::lowcase(s[i]);
    }
  }
}

bool check_header_value(const char *value)
{
  return strpbrk(value, "\r\n") == nullptr;
}

bool check_header_value(const nghttp2_nv* nv)
{
  size_t i;
  for(i = 0; i < nv->valuelen; ++i) {
    if(nv->value[i] == '\r' || nv->value[i] == '\n') {
      return false;
    }
  }
  return true;
}

void sanitize_header_value(std::string& s, size_t offset)
{
  for(size_t i = offset, eoi = s.size(); i < eoi; ++i) {
    if(s[i] == '\r' || s[i] == '\n') {
      s[i] = ' ';
    }
  }
}

void copy_url_component(std::string& dest, http_parser_url *u, int field,
                        const char* url)
{
  if(u->field_set & (1 << field)) {
    dest.assign(url+u->field_data[field].off, u->field_data[field].len);
  }
}

bool check_http2_allowed_header(const char *name)
{
  return check_http2_allowed_header(reinterpret_cast<const uint8_t*>(name),
                                    strlen(name));
}

bool check_http2_allowed_header(const uint8_t *name, size_t namelen)
{
  return
    !util::strieq("connection", name, namelen) &&
    !util::strieq("host", name, namelen) &&
    !util::strieq("keep-alive", name, namelen) &&
    !util::strieq("proxy-connection", name, namelen) &&
    !util::strieq("te", name, namelen) &&
    !util::strieq("transfer-encoding", name, namelen) &&
    !util::strieq("upgrade", name, namelen);
}

namespace {
const char *DISALLOWED_HD[] = {
  "connection",
  "keep-alive",
  "proxy-connection",
  "te",
  "transfer-encoding",
  "upgrade",
};
} // namespace

namespace {
size_t DISALLOWED_HDLEN = sizeof(DISALLOWED_HD)/sizeof(DISALLOWED_HD[0]);
} // namespace

namespace {
const char *IGN_HD[] = {
  "connection",
  "expect",
  "http2-settings",
  "keep-alive",
  "proxy-connection",
  "te",
  "transfer-encoding",
  "upgrade",
  "via",
  "x-forwarded-for",
  "x-forwarded-proto",
};
} // namespace

namespace {
size_t IGN_HDLEN = sizeof(IGN_HD)/sizeof(IGN_HD[0]);
} // namespace

namespace {
const char *HTTP1_IGN_HD[] = {
  "connection",
  "cookie",
  "expect",
  "http2-settings",
  "keep-alive",
  "proxy-connection",
  "upgrade",
  "via",
  "x-forwarded-for",
  "x-forwarded-proto",
};
} // namespace

namespace {
size_t HTTP1_IGN_HDLEN = sizeof(HTTP1_IGN_HD)/sizeof(HTTP1_IGN_HD[0]);
} // namespace

namespace {
auto nv_name_less = [](const nghttp2_nv& lhs, const nghttp2_nv& rhs)
{
  return nghttp2_nv_compare_name(&lhs, &rhs) < 0;
};
} // namespace

bool check_http2_headers(const std::vector<nghttp2_nv>& nva)
{
  for(size_t i = 0; i < DISALLOWED_HDLEN; ++i) {
    nghttp2_nv nv = {(uint8_t*)DISALLOWED_HD[i], nullptr,
                     (uint16_t)strlen(DISALLOWED_HD[i]), 0};
    if(std::binary_search(std::begin(nva), std::end(nva), nv, nv_name_less)) {
      return false;
    }
  }
  return true;
}

std::vector<nghttp2_nv> sort_nva(const nghttp2_nv *nva, size_t nvlen)
{
  auto v = std::vector<nghttp2_nv>(&nva[0], &nva[nvlen]);
  std::sort(std::begin(v), std::end(v), nv_name_less);
  auto res = std::vector<nghttp2_nv>();
  res.reserve(nvlen);
  for(size_t i = 0; i < nvlen; ++i) {
    if(v[i].valuelen == 0) {
      res.push_back(v[i]);
      continue;
    }
    auto j = v[i].value;
    auto end = v[i].value + v[i].valuelen;
    for(;;) {
      // Skip 0 length value
      j = std::find_if_not(j, end,
                           [](uint8_t c)
                           {
                             return c == '\0';
                           });
      if(j == end) {
        break;
      }
      auto l = std::find(j, end, '\0');
      res.push_back({v[i].name, j, v[i].namelen, static_cast<uint16_t>(l-j)});
      j = l;
    }
  }
  return res;
}

const nghttp2_nv* get_unique_header(const std::vector<nghttp2_nv>& nva,
                                    const char *name)
{
  size_t namelen = strlen(name);
  nghttp2_nv nv = {(uint8_t*)name, nullptr, (uint16_t)namelen, 0};
  auto i = std::lower_bound(std::begin(nva), std::end(nva), nv, nv_name_less);
  if(i != std::end(nva) && util::streq((*i).name, (*i).namelen,
                                       (const uint8_t*)name, namelen)) {
    auto j = i + 1;
    if(j == std::end(nva) || !util::streq((*j).name, (*j).namelen,
                                          (const uint8_t*)name, namelen)) {
      return &(*i);
    }
  }
  return nullptr;
}

const nghttp2_nv* get_header(const std::vector<nghttp2_nv>& nva,
                             const char *name)
{
  size_t namelen = strlen(name);
  nghttp2_nv nv = {(uint8_t*)name, nullptr, (uint16_t)namelen, 0};
  auto i = std::lower_bound(std::begin(nva), std::end(nva), nv, nv_name_less);
  if(i != std::end(nva) && util::streq((*i).name, (*i).namelen,
                                       (const uint8_t*)name, namelen)) {
    return &(*i);
  }
  return nullptr;
}

std::string name_to_str(const nghttp2_nv *nv)
{
  if(nv) {
    return std::string(reinterpret_cast<const char*>(nv->name), nv->namelen);
  }
  return "";
}

std::string value_to_str(const nghttp2_nv *nv)
{
  if(nv) {
    return std::string(reinterpret_cast<const char*>(nv->value), nv->valuelen);
  }
  return "";
}

bool value_lws(const nghttp2_nv *nv)
{
  for(size_t i = 0; i < nv->valuelen; ++i) {
    switch(nv->value[i]) {
    case '\t':
    case ' ':
      continue;
    default:
      return false;
    }
  }
  return true;
}

bool non_empty_value(const nghttp2_nv* nv)
{
  return nv && !http2::value_lws(nv) && http2::check_header_value(nv);
}

nghttp2_nv make_nv(const std::string& name, const std::string& value)
{
  return {
    (uint8_t*)name.c_str(),
      (uint8_t*)value.c_str(),
      (uint16_t)name.size(), (uint16_t)value.size()
      };
}

std::vector<std::pair<std::string, std::string>>
concat_norm_headers
(std::vector<std::pair<std::string, std::string>> headers)
{
  auto res = std::vector<std::pair<std::string, std::string>>();
  res.reserve(headers.size());
  for(auto& kv : headers) {
    if(!res.empty() && res.back().first == kv.first &&
       kv.first != "cookie" && kv.first != "set-cookie") {
      if(!kv.second.empty()) {
        res.back().second.append(1, '\0');
        res.back().second += kv.second;
      }
    } else {
      res.push_back(std::move(kv));
    }
  }
  return res;
}

void copy_norm_headers_to_nva
(std::vector<nghttp2_nv>& nva,
 const std::vector<std::pair<std::string, std::string>>& headers)
{
  size_t i, j;
  for(i = 0, j = 0; i < headers.size() && j < IGN_HDLEN;) {
    int rv = strcmp(headers[i].first.c_str(), IGN_HD[j]);
    if(rv < 0) {
      nva.push_back(make_nv(headers[i].first, headers[i].second));
      ++i;
    } else if(rv > 0) {
      ++j;
    } else {
      ++i;
    }
  }
  for(; i < headers.size(); ++i) {
    nva.push_back(make_nv(headers[i].first, headers[i].second));
  }
}

void build_http1_headers_from_norm_headers
(std::string& hdrs,
 const std::vector<std::pair<std::string,
 std::string>>& headers)
{
  size_t i, j;
  for(i = 0, j = 0; i < headers.size() && j < HTTP1_IGN_HDLEN;) {
    int rv = strcmp(headers[i].first.c_str(), HTTP1_IGN_HD[j]);
    if(rv < 0) {
      hdrs += headers[i].first;
      capitalize(hdrs, hdrs.size()-headers[i].first.size());
      hdrs += ": ";
      hdrs += headers[i].second;
      sanitize_header_value(hdrs, hdrs.size() - headers[i].second.size());
      hdrs += "\r\n";
      ++i;
    } else if(rv > 0) {
      ++j;
    } else {
      ++i;
    }
  }
  for(; i < headers.size(); ++i) {
    hdrs += headers[i].first;
    capitalize(hdrs, hdrs.size()-headers[i].first.size());
    hdrs += ": ";
    hdrs += headers[i].second;
    sanitize_header_value(hdrs, hdrs.size() - headers[i].second.size());
    hdrs += "\r\n";
  }
}

int32_t determine_window_update_transmission(nghttp2_session *session,
                                             int32_t stream_id)
{
  int32_t recv_length, window_size;
  if(stream_id == 0) {
    recv_length = nghttp2_session_get_effective_recv_data_length(session);
    window_size = nghttp2_session_get_effective_local_window_size(session);
  } else {
    recv_length = nghttp2_session_get_stream_effective_recv_data_length
      (session, stream_id);
    window_size = nghttp2_session_get_stream_effective_local_window_size
      (session, stream_id);
  }
  if(recv_length != -1 && window_size != -1) {
    if(recv_length >= window_size / 2) {
      return recv_length;
    }
  }
  return -1;
}

void dump_nv(FILE *out, const char **nv)
{
  for(size_t i = 0; nv[i]; i += 2) {
    fwrite(nv[i], strlen(nv[i]), 1, out);
    fwrite(": ", 2, 1, out);
    fwrite(nv[i+1], strlen(nv[i+1]), 1, out);
    fwrite("\n", 1, 1, out);
  }
  fwrite("\n", 1, 1, out);
  fflush(out);
}

void dump_nv(FILE *out, const nghttp2_nv *nva, size_t nvlen)
{
  // |nva| may have NULL-concatenated header fields
  auto v = sort_nva(nva, nvlen);
  for(auto& nv : v) {
    fwrite(nv.name, nv.namelen, 1, out);
    fwrite(": ", 2, 1, out);
    fwrite(nv.value, nv.valuelen, 1, out);
    fwrite("\n", 1, 1, out);
  }
  fwrite("\n", 1, 1, out);
  fflush(out);
}

} // namespace http2

} // namespace nghttp2
