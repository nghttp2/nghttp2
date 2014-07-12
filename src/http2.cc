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
  case 413: return "413 Payload Too Large";
  case 414: return "414 URI Too Long";
  case 415: return "415 Unsupported Media Type";
  case 416: return "416 Requested Range Not Satisfiable";
  case 417: return "417 Expectation Failed";
  case 426: return "426 Upgrade Required";
  case 428: return "428 Precondition Required";
  case 429: return "429 Too Many Requests";
  case 431: return "431 Request Header Fields Too Large";
  case 500: return "500 Internal Server Error";
  case 501: return "501 Not Implemented";
  case 502: return "502 Bad Gateway";
  case 503: return "503 Service Unavailable";
  case 504: return "504 Gateway Timeout";
  case 505: return "505 HTTP Version Not Supported";
  case 511: return "511 Network Authentication Required";
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

bool lws(const char *value)
{
  for(; *value; ++value) {
    switch(*value) {
    case '\t':
    case ' ':
      continue;
    default:
      return false;
    }
  }
  return true;
}

void sanitize_header_value(std::string& s, size_t offset)
{
  // Since both nghttp2 and spdylay do not allow \n and \r in header
  // values, we don't have to do this anymore.

  // for(size_t i = offset, eoi = s.size(); i < eoi; ++i) {
  //   if(s[i] == '\r' || s[i] == '\n') {
  //     s[i] = ' ';
  //   }
  // }
}

void copy_url_component(std::string& dest, const http_parser_url *u, int field,
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

bool name_less(const Headers::value_type& lhs,
               const Headers::value_type& rhs)
{
  return lhs.name < rhs.name;
}

bool check_http2_headers(const Headers& nva)
{
  for(size_t i = 0; i < DISALLOWED_HDLEN; ++i) {
    if(std::binary_search(std::begin(nva), std::end(nva),
                          Header(DISALLOWED_HD[i], ""), name_less)) {
      return false;
    }
  }
  return true;
}

void normalize_headers(Headers& nva)
{
  for(auto& kv : nva) {
    util::inp_strlower(kv.name);
  }
  std::stable_sort(std::begin(nva), std::end(nva), name_less);
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
      j = std::find_if(j, end,
                       [](uint8_t c)
                       {
                         return c != '\0';
                       });
      if(j == end) {
        break;
      }
      auto l = std::find(j, end, '\0');
      res.push_back({v[i].name, j, v[i].namelen, static_cast<size_t>(l - j)});
      j = l;
    }
  }
  return res;
}

Headers::value_type to_header(const uint8_t *name, size_t namelen,
                              const uint8_t *value, size_t valuelen,
                              bool no_index)
{
  return Header(std::string(reinterpret_cast<const char*>(name),
                            namelen),
                std::string(reinterpret_cast<const char*>(value),
                            valuelen),
                no_index);
}

void add_header(Headers& nva,
                const uint8_t *name, size_t namelen,
                const uint8_t *value, size_t valuelen,
                bool no_index)
{
  nva.push_back(to_header(name, namelen, value, valuelen, no_index));
}

const Headers::value_type* get_unique_header(const Headers& nva,
                                             const char *name)
{
  auto nv = Headers::value_type(name, "");
  auto i = std::lower_bound(std::begin(nva), std::end(nva), nv, name_less);
  if(i != std::end(nva) && (*i).name == nv.name) {
    auto j = i + 1;
    if(j == std::end(nva) || (*j).name != nv.name) {
      return &(*i);
    }
  }
  return nullptr;
}

const Headers::value_type* get_header(const Headers& nva, const char *name)
{
  auto nv = Headers::value_type(name, "");
  auto i = std::lower_bound(std::begin(nva), std::end(nva), nv, name_less);
  if(i != std::end(nva) && (*i).name == nv.name) {
    return &(*i);
  }
  return nullptr;
}

std::string value_to_str(const Headers::value_type *nv)
{
  if(nv) {
    return nv->value;
  }
  return "";
}

bool value_lws(const Headers::value_type *nv)
{
  return (*nv).value.find_first_not_of("\t ") == std::string::npos;
}

bool non_empty_value(const Headers::value_type *nv)
{
  return nv && !value_lws(nv);
}

nghttp2_nv make_nv(const std::string& name, const std::string& value,
                   bool no_index)
{
  uint8_t flags;

  flags = no_index ? NGHTTP2_NV_FLAG_NO_INDEX : NGHTTP2_NV_FLAG_NONE;

  return {(uint8_t*)name.c_str(), (uint8_t*)value.c_str(),
      name.size(), value.size(), flags};
}

void copy_norm_headers_to_nva
(std::vector<nghttp2_nv>& nva, const Headers& headers)
{
  size_t i, j;
  for(i = 0, j = 0; i < headers.size() && j < IGN_HDLEN;) {
    auto& kv = headers[i];
    int rv = strcmp(kv.name.c_str(), IGN_HD[j]);
    if(rv < 0) {
      if(!kv.name.empty() && kv.name.c_str()[0] != ':') {
        nva.push_back(make_nv(kv.name, kv.value, kv.no_index));
      }
      ++i;
    } else if(rv > 0) {
      ++j;
    } else {
      ++i;
    }
  }
  for(; i < headers.size(); ++i) {
    auto& kv = headers[i];
    if(!kv.name.empty() && kv.name.c_str()[0] != ':') {
      nva.push_back(make_nv(kv.name, kv.value, kv.no_index));
    }
  }
}

void build_http1_headers_from_norm_headers
(std::string& hdrs, const Headers& headers)
{
  size_t i, j;
  for(i = 0, j = 0; i < headers.size() && j < HTTP1_IGN_HDLEN;) {
    auto& kv = headers[i];
    auto rv = strcmp(kv.name.c_str(), HTTP1_IGN_HD[j]);

    if(rv < 0) {
      if(!kv.name.empty() && kv.name.c_str()[0] != ':') {
        hdrs += kv.name;
        capitalize(hdrs, hdrs.size() - kv.name.size());
        hdrs += ": ";
        hdrs += kv.value;
        sanitize_header_value(hdrs, hdrs.size() - kv.value.size());
        hdrs += "\r\n";
      }
      ++i;
    } else if(rv > 0) {
      ++j;
    } else {
      ++i;
    }
  }
  for(; i < headers.size(); ++i) {
    auto& kv = headers[i];

    if(!kv.name.empty() && kv.name.c_str()[0] != ':') {
      hdrs += kv.name;
      capitalize(hdrs, hdrs.size() - kv.name.size());
      hdrs += ": ";
      hdrs += kv.value;
      sanitize_header_value(hdrs, hdrs.size() - kv.value.size());
      hdrs += "\r\n";
    }
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

void dump_nv(FILE *out, const Headers& nva)
{
  for(auto& nv : nva) {
    fwrite(nv.name.c_str(), nv.name.size(), 1, out);
    fwrite(": ", 2, 1, out);
    fwrite(nv.value.c_str(), nv.value.size(), 1, out);
    fwrite("\n", 1, 1, out);
  }
  fwrite("\n", 1, 1, out);
  fflush(out);
}

std::string rewrite_location_uri(const std::string& uri,
                                 const http_parser_url& u,
                                 const std::string& request_host,
                                 const std::string& upstream_scheme,
                                 uint16_t upstream_port)
{
  // We just rewrite host and optionally port. We don't rewrite https
  // link. Not sure it happens in practice.
  if(u.field_set & (1 << UF_SCHEMA)) {
    auto field = &u.field_data[UF_SCHEMA];
    if(!util::streq("http", &uri[field->off], field->len)) {
      return "";
    }
  }
  if((u.field_set & (1 << UF_HOST)) == 0) {
    return "";
  }
  auto field = &u.field_data[UF_HOST];
  if(!util::startsWith(std::begin(request_host), std::end(request_host),
                       &uri[field->off], &uri[field->off] + field->len) ||
     (request_host.size() != field->len &&
      request_host[field->len] != ':')) {
    return "";
  }
  std::string res = upstream_scheme;
  res += "://";
  res.append(&uri[field->off], field->len);
  if(upstream_scheme == "http") {
    if(upstream_port != 80) {
      res += ":";
      res += util::utos(upstream_port);
    }
  } else if(upstream_scheme == "https") {
    if(upstream_port != 443) {
      res += ":";
      res += util::utos(upstream_port);
    }
  }
  if(u.field_set & (1 << UF_PATH)) {
    field = &u.field_data[UF_PATH];
    res.append(&uri[field->off], field->len);
  }
  if(u.field_set & (1 << UF_QUERY)) {
    field = &u.field_data[UF_QUERY];
    res += "?";
    res.append(&uri[field->off], field->len);
  }
  if(u.field_set & (1 << UF_FRAGMENT)) {
    field = &u.field_data[UF_FRAGMENT];
    res += "#";
    res.append(&uri[field->off], field->len);
  }
  return res;
}

int check_nv(const uint8_t *name, size_t namelen,
             const uint8_t *value, size_t valuelen)
{
  if(!nghttp2_check_header_name(name, namelen)) {
    return 0;
  }
  if(!nghttp2_check_header_value(value, valuelen)) {
    return 0;
  }
  return 1;
}

} // namespace http2

} // namespace nghttp2
