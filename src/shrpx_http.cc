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
#include "shrpx_http.h"

#include "shrpx_config.h"
#include "shrpx_log.h"
#include "http2.h"
#include "util.h"

using namespace nghttp2;

namespace shrpx {

namespace http {

std::string_view create_error_html(BlockAllocator &balloc,
                                   unsigned int http_status) {
  auto &httpconf = get_config()->http;

  const auto &error_pages = httpconf.error_pages;
  for (const auto &page : error_pages) {
    if (page.http_status == 0 || page.http_status == http_status) {
      return as_string_view(page.content);
    }
  }

  auto status_string = http2::stringify_status(balloc, http_status);
  auto reason_phrase = http2::get_reason_phrase(http_status);

  return concat_string_ref(
    balloc, R"(<!DOCTYPE html><html lang="en"><title>)"sv, status_string, " "sv,
    reason_phrase, "</title><body><h1>"sv, status_string, " "sv, reason_phrase,
    "</h1><footer>"sv, httpconf.server_name, "</footer></body></html>"sv);
}

std::string_view create_forwarded(BlockAllocator &balloc, uint32_t params,
                                  const std::string_view &node_by,
                                  const std::string_view &node_for,
                                  const std::string_view &host,
                                  const std::string_view &proto) {
  size_t len = 0;
  if ((params & FORWARDED_BY) && !node_by.empty()) {
    len += str_size("by=\"") + node_by.size() + str_size("\";");
  }
  if ((params & FORWARDED_FOR) && !node_for.empty()) {
    len += str_size("for=\"") + node_for.size() + str_size("\";");
  }
  if ((params & FORWARDED_HOST) && !host.empty()) {
    len += str_size("host=\"") + host.size() + str_size("\";");
  }
  if ((params & FORWARDED_PROTO) && !proto.empty()) {
    len += str_size("proto=") + proto.size() + str_size(";");
  }

  auto iov = make_byte_ref(balloc, len + 1);
  auto p = std::ranges::begin(iov);

  if ((params & FORWARDED_BY) && !node_by.empty()) {
    // This must be quoted-string unless it is obfuscated version
    // (which starts with "_") or some special value (e.g.,
    // "localhost" for UNIX domain socket), since ':' is not allowed
    // in token.  ':' is used to separate host and port.
    if (node_by[0] == '_' || node_by[0] == 'l') {
      p = std::ranges::copy("by="sv, p).out;
      p = std::ranges::copy(node_by, p).out;
      *p++ = ';';
    } else {
      p = std::ranges::copy("by=\""sv, p).out;
      p = std::ranges::copy(node_by, p).out;
      p = std::ranges::copy("\";"sv, p).out;
    }
  }
  if ((params & FORWARDED_FOR) && !node_for.empty()) {
    // We only quote IPv6 literal address only, which starts with '['.
    if (node_for[0] == '[') {
      p = std::ranges::copy("for=\""sv, p).out;
      p = std::ranges::copy(node_for, p).out;
      p = std::ranges::copy("\";"sv, p).out;
    } else {
      p = std::ranges::copy("for="sv, p).out;
      p = std::ranges::copy(node_for, p).out;
      *p++ = ';';
    }
  }
  if ((params & FORWARDED_HOST) && !host.empty()) {
    // Just be quoted to skip checking characters.
    p = std::ranges::copy("host=\""sv, p).out;
    p = std::ranges::copy(host, p).out;
    p = std::ranges::copy("\";"sv, p).out;
  }
  if ((params & FORWARDED_PROTO) && !proto.empty()) {
    // Scheme production rule only allow characters which are all in
    // token.
    p = std::ranges::copy("proto="sv, p).out;
    p = std::ranges::copy(proto, p).out;
    *p++ = ';';
  }

  if (std::ranges::begin(iov) == p) {
    return ""sv;
  }

  --p;
  *p = '\0';

  return as_string_view(std::ranges::begin(iov), p);
}

std::string colorize_headers(const std::string_view &hdrs) {
  std::string nhdrs;
  auto p = std::ranges::find(hdrs, '\n');
  if (p == hdrs.end()) {
    // Not valid HTTP header
    return std::string{hdrs};
  }

  nhdrs.append(hdrs.begin(), ++p);

  while (1) {
    auto np = std::ranges::find(p, hdrs.end(), ':');
    if (np == hdrs.end()) {
      nhdrs.append(p, hdrs.end());
      break;
    }

    nhdrs += TTY_HTTP_HD;
    nhdrs.append(p, np);
    nhdrs += TTY_RST;

    auto redact = util::strieq("authorization"sv, std::string_view{p, np});

    p = np;

    np = std::ranges::find(p, hdrs.end(), '\n');

    if (redact) {
      nhdrs.append(": <redacted>"sv);
    } else {
      nhdrs.append(p, np);
    }

    if (np == hdrs.end()) {
      return nhdrs;
    }

    nhdrs += '\n';
    p = np + 1;
  }

  return nhdrs;
}

nghttp2_ssize select_padding_callback(nghttp2_session *session,
                                      const nghttp2_frame *frame,
                                      size_t max_payload, void *user_data) {
  return as_signed(
    std::min(max_payload, frame->hd.length + get_config()->padding));
}

std::string_view create_affinity_cookie(BlockAllocator &balloc,
                                        const std::string_view &name,
                                        uint32_t affinity_cookie,
                                        const std::string_view &path,
                                        bool secure) {
  static constexpr auto PATH_PREFIX = "; Path="sv;
  static constexpr auto SECURE = "; Secure"sv;
  // <name>=<value>[; Path=<path>][; Secure]
  size_t len = name.size() + 1 + 8;

  if (!path.empty()) {
    len += PATH_PREFIX.size() + path.size();
  }
  if (secure) {
    len += SECURE.size();
  }

  auto iov = make_byte_ref(balloc, len + 1);
  auto p = std::ranges::copy(name, std::ranges::begin(iov)).out;
  *p++ = '=';
  affinity_cookie = htonl(affinity_cookie);
  p = util::format_hex(as_uint8_span(std::span{&affinity_cookie, 1}), p);
  if (!path.empty()) {
    p = std::ranges::copy(PATH_PREFIX, p).out;
    p = std::ranges::copy(path, p).out;
  }
  if (secure) {
    p = std::ranges::copy(SECURE, p).out;
  }
  *p = '\0';
  return as_string_view(std::ranges::begin(iov), p);
}

bool require_cookie_secure_attribute(SessionAffinityCookieSecure secure,
                                     const std::string_view &scheme) {
  switch (secure) {
  case SessionAffinityCookieSecure::AUTO:
    return scheme == "https"sv;
  case SessionAffinityCookieSecure::YES:
    return true;
  default:
    return false;
  }
}

std::string_view
create_altsvc_header_value(BlockAllocator &balloc,
                           const std::vector<AltSvc> &altsvcs) {
  // <PROTOID>="<HOST>:<SERVICE>"; <PARAMS>
  size_t len = 0;

  if (altsvcs.empty()) {
    return ""sv;
  }

  for (auto &altsvc : altsvcs) {
    len += util::percent_encode_tokenlen(altsvc.protocol_id);
    len += str_size("=\"");
    len += util::quote_stringlen(altsvc.host);
    len += str_size(":");
    len += altsvc.service.size();
    len += str_size("\"");
    if (!altsvc.params.empty()) {
      len += str_size("; ");
      len += altsvc.params.size();
    }
  }

  // ", " between items.
  len += (altsvcs.size() - 1) * 2;

  // We will write additional ", " at the end, and cut it later.
  auto iov = make_byte_ref(balloc, len + 2);
  auto p = std::ranges::begin(iov);

  for (auto &altsvc : altsvcs) {
    p = util::percent_encode_token(altsvc.protocol_id, p);
    p = std::ranges::copy("=\""sv, p).out;
    p = util::quote_string(altsvc.host, p);
    *p++ = ':';
    p = std::ranges::copy(altsvc.service, p).out;
    *p++ = '"';
    if (!altsvc.params.empty()) {
      p = std::ranges::copy("; "sv, p).out;
      p = std::ranges::copy(altsvc.params, p).out;
    }
    p = std::ranges::copy(", "sv, p).out;
  }

  p -= 2;
  *p = '\0';

  assert(static_cast<size_t>(p - std::ranges::begin(iov)) == len);

  return as_string_view(std::ranges::begin(iov), p);
}

bool check_http_scheme(const std::string_view &scheme, bool encrypted) {
  return encrypted ? scheme == "https"sv : scheme == "http"sv;
}

} // namespace http

} // namespace shrpx
