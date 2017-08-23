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

StringRef create_error_html(BlockAllocator &balloc, unsigned int http_status) {
  auto &httpconf = get_config()->http;

  const auto &error_pages = httpconf.error_pages;
  for (const auto &page : error_pages) {
    if (page.http_status == 0 || page.http_status == http_status) {
      return StringRef{std::begin(page.content), std::end(page.content)};
    }
  }

  auto status_string = http2::stringify_status(balloc, http_status);
  auto reason_phrase = http2::get_reason_phrase(http_status);

  return concat_string_ref(
      balloc, StringRef::from_lit(R"(<!DOCTYPE html><html lang="en"><title>)"),
      status_string, StringRef::from_lit(" "), reason_phrase,
      StringRef::from_lit("</title><body><h1>"), status_string,
      StringRef::from_lit(" "), reason_phrase,
      StringRef::from_lit("</h1><footer>"), httpconf.server_name,
      StringRef::from_lit("</footer></body></html>"));
}

StringRef create_forwarded(BlockAllocator &balloc, int params,
                           const StringRef &node_by, const StringRef &node_for,
                           const StringRef &host, const StringRef &proto) {
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
  auto p = iov.base;

  if ((params & FORWARDED_BY) && !node_by.empty()) {
    // This must be quoted-string unless it is obfuscated version
    // (which starts with "_") or some special value (e.g.,
    // "localhost" for UNIX domain socket), since ':' is not allowed
    // in token.  ':' is used to separate host and port.
    if (node_by[0] == '_' || node_by[0] == 'l') {
      p = util::copy_lit(p, "by=");
      p = std::copy(std::begin(node_by), std::end(node_by), p);
      p = util::copy_lit(p, ";");
    } else {
      p = util::copy_lit(p, "by=\"");
      p = std::copy(std::begin(node_by), std::end(node_by), p);
      p = util::copy_lit(p, "\";");
    }
  }
  if ((params & FORWARDED_FOR) && !node_for.empty()) {
    // We only quote IPv6 literal address only, which starts with '['.
    if (node_for[0] == '[') {
      p = util::copy_lit(p, "for=\"");
      p = std::copy(std::begin(node_for), std::end(node_for), p);
      p = util::copy_lit(p, "\";");
    } else {
      p = util::copy_lit(p, "for=");
      p = std::copy(std::begin(node_for), std::end(node_for), p);
      p = util::copy_lit(p, ";");
    }
  }
  if ((params & FORWARDED_HOST) && !host.empty()) {
    // Just be quoted to skip checking characters.
    p = util::copy_lit(p, "host=\"");
    p = std::copy(std::begin(host), std::end(host), p);
    p = util::copy_lit(p, "\";");
  }
  if ((params & FORWARDED_PROTO) && !proto.empty()) {
    // Scheme production rule only allow characters which are all in
    // token.
    p = util::copy_lit(p, "proto=");
    p = std::copy(std::begin(proto), std::end(proto), p);
    *p++ = ';';
  }

  if (iov.base == p) {
    return StringRef{};
  }

  --p;
  *p = '\0';

  return StringRef{iov.base, p};
}

std::string colorizeHeaders(const char *hdrs) {
  std::string nhdrs;
  const char *p = strchr(hdrs, '\n');
  if (!p) {
    // Not valid HTTP header
    return hdrs;
  }
  nhdrs.append(hdrs, p + 1);
  ++p;
  while (1) {
    const char *np = strchr(p, ':');
    if (!np) {
      nhdrs.append(p);
      break;
    }
    nhdrs += TTY_HTTP_HD;
    nhdrs.append(p, np);
    nhdrs += TTY_RST;
    p = np;
    np = strchr(p, '\n');
    if (!np) {
      nhdrs.append(p);
      break;
    }
    nhdrs.append(p, np + 1);
    p = np + 1;
  }
  return nhdrs;
}

ssize_t select_padding_callback(nghttp2_session *session,
                                const nghttp2_frame *frame, size_t max_payload,
                                void *user_data) {
  return (std::min)(max_payload, frame->hd.length + get_config()->padding);
}

} // namespace http

} // namespace shrpx
