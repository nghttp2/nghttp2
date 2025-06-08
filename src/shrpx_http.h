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
#ifndef SHRPX_HTTP_H
#define SHRPX_HTTP_H

#include "shrpx.h"

#include <string>
#include <algorithm>

#include <nghttp2/nghttp2.h>

#include "shrpx_config.h"
#include "util.h"
#include "allocator.h"

using namespace nghttp2;
using namespace std::literals;

namespace shrpx {

namespace http {

std::string_view create_error_html(BlockAllocator &balloc,
                                   unsigned int status_code);

struct ViaValueGenerator {
  template <std::weakly_incrementable O>
  requires(std::indirectly_writable<O, char>)
  constexpr O operator()(int major, int minor, O result) {
    using result_type = std::iter_value_t<O>;

    *result++ = static_cast<result_type>(major + '0');

    if (major < 2) {
      *result++ = '.';
      *result++ = static_cast<result_type>(minor + '0');
    }

    return std::ranges::copy(" nghttpx"sv, result).out;
  }
};

template <typename OutputIt>
OutputIt create_via_header_value(OutputIt dst, int major, int minor) {
  return ViaValueGenerator{}(major, minor, std::move(dst));
}

// Returns generated RFC 7239 Forwarded header field value.  The
// |params| is bitwise-OR of zero or more of shrpx_forwarded_param
// defined in shrpx_config.h.
std::string_view create_forwarded(BlockAllocator &balloc, uint32_t params,
                                  const std::string_view &node_by,
                                  const std::string_view &node_for,
                                  const std::string_view &host,
                                  const std::string_view &proto);

// Adds ANSI color codes to HTTP headers |hdrs|.
std::string colorize_headers(const std::string_view &hdrs);

nghttp2_ssize select_padding_callback(nghttp2_session *session,
                                      const nghttp2_frame *frame,
                                      size_t max_payload, void *user_data);

// Creates set-cookie-string for cookie based affinity.  If |path| is
// not empty, "; <path>" is added.  If |secure| is true, "; Secure" is
// added.
std::string_view create_affinity_cookie(BlockAllocator &balloc,
                                        const std::string_view &name,
                                        uint32_t affinity_cookie,
                                        const std::string_view &path,
                                        bool secure);

// Returns true if |secure| indicates that Secure attribute should be
// set.
bool require_cookie_secure_attribute(SessionAffinityCookieSecure secure,
                                     const std::string_view &scheme);

// Returns RFC 7838 alt-svc header field value.
std::string_view create_altsvc_header_value(BlockAllocator &balloc,
                                            const std::vector<AltSvc> &altsvcs);

// Returns true if either of the following conditions holds:
// - scheme is https and encrypted is true
// - scheme is http and encrypted is false
// Otherwise returns false.
bool check_http_scheme(const std::string_view &scheme, bool encrypted);

} // namespace http

} // namespace shrpx

#endif // SHRPX_HTTP_H
