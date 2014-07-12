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
#ifndef HTTP2_H
#define HTTP2_H

#include "nghttp2_config.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <nghttp2/nghttp2.h>

#include "http-parser/http_parser.h"

namespace nghttp2 {

struct Header {
  Header(std::string name, std::string value, bool no_index=false)
    : name(std::move(name)),
      value(std::move(value)),
      no_index(no_index)
  {}

  Header()
    : no_index(false)
  {}

  bool operator==(const Header& other) const
  {
    return name == other.name && value == other.value;
  }

  bool operator<(const Header& rhs) const
  {
    return name < rhs.name || (name == rhs.name && value < rhs.value);
  }

  std::string name;
  std::string value;
  bool no_index;
};

typedef std::vector<Header> Headers;

namespace http2 {

std::string get_status_string(unsigned int status_code);

void capitalize(std::string& s, size_t offset);

// Returns true if |value| is LWS
bool lws(const char *value);

void sanitize_header_value(std::string& s, size_t offset);

// Copies the |field| component value from |u| and |url| to the
// |dest|. If |u| does not have |field|, then this function does
// nothing.
void copy_url_component(std::string& dest, const http_parser_url *u, int field,
                        const char* url);

// Returns true if the header field |name| with length |namelen| bytes
// is valid for HTTP/2.
bool check_http2_allowed_header(const uint8_t *name, size_t namelen);

// Calls check_http2_allowed_header with |name| and strlen(name),
// assuming |name| is null-terminated string.
bool check_http2_allowed_header(const char *name);

// Checks that headers |nva| do not contain disallowed header fields
// in HTTP/2 spec. This function returns true if |nva| does not
// contains such headers.
bool check_http2_headers(const Headers& nva);

bool name_less(const Headers::value_type& lhs, const Headers::value_type& rhs);

void normalize_headers(Headers& nva);

Headers::value_type to_header(const uint8_t *name, size_t namelen,
                              const uint8_t *value, size_t valuelen,
                              bool no_index);

// Add name/value pairs to |nva|.  If |no_index| is true, this
// name/value pair won't be indexed when it is forwarded to the next
// hop.
void add_header(Headers& nva,
                const uint8_t *name, size_t namelen,
                const uint8_t *value, size_t valuelen,
                bool no_index);

// Returns sorted |nva| with |nvlen| elements. The headers are sorted
// by name only and not necessarily stable. In addition to the
// sorting, this function splits values concatenated with NULL. The
// ordering of the concatenated values are preserved. The element of
// the returned vector refers to the memory pointed by |nva|.
std::vector<nghttp2_nv> sort_nva(const nghttp2_nv *nva, size_t nvlen);

// Returns the iterator to the entry in |nva| which has name |name|
// and the |name| is uinque in the |nva|. If no such entry exist,
// returns nullptr.
const Headers::value_type* get_unique_header(const Headers& nva,
                                             const char *name);

// Returns the iterator to the entry in |nva| which has name
// |name|. If more than one entries which have the name |name|, first
// occurrence in |nva| is returned. If no such entry exist, returns
// nullptr.
const Headers::value_type* get_header(const Headers& nva, const char *name);

// Returns nv->second if nv is not nullptr. Otherwise, returns "".
std::string value_to_str(const Headers::value_type *nv);

// Returns true if the value of |nv| includes only ' ' (0x20) or '\t'.
bool value_lws(const Headers::value_type *nv);

// Returns true if the value of |nv| is not empty value and not LWS
// and not contain illegal characters.
bool non_empty_value(const Headers::value_type *nv);

// Creates nghttp2_nv using |name| and |value| and returns it. The
// returned value only references the data pointer to name.c_str() and
// value.c_str().  If |no_index| is true, nghttp2_nv flags member has
// NGHTTP2_NV_FLAG_NO_INDEX flag set.
nghttp2_nv make_nv(const std::string& name, const std::string& value,
                   bool no_index = false);

// Create nghttp2_nv from string literal |name| and |value|.
template<size_t N, size_t M>
nghttp2_nv make_nv_ll(const char(&name)[N], const char(&value)[M])
{
  return {(uint8_t*)name, (uint8_t*)value, N - 1, M - 1, NGHTTP2_NV_FLAG_NONE};
}

// Create nghttp2_nv from string literal |name| and c-string |value|.
template<size_t N>
nghttp2_nv make_nv_lc(const char(&name)[N], const char *value)
{
  return {(uint8_t*)name, (uint8_t*)value, N - 1, strlen(value),
      NGHTTP2_NV_FLAG_NONE};
}

// Create nghttp2_nv from string literal |name| and std::string
// |value|.
template<size_t N>
nghttp2_nv make_nv_ls(const char(&name)[N], const std::string& value)
{
  return {(uint8_t*)name, (uint8_t*)value.c_str(), N - 1, value.size(),
      NGHTTP2_NV_FLAG_NONE};
}

// Appends headers in |headers| to |nv|. Certain headers, including
// disallowed headers in HTTP/2 spec and headers which require
// special handling (i.e. via), are not copied.
void copy_norm_headers_to_nva
(std::vector<nghttp2_nv>& nva, const Headers& headers);

// Appends HTTP/1.1 style header lines to |hdrs| from headers in
// |headers|. Certain headers, which requires special handling
// (i.e. via and cookie), are not appended.
void build_http1_headers_from_norm_headers
(std::string& hdrs, const Headers& headers);

// Return positive window_size_increment if WINDOW_UPDATE should be
// sent for the stream |stream_id|. If |stream_id| == 0, this function
// determines the necessity of the WINDOW_UPDATE for a connection.
//
// If the function determines WINDOW_UPDATE is not necessary at the
// moment, it returns -1.
int32_t determine_window_update_transmission(nghttp2_session *session,
                                             int32_t stream_id);

// Dumps name/value pairs in |nv| to |out|. The |nv| must be
// terminated by nullptr.
void dump_nv(FILE *out, const char **nv);

// Dumps name/value pairs in |nva| to |out|.
void dump_nv(FILE *out, const nghttp2_nv *nva, size_t nvlen);

// Dumps name/value pairs in |nva| to |out|.
void dump_nv(FILE *out, const Headers& nva);

// Rewrites redirection URI which usually appears in location header
// field. The |uri| is the URI in the location header field. The |u|
// stores the result of parsed |uri|. The |request_host| is the host
// or :authority header field value in the request. The
// |upstream_scheme| is either "https" or "http" in the upstream
// interface.
//
// This function returns the new rewritten URI on success. If the
// location URI is not subject to the rewrite, this function returns
// emtpy string.
std::string rewrite_location_uri(const std::string& uri,
                                 const http_parser_url& u,
                                 const std::string& request_host,
                                 const std::string& upstream_scheme,
                                 uint16_t upstream_port);

// Checks the header name/value pair using nghttp2_check_header_name()
// and nghttp2_check_header_value(). If both function returns nonzero,
// this function returns nonzero.
int check_nv(const uint8_t *name, size_t namelen,
             const uint8_t *value, size_t valuelen);

} // namespace http2

} // namespace nghttp2

#endif // HTTP2_H
