/*
 * nghttp2 - HTTP/2.0 C Library
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

#include <string>
#include <vector>

#include <nghttp2/nghttp2.h>

#include "http-parser/http_parser.h"

namespace nghttp2 {

namespace http2 {

const char* get_status_string(int status_code);

void capitalize(std::string& s, size_t offset);

// Returns false if |value| contains \r or \n.
bool check_header_value(const char *value);

// Returns false if |nv->value| contains \r or \n.
bool check_header_value(const nghttp2_nv *nv);

void sanitize_header_value(std::string& s, size_t offset);

// Copies the |field| component value from |u| and |url| to the
// |dest|. If |u| does not have |field|, then this function does
// nothing.
void copy_url_component(std::string& dest, http_parser_url *u, int field,
                        const char* url);

// Returns true if the header field |name| with length |namelen| bytes
// is valid for HTTP/2.0.
bool check_http2_allowed_header(const uint8_t *name, size_t namelen);

// Calls check_http2_allowed_header with |name| and strlen(name),
// assuming |name| is null-terminated string.
bool check_http2_allowed_header(const char *name);

// Checks that headers |nva| including |nvlen| entries do not contain
// disallowed header fields in HTTP/2.0 spec. This function returns
// true if |nva| does not contains such headers.
bool check_http2_headers(const nghttp2_nv *nva, size_t nvlen);

// Returns the pointer to the entry in |nva| which has name |name| and
// the |name| is uinque in the |nva|. If no such entry exist, returns
// nullptr.
const nghttp2_nv* get_unique_header(const nghttp2_nv *nva, size_t nvlen,
                                    const char *name);

// Returns the poiter to the entry in |nva| which has name |name|. If
// more than one entries which have the name |name|, first occurrence
// in |nva| is returned. If no such entry exist, returns nullptr.
const nghttp2_nv* get_header(const nghttp2_nv *nva, size_t nvlen,
                             const char *name);

// Returns std::string version of nv->name with nv->namelen bytes.
std::string name_to_str(const nghttp2_nv *nv);
// Returns std::string version of nv->value with nv->valuelen bytes.
std::string value_to_str(const nghttp2_nv *nv);

// Returns true if the value of |nv| includes only ' ' (0x20) or '\t'.
bool value_lws(const nghttp2_nv *nv);

// Copies headers in |headers| to |nv|. Certain headers, including
// disallowed headers in HTTP/2.0 spec and headers which require
// special handling (i.e. via), are not copied.
size_t copy_norm_headers_to_nv
(const char **nv,
 const std::vector<std::pair<std::string, std::string>>& headers);

// Appends HTTP/1.1 style header lines to |hdrs| from headers in
// |headers|. Certain headers, which requires special handling
// (i.e. via), are not appended.
void build_http1_headers_from_norm_headers
(std::string& hdrs,
 const std::vector<std::pair<std::string, std::string>>& headers);

} // namespace http2

} // namespace nghttp2

#endif // HTTP2_H
