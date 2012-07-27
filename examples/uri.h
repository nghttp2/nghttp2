/*
 * Spdylay - SPDY Library
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
#ifndef URI_H
#define URI_H

#include "spdylay_config.h"

#include <stdint.h>

#include <string>

namespace spdylay {

namespace uri {

struct UriStruct {
  std::string protocol;
  std::string host;
  uint16_t port;
  std::string dir;
  std::string file;
  std::string query;
  std::string username;
  std::string password;
  bool hasPassword;
  bool ipv6LiteralAddress;

  UriStruct();
  UriStruct(const UriStruct& c);
  ~UriStruct();

  UriStruct& operator=(const UriStruct& c);
  void swap(UriStruct& other);
};

void swap(UriStruct& lhs, UriStruct& rhs);

// Splits URI uri into components and stores them into result.  On
// success returns true. Otherwise returns false and result is
// undefined.
bool parse(UriStruct& result, const std::string& uri);

std::string construct(const UriStruct& us);

std::string joinUri(const std::string& baseUri, const std::string& uri);

} // namespace uri

} // namespace spdylay

#endif // URI_H
