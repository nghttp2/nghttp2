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
#ifndef UTIL_H
#define UTIL_H

#include "spdylay_config.h"

#include <vector>
#include <string>
#include <algorithm>
#include <sstream>

namespace spdylay {

namespace util {

extern const std::string DEFAULT_STRIP_CHARSET;

template<typename InputIterator>
std::pair<InputIterator, InputIterator> stripIter
(InputIterator first, InputIterator last,
 const std::string& chars = DEFAULT_STRIP_CHARSET)
{
  for(; first != last &&
        std::find(chars.begin(), chars.end(), *first) != chars.end(); ++first);
  if(first == last) {
    return std::make_pair(first, last);
  }
  InputIterator left = last-1;
  for(; left != first &&
        std::find(chars.begin(), chars.end(), *left) != chars.end(); --left);
  return std::make_pair(first, left+1);
}

template<typename InputIterator, typename OutputIterator>
OutputIterator splitIter
(InputIterator first,
 InputIterator last,
 OutputIterator out,
 char delim,
 bool doStrip = false,
 bool allowEmpty = false)
{
  for(InputIterator i = first; i != last;) {
    InputIterator j = std::find(i, last, delim);
    std::pair<InputIterator, InputIterator> p(i, j);
    if(doStrip) {
      p = stripIter(i, j);
    }
    if(allowEmpty || p.first != p.second) {
      *out++ = p;
    }
    i = j;
    if(j != last) {
      ++i;
    }
  }
  if(allowEmpty &&
     (first == last || *(last-1) == delim)) {
    *out++ = std::make_pair(last, last);
  }
  return out;
}

template<typename InputIterator, typename OutputIterator>
OutputIterator split
(InputIterator first,
 InputIterator last,
 OutputIterator out,
 char delim,
 bool doStrip = false,
 bool allowEmpty = false)
{
  for(InputIterator i = first; i != last;) {
    InputIterator j = std::find(i, last, delim);
    std::pair<InputIterator, InputIterator> p(i, j);
    if(doStrip) {
      p = stripIter(i, j);
    }
    if(allowEmpty || p.first != p.second) {
      *out++ = std::string(p.first, p.second);
    }
    i = j;
    if(j != last) {
      ++i;
    }
  }
  if(allowEmpty &&
     (first == last || *(last-1) == delim)) {
    *out++ = std::string(last, last);
  }
  return out;
}

template<typename InputIterator, typename DelimiterType>
std::string strjoin(InputIterator first, InputIterator last,
                    const DelimiterType& delim)
{
  std::string result;
  if(first == last) {
    return result;
  }
  InputIterator beforeLast = last-1;
  for(; first != beforeLast; ++first) {
    result += *first;
    result += delim;
  }
  result += *beforeLast;
  return result;
}

template<typename InputIterator>
std::string joinPath(InputIterator first, InputIterator last)
{
  std::vector<std::string> elements;
  for(;first != last; ++first) {
    if(*first == "..") {
      if(!elements.empty()) {
        elements.pop_back();
      }
    } else if(*first == ".") {
      // do nothing
    } else {
      elements.push_back(*first);
    }
  }
  return strjoin(elements.begin(), elements.end(), "/");
}

bool isAlpha(const char c);

bool isDigit(const char c);

bool isHexDigit(const char c);

bool inRFC3986UnreservedChars(const char c);

std::string percentEncode(const unsigned char* target, size_t len);

std::string percentEncode(const std::string& target);

std::string percentDecode
(std::string::const_iterator first, std::string::const_iterator last);

std::string http_date(time_t t);

time_t parse_http_date(const std::string& s);

template<typename T>
std::string to_str(T value)
{
  std::stringstream ss;
  ss << value;
  return ss.str();
}

template<typename InputIterator1, typename InputIterator2>
bool startsWith
(InputIterator1 first1,
 InputIterator1 last1,
 InputIterator2 first2,
 InputIterator2 last2)
{
  if(last1-first1 < last2-first2) {
    return false;
  }
  return std::equal(first2, last2, first1);
}

bool startsWith(const std::string& a, const std::string& b);

struct CaseCmp {
  bool operator()(char lhs, char rhs) const
  {
    if('A' <= lhs && lhs <= 'Z') {
      lhs += 'a'-'A';
    }
    if('A' <= rhs && rhs <= 'Z') {
      rhs += 'a'-'A';
    }
    return lhs == rhs;
  }
};

template<typename InputIterator1, typename InputIterator2>
bool istartsWith
(InputIterator1 first1,
 InputIterator1 last1,
 InputIterator2 first2,
 InputIterator2 last2)
{
  if(last1-first1 < last2-first2) {
    return false;
  }
  return std::equal(first2, last2, first1, CaseCmp());
}

bool istartsWith(const std::string& a, const std::string& b);
bool istartsWith(const char *a, const char* b);

template<typename InputIterator1, typename InputIterator2>
bool endsWith
(InputIterator1 first1,
 InputIterator1 last1,
 InputIterator2 first2,
 InputIterator2 last2)
{
  if(last1-first1 < last2-first2) {
    return false;
  }
  return std::equal(first2, last2, last1-(last2-first2));
}

bool endsWith(const std::string& a, const std::string& b);

bool strieq(const char *a, const char *b);

bool strifind(const char *a, const char *b);

} // namespace util

} // namespace spdylay

#endif // UTIL_H
