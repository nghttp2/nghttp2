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

#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>

namespace spdylay {

namespace util {

template<typename T>
class auto_delete {
private:
  T obj_;
  void (*deleter_)(T);
public:
  auto_delete(T obj, void (*deleter)(T)):obj_(obj), deleter_(deleter) {}

  ~auto_delete()
  {
    deleter_(obj_);
  }
};

template<typename T>
class auto_delete_d {
private:
  T obj_;
public:
  auto_delete_d(T obj):obj_(obj) {}

  ~auto_delete_d()
  {
    delete obj_;
  }
};

template<typename T, typename R>
class auto_delete_r {
private:
  T obj_;
  R (*deleter_)(T);
public:
  auto_delete_r(T obj, R (*deleter)(T)):obj_(obj), deleter_(deleter) {}

  ~auto_delete_r()
  {
    (void)deleter_(obj_);
  }
};

extern const char DEFAULT_STRIP_CHARSET[];

template<typename InputIterator>
std::pair<InputIterator, InputIterator> stripIter
(InputIterator first, InputIterator last,
 const char* chars = DEFAULT_STRIP_CHARSET)
{
  for(; first != last && strchr(chars, *first) != 0; ++first);
  if(first == last) {
    return std::make_pair(first, last);
  }
  InputIterator left = last-1;
  for(; left != first && strchr(chars, *left) != 0; --left);
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

template<typename InputIterator1, typename InputIterator2>
bool iendsWith
(InputIterator1 first1,
 InputIterator1 last1,
 InputIterator2 first2,
 InputIterator2 last2)
{
  if(last1-first1 < last2-first2) {
    return false;
  }
  return std::equal(first2, last2, last1-(last2-first2), CaseCmp());
}

bool endsWith(const std::string& a, const std::string& b);

bool strieq(const std::string& a, const std::string& b);

bool strieq(const char *a, const char *b);

bool strifind(const char *a, const char *b);

char upcase(char c);

char lowcase(char c);

inline char lowcase(char c)
{
  static unsigned char tbl[] = {
    0, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55,
    56, 57, 58, 59, 60, 61, 62, 63,
    64, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', 91, 92, 93, 94, 95,
    96, 97, 98, 99, 100, 101, 102, 103,
    104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119,
    120, 121, 122, 123, 124, 125, 126, 127,
    128, 129, 130, 131, 132, 133, 134, 135,
    136, 137, 138, 139, 140, 141, 142, 143,
    144, 145, 146, 147, 148, 149, 150, 151,
    152, 153, 154, 155, 156, 157, 158, 159,
    160, 161, 162, 163, 164, 165, 166, 167,
    168, 169, 170, 171, 172, 173, 174, 175,
    176, 177, 178, 179, 180, 181, 182, 183,
    184, 185, 186, 187, 188, 189, 190, 191,
    192, 193, 194, 195, 196, 197, 198, 199,
    200, 201, 202, 203, 204, 205, 206, 207,
    208, 209, 210, 211, 212, 213, 214, 215,
    216, 217, 218, 219, 220, 221, 222, 223,
    224, 225, 226, 227, 228, 229, 230, 231,
    232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247,
    248, 249, 250, 251, 252, 253, 254, 255,
  };
  return tbl[static_cast<unsigned char>(c)];
}

template<typename T>
std::string utos(T n)
{
  std::string res;
  if(n == 0) {
    res = "0";
    return res;
  }
  int i = 0;
  T t = n;
  for(; t; t /= 10, ++i);
  res.resize(i);
  --i;
  for(; n; --i, n /= 10) {
    res[i] = (n%10) + '0';
  }
  return res;
}

} // namespace util

} // namespace spdylay

#endif // UTIL_H
