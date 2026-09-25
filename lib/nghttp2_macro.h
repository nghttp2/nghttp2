/*
 * nghttp2
 *
 * Copyright (c) 2026 nghttp2 contributors
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
#ifndef NGHTTP2_MACRO_H
#define NGHTTP2_MACRO_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <stddef.h>

#include <nghttp2v2/nghttp2.h>

#define nghttp2_struct_of(ptr, type, member)                                   \
  ((type *)(void *)((char *)(ptr) - offsetof(type, member)))

#define nghttp2_arraylen(A) (sizeof(A) / sizeof(*(A)))

/*
 * nghttp2_strlen_lit returns the length of string literal |S|.  This
 * macro assumes |S| is NULL-terminated string literal.  It must not
 * be used with pointers.
 */
#define nghttp2_strlen_lit(S) (sizeof(S) - 1)

#define lstreq(A, B, N)                                                        \
  (nghttp2_strlen_lit((A)) == (N) && memcmp((A), (B), (N)) == 0)

/* NGHTTP2_MAX_INT is the maximum integer value that can be used in
   HTTP/2 protocol values. */
#define NGHTTP2_MAX_INT ((1ULL << 62) - 1)

#define nghttp2_max_def(SUFFIX, T)                                             \
  static inline T nghttp2_max_##SUFFIX(T a, T b) { return a < b ? b : a; }

nghttp2_max_def(long_long_int, long long int)
nghttp2_max_def(long_int, long int)
nghttp2_max_def(int, int)
nghttp2_max_def(short_int, short int)
nghttp2_max_def(signed_char, signed char)
nghttp2_max_def(char, char)
nghttp2_max_def(unsigned_long_long_int, unsigned long long int)
nghttp2_max_def(unsigned_long_int, unsigned long int)
nghttp2_max_def(unsigned_int, unsigned int)
nghttp2_max_def(unsigned_short_int, unsigned short int)
nghttp2_max_def(unsigned_char, unsigned char)

#define nghttp2_max(A, B)                                                      \
  _Generic((A),                                                                \
    long long int: nghttp2_max_long_long_int,                                  \
    long int: nghttp2_max_long_int,                                            \
    int: _Generic((B),                                                         \
      long long int: nghttp2_max_long_long_int,                                \
      long int: nghttp2_max_long_int,                                          \
      int: nghttp2_max_int,                                                    \
      short int: nghttp2_max_short_int,                                        \
      signed char: nghttp2_max_signed_char,                                    \
      char: nghttp2_max_char,                                                  \
      unsigned long long int: nghttp2_max_unsigned_long_long_int,              \
      unsigned long int: nghttp2_max_unsigned_long_int,                        \
      unsigned int: nghttp2_max_unsigned_int,                                  \
      unsigned short int: nghttp2_max_unsigned_short_int,                      \
      unsigned char: nghttp2_max_unsigned_char),                               \
    short int: nghttp2_max_short_int,                                          \
    signed char: nghttp2_max_signed_char,                                      \
    char: nghttp2_max_char,                                                    \
    unsigned long long int: nghttp2_max_unsigned_long_long_int,                \
    unsigned long int: nghttp2_max_unsigned_long_int,                          \
    unsigned int: nghttp2_max_unsigned_int,                                    \
    unsigned short int: nghttp2_max_unsigned_short_int,                        \
    unsigned char: nghttp2_max_unsigned_char)((A), (B))

#define nghttp2_min_def(SUFFIX, T)                                             \
  static inline T nghttp2_min_##SUFFIX(T a, T b) { return a < b ? a : b; }

nghttp2_min_def(long_long_int, long long int)
nghttp2_min_def(long_int, long int)
nghttp2_min_def(int, int)
nghttp2_min_def(short_int, short int)
nghttp2_min_def(signed_char, signed char)
nghttp2_min_def(char, char)
nghttp2_min_def(unsigned_long_long_int, unsigned long long int)
nghttp2_min_def(unsigned_long_int, unsigned long int)
nghttp2_min_def(unsigned_int, unsigned int)
nghttp2_min_def(unsigned_short_int, unsigned short int)
nghttp2_min_def(unsigned_char, unsigned char)

#define nghttp2_min(A, B)                                                      \
  _Generic((A),                                                                \
    long long int: nghttp2_min_long_long_int,                                  \
    long int: nghttp2_min_long_int,                                            \
    int: _Generic((B),                                                         \
      long long int: nghttp2_min_long_long_int,                                \
      long int: nghttp2_min_long_int,                                          \
      int: nghttp2_min_int,                                                    \
      short int: nghttp2_min_short_int,                                        \
      signed char: nghttp2_min_signed_char,                                    \
      char: nghttp2_min_char,                                                  \
      unsigned long long int: nghttp2_min_unsigned_long_long_int,              \
      unsigned long int: nghttp2_min_unsigned_long_int,                        \
      unsigned int: nghttp2_min_unsigned_int,                                  \
      unsigned short int: nghttp2_min_unsigned_short_int,                      \
      unsigned char: nghttp2_min_unsigned_char),                               \
    short int: nghttp2_min_short_int,                                          \
    signed char: nghttp2_min_signed_char,                                      \
    char: nghttp2_min_char,                                                    \
    unsigned long long int: nghttp2_min_unsigned_long_long_int,                \
    unsigned long int: nghttp2_min_unsigned_long_int,                          \
    unsigned int: nghttp2_min_unsigned_int,                                    \
    unsigned short int: nghttp2_min_unsigned_short_int,                        \
    unsigned char: nghttp2_min_unsigned_char)((A), (B))

#endif /* !defined(NGHTTP2_MACRO_H) */
