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
#include "nghttp2_str.h"

#include <string.h>

#include "nghttp2_unreachable.h"

void *nghttp2_cpymem(void *dest, const void *src, size_t n) {
  memcpy(dest, src, n);
  return (uint8_t *)dest + n;
}

uint8_t *nghttp2_setmem(uint8_t *dest, uint8_t b, size_t n) {
  memset(dest, b, n);
  return dest + n;
}

#define LOWER_XDIGITS "0123456789abcdef"

uint8_t *nghttp2_encode_hex(uint8_t *dest, const uint8_t *data, size_t len) {
  size_t i;

  for (i = 0; i < len; ++i) {
    *dest++ = (uint8_t)LOWER_XDIGITS[data[i] >> 4];
    *dest++ = (uint8_t)LOWER_XDIGITS[data[i] & 0xFU];
  }

  return dest;
}

size_t nghttp2_encode_uint_hexlen(uint64_t n) {
  size_t i;
  uint8_t d;

  if (n == 0) {
    return 1;
  }

  for (i = 0; i < sizeof(n); ++i) {
    d = (uint8_t)(n >> (sizeof(n) - 1 - i) * 8);
    if (!d) {
      continue;
    }

    if (d >> 4) {
      return (sizeof(n) - i) * 2;
    }

    return (sizeof(n) - i) * 2 - 1;
  }

  nghttp2_unreachable();
}

uint8_t *nghttp2_encode_uint_hex(uint8_t *dest, uint64_t n) {
  size_t i;
  uint8_t d;

  if (n == 0) {
    *dest++ = '0';

    return dest;
  }

  for (i = 0; i < sizeof(n); ++i) {
    d = (uint8_t)(n >> (sizeof(n) - 1 - i) * 8);
    if (d) {
      if (d >> 4) {
        *dest++ = (uint8_t)LOWER_XDIGITS[d >> 4];
      }

      *dest++ = (uint8_t)LOWER_XDIGITS[d & 0xFU];
      ++i;

      break;
    }
  }

  for (; i < sizeof(n); ++i) {
    d = (uint8_t)(n >> (sizeof(n) - 1 - i) * 8);

    *dest++ = (uint8_t)LOWER_XDIGITS[d >> 4];
    *dest++ = (uint8_t)LOWER_XDIGITS[d & 0xFU];
  }

  return dest;
}

/* countl_zero counts the number of leading zeros in |x|.  It is
   undefined if |x| is 0. */
static int countl_zero(uint64_t x) {
#ifdef __GNUC__
  return __builtin_clzll(x);
#else  /* !defined(__GNUC__) */
  /* This is the same implementation of Go's LeadingZeros64 in
     math/bits package. */
  static const uint8_t len8tab[] = {
    0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
  };
  int n = 0;

  if (x >= 1ULL << 32) {
    x >>= 32;
    n += 32;
  }

  if (x >= 1 << 16) {
    x >>= 16;
    n += 16;
  }

  if (x >= 1 << 8) {
    x >>= 8;
    n += 8;
  }

  return 64 - (n + len8tab[x]);
#endif /* !defined(__GNUC__) */
}

/*
 * count_digit returns the minimum number of digits to represent |x|
 * in base 10.
 *
 * credit:
 * https://lemire.me/blog/2025/01/07/counting-the-digits-of-64-bit-integers/
 */
static size_t count_digit(uint64_t x) {
  static const uint64_t count_digit_tbl[] = {
    9ULL,
    99ULL,
    999ULL,
    9999ULL,
    99999ULL,
    999999ULL,
    9999999ULL,
    99999999ULL,
    999999999ULL,
    9999999999ULL,
    99999999999ULL,
    999999999999ULL,
    9999999999999ULL,
    99999999999999ULL,
    999999999999999ULL,
    9999999999999999ULL,
    99999999999999999ULL,
    999999999999999999ULL,
    9999999999999999999ULL,
  };
  size_t y = (size_t)(19 * (63 - countl_zero(x | 1)) >> 6);

  y += x > count_digit_tbl[y];

  return y + 1;
}

size_t nghttp2_encode_uintlen(uint64_t n) { return count_digit(n); }

uint8_t *nghttp2_encode_uint(uint8_t *dest, uint64_t n) {
  static const uint8_t uint_digits[] =
    "00010203040506070809101112131415161718192021222324252627282930313233343536"
    "37383940414243444546474849505152535455565758596061626364656667686970717273"
    "7475767778798081828384858687888990919293949596979899";
  uint8_t *p;
  const uint8_t *tp;

  if (n < 10) {
    *dest++ = (uint8_t)('0' + n);
    return dest;
  }

  if (n < 100) {
    tp = &uint_digits[n * 2];
    *dest++ = *tp++;
    *dest++ = *tp;
    return dest;
  }

  dest += count_digit(n);
  p = dest;

  for (; n >= 100; n /= 100) {
    p -= 2;
    tp = &uint_digits[(n % 100) * 2];
    p[0] = *tp++;
    p[1] = *tp;
  }

  if (n < 10) {
    *--p = (uint8_t)('0' + n);
    return dest;
  }

  p -= 2;
  tp = &uint_digits[n * 2];
  p[0] = *tp++;
  p[1] = *tp;

  return dest;
}

uint8_t *nghttp2_encode_printable_ascii(uint8_t *dest, const uint8_t *data,
                                        size_t len) {
  size_t i;
  uint8_t c;

  for (i = 0; i < len; ++i) {
    c = data[i];
    if (0x20 <= c && c <= 0x7E) {
      *dest++ = c;
    } else {
      *dest++ = '.';
    }
  }

  return dest;
}

/* Generated by gendowncasetbl.py */
const uint8_t nghttp2_downcase_tbl[] = {
  0x00 /* NUL  */, 0x01 /* SOH  */, 0x02 /* STX  */, 0x03 /* ETX  */,
  0x04 /* EOT  */, 0x05 /* ENQ  */, 0x06 /* ACK  */, 0x07 /* BEL  */,
  0x08 /* BS   */, 0x09 /* HT   */, 0x0A /* LF   */, 0x0B /* VT   */,
  0x0C /* FF   */, 0x0D /* CR   */, 0x0E /* SO   */, 0x0F /* SI   */,
  0x10 /* DLE  */, 0x11 /* DC1  */, 0x12 /* DC2  */, 0x13 /* DC3  */,
  0x14 /* DC4  */, 0x15 /* NAK  */, 0x16 /* SYN  */, 0x17 /* ETB  */,
  0x18 /* CAN  */, 0x19 /* EM   */, 0x1A /* SUB  */, 0x1B /* ESC  */,
  0x1C /* FS   */, 0x1D /* GS   */, 0x1E /* RS   */, 0x1F /* US   */,
  0x20 /* SPC  */, 0x21 /* !    */, 0x22 /* "    */, 0x23 /* #    */,
  0x24 /* $    */, 0x25 /* %    */, 0x26 /* &    */, 0x27 /* '    */,
  0x28 /* (    */, 0x29 /* )    */, 0x2A /* *    */, 0x2B /* +    */,
  0x2C /* ,    */, 0x2D /* -    */, 0x2E /* .    */, 0x2F /* /    */,
  0x30 /* 0    */, 0x31 /* 1    */, 0x32 /* 2    */, 0x33 /* 3    */,
  0x34 /* 4    */, 0x35 /* 5    */, 0x36 /* 6    */, 0x37 /* 7    */,
  0x38 /* 8    */, 0x39 /* 9    */, 0x3A /* :    */, 0x3B /* ;    */,
  0x3C /* <    */, 0x3D /* =    */, 0x3E /* >    */, 0x3F /* ?    */,
  0x40 /* @    */, 0x61 /* A    */, 0x62 /* B    */, 0x63 /* C    */,
  0x64 /* D    */, 0x65 /* E    */, 0x66 /* F    */, 0x67 /* G    */,
  0x68 /* H    */, 0x69 /* I    */, 0x6A /* J    */, 0x6B /* K    */,
  0x6C /* L    */, 0x6D /* M    */, 0x6E /* N    */, 0x6F /* O    */,
  0x70 /* P    */, 0x71 /* Q    */, 0x72 /* R    */, 0x73 /* S    */,
  0x74 /* T    */, 0x75 /* U    */, 0x76 /* V    */, 0x77 /* W    */,
  0x78 /* X    */, 0x79 /* Y    */, 0x7A /* Z    */, 0x5B /* [    */,
  0x5C /* \    */, 0x5D /* ]    */, 0x5E /* ^    */, 0x5F /* _    */,
  0x60 /* `    */, 0x61 /* a    */, 0x62 /* b    */, 0x63 /* c    */,
  0x64 /* d    */, 0x65 /* e    */, 0x66 /* f    */, 0x67 /* g    */,
  0x68 /* h    */, 0x69 /* i    */, 0x6A /* j    */, 0x6B /* k    */,
  0x6C /* l    */, 0x6D /* m    */, 0x6E /* n    */, 0x6F /* o    */,
  0x70 /* p    */, 0x71 /* q    */, 0x72 /* r    */, 0x73 /* s    */,
  0x74 /* t    */, 0x75 /* u    */, 0x76 /* v    */, 0x77 /* w    */,
  0x78 /* x    */, 0x79 /* y    */, 0x7A /* z    */, 0x7B /* {    */,
  0x7C /* |    */, 0x7D /* }    */, 0x7E /* ~    */, 0x7F /* DEL  */,
  0x80 /* 0x80 */, 0x81 /* 0x81 */, 0x82 /* 0x82 */, 0x83 /* 0x83 */,
  0x84 /* 0x84 */, 0x85 /* 0x85 */, 0x86 /* 0x86 */, 0x87 /* 0x87 */,
  0x88 /* 0x88 */, 0x89 /* 0x89 */, 0x8A /* 0x8A */, 0x8B /* 0x8B */,
  0x8C /* 0x8C */, 0x8D /* 0x8D */, 0x8E /* 0x8E */, 0x8F /* 0x8F */,
  0x90 /* 0x90 */, 0x91 /* 0x91 */, 0x92 /* 0x92 */, 0x93 /* 0x93 */,
  0x94 /* 0x94 */, 0x95 /* 0x95 */, 0x96 /* 0x96 */, 0x97 /* 0x97 */,
  0x98 /* 0x98 */, 0x99 /* 0x99 */, 0x9A /* 0x9A */, 0x9B /* 0x9B */,
  0x9C /* 0x9C */, 0x9D /* 0x9D */, 0x9E /* 0x9E */, 0x9F /* 0x9F */,
  0xA0 /* 0xA0 */, 0xA1 /* 0xA1 */, 0xA2 /* 0xA2 */, 0xA3 /* 0xA3 */,
  0xA4 /* 0xA4 */, 0xA5 /* 0xA5 */, 0xA6 /* 0xA6 */, 0xA7 /* 0xA7 */,
  0xA8 /* 0xA8 */, 0xA9 /* 0xA9 */, 0xAA /* 0xAA */, 0xAB /* 0xAB */,
  0xAC /* 0xAC */, 0xAD /* 0xAD */, 0xAE /* 0xAE */, 0xAF /* 0xAF */,
  0xB0 /* 0xB0 */, 0xB1 /* 0xB1 */, 0xB2 /* 0xB2 */, 0xB3 /* 0xB3 */,
  0xB4 /* 0xB4 */, 0xB5 /* 0xB5 */, 0xB6 /* 0xB6 */, 0xB7 /* 0xB7 */,
  0xB8 /* 0xB8 */, 0xB9 /* 0xB9 */, 0xBA /* 0xBA */, 0xBB /* 0xBB */,
  0xBC /* 0xBC */, 0xBD /* 0xBD */, 0xBE /* 0xBE */, 0xBF /* 0xBF */,
  0xC0 /* 0xC0 */, 0xC1 /* 0xC1 */, 0xC2 /* 0xC2 */, 0xC3 /* 0xC3 */,
  0xC4 /* 0xC4 */, 0xC5 /* 0xC5 */, 0xC6 /* 0xC6 */, 0xC7 /* 0xC7 */,
  0xC8 /* 0xC8 */, 0xC9 /* 0xC9 */, 0xCA /* 0xCA */, 0xCB /* 0xCB */,
  0xCC /* 0xCC */, 0xCD /* 0xCD */, 0xCE /* 0xCE */, 0xCF /* 0xCF */,
  0xD0 /* 0xD0 */, 0xD1 /* 0xD1 */, 0xD2 /* 0xD2 */, 0xD3 /* 0xD3 */,
  0xD4 /* 0xD4 */, 0xD5 /* 0xD5 */, 0xD6 /* 0xD6 */, 0xD7 /* 0xD7 */,
  0xD8 /* 0xD8 */, 0xD9 /* 0xD9 */, 0xDA /* 0xDA */, 0xDB /* 0xDB */,
  0xDC /* 0xDC */, 0xDD /* 0xDD */, 0xDE /* 0xDE */, 0xDF /* 0xDF */,
  0xE0 /* 0xE0 */, 0xE1 /* 0xE1 */, 0xE2 /* 0xE2 */, 0xE3 /* 0xE3 */,
  0xE4 /* 0xE4 */, 0xE5 /* 0xE5 */, 0xE6 /* 0xE6 */, 0xE7 /* 0xE7 */,
  0xE8 /* 0xE8 */, 0xE9 /* 0xE9 */, 0xEA /* 0xEA */, 0xEB /* 0xEB */,
  0xEC /* 0xEC */, 0xED /* 0xED */, 0xEE /* 0xEE */, 0xEF /* 0xEF */,
  0xF0 /* 0xF0 */, 0xF1 /* 0xF1 */, 0xF2 /* 0xF2 */, 0xF3 /* 0xF3 */,
  0xF4 /* 0xF4 */, 0xF5 /* 0xF5 */, 0xF6 /* 0xF6 */, 0xF7 /* 0xF7 */,
  0xF8 /* 0xF8 */, 0xF9 /* 0xF9 */, 0xFA /* 0xFA */, 0xFB /* 0xFB */,
  0xFC /* 0xFC */, 0xFD /* 0xFD */, 0xFE /* 0xFE */, 0xFF /* 0xFF */,
};

void nghttp2_downcase(uint8_t *s, size_t len) {
  size_t i;
  for (i = 0; i < len; ++i) {
    s[i] = nghttp2_downcase_byte(s[i]);
  }
}
