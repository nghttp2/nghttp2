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
#include "nghttp2_hd_huffman.h"

#include <string.h>
#include <assert.h>

#include "nghttp2_hd.h"

extern const nghttp2_huff_sym req_huff_sym_table[];
extern const int16_t req_huff_decode_table[][256];

extern const nghttp2_huff_sym res_huff_sym_table[];
extern const int16_t res_huff_decode_table[][256];

/*
 * Returns next 8 bits of data from |in|, starting |bitoff| bits
 * offset. If there are fewer bits left than |bitoff|, the left bits
 * with padded with 0 are returned. The |bitoff| must be strictly less
 * than 8.
 */
static uint8_t get_prefix_byte(const uint8_t *in, size_t len, size_t bitoff)
{
  uint8_t b;
  size_t bitleft;
  if(bitoff == 0) {
    return *in;
  }
  bitleft = 8 - bitoff;
  b = (*in & ((1 << bitleft) - 1)) << bitoff;
  if(len > 1) {
    b |= *(in + 1) >> bitleft;
  }
  return b;
}

/*
 * Decodes next byte from input |in| with length |len|, starting
 * |bitoff| bit offset.
 *
 * This function returns the decoded symbol number (0-255 and 256 for
 * special terminal symbol) if it succeeds, or -1.
 */
static int huff_decode(const uint8_t *in, size_t len, size_t bitoff,
                       const nghttp2_huff_sym *huff_sym_table,
                       const huff_decode_table_type *huff_decode_table)
{
  int rv = 0;
  size_t len_orig = len;
  if(len == 0) {
    return -1;
  }
  for(;;) {
    rv = huff_decode_table[rv][get_prefix_byte(in, len, bitoff)];
    if(rv >= 0) {
      break;
    }
    /* Negative return value means we need to lookup next table. */
    rv = -rv;
    ++in;
    --len;
    if(len == 0) {
      return -1;
    }
  }
  if(bitoff + huff_sym_table[rv].nbits > len_orig * 8) {
    return -1;
  }
  return rv;
}

/*
 * Returns next LSB aligned |nbits| bits from huffman symbol |sym|,
 * starting |codebitoff| bit offset (from beginning of code sequence,
 * so it could be more than 8).
 */
static uint8_t huff_get_lsb_aligned(const nghttp2_huff_sym *sym,
                                    size_t codebitoff,
                                    size_t nbits)
{
  uint8_t a = sym->code[codebitoff/8];
  size_t localbitoff = codebitoff & 0x7;
  size_t bitleft = 8 - localbitoff;

  if(bitleft >= nbits) {
    return (a >> (bitleft - nbits)) & ((1 << nbits) - 1);
  } else {
    uint8_t b = 0;
    a &= ((1 << bitleft) - 1);
    a <<= nbits - bitleft;
    if((sym->nbits + 7) / 8 > codebitoff / 8 + 1) {
      b = sym->code[codebitoff / 8 + 1] >> (8 - (nbits - bitleft));
    }
    return a | b;
  }
}

/*
 * Encodes huffman code |sym| into |*dest_ptr|,starting |bitoff|
 * offset. The |bitoff| must be strictly less than 8. At the end of
 * the process, the |*dest_ptr| is updated and points where next
 * output should be placed. The bit offset of the pointed location is
 * returned.
 */
static size_t huff_encode_sym(uint8_t **dest_ptr, size_t bitoff,
                              const nghttp2_huff_sym *sym)
{
  size_t b = 0;
  if(bitoff == 0) **dest_ptr = 0;
  **dest_ptr |= huff_get_lsb_aligned(sym, b, 8 - bitoff);
  b += 8 - bitoff;
  ++*dest_ptr;
  for(; b < sym->nbits; b += 8, ++*dest_ptr) {
    **dest_ptr = huff_get_lsb_aligned(sym, b, 8);
  }
  bitoff = 8 - (b - sym->nbits);
  if(bitoff > 0) {
    --*dest_ptr;
  }
  return bitoff;
}

size_t nghttp2_hd_huff_encode_count(const uint8_t *src, size_t len,
                                    nghttp2_hd_side side)
{
  size_t i;
  size_t nbits = 0;
  const nghttp2_huff_sym *huff_sym_table;

  if(side == NGHTTP2_HD_SIDE_REQUEST) {
    huff_sym_table = req_huff_sym_table;
  } else {
    huff_sym_table = res_huff_sym_table;
  }
  for(i = 0; i < len; ++i) {
    nbits += huff_sym_table[src[i]].nbits;
  }
  /* pad the prefix of EOS (256) */
  return (nbits + 7) / 8;
}

ssize_t nghttp2_hd_huff_encode(uint8_t *dest, size_t destlen,
                               const uint8_t *src, size_t srclen,
                               nghttp2_hd_side side)
{
  int bitoff = 0;
  uint8_t *dest_first = dest;
  size_t i;
  const nghttp2_huff_sym *huff_sym_table;

  if(side == NGHTTP2_HD_SIDE_REQUEST) {
    huff_sym_table = req_huff_sym_table;
  } else {
    huff_sym_table = res_huff_sym_table;
  }
  for(i = 0; i < srclen; ++i) {
    const nghttp2_huff_sym *sym = &huff_sym_table[src[i]];
    bitoff = huff_encode_sym(&dest, bitoff, sym);
  }
  /* 256 is special terminal symbol, pad with its prefix */
  if(bitoff > 0) {
    *dest |= huff_sym_table[256].code[0] >> bitoff;
  }
  return dest - dest_first + (bitoff > 0);
}

ssize_t nghttp2_hd_huff_decode_count(const uint8_t *src, size_t srclen,
                                     nghttp2_hd_side side)
{
  size_t bitoff = 0;
  size_t i, j;
  const nghttp2_huff_sym *huff_sym_table;
  const huff_decode_table_type *huff_decode_table;

  if(side == NGHTTP2_HD_SIDE_REQUEST) {
    huff_sym_table = req_huff_sym_table;
    huff_decode_table = req_huff_decode_table;
  } else {
    huff_sym_table = res_huff_sym_table;
    huff_decode_table = res_huff_decode_table;
  }
  j = 0;
  for(i = 0; i < srclen;) {
    int rv = huff_decode(src + i, srclen - i, bitoff,
                         huff_sym_table, huff_decode_table);
    if(rv == -1) {
      /* TODO Check prefix of EOS */
      if(i + 1 == srclen && bitoff > 0) {
        break;
      }
      return -1;
    }
    if(rv == 256) {
      /* 256 is special terminal symbol */
      break;
    }
    j++;
    bitoff += huff_sym_table[rv].nbits;
    i += bitoff / 8;
    bitoff &= 0x7;
  }
  return j;
}

ssize_t nghttp2_hd_huff_decode(uint8_t *dest, size_t destlen,
                               const uint8_t *src, size_t srclen,
                               nghttp2_hd_side side)
{
  size_t bitoff = 0;
  size_t i, j;
  const nghttp2_huff_sym *huff_sym_table;
  const huff_decode_table_type *huff_decode_table;

  if(side == NGHTTP2_HD_SIDE_REQUEST) {
    huff_sym_table = req_huff_sym_table;
    huff_decode_table = req_huff_decode_table;
  } else {
    huff_sym_table = res_huff_sym_table;
    huff_decode_table = res_huff_decode_table;
  }
  j = 0;
  for(i = 0; i < srclen;) {
    int rv = huff_decode(src + i, srclen - i, bitoff,
                         huff_sym_table, huff_decode_table);
    if(rv == -1) {
      /* TODO Check prefix of EOS */
      if(i + 1 == srclen && bitoff > 0) {
        break;
      }
      return -1;
    }
    if(rv == 256) {
      /* 256 is special terminal symbol */
      break;
    }
    dest[j++] = rv;
    bitoff += huff_sym_table[rv].nbits;
    i += bitoff / 8;
    bitoff &= 0x7;
  }
  return j;
}
