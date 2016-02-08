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
#ifndef NGHTTP2_HD_HUFFMAN_H
#define NGHTTP2_HD_HUFFMAN_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <nghttp2/nghttp2.h>

typedef enum {
  /* FSA accepts this state as the end of huffman encoding
     sequence. */
  NGHTTP2_HUFF_ACCEPTED = 1,
  /* This state emits 1st symbol */
  NGHTTP2_HUFF_SYM1 = (1 << 1),
  /* This state emits 2nd symbol */
  NGHTTP2_HUFF_SYM2 = (1 << 2),
  /* If state machine reaches this state, decoding fails. */
  NGHTTP2_HUFF_FAIL = (1 << 3)
} nghttp2_huff_decode_flag;

typedef struct {
  /* huffman decoding state, which is actually the node ID of internal
     huffman tree.  We have 257 leaf nodes, but they are identical to
     root node other than emitting a symbol, so we have 256 internal
     nodes [1..255], inclusive. */
  uint8_t state;
  /* bitwise OR of zero or more of the nghttp2_huff_decode_flag */
  uint8_t flags;
  /* symbols if NGHTTP2_HUFF_SYM1 and optionally NGHTTP2_HUFF_SYM2
     flag set.  If NGHTTP2_HUFF_SYM1 is set, sym[0] has the 1st
     symbol.  Additionally, NGHTTP2_HUFF_SYM2 is set, sym[1] has the
     2nd symbol.  Since maximum huffman code is 5 bits, we may get at
     most 2 symbols in one transition. */
  uint8_t sym[2];
} nghttp2_huff_decode;

typedef nghttp2_huff_decode huff_decode_table_type[256];

typedef struct {
  /* Current huffman decoding state. We stripped leaf nodes, so the
     value range is [0..255], inclusive. */
  uint8_t state;
  /* nonzero if we can say that the decoding process succeeds at this
     state */
  uint8_t accept;
} nghttp2_hd_huff_decode_context;

typedef struct {
  /* The number of bits in this code */
  uint32_t nbits;
  /* Huffman code aligned to LSB */
  uint32_t code;
} nghttp2_huff_sym;

extern const nghttp2_huff_sym huff_sym_table[];
extern const nghttp2_huff_decode huff_decode_table[][256];

#endif /* NGHTTP2_HD_HUFFMAN_H */
