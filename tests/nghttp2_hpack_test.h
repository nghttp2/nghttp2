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
#ifndef NGHTTP2_HPACK_TEST_H
#define NGHTTP2_HPACK_TEST_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#define MUNIT_ENABLE_ASSERT_ALIASES

#include "munit.h"

extern const MunitSuite hpack_suite;

munit_void_test_decl(test_nghttp2_hpack_encoder)
munit_void_test_decl(test_nghttp2_hpack_encoder_same_indexed_repr)
munit_void_test_decl(test_nghttp2_hpack_decoder_indexed)
munit_void_test_decl(test_nghttp2_hpack_decoder_indname_noinc)
munit_void_test_decl(test_nghttp2_hpack_decoder_indname_inc)
munit_void_test_decl(test_nghttp2_hpack_decoder_indname_inc_eviction)
munit_void_test_decl(test_nghttp2_hpack_decoder_newname_noinc)
munit_void_test_decl(test_nghttp2_hpack_decoder_newname_inc)
munit_void_test_decl(test_nghttp2_hpack_decoder_clearall_inc)
munit_void_test_decl(test_nghttp2_hpack_decoder_zero_length_huffman)
munit_void_test_decl(test_nghttp2_hpack_decoder_expect_table_size_update)
munit_void_test_decl(test_nghttp2_hpack_decoder_unexpected_table_size_update)
munit_void_test_decl(test_nghttp2_hpack_ringbuf_reserve)
munit_void_test_decl(test_nghttp2_hpack_set_max_dtable_capacity)
munit_void_test_decl(test_nghttp2_hpack_encode_decode)
munit_void_test_decl(test_nghttp2_hpack_never_index)
munit_void_test_decl(test_nghttp2_hpack_bound)
munit_void_test_decl(test_nghttp2_hpack_decode_length)
munit_void_test_decl(test_nghttp2_hpack_huffman_encode)
munit_void_test_decl(test_nghttp2_hpack_huffman_decode)

#endif /* !defined(NGHTTP2_HPACK_TEST_H) */
