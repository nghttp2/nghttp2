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
#include "nghttp2_hd_test.h"

#include <stdio.h>
#include <assert.h>

#include <CUnit/CUnit.h>

#include "nghttp2_hd.h"
#include "nghttp2_frame.h"
#include "nghttp2_test_helper.h"

#define GET_TABLE_ENT(context, index) nghttp2_hd_table_get(context, index)

void test_nghttp2_hd_deflate(void)
{
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_nv nva1[] = {MAKE_NV(":path", "/my-example/index.html"),
                       MAKE_NV(":scheme", "https"),
                       MAKE_NV("hello", "world")};
  nghttp2_nv nva2[] = {MAKE_NV(":path", "/script.js"),
                       MAKE_NV(":scheme", "https")};
  nghttp2_nv nva3[] = {MAKE_NV("cookie", "k1=v1"),
                       MAKE_NV("cookie", "k2=v2"),
                       MAKE_NV("via", "proxy")};
  nghttp2_nv nva4[] = {MAKE_NV(":path", "/style.css"),
                       MAKE_NV("cookie", "k1=v1"),
                       MAKE_NV("cookie", "k1=v1")};
  nghttp2_nv nva5[] = {MAKE_NV(":path", "/style.css"),
                       MAKE_NV("x-nghttp2", "")};
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nva_out out;
  int rv;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  CU_ASSERT(0 == nghttp2_hd_deflate_init(&deflater));
  CU_ASSERT(0 == nghttp2_hd_inflate_init(&inflater));

  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva1, ARRLEN(nva1));
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(3 == out.nvlen);
  assert_nv_equal(nva1, out.nva, 3);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  /* Second headers */
  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva2, ARRLEN(nva2));
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(2 == out.nvlen);
  assert_nv_equal(nva2, out.nva, 2);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  /* Third headers, including same header field name, but value is not
     the same. */
  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva3, ARRLEN(nva3));
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(3 == out.nvlen);
  assert_nv_equal(nva3, out.nva, 3);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  /* Fourth headers, including duplicate header fields. */
  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva4, ARRLEN(nva4));
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(3 == out.nvlen);
  assert_nv_equal(nva4, out.nva, 3);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  /* Fifth headers includes empty value */
  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva5, ARRLEN(nva5));
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(2 == out.nvlen);
  assert_nv_equal(nva5, out.nva, 2);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  /* Cleanup */
  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_hd_deflate_same_indexed_repr(void)
{
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_nv nva1[] = {MAKE_NV("cookie", "alpha"),
                       MAKE_NV("cookie", "alpha")};
  nghttp2_nv nva2[] = {MAKE_NV("cookie", "alpha"),
                       MAKE_NV("cookie", "alpha"),
                       MAKE_NV("cookie", "alpha")};
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nva_out out;
  int rv;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  CU_ASSERT(0 == nghttp2_hd_deflate_init(&deflater));
  CU_ASSERT(0 == nghttp2_hd_inflate_init(&inflater));

  /* Encode 2 same headers. cookie:alpha is not in the reference set,
     so first emit literal repr and then 2 emits of indexed repr. */
  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva1, ARRLEN(nva1));
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(2 == out.nvlen);
  assert_nv_equal(nva1, out.nva, 2);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  /* Encode 3 same headers. This time, cookie:alpha is in the
     reference set, so the encoder emits indexed repr 6 times */
  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva2, ARRLEN(nva2));
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen == 6);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(3 == out.nvlen);
  assert_nv_equal(nva2, out.nva, 3);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  /* Cleanup */
  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_hd_deflate_common_header_eviction(void)
{
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_nv nva[] = {MAKE_NV("h1", ""),
                      MAKE_NV("h2", "")};
  nghttp2_bufs bufs;
  ssize_t blocklen;
  /* Default header table capacity is 4096. Adding 2 byte header name
     and 4060 byte value, which is 4094 bytes including overhead, to
     the table evicts first entry. */
  uint8_t value[3038];
  nva_out out;
  size_t i;
  int rv;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  memset(value, '0', sizeof(value));
  for(i = 0; i < 2; ++i) {
    nva[i].value = value;
    nva[i].valuelen = sizeof(value);
  }

  nghttp2_hd_deflate_init(&deflater);
  nghttp2_hd_inflate_init(&inflater);

  /* First emit "h1: ..." to put it in the reference set (index
     = 0). */
  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva, 1);
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(1 == out.nvlen);
  nghttp2_nv_array_sort(nva, 1);
  assert_nv_equal(nva, out.nva, 1);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  /* Encode with second header */

  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva, 2);
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);

  /* Check common header "h1: ...:, which is removed from the
     header table because of eviction, is still emitted by the
     inflater */
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(2 == out.nvlen);
  nghttp2_nv_array_sort(nva, 2);
  assert_nv_equal(nva, out.nva, 2);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  CU_ASSERT(1 == deflater.ctx.hd_table.len);
  CU_ASSERT(1 == inflater.ctx.hd_table.len);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_hd_deflate_clear_refset(void)
{
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nghttp2_nv nv[] = {
    MAKE_NV(":path", "/"),
    MAKE_NV(":scheme", "http")
  };
  size_t i;
  nva_out out;
  int rv;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  nghttp2_hd_deflate_init2(&deflater,
                           NGHTTP2_HD_DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
  nghttp2_hd_deflate_set_no_refset(&deflater, 1);
  nghttp2_hd_inflate_init(&inflater);

  for(i = 0; i < 2; ++i) {
    rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nv, ARRLEN(nv));
    blocklen = nghttp2_bufs_len(&bufs);

    CU_ASSERT(0 == rv);
    CU_ASSERT(blocklen > 1);
    CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

    CU_ASSERT(ARRLEN(nv) == out.nvlen);
    assert_nv_equal(nv, out.nva, ARRLEN(nv));

    nva_out_reset(&out);
    nghttp2_bufs_reset(&bufs);
  }

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_hd_inflate_indname_noinc(void)
{
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nghttp2_nv nv[] = {
    /* Huffman */
    MAKE_NV("user-agent", "nghttp2"),
    /* Expecting no huffman */
    MAKE_NV("user-agent", "x")
  };
  size_t i;
  nva_out out;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  nghttp2_hd_inflate_init(&inflater);

  for(i = 0; i < ARRLEN(nv); ++i) {
    CU_ASSERT(0 == nghttp2_hd_emit_indname_block(&bufs, 56, &nv[i], 0));

    blocklen = nghttp2_bufs_len(&bufs);

    CU_ASSERT(blocklen > 0);
    CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

    CU_ASSERT(1 == out.nvlen);
    assert_nv_equal(&nv[i], out.nva, 1);
    CU_ASSERT(0 == inflater.ctx.hd_table.len);

    nva_out_reset(&out);
    nghttp2_bufs_reset(&bufs);
  }

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_indname_inc(void)
{
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nghttp2_nv nv = MAKE_NV("user-agent", "nghttp2");
  nva_out out;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  nghttp2_hd_inflate_init(&inflater);

  CU_ASSERT(0 == nghttp2_hd_emit_indname_block(&bufs, 56, &nv, 1));

  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1);
  CU_ASSERT(1 == inflater.ctx.hd_table.len);
  assert_nv_equal(&nv,
                  &GET_TABLE_ENT(&inflater.ctx,
                                 inflater.ctx.hd_table.len-1)->nv, 1);

  nva_out_reset(&out);
  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_indname_inc_eviction(void)
{
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  uint8_t value[1024];
  nva_out out;
  nghttp2_nv nv;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  nghttp2_hd_inflate_init(&inflater);

  memset(value, '0', sizeof(value));
  nv.value = value;
  nv.valuelen = sizeof(value);

  nv.flags = NGHTTP2_NV_FLAG_NONE;

  CU_ASSERT(0 == nghttp2_hd_emit_indname_block(&bufs, 13, &nv, 1));
  CU_ASSERT(0 == nghttp2_hd_emit_indname_block(&bufs, 14, &nv, 1));
  CU_ASSERT(0 == nghttp2_hd_emit_indname_block(&bufs, 15, &nv, 1));
  CU_ASSERT(0 == nghttp2_hd_emit_indname_block(&bufs, 16, &nv, 1));

  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(blocklen > 0);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(4 == out.nvlen);
  CU_ASSERT(14 == out.nva[0].namelen);
  CU_ASSERT(0 == memcmp("accept-charset", out.nva[0].name, out.nva[0].namelen));
  CU_ASSERT(sizeof(value) == out.nva[0].valuelen);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  CU_ASSERT(3 == inflater.ctx.hd_table.len);
  CU_ASSERT(GET_TABLE_ENT(&inflater.ctx, 0)->flags & NGHTTP2_HD_FLAG_REFSET);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_newname_noinc(void)
{
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nghttp2_nv nv[] = {
    /* Expecting huffman for both */
    MAKE_NV("my-long-content-length", "nghttp2"),
    /* Expecting no huffman for both */
    MAKE_NV("x", "y"),
    /* Huffman for key only */
    MAKE_NV("my-long-content-length", "y"),
    /* Huffman for value only */
    MAKE_NV("x", "nghttp2")
  };
  size_t i;
  nva_out out;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  nghttp2_hd_inflate_init(&inflater);
  for(i = 0; i < ARRLEN(nv); ++i) {
    CU_ASSERT(0 == nghttp2_hd_emit_newname_block(&bufs, &nv[i], 0));

    blocklen = nghttp2_bufs_len(&bufs);

    CU_ASSERT(blocklen > 0);
    CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

    CU_ASSERT(1 == out.nvlen);
    assert_nv_equal(&nv[i], out.nva, 1);
    CU_ASSERT(0 == inflater.ctx.hd_table.len);

    nva_out_reset(&out);
    nghttp2_bufs_reset(&bufs);
  }

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_newname_inc(void)
{
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nghttp2_nv nv = MAKE_NV("x-rel", "nghttp2");
  nva_out out;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  nghttp2_hd_inflate_init(&inflater);

  CU_ASSERT(0 == nghttp2_hd_emit_newname_block(&bufs, &nv, 1));

  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1);
  CU_ASSERT(1 == inflater.ctx.hd_table.len);
  assert_nv_equal(&nv,
                  &GET_TABLE_ENT(&inflater.ctx,
                                 inflater.ctx.hd_table.len-1)->nv, 1);

  nva_out_reset(&out);
  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_clearall_inc(void)
{
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nghttp2_nv nv;
  uint8_t value[4060];
  nva_out out;

  bufs_large_init(&bufs, 8192);

  nva_out_init(&out);
  /* Total 4097 bytes space required to hold this entry */
  nv.name = (uint8_t*)"alpha";
  nv.namelen = strlen((char*)nv.name);
  memset(value, '0', sizeof(value));
  nv.value = value;
  nv.valuelen = sizeof(value);

  nv.flags = NGHTTP2_NV_FLAG_NONE;

  nghttp2_hd_inflate_init(&inflater);

  CU_ASSERT(0 == nghttp2_hd_emit_newname_block(&bufs, &nv, 1));

  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1);
  CU_ASSERT(0 == inflater.ctx.hd_table.len);

  nva_out_reset(&out);

  /* Do it again */
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1);
  CU_ASSERT(0 == inflater.ctx.hd_table.len);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  /* This time, 4096 bytes space required, which is just fits in the
     header table */
  nv.valuelen = sizeof(value) - 1;

  CU_ASSERT(0 == nghttp2_hd_emit_newname_block(&bufs, &nv, 1));

  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1);
  CU_ASSERT(1 == inflater.ctx.hd_table.len);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_zero_length_huffman(void)
{
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  /* Literal header without indexing - new name */
  uint8_t data[] = { 0x40, 0x01, 0x78 /* 'x' */, 0x80 };
  nva_out out;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);

  nghttp2_bufs_add(&bufs, data, sizeof(data));

  /* /\* Literal header without indexing - new name *\/ */
  /* ptr[0] = 0x40; */
  /* ptr[1] = 1; */
  /* ptr[2] = 'x'; */
  /* ptr[3] = 0x80; */

  nghttp2_hd_inflate_init(&inflater);
  CU_ASSERT(4 == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(1 == out.nvlen);
  CU_ASSERT(1 == out.nva[0].namelen);
  CU_ASSERT('x' == out.nva[0].name[0]);
  CU_ASSERT(NULL == out.nva[0].value);
  CU_ASSERT(0 == out.nva[0].valuelen);

  nva_out_reset(&out);
  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_change_table_size(void)
{
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_nv nva[] = { MAKE_NV(":method", "GET"),
                       MAKE_NV(":path", "/") };
  nghttp2_bufs bufs;
  ssize_t rv;
  nva_out out;
  ssize_t blocklen;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);

  nghttp2_hd_deflate_init(&deflater);
  nghttp2_hd_inflate_init(&inflater);

  /* inflater changes notifies 8000 max header table size */
  CU_ASSERT(0 == nghttp2_hd_inflate_change_table_size(&inflater, 8000));
  CU_ASSERT(0 == nghttp2_hd_deflate_change_table_size(&deflater, 8000));

  CU_ASSERT(127 == deflater.ctx.hd_table.mask);
  CU_ASSERT(8000 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(255 == inflater.ctx.hd_table.mask);
  CU_ASSERT(8000 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(8000 == inflater.settings_hd_table_bufsize_max);

  /* This will emit encoding context update with header table size 4096 */
  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva, 2);
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(2 == deflater.ctx.hd_table.len);
  CU_ASSERT(4096 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));
  CU_ASSERT(2 == inflater.ctx.hd_table.len);
  CU_ASSERT(4096 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(8000 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  /* inflater changes header table size to 1024 */
  CU_ASSERT(0 == nghttp2_hd_inflate_change_table_size(&inflater, 1024));
  CU_ASSERT(0 == nghttp2_hd_deflate_change_table_size(&deflater, 1024));

  CU_ASSERT(127 == deflater.ctx.hd_table.mask);
  CU_ASSERT(1024 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(255 == inflater.ctx.hd_table.mask);
  CU_ASSERT(1024 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(1024 == inflater.settings_hd_table_bufsize_max);

  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva, 2);
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == blocklen);
  CU_ASSERT(2 == deflater.ctx.hd_table.len);
  CU_ASSERT(1024 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));
  CU_ASSERT(2 == inflater.ctx.hd_table.len);
  CU_ASSERT(1024 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(1024 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  /* inflater changes header table size to 0 */
  CU_ASSERT(0 == nghttp2_hd_inflate_change_table_size(&inflater, 0));
  CU_ASSERT(0 == nghttp2_hd_deflate_change_table_size(&deflater, 0));

  CU_ASSERT(127 == deflater.ctx.hd_table.mask);
  CU_ASSERT(0 == deflater.ctx.hd_table.len);
  CU_ASSERT(0 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(255 == inflater.ctx.hd_table.mask);
  CU_ASSERT(0 == inflater.ctx.hd_table.len);
  CU_ASSERT(0 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(0 == inflater.settings_hd_table_bufsize_max);

  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva, 2);
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(0 == deflater.ctx.hd_table.len);
  CU_ASSERT(0 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));
  CU_ASSERT(0 == inflater.ctx.hd_table.len);
  CU_ASSERT(0 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(0 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);

  /* Check table buffer is expanded */
  frame_pack_bufs_init(&bufs);

  nghttp2_hd_deflate_init2(&deflater, 8192);
  nghttp2_hd_inflate_init(&inflater);

  /* First inflater changes header table size to 8000 */
  CU_ASSERT(0 == nghttp2_hd_inflate_change_table_size(&inflater, 8000));
  CU_ASSERT(0 == nghttp2_hd_deflate_change_table_size(&deflater, 8000));

  CU_ASSERT(255 == deflater.ctx.hd_table.mask);
  CU_ASSERT(8000 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(255 == inflater.ctx.hd_table.mask);
  CU_ASSERT(8000 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(8000 == inflater.settings_hd_table_bufsize_max);

  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva, 2);
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(2 == deflater.ctx.hd_table.len);
  CU_ASSERT(8000 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));
  CU_ASSERT(2 == inflater.ctx.hd_table.len);
  CU_ASSERT(8000 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(8000 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  CU_ASSERT(0 == nghttp2_hd_inflate_change_table_size(&inflater, 16383));
  CU_ASSERT(0 == nghttp2_hd_deflate_change_table_size(&deflater, 16383));

  CU_ASSERT(255 == deflater.ctx.hd_table.mask);
  CU_ASSERT(16383 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(511 == inflater.ctx.hd_table.mask);
  CU_ASSERT(16383 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(16383 == inflater.settings_hd_table_bufsize_max);

  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva, 2);
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(2 == deflater.ctx.hd_table.len);
  CU_ASSERT(8192 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));
  CU_ASSERT(2 == inflater.ctx.hd_table.len);
  CU_ASSERT(8192 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(16383 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  /* Lastly, check the error condition */

  rv = nghttp2_hd_emit_table_size(&bufs, 25600);
  CU_ASSERT(rv == 0);
  CU_ASSERT(NGHTTP2_ERR_HEADER_COMP == inflate_hd(&inflater, &out, &bufs, 0));

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);

  /* Check that encoder can handle the case where its allowable buffer
     size is less than default size, 4096 */
  nghttp2_hd_deflate_init2(&deflater, 1024);
  nghttp2_hd_inflate_init(&inflater);

  CU_ASSERT(127 == deflater.ctx.hd_table.mask);
  CU_ASSERT(4096 == deflater.ctx.hd_table_bufsize_max);

  /* This emits context update with buffer size 1024 */
  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva, 2);
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(2 == deflater.ctx.hd_table.len);
  CU_ASSERT(1024 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));
  CU_ASSERT(2 == inflater.ctx.hd_table.len);
  CU_ASSERT(1024 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(4096 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out);
  nghttp2_bufs_reset(&bufs);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}

static void check_deflate_inflate(nghttp2_hd_deflater *deflater,
                                  nghttp2_hd_inflater *inflater,
                                  nghttp2_nv *nva, size_t nvlen)
{
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nva_out out;
  int rv;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  rv = nghttp2_hd_deflate_hd(deflater, &bufs, nva, nvlen);
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen >= 0);

  CU_ASSERT(blocklen == inflate_hd(inflater, &out, &bufs, 0));

  CU_ASSERT(nvlen == out.nvlen);
  assert_nv_equal(nva, out.nva, nvlen);

  nva_out_reset(&out);
  nghttp2_bufs_free(&bufs);
}

void test_nghttp2_hd_deflate_inflate(void)
{
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_nv nv1[] = {
    MAKE_NV(":status", "200 OK"),
    MAKE_NV("access-control-allow-origin", "*"),
    MAKE_NV("cache-control", "private, max-age=0, must-revalidate"),
    MAKE_NV("content-length", "76073"),
    MAKE_NV("content-type", "text/html"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("expires", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("server", "Apache"),
    MAKE_NV("vary", "foobar"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "MISS from alphabravo"),
    MAKE_NV("x-cache-action", "MISS"),
    MAKE_NV("x-cache-age", "0"),
    MAKE_NV("x-cache-lookup", "MISS from alphabravo:3128"),
    MAKE_NV("x-lb-nocache", "true"),
  };
  nghttp2_nv nv2[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=56682045"),
    MAKE_NV("content-type", "text/css"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("expires", "Thu, 14 May 2015 07:22:57 GMT"),
    MAKE_NV("last-modified", "Tue, 14 May 2013 07:22:15 GMT"),
    MAKE_NV("vary", "Accept-Encoding"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128")
  };
  nghttp2_nv nv3[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=56682072"),
    MAKE_NV("content-type", "text/css"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("expires", "Thu, 14 May 2015 07:23:24 GMT"),
    MAKE_NV("last-modified", "Tue, 14 May 2013 07:22:13 GMT"),
    MAKE_NV("vary", "Accept-Encoding"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_nv nv4[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=56682022"),
    MAKE_NV("content-type", "text/css"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("expires", "Thu, 14 May 2015 07:22:34 GMT"),
    MAKE_NV("last-modified", "Tue, 14 May 2013 07:22:14 GMT"),
    MAKE_NV("vary", "Accept-Encoding"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_nv nv5[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=4461139"),
    MAKE_NV("content-type", "application/x-javascript"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("expires", "Mon, 16 Sep 2013 21:34:31 GMT"),
    MAKE_NV("last-modified", "Thu, 05 May 2011 09:15:59 GMT"),
    MAKE_NV("vary", "Accept-Encoding"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_nv nv6[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=18645951"),
    MAKE_NV("content-type", "application/x-javascript"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("expires", "Fri, 28 Feb 2014 01:48:03 GMT"),
    MAKE_NV("last-modified", "Tue, 12 Jul 2011 16:02:59 GMT"),
    MAKE_NV("vary", "Accept-Encoding"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_nv nv7[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=31536000"),
    MAKE_NV("content-type", "application/javascript"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("etag", "\"6807-4dc5b54e0dcc0\""),
    MAKE_NV("expires", "Wed, 21 May 2014 08:32:17 GMT"),
    MAKE_NV("last-modified", "Fri, 10 May 2013 11:18:51 GMT"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_nv nv8[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=31536000"),
    MAKE_NV("content-type", "application/javascript"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("etag", "\"41c6-4de7d28585b00\""),
    MAKE_NV("expires", "Thu, 12 Jun 2014 10:00:58 GMT"),
    MAKE_NV("last-modified", "Thu, 06 Jun 2013 14:30:36 GMT"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_nv nv9[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=31536000"),
    MAKE_NV("content-type", "application/javascript"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("etag", "\"19d6e-4dc5b35a541c0\""),
    MAKE_NV("expires", "Wed, 21 May 2014 08:32:18 GMT"),
    MAKE_NV("last-modified", "Fri, 10 May 2013 11:10:07 GMT"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_nv nv10[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=56682045"),
    MAKE_NV("content-type", "text/css"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("expires", "Thu, 14 May 2015 07:22:57 GMT"),
    MAKE_NV("last-modified", "Tue, 14 May 2013 07:21:53 GMT"),
    MAKE_NV("vary", "Accept-Encoding"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };

  nghttp2_hd_deflate_init(&deflater);
  nghttp2_hd_inflate_init(&inflater);

  check_deflate_inflate(&deflater, &inflater, nv1, ARRLEN(nv1));
  check_deflate_inflate(&deflater, &inflater, nv2, ARRLEN(nv2));
  check_deflate_inflate(&deflater, &inflater, nv3, ARRLEN(nv3));
  check_deflate_inflate(&deflater, &inflater, nv4, ARRLEN(nv4));
  check_deflate_inflate(&deflater, &inflater, nv5, ARRLEN(nv5));
  check_deflate_inflate(&deflater, &inflater, nv6, ARRLEN(nv6));
  check_deflate_inflate(&deflater, &inflater, nv7, ARRLEN(nv7));
  check_deflate_inflate(&deflater, &inflater, nv8, ARRLEN(nv8));
  check_deflate_inflate(&deflater, &inflater, nv9, ARRLEN(nv9));
  check_deflate_inflate(&deflater, &inflater, nv10, ARRLEN(nv10));

  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_hd_no_index(void)
{
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nghttp2_nv nva[] = {
    MAKE_NV(":method", "GET"),
    MAKE_NV(":method", "POST"),
    MAKE_NV(":path", "/foo"),
    MAKE_NV("version", "HTTP/1.1"),
    MAKE_NV(":method", "GET"),
  };
  size_t i;
  nva_out out;
  int rv;

  /* 1st :method: GET can be indexable, last one is not */
  for(i = 1; i < ARRLEN(nva); ++i) {
    nva[i].flags = NGHTTP2_NV_FLAG_NO_INDEX;
  }

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);

  nghttp2_hd_deflate_init(&deflater);
  nghttp2_hd_inflate_init(&inflater);

  rv = nghttp2_hd_deflate_hd(&deflater, &bufs, nva, ARRLEN(nva));
  blocklen = nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  CU_ASSERT(ARRLEN(nva) == out.nvlen);
  assert_nv_equal(nva, out.nva, ARRLEN(nva));

  CU_ASSERT(out.nva[0].flags == NGHTTP2_NV_FLAG_NONE);
  for(i = 1; i < ARRLEN(nva); ++i) {
    CU_ASSERT(out.nva[i].flags == NGHTTP2_NV_FLAG_NO_INDEX);
  }

  nva_out_reset(&out);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}
