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
#include "nghttp2_hd_test.h"

#include <stdio.h>
#include <assert.h>

#include <CUnit/CUnit.h>

#include "nghttp2_hd.h"
#include "nghttp2_frame.h"

#define MAKE_NV(NAME, VALUE)                    \
  { (uint8_t*)NAME, (uint8_t*)VALUE, strlen(NAME), strlen(VALUE) }

static void assert_nv_equal(nghttp2_nv *a, nghttp2_nv *b, size_t len)
{
  size_t i;
  for(i = 0; i < len; ++i, ++a, ++b) {
    CU_ASSERT(nghttp2_nv_equal(a, b));
  }
}

void test_nghttp2_hd_deflate(void)
{
  nghttp2_hd_context deflater, inflater;
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
  size_t nv_offset = 12;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  nghttp2_nv *resnva;
  ssize_t blocklen;

  CU_ASSERT(0 == nghttp2_hd_deflate_init(&deflater, NGHTTP2_HD_SIDE_CLIENT));
  CU_ASSERT(0 == nghttp2_hd_inflate_init(&inflater, NGHTTP2_HD_SIDE_SERVER));

  blocklen = nghttp2_hd_deflate_hd(&deflater, &buf, &buflen, nv_offset, nva1,
                                   sizeof(nva1)/sizeof(nghttp2_nv));
  CU_ASSERT(blocklen > 0);
  nghttp2_hd_end_headers(&deflater);

  CU_ASSERT(3 == nghttp2_hd_inflate_hd(&inflater, &resnva, buf + nv_offset,
                                       blocklen));

  assert_nv_equal(nva1, resnva, 3);

  nghttp2_nv_array_del(resnva);
  nghttp2_hd_end_headers(&inflater);

  /* Second headers */
  blocklen = nghttp2_hd_deflate_hd(&deflater, &buf, &buflen, nv_offset, nva2,
                                   sizeof(nva2)/sizeof(nghttp2_nv));
  CU_ASSERT(blocklen > 0);
  nghttp2_hd_end_headers(&deflater);

  CU_ASSERT(2 == nghttp2_hd_inflate_hd(&inflater, &resnva, buf + nv_offset,
                                       blocklen));

  assert_nv_equal(nva2, resnva, 2);

  nghttp2_nv_array_del(resnva);
  nghttp2_hd_end_headers(&inflater);

  /* Third headers, including same header field name, but value is not
     the same. */
  blocklen = nghttp2_hd_deflate_hd(&deflater, &buf, &buflen, nv_offset, nva3,
                                   sizeof(nva3)/sizeof(nghttp2_nv));
  CU_ASSERT(blocklen > 0);
  nghttp2_hd_end_headers(&deflater);

  CU_ASSERT(3 == nghttp2_hd_inflate_hd(&inflater, &resnva, buf + nv_offset,
                                       blocklen));

  assert_nv_equal(nva3, resnva, 3);

  nghttp2_nv_array_del(resnva);
  nghttp2_hd_end_headers(&inflater);

  /* Fourth headers, including duplicate header fields. We don't
     encode duplicates. Only first one is encoded. */
  blocklen = nghttp2_hd_deflate_hd(&deflater, &buf, &buflen, nv_offset, nva4,
                                   sizeof(nva4)/sizeof(nghttp2_nv));
  CU_ASSERT(blocklen > 0);
  nghttp2_hd_end_headers(&deflater);

  CU_ASSERT(2 == nghttp2_hd_inflate_hd(&inflater, &resnva, buf + nv_offset,
                                       blocklen));

  assert_nv_equal(nva4, resnva, 2);

  nghttp2_nv_array_del(resnva);
  nghttp2_hd_end_headers(&inflater);

  /* Fifth headers includes empty value */
  blocklen = nghttp2_hd_deflate_hd(&deflater, &buf, &buflen, nv_offset, nva5,
                                   sizeof(nva5)/sizeof(nghttp2_nv));
  CU_ASSERT(blocklen > 0);
  nghttp2_hd_end_headers(&deflater);

  CU_ASSERT(2 == nghttp2_hd_inflate_hd(&inflater, &resnva, buf + nv_offset,
                                       blocklen));

  assert_nv_equal(nva5, resnva, 2);

  nghttp2_nv_array_del(resnva);
  nghttp2_hd_end_headers(&inflater);

  /* Cleanup */
  free(buf);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_hd_inflate_indname_inc(void)
{
  nghttp2_hd_context inflater;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  size_t offset = 0;
  nghttp2_nv nv = MAKE_NV("user-agent", "nghttp2");
  nghttp2_nv *resnva;
  nghttp2_hd_inflate_init(&inflater, NGHTTP2_HD_SIDE_SERVER);

  CU_ASSERT(0 == nghttp2_hd_emit_indname_block(&buf, &buflen, &offset, 12,
                                               nv.value, nv.valuelen, 1));
  CU_ASSERT(1 == nghttp2_hd_inflate_hd(&inflater, &resnva, buf, offset));
  assert_nv_equal(&nv, resnva, 1);
  CU_ASSERT(39 == inflater.hd_tablelen);
  assert_nv_equal(&nv, &inflater.hd_table[inflater.hd_tablelen-1]->nv, 1);

  nghttp2_nv_array_del(resnva);
  free(buf);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_indname_inc_eviction(void)
{
  nghttp2_hd_context inflater;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  size_t offset = 0;
  /* Default header table capacity is 1592. Adding 2547 bytes,
     including overhead, to the table evicts first entry.
     use name ":host" which index 2 and value length 2510. */
  uint8_t value[2510];
  nghttp2_nv *resnva;
  nghttp2_hd_inflate_init(&inflater, NGHTTP2_HD_SIDE_SERVER);

  CU_ASSERT(0 == nghttp2_hd_emit_indname_block(&buf, &buflen, &offset, 2,
                                               value, sizeof(value), 1));
  CU_ASSERT(1 == nghttp2_hd_inflate_hd(&inflater, &resnva, buf, offset));
  CU_ASSERT(5 == resnva[0].namelen);
  CU_ASSERT(0 == memcmp(":host", resnva[0].name, resnva[0].namelen));
  CU_ASSERT(sizeof(value) == resnva[0].valuelen);

  nghttp2_nv_array_del(resnva);
  nghttp2_hd_end_headers(&inflater);

  CU_ASSERT(38 == inflater.hd_tablelen);
  CU_ASSERT(37 == inflater.refset[0]->index);

  free(buf);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_newname_inc(void)
{
  nghttp2_hd_context inflater;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  size_t offset = 0;
  nghttp2_nv nv = MAKE_NV("x-rel", "nghttp2");
  nghttp2_nv *resnva;
  nghttp2_hd_inflate_init(&inflater, NGHTTP2_HD_SIDE_SERVER);

  CU_ASSERT(0 == nghttp2_hd_emit_newname_block(&buf, &buflen, &offset,
                                               &nv, 1));
  CU_ASSERT(1 == nghttp2_hd_inflate_hd(&inflater, &resnva, buf, offset));
  assert_nv_equal(&nv, resnva, 1);
  CU_ASSERT(39 == inflater.hd_tablelen);
  assert_nv_equal(&nv, &inflater.hd_table[inflater.hd_tablelen-1]->nv, 1);

  nghttp2_nv_array_del(resnva);
  free(buf);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_indname_subst(void)
{
  nghttp2_hd_context inflater;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  size_t offset = 0;
  nghttp2_nv nv = MAKE_NV("user-agent", "nghttp2");
  nghttp2_nv *resnva;
  nghttp2_hd_inflate_init(&inflater, NGHTTP2_HD_SIDE_SERVER);

  CU_ASSERT(0 == nghttp2_hd_emit_subst_indname_block(&buf, &buflen, &offset,
                                                     12,
                                                     nv.value, nv.valuelen,
                                                     12));
  CU_ASSERT(1 == nghttp2_hd_inflate_hd(&inflater, &resnva, buf, offset));
  assert_nv_equal(&nv, resnva, 1);
  CU_ASSERT(38 == inflater.hd_tablelen);
  assert_nv_equal(&nv, &inflater.hd_table[12]->nv, 1);

  nghttp2_nv_array_del(resnva);
  free(buf);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_indname_subst_eviction(void)
{
  nghttp2_hd_context inflater;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  size_t offset = 0;
  /* Default header table capacity is 1592. Adding 2547 bytes,
     including overhead, to the table evicts first entry.
     use name ":host" which index 2 and value length 2510. */
  uint8_t value[2510];
  nghttp2_nv *resnva;
  nghttp2_hd_inflate_init(&inflater, NGHTTP2_HD_SIDE_SERVER);

  CU_ASSERT(0 == nghttp2_hd_emit_subst_indname_block(&buf, &buflen, &offset,
                                                     2,
                                                     value, sizeof(value), 2));
  CU_ASSERT(1 == nghttp2_hd_inflate_hd(&inflater, &resnva, buf, offset));
  CU_ASSERT(5 == resnva[0].namelen);
  CU_ASSERT(0 == memcmp(":host", resnva[0].name, resnva[0].namelen));
  CU_ASSERT(sizeof(value) == resnva[0].valuelen);

  nghttp2_nv_array_del(resnva);
  nghttp2_hd_end_headers(&inflater);

  CU_ASSERT(37 == inflater.hd_tablelen);
  CU_ASSERT(1 == inflater.refset[0]->index);

  free(buf);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_indname_subst_eviction_neg(void)
{
  nghttp2_hd_context inflater;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  size_t offset = 0;
  /* Default header table capacity is 1592. Adding 2548 bytes,
     including overhead, to the table evicts first entry.
     use name ":host" which index 2 and value length 2511. */
  uint8_t value[2511];
  nghttp2_nv *resnva;
  nghttp2_hd_inflate_init(&inflater, NGHTTP2_HD_SIDE_SERVER);
  /* Try to substitute index 0, but it will be evicted */
  CU_ASSERT(0 == nghttp2_hd_emit_subst_indname_block(&buf, &buflen, &offset,
                                                     2,
                                                     value, sizeof(value), 0));
  CU_ASSERT(1 == nghttp2_hd_inflate_hd(&inflater, &resnva, buf, offset));
  CU_ASSERT(5 == resnva[0].namelen);
  CU_ASSERT(0 == memcmp(":host", resnva[0].name, resnva[0].namelen));
  CU_ASSERT(sizeof(value) == resnva[0].valuelen);

  nghttp2_nv_array_del(resnva);
  nghttp2_hd_end_headers(&inflater);

  CU_ASSERT(37 == inflater.hd_tablelen);
  CU_ASSERT(0 == inflater.refset[0]->index);

  free(buf);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_newname_subst(void)
{
  nghttp2_hd_context inflater;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  size_t offset = 0;
  nghttp2_nv nv = MAKE_NV("x-rel", "nghttp2");
  nghttp2_nv *resnva;
  nghttp2_hd_inflate_init(&inflater, NGHTTP2_HD_SIDE_SERVER);

  CU_ASSERT(0 == nghttp2_hd_emit_subst_newname_block(&buf, &buflen, &offset,
                                                     &nv, 1));
  CU_ASSERT(1 == nghttp2_hd_inflate_hd(&inflater, &resnva, buf, offset));
  assert_nv_equal(&nv, resnva, 1);
  CU_ASSERT(38 == inflater.hd_tablelen);
  assert_nv_equal(&nv, &inflater.hd_table[1]->nv, 1);

  nghttp2_nv_array_del(resnva);
  free(buf);
  nghttp2_hd_inflate_free(&inflater);
}
