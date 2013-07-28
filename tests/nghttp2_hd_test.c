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
#define ARRLEN(ARR) (sizeof(ARR)/sizeof(ARR[0]))

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

static void check_deflate_inflate(nghttp2_hd_context *deflater,
                                  nghttp2_hd_context *inflater,
                                  nghttp2_nv *nva, size_t nvlen)
{
  uint8_t *buf = NULL;
  size_t buflen = 0;
  ssize_t blocklen;
  nghttp2_nv *resnva;
  ssize_t resnvlen;

  blocklen = nghttp2_hd_deflate_hd(deflater, &buf, &buflen, 0, nva, nvlen);
  assert(blocklen >= 0);
  nghttp2_hd_end_headers(deflater);
  resnvlen = nghttp2_hd_inflate_hd(inflater, &resnva, buf, blocklen);
  CU_ASSERT(resnvlen == (ssize_t)nvlen);
  assert_nv_equal(nva, resnva, nvlen);
  nghttp2_hd_end_headers(inflater);

  free(resnva);
  free(buf);
}

void test_nghttp2_hd_deflate_inflate(void)
{
  nghttp2_hd_context inflater, deflater;
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

  nghttp2_hd_deflate_init(&deflater, NGHTTP2_HD_SIDE_SERVER);
  nghttp2_hd_inflate_init(&inflater, NGHTTP2_HD_SIDE_CLIENT);

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
