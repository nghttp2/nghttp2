/*
 * nghttp2 - HTTP/2.0 C Library
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
#include "nghttp2_client_cert_vector_test.h"

#include <CUnit/CUnit.h>

#include "nghttp2_client_cert_vector.h"

static nghttp2_origin* create_origin(const char *scheme, const char *host,
                                     uint16_t port)
{
  nghttp2_origin *origin = malloc(sizeof(nghttp2_origin));
  nghttp2_origin_set(origin, scheme, host, port);
  return origin;
}

void test_nghttp2_client_cert_vector_find(void)
{
  nghttp2_client_cert_vector certvec;
  nghttp2_origin *origin;
  const nghttp2_origin *origin_get;
  size_t slot;
  nghttp2_client_cert_vector_init(&certvec, 3);

  origin = create_origin("https", "example.org", 443);
  CU_ASSERT(0 == nghttp2_client_cert_vector_find(&certvec, origin));
  CU_ASSERT(1 == nghttp2_client_cert_vector_put(&certvec, origin));
  slot = nghttp2_client_cert_vector_find(&certvec, origin);
  CU_ASSERT(1 == slot);
  origin_get = nghttp2_client_cert_vector_get_origin(&certvec, slot);
  CU_ASSERT(strcmp(origin->scheme, origin_get->scheme) == 0);
  CU_ASSERT(strcmp(origin->host, origin_get->host) == 0);
  CU_ASSERT(origin->port == origin_get->port);

  origin = create_origin("https", "example.org", 8443);
  CU_ASSERT(0 == nghttp2_client_cert_vector_find(&certvec, origin));
  CU_ASSERT(2 == nghttp2_client_cert_vector_put(&certvec, origin));
  slot = nghttp2_client_cert_vector_find(&certvec, origin);
  CU_ASSERT(2 == slot);

  origin = create_origin("https", "example.com", 443);
  CU_ASSERT(0 == nghttp2_client_cert_vector_find(&certvec, origin));
  CU_ASSERT(3 == nghttp2_client_cert_vector_put(&certvec, origin));
  slot = nghttp2_client_cert_vector_find(&certvec, origin);
  CU_ASSERT(3 == slot);

  origin = create_origin("https", "example.com", 8443);
  CU_ASSERT(0 == nghttp2_client_cert_vector_find(&certvec, origin));
  CU_ASSERT(1 == nghttp2_client_cert_vector_put(&certvec, origin));
  slot = nghttp2_client_cert_vector_find(&certvec, origin);
  CU_ASSERT(1 == slot);

  origin = create_origin("https", "example.org", 443);
  CU_ASSERT(0 == nghttp2_client_cert_vector_find(&certvec, origin));
  free(origin);

  nghttp2_client_cert_vector_free(&certvec);
}

void test_nghttp2_client_cert_vector_resize(void)
{
  nghttp2_client_cert_vector certvec;
  nghttp2_origin *origin;
  size_t i;
  nghttp2_client_cert_vector_init(&certvec, 3);

  origin = create_origin("https", "example.org", 443);
  nghttp2_client_cert_vector_put(&certvec, origin);
  origin = create_origin("https", "example.com", 443);
  nghttp2_client_cert_vector_put(&certvec, origin);

  CU_ASSERT(0 == nghttp2_client_cert_vector_resize(&certvec, 1));
  CU_ASSERT(NULL != nghttp2_client_cert_vector_get_origin(&certvec, 1));
  CU_ASSERT(1 == certvec.last_slot);

  CU_ASSERT(0 == nghttp2_client_cert_vector_resize(&certvec, 8));
  CU_ASSERT(NULL != nghttp2_client_cert_vector_get_origin(&certvec, 1));
  CU_ASSERT(1 == certvec.last_slot);
  for(i = 2; i <= 8; ++i) {
    CU_ASSERT(NULL == nghttp2_client_cert_vector_get_origin(&certvec, i));
  }

  nghttp2_client_cert_vector_free(&certvec);
}

void test_nghttp2_client_cert_vector_get_origin(void)
{
  nghttp2_client_cert_vector certvec;
  nghttp2_origin *origin;
  nghttp2_client_cert_vector_init(&certvec, 3);

  origin = create_origin("https", "example.org", 443);
  CU_ASSERT(1 == nghttp2_client_cert_vector_put(&certvec, origin));

  CU_ASSERT(NULL == nghttp2_client_cert_vector_get_origin(&certvec, 0));
  CU_ASSERT(NULL != nghttp2_client_cert_vector_get_origin(&certvec, 1));
  CU_ASSERT(NULL == nghttp2_client_cert_vector_get_origin(&certvec, 2));
  CU_ASSERT(NULL == nghttp2_client_cert_vector_get_origin(&certvec, 3));
  CU_ASSERT(NULL == nghttp2_client_cert_vector_get_origin(&certvec, 4));

  nghttp2_client_cert_vector_free(&certvec);
}
