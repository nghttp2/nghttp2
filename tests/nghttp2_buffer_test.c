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
#include "nghttp2_buffer_test.h"

#include <stdio.h>

#include <CUnit/CUnit.h>

#include "nghttp2_buffer.h"
#include "nghttp2_net.h"

void test_nghttp2_buffer(void)
{
  nghttp2_buffer buffer;
  uint8_t out[1024];
  nghttp2_buffer_init(&buffer, 8);
  CU_ASSERT(0 == nghttp2_buffer_length(&buffer));
  CU_ASSERT(0 == nghttp2_buffer_avail(&buffer));
  CU_ASSERT(NULL == nghttp2_buffer_get(&buffer));
  CU_ASSERT(0 == nghttp2_buffer_alloc(&buffer));

  CU_ASSERT(8 == nghttp2_buffer_avail(&buffer));
  CU_ASSERT(NULL != nghttp2_buffer_get(&buffer));
  memcpy(nghttp2_buffer_get(&buffer), "012", 3);
  nghttp2_buffer_advance(&buffer, 3);
  CU_ASSERT(3 == nghttp2_buffer_length(&buffer));

  CU_ASSERT(5 == nghttp2_buffer_avail(&buffer));
  memcpy(nghttp2_buffer_get(&buffer), "34567", 5);
  nghttp2_buffer_advance(&buffer, 5);
  CU_ASSERT(8 == nghttp2_buffer_length(&buffer));

  CU_ASSERT(0 == nghttp2_buffer_avail(&buffer));
  CU_ASSERT(0 == nghttp2_buffer_alloc(&buffer));
  memcpy(nghttp2_buffer_get(&buffer), "89ABCDE", 7);
  nghttp2_buffer_advance(&buffer, 7);
  CU_ASSERT(15 == nghttp2_buffer_length(&buffer));

  CU_ASSERT(1 == nghttp2_buffer_avail(&buffer));

  nghttp2_buffer_serialize(&buffer, out);
  CU_ASSERT(0 == memcmp("0123456789ABCDE", out, 15));

  nghttp2_buffer_reset(&buffer);

  CU_ASSERT(0 == nghttp2_buffer_length(&buffer));
  CU_ASSERT(0 == nghttp2_buffer_avail(&buffer));
  CU_ASSERT(NULL == nghttp2_buffer_get(&buffer));
  CU_ASSERT(0 == nghttp2_buffer_alloc(&buffer));

  CU_ASSERT(8 == nghttp2_buffer_avail(&buffer));
  memcpy(nghttp2_buffer_get(&buffer), "Hello", 5);
  nghttp2_buffer_advance(&buffer, 5);
  CU_ASSERT(5 == nghttp2_buffer_length(&buffer));

  nghttp2_buffer_serialize(&buffer, out);
  CU_ASSERT(0 == memcmp("Hello", out, 5));

  nghttp2_buffer_free(&buffer);
}

void test_nghttp2_buffer_reader(void)
{
  nghttp2_buffer buffer;
  nghttp2_buffer_reader reader;
  uint16_t val16;
  uint32_t val32;
  uint8_t temp[256];

  nghttp2_buffer_init(&buffer, 3);
  nghttp2_buffer_write(&buffer, (const uint8_t*)"hello", 5);
  val16 = htons(678);
  nghttp2_buffer_write(&buffer, (const uint8_t*)&val16, sizeof(uint16_t));
  val32 = htonl(1000000007);
  nghttp2_buffer_write(&buffer, (const uint8_t*)&val32, sizeof(uint32_t));
  nghttp2_buffer_write(&buffer, (const uint8_t*)"world", 5);

  CU_ASSERT(5+2+4+5 == nghttp2_buffer_length(&buffer));

  nghttp2_buffer_reader_init(&reader, &buffer);

  nghttp2_buffer_reader_data(&reader, temp, 5);
  CU_ASSERT(memcmp(temp, "hello", 5) == 0);
  CU_ASSERT(678 == nghttp2_buffer_reader_uint16(&reader));
  CU_ASSERT(1000000007 == nghttp2_buffer_reader_uint32(&reader));
  CU_ASSERT('w' == nghttp2_buffer_reader_uint8(&reader));
  CU_ASSERT('o' == nghttp2_buffer_reader_uint8(&reader));
  CU_ASSERT('r' == nghttp2_buffer_reader_uint8(&reader));
  CU_ASSERT('l' == nghttp2_buffer_reader_uint8(&reader));
  CU_ASSERT('d' == nghttp2_buffer_reader_uint8(&reader));

  nghttp2_buffer_reader_init(&reader, &buffer);
  nghttp2_buffer_reader_advance(&reader, 5);
  CU_ASSERT(678 == nghttp2_buffer_reader_uint16(&reader));
  nghttp2_buffer_reader_advance(&reader, 1);
  nghttp2_buffer_reader_advance(&reader, 1);
  nghttp2_buffer_reader_advance(&reader, 1);
  nghttp2_buffer_reader_advance(&reader, 1);
  CU_ASSERT('w' == nghttp2_buffer_reader_uint8(&reader));

  nghttp2_buffer_free(&buffer);
}
