/*
 * Spdylay - SPDY Library
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
#include "spdylay_buffer_test.h"

#include <CUnit/CUnit.h>

#include <stdio.h>

#include "spdylay_buffer.h"
#include "spdylay_net.h"

void test_spdylay_buffer(void)
{
  spdylay_buffer buffer;
  uint8_t out[1024];
  spdylay_buffer_init(&buffer, 8);
  CU_ASSERT(0 == spdylay_buffer_length(&buffer));
  CU_ASSERT(0 == spdylay_buffer_avail(&buffer));
  CU_ASSERT(NULL == spdylay_buffer_get(&buffer));
  CU_ASSERT(0 == spdylay_buffer_alloc(&buffer));

  CU_ASSERT(8 == spdylay_buffer_avail(&buffer));
  CU_ASSERT(NULL != spdylay_buffer_get(&buffer));
  memcpy(spdylay_buffer_get(&buffer), "012", 3);
  spdylay_buffer_advance(&buffer, 3);
  CU_ASSERT(3 == spdylay_buffer_length(&buffer));

  CU_ASSERT(5 == spdylay_buffer_avail(&buffer));
  memcpy(spdylay_buffer_get(&buffer), "34567", 5);
  spdylay_buffer_advance(&buffer, 5);
  CU_ASSERT(8 == spdylay_buffer_length(&buffer));

  CU_ASSERT(0 == spdylay_buffer_avail(&buffer));
  CU_ASSERT(0 == spdylay_buffer_alloc(&buffer));
  memcpy(spdylay_buffer_get(&buffer), "89ABCDE", 7);
  spdylay_buffer_advance(&buffer, 7);
  CU_ASSERT(15 == spdylay_buffer_length(&buffer));

  CU_ASSERT(1 == spdylay_buffer_avail(&buffer));

  spdylay_buffer_serialize(&buffer, out);
  CU_ASSERT(0 == memcmp("0123456789ABCDE", out, 15));

  spdylay_buffer_reset(&buffer);

  CU_ASSERT(0 == spdylay_buffer_length(&buffer));
  CU_ASSERT(0 == spdylay_buffer_avail(&buffer));
  CU_ASSERT(NULL == spdylay_buffer_get(&buffer));
  CU_ASSERT(0 == spdylay_buffer_alloc(&buffer));

  CU_ASSERT(8 == spdylay_buffer_avail(&buffer));
  memcpy(spdylay_buffer_get(&buffer), "Hello", 5);
  spdylay_buffer_advance(&buffer, 5);
  CU_ASSERT(5 == spdylay_buffer_length(&buffer));

  spdylay_buffer_serialize(&buffer, out);
  CU_ASSERT(0 == memcmp("Hello", out, 5));

  spdylay_buffer_free(&buffer);
}

void test_spdylay_buffer_reader(void)
{
  spdylay_buffer buffer;
  spdylay_buffer_reader reader;
  uint16_t val16;
  uint32_t val32;
  uint8_t temp[256];

  spdylay_buffer_init(&buffer, 3);
  spdylay_buffer_write(&buffer, (const uint8_t*)"hello", 5);
  val16 = htons(678);
  spdylay_buffer_write(&buffer, (const uint8_t*)&val16, sizeof(uint16_t));
  val32 = htonl(1000000007);
  spdylay_buffer_write(&buffer, (const uint8_t*)&val32, sizeof(uint32_t));
  spdylay_buffer_write(&buffer, (const uint8_t*)"world", 5);

  CU_ASSERT(5+2+4+5 == spdylay_buffer_length(&buffer));

  spdylay_buffer_reader_init(&reader, &buffer);

  spdylay_buffer_reader_data(&reader, temp, 5);
  CU_ASSERT(memcmp(temp, "hello", 5) == 0);
  CU_ASSERT(678 == spdylay_buffer_reader_uint16(&reader));
  CU_ASSERT(1000000007 == spdylay_buffer_reader_uint32(&reader));
  CU_ASSERT('w' == spdylay_buffer_reader_uint8(&reader));
  CU_ASSERT('o' == spdylay_buffer_reader_uint8(&reader));
  CU_ASSERT('r' == spdylay_buffer_reader_uint8(&reader));
  CU_ASSERT('l' == spdylay_buffer_reader_uint8(&reader));
  CU_ASSERT('d' == spdylay_buffer_reader_uint8(&reader));

  spdylay_buffer_reader_init(&reader, &buffer);
  spdylay_buffer_reader_advance(&reader, 5);
  CU_ASSERT(678 == spdylay_buffer_reader_uint16(&reader));
  spdylay_buffer_reader_advance(&reader, 1);
  spdylay_buffer_reader_advance(&reader, 1);
  spdylay_buffer_reader_advance(&reader, 1);
  spdylay_buffer_reader_advance(&reader, 1);
  CU_ASSERT('w' == spdylay_buffer_reader_uint8(&reader));

  spdylay_buffer_free(&buffer);
}
