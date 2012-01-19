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

void test_spdylay_buffer()
{
  spdylay_buffer buffer;
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
  
  CU_ASSERT(8 == spdylay_buffer_front_length(&buffer));
  CU_ASSERT(memcmp("01234567", spdylay_buffer_front_data(&buffer), 8) == 0);
  spdylay_buffer_pop(&buffer);

  CU_ASSERT(7 == spdylay_buffer_length(&buffer));
  CU_ASSERT(memcmp("89ABCDE", spdylay_buffer_front_data(&buffer), 7) == 0);
  spdylay_buffer_pop(&buffer);

  CU_ASSERT(0 == spdylay_buffer_length(&buffer));

  CU_ASSERT(0 == spdylay_buffer_avail(&buffer));
  CU_ASSERT(NULL == spdylay_buffer_get(&buffer));

  CU_ASSERT(0 == spdylay_buffer_alloc(&buffer));

  CU_ASSERT(8 == spdylay_buffer_avail(&buffer));
  memcpy(spdylay_buffer_get(&buffer), "34567", 5);
  spdylay_buffer_advance(&buffer, 5);
  CU_ASSERT(5 == spdylay_buffer_length(&buffer));
  CU_ASSERT(memcmp("34567", spdylay_buffer_front_data(&buffer), 5) == 0);

  spdylay_buffer_free(&buffer);
}
