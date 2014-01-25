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

void test_nghttp2_buffer(void)
{
  nghttp2_buffer buffer;

  nghttp2_buffer_init(&buffer, 16);

  CU_ASSERT(0 == buffer.len);

  CU_ASSERT(0 == nghttp2_buffer_add(&buffer, (const uint8_t*)"foo", 3));
  CU_ASSERT(3 == buffer.len);

  CU_ASSERT(0 == nghttp2_buffer_add_byte(&buffer, '.'));
  CU_ASSERT(4 == buffer.len);

  CU_ASSERT(0 == nghttp2_buffer_add(&buffer,
                                    (const uint8_t*)"012345678901", 12));
  CU_ASSERT(16 == buffer.len);

  CU_ASSERT(NGHTTP2_ERR_BUFFER_ERROR == nghttp2_buffer_add_byte(&buffer, '.'));
  CU_ASSERT(NGHTTP2_ERR_BUFFER_ERROR ==
            nghttp2_buffer_add(&buffer, (const uint8_t*)".", 1));

  nghttp2_buffer_free(&buffer);
}
