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
#include "nghttp2_helper_test.h"

#include <CUnit/CUnit.h>

#include "nghttp2_helper.h"

void test_nghttp2_adjust_local_window_size(void)
{
  int32_t local_window_size = 100;
  int32_t recv_window_size = 50;

  CU_ASSERT(0 == nghttp2_adjust_local_window_size(&local_window_size,
                                                  &recv_window_size, 0));
  CU_ASSERT(100 == local_window_size);
  CU_ASSERT(50 == recv_window_size);

  CU_ASSERT(0 == nghttp2_adjust_local_window_size(&local_window_size,
                                                  &recv_window_size, 49));
  CU_ASSERT(100 == local_window_size);
  CU_ASSERT(1 == recv_window_size);

  CU_ASSERT(0 == nghttp2_adjust_local_window_size(&local_window_size,
                                                  &recv_window_size, 1));
  CU_ASSERT(100 == local_window_size);
  CU_ASSERT(0 == recv_window_size);

  CU_ASSERT(0 == nghttp2_adjust_local_window_size(&local_window_size,
                                                  &recv_window_size, 1));
  CU_ASSERT(101 == local_window_size);
  CU_ASSERT(0 == recv_window_size);

  CU_ASSERT(0 == nghttp2_adjust_local_window_size(&local_window_size,
                                                  &recv_window_size, -1));
  CU_ASSERT(100 == local_window_size);
  CU_ASSERT(0 == recv_window_size);

  recv_window_size = 50;
  CU_ASSERT(NGHTTP2_ERR_FLOW_CONTROL ==
            nghttp2_adjust_local_window_size(&local_window_size,
                                             &recv_window_size,
                                             INT32_MAX));
  CU_ASSERT(100 == local_window_size);
  CU_ASSERT(50 == recv_window_size);

  CU_ASSERT(NGHTTP2_ERR_FLOW_CONTROL ==
            nghttp2_adjust_local_window_size(&local_window_size,
                                             &recv_window_size,
                                             INT32_MIN));
  CU_ASSERT(100 == local_window_size);
  CU_ASSERT(50 == recv_window_size);
}
