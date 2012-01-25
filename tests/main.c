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
#include <stdio.h>
#include <string.h>
#include <CUnit/Basic.h>
/* include test cases' include files here */
#include "spdylay_pq_test.h"
#include "spdylay_map_test.h"
#include "spdylay_queue_test.h"
#include "spdylay_buffer_test.h"
#include "spdylay_zlib_test.h"
#include "spdylay_session_test.h"
#include "spdylay_frame_test.h"

int init_suite1(void)
{
  return 0;
}

int clean_suite1(void)
{
  return 0;
}


int main()
{
   CU_pSuite pSuite = NULL;

   /* initialize the CUnit test registry */
   if (CUE_SUCCESS != CU_initialize_registry())
      return CU_get_error();

   /* add a suite to the registry */
   pSuite = CU_add_suite("libspdylay_TestSuite", init_suite1, clean_suite1);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* add the tests to the suite */
   if(!CU_add_test(pSuite, "pq", test_spdylay_pq) ||
      !CU_add_test(pSuite, "map", test_spdylay_map) ||
      !CU_add_test(pSuite, "queue", test_spdylay_queue) ||
      !CU_add_test(pSuite, "buffer", test_spdylay_buffer) ||
      !CU_add_test(pSuite, "zlib", test_spdylay_zlib) ||
      !CU_add_test(pSuite, "session_recv", test_spdylay_session_recv) ||
      !CU_add_test(pSuite, "session_recv_invalid_stream_id",
                   test_spdylay_session_recv_invalid_stream_id) ||
      !CU_add_test(pSuite, "session_add_frame",
                   test_spdylay_session_add_frame) ||
      !CU_add_test(pSuite, "session_on_syn_stream_received",
                   test_spdylay_session_on_syn_stream_received) ||
      !CU_add_test(pSuite, "session_on_syn_reply_received",
                   test_spdylay_session_on_syn_reply_received) ||
      !CU_add_test(pSuite, "session_send_syn_stream",
                   test_spdylay_session_send_syn_stream) ||
      !CU_add_test(pSuite, "session_send_syn_reply",
                   test_spdylay_session_send_syn_reply) ||
      !CU_add_test(pSuite, "frame_unpack_nv", test_spdylay_frame_unpack_nv) ||
      !CU_add_test(pSuite, "frame_count_nv_space",
                   test_spdylay_frame_count_nv_space)) {
     CU_cleanup_registry();
     return CU_get_error();
   }

   /* Run all tests using the CUnit Basic interface */
   CU_basic_set_mode(CU_BRM_VERBOSE);
   CU_basic_run_tests();
   CU_cleanup_registry();
   return CU_get_error();
}
