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
#include <stdio.h>
#include <string.h>
#include <CUnit/Basic.h>
/* include test cases' include files here */
#include "nghttp2_pq_test.h"
#include "nghttp2_map_test.h"
#include "nghttp2_queue_test.h"
#include "nghttp2_buffer_test.h"
#include "nghttp2_session_test.h"
#include "nghttp2_frame_test.h"
#include "nghttp2_stream_test.h"
#include "nghttp2_hd_test.h"
#include "nghttp2_npn_test.h"
#include "nghttp2_gzip_test.h"

static int init_suite1(void)
{
  return 0;
}

static int clean_suite1(void)
{
  return 0;
}


int main(int argc, char* argv[])
{
   CU_pSuite pSuite = NULL;
   unsigned int num_tests_failed;

   /* initialize the CUnit test registry */
   if (CUE_SUCCESS != CU_initialize_registry())
      return CU_get_error();

   /* add a suite to the registry */
   pSuite = CU_add_suite("libnghttp2_TestSuite", init_suite1, clean_suite1);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* add the tests to the suite */
   if(!CU_add_test(pSuite, "pq", test_nghttp2_pq) ||
      !CU_add_test(pSuite, "map", test_nghttp2_map) ||
      !CU_add_test(pSuite, "map_functional", test_nghttp2_map_functional) ||
      !CU_add_test(pSuite, "map_each_free", test_nghttp2_map_each_free) ||
      !CU_add_test(pSuite, "queue", test_nghttp2_queue) ||
      !CU_add_test(pSuite, "buffer", test_nghttp2_buffer) ||
      !CU_add_test(pSuite, "buffer_reader", test_nghttp2_buffer_reader) ||
      !CU_add_test(pSuite, "npn", test_nghttp2_npn) ||
      !CU_add_test(pSuite, "session_recv", test_nghttp2_session_recv) ||
      !CU_add_test(pSuite, "session_recv_invalid_stream_id",
                   test_nghttp2_session_recv_invalid_stream_id) ||
      !CU_add_test(pSuite, "session_recv_invalid_frame",
                   test_nghttp2_session_recv_invalid_frame) ||
      !CU_add_test(pSuite, "session_recv_eof",
                   test_nghttp2_session_recv_eof) ||
      !CU_add_test(pSuite, "session_recv_data",
                   test_nghttp2_session_recv_data) ||
      !CU_add_test(pSuite, "session_add_frame",
                   test_nghttp2_session_add_frame) ||
      !CU_add_test(pSuite, "session_on_syn_stream_received",
                   test_nghttp2_session_on_syn_stream_received) ||
      !CU_add_test(pSuite, "session_on_syn_reply_received",
                   test_nghttp2_session_on_syn_reply_received) ||
      !CU_add_test(pSuite, "session_on_headers_received",
                   test_nghttp2_session_on_headers_received) ||
      !CU_add_test(pSuite, "session_on_push_reply_received",
                   test_nghttp2_session_on_push_reply_received) ||
      !CU_add_test(pSuite, "session_on_priority_received",
                   test_nghttp2_session_on_priority_received) ||
      !CU_add_test(pSuite, "session_on_rst_stream_received",
                   test_nghttp2_session_on_rst_stream_received) ||
      !CU_add_test(pSuite, "session_on_settings_received",
                   test_nghttp2_session_on_settings_received) ||
      !CU_add_test(pSuite, "session_on_push_promise_received",
                   test_nghttp2_session_on_push_promise_received) ||
      !CU_add_test(pSuite, "session_on_ping_received",
                   test_nghttp2_session_on_ping_received) ||
      !CU_add_test(pSuite, "session_on_goaway_received",
                   test_nghttp2_session_on_goaway_received) ||
      !CU_add_test(pSuite, "session_on_window_update_received",
                   test_nghttp2_session_on_window_update_received) ||
      !CU_add_test(pSuite, "session_on_data_received",
                   test_nghttp2_session_on_data_received) ||
      !CU_add_test(pSuite, "session_send_headers_start_stream",
                   test_nghttp2_session_send_headers_start_stream) ||
      !CU_add_test(pSuite, "session_send_headers_reply",
                   test_nghttp2_session_send_headers_reply) ||
      !CU_add_test(pSuite, "session_send_headers_header_comp_error",
                   test_nghttp2_session_send_headers_header_comp_error) ||
      !CU_add_test(pSuite, "session_send_headers_push_reply",
                   test_nghttp2_session_send_headers_push_reply) ||
      !CU_add_test(pSuite, "session_send_priority",
                   test_nghttp2_session_send_priority) ||
      !CU_add_test(pSuite, "session_send_rst_stream",
                   test_nghttp2_session_send_rst_stream) ||
      !CU_add_test(pSuite, "session_send_push_promise",
                   test_nghttp2_session_send_push_promise) ||
      !CU_add_test(pSuite, "session_is_my_stream_id",
                   test_nghttp2_session_is_my_stream_id) ||
      !CU_add_test(pSuite, "submit_response", test_nghttp2_submit_response) ||
      !CU_add_test(pSuite, "submit_response_without_data",
                   test_nghttp2_submit_response_without_data) ||
      !CU_add_test(pSuite, "submit_request_with_data",
                   test_nghttp2_submit_request_with_data) ||
      !CU_add_test(pSuite, "submit_request_without_data",
                   test_nghttp2_submit_request_without_data) ||
      !CU_add_test(pSuite, "submit_headers_start_stream",
                   test_nghttp2_submit_headers_start_stream) ||
      !CU_add_test(pSuite, "submit_headers_reply",
                   test_nghttp2_submit_headers_reply) ||
      !CU_add_test(pSuite, "submit_headers_push_reply",
                   test_nghttp2_submit_headers_push_reply) ||
      !CU_add_test(pSuite, "submit_headers", test_nghttp2_submit_headers) ||
      !CU_add_test(pSuite, "submit_priority", test_nghttp2_submit_priority) ||
      !CU_add_test(pSuite, "session_submit_settings",
                   test_nghttp2_submit_settings) ||
      !CU_add_test(pSuite, "session_submit_push_promise",
                   test_nghttp2_submit_push_promise) ||
      !CU_add_test(pSuite, "submit_window_update",
                   test_nghttp2_submit_window_update) ||
      !CU_add_test(pSuite, "submit_invalid_nv",
                   test_nghttp2_submit_invalid_nv) ||
      !CU_add_test(pSuite, "session_open_stream",
                   test_nghttp2_session_open_stream) ||
      !CU_add_test(pSuite, "session_get_next_ob_item",
                   test_nghttp2_session_get_next_ob_item) ||
      !CU_add_test(pSuite, "session_pop_next_ob_item",
                   test_nghttp2_session_pop_next_ob_item) ||
      !CU_add_test(pSuite, "session_reply_fail",
                   test_nghttp2_session_reply_fail) ||
      !CU_add_test(pSuite, "session_max_concurrent_streams",
                   test_nghttp2_session_max_concurrent_streams) ||
      !CU_add_test(pSuite, "session_stream_close_on_headers_push",
                   test_nghttp2_session_stream_close_on_headers_push) ||
      !CU_add_test(pSuite, "session_stop_data_with_rst_stream",
                   test_nghttp2_session_stop_data_with_rst_stream) ||
      !CU_add_test(pSuite, "session_defer_data",
                   test_nghttp2_session_defer_data) ||
      !CU_add_test(pSuite, "session_flow_control",
                   test_nghttp2_session_flow_control) ||
      !CU_add_test(pSuite, "session_flow_control_disable",
                   test_nghttp2_session_flow_control_disable) ||
      !CU_add_test(pSuite, "session_data_read_temporal_failure",
                   test_nghttp2_session_data_read_temporal_failure) ||
      !CU_add_test(pSuite, "session_on_request_recv_callback",
                   test_nghttp2_session_on_request_recv_callback) ||
      !CU_add_test(pSuite, "session_on_stream_close",
                   test_nghttp2_session_on_stream_close) ||
      !CU_add_test(pSuite, "session_on_ctrl_not_send",
                   test_nghttp2_session_on_ctrl_not_send) ||
      !CU_add_test(pSuite, "session_get_outbound_queue_size",
                   test_nghttp2_session_get_outbound_queue_size) ||
      !CU_add_test(pSuite, "session_set_option",
                   test_nghttp2_session_set_option) ||
      !CU_add_test(pSuite, "session_data_backoff_by_high_pri_frame",
                   test_nghttp2_session_data_backoff_by_high_pri_frame) ||
      !CU_add_test(pSuite, "frame_nv_sort", test_nghttp2_frame_nv_sort) ||
      !CU_add_test(pSuite, "frame_nv_downcase",
                   test_nghttp2_frame_nv_downcase) ||
      !CU_add_test(pSuite, "frame_nv_check_null",
                   test_nghttp2_frame_nv_check_null) ||
      !CU_add_test(pSuite, "frame_pack_headers",
                   test_nghttp2_frame_pack_headers) ||
      !CU_add_test(pSuite, "frame_pack_headers_frame_too_large",
                   test_nghttp2_frame_pack_headers_frame_too_large) ||
      !CU_add_test(pSuite, "frame_pack_priority",
                   test_nghttp2_frame_pack_priority) ||
      !CU_add_test(pSuite, "frame_pack_rst_stream",
                   test_nghttp2_frame_pack_rst_stream) ||
      !CU_add_test(pSuite, "frame_pack_settings",
                   test_nghttp2_frame_pack_settings) ||
      !CU_add_test(pSuite, "frame_pack_push_promise",
                   test_nghttp2_frame_pack_push_promise) ||
      !CU_add_test(pSuite, "frame_pack_ping", test_nghttp2_frame_pack_ping) ||
      !CU_add_test(pSuite, "frame_pack_goaway",
                   test_nghttp2_frame_pack_goaway) ||
      !CU_add_test(pSuite, "frame_pack_window_update",
                   test_nghttp2_frame_pack_window_update) ||
      !CU_add_test(pSuite, "nv_array_from_cstr",
                   test_nghttp2_nv_array_from_cstr) ||
      !CU_add_test(pSuite, "hd_deflate", test_nghttp2_hd_deflate) ||
      !CU_add_test(pSuite, "hd_inflate_indname_inc",
                   test_nghttp2_hd_inflate_indname_inc) ||
      !CU_add_test(pSuite, "hd_inflate_indname_inc_eviction",
                   test_nghttp2_hd_inflate_indname_inc_eviction) ||
      !CU_add_test(pSuite, "hd_inflate_newname_inc",
                   test_nghttp2_hd_inflate_newname_inc) ||
      !CU_add_test(pSuite, "hd_inflate_indname_subst",
                   test_nghttp2_hd_inflate_newname_inc) ||
      !CU_add_test(pSuite, "hd_inflate_indname_subst_eviction",
                   test_nghttp2_hd_inflate_indname_subst_eviction) ||
      !CU_add_test(pSuite, "hd_inflate_indname_subst_eviction_neg",
                   test_nghttp2_hd_inflate_indname_subst_eviction_neg) ||
      !CU_add_test(pSuite, "hd_inflate_newname_subst",
                   test_nghttp2_hd_inflate_newname_subst) ||
      !CU_add_test(pSuite, "gzip_inflate", test_nghttp2_gzip_inflate)
      ) {
     CU_cleanup_registry();
     return CU_get_error();
   }

   /* Run all tests using the CUnit Basic interface */
   CU_basic_set_mode(CU_BRM_VERBOSE);
   CU_basic_run_tests();
   num_tests_failed = CU_get_number_of_tests_failed();
   CU_cleanup_registry();
   if(CU_get_error() == CUE_SUCCESS) {
     return num_tests_failed;
   } else {
     printf("CUnit Error: %s\n", CU_get_error_msg());
     return CU_get_error();
   }
}
