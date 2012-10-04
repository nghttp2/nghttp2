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
#include "spdylay_stream_test.h"
#include "spdylay_npn_test.h"
#include "spdylay_client_cert_vector_test.h"
#include "spdylay_gzip_test.h"

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
   pSuite = CU_add_suite("libspdylay_TestSuite", init_suite1, clean_suite1);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* add the tests to the suite */
   if(!CU_add_test(pSuite, "pq", test_spdylay_pq) ||
      !CU_add_test(pSuite, "map", test_spdylay_map) ||
      !CU_add_test(pSuite, "map_functional", test_spdylay_map_functional) ||
      !CU_add_test(pSuite, "map_each_free", test_spdylay_map_each_free) ||
      !CU_add_test(pSuite, "queue", test_spdylay_queue) ||
      !CU_add_test(pSuite, "buffer", test_spdylay_buffer) ||
      !CU_add_test(pSuite, "buffer_reader", test_spdylay_buffer_reader) ||
      !CU_add_test(pSuite, "zlib_spdy2", test_spdylay_zlib_spdy2) ||
      !CU_add_test(pSuite, "zlib_spdy3", test_spdylay_zlib_spdy3) ||
      !CU_add_test(pSuite, "npn", test_spdylay_npn) ||
      !CU_add_test(pSuite, "npn_get_proto_list",
                   test_spdylay_npn_get_proto_list) ||
      !CU_add_test(pSuite, "session_recv", test_spdylay_session_recv) ||
      !CU_add_test(pSuite, "session_recv_invalid_stream_id",
                   test_spdylay_session_recv_invalid_stream_id) ||
      !CU_add_test(pSuite, "session_add_frame",
                   test_spdylay_session_add_frame) ||
      !CU_add_test(pSuite, "session_on_syn_stream_received",
                   test_spdylay_session_on_syn_stream_received) ||
      !CU_add_test(pSuite, "session_on_syn_stream_received_with_push",
                   test_spdylay_session_on_syn_stream_received_with_push) ||
      !CU_add_test(pSuite, "session_on_syn_reply_received",
                   test_spdylay_session_on_syn_reply_received) ||
      !CU_add_test(pSuite, "session_send_syn_stream",
                   test_spdylay_session_send_syn_stream) ||
      !CU_add_test(pSuite, "session_send_syn_reply",
                   test_spdylay_session_send_syn_reply) ||
      !CU_add_test(pSuite, "submit_response", test_spdylay_submit_response) ||
      !CU_add_test(pSuite, "submit_response_without_data",
                   test_spdylay_submit_response_with_null_data_read_callback) ||
      !CU_add_test(pSuite, "submit_request_with_data",
                   test_spdylay_submit_request_with_data) ||
      !CU_add_test(pSuite, "submit_request_without_data",
                   test_spdylay_submit_request_with_null_data_read_callback) ||
      !CU_add_test(pSuite, "submit_syn_stream",
                   test_spdylay_submit_syn_stream) ||
      !CU_add_test(pSuite, "submit_syn_reply", test_spdylay_submit_syn_reply) ||
      !CU_add_test(pSuite, "submit_headers", test_spdylay_submit_headers) ||
      !CU_add_test(pSuite, "submit_invalid_nv",
                   test_spdylay_submit_invalid_nv) ||
      !CU_add_test(pSuite, "session_reply_fail",
                   test_spdylay_session_reply_fail) ||
      !CU_add_test(pSuite, "session_on_headers_received",
                   test_spdylay_session_on_headers_received) ||
      !CU_add_test(pSuite, "session_on_window_update_received",
                   test_spdylay_session_on_window_update_received) ||
      !CU_add_test(pSuite, "session_on_ping_received",
                   test_spdylay_session_on_ping_received) ||
      !CU_add_test(pSuite, "session_on_goaway_received",
                   test_spdylay_session_on_goaway_received) ||
      !CU_add_test(pSuite, "session_on_data_received",
                   test_spdylay_session_on_data_received) ||
      !CU_add_test(pSuite, "session_on_rst_stream_received",
                   test_spdylay_session_on_rst_received) ||
      !CU_add_test(pSuite, "session_is_my_stream_id",
                   test_spdylay_session_is_my_stream_id) ||
      !CU_add_test(pSuite, "session_send_rst_stream",
                   test_spdylay_session_send_rst_stream) ||
      !CU_add_test(pSuite, "session_get_next_ob_item",
                   test_spdylay_session_get_next_ob_item) ||
      !CU_add_test(pSuite, "session_pop_next_ob_item",
                   test_spdylay_session_pop_next_ob_item) ||
      !CU_add_test(pSuite, "session_on_request_recv_callback",
                   test_spdylay_session_on_request_recv_callback) ||
      !CU_add_test(pSuite, "session_on_stream_close",
                   test_spdylay_session_on_stream_close) ||
      !CU_add_test(pSuite, "session_max_concurrent_streams",
                   test_spdylay_session_max_concurrent_streams) ||
      !CU_add_test(pSuite, "session_data_backoff_by_high_pri_frame",
                   test_spdylay_session_data_backoff_by_high_pri_frame) ||
      !CU_add_test(pSuite, "session_stop_data_with_rst_stream",
                   test_spdylay_session_stop_data_with_rst_stream) ||
      !CU_add_test(pSuite, "session_stream_close_on_syn_stream",
                   test_spdylay_session_stream_close_on_syn_stream) ||
      !CU_add_test(pSuite, "session_recv_invalid_frame",
                   test_spdylay_session_recv_invalid_frame) ||
      !CU_add_test(pSuite, "session_defer_data",
                   test_spdylay_session_defer_data) ||
      !CU_add_test(pSuite, "session_flow_control",
                   test_spdylay_session_flow_control) ||
      !CU_add_test(pSuite, "session_on_ctrl_not_send",
                   test_spdylay_session_on_ctrl_not_send) ||
      !CU_add_test(pSuite, "session_on_settings_received",
                   test_spdylay_session_on_settings_received) ||
      !CU_add_test(pSuite, "session_submit_settings",
                   test_spdylay_submit_settings) ||
      !CU_add_test(pSuite, "session_get_outbound_queue_size",
                   test_spdylay_session_get_outbound_queue_size) ||
      !CU_add_test(pSuite, "session_prep_credential",
                   test_spdylay_session_prep_credential) ||
      !CU_add_test(pSuite, "session_submit_syn_stream_with_credential",
                   test_spdylay_submit_syn_stream_with_credential) ||
      !CU_add_test(pSuite, "session_set_initial_client_cert_origin",
                   test_spdylay_session_set_initial_client_cert_origin) ||
      !CU_add_test(pSuite, "session_set_option",
                   test_spdylay_session_set_option) ||
      !CU_add_test(pSuite, "submit_window_update",
                   test_spdylay_submit_window_update) ||
      !CU_add_test(pSuite, "session_data_read_temporal_failure",
                   test_spdylay_session_data_read_temporal_failure) ||
      !CU_add_test(pSuite, "session_recv_eof",
                   test_spdylay_session_recv_eof) ||
      !CU_add_test(pSuite, "session_recv_data",
                   test_spdylay_session_recv_data) ||
      !CU_add_test(pSuite, "frame_unpack_nv_spdy2",
                   test_spdylay_frame_unpack_nv_spdy2) ||
      !CU_add_test(pSuite, "frame_unpack_nv_spdy3",
                   test_spdylay_frame_unpack_nv_spdy3) ||
      !CU_add_test(pSuite, "frame_count_nv_space",
                   test_spdylay_frame_count_nv_space) ||
      !CU_add_test(pSuite, "frame_count_unpack_nv_space",
                   test_spdylay_frame_count_unpack_nv_space) ||
      !CU_add_test(pSuite, "frame_pack_ping", test_spdylay_frame_pack_ping) ||
      !CU_add_test(pSuite, "frame_pack_goaway_spdy2",
                   test_spdylay_frame_pack_goaway_spdy2) ||
      !CU_add_test(pSuite, "frame_pack_goaway_spdy3",
                   test_spdylay_frame_pack_goaway_spdy3) ||
      !CU_add_test(pSuite, "frame_pack_syn_stream_spdy2",
                   test_spdylay_frame_pack_syn_stream_spdy2) ||
      !CU_add_test(pSuite, "frame_pack_syn_stream_spdy3",
                   test_spdylay_frame_pack_syn_stream_spdy3) ||
      !CU_add_test(pSuite, "frame_pack_syn_stream_frame_too_large",
                   test_spdylay_frame_pack_syn_stream_frame_too_large) ||
      !CU_add_test(pSuite, "frame_pack_syn_reply_spdy2",
                   test_spdylay_frame_pack_syn_reply_spdy2) ||
      !CU_add_test(pSuite, "frame_pack_syn_reply_spdy3",
                   test_spdylay_frame_pack_syn_reply_spdy3) ||
      !CU_add_test(pSuite, "frame_pack_headers_spdy2",
                   test_spdylay_frame_pack_headers_spdy2) ||
      !CU_add_test(pSuite, "frame_pack_headers_spdy3",
                   test_spdylay_frame_pack_headers_spdy3) ||
      !CU_add_test(pSuite, "frame_pack_window_update",
                   test_spdylay_frame_pack_window_update) ||
      !CU_add_test(pSuite, "frame_pack_settings_spdy2",
                   test_spdylay_frame_pack_settings_spdy2) ||
      !CU_add_test(pSuite, "frame_pack_settings_spdy3",
                   test_spdylay_frame_pack_settings_spdy3) ||
      !CU_add_test(pSuite, "frame_pack_credential",
                   test_spdylay_frame_pack_credential) ||
      !CU_add_test(pSuite, "frame_nv_sort", test_spdylay_frame_nv_sort) ||
      !CU_add_test(pSuite, "frame_nv_downcase",
                   test_spdylay_frame_nv_downcase) ||
      !CU_add_test(pSuite, "frame_pack_nv_duplicate_keys",
                   test_spdylay_frame_pack_nv_duplicate_keys) ||
      !CU_add_test(pSuite, "frame_nv_2to3", test_spdylay_frame_nv_2to3) ||
      !CU_add_test(pSuite, "frame_nv_3to2", test_spdylay_frame_nv_3to2) ||
      !CU_add_test(pSuite, "frame_unpack_nv_check_name_spdy2",
                   test_spdylay_frame_unpack_nv_check_name_spdy2) ||
      !CU_add_test(pSuite, "frame_unpack_nv_check_name_spdy3",
                   test_spdylay_frame_unpack_nv_check_name_spdy3) ||
      !CU_add_test(pSuite, "frame_nv_set_origin",
                   test_spdylay_frame_nv_set_origin) ||
      !CU_add_test(pSuite, "stream_add_pushed_stream",
                   test_spdylay_stream_add_pushed_stream) ||
      !CU_add_test(pSuite, "client_cert_vector_find",
                   test_spdylay_client_cert_vector_find) ||
      !CU_add_test(pSuite, "client_cert_vector_resize",
                   test_spdylay_client_cert_vector_resize) ||
      !CU_add_test(pSuite, "client_cert_vector_get_origin",
                   test_spdylay_client_cert_vector_get_origin) ||
      !CU_add_test(pSuite, "gzip_inflate", test_spdylay_gzip_inflate)) {
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
