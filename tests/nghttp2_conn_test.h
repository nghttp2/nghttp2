/*
 * nghttp2
 *
 * Copyright (c) 2026 nghttp2 contributors
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
#ifndef NGHTTP2_CONN_TEST_H
#define NGHTTP2_CONN_TEST_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#define MUNIT_ENABLE_ASSERT_ALIASES

#include "munit.h"

extern const MunitSuite conn_suite;

munit_void_test_decl(test_nghttp2_conn_read_request)
munit_void_test_decl(test_nghttp2_conn_submit_request)
munit_void_test_decl(test_nghttp2_conn_read_preface)
munit_void_test_decl(test_nghttp2_conn_recv_frame_hd)
munit_void_test_decl(test_nghttp2_conn_recv_headers)
munit_void_test_decl(test_nghttp2_conn_recv_continuation)
munit_void_test_decl(test_nghttp2_conn_recv_data)
munit_void_test_decl(test_nghttp2_conn_recv_rst_stream)
munit_void_test_decl(test_nghttp2_conn_recv_settings)
munit_void_test_decl(test_nghttp2_conn_recv_ping)
munit_void_test_decl(test_nghttp2_conn_recv_push_promise)
munit_void_test_decl(test_nghttp2_conn_recv_goaway)
munit_void_test_decl(test_nghttp2_conn_recv_window_update)
munit_void_test_decl(test_nghttp2_conn_recv_priority_update)
munit_void_test_decl(test_nghttp2_conn_recv_unknown_frame)
munit_void_test_decl(test_nghttp2_conn_recv_settings_ack)
munit_void_test_decl(test_nghttp2_conn_conn_rx_flow_control)
munit_void_test_decl(test_nghttp2_conn_stream_rx_flow_control)
munit_void_test_decl(test_nghttp2_conn_submit_ping)
munit_void_test_decl(test_nghttp2_conn_send_ping_ack)
munit_void_test_decl(test_nghttp2_conn_shutdown_stream)
munit_void_test_decl(test_nghttp2_conn_recv_rst_stream_mid_tx_frame)
munit_void_test_decl(test_nghttp2_conn_http_writer)
munit_void_test_decl(test_nghttp2_conn_graceful_shutdown)
munit_void_test_decl(test_nghttp2_conn_stream_concurrency)
munit_void_test_decl(test_nghttp2_conn_rx_flow_control)
munit_void_test_decl(test_nghttp2_conn_tx_flow_control)
munit_void_test_decl(test_nghttp2_conn_http_resp_header)
munit_void_test_decl(test_nghttp2_conn_http_req_header)
munit_void_test_decl(test_nghttp2_conn_http_content_length)
munit_void_test_decl(test_nghttp2_conn_http_content_length_mismatch)
munit_void_test_decl(test_nghttp2_conn_http_non_final_response)
munit_void_test_decl(test_nghttp2_conn_http_trailers)
munit_void_test_decl(test_nghttp2_conn_http_ignore_content_length)
munit_void_test_decl(test_nghttp2_conn_http_record_request_method)
munit_void_test_decl(test_nghttp2_conn_http_error)
munit_void_test_decl(test_nghttp2_conn_resume_stream)
munit_void_test_decl(test_nghttp2_conn_terminate)
munit_void_test_decl(test_nghttp2_conn_handle_expiry)
munit_void_test_decl(test_nghttp2_conn_client_priority_update)
munit_void_test_decl(test_nghttp2_conn_server_priority_update)
munit_void_test_decl(test_nghttp2_conn_rate_limit)
munit_void_test_decl(test_nghttp2_conn_get_streams_left)
munit_void_test_decl(test_nghttp2_conn_is_server)
munit_void_test_decl(test_nghttp2_conn_get_timestamp)
munit_void_test_decl(test_nghttp2_conn_get_stream_priority)

#endif /* !defined(NGHTTP2_CONN_TEST_H) */
