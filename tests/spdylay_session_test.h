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
#ifndef SPDYLAY_SESSION_TEST_H
#define SPDYLAY_SESSION_TEST_H

void test_spdylay_session_recv();
void test_spdylay_session_recv_invalid_stream_id();
void test_spdylay_session_add_frame();
void test_spdylay_session_on_syn_stream_received();
void test_spdylay_session_on_syn_stream_received_with_push();
void test_spdylay_session_on_syn_reply_received();
void test_spdylay_session_send_syn_stream();
void test_spdylay_session_send_syn_reply();
void test_spdylay_submit_response();
void test_spdylay_submit_request_with_data();
void test_spdylay_submit_request_with_null_data_read_callback();
void test_spdylay_session_reply_fail();
void test_spdylay_session_on_headers_received();
void test_spdylay_session_on_ping_received();
void test_spdylay_session_on_goaway_received();
void test_spdylay_session_on_data_received();
void test_spdylay_session_on_rst_received();
void test_spdylay_session_is_my_stream_id();
void test_spdylay_session_send_rst_stream();
void test_spdylay_session_get_next_ob_item();
void test_spdylay_session_pop_next_ob_item();
void test_spdylay_session_on_request_recv_callback();
void test_spdylay_session_on_stream_close();
void test_spdylay_session_max_concurrent_streams();
void test_spdylay_session_data_backoff_by_high_pri_frame();
void test_spdylay_session_stop_data_with_rst_stream();
void test_spdylay_session_stream_close_on_syn_stream();
void test_spdylay_session_recv_invalid_frame();
void test_spdylay_session_defer_data();

#endif // SPDYLAY_SESSION_TEST_H
