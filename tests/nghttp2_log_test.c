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
#include "nghttp2_log_test.h"

#include <stdio.h>

#include "nghttp2_log.h"
#include "nghttp2_macro.h"
#include "nghttp2_frame.h"
#include "nghttp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_nghttp2_log_info),
  munit_void_test(test_nghttp2_log_infof),
  munit_void_test(test_nghttp2_log_fr_data),
  munit_void_test(test_nghttp2_log_fr_headers),
  munit_void_test(test_nghttp2_log_fr_rst_stream),
  munit_void_test(test_nghttp2_log_fr_rx_settings),
  munit_void_test(test_nghttp2_log_fr_tx_settings),
  munit_void_test(test_nghttp2_log_fr_ping),
  munit_void_test(test_nghttp2_log_fr_goaway),
  munit_void_test(test_nghttp2_log_fr_window_update),
  munit_void_test(test_nghttp2_log_fr_priority_update),
  munit_void_test(test_nghttp2_log_fr_rx_unknown),
  munit_test_end(),
};

const MunitSuite log_suite = {
  .prefix = "/log",
  .tests = tests,
};

typedef struct log_data {
  char buf[NGHTTP2_LOG_BUFLEN];
  const char *expected[256];
  size_t idx;
} log_data;

static void log_write(void *user_data, char *msg, size_t len) {
  log_data *ld = user_data;

  assert_size(len, ==, strlen(msg));
  assert_size(nghttp2_arraylen(ld->expected), >, ld->idx);
  assert_not_null(ld->expected[ld->idx]);
  assert_string_equal(ld->expected[ld->idx], msg);

  ++ld->idx;
}

static void log_init(nghttp2_log *log, log_data *ld) {
  nghttp2_log_init(log, 0xDEADBEEF, log_write, ld->buf, 0, ld);
  log->last_ts = NGHTTP2_SECONDS + 123 * NGHTTP2_MILLISECONDS;
}

void test_nghttp2_log_info(void) {
  log_data ld;
  nghttp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef con message without formatting directive",
      },
  };

  log_init(&log, &ld);

  nghttp2_log_infof(&log, NGHTTP2_LOG_EVENT_CON,
                    "message without formatting directive");

  assert_null(ld.expected[ld.idx]);
}

void test_nghttp2_log_infof(void) {
  log_data ld;
  nghttp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef con message with formatting directive "
        "888",
      },
  };

  log_init(&log, &ld);

  nghttp2_log_infof(&log, NGHTTP2_LOG_EVENT_CON, "message ", "with",
                    " formatting ", "directive", " ", 888);

  assert_null(ld.expected[ld.idx]);
}

void test_nghttp2_log_fr_data(void) {
  static const nghttp2_frame_data fr = {
    .hd =
      {
        .len = 1000000007,
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM | NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = INT32_MAX,
      },
    .padlen = 99,
    .datalen = 1000000009,
  };
  log_data ld;
  nghttp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef frm tx DATA(0x0) len=1000000007 "
        "flags=PADDED|END_STREAM(0x9) id=0x7fffffff padlen=99 "
        "datalen=1000000009",
      },
  };

  log_init(&log, &ld);

  nghttp2_log_tx_data(&log, &fr);
}

void test_nghttp2_log_fr_headers(void) {
  static const nghttp2_frame_headers fr = {
    .hd =
      {
        .len = 1000000007,
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM |
                 NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_PADDED | NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = INT32_MAX,
      },
    .padlen = 98,
    .field_blocklen = 1000000009,
  };
  log_data ld;
  nghttp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef frm tx HEADERS(0x1) len=1000000007 "
        "flags=PRIORITY|PADDED|END_HEADERS|END_STREAM(0x2d) id=0x7fffffff "
        "padlen=98 field_blocklen=1000000009",
      },
  };

  log_init(&log, &ld);

  nghttp2_log_tx_headers(&log, &fr);
}

void test_nghttp2_log_fr_rst_stream(void) {
  static const nghttp2_frame_rst_stream fr = {
    .hd =
      {
        .len = 1000000007,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = INT32_MAX,
      },
    .error_code = NGHTTP2_PROTOCOL_ERROR,
  };
  log_data ld;
  nghttp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef frm tx RST_STREAM(0x3) len=1000000007 "
        "id=0x7fffffff error_code=PROTOCOL_ERROR(0x1)",
      },
  };

  log_init(&log, &ld);

  nghttp2_log_tx_rst_stream(&log, &fr);
}

void test_nghttp2_log_fr_rx_settings(void) {
  static const nghttp2_proto_settings settings = {
    .hpack_max_dtable_capacity = 1000000009,
    .max_concurrent_streams = 328232323,
    .initial_max_stream_data = INT32_MAX,
    .max_field_section_size = 123456789,
    .enable_connect_protocol = 1,
  };
  static const nghttp2_frame_settings fr = {
    .hd =
      {
        .len = 1000000007,
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .settings = (nghttp2_proto_settings *)&settings,
  };
  static const nghttp2_frame_settings ack = {
    .hd =
      {
        .len = 1000000007,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
        .type = NGHTTP2_FRAME_SETTINGS,
      },
  };
  log_data ld;
  nghttp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef frm rx SETTINGS(0x4) len=1000000007 "
        "flags=(none)(0x0) SETTINGS_HEADER_TABLE_SIZE(0x1)=1000000009",
        "I00001123 0x00000000deadbeef frm rx SETTINGS(0x4) len=1000000007 "
        "flags=(none)(0x0) SETTINGS_MAX_CONCURRENT_STREAMS(0x3)=328232323",
        "I00001123 0x00000000deadbeef frm rx SETTINGS(0x4) len=1000000007 "
        "flags=(none)(0x0) SETTINGS_INITIAL_WINDOW_SIZE(0x4)=2147483647",
        "I00001123 0x00000000deadbeef frm rx SETTINGS(0x4) len=1000000007 "
        "flags=(none)(0x0) SETTINGS_MAX_HEADER_LIST_SIZE(0x6)=123456789",
        "I00001123 0x00000000deadbeef frm rx SETTINGS(0x4) len=1000000007 "
        "flags=(none)(0x0) SETTINGS_ENABLE_CONNECT_PROTOCOL(0x8)=1",
      },
  };

  log_init(&log, &ld);

  nghttp2_log_rx_settings(&log, &fr);

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef frm rx SETTINGS(0x4) len=1000000007 "
        "flags=ACK(0x1)",
      },
  };

  nghttp2_log_rx_settings(&log, &ack);
}

void test_nghttp2_log_fr_tx_settings(void) {
  static const nghttp2_settings_entry iv[] = {
    {
      .id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
      .value = 1000000009,
    },
    {
      .id = NGHTTP2_SETTINGS_ENABLE_PUSH,
      .value = 1,
    },
    {
      .id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
      .value = 328232323,
    },
    {
      .id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
      .value = UINT32_MAX,
    },
    {
      .id = NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
      .value = INT32_MAX,
    },
    {
      .id = NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
      .value = 123456789,
    },
    {
      .id = NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL,
    },
    {
      .id = NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES,
      .value = 1,
    },
  };
  static const nghttp2_frame_settings fr = {
    .hd =
      {
        .len = 1000000007,
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = (nghttp2_settings_entry *)iv,
    .niv = nghttp2_arraylen(iv),
  };
  static const nghttp2_frame_settings ack = {
    .hd =
      {
        .len = 1000000007,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
        .type = NGHTTP2_FRAME_SETTINGS,
      },
  };
  log_data ld;
  nghttp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef frm tx SETTINGS(0x4) len=1000000007 "
        "flags=(none)(0x0) SETTINGS_HEADER_TABLE_SIZE(0x1)=1000000009",
        "I00001123 0x00000000deadbeef frm tx SETTINGS(0x4) len=1000000007 "
        "flags=(none)(0x0) SETTINGS_ENABLE_PUSH(0x2)=1",
        "I00001123 0x00000000deadbeef frm tx SETTINGS(0x4) len=1000000007 "
        "flags=(none)(0x0) SETTINGS_MAX_CONCURRENT_STREAMS(0x3)=328232323",
        "I00001123 0x00000000deadbeef frm tx SETTINGS(0x4) len=1000000007 "
        "flags=(none)(0x0) SETTINGS_INITIAL_WINDOW_SIZE(0x4)=4294967295",
        "I00001123 0x00000000deadbeef frm tx SETTINGS(0x4) len=1000000007 "
        "flags=(none)(0x0) SETTINGS_MAX_FRAME_SIZE(0x5)=2147483647",
        "I00001123 0x00000000deadbeef frm tx SETTINGS(0x4) len=1000000007 "
        "flags=(none)(0x0) SETTINGS_MAX_HEADER_LIST_SIZE(0x6)=123456789",
        "I00001123 0x00000000deadbeef frm tx SETTINGS(0x4) len=1000000007 "
        "flags=(none)(0x0) SETTINGS_ENABLE_CONNECT_PROTOCOL(0x8)=0",
        "I00001123 0x00000000deadbeef frm tx SETTINGS(0x4) len=1000000007 "
        "flags=(none)(0x0) SETTINGS_NO_RFC7540_PRIORITIES(0x9)=1",
      },
  };

  log_init(&log, &ld);

  nghttp2_log_tx_settings(&log, &fr);

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef frm tx SETTINGS(0x4) len=1000000007 "
        "flags=ACK(0x1)",
      },
  };

  nghttp2_log_tx_settings(&log, &ack);
}

void test_nghttp2_log_fr_ping(void) {
  static const nghttp2_frame_ping fr = {
    .hd =
      {
        .len = 1000000007,
        .type = NGHTTP2_FRAME_PING,
      },
    .data =
      {
        .data = {0xFA, 0xCE, 0xCA, 0xCE, 0xBA, 0xAD, 0xBE, 0xEF},
      },
  };
  static const nghttp2_frame_ping ack = {
    .hd =
      {
        .len = 1000000007,
        .type = NGHTTP2_FRAME_PING,
        .flags = NGHTTP2_PING_FLAG_ACK,
      },
    .data =
      {
        .data = {0xFA, 0xCE, 0xCA, 0xCE, 0xBA, 0xAD, 0xBE, 0xEF},
      },
  };
  log_data ld;
  nghttp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef frm tx PING(0x6) len=1000000007 "
        "flags=(none)(0x0) data=facecacebaadbeef",
      },
  };

  log_init(&log, &ld);

  nghttp2_log_tx_ping(&log, &fr);

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef frm tx PING(0x6) len=1000000007 "
        "flags=ACK(0x1) data=facecacebaadbeef",
      },
  };

  nghttp2_log_tx_ping(&log, &ack);
}

void test_nghttp2_log_fr_goaway(void) {
  static const nghttp2_frame_goaway fr = {
    .hd =
      {
        .len = 1000000007,
        .type = NGHTTP2_FRAME_GOAWAY,
      },
    .last_stream_id = 1000000009,
    .error_code = NGHTTP2_ENHANCE_YOUR_CALM,
  };
  log_data ld;
  nghttp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef frm tx GOAWAY(0x7) len=1000000007 "
        "last_stream_id=0x3b9aca09 error_code=ENHANCE_YOUR_CALM(0xb)",
      },
  };

  log_init(&log, &ld);

  nghttp2_log_tx_goaway(&log, &fr);
}

void test_nghttp2_log_fr_window_update(void) {
  static const nghttp2_frame_window_update fr = {
    .hd =
      {
        .len = 1000000007,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
        .stream_id = INT32_MAX,
      },
    .window_size_inc = 1000000009,
  };
  log_data ld;
  nghttp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef frm tx WINDOW_UPDATE(0x8) len=1000000007 "
        "id=0x7fffffff window_size_increment=1000000009",
      },
  };

  log_init(&log, &ld);

  nghttp2_log_tx_window_update(&log, &fr);
}

void test_nghttp2_log_fr_priority_update(void) {
  static const uint8_t pri[] = "u=5,i\xf0";
  static const nghttp2_frame_priority_update fr = {
    .hd =
      {
        .len = 1000000007,
        .type = NGHTTP2_FRAME_PRIORITY_UPDATE,
        .stream_id = INT32_MAX,
      },
    .prioritized_stream_id = 1000000009,
    .pri = pri,
    .prilen = nghttp2_strlen_lit(pri),
  };
  log_data ld;
  nghttp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef frm tx PRIORITY_UPDATE(0x10) "
        "len=1000000007 id=0x7fffffff prioritized_stream_id=0x3b9aca09 "
        "pri=u=5,i.",
      },
  };

  log_init(&log, &ld);

  nghttp2_log_tx_priority_update(&log, &fr);
}

void test_nghttp2_log_fr_rx_unknown(void) {
  static const nghttp2_frame_meta fr = {
    .hd =
      {
        .len = 1000000007,
        .type = 0xEFU,
        .flags = 0x8AU,
        .stream_id = INT32_MAX,
      },
  };
  log_data ld;
  nghttp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0x00000000deadbeef frm rx (unknown)(0xef) len=1000000007 "
        "flags=(none)(0x8a) id=0x7fffffff",
      },
  };

  log_init(&log, &ld);

  nghttp2_log_rx_unknown_frame(&log, &fr);
}
