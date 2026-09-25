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
#ifndef NGHTTP2_FRAME_READER_H
#define NGHTTP2_FRAME_READER_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <nghttp2v2/nghttp2.h>

#include "nghttp2_frame.h"

typedef enum nghttp2_frame_read_state {
  NGHTTP2_FRAME_READ_STATE_PREFACE,
  NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
  NGHTTP2_FRAME_READ_STATE_FRAME_TYPE,
  NGHTTP2_FRAME_READ_STATE_FRAME_FLAGS,
  NGHTTP2_FRAME_READ_STATE_FRAME_STREAM_ID,
  NGHTTP2_FRAME_READ_STATE_DATA_PADLEN,
  NGHTTP2_FRAME_READ_STATE_DATA_DATA,
  NGHTTP2_FRAME_READ_STATE_DATA_PADDING,
  NGHTTP2_FRAME_READ_STATE_HEADERS_PADLEN,
  NGHTTP2_FRAME_READ_STATE_HEADERS_PRIORITY,
  NGHTTP2_FRAME_READ_STATE_HEADERS_FIELD_BLOCK,
  NGHTTP2_FRAME_READ_STATE_HEADERS_PADDING,
  NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH,
  NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_TYPE,
  NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_FLAGS,
  NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_STREAM_ID,
  NGHTTP2_FRAME_READ_STATE_RST_STREAM_ERROR_CODE,
  NGHTTP2_FRAME_READ_STATE_SETTINGS_SETTINGS,
  NGHTTP2_FRAME_READ_STATE_SETTINGS_VALUE,
  NGHTTP2_FRAME_READ_STATE_PING_DATA,
  NGHTTP2_FRAME_READ_STATE_GOAWAY_LAST_STREAM_ID,
  NGHTTP2_FRAME_READ_STATE_GOAWAY_ERROR_CODE,
  NGHTTP2_FRAME_READ_STATE_GOAWAY_DEBUG_DATA,
  NGHTTP2_FRAME_READ_STATE_WINDOW_UPDATE_WINDOW_SIZE_INC,
  NGHTTP2_FRAME_READ_STATE_PRIORITY_UPDATE_PRIORITIZED_STREAM_ID,
  NGHTTP2_FRAME_READ_STATE_PRIORITY_UPDATE_PRI,
  NGHTTP2_FRAME_READ_STATE_DISCARD_FRAME,
  NGHTTP2_FRAME_READ_STATE_CLOSING,
} nghttp2_frame_read_state;

typedef struct nghttp2_frame_reader {
  nghttp2_frame_read_state state;
  nghttp2_frame fr;
  struct {
    struct {
      size_t num_continuations;
    } headers;
    struct {
      nghttp2_proto_settings data;
      uint32_t min_dtable_capacity;
      uint32_t value;
      uint16_t id;
    } settings;
    struct {
      size_t prilen;
      uint8_t pri[8];
    } priority_update;
  } scratch;
  size_t left;
  size_t field_left;
} nghttp2_frame_reader;

void nghttp2_frame_reader_server_init(nghttp2_frame_reader *frrd);

void nghttp2_frame_reader_reset(nghttp2_frame_reader *frrd);

typedef struct nghttp2_int_reader {
  uint32_t value;
  size_t left;
} nghttp2_int_reader;

/*
 * nghttp2_int_reader_reset resets |ird|.
 */
void nghttp2_int_reader_reset(nghttp2_int_reader *ird);

/*
 * nghttp2_int_reader_final resets |ird| and returns the value.
 */
uint32_t nghttp2_int_reader_final(nghttp2_int_reader *ird);

/*
 * nghttp2_int_reader_final31 behaves like nghttp2_int_reader_final,
 * but the return value is masked with INT32_MAX.
 */
static inline uint32_t nghttp2_int_reader_final31(nghttp2_int_reader *ird) {
  return nghttp2_int_reader_final(ird) & INT32_MAX;
}

/*
 * nghttp2_int_reader_read reads an integer encoded in network byte
 * order.  |fieldlen| is the number of bytes that the integer is
 * encoded.  Before using this function, |ird| must be initialized by
 * nghttp2_int_reader_reset.  When called first time after reset, it
 * records |fieldlen|.  It reads the next |fieldlen| bytes of input as
 * an integer encoded as network byte order.  |src| of length |srclen|
 * is the input bytes.  nghttp2_int_reader_read can be called
 * repeatedly to feed at least |fieldlen| bytes to |ird|.  This
 * function returns the number of bytes read.  Call
 * nghttp2_int_reader_done to know the integer is successfully
 * decoded.  When nghttp2_int_reader_done returns nonzero, call
 * nghttp2_int_reader_final to get the value and reset |ird|.
 */
size_t nghttp2_int_reader_read(nghttp2_int_reader *ird, const uint8_t *src,
                               size_t srclen, size_t fieldlen);

/*
 * nghttp2_int_reader_done returns nonzero if an integer has been
 * successfully decoded.
 */
int nghttp2_int_reader_done(const nghttp2_int_reader *ird);

#endif /* !defined(NGHTTP2_FRAME_READER_H) */
