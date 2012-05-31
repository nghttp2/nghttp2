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
#include "spdylay_test_helper.h"

#include <assert.h>

#include <CUnit/CUnit.h>

#include "spdylay_session.h"

ssize_t unpack_frame_with_nv_block(spdylay_frame_type type,
                                   uint16_t version,
                                   spdylay_frame *frame,
                                   spdylay_zlib *inflater,
                                   const uint8_t *in, size_t len)
{
  spdylay_buffer buffer;
  ssize_t rv;
  ssize_t pnvlen;
  pnvlen = spdylay_frame_nv_offset(type, version) - SPDYLAY_HEAD_LEN;
  assert(pnvlen > 0);

  spdylay_buffer_init(&buffer, 4096);
  rv = spdylay_zlib_inflate_hd(inflater, &buffer,
                               &in[SPDYLAY_HEAD_LEN + pnvlen],
                               len - SPDYLAY_HEAD_LEN - pnvlen);
  if(rv < 0) {
    return rv;
  }
  switch(type) {
  case SPDYLAY_SYN_STREAM:
    rv = spdylay_frame_unpack_syn_stream(&frame->syn_stream,
                                         &in[0], SPDYLAY_HEAD_LEN,
                                         &in[SPDYLAY_HEAD_LEN], pnvlen,
                                         &buffer);
    break;
  case SPDYLAY_SYN_REPLY:
    rv = spdylay_frame_unpack_syn_reply(&frame->syn_reply,
                                        &in[0], SPDYLAY_HEAD_LEN,
                                        &in[SPDYLAY_HEAD_LEN], pnvlen,
                                        &buffer);
    break;
  case SPDYLAY_HEADERS:
    rv = spdylay_frame_unpack_headers(&frame->headers,
                                      &in[0], SPDYLAY_HEAD_LEN,
                                      &in[SPDYLAY_HEAD_LEN], pnvlen,
                                      &buffer);
    break;
  default:
    /* Must not be reachable */
    assert(0);
  }
  spdylay_buffer_free(&buffer);
  return rv;
}
