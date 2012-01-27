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
#include "spdylay_frame_test.h"

#include <CUnit/CUnit.h>

#include "spdylay_frame.h"

static const char *headers[] = {
  "method", "GET",
  "scheme", "https",
  "url", "/",
  "x-head", "foo",
  "x-head", "bar",
  "version", "HTTP/1.1",
  NULL
};

void test_spdylay_frame_unpack_nv()
{
  uint8_t out[1024];
  char **nv;
  size_t inlen = spdylay_frame_pack_nv(out, (char**)headers);
  CU_ASSERT(0 == spdylay_frame_unpack_nv(&nv, out, inlen));
  spdylay_frame_nv_free(nv);
  free(nv);
}

void test_spdylay_frame_count_nv_space()
{
  CU_ASSERT(83 == spdylay_frame_count_nv_space((char**)headers));
}

void test_spdylay_frame_pack_headers()
{
  spdylay_zlib deflater, inflater;
  spdylay_frame frame, oframe;
  uint8_t *buf;
  ssize_t buflen;
  spdylay_zlib_deflate_hd_init(&deflater);
  spdylay_zlib_inflate_hd_init(&inflater);
  spdylay_frame_headers_init(&frame.headers, SPDYLAY_FLAG_FIN, 3,
                             spdylay_frame_nv_copy(headers));
  buflen = spdylay_frame_pack_headers(&buf, &frame.headers, &deflater);
  CU_ASSERT(0 == spdylay_frame_unpack_headers
            (&oframe.headers,
             &buf[0], SPDYLAY_FRAME_HEAD_LENGTH,
             &buf[SPDYLAY_FRAME_HEAD_LENGTH],
             buflen-SPDYLAY_FRAME_HEAD_LENGTH,
             &inflater));
  free(buf);
  spdylay_frame_headers_free(&oframe.headers);
  spdylay_frame_headers_free(&frame.headers);
  spdylay_zlib_inflate_free(&inflater);
  spdylay_zlib_deflate_free(&deflater);
}
