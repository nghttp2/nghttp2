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
#include "spdylay_zlib_test.h"

#include <CUnit/CUnit.h>

#include <stdio.h>

#include "spdylay_zlib.h"

static void test_spdylay_zlib_with(uint16_t version)
{
  spdylay_zlib deflater, inflater;
  const char msg[] =
    "GET /chat HTTP/1.1\r\n"
    "Host: server.example.com\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Origin: http://example.com\r\n"
    "Sec-WebSocket-Protocol: chat, superchat\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n";
  uint8_t inflatebuf[sizeof(msg)];
  spdylay_buffer buf;
  uint8_t *deflatebuf;
  size_t deflatebuf_max;
  ssize_t deflatebuf_len;
  spdylay_buffer_init(&buf, 4096);

  CU_ASSERT(0 == spdylay_zlib_deflate_hd_init(&deflater, 1,
                                              version));
  CU_ASSERT(0 == spdylay_zlib_inflate_hd_init(&inflater, version));

  deflatebuf_max = spdylay_zlib_deflate_hd_bound(&deflater, sizeof(msg));
  deflatebuf = malloc(deflatebuf_max);

  CU_ASSERT(0 < (deflatebuf_len = spdylay_zlib_deflate_hd
                 (&deflater, deflatebuf, deflatebuf_max,
                  (const uint8_t*)msg, sizeof(msg))));
  CU_ASSERT(sizeof(msg) == spdylay_zlib_inflate_hd
            (&inflater, &buf, deflatebuf, deflatebuf_len));
  free(deflatebuf);
  spdylay_buffer_serialize(&buf, inflatebuf);

  spdylay_zlib_deflate_free(&deflater);
  spdylay_zlib_inflate_free(&inflater);

  spdylay_buffer_free(&buf);
}

void test_spdylay_zlib_spdy2(void)
{
  test_spdylay_zlib_with(SPDYLAY_PROTO_SPDY2);
}

void test_spdylay_zlib_spdy3(void)
{
  test_spdylay_zlib_with(SPDYLAY_PROTO_SPDY3);
}
