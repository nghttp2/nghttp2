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
#include "nghttp2_zlib_test.h"

#include <CUnit/CUnit.h>

#include <stdio.h>

#include "nghttp2_zlib.h"

void test_nghttp2_zlib(void)
{
  nghttp2_zlib deflater, inflater;
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
  nghttp2_buffer buf;
  uint8_t *deflatebuf;
  size_t deflatebuf_max;
  ssize_t deflatebuf_len;
  nghttp2_buffer_init(&buf, 4096);

  CU_ASSERT(0 == nghttp2_zlib_deflate_hd_init(&deflater, 1, 0));
  CU_ASSERT(0 == nghttp2_zlib_inflate_hd_init(&inflater, 0));

  deflatebuf_max = nghttp2_zlib_deflate_hd_bound(&deflater, sizeof(msg));
  deflatebuf = malloc(deflatebuf_max);

  CU_ASSERT(0 < (deflatebuf_len = nghttp2_zlib_deflate_hd
                 (&deflater, deflatebuf, deflatebuf_max,
                  (const uint8_t*)msg, sizeof(msg))));
  CU_ASSERT(sizeof(msg) == nghttp2_zlib_inflate_hd
            (&inflater, &buf, deflatebuf, deflatebuf_len));
  free(deflatebuf);
  nghttp2_buffer_serialize(&buf, inflatebuf);

  nghttp2_zlib_deflate_free(&deflater);
  nghttp2_zlib_inflate_free(&inflater);

  nghttp2_buffer_free(&buf);
}
