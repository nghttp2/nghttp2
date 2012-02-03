/*
 * Spdylay - SPDY Library
 *
 * Copyright (c) 2012 Twist Inc.
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

#include <CUnit/CUnit.h>
#include <spdylay/spdylay.h>
#include <string.h>

static void spdy2()
{
  const unsigned char spdy[] = {
    8, 'h', 't', 't', 'p', '/', '1', '.', '0',
    6, 's', 'p', 'd', 'y', '/', '2',
    6, 's', 'p', 'd', 'y', '/', '3'
  };
  unsigned char outlen;
  unsigned char* out;
  CU_ASSERT(2 == spdylay_select_next_protocol(&out, &outlen,
                                              spdy, sizeof(spdy)));
  CU_ASSERT(6 == outlen);
  CU_ASSERT(memcmp("spdy/2", out, 6) == 0);
}

static void spdy4()
{
  const unsigned char spdy[] = {
    6, 's', 'p', 'd', 'y', '/', '4',
    8, 's', 'p', 'd', 'y', '/', '2', '.', '1',
    8, 'h', 't', 't', 'p', '/', '1', '.', '0',
  };
  unsigned char outlen;
  unsigned char* out;
  CU_ASSERT(-1 == spdylay_select_next_protocol(&out, &outlen,
                                               spdy, sizeof(spdy)));
  CU_ASSERT(8 == outlen);
  CU_ASSERT(memcmp("http/1.0", out, outlen) == 0);
}

void test_spdylay_npn()
{
  spdy2();
  spdy4();
}
