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
#include "nghttp2_test_helper.h"

#include <assert.h>

#include <CUnit/CUnit.h>

/* #include "nghttp2_session.h" */

ssize_t unpack_frame_with_nv_block(nghttp2_frame *frame,
                                   nghttp2_frame_type type,
                                   nghttp2_hd_context *inflater,
                                   const uint8_t *in, size_t len)
{
  ssize_t rv;
  switch(type) {
  case NGHTTP2_HEADERS:
    rv = nghttp2_frame_unpack_headers((nghttp2_headers*)frame,
                                      &in[0], NGHTTP2_FRAME_HEAD_LENGTH,
                                      &in[NGHTTP2_FRAME_HEAD_LENGTH],
                                      len - NGHTTP2_FRAME_HEAD_LENGTH,
                                      inflater);
    break;
  case NGHTTP2_PUSH_PROMISE:
    rv = nghttp2_frame_unpack_push_promise
      ((nghttp2_push_promise*)frame,
       &in[0], NGHTTP2_FRAME_HEAD_LENGTH,
       &in[NGHTTP2_FRAME_HEAD_LENGTH],
       len - NGHTTP2_FRAME_HEAD_LENGTH,
       inflater);
    break;
  default:
    /* Must not be reachable */
    assert(0);
  }
  return rv;
}

int strmemeq(const char *a, const uint8_t *b, size_t bn)
{
  const uint8_t *c;
  if(!a || !b) {
    return 0;
  }
  c = b + bn;
  for(; *a && b != c && *a == *b; ++a, ++b);
  return !*a && b == c;
}

int nvnameeq(const char *a, nghttp2_nv *nv)
{
  return strmemeq(a, nv->name, nv->namelen);
}

int nvvalueeq(const char *a, nghttp2_nv *nv)
{
  return strmemeq(a, nv->value, nv->valuelen);
}
