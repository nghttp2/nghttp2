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

ssize_t unpack_frame(nghttp2_frame *frame,
                     nghttp2_frame_type type,
                     const uint8_t *in, size_t len)
{
  ssize_t rv;
  switch(type) {
  case NGHTTP2_HEADERS:
    rv = nghttp2_frame_unpack_headers_without_nv
      ((nghttp2_headers*)frame,
       &in[0], NGHTTP2_FRAME_HEAD_LENGTH,
       &in[NGHTTP2_FRAME_HEAD_LENGTH],
       len - NGHTTP2_FRAME_HEAD_LENGTH);
    break;
  case NGHTTP2_PUSH_PROMISE:
    rv = nghttp2_frame_unpack_push_promise_without_nv
      ((nghttp2_push_promise*)frame,
       &in[0], NGHTTP2_FRAME_HEAD_LENGTH,
       &in[NGHTTP2_FRAME_HEAD_LENGTH],
       len - NGHTTP2_FRAME_HEAD_LENGTH);
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

void nva_out_init(nva_out *out)
{
  memset(out->nva, 0, sizeof(out->nva));
  out->nvlen = 0;
}

void nva_out_reset(nva_out *out)
{
  size_t i;
  for(i = 0; i < out->nvlen; ++i) {
    free(out->nva[i].name);
    free(out->nva[i].value);
  }
  memset(out->nva, 0, sizeof(out->nva));
  out->nvlen = 0;
}

void add_out(nva_out *out, nghttp2_nv *nv)
{
  nghttp2_nv *onv = &out->nva[out->nvlen];
  if(nv->namelen) {
    onv->name = malloc(nv->namelen);
    memcpy(onv->name, nv->name, nv->namelen);
  } else {
    onv->name = NULL;
  }
  if(nv->valuelen) {
    onv->value = malloc(nv->valuelen);
    memcpy(onv->value, nv->value, nv->valuelen);
  } else {
    onv->value = NULL;
  }
  onv->namelen = nv->namelen;
  onv->valuelen = nv->valuelen;
  ++out->nvlen;
}

ssize_t inflate_hd(nghttp2_hd_context *inflater, nva_out *out,
                   uint8_t *buf, size_t buflen)
{
  ssize_t rv;
  nghttp2_nv nv;
  int final;
  size_t initial = buflen;

  for(;;) {
    rv = nghttp2_hd_inflate_hd(inflater, &nv, &final, buf, buflen);
    if(rv < 0) {
      return rv;
    }
    buf += rv;
    buflen -= rv;
    if(final) {
      break;
    }
    add_out(out, &nv);
  }
  nghttp2_hd_inflate_end_headers(inflater);
  return initial - buflen;
}
