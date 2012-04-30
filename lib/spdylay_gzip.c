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

#include <assert.h>
#include <stdlib.h>
#include <zlib.h>
#include "spdylay_gzip.h"

z_stream *spdylay_new_inflate_stream()
{
  int rv;
  z_stream *inflater = malloc(sizeof(z_stream));
  if (inflater == NULL) {
    return NULL;
  }

  inflater->next_in = Z_NULL;
  inflater->zalloc = Z_NULL;
  inflater->zfree = Z_NULL;
  inflater->opaque = Z_NULL;
  rv = inflateInit2(inflater, 47);
  if(rv != Z_OK) {
    free(inflater);
    return NULL;
  }
  return inflater;
}


int spdylay_inflate_data
(z_stream *inflater, uint8_t *out, size_t *outlen_ptr,
 const uint8_t *in, size_t *inlen_ptr) {
  int rv;
  assert(inflater);
  inflater->avail_in = *inlen_ptr;
  inflater->next_in = (unsigned char*)in;
  inflater->avail_out = *outlen_ptr;
  inflater->next_out = out;

  rv = inflate(inflater, Z_NO_FLUSH);

  *inlen_ptr -= inflater->avail_in;
  *outlen_ptr -= inflater->avail_out;
  switch(rv) {
  case Z_OK:
  case Z_STREAM_END:
  case Z_BUF_ERROR:
    return 0;
  case Z_DATA_ERROR:
  case Z_STREAM_ERROR:
  case Z_NEED_DICT:
  case Z_MEM_ERROR:
    return -1;
  default:
    abort();
  }
}

void spdylay_free_inflate_stream(z_stream* stream)
{
  if (stream != NULL) {
    inflateEnd(stream);
    free(stream);
  }
}
