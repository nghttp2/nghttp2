/*
 * nghttp2 - HTTP/2 C Library
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
#include "malloc_wrapper.h"

#define __USE_GNU
#include <dlfcn.h>

int nghttp2_failmalloc = 0;
int nghttp2_failstart = 0;
int nghttp2_countmalloc = 1;
int nghttp2_nmalloc = 0;

static void* (*real_malloc)(size_t) = NULL;

static void init(void)
{
  real_malloc = dlsym(RTLD_NEXT, "malloc");
}

void* malloc(size_t size)
{
  if(real_malloc == NULL) {
    init();
  }
  if(nghttp2_failmalloc && nghttp2_nmalloc >= nghttp2_failstart) {
    return NULL;
  } else {
    if(nghttp2_countmalloc) {
      ++nghttp2_nmalloc;
    }
    return real_malloc(size);
  }
}

static int failmalloc_bk, countmalloc_bk;

void nghttp2_failmalloc_pause(void)
{
  failmalloc_bk = nghttp2_failmalloc;
  countmalloc_bk = nghttp2_countmalloc;
  nghttp2_failmalloc = 0;
  nghttp2_countmalloc = 0;
}

void nghttp2_failmalloc_unpause(void)
{
  nghttp2_failmalloc = failmalloc_bk;
  nghttp2_countmalloc = countmalloc_bk;
}
