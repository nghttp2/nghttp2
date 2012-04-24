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
#include "malloc_wrapper.h"

#define __USE_GNU
#include <dlfcn.h>

int spdylay_failmalloc = 0;
int spdylay_failstart = 0;
int spdylay_countmalloc = 1;
int spdylay_nmalloc = 0;

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
  if(spdylay_failmalloc && spdylay_nmalloc >= spdylay_failstart) {
    return NULL;
  } else {
    if(spdylay_countmalloc) {
      ++spdylay_nmalloc;
    }
    return real_malloc(size);
  }
}

static int failmalloc_bk, countmalloc_bk;

void spdylay_failmalloc_pause(void)
{
  failmalloc_bk = spdylay_failmalloc;
  countmalloc_bk = spdylay_countmalloc;
  spdylay_failmalloc = 0;
  spdylay_countmalloc = 0;
}

void spdylay_failmalloc_unpause(void)
{
  spdylay_failmalloc = failmalloc_bk;
  spdylay_countmalloc = countmalloc_bk;
}
