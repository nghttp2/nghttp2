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
#ifndef MALLOC_WRAPPER_H
#define MALLOC_WRAPPER_H

#include <stdlib.h>

/* Global variables to control the behavior of malloc() */

/* If nonzero, malloc failure mode is on */
extern int spdylay_failmalloc;
/* If spdylay_failstart <= spdylay_nmalloc and spdylay_failmalloc is
   nonzero, malloc() fails. */
extern int spdylay_failstart;
/* If nonzero, spdylay_nmalloc is incremented if malloc() succeeds. */
extern int spdylay_countmalloc;
/* The number of successful invocation of malloc(). This value is only
   incremented if spdylay_nmalloc is nonzero. */
extern int spdylay_nmalloc;

void* malloc(size_t size);

/* Copies spdylay_failmalloc and spdylay_countmalloc to statically
   allocated space and sets 0 to them. This will effectively make
   malloc() work like normal malloc(). This is useful when you want to
   disable malloc() failure mode temporarily. */
void spdylay_failmalloc_pause(void);

/* Restores the values of spdylay_failmalloc and spdylay_countmalloc
   with the values saved by the previous
   spdylay_failmalloc_pause(). */
void spdylay_failmalloc_unpause(void);

#endif /* MALLOC_WRAPPER_H */
