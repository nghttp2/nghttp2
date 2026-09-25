/*
 * nghttp2
 *
 * Copyright (c) 2026 nghttp2 contributors
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
#include "nghttp2_ratelim.h"

#include <assert.h>

#include "nghttp2_macro.h"

void nghttp2_ratelim_init(nghttp2_ratelim *rlim, uint64_t burst, uint64_t rate,
                          nghttp2_tstamp ts) {
  burst = nghttp2_min(burst, NGHTTP2_RATELIM_MAX_BURST);

  *rlim = (nghttp2_ratelim){
    .burst = burst,
    .rate = rate,
    .tokens = burst,
    .ts = ts,
  };
}

/* ratelim_update updates rlim->tokens with the current |ts|. */
static void ratelim_update(nghttp2_ratelim *rlim, nghttp2_tstamp ts) {
  uint64_t d, gain, gps;

  assert(ts >= rlim->ts);

  if (ts == rlim->ts) {
    return;
  }

  d = ts - rlim->ts;
  rlim->ts = ts;

  if (rlim->rate <= (UINT64_MAX - rlim->carry) / d) {
    gain = rlim->rate * d + rlim->carry;
    gps = gain / NGHTTP2_SECONDS;

    if (gps < rlim->burst && rlim->tokens < rlim->burst - gps) {
      rlim->tokens += gps;
      rlim->carry = gain % NGHTTP2_SECONDS;

      return;
    }
  }

  rlim->tokens = rlim->burst;
  rlim->carry = 0;
}

int nghttp2_ratelim_drain(nghttp2_ratelim *rlim, uint64_t n,
                          nghttp2_tstamp ts) {
  ratelim_update(rlim, ts);

  if (rlim->tokens < n) {
    return -1;
  }

  rlim->tokens -= n;

  return 0;
}
