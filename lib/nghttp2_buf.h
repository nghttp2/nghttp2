/*
 * nghttp2 - HTTP/2.0 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
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
#ifndef NGHTTP2_BUF_H
#define NGHTTP2_BUF_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <nghttp2/nghttp2.h>

#include "nghttp2_int.h"

typedef struct {
  /* This points to the beginning of the buffer. The effective range
     of buffer is [begin, end). */
  uint8_t *begin;
  /* This points to the memory one byte beyond the end of the
     buffer. */
  uint8_t *end;
  /* The position indicator for effective start of the buffer. pos <=
     last must be hold. */
  uint8_t *pos;
  /* The position indicator for effective one beyond of the end of the
     buffer. last <= end must be hold. */
  uint8_t *last;
  /* Mark arbitrary position in buffer [begin, end) */
  uint8_t *mark;
} nghttp2_buf;

#define nghttp2_buf_len(BUF) ((BUF)->last - (BUF)->pos)
#define nghttp2_buf_avail(BUF) ((BUF)->end - (BUF)->last)
#define nghttp2_buf_cap(BUF) ((BUF)->end - (BUF)->begin)

#define nghttp2_buf_pos_offset(BUF) ((BUF)->pos - (BUF)->begin)
#define nghttp2_buf_last_offset(BUF) ((BUF)->last - (BUF)->begin)

#define nghttp2_buf_shift_right(BUF, AMT) \
  do {                                    \
    (BUF)->pos += AMT;                    \
    (BUF)->last += AMT;                   \
  } while(0)

#define nghttp2_buf_shift_left(BUF, AMT)            \
  do {                                              \
    (BUF)->pos -= AMT;                              \
    (BUF)->last -= AMT;                             \
  } while(0)

/*
 * Initializes the |buf|. No memory is allocated in this function. Use
 * nghttp2_buf_reserve() or nghttp2_buf_reserve2() to allocate memory.
 */
void nghttp2_buf_init(nghttp2_buf *buf);


/*
 * Initializes the |buf| and allocates at least |initial| bytes of
 * memory.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_buf_init2(nghttp2_buf *buf, size_t initial);

/*
 * Frees buffer in |buf|.
 */
void nghttp2_buf_free(nghttp2_buf *buf);

/*
 * Extends buffer so that nghttp2_buf_cap() returns at least
 * |new_cap|. If extensions took place, buffer pointers in |buf| will
 * change.
 *
 * This function returns 0 if it succeeds, or one of the followings
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_buf_reserve(nghttp2_buf *buf, size_t new_cap);

/*
 * This function behaves like nghttp2_buf_reserve(), but new capacity
 * is calculated as nghttp2_buf_pos_offset(buf) + new_rel_cap. In
 * other words, this function reserves memory at least |new_rel_cap|
 * bytes from buf->pos.
 */
int nghttp2_buf_pos_reserve(nghttp2_buf *buf, size_t new_rel_cap);

/*
 * This function behaves like nghttp2_buf_reserve(), but new capacity
 * is calculated as nghttp2_buf_last_offset(buf) + new_rel_cap. In
 * other words, this function reserves memory at least |new_rel_cap|
 * bytes from buf->last.
 */
int nghttp2_buf_last_reserve(nghttp2_buf *buf, size_t new_rel_cap);

/*
 * Resets pos, last, mark member of |buf| to buf->begin.
 */
void nghttp2_buf_reset(nghttp2_buf *buf);

/*
 * Initializes |buf| using supplied buffer |begin| of length
 * |len|. Semantically, the application should not call *_reserve() or
 * nghttp2_free() functions for |buf|.
 */
void nghttp2_buf_wrap_init(nghttp2_buf *buf, uint8_t *begin, size_t len);

#endif /* NGHTTP2_BUF_H */
