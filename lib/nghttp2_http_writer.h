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
#ifndef NGHTTP2_HTTP_WRITER_H
#define NGHTTP2_HTTP_WRITER_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <nghttp2v2/nghttp2.h>

#include "nghttp2_frame.h"
#include "nghttp2_ringbuf.h"
#include "nghttp2_hpack.h"
#include "nghttp2_log.h"

#define NGHTTP2_HTTP_WRITER_FLAG_INPROGRESS 0x01U
#define NGHTTP2_HTTP_WRITER_FLAG_DATA_EOF 0x02U
#define NGHTTP2_HTTP_WRITER_FLAG_DATA_END_STREAM 0x04U

typedef struct nghttp2_conn nghttp2_conn;
typedef struct nghttp2_stream nghttp2_stream;

typedef struct nghttp2_http_writer {
  const nghttp2_mem *mem;
  nghttp2_ringbuf outq;
  size_t field_left;
  nghttp2_write_stream_data_offset write_stream_data_offset;

  /* Only used by HEADERS frame transmission */
  nghttp2_buf header_buf;

  /* Only used by DATA frame transmission */
  nghttp2_vec data[8];
  size_t datacnt;
  size_t data_idx;

  uint32_t flags;
} nghttp2_http_writer;

void nghttp2_http_writer_init(
  nghttp2_http_writer *hw,
  nghttp2_write_stream_data_offset write_stream_data_offset,
  const nghttp2_mem *mem);

void nghttp2_http_writer_free(nghttp2_http_writer *hw);

int nghttp2_http_writer_emplace(nghttp2_http_writer *hw, nghttp2_frame **pfr);

int nghttp2_http_writer_write(nghttp2_http_writer *hw, nghttp2_buf *dest,
                              nghttp2_hpack_encoder *henc,
                              nghttp2_stream *stream, nghttp2_conn *conn,
                              nghttp2_log *log);

int nghttp2_http_writer_write_headers(nghttp2_http_writer *hw,
                                      nghttp2_buf *dest,
                                      const nghttp2_frame_headers *fr,
                                      nghttp2_hpack_encoder *henc,
                                      nghttp2_stream *stream, nghttp2_log *log);

int nghttp2_http_writer_write_data(nghttp2_http_writer *hw, nghttp2_buf *dest,
                                   const nghttp2_frame_data *fr,
                                   nghttp2_stream *stream, nghttp2_conn *conn,
                                   nghttp2_log *log);

int nghttp2_http_writer_inprogress(const nghttp2_http_writer *hw);

int nghttp2_http_writer_empty(const nghttp2_http_writer *hw);

/* nghttp2_http_writer_frame_flow_controlled returns nonzero if the
   frame to send is flow controlled. */
int nghttp2_http_writer_frame_flow_controlled(const nghttp2_http_writer *hw);

#endif /* NGHTTP2_HTTP_WRITER_H */
