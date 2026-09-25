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
#include "nghttp2_http_writer.h"

#include <assert.h>

#include "nghttp2_macro.h"
#include "nghttp2_str.h"
#include "nghttp2_conn.h"
#include "nghttp2_stream.h"
#include "nghttp2_vec.h"

void nghttp2_http_writer_init(
  nghttp2_http_writer *hw,
  nghttp2_write_stream_data_offset write_stream_data_offset,
  const nghttp2_mem *mem) {
  hw->mem = mem;
  /* This does not allocate memory, and it always succeeds. */
  nghttp2_ringbuf_init(&hw->outq, 0, sizeof(nghttp2_frame), mem);
  hw->write_stream_data_offset = write_stream_data_offset;
  nghttp2_buf_init(&hw->header_buf);
  hw->datacnt = 0;
}

void nghttp2_http_writer_free(nghttp2_http_writer *hw) {
  const nghttp2_mem *mem;
  nghttp2_frame *fr;
  size_t i;

  if (!hw) {
    return;
  }

  mem = hw->mem;

  nghttp2_buf_free(&hw->header_buf, mem);

  for (i = 0; i < nghttp2_ringbuf_len(&hw->outq); ++i) {
    fr = nghttp2_ringbuf_get(&hw->outq, i);

    if (fr->meta.hd.type != NGHTTP2_FRAME_HEADERS) {
      continue;
    }

    nghttp2_mem_free(mem, fr->headers.nva);
  }

  nghttp2_ringbuf_free(&hw->outq);
}

int nghttp2_http_writer_emplace(nghttp2_http_writer *hw, nghttp2_frame **pfr) {
  int rv;

  if (nghttp2_ringbuf_full(&hw->outq)) {
    rv = nghttp2_ringbuf_reserve(
      &hw->outq, nghttp2_max(4, nghttp2_ringbuf_len(&hw->outq) * 2));
    if (rv != 0) {
      return rv;
    }
  }

  *pfr = nghttp2_ringbuf_push_back(&hw->outq);

  return 0;
}

int nghttp2_http_writer_write(nghttp2_http_writer *hw, nghttp2_buf *dest,
                              nghttp2_hpack_encoder *henc,
                              nghttp2_stream *stream, nghttp2_conn *conn,
                              nghttp2_log *log) {
  const nghttp2_frame *fr;
  int rv;

  if (nghttp2_ringbuf_len(&hw->outq) == 0) {
    return 0;
  }

  fr = nghttp2_ringbuf_get(&hw->outq, 0);
  if (fr->meta.hd.type == NGHTTP2_FRAME_HEADERS) {
    rv = nghttp2_http_writer_write_headers(hw, dest, &fr->headers, henc, stream,
                                           log);
    if (rv != 0) {
      return rv;
    }

    return 0;
  }

  assert(NGHTTP2_FRAME_DATA == fr->meta.hd.type);

  rv = nghttp2_http_writer_write_data(hw, dest, &fr->data, stream, conn, log);
  if (rv != 0) {
    return rv;
  }

  return 0;
}

static void http_writer_on_end_headers(nghttp2_http_writer *hw,
                                       const nghttp2_frame_headers *fr) {
  hw->flags &= ~NGHTTP2_HTTP_WRITER_FLAG_INPROGRESS;

  nghttp2_buf_reset(&hw->header_buf);
  nghttp2_mem_free(hw->mem, (nghttp2_nv *)fr->nva);
  nghttp2_ringbuf_pop_front(&hw->outq);
}

int nghttp2_http_writer_write_headers(
  nghttp2_http_writer *hw, nghttp2_buf *dest, const nghttp2_frame_headers *fr,
  nghttp2_hpack_encoder *henc, nghttp2_stream *stream, nghttp2_log *log) {
  nghttp2_frame_headers lfr;
  size_t nwrite;
  int rv;

  if (!(hw->flags & NGHTTP2_HTTP_WRITER_FLAG_INPROGRESS)) {
    if (nghttp2_buf_left(dest) < NGHTTP2_FRAME_HDLEN) {
      return NGHTTP2_ERR_NOBUF;
    }

    rv = nghttp2_hpack_encoder_write(henc, &hw->header_buf, fr->nva, fr->nvlen);
    if (rv != 0) {
      return rv;
    }

    hw->flags |= NGHTTP2_HTTP_WRITER_FLAG_INPROGRESS;
  }

  if (hw->field_left == 0) {
    if (nghttp2_buf_left(dest) < NGHTTP2_FRAME_HDLEN) {
      return NGHTTP2_ERR_NOBUF;
    }

    hw->field_left = nghttp2_min(NGHTTP2_DEFAULT_MAX_FRAME_SIZE,
                                 nghttp2_buf_len(&hw->header_buf));

    lfr.hd = fr->hd;
    lfr.hd.len = (uint32_t)hw->field_left;
    lfr.padlen = 0;
    lfr.field_blocklen = lfr.hd.len;

    if (hw->header_buf.pos == hw->header_buf.begin) {
      if (lfr.hd.len == nghttp2_buf_len(&hw->header_buf)) {
        lfr.hd.flags |= NGHTTP2_HEADERS_FLAG_END_HEADERS;
      } else {
        lfr.hd.flags &= (uint8_t)~NGHTTP2_HEADERS_FLAG_END_HEADERS;
      }

      nghttp2_log_tx_headers(log, &lfr);
    } else {
      lfr.hd.type = NGHTTP2_FRAME_CONTINUATION;
      if (lfr.hd.len == nghttp2_buf_len(&hw->header_buf)) {
        lfr.hd.flags = NGHTTP2_HEADERS_FLAG_END_HEADERS;
      } else {
        lfr.hd.flags = 0x00U;
      }

      nghttp2_log_tx_continuation(log, &lfr);
    }

    dest->last = nghttp2_frame_encode_hd(dest->last, &lfr.hd);

    stream->flags |= NGHTTP2_STREAM_FLAG_OPENED;

    if (hw->field_left == 0) {
      http_writer_on_end_headers(hw, fr);
      return 0;
    }

    if (nghttp2_buf_left(dest) == 0) {
      return 0;
    }
  }

  nwrite = nghttp2_min(hw->field_left, nghttp2_buf_left(dest));
  if (nwrite == 0) {
    return NGHTTP2_ERR_NOBUF;
  }

  dest->last = nghttp2_cpymem(dest->last, hw->header_buf.pos, nwrite);

  hw->header_buf.pos += nwrite;
  hw->field_left -= nwrite;

  if (nghttp2_buf_len(&hw->header_buf) == 0) {
    http_writer_on_end_headers(hw, fr);
  }

  return 0;
}

static size_t conn_flow_control_limit(const nghttp2_conn *conn) {
  if (conn->tx.max_offset <= conn->tx.offset) {
    return 0;
  }

  return (size_t)(conn->tx.max_offset - conn->tx.offset);
}

static size_t stream_flow_control_limit(const nghttp2_stream *stream) {
  if (stream->tx.max_offset <= stream->tx.offset) {
    return 0;
  }

  return (size_t)(stream->tx.max_offset - stream->tx.offset);
}

int nghttp2_http_writer_write_data(nghttp2_http_writer *hw, nghttp2_buf *dest,
                                   const nghttp2_frame_data *fr,
                                   nghttp2_stream *stream, nghttp2_conn *conn,
                                   nghttp2_log *log) {
  nghttp2_frame_data lfr;
  nghttp2_vec *v;
  nghttp2_ssize datacnt;
  uint64_t left;
  size_t conn_fc_limit;
  size_t stream_fc_limit;
  size_t nwrite;
  uint32_t flags;
  int rv;

  if (hw->datacnt == 0) {
    if (nghttp2_buf_left(dest) < NGHTTP2_FRAME_HDLEN) {
      return NGHTTP2_ERR_NOBUF;
    }

    assert(fr->dr.read_data);

    flags = 0;
    datacnt = fr->dr.read_data(conn, stream->stream_id, hw->data,
                               nghttp2_arraylen(hw->data), &flags,
                               conn->user_data, stream->user_data);
    if (datacnt < 0) {
      if (datacnt == NGHTTP2_ERR_WOULDBLOCK) {
        stream->flags |= NGHTTP2_STREAM_FLAG_READ_DATA_BLOCKED;
        return 0;
      }

      return (int)datacnt;
    }

    if (nghttp2_vec_len_max_int(&left, hw->data, (size_t)datacnt) != 0) {
      return NGHTTP2_ERR_STREAM_DATA_OVERFLOW;
    }

    if (left == 0) {
      hw->datacnt = 0;
    } else {
      hw->datacnt = (size_t)datacnt;
    }

    if (flags & NGHTTP2_READ_DATA_FLAG_EOF) {
      hw->flags |= NGHTTP2_HTTP_WRITER_FLAG_DATA_EOF;

      if (!(flags & NGHTTP2_READ_DATA_FLAG_NO_END_STREAM) &&
          !(stream->flags & NGHTTP2_STREAM_FLAG_TRAILERS_SUBMITTED)) {
        hw->flags |= NGHTTP2_HTTP_WRITER_FLAG_DATA_END_STREAM;
        stream->flags |= NGHTTP2_STREAM_FLAG_SHUT_WR;
      }
    }

    if (hw->datacnt == 0) {
      if (!(hw->flags & NGHTTP2_HTTP_WRITER_FLAG_DATA_EOF)) {
        return 0;
      }

      if (!(hw->flags & NGHTTP2_HTTP_WRITER_FLAG_DATA_END_STREAM)) {
        nghttp2_ringbuf_pop_front(&hw->outq);

        return 0;
      }
    }

    hw->data_idx = 0;
  }

  if (hw->field_left == 0) {
    if (nghttp2_buf_left(dest) < NGHTTP2_FRAME_HDLEN) {
      return NGHTTP2_ERR_NOBUF;
    }

    left = nghttp2_vec_len(&hw->data[hw->data_idx], hw->datacnt - hw->data_idx);

    conn_fc_limit = conn_flow_control_limit(conn);
    stream_fc_limit = stream_flow_control_limit(stream);

    hw->field_left = (size_t)nghttp2_min(
      (uint64_t)NGHTTP2_DEFAULT_MAX_FRAME_SIZE,
      nghttp2_min(left, (uint64_t)nghttp2_min(conn_fc_limit, stream_fc_limit)));

    lfr.hd = fr->hd;
    lfr.hd.len = (uint32_t)hw->field_left;
    lfr.padlen = 0;
    lfr.datalen = lfr.hd.len;

    if (lfr.hd.len == left &&
        hw->flags & NGHTTP2_HTTP_WRITER_FLAG_DATA_END_STREAM) {
      lfr.hd.flags = NGHTTP2_DATA_FLAG_END_STREAM;
    } else if (lfr.hd.len == 0) {
      if (stream_fc_limit == 0) {
        stream->flags |= NGHTTP2_STREAM_FLAG_FC_BLOCKED;
      }

      return 0;
    }

    nghttp2_log_tx_data(log, &lfr);

    dest->last = nghttp2_frame_encode_hd(dest->last, &lfr.hd);

    if (lfr.hd.len == 0) {
      hw->datacnt = 0;
      nghttp2_ringbuf_pop_front(&hw->outq);

      return 0;
    }

    hw->flags |= NGHTTP2_HTTP_WRITER_FLAG_INPROGRESS;

    stream->tx.offset += lfr.hd.len;
    conn->tx.offset += lfr.hd.len;

    if (nghttp2_buf_left(dest) == 0) {
      return 0;
    }
  }

  nwrite = nghttp2_min(hw->field_left, nghttp2_buf_left(dest));
  if (nwrite == 0) {
    return NGHTTP2_ERR_NOBUF;
  }

  left = nwrite;

  for (; hw->data_idx < hw->datacnt; ++hw->data_idx) {
    v = &hw->data[hw->data_idx];

    if (left < v->len) {
      dest->last = nghttp2_cpymem(dest->last, v->base, (size_t)left);
      v->len -= (size_t)left;

      break;
    }

    dest->last = nghttp2_cpymem(dest->last, v->base, v->len);
    left -= v->len;
  }

  if (hw->write_stream_data_offset) {
    rv = hw->write_stream_data_offset(
      conn, stream->stream_id, stream->tx.offset - hw->field_left, nwrite,
      conn->user_data, stream->user_data);
    if (rv != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  stream->sched.unscheduled_nwrite += nwrite;
  hw->field_left -= nwrite;

  if (hw->data_idx == hw->datacnt) {
    hw->flags &= ~NGHTTP2_HTTP_WRITER_FLAG_INPROGRESS;
    hw->datacnt = 0;

    if (hw->flags & NGHTTP2_HTTP_WRITER_FLAG_DATA_EOF) {
      nghttp2_ringbuf_pop_front(&hw->outq);
    }
  }

  return 0;
}

int nghttp2_http_writer_inprogress(const nghttp2_http_writer *hw) {
  return (hw->flags & NGHTTP2_HTTP_WRITER_FLAG_INPROGRESS) != 0;
}

int nghttp2_http_writer_empty(const nghttp2_http_writer *hw) {
  return nghttp2_ringbuf_len(&hw->outq) == 0;
}

static uint8_t http_writer_get_frame_type(const nghttp2_http_writer *hw) {
  const nghttp2_frame *fr;

  assert(nghttp2_ringbuf_len(&hw->outq));

  fr = nghttp2_ringbuf_get((nghttp2_ringbuf *)&hw->outq, 0);

  return fr->meta.hd.type;
}

int nghttp2_http_writer_frame_flow_controlled(const nghttp2_http_writer *hw) {
  return nghttp2_ringbuf_len(&hw->outq) &&
         http_writer_get_frame_type(hw) == NGHTTP2_FRAME_DATA;
}
