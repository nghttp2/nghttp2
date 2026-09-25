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
#include "nghttp2_stream.h"

#include <assert.h>

#include "nghttp2_http.h"
#include "nghttp2_unreachable.h"
#include "nghttp2_macro.h"

void nghttp2_stream_init(nghttp2_stream *stream, int64_t stream_id,
                         const nghttp2_stream_callbacks *callbacks,
                         uint32_t flags, uint64_t max_rx_offset,
                         uint64_t max_tx_offset, void *user_data,
                         const nghttp2_mem *mem) {
  *stream = (nghttp2_stream){
    .mem = mem,
    .stream_id = stream_id,
    .rx =
      {
        .max_offset = max_rx_offset,
        .unsent_max_offset = max_rx_offset,
        .http =
          {
            .status_code = -1,
            .content_length = -1,
            .pri.urgency = NGHTTP2_DEFAULT_URGENCY,
          },
      },
    .tx =
      {
        .max_offset = max_tx_offset,
      },
    .sched =
      {
        .pe.index = NGHTTP2_PQ_BAD_INDEX,
        .pri.urgency = NGHTTP2_DEFAULT_URGENCY,
      },
    .user_data = user_data,
    .flags = flags,
  };

  nghttp2_http_writer_init(&stream->tx.hw, callbacks->write_stream_data_offset,
                           mem);
}

void nghttp2_stream_free(nghttp2_stream *stream) {
  if (!stream) {
    return;
  }

  nghttp2_stream_free_client_pri(stream);
  nghttp2_http_writer_free(&stream->tx.hw);
}

int nghttp2_stream_transit_rx_http_state(nghttp2_stream *stream,
                                         nghttp2_stream_http_event event) {
  int rv;

  switch (stream->rx.hstate) {
  case NGHTTP2_HTTP_STATE_NONE:
    nghttp2_unreachable();
  case NGHTTP2_HTTP_STATE_REQ_INITIAL:
    if (event != NGHTTP2_HTTP_EVENT_HEADERS_BEGIN) {
      return NGHTTP2_ERR_PROTO;
    }

    stream->rx.hstate = NGHTTP2_HTTP_STATE_REQ_HEADERS_BEGIN;

    return 0;
  case NGHTTP2_HTTP_STATE_REQ_HEADERS_BEGIN:
    assert(NGHTTP2_HTTP_EVENT_HEADERS_END == event);
    stream->rx.hstate = NGHTTP2_HTTP_STATE_REQ_HEADERS_END;
    return 0;
  case NGHTTP2_HTTP_STATE_REQ_HEADERS_END:
    switch (event) {
    case NGHTTP2_HTTP_EVENT_HEADERS_BEGIN:
      /* TODO Better to check status code */
      if (stream->rx.http.flags & NGHTTP2_HTTP_FLAG_METH_CONNECT) {
        return NGHTTP2_ERR_PROTO;
      }
      stream->rx.hstate = NGHTTP2_HTTP_STATE_REQ_TRAILERS_BEGIN;
      return 0;
    case NGHTTP2_HTTP_EVENT_DATA_BEGIN:
      stream->rx.hstate = NGHTTP2_HTTP_STATE_REQ_DATA_BEGIN;
      return 0;
    case NGHTTP2_HTTP_EVENT_MSG_END:
      rv = nghttp2_http_on_remote_end_stream(stream);
      if (rv != 0) {
        return rv;
      }
      stream->rx.hstate = NGHTTP2_HTTP_STATE_REQ_END;
      return 0;
    default:
      nghttp2_unreachable();
    }
  case NGHTTP2_HTTP_STATE_REQ_DATA_BEGIN:
    assert(NGHTTP2_HTTP_EVENT_DATA_END == event);
    stream->rx.hstate = NGHTTP2_HTTP_STATE_REQ_DATA_END;
    return 0;
  case NGHTTP2_HTTP_STATE_REQ_DATA_END:
    switch (event) {
    case NGHTTP2_HTTP_EVENT_DATA_BEGIN:
      stream->rx.hstate = NGHTTP2_HTTP_STATE_REQ_DATA_BEGIN;
      return 0;
    case NGHTTP2_HTTP_EVENT_HEADERS_BEGIN:
      /* TODO Better to check status code */
      if (stream->rx.http.flags & NGHTTP2_HTTP_FLAG_METH_CONNECT) {
        return NGHTTP2_ERR_PROTO;
      }
      stream->rx.hstate = NGHTTP2_HTTP_STATE_REQ_TRAILERS_BEGIN;
      return 0;
    case NGHTTP2_HTTP_EVENT_MSG_END:
      rv = nghttp2_http_on_remote_end_stream(stream);
      if (rv != 0) {
        return rv;
      }
      stream->rx.hstate = NGHTTP2_HTTP_STATE_REQ_END;
      return 0;
    default:
      nghttp2_unreachable();
    }
  case NGHTTP2_HTTP_STATE_REQ_TRAILERS_BEGIN:
    assert(NGHTTP2_HTTP_EVENT_HEADERS_END == event);
    stream->rx.hstate = NGHTTP2_HTTP_STATE_REQ_TRAILERS_END;
    return 0;
  case NGHTTP2_HTTP_STATE_REQ_TRAILERS_END:
    if (event != NGHTTP2_HTTP_EVENT_MSG_END) {
      /* TODO Should ignore unexpected frame in this state as per
         spec. */
      return NGHTTP2_ERR_PROTO;
    }
    rv = nghttp2_http_on_remote_end_stream(stream);
    if (rv != 0) {
      return rv;
    }
    stream->rx.hstate = NGHTTP2_HTTP_STATE_REQ_END;
    return 0;
  case NGHTTP2_HTTP_STATE_REQ_END:
    return NGHTTP2_ERR_PROTO;
  case NGHTTP2_HTTP_STATE_RESP_INITIAL:
    if (event != NGHTTP2_HTTP_EVENT_HEADERS_BEGIN) {
      return NGHTTP2_ERR_PROTO;
    }
    stream->rx.hstate = NGHTTP2_HTTP_STATE_RESP_HEADERS_BEGIN;
    return 0;
  case NGHTTP2_HTTP_STATE_RESP_HEADERS_BEGIN:
    assert(NGHTTP2_HTTP_EVENT_HEADERS_END == event);
    stream->rx.hstate = NGHTTP2_HTTP_STATE_RESP_HEADERS_END;
    return 0;
  case NGHTTP2_HTTP_STATE_RESP_HEADERS_END:
    switch (event) {
    case NGHTTP2_HTTP_EVENT_HEADERS_BEGIN:
      if (stream->rx.http.status_code == -1) {
        stream->rx.hstate = NGHTTP2_HTTP_STATE_RESP_HEADERS_BEGIN;
        return 0;
      }
      if ((stream->rx.http.flags & NGHTTP2_HTTP_FLAG_METH_CONNECT) &&
          stream->rx.http.status_code / 100 == 2) {
        return NGHTTP2_ERR_PROTO;
      }
      stream->rx.hstate = NGHTTP2_HTTP_STATE_RESP_TRAILERS_BEGIN;
      return 0;
    case NGHTTP2_HTTP_EVENT_DATA_BEGIN:
      if (stream->rx.http.flags & NGHTTP2_HTTP_FLAG_EXPECT_FINAL_RESPONSE) {
        return NGHTTP2_ERR_PROTO;
      }
      stream->rx.hstate = NGHTTP2_HTTP_STATE_RESP_DATA_BEGIN;
      return 0;
    case NGHTTP2_HTTP_EVENT_MSG_END:
      rv = nghttp2_http_on_remote_end_stream(stream);
      if (rv != 0) {
        return rv;
      }
      stream->rx.hstate = NGHTTP2_HTTP_STATE_RESP_END;
      return 0;
    default:
      nghttp2_unreachable();
    }
  case NGHTTP2_HTTP_STATE_RESP_DATA_BEGIN:
    assert(NGHTTP2_HTTP_EVENT_DATA_END == event);
    stream->rx.hstate = NGHTTP2_HTTP_STATE_RESP_DATA_END;
    return 0;
  case NGHTTP2_HTTP_STATE_RESP_DATA_END:
    switch (event) {
    case NGHTTP2_HTTP_EVENT_DATA_BEGIN:
      stream->rx.hstate = NGHTTP2_HTTP_STATE_RESP_DATA_BEGIN;
      return 0;
    case NGHTTP2_HTTP_EVENT_HEADERS_BEGIN:
      if ((stream->rx.http.flags & NGHTTP2_HTTP_FLAG_METH_CONNECT) &&
          stream->rx.http.status_code / 100 == 2) {
        return NGHTTP2_ERR_PROTO;
      }
      stream->rx.hstate = NGHTTP2_HTTP_STATE_RESP_TRAILERS_BEGIN;
      return 0;
    case NGHTTP2_HTTP_EVENT_MSG_END:
      rv = nghttp2_http_on_remote_end_stream(stream);
      if (rv != 0) {
        return rv;
      }
      stream->rx.hstate = NGHTTP2_HTTP_STATE_RESP_END;
      return 0;
    default:
      nghttp2_unreachable();
    }
  case NGHTTP2_HTTP_STATE_RESP_TRAILERS_BEGIN:
    assert(NGHTTP2_HTTP_EVENT_HEADERS_END == event);
    stream->rx.hstate = NGHTTP2_HTTP_STATE_RESP_TRAILERS_END;
    return 0;
  case NGHTTP2_HTTP_STATE_RESP_TRAILERS_END:
    if (event != NGHTTP2_HTTP_EVENT_MSG_END) {
      return NGHTTP2_ERR_PROTO;
    }
    rv = nghttp2_http_on_remote_end_stream(stream);
    if (rv != 0) {
      return rv;
    }
    stream->rx.hstate = NGHTTP2_HTTP_STATE_RESP_END;
    return 0;
  case NGHTTP2_HTTP_STATE_RESP_END:
    return NGHTTP2_ERR_PROTO;
  default:
    nghttp2_unreachable();
  }
}

int nghttp2_stream_empty_headers_allowed(const nghttp2_stream *stream) {
  switch (stream->rx.hstate) {
  case NGHTTP2_HTTP_STATE_REQ_TRAILERS_BEGIN:
  case NGHTTP2_HTTP_STATE_RESP_TRAILERS_BEGIN:
    return 0;
  default:
    return NGHTTP2_ERR_MALFORMED_HTTP_MESSAGING;
  }
}

void nghttp2_stream_set_error_code(nghttp2_stream *stream,
                                   uint32_t error_code) {
  if (stream->flags & NGHTTP2_STREAM_FLAG_ERROR_CODE_SET) {
    return;
  }

  stream->flags |= NGHTTP2_STREAM_FLAG_ERROR_CODE_SET;
  stream->error_code = error_code;
}

int nghttp2_stream_require_strmq(const nghttp2_stream *stream) {
  return (!nghttp2_http_writer_empty(&stream->tx.hw) &&
          !nghttp2_http_writer_frame_flow_controlled(&stream->tx.hw)) ||
         (stream->flags & (NGHTTP2_STREAM_FLAG_SEND_RST_STREAM |
                           NGHTTP2_STREAM_FLAG_SEND_WINDOW_UPDATE |
                           NGHTTP2_STREAM_FLAG_SEND_PRIORITY_UPDATE));
}

int nghttp2_stream_require_schedule(const nghttp2_stream *stream) {
  return !nghttp2_http_writer_empty(&stream->tx.hw) &&
         !(stream->flags & (NGHTTP2_STREAM_FLAG_FC_BLOCKED |
                            NGHTTP2_STREAM_FLAG_READ_DATA_BLOCKED));
}

static uint64_t pq_get_first_cycle(const nghttp2_pq *pq) {
  nghttp2_stream *top;

  if (nghttp2_pq_empty(pq)) {
    return 0;
  }

  top = nghttp2_struct_of(nghttp2_pq_top(pq), nghttp2_stream, sched);

  return top->sched.cycle;
}

int nghttp2_stream_schedule(nghttp2_stream *stream, nghttp2_pq *pq,
                            uint64_t nwrite) {
  uint64_t penalty = nghttp2_max(1, nwrite);

  if (stream->sched.pe.index == NGHTTP2_PQ_BAD_INDEX) {
    stream->sched.cycle =
      pq_get_first_cycle(pq) +
      ((nwrite == 0 || !stream->sched.pri.inc) ? 0 : penalty);
  } else if (nwrite > 0) {
    if (!stream->sched.pri.inc || nghttp2_pq_size(pq) == 1) {
      return 0;
    }

    nghttp2_pq_remove(pq, &stream->sched.pe);
    stream->sched.pe.index = NGHTTP2_PQ_BAD_INDEX;
    stream->sched.cycle += penalty;
  } else {
    return 0;
  }

  return nghttp2_pq_push(pq, &stream->sched.pe);
}

void nghttp2_stream_unschedule(nghttp2_stream *stream, nghttp2_pq *pq) {
  if (stream->sched.pe.index == NGHTTP2_PQ_BAD_INDEX) {
    return;
  }

  nghttp2_pq_remove(pq, &stream->sched.pe);
  stream->sched.pe.index = NGHTTP2_PQ_BAD_INDEX;
}

int nghttp2_stream_add_tx_max_offset(nghttp2_stream *stream, uint64_t delta) {
  uint64_t max_offset;

  max_offset = stream->tx.max_offset + delta;
  if (max_offset > stream->tx.offset &&
      max_offset - stream->tx.offset > NGHTTP2_MAX_WINDOW_SIZE) {
    return NGHTTP2_ERR_FLOW_CONTROL;
  }

  stream->tx.max_offset = max_offset;

  if ((stream->flags & NGHTTP2_STREAM_FLAG_FC_BLOCKED) &&
      stream->tx.max_offset > stream->tx.offset) {
    stream->flags &= ~NGHTTP2_STREAM_FLAG_FC_BLOCKED;
  }

  return 0;
}

void nghttp2_stream_free_client_pri(nghttp2_stream *stream) {
  nghttp2_mem_free(stream->mem, stream->tx.priority.client_pri.base);
  stream->tx.priority.client_pri = (nghttp2_vec){0};
}
