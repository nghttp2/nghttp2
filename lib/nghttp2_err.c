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
#include "nghttp2_err.h"

const char *nghttp2_strerror(int liberr) {
  switch (liberr) {
  case NGHTTP2_ERR_INVALID_ARGUMENT:
    return "ERR_INVALID_ARGUMENT";
  case NGHTTP2_ERR_NOBUF:
    return "ERR_NOBUF";
  case NGHTTP2_ERR_PROTO:
    return "ERR_PROTO";
  case NGHTTP2_ERR_INVALID_STATE:
    return "ERR_INVALID_STATE";
  case NGHTTP2_ERR_HPACK_FATAL:
    return "ERR_HPACK_FATAL";
  case NGHTTP2_ERR_STREAM_ID_BLOCKED:
    return "ERR_STREAM_ID_BLOCKED";
  case NGHTTP2_ERR_REFUSED_STREAM:
    return "ERR_REFUSED_STREAM";
  case NGHTTP2_ERR_WOULDBLOCK:
    return "ERR_WOULDBLOCK";
  case NGHTTP2_ERR_FLOW_CONTROL:
    return "ERR_FLOW_CONTROL";
  case NGHTTP2_ERR_FRAME_SIZE:
    return "ERR_FRAME_SIZE";
  case NGHTTP2_ERR_STREAM_LIMIT:
    return "ERR_STREAM_LIMIT";
  case NGHTTP2_ERR_MALFORMED_HTTP_HEADER:
    return "ERR_MALFORMED_HTTP_HEADER";
  case NGHTTP2_ERR_REMOVE_HTTP_HEADER:
    return "ERR_REMOVE_HTTP_HEADER";
  case NGHTTP2_ERR_MALFORMED_HTTP_MESSAGING:
    return "ERR_MALFORMED_HTTP_MESSAGING";
  case NGHTTP2_ERR_STREAM_DATA_OVERFLOW:
    return "ERR_STREAM_DATA_OVERFLOW";
  case NGHTTP2_ERR_SETTINGS_TIMEOUT:
    return "ERR_SETTINGS_TIMEOUT";
  case NGHTTP2_ERR_FRAME_ENCODING:
    return "ERR_FRAME_ENCODING";
  case NGHTTP2_ERR_STREAM_SHUT_WR:
    return "NGHTTP2_ERR_STREAM_SHUT_WR";
  case NGHTTP2_ERR_STREAM_NOT_FOUND:
    return "ERR_STREAM_NOT_FOUND";
  case NGHTTP2_ERR_STREAM_STATE:
    return "ERR_STREAM_STATE";
  case NGHTTP2_ERR_CLOSING:
    return "ERR_CLOSING";
  case NGHTTP2_ERR_DRAINING:
    return "ERR_DRAINING";
  case NGHTTP2_ERR_INTERNAL:
    return "ERR_INTERNAL";
  case NGHTTP2_ERR_NOMEM:
    return "ERR_NOMEM";
  case NGHTTP2_ERR_CALLBACK_FAILURE:
    return "ERR_CALLBACK_FAILURE";
  case NGHTTP2_ERR_EXCESSIVE_LOAD:
    return "ERR_EXCESSIVE_LOAD";
  default:
    return "(unknown)";
  }
}

uint32_t nghttp2_err_infer_http2_error_code(int liberr) {
  switch (liberr) {
  case 0:
    return 0;
  case NGHTTP2_ERR_HPACK_FATAL:
    return NGHTTP2_COMPRESSION_ERROR;
  case NGHTTP2_ERR_REFUSED_STREAM:
    return NGHTTP2_REFUSED_STREAM;
  case NGHTTP2_ERR_FLOW_CONTROL:
    return NGHTTP2_FLOW_CONTROL_ERROR;
  case NGHTTP2_ERR_SETTINGS_TIMEOUT:
    return NGHTTP2_SETTINGS_TIMEOUT;
  case NGHTTP2_ERR_FRAME_SIZE:
    return NGHTTP2_FRAME_SIZE_ERROR;
  case NGHTTP2_ERR_INTERNAL:
  case NGHTTP2_ERR_NOMEM:
  case NGHTTP2_ERR_CALLBACK_FAILURE:
    return NGHTTP2_INTERNAL_ERROR;
  default:
    return NGHTTP2_PROTOCOL_ERROR;
  }
}

int nghttp2_err_is_fatal(int liberr) { return liberr < NGHTTP2_ERR_FATAL; }
