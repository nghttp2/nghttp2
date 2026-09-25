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
#ifndef NGHTTP2_HTTP_H
#define NGHTTP2_HTTP_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <nghttp2v2/nghttp2.h>

typedef struct nghttp2_stream nghttp2_stream;

typedef struct nghttp2_http_state nghttp2_http_state;

/* HTTP related flags to enforce HTTP semantics */

/* NGHTTP2_HTTP_FLAG_NONE indicates that no flag is set. */
#define NGHTTP2_HTTP_FLAG_NONE 0x00U
/* header field seen so far */
#define NGHTTP2_HTTP_FLAG__AUTHORITY 0x01U
#define NGHTTP2_HTTP_FLAG__PATH 0x02U
#define NGHTTP2_HTTP_FLAG__METHOD 0x04U
#define NGHTTP2_HTTP_FLAG__SCHEME 0x08U
/* host is not pseudo header, but we require either host or
   :authority */
#define NGHTTP2_HTTP_FLAG_HOST 0x10U
#define NGHTTP2_HTTP_FLAG__STATUS 0x20U
/* required header fields for HTTP request except for CONNECT
   method. */
#define NGHTTP2_HTTP_FLAG_REQ_HEADERS                                          \
  (NGHTTP2_HTTP_FLAG__METHOD | NGHTTP2_HTTP_FLAG__PATH |                       \
   NGHTTP2_HTTP_FLAG__SCHEME)
#define NGHTTP2_HTTP_FLAG_PSEUDO_HEADER_DISALLOWED 0x40U
/* HTTP method flags */
#define NGHTTP2_HTTP_FLAG_METH_CONNECT 0x80U
#define NGHTTP2_HTTP_FLAG_METH_HEAD 0x0100U
#define NGHTTP2_HTTP_FLAG_METH_OPTIONS 0x0200U
#define NGHTTP2_HTTP_FLAG_METH_ALL                                             \
  (NGHTTP2_HTTP_FLAG_METH_CONNECT | NGHTTP2_HTTP_FLAG_METH_HEAD |              \
   NGHTTP2_HTTP_FLAG_METH_OPTIONS)
/* :path category */
/* path starts with "/" */
#define NGHTTP2_HTTP_FLAG_PATH_REGULAR 0x0400U
/* path "*" */
#define NGHTTP2_HTTP_FLAG_PATH_ASTERISK 0x0800U
/* scheme */
/* "http" or "https" scheme */
#define NGHTTP2_HTTP_FLAG_SCHEME_HTTP 0x1000U
/* set if final response is expected */
#define NGHTTP2_HTTP_FLAG_EXPECT_FINAL_RESPONSE 0x2000U
/* NGHTTP2_HTTP_FLAG__PROTOCOL is set when :protocol pseudo header
   field is seen. */
#define NGHTTP2_HTTP_FLAG__PROTOCOL 0x4000U
/* NGHTTP2_HTTP_FLAG_PRIORITY is set when priority header field is
   processed. */
#define NGHTTP2_HTTP_FLAG_PRIORITY 0x8000U
/* NGHTTP2_HTTP_FLAG_BAD_PRIORITY is set when an error is encountered
   while parsing priority header field. */
#define NGHTTP2_HTTP_FLAG_BAD_PRIORITY 0x010000U

/*
 * This function is called when HTTP header field |nv| received for
 * |http|.  This function will validate |nv| against the current state
 * of stream.  Pass nonzero if this is request headers. Pass nonzero
 * to |trailers| if |nv| is included in trailers.  |connect_protocol|
 * is nonzero if Extended CONNECT Method is enabled.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_MALFORMED_HTTP_HEADER
 *     Invalid HTTP header field was received.
 * NGHTTP2_ERR_REMOVE_HTTP_HEADER
 *     Invalid HTTP header field was received but it can be treated as
 *     if it was not received because of compatibility reasons.
 */
int nghttp2_http_on_header(nghttp2_http_state *http, const nghttp2_hpack_nv *nv,
                           int request, int trailers, int connect_protocol);

/*
 * This function is called when request header is received.  This
 * function performs validation and returns 0 if it succeeds, or one
 * of the following negative error codes:
 *
 * NGHTTP2_ERR_MALFORMED_HTTP_HEADER
 *     Required HTTP header field was not received; or an invalid
 *     header field was received.
 */
int nghttp2_http_on_request_headers(nghttp2_http_state *http);

/*
 * This function is called when response header is received.  This
 * function performs validation and returns 0 if it succeeds, or one
 * of the following negative error codes:
 *
 * NGHTTP2_ERR_MALFORMED_HTTP_HEADER
 *     Required HTTP header field was not received; or an invalid
 *     header field was received.
 */
int nghttp2_http_on_response_headers(nghttp2_http_state *http);

/*
 * This function is called when read side stream is closed.  This
 *  function performs validation and returns 0 if it succeeds, or one
 *  of the following negative error codes:
 *
 * NGHTTP2_ERR_MALFORMED_HTTP_MESSAGING
 *     HTTP messaging is violated.
 */
int nghttp2_http_on_remote_end_stream(const nghttp2_stream *stream);

/*
 * This function is called when chunk of data is received.  This
 * function performs validation and returns 0 if it succeeds, or one
 * of the following negative error codes:
 *
 * NGHTTP2_ERR_MALFORMED_HTTP_MESSAGING
 *     HTTP messaging is violated.
 */
int nghttp2_http_on_data_chunk(nghttp2_stream *stream, size_t n);

/*
 * This function inspects header fields in |nva| of length |nvlen| and
 * records its method in stream->http_flags.
 */
void nghttp2_http_record_request_method(nghttp2_stream *stream,
                                        const nghttp2_nv *nva, size_t nvlen);

/**
 * @function
 *
 * `nghttp2_http_parse_priority` parses priority HTTP header field
 * stored in the buffer pointed by |value| of length |len|.  If it
 * successfully processed header field value, it stores the result
 * into |*dest|.  This function just overwrites what it sees in the
 * header field value and does not initialize any field in |*dest|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The function could not parse the provided value.
 */
int nghttp2_http_parse_priority(nghttp2_pri *dest, const uint8_t *value,
                                size_t len);

int nghttp2_pri_eq(const nghttp2_pri *a, const nghttp2_pri *b);

#endif /* !defined(NGHTTP2_HTTP_H) */
