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
#ifndef NGHTTP2_FRAME_H
#define NGHTTP2_FRAME_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <nghttp2v2/nghttp2.h>

/* NGHTTP2_MAX_WINDOW_SIZE is the maximum window size. */
#define NGHTTP2_MAX_WINDOW_SIZE ((uint32_t)INT32_MAX)

#define NGHTTP2_DEFAULT_MAX_FRAME_SIZE ((size_t)16384)
#define NGHTTP2_FRAME_HDLEN                                                    \
  ((size_t)(/* length = */ 3 + /* type = */ 1 + /* flags = */ 1 +              \
            /* stream_id = */ 4))

#define NGHTTP2_FRAME_DATA 0x00U
#define NGHTTP2_FRAME_HEADERS 0x01U
#define NGHTTP2_FRAME_PRIORITY 0x02U
#define NGHTTP2_FRAME_RST_STREAM 0x03U
#define NGHTTP2_FRAME_SETTINGS 0x04U
#define NGHTTP2_FRAME_PUSH_PROMISE 0x05U
#define NGHTTP2_FRAME_PING 0x06U
#define NGHTTP2_FRAME_GOAWAY 0x07U
#define NGHTTP2_FRAME_WINDOW_UPDATE 0x08U
#define NGHTTP2_FRAME_CONTINUATION 0x09U
#define NGHTTP2_FRAME_PRIORITY_UPDATE 0x10U

typedef struct nghttp2_frame_hd {
  uint32_t len;
  uint8_t type;
  uint8_t flags;
  int64_t stream_id;
} nghttp2_frame_hd;

typedef struct nghttp2_frame_meta {
  nghttp2_frame_hd hd;
} nghttp2_frame_meta;

#define NGHTTP2_DATA_FLAG_END_STREAM 0x01U
#define NGHTTP2_DATA_FLAG_PADDED 0x08U

typedef struct nghttp2_frame_data {
  nghttp2_frame_hd hd;
  size_t padlen;
  /* data is only used by unit test */
  const uint8_t *data;
  size_t datalen;
  /* dr is only used for transmission */
  nghttp2_data_reader dr;
} nghttp2_frame_data;

#define NGHTTP2_HEADERS_FLAG_END_STREAM 0x01U
#define NGHTTP2_HEADERS_FLAG_END_HEADERS 0x04U
#define NGHTTP2_HEADERS_FLAG_PADDED 0x08U
#define NGHTTP2_HEADERS_FLAG_PRIORITY 0x20U

typedef struct nghttp2_frame_headers {
  nghttp2_frame_hd hd;
  size_t padlen;
  /* field_block is a pointer to the encoded field block.  It is only
     used by unit test. */
  const uint8_t *field_block;
  size_t field_blocklen;
  /* nva and nvlen are only used for transmission */
  nghttp2_nv *nva;
  size_t nvlen;
} nghttp2_frame_headers;

typedef struct nghttp2_frame_rst_stream {
  nghttp2_frame_hd hd;
  uint32_t error_code;
} nghttp2_frame_rst_stream;

#define NGHTTP2_SETTINGS_FLAG_ACK 0x01U

#define NGHTTP2_SETTINGS_HEADER_TABLE_SIZE 0x01U
#define NGHTTP2_SETTINGS_ENABLE_PUSH 0x02U
#define NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS 0x03U
#define NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE 0x4U
#define NGHTTP2_SETTINGS_MAX_FRAME_SIZE 0x5U
#define NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE 0x6U
/* https://datatracker.ietf.org/doc/html/rfc8441 */
#define NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL 0x08U
/* https://datatracker.ietf.org/doc/html/rfc9218 */
#define NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES 0x09U

typedef struct nghttp2_settings_entry {
  uint16_t id;
  uint32_t value;
} nghttp2_settings_entry;

typedef struct nghttp2_frame_settings {
  nghttp2_frame_hd hd;
  /* iv and niv are only used when sending the frame. */
  nghttp2_settings_entry *iv;
  size_t niv;
  /* settings is only used for reception. */
  nghttp2_proto_settings *settings;
} nghttp2_frame_settings;

#define NGHTTP2_PING_FLAG_ACK 0x01U

typedef struct nghttp2_frame_ping {
  nghttp2_frame_hd hd;
  nghttp2_ping_data data;
} nghttp2_frame_ping;

typedef struct nghttp2_frame_goaway {
  nghttp2_frame_hd hd;
  uint32_t last_stream_id;
  uint32_t error_code;
  const uint8_t *debug_data;
  size_t debug_datalen;
} nghttp2_frame_goaway;

typedef struct nghttp2_frame_window_update {
  nghttp2_frame_hd hd;
  uint32_t window_size_inc;
} nghttp2_frame_window_update;

typedef struct nghttp2_frame_priority_update {
  nghttp2_frame_hd hd;
  uint32_t prioritized_stream_id;
  const uint8_t *pri;
  size_t prilen;
} nghttp2_frame_priority_update;

typedef union nghttp2_frame {
  nghttp2_frame_meta meta;
  nghttp2_frame_data data;
  nghttp2_frame_headers headers;
  nghttp2_frame_rst_stream rst_stream;
  nghttp2_frame_settings settings;
  nghttp2_frame_ping ping;
  nghttp2_frame_goaway goaway;
  nghttp2_frame_window_update window_update;
  nghttp2_frame_priority_update priority_update;
} nghttp2_frame;

uint8_t *nghttp2_frame_encode_hd(uint8_t *dets, const nghttp2_frame_hd *hd);

/*
 * nghttp2_frame_encode_data encodes DATA frame |fr| into |dest|.
 * |dest|->last is increased by the number of bytes written.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
int nghttp2_frame_encode_data(nghttp2_buf *dest, const nghttp2_frame_data *fr);

/*
 * nghttp2_frame_encode_data_payloadlen returns the payload length of
 * |fr|.
 */
size_t nghttp2_frame_encode_data_payloadlen(const nghttp2_frame_data *fr);

/*
 * nghttp2_frame_encode_headers encodes HEADERS frame |fr| into
 * |dest|.  |dest|->last is increased by the number of bytes written.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
int nghttp2_frame_encode_headers(nghttp2_buf *dest,
                                 const nghttp2_frame_headers *fr);

/*
 * nghttp2_frame_encode_headers_payloadlen returns the payload length
 * of |fr|.
 */
size_t nghttp2_frame_encode_headers_payloadlen(const nghttp2_frame_headers *fr);

/*
 * nghttp2_frame_encode_rst_stream encodes RST_STREAM frame |fr| into
 * |dest|.  |dest|->last is increased by the number of bytes written.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
int nghttp2_frame_encode_rst_stream(nghttp2_buf *dest,
                                    const nghttp2_frame_rst_stream *fr);

/*
 * nghttp2_frame_encode_settings encodes SETTINGS frame |fr| into
 * |dest|.  |dest|->last is increased by the number of bytes written.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
int nghttp2_frame_encode_settings(nghttp2_buf *dest,
                                  const nghttp2_frame_settings *fr);

/*
 * nghttp2_frame_encode_settings_payloadlen returns the payload length
 * of |fr|.
 */
size_t
nghttp2_frame_encode_settings_payloadlen(const nghttp2_frame_settings *fr);

/*
 * nghttp2_frame_encode_ping encodes PING frame |fr| into |dest|.
 * |dest|->last is increased by the number of bytes written.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
int nghttp2_frame_encode_ping(nghttp2_buf *dest, const nghttp2_frame_ping *fr);

/*
 * nghttp2_frame_encode_goaway encodes GOAWAY frame |fr| into |dest|.
 * |dest|->last is increased by the number of bytes written.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
int nghttp2_frame_encode_goaway(nghttp2_buf *dest,
                                const nghttp2_frame_goaway *fr);

/*
 * nghttp2_frame_encode_goaway_payloadlen returns the payload length
 * of |fr|.
 */
size_t nghttp2_frame_encode_goaway_payloadlen(const nghttp2_frame_goaway *fr);

/*
 * nghttp2_frame_encode_window_update encodes WINDOW_UPDATE frame |fr|
 * into |dest|.  |dest|->last is increased by the number of bytes
 * written.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
int nghttp2_frame_encode_window_update(nghttp2_buf *dest,
                                       const nghttp2_frame_window_update *fr);

/*
 * nghttp2_frame_encode_priority_update encodes PRIORITY_UPDATE frame
 * |fr| into |dest|.  |dest|->last is increased by the number of bytes
 * written.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
int nghttp2_frame_encode_priority_update(
  nghttp2_buf *dest, const nghttp2_frame_priority_update *fr);

/*
 * nghttp2_frame_encode_priority_update_payloadlen returns the payload
 * length of |fr|.
 */
size_t nghttp2_frame_encode_priority_update_payloadlen(
  const nghttp2_frame_priority_update *fr);

typedef struct nghttp2_frd {
  nghttp2_settings_entry iv[8];
} nghttp2_frd;

void nghttp2_frd_init(nghttp2_frd *frd);

int nghttp2_frd_decode_buf(nghttp2_frd *frd, nghttp2_frame *dest,
                           nghttp2_buf *src);

nghttp2_ssize nghttp2_frd_decode(nghttp2_frd *frd, nghttp2_frame *dest,
                                 const uint8_t *src, size_t srclen);

/*
 * nghttp2_frame_decode_hd decodes a frame header from the buffer
 * pointed by |src|, which must have at least NGHTTP2_FRAME_HDLEN
 * bytes long, and stores the result into the object pointed by |hd|.
 * It returns |src| + NGHTTP2_FRAME_HDLEN.
 */
const uint8_t *nghttp2_frame_decode_hd(nghttp2_frame_hd *hd,
                                       const uint8_t *src);

/*
 * nghttp2_frame_decode_data decodes DATA frame from |src| of length
 * |srclen|.  The result is stored in the object pointed by |dest|.
 * DATA frame must start at src[0].  This function finishes when it
 * decodes one DATA frame, and returns the exact number of bytes read
 * to decode a frame if it succeeds, or one of the following negative
 * error codes:
 *
 * NGHTTP2_ERR_FRAME_ENCODING
 *     |src| is too short to include DATA frame.
 */
nghttp2_ssize nghttp2_frame_decode_data(nghttp2_frame_data *dest,
                                        const uint8_t *src, size_t srclen);

/*
 * nghttp2_frame_decode_headers decodes HEADERS frame from |src| of
 * length |srclen|.  The result is stored in the object pointed by
 * |dest|.  HEADERS frame must start at src[0].  This function
 * finishes when it decodes one HEADERS frame, and returns the exact
 * number of bytes read to decode a frame if it succeeds, or one of
 * the following negative error codes:
 *
 * NGHTTP2_ERR_FRAME_ENCODING
 *     |src| is too short to include HEADERS frame.
 */
nghttp2_ssize nghttp2_frame_decode_headers(nghttp2_frame_headers *dest,
                                           const uint8_t *src, size_t srclen);

/*
 * nghttp2_frame_decode_rst_stream decodes RST_STREAM frame from |src|
 * of length |srclen|.  The result is stored in the object pointed by
 * |dest|.  RST_STREAM frame must start at src[0].  This function
 * finishes when it decodes one RST_STREAM frame, and returns the
 * exact number of bytes read to decode a frame if it succeeds, or one
 * of the following negative error codes:
 *
 * NGHTTP2_ERR_FRAME_ENCODING
 *     |src| is too short to include RST_STREAM frame.
 */
nghttp2_ssize nghttp2_frame_decode_rst_stream(nghttp2_frame_rst_stream *dest,
                                              const uint8_t *src,
                                              size_t srclen);

/*
 * nghttp2_frame_decode_settings decodes SETTINGS frame from |src| of
 * length |srclen|.  The result is stored in the object pointed by
 * |dest|.  SETTINGS frame must start at src[0].  This function
 * finishes when it decodes one SETTINGS frame, and returns the exact
 * number of bytes read to decode a frame if it succeeds, or one of
 * the following negative error codes:
 *
 * NGHTTP2_ERR_FRAME_ENCODING
 *     |src| is too short to include SETTINGS frame.
 */
nghttp2_ssize nghttp2_frame_decode_settings(nghttp2_frame_settings *dest,
                                            const uint8_t *src, size_t srclen);

/*
 * nghttp2_frame_decode_ping decodes PING frame from |src| of length
 * |srclen|.  The result is stored in the object pointed by |dest|.
 * PING frame must start at src[0].  This function finishes when it
 * decodes one PING frame, and returns the exact number of bytes read
 * to decode a frame if it succeeds, or one of the following negative
 * error codes:
 *
 * NGHTTP2_ERR_FRAME_ENCODING
 *     |src| is too short to include PING frame.
 */
nghttp2_ssize nghttp2_frame_decode_ping(nghttp2_frame_ping *dest,
                                        const uint8_t *src, size_t srclen);

/*
 * nghttp2_frame_decode_goaway decodes GOAWAY frame from |src| of
 * length |srclen|.  The result is stored in the object pointed by
 * |dest|.  GOAWAY frame must start at src[0].  This function finishes
 * when it decodes one GOAWAY frame, and returns the exact number of
 * bytes read to decode a frame if it succeeds, or one of the
 * following negative error codes:
 *
 * NGHTTP2_ERR_FRAME_ENCODING
 *     |src| is too short to include GOAWAY frame.
 */
nghttp2_ssize nghttp2_frame_decode_goaway(nghttp2_frame_goaway *dest,
                                          const uint8_t *src, size_t srclen);

/*
 * nghttp2_frame_decode_window_update decodes WINDOW_UPDATE frame from
 * |src| of length |srclen|.  The result is stored in the object
 * pointed by |dest|.  WINDOW_UPDATE frame must start at src[0].  This
 * function finishes when it decodes one WINDOW_UPDATE frame, and
 * returns the exact number of bytes read to decode a frame if it
 * succeeds, or one of the following negative error codes:
 *
 * NGHTTP2_ERR_FRAME_ENCODING
 *     |src| is too short to include WINDOW_UPDATE frame.
 */
nghttp2_ssize
nghttp2_frame_decode_window_update(nghttp2_frame_window_update *dest,
                                   const uint8_t *src, size_t srclen);

/*
 * nghttp2_frame_decode_continuation decodes CONTINUATION frame from
 * |src| of length |srclen|.  The result is stored in the object
 * pointed by |dest|.  CONTINUATION frame must start at src[0].  This
 * function finishes when it decodes one CONTINUATION frame, and
 * returns the exact number of bytes read to decode a frame if it
 * succeeds, or one of the following negative error codes:
 *
 * NGHTTP2_ERR_FRAME_ENCODING
 *     |src| is too short to include CONTINUATION frame.
 */
nghttp2_ssize nghttp2_frame_decode_continuation(nghttp2_frame_headers *dest,
                                                const uint8_t *src,
                                                size_t srclen);

/*
 * nghttp2_frame_decode_priority_update decodes PRIORITY_UPDATE frame
 * from |src| of length |srclen|.  The result is stored in the object
 * pointed by |dest|.  PRIORITY_UPDATE frame must start at src[0].
 * This function finishes when it decodes one PRIORITY_UPDATE frame,
 * and returns the exact number of bytes read to decode a frame if it
 * succeeds, or one of the following negative error codes:
 *
 * NGHTTP2_ERR_FRAME_ENCODING
 *     |src| is too short to include PRIORITY_UPDATE frame.
 */
nghttp2_ssize
nghttp2_frame_decode_priority_update(nghttp2_frame_priority_update *dest,
                                     const uint8_t *src, size_t srclen);

/*
 * nghttp2_nva_copy copies name/value pairs from |nva|, which contains
 * |nvlen| pairs, to |*nva_ptr|, which is dynamically allocated so
 * that all items can be stored.  The resultant name and value in
 * nghttp2_nv are guaranteed to be NULL-terminated even if the input
 * is not null-terminated.
 *
 * The |*pnva| must be freed using nghttp2_nva_del().
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_nva_copy(nghttp2_nv **pnva, const nghttp2_nv *nva, size_t nvlen,
                     const nghttp2_mem *mem);

/*
 * nghttp2_nva_del frees |nva|.
 */
void nghttp2_nva_del(nghttp2_nv *nva, const nghttp2_mem *mem);

/*
 * nghttp2_ping_data_eq returns nonzero if |a| and |b| contain the
 * same data.
 */
int nghttp2_ping_data_eq(const nghttp2_ping_data *a,
                         const nghttp2_ping_data *b);

#endif /* !defined(NGHTTP2_FRAME_H) */
