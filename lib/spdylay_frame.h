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
#ifndef SPDYLAY_FRAME_H
#define SPDYLAY_FRAME_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include "spdylay_zlib.h"
#include "spdylay_buffer.h"

typedef enum {
  SPDYLAY_SYN_STREAM = 1,
  SPDYLAY_SYN_REPLY = 2,
  SPDYLAY_RST_STREAM = 3,
  SPDYLAY_SETTINGS = 4,
  SPDYLAY_NOOP = 5,
  SPDYLAY_PING = 6,
  SPDYLAY_GOAWAY = 7,
} spdylay_frame_type;

typedef enum {
  SPDYLAY_FLAG_FIN = 1
} spdylay_flag;

typedef struct {
  uint16_t version;
  uint16_t type;
  uint8_t flags;
  int32_t length;
} spdylay_ctrl_hd;

typedef struct {
  spdylay_ctrl_hd hd;
  int32_t stream_id;
  int32_t assoc_stream_id;
  uint8_t pri;
  char **nv;
} spdylay_syn_stream;

typedef struct {
  spdylay_ctrl_hd hd;
  int32_t stream_id;
  char **nv;
} spdylay_syn_reply;

typedef union {
  spdylay_syn_stream syn_stream;
} spdylay_frame;

/*
 * Packs SYN_STREAM frame |frame| in wire frame format and store it in
 * |*buf_ptr|. This function allocates enough memory to store given
 * frame in |*buf_ptr|.  This function returns the size of packed
 * frame if it succeeds, or returns negative error
 * code. frame->hd.length is assigned after length is determined
 * during packing process.
 */
ssize_t spdylay_frame_pack_syn_stream(uint8_t **buf_ptr,
                                      spdylay_syn_stream *frame,
                                      spdylay_zlib *deflater);

/*
 * Unpacks SYN_STREAM frame byte sequence into |frame|.  Header is
 * given in head and headlen. In spdy/2 spec, headlen is 8
 * bytes. |payload| is the data after length field of the header.
 * This function returns 0 if it succeeds or negative error code.
 */
int spdylay_frame_unpack_syn_stream(spdylay_syn_stream *frame,
                                    const uint8_t *head, size_t headlen,
                                    const uint8_t *payload, size_t payloadlen,
                                    spdylay_zlib *inflater);

/*
 * Unpacks SYN_REPLY frame byte sequence into |frame|.  This function
 * returns 0 if it succeeds or negative error code.
 */
int spdylay_frame_unpack_syn_reply(spdylay_syn_reply *frame,
                                   const uint8_t *head, size_t headlen,
                                   const uint8_t *payload, size_t payloadlen,
                                   spdylay_zlib *inflater);

/*
 * Returns number of bytes to pack name/value pairs |nv|. This
 * function expects |nv| is sorted in ascending order of key.  This
 * function can handles duplicate keys and concatenation of thier
 * values with '\0'.
 */
size_t spdylay_frame_count_nv_space(char **nv);

/*
 * Packs name/value pairs in |nv| in |buf|. |buf| must have at least
 * spdylay_frame_count_nv_space(nv) bytes.
 */
ssize_t spdylay_frame_pack_nv(uint8_t *buf, char **nv);

/*
 * Unpacks name/value pairs in wire format |in| with length |inlen|
 * and stores them in |*nv_ptr|.  Thif function allocates enough
 * memory to store name/value pairs in |*nv_ptr|.  This function
 * returns 0 if it succeeds, or negative error code.
 */
int spdylay_frame_unpack_nv(char ***nv_ptr, const uint8_t *in, size_t inlen);

/*
 * Initializes SYN_STREAM frame |frame| with given values.  |frame|
 * takes ownership of |nv|, so caller must not free it. If stream_id
 * is not assigned yet, it must be 0.
 */
void spdylay_frame_syn_stream_init(spdylay_syn_stream *frame, uint8_t flags,
                                   int32_t stream_id, int32_t assoc_stream_id,
                                   uint8_t pri, char **nv);

void spdylay_frame_syn_stream_free(spdylay_syn_stream *frame);

void spdylay_frame_syn_reply_free(spdylay_syn_reply *frame);

/*
 * Returns 1 if the first byte of this frame indicates it is a control
 * frame.
 */
int spdylay_frame_is_ctrl_frame(uint8_t first_byte);

/*
 * Deallocates memory of key/value pairs in |nv|.
 */
void spdylay_frame_nv_free(char **nv);

#endif /* SPDYLAY_FRAME_H */
