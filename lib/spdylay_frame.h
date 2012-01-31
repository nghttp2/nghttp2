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

#include <spdylay/spdylay.h>
#include "spdylay_zlib.h"
#include "spdylay_buffer.h"

#define SPDYLAY_STREAM_ID_MASK 0x7fffffff
#define SPDYLAY_LENGTH_MASK 0xffffff
#define SPDYLAY_VERSION_MASK 0x7fff

#define SPDYLAY_DATA_FRAME_LENGTH 4096

/* The number of bytes of frame header. */
#define SPDYLAY_FRAME_HEAD_LENGTH 8

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
 * Packs SYN_REPLY frame |frame| in wire frame format and store it in
 * |*buf_ptr|. This function allocates enough memory to store given
 * frame in |*buf_ptr|. This function returns the size of packed frame
 * it it succeeds, or returns negative error code. frame->hd.length is
 * assigned after length is determined during packing process.
 */
ssize_t spdylay_frame_pack_syn_reply(uint8_t **buf_ptr,
                                     spdylay_syn_reply *frame,
                                     spdylay_zlib *deflater);

/*
 * Unpacks SYN_REPLY frame byte sequence into |frame|.  This function
 * returns 0 if it succeeds or negative error code.
 */
int spdylay_frame_unpack_syn_reply(spdylay_syn_reply *frame,
                                   const uint8_t *head, size_t headlen,
                                   const uint8_t *payload, size_t payloadlen,
                                   spdylay_zlib *inflater);

/*
 * Packs PING frame |frame| in wire format and store it in
 * |*buf_ptr|. This function allocates enough memory in |*buf_ptr| to
 * store given |frame|. This function returns the size of packed frame
 * if it succeeds, or negative error code.
 */
ssize_t spdylay_frame_pack_ping(uint8_t **buf_ptr, spdylay_ping *frame);

/*
 * Unpacks PING wire format into |frame|. This function returns 0 if
 * it succeeds, or negative error code.
 */
int spdylay_frame_unpack_ping(spdylay_ping *frame,
                              const uint8_t *head, size_t headlen,
                              const uint8_t *payload, size_t payloadlen);

/*
 * Packs GOAWAY frame |frame | in wire format and store it in
 * |*buf_ptr|. This function allocates enough memory in |*buf_ptr| to
 * store given |frame|. This function returns the size of packed frame
 * if it succeeds, or negative error code.
 */
ssize_t spdylay_frame_pack_goaway(uint8_t **buf_ptr, spdylay_goaway *frame);

/*
 * Unpacks GOAWAY wire format into |frame|. This function returns 0 if
 * it succeeds, or negative error code.
 */
int spdylay_frame_unpack_goaway(spdylay_goaway *frame,
                                const uint8_t *head, size_t headlen,
                                const uint8_t *payload, size_t payloadlen);

/*
 * Packs HEADERS frame |frame| in wire format and store it in
 * |*buf_ptr|. This function allocates enough memory in |*buf_ptr| to
 * store given |frame|. This function returns the size of packed frame
 * it it succeeds, or returns negative error code. frame->hd.length is
 * assigned after length is determined during packing process.
 */
ssize_t spdylay_frame_pack_headers(uint8_t **buf_ptr,
                                   spdylay_headers *frame,
                                   spdylay_zlib *deflater);

/*
 * Unpacks HEADERS wire format into |frame|. This function returns 0
 * if it succeeds or negative error code.
 */
int spdylay_frame_unpack_headers(spdylay_headers *frame,
                                 const uint8_t *head, size_t headlen,
                                 const uint8_t *payload, size_t payloadlen,
                                 spdylay_zlib *inflater);

/*
 * Packs RST_STREAM frame |frame| in wire frame format and store it in
 * |*buf_ptr|. This function allocates enough memory to store given
 * frame in |*buf_ptr|. In spdy/2 spc, RST_STREAM wire format is
 * always 16 bytes long. This function returns the size of packed
 * frame if it succeeds, or negative error code.
 */
ssize_t spdylay_frame_pack_rst_stream(uint8_t **buf_ptr,
                                      spdylay_rst_stream *frame);

/*
 * Unpacks RST_STREAM frame byte sequence into |frame|.  This function
 * returns 0 if it succeeds, or negative error code.
 */
int spdylay_frame_unpack_rst_stream(spdylay_rst_stream *frame,
                                    const uint8_t *head, size_t headlen,
                                    const uint8_t *payload, size_t payloadlen);

/*
 * Packs SETTINGS frame |frame| in wire format and store it in
 * |*buf_ptr|. This function allocates enough memory to store given
 * frame in |*buf_ptr|. This function returns the size of packed frame
 * if it succeeds, or negative error code.
 */
ssize_t spdylay_frame_pack_settings(uint8_t **buf_ptr, spdylay_settings *frame);

/*
 * Unpacks SETTINGS wire format into |frame|. This function returns 0
 * if it succeeds, or negative error code.
 */
int spdylay_frame_unpack_settings(spdylay_settings *frame,
                                  const uint8_t *head, size_t headlen,
                                  const uint8_t *payload, size_t payloadlen);

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

void spdylay_frame_syn_reply_init(spdylay_syn_reply *frame, uint8_t flags,
                                  int32_t stream_id, char **nv);

void spdylay_frame_syn_reply_free(spdylay_syn_reply *frame);

void spdylay_frame_ping_init(spdylay_ping *frame, uint32_t unique_id);

void spdylay_frame_ping_free(spdylay_ping *frame);

void spdylay_frame_goaway_init(spdylay_goaway *frame,
                               int32_t last_good_stream_id);

void spdylay_frame_goaway_free(spdylay_goaway *frame);

void spdylay_frame_headers_init(spdylay_headers *frame, uint8_t flags,
                                int32_t stream_id, char **nv);

void spdylay_frame_headers_free(spdylay_headers *frame);

void spdylay_frame_rst_stream_init(spdylay_rst_stream *frame,
                                   int32_t stream_id, uint32_t status_code);

void spdylay_frame_rst_stream_free(spdylay_rst_stream *frame);

/*
 * Initializes SETTINGS frame |frame| with given values. |frame| takes
 * ownership of |iv|, so caller must not free it.
 */
void spdylay_frame_settings_init(spdylay_settings *frame, uint8_t flags,
                                 spdylay_settings_entry *iv, size_t niv);

void spdylay_frame_settings_free(spdylay_settings *frame);

void spdylay_frame_data_init(spdylay_data *frame, int32_t stream_id,
                             spdylay_data_provider *data_prd);

void spdylay_frame_data_free(spdylay_data *frame);

/*
 * Returns 1 if the first byte of this frame indicates it is a control
 * frame.
 */
int spdylay_frame_is_ctrl_frame(uint8_t first_byte);

/*
 * Deallocates memory of key/value pairs in |nv|.
 */
void spdylay_frame_nv_free(char **nv);

/*
 * Makes a deep copy of |nv| and returns the copy.  This function
 * returns the pointer to the copy if it succeeds, or NULL.
 */
char** spdylay_frame_nv_copy(const char **nv);

/*
 * Sorts |nv| in the ascending order of name.
 */
void spdylay_frame_nv_sort(char **nv);

/*
 * Makes copy of |iv| and return the copy. The |niv| is the number of
 * entries in |iv|. This function returns the pointer to the copy if
 * it succeeds, or NULL.
 */
spdylay_settings_entry* spdylay_frame_iv_copy(const spdylay_settings_entry *iv,
                                              size_t niv);

#endif /* SPDYLAY_FRAME_H */
