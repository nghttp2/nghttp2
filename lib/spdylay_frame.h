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
#define SPDYLAY_DELTA_WINDOW_SIZE_MASK 0x7fffffff
#define SPDYLAY_SETTINGS_ID_MASK 0xffffff

/* The length of DATA frame payload. */
#define SPDYLAY_DATA_PAYLOAD_LENGTH 4096

/* The number of bytes of frame header. */
#define SPDYLAY_FRAME_HEAD_LENGTH 8

#define spdylay_frame_get_nv_len(IN, LEN_SIZE)                          \
  (LEN_SIZE == 2 ? spdylay_get_uint16(IN) : spdylay_get_uint32(IN))

#define spdylay_frame_put_nv_len(OUT, VAL, LEN_SIZE)                    \
  (LEN_SIZE == 2 ?                                                      \
   spdylay_put_uint16be(OUT, VAL) : spdylay_put_uint32be(OUT, VAL))

/* Category of SPDY frames. */
typedef enum {
  /* Control frame */
  SPDYLAY_CTRL,
  /* DATA frame */
  SPDYLAY_DATA
} spdylay_frame_category;

/**
 * @struct
 * The DATA frame. It has the following members:
 */
typedef struct {
  /**
   * The stream ID.
   */
  int32_t stream_id;
  /**
   * The DATA frame flags. See :type:`spdylay_data_flag`.
   */
  uint8_t flags;
  /**
   * The flag to indicate whether EOF was reached or not. Initially
   * |eof| is 0. It becomes 1 after all data were read.
   */
  uint8_t eof;
  /**
   * The data to be sent for this DATA frame.
   */
  spdylay_data_provider data_prd;
} spdylay_data;

/*
 * Returns the number of bytes in length of name/value pair for the
 * given protocol version |version|. If |version| is not supported,
 * returns 0.
 */
size_t spdylay_frame_get_len_size(uint16_t version);

/*
 * Packs SYN_STREAM frame |frame| in wire format and store it in
 * |*buf_ptr|.  The capacity of |*buf_ptr| is |*buflen_ptr| bytes.
 * The |*nvbuf_ptr| is used to store inflated name/value pairs in wire
 * format temporarily. Its length is |*nvbuflen_ptr| bytes.  This
 * function expands |*buf_ptr| and |*nvbuf_ptr| as necessary to store
 * frame and name/value pairs. When expansion occurred, memory
 * previously pointed by |*buf_ptr| and |*nvbuf_ptr| is freed.
 * |*buf_ptr|, |*buflen_ptr|, |*nvbuf_ptr| and |*nvbuflen_ptr| are
 * updated accordingly.
 *
 * frame->hd.length is assigned after length is determined during
 * packing process.
 *
 * This function returns the size of packed frame if it succeeds, or
 * returns one of the following negative error codes:
 *
 * SPDYLAY_ERR_UNSUPPORTED_VERSION
 *     The version is not supported.
 * SPDYLAY_ERR_ZLIB
 *     The deflate operation failed.
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
ssize_t spdylay_frame_pack_syn_stream(uint8_t **buf_ptr,
                                      size_t *buflen_ptr,
                                      uint8_t **nvbuf_ptr,
                                      size_t *nvbuflen_ptr,
                                      spdylay_syn_stream *frame,
                                      spdylay_zlib *deflater);

/*
 * Unpacks SYN_STREAM frame byte sequence into |frame|.  Header is
 * given in head and headlen. In spdy/2 spec, headlen is 8
 * bytes. |payload| is the data after length field of the header.
 *
 * |inflatebuf| is used to buffer name/value pairs while inflating
 * them using |inflater|.  The caller must reset |inflatebuf| before
 * the call.  |*nvbuf_ptr|, |*nvbuflen_ptr| is used to store temporal
 * inflated name/value pairs. This function expands |*nvbuf_ptr| as
 * necessary and updates these variables.
 *
 * This function also validates the name/value pairs. If unpacking
 * succeeds but validation fails, it is indicated by returning
 * SPDYLAY_ERR_INVALID_HEADER_BLOCK.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_INVALID_HEADER_BLOCK
 *     Unpacking succeeds but the header block is invalid.
 * SPDYLAY_ERR_INVALID_FRAME
 *     The input data are invalid.
 * SPDYLAY_ERR_UNSUPPORTED_VERSION
 *     The version is not supported.
 * SPDYLAY_ERR_ZLIB
 *     The inflate operation failed.
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_frame_unpack_syn_stream(spdylay_syn_stream *frame,
                                    spdylay_buffer *inflatebuf,
                                    uint8_t **nvbuf_ptr,
                                    size_t *nvbuflen_ptr,
                                    const uint8_t *head, size_t headlen,
                                    const uint8_t *payload, size_t payloadlen,
                                    spdylay_zlib *inflater);

/*
 * Packs SYN_REPLY frame |frame| in wire frame format and store it in
 * |*buf_ptr|.  The capacity of |*buf_ptr| is |*buflen_ptr| bytes.
 * The |*nvbuf_ptr| is used to store inflated name/value pairs in wire
 * format temporarily. Its length is |*nvbuflen_ptr| bytes.  This
 * function expands |*buf_ptr| and |*nvbuf_ptr| as necessary to store
 * frame and name/value pairs. When expansion occurred, memory
 * previously pointed by |*buf_ptr| and |*nvbuf_ptr| is freed.
 * |*buf_ptr|, |*buflen_ptr|, |*nvbuf_ptr| and |*nvbuflen_ptr| are
 * updated accordingly.
 *
 * frame->hd.length is assigned after length is determined during
 * packing process.
 *
 * This function returns the size of packed frame if it succeeds, or
 * returns one of the following negative error codes:
 *
 * SPDYLAY_ERR_UNSUPPORTED_VERSION
 *     The version is not supported.
 * SPDYLAY_ERR_ZLIB
 *     The deflate operation failed.
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
ssize_t spdylay_frame_pack_syn_reply(uint8_t **buf_ptr,
                                     size_t *buflen_ptr,
                                     uint8_t **nvbuf_ptr,
                                     size_t *nvbuflen_ptr,
                                     spdylay_syn_reply *frame,
                                     spdylay_zlib *deflater);

/*
 * Unpacks SYN_REPLY frame byte sequence into |frame|.
 *
 * |inflatebuf| is used to buffer name/value pairs while inflating
 * them using |inflater|.  The caller must reset |inflatebuf| before
 * the call.  |*nvbuf_ptr|, |*nvbuflen_ptr| is used to store temporal
 * inflated name/value pairs. This function expands |*nvbuf_ptr| as
 * necessary and updates these variables.
 *
 * This function also validates the name/value pairs. If unpacking
 * succeeds but validation fails, it is indicated by returning
 * SPDYLAY_ERR_INVALID_HEADER_BLOCK.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_INVALID_HEADER_BLOCK
 *     Unpacking succeeds but the header block is invalid.
 * SPDYLAY_ERR_UNSUPPORTED_VERSION
 *     The version is not supported.
 * SPDYLAY_ERR_INVALID_FRAME
 *     The input data are invalid.
 * SPDYLAY_ERR_ZLIB
 *     The inflate operation failed.
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_frame_unpack_syn_reply(spdylay_syn_reply *frame,
                                   spdylay_buffer *inflatebuf,
                                   uint8_t **nvbuf_ptr,
                                   size_t *nvbuflen_ptr,
                                   const uint8_t *head, size_t headlen,
                                   const uint8_t *payload, size_t payloadlen,
                                   spdylay_zlib *inflater);

/*
 * Packs PING frame |frame| in wire format and store it in
 * |*buf_ptr|. The capacity of |*buf_ptr| is |*buflen_ptr|
 * length. This function expands |*buf_ptr| as necessary to store
 * given |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
ssize_t spdylay_frame_pack_ping(uint8_t **buf_ptr, size_t *buflen_ptr,
                                spdylay_ping *frame);

/*
 * Unpacks PING wire format into |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_INVALID_FRAME
 *     The input data are invalid.
 */
int spdylay_frame_unpack_ping(spdylay_ping *frame,
                              const uint8_t *head, size_t headlen,
                              const uint8_t *payload, size_t payloadlen);

/*
 * Packs GOAWAY frame |frame | in wire format and store it in
 * |*buf_ptr|. The capacity of |*buf_ptr| is |*buflen_ptr|
 * length. This function expands |*buf_ptr| as necessary to store
 * given |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_UNSUPPORTED_VERSION
 *     The version is not supported.
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
ssize_t spdylay_frame_pack_goaway(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  spdylay_goaway *frame);

/*
 * Unpacks GOAWAY wire format into |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_UNSUPPORTED_VERSION
 *     The version is not supported.
 * SPDYLAY_ERR_INVALID_FRAME
 *     The input data are invalid.
 */
int spdylay_frame_unpack_goaway(spdylay_goaway *frame,
                                const uint8_t *head, size_t headlen,
                                const uint8_t *payload, size_t payloadlen);

/*
 * Packs HEADERS frame |frame| in wire format and store it in
 * |*buf_ptr|.  The capacity of |*buf_ptr| is |*buflen_ptr| bytes.
 * The |*nvbuf_ptr| is used to store inflated name/value pairs in wire
 * format temporarily. Its length is |*nvbuflen_ptr| bytes.  This
 * function expands |*buf_ptr| and |*nvbuf_ptr| as necessary to store
 * frame and name/value pairs. When expansion occurred, memory
 * previously pointed by |*buf_ptr| and |*nvbuf_ptr| is freed.
 * |*buf_ptr|, |*buflen_ptr|, |*nvbuf_ptr| and |*nvbuflen_ptr| are
 * updated accordingly.
 *
 * frame->hd.length is assigned after length is determined during
 * packing process.
 *
 * This function returns the size of packed frame if it succeeds, or
 * returns one of the following negative error codes:
 *
 * SPDYLAY_ERR_UNSUPPORTED_VERSION
 *     The version is not supported.
 * SPDYLAY_ERR_ZLIB
 *     The deflate operation failed.
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
ssize_t spdylay_frame_pack_headers(uint8_t **buf_ptr, size_t *buflen_ptr,
                                   uint8_t **nvbuf_ptr, size_t *nvbuflen_ptr,
                                   spdylay_headers *frame,
                                   spdylay_zlib *deflater);

/*
 * Unpacks HEADERS wire format into |frame|.
 *
 * |inflatebuf| is used to buffer name/value pairs while inflating
 * them using |inflater|.  The caller must reset |inflatebuf| before
 * the call.  |*nvbuf_ptr|, |*nvbuflen_ptr| is used to store temporal
 * inflated name/value pairs. This function expands |*nvbuf_ptr| as
 * necessary and updates these variables.
 *
 * This function also validates the name/value pairs. If unpacking
 * succeeds but validation fails, it is indicated by returning
 * SPDYLAY_ERR_INVALID_HEADER_BLOCK.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_INVALID_HEADER_BLOCK
 *     Unpacking succeeds but the header block is invalid.
 * SPDYLAY_ERR_UNSUPPORTED_VERSION
 *     The version is not supported.
 * SPDYLAY_ERR_INVALID_FRAME
 *     The input data are invalid.
 * SPDYLAY_ERR_ZLIB
 *     The inflate operation failed.
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_frame_unpack_headers(spdylay_headers *frame,
                                 spdylay_buffer *inflatebuf,
                                 uint8_t **nvbuf_ptr,
                                 size_t *nvbuflen_ptr,
                                 const uint8_t *head, size_t headlen,
                                 const uint8_t *payload, size_t payloadlen,
                                 spdylay_zlib *inflater);

/*
 * Packs RST_STREAM frame |frame| in wire frame format and store it in
 * |*buf_ptr|. The capacity of |*buf_ptr| is |*buflen_ptr|
 * length. This function expands |*buf_ptr| as necessary to store
 * given |frame|. In spdy/2 spec, RST_STREAM wire format is always 16
 * bytes long.
 *
 * This function returns the size of packed frame if it succeeds, or
 * returns one of the following negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
ssize_t spdylay_frame_pack_rst_stream(uint8_t **buf_ptr, size_t *buflen_ptr,
                                      spdylay_rst_stream *frame);

/*
 * Unpacks RST_STREAM frame byte sequence into |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_INVALID_FRAME
 *     The input data are invalid.
 */
int spdylay_frame_unpack_rst_stream(spdylay_rst_stream *frame,
                                    const uint8_t *head, size_t headlen,
                                    const uint8_t *payload, size_t payloadlen);


/*
 * Packs WINDOW_UPDATE frame |frame| in wire frame format and store it
 * in |*buf_ptr|. The capacity of |*buf_ptr| is |*buflen_ptr|
 * length. This function expands |*buf_ptr| as necessary to store
 * given |frame|. In SPDY/3 spec, WINDOW_UPDATE wire format is always 16
 * bytes long.
 *
 * This function returns the size of packed frame if it succeeds, or
 * returns one of the following negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
ssize_t spdylay_frame_pack_window_update(uint8_t **buf_ptr, size_t *buflen_ptr,
                                         spdylay_window_update *frame);

/*
 * Unpacks WINDOW_UPDATE frame byte sequence into |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_INVALID_FRAME
 *     The input data are invalid.
 */
int spdylay_frame_unpack_window_update(spdylay_window_update *frame,
                                       const uint8_t *head, size_t headlen,
                                       const uint8_t *payload,
                                       size_t payloadlen);

/*
 * Packs SETTINGS frame |frame| in wire format and store it in
 * |*buf_ptr|. The capacity of |*buf_ptr| is |*buflen_ptr|
 * length. This function expands |*buf_ptr| as necessary to store
 * given |frame|.
 *
 * This function returns the size of packed frame if it succeeds, or
 * returns one of the following negative error codes:
 *
 * SPDYLAY_ERR_UNSUPPORTED_VERSION
 *     The version is not supported.
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
ssize_t spdylay_frame_pack_settings(uint8_t **buf_ptr, size_t *buflen_ptr,
                                    spdylay_settings *frame);

/*
 * Unpacks SETTINGS wire format into |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_UNSUPPORTED_VERSION
 *     The version is not supported.
 * SPDYLAY_ERR_INVALID_FRAME
 *     The input data are invalid.
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_frame_unpack_settings(spdylay_settings *frame,
                                  const uint8_t *head, size_t headlen,
                                  const uint8_t *payload, size_t payloadlen);

/*
 * Returns number of bytes to pack name/value pairs |nv|. This
 * function expects |nv| is sorted in ascending order of key.
 * |len_size| is the number of bytes in length of name/value pair and
 * it must be 2 or 4.
 *
 * This function can handles duplicate keys and concatenation of thier
 * values with '\0'.
 */
size_t spdylay_frame_count_nv_space(char **nv, size_t len_size);

/*
 * Packs name/value pairs in |nv| in |buf|. |buf| must have at least
 * spdylay_frame_count_nv_space(nv) bytes.  |len_size| is the number
 * of bytes in length of name/value pair and it must be 2 or 4.
 */
ssize_t spdylay_frame_pack_nv(uint8_t *buf, char **nv, size_t len_size);

/*
 * Packs name/value pairs in |nv| in |*buf_ptr| with offset
 * |nv_offset|.  It means first byte of packed name/value pairs is
 * stored in |*buf_ptr|+|nv_offset|.  |*buf_ptr| and |*nvbuf_ptr| are
 * expanded as necessary.
 *
 * This function returns the number of the bytes for the frame
 * containing this name/value pairs if it succeeds, or one of the
 * following negative error codes:
 *
 * SPDYLAY_ERR_ZLIB
 *     The deflate operation failed.
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
ssize_t spdylay_frame_alloc_pack_nv(uint8_t **buf_ptr,
                                    size_t *buflen_ptr,
                                    uint8_t **nvbuf_ptr,
                                    size_t *nvbuflen_ptr,
                                    char **nv, size_t nv_offset,
                                    size_t len_size,
                                    spdylay_zlib *deflater);

/*
 * Counts number of name/value pair in |in| and computes length of
 * buffers to store unpacked name/value pair and store them in
 * |*num_nv_ptr| and |*buf_size_ptr| respectively. |len_size| is the
 * number of bytes in length of name/value pair and it must be 2 or
 * 4. We use folloing data structure in |*buf_size_ptr|.  First part
 * of the data is array of pointer to name/value pair.  Supporse the
 * buf pointer points to the data region and N is the number of
 * name/value pair.  First (N*2+1)*sizeof(char*) bytes contain array
 * of pointer to name/value pair and terminating NULL.  Each pointer
 * to name/value pair points to the string in remaining data.  For
 * each name/value pair, the name is copied to the remaining data with
 * terminating NULL character. The value is also copied to the
 * position after the data with terminating NULL character. The
 * corresponding index is assigned to these pointers. If the value
 * contains multiple values (delimited by single NULL), for each such
 * data, corresponding index is assigned to name/value pointers. In
 * this case, the name string is reused.
 *
 * With the above stragety, |*buf_size_ptr| is calculated as
 * (N*2+1)*sizeof(char*)+sum(strlen(name)+1+strlen(value)+1){for each
 * name/value pair}.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_INVALID_FRAME
 *     The input data are invalid.
 */
int spdylay_frame_count_unpack_nv_space
(size_t *num_nv_ptr, size_t *buf_size_ptr, const uint8_t *in, size_t inlen,
 size_t len_size);

/*
 * Validates name of Name/Value header Block. The |buf| is the
 * allocated buffer with the length at least |buflen| bytes. The
 * |buflen| must be at least the number of Name/Value pairs in the
 * packed name/value header block |in|. The length of |in| is given in
 * |inlen|.  The |buf| is used as a work memory to validate header
 * names and the caller must not use its content on return.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_INVALID_HEADER_BLOCK
 *     There are duplicate header names; or the header names are not
 *     encoded in US-ASCII character set and not lower cased; or the
 *     header name is zero-length string.
 */
int spdylay_frame_unpack_nv_check_name(uint8_t *buf, size_t buflen,
                                       const uint8_t *in, size_t inlen,
                                       size_t len_size);

/*
 * Unpacks name/value pairs in wire format |in| with length |inlen|
 * and stores them in |*nv_ptr|.  Thif function allocates enough
 * memory to store name/value pairs in |*nv_ptr|.  |len_size| is the
 * number of bytes in length of name/value pair and it must be 2 or 4.
 *
 * This function also validates the name/value pairs. If unpacking
 * succeeds but validation fails, it is indicated by returning
 * SPDYLAY_ERR_INVALID_HEADER_BLOCK.
 *
 * If error other than SPDYLAY_ERR_INVALID_HEADER_BLOCK is returned,
 * the |nv_ptr| is not assigned. In other words,
 * SPDYLAY_ERR_INVALID_HEADER_BLOCK means unpacking succeeded, but
 * header block validation failed.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_INVALID_HEADER_BLOCK
 *     Unpacking succeeds but the header block is invalid.
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_frame_unpack_nv(char ***nv_ptr, const uint8_t *in, size_t inlen,
                            size_t len_size);

/*
 * Unpacks name/value pairs from buffer |in| with length |inlen|.  The
 * necessary memory area required for output is allocated and its
 * pointer is assigned to |nv_ptr|. |inflatebuf| is used for inflate
 * operation. |*nvbuf_ptr| is used for temporarily stored inflated
 * name/value pair in wire format. It is expanded as necessary.
 * |len_size| is the number of bytes used in name/value length. It
 * must be either 2 or 4.
 *
 * This function also validates the name/value pairs. If unpacking
 * succeeds but validation fails, it is indicated by returning
 * SPDYLAY_ERR_INVALID_HEADER_BLOCK.
 *
 * If error other than SPDYLAY_ERR_INVALID_HEADER_BLOCK is returned,
 * the |nv_ptr| is not assigned. In other words,
 * SPDYLAY_ERR_INVALID_HEADER_BLOCK means unpacking succeeded, but
 * header block validation failed.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_INVALID_HEADER_BLOCK
 *     Unpacking succeeds but the header block is invalid.
 * SPDYLAY_ERR_ZLIB
 *     The inflate operation failed.
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_frame_alloc_unpack_nv(char ***nv_ptr,
                                  spdylay_buffer *inflatebuf,
                                  uint8_t **nvbuf_ptr,
                                  size_t *nvbuflen_ptr,
                                  const uint8_t *in, size_t inlen,
                                  size_t len_size,
                                  spdylay_zlib *inflater);

/*
 * Initializes SYN_STREAM frame |frame| with given values.  |frame|
 * takes ownership of |nv|, so caller must not free it. If stream_id
 * is not assigned yet, it must be 0.
 */
void spdylay_frame_syn_stream_init(spdylay_syn_stream *frame,
                                   uint16_t version, uint8_t flags,
                                   int32_t stream_id, int32_t assoc_stream_id,
                                   uint8_t pri, char **nv);

void spdylay_frame_syn_stream_free(spdylay_syn_stream *frame);

void spdylay_frame_syn_reply_init(spdylay_syn_reply *frame,
                                  uint16_t version, uint8_t flags,
                                  int32_t stream_id, char **nv);

void spdylay_frame_syn_reply_free(spdylay_syn_reply *frame);

void spdylay_frame_ping_init(spdylay_ping *frame, uint16_t version,
                             uint32_t unique_id);

void spdylay_frame_ping_free(spdylay_ping *frame);

/*
 * Initializes GOAWAY frame |frame| with given values.  The
 * |status_code| is ignored if |version| == SPDYLAY_PROTO_SPDY2.
 */
void spdylay_frame_goaway_init(spdylay_goaway *frame, uint16_t version,
                               int32_t last_good_stream_id,
                               uint32_t status_code);

void spdylay_frame_goaway_free(spdylay_goaway *frame);

void spdylay_frame_headers_init(spdylay_headers *frame, uint16_t version,
                                uint8_t flags,
                                int32_t stream_id, char **nv);

void spdylay_frame_headers_free(spdylay_headers *frame);

void spdylay_frame_rst_stream_init(spdylay_rst_stream *frame,
                                   uint16_t version,
                                   int32_t stream_id, uint32_t status_code);

void spdylay_frame_rst_stream_free(spdylay_rst_stream *frame);

void spdylay_frame_window_update_init(spdylay_window_update *frame,
                                      uint16_t version,
                                      int32_t stream_id,
                                      int32_t delta_window_size);

void spdylay_frame_window_update_free(spdylay_window_update *frame);

/*
 * Initializes SETTINGS frame |frame| with given values. |frame| takes
 * ownership of |iv|, so caller must not free it.
 */
void spdylay_frame_settings_init(spdylay_settings *frame,
                                 uint16_t version, uint8_t flags,
                                 spdylay_settings_entry *iv, size_t niv);

void spdylay_frame_settings_free(spdylay_settings *frame);

void spdylay_frame_data_init(spdylay_data *frame, int32_t stream_id,
                             uint8_t flags,
                             const spdylay_data_provider *data_prd);

void spdylay_frame_data_free(spdylay_data *frame);

/*
 * Returns 1 if the first byte of this frame indicates it is a control
 * frame.
 */
int spdylay_frame_is_ctrl_frame(uint8_t first_byte);

/*
 * Deallocates memory of name/value pair |nv|.
 */
void spdylay_frame_nv_del(char **nv);

/*
 * Makes a deep copy of |nv| and returns the copy.  This function
 * returns the pointer to the copy if it succeeds, or NULL.  To free
 * allocated memory, use spdylay_frame_nv_del().
 */
char** spdylay_frame_nv_copy(const char **nv);

/*
 * Sorts |nv| in the ascending order of name.
 */
void spdylay_frame_nv_sort(char **nv);

/*
 * Makes names in |nv| lower cased.
 */
void spdylay_frame_nv_downcase(char **nv);

/*
 * This function first makes a copy of |nv| using
 * spdylay_frame_nv_copy().  If it succeeds, then call
 * spdylay_frame_nv_downcase() and spdylay_frame_nv_sort() with the
 * copied name/value pairs.
 *
 * This function returns the copied name/value pairs if it succeeds,
 * or NULL.
 */
char** spdylay_frame_nv_norm_copy(const char **nv);

/*
 * Translates the |nv| in SPDY/3 header names into SPDY/2.
 */
void spdylay_frame_nv_3to2(char **nv);

/*
 * Translates the |nv| in SPDY/2 header names into SPDY/3.
 */
void spdylay_frame_nv_2to3(char **nv);

/*
 * Makes copy of |iv| and return the copy. The |niv| is the number of
 * entries in |iv|. This function returns the pointer to the copy if
 * it succeeds, or NULL.
 */
spdylay_settings_entry* spdylay_frame_iv_copy(const spdylay_settings_entry *iv,
                                              size_t niv);

/*
 * Sorts the |iv| with the ascending order of the settings_id member.
 * The number of the element in the array pointed by the |iv| is given
 * by the |niv|.
 */
void spdylay_frame_iv_sort(spdylay_settings_entry *iv, size_t niv);

#endif /* SPDYLAY_FRAME_H */
