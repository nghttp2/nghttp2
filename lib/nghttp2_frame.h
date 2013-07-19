/*
 * nghttp2 - HTTP/2.0 C Library
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
#ifndef NGHTTP2_FRAME_H
#define NGHTTP2_FRAME_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <nghttp2/nghttp2.h>
#include "nghttp2_zlib.h"
#include "nghttp2_buffer.h"

/**
 * @macro
 * default priority value
 */
#define NGHTTP2_PRI_DEFAULT (1 << 30)
#define NGHTTP2_PRI_LOWEST ((1U << 31) - 1)

#define NGHTTP2_MAX_FRAME_SIZE ((1 << 16) - 1)

#define NGHTTP2_STREAM_ID_MASK 0x7fffffff
#define NGHTTP2_PRIORITY_MASK 0x7fffffff
#define NGHTTP2_WINDOW_SIZE_INCREMENT_MASK 0x7fffffff
#define NGHTTP2_SETTINGS_ID_MASK 0xffffff

/* The maximum length of DATA frame payload. */
#define NGHTTP2_DATA_PAYLOAD_LENGTH 4096

/* The number of bytes of frame header. */
#define NGHTTP2_FRAME_HEAD_LENGTH 8

/* Category of frames. */
typedef enum {
  /* non-DATA frame */
  NGHTTP2_CAT_CTRL,
  /* DATA frame */
  NGHTTP2_CAT_DATA
} nghttp2_frame_category;

#define nghttp2_frame_get_nv_len(RED) nghttp2_buffer_reader_uint16(RED)
#define nghttp2_frame_put_nv_len(OUT, VAL) nghttp2_put_uint16be(OUT, VAL)

/**
 * @struct
 * The DATA frame. It has the following members:
 */
typedef struct {
  nghttp2_frame_hd hd;
  /**
   * The flag to indicate whether EOF was reached or not. Initially
   * |eof| is 0. It becomes 1 after all data were read. This is used
   * exclusively by nghttp2 library and not in the spec.
   */
  uint8_t eof;
  /**
   * The data to be sent for this DATA frame.
   */
  nghttp2_data_provider data_prd;
} nghttp2_data;

int nghttp2_frame_is_data_frame(uint8_t *head);

void nghttp2_frame_pack_frame_hd(uint8_t *buf, const nghttp2_frame_hd *hd);

void nghttp2_frame_unpack_frame_hd(nghttp2_frame_hd *hd, const uint8_t* buf);

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
 * NGHTTP2_ERR_ZLIB
 *     The deflate operation failed.
 * NGHTTP2_ERR_FRAME_TOO_LARGE
 *     The length of the frame is too large.
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
ssize_t nghttp2_frame_pack_headers(uint8_t **buf_ptr,
                                   size_t *buflen_ptr,
                                   uint8_t **nvbuf_ptr,
                                   size_t *nvbuflen_ptr,
                                   nghttp2_headers *frame,
                                   nghttp2_zlib *deflater);

/*
 * Unpacks HEADERS frame byte sequence into |frame|.  The control
 * frame header is given in |head| with |headlen| length. In the spec,
 * headlen is 8 bytes. |payload| is the data after frame header and
 * just before name/value header block.
 *
 * The |inflatebuf| contains inflated name/value header block in wire
 * foramt.
 *
 * This function also validates the name/value pairs. If unpacking
 * succeeds but validation fails, it is indicated by returning
 * NGHTTP2_ERR_INVALID_HEADER_BLOCK.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_HEADER_BLOCK
 *     Unpacking succeeds but the header block is invalid.
 * NGHTTP2_ERR_INVALID_FRAME
 *     The input data are invalid.
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_frame_unpack_headers(nghttp2_headers *frame,
                                 const uint8_t *head, size_t headlen,
                                 const uint8_t *payload, size_t payloadlen,
                                 nghttp2_buffer *inflatebuf);

/*
 * Unpacks HEADERS frame byte sequence into |frame|. This function
 * only unapcks bytes that come before name/value header block.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_FRAME
 *     The input data are invalid.
 */
int nghttp2_frame_unpack_headers_without_nv(nghttp2_headers *frame,
                                            const uint8_t *head,
                                            size_t headlen,
                                            const uint8_t *payload,
                                            size_t payloadlen);

/*
 * Packs PRIORITY frame |frame| in wire format and store it in
 * |*buf_ptr|. The capacity of |*buf_ptr| is |*buflen_ptr|
 * length. This function expands |*buf_ptr| as necessary to store
 * given |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
ssize_t nghttp2_frame_pack_priority(uint8_t **buf_ptr, size_t *buflen_ptr,
                                    nghttp2_priority *frame);

/*
 * Unpacks PRIORITY wire format into |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_FRAME
 *     The input data are invalid.
 */
int nghttp2_frame_unpack_priority(nghttp2_priority *frame,
                                  const uint8_t *head, size_t headlen,
                                  const uint8_t *payload, size_t payloadlen);

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
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
ssize_t nghttp2_frame_pack_rst_stream(uint8_t **buf_ptr, size_t *buflen_ptr,
                                      nghttp2_rst_stream *frame);

/*
 * Unpacks RST_STREAM frame byte sequence into |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_FRAME
 *     The input data are invalid.
 */
int nghttp2_frame_unpack_rst_stream(nghttp2_rst_stream *frame,
                                    const uint8_t *head, size_t headlen,
                                    const uint8_t *payload, size_t payloadlen);

/*
 * Packs SETTINGS frame |frame| in wire format and store it in
 * |*buf_ptr|. The capacity of |*buf_ptr| is |*buflen_ptr|
 * length. This function expands |*buf_ptr| as necessary to store
 * given |frame|.
 *
 * This function returns the size of packed frame if it succeeds, or
 * returns one of the following negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
ssize_t nghttp2_frame_pack_settings(uint8_t **buf_ptr, size_t *buflen_ptr,
                                    nghttp2_settings *frame);

/*
 * Unpacks SETTINGS wire format into |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_FRAME
 *     The input data are invalid.
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_frame_unpack_settings(nghttp2_settings *frame,
                                  const uint8_t *head, size_t headlen,
                                  const uint8_t *payload, size_t payloadlen);

/*
 * Packs PING frame |frame| in wire format and store it in
 * |*buf_ptr|. The capacity of |*buf_ptr| is |*buflen_ptr|
 * length. This function expands |*buf_ptr| as necessary to store
 * given |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
ssize_t nghttp2_frame_pack_ping(uint8_t **buf_ptr, size_t *buflen_ptr,
                                nghttp2_ping *frame);

/*
 * Unpacks PING wire format into |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_FRAME
 *     The input data are invalid.
 */
int nghttp2_frame_unpack_ping(nghttp2_ping *frame,
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
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
ssize_t nghttp2_frame_pack_goaway(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  nghttp2_goaway *frame);

/*
 * Unpacks GOAWAY wire format into |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_FRAME
 *     The input data are invalid.
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_frame_unpack_goaway(nghttp2_goaway *frame,
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
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
ssize_t nghttp2_frame_pack_window_update(uint8_t **buf_ptr, size_t *buflen_ptr,
                                         nghttp2_window_update *frame);

/*
 * Unpacks WINDOW_UPDATE frame byte sequence into |frame|.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_FRAME
 *     The input data are invalid.
 */
int nghttp2_frame_unpack_window_update(nghttp2_window_update *frame,
                                       const uint8_t *head, size_t headlen,
                                       const uint8_t *payload,
                                       size_t payloadlen);

/*
 * Returns number of bytes to pack name/value pairs |nv|. This
 * function expects |nv| is sorted in ascending order of key.
 * |len_size| is the number of bytes in length of name/value pair and
 * it must be 2 or 4.
 *
 * This function can handles duplicate keys and concatenation of thier
 * values with '\0'.
 */
size_t nghttp2_frame_count_nv_space(char **nv, size_t len_size);

/*
 * Packs name/value pairs in |nv| in |buf|. |buf| must have at least
 * nghttp2_frame_count_nv_space(nv) bytes.  |len_size| is the number
 * of bytes in length of name/value pair and it must be 2 or 4.
 */
ssize_t nghttp2_frame_pack_nv(uint8_t *buf, char **nv, size_t len_size);

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
 * NGHTTP2_ERR_ZLIB
 *     The deflate operation failed.
 * NGHTTP2_ERR_FRAME_TOO_LARGE
 *     The length of the frame is too large.
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
ssize_t nghttp2_frame_alloc_pack_nv(uint8_t **buf_ptr,
                                    size_t *buflen_ptr,
                                    uint8_t **nvbuf_ptr,
                                    size_t *nvbuflen_ptr,
                                    char **nv, size_t nv_offset,
                                    size_t len_size,
                                    nghttp2_zlib *deflater);

/*
 * Counts number of name/value pair in |in| and computes length of
 * buffers to store unpacked name/value pair and store them in
 * |*nvlen_ptr| and |*buflen_ptr| respectively. |len_size| is the
 * number of bytes in length of name/value pair and it must be 2 or
 * 4. We use folloing data structure in |*buflen_ptr| size.  First
 * part of the data is array of pointer to name/value pair.  Supporse
 * the buf pointer points to the data region and N is the number of
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
 * With the above stragety, |*buflen_ptr| is calculated as
 * (N*2+1)*sizeof(char*)+sum(strlen(name)+1+strlen(value)+1){for each
 * name/value pair}.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_FRAME
 *     The input data are invalid.
 */
int nghttp2_frame_count_unpack_nv_space(size_t *nvlen_ptr, size_t *buflen_ptr,
                                        nghttp2_buffer *in, size_t len_size);

/*
 * Unpacks name/value header block in wire format |in| and stores them
 * in |*nv_ptr|.  Thif function allocates enough memory to store
 * name/value pairs in |*nv_ptr|.  |len_size| is the number of bytes
 * in length of name/value pair and it must be 2 or 4.
 *
 * This function also validates the name/value pairs. If unpacking
 * succeeds but validation fails, it is indicated by returning
 * NGHTTP2_ERR_INVALID_HEADER_BLOCK.
 *
 * If error other than NGHTTP2_ERR_INVALID_HEADER_BLOCK is returned,
 * the |nv_ptr| is not assigned. In other words,
 * NGHTTP2_ERR_INVALID_HEADER_BLOCK means unpacking succeeded, but
 * header block validation failed.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_HEADER_BLOCK
 *     Unpacking succeeds but the header block is invalid. The
 *     possible reasons are: There are duplicate header names; or the
 *     header names are not encoded in US-ASCII character set and not
 *     lower cased; or the header name is zero-length string.
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_frame_unpack_nv(char ***nv_ptr, nghttp2_buffer *in,
                            size_t len_size);

/*
 * Initializes HEADERS frame |frame| with given values.  |frame|
 * takes ownership of |nv|, so caller must not free it. If |stream_id|
 * is not assigned yet, it must be -1.
 */
void nghttp2_frame_headers_init(nghttp2_headers *frame,
                                uint8_t flags, int32_t stream_id, int32_t pri,
                                char **nv);

void nghttp2_frame_headers_free(nghttp2_headers *frame);


void nghttp2_frame_priority_init(nghttp2_priority *frame, int32_t stream_id,
                                 int32_t pri);

void nghttp2_frame_priority_free(nghttp2_priority *frame);

void nghttp2_frame_rst_stream_init(nghttp2_rst_stream *frame,
                                   int32_t stream_id,
                                   nghttp2_error_code error_code);

void nghttp2_frame_rst_stream_free(nghttp2_rst_stream *frame);

/*
 * Initializes SETTINGS frame |frame| with given values. |frame| takes
 * ownership of |iv|, so caller must not free it. The |flags| are
 * bitwise-OR of one or more of nghttp2_settings_flag.
 */
void nghttp2_frame_settings_init(nghttp2_settings *frame,
                                 nghttp2_settings_entry *iv, size_t niv);

void nghttp2_frame_settings_free(nghttp2_settings *frame);

/*
 * Initializes PING frame |frame| with given values. If the
 * |opqeue_data| is not NULL, it must point to 8 bytes memory region
 * of data. The data pointed by |opaque_data| is copied. It can be
 * NULL. In this case, 8 bytes NULL is used.
 */
void nghttp2_frame_ping_init(nghttp2_ping *frame, uint8_t flags,
                             const uint8_t *opque_data);

void nghttp2_frame_ping_free(nghttp2_ping *frame);

/*
 * Initializes GOAWAY frame |frame| with given values. On success,
 * this function takes ownership of |opaque_data|, so caller must not
 * free it. If the |opaque_data_len| is 0, opaque_data could be NULL.
 */
void nghttp2_frame_goaway_init(nghttp2_goaway *frame, int32_t last_stream_id,
                               nghttp2_error_code error_code,
                               uint8_t *opaque_data, size_t opaque_data_len);

void nghttp2_frame_goaway_free(nghttp2_goaway *frame);

void nghttp2_frame_window_update_init(nghttp2_window_update *frame,
                                      uint8_t flags,
                                      int32_t stream_id,
                                      int32_t window_size_increment);

void nghttp2_frame_window_update_free(nghttp2_window_update *frame);

void nghttp2_frame_data_init(nghttp2_data *frame, uint8_t flags,
                             int32_t stream_id,
                             const nghttp2_data_provider *data_prd);

void nghttp2_frame_data_free(nghttp2_data *frame);

/*
 * Deallocates memory of name/value pair |nv|.
 */
void nghttp2_frame_nv_del(char **nv);

/*
 * Makes a deep copy of |nv| and returns the copy.  This function
 * returns the pointer to the copy if it succeeds, or NULL.  To free
 * allocated memory, use nghttp2_frame_nv_del().
 */
char** nghttp2_frame_nv_copy(const char **nv);

/*
 * Sorts |nv| in the ascending order of name.
 */
void nghttp2_frame_nv_sort(char **nv);

/*
 * Makes names in |nv| lower cased.
 */
void nghttp2_frame_nv_downcase(char **nv);

/*
 * This function first makes a copy of |nv| using
 * nghttp2_frame_nv_copy().  If it succeeds, then call
 * nghttp2_frame_nv_downcase() and nghttp2_frame_nv_sort() with the
 * copied name/value pairs.
 *
 * This function returns the copied name/value pairs if it succeeds,
 * or NULL.
 */
char** nghttp2_frame_nv_norm_copy(const char **nv);

/*
 * Makes copy of |iv| and return the copy. The |niv| is the number of
 * entries in |iv|. This function returns the pointer to the copy if
 * it succeeds, or NULL.
 */
nghttp2_settings_entry* nghttp2_frame_iv_copy(const nghttp2_settings_entry *iv,
                                              size_t niv);

/*
 * Sorts the |iv| with the ascending order of the settings_id member.
 * The number of the element in the array pointed by the |iv| is given
 * by the |niv|.
 */
void nghttp2_frame_iv_sort(nghttp2_settings_entry *iv, size_t niv);

/*
 * Returns the offset of the name/header block in the frame, including
 * frame header. The |head| is frame header. If the indicated frame
 * type does not have header block, this function returns -1.
 */
ssize_t nghttp2_frame_nv_offset(const uint8_t *head);

/*
 * Checks names are not empty string and do not contain control
 * characters and values are not NULL.
 *
 * This function returns nonzero if it succeeds, or 0.
 */
int nghttp2_frame_nv_check_null(const char **nv);

/*
 * Returns nonzero if the name/value pair |a| equals to |b|. The name
 * is compared in case-sensitive, because we ensure that this function
 * is called after the name is lower-cased.
 */
int nghttp2_nv_equal(const nghttp2_nv *a, const nghttp2_nv *b);

void nghttp2_nv_array_free(nghttp2_nv *nva);

#endif /* NGHTTP2_FRAME_H */
