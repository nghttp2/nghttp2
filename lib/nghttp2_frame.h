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
#include "nghttp2_hd.h"
#include "nghttp2_buffer.h"

/* The maximum payload length of a frame */
#define NGHTTP2_MAX_FRAME_LENGTH ((1 << 16) - 1)
/* The maximum paylaod length of a frame used in HTTP */
#define NGHTTP2_MAX_HTTP_FRAME_LENGTH ((1 << 14) - 1)

/* The maximum header block length. This is not specified by the
   spec. We just chose the arbitrary size */
#define NGHTTP2_MAX_HD_BLOCK_LENGTH ((1 << 16) - 1)
/* The maximum value length of name/value pair. This is not specified
   by the spec. We just chose the arbitrary size */
#define NGHTTP2_MAX_HD_VALUE_LENGTH ((1 << 13) - 1)

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
 * This function expands |*buf_ptr| as necessary to store frame. When
 * expansion occurred, memory previously pointed by |*buf_ptr| may
 * change.  |*buf_ptr| and |*buflen_ptr| are updated accordingly.
 *
 * frame->hd.length is assigned after length is determined during
 * packing process.
 *
 * This function returns the size of packed frame if it succeeds, or
 * returns one of the following negative error codes:
 *
 * NGHTTP2_ERR_HEADER_COMP
 *     The deflate operation failed.
 * NGHTTP2_ERR_FRAME_TOO_LARGE
 *     The length of the frame is too large.
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
ssize_t nghttp2_frame_pack_headers(uint8_t **buf_ptr,
                                   size_t *buflen_ptr,
                                   nghttp2_headers *frame,
                                   nghttp2_hd_context *deflater);

/*
 * Unpacks HEADERS frame byte sequence into |frame|.  The control
 * frame header is given in |head| with |headlen| length. In the spec,
 * headlen is 8 bytes. |payload| is the data after frame header and
 * just before name/value header block.
 *
 * The |inflater| inflates name/value header block.
 *
 * This function also validates the name/value pairs. If unpacking
 * succeeds but validation fails, it is indicated by returning
 * NGHTTP2_ERR_INVALID_HEADER_BLOCK.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_HEADER_COMP
 *     The inflate operation failed.
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
                                 nghttp2_hd_context *inflater);

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
 * Packs the |iv|, which includes |niv| entries, in the |buf|,
 * assuming the |buf| has at least 8 * |niv| bytes.
 *
 * Returns the number of bytes written into the |buf|.
 */
size_t nghttp2_frame_pack_settings_payload(uint8_t *buf,
                                           const nghttp2_settings_entry *iv,
                                           size_t niv);

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
 * Unpacks SETTINGS payload into |*iv_ptr|. The number of entries are
 * assigned to the |*niv_ptr|. This function allocates enough memory
 * to store the result in |*iv_ptr|. The caller is responsible to free
 * |*iv_ptr| after its use.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_frame_unpack_settings_payload(nghttp2_settings_entry **iv_ptr,
                                          size_t *niv_ptr,
                                          const uint8_t *payload,
                                          size_t payloadlen);

/*
 * Packs PUSH_PROMISE frame |frame| in wire format and store it in
 * |*buf_ptr|.  The capacity of |*buf_ptr| is |*buflen_ptr| bytes.
 * This function expands |*buf_ptr| as necessary to store frame. When
 * expansion occurred, memory previously pointed by |*buf_ptr| may
 * change.  |*buf_ptr| and |*buflen_ptr| are updated accordingly.
 *
 * frame->hd.length is assigned after length is determined during
 * packing process.
 *
 * This function returns the size of packed frame if it succeeds, or
 * returns one of the following negative error codes:
 *
 * NGHTTP2_ERR_HEADER_COMP
 *     The deflate operation failed.
 * NGHTTP2_ERR_FRAME_TOO_LARGE
 *     The length of the frame is too large.
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
ssize_t nghttp2_frame_pack_push_promise(uint8_t **buf_ptr,
                                        size_t *buflen_ptr,
                                        nghttp2_push_promise *frame,
                                        nghttp2_hd_context *deflater);

/*
 * Unpacks PUSH_PROMISE frame byte sequence into |frame|.  The control
 * frame header is given in |head| with |headlen| length. In the spec,
 * headlen is 8 bytes. |payload| is the data after frame header and
 * just before name/value header block.
 *
 * The |inflater| inflates name/value header block.
 *
 * This function also validates the name/value pairs. If unpacking
 * succeeds but validation fails, it is indicated by returning
 * NGHTTP2_ERR_INVALID_HEADER_BLOCK.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_HEADER_COMP
 *     The inflate operation failed.
 * NGHTTP2_ERR_INVALID_HEADER_BLOCK
 *     Unpacking succeeds but the header block is invalid.
 * NGHTTP2_ERR_INVALID_FRAME
 *     The input data are invalid.
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_frame_unpack_push_promise(nghttp2_push_promise *frame,
                                      const uint8_t *head, size_t headlen,
                                      const uint8_t *payload,
                                      size_t payloadlen,
                                      nghttp2_hd_context *inflater);

/*
 * Unpacks PUSH_PROMISE frame byte sequence into |frame|. This function
 * only unapcks bytes that come before name/value header block.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_FRAME
 *     The input data are invalid.
 */
int nghttp2_frame_unpack_push_promise_without_nv(nghttp2_push_promise *frame,
                                                 const uint8_t *head,
                                                 size_t headlen,
                                                 const uint8_t *payload,
                                                 size_t payloadlen);

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
 * given |frame|.
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
 * Initializes HEADERS frame |frame| with given values.  |frame| takes
 * ownership of |nva|, so caller must not free it. If |stream_id| is
 * not assigned yet, it must be -1.
 */
void nghttp2_frame_headers_init(nghttp2_headers *frame,
                                uint8_t flags, int32_t stream_id, int32_t pri,
                                nghttp2_nv *nva, size_t nvlen);

void nghttp2_frame_headers_free(nghttp2_headers *frame);


void nghttp2_frame_priority_init(nghttp2_priority *frame, int32_t stream_id,
                                 int32_t pri);

void nghttp2_frame_priority_free(nghttp2_priority *frame);

void nghttp2_frame_rst_stream_init(nghttp2_rst_stream *frame,
                                   int32_t stream_id,
                                   nghttp2_error_code error_code);

void nghttp2_frame_rst_stream_free(nghttp2_rst_stream *frame);

/*
 * Initializes PUSH_PROMISE frame |frame| with given values.  |frame|
 * takes ownership of |nva|, so caller must not free it.
 */
void nghttp2_frame_push_promise_init(nghttp2_push_promise *frame,
                                     uint8_t flags, int32_t stream_id,
                                     int32_t promised_stream_id,
                                     nghttp2_nv *nva, size_t nvlen);

void nghttp2_frame_push_promise_free(nghttp2_push_promise *frame);

/*
 * Initializes SETTINGS frame |frame| with given values. |frame| takes
 * ownership of |iv|, so caller must not free it. The |flags| are
 * bitwise-OR of one or more of nghttp2_settings_flag.
 */
void nghttp2_frame_settings_init(nghttp2_settings *frame, uint8_t flags,
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
 * Makes copy of |iv| and return the copy. The |niv| is the number of
 * entries in |iv|. This function returns the pointer to the copy if
 * it succeeds, or NULL.
 */
nghttp2_settings_entry* nghttp2_frame_iv_copy(const nghttp2_settings_entry *iv,
                                              size_t niv);

/*
 * Checks names are not empty string and do not contain control
 * characters and values are not NULL.
 *
 * This function returns nonzero if it succeeds, or 0.
 */
int nghttp2_frame_nv_check_null(const char **nv);

/*
 * Sorts the |nva| in ascending order of name. The relative order of
 * the same name pair is undefined.
 */
void nghttp2_nv_array_sort(nghttp2_nv *nva, size_t nvlen);

/*
 * Copies name/value pairs from |nv| to |*nva_ptr|, which is
 * dynamically allocated so that all items can be stored.
 *
 * The |*nva_ptr| must be freed using nghttp2_nv_array_del().
 *
 * This function returns the number of name/value pairs in |*nva_ptr|,
 * or one of the following negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_INVALID_ARGUMENT
 *     The length of name or value in |nv| is strictly larger than
 *     NGHTTP2_MAX_HD_VALUE_LENGTH.
 */
ssize_t nghttp2_nv_array_from_cstr(nghttp2_nv **nva_ptr, const char **nv);

/*
 * Copies name/value pairs from |nva|, which contains |nvlen| pairs,
 * to |*nva_ptr|, which is dynamically allocated so that all items can
 * be stored.
 *
 * The |*nva_ptr| must be freed using nghttp2_nv_array_del().
 *
 * This function returns the number of name/value pairs in |*nva_ptr|,
 * or one of the following negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_INVALID_ARGUMENT
 *     The length of name or value in |nva| is strictly larger than
 *     NGHTTP2_MAX_HD_VALUE_LENGTH.
 */
ssize_t nghttp2_nv_array_copy(nghttp2_nv **nva_ptr,
                              const nghttp2_nv *nva, size_t nvlen);

/*
 * Returns nonzero if the name/value pair |a| equals to |b|. The name
 * is compared in case-sensitive, because we ensure that this function
 * is called after the name is lower-cased.
 */
int nghttp2_nv_equal(const nghttp2_nv *a, const nghttp2_nv *b);

/*
 * Frees |nva|.
 */
void nghttp2_nv_array_del(nghttp2_nv *nva);

/*
 * Checks names are not empty string and do not contain control
 * characters. This function allows captital alphabet letters in name.
 *
 * This function returns nonzero if it succeeds, or 0.
 */
int nghttp2_nv_array_check_null(const nghttp2_nv *nva, size_t nvlen);


/*
 * Checks that the |iv|, which includes |niv| entries, does not have
 * invalid values. The |flow_control_opt| is current flow control
 * option value.
 *
 * This function returns nonzero if it succeeds, or 0.
 */
int nghttp2_iv_check(const nghttp2_settings_entry *iv, size_t niv,
                     int32_t flow_control_opt);

#endif /* NGHTTP2_FRAME_H */
