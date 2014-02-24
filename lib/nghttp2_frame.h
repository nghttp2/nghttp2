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

#define NGHTTP2_FRAME_LENGTH_MASK ((1 << 14) - 1)
#define NGHTTP2_STREAM_ID_MASK ((1u << 31) - 1)
#define NGHTTP2_PRIORITY_MASK ((1u << 31) - 1)
#define NGHTTP2_WINDOW_SIZE_INCREMENT_MASK ((1u << 31) - 1)
#define NGHTTP2_SETTINGS_ID_MASK ((1 << 24) - 1)

/* The maximum payload length of a frame */
#define NGHTTP2_MAX_FRAME_LENGTH ((1 << 14) - 1)

/* The maximum length of DATA frame payload. */
#define NGHTTP2_DATA_PAYLOAD_LENGTH 4096

/* The number of bytes of frame header. */
#define NGHTTP2_FRAME_HEAD_LENGTH 8

/* The number of bytes for each SETTINGS entry */
#define NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH 5

/* Category of frames. */
typedef enum {
  /* non-DATA frame */
  NGHTTP2_CAT_CTRL,
  /* DATA frame */
  NGHTTP2_CAT_DATA
} nghttp2_frame_category;

/**
 * @struct
 *
 * The DATA frame used in the library privately. It has the following
 * members:
 */
typedef struct {
  nghttp2_frame_hd hd;
  /**
   * The data to be sent for this DATA frame.
   */
  nghttp2_data_provider data_prd;
  /**
   * The number of bytes added as padding. This includes PAD_HIGH and
   * PAD_LOW.
   */
  size_t padlen;
  /**
   * The flag to indicate whether EOF was reached or not. Initially
   * |eof| is 0. It becomes 1 after all data were read. This is used
   * exclusively by nghttp2 library and not in the spec.
   */
  uint8_t eof;
} nghttp2_private_data;

int nghttp2_frame_is_data_frame(uint8_t *head);

void nghttp2_frame_pack_frame_hd(uint8_t *buf, const nghttp2_frame_hd *hd);

void nghttp2_frame_unpack_frame_hd(nghttp2_frame_hd *hd, const uint8_t* buf);

/*
 * Returns the offset from the HEADERS frame payload where the
 * compressed header block starts. The frame payload does not include
 * frame header.
 */
size_t nghttp2_frame_headers_payload_nv_offset(nghttp2_headers *frame);

/*
 * Packs HEADERS frame |frame| in wire format and store it in
 * |*buf_ptr|.  The capacity of |*buf_ptr| is |*buflen_ptr| bytes.
 * This function expands |*buf_ptr| as necessary to store frame. When
 * expansion occurred, memory previously pointed by |*buf_ptr| may
 * change.  |*buf_ptr| and |*buflen_ptr| are updated accordingly.
 *
 * The first byte the frame is serialized is returned in the
 * |*bufoff_ptr|. Currently, it is always 2 to account for possible
 * PAD_HIGH and PAD_LOW.
 *
 * frame->hd.length is assigned after length is determined during
 * packing process. If payload length is strictly larger than
 * NGHTTP2_MAX_FRAME_LENGTH, payload data is still serialized as is,
 * but frame->hd.length is set to NGHTTP2_MAX_FRAME_LENGTH and
 * NGHTTP2_FLAG_END_HEADERS flag is cleared from frame->hd.flags.
 *
 * This function returns the size of packed frame (which includes
 * |*bufoff_ptr| bytes) if it succeeds, or returns one of the
 * following negative error codes:
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
                                   size_t *bufoff_ptr,
                                   nghttp2_headers *frame,
                                   nghttp2_hd_deflater *deflater);

/*
 * Unpacks HEADERS frame byte sequence into |frame|. This function
 * only unapcks bytes that come before name/value header block.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_PROTO
 *     TODO END_HEADERS flag is not set
 */
int nghttp2_frame_unpack_headers_payload(nghttp2_headers *frame,
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
 */
void nghttp2_frame_unpack_priority_payload(nghttp2_priority *frame,
                                           const uint8_t *payload,
                                           size_t payloadlen);

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
 */
void nghttp2_frame_unpack_rst_stream_payload(nghttp2_rst_stream *frame,
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

void nghttp2_frame_unpack_settings_entry(nghttp2_settings_entry *iv,
                                         const uint8_t *payload);

/*
 * Makes a copy of |iv| in frame->settings.iv. The |niv| is assigned
 * to frame->settings.niv.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_frame_unpack_settings_payload(nghttp2_settings *frame,
                                          nghttp2_settings_entry *iv,
                                          size_t niv);

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
int nghttp2_frame_unpack_settings_payload2(nghttp2_settings_entry **iv_ptr,
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
 * The first byte the frame is serialized is returned in the
 * |*bufoff_ptr|. Currently, it is always 2 to account for possible
 * PAD_HIGH and PAD_LOW.
 *
 * frame->hd.length is assigned after length is determined during
 * packing process. If payload length is strictly larger than
 * NGHTTP2_MAX_FRAME_LENGTH, payload data is still serialized as is,
 * but frame->hd.length is set to NGHTTP2_MAX_FRAME_LENGTH and
 * NGHTTP2_FLAG_END_HEADERS flag is cleared from frame->hd.flags.
 *
 * This function returns the size of packed frame (which includes
 * |*bufoff_ptr| bytes) if it succeeds, or returns one of the
 * following negative error codes:
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
                                        size_t *bufoff_ptr,
                                        nghttp2_push_promise *frame,
                                        nghttp2_hd_deflater *deflater);

/*
 * Unpacks PUSH_PROMISE frame byte sequence into |frame|. This function
 * only unapcks bytes that come before name/value header block.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_PROTO
 *     TODO END_HEADERS flag is not set
 */
int nghttp2_frame_unpack_push_promise_payload(nghttp2_push_promise *frame,
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
 */
void nghttp2_frame_unpack_ping_payload(nghttp2_ping *frame,
                                       const uint8_t *payload,
                                       size_t payloadlen);

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
 */
void nghttp2_frame_unpack_goaway_payload(nghttp2_goaway *frame,
                                         const uint8_t *payload,
                                         size_t payloadlen);

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
 */
void nghttp2_frame_unpack_window_update_payload(nghttp2_window_update *frame,
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

void nghttp2_frame_data_init(nghttp2_data *frame, nghttp2_private_data *pdata);

/*
 * Returns the number of padding bytes after payload. The total
 * padding length is given in the |padlen|. The returned value does
 * not include the PAD_HIGH and PAD_LOW.
 */
size_t nghttp2_frame_trail_padlen(nghttp2_frame *frame, size_t padlen);

void nghttp2_frame_private_data_init(nghttp2_private_data *frame,
                                     uint8_t flags,
                                     int32_t stream_id,
                                     const nghttp2_data_provider *data_prd);

void nghttp2_frame_private_data_free(nghttp2_private_data *frame);

/*
 * Makes copy of |iv| and return the copy. The |niv| is the number of
 * entries in |iv|. This function returns the pointer to the copy if
 * it succeeds, or NULL.
 */
nghttp2_settings_entry* nghttp2_frame_iv_copy(const nghttp2_settings_entry *iv,
                                              size_t niv);

/*
 * Sorts the |nva| in ascending order of name and value. If names are
 * equivalent, sort them by value.
 */
void nghttp2_nv_array_sort(nghttp2_nv *nva, size_t nvlen);

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
 * Checks that the |iv|, which includes |niv| entries, does not have
 * invalid values.
 *
 * This function returns nonzero if it succeeds, or 0.
 */
int nghttp2_iv_check(const nghttp2_settings_entry *iv, size_t niv);

/*
 * Add padding to the payload in the |*buf_ptr| of length
 * |*buflen_ptr|. The payload length is given in |payloadlen|. The
 * frame header starts at offset |*bufoff_ptr|. Therefore, the payload
 * must start at offset *bufoff_ptr + NGHTTP2_FRAME_HEAD_LENGTH from
 * |*buf_ptr| to account for PAD_HIGH and PAD_LOW. The padding is
 * given in the |padlen|.
 *
 * The |*flags_ptr| is updated to include NGHTTP2_FLAG_PAD_LOW and
 * NGHTTP2_FLAG_PAD_HIGH based on the padding length. The
 * |*bufoff_ptr| will have the offset starting the frame header in
 * |*buf_ptr|.
 *
 * The |*buf_ptr| and |*buflen_ptr| may be extended to include padding
 * bytes.
 *
 * The padding specifier PAD_HIGH and PAD_LOW are located right after
 * the frame header. But they may not be there depending of the length
 * of the padding. To save the additional buffer copy, we allocate
 * buffer size as if these 2 bytes always exist. Depending of the
 * length of the padding, we move the location of frame header and
 * adjust |*bufoff_ptr|. If more than or equal to 256 padding is made,
 * the |*bufoff_ptr| is 0 and the content of the |*buf_ptr| looks like
 * this:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Frame header                                                ...
 * +---------------------------------------------------------------+
 * . Frame header                                                  |
 * +---------------+---------------+-------------------------------+
 * | Pad high      | Pad low       | Payload                     ...
 * +---------------+---------------+-------------------------------+
 *
 *
 * If padding is less than 256 but strictly more than 0, the
 * |*bufoff_ptr| is 1 and the |*buf_ptr| looks like this:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Unused        | Frame header                                ...
 * +---------------+-----------------------------------------------+
 * . Frame header                                                ...
 * +---------------+---------------+-------------------------------+
 * . Frame Header  | Pad low       | Payload                     ...
 * +---------------+---------------+-------------------------------+
 *
 * If no padding is added, the |*bufoff_ptr| is 2 and the |*buf_ptr|
 * looks like this:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Unused                        | Frame header                ...
 * +-------------------------------+-------------------------------+
 * . Frame header                                                ...
 * +-------------------------------+-------------------------------+
 * . Frame Header                  | Payload                     ...
 * +-------------------------------+-------------------------------+
 *
 * Notice that the position of payload does not change. This way, we
 * can set PAD_HIGH and PAD_LOW after payload was serialized and no
 * additional copy operation is required (if the |*buf_ptr| is large
 * enough to account the additional padding, of course).
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_frame_add_pad(uint8_t **buf_ptr, size_t *buflen_ptr,
                          size_t *bufoff_ptr, uint8_t *flags_ptr,
                          size_t payloadlen, size_t padlen);

#endif /* NGHTTP2_FRAME_H */
