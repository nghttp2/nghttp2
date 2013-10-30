/*
 * nghttp2 - HTTP/2.0 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
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
#ifndef NGHTTP2_HD_COMP_H
#define NGHTTP2_HD_COMP_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <nghttp2/nghttp2.h>

#define NGHTTP2_INITIAL_EMIT_SET_SIZE 128
#define NGHTTP2_INITIAL_BUF_TRACK_SIZE 128

#define NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE (1 << 12)
#define NGHTTP2_HD_MAX_ENTRY_SIZE 3072
#define NGHTTP2_HD_ENTRY_OVERHEAD 32

/* Default size of maximum table buffer size for encoder. Even if
   remote decoder notifies larger buffer size for its decoding,
   encoder only uses the memory up to this value. */
#define NGHTTP2_HD_DEFAULT_MAX_DEFLATE_BUFFER_SIZE (1 << 12)

typedef enum {
  NGHTTP2_HD_SIDE_REQUEST = 0,
  NGHTTP2_HD_SIDE_RESPONSE = 1
} nghttp2_hd_side;

typedef enum {
  NGHTTP2_HD_ROLE_DEFLATE,
  NGHTTP2_HD_ROLE_INFLATE
} nghttp2_hd_role;

typedef enum {
  NGHTTP2_HD_FLAG_NONE = 0,
  /* Indicates name was dynamically allocated and must be freed */
  NGHTTP2_HD_FLAG_NAME_ALLOC = 1,
  /* Indicates value was dynamically allocated and must be freed */
  NGHTTP2_HD_FLAG_VALUE_ALLOC = 1 << 1,
  /* Indicates that the entry is in the reference set */
  NGHTTP2_HD_FLAG_REFSET = 1 << 2,
  /* Indicates that the entry is emitted in the current header
     processing. */
  NGHTTP2_HD_FLAG_EMIT = 1 << 3,
  NGHTTP2_HD_FLAG_IMPLICIT_EMIT = 1 << 4,
  /* Indicates that the name was gifted to the entry and no copying
     necessary. */
  NGHTTP2_HD_FLAG_NAME_GIFT = 1 << 5,
  /* Indicates that the value was gifted to the entry and no copying
     necessary. */
  NGHTTP2_HD_FLAG_VALUE_GIFT = 1 << 6
} nghttp2_hd_flags;

typedef struct {
  nghttp2_nv nv;
  /* Reference count */
  uint8_t ref;
  uint8_t flags;
} nghttp2_hd_entry;

typedef struct {
  nghttp2_hd_entry **buffer;
  size_t mask;
  size_t first;
  size_t len;
} nghttp2_hd_ringbuf;

typedef struct {
  /* dynamic header table */
  nghttp2_hd_ringbuf hd_table;
  /* The header table size for decoding. If the context is initialized
     as encoder, this value is advertised by remote endpoint
     decoder. */
  size_t hd_table_bufsize;
  /* If inflate/deflate error occurred, this value is set to 1 and
     further invocation of inflate/deflate will fail with
     NGHTTP2_ERR_HEADER_COMP. */
  size_t hd_table_bufsize_max;
  /* The current effective header table size for encoding. This value
     is always equal to |hd_table_bufsize| on decoder
     context. |deflate_hd_table_bufsize| <= |hd_table_bufsize| must be
     hold. */
  size_t deflate_hd_table_bufsize;
  /* The maximum effective header table for encoding. Although header
     table size is bounded by |hd_table_bufsize_max|, the encoder can
     use smaller buffer by not retaining the header name/values beyond
     the |deflate_hd_table_bufsize_max| and not referencing those
     entries. This value is always equal to |hd_table_bufsize_max| on
     decoder context. */
  size_t deflate_hd_table_bufsize_max;
  /* The number of effective entry in |hd_table|. */
  size_t deflate_hd_tablelen;
  /* Holding emitted entry in deflating header block to retain
     reference count. */
  nghttp2_hd_entry **emit_set;
  /* The capacity of the |emit_set| */
  uint16_t emit_set_capacity;
  /* The number of entry the |emit_set| contains */
  uint16_t emit_setlen;
  /* Abstract buffer size of hd_table as described in the spec. This
     is the sum of length of name/value in hd_table +
     NGHTTP2_HD_ENTRY_OVERHEAD bytes overhead per each entry. */
  uint8_t bad;
  /* Role of this context; deflate or infalte */
  nghttp2_hd_role role;
  /* NGHTTP2_HD_SIDE_REQUEST for processing request, otherwise
     response. */
  nghttp2_hd_side side;
  /* Keep track of allocated buffers in inflation */
  uint8_t **buf_track;
  /* The capacity of |buf_track| */
  uint16_t buf_track_capacity;
  /* The number of entry the |buf_track| contains. */
  size_t buf_tracklen;
} nghttp2_hd_context;

/*
 * Initializes the |ent| members. If NGHTTP2_HD_FLAG_NAME_ALLOC bit
 * set in the |flags|, the content pointed by the |name| with length
 * |namelen| is copied. Likewise, if NGHTTP2_HD_FLAG_VALUE_ALLOC bit
 * set in the |flags|, the content pointed by the |value| with length
 * |valuelen| is copied.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_hd_entry_init(nghttp2_hd_entry *ent, uint8_t flags,
                          uint8_t *name, uint16_t namelen,
                          uint8_t *value, uint16_t valuelen);

void nghttp2_hd_entry_free(nghttp2_hd_entry *ent);

/*
 * Initializes |deflater| for deflating name/values pairs.
 *
 * The encoder only uses up to
 * NGHTTP2_HD_DEFAULT_MAX_DEFLATE_BUFFER_SIZE bytes for header table
 * even if the larger value is specified later in
 * nghttp2_hd_change_table_size().
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_hd_deflate_init(nghttp2_hd_context *deflater,
                            nghttp2_hd_side side);

/*
 * Initializes |deflater| for deflating name/values pairs.
 *
 * The encoder only uses up to |deflate_hd_table_bufsize_max| bytes
 * for header table even if the larger value is specified later in
 * nghttp2_hd_change_table_size().
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_hd_deflate_init2(nghttp2_hd_context *deflater,
                             nghttp2_hd_side side,
                             size_t deflate_hd_table_bufsize_max);

/*
 * Initializes |inflater| for inflating name/values pairs.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_hd_inflate_init(nghttp2_hd_context *inflater,
                            nghttp2_hd_side side);

/*
 * Deallocates any resources allocated for |deflater|.
 */
void nghttp2_hd_deflate_free(nghttp2_hd_context *deflater);

/*
 * Deallocates any resources allocated for |inflater|.
 */
void nghttp2_hd_inflate_free(nghttp2_hd_context *inflater);


/*
 * Changes header table size in |context|. This may trigger eviction
 * in the dynamic table.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_hd_change_table_size(nghttp2_hd_context *context,
                                 size_t hd_table_bufsize_max);

/*
 * Deflates the |nva|, which has the |nvlen| name/value pairs, into
 * the buffer pointed by the |*buf_ptr| with the length |*buflen_ptr|.
 * The output starts after |nv_offset| bytes from |*buf_ptr|.
 *
 * This function expands |*buf_ptr| as necessary to store the
 * result. When expansion occurred, memory previously pointed by
 * |*buf_ptr| may change.  |*buf_ptr| and |*buflen_ptr| are updated
 * accordingly.
 *
 * This function copies necessary data into |*buf_ptr|. After this
 * function returns, it is safe to delete the |nva|.
 *
 * TODO: The rest of the code call nghttp2_hd_end_headers() after this
 * call, but it is just a regacy of the first implementation. Now it
 * is not required to be called as of now.
 *
 * This function returns the number of bytes outputted if it succeeds,
 * or one of the following negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_HEADER_COMP
 *     Deflation process has failed.
 */
ssize_t nghttp2_hd_deflate_hd(nghttp2_hd_context *deflater,
                              uint8_t **buf_ptr, size_t *buflen_ptr,
                              size_t nv_offset,
                              nghttp2_nv *nva, size_t nvlen);

/*
 * Inflates name/value block stored in |in| with length |inlen|. This
 * function performs decompression. The |*nva_ptr| points to the final
 * result on successful decompression. The caller must free |*nva_ptr|
 * using nghttp2_nv_array_del().
 *
 * The |*nva_ptr| includes pointers to the memory region in the
 * |in|. The caller must retain the |in| while the |*nva_ptr| is
 * used. After the use of |*nva_ptr| is over, if the caller intends to
 * inflate another set of headers, the caller must call
 * nghttp2_hd_end_headers().
 *
 * This function returns the number of name/value pairs in |*nva_ptr|
 * if it succeeds, or one of the following negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_HEADER_COMP
 *     Inflation process has failed.
 */
ssize_t nghttp2_hd_inflate_hd(nghttp2_hd_context *inflater,
                              nghttp2_nv **nva_ptr,
                              uint8_t *in, size_t inlen);

/*
 * Signals the end of processing one header block.
 *
 * This function returns 0 if it succeeds. Currently this function
 * always succeeds.
 */
int nghttp2_hd_end_headers(nghttp2_hd_context *deflater_or_inflater);

/* For unittesting purpose */
int nghttp2_hd_emit_indname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  size_t *offset_ptr, size_t index,
                                  const uint8_t *value, size_t valuelen,
                                  int inc_indexing,
                                  nghttp2_hd_side side);

/* For unittesting purpose */
int nghttp2_hd_emit_newname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  size_t *offset_ptr, nghttp2_nv *nv,
                                  int inc_indexing,
                                  nghttp2_hd_side side);

/* For unittesting purpose */
int nghttp2_hd_emit_subst_indname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                        size_t *offset_ptr, size_t index,
                                        const uint8_t *value, size_t valuelen,
                                        size_t subindex);

/* For unittesting purpose */
int nghttp2_hd_emit_subst_newname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                        size_t *offset_ptr, nghttp2_nv *nv,
                                        size_t subindex);

/* For unittesting purpose */
nghttp2_hd_entry* nghttp2_hd_table_get(nghttp2_hd_context *context,
                                       size_t index);

/* Huffman encoding/decoding functions */

/*
 * Counts the required bytes to encode |src| with length |len|. If
 * |side| is NGHTTP2_HD_SIDE_REQUEST, the request huffman code table
 * is used. Otherwise, the response code table is used.
 *
 * This function returns the number of required bytes to encode given
 * data, including padding of prefix of terminal symbol code. This
 * function always succeeds.
 */
size_t nghttp2_hd_huff_encode_count(const uint8_t *src, size_t len,
                                    nghttp2_hd_side side);

/*
 * Encodes the given data |src| with length |srclen| to the given
 * memory location pointed by |dest|, allocated at lest |destlen|
 * bytes. The caller is responsible to specify |destlen| at least the
 * length that nghttp2_hd_huff_encode_count() returns.  If |side| is
 * NGHTTP2_HD_SIDE_REQUEST, the request huffman code table is
 * used. Otherwise, the response code table is used.
 *
 * This function returns the number of written bytes, including
 * padding of prefix of terminal symbol code. This return value is
 * exactly the same with the return value of
 * nghttp2_hd_huff_encode_count() if it is given with the same |src|,
 * |srclen|, and |side|. This function always succeeds.
 */
ssize_t nghttp2_hd_huff_encode(uint8_t *dest, size_t destlen,
                               const uint8_t *src, size_t srclen,
                               nghttp2_hd_side side);

/*
 * Counts the number of required bytes to decode |src| with length
 * |srclen|. The given input must be padded with the prefix of
 * terminal code. If |side| is NGHTTP2_HD_SIDE_REQUEST, the request
 * huffman code table is used. Otherwise, the response code table is
 * used.
 *
 * This function returns the number of required bytes to decode given
 * data if it succeeds, or -1.
 */
ssize_t nghttp2_hd_huff_decode_count(const uint8_t *src, size_t srclen,
                                     nghttp2_hd_side side);

/*
 * Decodes the given data |src| with length |srclen| to the given
 * memory location pointed by |dest|, allocated at lest |destlen|
 * bytes. The given input must be padded with the prefix of terminal
 * code. The caller is responsible to specify |destlen| at least the
 * length that nghttp2_hd_huff_decode_count() returns.  If |side| is
 * NGHTTP2_HD_SIDE_REQUEST, the request huffman code table is
 * used. Otherwise, the response code table is used.
 *
 * This function returns the number of written bytes.  This return
 * value is exactly the same with the return value of
 * nghttp2_hd_huff_decode_count() if it is given with the same |src|,
 * |srclen|, and |side|.
 *
 * This function returns -1 if it fails.
 */
ssize_t nghttp2_hd_huff_decode(uint8_t *dest, size_t destlen,
                               const uint8_t *src, size_t srclen,
                               nghttp2_hd_side side);

#endif /* NGHTTP2_HD_COMP_H */
