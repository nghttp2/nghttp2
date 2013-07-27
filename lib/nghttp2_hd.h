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

#define NGHTTP2_INITIAL_HD_TABLE_SIZE 128
#define NGHTTP2_INITIAL_REFSET_SIZE 128
#define NGHTTP2_INITIAL_WS_SIZE 128

#define NGHTTP2_HD_MAX_BUFFER_SIZE 4096
#define NGHTTP2_HD_MAX_ENTRY_SIZE 1024
#define NGHTTP2_HD_ENTRY_OVERHEAD 32

/* This value is sensible to NGHTTP2_HD_MAX_BUFFER_SIZE. Currently,
   the index is at most 128, so 255 is good choice */
#define NGHTTP2_HD_INVALID_INDEX 255

typedef enum {
  NGHTTP2_HD_SIDE_CLIENT = 0,
  NGHTTP2_HD_SIDE_SERVER = 1
} nghttp2_hd_side;

typedef enum {
  NGHTTP2_HD_FLAG_NONE = 0,
  /* Indicates name was dynamically allocated and must be freed */
  NGHTTP2_HD_FLAG_NAME_ALLOC = 1,
  /* Indicates value was dynamically allocated and must be freed */
  NGHTTP2_HD_FLAG_VALUE_ALLOC = 1 << 1,
} nghttp2_hd_flags;

typedef struct {
  nghttp2_nv nv;
  /* Reference count */
  uint8_t ref;
  /* Index in the header table */
  uint8_t index;
  uint8_t flags;
} nghttp2_hd_entry;

typedef enum {
  NGHTTP2_HD_CAT_NONE,
  NGHTTP2_HD_CAT_INDEXED,
  NGHTTP2_HD_CAT_INDNAME,
  NGHTTP2_HD_CAT_NEWNAME
} nghttp2_hd_entry_cat;

typedef struct nghttp2_hd_ws_entry {
  nghttp2_hd_entry_cat cat;
  union {
    /* For NGHTTP2_HD_CAT_INDEXED */
    struct {
      nghttp2_hd_entry *entry;
      uint8_t index;
    } indexed;
    /* For NGHTTP2_HD_CAT_NEWNAME */
    struct {
      nghttp2_nv nv;
    } newname;
    /* For NGHTTP2_HD_CAT_LITERAL_INDNAME */
    struct {
      /* The entry in header table the name stored */
      nghttp2_hd_entry *entry;
      uint8_t *value;
      uint16_t valuelen;
    } indname;
  };
} nghttp2_hd_ws_entry;

typedef struct {
  /* Header table */
  nghttp2_hd_entry **hd_table;
  /* Reference set */
  nghttp2_hd_entry **refset;
  /* Working set */
  nghttp2_hd_ws_entry *ws;
  /* The capacity of the |hd_table| */
  uint16_t hd_table_capacity;
  /* the number of entry the |hd_table| contains */
  uint16_t hd_tablelen;
  /* The capacity of the |refset| */
  uint16_t refset_capacity;
  /* The number of entry the |refset| contains */
  uint16_t refsetlen;
  /* The capacity of the |ws| */
  uint16_t ws_capacity;
  /* The number of entry the |ws| contains */
  uint16_t wslen;
  /* Abstract buffer size of hd_table as described in the spec. This
     is the sum of length of name/value in hd_table +
     NGHTTP2_HD_ENTRY_OVERHEAD bytes overhead per each entry. */
  uint16_t hd_table_bufsize;
  /* If inflate/deflate error occurred, this value is set to 1 and
     further invocation of inflate/deflate will fail with
     NGHTTP2_ERR_HEADER_COMP. */
  uint8_t bad;
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
int nghttp2_hd_entry_init(nghttp2_hd_entry *ent, uint8_t index, uint8_t flags,
                          uint8_t *name, uint16_t namelen,
                          uint8_t *value, uint16_t valuelen);

void nghttp2_hd_entry_free(nghttp2_hd_entry *ent);

/*
 * Initializes |deflater| for deflating name/values pairs.
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
 * Deflates the |nva|, which has the |nvlen| name/value pairs, into
 * the buffer pointed by the |*buf_ptr| with the length |*buflen_ptr|.
 * The output starts after |nv_offset| bytes from |*buf_ptr|.
 *
 * This function expands |*buf_ptr| as necessary to store the
 * result. When expansion occurred, memory previously pointed by
 * |*buf_ptr| is freed.  |*buf_ptr| and |*buflen_ptr| are updated
 * accordingly.
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
 * result on succesful decompression. The caller must free |*nva_ptr|
 * using nghttp2_nv_array_del().
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
 * Signals the end of processing one header block. This function
 * creates new reference set from working set.
 *
 * This function returns 0 if it succeeds. Currently this function
 * always succeeds.
 */
int nghttp2_hd_end_headers(nghttp2_hd_context *deflater_or_inflater);

/* For unittesting purpose */
int nghttp2_hd_emit_indname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  size_t *offset_ptr, size_t index,
                                  const uint8_t *value, size_t valuelen,
                                  int inc_indexing);

/* For unittesting purpose */
int nghttp2_hd_emit_newname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  size_t *offset_ptr, nghttp2_nv *nv,
                                  int inc_indexing);

/* For unittesting purpose */
int nghttp2_hd_emit_subst_indname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                        size_t *offset_ptr, size_t index,
                                        const uint8_t *value, size_t valuelen,
                                        size_t subindex);

/* For unittesting purpose */
int nghttp2_hd_emit_subst_newname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                        size_t *offset_ptr, nghttp2_nv *nv,
                                        size_t subindex);

#endif /* NGHTTP2_HD_COMP_H */
