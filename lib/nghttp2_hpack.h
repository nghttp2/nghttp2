/*
 * nghttp2 - HTTP/2 C Library
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
#ifndef NGHTTP2_HPACK_H
#define NGHTTP2_HPACK_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <nghttp2v2/nghttp2.h>

#include "nghttp2_hpack_huffman.h"
#include "nghttp2_buf.h"
#include "nghttp2_mem.h"
#include "nghttp2_rcbuf.h"
#include "nghttp2_ringbuf.h"

#define NGHTTP2_HPACK_ENTRY_OVERHEAD 32

/* The maximum length of one name/value pair.  This is the sum of the
   length of name and value.  This is not specified by the spec. We
   just chose the arbitrary size */
#define NGHTTP2_HPACK_MAX_NV 65536

/* Default size of maximum table buffer size for encoder. Even if
   remote decoder notifies larger buffer size for its decoding,
   encoder only uses the memory up to this value. */
#define NGHTTP2_HPACK_DEFAULT_MAX_DEFLATE_BUFFER_SIZE (1 << 12)

/* Exported for unit test */
#define NGHTTP2_STATIC_TABLE_LENGTH 61

struct nghttp2_hpack_entry;
typedef struct nghttp2_hpack_entry nghttp2_hpack_entry;

struct nghttp2_hpack_entry {
  /* The header field name/value pair */
  nghttp2_hpack_nv nv;
  /* The next entry which shares same bucket in hash table. */
  nghttp2_hpack_entry *next;
  /* The sequence number.  We will increment it by one whenever we
     store nghttp2_hpack_entry to dynamic header table. */
  uint64_t seq;
  /* The hash value for header name (nv.name). */
  uint32_t hash;
};

/* The entry used for static header table. */
typedef struct nghttp2_hpack_static_entry {
  nghttp2_hpack_nv nv;
  uint32_t hash;
} nghttp2_hpack_static_entry;

typedef enum {
  NGHTTP2_HPACK_OPCODE_NONE,
  NGHTTP2_HPACK_OPCODE_INDEXED,
  NGHTTP2_HPACK_OPCODE_NEWNAME,
  NGHTTP2_HPACK_OPCODE_INDNAME
} nghttp2_hpack_opcode;

typedef enum {
  NGHTTP2_HPACK_STATE_EXPECT_TABLE_SIZE,
  NGHTTP2_HPACK_STATE_START,
  NGHTTP2_HPACK_STATE_OPCODE,
  NGHTTP2_HPACK_STATE_READ_TABLE_SIZE,
  NGHTTP2_HPACK_STATE_READ_INDEX,
  NGHTTP2_HPACK_STATE_NEWNAME_CHECK_NAMELEN,
  NGHTTP2_HPACK_STATE_NEWNAME_READ_NAMELEN,
  NGHTTP2_HPACK_STATE_NEWNAME_READ_NAME,
  NGHTTP2_HPACK_STATE_CHECK_VALUELEN,
  NGHTTP2_HPACK_STATE_READ_VALUELEN,
  NGHTTP2_HPACK_STATE_READ_VALUE
} nghttp2_hpack_decoder_state;

typedef enum {
  NGHTTP2_HPACK_WITH_INDEXING,
  NGHTTP2_HPACK_WITHOUT_INDEXING,
  NGHTTP2_HPACK_NEVER_INDEXING
} nghttp2_hpack_indexing_mode;

typedef struct nghttp2_hpack_context {
  /* dynamic header table */
  nghttp2_ringbuf dtable;
  /* Memory allocator */
  const nghttp2_mem *mem;
  /* Abstract buffer size of dtable as described in the spec. This is
     the sum of length of name/value in dtable +
     NGHTTP2_HPACK_ENTRY_OVERHEAD bytes overhead per each entry. */
  size_t dtable_size;
  /* hard_max_dtable_capacity is the upper bound of
     max_dtable_capacity.  For decoder, this is the same value
     transmitted in SETTINGS_HEADER_TABLE_SIZE*/
  size_t hard_max_dtable_capacity;
  /* The effective header table size. */
  size_t max_dtable_capacity;
  /* Next sequence number for nghttp2_hpack_entry */
  uint32_t next_seq;
  /* If encoding/decoding error occurred, this value is set to 1 and
     further invocation of encoding/decoding will fail with
     NGHTTP2_ERR_HPACK_FATAL. */
  uint8_t bad;
} nghttp2_hpack_context;

#define HD_MAP_SIZE 128

typedef struct {
  nghttp2_hpack_entry *table[HD_MAP_SIZE];
} nghttp2_hpack_map;

typedef struct nghttp2_hpack_encoder {
  nghttp2_hpack_context ctx;
  nghttp2_hpack_map map;
  /* Minimum header table size notified in the next context update */
  size_t min_dtable_capacity;
  /* If nonzero, send header table size using encoding context update
     in the next encoding process */
  uint8_t notify_table_size_change;
} nghttp2_hpack_encoder;

typedef struct nghttp2_hpack_read_state {
  /* Stores current state of huffman decoding */
  nghttp2_hpack_huffman_decode_context huffman_ctx;
  /* header buffer */
  nghttp2_rcbuf *name, *value;
  nghttp2_buf namebuf, valuebuf;
  /* The number of bytes to read */
  size_t left;
  size_t prefix;
  /* The number of next shift to decode integer */
  size_t shift;
  /* The index in indexed repr or indexed name */
  size_t index;
  /* nonzero if encoder requires that current entry must not be
     indexed */
  uint8_t never;
  /* nonzero if encoder requires that current entry is indexed */
  uint8_t indexing;
  /* nonzero if string is huffman encoded */
  uint8_t huffman_encoded;
} nghttp2_hpack_read_state;

void nghttp2_hpack_read_state_free(nghttp2_hpack_read_state *rstate);

void nghttp2_hpack_read_state_reset(nghttp2_hpack_read_state *rstate);

typedef struct nghttp2_hpack_decoder {
  nghttp2_hpack_context ctx;
  nghttp2_hpack_read_state rstate;
  /* Minimum header table size set by
     nghttp2_hpack_decoder_change_table_size */
  size_t min_dtable_capacity;
  nghttp2_hpack_opcode opcode;
  nghttp2_hpack_decoder_state state;
} nghttp2_hpack_decoder;

/*
 * nghttp2_hpack_entry_init initializes the |ent| members.  The
 * reference counts of |nv|->name and |nv|->value are increased by one
 * for each.
 */
void nghttp2_hpack_entry_init(nghttp2_hpack_entry *ent,
                              const nghttp2_hpack_nv *nv, uint64_t seq,
                              uint32_t hash);

/*
 * nghttp2_hpack_entry_free decreases the reference counts of
 * |nv|->name and |nv|->value.
 */
void nghttp2_hpack_entry_free(nghttp2_hpack_entry *ent);

/*
 * nghttp2_hpack_encoder_init initializes |encoder| for encoding
 * name/values pairs.
 *
 * The encoder only uses up to |hard_max_dtable_capacity| bytes for
 * header table even if the larger value is specified later in
 * nghttp2_hpack_change_table_size.
 */
void nghttp2_hpack_encoder_init(nghttp2_hpack_encoder *encoder,
                                size_t hard_max_dtable_capacity,
                                const nghttp2_mem *mem);

/*
 * nghttp2_hpack_encoder_free deallocates any resources allocated for
 * |encoder|.
 */
void nghttp2_hpack_encoder_free(nghttp2_hpack_encoder *encoder);

/*
 * nghttp2_hpack_encoder_write endoes the |nva|, which has the |nvlen|
 * name/value pairs, into the |buf|.
 *
 * This function expands |buf| as necessary to store the result. If
 * buffers is full and the process still requires more space, this
 * function fails and returns NGHTTP2_ERR_HPACK_FATAL.
 *
 * After this function returns, it is safe to delete the |nva|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_HPACK_FATAL
 *     Encoding process has failed.
 * NGHTTP2_ERR_BUFFER_ERROR
 *     Out of buffer space.
 */
int nghttp2_hpack_encoder_write(nghttp2_hpack_encoder *encoder,
                                nghttp2_buf *buf, const nghttp2_nv *nva,
                                size_t nvlen);

/*
 * nghttp2_hpack_decoder_init initializes |decoder| for decoding
 * name/values pairs.
 */
void nghttp2_hpack_decoder_init(nghttp2_hpack_decoder *decoder,
                                const nghttp2_mem *mem);

/*
 * nghttp2_hpack_decoder_free deallocates any resources allocated for
 * |decoder|.
 */
void nghttp2_hpack_decoder_free(nghttp2_hpack_decoder *decoder);

/**
 * No flag set.
 */
#define NGHTTP2_HPACK_DECODE_FLAG_NONE 0x0U
/**
 * Indicates all headers were decoded.
 */
#define NGHTTP2_HPACK_DECODE_FLAG_FINAL 0x01U
/**
 * Indicates a header was emitted.
 */
#define NGHTTP2_HPACK_DECODE_FLAG_EMIT 0x02U

nghttp2_ssize nghttp2_hpack_decoder_read(nghttp2_hpack_decoder *decoder,
                                         nghttp2_hpack_nv *dest,
                                         uint8_t *pflags, const uint8_t *src,
                                         size_t srclen, int fin);

/* For unittesting purpose */
int nghttp2_hpack_encoder_write_indname(nghttp2_hpack_encoder *encoder,
                                        nghttp2_buf *buf, size_t index,
                                        const nghttp2_nv *nv,
                                        int indexing_mode);

/* For unittesting purpose */
int nghttp2_hpack_encoder_write_newname(nghttp2_hpack_encoder *encoder,
                                        nghttp2_buf *buf, const nghttp2_nv *nv,
                                        int indexing_mode);

/* For unittesting purpose */
int nghttp2_hpack_encoder_write_table_size(nghttp2_hpack_encoder *encoder,
                                           nghttp2_buf *buf, size_t table_size);

/* For unittesting purpose */
const nghttp2_hpack_nv *
nghttp2_hpack_context_table_get(const nghttp2_hpack_context *ctx, size_t index);

/* For unittesting purpose */
nghttp2_ssize nghttp2_hpack_decode_length(uint32_t *res, size_t *pshift,
                                          int *pfin, uint32_t initial,
                                          size_t shift, uint8_t *first,
                                          uint8_t *last, size_t prefix);

/* From former public API */
/**
 * @function
 *
 * nghttp2_hpack_encoder_set_max_dtable_capacity sets the maximum
 * dynamic table size of the |encoder| to |max_dtable_capacity| bytes.
 * This may trigger eviction in the dynamic table.
 *
 * The |max_dtable_capacity| should be the value received
 * in SETTINGS_HEADER_TABLE_SIZE.
 *
 * The encoder never uses more memory than
 * ``hard_max_dtable_capacity`` bytes specified in
 * `nghttp2_hpack_encoder_init`.  Therefore, if |max_dtable_capacity|
 * > ``hard_max_dtable_capacity``, resulting maximum table size
 * becomes ``hard_max_dtable_capacity``.
 */
void nghttp2_hpack_encoder_set_max_dtable_capacity(
  nghttp2_hpack_encoder *encoder, size_t max_dtable_capacity);

/**
 * @function
 *
 * nghttp2_hpack_bound returns an upper bound on the encoded size for
 * |nva| of length |nvlen|.
 */
size_t nghttp2_hpack_bound(const nghttp2_nv *nva, size_t nvlen);

/**
 * @function
 *
 * nghttp2_hpack_encoder_get_num_table_entries returns the number of
 * entries that header table of |encoder| contains.  This is the sum
 * of the number of static table and dynamic table, so the return
 * value is at least 61.
 */
size_t nghttp2_hpack_encoder_get_num_table_entries(
  const nghttp2_hpack_encoder *encoder);

/**
 * @function
 *
 * nghttp2_hpack_encoder_get_table_entry returns the table entry
 * denoted by |idx| from header table of |encoder|.  The |idx| is
 * 1-based, and idx=1 returns first entry of static table.  idx=62
 * returns first entry of dynamic table if it exists.  Specifying
 * idx=0 is error, and this function returns NULL.  If |idx| is
 * strictly greater than the number of entries the tables contain,
 * this function returns NULL.
 */
const nghttp2_hpack_nv *
nghttp2_hpack_encoder_get_table_entry(const nghttp2_hpack_encoder *encoder,
                                      size_t idx);

/**
 * @function
 *
 * nghttp2_hpack_encoder_get_dtable_size returns the used dynamic
 * table size, including the overhead 32 bytes per entry described in
 * RFC 7541.
 */
size_t
nghttp2_hpack_encoder_get_dtable_size(const nghttp2_hpack_encoder *encoder);

/**
 * @function
 *
 * nghttp2_hpack_encoder_get_max_dtable_capacity returns the maximum
 * dynamic table size.
 */
size_t nghttp2_hpack_encoder_get_max_dtable_capacity(
  const nghttp2_hpack_encoder *encoder);

/**
 * @function
 *
 * nghttp2_hpack_decoder_set_max_dtable_capacity sets the maximum
 * dynamic table size in the |decoder|.  This may trigger eviction in
 * the dynamic table.
 *
 * The |max_dtable_capacity| should be the value transmitted in
 * SETTINGS_HEADER_TABLE_SIZE.
 *
 * This function must not be called while header block is being
 * decoded.  In other words, this function must be called after
 * initialization of |decoder|, but before calling
 * `nghttp2_hpack_decoder_read`, or after `nghttp2_hpack_decoder_read`
 * emits NGHTTP2_HPACK_DECODE_FLAG_FINAL.  Otherwise,
 * `NGHTTP2_ERR_INVALID_STATE` was returned.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`
 *     The function is called while header block is being decoded.
 */
int nghttp2_hpack_decoder_set_max_dtable_capacity(
  nghttp2_hpack_decoder *decoder, size_t max_dtable_capacity);

/**
 * @function
 *
 * nghttp2_hpack_decoder_get_num_table_entries returns the number of
 * entries that header table of |decoder| contains.  This is the sum
 * of the number of static table and dynamic table, so the return
 * value is at least 61.
 */
size_t nghttp2_hpack_decoder_get_num_table_entries(
  const nghttp2_hpack_decoder *decoder);

/**
 * @function
 *
 * nghttp2_hpack_decoder_get_table_entry returns the table entry
 * denoted by |idx| from header table of |decoder|.  The |idx| is
 * 1-based, and idx=1 returns first entry of static table.  idx=62
 * returns first entry of dynamic table if it exists.  Specifying
 * idx=0 is error, and this function returns NULL.  If |idx| is
 * strictly greater than the number of entries the tables contain,
 * this function returns NULL.
 */
const nghttp2_hpack_nv *
nghttp2_hpack_decoder_get_table_entry(const nghttp2_hpack_decoder *decoder,
                                      size_t idx);

/**
 * @function
 *
 * nghttp2_hpack_decoder_get_dtable_size returns the used dynamic
 * table size, including the overhead 32 bytes per entry described in
 * RFC 7541.
 */
size_t
nghttp2_hpack_decoder_get_dtable_size(const nghttp2_hpack_decoder *decoder);

/**
 * @function
 *
 * nghttp2_hpack_decoder_get_max_dtable_capacity returns the maximum
 * dynamic table size.
 */
size_t nghttp2_hpack_decoder_get_max_dtable_capacity(
  const nghttp2_hpack_decoder *decoder);

#endif /* !defined(NGHTTP2_HPACK_H) */
