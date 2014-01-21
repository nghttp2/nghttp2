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
#include "nghttp2_hd.h"

#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "nghttp2_frame.h"
#include "nghttp2_helper.h"
#include "nghttp2_int.h"

/* Make scalar initialization form of nghttp2_nv */
#define MAKE_STATIC_ENT(I, N, V, NH, VH)                                \
  { { { (uint8_t*)N, (uint8_t*)V, sizeof(N) - 1, sizeof(V) - 1 },       \
        NH, VH, 1, NGHTTP2_HD_FLAG_NONE }, I }

/* Sorted by hash(name) and its table index */
static nghttp2_hd_static_entry static_table[] = {
  MAKE_STATIC_ENT(19, "age", "", 96511u, 0u),
  MAKE_STATIC_ENT(58, "via", "", 116750u, 0u),
  MAKE_STATIC_ENT(31, "date", "", 3076014u, 0u),
  MAKE_STATIC_ENT(32, "etag", "", 3123477u, 0u),
  MAKE_STATIC_ENT(35, "from", "", 3151786u, 0u),
  MAKE_STATIC_ENT(36, "host", "", 3208616u, 0u),
  MAKE_STATIC_ENT(43, "link", "", 3321850u, 0u),
  MAKE_STATIC_ENT(57, "vary", "", 3612210u, 0u),
  MAKE_STATIC_ENT(37, "if-match", "", 34533653u, 0u),
  MAKE_STATIC_ENT(40, "if-range", "", 39145613u, 0u),
  MAKE_STATIC_ENT(3, ":path", "/", 56997727u, 47u),
  MAKE_STATIC_ENT(4, ":path", "/index.html", 56997727u, 2144181430u),
  MAKE_STATIC_ENT(20, "allow", "", 92906313u, 0u),
  MAKE_STATIC_ENT(48, "range", "", 108280125u, 0u),
  MAKE_STATIC_ENT(13, "accept-charset", "", 124285319u, 0u),
  MAKE_STATIC_ENT(42, "last-modified", "", 150043680u, 0u),
  MAKE_STATIC_ENT(47, "proxy-authorization", "", 329532250u, 0u),
  MAKE_STATIC_ENT(56, "user-agent", "", 486342275u, 0u),
  MAKE_STATIC_ENT(39, "if-none-match", "", 646073760u, 0u),
  MAKE_STATIC_ENT(29, "content-type", "", 785670158u, 0u),
  MAKE_STATIC_ENT(15, "accept-language", "", 802785917u, 0u),
  MAKE_STATIC_ENT(49, "referer", "", 1085069613u, 0u),
  MAKE_STATIC_ENT(50, "refresh", "", 1085444827u, 0u),
  MAKE_STATIC_ENT(54, "strict-transport-security", "", 1153852136u, 0u),
  MAKE_STATIC_ENT(53, "set-cookie", "", 1237214767u, 0u),
  MAKE_STATIC_ENT(55, "transfer-encoding", "", 1274458357u, 0u),
  MAKE_STATIC_ENT(16, "accept-ranges", "", 1397189435u, 0u),
  MAKE_STATIC_ENT(41, "if-unmodified-since", "", 1454068927u, 0u),
  MAKE_STATIC_ENT(45, "max-forwards", "", 1619948695u, 0u),
  MAKE_STATIC_ENT(44, "location", "", 1901043637u, 0u),
  MAKE_STATIC_ENT(51, "retry-after", "", 1933352567u, 0u),
  MAKE_STATIC_ENT(24, "content-encoding", "", 2095084583u, 0u),
  MAKE_STATIC_ENT(27, "content-location", "", 2284906121u, 0u),
  MAKE_STATIC_ENT(38, "if-modified-since", "", 2302095846u, 0u),
  MAKE_STATIC_ENT(17, "accept", "", 2871506184u, 0u),
  MAKE_STATIC_ENT(28, "content-range", "", 2878374633u, 0u),
  MAKE_STATIC_ENT(21, "authorization", "", 2909397113u, 0u),
  MAKE_STATIC_ENT(30, "cookie", "", 2940209764u, 0u),
  MAKE_STATIC_ENT(0, ":authority", "", 2962729033u, 0u),
  MAKE_STATIC_ENT(34, "expires", "", 2985731892u, 0u),
  MAKE_STATIC_ENT(33, "expect", "", 3005803609u, 0u),
  MAKE_STATIC_ENT(23, "content-disposition", "", 3027699811u, 0u),
  MAKE_STATIC_ENT(25, "content-language", "", 3065240108u, 0u),
  MAKE_STATIC_ENT(1, ":method", "GET", 3153018267u, 70454u),
  MAKE_STATIC_ENT(2, ":method", "POST", 3153018267u, 2461856u),
  MAKE_STATIC_ENT(26, "content-length", "", 3162187450u, 0u),
  MAKE_STATIC_ENT(18, "access-control-allow-origin", "", 3297999203u, 0u),
  MAKE_STATIC_ENT(5, ":scheme", "http", 3322585695u, 3213448u),
  MAKE_STATIC_ENT(6, ":scheme", "https", 3322585695u, 99617003u),
  MAKE_STATIC_ENT(7, ":status", "200", 3338091692u, 49586u),
  MAKE_STATIC_ENT(8, ":status", "500", 3338091692u, 52469u),
  MAKE_STATIC_ENT(9, ":status", "404", 3338091692u, 51512u),
  MAKE_STATIC_ENT(10, ":status", "403", 3338091692u, 51511u),
  MAKE_STATIC_ENT(11, ":status", "400", 3338091692u, 51508u),
  MAKE_STATIC_ENT(12, ":status", "401", 3338091692u, 51509u),
  MAKE_STATIC_ENT(52, "server", "", 3389140803u, 0u),
  MAKE_STATIC_ENT(46, "proxy-authenticate", "", 3993199572u, 0u),
  MAKE_STATIC_ENT(59, "www-authenticate", "", 4051929931u, 0u),
  MAKE_STATIC_ENT(22, "cache-control", "", 4086191634u, 0u),
  MAKE_STATIC_ENT(14, "accept-encoding", "", 4127597688u, 0u)
};

/* Index to the position in static_table */
const size_t static_table_index[] = {
  38, 43, 44, 10, 11, 47, 48, 49, 50, 51, 52, 53, 54, 14, 59, 20,
  26, 34, 46, 0 , 12, 36, 58, 41, 31, 42, 45, 32, 35, 19, 37, 2 ,
  3 , 40, 39, 4 , 5 , 8 , 33, 18, 9 , 27, 15, 6 , 29, 28, 56, 16,
  13, 21, 22, 30, 55, 24, 23, 25, 17, 7 , 1 , 57
};

static const size_t STATIC_TABLE_LENGTH =
  sizeof(static_table)/sizeof(static_table[0]);

static int memeq(const void *s1, const void *s2, size_t n)
{
  const uint8_t *a = (const uint8_t*)s1, *b = (const uint8_t*)s2;
  uint8_t c = 0;
  while(n > 0) {
    c |= (*a++) ^ (*b++);
    --n;
  }
  return c == 0;
}

static uint32_t hash(const uint8_t *s, size_t n)
{
  uint32_t h = 0;
  while(n > 0) {
    h = h * 31 + *s++;
    --n;
  }
  return h;
}

typedef struct {
  nghttp2_nv *nva;
  size_t nvacap;
  size_t nvlen;
} nghttp2_nva_out;

int nghttp2_hd_entry_init(nghttp2_hd_entry *ent, uint8_t flags,
                          uint8_t *name, uint16_t namelen,
                          uint8_t *value, uint16_t valuelen)
{
  int rv = 0;
  if((flags & NGHTTP2_HD_FLAG_NAME_ALLOC) &&
     (flags & NGHTTP2_HD_FLAG_NAME_GIFT) == 0) {
    if(namelen == 0) {
      /* We should not allow empty header field name */
      ent->nv.name = NULL;
    } else {
      ent->nv.name = nghttp2_memdup(name, namelen);
      if(ent->nv.name == NULL) {
        rv = NGHTTP2_ERR_NOMEM;
        goto fail;
      }
    }
  } else {
    ent->nv.name = name;
  }
  if((flags & NGHTTP2_HD_FLAG_VALUE_ALLOC) &&
     (flags & NGHTTP2_HD_FLAG_VALUE_GIFT) == 0) {
    if(valuelen == 0) {
      ent->nv.value = NULL;
    } else {
      ent->nv.value = nghttp2_memdup(value, valuelen);
      if(ent->nv.value == NULL) {
        rv = NGHTTP2_ERR_NOMEM;
        goto fail2;
      }
    }
  } else {
    ent->nv.value = value;
  }
  ent->nv.namelen = namelen;
  ent->nv.valuelen = valuelen;
  ent->ref = 1;
  ent->flags = flags;
  if(ent->nv.name) {
    ent->name_hash = hash(ent->nv.name, ent->nv.namelen);
  } else {
    ent->name_hash = 0;
  }
  if(ent->nv.value) {
    ent->value_hash = hash(ent->nv.value, ent->nv.valuelen);
  } else {
    ent->value_hash = 0;
  }
  return 0;

 fail2:
  if(flags & NGHTTP2_HD_FLAG_NAME_ALLOC) {
    free(ent->nv.name);
  }
 fail:
  return rv;
}

void nghttp2_hd_entry_free(nghttp2_hd_entry *ent)
{
  assert(ent->ref == 0);
  if(ent->flags & NGHTTP2_HD_FLAG_NAME_ALLOC) {
    free(ent->nv.name);
  }
  if(ent->flags & NGHTTP2_HD_FLAG_VALUE_ALLOC) {
    free(ent->nv.value);
  }
}

static int nghttp2_hd_ringbuf_init(nghttp2_hd_ringbuf *ringbuf,
                                   size_t bufsize)
{
  size_t size;
  for(size = 1; size < bufsize; size <<= 1);
  ringbuf->buffer = malloc(sizeof(nghttp2_hd_entry*)*size);
  if(ringbuf->buffer == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  ringbuf->mask = size - 1;
  ringbuf->first = 0;
  ringbuf->len = 0;
  return 0;
}

static nghttp2_hd_entry* nghttp2_hd_ringbuf_get(nghttp2_hd_ringbuf *ringbuf,
                                                size_t index)
{
  assert(index < ringbuf->len);
  return ringbuf->buffer[(ringbuf->first + index) & ringbuf->mask];
}

static int nghttp2_hd_ringbuf_reserve(nghttp2_hd_ringbuf *ringbuf,
                                      size_t bufsize)
{
  size_t i;
  size_t size;
  nghttp2_hd_entry **buffer;

  if(ringbuf->mask + 1 >= bufsize) {
    return 0;
  }
  for(size = 1; size < bufsize; size <<= 1);
  buffer = malloc(sizeof(nghttp2_hd_entry*) * size);
  if(buffer == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  for(i = 0; i < ringbuf->len; ++i) {
    buffer[i] = nghttp2_hd_ringbuf_get(ringbuf, i);
  }
  free(ringbuf->buffer);
  ringbuf->buffer = buffer;
  ringbuf->mask = size - 1;
  ringbuf->first = 0;
  return 0;
}

static void nghttp2_hd_ringbuf_free(nghttp2_hd_ringbuf *ringbuf)
{
  size_t i;
  if(ringbuf == NULL) {
    return;
  }
  for(i = 0; i < ringbuf->len; ++i) {
    nghttp2_hd_entry *ent = nghttp2_hd_ringbuf_get(ringbuf, i);
    --ent->ref;
    nghttp2_hd_entry_free(ent);
    free(ent);
  }
  free(ringbuf->buffer);
}

static size_t nghttp2_hd_ringbuf_push_front(nghttp2_hd_ringbuf *ringbuf,
                                            nghttp2_hd_entry *ent)
{
  assert(ringbuf->len <= ringbuf->mask);
  ringbuf->buffer[--ringbuf->first & ringbuf->mask] = ent;
  ++ringbuf->len;
  return 0;
}

static void nghttp2_hd_ringbuf_pop_back(nghttp2_hd_ringbuf *ringbuf)
{
  assert(ringbuf->len > 0);
  --ringbuf->len;
}

static int nghttp2_hd_context_init(nghttp2_hd_context *context,
                                   nghttp2_hd_role role,
                                   nghttp2_hd_side side,
                                   size_t deflate_hd_table_bufsize_max)
{
  int rv;
  context->role = role;
  context->side = side;
  context->bad = 0;
  context->no_refset = 0;
  context->hd_table_bufsize_max = NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE;
  rv = nghttp2_hd_ringbuf_init
    (&context->hd_table,
     context->hd_table_bufsize_max/NGHTTP2_HD_ENTRY_OVERHEAD);
  if(rv != 0) {
    return rv;
  }

  context->ent_keep = NULL;
  context->name_keep = NULL;
  context->value_keep = NULL;
  context->end_headers_index = 0;

  context->deflate_hd_table_bufsize_max = deflate_hd_table_bufsize_max;
  context->deflate_hd_table_bufsize = 0;
  context->deflate_hd_tablelen = 0;
  context->hd_table_bufsize = 0;
  return 0;
}

int nghttp2_hd_deflate_init(nghttp2_hd_context *deflater, nghttp2_hd_side side)
{
  return nghttp2_hd_deflate_init2(deflater, side,
                                  NGHTTP2_HD_DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
}

int nghttp2_hd_deflate_init2(nghttp2_hd_context *deflater,
                             nghttp2_hd_side side,
                             size_t deflate_hd_table_bufsize_max)
{
  return nghttp2_hd_context_init(deflater, NGHTTP2_HD_ROLE_DEFLATE, side,
                                 deflate_hd_table_bufsize_max);
}

int nghttp2_hd_inflate_init(nghttp2_hd_context *inflater, nghttp2_hd_side side)
{
  return nghttp2_hd_context_init(inflater, NGHTTP2_HD_ROLE_INFLATE, side,
                                 NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE);
}

static void hd_inflate_keep_free(nghttp2_hd_context *inflater)
{
  if(inflater->ent_keep) {
    if(inflater->ent_keep->ref == 0) {
      nghttp2_hd_entry_free(inflater->ent_keep);
      free(inflater->ent_keep);
    }
    inflater->ent_keep = NULL;
  }
  free(inflater->name_keep);
  free(inflater->value_keep);
  inflater->name_keep = NULL;
  inflater->value_keep = NULL;
}

static void nghttp2_hd_context_free(nghttp2_hd_context *context)
{
  nghttp2_hd_ringbuf_free(&context->hd_table);
}

void nghttp2_hd_deflate_free(nghttp2_hd_context *deflater)
{
  nghttp2_hd_context_free(deflater);
}

void nghttp2_hd_inflate_free(nghttp2_hd_context *inflater)
{
  hd_inflate_keep_free(inflater);
  nghttp2_hd_context_free(inflater);
}

void nghttp2_hd_deflate_set_no_refset(nghttp2_hd_context *deflater,
                                      uint8_t no_refset)
{
  deflater->no_refset = no_refset;
}

static size_t entry_room(size_t namelen, size_t valuelen)
{
  return NGHTTP2_HD_ENTRY_OVERHEAD + namelen + valuelen;
}

static int emit_indexed_header(nghttp2_hd_context *inflater,
                               nghttp2_nv *nv_out,
                               nghttp2_hd_entry *ent)
{
  DEBUGF(fprintf(stderr, "Header emission:\n"));
  DEBUGF(fwrite(ent->nv.name, ent->nv.namelen, 1, stderr));
  DEBUGF(fprintf(stderr, ": "));
  DEBUGF(fwrite(ent->nv.value, ent->nv.valuelen, 1, stderr));
  DEBUGF(fprintf(stderr, "\n"));
  /* ent->ref may be 0. This happens if the careless stupid encoder
     emits literal block larger than header table capacity with
     indexing. */
  ent->flags |= NGHTTP2_HD_FLAG_EMIT;
  *nv_out = ent->nv;
  return 0;
}

static int emit_newname_header(nghttp2_hd_context *inflater,
                               nghttp2_nv *nv_out,
                               nghttp2_nv *nv)
{
  DEBUGF(fprintf(stderr, "Header emission:\n"));
  DEBUGF(fwrite(nv->name, nv->namelen, 1, stderr));
  DEBUGF(fprintf(stderr, ": "));
  DEBUGF(fwrite(nv->value, nv->valuelen, 1, stderr));
  DEBUGF(fprintf(stderr, "\n"));
  *nv_out = *nv;
  return 0;
}

static int emit_indname_header(nghttp2_hd_context *inflater,
                               nghttp2_nv *nv_out,
                               nghttp2_hd_entry *ent,
                               uint8_t *value, size_t valuelen)
{
  DEBUGF(fprintf(stderr, "Header emission:\n"));
  DEBUGF(fwrite(ent->nv.name, ent->nv.namelen, 1, stderr));
  DEBUGF(fprintf(stderr, ": "));
  DEBUGF(fwrite(value, valuelen, 1, stderr));
  DEBUGF(fprintf(stderr, "\n"));
  nv_out->name = ent->nv.name;
  nv_out->namelen = ent->nv.namelen;
  nv_out->value = value;
  nv_out->valuelen = valuelen;
  return 0;
}


static int ensure_write_buffer(uint8_t **buf_ptr, size_t *buflen_ptr,
                               size_t offset, size_t need)
{
  int rv;
  /* TODO Remove this limitation when header continuation is
     implemented. */
  if(need + offset > NGHTTP2_MAX_FRAME_LENGTH) {
    return NGHTTP2_ERR_HEADER_COMP;
  }
  rv = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, offset + need);
  if(rv != 0) {
    return NGHTTP2_ERR_NOMEM;
  }
  return 0;
}

static size_t count_encoded_length(size_t n, int prefix)
{
  size_t k = (1 << prefix) - 1;
  size_t len = 0;
  if(n >= k) {
    n -= k;
    ++len;
  } else {
    return 1;
  }
  do {
    ++len;
    if(n >= 128) {
      n >>= 7;
    } else {
      break;
    }
  } while(n);
  return len;
}

static size_t encode_length(uint8_t *buf, size_t n, int prefix)
{
  size_t k = (1 << prefix) - 1;
  size_t len = 0;
  *buf &= ~k;
  if(n >= k) {
    *buf++ |= k;
    n -= k;
    ++len;
  } else {
    *buf++ |= n;
    return 1;
  }
  do {
    ++len;
    if(n >= 128) {
      *buf++ = (1 << 7) | (n & 0x7f);
      n >>= 7;
    } else {
      *buf++ = n;
      break;
    }
  } while(n);
  return len;
}

/*
 * Decodes |prefx| prefixed integer stored from |in|. The |last|
 * represents the 1 beyond the last of the valid contiguous memory
 * region from |in|. The decoded integer must be strictly less than 1
 * << 16.
 *
 * This function returns the next byte of read byte. This function
 * stores the decoded integer in |*res| if it succeeds, or stores -1
 * in |*res|, indicating decoding error.
 */
static  uint8_t* decode_length(ssize_t *res, uint8_t *in, uint8_t *last,
                               int prefix)
{
  int k = (1 << prefix) - 1, r;
  if(in == last) {
    *res = -1;
    return in;
  }
  if((*in & k) == k) {
    *res = k;
  } else {
    *res = (*in) & k;
    return in + 1;
  }
  ++in;
  for(r = 0; in != last; ++in, r += 7) {
    *res += (*in & 0x7f) << r;
    if(*res >= (1 << 16)) {
      *res = -1;
      return in + 1;
    }
    if((*in & (1 << 7)) == 0) {
      break;
    }
  }
  if(in == last || *in & (1 << 7)) {
    *res = -1;
    return NULL;
  } else {
    return in + 1;
  }
}

static int emit_indexed0(uint8_t **buf_ptr, size_t *buflen_ptr,
                         size_t *offset_ptr)
{
  int rv;
  rv = ensure_write_buffer(buf_ptr, buflen_ptr, *offset_ptr, 1);
  if(rv != 0) {
    return rv;
  }
  *(*buf_ptr + *offset_ptr) = 0x80u;
  ++*offset_ptr;
  return 0;
}

static int emit_indexed_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                              size_t *offset_ptr, size_t index)
{
  int rv;
  uint8_t *bufp;
  size_t blocklen = count_encoded_length(index + 1, 7);
  rv = ensure_write_buffer(buf_ptr, buflen_ptr, *offset_ptr, blocklen);
  if(rv != 0) {
    return rv;
  }
  bufp = *buf_ptr + *offset_ptr;
  *bufp = 0x80u;
  encode_length(bufp, index + 1, 7);
  *offset_ptr += blocklen;
  return 0;
}

static size_t emit_string(uint8_t *buf, size_t buflen,
                          size_t enclen, int huffman,
                          const uint8_t *str, size_t len,
                          nghttp2_hd_side side)
{
  size_t rv;
  *buf = huffman ? 1 << 7 : 0;
  rv = encode_length(buf, enclen, 7);
  buf += rv;
  if(huffman) {
    nghttp2_hd_huff_encode(buf, buflen - rv, str, len, side);
  } else {
    assert(enclen == len);
    memcpy(buf, str, len);
  }
  return rv + enclen;
}

static int emit_indname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                              size_t *offset_ptr, size_t index,
                              const uint8_t *value, size_t valuelen,
                              int inc_indexing,
                              nghttp2_hd_side side)
{
  int rv;
  uint8_t *bufp;
  size_t encvallen = nghttp2_hd_huff_encode_count(value, valuelen, side);
  size_t blocklen = count_encoded_length(index + 1, 6);
  int huffman = encvallen < valuelen;
  if(!huffman) {
    encvallen = valuelen;
  }
  blocklen += count_encoded_length(encvallen, 7) + encvallen;
  rv = ensure_write_buffer(buf_ptr, buflen_ptr, *offset_ptr, blocklen);
  if(rv != 0) {
    return rv;
  }
  bufp = *buf_ptr + *offset_ptr;
  *bufp = inc_indexing ? 0 : 0x40u;
  bufp += encode_length(bufp, index + 1, 6);
  bufp += emit_string(bufp, *buflen_ptr - (bufp - *buf_ptr),
                      encvallen, huffman, value, valuelen, side);
  assert(bufp - (*buf_ptr + *offset_ptr) == (ssize_t)blocklen);
  *offset_ptr += blocklen;
  return 0;
}

static int emit_newname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                              size_t *offset_ptr, nghttp2_nv *nv,
                              int inc_indexing,
                              nghttp2_hd_side side)
{
  int rv;
  uint8_t *bufp;
  size_t encnamelen =
    nghttp2_hd_huff_encode_count(nv->name, nv->namelen, side);
  size_t encvallen =
    nghttp2_hd_huff_encode_count(nv->value, nv->valuelen, side);
  size_t blocklen = 1;
  int name_huffman = encnamelen < nv->namelen;
  int value_huffman = encvallen < nv->valuelen;
  if(!name_huffman) {
    encnamelen = nv->namelen;
  }
  if(!value_huffman) {
    encvallen = nv->valuelen;
  }
  blocklen += count_encoded_length(encnamelen, 7) + encnamelen +
    count_encoded_length(encvallen, 7) + encvallen;
  rv = ensure_write_buffer(buf_ptr, buflen_ptr, *offset_ptr, blocklen);
  if(rv != 0) {
    return rv;
  }
  bufp = *buf_ptr + *offset_ptr;
  *bufp++ = inc_indexing ? 0 : 0x40u;
  bufp += emit_string(bufp, *buflen_ptr - (bufp - *buf_ptr),
                      encnamelen, name_huffman, nv->name, nv->namelen, side);
  bufp += emit_string(bufp, *buflen_ptr - (bufp - *buf_ptr),
                      encvallen, value_huffman, nv->value, nv->valuelen, side);
  *offset_ptr += blocklen;
  return 0;
}

/*
 * Emit common header with |index| by toggle off and on (thus 2
 * indexed representation emissions).
 */
static int emit_implicit(uint8_t **buf_ptr,
                         size_t *buflen_ptr,
                         size_t *offset_ptr,
                         size_t index)
{
  int i;
  int rv;
  for(i = 0; i < 2; ++i) {
    rv = emit_indexed_block(buf_ptr, buflen_ptr, offset_ptr, index);
    if(rv != 0) {
      return rv;
    }
  }
  return 0;
}

static nghttp2_hd_entry* add_hd_table_incremental(nghttp2_hd_context *context,
                                                  uint8_t **buf_ptr,
                                                  size_t *buflen_ptr,
                                                  size_t *offset_ptr,
                                                  nghttp2_nv *nv,
                                                  uint8_t entry_flags)
{
  int rv;
  nghttp2_hd_entry *new_ent;
  size_t room = entry_room(nv->namelen, nv->valuelen);
  while(context->hd_table_bufsize + room > context->hd_table_bufsize_max &&
        context->hd_table.len > 0) {
    size_t index = context->hd_table.len - 1;
    nghttp2_hd_entry* ent = nghttp2_hd_ringbuf_get(&context->hd_table, index);
    context->hd_table_bufsize -= entry_room(ent->nv.namelen, ent->nv.valuelen);
    if(context->hd_table_bufsize < context->deflate_hd_table_bufsize) {
      context->deflate_hd_table_bufsize -= entry_room(ent->nv.namelen,
                                                      ent->nv.valuelen);
      --context->deflate_hd_tablelen;
    }
    if(context->role == NGHTTP2_HD_ROLE_DEFLATE) {
      if(ent->flags & NGHTTP2_HD_FLAG_IMPLICIT_EMIT) {
        /* Emit common header just before it slips away from the
           table. If we don't do this, we have to emit it in literal
           representation which hurts compression. */
        rv = emit_implicit(buf_ptr, buflen_ptr, offset_ptr, index);
        if(rv != 0) {
          return NULL;
        }
      }
    }
    DEBUGF(fprintf(stderr, "Remove item from header table:\n"));
    DEBUGF(fwrite(ent->nv.name, ent->nv.namelen, 1, stderr));
    DEBUGF(fprintf(stderr, ": "));
    DEBUGF(fwrite(ent->nv.value, ent->nv.valuelen, 1, stderr));
    DEBUGF(fprintf(stderr, "\n"));
    nghttp2_hd_ringbuf_pop_back(&context->hd_table);
    if(--ent->ref == 0) {
      nghttp2_hd_entry_free(ent);
      free(ent);
    }
  }
  while(context->deflate_hd_table_bufsize + room >
        context->deflate_hd_table_bufsize_max
        && context->deflate_hd_tablelen > 0) {
    size_t index = context->deflate_hd_tablelen - 1;
    nghttp2_hd_entry *ent =
      nghttp2_hd_ringbuf_get(&context->hd_table, index);
    context->deflate_hd_table_bufsize -= entry_room(ent->nv.namelen,
                                                    ent->nv.valuelen);
    --context->deflate_hd_tablelen;
    if(ent->flags & NGHTTP2_HD_FLAG_IMPLICIT_EMIT) {
      /* Just like a normal eviction, implicit header must be
         emitted twice. */
      rv = emit_implicit(buf_ptr, buflen_ptr, offset_ptr, index);
      if(rv != 0) {
        return NULL;
      }
      ent->flags ^= NGHTTP2_HD_FLAG_IMPLICIT_EMIT;
    }
    if(ent->flags & NGHTTP2_HD_FLAG_REFSET) {
      /* We need to drop entry from reference set. */
      rv = emit_indexed_block(buf_ptr, buflen_ptr, offset_ptr, index);
      if(rv != 0) {
        return NULL;
      }
      ent->flags ^= NGHTTP2_HD_FLAG_REFSET;
    }
    /* Release memory. We don't remove entry from the header table
       at this moment. */
    if(ent->flags & NGHTTP2_HD_FLAG_NAME_ALLOC) {
      free(ent->nv.name);
      ent->nv.name = NULL;
      ent->flags ^= NGHTTP2_HD_FLAG_NAME_ALLOC;
    }
    if(ent->flags & NGHTTP2_HD_FLAG_VALUE_ALLOC) {
      free(ent->nv.value);
      ent->nv.value = NULL;
      ent->flags ^= NGHTTP2_HD_FLAG_VALUE_ALLOC;
    }
  }

  new_ent = malloc(sizeof(nghttp2_hd_entry));
  if(new_ent == NULL) {
    return NULL;
  }

  if(context->role == NGHTTP2_HD_ROLE_DEFLATE &&
     room > context->deflate_hd_table_bufsize_max) {
    uint8_t flags = entry_flags &
      ~(NGHTTP2_HD_FLAG_NAME_ALLOC | NGHTTP2_HD_FLAG_VALUE_ALLOC |
        NGHTTP2_HD_FLAG_NAME_GIFT | NGHTTP2_HD_FLAG_VALUE_GIFT);
    rv = nghttp2_hd_entry_init(new_ent, flags,
                               NULL, nv->namelen, NULL, nv->valuelen);
    if(rv != 0) {
      free(new_ent);
      return NULL;
    }
    if(flags & NGHTTP2_HD_FLAG_NAME_GIFT) {
      free(nv->name);
      nv->name = NULL;
    }
    if(flags & NGHTTP2_HD_FLAG_VALUE_GIFT) {
      free(nv->value);
      nv->value = NULL;
    }
    /* caller must emit indexed repr to toggle off new_ent from
       reference set. We cannot do it here because it may break the
       indexing. */
  } else {
    rv = nghttp2_hd_entry_init(new_ent,
                               entry_flags,
                               nv->name, nv->namelen, nv->value, nv->valuelen);
    if(rv != 0) {
      free(new_ent);
      return NULL;
    }
  }
  if(room > context->hd_table_bufsize_max) {
    /* The entry taking more than NGHTTP2_HD_MAX_BUFFER_SIZE is
       immediately evicted. */
    --new_ent->ref;
  } else {
    context->hd_table_bufsize += room;
    nghttp2_hd_ringbuf_push_front(&context->hd_table, new_ent);
    if(room <= context->deflate_hd_table_bufsize_max) {
      new_ent->flags |= NGHTTP2_HD_FLAG_REFSET;
      context->deflate_hd_table_bufsize += room;
      ++context->deflate_hd_tablelen;
    }
  }
  return new_ent;
}

static int name_eq(const nghttp2_nv *a, const nghttp2_nv *b)
{
  return a->namelen == b->namelen && memeq(a->name, b->name, a->namelen);
}

static int value_eq(const nghttp2_nv *a, const nghttp2_nv *b)
{
  return a->valuelen == b->valuelen && memeq(a->value, b->value, a->valuelen);
}

typedef struct {
  ssize_t index;
  /* Nonzero if both name and value are matched. */
  uint8_t name_value_match;
} search_result;

static search_result search_hd_table(nghttp2_hd_context *context,
                                     nghttp2_nv *nv)
{
  search_result res = { -1, 0 };
  size_t i;
  uint32_t name_hash = hash(nv->name, nv->namelen);
  uint32_t value_hash = hash(nv->value, nv->valuelen);
  ssize_t left = -1, right = STATIC_TABLE_LENGTH;

  for(i = 0; i < context->deflate_hd_tablelen; ++i) {
    nghttp2_hd_entry *ent = nghttp2_hd_ringbuf_get(&context->hd_table, i);
    if(ent->name_hash == name_hash && name_eq(&ent->nv, nv)) {
      if(res.index == -1) {
        res.index = i;
      }
      if(ent->value_hash == value_hash && value_eq(&ent->nv, nv)) {
        res.index = i;
        res.name_value_match = 1;
        return res;
      }
    }
  }

  while(right - left > 1) {
    ssize_t mid = (left + right) / 2;
    nghttp2_hd_entry *ent = &static_table[mid].ent;
    if(ent->name_hash < name_hash) {
      left = mid;
    } else {
      right = mid;
    }
  }
  for(i = right; i < STATIC_TABLE_LENGTH; ++i) {
    nghttp2_hd_entry *ent = &static_table[i].ent;
    if(ent->name_hash != name_hash) {
      break;
    }
    if(name_eq(&ent->nv, nv)) {
      if(res.index == -1) {
        res.index = context->hd_table.len + static_table[i].index;
      }
      if(ent->value_hash == value_hash && value_eq(&ent->nv, nv)) {
        res.index = context->hd_table.len + static_table[i].index;
        res.name_value_match = 1;
        return res;
      }
    }
  }
  return res;
}

int nghttp2_hd_change_table_size(nghttp2_hd_context *context,
                                 size_t hd_table_bufsize_max)
{
  int rv;
  rv = nghttp2_hd_ringbuf_reserve
    (&context->hd_table, hd_table_bufsize_max / NGHTTP2_HD_ENTRY_OVERHEAD);
  if(rv != 0) {
    return rv;
  }
  context->hd_table_bufsize_max = hd_table_bufsize_max;
  if(context->role == NGHTTP2_HD_ROLE_INFLATE) {
    context->deflate_hd_table_bufsize_max = hd_table_bufsize_max;
  }
  while(context->hd_table_bufsize > context->hd_table_bufsize_max &&
        context->hd_table.len > 0) {
    size_t index = context->hd_table.len - 1;
    nghttp2_hd_entry* ent = nghttp2_hd_ringbuf_get(&context->hd_table, index);
    context->hd_table_bufsize -= entry_room(ent->nv.namelen, ent->nv.valuelen);
    if(context->hd_table_bufsize < context->deflate_hd_table_bufsize) {
      context->deflate_hd_table_bufsize -= entry_room(ent->nv.namelen,
                                                      ent->nv.valuelen);
      --context->deflate_hd_tablelen;
    }
    nghttp2_hd_ringbuf_pop_back(&context->hd_table);
    if(--ent->ref == 0) {
      nghttp2_hd_entry_free(ent);
      free(ent);
    }
  }
  return 0;
}

static void clear_refset(nghttp2_hd_context *context)
{
  size_t i;
  for(i = 0; i < context->hd_table.len; ++i) {
    nghttp2_hd_entry *ent = nghttp2_hd_ringbuf_get(&context->hd_table, i);
    ent->flags &= ~NGHTTP2_HD_FLAG_REFSET;
  }
}

static int check_index_range(nghttp2_hd_context *context, size_t index)
{
  return index < context->hd_table.len + STATIC_TABLE_LENGTH;
}

nghttp2_hd_entry* nghttp2_hd_table_get(nghttp2_hd_context *context,
                                       size_t index)
{
  assert(check_index_range(context, index));
  if(index < context->hd_table.len) {
    return nghttp2_hd_ringbuf_get(&context->hd_table, index);
  } else {
    return
      &static_table[static_table_index[index - context->hd_table.len]].ent;
  }
}

#define name_match(NV, NAME)                                            \
  (nv->namelen == sizeof(NAME) - 1 && memeq(nv->name, NAME, sizeof(NAME) - 1))

static int hd_deflate_should_indexing(nghttp2_hd_context *deflater,
                                      const nghttp2_nv *nv)
{
  size_t table_size = nghttp2_min(deflater->deflate_hd_table_bufsize_max,
                                  deflater->hd_table_bufsize_max);
  if(entry_room(nv->namelen, nv->valuelen) > table_size * 3 / 4) {
    return 0;
  }
#ifdef NGHTTP2_XHD
  return !name_match(nv, NGHTTP2_XHD);
#else /* !NGHTTP2_XHD */
  return
    !name_match(nv, "set-cookie") &&
    !name_match(nv, "content-length") &&
    !name_match(nv, "location") &&
    !name_match(nv, "etag") &&
    !name_match(nv, ":path");
#endif /* !NGHTTP2_XHD */
}

static int deflate_nv(nghttp2_hd_context *deflater,
                      uint8_t **buf_ptr, size_t *buflen_ptr,
                      size_t *offset_ptr,
                      nghttp2_nv *nv)
{
  int rv;
  nghttp2_hd_entry *ent;
  search_result res;
  res = search_hd_table(deflater, nv);
  if(res.index != -1 && res.name_value_match) {
    size_t index = res.index;
    ent = nghttp2_hd_table_get(deflater, index);
    if(index >= deflater->hd_table.len) {
      nghttp2_hd_entry *new_ent;
      /* It is important to first add entry to the header table and
         let eviction go. If NGHTTP2_HD_FLAG_IMPLICIT_EMIT entry is
         evicted, it must be emitted before the |nv|. */
      new_ent = add_hd_table_incremental(deflater, buf_ptr, buflen_ptr,
                                         offset_ptr, &ent->nv,
                                         NGHTTP2_HD_FLAG_NONE);
      if(!new_ent) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      if(new_ent->ref == 0) {
        nghttp2_hd_entry_free(new_ent);
        free(new_ent);
        new_ent = NULL;
      } else if(new_ent->nv.name != NULL) {
        /* new_ent->ref > 0 and nv.name is not NULL means that new_ent is
           in the reference set and in deflate_hd_table_bufsize */
        new_ent->flags |= NGHTTP2_HD_FLAG_EMIT;
      }
      rv = emit_indexed_block(buf_ptr, buflen_ptr, offset_ptr, index);
      if(rv != 0) {
        return rv;
      }
    } else if((ent->flags & NGHTTP2_HD_FLAG_REFSET) == 0) {
      ent->flags |= NGHTTP2_HD_FLAG_REFSET | NGHTTP2_HD_FLAG_EMIT;
      rv = emit_indexed_block(buf_ptr, buflen_ptr, offset_ptr, index);
      if(rv != 0) {
        return rv;
      }
    } else {
      int num_emits = 0;
      if(ent->flags & NGHTTP2_HD_FLAG_EMIT) {
        /* occurrences of the same indexed representation. Emit index
           twice. */
        num_emits = 2;
      } else if(ent->flags & NGHTTP2_HD_FLAG_IMPLICIT_EMIT) {
        /* ent was implicitly emitted because it is the common
           header field. To support occurrences of the same indexed
           representation, we have to emit 4 times. This is because
           "implicitly emitted" means actually not emitted at
           all. So first 2 emits performs 1st header appears in the
           reference set. And another 2 emits are done for 2nd
           (current) header. */
        ent->flags ^= NGHTTP2_HD_FLAG_IMPLICIT_EMIT;
        ent->flags |= NGHTTP2_HD_FLAG_EMIT;
        num_emits = 4;
      } else {
        /* This is common header and not emitted in the current
           run. Just mark IMPLICIT_EMIT, in the hope that we are not
           required to emit anything for this. We will emit toggle
           off/on for this entry if it is removed from the header
           table. */
        ent->flags |= NGHTTP2_HD_FLAG_IMPLICIT_EMIT;
      }
      for(; num_emits > 0; --num_emits) {
        rv = emit_indexed_block(buf_ptr, buflen_ptr, offset_ptr, index);
        if(rv != 0) {
          break;
        }
      }
    }
  } else {
    ssize_t index = -1;
    int incidx = 0;
    if(res.index != -1) {
      index = res.index;
    }
    if(hd_deflate_should_indexing(deflater, nv)) {
      nghttp2_hd_entry *new_ent;
      if(index >= (ssize_t)deflater->hd_table.len) {
        nghttp2_nv nv_indname;
        nv_indname = *nv;
        nv_indname.name = nghttp2_hd_table_get(deflater, index)->nv.name;
        new_ent = add_hd_table_incremental(deflater, buf_ptr, buflen_ptr,
                                           offset_ptr, &nv_indname,
                                           NGHTTP2_HD_FLAG_VALUE_ALLOC);
      } else {
        new_ent = add_hd_table_incremental(deflater, buf_ptr, buflen_ptr,
                                           offset_ptr, nv,
                                           NGHTTP2_HD_FLAG_NAME_ALLOC |
                                           NGHTTP2_HD_FLAG_VALUE_ALLOC);
      }
      if(!new_ent) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      if(new_ent->ref == 0) {
        nghttp2_hd_entry_free(new_ent);
        free(new_ent);
      } else if(new_ent->nv.name != NULL) {
        /* new_ent->ref > 0 and nv.name is not NULL means that new_ent is
           in the reference set and in deflate_hd_table_bufsize */
        new_ent->flags |= NGHTTP2_HD_FLAG_EMIT;
      }
      incidx = 1;
    }
    if(index == -1) {
      rv = emit_newname_block(buf_ptr, buflen_ptr, offset_ptr, nv, incidx,
                              deflater->side);
    } else {
      rv = emit_indname_block(buf_ptr, buflen_ptr, offset_ptr, index,
                              nv->value, nv->valuelen, incidx,
                              deflater->side);
    }
    if(rv != 0) {
      return rv;
    }
  }
  return 0;
}

static int deflate_post_process_hd_entry(nghttp2_hd_entry *ent,
                                         size_t index,
                                         uint8_t **buf_ptr,
                                         size_t *buflen_ptr,
                                         size_t *offset_ptr)
{
  int rv;
  if((ent->flags & NGHTTP2_HD_FLAG_REFSET) &&
     (ent->flags & NGHTTP2_HD_FLAG_IMPLICIT_EMIT) == 0 &&
     (ent->flags & NGHTTP2_HD_FLAG_EMIT) == 0) {
    /* This entry is not present in the current header set and must
       be removed. */
    ent->flags ^= NGHTTP2_HD_FLAG_REFSET;
    rv = emit_indexed_block(buf_ptr, buflen_ptr, offset_ptr, index);
    if(rv != 0) {
      return rv;
    }
  }
  ent->flags &= ~(NGHTTP2_HD_FLAG_EMIT | NGHTTP2_HD_FLAG_IMPLICIT_EMIT);
  return 0;
}

ssize_t nghttp2_hd_deflate_hd(nghttp2_hd_context *deflater,
                              uint8_t **buf_ptr, size_t *buflen_ptr,
                              size_t nv_offset,
                              nghttp2_nv *nv, size_t nvlen)
{
  size_t i, offset;
  int rv = 0;
  if(deflater->bad) {
    return NGHTTP2_ERR_HEADER_COMP;
  }
  offset = nv_offset;
  if(deflater->no_refset) {
    rv = emit_indexed0(buf_ptr, buflen_ptr, &offset);
    if(rv != 0) {
      goto fail;
    }
    clear_refset(deflater);
  }
  for(i = 0; i < nvlen; ++i) {
    rv = deflate_nv(deflater, buf_ptr, buflen_ptr, &offset, &nv[i]);
    if(rv != 0) {
      goto fail;
    }
  }
  for(i = 0; i < deflater->deflate_hd_tablelen; ++i) {
    nghttp2_hd_entry *ent = nghttp2_hd_ringbuf_get(&deflater->hd_table, i);
    rv = deflate_post_process_hd_entry(ent, i, buf_ptr, buflen_ptr, &offset);
    if(rv != 0) {
      goto fail;
    }
  }
  return offset - nv_offset;
 fail:
  deflater->bad = 1;
  return rv;
}

ssize_t nghttp2_hd_inflate_hd(nghttp2_hd_context *inflater,
                              nghttp2_nv *nv_out, int *final,
                              uint8_t *in, size_t inlen)
{
  int rv = 0;
  uint8_t *first = in;
  uint8_t *last = in + inlen;

  DEBUGF(fprintf(stderr, "infalte_hd start\n"));
  if(inflater->bad) {
    return NGHTTP2_ERR_HEADER_COMP;
  }

  *final = 0;
  hd_inflate_keep_free(inflater);

  for(; in != last;) {
    uint8_t c = *in;
    if(c & 0x80u) {
      /* Indexed Header Repr */
      ssize_t index;
      nghttp2_hd_entry *ent;
      in = decode_length(&index, in, last, 7);
      DEBUGF(fprintf(stderr, "Indexed repr index=%zd\n", index));
      if(index < 0) {
        DEBUGF(fprintf(stderr, "Index out of range index=%zd\n", index));
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      if(index == 0) {
        DEBUGF(fprintf(stderr, "Clearing reference set\n"));
        clear_refset(inflater);
        continue;
      }
      --index;
      if(!check_index_range(inflater, index)) {
        DEBUGF(fprintf(stderr, "Index out of range index=%zd\n", index));
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      ent = nghttp2_hd_table_get(inflater, index);
      if(index >= (ssize_t)inflater->hd_table.len) {
        nghttp2_hd_entry *new_ent;
        new_ent = add_hd_table_incremental(inflater, NULL, NULL, NULL,
                                           &ent->nv, NGHTTP2_HD_FLAG_NONE);
        if(!new_ent) {
          rv = NGHTTP2_ERR_HEADER_COMP;
          goto fail;
        }
        /* new_ent->ref == 0 may be hold but emit_indexed_header
           tracks new_ent, so there is no leak. */
        emit_indexed_header(inflater, nv_out, new_ent);
        inflater->ent_keep = new_ent;
        return in - first;
      } else {
        ent->flags ^= NGHTTP2_HD_FLAG_REFSET;
        if(ent->flags & NGHTTP2_HD_FLAG_REFSET) {
          emit_indexed_header(inflater, nv_out, ent);
          return in - first;
        } else {
          DEBUGF(fprintf(stderr, "Toggle off item:\n"));
          DEBUGF(fwrite(ent->nv.name, ent->nv.namelen, 1, stderr));
          DEBUGF(fprintf(stderr, ": "));
          DEBUGF(fwrite(ent->nv.value, ent->nv.valuelen, 1, stderr));
          DEBUGF(fprintf(stderr, "\n"));
        }
      }
      if(rv != 0) {
        goto fail;
      }
    } else if(c == 0x40u || c == 0) {
      /* Literal Header Repr - New Name */
      nghttp2_nv nv;
      ssize_t namelen, valuelen;
      int name_huffman, value_huffman;
      uint8_t *decoded_huffman_name = NULL, *decoded_huffman_value = NULL;
      DEBUGF(fprintf(stderr, "Literal header repr - new name\n"));
      if(++in == last) {
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      name_huffman = *in & (1 << 7);
      in = decode_length(&namelen, in, last, 7);
      if(namelen < 0 || in + namelen > last) {
        DEBUGF(fprintf(stderr, "Invalid namelen=%zd\n", namelen));
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      if(name_huffman) {
        rv = nghttp2_hd_huff_decode(&nv.name, in, namelen, inflater->side);
        if(rv < 0) {
          DEBUGF(fprintf(stderr, "Name huffman decoding failed\n"));
          goto fail;
        }
        decoded_huffman_name = nv.name;
        nv.namelen = rv;
      } else {
        nv.name = in;
        nv.namelen = namelen;
      }
      in += namelen;

      if(in == last) {
        DEBUGF(fprintf(stderr, "No value found\n"));
        free(decoded_huffman_name);
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      value_huffman = *in & (1 << 7);
      in = decode_length(&valuelen, in, last, 7);
      if(valuelen < 0 || in + valuelen > last) {
        DEBUGF(fprintf(stderr, "Invalid valuelen=%zd\n", valuelen));
        free(decoded_huffman_name);
        rv =  NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      if(value_huffman) {
        rv = nghttp2_hd_huff_decode(&nv.value, in, valuelen, inflater->side);
        if(rv < 0) {
          DEBUGF(fprintf(stderr, "Value huffman decoding failed\n"));
          free(decoded_huffman_name);
          goto fail;
        }
        decoded_huffman_value = nv.value;
        nv.valuelen = rv;
      } else {
        nv.value = in;
        nv.valuelen = valuelen;
      }
      in += valuelen;

      if(c == 0x40u) {
        int flags = NGHTTP2_HD_FLAG_NONE;
        if(name_huffman) {
          flags |= NGHTTP2_HD_FLAG_NAME_GIFT;
        }
        if(value_huffman) {
          flags |= NGHTTP2_HD_FLAG_VALUE_GIFT;
        }
        emit_newname_header(inflater, nv_out, &nv);
        inflater->name_keep = decoded_huffman_name;
        inflater->value_keep = decoded_huffman_value;
        return in - first;
      } else {
        nghttp2_hd_entry *new_ent;
        uint8_t ent_flags = NGHTTP2_HD_FLAG_NAME_ALLOC |
          NGHTTP2_HD_FLAG_VALUE_ALLOC;
        if(name_huffman) {
          ent_flags |= NGHTTP2_HD_FLAG_NAME_GIFT;
        }
        if(value_huffman) {
          ent_flags |= NGHTTP2_HD_FLAG_VALUE_GIFT;
        }
        new_ent = add_hd_table_incremental(inflater, NULL, NULL, NULL, &nv,
                                           ent_flags);
        if(new_ent) {
          emit_indexed_header(inflater, nv_out, new_ent);
          inflater->ent_keep = new_ent;
          return in - first;
        } else {
          free(decoded_huffman_name);
          free(decoded_huffman_value);
          rv = NGHTTP2_ERR_HEADER_COMP;
        }
      }
      if(rv != 0) {
        goto fail;
      }
    } else {
      /* Literal Header Repr - Indexed Name */
      nghttp2_hd_entry *ent;
      uint8_t *value;
      ssize_t valuelen, index;
      int value_huffman;
      uint8_t *decoded_huffman_value = NULL;
      DEBUGF(fprintf(stderr, "Literal header repr - indexed name\n"));
      in = decode_length(&index, in, last, 6);
      if(index <= 0) {
        DEBUGF(fprintf(stderr, "Index out of range index=%zd\n", index));
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      --index;
      if(!check_index_range(inflater, index)) {
        DEBUGF(fprintf(stderr, "Index out of range index=%zd\n", index));
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      ent = nghttp2_hd_table_get(inflater, index);
      if(in == last) {
        DEBUGF(fprintf(stderr, "No value found\n"));
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      value_huffman = *in & (1 << 7);
      in = decode_length(&valuelen, in , last, 7);
      if(valuelen < 0 || in + valuelen > last) {
        DEBUGF(fprintf(stderr, "Invalid valuelen=%zd\n", valuelen));
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      if(value_huffman) {
        rv = nghttp2_hd_huff_decode(&value, in, valuelen, inflater->side);
        if(rv < 0) {
          DEBUGF(fprintf(stderr, "Value huffman decoding failed\n"));
          goto fail;
        }
        decoded_huffman_value = value;
        in += valuelen;
        valuelen = rv;
      } else {
        value = in;
        in += valuelen;
      }
      if((c & 0x40u) == 0x40u) {
        emit_indname_header(inflater, nv_out, ent, value, valuelen);
        inflater->value_keep = decoded_huffman_value;
        return in - first;
      } else {
        nghttp2_nv nv;
        nghttp2_hd_entry *new_ent;
        uint8_t ent_flags = NGHTTP2_HD_FLAG_VALUE_ALLOC;
        if(value_huffman) {
          ent_flags |= NGHTTP2_HD_FLAG_VALUE_GIFT;
        }
        ++ent->ref;
        nv.name = ent->nv.name;
        if((size_t)index < inflater->hd_table.len) {
          ent_flags |= NGHTTP2_HD_FLAG_NAME_ALLOC;
        }
        nv.namelen = ent->nv.namelen;
        nv.value = value;
        nv.valuelen = valuelen;
        new_ent = add_hd_table_incremental(inflater, NULL, NULL, NULL, &nv,
                                           ent_flags);
        if(--ent->ref == 0) {
          nghttp2_hd_entry_free(ent);
          free(ent);
        }
        if(new_ent) {
          emit_indexed_header(inflater, nv_out, new_ent);
          inflater->ent_keep = new_ent;
          return in - first;
        } else {
          free(decoded_huffman_value);
          rv = NGHTTP2_ERR_HEADER_COMP;
        }
      }
      if(rv != 0) {
        goto fail;
      }
    }
  }

  for(; inflater->end_headers_index < inflater->hd_table.len;
      ++inflater->end_headers_index) {
    nghttp2_hd_entry *ent;
    ent = nghttp2_hd_ringbuf_get(&inflater->hd_table,
                                 inflater->end_headers_index);

    if((ent->flags & NGHTTP2_HD_FLAG_REFSET) &&
       (ent->flags & NGHTTP2_HD_FLAG_EMIT) == 0) {
      emit_indexed_header(inflater, nv_out, ent);
      return in - first;
    }
    ent->flags &= ~NGHTTP2_HD_FLAG_EMIT;
  }
  *final = 1;
  return in - first;
 fail:
  inflater->bad = 1;
  return rv;
}

int nghttp2_hd_inflate_end_headers(nghttp2_hd_context *inflater)
{
  hd_inflate_keep_free(inflater);
  inflater->end_headers_index = 0;
  return 0;
}

int nghttp2_hd_emit_indname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  size_t *offset_ptr, size_t index,
                                  const uint8_t *value, size_t valuelen,
                                  int inc_indexing,
                                  nghttp2_hd_side side)
{
  return emit_indname_block(buf_ptr, buflen_ptr, offset_ptr,
                            index, value, valuelen, inc_indexing,
                            side);
}

int nghttp2_hd_emit_newname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  size_t *offset_ptr, nghttp2_nv *nv,
                                  int inc_indexing,
                                  nghttp2_hd_side side)
{
  return emit_newname_block(buf_ptr, buflen_ptr, offset_ptr, nv, inc_indexing,
                            side);
}
