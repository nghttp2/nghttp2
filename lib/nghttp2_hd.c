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

#include "nghttp2_frame.h"
#include "nghttp2_helper.h"

/* Make scalar initialization form of nghttp2_nv */
#define MAKE_NV(N, V)                                           \
  { { (uint8_t*)N, (uint8_t*)V, sizeof(N) - 1, sizeof(V) - 1 }, \
      1, NGHTTP2_HD_FLAG_NONE }

static nghttp2_hd_entry static_table[] = {
  /* 0 */ MAKE_NV(":authority", ""),
  /* 1 */ MAKE_NV(":method", "GET"),
  /* 2 */ MAKE_NV(":method", "POST"),
  /* 3 */ MAKE_NV(":path", "/"),
  /* 4 */ MAKE_NV(":path", "/index.html"),
  /* 5 */ MAKE_NV(":scheme", "http"),
  /* 6 */ MAKE_NV(":scheme", "https"),
  /* 7 */ MAKE_NV(":status", "200"),
  /* 8 */ MAKE_NV(":status", "500"),
  /* 9 */ MAKE_NV(":status", "404"),
  /* 10 */ MAKE_NV(":status", "403"),
  /* 11 */ MAKE_NV(":status", "400"),
  /* 12 */ MAKE_NV(":status", "401"),
  /* 13 */ MAKE_NV("accept-charset", ""),
  /* 14 */ MAKE_NV("accept-encoding", ""),
  /* 15 */ MAKE_NV("accept-language", ""),
  /* 16 */ MAKE_NV("accept-ranges", ""),
  /* 17 */ MAKE_NV("accept", ""),
  /* 18 */ MAKE_NV("access-control-allow-origin", ""),
  /* 19 */ MAKE_NV("age", ""),
  /* 20 */ MAKE_NV("allow", ""),
  /* 21 */ MAKE_NV("authorization", ""),
  /* 22 */ MAKE_NV("cache-control", ""),
  /* 23 */ MAKE_NV("content-disposition", ""),
  /* 24 */ MAKE_NV("content-encoding", ""),
  /* 25 */ MAKE_NV("content-language", ""),
  /* 26 */ MAKE_NV("content-length", ""),
  /* 27 */ MAKE_NV("content-location", ""),
  /* 28 */ MAKE_NV("content-range", ""),
  /* 29 */ MAKE_NV("content-type", ""),
  /* 30 */ MAKE_NV("cookie", ""),
  /* 31 */ MAKE_NV("date", ""),
  /* 32 */ MAKE_NV("etag", ""),
  /* 33 */ MAKE_NV("expect", ""),
  /* 34 */ MAKE_NV("expires", ""),
  /* 35 */ MAKE_NV("from", ""),
  /* 36 */ MAKE_NV("if-match", ""),
  /* 37 */ MAKE_NV("if-modified-since", ""),
  /* 38 */ MAKE_NV("if-none-match", ""),
  /* 39 */ MAKE_NV("if-range", ""),
  /* 40 */ MAKE_NV("if-unmodified-since", ""),
  /* 41 */ MAKE_NV("last-modified", ""),
  /* 42 */ MAKE_NV("link", ""),
  /* 43 */ MAKE_NV("location", ""),
  /* 44 */ MAKE_NV("max-forwards", ""),
  /* 45 */ MAKE_NV("proxy-authenticate", ""),
  /* 46 */ MAKE_NV("proxy-authorization", ""),
  /* 47 */ MAKE_NV("range", ""),
  /* 48 */ MAKE_NV("referer", ""),
  /* 49 */ MAKE_NV("refresh", ""),
  /* 50 */ MAKE_NV("retry-after", ""),
  /* 51 */ MAKE_NV("server", ""),
  /* 52 */ MAKE_NV("set-cookie", ""),
  /* 53 */ MAKE_NV("strict-transport-security", ""),
  /* 54 */ MAKE_NV("transfer-encoding", ""),
  /* 55 */ MAKE_NV("user-agent", ""),
  /* 56 */ MAKE_NV("vary", ""),
  /* 57 */ MAKE_NV("via", ""),
  /* 58 */ MAKE_NV("www-authenticate", "")
};

static const size_t STATIC_TABLE_LENGTH =
  sizeof(static_table)/sizeof(static_table[0]);

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
  assert(ringbuf->len + 1 <= ringbuf->mask);
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
  context->hd_table_bufsize_max = NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE;
  rv = nghttp2_hd_ringbuf_init
    (&context->hd_table,
     context->hd_table_bufsize_max/NGHTTP2_HD_ENTRY_OVERHEAD);
  if(rv != 0) {
    return rv;
  }

  context->emit_set = NULL;
  context->buf_track = NULL;

  if(role == NGHTTP2_HD_ROLE_INFLATE) {
    context->emit_set = malloc(sizeof(nghttp2_hd_entry*)*
                               NGHTTP2_INITIAL_EMIT_SET_SIZE);
    if(context->emit_set == NULL) {
      goto fail;
    }
    memset(context->emit_set, 0, sizeof(nghttp2_hd_entry*)*
           NGHTTP2_INITIAL_EMIT_SET_SIZE);
    context->emit_set_capacity = NGHTTP2_INITIAL_EMIT_SET_SIZE;

    context->buf_track = malloc(sizeof(uint8_t*)*
                                NGHTTP2_INITIAL_BUF_TRACK_SIZE);
    if(context->buf_track == NULL) {
      goto fail;
    }
    context->buf_track_capacity = NGHTTP2_INITIAL_BUF_TRACK_SIZE;
  } else {
    context->emit_set = NULL;
    context->emit_set_capacity = 0;
    context->buf_track = NULL;
    context->buf_track_capacity = 0;
  }
  context->deflate_hd_table_bufsize_max = deflate_hd_table_bufsize_max;
  context->deflate_hd_table_bufsize = 0;
  context->deflate_hd_tablelen = 0;
  context->emit_setlen = 0;
  context->buf_tracklen = 0;
  context->hd_table_bufsize = 0;
  return 0;
 fail:
  free(context->buf_track);
  free(context->emit_set);
  nghttp2_hd_ringbuf_free(&context->hd_table);
  return NGHTTP2_ERR_NOMEM;
}

int nghttp2_hd_deflate_init(nghttp2_hd_context *deflater, nghttp2_hd_side side)
{
  return nghttp2_hd_context_init(deflater, NGHTTP2_HD_ROLE_DEFLATE, side,
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
  return nghttp2_hd_context_init(inflater, NGHTTP2_HD_ROLE_INFLATE, side, 0);
}

static void nghttp2_hd_context_free(nghttp2_hd_context *context)
{
  size_t i;
  for(i = 0; i < context->buf_tracklen; ++i) {
    free(context->buf_track[i]);
  }
  free(context->buf_track);

  for(i = 0; i < context->emit_setlen; ++i) {
    nghttp2_hd_entry *ent = context->emit_set[i];
    if(--ent->ref == 0) {
      nghttp2_hd_entry_free(ent);
      free(ent);
    }
  }
  free(context->emit_set);

  nghttp2_hd_ringbuf_free(&context->hd_table);
}

void nghttp2_hd_deflate_free(nghttp2_hd_context *deflater)
{
  nghttp2_hd_context_free(deflater);
}

void nghttp2_hd_inflate_free(nghttp2_hd_context *inflater)
{
  nghttp2_hd_context_free(inflater);
}

static size_t entry_room(size_t namelen, size_t valuelen)
{
  return NGHTTP2_HD_ENTRY_OVERHEAD + namelen + valuelen;
}

static int add_nva(nghttp2_nva_out *nva_out_ptr,
                   uint8_t *name, uint16_t namelen,
                   uint8_t *value, uint16_t valuelen)
{
  nghttp2_nv *nv;
  if(nva_out_ptr->nvacap == nva_out_ptr->nvlen) {
    size_t newcap = nva_out_ptr->nvacap == 0 ? 16 : nva_out_ptr->nvacap * 2;
    nghttp2_nv *new_nva = realloc(nva_out_ptr->nva, sizeof(nghttp2_nv)*newcap);
    if(new_nva == NULL) {
      return NGHTTP2_ERR_NOMEM;
    }
    nva_out_ptr->nva = new_nva;
    nva_out_ptr->nvacap = newcap;
  }
  nv = &nva_out_ptr->nva[nva_out_ptr->nvlen++];
  nv->name = name;
  nv->namelen = namelen;
  nv->value = value;
  nv->valuelen = valuelen;
  return 0;
}

static int track_decode_buf(nghttp2_hd_context *context, uint8_t *buf)
{
  if(context->buf_tracklen == context->buf_track_capacity) {
    return NGHTTP2_ERR_HEADER_COMP;
  }
  context->buf_track[context->buf_tracklen++] = buf;
  return 0;
}

static int track_decode_buf2(nghttp2_hd_context *context,
                             uint8_t *buf1, uint8_t *buf2)
{
  if(context->buf_tracklen + 2 > context->buf_track_capacity) {
    return NGHTTP2_ERR_HEADER_COMP;
  }
  context->buf_track[context->buf_tracklen++] = buf1;
  context->buf_track[context->buf_tracklen++] = buf2;
  return 0;
}

static int add_emit_set(nghttp2_hd_context *context, nghttp2_hd_entry *ent)
{
  if(context->emit_setlen == context->emit_set_capacity) {
    return NGHTTP2_ERR_HEADER_COMP;
  }
  context->emit_set[context->emit_setlen++] = ent;
  ++ent->ref;
  return 0;
}

static int emit_indexed_header(nghttp2_hd_context *context,
                               nghttp2_nva_out *nva_out_ptr,
                               nghttp2_hd_entry *ent)
{
  int rv;
  /* ent->ref may be 0. This happens if the careless stupid encoder
     emits literal block larger than header table capacity with
     indexing. */
  rv = add_emit_set(context, ent);
  if(rv != 0) {
    return rv;
  }
  ent->flags |= NGHTTP2_HD_FLAG_EMIT;
  return add_nva(nva_out_ptr,
                 ent->nv.name, ent->nv.namelen,
                 ent->nv.value, ent->nv.valuelen);
}

static int emit_newname_header(nghttp2_hd_context *context,
                               nghttp2_nva_out *nva_out_ptr,
                               nghttp2_nv *nv,
                               uint8_t flags)
{
  int rv;
  rv = add_nva(nva_out_ptr,
               nv->name, nv->namelen, nv->value, nv->valuelen);
  if(rv != 0) {
    return rv;
  }
  if(flags & NGHTTP2_HD_FLAG_NAME_GIFT) {
    if(flags & NGHTTP2_HD_FLAG_VALUE_GIFT) {
      return track_decode_buf2(context, nv->name, nv->value);
    } else {
      return track_decode_buf(context, nv->name);
    }
  } else if(flags & NGHTTP2_HD_FLAG_VALUE_GIFT) {
    return track_decode_buf(context, nv->value);
  }
  return 0;
}

static int emit_indname_header(nghttp2_hd_context *context,
                               nghttp2_nva_out *nva_out_ptr,
                               nghttp2_hd_entry *ent,
                               uint8_t *value, size_t valuelen,
                               uint8_t flags)
{
  int rv;
  rv = add_emit_set(context, ent);
  if(rv != 0) {
    return rv;
  }
  rv = add_nva(nva_out_ptr, ent->nv.name, ent->nv.namelen, value, valuelen);
  if(rv != 0) {
    return rv;
  }
  if(flags & NGHTTP2_HD_FLAG_VALUE_GIFT) {
    return track_decode_buf(context, value);
  }
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

static int emit_indexed_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                              size_t *offset_ptr, size_t index)
{
  int rv;
  uint8_t *bufp;
  size_t blocklen = count_encoded_length(index, 7);
  rv = ensure_write_buffer(buf_ptr, buflen_ptr, *offset_ptr, blocklen);
  if(rv != 0) {
    return rv;
  }
  bufp = *buf_ptr + *offset_ptr;
  *bufp = 0x80u;
  encode_length(bufp, index, 7);
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
    new_ent->flags |= NGHTTP2_HD_FLAG_REFSET;
    nghttp2_hd_ringbuf_push_front(&context->hd_table, new_ent);
    if(room <= context->deflate_hd_table_bufsize_max) {
      context->deflate_hd_table_bufsize += room;
      ++context->deflate_hd_tablelen;
    }
  }
  return new_ent;
}

static ssize_t find_in_hd_table(nghttp2_hd_context *context, nghttp2_nv *nv)
{
  size_t i;
  for(i = 0; i < context->deflate_hd_tablelen; ++i) {
    nghttp2_hd_entry *ent = nghttp2_hd_ringbuf_get(&context->hd_table, i);
    if(nghttp2_nv_equal(&ent->nv, nv)) {
      return i;
    }
  }
  for(i = 0; i < STATIC_TABLE_LENGTH; ++i) {
    nghttp2_hd_entry *ent = &static_table[i];
    if(nghttp2_nv_equal(&ent->nv, nv)) {
      return context->hd_table.len + i;
    }
  }
  return -1;
}

static ssize_t find_name_in_hd_table(nghttp2_hd_context *context,
                                     nghttp2_nv *nv)
{
  size_t i;
  for(i = 0; i < context->deflate_hd_tablelen; ++i) {
    nghttp2_hd_entry *ent = nghttp2_hd_ringbuf_get(&context->hd_table, i);
    if(ent->nv.namelen == nv->namelen &&
       memcmp(ent->nv.name, nv->name, nv->namelen) == 0) {
      return i;
    }
  }
  for(i = 0; i < STATIC_TABLE_LENGTH; ++i) {
    nghttp2_hd_entry *ent = &static_table[i];
    if(ent->nv.namelen == nv->namelen &&
       memcmp(ent->nv.name, nv->name, nv->namelen) == 0) {
      return context->hd_table.len + i;
    }
  }
  return -1;
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
    return &static_table[index - context->hd_table.len];
  }
}

static int deflate_nv(nghttp2_hd_context *deflater,
                      uint8_t **buf_ptr, size_t *buflen_ptr,
                      size_t *offset_ptr,
                      nghttp2_nv *nv)
{
  int rv;
  nghttp2_hd_entry *ent;
  rv = find_in_hd_table(deflater, nv);
  if(rv != -1) {
    size_t index = rv;
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
    rv = find_name_in_hd_table(deflater, nv);
    if(rv != -1) {
      index = rv;
    }
    if(entry_room(nv->namelen, nv->valuelen) <= NGHTTP2_HD_MAX_ENTRY_SIZE) {
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
  for(i = 0; i < nvlen; ++i) {
    rv = deflate_nv(deflater, buf_ptr, buflen_ptr, &offset, &nv[i]);
    if(rv != 0) {
      goto fail;
    }
  }
  for(i = 0; i < deflater->hd_table.len; ++i) {
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

static int inflater_post_process_hd_entry(nghttp2_hd_context *inflater,
                                          nghttp2_hd_entry *ent,
                                          nghttp2_nva_out *nva_out_ptr)
{
  int rv;
  if((ent->flags & NGHTTP2_HD_FLAG_REFSET) &&
     (ent->flags & NGHTTP2_HD_FLAG_EMIT) == 0) {
    rv = emit_indexed_header(inflater, nva_out_ptr, ent);
    if(rv != 0) {
      return rv;
    }
  }
  ent->flags &= ~NGHTTP2_HD_FLAG_EMIT;
  return 0;
}

static ssize_t inflate_decode(uint8_t **dest_ptr, uint8_t *in, size_t inlen,
                              nghttp2_hd_side side)
{
  ssize_t declen = nghttp2_hd_huff_decode_count(in, inlen, side);
  if(declen == -1) {
    return NGHTTP2_ERR_HEADER_COMP;
  }
  *dest_ptr = malloc(declen);
  if(*dest_ptr == NULL) {
    return NGHTTP2_ERR_HEADER_COMP;
  }
  nghttp2_hd_huff_decode(*dest_ptr, declen, in, inlen, side);
  return declen;
}

ssize_t nghttp2_hd_inflate_hd(nghttp2_hd_context *inflater,
                              nghttp2_nv **nva_ptr,
                              uint8_t *in, size_t inlen)
{
  size_t i;
  int rv = 0;
  uint8_t *last = in + inlen;
  nghttp2_nva_out nva_out;
  memset(&nva_out, 0, sizeof(nva_out));
  if(inflater->bad) {
    return NGHTTP2_ERR_HEADER_COMP;
  }
  *nva_ptr = NULL;
  for(; in != last;) {
    uint8_t c = *in;
    if(c & 0x80u) {
      /* Indexed Header Repr */
      ssize_t index;
      nghttp2_hd_entry *ent;
      in = decode_length(&index, in, last, 7);
      if(index < 0) {
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      if(!check_index_range(inflater, index)) {
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
        rv = emit_indexed_header(inflater, &nva_out, new_ent);
      } else {
        ent->flags ^= NGHTTP2_HD_FLAG_REFSET;
        if(ent->flags & NGHTTP2_HD_FLAG_REFSET) {
          rv = emit_indexed_header(inflater, &nva_out, ent);
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
      if(++in == last) {
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      name_huffman = *in & (1 << 7);
      in = decode_length(&namelen, in, last, 7);
      if(namelen < 0 || in + namelen > last) {
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      if(name_huffman) {
        rv = inflate_decode(&nv.name, in, namelen, inflater->side);
        if(rv < 0) {
          goto fail;
        }
        decoded_huffman_name = nv.name;
        nv.namelen = rv;
      } else {
        nv.name = in;
        nv.namelen = namelen;
      }
      in += namelen;

      if(!nghttp2_check_header_name(nv.name, nv.namelen)) {
        free(decoded_huffman_name);
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }

      if(in == last) {
        free(decoded_huffman_name);
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      value_huffman = *in & (1 << 7);
      in = decode_length(&valuelen, in, last, 7);
      if(valuelen < 0 || in + valuelen > last) {
        free(decoded_huffman_name);
        rv =  NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      if(value_huffman) {
        rv = inflate_decode(&nv.value, in, valuelen, inflater->side);
        if(rv < 0) {
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

      nghttp2_downcase(nv.name, nv.namelen);
      if(c == 0x40u) {
        int flags = NGHTTP2_HD_FLAG_NONE;
        if(name_huffman) {
          flags |= NGHTTP2_HD_FLAG_NAME_GIFT;
        }
        if(value_huffman) {
          flags |= NGHTTP2_HD_FLAG_VALUE_GIFT;
        }
        rv = emit_newname_header(inflater, &nva_out, &nv, flags);
        if(rv != 0) {
          free(decoded_huffman_name);
          free(decoded_huffman_value);
        }
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
          rv = emit_indexed_header(inflater, &nva_out, new_ent);
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
      in = decode_length(&index, in, last, 6);
      if(index < 0) {
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      --index;
      if(!check_index_range(inflater, index)) {
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      ent = nghttp2_hd_table_get(inflater, index);
      if(in == last) {
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      value_huffman = *in & (1 << 7);
      in = decode_length(&valuelen, in , last, 7);
      if(valuelen < 0 || in + valuelen > last) {
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      if(value_huffman) {
        rv = inflate_decode(&value, in, valuelen, inflater->side);
        if(rv < 0) {
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
        uint8_t flags = NGHTTP2_HD_FLAG_NONE;
        if(value_huffman) {
          flags = NGHTTP2_HD_FLAG_VALUE_GIFT;
        }
        rv = emit_indname_header(inflater, &nva_out, ent, value, valuelen,
                                 flags);
        if(rv != 0) {
          free(decoded_huffman_value);
        }
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
          rv = emit_indexed_header(inflater, &nva_out, new_ent);
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
  for(i = 0; i < inflater->hd_table.len; ++i) {
    nghttp2_hd_entry *ent = nghttp2_hd_ringbuf_get(&inflater->hd_table, i);
    rv = inflater_post_process_hd_entry(inflater, ent, &nva_out);
    if(rv != 0) {
      goto fail;
    }
  }
  nghttp2_nv_array_sort(nva_out.nva, nva_out.nvlen);
  *nva_ptr = nva_out.nva;
  return nva_out.nvlen;
 fail:
  inflater->bad = 1;
  free(nva_out.nva);
  return rv;
}

int nghttp2_hd_end_headers(nghttp2_hd_context *context)
{
  size_t i;
  for(i = 0; i < context->emit_setlen; ++i) {
    nghttp2_hd_entry *ent = context->emit_set[i];
    if(--ent->ref == 0) {
      nghttp2_hd_entry_free(ent);
      free(ent);
    }
  }
  context->emit_setlen = 0;
  for(i = 0; i < context->buf_tracklen; ++i) {
    free(context->buf_track[i]);
  }
  context->buf_tracklen = 0;
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
