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

static const char *static_table[] = {
  ":scheme", "http",
  ":scheme", "https",
  ":host", "",
  ":path", "/",
  ":method", "GET",
  "accept", "",
  "accept-charset", "",
  "accept-encoding", "",
  "accept-language", "",
  "cookie", "",
  "if-modified-since", "",
  "user-agent", "",
  "referer", "",
  "authorization", "",
  "allow", "",
  "cache-control", "",
  "connection", "",
  "content-length", "",
  "content-type", "",
  "date", "",
  "expect", "",
  "from", "",
  "if-match", "",
  "if-none-match", "",
  "if-range", "",
  "if-unmodified-since", "",
  "max-forwards", "",
  "proxy-authorization", "",
  "range", "",
  "via", "",

  ":status", "200",
  "age", "",
  "cache-control", "",
  "content-length", "",
  "content-type", "",
  "date", "",
  "etag", "",
  "expires", "",
  "last-modified", "",
  "server", "",
  "set-cookie", "",
  "vary", "",
  "via", "",
  "access-control-allow-origin", "",
  "accept-ranges", "",
  "allow", "",
  "connection", "",
  "content-disposition", "",
  "content-encoding", "",
  "content-language", "",
  "content-location", "",
  "content-range", "",
  "link", "",
  "location", "",
  "proxy-authenticate", "",
  "refresh", "",
  "retry-after", "",
  "strict-transport-security", "",
  "transfer-encoding", "",
  "www-authenticate", "",
  NULL
};

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
  if(flags & NGHTTP2_HD_FLAG_NAME_ALLOC) {
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
  if(flags & NGHTTP2_HD_FLAG_VALUE_ALLOC) {
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
                                   nghttp2_hd_side side)
{
  int i;
  int rv;
  context->role = role;
  context->bad = 0;
  rv = nghttp2_hd_ringbuf_init(&context->hd_table,
                               NGHTTP2_INITIAL_HD_TABLE_SIZE);
  if(rv != 0) {
    return rv;
  }
  for(i = 0; static_table[i]; i += 2);
  /* TODO handle nomem */
  context->static_hd_table = malloc(sizeof(nghttp2_hd_entry*)*(i / 2 + 1));
  context->static_hd_table[i / 2] = NULL;

  if(role == NGHTTP2_HD_ROLE_INFLATE) {
    context->emit_set = malloc(sizeof(nghttp2_hd_entry*)*
                               NGHTTP2_INITIAL_EMIT_SET_SIZE);
    if(context->emit_set == NULL) {
      nghttp2_hd_ringbuf_free(&context->hd_table);
      return NGHTTP2_ERR_NOMEM;
    }
    memset(context->emit_set, 0, sizeof(nghttp2_hd_entry*)*
           NGHTTP2_INITIAL_EMIT_SET_SIZE);
    context->emit_set_capacity = NGHTTP2_INITIAL_EMIT_SET_SIZE;
  } else {
    context->emit_set = NULL;
    context->emit_set_capacity = 0;
  }
  context->emit_setlen = 0;

  context->hd_table_bufsize = 0;
  for(i = 0; static_table[i]; i += 2) {
    nghttp2_hd_entry *p = malloc(sizeof(nghttp2_hd_entry));
    if(p == NULL) {
      nghttp2_hd_ringbuf_free(&context->hd_table);
      free(context->emit_set);
      return NGHTTP2_ERR_NOMEM;
    }
    nghttp2_hd_entry_init(p, NGHTTP2_HD_FLAG_NONE,
                          (uint8_t*)static_table[i], strlen(static_table[i]),
                          (uint8_t*)static_table[i + 1],
                          strlen(static_table[i+1]));
    context->static_hd_table[i / 2] = p;
  }
  return 0;
}

int nghttp2_hd_deflate_init(nghttp2_hd_context *deflater, nghttp2_hd_side side)
{
  return nghttp2_hd_context_init(deflater, NGHTTP2_HD_ROLE_DEFLATE, side);
}

int nghttp2_hd_inflate_init(nghttp2_hd_context *inflater, nghttp2_hd_side side)
{
  return nghttp2_hd_context_init(inflater, NGHTTP2_HD_ROLE_INFLATE, side^1);
}

static void nghttp2_hd_context_free(nghttp2_hd_context *context)
{
  size_t i;
  for(i = 0; i < context->emit_setlen; ++i) {
    nghttp2_hd_entry *ent = context->emit_set[i];
    if(--ent->ref == 0) {
      nghttp2_hd_entry_free(ent);
      free(ent);
    }
  }
  nghttp2_hd_ringbuf_free(&context->hd_table);
  free(context->static_hd_table);
  free(context->emit_set);
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
                               nghttp2_nv *nv)
{
  return add_nva(nva_out_ptr,
                 nv->name, nv->namelen, nv->value, nv->valuelen);
}

static int emit_indname_header(nghttp2_hd_context *context,
                               nghttp2_nva_out *nva_out_ptr,
                               nghttp2_hd_entry *ent,
                               uint8_t *value, size_t valuelen)
{
  int rv;
  rv = add_emit_set(context, ent);
  if(rv != 0) {
    return rv;
  }
  return add_nva(nva_out_ptr, ent->nv.name, ent->nv.namelen, value, valuelen);
}


static int ensure_write_buffer(uint8_t **buf_ptr, size_t *buflen_ptr,
                               size_t offset, size_t need)
{
  int rv;
  /* TODO Remove this limitation when header continuation is
     implemented. */
  if(need + offset > NGHTTP2_MAX_HTTP_FRAME_LENGTH) {
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
  size_t len = 0;
  if(prefix > 0) {
    size_t k = (1 << prefix) - 1;
    if(n >= k) {
      n -= k;
      ++len;
    } else {
      return 1;
    }
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
  size_t len = 0;
  if(prefix > 0) {
    size_t k = (1 << prefix) - 1;
    if(n >= k) {
      *buf++ = k;
      n -= k;
      ++len;
    } else {
      *buf++ = n;
      return 1;
    }
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
  if(prefix > 0) {
    if((*in & k) == k) {
      *res = k;
    } else {
      *res = (*in) & k;
      return in + 1;
    }
    ++in;
  } else {
    *res = 0;
  }
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
  if(*in & (1 << 7)) {
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
  encode_length(bufp, index, 7);
  (*buf_ptr)[*offset_ptr] |= 0x80u;
  *offset_ptr += blocklen;
  return 0;
}

static int emit_indname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                              size_t *offset_ptr, size_t index,
                              const uint8_t *value, size_t valuelen,
                              int inc_indexing)
{
  int rv;
  uint8_t *bufp;
  size_t blocklen = count_encoded_length(index + 1, 6) +
    count_encoded_length(valuelen, 0) + valuelen;
  rv = ensure_write_buffer(buf_ptr, buflen_ptr, *offset_ptr, blocklen);
  if(rv != 0) {
    return rv;
  }
  bufp = *buf_ptr + *offset_ptr;
  bufp += encode_length(bufp, index + 1, 6);
  bufp += encode_length(bufp, valuelen, 0);
  memcpy(bufp, value, valuelen);
  if(!inc_indexing) {
    (*buf_ptr)[*offset_ptr] |= 0x40u;
  }
  assert(bufp+valuelen - (*buf_ptr + *offset_ptr) == (ssize_t)blocklen);
  *offset_ptr += blocklen;
  return 0;
}

static int emit_newname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                              size_t *offset_ptr, nghttp2_nv *nv,
                              int inc_indexing)
{
  int rv;
  uint8_t *bufp;
  size_t blocklen = 1 + count_encoded_length(nv->namelen, 0) + nv->namelen +
    count_encoded_length(nv->valuelen, 0) + nv->valuelen;
  rv = ensure_write_buffer(buf_ptr, buflen_ptr, *offset_ptr, blocklen);
  if(rv != 0) {
    return rv;
  }
  bufp = *buf_ptr + *offset_ptr;
  *bufp++ = inc_indexing ? 0 : 0x40u;
  bufp += encode_length(bufp, nv->namelen, 0);
  memcpy(bufp, nv->name, nv->namelen);
  bufp += nv->namelen;
  bufp += encode_length(bufp, nv->valuelen, 0);
  memcpy(bufp, nv->value, nv->valuelen);
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
  context->hd_table_bufsize += room;
  while(context->hd_table_bufsize > NGHTTP2_HD_MAX_BUFFER_SIZE &&
        context->hd_table.len > 0) {
    size_t index = context->hd_table.len - 1;
    nghttp2_hd_entry* ent = nghttp2_hd_ringbuf_get(&context->hd_table, index);
    context->hd_table_bufsize -= entry_room(ent->nv.namelen, ent->nv.valuelen);
    if(context->role == NGHTTP2_HD_ROLE_DEFLATE &&
       (ent->flags & NGHTTP2_HD_FLAG_IMPLICIT_EMIT)) {
      /* Emit common header just before it slips away from the
         table. If we don't do this, we have to emit it in literal
         representation which hurts compression. */
      rv = emit_implicit(buf_ptr, buflen_ptr, offset_ptr, index);
      if(rv != 0) {
        return NULL;
      }
    }
    nghttp2_hd_ringbuf_pop_back(&context->hd_table);
    if(--ent->ref == 0) {
      nghttp2_hd_entry_free(ent);
      free(ent);
    }
  }
  new_ent = malloc(sizeof(nghttp2_hd_entry));
  if(new_ent == NULL) {
    return NULL;
  }
  rv = nghttp2_hd_entry_init(new_ent,
                             entry_flags,
                             nv->name, nv->namelen, nv->value, nv->valuelen);
  if(rv != 0) {
    free(new_ent);
    return NULL;
  }
  if(room > NGHTTP2_HD_MAX_BUFFER_SIZE) {
    /* The entry taking more than NGHTTP2_HD_MAX_BUFFER_SIZE is
       immediately evicted. */
    --new_ent->ref;
  } else {
    new_ent->flags |= NGHTTP2_HD_FLAG_REFSET;
    nghttp2_hd_ringbuf_push_front(&context->hd_table, new_ent);
  }
  return new_ent;
}

static ssize_t find_in_hd_table(nghttp2_hd_context *context, nghttp2_nv *nv)
{
  size_t i;
  for(i = 0; i < context->hd_table.len; ++i) {
    nghttp2_hd_entry *ent = nghttp2_hd_ringbuf_get(&context->hd_table, i);
    if(nghttp2_nv_equal(&ent->nv, nv)) {
      return i;
    }
  }
  for(i = 0; context->static_hd_table[i]; ++i) {
    nghttp2_hd_entry *ent = context->static_hd_table[i];
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
  for(i = 0; i < context->hd_table.len; ++i) {
    nghttp2_hd_entry *ent = nghttp2_hd_ringbuf_get(&context->hd_table, i);
    if(ent->nv.namelen == nv->namelen &&
       memcmp(ent->nv.name, nv->name, nv->namelen) == 0) {
      return i;
    }
  }
  for(i = 0; context->static_hd_table[i]; ++i) {
    nghttp2_hd_entry *ent = context->static_hd_table[i];
    if(ent->nv.namelen == nv->namelen &&
       memcmp(ent->nv.name, nv->name, nv->namelen) == 0) {
      return context->hd_table.len + i;
    }
  }
  return -1;
}

nghttp2_hd_entry* nghttp2_hd_table_get(nghttp2_hd_context *context,
                                       size_t index)
{
  if(index < context->hd_table.len) {
    return nghttp2_hd_ringbuf_get(&context->hd_table, index);
  } else {
    return context->static_hd_table[index - context->hd_table.len];
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
    if((ent->flags & NGHTTP2_HD_FLAG_REFSET) == 0) {
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
      new_ent->flags |= NGHTTP2_HD_FLAG_EMIT;
      incidx = 1;
    }
    if(index == -1) {
      rv = emit_newname_block(buf_ptr, buflen_ptr, offset_ptr, nv, incidx);
    } else {
      rv = emit_indname_block(buf_ptr, buflen_ptr, offset_ptr, index,
                              nv->value, nv->valuelen, incidx);
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
  for(i = 0; deflater->static_hd_table[i]; ++i) {
    nghttp2_hd_entry *ent = deflater->static_hd_table[i];
    rv = deflate_post_process_hd_entry(ent, i + deflater->hd_table.len,
                                       buf_ptr, buflen_ptr, &offset);
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

static int check_index_range(nghttp2_hd_context *context, size_t index)
{
  return index < context->hd_table.len +
    sizeof(static_table)/sizeof(static_table[0])/2;
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
      ent->flags ^= NGHTTP2_HD_FLAG_REFSET;
      if(ent->flags & NGHTTP2_HD_FLAG_REFSET) {
        rv = emit_indexed_header(inflater, &nva_out, ent);
        if(rv != 0) {
          goto fail;
        }
      }
    } else if(c == 0x40u || c == 0) {
      /* Literal Header Repr - New Name */
      nghttp2_nv nv;
      ssize_t namelen, valuelen;
      if(++in == last) {
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      in = decode_length(&namelen, in, last, 0);
      if(namelen < 0 || in + namelen > last) {
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      if(!nghttp2_check_header_name(in, namelen)) {
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      nv.name = in;
      in += namelen;
      in = decode_length(&valuelen, in, last, 0);
      if(valuelen < 0 || in + valuelen > last) {
        rv =  NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      nv.namelen = namelen;
      nv.value = in;
      nv.valuelen = valuelen;
      in += valuelen;
      nghttp2_downcase(nv.name, nv.namelen);
      if(c == 0x40u) {
        rv = emit_newname_header(inflater, &nva_out, &nv);
      } else {
        nghttp2_hd_entry *new_ent;
        new_ent = add_hd_table_incremental(inflater, NULL, NULL, NULL, &nv,
                                           NGHTTP2_HD_FLAG_NAME_ALLOC |
                                           NGHTTP2_HD_FLAG_VALUE_ALLOC);
        if(new_ent) {
          rv = emit_indexed_header(inflater, &nva_out, new_ent);
        } else {
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
      in = decode_length(&valuelen, in , last, 0);
      if(valuelen < 0 || in + valuelen > last) {
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }
      value = in;
      in += valuelen;
      if((c & 0x40u) == 0x40u) {
        rv = emit_indname_header(inflater, &nva_out, ent, value, valuelen);
      } else {
        nghttp2_nv nv;
        nghttp2_hd_entry *new_ent;
        uint8_t ent_flags = NGHTTP2_HD_FLAG_VALUE_ALLOC;
        ++ent->ref;
        if(index >= inflater->hd_table.len) {
          nv.name = nghttp2_hd_table_get(inflater, index)->nv.name;
        } else {
          nv.name = ent->nv.name;
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
  for(i = 0; inflater->static_hd_table[i]; ++i) {
    nghttp2_hd_entry *ent = inflater->static_hd_table[i];
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
  return 0;
}

int nghttp2_hd_emit_indname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  size_t *offset_ptr, size_t index,
                                  const uint8_t *value, size_t valuelen,
                                  int inc_indexing)
{
  return emit_indname_block(buf_ptr, buflen_ptr, offset_ptr,
                            index, value, valuelen, inc_indexing);
}

int nghttp2_hd_emit_newname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  size_t *offset_ptr, nghttp2_nv *nv,
                                  int inc_indexing)
{
  return emit_newname_block(buf_ptr, buflen_ptr, offset_ptr, nv, inc_indexing);
}
