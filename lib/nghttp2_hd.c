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

static const char *reqhd_table[] = {
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
  "keep-alive", "",
  "user-agent", "",
  "proxy-connection", "",
  "referer", "",
  "accept-datetime", "",
  "authorization", "",
  "allow", "",
  "cache-control", "",
  "connection", "",
  "content-length", "",
  "content-md5", "",
  "content-type", "",
  "date", "",
  "expect", "",
  "from", "",
  "if-match", "",
  "if-none-match", "",
  "if-range", "",
  "if-unmodified-since", "",
  "max-forwards", "",
  "pragma", "",
  "proxy-authorization", "",
  "range", "",
  "te", "",
  "upgrade", "",
  "via", "",
  "warning", "",
  NULL
};

static const char *reshd_table[] = {
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
  "content-md5", "",
  "content-range", "",
  "link", "",
  "location", "",
  "p3p", "",
  "pragma", "",
  "proxy-authenticate", "",
  "refresh", "",
  "retry-after", "",
  "strict-transport-security", "",
  "trailer", "",
  "transfer-encoding", "",
  "warning", "",
  "www-authenticate", "",
  NULL
};

int nghttp2_hd_entry_init(nghttp2_hd_entry *ent, uint8_t index, uint8_t flags,
                          uint8_t *name, uint16_t namelen,
                          uint8_t *value, uint16_t valuelen)
{
  int rv = 0;
  if(flags & NGHTTP2_HD_FLAG_NAME_ALLOC) {
    ent->nv.name = nghttp2_memdup(name, namelen);
    if(ent->nv.name == NULL) {
      rv = NGHTTP2_ERR_NOMEM;
      goto fail;
    }
  } else {
    ent->nv.name = name;
  }
  if(flags & NGHTTP2_HD_FLAG_VALUE_ALLOC) {
    ent->nv.value = nghttp2_memdup(value, valuelen);
    if(ent->nv.value == NULL) {
      rv = NGHTTP2_ERR_NOMEM;
      goto fail2;
    }
  } else {
    ent->nv.value = value;
  }
  ent->nv.namelen = namelen;
  ent->nv.valuelen = valuelen;
  ent->ref = 1;
  ent->index = index;
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

static int nghttp2_hd_context_init(nghttp2_hd_context *context,
                                   nghttp2_hd_side side)
{
  int i;
  const char **ini_table;
  context->hd_table = malloc(sizeof(nghttp2_hd_entry*)*
                             NGHTTP2_INITIAL_HD_TABLE_SIZE);
  memset(context->hd_table, 0, sizeof(nghttp2_hd_entry*)*
         NGHTTP2_INITIAL_HD_TABLE_SIZE);
  context->hd_table_capacity = NGHTTP2_INITIAL_HD_TABLE_SIZE;
  context->hd_tablelen = 0;

  context->refset = malloc(sizeof(nghttp2_hd_entry*)*
                           NGHTTP2_INITIAL_REFSET_SIZE);
  context->refset_capacity = NGHTTP2_INITIAL_REFSET_SIZE;
  context->refsetlen = 0;

  context->ws = malloc(sizeof(nghttp2_hd_ws_entry)*NGHTTP2_INITIAL_WS_SIZE);
  context->ws_capacity = NGHTTP2_INITIAL_WS_SIZE;
  context->wslen = 0;

  if(side == NGHTTP2_HD_SIDE_CLIENT) {
    ini_table = reqhd_table;
  } else {
    ini_table = reshd_table;
  }
  context->hd_table_bufsize = 0;
  for(i = 0; ini_table[i]; i += 2) {
    nghttp2_hd_entry *p = malloc(sizeof(nghttp2_hd_entry));
    nghttp2_hd_entry_init(p, i / 2, NGHTTP2_HD_FLAG_NONE,
                          (uint8_t*)ini_table[i], strlen(ini_table[i]),
                          (uint8_t*)ini_table[i + 1],
                          strlen(ini_table[i+1]));
    context->hd_table[context->hd_tablelen++] = p;
    context->hd_table_bufsize += NGHTTP2_HD_ENTRY_OVERHEAD +
      p->nv.namelen + p->nv.valuelen;
  }
  return 0;
}

int nghttp2_hd_deflate_init(nghttp2_hd_context *deflater, nghttp2_hd_side side)
{
  return nghttp2_hd_context_init(deflater, side);
}

int nghttp2_hd_inflate_init(nghttp2_hd_context *inflater, nghttp2_hd_side side)
{
  return nghttp2_hd_context_init(inflater, side^1);
}

static void nghttp2_hd_context_free(nghttp2_hd_context *context)
{
  size_t i;
  for(i = 0; i < context->wslen; ++i) {
    nghttp2_hd_ws_entry *ent = &context->ws[i];
    switch(ent->cat) {
    case NGHTTP2_HD_CAT_INDEXED:
      --ent->indexed.entry->ref;
      if(ent->indexed.entry->ref == 0) {
        nghttp2_hd_entry_free(ent->indexed.entry);
      }
      break;
    case NGHTTP2_HD_CAT_INDNAME:
      --ent->indname.entry->ref;
      if(ent->indname.entry->ref == 0) {
        nghttp2_hd_entry_free(ent->indname.entry);
      }
      break;
    default:
      break;
    }
  }
  for(i = 0; i < context->refsetlen; ++i) {
    nghttp2_hd_entry *ent = context->refset[i];
    --ent->ref;
    if(ent->ref == 0) {
      nghttp2_hd_entry_free(ent);
    }
  }
  for(i = 0; i < context->hd_tablelen; ++i) {
    nghttp2_hd_entry *ent = context->hd_table[i];
    --ent->ref;
    nghttp2_hd_entry_free(ent);
    free(ent);
  }
  free(context->ws);
  free(context->refset);
  free(context->hd_table);
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

static nghttp2_hd_entry* add_hd_table_incremental(nghttp2_hd_context *context,
                                                  nghttp2_nv *nv)
{
  int rv;
  size_t i;
  nghttp2_hd_entry *new_ent;
  size_t room = entry_room(nv->namelen, nv->valuelen);
  if(context->hd_tablelen == context->hd_table_capacity ||
     room > NGHTTP2_HD_MAX_BUFFER_SIZE) {
    return NULL;
  }
  context->hd_table_bufsize += room;
  for(i = 0; i < context->hd_tablelen &&
        context->hd_table_bufsize > NGHTTP2_HD_MAX_BUFFER_SIZE; ++i) {
    nghttp2_hd_entry *ent = context->hd_table[i];
    --ent->ref;
    context->hd_table_bufsize -= entry_room(ent->nv.namelen, ent->nv.valuelen);
    if(ent->ref == 0) {
      nghttp2_hd_entry_free(ent);
      free(ent);
    }
  }
  if(i > 0) {
    size_t j;
    for(j = 0; i < context->hd_tablelen; ++i, ++j) {
      context->hd_table[j] = context->hd_table[i];
      context->hd_table[j]->index = j;
    }
    context->hd_tablelen = j;
  }
  new_ent = malloc(sizeof(nghttp2_hd_entry));
  if(new_ent == NULL) {
    return NULL;
  }
  rv = nghttp2_hd_entry_init(new_ent, context->hd_tablelen,
                             NGHTTP2_HD_FLAG_NAME_ALLOC |
                             NGHTTP2_HD_FLAG_VALUE_ALLOC,
                             nv->name, nv->namelen, nv->value, nv->valuelen);
  if(rv < 0) {
    return NULL;
  }
  context->hd_table[context->hd_tablelen++] = new_ent;
  return new_ent;
}

static nghttp2_hd_entry* add_hd_table_subst(nghttp2_hd_context *context,
                                            nghttp2_nv *nv, size_t subindex)
{
  int rv;
  size_t i;
  int k;
  nghttp2_hd_entry *new_ent;
  size_t room = entry_room(nv->namelen, nv->valuelen);
  if(room > NGHTTP2_HD_MAX_BUFFER_SIZE ||
     context->hd_tablelen <= subindex) {
    return NULL;
  }
  context->hd_table_bufsize -=
    entry_room(context->hd_table[subindex]->nv.namelen,
               context->hd_table[subindex]->nv.valuelen);
  context->hd_table_bufsize += room;
  k = subindex;
  for(i = 0; i < context->hd_tablelen &&
        context->hd_table_bufsize > NGHTTP2_HD_MAX_BUFFER_SIZE; ++i, --k) {
    nghttp2_hd_entry *ent = context->hd_table[i];
    --ent->ref;
    if(i != subindex) {
      context->hd_table_bufsize -= entry_room(ent->nv.namelen,
                                              ent->nv.valuelen);
    }
    if(ent->ref == 0) {
      nghttp2_hd_entry_free(ent);
      free(ent);
    }
  }
  if(i > 0) {
    size_t j;
    if(k < 0) {
      j = 1;
    } else {
      j = 0;
    }
    for(; i < context->hd_tablelen; ++i, ++j) {
      context->hd_table[j] = context->hd_table[i];
      context->hd_table[j]->index = j;
    }
    context->hd_tablelen = j;
  }
  new_ent = malloc(sizeof(nghttp2_hd_entry));
  if(new_ent == NULL) {
    return NULL;
  }
  if(k >= 0) {
    nghttp2_hd_entry *ent = context->hd_table[k];
    if(--ent->ref == 0) {
      nghttp2_hd_entry_free(ent);
      free(ent);
    }
  } else {
    k = 0;
  }
  rv = nghttp2_hd_entry_init(new_ent, k,
                             NGHTTP2_HD_FLAG_NAME_ALLOC |
                             NGHTTP2_HD_FLAG_VALUE_ALLOC,
                             nv->name, nv->namelen, nv->value, nv->valuelen);
  if(rv < 0) {
    return NULL;
  }
  context->hd_table[new_ent->index] = new_ent;
  return new_ent;
}

static int add_workingset(nghttp2_hd_context *context, nghttp2_hd_entry *ent)
{
  nghttp2_hd_ws_entry *ws_ent;
  if(context->wslen == context->ws_capacity) {
    return NGHTTP2_ERR_HEADER_COMP;
  }
  ws_ent = &context->ws[context->wslen++];
  ws_ent->cat = NGHTTP2_HD_CAT_INDEXED;
  ws_ent->indexed.entry = ent;
  ws_ent->indexed.index = ent->index;
  ws_ent->indexed.checked = 1;
  ++ent->ref;
  return 0;
}

static int add_workingset_newname(nghttp2_hd_context *context,
                                  nghttp2_nv *nv)
{
  nghttp2_hd_ws_entry *ws_ent;
  if(context->wslen == context->ws_capacity) {
    return NGHTTP2_ERR_HEADER_COMP;
  }
  ws_ent = &context->ws[context->wslen++];
  ws_ent->cat = NGHTTP2_HD_CAT_NEWNAME;
  ws_ent->newname.nv = *nv;
  return 0;
}

static int add_workingset_indname(nghttp2_hd_context *context,
                                  nghttp2_hd_entry *ent,
                                  uint8_t *value, size_t valuelen)
{
  nghttp2_hd_ws_entry *ws_ent;
  if(context->wslen == context->ws_capacity) {
    return NGHTTP2_ERR_HEADER_COMP;
  }
  ws_ent = &context->ws[context->wslen++];
  ws_ent->cat = NGHTTP2_HD_CAT_INDNAME;
  ws_ent->indname.entry = ent;
  ++ent->ref;
  ws_ent->indname.value = value;
  ws_ent->indname.valuelen = valuelen;
  return 0;
}

static nghttp2_hd_ws_entry* find_in_workingset(nghttp2_hd_context *context,
                                               nghttp2_nv *nv)
{
  size_t i;
  for(i = 0; i < context->wslen; ++i) {
    nghttp2_hd_ws_entry *ent = &context->ws[i];
    switch(ent->cat) {
    case NGHTTP2_HD_CAT_INDEXED:
      if(nghttp2_nv_equal(&ent->indexed.entry->nv, nv)) {
        return ent;
      }
      break;
    case NGHTTP2_HD_CAT_INDNAME:
      if(ent->indname.entry->nv.namelen == nv->namelen &&
         ent->indname.valuelen == nv->valuelen &&
         memcmp(ent->indname.entry->nv.name, nv->name, nv->namelen) == 0 &&
         memcmp(ent->indname.value, nv->value, nv->valuelen) == 0) {
        return ent;
      }
      break;
    case NGHTTP2_HD_CAT_NEWNAME:
      if(nghttp2_nv_equal(&ent->newname.nv, nv)) {
        return ent;
      }
    default:
      break;
    }
  }
  return NULL;
}

static nghttp2_hd_ws_entry* find_in_workingset_by_index
(nghttp2_hd_context *context, size_t index)
{
  size_t i;
  for(i = 0; i < context->wslen; ++i) {
    nghttp2_hd_ws_entry *ent = &context->ws[i];
    /* Compare against *frozen* index, not the current header table
       index. */
    if(ent->cat == NGHTTP2_HD_CAT_INDEXED && ent->indexed.index == index) {
      return ent;
    }
  }
  return NULL;
}

static nghttp2_hd_entry* find_in_hd_table(nghttp2_hd_context *context,
                                          nghttp2_nv *nv)
{
  size_t i;
  for(i = 0; i < context->hd_tablelen; ++i) {
    nghttp2_hd_entry *ent = context->hd_table[i];
    if(nghttp2_nv_equal(&ent->nv, nv)) {
      return ent;
    }
  }
  return NULL;
}

static nghttp2_hd_entry* find_name_in_hd_table(nghttp2_hd_context *context,
                                               nghttp2_nv *nv)
{
  size_t i;
  for(i = 0; i < context->hd_tablelen; ++i) {
    nghttp2_hd_entry *ent = context->hd_table[i];
    if(ent->nv.namelen == nv->namelen &&
       memcmp(ent->nv.name, nv->name, nv->namelen) == 0) {
      return ent;
    }
  }
  return NULL;
}

static int ensure_write_buffer(uint8_t **buf_ptr, size_t *buflen_ptr,
                               size_t offset, size_t need)
{
  int rv;
  if(need + offset > NGHTTP2_MAX_FRAME_SIZE) {
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
  if(n > k) {
    n -= k;
    ++len;
  } else {
    return 1;
  }
  while(n) {
    ++len;
    if(n >= 128) {
      n >>= 7;
    } else {
      break;
    }
  }
  return len;
}

static size_t encode_length(uint8_t *buf, size_t n, int prefix)
{
  size_t k = (1 << prefix) - 1;
  size_t len = 0;
  if(n > k) {
    *buf++ = k;
    n -= k;
    ++len;
  } else {
    *buf++ = n;
    return 1;
  }
  while(n) {
    ++len;
    if(n >= 128) {
      *buf++ = (1 << 7) | (n & 0x7f);
      n >>= 7;
    } else {
      *buf++ = n;
      break;
    }
  }
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
  if(*in == k) {
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
  if(*in & (1 << 7)) {
    *res = -1;
    return 0;
  } else {
    return in + 1;
  }
}

static int emit_indexed_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                              size_t *offset_ptr, nghttp2_hd_entry *ent)
{
  int rv;
  uint8_t *bufp;
  size_t blocklen = count_encoded_length(ent->index, 7);
  rv = ensure_write_buffer(buf_ptr, buflen_ptr, *offset_ptr, blocklen);
  if(rv != 0) {
    return rv;
  }
  bufp = *buf_ptr + *offset_ptr;
  encode_length(bufp, ent->index, 7);
  (*buf_ptr)[*offset_ptr] |= 0x80u;
  *offset_ptr += blocklen;
  return 0;
}

static int emit_indname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                              size_t *offset_ptr, nghttp2_hd_entry *ent,
                              const uint8_t *value, size_t valuelen,
                              int inc_indexing)
{
  int rv;
  uint8_t *bufp;
  size_t blocklen = count_encoded_length(ent->index, 5) +
    count_encoded_length(valuelen, 8) + valuelen;
  rv = ensure_write_buffer(buf_ptr, buflen_ptr, *offset_ptr, blocklen);
  if(rv != 0) {
    return rv;
  }
  bufp = *buf_ptr + *offset_ptr;
  bufp += encode_length(bufp, ent->index + 1, 5);
  bufp += encode_length(bufp, valuelen, 8);
  memcpy(bufp, value, valuelen);
  (*buf_ptr)[*offset_ptr] |= inc_indexing ? 0x40u : 0x60u;
  *offset_ptr += blocklen;
  return 0;
}

static int emit_newname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                              size_t *offset_ptr, nghttp2_nv *nv,
                              int inc_indexing)
{
  int rv;
  uint8_t *bufp;
  size_t blocklen = 1 + count_encoded_length(nv->namelen, 8) + nv->namelen +
    count_encoded_length(nv->valuelen, 8) + nv->valuelen;
  rv = ensure_write_buffer(buf_ptr, buflen_ptr, *offset_ptr, blocklen);
  if(rv != 0) {
    return rv;
  }
  bufp = *buf_ptr + *offset_ptr;
  *bufp++ = inc_indexing ? 0x40u : 0x60u;
  bufp += encode_length(bufp, nv->namelen, 8);
  memcpy(bufp, nv->name, nv->namelen);
  bufp += nv->namelen;
  bufp += encode_length(bufp, nv->valuelen, 8);
  memcpy(bufp, nv->value, nv->valuelen);
  *offset_ptr += blocklen;
  return 0;
}

static int emit_subst_indname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                    size_t *offset_ptr, nghttp2_hd_entry *ent,
                                    const uint8_t *value, size_t valuelen,
                                    size_t index)
{
  int rv;
  uint8_t *bufp;
  size_t blocklen = count_encoded_length(ent->index + 1, 5) +
    count_encoded_length(index, 8) +
    count_encoded_length(valuelen, 8) + valuelen;
  rv = ensure_write_buffer(buf_ptr, buflen_ptr, *offset_ptr, blocklen);
  if(rv != 0) {
    return rv;
  }
  bufp = *buf_ptr + *offset_ptr;
  bufp += encode_length(bufp, ent->index + 1, 5);
  bufp += encode_length(bufp, index, 8);
  bufp += encode_length(bufp, valuelen, 8);
  memcpy(bufp, value, valuelen);
  *offset_ptr += blocklen;
  return 0;
}

static int emit_subst_newname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                    size_t *offset_ptr, nghttp2_nv *nv,
                                    size_t index)
{
  int rv;
  uint8_t *bufp;
  size_t blocklen = 1 + count_encoded_length(nv->namelen, 8) + nv->namelen +
    count_encoded_length(index, 8) +
    count_encoded_length(nv->valuelen, 8) + nv->valuelen;
  rv = ensure_write_buffer(buf_ptr, buflen_ptr, *offset_ptr, blocklen);
  if(rv != 0) {
    return rv;
  }
  bufp = *buf_ptr + *offset_ptr;
  *bufp++ = 0;
  bufp += encode_length(bufp, nv->namelen, 8);
  memcpy(bufp, nv->name, nv->namelen);
  bufp += nv->namelen;
  bufp += encode_length(bufp, index, 8);
  bufp += encode_length(bufp, nv->valuelen, 8);
  memcpy(bufp, nv->value, nv->valuelen);
  *offset_ptr += blocklen;
  return 0;
}

static void create_workingset(nghttp2_hd_context *context)
{
  int i;
  for(i = 0; i < context->refsetlen; ++i) {
    nghttp2_hd_ws_entry *ent = &context->ws[i];
    ent->cat = NGHTTP2_HD_CAT_INDEXED;
    ent->indexed.entry = context->refset[i];
    ent->indexed.index = ent->indexed.entry->index;
    ent->indexed.checked = 0;
    context->refset[i] = NULL;
  }
  context->wslen = context->refsetlen;
  context->refsetlen = 0;
}

static int require_eviction_on_subst(nghttp2_hd_context *context,
                                     nghttp2_nv *nv,
                                     nghttp2_hd_entry *ent)
{
  return context->hd_table_bufsize - entry_room(ent->nv.namelen,
                                                ent->nv.valuelen) +
    entry_room(nv->namelen, nv->valuelen) > NGHTTP2_HD_MAX_BUFFER_SIZE;
}

ssize_t nghttp2_hd_deflate_hd(nghttp2_hd_context *deflater,
                              uint8_t **buf_ptr, size_t *buflen_ptr,
                              size_t nv_offset,
                              nghttp2_nv *nv, size_t nvlen)
{
  size_t i, offset;
  int rv;
  create_workingset(deflater);
  offset = nv_offset;
  for(i = 0; i < nvlen; ++i) {
    nghttp2_hd_ws_entry *ws_ent;
    ws_ent = find_in_workingset(deflater, &nv[i]);
    if(ws_ent) {
      if(ws_ent->cat == NGHTTP2_HD_CAT_INDEXED) {
        ws_ent->indexed.checked = 1;
      }
    } else {
      nghttp2_hd_entry *ent;
      ent = find_in_hd_table(deflater, &nv[i]);
      if(ent) {
        /* If nv[i] is found in hd_table, use Indexed Header repr */
        rv = add_workingset(deflater, ent);
        if(rv < 0) {
          return rv;
        }
        rv = emit_indexed_block(buf_ptr, buflen_ptr, &offset, ent);
        if(rv < 0) {
          return rv;
        }
      } else {
        /* Check name exists in hd_table */
        ent = find_name_in_hd_table(deflater, &nv[i]);
        if(ent) {
          /* As long as no eviction kicked in and the same header
             field name is not indexed and added, perform
             substitution. Since we never evict anything, searching
             ent->index in working set is safe. */
          if(require_eviction_on_subst(deflater, &nv[i], ent) ||
             find_in_workingset_by_index(deflater, ent->index)) {
            rv = emit_indname_block(buf_ptr, buflen_ptr, &offset, ent,
                                    nv[i].value, nv[i].valuelen, 0);
            if(rv < 0) {
              return rv;
            }
          } else {
            nghttp2_hd_entry *new_ent;
            /* No need to increment ent->ref here */
            new_ent = add_hd_table_subst(deflater, &nv[i], ent->index);
            if(!new_ent) {
              return NGHTTP2_ERR_HEADER_COMP;
            }
            rv = add_workingset(deflater, new_ent);
            if(rv < 0) {
              return rv;
            }
            rv = emit_subst_indname_block(buf_ptr, buflen_ptr, &offset,
                                          new_ent,
                                          nv[i].value, nv[i].valuelen,
                                          new_ent->index);
            if(rv < 0) {
              return rv;
            }
          }
        } else {
          rv = emit_newname_block(buf_ptr, buflen_ptr, &offset, &nv[i], 0);
          if(rv < 0) {
            return rv;
          }
        }
      }
    }
  }
  for(i = 0; i < deflater->wslen; ++i) {
    nghttp2_hd_ws_entry *ws_ent = &deflater->ws[i];
    if(ws_ent->cat == NGHTTP2_HD_CAT_INDEXED &&
       !ws_ent->indexed.checked) {
      rv = emit_indexed_block(buf_ptr, buflen_ptr, &offset,
                              ws_ent->indexed.entry);
      if(rv < 0) {
        return rv;
      }
    }
  }
  return offset - nv_offset;
}

static ssize_t build_nv_array(nghttp2_hd_context *inflater,
                              nghttp2_nv **nva_ptr)
{
  int nvlen = 0, i;
  nghttp2_nv *nv;
  for(i = 0; i < inflater->wslen; ++i) {
    nghttp2_hd_ws_entry *ent = &inflater->ws[i];
    if(ent->cat != NGHTTP2_HD_CAT_NONE) {
      ++nvlen;
    }
  }
  *nva_ptr = malloc(sizeof(nghttp2_nv)*nvlen);
  if(*nva_ptr == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  nv = *nva_ptr;
  for(i = 0; i < inflater->wslen; ++i) {
    nghttp2_hd_ws_entry *ent = &inflater->ws[i];
    switch(ent->cat) {
    case NGHTTP2_HD_CAT_INDEXED:
      *nv = ent->indexed.entry->nv;
      ent->indexed.checked = 1;
      ++nv;
      break;
    case NGHTTP2_HD_CAT_INDNAME:
      nv->name = ent->indname.entry->nv.name;
      nv->namelen = ent->indname.entry->nv.namelen;
      nv->value = ent->indname.value;
      nv->valuelen = ent->indname.valuelen;
      ++nv;
      break;
    case NGHTTP2_HD_CAT_NEWNAME:
      *nv = ent->newname.nv;
      ++nv;
      break;
    default:
      break;
    }
  }
  nghttp2_nv_array_sort(*nva_ptr, nvlen);
  return nvlen;
}

ssize_t nghttp2_hd_inflate_hd(nghttp2_hd_context *inflater,
                              nghttp2_nv **nva_ptr,
                              uint8_t *in, size_t inlen)
{
  int rv;
  uint8_t *last = in + inlen;
  create_workingset(inflater);
  for(; in != last;) {
    uint8_t c = *in;
    if(c & 0x80u) {
      /* Indexed Header Repr */
      nghttp2_hd_ws_entry *ws_ent;
      ssize_t index;
      in = decode_length(&index, in, last, 7);
      if(index < 0) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      ws_ent = find_in_workingset_by_index(inflater, index);
      if(ws_ent) {
        assert(ws_ent->cat == NGHTTP2_HD_CAT_INDEXED);
        --ws_ent->indexed.entry->ref;
        if(ws_ent->indexed.entry->ref == 0) {
          nghttp2_hd_entry_free(ws_ent->indexed.entry);
          free(ws_ent->indexed.entry);
        }
        ws_ent->cat = NGHTTP2_HD_CAT_NONE;
      } else {
        nghttp2_hd_entry *ent;
        if(inflater->hd_tablelen <= index) {
          return NGHTTP2_ERR_HEADER_COMP;
        }
        ent = inflater->hd_table[index];
        rv = add_workingset(inflater, ent);
        if(rv < 0) {
          return rv;
        }
      }
    } else if(c == 0x60u || c == 0x40u) {
      /* Literal Header without Indexing - new name or Literal Header
         with incremental indexing - new name */
      nghttp2_nv nv;
      ssize_t namelen, valuelen;
      if(++in == last) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      in = decode_length(&namelen, in, last, 8);
      if(namelen < 0 || in + namelen > last) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      nv.name = in;
      in += namelen;
      in = decode_length(&valuelen, in, last, 8);
      if(valuelen < 0 || in + valuelen > last) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      nv.namelen = namelen;
      nv.value = in;
      nv.valuelen = valuelen;
      in += valuelen;
      nghttp2_downcase(nv.name, nv.namelen);
      if(c == 0x60u) {
        rv = add_workingset_newname(inflater, &nv);
      } else {
        nghttp2_hd_entry *ent = add_hd_table_incremental(inflater, &nv);
        if(ent) {
          rv = add_workingset(inflater, ent);
        } else {
          return NGHTTP2_ERR_HEADER_COMP;
        }
      }
      if(rv < 0) {
        return rv;
      }
    } else if((c & 0x60u) == 0x60u || (c & 0x40) == 0x40u) {
      /* Literal Header without Indexing - indexed name or Literal
         Header with incremental indexing - indexed name */
      nghttp2_hd_entry *ent;
      uint8_t *value;
      ssize_t valuelen;
      ssize_t index;
      in = decode_length(&index, in, last, 5);
      if(index < 0) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      --index;
      if(inflater->hd_tablelen <= index) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      ent = inflater->hd_table[index];
      in = decode_length(&valuelen, in , last, 8);
      if(valuelen < 0 || in + valuelen > last) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      value = in;
      in += valuelen;
      if((c & 0x60u) == 0x60u) {
        rv = add_workingset_indname(inflater, ent, value, valuelen);
      } else {
        nghttp2_nv nv;
        nghttp2_hd_entry *new_ent;
        ++ent->ref;
        nv.name = ent->nv.name;
        nv.namelen = ent->nv.namelen;
        nv.value = value;
        nv.valuelen = valuelen;
        new_ent = add_hd_table_incremental(inflater, &nv);
        if(--ent->ref == 0) {
          nghttp2_hd_entry_free(ent);
          free(ent);
        }
        if(new_ent) {
          rv = add_workingset(inflater, new_ent);
        } else {
          return NGHTTP2_ERR_HEADER_COMP;
        }
      }
      if(rv < 0) {
        return rv;
      }
    } else if(c == 0) {
      /* Literal Header with substitution indexing - new name */
      nghttp2_hd_entry *new_ent;
      nghttp2_nv nv;
      ssize_t namelen, valuelen, subindex;
      if(++in == last) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      in = decode_length(&namelen, in, last, 8);
      if(namelen < 0 || in + namelen > last) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      nv.name = in;
      in += namelen;
      in = decode_length(&subindex, in, last, 8);
      if(subindex < 0) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      in = decode_length(&valuelen, in, last, 8);
      if(valuelen < 0 || in + valuelen > last) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      nv.value = in;
      nv.namelen = namelen;
      nv.valuelen = valuelen;
      in += valuelen;
      nghttp2_downcase(nv.name, nv.namelen);
      new_ent = add_hd_table_subst(inflater, &nv, subindex);
      if(new_ent) {
        rv = add_workingset(inflater, new_ent);
        if(rv < 0) {
          return rv;
        }
      } else {
        return NGHTTP2_ERR_HEADER_COMP;
      }
    } else {
      /* Literal Header with substitution indexing - indexed name */
      nghttp2_hd_entry *ent, *new_ent;
      ssize_t valuelen;
      ssize_t index, subindex;
      nghttp2_nv nv;
      in = decode_length(&index, in, last, 6);
      if(index < 0) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      --index;
      if(inflater->hd_tablelen <= index) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      ent = inflater->hd_table[index];
      in = decode_length(&subindex, in, last, 8);
      if(subindex < 0) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      in = decode_length(&valuelen, in, last, 8);
      if(valuelen < 0 || in + valuelen > last) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      ++ent->ref;
      nv.name = ent->nv.name;
      nv.namelen = ent->nv.namelen;
      nv.value = in;
      nv.valuelen = valuelen;
      in += valuelen;
      new_ent = add_hd_table_subst(inflater, &nv, subindex);
      if(--ent->ref == 0) {
        nghttp2_hd_entry_free(ent);
        free(ent);
      }
      if(new_ent) {
        rv = add_workingset(inflater, new_ent);
        if(rv < 0) {
          return rv;
        }
      } else {
        return NGHTTP2_ERR_HEADER_COMP;
      }
    }
  }
  return build_nv_array(inflater, nva_ptr);
}

int nghttp2_hd_end_headers(nghttp2_hd_context *context)
{
  int i;
  assert(context->refsetlen == 0);
  for(i = 0; i < context->wslen; ++i) {
    nghttp2_hd_ws_entry *ws_ent = &context->ws[i];
    switch(ws_ent->cat) {
    case NGHTTP2_HD_CAT_INDEXED:
      if(ws_ent->indexed.checked == 0 || ws_ent->indexed.entry->ref == 1) {
        --ws_ent->indexed.entry->ref;
        if(ws_ent->indexed.entry->ref == 0) {
          nghttp2_hd_entry_free(ws_ent->indexed.entry);
          free(ws_ent->indexed.entry);
        }
      } else {
        context->refset[context->refsetlen++] = ws_ent->indexed.entry;
      }
      break;
    case NGHTTP2_HD_CAT_INDNAME:
      --ws_ent->indname.entry->ref;
      if(ws_ent->indname.entry->ref == 0) {
        nghttp2_hd_entry_free(ws_ent->indname.entry);
        free(ws_ent->indname.entry);
      }
      break;
    default:
      break;
    }
  }
  context->wslen = 0;
  return 0;
}

int nghttp2_hd_emit_indname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  size_t *offset_ptr, nghttp2_hd_entry *ent,
                                  const uint8_t *value, size_t valuelen,
                                  int inc_indexing)
{
  return emit_indname_block(buf_ptr, buflen_ptr, offset_ptr,
                            ent, value, valuelen, inc_indexing);
}

int nghttp2_hd_emit_newname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  size_t *offset_ptr, nghttp2_nv *nv,
                                  int inc_indexing)
{
  return emit_newname_block(buf_ptr, buflen_ptr, offset_ptr, nv, inc_indexing);
}

int nghttp2_hd_emit_subst_indname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                        size_t *offset_ptr,
                                        nghttp2_hd_entry *ent,
                                        const uint8_t *value, size_t valuelen,
                                        size_t index)
{
  return emit_subst_indname_block(buf_ptr, buflen_ptr, offset_ptr,
                                  ent, value, valuelen, index);
}

int nghttp2_hd_emit_subst_newname_block(uint8_t **buf_ptr, size_t *buflen_ptr,
                                        size_t *offset_ptr, nghttp2_nv *nv,
                                        size_t index)
{
  return emit_subst_newname_block(buf_ptr, buflen_ptr, offset_ptr, nv, index);
}
