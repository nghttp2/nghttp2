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
#include "nghttp2_frame.h"

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#include "nghttp2_helper.h"
#include "nghttp2_net.h"

size_t nghttp2_frame_get_len_size(uint16_t version)
{
  if(NGHTTP2_PROTO_SPDY2 == version) {
    return 2;
  } else if(NGHTTP2_PROTO_SPDY3 == version) {
    return 4;
  } else {
    /* Unsupported version */
    return 0;
  }
}

static uint8_t* nghttp2_pack_str(uint8_t *buf, const char *str, size_t len,
                                 size_t len_size)
{
  nghttp2_frame_put_nv_len(buf, len, len_size);
  buf += len_size;
  memcpy(buf, str, len);
  return buf+len;
}

static void nghttp2_frame_pack_ctrl_hd(uint8_t* buf, const nghttp2_ctrl_hd *hd)
{
  nghttp2_put_uint16be(&buf[0], hd->version);
  buf[0] |= 1 << 7;
  nghttp2_put_uint16be(&buf[2], hd->type);
  nghttp2_put_uint32be(&buf[4], hd->length);
  buf[4] = hd->flags;
}

static void nghttp2_frame_unpack_ctrl_hd(nghttp2_ctrl_hd *hd,
                                         const uint8_t* buf)
{
  hd->version = nghttp2_get_uint16(buf) & NGHTTP2_VERSION_MASK;
  hd->type = nghttp2_get_uint16(&buf[2]);
  hd->flags = buf[4];
  hd->length = nghttp2_get_uint32(&buf[4]) & NGHTTP2_LENGTH_MASK;
}

ssize_t nghttp2_frame_alloc_pack_nv(uint8_t **buf_ptr,
                                    size_t *buflen_ptr,
                                    uint8_t **nvbuf_ptr,
                                    size_t *nvbuflen_ptr,
                                    char **nv, size_t nv_offset,
                                    size_t len_size,
                                    nghttp2_zlib *deflater)
{
  size_t nvspace;
  size_t maxframelen;
  ssize_t framelen;
  int r;
  nvspace = nghttp2_frame_count_nv_space(nv, len_size);
  r = nghttp2_reserve_buffer(nvbuf_ptr, nvbuflen_ptr, nvspace);
  if(r != 0) {
    return NGHTTP2_ERR_NOMEM;
  }
  maxframelen = nv_offset+nghttp2_zlib_deflate_hd_bound(deflater, nvspace);
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, maxframelen);
  if(r != 0) {
    return NGHTTP2_ERR_NOMEM;
  }
  nghttp2_frame_pack_nv(*nvbuf_ptr, nv, len_size);
  framelen = nghttp2_zlib_deflate_hd(deflater,
                                     (*buf_ptr)+nv_offset,
                                     maxframelen-nv_offset,
                                     *nvbuf_ptr, nvspace);
  if(framelen < 0) {
    return framelen;
  }
  framelen += nv_offset;

  if(framelen - NGHTTP2_FRAME_HEAD_LENGTH > NGHTTP2_LENGTH_MASK) {
    /* In SPDY/2 and 3, Max frame size is 2**24 - 1. */
    return NGHTTP2_ERR_FRAME_TOO_LARGE;
  }
  return framelen;
}

int nghttp2_frame_count_unpack_nv_space(size_t *nvlen_ptr, size_t *buflen_ptr,
                                        nghttp2_buffer *in, size_t len_size)
{
  uint32_t n;
  size_t buflen = 0;
  size_t nvlen = 0;
  size_t off = 0;
  size_t inlen = nghttp2_buffer_length(in);
  size_t i;
  nghttp2_buffer_reader reader;
  if(inlen < len_size) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_buffer_reader_init(&reader, in);

  /* TODO limit n in a reasonable number */
  n = nghttp2_frame_get_nv_len(&reader, len_size);
  off += len_size;
  for(i = 0; i < n; ++i) {
    uint32_t len;
    size_t j;
    for(j = 0; j < 2; ++j) {
      if(inlen-off < len_size) {
        return NGHTTP2_ERR_INVALID_FRAME;
      }
      len = nghttp2_frame_get_nv_len(&reader, len_size);
      off += len_size;
      if(inlen-off < len) {
        return NGHTTP2_ERR_INVALID_FRAME;
      }
      buflen += len+1;
      off += len;
      if(j == 0) {
        nghttp2_buffer_reader_advance(&reader, len);
      }
    }
    nvlen += nghttp2_buffer_reader_count(&reader, len, '\0');
    ++nvlen;
  }
  if(inlen == off) {
    *nvlen_ptr = nvlen;
    *buflen_ptr = buflen+(nvlen*2+1)*sizeof(char*);
    return 0;
  } else {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
}

int nghttp2_frame_unpack_nv(char ***nv_ptr, nghttp2_buffer *in,
                            size_t len_size)
{
  size_t nvlen, buflen;
  int r;
  size_t i;
  char *buf, **idx, *data;
  uint32_t n;
  int invalid_header_block = 0;
  nghttp2_buffer_reader reader;
  r = nghttp2_frame_count_unpack_nv_space(&nvlen, &buflen, in, len_size);
  if(r != 0) {
    return r;
  }

  buf = malloc(buflen);
  if(buf == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  nghttp2_buffer_reader_init(&reader, in);
  idx = (char**)buf;
  data = buf+(nvlen*2+1)*sizeof(char*);
  n = nghttp2_frame_get_nv_len(&reader, len_size);
  for(i = 0; i < n; ++i) {
    uint32_t len;
    char *name, *val;
    char *stop;
    int multival;
    len = nghttp2_frame_get_nv_len(&reader, len_size);
    if(len == 0) {
      invalid_header_block = 1;
    }
    name = data;
    nghttp2_buffer_reader_data(&reader, (uint8_t*)data, len);
    for(stop = data+len; data != stop; ++data) {
      unsigned char c = *data;
      if(c < 0x20 || c > 0x7e || ('A' <= c && c <= 'Z')) {
        invalid_header_block = 1;
      }
    }
    *data = '\0';
    ++data;

    len = nghttp2_frame_get_nv_len(&reader, len_size);
    val = data;
    nghttp2_buffer_reader_data(&reader, (uint8_t*)data, len);

    multival = 0;
    for(stop = data+len; data != stop; ++data) {
      if(*data == '\0') {
        *idx++ = name;
        *idx++ = val;
        if(val == data) {
          invalid_header_block = 1;
        }
        val = data+1;
        multival = 1;
      }
    }
    *data = '\0';
    /* Check last header value is empty if NULL separator was
       found. */
    if(multival && val == data) {
      invalid_header_block = 1;
    }
    ++data;

    *idx++ = name;
    *idx++ = val;
  }
  *idx = NULL;
  assert((size_t)((char*)idx - buf) == (nvlen*2)*sizeof(char*));
  *nv_ptr = (char**)buf;
  if(!invalid_header_block) {
    nghttp2_frame_nv_sort(*nv_ptr);
    for(i = 2; i < nvlen*2; i += 2) {
      if(strcmp((*nv_ptr)[i-2], (*nv_ptr)[i]) == 0 &&
         (*nv_ptr)[i-2] != (*nv_ptr)[i]) {
        invalid_header_block = 1;
        break;
      }
    }
  }
  return invalid_header_block ? NGHTTP2_ERR_INVALID_HEADER_BLOCK : 0;
}

size_t nghttp2_frame_count_nv_space(char **nv, size_t len_size)
{
  size_t sum = len_size;
  int i;
  const char *prev = "";
  size_t prevlen = 0;
  size_t prevvallen = 0;
  for(i = 0; nv[i]; i += 2) {
    const char *key = nv[i];
    const char *val = nv[i+1];
    size_t keylen = strlen(key);
    size_t vallen = strlen(val);
    if(prevlen == keylen && memcmp(prev, key, keylen) == 0) {
      if(vallen) {
        if(prevvallen) {
          /* Join previous value, with NULL character */
          sum += vallen+1;
          prevvallen = vallen;
        } else {
          /* Previous value is empty. In this case, drop the
             previous. */
          sum += vallen;
        }
      }
    } else {
      prev = key;
      prevlen = keylen;
      prevvallen = vallen;
      /* SPDY NV header does not include terminating NULL byte */
      sum += keylen+vallen+len_size*2;
    }
  }
  return sum;
}

ssize_t nghttp2_frame_pack_nv(uint8_t *buf, char **nv, size_t len_size)
{
  int i;
  uint8_t *bufp = buf+len_size;
  uint32_t num_nv = 0;
  const char *prev = "";
  uint8_t *cur_vallen_buf = NULL;
  uint32_t cur_vallen = 0;
  size_t prevkeylen = 0;
  size_t prevvallen = 0;
  for(i = 0; nv[i]; i += 2) {
    const char *key = nv[i];
    const char *val = nv[i+1];
    size_t keylen = strlen(key);
    size_t vallen = strlen(val);
    if(prevkeylen == keylen && memcmp(prev, key, keylen) == 0) {
      if(vallen) {
        if(prevvallen) {
          /* Join previous value, with NULL character */
          cur_vallen += vallen+1;
          nghttp2_frame_put_nv_len(cur_vallen_buf, cur_vallen, len_size);
          *bufp = '\0';
          ++bufp;
          memcpy(bufp, val, vallen);
          bufp += vallen;
        } else {
          /* Previous value is empty. In this case, drop the
             previous. */
          cur_vallen += vallen;
          nghttp2_frame_put_nv_len(cur_vallen_buf, cur_vallen, len_size);
          memcpy(bufp, val, vallen);
          bufp += vallen;
        }
      }
    } else {
      ++num_nv;
      bufp = nghttp2_pack_str(bufp, key, keylen, len_size);
      prev = key;
      cur_vallen_buf = bufp;
      cur_vallen = vallen;
      prevkeylen = keylen;
      prevvallen = vallen;
      bufp = nghttp2_pack_str(bufp, val, vallen, len_size);
    }
  }
  nghttp2_frame_put_nv_len(buf, num_nv, len_size);
  return bufp-buf;
}

int nghttp2_frame_is_ctrl_frame(uint8_t first_byte)
{
  return first_byte & 0x80;
}

void nghttp2_frame_nv_del(char **nv)
{
  free(nv);
}

char** nghttp2_frame_nv_copy(const char **nv)
{
  int i;
  char *buf;
  char **idx, *data;
  size_t buflen = 0;
  for(i = 0; nv[i]; ++i) {
    buflen += strlen(nv[i])+1;
  }
  buflen += (i+1)*sizeof(char*);
  buf = malloc(buflen);
  if(buf == NULL) {
    return NULL;
  }
  idx = (char**)buf;
  data = buf+(i+1)*sizeof(char*);

  for(i = 0; nv[i]; ++i) {
    size_t len = strlen(nv[i])+1;
    memcpy(data, nv[i], len);
    *idx++ = data;
    data += len;
  }
  *idx = NULL;
  return (char**)buf;
}

static int nghttp2_string_compar(const void *lhs, const void *rhs)
{
  return strcmp(*(char **)lhs, *(char **)rhs);
}

void nghttp2_frame_nv_sort(char **nv)
{
  int n;
  for(n = 0; nv[n]; ++n);
  qsort(nv, n/2, 2*sizeof(char*), nghttp2_string_compar);
}

void nghttp2_frame_nv_downcase(char **nv)
{
  int i, j;
  for(i = 0; nv[i]; i += 2) {
    for(j = 0; nv[i][j] != '\0'; ++j) {
      if('A' <= nv[i][j] && nv[i][j] <= 'Z') {
        nv[i][j] += 'a'-'A';
      }
    }
  }
}

char** nghttp2_frame_nv_norm_copy(const char **nv)
{
  char **nv_copy;
  nv_copy = nghttp2_frame_nv_copy(nv);
  if(nv_copy != NULL) {
    nghttp2_frame_nv_downcase(nv_copy);
    nghttp2_frame_nv_sort(nv_copy);
  }
  return nv_copy;
}

/* Table to translate SPDY/3 header names to SPDY/2. */
static const char *nghttp2_nv_3to2[] = {
  ":host", "host",
  ":method", "method",
  ":path", "url",
  ":scheme", "scheme",
  ":status", "status",
  ":version", "version",
  NULL
};

void nghttp2_frame_nv_3to2(char **nv)
{
  int i, j;
  for(i = 0; nv[i]; i += 2) {
    for(j = 0; nghttp2_nv_3to2[j]; j += 2) {
      if(strcmp(nv[i], nghttp2_nv_3to2[j]) == 0) {
        nv[i] = (char*)nghttp2_nv_3to2[j+1];
        break;
      }
    }
  }
}

void nghttp2_frame_nv_2to3(char **nv)
{
  int i, j;
  for(i = 0; nv[i]; i += 2) {
    for(j = 0; nghttp2_nv_3to2[j]; j += 2) {
      if(strcmp(nv[i], nghttp2_nv_3to2[j+1]) == 0) {
        nv[i] = (char*)nghttp2_nv_3to2[j];
        break;
      }
    }
  }
}

#define NGHTTP2_HTTPS_PORT 443

int nghttp2_frame_nv_set_origin(char **nv, nghttp2_origin *origin)
{
  int scheme_found, host_found;
  int i;
  scheme_found = host_found = 0;
  for(i = 0; nv[i]; i += 2) {
    if(scheme_found == 0 && strcmp(":scheme", nv[i]) == 0) {
      size_t len = strlen(nv[i+1]);
      if(len <= NGHTTP2_MAX_SCHEME) {
        strcpy(origin->scheme, nv[i+1]);
        scheme_found = 1;
      }
    } else if(host_found == 0 && strcmp(":host", nv[i]) == 0) {
      size_t len = strlen(nv[i+1]);
      char *sep = memchr(nv[i+1], ':', len);
      size_t hostlen;
      if(sep == NULL) {
        origin->port = NGHTTP2_HTTPS_PORT;
        sep = nv[i+1]+len;
      } else {
        unsigned long int port;
        errno = 0;
        port = strtoul(sep+1, NULL, 10);
        if(errno != 0 || port == 0 || port > UINT16_MAX) {
          continue;
        }
        origin->port = port;
      }
      hostlen = sep-nv[i+1];
      if(hostlen > NGHTTP2_MAX_HOSTNAME) {
        continue;
      }
      memcpy(origin->host, nv[i+1], hostlen);
      origin->host[hostlen] = '\0';
      host_found = 1;
    }
  }
  if(scheme_found && host_found) {
    return 0;
  } else {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }
}

void nghttp2_frame_syn_stream_init(nghttp2_syn_stream *frame,
                                   uint16_t version, uint8_t flags,
                                   int32_t stream_id, int32_t assoc_stream_id,
                                   uint8_t pri, char **nv)
{
  memset(frame, 0, sizeof(nghttp2_syn_stream));
  frame->hd.version = version;
  frame->hd.type = NGHTTP2_SYN_STREAM;
  frame->hd.flags = flags;
  frame->stream_id = stream_id;
  frame->assoc_stream_id = assoc_stream_id;
  frame->pri = pri;
  frame->nv = nv;
}

void nghttp2_frame_syn_stream_free(nghttp2_syn_stream *frame)
{
  nghttp2_frame_nv_del(frame->nv);
}

void nghttp2_frame_syn_reply_init(nghttp2_syn_reply *frame,
                                  uint16_t version, uint8_t flags,
                                  int32_t stream_id, char **nv)
{
  memset(frame, 0, sizeof(nghttp2_syn_reply));
  frame->hd.version = version;
  frame->hd.type = NGHTTP2_SYN_REPLY;
  frame->hd.flags = flags;
  frame->stream_id = stream_id;
  frame->nv = nv;
}

void nghttp2_frame_syn_reply_free(nghttp2_syn_reply *frame)
{
  nghttp2_frame_nv_del(frame->nv);
}

void nghttp2_frame_ping_init(nghttp2_ping *frame,
                             uint16_t version, uint32_t unique_id)
{
  memset(frame, 0, sizeof(nghttp2_ping));
  frame->hd.version = version;
  frame->hd.type = NGHTTP2_PING;
  frame->hd.flags = NGHTTP2_CTRL_FLAG_NONE;
  frame->hd.length = 4;
  frame->unique_id = unique_id;
}

void nghttp2_frame_ping_free(nghttp2_ping *frame)
{}

void nghttp2_frame_goaway_init(nghttp2_goaway *frame,
                               uint16_t version, int32_t last_good_stream_id,
                               uint32_t status_code)
{
  memset(frame, 0, sizeof(nghttp2_goaway));
  frame->hd.version = version;
  frame->hd.type = NGHTTP2_GOAWAY;
  if(version == NGHTTP2_PROTO_SPDY2) {
    frame->hd.length = 4;
  } else if(version == NGHTTP2_PROTO_SPDY3) {
    frame->hd.length = 8;
    frame->status_code = status_code;
  } else {
    frame->hd.length = 0;
  }
  frame->last_good_stream_id = last_good_stream_id;
}

void nghttp2_frame_goaway_free(nghttp2_goaway *frame)
{}

void nghttp2_frame_headers_init(nghttp2_headers *frame,
                                uint16_t version, uint8_t flags,
                                int32_t stream_id, char **nv)
{
  memset(frame, 0, sizeof(nghttp2_headers));
  frame->hd.version = version;
  frame->hd.type = NGHTTP2_HEADERS;
  frame->hd.flags = flags;
  frame->stream_id = stream_id;
  frame->nv = nv;
}

void nghttp2_frame_headers_free(nghttp2_headers *frame)
{
  nghttp2_frame_nv_del(frame->nv);
}

void nghttp2_frame_rst_stream_init(nghttp2_rst_stream *frame,
                                   uint16_t version,
                                   int32_t stream_id, uint32_t status_code)
{
  memset(frame, 0, sizeof(nghttp2_rst_stream));
  frame->hd.version = version;
  frame->hd.type = NGHTTP2_RST_STREAM;
  frame->hd.flags = 0;
  frame->hd.length = 8;
  frame->stream_id = stream_id;
  frame->status_code = status_code;
}

void nghttp2_frame_rst_stream_free(nghttp2_rst_stream *frame)
{}

void nghttp2_frame_window_update_init(nghttp2_window_update *frame,
                                      uint16_t version,
                                      int32_t stream_id,
                                      int32_t delta_window_size)
{
  memset(frame, 0, sizeof(nghttp2_window_update));
  frame->hd.version = version;
  frame->hd.type = NGHTTP2_WINDOW_UPDATE;
  frame->hd.flags = 0;
  frame->hd.length = 8;
  frame->stream_id = stream_id;
  frame->delta_window_size = delta_window_size;
}

void nghttp2_frame_window_update_free(nghttp2_window_update *frame)
{}

void nghttp2_frame_settings_init(nghttp2_settings *frame,
                                 uint16_t version, uint8_t flags,
                                 nghttp2_settings_entry *iv, size_t niv)
{
  memset(frame, 0, sizeof(nghttp2_settings));
  frame->hd.version = version;
  frame->hd.type = NGHTTP2_SETTINGS;
  frame->hd.flags = flags;
  frame->hd.length = 4+niv*8;
  frame->niv = niv;
  frame->iv = iv;
}

void nghttp2_frame_settings_free(nghttp2_settings *frame)
{
  free(frame->iv);
}

void nghttp2_frame_credential_init(nghttp2_credential *frame,
                                   uint16_t version, uint16_t slot,
                                   nghttp2_mem_chunk *proof,
                                   nghttp2_mem_chunk *certs,
                                   size_t ncerts)
{
  size_t i;
  memset(frame, 0, sizeof(nghttp2_credential));
  frame->hd.version = version;
  frame->hd.type = NGHTTP2_CREDENTIAL;
  frame->slot = slot;
  frame->proof = *proof;
  frame->certs = certs;
  frame->ncerts = ncerts;
  frame->hd.length = 2+4+frame->proof.length;
  for(i = 0; i < ncerts; ++i) {
    frame->hd.length += 4+frame->certs[i].length;
  }
}

void nghttp2_frame_credential_free(nghttp2_credential *frame)
{
  size_t i;
  free(frame->proof.data);
  for(i = 0; i < frame->ncerts; ++i) {
    free(frame->certs[i].data);
  }
  free(frame->certs);
}

void nghttp2_frame_data_init(nghttp2_data *frame, int32_t stream_id,
                             uint8_t flags,
                             const nghttp2_data_provider *data_prd)
{
  memset(frame, 0, sizeof(nghttp2_data));
  frame->stream_id = stream_id;
  frame->flags = flags;
  frame->data_prd = *data_prd;
}

void nghttp2_frame_data_free(nghttp2_data *frame)
{}

ssize_t nghttp2_frame_pack_syn_stream(uint8_t **buf_ptr,
                                      size_t *buflen_ptr,
                                      uint8_t **nvbuf_ptr,
                                      size_t *nvbuflen_ptr,
                                      nghttp2_syn_stream *frame,
                                      nghttp2_zlib *deflater)
{
  ssize_t framelen;
  size_t len_size = nghttp2_frame_get_len_size(frame->hd.version);
  if(len_size == 0) {
    return NGHTTP2_ERR_UNSUPPORTED_VERSION;
  }
  framelen = nghttp2_frame_alloc_pack_nv(buf_ptr, buflen_ptr,
                                         nvbuf_ptr, nvbuflen_ptr,
                                         frame->nv,
                                         NGHTTP2_SYN_STREAM_NV_OFFSET,
                                         len_size,
                                         deflater);
  if(framelen < 0) {
    return framelen;
  }
  frame->hd.length = framelen-NGHTTP2_FRAME_HEAD_LENGTH;
  memset(*buf_ptr, 0, NGHTTP2_SYN_STREAM_NV_OFFSET);
  /* pack ctrl header after length is determined */
  nghttp2_frame_pack_ctrl_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->stream_id);
  nghttp2_put_uint32be(&(*buf_ptr)[12], frame->assoc_stream_id);
  if(frame->hd.version == NGHTTP2_PROTO_SPDY3) {
    (*buf_ptr)[16] = (frame->pri << 5);
    (*buf_ptr)[17] = frame->slot;
  } else {
    (*buf_ptr)[16] = (frame->pri << 6);
  }
  return framelen;
}

int nghttp2_frame_unpack_syn_stream(nghttp2_syn_stream *frame,
                                    const uint8_t *head, size_t headlen,
                                    const uint8_t *payload, size_t payloadlen,
                                    nghttp2_buffer *inflatebuf)
{
  int r;
  size_t len_size;
  r = nghttp2_frame_unpack_syn_stream_without_nv(frame, head, headlen,
                                                 payload, payloadlen);
  len_size = nghttp2_frame_get_len_size(frame->hd.version);
  if(len_size == 0) {
    return NGHTTP2_ERR_UNSUPPORTED_VERSION;
  }
  if(r == 0) {
    r = nghttp2_frame_unpack_nv(&frame->nv, inflatebuf, len_size);
  }
  return r;
}

int nghttp2_frame_unpack_syn_stream_without_nv(nghttp2_syn_stream *frame,
                                               const uint8_t *head,
                                               size_t headlen,
                                               const uint8_t *payload,
                                               size_t payloadlen)
{
  nghttp2_frame_unpack_ctrl_hd(&frame->hd, head);
  if(headlen + payloadlen != NGHTTP2_SYN_STREAM_NV_OFFSET) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  frame->stream_id = nghttp2_get_uint32(payload) & NGHTTP2_STREAM_ID_MASK;
  frame->assoc_stream_id =
    nghttp2_get_uint32(payload+4) & NGHTTP2_STREAM_ID_MASK;
  if(frame->hd.version == NGHTTP2_PROTO_SPDY3) {
    frame->pri = (*(payload+8) >> 5);
    frame->slot = payload[9];
  } else {
    frame->pri = (*(payload+8) >> 6);
    frame->slot = 0;
  }
  frame->nv = NULL;
  return 0;
}

ssize_t nghttp2_frame_pack_syn_reply(uint8_t **buf_ptr,
                                     size_t *buflen_ptr,
                                     uint8_t **nvbuf_ptr,
                                     size_t *nvbuflen_ptr,
                                     nghttp2_syn_reply *frame,
                                     nghttp2_zlib *deflater)
{
  ssize_t framelen;
  size_t len_size;
  ssize_t nv_offset;
  len_size = nghttp2_frame_get_len_size(frame->hd.version);
  if(len_size == 0) {
    return NGHTTP2_ERR_UNSUPPORTED_VERSION;
  }
  nv_offset = nghttp2_frame_nv_offset(NGHTTP2_SYN_REPLY, frame->hd.version);
  assert(nv_offset > 0);
  framelen = nghttp2_frame_alloc_pack_nv(buf_ptr, buflen_ptr,
                                         nvbuf_ptr, nvbuflen_ptr,
                                         frame->nv, nv_offset,
                                         len_size, deflater);
  if(framelen < 0) {
    return framelen;
  }
  frame->hd.length = framelen-NGHTTP2_FRAME_HEAD_LENGTH;
  memset(*buf_ptr, 0, nv_offset);
  nghttp2_frame_pack_ctrl_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->stream_id);
  return framelen;
}

int nghttp2_frame_unpack_syn_reply(nghttp2_syn_reply *frame,
                                   const uint8_t *head, size_t headlen,
                                   const uint8_t *payload, size_t payloadlen,
                                   nghttp2_buffer *inflatebuf)
{
  int r;
  r = nghttp2_frame_unpack_syn_reply_without_nv(frame, head, headlen,
                                                payload, payloadlen);
  if(r == 0) {
    size_t len_size;
    len_size = nghttp2_frame_get_len_size(frame->hd.version);
    if(len_size == 0) {
      return NGHTTP2_ERR_UNSUPPORTED_VERSION;
    }
    r = nghttp2_frame_unpack_nv(&frame->nv, inflatebuf, len_size);
  }
  return r;
}

int nghttp2_frame_unpack_syn_reply_without_nv(nghttp2_syn_reply *frame,
                                              const uint8_t *head,
                                              size_t headlen,
                                              const uint8_t *payload,
                                              size_t payloadlen)
{
  ssize_t nv_offset;
  nghttp2_frame_unpack_ctrl_hd(&frame->hd, head);
  nv_offset = nghttp2_frame_nv_offset(NGHTTP2_SYN_REPLY, frame->hd.version);
  assert(nv_offset > 0);
  if((ssize_t)(headlen + payloadlen) != nv_offset) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  frame->stream_id = nghttp2_get_uint32(payload) & NGHTTP2_STREAM_ID_MASK;
  frame->nv = NULL;
  return 0;
}

ssize_t nghttp2_frame_pack_ping(uint8_t **buf_ptr, size_t *buflen_ptr,
                                nghttp2_ping *frame)
{
  ssize_t framelen = 12;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_ctrl_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->unique_id);
  return framelen;
}

int nghttp2_frame_unpack_ping(nghttp2_ping *frame,
                              const uint8_t *head, size_t headlen,
                              const uint8_t *payload, size_t payloadlen)
{
  if(payloadlen != 4) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_ctrl_hd(&frame->hd, head);
  frame->unique_id = nghttp2_get_uint32(payload);
  return 0;
}

ssize_t nghttp2_frame_pack_goaway(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  nghttp2_goaway *frame)
{
  ssize_t framelen;
  int r;
  if(frame->hd.version == NGHTTP2_PROTO_SPDY2) {
    framelen = 12;
  } else if(frame->hd.version == NGHTTP2_PROTO_SPDY3) {
    framelen = 16;
  } else {
    return NGHTTP2_ERR_UNSUPPORTED_VERSION;
  }
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_ctrl_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->last_good_stream_id);
  if(frame->hd.version == NGHTTP2_PROTO_SPDY3) {
    nghttp2_put_uint32be(&(*buf_ptr)[12], frame->status_code);
  }
  return framelen;
}

int nghttp2_frame_unpack_goaway(nghttp2_goaway *frame,
                                const uint8_t *head, size_t headlen,
                                const uint8_t *payload, size_t payloadlen)
{
  nghttp2_frame_unpack_ctrl_hd(&frame->hd, head);
  if(frame->hd.version == NGHTTP2_PROTO_SPDY2) {
    if(payloadlen != 4) {
      return NGHTTP2_ERR_INVALID_FRAME;
    }
  } else if(frame->hd.version == NGHTTP2_PROTO_SPDY3) {
    if(payloadlen != 8) {
      return NGHTTP2_ERR_INVALID_FRAME;
    }
  } else {
    return NGHTTP2_ERR_UNSUPPORTED_VERSION;
  }
  frame->last_good_stream_id = nghttp2_get_uint32(payload) &
    NGHTTP2_STREAM_ID_MASK;
  if(frame->hd.version == NGHTTP2_PROTO_SPDY3) {
    frame->status_code = nghttp2_get_uint32(payload+4);
  } else {
    frame->status_code = 0;
  }
  return 0;
}

ssize_t nghttp2_frame_pack_headers(uint8_t **buf_ptr, size_t *buflen_ptr,
                                   uint8_t **nvbuf_ptr, size_t *nvbuflen_ptr,
                                   nghttp2_headers *frame,
                                   nghttp2_zlib *deflater)
{
  ssize_t framelen;
  size_t len_size;
  ssize_t nv_offset;
  len_size = nghttp2_frame_get_len_size(frame->hd.version);
  if(len_size == 0) {
    return NGHTTP2_ERR_UNSUPPORTED_VERSION;
  }
  nv_offset = nghttp2_frame_nv_offset(NGHTTP2_HEADERS, frame->hd.version);
  assert(nv_offset > 0);
  framelen = nghttp2_frame_alloc_pack_nv(buf_ptr, buflen_ptr,
                                         nvbuf_ptr, nvbuflen_ptr,
                                         frame->nv, nv_offset,
                                         len_size, deflater);
  if(framelen < 0) {
    return framelen;
  }
  frame->hd.length = framelen-NGHTTP2_FRAME_HEAD_LENGTH;
  memset(*buf_ptr, 0, nv_offset);
  nghttp2_frame_pack_ctrl_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->stream_id);
  return framelen;
}

int nghttp2_frame_unpack_headers(nghttp2_headers *frame,
                                 const uint8_t *head, size_t headlen,
                                 const uint8_t *payload, size_t payloadlen,
                                 nghttp2_buffer *inflatebuf)
{
  int r;
  r = nghttp2_frame_unpack_headers_without_nv(frame, head, headlen,
                                              payload, payloadlen);
  if(r == 0) {
    size_t len_size;
    len_size = nghttp2_frame_get_len_size(frame->hd.version);
    if(len_size == 0) {
      return NGHTTP2_ERR_UNSUPPORTED_VERSION;
    }
    r = nghttp2_frame_unpack_nv(&frame->nv, inflatebuf, len_size);
  }
  return r;
}

int nghttp2_frame_unpack_headers_without_nv(nghttp2_headers *frame,
                                            const uint8_t *head,
                                            size_t headlen,
                                            const uint8_t *payload,
                                            size_t payloadlen)
{
  ssize_t nv_offset;
  nghttp2_frame_unpack_ctrl_hd(&frame->hd, head);
  nv_offset = nghttp2_frame_nv_offset(NGHTTP2_HEADERS, frame->hd.version);
  assert(nv_offset > 0);
  if((ssize_t)(headlen + payloadlen) != nv_offset) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  frame->stream_id = nghttp2_get_uint32(payload) & NGHTTP2_STREAM_ID_MASK;
  frame->nv = NULL;
  return 0;
}

ssize_t nghttp2_frame_pack_rst_stream(uint8_t **buf_ptr, size_t *buflen_ptr,
                                      nghttp2_rst_stream *frame)
{
  ssize_t framelen = 16;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_ctrl_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->stream_id);
  nghttp2_put_uint32be(&(*buf_ptr)[12], frame->status_code);
  return framelen;
}

int nghttp2_frame_unpack_rst_stream(nghttp2_rst_stream *frame,
                                    const uint8_t *head, size_t headlen,
                                    const uint8_t *payload, size_t payloadlen)
{
  if(payloadlen != 8) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_ctrl_hd(&frame->hd, head);
  frame->stream_id = nghttp2_get_uint32(payload) & NGHTTP2_STREAM_ID_MASK;
  frame->status_code = nghttp2_get_uint32(payload+4);
  return 0;
}

ssize_t nghttp2_frame_pack_window_update(uint8_t **buf_ptr, size_t *buflen_ptr,
                                         nghttp2_window_update *frame)
{
  ssize_t framelen = 16;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_ctrl_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->stream_id);
  nghttp2_put_uint32be(&(*buf_ptr)[12], frame->delta_window_size);
  return framelen;
}

int nghttp2_frame_unpack_window_update(nghttp2_window_update *frame,
                                       const uint8_t *head, size_t headlen,
                                       const uint8_t *payload,
                                       size_t payloadlen)
{
  if(payloadlen != 8) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_ctrl_hd(&frame->hd, head);
  frame->stream_id = nghttp2_get_uint32(payload) & NGHTTP2_STREAM_ID_MASK;
  frame->delta_window_size = nghttp2_get_uint32(&payload[4]) &
    NGHTTP2_DELTA_WINDOW_SIZE_MASK;
  return 0;
}

ssize_t nghttp2_frame_pack_settings(uint8_t **buf_ptr, size_t *buflen_ptr,
                                    nghttp2_settings *frame)
{
  ssize_t framelen = NGHTTP2_FRAME_HEAD_LENGTH+frame->hd.length;
  size_t i;
  int r;
  if(frame->hd.version != NGHTTP2_PROTO_SPDY2 &&
     frame->hd.version != NGHTTP2_PROTO_SPDY3) {
    return NGHTTP2_ERR_UNSUPPORTED_VERSION;
  }
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_ctrl_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->niv);
  if(frame->hd.version == NGHTTP2_PROTO_SPDY2) {
    for(i = 0; i < frame->niv; ++i) {
      int off = i*8;
      /* spdy/2 spec says ID is network byte order, but publicly
         deployed server sends little endian host byte order. */
      (*buf_ptr)[12+off+0] = (frame->iv[i].settings_id) & 0xff;
      (*buf_ptr)[12+off+1] = (frame->iv[i].settings_id >> 8) & 0xff;
      (*buf_ptr)[12+off+2] = (frame->iv[i].settings_id >>16) & 0xff;
      (*buf_ptr)[15+off] = frame->iv[i].flags;
      nghttp2_put_uint32be(&(*buf_ptr)[16+off], frame->iv[i].value);
    }
  } else {
    for(i = 0; i < frame->niv; ++i) {
      int off = i*8;
      nghttp2_put_uint32be(&(*buf_ptr)[12+off], frame->iv[i].settings_id);
      (*buf_ptr)[12+off] = frame->iv[i].flags;
      nghttp2_put_uint32be(&(*buf_ptr)[16+off], frame->iv[i].value);
    }
  }
  return framelen;
}

int nghttp2_frame_unpack_settings(nghttp2_settings *frame,
                                  const uint8_t *head, size_t headlen,
                                  const uint8_t *payload, size_t payloadlen)
{
  size_t i;
  if(payloadlen < 4) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_ctrl_hd(&frame->hd, head);
  if(frame->hd.version != NGHTTP2_PROTO_SPDY2 &&
     frame->hd.version != NGHTTP2_PROTO_SPDY3) {
    return NGHTTP2_ERR_UNSUPPORTED_VERSION;
  }
  frame->niv = nghttp2_get_uint32(payload);
  if(payloadlen != 4+frame->niv*8) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  frame->iv = malloc(frame->niv*sizeof(nghttp2_settings_entry));
  if(frame->iv == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  if(frame->hd.version == NGHTTP2_PROTO_SPDY2) {
    for(i = 0; i < frame->niv; ++i) {
      size_t off = i*8;
      /* ID is little endian. See comments in
         nghttp2_frame_pack_settings(). */
      frame->iv[i].settings_id = payload[4+off] + (payload[4+off+1] << 8)
        +(payload[4+off+2] << 16);
      frame->iv[i].flags = payload[7+off];
      frame->iv[i].value = nghttp2_get_uint32(&payload[8+off]);
    }
  } else {
    for(i = 0; i < frame->niv; ++i) {
      size_t off = i*8;
      frame->iv[i].settings_id = nghttp2_get_uint32(&payload[4+off]) &
        NGHTTP2_SETTINGS_ID_MASK;
      frame->iv[i].flags = payload[4+off];
      frame->iv[i].value = nghttp2_get_uint32(&payload[8+off]);
    }
  }
  return 0;
}

ssize_t nghttp2_frame_pack_credential(uint8_t **buf_ptr, size_t *buflen_ptr,
                                      nghttp2_credential *frame)
{
  ssize_t framelen;
  int r;
  size_t i, offset;
  framelen = NGHTTP2_FRAME_HEAD_LENGTH+2+4+frame->proof.length;
  for(i = 0; i < frame->ncerts; ++i) {
    framelen += 4+frame->certs[i].length;
  }
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_ctrl_hd(*buf_ptr, &frame->hd);
  offset = NGHTTP2_FRAME_HEAD_LENGTH;
  nghttp2_put_uint16be(&(*buf_ptr)[offset], frame->slot);
  offset += 2;
  nghttp2_put_uint32be(&(*buf_ptr)[offset], frame->proof.length);
  offset += 4;
  memcpy(&(*buf_ptr)[offset], frame->proof.data, frame->proof.length);
  offset += frame->proof.length;
  for(i = 0; i < frame->ncerts; ++i) {
    nghttp2_put_uint32be(&(*buf_ptr)[offset], frame->certs[i].length);
    offset += 4;
    memcpy(&(*buf_ptr)[offset], frame->certs[i].data, frame->certs[i].length);
    offset += frame->certs[i].length;
  }
  return framelen;
}

/*
 * Counts number of client certificate in CREDENTIAL frame payload
 * |payload| with length |payloadlen|. The |payload| points to the
 * length of the first certificate. This function also checks the
 * frame payload is properly composed.
 *
 * This function returns the number of certificates in |payload| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGHTTP2_ERR_INVALID_FRAME
 *     The frame payload is invalid.
 */
static int nghttp2_frame_count_unpack_cert(const uint8_t *payload,
                                           size_t payloadlen)
{
  size_t n, offset = 0;
  for(n = 1; 1; ++n) {
    size_t len;
    if(offset+4 > payloadlen) {
      return NGHTTP2_ERR_INVALID_FRAME;
    }
    len = nghttp2_get_uint32(&payload[offset]);
    offset += 4;
    if(len > payloadlen || offset+len > payloadlen) {
      return NGHTTP2_ERR_INVALID_FRAME;
    } else {
      offset += len;
      if(offset == payloadlen) {
        break;
      }
    }
  }
  return n;
}

/*
 * Unpacks client certificates in the |payload| with length
 * |payloadlen|.  First allocates memory to store the |ncerts|
 * certificates.  Stores certificates in the allocated space and set
 * its pointer to |*certs_ptr|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
static int nghttp2_frame_unpack_cert(nghttp2_mem_chunk **certs_ptr,
                                     size_t ncerts,
                                     const uint8_t *payload, size_t payloadlen)
{
  size_t offset, i, j;
  nghttp2_mem_chunk *certs;
  certs = malloc(sizeof(nghttp2_mem_chunk)*ncerts);
  if(certs == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  offset = 0;
  for(i = 0; i < ncerts; ++i) {
    certs[i].length = nghttp2_get_uint32(&payload[offset]);
    offset += 4;
    certs[i].data = malloc(certs[i].length);
    if(certs[i].data == NULL) {
      goto fail;
    }
    memcpy(certs[i].data, &payload[offset], certs[i].length);
    offset += certs[i].length;
  }
  *certs_ptr = certs;
  return 0;
 fail:
  for(j = 0; j < i; ++j) {
    free(certs[j].data);
  }
  free(certs);
  return NGHTTP2_ERR_NOMEM;
}

int nghttp2_frame_unpack_credential(nghttp2_credential *frame,
                                    const uint8_t *head, size_t headlen,
                                    const uint8_t *payload,
                                    size_t payloadlen)
{
  size_t offset;
  int rv;
  if(payloadlen < 10) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_ctrl_hd(&frame->hd, head);
  offset = 0;
  frame->slot = nghttp2_get_uint16(&payload[offset]);
  offset += 2;
  frame->proof.length = nghttp2_get_uint32(&payload[offset]);
  offset += 4;
  if(frame->proof.length > payloadlen ||
     offset+frame->proof.length > payloadlen) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  frame->proof.data = malloc(frame->proof.length);
  if(frame->proof.data == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  memcpy(frame->proof.data, &payload[offset], frame->proof.length);
  offset += frame->proof.length;
  rv = nghttp2_frame_count_unpack_cert(payload+offset, payloadlen-offset);
  if(rv < 0) {
    goto fail;
  }
  frame->ncerts = rv;
  rv = nghttp2_frame_unpack_cert(&frame->certs, frame->ncerts,
                                 payload+offset, payloadlen-offset);
  if(rv != 0) {
    goto fail;
  }
  return 0;
 fail:
  free(frame->proof.data);
  return rv;
}

nghttp2_settings_entry* nghttp2_frame_iv_copy(const nghttp2_settings_entry *iv,
                                              size_t niv)
{
  nghttp2_settings_entry *iv_copy;
  size_t len = niv*sizeof(nghttp2_settings_entry);
  iv_copy = malloc(len);
  if(iv_copy == NULL) {
    return NULL;
  }
  memcpy(iv_copy, iv, len);
  return iv_copy;
}

static int nghttp2_settings_entry_compar(const void *lhs, const void *rhs)
{
  return ((nghttp2_settings_entry *)lhs)->settings_id
    -((nghttp2_settings_entry *)rhs)->settings_id;
}

void nghttp2_frame_iv_sort(nghttp2_settings_entry *iv, size_t niv)
{
  qsort(iv, niv, sizeof(nghttp2_settings_entry), nghttp2_settings_entry_compar);
}

ssize_t nghttp2_frame_nv_offset(nghttp2_frame_type type, uint16_t version)
{
  switch(type) {
  case NGHTTP2_SYN_STREAM:
    return NGHTTP2_SYN_STREAM_NV_OFFSET;
  case NGHTTP2_SYN_REPLY: {
    if(version == NGHTTP2_PROTO_SPDY2) {
      return NGHTTP2_SPDY2_SYN_REPLY_NV_OFFSET;
    } else if(version == NGHTTP2_PROTO_SPDY3) {
      return NGHTTP2_SPDY3_SYN_REPLY_NV_OFFSET;
    }
    break;
    }
  case NGHTTP2_HEADERS: {
    if(version == NGHTTP2_PROTO_SPDY2) {
      return NGHTTP2_SPDY2_HEADERS_NV_OFFSET;
    } else if(version == NGHTTP2_PROTO_SPDY3) {
      return NGHTTP2_SPDY3_HEADERS_NV_OFFSET;
    }
    break;
  }
  default:
    break;
  }
  return -1;
}

int nghttp2_frame_nv_check_null(const char **nv)
{
  size_t i, j;
  for(i = 0; nv[i]; i += 2) {
    if(nv[i][0] == '\0' || nv[i+1] == NULL) {
      return 0;
    }
    for(j = 0; nv[i][j]; ++j) {
      unsigned char c = nv[i][j];
      if(c < 0x20 || c > 0x7e) {
        return 0;
      }
    }
  }
  return 1;
}
