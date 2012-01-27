/*
 * Spdylay - SPDY Library
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
#include "spdylay_frame.h"

#include <arpa/inet.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "spdylay_helper.h"

static uint8_t spdylay_unpack_pri(const uint8_t *data)
{
  return (data[0] >> 6) & 0x3;
}

static uint8_t* spdylay_pack_str(uint8_t *buf, const char *str, size_t len)
{
  spdylay_put_uint16be(buf, len);
  buf += 2;
  memcpy(buf, str, len);
  return buf+len;
}

static void spdylay_frame_pack_ctrl_hd(uint8_t* buf, const spdylay_ctrl_hd *hd)
{
  spdylay_put_uint16be(&buf[0], hd->version);
  buf[0] |= 1 << 7;
  spdylay_put_uint16be(&buf[2], hd->type);
  spdylay_put_uint32be(&buf[4], hd->length);
  buf[4] = hd->flags;
}

static void spdylay_frame_unpack_ctrl_hd(spdylay_ctrl_hd *hd,
                                         const uint8_t* buf)
{
  hd->version = spdylay_get_uint16(buf) & SPDYLAY_VERSION_MASK;
  hd->type = spdylay_get_uint16(&buf[2]);
  hd->flags = buf[4];
  hd->length = spdylay_get_uint32(&buf[4]) & SPDYLAY_LENGTH_MASK;
}

static ssize_t spdylay_frame_alloc_pack_nv(uint8_t **buf_ptr,
                                           char **nv, size_t nv_offset,
                                           spdylay_zlib *deflater)
{
  size_t nvbuflen = spdylay_frame_count_nv_space(nv);
  uint8_t *nvbuf = malloc(nvbuflen);
  size_t maxframelen = nv_offset+
    spdylay_zlib_deflate_hd_bound(deflater, nvbuflen);
  uint8_t *framebuf = malloc(maxframelen);
  ssize_t framelen;
  spdylay_frame_pack_nv(nvbuf, nv);
  framelen = spdylay_zlib_deflate_hd(deflater,
                                     framebuf+nv_offset,
                                     maxframelen-nv_offset,
                                     nvbuf, nvbuflen);
  free(nvbuf);
  if(framelen < 0) {
    free(framebuf);
    return framelen;
  }
  framelen += nv_offset;
  *buf_ptr = framebuf;
  return framelen;
}

int spdylay_frame_unpack_nv(char ***nv_ptr, const uint8_t *in, size_t inlen)
{
  int r = 0;
  uint16_t n;
  size_t off;
  size_t nv_max = 126;
  int i, j, k;
  char *name = NULL, *val = NULL;
  if(inlen < 2) {
    return SPDYLAY_ERR_PROTO;
  }
  memcpy(&n, in, sizeof(uint16_t));
  n = ntohs(n);
  if(n > nv_max) {
    nv_max = n;
  }
  *nv_ptr = malloc(nv_max*sizeof(char*)+1);
  if(*nv_ptr == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  off = 2;
  for(i = 0, j = 0; i < n; ++i) {
    uint16_t nlen, vlen;
    size_t last, len;
    if(off+2 > inlen) {
      r = SPDYLAY_ERR_PROTO;
      break;
    }
    /* For NULL delimited values, they are splitted with each name */
    memcpy(&nlen, &in[off], sizeof(uint16_t));
    nlen = ntohs(nlen);
    off += 2;
    if(off+nlen > inlen || nlen == 0) {
      r = SPDYLAY_ERR_PROTO;
      break;
    }
    name = malloc(nlen+1);
    if(name == NULL) {
      r = SPDYLAY_ERR_NOMEM;
      break;
    }
    memcpy(name, &in[off], nlen);
    name[nlen] = '\0';
    off += nlen;
    if(off+2 > inlen) {
      r = SPDYLAY_ERR_PROTO;
      break;
    }
    memcpy(&vlen, &in[off], sizeof(uint16_t));
    vlen = ntohs(vlen);
    off += 2;
    if(off+vlen > inlen) {
      r = SPDYLAY_ERR_PROTO;
      break;
    }
    for(k = 0, last = off; k < vlen; ++k) {
      size_t len;
      if(in[off+k] == '\0') {
        len = off+k-last;
        if(len == 0) {
          r = SPDYLAY_ERR_PROTO;
          break;
        }
        val = malloc(len+1);
        if(val == NULL) {
          r = SPDYLAY_ERR_NOMEM;
          break;
        }
        memcpy(val, &in[last], len);
        val[len] = '\0';
        if(j >= nv_max) {
          char **nnv;
          nv_max *= 2;
          nnv = realloc(*nv_ptr, nv_max+1);
          if(nnv == NULL) {
            r = SPDYLAY_ERR_NOMEM;
            break;
          } else {
            *nv_ptr = nnv;
          }
        }
        (*nv_ptr)[j] = strdup(name);
        (*nv_ptr)[j+1] = val;
        val = NULL;
        last = off+k+1;
        j += 2;
      }
    }
    if(r != 0) {
      break;
    }
    len = vlen-(last-off);
    if(len == 0) {
      r = SPDYLAY_ERR_PROTO;
      break;
    }
    val = malloc(len+1);
    if(val == NULL) {
      free(name);
      r = SPDYLAY_ERR_NOMEM;
      break;
    }
    memcpy(val, &in[last], len);
    val[len] = '\0';
    if(j >= nv_max) {
      char **nnv;
      nv_max *= 2;
      nnv = realloc(*nv_ptr, nv_max+1);
      if(nnv == NULL) {
        r = SPDYLAY_ERR_NOMEM;
        break;
      } else {
        *nv_ptr = nnv;
      }
    }
    (*nv_ptr)[j] = name;
    (*nv_ptr)[j+1] = val;
    name = val = NULL;
    j += 2;
    off += vlen;
  }
  free(name);
  free(val);
  if(r == 0) {
    (*nv_ptr)[j] = NULL;
  } else {
    for(i = 0; i < j; ++i) {
      free((*nv_ptr)[i]);
    }
    free(*nv_ptr);
  }
  return r;
}

static int spdylay_frame_alloc_unpack_nv(char ***nv_ptr,
                                         const uint8_t *in, size_t inlen,
                                         spdylay_zlib *inflater)
{
  ssize_t r;
  spdylay_buffer outbuffer;
  spdylay_buffer_init(&outbuffer, 4096);
  r = spdylay_zlib_inflate_hd(inflater, &outbuffer, in, inlen);
  if(r < 0) {
    spdylay_buffer_free(&outbuffer);
    return r;
  } else {
    uint8_t *buf = malloc(r);
    if(buf == NULL) {
      spdylay_buffer_free(&outbuffer);
      return SPDYLAY_ERR_NOMEM;
    }
    spdylay_buffer_serialize(&outbuffer, buf);
    spdylay_buffer_free(&outbuffer);
    r = spdylay_frame_unpack_nv(nv_ptr, buf, r);
    free(buf);
    return r;
  }
}

size_t spdylay_frame_count_nv_space(char **nv)
{
  size_t sum = 2;
  int i;
  const char *prev = "";
  size_t prevlen = 0;
  for(i = 0; nv[i]; i += 2) {
    const char *key = nv[i];
    const char *val = nv[i+1];
    size_t keylen = strlen(key);
    size_t vallen = strlen(val);
    if(prevlen == keylen && memcmp(prev, key, keylen) == 0) {
      /* Join previous value, with NULL character */
      sum += vallen+1;
    } else {
      prev = key;
      /* SPDY NV header does not include terminating NULL byte */
      sum += keylen+vallen+4;
    }
  }
  return sum;
}

ssize_t spdylay_frame_pack_nv(uint8_t *buf, char **nv)
{
  int i;
  uint8_t *bufp = buf+2;
  uint16_t num_nv = 0;
  /* TODO Join values with same keys, using '\0' as a delimiter */
  const char *prev = "";
  uint8_t *prev_vallen_buf = NULL;
  uint16_t prev_vallen = 0;
  for(i = 0; nv[i]; i += 2) {
    const char *key = nv[i];
    const char *val = nv[i+1];
    size_t keylen = strlen(key);
    size_t vallen = strlen(val);
    if(strcmp(prev, key) == 0) {
      prev_vallen += vallen+1;
      spdylay_put_uint16be(prev_vallen_buf, prev_vallen);
      *bufp = '\0';
      ++bufp;
      memcpy(bufp, val, vallen);
      bufp += vallen;
    } else {
      ++num_nv;
      bufp = spdylay_pack_str(bufp, key, keylen);
      prev = key;
      prev_vallen_buf = bufp;
      prev_vallen = vallen;
      bufp = spdylay_pack_str(bufp, val, vallen);
    }
  }
  spdylay_put_uint16be(buf, num_nv);
  return bufp-buf;
}

int spdylay_frame_is_ctrl_frame(uint8_t first_byte)
{
  return first_byte & 0x80;
}

void spdylay_frame_nv_free(char **nv)
{
  int i;
  for(i = 0; nv[i]; ++i) {
    free(nv[i]);
  }
}

char** spdylay_frame_nv_copy(const char **nv)
{
  int n, i;
  char **nnv;
  for(n = 0;nv[n]; ++n);
  nnv = malloc((n+1)*sizeof(char*));
  if(nnv == NULL) {
    return NULL;
  }
  for(i = 0; i < n; ++i) {
    nnv[i] = strdup(nv[i]);
    if(nnv[i] == NULL) {
      spdylay_frame_nv_free(nnv);
      free(nnv);
      return NULL;
    }
  }
  nnv[n] = NULL;
  return nnv;
}

static int spdylay_string_compar(const void *lhs, const void *rhs)
{
  return strcmp(*(char **)lhs, *(char **)rhs);
}

void spdylay_frame_nv_sort(char **nv)
{
  int n;
  for(n = 0; nv[n]; ++n);
  qsort(nv, n/2, 2*sizeof(char*), spdylay_string_compar);
}

void spdylay_frame_syn_stream_init(spdylay_syn_stream *frame, uint8_t flags,
                                   int32_t stream_id, int32_t assoc_stream_id,
                                   uint8_t pri, char **nv)
{
  memset(frame, 0, sizeof(spdylay_syn_stream));
  frame->hd.version = SPDYLAY_PROTO_VERSION;
  frame->hd.type = SPDYLAY_SYN_STREAM;
  frame->hd.flags = flags;
  frame->stream_id = stream_id;
  frame->assoc_stream_id = assoc_stream_id;
  frame->pri = pri;
  frame->nv = nv;
}

void spdylay_frame_syn_stream_free(spdylay_syn_stream *frame)
{
  spdylay_frame_nv_free(frame->nv);
  free(frame->nv);
}

void spdylay_frame_syn_reply_init(spdylay_syn_reply *frame, uint8_t flags,
                                  int32_t stream_id, char **nv)
{
  memset(frame, 0, sizeof(spdylay_syn_reply));
  frame->hd.version = SPDYLAY_PROTO_VERSION;
  frame->hd.type = SPDYLAY_SYN_REPLY;
  frame->hd.flags = flags;
  frame->stream_id = stream_id;
  frame->nv = nv;
}

void spdylay_frame_syn_reply_free(spdylay_syn_reply *frame)
{
  spdylay_frame_nv_free(frame->nv);
  free(frame->nv);
}

void spdylay_frame_ping_init(spdylay_ping *frame, uint32_t unique_id)
{
  memset(frame, 0, sizeof(spdylay_ping));
  frame->hd.version = SPDYLAY_PROTO_VERSION;
  frame->hd.type = SPDYLAY_PING;
  frame->hd.flags = SPDYLAY_FLAG_NONE;
  frame->hd.length = 4;
  frame->unique_id = unique_id;
}

void spdylay_frame_ping_free(spdylay_ping *frame)
{}

void spdylay_frame_headers_init(spdylay_headers *frame, uint8_t flags,
                                int32_t stream_id, char **nv)
{
  memset(frame, 0, sizeof(spdylay_headers));
  frame->hd.version = SPDYLAY_PROTO_VERSION;
  frame->hd.type = SPDYLAY_HEADERS;
  frame->hd.flags = flags;
  frame->stream_id = stream_id;
  frame->nv = nv;
}

void spdylay_frame_headers_free(spdylay_headers *frame)
{
  spdylay_frame_nv_free(frame->nv);
  free(frame->nv);
}

void spdylay_frame_rst_stream_init(spdylay_rst_stream *frame,
                                   int32_t stream_id, uint32_t status_code)
{
  memset(frame, 0, sizeof(spdylay_rst_stream));
  frame->hd.version = SPDYLAY_PROTO_VERSION;
  frame->hd.type = SPDYLAY_RST_STREAM;
  frame->hd.flags = 0;
  frame->hd.length = 8;
  frame->stream_id = stream_id;
  frame->status_code = status_code;
}

void spdylay_frame_rst_stream_free(spdylay_rst_stream *frame)
{}

void spdylay_frame_data_init(spdylay_data *frame, int32_t stream_id,
                             spdylay_data_provider *data_prd)
{
  memset(frame, 0, sizeof(spdylay_data));
  frame->stream_id = stream_id;
  frame->data_prd = *data_prd;
}

void spdylay_frame_data_free(spdylay_data *frame)
{}

#define SPDYLAY_SYN_STREAM_NV_OFFSET 18

ssize_t spdylay_frame_pack_syn_stream(uint8_t **buf_ptr,
                                      spdylay_syn_stream *frame,
                                      spdylay_zlib *deflater)
{
  uint8_t *framebuf = NULL;
  ssize_t framelen;
  framelen = spdylay_frame_alloc_pack_nv(&framebuf, frame->nv,
                                         SPDYLAY_SYN_STREAM_NV_OFFSET,
                                         deflater);
  if(framelen < 0) {
    return framelen;
  }
  frame->hd.length = framelen-SPDYLAY_FRAME_HEAD_LENGTH;
  memset(framebuf, 0, SPDYLAY_SYN_STREAM_NV_OFFSET);
  /* pack ctrl header after length is determined */
  spdylay_frame_pack_ctrl_hd(framebuf, &frame->hd);
  spdylay_put_uint32be(&framebuf[8], frame->stream_id);
  spdylay_put_uint32be(&framebuf[12], frame->assoc_stream_id);
  framebuf[16] = (frame->pri << 6);

  *buf_ptr = framebuf;
  return framelen;
}

int spdylay_frame_unpack_syn_stream(spdylay_syn_stream *frame,
                                    const uint8_t *head, size_t headlen,
                                    const uint8_t *payload, size_t payloadlen,
                                    spdylay_zlib *inflater)
{
  int r;
  if(payloadlen < 12) {
    return SPDYLAY_ERR_INVALID_FRAME;
  }
  spdylay_frame_unpack_ctrl_hd(&frame->hd, head);
  frame->stream_id = spdylay_get_uint32(payload) & SPDYLAY_STREAM_ID_MASK;
  frame->assoc_stream_id =
    spdylay_get_uint32(payload+4) & SPDYLAY_STREAM_ID_MASK;
  frame->pri = spdylay_unpack_pri(payload+8);
  r = spdylay_frame_alloc_unpack_nv(&frame->nv, payload+10, payloadlen-10,
                                    inflater);
  return r;
}

#define SPDYLAY_SYN_REPLY_NV_OFFSET 14

ssize_t spdylay_frame_pack_syn_reply(uint8_t **buf_ptr,
                                     spdylay_syn_reply *frame,
                                     spdylay_zlib *deflater)
{
  uint8_t *framebuf = NULL;
  ssize_t framelen;
  framelen = spdylay_frame_alloc_pack_nv(&framebuf, frame->nv,
                                         SPDYLAY_SYN_REPLY_NV_OFFSET, deflater);
  if(framelen < 0) {
    return framelen;
  }
  frame->hd.length = framelen-SPDYLAY_FRAME_HEAD_LENGTH;
  memset(framebuf, 0, SPDYLAY_SYN_REPLY_NV_OFFSET);
  spdylay_frame_pack_ctrl_hd(framebuf, &frame->hd);
  spdylay_put_uint32be(&framebuf[8], frame->stream_id);
  *buf_ptr = framebuf;
  return framelen;
}

int spdylay_frame_unpack_syn_reply(spdylay_syn_reply *frame,
                                   const uint8_t *head, size_t headlen,
                                   const uint8_t *payload, size_t payloadlen,
                                   spdylay_zlib *inflater)
{
  int r;
  if(payloadlen < 8) {
    return SPDYLAY_ERR_INVALID_FRAME;
  }
  spdylay_frame_unpack_ctrl_hd(&frame->hd, head);
  frame->stream_id = spdylay_get_uint32(payload) & SPDYLAY_STREAM_ID_MASK;
  r = spdylay_frame_alloc_unpack_nv(&frame->nv, payload+6, payloadlen-6,
                                    inflater);
  return r;
}

ssize_t spdylay_frame_pack_ping(uint8_t **buf_ptr, spdylay_ping *frame)
{
  uint8_t *framebuf = NULL;
  ssize_t framelen = 12;
  framebuf = malloc(framelen);
  if(framebuf == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  memset(framebuf, 0, framelen);
  spdylay_frame_pack_ctrl_hd(framebuf, &frame->hd);
  spdylay_put_uint32be(&framebuf[8], frame->unique_id);
  *buf_ptr = framebuf;
  return framelen;
}

int spdylay_frame_unpack_ping(spdylay_ping *frame,
                              const uint8_t *head, size_t headlen,
                              const uint8_t *payload, size_t payloadlen)
{
  if(payloadlen < 4) {
    return SPDYLAY_ERR_INVALID_FRAME;
  }
  spdylay_frame_unpack_ctrl_hd(&frame->hd, head);
  frame->unique_id = spdylay_get_uint32(payload);
  return 0;
}

#define SPDYLAY_HEADERS_NV_OFFSET 14

ssize_t spdylay_frame_pack_headers(uint8_t **buf_ptr,
                                   spdylay_headers *frame,
                                   spdylay_zlib *deflater)
{
  uint8_t *framebuf = NULL;
  ssize_t framelen;
  framelen = spdylay_frame_alloc_pack_nv(&framebuf, frame->nv,
                                         SPDYLAY_HEADERS_NV_OFFSET, deflater);
  if(framelen < 0) {
    return framelen;
  }
  frame->hd.length = framelen-SPDYLAY_FRAME_HEAD_LENGTH;
  memset(framebuf, 0, SPDYLAY_HEADERS_NV_OFFSET);
  spdylay_frame_pack_ctrl_hd(framebuf, &frame->hd);
  spdylay_put_uint32be(&framebuf[8], frame->stream_id);
  *buf_ptr = framebuf;
  return framelen;
}

int spdylay_frame_unpack_headers(spdylay_headers *frame,
                                 const uint8_t *head, size_t headlen,
                                 const uint8_t *payload, size_t payloadlen,
                                 spdylay_zlib *inflater)
{
  int r;
  if(payloadlen < 8) {
    return SPDYLAY_ERR_INVALID_FRAME;
  }
  spdylay_frame_unpack_ctrl_hd(&frame->hd, head);
  frame->stream_id = spdylay_get_uint32(payload) & SPDYLAY_STREAM_ID_MASK;
  r = spdylay_frame_alloc_unpack_nv(&frame->nv, payload+6, payloadlen-6,
                                    inflater);
  return r;
}

ssize_t spdylay_frame_pack_rst_stream(uint8_t **buf_ptr,
                                      spdylay_rst_stream *frame)
{
  uint8_t *framebuf;
  ssize_t framelen = 16;
  framebuf = malloc(framelen);
  if(framebuf == NULL) {
    return SPDYLAY_ERR_NOMEM;
  }
  memset(framebuf, 0, framelen);
  spdylay_frame_pack_ctrl_hd(framebuf, &frame->hd);
  spdylay_put_uint32be(&framebuf[8], frame->stream_id);
  spdylay_put_uint32be(&framebuf[12], frame->status_code);
  *buf_ptr = framebuf;
  return framelen;
}

int spdylay_frame_unpack_rst_stream(spdylay_rst_stream *frame,
                                    const uint8_t *head, size_t headlen,
                                    const uint8_t *payload, size_t payloadlen)
{
  if(payloadlen < 8) {
    return SPDYLAY_ERR_INVALID_FRAME;
  }
  spdylay_frame_unpack_ctrl_hd(&frame->hd, head);
  frame->stream_id = spdylay_get_uint32(payload) & SPDYLAY_STREAM_ID_MASK;
  frame->status_code = spdylay_get_uint32(payload+4);
  return 0;
}
