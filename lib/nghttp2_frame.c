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
#include "nghttp2_frame.h"

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#include "nghttp2_helper.h"
#include "nghttp2_net.h"

/* This is SPDY stuff, and will be removed after header compression is
   implemented */
static size_t nghttp2_frame_get_len_size(void)
{
  return 2;
}

static uint8_t* nghttp2_pack_str(uint8_t *buf, const char *str, size_t len)
{
  nghttp2_frame_put_nv_len(buf, len);
  buf += nghttp2_frame_get_len_size();
  memcpy(buf, str, len);
  return buf+len;
}

int nghttp2_frame_is_data_frame(uint8_t *head)
{
  return head[2] == 0;
}

void nghttp2_frame_pack_frame_hd(uint8_t* buf, const nghttp2_frame_hd *hd)
{
  nghttp2_put_uint16be(&buf[0], hd->length);
  buf[2]=  hd->type;
  buf[3] = hd->flags;
  nghttp2_put_uint32be(&buf[4], hd->stream_id);
}

void nghttp2_frame_unpack_frame_hd(nghttp2_frame_hd *hd, const uint8_t* buf)
{
  hd->length = nghttp2_get_uint16(&buf[0]);
  hd->type = buf[2];
  hd->flags = buf[3];
  hd->stream_id = nghttp2_get_uint32(&buf[4]) & NGHTTP2_STREAM_ID_MASK;
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

  if(framelen - NGHTTP2_FRAME_HEAD_LENGTH >= 1 << 16) {
    /* Max frame size is 2**16 - 1 */
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
  n = nghttp2_frame_get_nv_len(&reader);
  off += len_size;
  for(i = 0; i < n; ++i) {
    uint32_t len;
    size_t j;
    for(j = 0; j < 2; ++j) {
      if(inlen-off < len_size) {
        return NGHTTP2_ERR_INVALID_FRAME;
      }
      len = nghttp2_frame_get_nv_len(&reader);
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
  n = nghttp2_frame_get_nv_len(&reader);
  for(i = 0; i < n; ++i) {
    uint32_t len;
    char *name, *val;
    char *stop;
    int multival;
    len = nghttp2_frame_get_nv_len(&reader);
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

    len = nghttp2_frame_get_nv_len(&reader);
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
          nghttp2_frame_put_nv_len(cur_vallen_buf, cur_vallen);
          *bufp = '\0';
          ++bufp;
          memcpy(bufp, val, vallen);
          bufp += vallen;
        } else {
          /* Previous value is empty. In this case, drop the
             previous. */
          cur_vallen += vallen;
          nghttp2_frame_put_nv_len(cur_vallen_buf, cur_vallen);
          memcpy(bufp, val, vallen);
          bufp += vallen;
        }
      }
    } else {
      ++num_nv;
      bufp = nghttp2_pack_str(bufp, key, keylen);
      prev = key;
      cur_vallen_buf = bufp;
      cur_vallen = vallen;
      prevkeylen = keylen;
      prevvallen = vallen;
      bufp = nghttp2_pack_str(bufp, val, vallen);
    }
  }
  nghttp2_frame_put_nv_len(buf, num_nv);
  return bufp-buf;
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

static void nghttp2_frame_set_hd(nghttp2_frame_hd *hd, uint16_t length,
                                 uint8_t type, uint8_t flags,
                                 int32_t stream_id)
{
  hd->length = length;
  hd->type = type;
  hd->flags = flags;
  hd->stream_id = stream_id;
}

void nghttp2_frame_headers_init(nghttp2_headers *frame,
                                uint8_t flags, int32_t stream_id, int32_t pri,
                                char **nv)
{
  memset(frame, 0, sizeof(nghttp2_headers));
  nghttp2_frame_set_hd(&frame->hd, 0, NGHTTP2_HEADERS, flags, stream_id);
  frame->pri = pri;
  frame->nv = nv;
  frame->cat = NGHTTP2_HCAT_START_STREAM;
}

void nghttp2_frame_headers_free(nghttp2_headers *frame)
{
  nghttp2_frame_nv_del(frame->nv);
}

void nghttp2_frame_priority_init(nghttp2_priority *frame, int32_t stream_id,
                                 int32_t pri)
{
  memset(frame, 0, sizeof(nghttp2_priority));
  nghttp2_frame_set_hd(&frame->hd, 4, NGHTTP2_PRIORITY, NGHTTP2_FLAG_NONE,
                       stream_id);
  frame->pri = pri;
}

void nghttp2_frame_priority_free(nghttp2_priority *frame)
{}

void nghttp2_frame_rst_stream_init(nghttp2_rst_stream *frame,
                                   int32_t stream_id,
                                   nghttp2_error_code error_code)
{
  memset(frame, 0, sizeof(nghttp2_rst_stream));
  nghttp2_frame_set_hd(&frame->hd, 4, NGHTTP2_RST_STREAM, NGHTTP2_FLAG_NONE,
                       stream_id);
  frame->error_code = error_code;
}

void nghttp2_frame_rst_stream_free(nghttp2_rst_stream *frame)
{}


void nghttp2_frame_settings_init(nghttp2_settings *frame,
                                 nghttp2_settings_entry *iv, size_t niv)
{
  memset(frame, 0, sizeof(nghttp2_settings));
  nghttp2_frame_set_hd(&frame->hd, niv*8, NGHTTP2_SETTINGS, NGHTTP2_FLAG_NONE,
                       0);
  frame->niv = niv;
  frame->iv = iv;
}

void nghttp2_frame_settings_free(nghttp2_settings *frame)
{
  free(frame->iv);
}


void nghttp2_frame_ping_init(nghttp2_ping *frame, uint8_t flags,
                             const uint8_t *opaque_data)
{
  memset(frame, 0, sizeof(nghttp2_ping));
  nghttp2_frame_set_hd(&frame->hd, 8, NGHTTP2_PING, flags, 0);
  if(opaque_data) {
    memcpy(frame->opaque_data, opaque_data, sizeof(frame->opaque_data));
  }
}

void nghttp2_frame_ping_free(nghttp2_ping *frame)
{}

void nghttp2_frame_goaway_init(nghttp2_goaway *frame, int32_t last_stream_id,
                               nghttp2_error_code error_code,
                               uint8_t *opaque_data, size_t opaque_data_len)
{
  memset(frame, 0, sizeof(nghttp2_goaway));
  nghttp2_frame_set_hd(&frame->hd, 8+opaque_data_len, NGHTTP2_GOAWAY,
                       NGHTTP2_FLAG_NONE, 0);
  frame->last_stream_id = last_stream_id;
  frame->error_code = error_code;
  frame->opaque_data = opaque_data;
  frame->opaque_data_len = opaque_data_len;
}

void nghttp2_frame_goaway_free(nghttp2_goaway *frame)
{
  free(frame->opaque_data);
}

void nghttp2_frame_window_update_init(nghttp2_window_update *frame,
                                      uint8_t flags,
                                      int32_t stream_id,
                                      int32_t window_size_increment)
{
  memset(frame, 0, sizeof(nghttp2_window_update));
  nghttp2_frame_set_hd(&frame->hd, 4, NGHTTP2_WINDOW_UPDATE, flags, stream_id);
  frame->window_size_increment = window_size_increment;
}

void nghttp2_frame_window_update_free(nghttp2_window_update *frame)
{}

void nghttp2_frame_data_init(nghttp2_data *frame, uint8_t flags,
                             int32_t stream_id,
                             const nghttp2_data_provider *data_prd)
{
  memset(frame, 0, sizeof(nghttp2_data));
  /* At this moment, the length of DATA frame is unknown */
  nghttp2_frame_set_hd(&frame->hd, 0, NGHTTP2_DATA, flags, stream_id);
  frame->data_prd = *data_prd;
}

void nghttp2_frame_data_free(nghttp2_data *frame)
{}

ssize_t nghttp2_frame_pack_headers(uint8_t **buf_ptr,
                                   size_t *buflen_ptr,
                                   uint8_t **nvbuf_ptr,
                                   size_t *nvbuflen_ptr,
                                   nghttp2_headers *frame,
                                   nghttp2_zlib *deflater)
{
  ssize_t framelen;
  size_t len_size = nghttp2_frame_get_len_size();
  ssize_t nv_offset;
  if(frame->hd.flags & NGHTTP2_FLAG_PRIORITY) {
    nv_offset = NGHTTP2_FRAME_HEAD_LENGTH + 4;
  } else {
    nv_offset = NGHTTP2_FRAME_HEAD_LENGTH;
  }
  framelen = nghttp2_frame_alloc_pack_nv(buf_ptr, buflen_ptr,
                                         nvbuf_ptr, nvbuflen_ptr,
                                         frame->nv,
                                         nv_offset,
                                         len_size,
                                         deflater);
  if(framelen < 0) {
    return framelen;
  }
  frame->hd.length = framelen - NGHTTP2_FRAME_HEAD_LENGTH;
  memset(*buf_ptr, 0, nv_offset);
  /* pack ctrl header after length is determined */
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  if(frame->hd.flags & NGHTTP2_FLAG_PRIORITY) {
    nghttp2_put_uint32be(&(*buf_ptr)[8], frame->pri);
  }
  return framelen;
}

int nghttp2_frame_unpack_headers(nghttp2_headers *frame,
                                 const uint8_t *head, size_t headlen,
                                 const uint8_t *payload, size_t payloadlen,
                                 nghttp2_buffer *inflatebuf)
{
  int r;
  size_t len_size = nghttp2_frame_get_len_size();
  r = nghttp2_frame_unpack_headers_without_nv(frame, head, headlen,
                                              payload, payloadlen);
  if(r == 0) {
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
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  if(head[3] & NGHTTP2_FLAG_PRIORITY) {
    if(payloadlen != 4) {
      return NGHTTP2_ERR_INVALID_FRAME;
    }
    frame->pri = nghttp2_get_uint32(payload) & NGHTTP2_PRIORITY_MASK;
  } else {
    if(payloadlen != 0) {
      return NGHTTP2_ERR_INVALID_FRAME;
    }
    frame->pri = NGHTTP2_PRI_DEFAULT;
  }
  frame->nv = NULL;
  return 0;
}

ssize_t nghttp2_frame_pack_priority(uint8_t **buf_ptr, size_t *buflen_ptr,
                                    nghttp2_priority *frame)
{
  ssize_t framelen= NGHTTP2_FRAME_HEAD_LENGTH + 4;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->pri);
  return framelen;
}

int nghttp2_frame_unpack_priority(nghttp2_priority *frame,
                                  const uint8_t *head, size_t headlen,
                                  const uint8_t *payload, size_t payloadlen)
{
  if(payloadlen != 4) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  frame->pri = nghttp2_get_uint32(payload) & NGHTTP2_PRIORITY_MASK;
  return 0;

}

ssize_t nghttp2_frame_pack_rst_stream(uint8_t **buf_ptr, size_t *buflen_ptr,
                                      nghttp2_rst_stream *frame)
{
  ssize_t framelen = NGHTTP2_FRAME_HEAD_LENGTH + 4;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->error_code);
  return framelen;
}

int nghttp2_frame_unpack_rst_stream(nghttp2_rst_stream *frame,
                                    const uint8_t *head, size_t headlen,
                                    const uint8_t *payload, size_t payloadlen)
{
  if(payloadlen != 4) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  frame->error_code = nghttp2_get_uint32(payload);
  return 0;
}

ssize_t nghttp2_frame_pack_settings(uint8_t **buf_ptr, size_t *buflen_ptr,
                                    nghttp2_settings *frame)
{
  ssize_t framelen = NGHTTP2_FRAME_HEAD_LENGTH + frame->hd.length;
  size_t i;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  for(i = 0; i < frame->niv; ++i) {
    int off = i*8;
    nghttp2_put_uint32be(&(*buf_ptr)[8+off], frame->iv[i].settings_id);
    nghttp2_put_uint32be(&(*buf_ptr)[12+off], frame->iv[i].value);
  }
  return framelen;
}

int nghttp2_frame_unpack_settings(nghttp2_settings *frame,
                                  const uint8_t *head, size_t headlen,
                                  const uint8_t *payload, size_t payloadlen)
{
  size_t i;
  if(payloadlen % 8) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  frame->niv = payloadlen / 8;
  frame->iv = malloc(frame->niv*sizeof(nghttp2_settings_entry));
  if(frame->iv == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  for(i = 0; i < frame->niv; ++i) {
    size_t off = i*8;
    frame->iv[i].settings_id = nghttp2_get_uint32(&payload[off]) &
      NGHTTP2_SETTINGS_ID_MASK;
    frame->iv[i].value = nghttp2_get_uint32(&payload[4+off]);
  }
  return 0;
}

ssize_t nghttp2_frame_pack_ping(uint8_t **buf_ptr, size_t *buflen_ptr,
                                nghttp2_ping *frame)
{
  ssize_t framelen = NGHTTP2_FRAME_HEAD_LENGTH + 8;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  memcpy(&(*buf_ptr)[8], frame->opaque_data, sizeof(frame->opaque_data));
  return framelen;
}

int nghttp2_frame_unpack_ping(nghttp2_ping *frame,
                              const uint8_t *head, size_t headlen,
                              const uint8_t *payload, size_t payloadlen)
{
  if(payloadlen != 8) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  memcpy(frame->opaque_data, payload, sizeof(frame->opaque_data));
  return 0;
}


ssize_t nghttp2_frame_pack_goaway(uint8_t **buf_ptr, size_t *buflen_ptr,
                                  nghttp2_goaway *frame)
{
  ssize_t framelen = NGHTTP2_FRAME_HEAD_LENGTH + frame->hd.length;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->last_stream_id);
  nghttp2_put_uint32be(&(*buf_ptr)[12], frame->error_code);
  memcpy(&(*buf_ptr)[16], frame->opaque_data, frame->opaque_data_len);
  return framelen;
}

int nghttp2_frame_unpack_goaway(nghttp2_goaway *frame,
                                const uint8_t *head, size_t headlen,
                                const uint8_t *payload, size_t payloadlen)
{
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  if(payloadlen < 8) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  frame->last_stream_id = nghttp2_get_uint32(payload) & NGHTTP2_STREAM_ID_MASK;
  frame->error_code = nghttp2_get_uint32(payload+4);
  frame->opaque_data_len = payloadlen - 8;
  if(frame->opaque_data_len == 0) {
    frame->opaque_data = NULL;
  } else {
    frame->opaque_data = malloc(frame->opaque_data_len);
    if(frame->opaque_data == NULL) {
      return NGHTTP2_ERR_NOMEM;
    }
    memcpy(frame->opaque_data, &payload[8], frame->opaque_data_len);
  }
  return 0;
}

ssize_t nghttp2_frame_pack_window_update(uint8_t **buf_ptr, size_t *buflen_ptr,
                                         nghttp2_window_update *frame)
{
  ssize_t framelen = NGHTTP2_FRAME_HEAD_LENGTH + 4;
  int r;
  r = nghttp2_reserve_buffer(buf_ptr, buflen_ptr, framelen);
  if(r != 0) {
    return r;
  }
  memset(*buf_ptr, 0, framelen);
  nghttp2_frame_pack_frame_hd(*buf_ptr, &frame->hd);
  nghttp2_put_uint32be(&(*buf_ptr)[8], frame->window_size_increment);
  return framelen;
}

int nghttp2_frame_unpack_window_update(nghttp2_window_update *frame,
                                       const uint8_t *head, size_t headlen,
                                       const uint8_t *payload,
                                       size_t payloadlen)
{
  if(payloadlen != 4) {
    return NGHTTP2_ERR_INVALID_FRAME;
  }
  nghttp2_frame_unpack_frame_hd(&frame->hd, head);
  frame->window_size_increment = nghttp2_get_uint32(payload) &
    NGHTTP2_WINDOW_SIZE_INCREMENT_MASK;
  return 0;
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

ssize_t nghttp2_frame_nv_offset(const uint8_t *head)
{
  switch(head[2]) {
  case NGHTTP2_HEADERS:
    if(head[3] & NGHTTP2_FLAG_PRIORITY) {
      return NGHTTP2_FRAME_HEAD_LENGTH + 4;
    } else {
      return NGHTTP2_FRAME_HEAD_LENGTH;
    }
  case NGHTTP2_PUSH_PROMISE:
    return NGHTTP2_FRAME_HEAD_LENGTH + 4;
  default:
    return -1;
  }
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

int nghttp2_nv_equal(const nghttp2_nv *a, const nghttp2_nv *b)
{
  return a->namelen == b->namelen && a->valuelen == b->valuelen &&
    memcmp(a->name, b->name, a->namelen) == 0 &&
    memcmp(a->value, b->value, a->valuelen) == 0;
}

void nghttp2_nv_array_free(nghttp2_nv *nva)
{
  free(nva);
}
