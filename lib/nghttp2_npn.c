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
#include "nghttp2_npn.h"

#include <string.h>

static const nghttp2_npn_proto proto_list[] = {
  { (const unsigned char*)"spdy/3", 6, NGHTTP2_PROTO_SPDY3 },
  { (const unsigned char*)"spdy/2", 6, NGHTTP2_PROTO_SPDY2 }
};

const nghttp2_npn_proto* nghttp2_npn_get_proto_list(size_t *len_ptr)
{
  *len_ptr = sizeof(proto_list)/sizeof(nghttp2_npn_proto);
  return proto_list;
}

int nghttp2_select_next_protocol(unsigned char **out, unsigned char *outlen,
                                 const unsigned char *in, unsigned int inlen)
{
  int http_selected = 0;
  unsigned int i = 0;
  for(; i < inlen; i += in[i]+1) {
    unsigned int j;
    for(j = 0; j < sizeof(proto_list)/sizeof(nghttp2_npn_proto); ++j) {
      if(in[i] == proto_list[j].len &&
         memcmp(&in[i+1], proto_list[j].proto, in[i]) == 0) {
        *out = (unsigned char*)&in[i+1];
        *outlen = in[i];
        return proto_list[j].version;
      }
    }
    if(in[i] == 8 && memcmp(&in[i+1], "http/1.1", in[i]) == 0) {
      http_selected = 1;
      *out = (unsigned char*)&in[i+1];
      *outlen = in[i];
      /* Go through to the next iteration, because "spdy/X" may be
         there */
    }
  }
  if(http_selected) {
    return 0;
  } else {
    return -1;
  }
}

uint16_t nghttp2_npn_get_version(const unsigned char *proto, size_t protolen)
{
  if(proto == NULL) {
    return 0;
  } else {
    if(protolen == 6) {
      if(memcmp("spdy/2", proto, 6) == 0) {
        return NGHTTP2_PROTO_SPDY2;
      } else if(memcmp("spdy/3", proto, 6) == 0) {
        return NGHTTP2_PROTO_SPDY3;
      }
    }
    return 0;
  }
}
