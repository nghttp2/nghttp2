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
#include "spdylay_zlib.h"

#define COMPRESSION_LEVEL 9
#define WINDOW_BITS 11
#define MEM_LEVEL 1

static const char hd_dict[] =
  "optionsgetheadpostputdeletetraceacceptaccept-charsetaccept-encodingaccept-"
  "languageauthorizationexpectfromhostif-modified-sinceif-matchif-none-matchi"
  "f-rangeif-unmodifiedsincemax-forwardsproxy-authorizationrangerefererteuser"
  "-agent10010120020120220320420520630030130230330430530630740040140240340440"
  "5406407408409410411412413414415416417500501502503504505accept-rangesageeta"
  "glocationproxy-authenticatepublicretry-afterservervarywarningwww-authentic"
  "ateallowcontent-basecontent-encodingcache-controlconnectiondatetrailertran"
  "sfer-encodingupgradeviawarningcontent-languagecontent-lengthcontent-locati"
  "oncontent-md5content-rangecontent-typeetagexpireslast-modifiedset-cookieMo"
  "ndayTuesdayWednesdayThursdayFridaySaturdaySundayJanFebMarAprMayJunJulAugSe"
  "pOctNovDecchunkedtext/htmlimage/pngimage/jpgimage/gifapplication/xmlapplic"
  "ation/xhtmltext/plainpublicmax-agecharset=iso-8859-1utf-8gzipdeflateHTTP/1"
  ".1statusversionurl";

int spdylay_zlib_deflate_hd_init(spdylay_zlib *deflater)
{
  deflater->zst.next_in = Z_NULL;
  deflater->zst.zalloc = Z_NULL;
  deflater->zst.zfree = Z_NULL;
  deflater->zst.opaque = Z_NULL;
  if(Z_OK != deflateInit2(&deflater->zst, COMPRESSION_LEVEL, Z_DEFLATED,
                          WINDOW_BITS, MEM_LEVEL, Z_DEFAULT_STRATEGY)) {
    return SPDYLAY_ERR_ZLIB;
  }
  if(Z_OK != deflateSetDictionary(&deflater->zst, (uint8_t*)hd_dict,
                                  sizeof(hd_dict))) {
    return SPDYLAY_ERR_ZLIB;
  }
  return 0;
}

int spdylay_zlib_inflate_hd_init(spdylay_zlib *inflater)
{
  inflater->zst.next_in = Z_NULL;
  inflater->zst.avail_in = 0;
  inflater->zst.zalloc = Z_NULL;
  inflater->zst.zfree = Z_NULL;
  if(Z_OK != inflateInit(&inflater->zst)) {
    return SPDYLAY_ERR_ZLIB;
  }
  return 0;
}

void spdylay_zlib_deflate_free(spdylay_zlib *deflater)
{
  deflateEnd(&deflater->zst);
}

void spdylay_zlib_inflate_free(spdylay_zlib *inflater)
{
  inflateEnd(&inflater->zst);
}

ssize_t spdylay_zlib_deflate_hd(spdylay_zlib *deflater,
                                uint8_t *out, size_t outlen,
                                const uint8_t *in, size_t inlen)
{
  int r;
  deflater->zst.avail_in = inlen;
  deflater->zst.next_in = (uint8_t*)in;
  deflater->zst.avail_out = outlen;
  deflater->zst.next_out = out;
  r = deflate(&deflater->zst, Z_SYNC_FLUSH);
  if(r == Z_OK) {
    return outlen-deflater->zst.avail_out;
  } else {
    return SPDYLAY_ERR_ZLIB;
  }
}

size_t spdylay_zlib_deflate_hd_bound(spdylay_zlib *deflater, size_t len)
{
  return deflateBound(&deflater->zst, len);
}

ssize_t spdylay_zlib_inflate_hd(spdylay_zlib *inflater,
                                spdylay_buffer* buf,
                                const uint8_t *in, size_t inlen)
{
  int r;
  inflater->zst.avail_in = inlen;
  inflater->zst.next_in = (uint8_t*)in;
  while(1) {
    if(spdylay_buffer_avail(buf) == 0) {
      if((r = spdylay_buffer_alloc(buf)) != 0) {
        return r;
      }
    }
    inflater->zst.avail_out = spdylay_buffer_avail(buf);
    inflater->zst.next_out = spdylay_buffer_get(buf);
    r = inflate(&inflater->zst, Z_NO_FLUSH);
    if(r == Z_STREAM_ERROR || r == Z_STREAM_END || r == Z_DATA_ERROR) {
      return SPDYLAY_ERR_ZLIB;
    } else if(r == Z_NEED_DICT) {
      if(Z_OK != inflateSetDictionary(&inflater->zst, (uint8_t*)hd_dict,
                                      sizeof(hd_dict))) {
        return SPDYLAY_ERR_ZLIB;
      }
    } else {
      if(r == Z_OK) {
        size_t adv = spdylay_buffer_avail(buf)-inflater->zst.avail_out;
        spdylay_buffer_advance(buf, adv);
      }
      if(inflater->zst.avail_in == 0 && inflater->zst.avail_out > 0) {
        break;
      }
    }
  }
  return spdylay_buffer_length(buf);
}
