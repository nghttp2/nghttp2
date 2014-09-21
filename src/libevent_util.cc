/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
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
#include "libevent_util.h"

#include <cstring>

namespace nghttp2 {

namespace util {

EvbufferBuffer::EvbufferBuffer()
  : evbuffer_(nullptr),
    buf_(nullptr),
    bufmax_(0),
    buflen_(0)
{}

EvbufferBuffer::EvbufferBuffer(evbuffer *evbuffer, uint8_t *buf, size_t bufmax)
  : evbuffer_(evbuffer),
    buf_(buf),
    bufmax_(bufmax),
    buflen_(0)
{}

void EvbufferBuffer::reset(evbuffer *evbuffer, uint8_t *buf, size_t bufmax)
{
  evbuffer_ = evbuffer;
  buf_ = buf;
  bufmax_ = bufmax;
  buflen_ = 0;
}

int EvbufferBuffer::flush()
{
  int rv;
  if(buflen_ > 0) {
    rv = evbuffer_add(evbuffer_, buf_, buflen_);
    if(rv == -1) {
      return -1;
    }
    buflen_ = 0;
  }
  return 0;
}

int EvbufferBuffer::add(const uint8_t *data, size_t datalen)
{
  int rv;
  if(buflen_ + datalen > bufmax_) {
    if(buflen_ > 0) {
      rv = evbuffer_add(evbuffer_, buf_, buflen_);
      if(rv == -1) {
        return -1;
      }
      buflen_ = 0;
    }
    if(datalen > bufmax_) {
      rv = evbuffer_add(evbuffer_, data, datalen);
      if(rv == -1) {
        return -1;
      }
      return 0;
    }
  }
  memcpy(buf_ + buflen_, data, datalen);
  buflen_ += datalen;
  return 0;
}

size_t EvbufferBuffer::get_buflen() const
{
  return buflen_;
}

void bev_enable_unless(bufferevent *bev, int events)
{
  if((bufferevent_get_enabled(bev) & events) == events) {
    return;
  }

  bufferevent_enable(bev, events);
}

void bev_disable_unless(bufferevent *bev, int events)
{
  if((bufferevent_get_enabled(bev) & events) == 0) {
    return;
  }

  bufferevent_disable(bev, events);
}

} // namespace util

} // namespace nghttp2
