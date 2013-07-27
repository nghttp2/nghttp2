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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>

#include <cassert>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <string>
#include <set>
#include <iomanip>
#include <fstream>

#include "app_helper.h"
#include "util.h"

namespace nghttp2 {

namespace {
const char* strstatus(nghttp2_error_code error_code)
{
  switch(error_code) {
  case NGHTTP2_NO_ERROR:
    return "NO_ERROR";
  case NGHTTP2_PROTOCOL_ERROR:
    return "PROTOCOL_ERROR";
  case NGHTTP2_INTERNAL_ERROR:
    return "INTERNAL_ERROR";
  case NGHTTP2_FLOW_CONTROL_ERROR:
    return "FLOW_CONTROL_ERROR";
  case NGHTTP2_STREAM_CLOSED:
    return "STREAM_CLOSED";
  case NGHTTP2_FRAME_TOO_LARGE:
    return "FRAME_TOO_LARGE";
  case NGHTTP2_REFUSED_STREAM:
    return "REFUSED_STREAM";
  case NGHTTP2_CANCEL:
    return "CANCEL";
  default:
    return "UNKNOWN";
  }
}
} // namespace

namespace {
const char *frame_names[] = {
  "DATA",
  "HEADERS",
  "PRIORITY",
  "RST_STREAM",
  "SETTINGS",
  "PUSH_PROMISE",
  "PING",
  "GOAWAY",
  "UNKNOWN",
  "WINDOW_UPDATE"
};
} // namespace

namespace {
void print_frame_attr_indent()
{
  printf("          ");
}
} // namespace

namespace {
bool color_output = false;
} // namespace

void set_color_output(bool f)
{
  color_output = f;
}

namespace {
const char* ansi_esc(const char *code)
{
  return color_output ? code : "";
}
} // namespace

namespace {
const char* ansi_escend()
{
  return color_output ? "\033[0m" : "";
}
} // namespace


void print_nv(nghttp2_nv *nva, size_t nvlen)
{
  size_t i;
  for(i = 0; i < nvlen; ++i) {
    print_frame_attr_indent();
    printf("%s", ansi_esc("\033[1;34m"));
    fwrite(nva[i].name, nva[i].namelen, 1, stdout);
    printf("%s: ", ansi_escend());
    fwrite(nva[i].value, nva[i].valuelen, 1, stdout);
    printf("\n");
  }
}

void print_timer()
{
  timeval tv;
  get_timer(&tv);
  printf("%s[%3ld.%03ld]%s",
         ansi_esc("\033[33m"),
         (long int)tv.tv_sec, tv.tv_usec/1000,
         ansi_escend());
}

namespace {
void print_frame_hd(const nghttp2_frame_hd& hd)
{
  printf("<length=%d, flags=%u, stream_id=%d>\n",
         hd.length, hd.flags, hd.stream_id);
}
} // namespace

namespace {
void print_flags(const nghttp2_frame_hd& hd)
{
  std::string s;
  switch(hd.type) {
  case NGHTTP2_DATA:
    if(hd.flags & NGHTTP2_FLAG_END_STREAM) {
      s += "END_STREAM";
    }
    break;
  case NGHTTP2_HEADERS:
    if(hd.flags & NGHTTP2_FLAG_END_STREAM) {
      s += "END_STREAM";
    }
    if(hd.flags & NGHTTP2_FLAG_END_HEADERS) {
      if(!s.empty()) {
        s += " | ";
      }
      s += "END_HEADERS";
    }
    if(hd.flags & NGHTTP2_FLAG_PRIORITY) {
      if(!s.empty()) {
        s += " | ";
      }
      s += "PRIORITY";
    }
    break;
  case NGHTTP2_PUSH_PROMISE:
    if(hd.flags & NGHTTP2_FLAG_END_PUSH_PROMISE) {
      s += "END_PUSH_PROMISE";
    }
    break;
  case NGHTTP2_PING:
    if(hd.flags & NGHTTP2_FLAG_PONG) {
      s += "PONG";
    }
    break;
  case NGHTTP2_WINDOW_UPDATE:
    if(hd.flags & NGHTTP2_FLAG_END_FLOW_CONTROL) {
      s += "END_FLOW_CONTROL";
    }
    break;
  }
  printf("; %s\n", s.c_str());
}
} // namespace

enum print_type {
  PRINT_SEND,
  PRINT_RECV
};

namespace {
const char* frame_name_ansi_esc(print_type ptype)
{
  return ansi_esc(ptype == PRINT_SEND ? "\033[1;35m" : "\033[1;36m");
}
} // namespace

namespace {
void print_frame(print_type ptype, nghttp2_frame *frame)
{
  printf("%s%s%s frame ",
         frame_name_ansi_esc(ptype),
         frame_names[frame->hd.type],
         ansi_escend());
  print_frame_hd(frame->hd);
  if(frame->hd.flags) {
    print_frame_attr_indent();
    print_flags(frame->hd);
  }
  switch(frame->hd.type) {
  case NGHTTP2_HEADERS:
    if(frame->hd.flags & NGHTTP2_FLAG_PRIORITY) {
      print_frame_attr_indent();
      printf("(pri=%d)\n", frame->headers.pri);
    }
    switch(frame->headers.cat) {
    case NGHTTP2_HCAT_REQUEST:
      print_frame_attr_indent();
      printf("; Open new stream\n");
      break;
    case NGHTTP2_HCAT_RESPONSE:
      print_frame_attr_indent();
      printf("; First response header\n");
      break;
    case NGHTTP2_HCAT_PUSH_RESPONSE:
      print_frame_attr_indent();
      printf("; First push response header\n");
      break;
    default:
      break;
    }
    print_nv(frame->headers.nva, frame->headers.nvlen);
    break;
  case NGHTTP2_PRIORITY:
    print_frame_attr_indent();
    printf("(pri=%d)\n", frame->priority.pri);
    break;
  case NGHTTP2_RST_STREAM:
    print_frame_attr_indent();
    printf("(error_code=%s(%u))\n",
           strstatus(frame->rst_stream.error_code),
           frame->rst_stream.error_code);
    break;
  case NGHTTP2_SETTINGS:
    print_frame_attr_indent();
    printf("(niv=%lu)\n", static_cast<unsigned long>(frame->settings.niv));
    for(size_t i = 0; i < frame->settings.niv; ++i) {
      print_frame_attr_indent();
      printf("[%d:%u]\n",
             frame->settings.iv[i].settings_id,
             frame->settings.iv[i].value);
    }
    break;
  case NGHTTP2_PUSH_PROMISE:
    print_frame_attr_indent();
    printf("(promised_stream_id=%d)\n",
           frame->push_promise.promised_stream_id);
    break;
  case NGHTTP2_PING:
    print_frame_attr_indent();
    printf("(opaque_data=%s)\n",
           util::format_hex(frame->ping.opaque_data, 8).c_str());
    break;
  case NGHTTP2_GOAWAY:
    print_frame_attr_indent();
    printf("(last_stream_id=%d, error_code=%s(%u), opaque_data=%s)\n",
           frame->goaway.last_stream_id,
           strstatus(frame->goaway.error_code),
           frame->goaway.error_code,
           util::format_hex(frame->goaway.opaque_data,
                            frame->goaway.opaque_data_len).c_str());
    break;
  case NGHTTP2_WINDOW_UPDATE:
    print_frame_attr_indent();
    printf("(window_size_increment=%d)\n",
           frame->window_update.window_size_increment);
    break;
  default:
    printf("\n");
    break;
  }
}
} // namespace

void on_frame_recv_callback
(nghttp2_session *session, nghttp2_frame *frame, void *user_data)
{
  print_timer();
  printf(" recv ");
  print_frame(PRINT_RECV, frame);
  fflush(stdout);
}

void on_invalid_frame_recv_callback
(nghttp2_session *session, nghttp2_frame *frame,
 nghttp2_error_code error_code, void *user_data)
{
  print_timer();
  printf(" [INVALID; status=%s] recv ", strstatus(error_code));
  print_frame(PRINT_RECV, frame);
  fflush(stdout);
}

namespace {
void dump_header(const uint8_t *head, size_t headlen)
{
  size_t i;
  print_frame_attr_indent();
  printf("Header dump: ");
  for(i = 0; i < headlen; ++i) {
    printf("%02X ", head[i]);
  }
  printf("\n");
}
} // namespace

void on_frame_recv_parse_error_callback(nghttp2_session *session,
                                       nghttp2_frame_type type,
                                       const uint8_t *head,
                                       size_t headlen,
                                       const uint8_t *payload,
                                       size_t payloadlen,
                                       int error_code, void *user_data)
{
  print_timer();
  printf(" [PARSE_ERROR] recv %s%s%s frame\n",
         frame_name_ansi_esc(PRINT_RECV),
         frame_names[type],
         ansi_escend());
  print_frame_attr_indent();
  printf("Error: %s\n", nghttp2_strerror(error_code));
  dump_header(head, headlen);
  fflush(stdout);
}

void on_unknown_frame_recv_callback(nghttp2_session *session,
                                   const uint8_t *head,
                                   size_t headlen,
                                   const uint8_t *payload,
                                   size_t payloadlen,
                                   void *user_data)
{
  print_timer();
  printf(" recv unknown frame\n");
  dump_header(head, headlen);
  fflush(stdout);
}

void on_frame_send_callback
(nghttp2_session *session, nghttp2_frame *frame, void *user_data)
{
  print_timer();
  printf(" send ");
  print_frame(PRINT_SEND, frame);
  fflush(stdout);
}

namespace {
void print_data_frame(print_type ptype, uint16_t length, uint8_t flags,
                      int32_t stream_id)
{
  printf("%sDATA%s frame (length=%d, flags=%d, stream_id=%d)\n",
         frame_name_ansi_esc(ptype), ansi_escend(),
         length, flags, stream_id);
}
} // namespace

void on_data_recv_callback
(nghttp2_session *session, uint16_t length, uint8_t flags, int32_t stream_id,
 void *user_data)
{
  print_timer();
  printf(" recv ");
  print_data_frame(PRINT_RECV, length, flags, stream_id);
  fflush(stdout);
}

void on_data_send_callback
(nghttp2_session *session, uint16_t length, uint8_t flags, int32_t stream_id,
 void *user_data)
{
  print_timer();
  printf(" send ");
  print_data_frame(PRINT_SEND, length, flags, stream_id);
  fflush(stdout);
}

int64_t time_delta(const timeval& a, const timeval& b)
{
  int64_t res = (a.tv_sec - b.tv_sec) * 1000;
  res += (a.tv_usec - b.tv_usec) / 1000;
  return res;
}

namespace {
timeval base_tv;
} // namespace

void reset_timer()
{
  get_time(&base_tv);
}

void get_timer(timeval* tv)
{
  get_time(tv);
  tv->tv_usec -= base_tv.tv_usec;
  tv->tv_sec -= base_tv.tv_sec;
  if(tv->tv_usec < 0) {
    tv->tv_usec += 1000000;
    --tv->tv_sec;
  }
}

int get_time(timeval *tv)
{
  int rv;
#ifdef HAVE_CLOCK_GETTIME
  timespec ts;
  rv = clock_gettime(CLOCK_MONOTONIC, &ts);
  tv->tv_sec = ts.tv_sec;
  tv->tv_usec = ts.tv_nsec/1000;
#else // !HAVE_CLOCK_GETTIME
  rv = gettimeofday(tv, 0);
#endif // !HAVE_CLOCK_GETTIME
  return rv;
}

} // namespace nghttp2
