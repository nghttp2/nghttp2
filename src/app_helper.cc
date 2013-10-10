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
  case NGHTTP2_COMPRESSION_ERROR:
    return "COMPRESSION_ERROR";
  default:
    return "UNKNOWN";
  }
}
} // namespace

namespace {
const char* strsettingsid(int32_t id)
{
  switch(id) {
  case NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
    return "MAX_CONCURRENT_STREAMS";
  case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
    return "INITIAL_WINDOW_SIZE";
  case NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS:
    return "FLOW_CONTROL_OPTIONS";
  default:
    return "UNKNOWN";
  }
}
} // namespace

namespace {
const char* strframetype(uint8_t type)
{
  switch(type) {
  case NGHTTP2_DATA:
    return "DATA";
  case NGHTTP2_HEADERS:
    return "HEADERS";
  case NGHTTP2_PRIORITY:
    return "PRIORITY";
  case NGHTTP2_RST_STREAM:
    return "RST_STREAM";
  case NGHTTP2_SETTINGS:
    return "SETTINGS";
  case NGHTTP2_PUSH_PROMISE:
    return "PUSH_PROMISE";
  case NGHTTP2_PING:
    return "PING";
  case NGHTTP2_GOAWAY:
    return "GOAWAY";
  case NGHTTP2_WINDOW_UPDATE:
    return "WINDOW_UPDATE";
  default:
    return "UNKNOWN";
  }
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
  auto millis = get_timer();
  printf("%s[%3ld.%03ld]%s",
         ansi_esc("\033[33m"),
         (long int)(millis.count()/1000), (long int)(millis.count()%1000),
         ansi_escend());
}

namespace {
void print_frame_hd(const nghttp2_frame_hd& hd)
{
  printf("<length=%d, flags=0x%02x, stream_id=%d>\n",
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
void print_frame(print_type ptype, const nghttp2_frame *frame)
{
  printf("%s%s%s frame ",
         frame_name_ansi_esc(ptype),
         strframetype(frame->hd.type),
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
      printf("[%s(%d):%u]\n",
             strsettingsid(frame->settings.iv[i].settings_id),
             frame->settings.iv[i].settings_id,
             frame->settings.iv[i].value);
    }
    break;
  case NGHTTP2_PUSH_PROMISE:
    print_frame_attr_indent();
    printf("(promised_stream_id=%d)\n",
           frame->push_promise.promised_stream_id);
    print_nv(frame->headers.nva, frame->headers.nvlen);
    break;
  case NGHTTP2_PING:
    print_frame_attr_indent();
    printf("(opaque_data=%s)\n",
           util::format_hex(frame->ping.opaque_data, 8).c_str());
    break;
  case NGHTTP2_GOAWAY:
    print_frame_attr_indent();
    printf("(last_stream_id=%d, error_code=%s(%u), opaque_data(%u)=[%s])\n",
           frame->goaway.last_stream_id,
           strstatus(frame->goaway.error_code),
           frame->goaway.error_code,
           static_cast<unsigned int>(frame->goaway.opaque_data_len),
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

int on_frame_recv_callback
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
  print_timer();
  printf(" recv ");
  print_frame(PRINT_RECV, frame);
  fflush(stdout);
  return 0;
}

int on_invalid_frame_recv_callback
(nghttp2_session *session, const nghttp2_frame *frame,
 nghttp2_error_code error_code, void *user_data)
{
  print_timer();
  printf(" [INVALID; status=%s] recv ", strstatus(error_code));
  print_frame(PRINT_RECV, frame);
  fflush(stdout);
  return 0;
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

int on_frame_recv_parse_error_callback(nghttp2_session *session,
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
         strframetype(type),
         ansi_escend());
  print_frame_attr_indent();
  printf("Error: %s\n", nghttp2_strerror(error_code));
  dump_header(head, headlen);
  fflush(stdout);
  return 0;
}

int on_unknown_frame_recv_callback(nghttp2_session *session,
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
  return 0;
}

int on_frame_send_callback
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
  print_timer();
  printf(" send ");
  print_frame(PRINT_SEND, frame);
  fflush(stdout);
  return 0;
}

namespace {
void print_data_frame(print_type ptype, uint16_t length, uint8_t flags,
                      int32_t stream_id)
{
  printf("%sDATA%s frame ",
         frame_name_ansi_esc(ptype), ansi_escend());
  nghttp2_frame_hd hd = {length, NGHTTP2_DATA, flags, stream_id};
  print_frame_hd(hd);
  if(flags) {
    print_frame_attr_indent();
    print_flags(hd);
  }
}
} // namespace

int on_data_recv_callback
(nghttp2_session *session, uint16_t length, uint8_t flags, int32_t stream_id,
 void *user_data)
{
  print_timer();
  printf(" recv ");
  print_data_frame(PRINT_RECV, length, flags, stream_id);
  fflush(stdout);
  return 0;
}

int on_data_send_callback
(nghttp2_session *session, uint16_t length, uint8_t flags, int32_t stream_id,
 void *user_data)
{
  print_timer();
  printf(" send ");
  print_data_frame(PRINT_SEND, length, flags, stream_id);
  fflush(stdout);
  return 0;
}

namespace {
std::chrono::steady_clock::time_point base_tv;
} // namespace

void reset_timer()
{
  base_tv = std::chrono::steady_clock::now();
}

std::chrono::milliseconds get_timer()
{
  return time_delta(std::chrono::steady_clock::now(), base_tv);
}

std::chrono::steady_clock::time_point get_time()
{
  return std::chrono::steady_clock::now();
}

} // namespace nghttp2
