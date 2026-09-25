/*
 * nghttp2 - HTTP/2 C Library
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
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif // defined(HAVE_SYS_SOCKET_H)
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif // defined(HAVE_NETDB_H)
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif // defined(HAVE_UNISTD_H)
#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif // defined(HAVE_FCNTL_H)
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif // defined(HAVE_NETINET_IN_H)
#include <netinet/tcp.h>
#include <poll.h>

#include <cassert>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string>
#include <iomanip>
#include <fstream>
#include <print>

#include "app_helper.h"
#include "util.h"
#include "http2.h"
#include "template.h"

namespace nghttp2 {

// namespace {
// const char *strsettingsid(int32_t id) {
//   switch (id) {
//   case NGHTTP2_SETTINGS_HEADER_TABLE_SIZE:
//     return "SETTINGS_HEADER_TABLE_SIZE";
//   case NGHTTP2_SETTINGS_ENABLE_PUSH:
//     return "SETTINGS_ENABLE_PUSH";
//   case NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
//     return "SETTINGS_MAX_CONCURRENT_STREAMS";
//   case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
//     return "SETTINGS_INITIAL_WINDOW_SIZE";
//   case NGHTTP2_SETTINGS_MAX_FRAME_SIZE:
//     return "SETTINGS_MAX_FRAME_SIZE";
//   case NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
//     return "SETTINGS_MAX_HEADER_LIST_SIZE";
//   case NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL:
//     return "SETTINGS_ENABLE_CONNECT_PROTOCOL";
//   case NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES:
//     return "SETTINGS_NO_RFC7540_PRIORITIES";
//   default:
//     return "UNKNOWN";
//   }
// }
// } // namespace

// namespace {
// std::string strframetype(uint8_t type) {
//   switch (type) {
//   case NGHTTP2_DATA:
//     return "DATA";
//   case NGHTTP2_HEADERS:
//     return "HEADERS";
//   case NGHTTP2_PRIORITY:
//     return "PRIORITY";
//   case NGHTTP2_RST_STREAM:
//     return "RST_STREAM";
//   case NGHTTP2_SETTINGS:
//     return "SETTINGS";
//   case NGHTTP2_PUSH_PROMISE:
//     return "PUSH_PROMISE";
//   case NGHTTP2_PING:
//     return "PING";
//   case NGHTTP2_GOAWAY:
//     return "GOAWAY";
//   case NGHTTP2_WINDOW_UPDATE:
//     return "WINDOW_UPDATE";
//   case NGHTTP2_ALTSVC:
//     return "ALTSVC";
//   case NGHTTP2_ORIGIN:
//     return "ORIGIN";
//   case NGHTTP2_PRIORITY_UPDATE:
//     return "PRIORITY_UPDATE";
//   }

//   std::string s = "extension(0x";
//   s += util::format_hex(std::span{&type, 1});
//   s += ')';

//   return s;
// }
// } // namespace

namespace {
bool color_output = false;
} // namespace

void set_color_output(bool f) { color_output = f; }

namespace {
FILE *outfile = stdout;
} // namespace

// void set_output(FILE *file) { outfile = file; }

// namespace {
// void print_frame_attr_indent() { std::print(outfile, "          "); }
// } // namespace

namespace {
const char *ansi_esc(const char *code) { return color_output ? code : ""; }
} // namespace

namespace {
const char *ansi_escend() { return color_output ? "\033[0m" : ""; }
} // namespace

// namespace {
// void print_nv(nghttp2_nv *nv) {
//   std::println(outfile, "{}{}{}: {}", ansi_esc("\033[1;34m"),
//                as_string_view(nv->name, nv->namelen), ansi_escend(),
//                as_string_view(nv->value, nv->valuelen));
// }
// } // namespace
// namespace {
// void print_nv(nghttp2_nv *nva, size_t nvlen) {
//   auto end = nva + nvlen;
//   for (; nva != end; ++nva) {
//     print_frame_attr_indent();

//     print_nv(nva);
//   }
// }
// } // namespace

void print_timer() {
  auto millis = get_timer();
  std::print(outfile, "{}[{:3}.{:03}]{}", ansi_esc("\033[33m"),
             millis.count() / 1000, millis.count() % 1000, ansi_escend());
}

// namespace {
// void print_frame_hd(const nghttp2_frame_hd &hd) {
//   std::println(outfile, "<length={}, flags=0x{:02x}, stream_id={}>",
//   hd.length,
//                hd.flags, hd.stream_id);
// }
// } // namespace

// namespace {
// void print_flags(const nghttp2_frame_hd &hd) {
//   std::string s;
//   switch (hd.type) {
//   case NGHTTP2_DATA:
//     if (hd.flags & NGHTTP2_FLAG_END_STREAM) {
//       s += "END_STREAM";
//     }
//     if (hd.flags & NGHTTP2_FLAG_PADDED) {
//       if (!s.empty()) {
//         s += " | ";
//       }
//       s += "PADDED";
//     }
//     break;
//   case NGHTTP2_HEADERS:
//     if (hd.flags & NGHTTP2_FLAG_END_STREAM) {
//       s += "END_STREAM";
//     }
//     if (hd.flags & NGHTTP2_FLAG_END_HEADERS) {
//       if (!s.empty()) {
//         s += " | ";
//       }
//       s += "END_HEADERS";
//     }
//     if (hd.flags & NGHTTP2_FLAG_PADDED) {
//       if (!s.empty()) {
//         s += " | ";
//       }
//       s += "PADDED";
//     }
//     if (hd.flags & NGHTTP2_FLAG_PRIORITY) {
//       if (!s.empty()) {
//         s += " | ";
//       }
//       s += "PRIORITY";
//     }

//     break;
//   case NGHTTP2_PRIORITY:
//     break;
//   case NGHTTP2_SETTINGS:
//     if (hd.flags & NGHTTP2_FLAG_ACK) {
//       s += "ACK";
//     }
//     break;
//   case NGHTTP2_PUSH_PROMISE:
//     if (hd.flags & NGHTTP2_FLAG_END_HEADERS) {
//       s += "END_HEADERS";
//     }
//     if (hd.flags & NGHTTP2_FLAG_PADDED) {
//       if (!s.empty()) {
//         s += " | ";
//       }
//       s += "PADDED";
//     }
//     break;
//   case NGHTTP2_PING:
//     if (hd.flags & NGHTTP2_FLAG_ACK) {
//       s += "ACK";
//     }
//     break;
//   }
//   std::println(outfile, "; {}", s);
// }
// } // namespace

// enum print_type { PRINT_SEND, PRINT_RECV };

// namespace {
// const char *frame_name_ansi_esc(print_type ptype) {
//   return ansi_esc(ptype == PRINT_SEND ? "\033[1;35m" : "\033[1;36m");
// }
// } // namespace

// namespace {
// void print_frame(print_type ptype, const nghttp2_frame *frame) {
//   std::print(outfile, "{}{}{} frame ", frame_name_ansi_esc(ptype),
//              strframetype(frame->hd.type), ansi_escend());
//   print_frame_hd(frame->hd);
//   if (frame->hd.flags) {
//     print_frame_attr_indent();
//     print_flags(frame->hd);
//   }
//   switch (frame->hd.type) {
//   case NGHTTP2_DATA:
//     if (frame->data.padlen > 0) {
//       print_frame_attr_indent();
//       std::println(outfile, "(padlen={})", frame->data.padlen);
//     }
//     break;
//   case NGHTTP2_HEADERS:
//     print_frame_attr_indent();
//     std::print(outfile, "(padlen={}", frame->headers.padlen);
//     if (frame->hd.flags & NGHTTP2_FLAG_PRIORITY) {
//       std::print(outfile, ", dep_stream_id={}, weight={}, exclusive={}",
//                  frame->headers.pri_spec.stream_id,
//                  frame->headers.pri_spec.weight,
//                  frame->headers.pri_spec.exclusive);
//     }
//     std::println(outfile, ")");
//     switch (frame->headers.cat) {
//     case NGHTTP2_HCAT_REQUEST:
//       print_frame_attr_indent();
//       std::println(outfile, "; Open new stream");
//       break;
//     case NGHTTP2_HCAT_RESPONSE:
//       print_frame_attr_indent();
//       std::println(outfile, "; First response header");
//       break;
//     case NGHTTP2_HCAT_PUSH_RESPONSE:
//       print_frame_attr_indent();
//       std::println(outfile, "; First push response header");
//       break;
//     default:
//       break;
//     }
//     print_nv(frame->headers.nva, frame->headers.nvlen);
//     break;
//   case NGHTTP2_PRIORITY:
//     print_frame_attr_indent();

//     std::println(outfile, "(dep_stream_id={}, weight={}, exclusive={})",
//                  frame->priority.pri_spec.stream_id,
//                  frame->priority.pri_spec.weight,
//                  frame->priority.pri_spec.exclusive);

//     break;
//   case NGHTTP2_RST_STREAM:
//     print_frame_attr_indent();
//     std::println(outfile, "(error_code={}(0x{:02x}))",
//                  nghttp2_http2_strerror(frame->rst_stream.error_code),
//                  frame->rst_stream.error_code);
//     break;
//   case NGHTTP2_SETTINGS:
//     print_frame_attr_indent();
//     std::println(outfile, "(niv={})", frame->settings.niv);
//     for (size_t i = 0; i < frame->settings.niv; ++i) {
//       print_frame_attr_indent();
//       std::println(outfile, "[{}(0x{:02x}):{}]",
//                    strsettingsid(frame->settings.iv[i].settings_id),
//                    frame->settings.iv[i].settings_id,
//                    frame->settings.iv[i].value);
//     }
//     break;
//   case NGHTTP2_PUSH_PROMISE:
//     print_frame_attr_indent();
//     std::println(outfile, "(padlen={}, promised_stream_id={})",
//                  frame->push_promise.padlen,
//                  frame->push_promise.promised_stream_id);
//     print_nv(frame->push_promise.nva, frame->push_promise.nvlen);
//     break;
//   case NGHTTP2_PING:
//     print_frame_attr_indent();
//     std::println(outfile, "(opaque_data={})",
//                  util::format_hex(std::span{frame->ping.opaque_data}));
//     break;
//   case NGHTTP2_GOAWAY:
//     print_frame_attr_indent();
//     std::println(
//       outfile,
//       "(last_stream_id={}, error_code={}(0x{:02x}), opaque_data({})=[{}])",
//       frame->goaway.last_stream_id,
//       nghttp2_http2_strerror(frame->goaway.error_code),
//       frame->goaway.error_code, frame->goaway.opaque_data_len,
//       util::ascii_dump(frame->goaway.opaque_data,
//                        frame->goaway.opaque_data_len));
//     break;
//   case NGHTTP2_WINDOW_UPDATE:
//     print_frame_attr_indent();
//     std::println(outfile, "(window_size_increment={})",
//                  frame->window_update.window_size_increment);
//     break;
//   case NGHTTP2_ALTSVC: {
//     auto altsvc = static_cast<nghttp2_ext_altsvc *>(frame->ext.payload);
//     print_frame_attr_indent();
//     std::println(outfile, "(origin=[{}], altsvc_field_value=[{}])",
//                  as_string_view(altsvc->origin, altsvc->origin_len),
//                  as_string_view(altsvc->field_value,
//                  altsvc->field_value_len));
//     break;
//   }
//   case NGHTTP2_ORIGIN: {
//     auto origin = static_cast<nghttp2_ext_origin *>(frame->ext.payload);
//     for (size_t i = 0; i < origin->nov; ++i) {
//       auto ent = &origin->ov[i];
//       print_frame_attr_indent();
//       std::println(outfile, "[{}]",
//                    as_string_view(ent->origin, ent->origin_len));
//     }
//     break;
//   }
//   case NGHTTP2_PRIORITY_UPDATE: {
//     auto priority_update =
//       static_cast<nghttp2_ext_priority_update *>(frame->ext.payload);
//     print_frame_attr_indent();
//     std::println(outfile,
//                  "(prioritized_stream_id={}, priority_field_value=[{}])",
//                  priority_update->stream_id,
//                  as_string_view(priority_update->field_value,
//                                 priority_update->field_value_len));
//     break;
//   }
//   default:
//     break;
//   }
// }
// } // namespace

// int verbose_on_header_callback(nghttp2_session *session,
//                                const nghttp2_frame *frame, const uint8_t
//                                *name, size_t namelen, const uint8_t *value,
//                                size_t valuelen, uint8_t flags,
//                                void *user_data) {
//   nghttp2_nv nv = {const_cast<uint8_t *>(name), const_cast<uint8_t *>(value),
//                    namelen, valuelen};

//   print_timer();
//   std::print(outfile, " recv (stream_id={}", frame->hd.stream_id);
//   if (flags & NGHTTP2_NV_FLAG_NO_INDEX) {
//     std::print(outfile, ", sensitive");
//   }
//   std::print(outfile, ") ");

//   print_nv(&nv);
//   fflush(outfile);

//   return 0;
// }

// int verbose_on_frame_recv_callback(nghttp2_session *session,
//                                    const nghttp2_frame *frame,
//                                    void *user_data) {
//   print_timer();
//   std::print(outfile, " recv ");
//   print_frame(PRINT_RECV, frame);
//   fflush(outfile);
//   return 0;
// }

// int verbose_on_invalid_frame_recv_callback(nghttp2_session *session,
//                                            const nghttp2_frame *frame,
//                                            int lib_error_code,
//                                            void *user_data) {
//   print_timer();
//   std::print(outfile, " [INVALID; error={}] recv ",
//              nghttp2_strerror(lib_error_code));
//   print_frame(PRINT_RECV, frame);
//   fflush(outfile);
//   return 0;
// }

// int verbose_on_frame_send_callback(nghttp2_session *session,
//                                    const nghttp2_frame *frame,
//                                    void *user_data) {
//   print_timer();
//   std::print(outfile, " send ");
//   print_frame(PRINT_SEND, frame);
//   fflush(outfile);
//   return 0;
// }

// int verbose_on_data_chunk_recv_callback(nghttp2_session *session, uint8_t
// flags,
//                                         int32_t stream_id, const uint8_t
//                                         *data, size_t len, void *user_data) {
//   print_timer();
//   auto srecv =
//     nghttp2_session_get_stream_effective_recv_data_length(session,
//     stream_id);
//   auto crecv = nghttp2_session_get_effective_recv_data_length(session);

//   std::println(outfile,
//                " recv (stream_id={}, length={}, srecv={}, crecv={}) DATA",
//                stream_id, len, srecv, crecv);
//   fflush(outfile);

//   return 0;
// }

// int verbose_error_callback(nghttp2_session *session, int lib_error_code,
//                            const char *msg, size_t len, void *user_data) {
//   print_timer();
//   std::println(outfile, " [ERROR] {}", as_string_view(msg, len));
//   fflush(outfile);

//   return 0;
// }

namespace {
std::chrono::steady_clock::time_point base_tv;
} // namespace

void reset_timer() { base_tv = std::chrono::steady_clock::now(); }

std::chrono::milliseconds get_timer() {
  return time_delta(std::chrono::steady_clock::now(), base_tv);
}

std::chrono::steady_clock::time_point get_time() {
  return std::chrono::steady_clock::now();
}

} // namespace nghttp2
