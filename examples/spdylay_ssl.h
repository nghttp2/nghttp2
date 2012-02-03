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
#ifndef SPDYLAY_SSL_H
#define SPDYLAY_SSL_H

#include <stdint.h>
#include <cstdlib>
#include <sys/time.h>
#include <poll.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <spdylay/spdylay.h>

namespace spdylay {

extern bool ssl_debug;

class Spdylay {
public:
  Spdylay(int fd, SSL *ssl, const spdylay_session_callbacks *callbacks);
  ~Spdylay();
  int recv();
  int send();
  ssize_t send_data(const uint8_t *data, size_t len, int flags);
  ssize_t recv_data(uint8_t *data, size_t len, int flags);
  bool want_read();
  bool want_write();
  int fd() const;
  int submit_request(const std::string& hostport, const std::string& path,
                     uint8_t pri, void *stream_user_data);
  bool would_block(int r);
private:
  int fd_;
  SSL *ssl_;
  spdylay_session *session_;
  bool want_write_;
  bool debug_;
};

int connect_to(const std::string& host, uint16_t port);

int make_non_block(int fd);

ssize_t send_callback(spdylay_session *session,
                      const uint8_t *data, size_t len, int flags,
                      void *user_data);

ssize_t recv_callback(spdylay_session *session,
                      uint8_t *data, size_t len, int flags, void *user_data);

void print_nv(char **nv);

void on_ctrl_recv_callback
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data);

void on_data_recv_callback
(spdylay_session *session, uint8_t flags, int32_t stream_id, int32_t length,
 void *user_data);

void on_ctrl_send_callback
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data);

void ctl_poll(pollfd *pollfd, Spdylay *sc);

int select_next_proto_cb(SSL* ssl,
                         unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg);

void setup_ssl_ctx(SSL_CTX *ssl_ctx);

int ssl_handshake(SSL *ssl, int fd);

void reset_timer();

void get_timer(timeval *tv);

} // namespace spdylay

#endif // SPDYLAY_SSL_H
