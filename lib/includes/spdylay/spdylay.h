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
#ifndef SPDYLAY_H
#define SPDYLAY_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

typedef enum {
  SPDYLAY_ERR_NOMEM = -500,
  SPDYLAY_ERR_INVALID_ARGUMENT = -501,
  SPDYLAY_ERR_ZLIB = -502,
  SPDYLAY_ERR_ZLIB_BUF = -503,
  SPDYLAY_ERR_WOULDBLOCK = -504,
  SPDYLAY_ERR_PROTO = -505,
  SPDYLAY_ERR_CALLBACK_FAILURE = -505,
} spdylay_error;

typedef enum {
  SPDYLAY_MSG_MORE
} spdylay_io_flag;

typedef ssize_t (*spdylay_send_callback)
(const uint8_t *data, size_t length, int flags, void *user_data);

typedef ssize_t (*spdylay_recv_callback)
(uint8_t *buf, size_t length, int flags, void *user_data);

typedef struct {
  spdylay_send_callback send_callback;
  spdylay_recv_callback recv_callback;
} spdylay_session_callbacks;

struct spdylay_session;
typedef struct spdylay_session spdylay_session;

int spdylay_session_client_init(spdylay_session **session_ptr,
                                const spdylay_session_callbacks *callbacks,
                                void *user_data);

void spdylay_session_free(struct spdylay_session *session);

int spdylay_session_send(spdylay_session *session);

int spdylay_session_recv(spdylay_session *session);

int spdylay_session_want_read(spdylay_session *session);

int spdylay_session_want_write(spdylay_session *session);

int spdylay_req_submit(spdylay_session *session, const char *path);

#ifdef __cplusplus
}
#endif

#endif /* SPDYLAY_H */
