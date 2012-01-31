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
#include <sys/types.h>

struct spdylay_session;
typedef struct spdylay_session spdylay_session;

/* SPDY protocol version 2 */
#define SPDYLAY_PROTO_VERSION 2

typedef enum {
  SPDYLAY_ERR_INVALID_ARGUMENT = -501,
  SPDYLAY_ERR_ZLIB = -502,
  SPDYLAY_ERR_ZLIB_BUF = -503,
  SPDYLAY_ERR_WOULDBLOCK = -504,
  SPDYLAY_ERR_PROTO = -505,
  SPDYLAY_ERR_INVALID_FRAME = -506,
  SPDYLAY_ERR_EOF = -507,

  /* The errors < SPDYLAY_ERR_FATAL mean that the library is under
     unexpected condition that it cannot process any further data
     reliably (e.g., out of memory). */
  SPDYLAY_ERR_FATAL = -900,
  SPDYLAY_ERR_NOMEM = -901,
  SPDYLAY_ERR_CALLBACK_FAILURE = -902,
} spdylay_error;

typedef enum {
  SPDYLAY_MSG_MORE
} spdylay_io_flag;

typedef enum {
  SPDYLAY_SYN_STREAM = 1,
  SPDYLAY_SYN_REPLY = 2,
  SPDYLAY_RST_STREAM = 3,
  SPDYLAY_SETTINGS = 4,
  SPDYLAY_NOOP = 5,
  SPDYLAY_PING = 6,
  SPDYLAY_GOAWAY = 7,
  SPDYLAY_HEADERS = 8,
  SPDYLAY_DATA = 100,
} spdylay_frame_type;

typedef enum {
  SPDYLAY_FLAG_NONE = 0,
  SPDYLAY_FLAG_FIN = 1,
  SPDYLAY_FLAG_UNIDIRECTIONAL = 2
} spdylay_flag;

typedef enum {
  SPDYLAY_OK = 0,
  SPDYLAY_PROTOCOL_ERROR = 1,
  SPDYLAY_INVALID_STREAM = 2,
  SPDYLAY_REFUSED_STREAM = 3,
  SPDYLAY_UNSUPPORTED_VERSION = 4,
  SPDYLAY_CANCEL = 5,
  SPDYLAY_INTERNAL_ERROR = 6,
  SPDYLAY_FLOW_CONTROL_ERROR = 7
} spdylay_status_code;

typedef struct {
  uint16_t version;
  uint16_t type;
  uint8_t flags;
  int32_t length;
} spdylay_ctrl_hd;

typedef struct {
  spdylay_ctrl_hd hd;
  int32_t stream_id;
  int32_t assoc_stream_id;
  /* 0 (Highest) to 3 (Lowest). Looks like spdy/2 spec is wrong. */
  uint8_t pri;
  char **nv;
} spdylay_syn_stream;

typedef struct {
  spdylay_ctrl_hd hd;
  int32_t stream_id;
  char **nv;
} spdylay_syn_reply;

typedef struct {
  spdylay_ctrl_hd hd;
  int32_t stream_id;
  char **nv;
} spdylay_headers;

typedef struct {
  spdylay_ctrl_hd hd;
  int32_t stream_id;
  uint32_t status_code;
} spdylay_rst_stream;

typedef struct {
  spdylay_ctrl_hd hd;
  uint32_t unique_id;
} spdylay_ping;

typedef struct {
  spdylay_ctrl_hd hd;
  int32_t last_good_stream_id;
  uint32_t status_code;
} spdylay_goaway;

typedef union {
  int fd;
  void *ptr;
} spdylay_data_source;

typedef ssize_t (*spdylay_data_source_read_callback)
(spdylay_session *session, uint8_t *buf, size_t length, int *eof,
 spdylay_data_source *source, void *user_data);

typedef struct {
  spdylay_data_source source;
  spdylay_data_source_read_callback read_callback;
} spdylay_data_provider;

typedef struct {
  int32_t stream_id;
  uint8_t flags;
  spdylay_data_provider data_prd;
} spdylay_data;

typedef union {
  spdylay_syn_stream syn_stream;
  spdylay_syn_reply syn_reply;
  spdylay_rst_stream rst_stream;
  spdylay_ping ping;
  spdylay_goaway goaway;
  spdylay_headers headers;
  spdylay_data data;
} spdylay_frame;

/*
 * Callback function invoked when |session| want to send data to
 * remote peer. The implementation of this function must send at most
 * |length| bytes of data stored in |data|. It must return the number
 * of bytes sent if it succeeds.  If it cannot send any single byte
 * without blocking, it must return SPDYLAY_ERR_WOULDBLOCK. For other
 * errors, it must return SPDYLAY_ERR_CALLBACK_FAILURE.
 */
typedef ssize_t (*spdylay_send_callback)
(spdylay_session *session,
 const uint8_t *data, size_t length, int flags, void *user_data);

/*
 * Callback function invoked when |session| want to receive data from
 * remote peer. The implementation of this function must read at most
 * |length| bytes of data and store it in |buf|. It must return the
 * number of bytes written in |buf| if it succeeds. If it cannot read
 * any single byte without blocking, it must return
 * SPDYLAY_ERR_WOULDBLOCK. If it gets EOF before it reads any single
 * byte, it must return SPDYLAY_ERR_EOF. For other errors, it must
 * return SPDYLAY_ERR_CALLBACK_FAILURE.
 */
typedef ssize_t (*spdylay_recv_callback)
(spdylay_session *session,
 uint8_t *buf, size_t length, int flags, void *user_data);

/*
 * Callback function invoked by spdylay_session_recv() when a control
 * frame is arrived.
 */
typedef void (*spdylay_on_ctrl_recv_callback)
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data);

/*
 * Callback function invoked by spdylay_session_recv() when an invalid
 * control frame is arrived, which typically the case where RST_STREAM
 * will be sent
 */
typedef void (*spdylay_on_invalid_ctrl_recv_callback)
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data);

/*
 * Callback function invoked when PING reply is received from peer.
 */
typedef void (*spdylay_on_ping_recv_callback)
(spdylay_session *session, const struct timespec *rtt, void *user_data);

/*
 * Callback function invoked when data chunk of DATA frame is
 * received. |stream_id| is the stream ID of this DATA frame belongs
 * to. |flags| is the flags of DATA frame which this data chunk is
 * contained. flags & SPDYLAY_FLAG_FIN does not necessarily mean this
 * chunk of data is the last one in the stream. You should use
 * spdylay_on_data_recv_callback to know all data frame is received
 * whose flags contains SPDYLAY_FLAG_FIN.
 */
typedef void (*spdylay_on_data_chunk_recv_callback)
(spdylay_session *session, uint8_t flags, int32_t stream_id,
 const uint8_t *data, size_t len, void *user_data);

/*
 * Callback function invoked when DATA frame is received. The actual
 * data it contains are received by spdylay_on_data_recv_callback.
 */
typedef void (*spdylay_on_data_recv_callback)
(spdylay_session *session, uint8_t flags, int32_t stream_id, int32_t length,
 void *user_data);

/*
 * Callback function invoked after frame |frame| of type |type| is
 * sent.
 */
typedef void (*spdylay_on_ctrl_send_callback)
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data);

/*
 * Callback function invoked after DATA frame is sent.
 */
typedef void (*spdylay_on_data_send_callback)
(spdylay_session *session, uint8_t flags, int32_t stream_id, int32_t length,
 void *user_data);

/*
 * Callback function invoked before frame |frame| of type |type| is
 * sent. This may be useful, for example, to know the stream ID of
 * SYN_STREAM frame, which is not assigned when it was queued.
 */
typedef void (*spdylay_before_ctrl_send_callback)
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data);

/*
 * Callback function invoked when stream |stream_id| is closed. The
 * reason of closure is indicated by |status_code|.
 */
typedef void (*spdylay_on_stream_close_callback)
(spdylay_session *session, int32_t stream_id, spdylay_status_code status_code,
 void *user_data);

typedef struct {
  spdylay_send_callback send_callback;
  spdylay_recv_callback recv_callback;
  spdylay_on_ctrl_recv_callback on_ctrl_recv_callback;
  spdylay_on_invalid_ctrl_recv_callback on_invalid_ctrl_recv_callback;
  spdylay_on_ping_recv_callback on_ping_recv_callback;
  spdylay_on_data_chunk_recv_callback on_data_chunk_recv_callback;
  spdylay_on_data_recv_callback on_data_recv_callback;
  spdylay_before_ctrl_send_callback before_ctrl_send_callback;
  spdylay_on_ctrl_send_callback on_ctrl_send_callback;
  spdylay_on_data_send_callback on_data_send_callback;
  spdylay_on_stream_close_callback on_stream_close_callback;
} spdylay_session_callbacks;

/*
 * Initializes |*session_ptr| for client use. This function returns 0
 * if it succeeds, or negative error code.
 */
int spdylay_session_client_new(spdylay_session **session_ptr,
                               const spdylay_session_callbacks *callbacks,
                               void *user_data);

/*
 * Frees any resources allocated for |session|.
 */
void spdylay_session_del(spdylay_session *session);

/*
 * Sends pending frames to the remote peer. This function returns 0 if
 * it succeeds, or negative error code.
 */
int spdylay_session_send(spdylay_session *session);

/*
 * Receives frames from the remote peer. This function returns 0 if it
 * succeeds, or negative error code.
 */
int spdylay_session_recv(spdylay_session *session);

/*
 * Returns non-zero value if |session| want to receive data from the
 * remote peer, or 0.
 */
int spdylay_session_want_read(spdylay_session *session);

/*
 * Returns non-zero value if |session| want to send data to the remote
 * peer, or 0.
 */
int spdylay_session_want_write(spdylay_session *session);

/*
 * Submits SYN_STREAM frame. |pri| is priority of this request and it
 * must be in the range of [0, 3]. 0 means the higest priority. |nv|
 * must include following name/value pairs:
 *
 * "method": HTTP method (e.g., "GET" or "POST")
 * "scheme": URI scheme (e.g., "https")
 * "url": Abosolute path of this request (e.g., "/foo")
 * "version": HTTP version (e.g., "HTTP/1.1")
 *
 * This function creates copies of all name/value pairs in |nv|.
 *
 * If |data_prd| is not NULL, it provides data which will be sent in
 * subsequent DATA frames. In this case, "POST" must be specified with
 * "method" key in |nv|. If |data_prd| is NULL, SYN_STREAM have
 * FLAG_FIN.
 *
 * This function returns 0 if it succeeds, or negative error code.
 */
int spdylay_submit_request(spdylay_session *session, uint8_t pri,
                           const char **nv,
                           spdylay_data_provider *data_prd);

/*
 * Submits DATA frame to stream |stream_id|.
 *
 * This function returns 0 if it succeeds, or negative error code.
 */
int spdylay_submit_data(spdylay_session *session, int32_t stream_id,
                        spdylay_data_provider *data_prd);

/*
 * Submits SYN_REPLY frame against stream |stream_id|. |nv| must
 * include following name/value pairs:
 *
 * "status": HTTP status code (e.g., "200" or "200 OK")
 * "version": HTTP response version (e.g., "HTTP/1.1")
 *
 * This function creates copies of all name/value pairs in |nv|. If
 * |data_prd| is not NULL, it provides data which will be sent in
 * subsequent DATA frames. If |data_prd| is NULL, SYN_REPLY will have
 * FLAG_FIN.
 *
 * This function returns 0 if it succeeds, or negative error code.
 */
int spdylay_submit_response(spdylay_session *session,
                            int32_t stream_id, const char **nv,
                            spdylay_data_provider *data_prd);

/*
 * Submits PING frame. This function returns 0 if it succeeds, or
 * negative error code.
 */
int spdylay_submit_ping(spdylay_session *session);

/*
 * Submits GOAWAY frame. This function returns 0 if it succeeds, or
 * negative error code.
 */
int spdylay_submit_goaway(spdylay_session *session);

#ifdef __cplusplus
}
#endif

#endif /* SPDYLAY_H */
