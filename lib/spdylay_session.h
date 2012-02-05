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
#ifndef SPDYLAY_SESSION_H
#define SPDYLAY_SESSION_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <spdylay/spdylay.h>
#include "spdylay_pq.h"
#include "spdylay_map.h"
#include "spdylay_frame.h"
#include "spdylay_zlib.h"
#include "spdylay_stream.h"

typedef struct {
  spdylay_frame_type frame_type;
  spdylay_frame *frame;
  void *aux_data;
  int pri;
  int64_t seq;
} spdylay_outbound_item;

typedef struct {
  spdylay_outbound_item *item;
  uint8_t *framebuf;
  size_t framebuflen;
  size_t framebufoff;
} spdylay_active_outbound_item;

typedef struct {
  uint8_t buf[4096];
  uint8_t *mark;
  uint8_t *limit;
} spdylay_inbound_buffer;

typedef enum {
  SPDYLAY_RECV_HEAD,
  SPDYLAY_RECV_PAYLOAD
} spdylay_inbound_state;

#define SPDYLAY_HEAD_LEN 8

/* Maximum unique ID in use for PING. If unique ID exeeds this number,
   it wraps to 1 (client) or 2 (server) */
#define SPDYLAY_MAX_UNIQUE_ID ((1u << 31)-1)

typedef struct {
  spdylay_inbound_state state;
  uint8_t headbuf[SPDYLAY_HEAD_LEN];
  /* NULL if inbound frame is data frame */
  uint8_t *buf;
  /* length in Length field */
  size_t len;
  size_t off;
  uint8_t ign;
} spdylay_inbound_frame;

typedef enum {
  SPDYLAY_GOAWAY_NONE = 0,
  /* Flag means GOAWAY frame is sent to the remote peer. */
  SPDYLAY_GOAWAY_SEND = 0x1,
  /* Flag means GOAWAY frame is received from the remote peer. */
  SPDYLAY_GOAWAY_RECV = 0x2
} spdylay_goaway_flag;

struct spdylay_session {
  uint8_t server;
  int32_t next_stream_id;
  int32_t last_recv_stream_id;
  /* Counter of unique ID of PING. Wraps when it exceeds
     SPDYLAY_MAX_UNIQUE_ID */
  uint32_t next_unique_id;

  /* Sequence number of outbound frame to maintain the order of
     enqueue if priority is equal. */
  int64_t next_seq;

  spdylay_map /* <spdylay_stream*> */ streams;
  /* Queue for outbound frames other than SYN_STREAM */
  spdylay_pq /* <spdylay_outbound_item*> */ ob_pq;
  /* Queue for outbound SYN_STREAM frame */
  spdylay_pq /* <spdylay_outbound_item*> */ ob_ss_pq;

  spdylay_active_outbound_item aob;

  spdylay_inbound_buffer ibuf;
  spdylay_inbound_frame iframe;

  spdylay_zlib hd_deflater;
  spdylay_zlib hd_inflater;

  /* The last unique ID sent to the peer. */
  uint32_t last_ping_unique_id;

  /* Flags indicating GOAWAY is sent and/or recieved. The flags are
     composed by bitwise OR-ing spdylay_goaway_flag. */
  uint8_t goaway_flags;
  /* This is the value in GOAWAY frame sent by remote endpoint. */
  int32_t last_good_stream_id;

  /* Settings value store. We just use ID as index. The index = 0 is
     unused. */
  uint32_t settings[SPDYLAY_SETTINGS_MAX+1];

  spdylay_session_callbacks callbacks;
  void *user_data;
};

typedef struct {
  spdylay_data_provider *data_prd;
  void *stream_user_data;
} spdylay_syn_stream_aux_data;

/* TODO stream timeout etc */

/*
 * Returns non-zero value if |stream_id| is initiated by local host.
 * Otherwrise returns 0.
 */
int spdylay_session_is_my_stream_id(spdylay_session *session,
                                    int32_t stream_id);

/*
 * Adds frame |frame| of type |frame_type| to tx queue in |session|.
 * |aux_data| is a pointer to arbitrary data. Its interpretation is
 * defined per |frame_type|. When this function succeeds, it takes
 * ownership of |frame| and |aux_data|, so caller must not free them.
 * This function returns 0 if it succeeds, or negative error code.
 */
int spdylay_session_add_frame(spdylay_session *session,
                              spdylay_frame_type frame_type,
                              spdylay_frame *frame,
                              void *aux_data);

int spdylay_session_add_rst_stream(spdylay_session *session,
                                   int32_t stream_id, uint32_t status_code);

int spdylay_session_add_ping(spdylay_session *session, uint32_t unique_id);

int spdylay_session_add_goaway(spdylay_session *session,
                               int32_t last_good_stream_id);

/*
 * Creates new stream in |session| with stream ID |stream_id|,
 * priority |pri| and flags |flags|. Currently, |flags| &
 * SPDYLAY_FLAG_UNIDIRECTIONAL is non-zero, this stream is
 * unidirectional. |flags| & SPDYLAY_FLAG_FIN is non-zero, the sender
 * of SYN_STREAM will not send any further data in this stream.  The
 * state of stream is set to |initial_state|.  This function returns a
 * pointer to created new stream object, or NULL.
 */
spdylay_stream* spdylay_session_open_stream(spdylay_session *session,
                                            int32_t stream_id,
                                            uint8_t flags, uint8_t pri,
                                            spdylay_stream_state initial_state,
                                            void *stream_user_data);

/*
 * Closes stream whose stream ID is |stream_id|. The reason of closure
 * is indicated by |status_code|. This function returns 0 if it
 * succeeds, or negative error code.  The possible error code is
 * SPDYLAY_ERR_INVALID_ARGUMENT, which is used when stream |stream_id|
 * does not exist. So the caller may ignore this error.
 */
int spdylay_session_close_stream(spdylay_session *session, int32_t stream_id,
                                 spdylay_status_code status_code);

/*
 * Closes all pushed streams which associate them to stream
 * |stream_id| with the status code |status_code|.
 */
void spdylay_session_close_pushed_streams(spdylay_session *session,
                                          int32_t stream_id,
                                          spdylay_status_code status_code);

/*
 * If further receptions and transmissions over this stream are
 * disallowed, close this stream. This function returns 0 if it
 * succeeds, or negative error code. If either receptions or
 * transmissions is allowed, this function returns 0 and the stream
 * will not be closed.
 */
int spdylay_session_close_stream_if_shut_rdwr(spdylay_session *session,
                                              spdylay_stream *stream);

/*
 * Called when SYN_STREAM is received. Received frame is |frame|.
 * This function does first validate received frame and then open
 * stream and call callback functions.  This function returns 0 if it
 * succeeds, or negative error code.  This function does not return
 * error if frame is not valid.
 */
int spdylay_session_on_syn_stream_received(spdylay_session *session,
                                           spdylay_frame *frame);

/*
 * Called when SYN_REPLY is received. Received frame is |frame|.
 */
int spdylay_session_on_syn_reply_received(spdylay_session *session,
                                          spdylay_frame *frame);


/*
 * Called when RST_STREAM is received. Received frame is |frame|.
 */
int spdylay_session_on_rst_stream_received(spdylay_session *session,
                                           spdylay_frame *frame);

/*
 * Called when SETTINGS is received. Received frame is |frame|.
 */
int spdylay_session_on_settings_received(spdylay_session *session,
                                         spdylay_frame *frame);

/*
 * Called when PING is received. Received frame is |frame|.
 */
int spdylay_session_on_ping_received(spdylay_session *session,
                                     spdylay_frame *frame);

/*
 * Called when GOAWAY is received. Received frame is |frame|.
 */
int spdylay_session_on_goaway_received(spdylay_session *session,
                                       spdylay_frame *frame);

/*
 * Called when HEADERS is recieved. Received frame is |frame|.
 */
int spdylay_session_on_headers_received(spdylay_session *session,
                                        spdylay_frame *frame);

/*
 * Called when DATA is received.
 */
int spdylay_session_on_data_received(spdylay_session *session,
                                     uint8_t flags, int32_t length,
                                     int32_t stream_id);

/*
 * Returns spdylay_stream* object whose stream ID is |stream_id|.  It
 * could be NULL if such stream does not exist.
 */
spdylay_stream* spdylay_session_get_stream(spdylay_session *session,
                                           int32_t stream_id);

/*
 * Packs DATA frame |frame| in wire frame format and store it in
 * |*buf_ptr|.  This function always allocates
 * 8+SPDYLAY_DATA_CHUNK_LENGTH bytes. It packs header in first 8
 * bytes. Remaining bytes are filled using frame->data_prd.  This
 * function returns the size of packed frame if it succeeds, or
 * negative error code.
 */
ssize_t spdylay_session_pack_data(spdylay_session *session,
                                  uint8_t **buf_ptr, spdylay_data *frame);

/*
 * Packs DATA frame |frame| in wire frame format and store it in
 * |buf|.  |len| must be greater than or equal to 8.  This function
 * returns the sizeof packed frame if it succeeds, or negative error
 * code.
 */
ssize_t spdylay_session_pack_data_overwrite(spdylay_session *session,
                                            uint8_t *buf, size_t len,
                                            spdylay_data *frame);

/*
 * Returns next unique ID which can be used with PING.
 */
uint32_t spdylay_session_get_next_unique_id(spdylay_session *session);

/*
 * Returns top of outbound frame queue. This function returns NULL if
 * queue is empty.
 */
spdylay_outbound_item* spdylay_session_get_ob_pq_top(spdylay_session *session);

/*
 * Pops and returns next item to send. If there is no such item,
 * returns NULL.  This function takes into account max concurrent
 * streams. That means if session->ob_pq is empty but
 * session->ob_ss_pq has item and max concurrent streams is reached,
 * then this function returns NULL.
 */
spdylay_outbound_item* spdylay_session_pop_next_ob_item
(spdylay_session *session);

/*
 * Returns next item to send. If there is no such item, this function
 * returns NULL.  This function takes into account max concurrent
 * streams. That means if session->ob_pq is empty but
 * session->ob_ss_pq has item and max concurrent streams is reached,
 * then this function returns NULL.
 */
spdylay_outbound_item* spdylay_session_get_next_ob_item
(spdylay_session *session);

/*
 * Deallocates resource for |item|. If |item| is NULL, this function
 * does nothing.
 */
void spdylay_outbound_item_free(spdylay_outbound_item *item);

#endif /* SPDYLAY_SESSION_H */
