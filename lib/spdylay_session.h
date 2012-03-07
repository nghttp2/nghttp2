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
#include "spdylay_buffer.h"
#include "spdylay_outbound_item.h"

typedef struct {
  spdylay_outbound_item *item;
  /* Buffer for outbound frames. Used to pack one frame. The memory
     pointed by framebuf is initially allocated by
     spdylay_session_{client,server}_new() and deallocated by
     spdylay_session_del() */
  uint8_t *framebuf;
  /* The capacity of framebuf in bytes */
  size_t framebufmax;
  /* The length of the frame stored in framebuf */
  size_t framebuflen;
  /* The number of bytes has been sent */
  size_t framebufoff;
} spdylay_active_outbound_item;

/* Buffer length for inbound SPDY frames. Same value for the size of
   message block of SSLv3/TLSv1 */
#define SPDYLAY_INBOUND_BUFFER_LENGTH 16384

#define SPDYLAY_INITIAL_OUTBOUND_FRAMEBUF_LENGTH (SPDYLAY_DATA_PAYLOAD_LENGTH+8)
#define SPDYLAY_INITIAL_INBOUND_FRAMEBUF_LENGTH \
  SPDYLAY_INITIAL_OUTBOUND_FRAMEBUF_LENGTH
#define SPDYLAY_INITIAL_NV_BUFFER_LENGTH 4096

#define SPDYLAY_INITIAL_WINDOW_SIZE 65536

typedef struct {
  uint8_t buf[SPDYLAY_INBOUND_BUFFER_LENGTH];
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
  /* Payload for control frames. It is not used for DATA frames */
  uint8_t *buf;
  /* Capacity of buf */
  size_t bufmax;
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
  SPDYLAY_GOAWAY_RECV = 0x2,
  /* Flag means connection should be dropped after sending GOAWAY. */
  SPDYLAY_GOAWAY_FAIL_ON_SEND = 0x4
} spdylay_goaway_flag;

struct spdylay_session {
  /* The protocol version: either SPDYLAY_PROTO_SPDY2 or
     SPDYLAY_PROTO_SPDY3  */
  uint16_t version;
  uint8_t server;
  /* Next Stream ID. Made unsigned int to detect >= (1 << 31). */
  uint32_t next_stream_id;
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

  /* Buffer used to store inflated name/value pairs in wire format
     temporarily on pack/unpack. */
  uint8_t *nvbuf;
  /* The number of bytes allocated for nvbuf */
  size_t nvbuflen;
  /* Buffer used to store name/value pairs while inflating them using
     zlib on unpack */
  spdylay_buffer inflatebuf;

  spdylay_zlib hd_deflater;
  spdylay_zlib hd_inflater;

  /* The last unique ID sent to the peer. */
  uint32_t last_ping_unique_id;

  /* Flags indicating GOAWAY is sent and/or recieved. The flags are
     composed by bitwise OR-ing spdylay_goaway_flag. */
  uint8_t goaway_flags;
  /* This is the value in GOAWAY frame sent by remote endpoint. */
  int32_t last_good_stream_id;

  /* Flag to indicate whether this session enforces flow
     control. Nonzero for flow control enabled. */
  uint8_t flow_control;

  /* Settings value store. We just use ID as index. The index = 0 is
     unused. */
  uint32_t settings[SPDYLAY_SETTINGS_MAX+1];

  spdylay_session_callbacks callbacks;
  void *user_data;
};

/* TODO stream timeout etc */

/*
 * Returns nonzero value if |stream_id| is initiated by local
 * endpoint.
 */
int spdylay_session_is_my_stream_id(spdylay_session *session,
                                    int32_t stream_id);

/*
 * Adds frame |frame| of type |frame_type| to the outbound queue in
 * |session|.  |aux_data| is a pointer to the arbitrary data. Its
 * interpretation is defined per |frame_type|. When this function
 * succeeds, it takes ownership of |frame| and |aux_data|, so caller
 * must not free them on success.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_session_add_frame(spdylay_session *session,
                              spdylay_frame_type frame_type,
                              spdylay_frame *frame,
                              void *aux_data);

/*
 * Adds RST_STREAM frame for the stream |stream_id| with status code
 * |status_code|. This is a convenient function built on top of
 * spdylay_session_add_frame() to add RST_STREAM easily.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_session_add_rst_stream(spdylay_session *session,
                                   int32_t stream_id, uint32_t status_code);

/*
 * Adds PING frame with unique ID |unique_id|. This is a convenient
 * functin built on top of spdylay_session_add_frame() to add PING
 * easily.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_session_add_ping(spdylay_session *session, uint32_t unique_id);

/*
 * Adds GOAWAY frame with last-good-stream-ID |last_good_stream_id|
 * and the status code |status_code|. The |status_code| is ignored if
 * the protocol version is SPDYLAY_PROTO_SPDY2. This is a convenient
 * function built on top of spdylay_session_add_frame() to add GOAWAY
 * easily.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_session_add_goaway(spdylay_session *session,
                               int32_t last_good_stream_id,
                               uint32_t status_code);

/*
 * Adds WINDOW_UPDATE frame with stream ID |stream_id| and
 * delta-window-size |delta_window_size|. This is a convenient
 * function built on top of spdylay_session_add_frame() to add
 * WINDOW_UPDATE easily.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_session_add_window_update(spdylay_session *session,
                                      int32_t stream_id,
                                      int32_t delta_window_size);

/*
 * Creates new stream in |session| with stream ID |stream_id|,
 * priority |pri| and flags |flags|.  SPDYLAY_CTRL_FLAG_UNIDIRECTIONAL
 * flag is set in |flags|, this stream is
 * unidirectional. SPDYLAY_CTRL_FLAG_FIN flag is set in |flags|, the
 * sender of SYN_STREAM will not send any further data in this
 * stream. Since this function is called when SYN_STREAM is sent or
 * received, these flags are taken from SYN_STREAM.  The state of
 * stream is set to |initial_state|.  |stream_user_data| is a pointer
 * to the arbitrary user supplied data to be associated to this
 * stream.
 *
 * This function returns a pointer to created new stream object, or
 * NULL.
 */
spdylay_stream* spdylay_session_open_stream(spdylay_session *session,
                                            int32_t stream_id,
                                            uint8_t flags, uint8_t pri,
                                            spdylay_stream_state initial_state,
                                            void *stream_user_data);

/*
 * Closes stream whose stream ID is |stream_id|. The reason of closure
 * is indicated by |status_code|. When closing the stream,
 * on_stream_close_callback will be called.
 *
 * This function returns 0 if it succeeds, or one the following
 * negative error codes:
 *
 * SPDYLAY_ERR_INVALID_ARGUMENT
 *     The specified stream does not exist.
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
 * If further receptions and transmissions over the stream |stream_id|
 * are disallowed, close the stream with status code |status_code|.
 *
 * This function returns 0 if it
 * succeeds, or one of the following negative error codes:
 *
 * SPDYLAY_ERR_INVALID_ARGUMENT
 *     The specified stream does not exist.
 */
int spdylay_session_close_stream_if_shut_rdwr(spdylay_session *session,
                                              spdylay_stream *stream);

/*
 * Called when SYN_STREAM is received, assuming |frame.syn_stream| is
 * properly initialized.  This function does first validate received
 * frame and then open stream and call callback functions. This
 * function does not return error if frame is not valid.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_session_on_syn_stream_received(spdylay_session *session,
                                           spdylay_frame *frame);

/*
 * Called when SYN_REPLY is received, assuming |frame.syn_reply| is
 * properly initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_session_on_syn_reply_received(spdylay_session *session,
                                          spdylay_frame *frame);


/*
 * Called when RST_STREAM is received, assuming |frame.rst_stream| is
 * properly initialized.
 *
 * This function returns 0 and never fail.
 */
int spdylay_session_on_rst_stream_received(spdylay_session *session,
                                           spdylay_frame *frame);

/*
 * Called when SETTINGS is received, assuming |frame.settings| is
 * properly initialized.
 *
 * This function returns 0 and never fail.
 */
int spdylay_session_on_settings_received(spdylay_session *session,
                                         spdylay_frame *frame);

/*
 * Called when PING is received, assuming |frame.ping| is properly
 * initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_session_on_ping_received(spdylay_session *session,
                                     spdylay_frame *frame);

/*
 * Called when GOAWAY is received, assuming |frame.goaway| is properly
 * initialized.
 *
 * This function returns 0 and never fail.
 */
int spdylay_session_on_goaway_received(spdylay_session *session,
                                       spdylay_frame *frame);

/*
 * Called when HEADERS is recieved, assuming |frame.headers| is
 * properly initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_session_on_headers_received(spdylay_session *session,
                                        spdylay_frame *frame);

/*
 * Called when WINDOW_UPDATE is recieved, assuming
 * |frame.window_update| is properly initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_session_on_window_update_received(spdylay_session *session,
                                              spdylay_frame *frame);

/*
 * Called when DATA is received.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
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
 * Packs DATA frame |frame| in wire frame format and stores it in
 * |*buf_ptr|.  The capacity of |*buf_ptr| is |*buflen_ptr|
 * length. This function expands |*buf_ptr| as necessary to store
 * given |frame|. It packs header in first 8 bytes. Remaining bytes
 * are the DATA apyload and are filled using |frame->data_prd|. The
 * length of payload is at most |datamax| bytes.
 *
 * This function returns the size of packed frame if it succeeds, or
 * one of the following negative error codes:
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 * SPDYLAY_ERR_DEFERRED
 *     The DATA frame is postponed.
 * SPDYLAY_ERR_CALLBACK_FAILURE
 *     The read_callback failed.
 */
ssize_t spdylay_session_pack_data(spdylay_session *session,
                                  uint8_t **buf_ptr, size_t *buflen_ptr,
                                  size_t datamax,
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
 * Returns lowest priority value.
 */
uint8_t spdylay_session_get_pri_lowest(spdylay_session *session);

#endif /* SPDYLAY_SESSION_H */
