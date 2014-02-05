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
#ifndef NGHTTP2_SESSION_H
#define NGHTTP2_SESSION_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <nghttp2/nghttp2.h>
#include "nghttp2_pq.h"
#include "nghttp2_map.h"
#include "nghttp2_frame.h"
#include "nghttp2_hd.h"
#include "nghttp2_stream.h"
#include "nghttp2_buffer.h"
#include "nghttp2_outbound_item.h"
#include "nghttp2_int.h"

/*
 * Option flags.
 */
typedef enum {
  NGHTTP2_OPTMASK_NO_AUTO_STREAM_WINDOW_UPDATE = 1 << 0,
  NGHTTP2_OPTMASK_NO_AUTO_CONNECTION_WINDOW_UPDATE = 1 << 1
} nghttp2_optmask;

typedef struct {
  nghttp2_outbound_item *item;
  /* Buffer for outbound frames. Used to pack one frame. The memory
     pointed by framebuf is initially allocated by
     nghttp2_session_{client,server}_new() and deallocated by
     nghttp2_session_del() */
  uint8_t *framebuf;
  /* The capacity of framebuf in bytes */
  size_t framebufmax;
  /* The length of the frame stored in framebuf */
  size_t framebuflen;
  /* The number of bytes has been sent */
  size_t framebufoff;
  /* Marks the last position to send. This is used to implement
     CONTINUATION */
  size_t framebufmark;
} nghttp2_active_outbound_item;

/* Buffer length for inbound raw byte stream. */
#define NGHTTP2_INBOUND_BUFFER_LENGTH 16384

#define NGHTTP2_INITIAL_OUTBOUND_FRAMEBUF_LENGTH (NGHTTP2_DATA_PAYLOAD_LENGTH+8)
#define NGHTTP2_INITIAL_INBOUND_FRAMEBUF_LENGTH \
  NGHTTP2_INITIAL_OUTBOUND_FRAMEBUF_LENGTH
#define NGHTTP2_INITIAL_NV_BUFFER_LENGTH 4096

/* Internal state when receiving incoming frame */
typedef enum {
  /* Receiving frame header */
  NGHTTP2_IB_READ_HEAD,
  NGHTTP2_IB_READ_NBYTE,
  NGHTTP2_IB_READ_HEADER_BLOCK,
  NGHTTP2_IB_IGN_HEADER_BLOCK,
  NGHTTP2_IB_IGN_PAYLOAD,
  NGHTTP2_IB_FRAME_SIZE_ERROR,
  NGHTTP2_IB_READ_SETTINGS,
  NGHTTP2_IB_READ_GOAWAY_DEBUG,
  NGHTTP2_IB_EXPECT_CONTINUATION,
  NGHTTP2_IB_IGN_CONTINUATION,
  NGHTTP2_IB_READ_DATA,
  NGHTTP2_IB_IGN_DATA
} nghttp2_inbound_state;

typedef struct {
  nghttp2_frame frame;
  /* The received SETTINGS entry. The protocol says that we only cares
     about the defined settings ID. If unknown ID is received, it is
     subject to connection error */
  nghttp2_settings_entry iv[5];
  /* The number of entry filled in |iv| */
  size_t niv;
  /* How many bytes we still need to receive in the |buf| */
  size_t left;
  /* How many bytes we still need to receive for current frame */
  size_t payloadleft;
  nghttp2_inbound_state state;
  /* TODO, remove this. Error code */
  int error_code;
  uint8_t buf[8];
  /* How many bytes have been written to |buf| */
  uint8_t buflen;
} nghttp2_inbound_frame;

typedef enum {
  NGHTTP2_GOAWAY_NONE = 0,
  /* Flag means GOAWAY frame is sent to the remote peer. */
  NGHTTP2_GOAWAY_SEND = 0x1,
  /* Flag means GOAWAY frame is received from the remote peer. */
  NGHTTP2_GOAWAY_RECV = 0x2,
  /* Flag means connection should be dropped after sending GOAWAY. */
  NGHTTP2_GOAWAY_FAIL_ON_SEND = 0x4
} nghttp2_goaway_flag;

struct nghttp2_session {
  nghttp2_map /* <nghttp2_stream*> */ streams;
  /* Queue for outbound frames other than stream-creating HEADERS */
  nghttp2_pq /* <nghttp2_outbound_item*> */ ob_pq;
  /* Queue for outbound stream-creating HEADERS frame */
  nghttp2_pq /* <nghttp2_outbound_item*> */ ob_ss_pq;
  nghttp2_active_outbound_item aob;
  nghttp2_inbound_frame iframe;
  nghttp2_hd_deflater hd_deflater;
  nghttp2_hd_inflater hd_inflater;
  nghttp2_session_callbacks callbacks;
  /* Sequence number of outbound frame to maintain the order of
     enqueue if priority is equal. */
  int64_t next_seq;
  void *user_data;
  /* In-flight SETTINGS values. NULL does not necessarily mean there
     is no in-flight SETTINGS. */
  nghttp2_settings_entry *inflight_iv;
  /* The number of entries in |inflight_iv|. -1 if there is no
     in-flight SETTINGS. */
  ssize_t inflight_niv;
  /* The number of outgoing streams. This will be capped by
     remote_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS]. */
  size_t num_outgoing_streams;
  /* The number of incoming streams. This will be capped by
     local_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS]. */
  size_t num_incoming_streams;
  /* The number of bytes allocated for nvbuf */
  size_t nvbuflen;
  /* Next Stream ID. Made unsigned int to detect >= (1 << 31). */
  uint32_t next_stream_id;
  /* The largest stream ID received so far */
  int32_t last_recv_stream_id;
  /* The largest stream ID which has been processed in some way. This
     value will be used as last-stream-id when sending GOAWAY
     frame. */
  int32_t last_proc_stream_id;
  /* Counter of unique ID of PING. Wraps when it exceeds
     NGHTTP2_MAX_UNIQUE_ID */
  uint32_t next_unique_id;
  /* This is the value in GOAWAY frame received from remote endpoint. */
  int32_t last_stream_id;
  /* Current sender window size. This value is computed against the
     current initial window size of remote endpoint. */
  int32_t remote_window_size;
  /* Keep track of the number of bytes received without
     WINDOW_UPDATE. This could be negative after submitting negative
     value to WINDOW_UPDATE. */
  int32_t recv_window_size;
  /* The amount of recv_window_size cut using submitting negative
     value to WINDOW_UPDATE */
  int32_t recv_reduction;
  /* window size for local flow control. It is initially set to
     NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE and could be
     increased/decreased by submitting WINDOW_UPDATE. See
     nghttp2_submit_window_update(). */
  int32_t local_window_size;
  /* Settings value received from the remote endpoint. We just use ID
     as index. The index = 0 is unused. */
  uint32_t remote_settings[NGHTTP2_SETTINGS_MAX+1];
  /* Settings value of the local endpoint. */
  uint32_t local_settings[NGHTTP2_SETTINGS_MAX+1];
  /* Option flags. This is bitwise-OR of 0 or more of nghttp2_optmask. */
  uint32_t opt_flags;
  /* Nonzero if the session is server side. */
  uint8_t server;
  /* Flags indicating GOAWAY is sent and/or recieved. The flags are
     composed by bitwise OR-ing nghttp2_goaway_flag. */
  uint8_t goaway_flags;
};

/* Struct used when updating initial window size of each active
   stream. */
typedef struct {
  nghttp2_session *session;
  int32_t new_window_size, old_window_size;
} nghttp2_update_window_size_arg;

/* TODO stream timeout etc */

/*
 * Returns nonzero value if |stream_id| is initiated by local
 * endpoint.
 */
int nghttp2_session_is_my_stream_id(nghttp2_session *session,
                                    int32_t stream_id);

/*
 * Adds frame |frame| to the outbound queue in |session|. The
 * |frame_cat| must be either NGHTTP2_CTRL or NGHTTP2_DATA. If the
 * |frame_cat| is NGHTTP2_CTRL, the |frame| must be a pointer to
 * nghttp2_frame. If the |frame_cat| is NGHTTP2_DATA, it must be a
 * pointer to nghttp2_private_data. |aux_data| is a pointer to the arbitrary
 * data. Its interpretation is defined per the type of the frame. When
 * this function succeeds, it takes ownership of |frame| and
 * |aux_data|, so caller must not free them on success.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_add_frame(nghttp2_session *session,
                              nghttp2_frame_category frame_cat,
                              void *abs_frame, void *aux_data);

/*
 * Adds RST_STREAM frame for the stream |stream_id| with the error
 * code |error_code|. This is a convenient function built on top of
 * nghttp2_session_add_frame() to add RST_STREAM easily.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_add_rst_stream(nghttp2_session *session,
                                   int32_t stream_id,
                                   nghttp2_error_code error_code);

/*
 * Adds PING frame. This is a convenient functin built on top of
 * nghttp2_session_add_frame() to add PING easily.
 *
 * If the |opaque_data| is not NULL, it must point to 8 bytes memory
 * region of data. The data pointed by |opaque_data| is copied. It can
 * be NULL. In this case, 8 bytes NULL is used.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_add_ping(nghttp2_session *session, uint8_t flags,
                             uint8_t *opaque_data);

/*
 * Adds GOAWAY frame with the last-stream-ID |last_stream_id| and the
 * error code |error_code|. This is a convenient function built on top
 * of nghttp2_session_add_frame() to add GOAWAY easily.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_add_goaway(nghttp2_session *session,
                               int32_t last_stream_id,
                               nghttp2_error_code error_code,
                               uint8_t *opaque_data, size_t opaque_data_len);

/*
 * Adds WINDOW_UPDATE frame with stream ID |stream_id| and
 * window-size-increment |window_size_increment|. This is a convenient
 * function built on top of nghttp2_session_add_frame() to add
 * WINDOW_UPDATE easily.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_add_window_update(nghttp2_session *session, uint8_t flags,
                                      int32_t stream_id,
                                      int32_t window_size_increment);

/*
 * Adds SETTINGS frame.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_add_settings(nghttp2_session *session, uint8_t flags,
                                 const nghttp2_settings_entry *iv, size_t niv);

/*
 * Creates new stream in |session| with stream ID |stream_id|,
 * priority |pri| and flags |flags|. NGHTTP2_FLAG_END_STREAM flag is
 * set in |flags|, the sender of HEADERS will not send any further
 * data in this stream. Since this function is called when initial
 * HEADERS is sent or received, these flags are taken from it.  The
 * state of stream is set to |initial_state|. The |stream_user_data|
 * is a pointer to the arbitrary user supplied data to be associated
 * to this stream.
 *
 * This function returns a pointer to created new stream object, or
 * NULL.
 */
nghttp2_stream* nghttp2_session_open_stream(nghttp2_session *session,
                                            int32_t stream_id,
                                            uint8_t flags, int32_t pri,
                                            nghttp2_stream_state initial_state,
                                            void *stream_user_data);

/*
 * Closes stream whose stream ID is |stream_id|. The reason of closure
 * is indicated by the |error_code|. When closing the stream,
 * on_stream_close_callback will be called.
 *
 * This function returns 0 if it succeeds, or one the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_ARGUMENT
 *     The specified stream does not exist.
 */
int nghttp2_session_close_stream(nghttp2_session *session, int32_t stream_id,
                                 nghttp2_error_code error_code);

/*
 * If further receptions and transmissions over the stream |stream_id|
 * are disallowed, close the stream with error code NGHTTP2_NO_ERROR.
 *
 * This function returns 0 if it
 * succeeds, or one of the following negative error codes:
 *
 * NGHTTP2_ERR_INVALID_ARGUMENT
 *     The specified stream does not exist.
 */
int nghttp2_session_close_stream_if_shut_rdwr(nghttp2_session *session,
                                              nghttp2_stream *stream);


int nghttp2_session_end_request_headers_received(nghttp2_session *session,
                                                 nghttp2_frame *frame,
                                                 nghttp2_stream *stream);

int nghttp2_session_end_response_headers_received(nghttp2_session *session,
                                                  nghttp2_frame *frame,
                                                  nghttp2_stream *stream);

int nghttp2_session_end_headers_received(nghttp2_session *session,
                                         nghttp2_frame *frame,
                                         nghttp2_stream *stream);

int nghttp2_session_on_request_headers_received(nghttp2_session *session,
                                                nghttp2_frame *frame);

int nghttp2_session_on_response_headers_received(nghttp2_session *session,
                                                 nghttp2_frame *frame,
                                                 nghttp2_stream *stream);

int nghttp2_session_on_push_response_headers_received(nghttp2_session *session,
                                                      nghttp2_frame *frame,
                                                      nghttp2_stream *stream);

/*
 * Called when HEADERS is received, assuming |frame| is properly
 * initialized.  This function does first validate received frame and
 * then open stream and call callback functions.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_on_headers_received(nghttp2_session *session,
                                        nghttp2_frame *frame,
                                        nghttp2_stream *stream);


/*
 * Called when PRIORITY is received, assuming |frame| is properly
 * initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_on_priority_received(nghttp2_session *session,
                                         nghttp2_frame *frame);

/*
 * Called when RST_STREAM is received, assuming |frame| is properly
 * initialized.
 *
 * This function returns 0 if it succeeds, or one the following
 * negative error codes:
 *
 * TBD
 */
int nghttp2_session_on_rst_stream_received(nghttp2_session *session,
                                           nghttp2_frame *frame);

/*
 * Called when SETTINGS is received, assuming |frame| is properly
 * initialized. If |noack| is non-zero, SETTINGS with ACK will not be
 * submitted. If |frame| has NGHTTP2_FLAG_ACK flag set, no SETTINGS
 * with ACK will not be submitted regardless of |noack|.
 *
 * This function returns 0 if it succeeds, or one the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 * NGHTTP2_ERR_PAUSE
 *     Callback function returns NGHTTP2_ERR_PAUSE
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *     The read_callback failed
 */
int nghttp2_session_on_settings_received(nghttp2_session *session,
                                         nghttp2_frame *frame,
                                         int noack);

/*
 * Called when PUSH_PROMISE is received, assuming |frame| is properly
 * initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_on_push_promise_received(nghttp2_session *session,
                                             nghttp2_frame *frame);

/*
 * Called when PING is received, assuming |frame| is properly
 * initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_on_ping_received(nghttp2_session *session,
                                     nghttp2_frame *frame);

/*
 * Called when GOAWAY is received, assuming |frame| is properly
 * initialized.
 *
 * This function returns 0 and never fail.
 */
int nghttp2_session_on_goaway_received(nghttp2_session *session,
                                       nghttp2_frame *frame);

/*
 * Called when WINDOW_UPDATE is recieved, assuming |frame| is properly
 * initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_on_window_update_received(nghttp2_session *session,
                                              nghttp2_frame *frame);

/*
 * Called when DATA is received, assuming |frame| is properly
 * initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *   The callback function failed.
 */
int nghttp2_session_on_data_received(nghttp2_session *session,
                                     nghttp2_frame *frame);

/*
 * Returns nghttp2_stream* object whose stream ID is |stream_id|.  It
 * could be NULL if such stream does not exist.
 */
nghttp2_stream* nghttp2_session_get_stream(nghttp2_session *session,
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
 * NGHTTP2_ERR_DEFERRED
 *     The DATA frame is postponed.
 * NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE
 *     The read_callback failed (stream error).
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *     The read_callback failed (session error).
 */
ssize_t nghttp2_session_pack_data(nghttp2_session *session,
                                  uint8_t **buf_ptr, size_t *buflen_ptr,
                                  size_t datamax,
                                  nghttp2_private_data *frame);

/*
 * Returns top of outbound frame queue. This function returns NULL if
 * queue is empty.
 */
nghttp2_outbound_item* nghttp2_session_get_ob_pq_top(nghttp2_session *session);

/*
 * Pops and returns next item to send. If there is no such item,
 * returns NULL.  This function takes into account max concurrent
 * streams. That means if session->ob_pq is empty but
 * session->ob_ss_pq has item and max concurrent streams is reached,
 * then this function returns NULL.
 */
nghttp2_outbound_item* nghttp2_session_pop_next_ob_item
(nghttp2_session *session);

/*
 * Returns next item to send. If there is no such item, this function
 * returns NULL.  This function takes into account max concurrent
 * streams. That means if session->ob_pq is empty but
 * session->ob_ss_pq has item and max concurrent streams is reached,
 * then this function returns NULL.
 */
nghttp2_outbound_item* nghttp2_session_get_next_ob_item
(nghttp2_session *session);

/*
 * Updates local settings with the |iv|. The number of elements in the
 * array pointed by the |iv| is given by the |niv|.  This function
 * assumes that the all settings_id member in |iv| are in range 1 to
 * NGHTTP2_SETTINGS_MAX, inclusive.
 *
 * While updating individual stream's local window size, if the window
 * size becomes strictly larger than NGHTTP2_MAX_WINDOW_SIZE,
 * RST_STREAM is issued against such a stream.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_session_update_local_settings(nghttp2_session *session,
                                          nghttp2_settings_entry *iv,
                                          size_t niv);

/*
 * Re-prioritize |stream|. The new priority is |pri|.
 */
void nghttp2_session_reprioritize_stream
(nghttp2_session *session, nghttp2_stream *stream, int32_t pri);

#endif /* NGHTTP2_SESSION_H */
