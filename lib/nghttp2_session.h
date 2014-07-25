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
#include "nghttp2_outbound_item.h"
#include "nghttp2_int.h"
#include "nghttp2_buf.h"

/*
 * Option flags.
 */
typedef enum {
  NGHTTP2_OPTMASK_NO_AUTO_WINDOW_UPDATE = 1 << 0,
} nghttp2_optmask;

typedef enum {
  NGHTTP2_OB_POP_ITEM,
  NGHTTP2_OB_SEND_DATA
} nghttp2_outbound_state;

typedef struct {
  nghttp2_outbound_item *item;
  nghttp2_bufs framebufs;
  nghttp2_outbound_state state;
} nghttp2_active_outbound_item;

/* Buffer length for inbound raw byte stream used in
   nghttp2_session_recv(). */
#define NGHTTP2_INBOUND_BUFFER_LENGTH 16384

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
  NGHTTP2_IB_READ_ALTSVC,
  NGHTTP2_IB_EXPECT_CONTINUATION,
  NGHTTP2_IB_IGN_CONTINUATION,
  NGHTTP2_IB_READ_PAD_DATA,
  NGHTTP2_IB_READ_DATA,
  NGHTTP2_IB_IGN_DATA
} nghttp2_inbound_state;

#define NGHTTP2_INBOUND_NUM_IV 5

typedef struct {
  nghttp2_frame frame;
  /* Storage for extension frame payload.  frame->ext.payload points
     to this structure to avoid frequent memory allocation. */
  nghttp2_ext_frame_payload ext_frame_payload;
  /* The received SETTINGS entry. The protocol says that we only cares
     about the defined settings ID. If unknown ID is received, it is
     ignored.  We use last entry to hold minimum header table size if
     same settings are multiple times. */
  nghttp2_settings_entry iv[NGHTTP2_INBOUND_NUM_IV];
  /* buffer pointers to small buffer, raw_sbuf */
  nghttp2_buf sbuf;
  /* buffer pointers to large buffer, raw_lbuf */
  nghttp2_buf lbuf;
  /* Large buffer, malloced on demand */
  uint8_t *raw_lbuf;
  /* The number of entry filled in |iv| */
  size_t niv;
  /* How many bytes we still need to receive for current frame */
  size_t payloadleft;
  /* padding length for the current frame */
  size_t padlen;
  /* Sum of payload of (HEADERS | PUSH_PROMISE) + possible
     CONTINUATION received so far. */
  size_t headers_payload_length;
  nghttp2_inbound_state state;
  uint8_t raw_sbuf[8];
} nghttp2_inbound_frame;

typedef struct {
  uint32_t header_table_size;
  uint32_t enable_push;
  uint32_t max_concurrent_streams;
  uint32_t initial_window_size;
} nghttp2_settings_storage;

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
  nghttp2_stream_roots roots;
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
  /* Reset count of nghttp2_outbound_item's weight.  We decrements
     weight each time DATA is sent to simulate resource sharing.  We
     use priority queue and larger weight has the precedence.  If
     weight is reached to lowest weight, it resets to its initial
     weight.  If this happens, other items which have the lower weight
     currently but same initial weight cannot send DATA until item
     having large weight is decreased.  To avoid this, we use this
     cycle variable.  Initally, this is set to 1.  If weight gets
     lowest weight, and if item's cycle == last_cycle, we increments
     last_cycle and assigns it to item's cycle.  Otherwise, just
     assign last_cycle.  In priority queue comparator, we first
     compare items' cycle value.  Lower cycle value has the
     precedence. */
  uint64_t last_cycle;
  void *user_data;
  /* Points to the latest closed stream.  NULL if there is no closed
     stream.  Only used when session is initialized as server. */
  nghttp2_stream *closed_stream_head;
  /* Points to the oldest closed stream.  NULL if there is no closed
     stream.  Only used when session is initialized as server. */
  nghttp2_stream *closed_stream_tail;
  /* In-flight SETTINGS values. NULL does not necessarily mean there
     is no in-flight SETTINGS. */
  nghttp2_settings_entry *inflight_iv;
  /* The number of entries in |inflight_iv|. -1 if there is no
     in-flight SETTINGS. */
  ssize_t inflight_niv;
  /* The number of outgoing streams. This will be capped by
     remote_settings.max_concurrent_streams. */
  size_t num_outgoing_streams;
  /* The number of incoming streams. This will be capped by
     local_settings.max_concurrent_streams. */
  size_t num_incoming_streams;
  /* The number of closed streams still kept in |streams| hash.  The
     closed streams can be accessed through single linked list
     |closed_stream_head|.  The current implementation only keeps
     incoming streams and session is initialized as server. */
  size_t num_closed_streams;
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
  /* This is the last-stream-ID we have sent in GOAWAY */
  int32_t local_last_stream_id;
  /* This is the value in GOAWAY frame received from remote endpoint. */
  int32_t remote_last_stream_id;
  /* Current sender window size. This value is computed against the
     current initial window size of remote endpoint. */
  int32_t remote_window_size;
  /* Keep track of the number of bytes received without
     WINDOW_UPDATE. This could be negative after submitting negative
     value to WINDOW_UPDATE. */
  int32_t recv_window_size;
  /* The number of bytes consumed by the application and now is
     subject to WINDOW_UPDATE.  This is only used when auto
     WINDOW_UPDATE is turned off. */
  int32_t consumed_size;
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
  nghttp2_settings_storage remote_settings;
  /* Settings value of the local endpoint. */
  nghttp2_settings_storage local_settings;
  /* Option flags. This is bitwise-OR of 0 or more of nghttp2_optmask. */
  uint32_t opt_flags;
  /* Unacked local SETTINGS_MAX_CONCURRENT_STREAMS value. We use this
     to refuse the incoming stream if it exceeds this value. */
  uint32_t pending_local_max_concurrent_stream;
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
 * This function simply returns 0 without adding RST_STREAM frame if
 * given stream is in NGHTTP2_STREAM_CLOSING state, because multiple
 * RST_STREAM for a stream is redundant.
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
                             const uint8_t *opaque_data);

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
 * NGHTTP2_ERR_INVALID_ARGUMENT
 *     The |opaque_data_len| is too large.
 */
int nghttp2_session_add_goaway(nghttp2_session *session,
                               int32_t last_stream_id,
                               nghttp2_error_code error_code,
                               const uint8_t *opaque_data,
                               size_t opaque_data_len);

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
 * priority |pri_spec| and flags |flags|.  The |flags| is bitwise OR
 * of nghttp2_stream_flag.  Since this function is called when initial
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
                                            uint8_t flags,
                                            nghttp2_priority_spec *pri_spec,
                                            nghttp2_stream_state initial_state,
                                            void *stream_user_data);

/*
 * Closes stream whose stream ID is |stream_id|. The reason of closure
 * is indicated by the |error_code|. When closing the stream,
 * on_stream_close_callback will be called.
 *
 * If the session is initialized as server and |stream| is incoming
 * stream, stream is just marked closed and this function calls
 * nghttp2_session_keep_closed_stream() with |stream|.  Otherwise,
 * |stream| will be deleted from memory.
 *
 * This function returns 0 if it succeeds, or one the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 * NGHTTP2_ERR_INVALID_ARGUMENT
 *     The specified stream does not exist.
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *     The callback function failed.
 */
int nghttp2_session_close_stream(nghttp2_session *session, int32_t stream_id,
                                 nghttp2_error_code error_code);

/*
 * Deletes |stream| from memory.  After this function returns, stream
 * cannot be accessed.
 *
 */
void nghttp2_session_destroy_stream(nghttp2_session *session,
                                    nghttp2_stream *stream);

/*
 * Tries to keep incoming closed stream |stream|.  Due to the
 * limitation of maximum number of streams in memory, |stream| is not
 * closed and just deleted from memory (see
 * nghttp2_session_destroy_stream).
 */
void nghttp2_session_keep_closed_stream(nghttp2_session *session,
                                        nghttp2_stream *stream);

/*
 * Deletes closed stream to ensure that number of incoming streams
 * including active and closed is in the maximum number of allowed
 * stream.  If |offset| is nonzero, it is decreased from the maximum
 * number of allowed stream when comparing number of active and closed
 * stream and the maximum number.
 */
void nghttp2_session_adjust_closed_stream(nghttp2_session *session,
                                          ssize_t offset);

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
 * NGHTTP2_ERR_IGN_HEADER_BLOCK
 *     Frame was rejected and header block must be decoded but
 *     result must be ignored.
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *     The read_callback failed
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
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *     The read_callback failed
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
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *     The read_callback failed
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
 * NGHTTP2_ERR_IGN_HEADER_BLOCK
 *     Frame was rejected and header block must be decoded but
 *     result must be ignored.
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *     The read_callback failed
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
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *   The callback function failed.
 */
int nghttp2_session_on_ping_received(nghttp2_session *session,
                                     nghttp2_frame *frame);

/*
 * Called when GOAWAY is received, assuming |frame| is properly
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
 * NGHTTP2_ERR_CALLBACK_FAILURE
 *   The callback function failed.
 */
int nghttp2_session_on_window_update_received(nghttp2_session *session,
                                              nghttp2_frame *frame);

/*
 * Called when ALTSVC is received, assuming |frame| is properly
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
int nghttp2_session_on_altsvc_received(nghttp2_session *session,
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
 * could be NULL if such stream does not exist.  This function returns
 * NULL if stream is marked as closed.
 */
nghttp2_stream* nghttp2_session_get_stream(nghttp2_session *session,
                                           int32_t stream_id);

/*
 * This function behaves like nghttp2_session_get_stream(), but it
 * returns stream object even if it is marked as closed.
 */
nghttp2_stream* nghttp2_session_get_stream_raw(nghttp2_session *session,
                                               int32_t stream_id);

/*
 * Packs DATA frame |frame| in wire frame format and stores it in
 * |*buf_ptr|.  The capacity of |*buf_ptr| is |*buflen_ptr|
 * length. This function expands |*buf_ptr| as necessary to store
 * given |frame|. It packs header in first 8 bytes starting
 * |*bufoff_ptr| offset. The |*bufoff_ptr| is calculated based on
 * usage of padding. Remaining bytes are the DATA apyload and are
 * filled using |frame->data_prd|. The length of payload is at most
 * |datamax| bytes.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
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
int nghttp2_session_pack_data(nghttp2_session *session,
                              nghttp2_bufs *bufs,
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
 * Re-prioritize |stream|. The new priority specification is
 * |pri_spec|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_session_reprioritize_stream
(nghttp2_session *session, nghttp2_stream *stream,
 const nghttp2_priority_spec *pri_spec);

/*
 * Terminates current |session| with the |error_code|.  The |reason|
 * is NULL-terminated debug string.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_INVALID_ARGUMENT
 *     The |reason| is too long.
 */
int nghttp2_session_terminate_session_with_reason
(nghttp2_session *session, nghttp2_error_code error_code, const char *reason);

#endif /* NGHTTP2_SESSION_H */
