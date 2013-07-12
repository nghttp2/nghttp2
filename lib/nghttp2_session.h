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
#include "nghttp2_zlib.h"
#include "nghttp2_stream.h"
#include "nghttp2_buffer.h"
#include "nghttp2_outbound_item.h"
#include "nghttp2_client_cert_vector.h"

/**
 * @macro
 * Lowest priority value in SPDY/2, which is 3.
 */
#define NGHTTP2_PRI_LOWEST_SPDY2 3
/**
 * @macro
 * Lowest priority value in SPDY/3, which is 7.
 */
#define NGHTTP2_PRI_LOWEST_SPDY3 7

/*
 * Option flags.
 */
typedef enum {
  NGHTTP2_OPTMASK_NO_AUTO_WINDOW_UPDATE = 1 << 0
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
} nghttp2_active_outbound_item;

/* Buffer length for inbound raw byte stream. */
#define NGHTTP2_INBOUND_BUFFER_LENGTH 16384

#define NGHTTP2_INITIAL_OUTBOUND_FRAMEBUF_LENGTH (NGHTTP2_DATA_PAYLOAD_LENGTH+8)
#define NGHTTP2_INITIAL_INBOUND_FRAMEBUF_LENGTH \
  NGHTTP2_INITIAL_OUTBOUND_FRAMEBUF_LENGTH
#define NGHTTP2_INITIAL_NV_BUFFER_LENGTH 4096

#define NGHTTP2_INITIAL_WINDOW_SIZE 65536

/* Initial size of client certificate vector */
#define NGHTTP2_INITIAL_CLIENT_CERT_VECTOR_LENGTH 8
/* Maxmum size of client certificate vector */
#define NGHTTP2_MAX_CLIENT_CERT_VECTOR_LENGTH 255

/* Internal state when receiving incoming frame */
typedef enum {
  /* Receiving frame header */
  NGHTTP2_RECV_HEAD,
  /* Receiving frame payload (comes after length field) */
  NGHTTP2_RECV_PAYLOAD,
  /* Receiving frame payload, but the received bytes are discarded. */
  NGHTTP2_RECV_PAYLOAD_IGN,
  /* Receiving frame payload that comes before name/value header
     block. Applied only for SYN_STREAM, SYN_REPLY and HEADERS. */
  NGHTTP2_RECV_PAYLOAD_PRE_NV,
  /* Receiving name/value header block in frame payload. Applied only
     for SYN_STREAM, SYN_REPLY and HEADERS. */
  NGHTTP2_RECV_PAYLOAD_NV
} nghttp2_inbound_state;

#define NGHTTP2_HEAD_LEN 8

/* Maximum unique ID in use for PING. If unique ID exeeds this number,
   it wraps to 1 (client) or 2 (server) */
#define NGHTTP2_MAX_UNIQUE_ID ((1u << 31)-1)

typedef struct {
  nghttp2_inbound_state state;
  uint8_t headbuf[NGHTTP2_HEAD_LEN];
  /* How many bytes are filled in headbuf */
  size_t headbufoff;
  /* Payload for control frames. It is not used for DATA frames */
  uint8_t *buf;
  /* Capacity of buf */
  size_t bufmax;
  /* For frames without name/value header block, this is how many
     bytes are going to filled in buf. For frames with the block, buf
     only contains bytes that come before ther block, but this value
     includes the length of the block. buflen <= bufmax must be
     fulfilled. */
  size_t buflen;
  /* length in Length field */
  size_t payloadlen;
  /* How many bytes are received for this frame. off <= payloadlen
     must be fulfilled. */
  size_t off;
  /* Buffer used to store name/value pairs while inflating them using
     zlib on unpack */
  nghttp2_buffer inflatebuf;
  /* Error code */
  int error_code;
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
  /* The protocol version: either NGHTTP2_PROTO_SPDY2 or
     NGHTTP2_PROTO_SPDY3  */
  uint16_t version;
  uint8_t server;
  /* Next Stream ID. Made unsigned int to detect >= (1 << 31). */
  uint32_t next_stream_id;
  int32_t last_recv_stream_id;
  /* Counter of unique ID of PING. Wraps when it exceeds
     NGHTTP2_MAX_UNIQUE_ID */
  uint32_t next_unique_id;

  /* Sequence number of outbound frame to maintain the order of
     enqueue if priority is equal. */
  int64_t next_seq;

  nghttp2_map /* <nghttp2_stream*> */ streams;
  /* The number of outgoing streams. This will be capped by
     remote_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS]. */
  size_t num_outgoing_streams;
  /* The number of incoming streams. This will be capped by
     local_settings[NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS]. */
  size_t num_incoming_streams;

  /* Queue for outbound frames other than SYN_STREAM */
  nghttp2_pq /* <nghttp2_outbound_item*> */ ob_pq;
  /* Queue for outbound SYN_STREAM frame */
  nghttp2_pq /* <nghttp2_outbound_item*> */ ob_ss_pq;

  nghttp2_active_outbound_item aob;

  nghttp2_inbound_frame iframe;

  /* Buffer used to store inflated name/value pairs in wire format
     temporarily on pack/unpack. */
  uint8_t *nvbuf;
  /* The number of bytes allocated for nvbuf */
  size_t nvbuflen;

  nghttp2_zlib hd_deflater;
  nghttp2_zlib hd_inflater;

  /* The last unique ID sent to the peer. */
  uint32_t last_ping_unique_id;

  /* Flags indicating GOAWAY is sent and/or recieved. The flags are
     composed by bitwise OR-ing nghttp2_goaway_flag. */
  uint8_t goaway_flags;
  /* This is the value in GOAWAY frame sent by remote endpoint. */
  int32_t last_good_stream_id;

  /* Flag to indicate whether this session enforces flow
     control. Nonzero for flow control enabled. */
  uint8_t flow_control;

  /* Settings value received from the remote endpoint. We just use ID
     as index. The index = 0 is unused. */
  uint32_t remote_settings[NGHTTP2_SETTINGS_MAX+1];
  /* Settings value of the local endpoint. */
  uint32_t local_settings[NGHTTP2_SETTINGS_MAX+1];

  /* Option flags. This is bitwise-OR of 0 or more of nghttp2_optmask. */
  uint32_t opt_flags;
  /* Maxmum size of buffer to use when receving control frame. */
  uint32_t max_recv_ctrl_frame_buf;

  /* Client certificate vector */
  nghttp2_client_cert_vector cli_certvec;

  nghttp2_session_callbacks callbacks;
  void *user_data;
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
 * pointer to nghttp2_data. |aux_data| is a pointer to the arbitrary
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
 * Adds RST_STREAM frame for the stream |stream_id| with status code
 * |status_code|. This is a convenient function built on top of
 * nghttp2_session_add_frame() to add RST_STREAM easily.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_add_rst_stream(nghttp2_session *session,
                                   int32_t stream_id, uint32_t status_code);

/*
 * Adds PING frame with unique ID |unique_id|. This is a convenient
 * functin built on top of nghttp2_session_add_frame() to add PING
 * easily.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_add_ping(nghttp2_session *session, uint32_t unique_id);

/*
 * Adds GOAWAY frame with last-good-stream-ID |last_good_stream_id|
 * and the status code |status_code|. The |status_code| is ignored if
 * the protocol version is NGHTTP2_PROTO_SPDY2. This is a convenient
 * function built on top of nghttp2_session_add_frame() to add GOAWAY
 * easily.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_add_goaway(nghttp2_session *session,
                               int32_t last_good_stream_id,
                               uint32_t status_code);

/*
 * Adds WINDOW_UPDATE frame with stream ID |stream_id| and
 * delta-window-size |delta_window_size|. This is a convenient
 * function built on top of nghttp2_session_add_frame() to add
 * WINDOW_UPDATE easily.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_add_window_update(nghttp2_session *session,
                                      int32_t stream_id,
                                      int32_t delta_window_size);

/*
 * Creates new stream in |session| with stream ID |stream_id|,
 * priority |pri| and flags |flags|.  NGHTTP2_CTRL_FLAG_UNIDIRECTIONAL
 * flag is set in |flags|, this stream is
 * unidirectional. NGHTTP2_CTRL_FLAG_FIN flag is set in |flags|, the
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
nghttp2_stream* nghttp2_session_open_stream(nghttp2_session *session,
                                            int32_t stream_id,
                                            uint8_t flags, uint8_t pri,
                                            nghttp2_stream_state initial_state,
                                            void *stream_user_data);

/*
 * Closes stream whose stream ID is |stream_id|. The reason of closure
 * is indicated by |status_code|. When closing the stream,
 * on_stream_close_callback will be called.
 *
 * This function returns 0 if it succeeds, or one the following
 * negative error codes:
 *
 * NGHTTP2_ERR_INVALID_ARGUMENT
 *     The specified stream does not exist.
 */
int nghttp2_session_close_stream(nghttp2_session *session, int32_t stream_id,
                                 nghttp2_status_code status_code);

/*
 * Closes all pushed streams which associate them to stream
 * |stream_id| with the status code |status_code|.
 */
void nghttp2_session_close_pushed_streams(nghttp2_session *session,
                                          int32_t stream_id,
                                          nghttp2_status_code status_code);

/*
 * If further receptions and transmissions over the stream |stream_id|
 * are disallowed, close the stream with status code |status_code|.
 *
 * This function returns 0 if it
 * succeeds, or one of the following negative error codes:
 *
 * NGHTTP2_ERR_INVALID_ARGUMENT
 *     The specified stream does not exist.
 */
int nghttp2_session_close_stream_if_shut_rdwr(nghttp2_session *session,
                                              nghttp2_stream *stream);

/*
 * Called when SYN_STREAM is received, assuming |frame.syn_stream| is
 * properly initialized.  This function does first validate received
 * frame and then open stream and call callback functions. This
 * function does not return error if frame is not valid.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_on_syn_stream_received(nghttp2_session *session,
                                           nghttp2_frame *frame);

/*
 * Called when SYN_REPLY is received, assuming |frame.syn_reply| is
 * properly initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_on_syn_reply_received(nghttp2_session *session,
                                          nghttp2_frame *frame);


/*
 * Called when RST_STREAM is received, assuming |frame.rst_stream| is
 * properly initialized.
 *
 * This function returns 0 and never fail.
 */
int nghttp2_session_on_rst_stream_received(nghttp2_session *session,
                                           nghttp2_frame *frame);

/*
 * Called when SETTINGS is received, assuming |frame.settings| is
 * properly initialized.
 *
 * This function returns 0 and never fail.
 */
int nghttp2_session_on_settings_received(nghttp2_session *session,
                                         nghttp2_frame *frame);

/*
 * Called when PING is received, assuming |frame.ping| is properly
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
 * Called when GOAWAY is received, assuming |frame.goaway| is properly
 * initialized.
 *
 * This function returns 0 and never fail.
 */
int nghttp2_session_on_goaway_received(nghttp2_session *session,
                                       nghttp2_frame *frame);

/*
 * Called when HEADERS is recieved, assuming |frame.headers| is
 * properly initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_on_headers_received(nghttp2_session *session,
                                        nghttp2_frame *frame);

/*
 * Called when WINDOW_UPDATE is recieved, assuming
 * |frame.window_update| is properly initialized.
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
 * Called when CREDENTIAL is received, assuming |frame.credential| is
 * properly initialized.
 *
 * Currently, this function always succeeds and returns 0.
 */
int nghttp2_session_on_credential_received(nghttp2_session *session,
                                           nghttp2_frame *frame);

/*
 * Called when DATA is received.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_session_on_data_received(nghttp2_session *session,
                                     uint8_t flags, int32_t length,
                                     int32_t stream_id);

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
                                  nghttp2_data *frame);

/*
 * Returns next unique ID which can be used with PING.
 */
uint32_t nghttp2_session_get_next_unique_id(nghttp2_session *session);

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
 */
void nghttp2_session_update_local_settings(nghttp2_session *session,
                                           nghttp2_settings_entry *iv,
                                           size_t niv);

/*
 * Returns the index in the client certificate vector for the
 * |syn_stream|. The origin is computed from |syn_stream->nv|.  If no
 * client certificate is required, return 0. If CREDENTIAL frame needs
 * to be sent before the |syn_stream|, this function returns
 * :macro:`NGHTTP2_ERR_CREDENTIAL_PENDING`. In this case, CREDENTIAL
 * frame has been already queued. This function returns one of the
 * following negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_CREDENTIAL_PENDING
 *     The CREDENTIAL frame must be sent before the |syn_stream|.
 */
int nghttp2_session_prep_credential(nghttp2_session *session,
                                    nghttp2_syn_stream *syn_stream);

#endif /* NGHTTP2_SESSION_H */
