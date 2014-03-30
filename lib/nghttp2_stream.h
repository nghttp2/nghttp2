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
#ifndef NGHTTP2_STREAM_H
#define NGHTTP2_STREAM_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <nghttp2/nghttp2.h>
#include "nghttp2_outbound_item.h"
#include "nghttp2_map.h"
#include "nghttp2_pq.h"
#include "nghttp2_int.h"

/*
 * Maximum number of streams in one dependency tree.
 */
#define NGHTTP2_MAX_DEP_TREE_LENGTH 100

/*
 * If local peer is stream initiator:
 * NGHTTP2_STREAM_OPENING : upon sending request HEADERS
 * NGHTTP2_STREAM_OPENED : upon receiving response HEADERS
 * NGHTTP2_STREAM_CLOSING : upon queuing RST_STREAM
 *
 * If remote peer is stream initiator:
 * NGHTTP2_STREAM_OPENING : upon receiving request HEADERS
 * NGHTTP2_STREAM_OPENED : upon sending response HEADERS
 * NGHTTP2_STREAM_CLOSING : upon queuing RST_STREAM
 */
typedef enum {
  /* Initial state */
  NGHTTP2_STREAM_INITIAL,
  /* For stream initiator: request HEADERS has been sent, but response
     HEADERS has not been received yet.  For receiver: request HEADERS
     has been received, but it does not send response HEADERS yet. */
  NGHTTP2_STREAM_OPENING,
  /* For stream initiator: response HEADERS is received. For receiver:
     response HEADERS is sent. */
  NGHTTP2_STREAM_OPENED,
  /* RST_STREAM is received, but somehow we need to keep stream in
     memory. */
  NGHTTP2_STREAM_CLOSING,
  /* PUSH_PROMISE is received or sent */
  NGHTTP2_STREAM_RESERVED
} nghttp2_stream_state;

typedef enum {
  NGHTTP2_SHUT_NONE = 0,
  /* Indicates further receptions will be disallowed. */
  NGHTTP2_SHUT_RD = 0x01,
  /* Indicates further transmissions will be disallowed. */
  NGHTTP2_SHUT_WR = 0x02,
  /* Indicates both further receptions and transmissions will be
     disallowed. */
  NGHTTP2_SHUT_RDWR = NGHTTP2_SHUT_RD | NGHTTP2_SHUT_WR
} nghttp2_shut_flag;

typedef enum {
  NGHTTP2_STREAM_FLAG_NONE = 0,
  /* Indicates that this stream is pushed stream */
  NGHTTP2_STREAM_FLAG_PUSH = 0x01,
  /* Indicates that this stream was closed */
  NGHTTP2_STREAM_FLAG_CLOSED = 0x02
} nghttp2_stream_flag;

typedef enum {
  NGHTTP2_STREAM_DPRI_NONE = 0,
  NGHTTP2_STREAM_DPRI_NO_DATA = 0x01,
  NGHTTP2_STREAM_DPRI_TOP = 0x02,
  NGHTTP2_STREAM_DPRI_REST = 0x04
} nghttp2_stream_dpri;

typedef enum {
  NGHTTP2_DEFERRED_NONE = 0,
  /* Indicates the DATA is deferred due to flow control. */
  NGHTTP2_DEFERRED_FLOW_CONTROL = 0x01
} nghttp2_deferred_flag;

struct nghttp2_stream_group;

typedef struct nghttp2_stream_group nghttp2_stream_group;

struct nghttp2_stream;

typedef struct nghttp2_stream nghttp2_stream;

struct nghttp2_stream {
  /* Intrusive Map */
  nghttp2_map_entry map_entry;
  /* pointers to form dependency tree.  If multiple streams depend on
     a stream, only one stream (left most) has non-NULL dep_prev which
     points to the stream it depends on. The remaining streams are
     linked using sib_prev and sib_next.  The stream which has
     non-NULL dep_prev always NULL sib_prev.  The right most stream
     has NULL sib_next.  If this stream is a root of dependency tree,
     dep_prev and sib_prev are NULL. */
  nghttp2_stream *dep_prev, *dep_next;
  nghttp2_stream *sib_prev, *sib_next;
  /* When stream is kept after closure, it may be kept in single
     linked list pointed by nghttp2_session closed_stream_head.
     closed_next points to the next stream object if it is the element
     of the list. */
  nghttp2_stream *closed_next;
  /* The arbitrary data provided by user for this stream. */
  void *stream_user_data;
  /* Active DATA frame */
  nghttp2_outbound_item *data;
  /* Deferred DATA frame */
  nghttp2_outbound_item *deferred_data;
  /* stream ID */
  int32_t stream_id;
  /* priority group this stream belongs to */
  nghttp2_stream_group *stream_group;
  /* categorized priority of this stream.  Only stream bearing
     NGHTTP2_STREAM_DPRI_TOP can send DATA frame. */
  nghttp2_stream_dpri dpri;
  /* the number of nodes in subtree */
  size_t num_substreams;
  /* Current remote window size. This value is computed against the
     current initial window size of remote endpoint. */
  int32_t remote_window_size;
  /* Keep track of the number of bytes received without
     WINDOW_UPDATE. This could be negative after submitting negative
     value to WINDOW_UPDATE */
  int32_t recv_window_size;
  /* The amount of recv_window_size cut using submitting negative
     value to WINDOW_UPDATE */
  int32_t recv_reduction;
  /* window size for local flow control. It is initially set to
     NGHTTP2_INITIAL_WINDOW_SIZE and could be increased/decreased by
     submitting WINDOW_UPDATE. See nghttp2_submit_window_update(). */
  int32_t local_window_size;
  nghttp2_stream_state state;
  /* This is bitwise-OR of 0 or more of nghttp2_stream_flag. */
  uint8_t flags;
  /* Bitwise OR of zero or more nghttp2_shut_flag values */
  uint8_t shut_flags;
  /* The flags for defered DATA. Bitwise OR of zero or more
     nghttp2_deferred_flag values */
  uint8_t deferred_flags;
};

void nghttp2_stream_init(nghttp2_stream *stream, int32_t stream_id,
                         uint8_t flags,
                         nghttp2_stream_state initial_state,
                         int32_t remote_initial_window_size,
                         int32_t local_initial_window_size,
                         void *stream_user_data);

void nghttp2_stream_free(nghttp2_stream *stream);

/*
 * Disallow either further receptions or transmissions, or both.
 * |flag| is bitwise OR of one or more of nghttp2_shut_flag.
 */
void nghttp2_stream_shutdown(nghttp2_stream *stream, nghttp2_shut_flag flag);

/*
 * Defer DATA frame |data|. We won't call this function in the
 * situation where stream->deferred_data != NULL.  If |flags| is
 * bitwise OR of zero or more nghttp2_deferred_flag values.
 */
void nghttp2_stream_defer_data(nghttp2_stream *stream,
                               nghttp2_outbound_item *data,
                               uint8_t flags);

/*
 * Detaches deferred data from this stream. This function does not
 * free deferred data.
 */
int nghttp2_stream_detach_deferred_data(nghttp2_stream *stream,
                                        nghttp2_pq *pq);

/*
 * Updates the remote window size with the new value
 * |new_initial_window_size|. The |old_initial_window_size| is used to
 * calculate the current window size.
 *
 * This function returns 0 if it succeeds or -1. The failure is due to
 * overflow.
 */
int nghttp2_stream_update_remote_initial_window_size
(nghttp2_stream *stream,
 int32_t new_initial_window_size,
 int32_t old_initial_window_size);

/*
 * Updates the local window size with the new value
 * |new_initial_window_size|. The |old_initial_window_size| is used to
 * calculate the current window size.
 *
 * This function returns 0 if it succeeds or -1. The failure is due to
 * overflow.
 */
int nghttp2_stream_update_local_initial_window_size
(nghttp2_stream *stream,
 int32_t new_initial_window_size,
 int32_t old_initial_window_size);

/*
 * Call this function if promised stream |stream| is replied with
 * HEADERS.  This function makes the state of the |stream| to
 * NGHTTP2_STREAM_OPENED.
 */
void nghttp2_stream_promise_fulfilled(nghttp2_stream *stream);

/*
 * Returns the stream positioned in root of the dependency tree the
 * |stream| belongs to.
 */
nghttp2_stream* nghttp2_stream_get_dep_root(nghttp2_stream *stream);

/*
 * Returns nonzero if |target| is found in subtree of |stream|.
 */
int nghttp2_stream_dep_subtree_find(nghttp2_stream *stream,
                                    nghttp2_stream *target);

/*
 * Makes the |stream| depend on the |dep_stream|.  This dependency is
 * exclusive.  All existing direct descendants of |dep_stream| become
 * the descendants of the |stream|.  This function assumes
 * |stream->data| is NULL and no dpri members are changed in this
 * dependency tree.  It also does not change stream->stream_group.
 */
void nghttp2_stream_dep_insert(nghttp2_stream *dep_stream,
                               nghttp2_stream *stream);

/*
 * Makes the |stream| depend on the |dep_stream|.  This dependency is
 * not exclusive.  This function assumes |stream->data| is NULL and no
 * dpri members are changed in this dependency tree.  It also does not
 * change stream->stream_group.
 */
void nghttp2_stream_dep_add(nghttp2_stream *dep_stream,
                            nghttp2_stream *stream);

/*
 * Removes the |stream| from the current dependency tree.  This
 * function assumes |stream->data| is NULL.
 */
void nghttp2_stream_dep_remove(nghttp2_stream *stream);

/*
 * Attaches |data| to |stream|.  Updates dpri members in this
 * dependency tree.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_stream_attach_data(nghttp2_stream *stream,
                               nghttp2_outbound_item *data,
                               nghttp2_pq *pq);

/*
 * Detaches |data| from |stream|.  Updates dpri members in this
 * dependency tree.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_stream_detach_data(nghttp2_stream *stream, nghttp2_pq *pq);


/*
 * Makes the |stream| depend on the |dep_stream|.  This dependency is
 * exclusive.  Updates dpri members in this dependency tree.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_stream_dep_insert_subtree(nghttp2_stream *dep_stream,
                                      nghttp2_stream *stream,
                                      nghttp2_pq *pq);

/*
 * Makes the |stream| depend on the |dep_stream|.  This dependency is
 * not exclusive.  Updates dpri members in this dependency tree.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_stream_dep_add_subtree(nghttp2_stream *dep_stream,
                                   nghttp2_stream *stream,
                                   nghttp2_pq *pq);

/*
 * Removes subtree whose root stream is |stream|.  Removing subtree
 * does not change dpri values.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
void nghttp2_stream_dep_remove_subtree(nghttp2_stream *stream);

/*
 * Makes the |stream| as root for |stream_group|.  Updates dpri
 * members in this dependency tree.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_stream_dep_make_root(nghttp2_stream_group *stream_group,
                                 nghttp2_stream *stream,
                                 nghttp2_pq *pq);

/*
 * Priority group of streams.
 */
struct nghttp2_stream_group {
  /* Intrusive Map */
  nghttp2_map_entry map_entry;
  /* The number of streams this priority group contains */
  size_t num_streams;
  /* The priority group ID */
  int32_t pri_group_id;
  /* The weight of this group */
  int32_t weight;
};

void nghttp2_stream_group_init(nghttp2_stream_group *stream_group,
                               int32_t pri_group_id,
                               int32_t weight);

void nghttp2_stream_group_free(nghttp2_stream_group *stream_group);

/*
 * Adds |stream| to |stream_group|.
 */
void nghttp2_stream_group_add_stream(nghttp2_stream_group *stream_group,
                                     nghttp2_stream *stream);

/*
 * Removes |stream| from |stream_group|.
 */
void nghttp2_stream_group_remove_stream(nghttp2_stream_group *stream_group,
                                        nghttp2_stream *stream);

#endif /* NGHTTP2_STREAM */
