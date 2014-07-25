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
  NGHTTP2_STREAM_FLAG_CLOSED = 0x02,
  /* Indicates the DATA is deferred due to flow control. */
  NGHTTP2_STREAM_FLAG_DEFERRED_FLOW_CONTROL = 0x04,
  /* Indicates the DATA is deferred by user callback */
  NGHTTP2_STREAM_FLAG_DEFERRED_USER = 0x08,
  /* bitwise OR of NGHTTP2_STREAM_FLAG_DEFERRED_FLOW_CONTROL and
     NGHTTP2_STREAM_FLAG_DEFERRED_USER. */
  NGHTTP2_STREAM_FLAG_DEFERRED_ALL =  0x0c

} nghttp2_stream_flag;

typedef enum {
  NGHTTP2_STREAM_DPRI_NONE = 0,
  NGHTTP2_STREAM_DPRI_NO_DATA = 0x01,
  NGHTTP2_STREAM_DPRI_TOP = 0x02,
  NGHTTP2_STREAM_DPRI_REST = 0x04
} nghttp2_stream_dpri;

struct nghttp2_stream_roots;

typedef struct nghttp2_stream_roots nghttp2_stream_roots;

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
  /* pointers to track dependency tree root streams.  This is
     doubly-linked list and first element is pointed by
     roots->head. */
  nghttp2_stream *root_prev, *root_next;
  /* When stream is kept after closure, it may be kept in single
     linked list pointed by nghttp2_session closed_stream_head.
     closed_next points to the next stream object if it is the element
     of the list. */
  nghttp2_stream *closed_next;
  /* pointer to roots, which tracks dependency tree roots */
  nghttp2_stream_roots *roots;
  /* The arbitrary data provided by user for this stream. */
  void *stream_user_data;
  /* DATA frame item */
  nghttp2_outbound_item *data_item;
  /* stream ID */
  int32_t stream_id;
  /* categorized priority of this stream.  Only stream bearing
     NGHTTP2_STREAM_DPRI_TOP can send DATA frame. */
  nghttp2_stream_dpri dpri;
  /* the number of streams in subtree */
  size_t num_substreams;
  /* Current remote window size. This value is computed against the
     current initial window size of remote endpoint. */
  int32_t remote_window_size;
  /* Keep track of the number of bytes received without
     WINDOW_UPDATE. This could be negative after submitting negative
     value to WINDOW_UPDATE */
  int32_t recv_window_size;
  /* The number of bytes consumed by the application and now is
     subject to WINDOW_UPDATE.  This is only used when auto
     WINDOW_UPDATE is turned off. */
  int32_t consumed_size;
  /* The amount of recv_window_size cut using submitting negative
     value to WINDOW_UPDATE */
  int32_t recv_reduction;
  /* window size for local flow control. It is initially set to
     NGHTTP2_INITIAL_WINDOW_SIZE and could be increased/decreased by
     submitting WINDOW_UPDATE. See nghttp2_submit_window_update(). */
  int32_t local_window_size;
  /* weight of this stream */
  int32_t weight;
  /* effective weight of this stream in belonging dependency tree */
  int32_t effective_weight;
  /* sum of weight (not effective_weight) of direct descendants */
  int32_t sum_dep_weight;
  /* sum of weight of direct descendants which have at least one
     descendant with dpri == NGHTTP2_STREAM_DPRI_TOP.  We use this
     value to calculate effective weight. */
  int32_t sum_norest_weight;
  nghttp2_stream_state state;
  /* This is bitwise-OR of 0 or more of nghttp2_stream_flag. */
  uint8_t flags;
  /* Bitwise OR of zero or more nghttp2_shut_flag values */
  uint8_t shut_flags;
  /* nonzero if blocked was sent and remote_window_size is still 0 or
     negative */
  uint8_t blocked_sent;
};

void nghttp2_stream_init(nghttp2_stream *stream, int32_t stream_id,
                         uint8_t flags,
                         nghttp2_stream_state initial_state,
                         int32_t weight,
                         nghttp2_stream_roots *roots,
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
 * Defer DATA frame |stream->data_item|.  We won't call this function
 * in the situation where |stream->data_item| == NULL.  If |flags| is
 * bitwise OR of zero or more of NGHTTP2_STREAM_FLAG_DEFERRED_USER and
 * NGHTTP2_STREAM_FLAG_DEFERRED_FLOW_CONTROL.  The |flags| indicates
 * the reason of this action.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_stream_defer_data(nghttp2_stream *stream, uint8_t flags,
                              nghttp2_pq *pq, uint64_t cycle);

/*
 * Detaches deferred data in this stream and it is back to active
 * state.  The flags NGHTTP2_STREAM_FLAG_DEFERRED_USER and
 * NGHTTP2_STREAM_FLAG_DEFERRED_FLOW_CONTROL are cleared if they are
 * set.
 */
int nghttp2_stream_resume_deferred_data(nghttp2_stream *stream,
                                        nghttp2_pq *pq, uint64_t cycle);

/*
 * Returns nonzero if data item is deferred by whatever reason.
 */
int nghttp2_stream_check_deferred_data(nghttp2_stream *stream);

/*
 * Returns nonzero if data item is deferred by flow control.
 */
int nghttp2_stream_check_deferred_by_flow_control(nghttp2_stream *stream);

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
 * Computes distributed weight of a stream of the |weight| under the
 * |stream| if |stream| is removed from a dependency tree.  The result
 * is computed using stream->weight rather than
 * stream->effective_weight.
 */
int32_t nghttp2_stream_dep_distributed_weight(nghttp2_stream *stream,
                                              int32_t weight);

/*
 * Computes effective weight of a stream of the |weight| under the
 * |stream|.  The result is computed using stream->effective_weight
 * rather than stream->weight.  This function is used to determine
 * weight in dependency tree.
 */
int32_t nghttp2_stream_dep_distributed_effective_weight
(nghttp2_stream *stream, int32_t weight);

/*
 * Makes the |stream| depend on the |dep_stream|.  This dependency is
 * exclusive.  All existing direct descendants of |dep_stream| become
 * the descendants of the |stream|.  This function assumes
 * |stream->data| is NULL and no dpri members are changed in this
 * dependency tree.
 */
void nghttp2_stream_dep_insert(nghttp2_stream *dep_stream,
                               nghttp2_stream *stream);

/*
 * Makes the |stream| depend on the |dep_stream|.  This dependency is
 * not exclusive.  This function assumes |stream->data| is NULL and no
 * dpri members are changed in this dependency tree.
 */
void nghttp2_stream_dep_add(nghttp2_stream *dep_stream,
                            nghttp2_stream *stream);

/*
 * Removes the |stream| from the current dependency tree.  This
 * function assumes |stream->data| is NULL.
 */
void nghttp2_stream_dep_remove(nghttp2_stream *stream);

/*
 * Attaches |data_item| to |stream|.  Updates dpri members in this
 * dependency tree.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_stream_attach_data(nghttp2_stream *stream,
                               nghttp2_outbound_item *data_item,
                               nghttp2_pq *pq,
                               uint64_t cycle);

/*
 * Detaches |stream->data_item|.  Updates dpri members in this
 * dependency tree.  This function does not free |stream->data_item|.
 * The caller must free it.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_stream_detach_data(nghttp2_stream *stream, nghttp2_pq *pq,
                               uint64_t cycle);


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
                                      nghttp2_pq *pq,
                                      uint64_t cycle);

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
                                   nghttp2_pq *pq,
                                   uint64_t cycle);

/*
 * Removes subtree whose root stream is |stream|.  Removing subtree
 * does not change dpri values.  The effective_weight of streams in
 * removed subtree is not updated.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
void nghttp2_stream_dep_remove_subtree(nghttp2_stream *stream);

/*
 * Makes the |stream| as root.  Updates dpri members in this
 * dependency tree.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_stream_dep_make_root(nghttp2_stream *stream, nghttp2_pq *pq,
                                 uint64_t cycle);

/*
 * Makes the |stream| as root and all existing root streams become
 * direct children of |stream|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
int nghttp2_stream_dep_all_your_stream_are_belong_to_us
(nghttp2_stream *stream, nghttp2_pq *pq, uint64_t cycle);

/*
 * Returns nonzero if |stream| is in any dependency tree.
 */
int nghttp2_stream_in_dep_tree(nghttp2_stream *stream);

struct nghttp2_stream_roots {
  nghttp2_stream *head;

  int32_t num_streams;
};

void nghttp2_stream_roots_init(nghttp2_stream_roots *roots);

void nghttp2_stream_roots_free(nghttp2_stream_roots *roots);

void nghttp2_stream_roots_add(nghttp2_stream_roots *roots,
                              nghttp2_stream *stream);

void nghttp2_stream_roots_remove(nghttp2_stream_roots *roots,
                                 nghttp2_stream *stream);

void nghttp2_stream_roots_remove_all(nghttp2_stream_roots *roots);

#endif /* NGHTTP2_STREAM */
