/*
 * nghttp2
 *
 * Copyright (c) 2026 nghttp2 contributors
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
#ifndef NGHTTP2_LOG_H
#define NGHTTP2_LOG_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <nghttp2v2/nghttp2.h>

#include "nghttp2_frame.h"
#include "nghttp2_fmt.h"

#define NGHTTP2_LOG_BUFLEN 1024

typedef struct nghttp2_log {
  nghttp2_log_write log_write;
  uint64_t conn_id;
  /* events is an event filter.  Only events set in this field are
     emitted. */
  uint8_t events;
  /* ts is the time point used to write time delta in the log. */
  nghttp2_tstamp ts;
  /* last_ts is the most recent time point that this object is
     told. */
  nghttp2_tstamp last_ts;
  /* user_data is user-defined opaque data which is passed to
     log_write. */
  void *user_data;
  /* conn_id is the identifier of the connection so that we can
     distinguish the logs of the particular connection from the
     others. */
  char *buf;
} nghttp2_log;

/**
 * @enum
 *
 * :type:`nghttp2_log_event` defines an event of nghttp2 library
 * internal logger.
 */
typedef enum nghttp2_log_event {
  /**
   * :enum:`NGHTTP2_LOG_EVENT_NONE` represents no event.
   */
  NGHTTP2_LOG_EVENT_NONE,
  /**
   * :enum:`NGHTTP2_LOG_EVENT_CON` is a connection (catch-all) event
   */
  NGHTTP2_LOG_EVENT_CON = 0x1,
  /**
   * :enum:`NGHTTP2_LOG_EVENT_FRM` is a HTTP/2 frame event.
   */
  NGHTTP2_LOG_EVENT_FRM = 0x2,
} nghttp2_log_event;

void nghttp2_log_init(nghttp2_log *log, uint64_t conn_id,
                      nghttp2_log_write log_write, char *buf, nghttp2_tstamp ts,
                      void *user_data);

void nghttp2_log_rx_data(nghttp2_log *log, const nghttp2_frame_data *fr);

void nghttp2_log_rx_headers(nghttp2_log *log, const nghttp2_frame_headers *fr);

void nghttp2_log_rx_rst_stream(nghttp2_log *log,
                               const nghttp2_frame_rst_stream *fr);

void nghttp2_log_rx_settings(nghttp2_log *log,
                             const nghttp2_frame_settings *fr);

void nghttp2_log_rx_ping(nghttp2_log *log, const nghttp2_frame_ping *fr);

void nghttp2_log_rx_goaway(nghttp2_log *log, const nghttp2_frame_goaway *fr);

void nghttp2_log_rx_window_update(nghttp2_log *log,
                                  const nghttp2_frame_window_update *fr);

void nghttp2_log_rx_priority_update(nghttp2_log *log,
                                    const nghttp2_frame_priority_update *fr);

void nghttp2_log_rx_unknown_frame(nghttp2_log *log,
                                  const nghttp2_frame_meta *fr);

void nghttp2_log_tx_data(nghttp2_log *log, const nghttp2_frame_data *fr);

void nghttp2_log_tx_headers(nghttp2_log *log, const nghttp2_frame_headers *fr);

void nghttp2_log_tx_continuation(nghttp2_log *log,
                                 const nghttp2_frame_headers *fr);

void nghttp2_log_tx_rst_stream(nghttp2_log *log,
                               const nghttp2_frame_rst_stream *fr);

void nghttp2_log_tx_settings(nghttp2_log *log,
                             const nghttp2_frame_settings *fr);

void nghttp2_log_tx_ping(nghttp2_log *log, const nghttp2_frame_ping *fr);

void nghttp2_log_tx_goaway(nghttp2_log *log, const nghttp2_frame_goaway *fr);

void nghttp2_log_tx_window_update(nghttp2_log *log,
                                  const nghttp2_frame_window_update *fr);

void nghttp2_log_tx_priority_update(nghttp2_log *log,
                                    const nghttp2_frame_priority_update *fr);

uint64_t nghttp2_log_timestamp(const nghttp2_log *log);

static inline const char *nghttp2_log_event_str(nghttp2_log_event ev) {
  switch (ev) {
  case NGHTTP2_LOG_EVENT_CON:
    return "con";
  case NGHTTP2_LOG_EVENT_FRM:
    return "frm";
  case NGHTTP2_LOG_EVENT_NONE:
  default:
    return "non";
  }
}

#define NGHTTP2_LOG_HD(LOG, EV)                                                \
  "I", uintw(nghttp2_log_timestamp(LOG), 8), " 0x",                            \
    hexw((LOG)->conn_id, sizeof((LOG)->conn_id) * 2), " ",                     \
    nghttp2_log_event_str(EV), " "

#define nghttp2_log_infof_raw(LOG, EV, ...)                                    \
  do {                                                                         \
    size_t log_nwrite;                                                         \
                                                                               \
    nghttp2_fmt_format((LOG)->buf, &log_nwrite, NGHTTP2_LOG_HD((LOG), (EV)),   \
                       __VA_ARGS__);                                           \
    (LOG)->log_write((LOG)->user_data, (LOG)->buf, log_nwrite);                \
  } while (0)

#define nghttp2_log_infof(LOG, EV, ...)                                        \
  do {                                                                         \
    if (!(LOG)->log_write || !((LOG)->events & (EV))) {                        \
      break;                                                                   \
    }                                                                          \
                                                                               \
    nghttp2_log_infof_raw((LOG), (EV), __VA_ARGS__);                           \
  } while (0)

#define nghttp2_log_info(LOG, EV, ARG) nghttp2_log_infof((LOG), (EV), (ARG))

#endif /* !defined(NGHTTP2_LOG_H) */
