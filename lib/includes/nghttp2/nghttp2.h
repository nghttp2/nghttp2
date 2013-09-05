/*
 * nghttp2 - HTTP/2.0 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
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
#ifndef NGHTTP2_H
#define NGHTTP2_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#include <nghttp2/nghttp2ver.h>

/**
 * @macro
 *
 * The protocol version identification of this library supports.
 */
#define NGHTTP2_PROTO_VERSION_ID "HTTP-draft-06/2.0"
/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_PROTO_VERSION_ID`.
 */
#define NGHTTP2_PROTO_VERSION_ID_LEN 17

struct nghttp2_session;
/**
 * @struct
 *
 * The primary structure to hold the resources needed for a HTTP/2.0
 * session. The details of this structure are intentionally hidden
 * from the public API.
 */
typedef struct nghttp2_session nghttp2_session;

/**
 * @macro
 *
 * The age of :type:`nghttp2_info`
 */
#define NGHTTP2_VERSION_AGE 1

/**
 * @struct
 *
 * This struct is what `nghttp2_version()` returns. It holds
 * information about the particular nghttp2 version.
 */
typedef struct {
  /**
   * Age of this struct. This instance of nghttp2 sets it to
   * :macro:`NGHTTP2_VERSION_AGE` but a future version may bump it and
   * add more struct fields at the bottom
   */
  int age;
  /**
   * the :macro:`NGHTTP2_VERSION_NUM` number (since age ==1)
   */
  int version_num;
  /**
   * points to the :macro:`NGHTTP2_VERSION` string (since age ==1)
   */
  const char *version_str;
  /**
   * points to the :macro:`NGHTTP2_PROTO_VERSION_ID` string this
   * instance implements (since age ==1)
   */
  const char *proto_str;
  /* -------- the above fields all exist when age == 1 */
} nghttp2_info;

/**
 * @macro
 *
 * The default priority value
 */
#define NGHTTP2_PRI_DEFAULT (1 << 30)
/**
 * @macro
 *
 * The lowest priority value
 */
#define NGHTTP2_PRI_LOWEST ((1U << 31) - 1)

/**
 * @macro
 *
 * The maximum window size
 */
#define NGHTTP2_MAX_WINDOW_SIZE ((int32_t)((1U << 31) - 1))

/**
 * @macro
 *
 * The initial window size for stream level flow control.
 */
#define NGHTTP2_INITIAL_WINDOW_SIZE ((1 << 16) - 1)
/**
 * @macro
 *
 * The initial window size for connection level flow control.
 */
#define NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE ((1 << 16) - 1)

/**
 * @macro
 *
 * The client connection header.
 */
#define NGHTTP2_CLIENT_CONNECTION_HEADER "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_CLIENT_CONNECTION_HEADER`.
 */
#define NGHTTP2_CLIENT_CONNECTION_HEADER_LEN 24

/**
 * @enum
 *
 * Error codes used in this library. The code range is [-999, -500],
 * inclusive. The following values are defined:
 */
typedef enum {
  /**
   * Invalid argument passed.
   */
  NGHTTP2_ERR_INVALID_ARGUMENT = -501,
  /**
   * The specified protocol version is not supported.
   */
  NGHTTP2_ERR_UNSUPPORTED_VERSION = -503,
  /**
   * Used as a return value from :type:`nghttp2_send_callback` and
   * :type:`nghttp2_recv_callback` to indicate that the operation
   * would block.
   */
  NGHTTP2_ERR_WOULDBLOCK = -504,
  /**
   * General protocol error
   */
  NGHTTP2_ERR_PROTO = -505,
  /**
   * The frame is invalid.
   */
  NGHTTP2_ERR_INVALID_FRAME = -506,
  /**
   * The peer performed a shutdown on the connection.
   */
  NGHTTP2_ERR_EOF = -507,
  /**
   * Used as a return value from
   * :func:`nghttp2_data_source_read_callback` to indicate that data
   * transfer is postponed. See
   * :func:`nghttp2_data_source_read_callback` for details.
   */
  NGHTTP2_ERR_DEFERRED = -508,
  /**
   * Stream ID has reached the maximum value. Therefore no stream ID
   * is available.
   */
  NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE = -509,
  /**
   * The stream is already closed; or the stream ID is invalid.
   */
  NGHTTP2_ERR_STREAM_CLOSED = -510,
  /**
   * RST_STREAM has been added to the outbound queue. The stream is in
   * closing state.
   */
  NGHTTP2_ERR_STREAM_CLOSING = -511,
  /**
   * The transmission is not allowed for this stream (e.g., a frame
   * with END_STREAM flag set has already sent).
   */
  NGHTTP2_ERR_STREAM_SHUT_WR = -512,
  /**
   * The stream ID is invalid.
   */
  NGHTTP2_ERR_INVALID_STREAM_ID = -513,
  /**
   * The state of the stream is not valid (e.g., DATA cannot be sent
   * to the stream if response HEADERS has not been sent).
   */
  NGHTTP2_ERR_INVALID_STREAM_STATE = -514,
  /**
   * Another DATA frame has already been deferred.
   */
  NGHTTP2_ERR_DEFERRED_DATA_EXIST = -515,
  /**
   * Starting new stream is not allowed. (e.g., GOAWAY has been sent
   * and/or received.
   */
  NGHTTP2_ERR_START_STREAM_NOT_ALLOWED = -516,
  /**
   * GOAWAY has already been sent.
   */
  NGHTTP2_ERR_GOAWAY_ALREADY_SENT = -517,
  /**
   * The received frame contains the invalid header block. (e.g.,
   * There are duplicate header names; or the header names are not
   * encoded in US-ASCII character set and not lower cased; or the
   * header name is zero-length string; or the header value contains
   * multiple in-sequence NUL bytes).
   */
  NGHTTP2_ERR_INVALID_HEADER_BLOCK = -518,
  /**
   * Indicates that the context is not suitable to perform the
   * requested operation.
   */
  NGHTTP2_ERR_INVALID_STATE = -519,
  /**
   * The gzip error.
   */
  NGHTTP2_ERR_GZIP = -520,
  /**
   * The user callback function failed due to the temporal error.
   */
  NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE = -521,
  /**
   * The length of the frame is too large.
   */
  NGHTTP2_ERR_FRAME_TOO_LARGE = -522,
  /**
   * Header block inflate/deflate error.
   */
  NGHTTP2_ERR_HEADER_COMP = -523,
  /**
   * Flow control error
   */
  NGHTTP2_ERR_FLOW_CONTROL = -524,
  /**
   * The errors < :enum:`NGHTTP2_ERR_FATAL` mean that the library is
   * under unexpected condition and cannot process any further data
   * reliably (e.g., out of memory).
   */
  NGHTTP2_ERR_FATAL = -900,
  /**
   * Out of memory. This is a fatal error.
   */
  NGHTTP2_ERR_NOMEM = -901,
  /**
   * The user callback function failed. This is a fatal error.
   */
  NGHTTP2_ERR_CALLBACK_FAILURE = -902
} nghttp2_error;

typedef enum {
  NGHTTP2_MSG_MORE
} nghttp2_io_flag;

/**
 * @struct
 *
 * The name/value pair, which mainly used to represent header fields.
 */
typedef struct {
  /**
   * The |name| byte string, which is not necessarily ``NULL``
   * terminated.
   */
  uint8_t *name;
  /**
   * The |value| byte string, which is not necessarily ``NULL``
   * terminated.
   */
  uint8_t *value;
  /**
   * The length of the |name|.
   */
  uint16_t namelen;
  /**
   * The length of the |value|.
   */
  uint16_t valuelen;
} nghttp2_nv;

/**
 * @enum
 * The control frame types in HTTP/2.0.
 */
typedef enum {
  /**
   * The DATA frame.
   */
  NGHTTP2_DATA = 0,
  /**
   * The HEADERS frame.
   */
  NGHTTP2_HEADERS = 1,
  /**
   * The PRIORITY frame.
   */
  NGHTTP2_PRIORITY = 2,
  /**
   * The RST_STREAM frame.
   */
  NGHTTP2_RST_STREAM = 3,
  /**
   * The SETTINGS frame.
   */
  NGHTTP2_SETTINGS = 4,
  /**
   * The PUSH_PROMISE frame.
   */
  NGHTTP2_PUSH_PROMISE = 5,
  /**
   * The PING frame.
   */
  NGHTTP2_PING = 6,
  /**
   * The GOAWAY frame.
   */
  NGHTTP2_GOAWAY = 7,
  /**
   * The WINDOW_UPDATE frame.
   */
  NGHTTP2_WINDOW_UPDATE = 9
} nghttp2_frame_type;

/**
 * @enum
 *
 * The flags for HTTP/2.0 frames. This enum defines all flags for
 * frames, assuming that the same flag name has the same mask.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_FLAG_NONE = 0,
  /**
   * The END_STREAM flag.
   */
  NGHTTP2_FLAG_END_STREAM = 0x1,
  /**
   * The END_HEADERS flag.
   */
  NGHTTP2_FLAG_END_HEADERS = 0x4,
  /**
   * The PRIORITY flag.
   */
  NGHTTP2_FLAG_PRIORITY = 0x8,
  /**
   * The END_PUSH_PROMISE flag.
   */
  NGHTTP2_FLAG_END_PUSH_PROMISE = 0x4,
  /**
   * The PONG flag.
   */
  NGHTTP2_FLAG_PONG = 0x1
} nghttp2_flag;

/**
 * @enum
 * The SETTINGS ID.
 */
typedef enum {
  /**
   * SETTINGS_MAX_CONCURRENT_STREAMS
   */
  NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 4,
  /**
   * SETTINGS_INITIAL_WINDOW_SIZE
   */
  NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 7,
  /**
   * SETTINGS_FLOW_CONTROL_OPTIONS
   */
  NGHTTP2_SETTINGS_FLOW_CONTROL_OPTIONS = 10,
  /**
   * Maximum ID of :type:`nghttp2_settings_id`.
   */
  NGHTTP2_SETTINGS_MAX = 10
} nghttp2_settings_id;

/**
 * @macro
 * Default maximum concurrent streams.
 */
#define NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS ((1U << 31) - 1)

/**
 * @enum
 * The status codes for the RST_STREAM and GOAWAY frames.
 */
typedef enum {
  /**
   * No errors.
   */
  NGHTTP2_NO_ERROR = 0,
  /**
   * PROTOCOL_ERROR
   */
  NGHTTP2_PROTOCOL_ERROR = 1,
  /**
   * INTERNAL_ERROR
   */
  NGHTTP2_INTERNAL_ERROR = 2,
  /**
   * FLOW_CONTROL_ERROR
   */
  NGHTTP2_FLOW_CONTROL_ERROR = 3,
  /**
   * STREAM_CLOSED
   */
  NGHTTP2_STREAM_CLOSED = 5,
  /**
   * FRAME_TOO_LARGE
   */
  NGHTTP2_FRAME_TOO_LARGE = 6,
  /**
   * REFUSED_STREAM
   */
  NGHTTP2_REFUSED_STREAM = 7,
  /**
   * CANCEL
   */
  NGHTTP2_CANCEL = 8,
  /**
   * COMPRESSION_ERROR
   */
  NGHTTP2_COMPRESSION_ERROR = 9
} nghttp2_error_code;

/**
 * @struct
 * The frame header.
 */
typedef struct {
  /**
   * The length field of this frame, excluding frame header.
   */
  uint16_t length;
  /**
   * The type of this frame. See `nghttp2_frame`.
   */
  uint8_t type;
  /**
   * The flags.
   */
  uint8_t flags;
  /**
   * The stream identifier (aka, stream ID)
   */
  int32_t stream_id;
} nghttp2_frame_hd;


/**
 * @union
 *
 * This union represents the some kind of data source passed to
 * :type:`nghttp2_data_source_read_callback`.
 */
typedef union {
  /**
   * The integer field, suitable for a file descriptor.
   */
  int fd;
  /**
   * The pointer to an arbitrary object.
   */
  void *ptr;
} nghttp2_data_source;

/**
 * @functypedef
 *
 * Callback function invoked when the library wants to read data from
 * the |source|. The read data is sent in the stream |stream_id|. The
 * implementation of this function must read at most |length| bytes of
 * data from |source| (or possibly other places) and store them in
 * |buf| and return number of data stored in |buf|. If EOF is reached,
 * set |*eof| to 1.  If the application wants to postpone DATA frames,
 * (e.g., asynchronous I/O, or reading data blocks for long time), it
 * is achieved by returning :enum:`NGHTTP2_ERR_DEFERRED` without
 * reading any data in this invocation.  The library removes DATA
 * frame from the outgoing queue temporarily.  To move back deferred
 * DATA frame to outgoing queue, call `nghttp2_session_resume_data()`.
 * In case of error, there are 2 choices. Returning
 * :enum:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE` will close the stream
 * by issuing RST_STREAM with :enum:`NGHTTP2_INTERNAL_ERROR`.
 * Returning :enum:`NGHTTP2_ERR_CALLBACK_FAILURE` will signal the
 * entire session failure.
 */
typedef ssize_t (*nghttp2_data_source_read_callback)
(nghttp2_session *session, int32_t stream_id,
 uint8_t *buf, size_t length, int *eof,
 nghttp2_data_source *source, void *user_data);

/**
 * @struct
 *
 * This struct represents the data source and the way to read a chunk
 * of data from it.
 */
typedef struct {
  /**
   * The data source.
   */
  nghttp2_data_source source;
  /**
   * The callback function to read a chunk of data from the |source|.
   */
  nghttp2_data_source_read_callback read_callback;
} nghttp2_data_provider;

/**
 * @enum
 *
 * The category of HEADERS, which indicates the role of the frame. In
 * HTTP/2.0 spec, request, response, push response and other arbitrary
 * headers (e.g., trailers) are all called just HEADERS. To give the
 * application the role of incoming HEADERS frame, we define several
 * categories.
 */
typedef enum {
  /**
   * The HEADERS frame is opening new stream, which is analogous to
   * SYN_STREAM in SPDY.
   */
  NGHTTP2_HCAT_REQUEST = 0,
  /**
   * The HEADERS frame is the first response headers, which is
   * analogous to SYN_REPLY in SPDY.
   */
  NGHTTP2_HCAT_RESPONSE = 1,
  /**
   * The HEADERS frame is the first headers sent against reserved
   * stream.
   */
  NGHTTP2_HCAT_PUSH_RESPONSE = 2,
  /**
   * The HEADERS frame which does not apply for the above categories,
   * which is analogous to HEADERS in SPDY.
   */
  NGHTTP2_HCAT_HEADERS = 3
} nghttp2_headers_category;

/**
 * @struct
 * The HEADERS frame. It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The priority.
   */
  int32_t pri;
  /**
   * The name/value pairs.
   */
  nghttp2_nv *nva;
  /**
   * The number of name/value pairs in |nva|.
   */
  size_t nvlen;
  nghttp2_headers_category cat;
} nghttp2_headers;

/**
 * @struct
 * The PRIORITY frame. It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The priority.
   */
  int32_t pri;
} nghttp2_priority;

/**
 * @struct
 * The RST_STREAM frame. It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The error code. See :type:`nghttp2_error_code`.
   */
  nghttp2_error_code error_code;
} nghttp2_rst_stream;

/**
 * @struct
 * The SETTINGS ID/Value pair. It has the following members:
 */
typedef struct {
  /**
   * The SETTINGS ID. See :type:`nghttp2_settings_id`.
   */
  int32_t settings_id;
  /**
   * The value of this entry.
   */
  uint32_t value;
} nghttp2_settings_entry;

/**
 * @struct
 * The SETTINGS frame. It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The number of SETTINGS ID/Value pairs in |iv|.
   */
  size_t niv;
  /**
   * The pointer to the array of SETTINGS ID/Value pair.
   */
  nghttp2_settings_entry *iv;
} nghttp2_settings;

/**
 * @struct
 * The PUSH_PROMISE frame. It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The promised stream ID
   */
  int32_t promised_stream_id;
  /**
   * The name/value pairs.
   */
  nghttp2_nv *nva;
  /**
   * The number of name/value pairs in |nva|.
   */
  size_t nvlen;
} nghttp2_push_promise;

/**
 * @struct
 * The PING frame. It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The opaque data
   */
  uint8_t opaque_data[8];
} nghttp2_ping;

/**
 * @struct
 * The GOAWAY frame. It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The last stream stream ID.
   */
  int32_t last_stream_id;
  /**
   * The error code. See :type:`nghttp2_error_code`.
   */
  nghttp2_error_code error_code;
  /**
   * The additional debug data
   */
  uint8_t *opaque_data;
  /**
   * The length of |opaque_data| member.
   */
  size_t opaque_data_len;
} nghttp2_goaway;

/**
 * @struct
 *
 * The WINDOW_UPDATE frame. It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The window size increment.
   */
  int32_t window_size_increment;
} nghttp2_window_update;

/**
 * @union
 *
 * This union includes all frames to pass them to various function
 * calls as nghttp2_frame type. The DATA frame is intentionally
 * omitted from here.
 */
typedef union {
  /**
   * The frame header, which is convenient to inspect frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The HEADERS frame.
   */
  nghttp2_headers headers;
  /**
   * The PRIORITY frame.
   */
  nghttp2_priority priority;
  /**
   * The RST_STREAM frame.
   */
  nghttp2_rst_stream rst_stream;
  /**
   * The SETTINGS frame.
   */
  nghttp2_settings settings;
  /**
   * The PUSH_PROMISE frame.
   */
  nghttp2_push_promise push_promise;
  /**
   * The PING frame.
   */
  nghttp2_ping ping;
  /**
   * The GOAWAY frame.
   */
  nghttp2_goaway goaway;
  /**
   * The WINDOW_UPDATE frame.
   */
  nghttp2_window_update window_update;
} nghttp2_frame;

/**
 * @functypedef
 *
 * Callback function invoked when |session| wants to send data to the
 * remote peer. The implementation of this function must send at most
 * |length| bytes of data stored in |data|. The |flags| is currently
 * not used and always 0. It must return the number of bytes sent if
 * it succeeds.  If it cannot send any single byte without blocking,
 * it must return :enum:`NGHTTP2_ERR_WOULDBLOCK`. For other errors, it
 * must return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef ssize_t (*nghttp2_send_callback)
(nghttp2_session *session,
 const uint8_t *data, size_t length, int flags, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when |session| wants to receive data from
 * the remote peer. The implementation of this function must read at
 * most |length| bytes of data and store it in |buf|. The |flags| is
 * currently not used and always 0. It must return the number of bytes
 * written in |buf| if it succeeds. If it cannot read any single byte
 * without blocking, it must return :enum:`NGHTTP2_ERR_WOULDBLOCK`. If
 * it gets EOF before it reads any single byte, it must return
 * :enum:`NGHTTP2_ERR_EOF`. For other errors, it must return
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`. Returning 0 is treated as
 * :enum:`NGHTTP2_ERR_WOULDBLOCK`.
 */
typedef ssize_t (*nghttp2_recv_callback)
(nghttp2_session *session,
 uint8_t *buf, size_t length, int flags, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked by `nghttp2_session_recv()` when a
 * non-DATA frame is received.
 *
 * The implementation of this function must return 0 if it
 * succeeds. If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_frame_recv_callback)
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked by `nghttp2_session_recv()` when an
 * invalid non-DATA frame is received. The |error_code| is one of the
 * :enum:`nghttp2_error_code` and indicates the error. When this
 * callback function is invoked, the library automatically submits
 * either RST_STREAM or GOAWAY frame.
 *
 * The implementation of this function must return 0 if it
 * succeeds. If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_invalid_frame_recv_callback)
(nghttp2_session *session, const nghttp2_frame *frame,
 nghttp2_error_code error_code, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when a chunk of data in DATA frame is
 * received. The |stream_id| is the stream ID this DATA frame belongs
 * to. The |flags| is the flags of DATA frame which this data chunk is
 * contained. ``(flags & NGHTTP2_FLAG_END_STREAM) != 0`` does not
 * necessarily mean this chunk of data is the last one in the
 * stream. You should use :type:`nghttp2_on_data_recv_callback` to
 * know all data frames are received.
 *
 * The implementation of this function must return 0 if it
 * succeeds. If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_data_chunk_recv_callback)
(nghttp2_session *session, uint8_t flags, int32_t stream_id,
 const uint8_t *data, size_t len, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when DATA frame is received. The actual
 * data it contains are received by
 * :type:`nghttp2_on_data_chunk_recv_callback`.
 *
 * The implementation of this function must return 0 if it
 * succeeds. If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_data_recv_callback)
(nghttp2_session *session, uint16_t length, uint8_t flags, int32_t stream_id,
 void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked before the non-DATA frame |frame| is
 * sent. This may be useful, for example, to know the stream ID of
 * HEADERS and PUSH_PROMISE frame (see also
 * `nghttp2_session_get_stream_user_data()`), which is not assigned
 * when it was queued.
 *
 * The implementation of this function must return 0 if it
 * succeeds. If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_before_frame_send_callback)
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked after the non-DATA frame |frame| is sent.
 *
 * The implementation of this function must return 0 if it
 * succeeds. If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_frame_send_callback)
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked after the non-DATA frame |frame| is not
 * sent because of the error. The error is indicated by the
 * |lib_error_code|, which is one of the values defined in
 * :type:`nghttp2_error`.
 *
 * The implementation of this function must return 0 if it
 * succeeds. If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_frame_not_send_callback)
(nghttp2_session *session, const nghttp2_frame *frame, int lib_error_code,
 void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked after DATA frame is sent.
 *
 * The implementation of this function must return 0 if it
 * succeeds. If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_data_send_callback)
(nghttp2_session *session, uint16_t length, uint8_t flags, int32_t stream_id,
 void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when the stream |stream_id| is
 * closed. The reason of closure is indicated by the
 * |error_code|. The stream_user_data, which was specified in
 * `nghttp2_submit_request()` or `nghttp2_submit_headers()`, is
 * still available in this function.
 *
 * The implementation of this function must return 0 if it
 * succeeds. If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_stream_close_callback)
(nghttp2_session *session, int32_t stream_id, nghttp2_error_code error_code,
 void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when the request from the remote peer is
 * received.  In other words, the frame with END_STREAM flag set is
 * received.  In HTTP, this means HTTP request, including request
 * body, is fully received.
 *
 * The implementation of this function must return 0 if it
 * succeeds. If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_request_recv_callback)
(nghttp2_session *session, int32_t stream_id, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when the received control frame octets
 * could not be parsed correctly. The |type| indicates the type of
 * received non-DATA frame. The |head| is the pointer to the header of
 * the received frame. The |headlen| is the length of the
 * |head|. According to the spec, the |headlen| is always 8. In other
 * words, the |head| is the first 8 bytes of the received frame.  The
 * |payload| is the pointer to the data portion of the received frame.
 * The |payloadlen| is the length of the |payload|. This is the data
 * after the length field. The |lib_error_code| is one of the error code
 * defined in :enum:`nghttp2_error` and indicates the error.
 *
 * The implementation of this function must return 0 if it
 * succeeds. If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_frame_recv_parse_error_callback)
(nghttp2_session *session, nghttp2_frame_type type,
 const uint8_t *head, size_t headlen,
 const uint8_t *payload, size_t payloadlen,
 int lib_error_code, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when the received frame type is
 * unknown. The |head| is the pointer to the header of the received
 * frame. The |headlen| is the length of the |head|. According to the
 * spec, the |headlen| is always 8. In other words, the |head| is the
 * first 8 bytes of the received frame.  The |payload| is the pointer
 * to the data portion of the received frame.  The |payloadlen| is the
 * length of the |payload|. This is the data after the length field.
 *
 * The implementation of this function must return 0 if it
 * succeeds. If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_unknown_frame_recv_callback)
(nghttp2_session *session,
 const uint8_t *head, size_t headlen,
 const uint8_t *payload, size_t payloadlen,
 void *user_data);

/**
 * @struct
 *
 * Callback functions.
 */
typedef struct {
  /**
   * Callback function invoked when the |session| wants to send data
   * to the remote peer.
   */
  nghttp2_send_callback send_callback;
  /**
   * Callback function invoked when the |session| wants to receive
   * data from the remote peer.
   */
  nghttp2_recv_callback recv_callback;
  /**
   * Callback function invoked by `nghttp2_session_recv()` when a
   * non-DATA frame is received.
   */
  nghttp2_on_frame_recv_callback on_frame_recv_callback;
  /**
   * Callback function invoked by `nghttp2_session_recv()` when an
   * invalid non-DATA frame is received.
   */
  nghttp2_on_invalid_frame_recv_callback on_invalid_frame_recv_callback;
  /**
   * Callback function invoked when a chunk of data in DATA frame is
   * received.
   */
  nghttp2_on_data_chunk_recv_callback on_data_chunk_recv_callback;
  /**
   * Callback function invoked when DATA frame is received.
   */
  nghttp2_on_data_recv_callback on_data_recv_callback;
  /**
   * Callback function invoked before the non-DATA frame is sent.
   */
  nghttp2_before_frame_send_callback before_frame_send_callback;
  /**
   * Callback function invoked after the non-DATA frame is sent.
   */
  nghttp2_on_frame_send_callback on_frame_send_callback;
  /**
   * The callback function invoked when a non-DATA frame is not sent
   * because of an error.
   */
  nghttp2_on_frame_not_send_callback on_frame_not_send_callback;
  /**
   * Callback function invoked after DATA frame is sent.
   */
  nghttp2_on_data_send_callback on_data_send_callback;
  /**
   * Callback function invoked when the stream is closed.
   */
  nghttp2_on_stream_close_callback on_stream_close_callback;
  /**
   * Callback function invoked when request from the remote peer is
   * received.
   */
  nghttp2_on_request_recv_callback on_request_recv_callback;
  /**
   * Callback function invoked when the received non-DATA frame octets
   * could not be parsed correctly.
   */
  nghttp2_on_frame_recv_parse_error_callback
  on_frame_recv_parse_error_callback;
  /**
   * Callback function invoked when the received frame type is
   * unknown.
   */
  nghttp2_on_unknown_frame_recv_callback on_unknown_frame_recv_callback;
} nghttp2_session_callbacks;

/**
 * @function
 *
 * Initializes |*session_ptr| for client use. The all members of
 * |callbacks| are copied to |*session_ptr|. Therefore |*session_ptr|
 * does not store |callbacks|. |user_data| is an arbitrary user
 * supplied data, which will be passed to the callback functions.
 *
 * The :member:`nghttp2_session_callbacks.send_callback` must be
 * specified.  If the application code uses `nghttp2_session_recv()`,
 * the :member:`nghttp2_session_callbacks.recv_callback` must be
 * specified. The other members of |callbacks| can be ``NULL``.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_session_client_new(nghttp2_session **session_ptr,
                               const nghttp2_session_callbacks *callbacks,
                               void *user_data);

/**
 * @function
 *
 * Initializes |*session_ptr| for server use. The all members of
 * |callbacks| are copied to |*session_ptr|. Therefore |*session_ptr|
 * does not store |callbacks|. |user_data| is an arbitrary user
 * supplied data, which will be passed to the callback functions.
 *
 * The :member:`nghttp2_session_callbacks.send_callback` must be
 * specified.  If the application code uses `nghttp2_session_recv()`,
 * the :member:`nghttp2_session_callbacks.recv_callback` must be
 * specified. The other members of |callbacks| can be ``NULL``.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_session_server_new(nghttp2_session **session_ptr,
                               const nghttp2_session_callbacks *callbacks,
                               void *user_data);

/**
 * @function
 *
 * Frees any resources allocated for |session|. If |session| is
 * ``NULL``, this function does nothing.
 */
void nghttp2_session_del(nghttp2_session *session);

/**
 * @enum
 *
 * Configuration options for :type:`nghttp2_session`.
 */
typedef enum {
  /**
   * This option prevents the library from sending WINDOW_UPDATE for a
   * stream automatically. If this option is set, the application is
   * responsible for sending WINDOW_UPDATE using
   * `nghttp2_submit_window_update`.
   */
  NGHTTP2_OPT_NO_AUTO_STREAM_WINDOW_UPDATE = 1,
  /**
   * This option prevents the library from sending WINDOW_UPDATE for a
   * connection automatically. If this option is set, the application
   * is responsible for sending WINDOW_UPDATE with stream ID 0 using
   * `nghttp2_submit_window_update`.
   */
  NGHTTP2_OPT_NO_AUTO_CONNECTION_WINDOW_UPDATE = 2
} nghttp2_opt;

/**
 * @function
 *
 * Sets the configuration option for the |session|.  The |optname| is
 * one of :type:`nghttp2_opt`. The |optval| is the pointer to the
 * option value and the |optlen| is the size of |*optval|. The
 * required type of |optval| varies depending on the |optname|. See
 * below.
 *
 * The following |optname| are supported:
 *
 * :enum:`NGHTTP2_OPT_NO_AUTO_STREAM_WINDOW_UPDATE`
 *     The |optval| must be a pointer to ``int``. If the |*optval| is
 *     nonzero, the library will not send WINDOW_UPDATE for a stream
 *     automatically.  Therefore, the application is responsible for
 *     sending WINDOW_UPDATE using
 *     `nghttp2_submit_window_update`. This option defaults to 0.
 *
 * :enum:`NGHTTP2_OPT_NO_AUTO_CONNECTION_WINDOW_UPDATE`
 *     The |optval| must be a pointer to ``int``. If the |*optval| is
 *     nonzero, the library will not send WINDOW_UPDATE for connection
 *     automatically.  Therefore, the application is responsible for
 *     sending WINDOW_UPDATE using
 *     `nghttp2_submit_window_update`. This option defaults to 0.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |optname| is not supported; or the |optval| and/or the
 *     |optlen| are invalid.
 */
int nghttp2_session_set_option(nghttp2_session *session,
                               int optname, void *optval, size_t optlen);

/**
 * @function
 *
 * Sends pending frames to the remote peer.
 *
 * This function retrieves the highest prioritized frame from the
 * outbound queue and sends it to the remote peer. It does this as
 * many as possible until the user callback
 * :member:`nghttp2_session_callbacks.send_callback` returns
 * :enum:`NGHTTP2_ERR_WOULDBLOCK` or the outbound queue becomes empty.
 * This function calls several callback functions which are passed
 * when initializing the |session|. Here is the simple time chart
 * which tells when each callback is invoked:
 *
 * 1. Get the next frame to send from outbound queue.
 * 2. Prepare transmission of the frame.
 * 3. If the control frame cannot be sent because some preconditions
 *    are not met (e.g., request HEADERS cannot be sent after
 *    GOAWAY),
 *    :member:`nghttp2_session_callbacks.on_ctrl_not_send_callback` is
 *    invoked. Abort the following steps.
 * 4. If the frame is request HEADERS, the stream is opened
 *    here.
 * 5. :member:`nghttp2_session_callbacks.before_ctrl_send_callback` is
 *    invoked.
 * 6. :member:`nghttp2_session_callbacks.send_callback` is invoked one
 *    or more times to send the frame.
 * 7. If the frame is a control frame,
 *    :member:`nghttp2_session_callbacks.on_ctrl_send_callback` is
 *    invoked.
 * 8. If the frame is a DATA frame,
 *    :member:`nghttp2_session_callbacks.on_data_send_callback` is
 *    invoked.
 * 9. If the transmission of the frame triggers closure of the stream,
 *    the stream is closed and
 *    :member:`nghttp2_session_callbacks.on_stream_close_callback` is
 *    invoked.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`
 *     The callback function failed.
 */
int nghttp2_session_send(nghttp2_session *session);

/**
 * @function
 *
 * Receives frames from the remote peer.
 *
 * This function receives as many frames as possible until the user
 * callback :member:`nghttp2_session_callbacks.recv_callback` returns
 * :enum:`NGHTTP2_ERR_WOULDBLOCK`. This function calls several
 * callback functions which are passed when initializing the
 * |session|. Here is the simple time chart which tells when each
 * callback is invoked:
 *
 * 1. :member:`nghttp2_session_callbacks.recv_callback` is invoked one
 *    or more times to receive frame header.
 * 2. If the frame is DATA frame:
 *
 *   2.1. :member:`nghttp2_session_callbacks.recv_callback` is invoked
 *        to receive DATA payload. For each chunk of data,
 *        :member:`nghttp2_session_callbacks.on_data_chunk_recv_callback`
 *        is invoked.
 *   2.2. If one DATA frame is completely received,
 *        :member:`nghttp2_session_callbacks.on_data_recv_callback` is
 *        invoked.  If the frame is the final frame of the request,
 *        :member:`nghttp2_session_callbacks.on_request_recv_callback`
 *        is invoked.  If the reception of the frame triggers the
 *        closure of the stream,
 *        :member:`nghttp2_session_callbacks.on_stream_close_callback`
 *        is invoked.
 *
 * 3. If the frame is the control frame:
 *
 *   3.1. :member:`nghttp2_session_callbacks.recv_callback` is invoked
 *        one or more times to receive whole frame.
 *   3.2. If the received frame is valid,
 *        :member:`nghttp2_session_callbacks.on_ctrl_recv_callback` is
 *        invoked.  If the frame is the final frame of the request,
 *        :member:`nghttp2_session_callbacks.on_request_recv_callback`
 *        is invoked.  If the reception of the frame triggers the
 *        closure of the stream,
 *        :member:`nghttp2_session_callbacks.on_stream_close_callback`
 *        is invoked.
 *   3.3. If the received frame is unpacked but is interpreted as
 *        invalid,
 *        :member:`nghttp2_session_callbacks.on_invalid_ctrl_recv_callback`
 *        is invoked.
 *   3.4. If the received frame could not be unpacked correctly,
 *        :member:`nghttp2_session_callbacks.on_ctrl_recv_parse_error_callback`
 *        is invoked.
 *   3.5. If the received frame type is unknown,
 *        :member:`nghttp2_session_callbacks.on_unknown_ctrl_recv_callback`
 *        is invoked.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_EOF`
 *     The remote peer did shutdown on the connection.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`
 *     The callback function failed.
 */
int nghttp2_session_recv(nghttp2_session *session);

/**
 * @function
 *
 * Processes data |in| as an input from the remote endpoint. The
 * |inlen| indicates the number of bytes in the |in|.
 *
 * This function behaves like `nghttp2_session_recv()` except that it
 * does not use :member:`nghttp2_session_callbacks.recv_callback` to
 * receive data; the |in| is the only data for the invocation of this
 * function. If all bytes are processed, this function returns. The
 * other callbacks are called in the same way as they are in
 * `nghttp2_session_recv()`.
 *
 * In the current implementation, this function always tries to
 * processes all input data unless an error occurs.
 *
 * This function returns the number of processed bytes, or one of the
 * following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
ssize_t nghttp2_session_mem_recv(nghttp2_session *session,
                                 const uint8_t *in, size_t inlen);

/**
 * @function
 *
 * Puts back previously deferred DATA frame in the stream |stream_id|
 * to the outbound queue.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The stream does not exist or no deferred data exist.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_session_resume_data(nghttp2_session *session, int32_t stream_id);

/**
 * @function
 *
 * Returns nonzero value if |session| wants to receive data from the
 * remote peer.
 *
 * If both `nghttp2_session_want_read()` and
 * `nghttp2_session_want_write()` return 0, the application should
 * drop the connection.
 */
int nghttp2_session_want_read(nghttp2_session *session);

/**
 * @function
 *
 * Returns nonzero value if |session| wants to send data to the remote
 * peer.
 *
 * If both `nghttp2_session_want_read()` and
 * `nghttp2_session_want_write()` return 0, the application should
 * drop the connection.
 */
int nghttp2_session_want_write(nghttp2_session *session);

/**
 * @function
 *
 * Returns stream_user_data for the stream |stream_id|. The
 * stream_user_data is provided by `nghttp2_submit_request()` or
 * `nghttp2_submit_syn_stream()`.  If the stream is initiated by the
 * remote endpoint, stream_user_data is always ``NULL``. If the stream
 * is initiated by the local endpoint and ``NULL`` is given in
 * `nghttp2_submit_request()` or `nghttp2_submit_syn_stream()`, then
 * this function returns ``NULL``. If the stream does not exist, this
 * function returns ``NULL``.
 */
void* nghttp2_session_get_stream_user_data(nghttp2_session *session,
                                           int32_t stream_id);

/**
 * @function
 *
 * Returns the number of frames in the outbound queue. This does not
 * include the deferred DATA frames.
 */
size_t nghttp2_session_get_outbound_queue_size(nghttp2_session *session);

/**
 * @function
 *
 * Submits GOAWAY frame with the given |error_code|.
 *
 * This function should be called when the connection should be
 * terminated after sending GOAWAY. If the remaining streams should be
 * processed after GOAWAY, use `nghttp2_submit_goaway()` instead.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_session_fail_session(nghttp2_session *session,
                                 nghttp2_error_code error_code);

/**
 * @function
 *
 * Performs post-process of HTTP Upgrade request. This function can be
 * called from both client and server, but the behavior is very
 * different in each other.
 *
 * If called from client side, the |settings_payload| must be the
 * value sent in ``HTTP2-Settings`` header field and must be decoded
 * by base64url decoder. The |settings_payloadlen| is the length of
 * |settings_payload|. The |settings_payload| is unpacked and its
 * setting values will be submitted using
 * `nghttp2_submit_settings()`. This means that the client application
 * code does not need to submit SETTINGS by itself. The stream with
 * stream ID=1 is opened and the |stream_user_data| is used for its
 * stream_user_data. The opened stream becomes half-closed (local)
 * state.
 *
 * If called from server side, the |settings_payload| must be the
 * value received in ``HTTP2-Settings`` header field and must be
 * decoded by base64url decoder. The |settings_payloadlen| is the
 * length of |settings_payload|. It is treated as if the SETTINGS
 * frame with that payload is received. Thus, callback functions for
 * the reception of SETTINGS frame will be invoked. The stream with
 * stream ID=1 is opened. The |stream_user_data| is ignored. The
 * opened stream becomes half-closed (remote).
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |settings_payload| is badly formed.
 * :enum:`NGHTTP2_ERR_PROTO`
 *     The stream ID 1 is already used or closed; or is not available;
 *     or the |settings_payload| does not include both
 *     :enum:`NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS` and
 *     :enum:`NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE`.
 */
int nghttp2_session_upgrade(nghttp2_session *session,
                            const uint8_t *settings_payload,
                            size_t settings_payloadlen,
                            void *stream_user_data);

/**
 * @function
 *
 * Serializes the SETTINGS values |iv| in the |buf|. The number of
 * entry pointed by |iv| array is given by the |niv|. This function
 * may reorder the pointers in |iv|. The |buf| must have enough region
 * to hold serialized data. The required space for the |niv| entries
 * are ``8*niv`` bytes. This function is used mainly for creating
 * SETTINGS payload to be sent with ``HTTP2-Settings`` header field in
 * HTTP Upgrade request. The data written in |buf| is not still
 * base64url encoded and the application is responsible for encoding.
 *
 * This function returns the number of bytes written in |buf|, or one
 * of the following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |iv| contains duplicate settings ID or invalid value.
 */
ssize_t nghttp2_pack_settings_payload(uint8_t *buf,
                                      nghttp2_settings_entry *iv, size_t niv);

/**
 * @function
 *
 * Returns string describing the |lib_error_code|. The
 * |lib_error_code| must be one of the :enum:`nghttp2_error`.
 */
const char* nghttp2_strerror(int lib_error_code);

/**
 * @function
 *
 * Submits HEADERS frame and optionally one or more DATA frames.
 *
 * The |pri| is priority of this request. 0 is the highest priority
 * value and :macro:`NGHTTP2_PRI_LOWEST` is the lowest value.
 *
 * The |nv| contains the name/value pairs. For i >= 0, ``nv[2*i]``
 * contains a pointer to the name string and ``nv[2*i+1]`` contains a
 * pointer to the value string. The one beyond last value must be
 * ``NULL``. That is, if the |nv| contains N name/value pairs,
 * ``nv[2*N]`` must be ``NULL``.
 *
 * The |nv| must include following name/value pairs:
 *
 * ``:method``
 *     HTTP method (e.g., ``GET``, ``POST``, ``HEAD``, etc)
 * ``:scheme``
 *     URI scheme (e.g., ``https``)
 * ``:path``
 *     Absolute path and parameters of this request (e.g., ``/foo``,
 *     ``/foo;bar;haz?h=j&y=123``)
 * ``:host``
 *     The hostport portion of the URI for this request (e.g.,
 *     ``example.org:443``). This is the same as the HTTP "Host" header
 *     field.
 *
 * This function creates copies of all name/value pairs in |nv|.  It
 * also lower-cases all names in |nv|.
 *
 * If |data_prd| is not ``NULL``, it provides data which will be sent
 * in subsequent DATA frames. In this case, a method that allows
 * request message bodies
 * (http://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9) must
 * be specified with ``:method`` key in |nv| (e.g. ``POST``). This
 * function does not take ownership of the |data_prd|. The function
 * copies the members of the |data_prd|. If |data_prd| is ``NULL``,
 * HEADERS have END_STREAM set. The |stream_user_data| is data
 * associated to the stream opened by this request and can be an
 * arbitrary pointer, which can be retrieved later by
 * `nghttp2_session_get_stream_user_data()`.
 *
 * Since the library reorders the frames and tries to send the highest
 * prioritized one first and the HTTP/2.0 specification requires the
 * stream ID must be strictly increasing, the stream ID of this
 * request cannot be known until it is about to sent.  To know the
 * stream ID of the request, the application can use
 * :member:`nghttp2_session_callbacks.before_ctrl_send_callback`. This
 * callback is called just before the frame is sent. For HEADERS
 * frame, the argument frame has the stream ID assigned. Also since
 * the stream is already opened,
 * `nghttp2_session_get_stream_user_data()` can be used to get
 * |stream_user_data| to identify which HEADERS we are processing.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |pri| is invalid; or the |nv| includes empty name or
 *     ``NULL`` value.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_submit_request(nghttp2_session *session, int32_t pri,
                           const char **nv,
                           const nghttp2_data_provider *data_prd,
                           void *stream_user_data);

/**
 * @function
 *
 * Submits response HEADERS frame and optionally one or more DATA
 * frames against the stream |stream_id|.
 *
 * The |nv| contains the name/value pairs. For i >= 0, ``nv[2*i]``
 * contains a pointer to the name string and ``nv[2*i+1]`` contains a
 * pointer to the value string. The one beyond last value must be
 * ``NULL``. That is, if the |nv| contains N name/value pairs,
 * ``nv[2*N]`` must be ``NULL``.
 *
 * The |nv| must include following name/value pairs:
 *
 * ``:status``
 *     HTTP status code (e.g., ``200`` or ``200 OK``)
 *
 * This function creates copies of all name/value pairs in |nv|.  It
 * also lower-cases all names in |nv|.
 *
 * If |data_prd| is not ``NULL``, it provides data which will be sent
 * in subsequent DATA frames.  This function does not take ownership
 * of the |data_prd|. The function copies the members of the
 * |data_prd|.  If |data_prd| is ``NULL``, HEADERS will have
 * END_STREAM flag set.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |nv| includes empty name or ``NULL`` value.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_submit_response(nghttp2_session *session,
                            int32_t stream_id, const char **nv,
                            const nghttp2_data_provider *data_prd);

/**
 * @function
 *
 * Submits HEADERS frame. The |flags| is bitwise OR of the
 * following values:
 *
 * * :enum:`NGHTTP2_FLAG_END_STREAM`
 * * :enum:`NGHTTP2_FLAG_END_HEADERS`
 * * :enum:`NGHTTP2_FLAG_PRIORITY`
 *
 * If |flags| includes :enum:`NGHTTP2_FLAG_END_STREAM`, this frame has
 * END_STREAM flag set. The library does not support header
 * continuation and the HEADERS frame always has
 * :enum:`NGHTTP2_FLAG_END_HEADERS` flag set regardless of the |flags|
 * value.
 *
 * If the |stream_id| is -1, this frame is assumed as request (i.e.,
 * request HEADERS frame which opens new stream). In this case, the
 * actual stream ID is assigned just before the frame is sent. For
 * response, specify stream ID in |stream_id|.
 *
 * The |pri| is priority of this request.
 *
 * The |nv| contains the name/value pairs. For i >= 0, ``nv[2*i]``
 * contains a pointer to the name string and ``nv[2*i+1]`` contains a
 * pointer to the value string. The one beyond last value must be
 * ``NULL``. That is, if the |nv| contains N name/value pairs,
 * ``nv[2*N]`` must be ``NULL``.
 *
 * This function creates copies of all name/value pairs in |nv|.  It
 * also lower-cases all names in |nv|.
 *
 * The |stream_user_data| is a pointer to an arbitrary data which is
 * associated to the stream this frame will open. Therefore it is only
 * used if this frame opens streams, in other words, it changes stream
 * state from idle or reserved to open.
 *
 * This function is low-level in a sense that the application code can
 * specify flags directly. For usual HTTP request,
 * `nghttp2_submit_request()` is useful.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |pri| is invalid; or the |nv| includes empty name or
 *     ``NULL`` value.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_submit_headers(nghttp2_session *session, uint8_t flags,
                           int32_t stream_id, int32_t pri, const char **nv,
                           void *stream_user_data);

/**
 * @function
 *
 * Submits one or more DATA frames to the stream |stream_id|.  The
 * data to be sent are provided by |data_prd|. If |flags| contains
 * :enum:`NGHTTP2_FLAG_END_STREAM`, the last DATA frame has END_STREAM
 * flag set.
 *
 * This function does not take ownership of the |data_prd|. The
 * function copies the members of the |data_prd|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_STREAM_CLOSED`
 *     The stream is already closed or does not exist.
 */
int nghttp2_submit_data(nghttp2_session *session, uint8_t flags,
                        int32_t stream_id,
                        const nghttp2_data_provider *data_prd);

/**
 * @function
 *
 * Submits PRIORITY frame to change the priority of stream |stream_id|
 * to the priority value |pri|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |pri| is negative.
 * :enum:`NGHTTP2_ERR_STREAM_CLOSED`
 *     The stream is already closed or does not exist.
 */
int nghttp2_submit_priority(nghttp2_session *session, int32_t stream_id,
                            int32_t pri);

/**
 * @function
 *
 * Submits RST_STREAM frame to cancel/reject the stream |stream_id|
 * with the error code |error_code|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_submit_rst_stream(nghttp2_session *session, int32_t stream_id,
                              nghttp2_error_code error_code);

/**
 * @function
 *
 * Stores local settings and submits SETTINGS frame. The |iv| is the
 * pointer to the array of :type:`nghttp2_settings_entry`. The |niv|
 * indicates the number of :type:`nghttp2_settings_entry`.
 *
 * This function does not take ownership of the |iv|. This function
 * copies all the elements in the |iv|.
 *
 * While updating individual stream's local window size, if the window
 * size becomes strictly larger than NGHTTP2_MAX_WINDOW_SIZE,
 * RST_STREAM is issued against such a stream.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |iv| contains invalid value (e.g., attempting to re-enable
 *     flow control).
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_submit_settings(nghttp2_session *session,
                            const nghttp2_settings_entry *iv, size_t niv);


/**
 * @function
 *
 * Submits PUSH_PROMISE frame. The |flags| is currently ignored and
 * the resulting PUSH_PROMISE frame always has
 * :enum:`NGHTTP2_FLAG_END_PUSH_PROMISE` flag set due to the lack of
 * header continuation support in the library.
 *
 * The |stream_id| must be client initiated stream ID.
 *
 * The |nv| contains the name/value pairs. For i >= 0, ``nv[2*i]``
 * contains a pointer to the name string and ``nv[2*i+1]`` contains a
 * pointer to the value string. The one beyond last value must be
 * ``NULL``. That is, if the |nv| contains N name/value pairs,
 * ``nv[2*N]`` must be ``NULL``.
 *
 * This function creates copies of all name/value pairs in |nv|.  It
 * also lower-cases all names in |nv|.
 *
 * Since the library reorders the frames and tries to send the highest
 * prioritized one first and the HTTP/2.0 specification requires the
 * stream ID must be strictly increasing, the promised stream ID
 * cannot be known until it is about to sent.  To know the promised
 * stream ID, the application can use
 * :member:`nghttp2_session_callbacks.before_frame_send_callback`. This
 * callback is called just before the frame is sent. For PUSH_PROMISE
 * frame, the argument frame has the promised stream ID assigned.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |nv| includes empty name or ``NULL`` value.
 * :enum:`NGHTTP2_ERR_STREAM_CLOSED`
 *     The stream is already closed or does not exist.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_submit_push_promise(nghttp2_session *session, uint8_t flags,
                                int32_t stream_id, const char **nv);

/**
 * @function
 *
 * Submits PING frame. You don't have to send PING back when you
 * received PING frame. The library automatically submits PING frame
 * in this case.
 *
 * If the |opaque_data| is non ``NULL``, then it should point to the 8
 * bytes array of memory to specify opaque data to send with PING
 * frame. If the |opaque_data| is ``NULL``, zero-cleared 8 bytes will
 * be sent as opaque data.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_submit_ping(nghttp2_session *session, uint8_t *opaque_data);

/**
 * @function
 *
 * Submits GOAWAY frame with the error code |error_code|.
 *
 * If the |opaque_data| is not ``NULL`` and |opaque_data_len| is not
 * zero, those data will be sent as additional debug data.  The
 * library makes a copy of the memory region pointed by |opaque_data|
 * with the length |opaque_data_len|, so the caller does not need to
 * keep this memory after the return of this function. If the
 * |opaque_data_len| is 0, the |opaque_data| could be ``NULL``.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_submit_goaway(nghttp2_session *session,
                          nghttp2_error_code error_code,
                          uint8_t *opaque_data, size_t opaque_data_len);

/**
 * @function
 *
 * Submits WINDOW_UPDATE frame.
 *
 * The |flags| is currently ignored.
 *
 * If the |window_size_increment| is positive, the WINDOW_UPDATE with
 * that value as window_size_increment is queued. If the
 * |window_size_increment| is larger than the received bytes from the
 * remote endpoint, the local window size is increased by that
 * difference.
 *
 * If the |window_size_increment| is negative, the local window size
 * is decreased by -|window_size_increment|.  If
 * :enum:`NGHTTP2_OPT_NO_AUTO_STREAM_WINDOW_UPDATE` (or
 * :enum:`NGHTTP2_OPT_NO_AUTO_CONNECTION_WINDOW_UPDATE` if |stream_id|
 * is 0) is not set and the library decided that the WINDOW_UPDATE
 * should be submitted, then WINDOW_UPDATE is queued with the current
 * received bytes count.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |delta_window_size| is 0.
 * :enum:`NGHTTP2_ERR_FLOW_CONTROL`
 *     The local window size overflow or gets negative.
 * :enum:`NGHTTP2_ERR_STREAM_CLOSED`
 *     The stream is already closed or does not exist.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_submit_window_update(nghttp2_session *session, uint8_t flags,
                                 int32_t stream_id,
                                 int32_t window_size_increment);

/**
 * @function
 *
 * Compares lhs->name with lhs->namelen bytes and rhs->name with
 * rhs->namelen bytes. Returns negative integer if lhs->name is found
 * to be less than rhs->name; or returns positive integer if lhs->name
 * is found to be greater than rhs->name; or returns 0 otherwise.
 */
int nghttp2_nv_compare_name(const nghttp2_nv *lhs, const nghttp2_nv *rhs);

/**
 * @function
 *
 * A helper function for dealing with NPN in client side.  The |in|
 * contains server's protocol in preferable order.  The format of |in|
 * is length-prefixed and not null-terminated.  For example,
 * ``HTTP-draft-04/2.0`` and ``http/1.1`` stored in |in| like this::
 *
 *     in[0] = 17
 *     in[1..17] = "HTTP-draft-04/2.0"
 *     in[18] = 8
 *     in[19..26] = "http/1.1"
 *     inlen = 27
 *
 * The selection algorithm is as follows:
 *
 * 1. If server's list contains ``HTTP-draft-04/2.0``, it is selected
 *    and returns 1. The following step is not taken.
 *
 * 2. If server's list contains ``http/1.1``, this function selects
 *    ``http/1.1`` and returns 0. The following step is not taken.
 *
 * 3. This function selects nothing and returns -1. (So called
 *    non-overlap case). In this case, |out| and |outlen| are left
 *    untouched.
 *
 * Selecting ``HTTP-draft-04/2.0`` means that ``HTTP-draft-04/2.0`` is
 * written into |*out| and its length (which is 17) is
 * assigned to |*outlen|.
 *
 * See http://technotes.googlecode.com/git/nextprotoneg.html for more
 * details about NPN.
 *
 * To use this method you should do something like::
 *
 *     static int select_next_proto_cb(SSL* ssl,
 *                                     unsigned char **out,
 *                                     unsigned char *outlen,
 *                                     const unsigned char *in,
 *                                     unsigned int inlen,
 *                                     void *arg)
 *     {
 *         int rv;
 *         rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
 *         if(rv == 1) {
 *             ((MyType*)arg)->http2_selected = 1;
 *         }
 *         return SSL_TLSEXT_ERR_OK;
 *     }
 *     ...
 *     SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, my_obj);
 *
 * Note that the HTTP/2.0 spec does use ALPN instead of NPN. This
 * function is provided for transitional period before ALPN is got
 * implemented in major SSL/TLS libraries.
 *
 */
int nghttp2_select_next_protocol(unsigned char **out, unsigned char *outlen,
                                 const unsigned char *in, unsigned int inlen);

struct nghttp2_gzip;

/**
 * @struct
 *
 * The gzip stream to inflate data. The details of this structure are
 * intentionally hidden from the public API.
 */
typedef struct nghttp2_gzip nghttp2_gzip;

/**
 * @function
 *
 * A helper function to set up a per request gzip stream to inflate data.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_GZIP`
 *     The initialization of gzip stream failed.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_gzip_inflate_new(nghttp2_gzip **inflater_ptr);

/**
 * @function
 *
 * Frees the inflate stream.  The |inflater| may be ``NULL``.
 */
void nghttp2_gzip_inflate_del(nghttp2_gzip *inflater);

/**
 * @function
 *
 * Inflates data in |in| with the length |*inlen_ptr| and stores the
 * inflated data to |out| which has allocated size at least
 * |*outlen_ptr|. On return, |*outlen_ptr| is updated to represent
 * the number of data written in |out|.  Similarly, |*inlen_ptr| is
 * updated to represent the number of input bytes processed.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_GZIP`
 *     The inflation of gzip stream failed.
 *
 * The example follows::
 *
 *     void on_data_chunk_recv_callback(nghttp2_session *session,
 *                                      uint8_t flags,
 *                                      int32_t stream_id,
 *                                      const uint8_t *data, size_t len,
 *                                      void *user_data)
 *     {
 *         ...
 *         req = nghttp2_session_get_stream_user_data(session, stream_id);
 *         nghttp2_gzip *inflater = req->inflater;
 *         while(len > 0) {
 *             uint8_t out[MAX_OUTLEN];
 *             size_t outlen = MAX_OUTLEN;
 *             size_t tlen = len;
 *             int rv;
 *             rv = nghttp2_gzip_inflate(inflater, out, &outlen, data, &tlen);
 *             if(rv != 0) {
 *                 nghttp2_submit_rst_stream(session, stream_id,
 *                                           NGHTTP2_INTERNAL_ERROR);
 *                 break;
 *             }
 *             ... Do stuff ...
 *             data += tlen;
 *             len -= tlen;
 *         }
 *         ....
 *     }
 */
int nghttp2_gzip_inflate(nghttp2_gzip *inflater,
                         uint8_t *out, size_t *outlen_ptr,
                         const uint8_t *in, size_t *inlen_ptr);

/**
 * @function
 *
 * Returns a pointer to a nghttp2_info struct with version information about
 * the run-time library in use.  The |least_version| argument can be set to a
 * 24 bit numerical value for the least accepted version number and if the
 * condition is not met, this function will return a NULL. Pass in 0 to skip
 * the version checking.
 */
nghttp2_info *nghttp2_version(int least_version);

#ifdef __cplusplus
}
#endif

#endif /* NGHTTP2_H */
