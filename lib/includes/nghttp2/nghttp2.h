/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013, 2014 Tatsuhiro Tsujikawa
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

/* Define WIN32 when build target is Win32 API (borrowed from
   libcurl) */
#if (defined(_WIN32) || defined(__WIN32__)) && !defined(WIN32)
#define WIN32
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#if defined(_MSC_VER) && (_MSC_VER < 1800)
/* MSVC < 2013 does not have inttypes.h because it is not C99
   compliant.  See compiler macros and version number in
   https://sourceforge.net/p/predef/wiki/Compilers/ */
#include <stdint.h>
#else /* !defined(_MSC_VER) || (_MSC_VER >= 1800) */
#include <inttypes.h>
#endif /* !defined(_MSC_VER) || (_MSC_VER >= 1800) */
#include <sys/types.h>

#include <nghttp2/nghttp2ver.h>

#ifdef NGHTTP2_STATICLIB
#define NGHTTP2_EXTERN
#elif defined(WIN32)
#ifdef BUILDING_NGHTTP2
#define NGHTTP2_EXTERN __declspec(dllexport)
#else /* !BUILDING_NGHTTP2 */
#define NGHTTP2_EXTERN __declspec(dllimport)
#endif /* !BUILDING_NGHTTP2 */
#else  /* !defined(WIN32) */
#define NGHTTP2_EXTERN
#endif /* !defined(WIN32) */

/**
 * @macro
 *
 * The protocol version identification string of this library
 * supports.  This identifier is used if HTTP/2 is used over TLS.
 */
#define NGHTTP2_PROTO_VERSION_ID "h2"
/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_PROTO_VERSION_ID`.
 */
#define NGHTTP2_PROTO_VERSION_ID_LEN 2

/**
 * @macro
 *
 * The seriazlied form of ALPN protocol identifier this library
 * supports.  Notice that first byte is the length of following
 * protocol identifier.  This is the same wire format of `TLS ALPN
 * extension <https://tools.ietf.org/html/rfc7301>`_.  This is useful
 * to process incoming ALPN tokens in wire format.
 */
#define NGHTTP2_PROTO_ALPN "\x2h2"

/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_PROTO_ALPN`.
 */
#define NGHTTP2_PROTO_ALPN_LEN (sizeof(NGHTTP2_PROTO_ALPN) - 1)

/**
 * @macro
 *
 * The protocol version identification string of this library
 * supports.  This identifier is used if HTTP/2 is used over cleartext
 * TCP.
 */
#define NGHTTP2_CLEARTEXT_PROTO_VERSION_ID "h2c"

/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_CLEARTEXT_PROTO_VERSION_ID`.
 */
#define NGHTTP2_CLEARTEXT_PROTO_VERSION_ID_LEN 3

struct nghttp2_session;
/**
 * @struct
 *
 * The primary structure to hold the resources needed for a HTTP/2
 * session.  The details of this structure are intentionally hidden
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
 * This struct is what `nghttp2_version()` returns.  It holds
 * information about the particular nghttp2 version.
 */
typedef struct {
  /**
   * Age of this struct.  This instance of nghttp2 sets it to
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
 * The default weight of stream dependency.
 */
#define NGHTTP2_DEFAULT_WEIGHT 16

/**
 * @macro
 *
 * The maximum weight of stream dependency.
 */
#define NGHTTP2_MAX_WEIGHT 256

/**
 * @macro
 *
 * The minimum weight of stream dependency.
 */
#define NGHTTP2_MIN_WEIGHT 1

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
 * The default header table size.
 */
#define NGHTTP2_DEFAULT_HEADER_TABLE_SIZE (1 << 12)

/**
 * @macro
 *
 * The client magic string, which is the first 24 bytes byte string of
 * client connection preface.
 */
#define NGHTTP2_CLIENT_MAGIC "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_CLIENT_MAGIC`.
 */
#define NGHTTP2_CLIENT_MAGIC_LEN 24

/**
 * @enum
 *
 * Error codes used in this library.  The code range is [-999, -500],
 * inclusive. The following values are defined:
 */
typedef enum {
  /**
   * Invalid argument passed.
   */
  NGHTTP2_ERR_INVALID_ARGUMENT = -501,
  /**
   * Out of buffer space.
   */
  NGHTTP2_ERR_BUFFER_ERROR = -502,
  /**
   * The specified protocol version is not supported.
   */
  NGHTTP2_ERR_UNSUPPORTED_VERSION = -503,
  /**
   * Used as a return value from :type:`nghttp2_send_callback`,
   * :type:`nghttp2_recv_callback` and
   * :type:`nghttp2_send_data_callback` to indicate that the operation
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
   * transfer is postponed.  See
   * :func:`nghttp2_data_source_read_callback` for details.
   */
  NGHTTP2_ERR_DEFERRED = -508,
  /**
   * Stream ID has reached the maximum value.  Therefore no stream ID
   * is available.
   */
  NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE = -509,
  /**
   * The stream is already closed; or the stream ID is invalid.
   */
  NGHTTP2_ERR_STREAM_CLOSED = -510,
  /**
   * RST_STREAM has been added to the outbound queue.  The stream is
   * in closing state.
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
   * Starting new stream is not allowed (e.g., GOAWAY has been sent
   * and/or received).
   */
  NGHTTP2_ERR_START_STREAM_NOT_ALLOWED = -516,
  /**
   * GOAWAY has already been sent.
   */
  NGHTTP2_ERR_GOAWAY_ALREADY_SENT = -517,
  /**
   * The received frame contains the invalid header block (e.g., There
   * are duplicate header names; or the header names are not encoded
   * in US-ASCII character set and not lower cased; or the header name
   * is zero-length string; or the header value contains multiple
   * in-sequence NUL bytes).
   */
  NGHTTP2_ERR_INVALID_HEADER_BLOCK = -518,
  /**
   * Indicates that the context is not suitable to perform the
   * requested operation.
   */
  NGHTTP2_ERR_INVALID_STATE = -519,
  /**
   * The user callback function failed due to the temporal error.
   */
  NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE = -521,
  /**
   * The length of the frame is invalid, either too large or too small.
   */
  NGHTTP2_ERR_FRAME_SIZE_ERROR = -522,
  /**
   * Header block inflate/deflate error.
   */
  NGHTTP2_ERR_HEADER_COMP = -523,
  /**
   * Flow control error
   */
  NGHTTP2_ERR_FLOW_CONTROL = -524,
  /**
   * Insufficient buffer size given to function.
   */
  NGHTTP2_ERR_INSUFF_BUFSIZE = -525,
  /**
   * Callback was paused by the application
   */
  NGHTTP2_ERR_PAUSE = -526,
  /**
   * There are too many in-flight SETTING frame and no more
   * transmission of SETTINGS is allowed.
   */
  NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS = -527,
  /**
   * The server push is disabled.
   */
  NGHTTP2_ERR_PUSH_DISABLED = -528,
  /**
   * DATA or HEADERS frame for a given stream has been already
   * submitted and has not been fully processed yet.  Application
   * should wait for the transmission of the previously submitted
   * frame before submitting another.
   */
  NGHTTP2_ERR_DATA_EXIST = -529,
  /**
   * The current session is closing due to a connection error or
   * `nghttp2_session_terminate_session()` is called.
   */
  NGHTTP2_ERR_SESSION_CLOSING = -530,
  /**
   * Invalid HTTP header field was received and stream is going to be
   * closed.
   */
  NGHTTP2_ERR_HTTP_HEADER = -531,
  /**
   * Violation in HTTP messaging rule.
   */
  NGHTTP2_ERR_HTTP_MESSAGING = -532,
  /**
   * Stream was refused.
   */
  NGHTTP2_ERR_REFUSED_STREAM = -533,
  /**
   * Unexpected internal error, but recovered.
   */
  NGHTTP2_ERR_INTERNAL = -534,
  /**
   * The errors < :enum:`NGHTTP2_ERR_FATAL` mean that the library is
   * under unexpected condition and processing was terminated (e.g.,
   * out of memory).  If application receives this error code, it must
   * stop using that :type:`nghttp2_session` object and only allowed
   * operation for that object is deallocate it using
   * `nghttp2_session_del()`.
   */
  NGHTTP2_ERR_FATAL = -900,
  /**
   * Out of memory.  This is a fatal error.
   */
  NGHTTP2_ERR_NOMEM = -901,
  /**
   * The user callback function failed.  This is a fatal error.
   */
  NGHTTP2_ERR_CALLBACK_FAILURE = -902,
  /**
   * Invalid client magic (see :macro:`NGHTTP2_CLIENT_MAGIC`) was
   * received and further processing is not possible.
   */
  NGHTTP2_ERR_BAD_CLIENT_MAGIC = -903
} nghttp2_error;

/**
 * @enum
 *
 * The flags for header field name/value pair.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_NV_FLAG_NONE = 0,
  /**
   * Indicates that this name/value pair must not be indexed ("Literal
   * Header Field never Indexed" representation must be used in HPACK
   * encoding).  Other implementation calls this bit as "sensitive".
   */
  NGHTTP2_NV_FLAG_NO_INDEX = 0x01
} nghttp2_nv_flag;

/**
 * @struct
 *
 * The name/value pair, which mainly used to represent header fields.
 */
typedef struct {
  /**
   * The |name| byte string.  If this struct is presented from library
   * (e.g., :type:`nghttp2_on_frame_recv_callback`), |name| is
   * guaranteed to be NULL-terminated.  When application is
   * constructing this struct, |name| is not required to be
   * NULL-terminated.
   */
  uint8_t *name;
  /**
   * The |value| byte string.  If this struct is presented from
   * library (e.g., :type:`nghttp2_on_frame_recv_callback`), |value|
   * is guaranteed to be NULL-terminated.  When application is
   * constructing this struct, |value| is not required to be
   * NULL-terminated.
   */
  uint8_t *value;
  /**
   * The length of the |name|, excluding terminating NULL.
   */
  size_t namelen;
  /**
   * The length of the |value|, excluding terminating NULL.
   */
  size_t valuelen;
  /**
   * Bitwise OR of one or more of :type:`nghttp2_nv_flag`.
   */
  uint8_t flags;
} nghttp2_nv;

/**
 * @enum
 *
 * The frame types in HTTP/2 specification.
 */
typedef enum {
  /**
   * The DATA frame.
   */
  NGHTTP2_DATA = 0,
  /**
   * The HEADERS frame.
   */
  NGHTTP2_HEADERS = 0x01,
  /**
   * The PRIORITY frame.
   */
  NGHTTP2_PRIORITY = 0x02,
  /**
   * The RST_STREAM frame.
   */
  NGHTTP2_RST_STREAM = 0x03,
  /**
   * The SETTINGS frame.
   */
  NGHTTP2_SETTINGS = 0x04,
  /**
   * The PUSH_PROMISE frame.
   */
  NGHTTP2_PUSH_PROMISE = 0x05,
  /**
   * The PING frame.
   */
  NGHTTP2_PING = 0x06,
  /**
   * The GOAWAY frame.
   */
  NGHTTP2_GOAWAY = 0x07,
  /**
   * The WINDOW_UPDATE frame.
   */
  NGHTTP2_WINDOW_UPDATE = 0x08,
  /**
   * The CONTINUATION frame.  This frame type won't be passed to any
   * callbacks because the library processes this frame type and its
   * preceding HEADERS/PUSH_PROMISE as a single frame.
   */
  NGHTTP2_CONTINUATION = 0x09
} nghttp2_frame_type;

/**
 * @enum
 *
 * The flags for HTTP/2 frames.  This enum defines all flags for all
 * frames.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_FLAG_NONE = 0,
  /**
   * The END_STREAM flag.
   */
  NGHTTP2_FLAG_END_STREAM = 0x01,
  /**
   * The END_HEADERS flag.
   */
  NGHTTP2_FLAG_END_HEADERS = 0x04,
  /**
   * The ACK flag.
   */
  NGHTTP2_FLAG_ACK = 0x01,
  /**
   * The PADDED flag.
   */
  NGHTTP2_FLAG_PADDED = 0x08,
  /**
   * The PRIORITY flag.
   */
  NGHTTP2_FLAG_PRIORITY = 0x20
} nghttp2_flag;

/**
 * @enum
 * The SETTINGS ID.
 */
typedef enum {
  /**
   * SETTINGS_HEADER_TABLE_SIZE
   */
  NGHTTP2_SETTINGS_HEADER_TABLE_SIZE = 0x01,
  /**
   * SETTINGS_ENABLE_PUSH
   */
  NGHTTP2_SETTINGS_ENABLE_PUSH = 0x02,
  /**
   * SETTINGS_MAX_CONCURRENT_STREAMS
   */
  NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x03,
  /**
   * SETTINGS_INITIAL_WINDOW_SIZE
   */
  NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 0x04,
  /**
   * SETTINGS_MAX_FRAME_SIZE
   */
  NGHTTP2_SETTINGS_MAX_FRAME_SIZE = 0x05,
  /**
   * SETTINGS_MAX_HEADER_LIST_SIZE
   */
  NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x06
} nghttp2_settings_id;
/* Note: If we add SETTINGS, update the capacity of
   NGHTTP2_INBOUND_NUM_IV as well */

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
  NGHTTP2_NO_ERROR = 0x00,
  /**
   * PROTOCOL_ERROR
   */
  NGHTTP2_PROTOCOL_ERROR = 0x01,
  /**
   * INTERNAL_ERROR
   */
  NGHTTP2_INTERNAL_ERROR = 0x02,
  /**
   * FLOW_CONTROL_ERROR
   */
  NGHTTP2_FLOW_CONTROL_ERROR = 0x03,
  /**
   * SETTINGS_TIMEOUT
   */
  NGHTTP2_SETTINGS_TIMEOUT = 0x04,
  /**
   * STREAM_CLOSED
   */
  NGHTTP2_STREAM_CLOSED = 0x05,
  /**
   * FRAME_SIZE_ERROR
   */
  NGHTTP2_FRAME_SIZE_ERROR = 0x06,
  /**
   * REFUSED_STREAM
   */
  NGHTTP2_REFUSED_STREAM = 0x07,
  /**
   * CANCEL
   */
  NGHTTP2_CANCEL = 0x08,
  /**
   * COMPRESSION_ERROR
   */
  NGHTTP2_COMPRESSION_ERROR = 0x09,
  /**
   * CONNECT_ERROR
   */
  NGHTTP2_CONNECT_ERROR = 0x0a,
  /**
   * ENHANCE_YOUR_CALM
   */
  NGHTTP2_ENHANCE_YOUR_CALM = 0x0b,
  /**
   * INADEQUATE_SECURITY
   */
  NGHTTP2_INADEQUATE_SECURITY = 0x0c,
  /**
   * HTTP_1_1_REQUIRED
   */
  NGHTTP2_HTTP_1_1_REQUIRED = 0x0d
} nghttp2_error_code;

/**
 * @struct
 * The frame header.
 */
typedef struct {
  /**
   * The length field of this frame, excluding frame header.
   */
  size_t length;
  /**
   * The stream identifier (aka, stream ID)
   */
  int32_t stream_id;
  /**
   * The type of this frame.  See `nghttp2_frame_type`.
   */
  uint8_t type;
  /**
   * The flags.
   */
  uint8_t flags;
  /**
   * Reserved bit in frame header.  Currently, this is always set to 0
   * and application should not expect something useful in here.
   */
  uint8_t reserved;
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
 * @enum
 *
 * The flags used to set in |data_flags| output parameter in
 * :type:`nghttp2_data_source_read_callback`.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_DATA_FLAG_NONE = 0,
  /**
   * Indicates EOF was sensed.
   */
  NGHTTP2_DATA_FLAG_EOF = 0x01,
  /**
   * Indicates that END_STREAM flag must not be set even if
   * NGHTTP2_DATA_FLAG_EOF is set.  Usually this flag is used to send
   * trailer header fields with `nghttp2_submit_request()` or
   * `nghttp2_submit_response()`.
   */
  NGHTTP2_DATA_FLAG_NO_END_STREAM = 0x02,
  /**
   * Indicates that application will send complete DATA frame in
   * :type:`nghttp2_send_data_callback`.
   */
  NGHTTP2_DATA_FLAG_NO_COPY = 0x04
} nghttp2_data_flag;

/**
 * @functypedef
 *
 * Callback function invoked when the library wants to read data from
 * the |source|.  The read data is sent in the stream |stream_id|.
 * The implementation of this function must read at most |length|
 * bytes of data from |source| (or possibly other places) and store
 * them in |buf| and return number of data stored in |buf|.  If EOF is
 * reached, set :enum:`NGHTTP2_DATA_FLAG_EOF` flag in |*data_flags|.
 *
 * Sometime it is desirable to avoid copying data into |buf| and let
 * application to send data directly.  To achieve this, set
 * :enum:`NGHTTP2_DATA_FLAG_NO_COPY` to |*data_flags| (and possibly
 * other flags, just like when we do copy), and return the number of
 * bytes to send without copying data into |buf|.  The library, seeing
 * :enum:`NGHTTP2_DATA_FLAG_NO_COPY`, will invoke
 * :type:`nghttp2_send_data_callback`.  The application must send
 * complete DATA frame in that callback.
 *
 * If this callback is set by `nghttp2_submit_request()`,
 * `nghttp2_submit_response()` or `nghttp2_submit_headers()` and
 * `nghttp2_submit_data()` with flag parameter
 * :enum:`NGHTTP2_FLAG_END_STREAM` set, and
 * :enum:`NGHTTP2_DATA_FLAG_EOF` flag is set to |*data_flags|, DATA
 * frame will have END_STREAM flag set.  Usually, this is expected
 * behaviour and all are fine.  One exception is send trailer header
 * fields.  You cannot send trailers after sending frame with
 * END_STREAM set.  To avoid this problem, one can set
 * :enum:`NGHTTP2_DATA_FLAG_NO_END_STREAM` along with
 * :enum:`NGHTTP2_DATA_FLAG_EOF` to signal the library not to set
 * END_STREAM in DATA frame.  Then application can use
 * `nghttp2_submit_trailer()` to send trailers.
 * `nghttp2_submit_trailer()` can be called inside this callback.
 *
 * If the application wants to postpone DATA frames (e.g.,
 * asynchronous I/O, or reading data blocks for long time), it is
 * achieved by returning :enum:`NGHTTP2_ERR_DEFERRED` without reading
 * any data in this invocation.  The library removes DATA frame from
 * the outgoing queue temporarily.  To move back deferred DATA frame
 * to outgoing queue, call `nghttp2_session_resume_data()`.  In case
 * of error, there are 2 choices. Returning
 * :enum:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE` will close the stream
 * by issuing RST_STREAM with :enum:`NGHTTP2_INTERNAL_ERROR`.  If a
 * different error code is desirable, use
 * `nghttp2_submit_rst_stream()` with a desired error code and then
 * return :enum:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.  Returning
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE` will signal the entire session
 * failure.
 */
typedef ssize_t (*nghttp2_data_source_read_callback)(
    nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
    uint32_t *data_flags, nghttp2_data_source *source, void *user_data);

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
 * @struct
 *
 * The DATA frame.  The received data is delivered via
 * :type:`nghttp2_on_data_chunk_recv_callback`.
 */
typedef struct {
  nghttp2_frame_hd hd;
  /**
   * The length of the padding in this frame.  This includes PAD_HIGH
   * and PAD_LOW.
   */
  size_t padlen;
} nghttp2_data;

/**
 * @enum
 *
 * The category of HEADERS, which indicates the role of the frame.  In
 * HTTP/2 spec, request, response, push response and other arbitrary
 * headers (e.g., trailers) are all called just HEADERS.  To give the
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
   * which is analogous to HEADERS in SPDY.  If non-final response
   * (e.g., status 1xx) is used, final response HEADERS frame will be
   * categorized here.
   */
  NGHTTP2_HCAT_HEADERS = 3
} nghttp2_headers_category;

/**
 * @struct
 *
 * The structure to specify stream dependency.
 */
typedef struct {
  /**
   * The stream ID of the stream to depend on.  Specifying 0 makes
   * stream not depend any other stream.
   */
  int32_t stream_id;
  /**
   * The weight of this dependency.
   */
  int32_t weight;
  /**
   * nonzero means exclusive dependency
   */
  uint8_t exclusive;
} nghttp2_priority_spec;

/**
 * @struct
 *
 * The HEADERS frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The length of the padding in this frame.  This includes PAD_HIGH
   * and PAD_LOW.
   */
  size_t padlen;
  /**
   * The priority specification
   */
  nghttp2_priority_spec pri_spec;
  /**
   * The name/value pairs.
   */
  nghttp2_nv *nva;
  /**
   * The number of name/value pairs in |nva|.
   */
  size_t nvlen;
  /**
   * The category of this HEADERS frame.
   */
  nghttp2_headers_category cat;
} nghttp2_headers;

/**
 * @struct
 *
 * The PRIORITY frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The priority specification.
   */
  nghttp2_priority_spec pri_spec;
} nghttp2_priority;

/**
 * @struct
 *
 * The RST_STREAM frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The error code.  See :type:`nghttp2_error_code`.
   */
  uint32_t error_code;
} nghttp2_rst_stream;

/**
 * @struct
 *
 * The SETTINGS ID/Value pair.  It has the following members:
 */
typedef struct {
  /**
   * The SETTINGS ID.  See :type:`nghttp2_settings_id`.
   */
  int32_t settings_id;
  /**
   * The value of this entry.
   */
  uint32_t value;
} nghttp2_settings_entry;

/**
 * @struct
 *
 * The SETTINGS frame.  It has the following members:
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
 *
 * The PUSH_PROMISE frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The length of the padding in this frame.  This includes PAD_HIGH
   * and PAD_LOW.
   */
  size_t padlen;
  /**
   * The name/value pairs.
   */
  nghttp2_nv *nva;
  /**
   * The number of name/value pairs in |nva|.
   */
  size_t nvlen;
  /**
   * The promised stream ID
   */
  int32_t promised_stream_id;
  /**
   * Reserved bit.  Currently this is always set to 0 and application
   * should not expect something useful in here.
   */
  uint8_t reserved;
} nghttp2_push_promise;

/**
 * @struct
 *
 * The PING frame.  It has the following members:
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
 *
 * The GOAWAY frame.  It has the following members:
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
   * The error code.  See :type:`nghttp2_error_code`.
   */
  uint32_t error_code;
  /**
   * The additional debug data
   */
  uint8_t *opaque_data;
  /**
   * The length of |opaque_data| member.
   */
  size_t opaque_data_len;
  /**
   * Reserved bit.  Currently this is always set to 0 and application
   * should not expect something useful in here.
   */
  uint8_t reserved;
} nghttp2_goaway;

/**
 * @struct
 *
 * The WINDOW_UPDATE frame.  It has the following members:
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
  /**
   * Reserved bit.  Currently this is always set to 0 and application
   * should not expect something useful in here.
   */
  uint8_t reserved;
} nghttp2_window_update;

/**
 * @struct
 *
 * The extension frame.  It has following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The pointer to extension payload.  The exact pointer type is
   * determined by hd.type.
   *
   * Currently, no extension is supported.  This is a place holder for
   * the future extensions.
   */
  void *payload;
} nghttp2_extension;

/**
 * @union
 *
 * This union includes all frames to pass them to various function
 * calls as nghttp2_frame type.  The CONTINUATION frame is omitted
 * from here because the library deals with it internally.
 */
typedef union {
  /**
   * The frame header, which is convenient to inspect frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The DATA frame.
   */
  nghttp2_data data;
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
  /**
   * The extension frame.
   */
  nghttp2_extension ext;
} nghttp2_frame;

/**
 * @functypedef
 *
 * Callback function invoked when |session| wants to send data to the
 * remote peer.  The implementation of this function must send at most
 * |length| bytes of data stored in |data|.  The |flags| is currently
 * not used and always 0. It must return the number of bytes sent if
 * it succeeds.  If it cannot send any single byte without blocking,
 * it must return :enum:`NGHTTP2_ERR_WOULDBLOCK`.  For other errors,
 * it must return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.  The
 * |user_data| pointer is the third argument passed in to the call to
 * `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
 *
 * This callback is required if the application uses
 * `nghttp2_session_send()` to send data to the remote endpoint.  If
 * the application uses solely `nghttp2_session_mem_send()` instead,
 * this callback function is unnecessary.
 *
 * To set this callback to :type:`nghttp2_session_callbacks`, use
 * `nghttp2_session_callbacks_set_send_callback()`.
 *
 * .. note::
 *
 *   The |length| may be very small.  If that is the case, and
 *   application disables Nagle algorithm (``TCP_NODELAY``), then just
 *   writing |data| to the network stack leads to very small packet,
 *   and it is very inefficient.  An application should be responsible
 *   to buffer up small chunks of data as necessary to avoid this
 *   situation.
 */
typedef ssize_t (*nghttp2_send_callback)(nghttp2_session *session,
                                         const uint8_t *data, size_t length,
                                         int flags, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when :enum:`NGHTTP2_DATA_FLAG_NO_COPY` is
 * used in :type:`nghttp2_data_source_read_callback` to send complete
 * DATA frame.
 *
 * The |frame| is a DATA frame to send.  The |framehd| is the
 * serialized frame header (9 bytes). The |length| is the length of
 * application data to send (this does not include padding).  The
 * |source| is the same pointer passed to
 * :type:`nghttp2_data_source_read_callback`.
 *
 * The application first must send frame header |framehd| of length 9
 * bytes.  If ``frame->padlen > 0``, send 1 byte of value
 * ``frame->padlen - 1``.  Then send exactly |length| bytes of
 * application data.  Finally, if ``frame->padlen > 0``, send
 * ``frame->padlen - 1`` bytes of zero (they are padding).
 *
 * The application has to send complete DATA frame in this callback.
 * If all data were written successfully, return 0.
 *
 * If it cannot send it all, just return
 * :enum:`NGHTTP2_ERR_WOULDBLOCK`; the library will call this callback
 * with the same parameters later (It is recommended to send complete
 * DATA frame at once in this function to deal with error; if partial
 * frame data has already sent, it is impossible to send another data
 * in that state, and all we can do is tear down connection).  If
 * application decided to reset this stream, return
 * :enum:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`, then the library
 * will send RST_STREAM with INTERNAL_ERROR as error code.  The
 * application can also return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`,
 * which will result in connection closure.  Returning any other value
 * is treated as :enum:`NGHTTP2_ERR_CALLBACK_FAILURE` is returned.
 */
typedef int (*nghttp2_send_data_callback)(nghttp2_session *session,
                                          nghttp2_frame *frame,
                                          const uint8_t *framehd, size_t length,
                                          nghttp2_data_source *source,
                                          void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when |session| wants to receive data from
 * the remote peer.  The implementation of this function must read at
 * most |length| bytes of data and store it in |buf|.  The |flags| is
 * currently not used and always 0.  It must return the number of
 * bytes written in |buf| if it succeeds.  If it cannot read any
 * single byte without blocking, it must return
 * :enum:`NGHTTP2_ERR_WOULDBLOCK`.  If it gets EOF before it reads any
 * single byte, it must return :enum:`NGHTTP2_ERR_EOF`.  For other
 * errors, it must return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 * Returning 0 is treated as :enum:`NGHTTP2_ERR_WOULDBLOCK`.  The
 * |user_data| pointer is the third argument passed in to the call to
 * `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
 *
 * This callback is required if the application uses
 * `nghttp2_session_recv()` to receive data from the remote endpoint.
 * If the application uses solely `nghttp2_session_mem_recv()`
 * instead, this callback function is unnecessary.
 *
 * To set this callback to :type:`nghttp2_session_callbacks`, use
 * `nghttp2_session_callbacks_set_recv_callback()`.
 */
typedef ssize_t (*nghttp2_recv_callback)(nghttp2_session *session, uint8_t *buf,
                                         size_t length, int flags,
                                         void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked by `nghttp2_session_recv()` and
 * `nghttp2_session_mem_recv()` when a frame is received.  The
 * |user_data| pointer is the third argument passed in to the call to
 * `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
 *
 * If frame is HEADERS or PUSH_PROMISE, the ``nva`` and ``nvlen``
 * member of their data structure are always ``NULL`` and 0
 * respectively.  The header name/value pairs are emitted via
 * :type:`nghttp2_on_header_callback`.
 *
 * For HEADERS, PUSH_PROMISE and DATA frames, this callback may be
 * called after stream is closed (see
 * :type:`nghttp2_on_stream_close_callback`).  The application should
 * check that stream is still alive using its own stream management or
 * :func:`nghttp2_session_get_stream_user_data()`.
 *
 * Only HEADERS and DATA frame can signal the end of incoming data.
 * If ``frame->hd.flags & NGHTTP2_FLAG_END_STREAM`` is nonzero, the
 * |frame| is the last frame from the remote peer in this stream.
 *
 * This callback won't be called for CONTINUATION frames.
 * HEADERS/PUSH_PROMISE + CONTINUATIONs are treated as single frame.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero value is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_mem_recv()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 *
 * To set this callback to :type:`nghttp2_session_callbacks`, use
 * `nghttp2_session_callbacks_set_on_frame_recv_callback()`.
 */
typedef int (*nghttp2_on_frame_recv_callback)(nghttp2_session *session,
                                              const nghttp2_frame *frame,
                                              void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked by `nghttp2_session_recv()` and
 * `nghttp2_session_mem_recv()` when an invalid non-DATA frame is
 * received.  The error is indicated by the |lib_error_code|, which is
 * one of the values defined in :type:`nghttp2_error`.  When this
 * callback function is invoked, the library automatically submits
 * either RST_STREAM or GOAWAY frame.  The |user_data| pointer is the
 * third argument passed in to the call to
 * `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
 *
 * If frame is HEADERS or PUSH_PROMISE, the ``nva`` and ``nvlen``
 * member of their data structure are always ``NULL`` and 0
 * respectively.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_mem_recv()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 *
 * To set this callback to :type:`nghttp2_session_callbacks`, use
 * `nghttp2_session_callbacks_set_on_invalid_frame_recv_callback()`.
 */
typedef int (*nghttp2_on_invalid_frame_recv_callback)(
    nghttp2_session *session, const nghttp2_frame *frame, int lib_error_code,
    void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when a chunk of data in DATA frame is
 * received.  The |stream_id| is the stream ID this DATA frame belongs
 * to.  The |flags| is the flags of DATA frame which this data chunk
 * is contained.  ``(flags & NGHTTP2_FLAG_END_STREAM) != 0`` does not
 * necessarily mean this chunk of data is the last one in the stream.
 * You should use :type:`nghttp2_on_frame_recv_callback` to know all
 * data frames are received.  The |user_data| pointer is the third
 * argument passed in to the call to `nghttp2_session_client_new()` or
 * `nghttp2_session_server_new()`.
 *
 * If the application uses `nghttp2_session_mem_recv()`, it can return
 * :enum:`NGHTTP2_ERR_PAUSE` to make `nghttp2_session_mem_recv()`
 * return without processing further input bytes.  The memory by
 * pointed by the |data| is retained until
 * `nghttp2_session_mem_recv()` or `nghttp2_session_recv()` is called.
 * The application must retain the input bytes which was used to
 * produce the |data| parameter, because it may refer to the memory
 * region included in the input bytes.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero is returned, it is treated as fatal error, and
 * `nghttp2_session_recv()` and `nghttp2_session_mem_recv()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 *
 * To set this callback to :type:`nghttp2_session_callbacks`, use
 * `nghttp2_session_callbacks_set_on_data_chunk_recv_callback()`.
 */
typedef int (*nghttp2_on_data_chunk_recv_callback)(nghttp2_session *session,
                                                   uint8_t flags,
                                                   int32_t stream_id,
                                                   const uint8_t *data,
                                                   size_t len, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked just before the non-DATA frame |frame| is
 * sent.  The |user_data| pointer is the third argument passed in to
 * the call to `nghttp2_session_client_new()` or
 * `nghttp2_session_server_new()`.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_send()` and `nghttp2_session_mem_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 *
 * To set this callback to :type:`nghttp2_session_callbacks`, use
 * `nghttp2_session_callbacks_set_before_frame_send_callback()`.
 */
typedef int (*nghttp2_before_frame_send_callback)(nghttp2_session *session,
                                                  const nghttp2_frame *frame,
                                                  void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked after the frame |frame| is sent.  The
 * |user_data| pointer is the third argument passed in to the call to
 * `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_send()` and `nghttp2_session_mem_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 *
 * To set this callback to :type:`nghttp2_session_callbacks`, use
 * `nghttp2_session_callbacks_set_on_frame_send_callback()`.
 */
typedef int (*nghttp2_on_frame_send_callback)(nghttp2_session *session,
                                              const nghttp2_frame *frame,
                                              void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked after the non-DATA frame |frame| is not
 * sent because of the error.  The error is indicated by the
 * |lib_error_code|, which is one of the values defined in
 * :type:`nghttp2_error`.  The |user_data| pointer is the third
 * argument passed in to the call to `nghttp2_session_client_new()` or
 * `nghttp2_session_server_new()`.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_send()` and `nghttp2_session_mem_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 *
 * `nghttp2_session_get_stream_user_data()` can be used to get
 * associated data.
 *
 * To set this callback to :type:`nghttp2_session_callbacks`, use
 * `nghttp2_session_callbacks_set_on_frame_not_send_callback()`.
 */
typedef int (*nghttp2_on_frame_not_send_callback)(nghttp2_session *session,
                                                  const nghttp2_frame *frame,
                                                  int lib_error_code,
                                                  void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when the stream |stream_id| is closed.
 * The reason of closure is indicated by the |error_code|.  The
 * |error_code| is usually one of :enum:`nghttp2_error_code`, but that
 * is not guaranteed.  The stream_user_data, which was specified in
 * `nghttp2_submit_request()` or `nghttp2_submit_headers()`, is still
 * available in this function.  The |user_data| pointer is the third
 * argument passed in to the call to `nghttp2_session_client_new()` or
 * `nghttp2_session_server_new()`.
 *
 * This function is also called for a stream in reserved state.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()`, `nghttp2_session_mem_recv()`,
 * `nghttp2_session_send()`, and `nghttp2_session_mem_send()`
 * functions immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 *
 * To set this callback to :type:`nghttp2_session_callbacks`, use
 * `nghttp2_session_callbacks_set_on_stream_close_callback()`.
 */
typedef int (*nghttp2_on_stream_close_callback)(nghttp2_session *session,
                                                int32_t stream_id,
                                                uint32_t error_code,
                                                void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when the reception of header block in
 * HEADERS or PUSH_PROMISE is started.  Each header name/value pair
 * will be emitted by :type:`nghttp2_on_header_callback`.
 *
 * The ``frame->hd.flags`` may not have
 * :enum:`NGHTTP2_FLAG_END_HEADERS` flag set, which indicates that one
 * or more CONTINUATION frames are involved.  But the application does
 * not need to care about that because the header name/value pairs are
 * emitted transparently regardless of CONTINUATION frames.
 *
 * The server applications probably create an object to store
 * information about new stream if ``frame->hd.type ==
 * NGHTTP2_HEADERS`` and ``frame->headers.cat ==
 * NGHTTP2_HCAT_REQUEST``.  If |session| is configured as server side,
 * ``frame->headers.cat`` is either ``NGHTTP2_HCAT_REQUEST``
 * containing request headers or ``NGHTTP2_HCAT_HEADERS`` containing
 * trailer headers and never get PUSH_PROMISE in this callback.
 *
 * For the client applications, ``frame->hd.type`` is either
 * ``NGHTTP2_HEADERS`` or ``NGHTTP2_PUSH_PROMISE``.  In case of
 * ``NGHTTP2_HEADERS``, ``frame->headers.cat ==
 * NGHTTP2_HCAT_RESPONSE`` means that it is the first response
 * headers, but it may be non-final response which is indicated by 1xx
 * status code.  In this case, there may be zero or more HEADERS frame
 * with ``frame->headers.cat == NGHTTP2_HCAT_HEADERS`` which has
 * non-final response code and finally client gets exactly one HEADERS
 * frame with ``frame->headers.cat == NGHTTP2_HCAT_HEADERS``
 * containing final response headers (non-1xx status code).  The
 * trailer headers also has ``frame->headers.cat ==
 * NGHTTP2_HCAT_HEADERS`` which does not contain any status code.
 *
 * Returning :enum:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE` will close
 * the stream (promised stream if frame is PUSH_PROMISE) by issuing
 * RST_STREAM with :enum:`NGHTTP2_INTERNAL_ERROR`.  In this case,
 * :type:`nghttp2_on_header_callback` and
 * :type:`nghttp2_on_frame_recv_callback` will not be invoked.  If a
 * different error code is desirable, use
 * `nghttp2_submit_rst_stream()` with a desired error code and then
 * return :enum:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.  Again, use
 * ``frame->push_promise.promised_stream_id`` as stream_id parameter
 * in `nghttp2_submit_rst_stream()` if frame is PUSH_PROMISE.
 *
 * The implementation of this function must return 0 if it succeeds.
 * It can return :enum:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE` to
 * reset the stream (promised stream if frame is PUSH_PROMISE).  For
 * critical errors, it must return
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.  If the other value is
 * returned, it is treated as if :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`
 * is returned.  If :enum:`NGHTTP2_ERR_CALLBACK_FAILURE` is returned,
 * `nghttp2_session_mem_recv()` function will immediately return
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 *
 * To set this callback to :type:`nghttp2_session_callbacks`, use
 * `nghttp2_session_callbacks_set_on_begin_headers_callback()`.
 */
typedef int (*nghttp2_on_begin_headers_callback)(nghttp2_session *session,
                                                 const nghttp2_frame *frame,
                                                 void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when a header name/value pair is received
 * for the |frame|.  The |name| of length |namelen| is header name.
 * The |value| of length |valuelen| is header value.  The |flags| is
 * bitwise OR of one or more of :type:`nghttp2_nv_flag`.
 *
 * If :enum:`NGHTTP2_NV_FLAG_NO_INDEX` is set in |flags|, the receiver
 * must not index this name/value pair when forwarding it to the next
 * hop.  More specifically, "Literal Header Field never Indexed"
 * representation must be used in HPACK encoding.
 *
 * When this callback is invoked, ``frame->hd.type`` is either
 * :enum:`NGHTTP2_HEADERS` or :enum:`NGHTTP2_PUSH_PROMISE`.  After all
 * header name/value pairs are processed with this callback, and no
 * error has been detected, :type:`nghttp2_on_frame_recv_callback`
 * will be invoked.  If there is an error in decompression,
 * :type:`nghttp2_on_frame_recv_callback` for the |frame| will not be
 * invoked.
 *
 * Both |name| and |value| are guaranteed to be NULL-terminated.  The
 * |namelen| and |valuelen| do not include terminal NULL.  If
 * `nghttp2_option_set_no_http_messaging()` is used with nonzero
 * value, NULL character may be included in |name| or |value| before
 * terminating NULL.
 *
 * Please note that unless `nghttp2_option_set_no_http_messaging()` is
 * used, nghttp2 library does perform validation against the |name|
 * and the |value| using `nghttp2_check_header_name()` and
 * `nghttp2_check_header_value()`.  In addition to this, nghttp2
 * performs validation based on HTTP Messaging rule, which is briefly
 * explained in :ref:`http-messaging` section.
 *
 * If the application uses `nghttp2_session_mem_recv()`, it can return
 * :enum:`NGHTTP2_ERR_PAUSE` to make `nghttp2_session_mem_recv()`
 * return without processing further input bytes.  The memory pointed
 * by |frame|, |name| and |value| parameters are retained until
 * `nghttp2_session_mem_recv()` or `nghttp2_session_recv()` is called.
 * The application must retain the input bytes which was used to
 * produce these parameters, because it may refer to the memory region
 * included in the input bytes.
 *
 * Returning :enum:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE` will close
 * the stream (promised stream if frame is PUSH_PROMISE) by issuing
 * RST_STREAM with :enum:`NGHTTP2_INTERNAL_ERROR`.  In this case,
 * :type:`nghttp2_on_header_callback` and
 * :type:`nghttp2_on_frame_recv_callback` will not be invoked.  If a
 * different error code is desirable, use
 * `nghttp2_submit_rst_stream()` with a desired error code and then
 * return :enum:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.  Again, use
 * ``frame->push_promise.promised_stream_id`` as stream_id parameter
 * in `nghttp2_submit_rst_stream()` if frame is PUSH_PROMISE.
 *
 * The implementation of this function must return 0 if it succeeds.
 * It may return :enum:`NGHTTP2_ERR_PAUSE` or
 * :enum:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.  For other critical
 * failures, it must return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.  If
 * the other nonzero value is returned, it is treated as
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.  If
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE` is returned,
 * `nghttp2_session_recv()` and `nghttp2_session_mem_recv()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 *
 * To set this callback to :type:`nghttp2_session_callbacks`, use
 * `nghttp2_session_callbacks_set_on_header_callback()`.
 */
typedef int (*nghttp2_on_header_callback)(nghttp2_session *session,
                                          const nghttp2_frame *frame,
                                          const uint8_t *name, size_t namelen,
                                          const uint8_t *value, size_t valuelen,
                                          uint8_t flags, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when the library asks application how
 * many padding bytes are required for the transmission of the
 * |frame|.  The application must choose the total length of payload
 * including padded bytes in range [frame->hd.length, max_payloadlen],
 * inclusive.  Choosing number not in this range will be treated as
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.  Returning
 * ``frame->hd.length`` means no padding is added.  Returning
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE` will make
 * `nghttp2_session_send()` and `nghttp2_session_mem_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 *
 * To set this callback to :type:`nghttp2_session_callbacks`, use
 * `nghttp2_session_callbacks_set_select_padding_callback()`.
 */
typedef ssize_t (*nghttp2_select_padding_callback)(nghttp2_session *session,
                                                   const nghttp2_frame *frame,
                                                   size_t max_payloadlen,
                                                   void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when library wants to get max length of
 * data to send data to the remote peer.  The implementation of this
 * function should return a value in the following range.  [1,
 * min(|session_remote_window_size|, |stream_remote_window_size|,
 * |remote_max_frame_size|)].  If a value greater than this range is
 * returned than the max allow value will be used.  Returning a value
 * smaller than this range is treated as
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.  The |frame_type| is provided
 * for future extensibility and identifies the type of frame (see
 * :type:`nghttp2_frame_type`) for which to get the length for.
 * Currently supported frame types are: :enum:`NGHTTP2_DATA`.
 *
 * This callback can be used to control the length in bytes for which
 * :type:`nghttp2_data_source_read_callback` is allowed to send to the
 * remote endpoint.  This callback is optional.  Returning
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE` will signal the entire session
 * failure.
 *
 * To set this callback to :type:`nghttp2_session_callbacks`, use
 * `nghttp2_session_callbacks_set_data_source_read_length_callback()`.
 */
typedef ssize_t (*nghttp2_data_source_read_length_callback)(
    nghttp2_session *session, uint8_t frame_type, int32_t stream_id,
    int32_t session_remote_window_size, int32_t stream_remote_window_size,
    uint32_t remote_max_frame_size, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when a frame header is received.  The
 * |hd| points to received frame header.
 *
 * Unlike :type:`nghttp2_on_frame_recv_callback`, this callback will
 * also be called when frame header of CONTINUATION frame is received.
 *
 * If both :type:`nghttp2_on_begin_frame_callback` and
 * :type:`nghttp2_on_begin_headers_callback` are set and HEADERS or
 * PUSH_PROMISE is received, :type:`nghttp2_on_begin_frame_callback`
 * will be called first.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero value is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_mem_recv()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 *
 * To set this callback to :type:`nghttp2_session_callbacks`, use
 * `nghttp2_session_callbacks_set_on_begin_frame_callback()`.
 */
typedef int (*nghttp2_on_begin_frame_callback)(nghttp2_session *session,
                                               const nghttp2_frame_hd *hd,
                                               void *user_data);

struct nghttp2_session_callbacks;

/**
 * @struct
 *
 * Callback functions for :type:`nghttp2_session`.  The details of
 * this structure are intentionally hidden from the public API.
 */
typedef struct nghttp2_session_callbacks nghttp2_session_callbacks;

/**
 * @function
 *
 * Initializes |*callbacks_ptr| with NULL values.
 *
 * The initialized object can be used when initializing multiple
 * :type:`nghttp2_session` objects.
 *
 * When the application finished using this object, it can use
 * `nghttp2_session_callbacks_del()` to free its memory.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int
nghttp2_session_callbacks_new(nghttp2_session_callbacks **callbacks_ptr);

/**
 * @function
 *
 * Frees any resources allocated for |callbacks|.  If |callbacks| is
 * ``NULL``, this function does nothing.
 */
NGHTTP2_EXTERN void
nghttp2_session_callbacks_del(nghttp2_session_callbacks *callbacks);

/**
 * @function
 *
 * Sets callback function invoked when a session wants to send data to
 * the remote peer.  This callback is not necessary if the application
 * uses solely `nghttp2_session_mem_send()` to serialize data to
 * transmit.
 */
NGHTTP2_EXTERN void nghttp2_session_callbacks_set_send_callback(
    nghttp2_session_callbacks *cbs, nghttp2_send_callback send_callback);

/**
 * @function
 *
 * Sets callback function invoked when the a session wants to receive
 * data from the remote peer.  This callback is not necessary if the
 * application uses solely `nghttp2_session_mem_recv()` to process
 * received data.
 */
NGHTTP2_EXTERN void nghttp2_session_callbacks_set_recv_callback(
    nghttp2_session_callbacks *cbs, nghttp2_recv_callback recv_callback);

/**
 * @function
 *
 * Sets callback function invoked by `nghttp2_session_recv()` and
 * `nghttp2_session_mem_recv()` when a frame is received.
 */
NGHTTP2_EXTERN void nghttp2_session_callbacks_set_on_frame_recv_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_frame_recv_callback on_frame_recv_callback);

/**
 * @function
 *
 * Sets callback function invoked by `nghttp2_session_recv()` and
 * `nghttp2_session_mem_recv()` when an invalid non-DATA frame is
 * received.
 */
NGHTTP2_EXTERN void
nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_invalid_frame_recv_callback on_invalid_frame_recv_callback);

/**
 * @function
 *
 * Sets callback function invoked when a chunk of data in DATA frame
 * is received.
 */
NGHTTP2_EXTERN void nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_data_chunk_recv_callback on_data_chunk_recv_callback);

/**
 * @function
 *
 * Sets callback function invoked before a non-DATA frame is sent.
 */
NGHTTP2_EXTERN void nghttp2_session_callbacks_set_before_frame_send_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_before_frame_send_callback before_frame_send_callback);

/**
 * @function
 *
 * Sets callback function invoked after a frame is sent.
 */
NGHTTP2_EXTERN void nghttp2_session_callbacks_set_on_frame_send_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_frame_send_callback on_frame_send_callback);

/**
 * @function
 *
 * Sets callback function invoked when a non-DATA frame is not sent
 * because of an error.
 */
NGHTTP2_EXTERN void nghttp2_session_callbacks_set_on_frame_not_send_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_frame_not_send_callback on_frame_not_send_callback);

/**
 * @function
 *
 * Sets callback function invoked when the stream is closed.
 */
NGHTTP2_EXTERN void nghttp2_session_callbacks_set_on_stream_close_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_stream_close_callback on_stream_close_callback);

/**
 * @function
 *
 * Sets callback function invoked when the reception of header block
 * in HEADERS or PUSH_PROMISE is started.
 */
NGHTTP2_EXTERN void nghttp2_session_callbacks_set_on_begin_headers_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_begin_headers_callback on_begin_headers_callback);

/**
 * @function
 *
 * Sets callback function invoked when a header name/value pair is
 * received.
 */
NGHTTP2_EXTERN void nghttp2_session_callbacks_set_on_header_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_header_callback on_header_callback);

/**
 * @function
 *
 * Sets callback function invoked when the library asks application
 * how many padding bytes are required for the transmission of the
 * given frame.
 */
NGHTTP2_EXTERN void nghttp2_session_callbacks_set_select_padding_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_select_padding_callback select_padding_callback);

/**
 * @function
 *
 * Sets callback function determine the length allowed in
 * :type:`nghttp2_data_source_read_callback`.
 */
NGHTTP2_EXTERN void
nghttp2_session_callbacks_set_data_source_read_length_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_data_source_read_length_callback data_source_read_length_callback);

/**
 * @function
 *
 * Sets callback function invoked when a frame header is received.
 */
NGHTTP2_EXTERN void nghttp2_session_callbacks_set_on_begin_frame_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_begin_frame_callback on_begin_frame_callback);

/**
 * @function
 *
 * Sets callback function invoked when
 * :enum:`NGHTTP2_DATA_FLAG_NO_COPY` is used in
 * :type:`nghttp2_data_source_read_callback` to avoid data copy.
 */
NGHTTP2_EXTERN void nghttp2_session_callbacks_set_send_data_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_send_data_callback send_data_callback);

/**
 * @functypedef
 *
 * Custom memory allocator to replace malloc().  The |mem_user_data|
 * is the mem_user_data member of :type:`nghttp2_mem` structure.
 */
typedef void *(*nghttp2_malloc)(size_t size, void *mem_user_data);

/**
 * @functypedef
 *
 * Custom memory allocator to replace free().  The |mem_user_data| is
 * the mem_user_data member of :type:`nghttp2_mem` structure.
 */
typedef void (*nghttp2_free)(void *ptr, void *mem_user_data);

/**
 * @functypedef
 *
 * Custom memory allocator to replace calloc().  The |mem_user_data|
 * is the mem_user_data member of :type:`nghttp2_mem` structure.
 */
typedef void *(*nghttp2_calloc)(size_t nmemb, size_t size, void *mem_user_data);

/**
 * @functypedef
 *
 * Custom memory allocator to replace realloc().  The |mem_user_data|
 * is the mem_user_data member of :type:`nghttp2_mem` structure.
 */
typedef void *(*nghttp2_realloc)(void *ptr, size_t size, void *mem_user_data);

/**
 * @struct
 *
 * Custom memory allocator functions and user defined pointer.  The
 * |mem_user_data| member is passed to each allocator function.  This
 * can be used, for example, to achieve per-session memory pool.
 *
 * In the following example code, ``my_malloc``, ``my_free``,
 * ``my_calloc`` and ``my_realloc`` are the replacement of the
 * standard allocators ``malloc``, ``free``, ``calloc`` and
 * ``realloc`` respectively::
 *
 *     void *my_malloc_cb(size_t size, void *mem_user_data) {
 *       return my_malloc(size);
 *     }
 *
 *     void my_free_cb(void *ptr, void *mem_user_data) { my_free(ptr); }
 *
 *     void *my_calloc_cb(size_t nmemb, size_t size, void *mem_user_data) {
 *       return my_calloc(nmemb, size);
 *     }
 *
 *     void *my_realloc_cb(void *ptr, size_t size, void *mem_user_data) {
 *       return my_realloc(ptr, size);
 *     }
 *
 *     void session_new() {
 *       nghttp2_session *session;
 *       nghttp2_session_callbacks *callbacks;
 *       nghttp2_mem mem = {NULL, my_malloc_cb, my_free_cb, my_calloc_cb,
 *                          my_realloc_cb};
 *
 *       ...
 *
 *       nghttp2_session_client_new3(&session, callbacks, NULL, NULL, &mem);
 *
 *       ...
 *     }
 */
typedef struct {
  /**
   * An arbitrary user supplied data.  This is passed to each
   * allocator function.
   */
  void *mem_user_data;
  /**
   * Custom allocator function to replace malloc().
   */
  nghttp2_malloc malloc;
  /**
   * Custom allocator function to replace free().
   */
  nghttp2_free free;
  /**
   * Custom allocator function to replace calloc().
   */
  nghttp2_calloc calloc;
  /**
   * Custom allocator function to replace realloc().
   */
  nghttp2_realloc realloc;
} nghttp2_mem;

struct nghttp2_option;

/**
 * @struct
 *
 * Configuration options for :type:`nghttp2_session`.  The details of
 * this structure are intentionally hidden from the public API.
 */
typedef struct nghttp2_option nghttp2_option;

/**
 * @function
 *
 * Initializes |*option_ptr| with default values.
 *
 * When the application finished using this object, it can use
 * `nghttp2_option_del()` to free its memory.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_option_new(nghttp2_option **option_ptr);

/**
 * @function
 *
 * Frees any resources allocated for |option|.  If |option| is
 * ``NULL``, this function does nothing.
 */
NGHTTP2_EXTERN void nghttp2_option_del(nghttp2_option *option);

/**
 * @function
 *
 * This option prevents the library from sending WINDOW_UPDATE for a
 * connection automatically.  If this option is set to nonzero, the
 * library won't send WINDOW_UPDATE for DATA until application calls
 * `nghttp2_session_consume()` to indicate the consumed amount of
 * data.  Don't use `nghttp2_submit_window_update()` for this purpose.
 * By default, this option is set to zero.
 */
NGHTTP2_EXTERN void
nghttp2_option_set_no_auto_window_update(nghttp2_option *option, int val);

/**
 * @function
 *
 * This option sets the SETTINGS_MAX_CONCURRENT_STREAMS value of
 * remote endpoint as if it is received in SETTINGS frame.  Without
 * specifying this option, before the local endpoint receives
 * SETTINGS_MAX_CONCURRENT_STREAMS in SETTINGS frame from remote
 * endpoint, SETTINGS_MAX_CONCURRENT_STREAMS is unlimited.  This may
 * cause problem if local endpoint submits lots of requests initially
 * and sending them at once to the remote peer may lead to the
 * rejection of some requests.  Specifying this option to the sensible
 * value, say 100, may avoid this kind of issue. This value will be
 * overwritten if the local endpoint receives
 * SETTINGS_MAX_CONCURRENT_STREAMS from the remote endpoint.
 */
NGHTTP2_EXTERN void
nghttp2_option_set_peer_max_concurrent_streams(nghttp2_option *option,
                                               uint32_t val);

/**
 * @function
 *
 * By default, nghttp2 library, if configured as server, requires
 * first 24 bytes of client magic byte string (MAGIC).  In most cases,
 * this will simplify the implementation of server.  But sometimes
 * server may want to detect the application protocol based on first
 * few bytes on clear text communication.
 *
 * If this option is used with nonzero |val|, nghttp2 library does not
 * handle MAGIC.  It still checks following SETTINGS frame.  This
 * means that applications should deal with MAGIC by themselves.
 *
 * If this option is not used or used with zero value, if MAGIC does
 * not match :macro:`NGHTTP2_CLIENT_MAGIC`, `nghttp2_session_recv()`
 * and `nghttp2_session_mem_recv()` will return error
 * :enum:`NGHTTP2_ERR_BAD_CLIENT_MAGIC`, which is fatal error.
 */
NGHTTP2_EXTERN void
nghttp2_option_set_no_recv_client_magic(nghttp2_option *option, int val);

/**
 * @function
 *
 * By default, nghttp2 library enforces subset of HTTP Messaging rules
 * described in `HTTP/2 specification, section 8
 * <https://tools.ietf.org/html/rfc7540#section-8>`_.  See
 * :ref:`http-messaging` section for details.  For those applications
 * who use nghttp2 library as non-HTTP use, give nonzero to |val| to
 * disable this enforcement.
 */
NGHTTP2_EXTERN void nghttp2_option_set_no_http_messaging(nghttp2_option *option,
                                                         int val);

/**
 * @function
 *
 * Initializes |*session_ptr| for client use.  The all members of
 * |callbacks| are copied to |*session_ptr|.  Therefore |*session_ptr|
 * does not store |callbacks|.  The |user_data| is an arbitrary user
 * supplied data, which will be passed to the callback functions.
 *
 * The :type:`nghttp2_send_callback` must be specified.  If the
 * application code uses `nghttp2_session_recv()`, the
 * :type:`nghttp2_recv_callback` must be specified.  The other members
 * of |callbacks| can be ``NULL``.
 *
 * If this function fails, |*session_ptr| is left untouched.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int
nghttp2_session_client_new(nghttp2_session **session_ptr,
                           const nghttp2_session_callbacks *callbacks,
                           void *user_data);

/**
 * @function
 *
 * Initializes |*session_ptr| for server use.  The all members of
 * |callbacks| are copied to |*session_ptr|. Therefore |*session_ptr|
 * does not store |callbacks|.  The |user_data| is an arbitrary user
 * supplied data, which will be passed to the callback functions.
 *
 * The :type:`nghttp2_send_callback` must be specified.  If the
 * application code uses `nghttp2_session_recv()`, the
 * :type:`nghttp2_recv_callback` must be specified.  The other members
 * of |callbacks| can be ``NULL``.
 *
 * If this function fails, |*session_ptr| is left untouched.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int
nghttp2_session_server_new(nghttp2_session **session_ptr,
                           const nghttp2_session_callbacks *callbacks,
                           void *user_data);

/**
 * @function
 *
 * Like `nghttp2_session_client_new()`, but with additional options
 * specified in the |option|.
 *
 * The |option| can be ``NULL`` and the call is equivalent to
 * `nghttp2_session_client_new()`.
 *
 * This function does not take ownership |option|.  The application is
 * responsible for freeing |option| if it finishes using the object.
 *
 * The library code does not refer to |option| after this function
 * returns.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int
nghttp2_session_client_new2(nghttp2_session **session_ptr,
                            const nghttp2_session_callbacks *callbacks,
                            void *user_data, const nghttp2_option *option);

/**
 * @function
 *
 * Like `nghttp2_session_server_new()`, but with additional options
 * specified in the |option|.
 *
 * The |option| can be ``NULL`` and the call is equivalent to
 * `nghttp2_session_server_new()`.
 *
 * This function does not take ownership |option|.  The application is
 * responsible for freeing |option| if it finishes using the object.
 *
 * The library code does not refer to |option| after this function
 * returns.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int
nghttp2_session_server_new2(nghttp2_session **session_ptr,
                            const nghttp2_session_callbacks *callbacks,
                            void *user_data, const nghttp2_option *option);

/**
 * @function
 *
 * Like `nghttp2_session_client_new2()`, but with additional custom
 * memory allocator specified in the |mem|.
 *
 * The |mem| can be ``NULL`` and the call is equivalent to
 * `nghttp2_session_client_new2()`.
 *
 * This function does not take ownership |mem|.  The application is
 * responsible for freeing |mem|.
 *
 * The library code does not refer to |mem| pointer after this
 * function returns, so the application can safely free it.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_session_client_new3(
    nghttp2_session **session_ptr, const nghttp2_session_callbacks *callbacks,
    void *user_data, const nghttp2_option *option, nghttp2_mem *mem);

/**
 * @function
 *
 * Like `nghttp2_session_server_new2()`, but with additional custom
 * memory allocator specified in the |mem|.
 *
 * The |mem| can be ``NULL`` and the call is equivalent to
 * `nghttp2_session_server_new2()`.
 *
 * This function does not take ownership |mem|.  The application is
 * responsible for freeing |mem|.
 *
 * The library code does not refer to |mem| pointer after this
 * function returns, so the application can safely free it.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_session_server_new3(
    nghttp2_session **session_ptr, const nghttp2_session_callbacks *callbacks,
    void *user_data, const nghttp2_option *option, nghttp2_mem *mem);

/**
 * @function
 *
 * Frees any resources allocated for |session|.  If |session| is
 * ``NULL``, this function does nothing.
 */
NGHTTP2_EXTERN void nghttp2_session_del(nghttp2_session *session);

/**
 * @function
 *
 * Sends pending frames to the remote peer.
 *
 * This function retrieves the highest prioritized frame from the
 * outbound queue and sends it to the remote peer.  It does this as
 * many as possible until the user callback
 * :type:`nghttp2_send_callback` returns
 * :enum:`NGHTTP2_ERR_WOULDBLOCK` or the outbound queue becomes empty.
 * This function calls several callback functions which are passed
 * when initializing the |session|.  Here is the simple time chart
 * which tells when each callback is invoked:
 *
 * 1. Get the next frame to send from outbound queue.
 *
 * 2. Prepare transmission of the frame.
 *
 * 3. If the control frame cannot be sent because some preconditions
 *    are not met (e.g., request HEADERS cannot be sent after GOAWAY),
 *    :type:`nghttp2_on_frame_not_send_callback` is invoked.  Abort
 *    the following steps.
 *
 * 4. If the frame is HEADERS, PUSH_PROMISE or DATA,
 *    :type:`nghttp2_select_padding_callback` is invoked.
 *
 * 5. If the frame is request HEADERS, the stream is opened here.
 *
 * 6. :type:`nghttp2_before_frame_send_callback` is invoked.
 *
 * 7. :type:`nghttp2_send_callback` is invoked one or more times to
 *    send the frame.
 *
 * 8. :type:`nghttp2_on_frame_send_callback` is invoked.
 *
 * 9. If the transmission of the frame triggers closure of the stream,
 *    the stream is closed and
 *    :type:`nghttp2_on_stream_close_callback` is invoked.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`
 *     The callback function failed.
 */
NGHTTP2_EXTERN int nghttp2_session_send(nghttp2_session *session);

/**
 * @function
 *
 * Returns the serialized data to send.
 *
 * This function behaves like `nghttp2_session_send()` except that it
 * does not use :type:`nghttp2_send_callback` to transmit data.
 * Instead, it assigns the pointer to the serialized data to the
 * |*data_ptr| and returns its length.  The other callbacks are called
 * in the same way as they are in `nghttp2_session_send()`.
 *
 * If no data is available to send, this function returns 0.
 *
 * This function may not return all serialized data in one invocation.
 * To get all data, call this function repeatedly until it returns 0
 * or one of negative error codes.
 *
 * The assigned |*data_ptr| is valid until the next call of
 * `nghttp2_session_mem_send()` or `nghttp2_session_send()`.
 *
 * The caller must send all data before sending the next chunk of
 * data.
 *
 * This function returns the length of the data pointed by the
 * |*data_ptr| if it succeeds, or one of the following negative error
 * codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 *
 * .. note::
 *
 *   This function may produce very small byte string.  If that is the
 *   case, and application disables Nagle algorithm (``TCP_NODELAY``),
 *   then writing this small chunk leads to very small packet, and it
 *   is very inefficient.  An application should be responsible to
 *   buffer up small chunks of data as necessary to avoid this
 *   situation.
 */
NGHTTP2_EXTERN ssize_t nghttp2_session_mem_send(nghttp2_session *session,
                                                const uint8_t **data_ptr);

/**
 * @function
 *
 * Receives frames from the remote peer.
 *
 * This function receives as many frames as possible until the user
 * callback :type:`nghttp2_recv_callback` returns
 * :enum:`NGHTTP2_ERR_WOULDBLOCK`.  This function calls several
 * callback functions which are passed when initializing the
 * |session|.  Here is the simple time chart which tells when each
 * callback is invoked:
 *
 * 1. :type:`nghttp2_recv_callback` is invoked one or more times to
 *    receive frame header.
 *
 * 2. When frame header is received,
 *    :type:`nghttp2_on_begin_frame_callback` is invoked.
 *
 * 3. If the frame is DATA frame:
 *
 *    1. :type:`nghttp2_recv_callback` is invoked to receive DATA
 *       payload. For each chunk of data,
 *       :type:`nghttp2_on_data_chunk_recv_callback` is invoked.
 *
 *    2. If one DATA frame is completely received,
 *       :type:`nghttp2_on_frame_recv_callback` is invoked.  If the
 *       reception of the frame triggers the closure of the stream,
 *       :type:`nghttp2_on_stream_close_callback` is invoked.
 *
 * 4. If the frame is the control frame:
 *
 *    1. :type:`nghttp2_recv_callback` is invoked one or more times to
 *       receive whole frame.
 *
 *    2. If the received frame is valid, then following actions are
 *       taken.  If the frame is either HEADERS or PUSH_PROMISE,
 *       :type:`nghttp2_on_begin_headers_callback` is invoked.  Then
 *       :type:`nghttp2_on_header_callback` is invoked for each header
 *       name/value pair.  After all name/value pairs are emitted
 *       successfully, :type:`nghttp2_on_frame_recv_callback` is
 *       invoked.  For other frames,
 *       :type:`nghttp2_on_frame_recv_callback` is invoked.  If the
 *       reception of the frame triggers the closure of the stream,
 *       :type:`nghttp2_on_stream_close_callback` is invoked.
 *
 *    3. If the received frame is unpacked but is interpreted as
 *       invalid, :type:`nghttp2_on_invalid_frame_recv_callback` is
 *       invoked.
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
 * :enum:`NGHTTP2_ERR_BAD_CLIENT_MAGIC`
 *     Invalid client magic was detected.  This error only returns
 *     when |session| was configured as server and
 *     `nghttp2_option_set_no_recv_client_magic()` is not used with
 *     nonzero value.
 */
NGHTTP2_EXTERN int nghttp2_session_recv(nghttp2_session *session);

/**
 * @function
 *
 * Processes data |in| as an input from the remote endpoint.  The
 * |inlen| indicates the number of bytes in the |in|.
 *
 * This function behaves like `nghttp2_session_recv()` except that it
 * does not use :type:`nghttp2_recv_callback` to receive data; the
 * |in| is the only data for the invocation of this function.  If all
 * bytes are processed, this function returns.  The other callbacks
 * are called in the same way as they are in `nghttp2_session_recv()`.
 *
 * In the current implementation, this function always tries to
 * processes all input data unless either an error occurs or
 * :enum:`NGHTTP2_ERR_PAUSE` is returned from
 * :type:`nghttp2_on_header_callback` or
 * :type:`nghttp2_on_data_chunk_recv_callback`.  If
 * :enum:`NGHTTP2_ERR_PAUSE` is used, the return value includes the
 * number of bytes which was used to produce the data or frame for the
 * callback.
 *
 * This function returns the number of processed bytes, or one of the
 * following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`
 *     The callback function failed.
 * :enum:`NGHTTP2_ERR_BAD_CLIENT_MAGIC`
 *     Invalid client magic was detected.  This error only returns
 *     when |session| was configured as server and
 *     `nghttp2_option_set_no_recv_client_magic()` is not used with
 *     nonzero value.
 */
NGHTTP2_EXTERN ssize_t nghttp2_session_mem_recv(nghttp2_session *session,
                                                const uint8_t *in,
                                                size_t inlen);

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
 *     The stream does not exist; or no deferred data exist.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_session_resume_data(nghttp2_session *session,
                                               int32_t stream_id);

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
NGHTTP2_EXTERN int nghttp2_session_want_read(nghttp2_session *session);

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
NGHTTP2_EXTERN int nghttp2_session_want_write(nghttp2_session *session);

/**
 * @function
 *
 * Returns stream_user_data for the stream |stream_id|.  The
 * stream_user_data is provided by `nghttp2_submit_request()`,
 * `nghttp2_submit_headers()` or
 * `nghttp2_session_set_stream_user_data()`.  Unless it is set using
 * `nghttp2_session_set_stream_user_data()`, if the stream is
 * initiated by the remote endpoint, stream_user_data is always
 * ``NULL``.  If the stream does not exist, this function returns
 * ``NULL``.
 */
NGHTTP2_EXTERN void *
nghttp2_session_get_stream_user_data(nghttp2_session *session,
                                     int32_t stream_id);

/**
 * @function
 *
 * Sets the |stream_user_data| to the stream denoted by the
 * |stream_id|.  If a stream user data is already set to the stream,
 * it is replaced with the |stream_user_data|.  It is valid to specify
 * ``NULL`` in the |stream_user_data|, which nullifies the associated
 * data pointer.
 *
 * It is valid to set the |stream_user_data| to the stream reserved by
 * PUSH_PROMISE frame.
 *
 * This function returns 0 if it succeeds, or one of following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The stream does not exist
 */
NGHTTP2_EXTERN int
nghttp2_session_set_stream_user_data(nghttp2_session *session,
                                     int32_t stream_id, void *stream_user_data);

/**
 * @function
 *
 * Returns the number of frames in the outbound queue.  This does not
 * include the deferred DATA frames.
 */
NGHTTP2_EXTERN size_t
    nghttp2_session_get_outbound_queue_size(nghttp2_session *session);

/**
 * @function
 *
 * Returns the number of DATA payload in bytes received without
 * WINDOW_UPDATE transmission for the stream |stream_id|.  The local
 * (receive) window size can be adjusted by
 * `nghttp2_submit_window_update()`.  This function takes into account
 * that and returns effective data length.  In particular, if the
 * local window size is reduced by submitting negative
 * window_size_increment with `nghttp2_submit_window_update()`, this
 * function returns the number of bytes less than actually received.
 *
 * This function returns -1 if it fails.
 */
NGHTTP2_EXTERN int32_t nghttp2_session_get_stream_effective_recv_data_length(
    nghttp2_session *session, int32_t stream_id);

/**
 * @function
 *
 * Returns the local (receive) window size for the stream |stream_id|.
 * The local window size can be adjusted by
 * `nghttp2_submit_window_update()`.  This function takes into account
 * that and returns effective window size.
 *
 * This function returns -1 if it fails.
 */
NGHTTP2_EXTERN int32_t nghttp2_session_get_stream_effective_local_window_size(
    nghttp2_session *session, int32_t stream_id);

/**
 * @function
 *
 * Returns the number of DATA payload in bytes received without
 * WINDOW_UPDATE transmission for a connection.  The local (receive)
 * window size can be adjusted by `nghttp2_submit_window_update()`.
 * This function takes into account that and returns effective data
 * length.  In particular, if the local window size is reduced by
 * submitting negative window_size_increment with
 * `nghttp2_submit_window_update()`, this function returns the number
 * of bytes less than actually received.
 *
 * This function returns -1 if it fails.
 */
NGHTTP2_EXTERN int32_t
    nghttp2_session_get_effective_recv_data_length(nghttp2_session *session);

/**
 * @function
 *
 * Returns the local (receive) window size for a connection.  The
 * local window size can be adjusted by
 * `nghttp2_submit_window_update()`.  This function takes into account
 * that and returns effective window size.
 *
 * This function returns -1 if it fails.
 */
NGHTTP2_EXTERN int32_t
    nghttp2_session_get_effective_local_window_size(nghttp2_session *session);

/**
 * @function
 *
 * Returns the remote window size for a given stream |stream_id|.
 *
 * This is the amount of flow-controlled payload (e.g., DATA) that the
 * local endpoint can send without stream level WINDOW_UPDATE.  There
 * is also connection level flow control, so the effective size of
 * payload that the local endpoint can actually send is
 * min(`nghttp2_session_get_stream_remote_window_size()`,
 * `nghttp2_session_get_remote_window_size()`).
 *
 * This function returns -1 if it fails.
 */
NGHTTP2_EXTERN int32_t
    nghttp2_session_get_stream_remote_window_size(nghttp2_session *session,
                                                  int32_t stream_id);

/**
 * @function
 *
 * Returns the remote window size for a connection.
 *
 * This function always succeeds.
 */
NGHTTP2_EXTERN int32_t
    nghttp2_session_get_remote_window_size(nghttp2_session *session);

/**
 * @function
 *
 * Returns 1 if local peer half closed the given stream |stream_id|.
 * Returns 0 if it did not.  Returns -1 if no such stream exists.
 */
NGHTTP2_EXTERN int
nghttp2_session_get_stream_local_close(nghttp2_session *session,
                                       int32_t stream_id);

/**
 * @function
 *
 * Returns 1 if remote peer half closed the given stream |stream_id|.
 * Returns 0 if it did not.  Returns -1 if no such stream exists.
 */
NGHTTP2_EXTERN int
nghttp2_session_get_stream_remote_close(nghttp2_session *session,
                                        int32_t stream_id);

/**
 * @function
 *
 * Signals the session so that the connection should be terminated.
 *
 * The last stream ID is the minimum value between the stream ID of a
 * stream for which :type:`nghttp2_on_frame_recv_callback` was called
 * most recently and the last stream ID we have sent to the peer
 * previously.
 *
 * The |error_code| is the error code of this GOAWAY frame.  The
 * pre-defined error code is one of :enum:`nghttp2_error_code`.
 *
 * After the transmission, both `nghttp2_session_want_read()` and
 * `nghttp2_session_want_write()` return 0.
 *
 * This function should be called when the connection should be
 * terminated after sending GOAWAY.  If the remaining streams should
 * be processed after GOAWAY, use `nghttp2_submit_goaway()` instead.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_session_terminate_session(nghttp2_session *session,
                                                     uint32_t error_code);

/**
 * @function
 *
 * Signals the session so that the connection should be terminated.
 *
 * This function behaves like `nghttp2_session_terminate_session()`,
 * but the last stream ID can be specified by the application for fine
 * grained control of stream.  The HTTP/2 specification does not allow
 * last_stream_id to be increased.  So the actual value sent as
 * last_stream_id is the minimum value between the given
 * |last_stream_id| and the last_stream_id we have previously sent to
 * the peer.
 *
 * The |last_stream_id| is peer's stream ID or 0.  So if |session| is
 * initialized as client, |last_stream_id| must be even or 0.  If
 * |session| is initialized as server, |last_stream_id| must be odd or
 * 0.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |last_stream_id| is invalid.
 */
NGHTTP2_EXTERN int nghttp2_session_terminate_session2(nghttp2_session *session,
                                                      int32_t last_stream_id,
                                                      uint32_t error_code);

/**
 * @function
 *
 * Signals to the client that the server started graceful shutdown
 * procedure.
 *
 * This function is only usable for server.  If this function is
 * called with client side session, this function returns
 * :enum:`NGHTTP2_ERR_INVALID_STATE`.
 *
 * To gracefully shutdown HTTP/2 session, server should call this
 * function to send GOAWAY with last_stream_id (1u << 31) - 1.  And
 * after some delay (e.g., 1 RTT), send another GOAWAY with the stream
 * ID that the server has some processing using
 * `nghttp2_submit_goaway()`.  See also
 * `nghttp2_session_get_last_proc_stream_id()`.
 *
 * Unlike `nghttp2_submit_goaway()`, this function just sends GOAWAY
 * and does nothing more.  This is a mere indication to the client
 * that session shutdown is imminent.  The application should call
 * `nghttp2_submit_goaway()` with appropriate last_stream_id after
 * this call.
 *
 * If one or more GOAWAY frame have been already sent by either
 * `nghttp2_submit_goaway()` or `nghttp2_session_terminate_session()`,
 * this function has no effect.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_STATE`
 *     The |session| is initialized as client.
 */
NGHTTP2_EXTERN int nghttp2_submit_shutdown_notice(nghttp2_session *session);

/**
 * @function
 *
 * Returns the value of SETTINGS |id| notified by a remote endpoint.
 * The |id| must be one of values defined in
 * :enum:`nghttp2_settings_id`.
 */
NGHTTP2_EXTERN uint32_t
    nghttp2_session_get_remote_settings(nghttp2_session *session,
                                        nghttp2_settings_id id);

/**
 * @function
 *
 * Tells the |session| that next stream ID is |next_stream_id|.  The
 * |next_stream_id| must be equal or greater than the value returned
 * by `nghttp2_session_get_next_stream_id()`.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |next_stream_id| is strictly less than the value
 *     `nghttp2_session_get_next_stream_id()` returns; or
 *     |next_stream_id| is invalid (e.g., even integer for client, or
 *     odd integer for server).
 */
NGHTTP2_EXTERN int nghttp2_session_set_next_stream_id(nghttp2_session *session,
                                                      int32_t next_stream_id);

/**
 * @function
 *
 * Returns the next outgoing stream ID.  Notice that return type is
 * uint32_t.  If we run out of stream ID for this session, this
 * function returns 1 << 31.
 */
NGHTTP2_EXTERN uint32_t
    nghttp2_session_get_next_stream_id(nghttp2_session *session);

/**
 * @function
 *
 * Tells the |session| that |size| bytes for a stream denoted by
 * |stream_id| were consumed by application and are ready to
 * WINDOW_UPDATE.  The consumed bytes are counted towards both
 * connection and stream level WINDOW_UPDATE (see
 * `nghttp2_session_consume_connection()` and
 * `nghttp2_session_consume_stream()` to update consumption
 * independently).  This function is intended to be used without
 * automatic window update (see
 * `nghttp2_option_set_no_auto_window_update()`).
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |stream_id| is 0.
 * :enum:`NGHTTP2_ERR_INVALID_STATE`
 *     Automatic WINDOW_UPDATE is not disabled.
 */
NGHTTP2_EXTERN int nghttp2_session_consume(nghttp2_session *session,
                                           int32_t stream_id, size_t size);

/**
 * @function
 *
 * Like `nghttp2_session_consume()`, but this only tells library that
 * |size| bytes were consumed only for connection level.  Note that
 * HTTP/2 maintains connection and stream level flow control windows
 * independently.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_STATE`
 *     Automatic WINDOW_UPDATE is not disabled.
 */
NGHTTP2_EXTERN int nghttp2_session_consume_connection(nghttp2_session *session,
                                                      size_t size);

/**
 * @function
 *
 * Like `nghttp2_session_consume()`, but this only tells library that
 * |size| bytes were consumed only for stream denoted by |stream_id|.
 * Note that HTTP/2 maintains connection and stream level flow control
 * windows independently.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |stream_id| is 0.
 * :enum:`NGHTTP2_ERR_INVALID_STATE`
 *     Automatic WINDOW_UPDATE is not disabled.
 */
NGHTTP2_EXTERN int nghttp2_session_consume_stream(nghttp2_session *session,
                                                  int32_t stream_id,
                                                  size_t size);

/**
 * @function
 *
 * Performs post-process of HTTP Upgrade request.  This function can
 * be called from both client and server, but the behavior is very
 * different in each other.
 *
 * If called from client side, the |settings_payload| must be the
 * value sent in ``HTTP2-Settings`` header field and must be decoded
 * by base64url decoder.  The |settings_payloadlen| is the length of
 * |settings_payload|.  The |settings_payload| is unpacked and its
 * setting values will be submitted using `nghttp2_submit_settings()`.
 * This means that the client application code does not need to submit
 * SETTINGS by itself.  The stream with stream ID=1 is opened and the
 * |stream_user_data| is used for its stream_user_data.  The opened
 * stream becomes half-closed (local) state.
 *
 * If called from server side, the |settings_payload| must be the
 * value received in ``HTTP2-Settings`` header field and must be
 * decoded by base64url decoder.  The |settings_payloadlen| is the
 * length of |settings_payload|.  It is treated as if the SETTINGS
 * frame with that payload is received.  Thus, callback functions for
 * the reception of SETTINGS frame will be invoked.  The stream with
 * stream ID=1 is opened.  The |stream_user_data| is ignored.  The
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
 *     The stream ID 1 is already used or closed; or is not available.
 */
NGHTTP2_EXTERN int nghttp2_session_upgrade(nghttp2_session *session,
                                           const uint8_t *settings_payload,
                                           size_t settings_payloadlen,
                                           void *stream_user_data);

/**
 * @function
 *
 * Serializes the SETTINGS values |iv| in the |buf|.  The size of the
 * |buf| is specified by |buflen|.  The number of entries in the |iv|
 * array is given by |niv|.  The required space in |buf| for the |niv|
 * entries is ``8*niv`` bytes and if the given buffer is too small, an
 * error is returned.  This function is used mainly for creating a
 * SETTINGS payload to be sent with the ``HTTP2-Settings`` header
 * field in an HTTP Upgrade request.  The data written in |buf| is NOT
 * base64url encoded and the application is responsible for encoding.
 *
 * This function returns the number of bytes written in |buf|, or one
 * of the following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |iv| contains duplicate settings ID or invalid value.
 *
 * :enum:`NGHTTP2_ERR_INSUFF_BUFSIZE`
 *     The provided |buflen| size is too small to hold the output.
 */
NGHTTP2_EXTERN ssize_t
    nghttp2_pack_settings_payload(uint8_t *buf, size_t buflen,
                                  const nghttp2_settings_entry *iv, size_t niv);

/**
 * @function
 *
 * Returns string describing the |lib_error_code|.  The
 * |lib_error_code| must be one of the :enum:`nghttp2_error`.
 */
NGHTTP2_EXTERN const char *nghttp2_strerror(int lib_error_code);

/**
 * @function
 *
 * Initializes |pri_spec| with the |stream_id| of the stream to depend
 * on with |weight| and its exclusive flag.  If |exclusive| is
 * nonzero, exclusive flag is set.
 *
 * The |weight| must be in [:enum:`NGHTTP2_MIN_WEIGHT`,
 * :enum:`NGHTTP2_MAX_WEIGHT`], inclusive.
 */
NGHTTP2_EXTERN void nghttp2_priority_spec_init(nghttp2_priority_spec *pri_spec,
                                               int32_t stream_id,
                                               int32_t weight, int exclusive);

/**
 * @function
 *
 * Initializes |pri_spec| with the default values.  The default values
 * are: stream_id = 0, weight = :macro:`NGHTTP2_DEFAULT_WEIGHT` and
 * exclusive = 0.
 */
NGHTTP2_EXTERN void
nghttp2_priority_spec_default_init(nghttp2_priority_spec *pri_spec);

/**
 * @function
 *
 * Returns nonzero if the |pri_spec| is filled with default values.
 */
NGHTTP2_EXTERN int
nghttp2_priority_spec_check_default(const nghttp2_priority_spec *pri_spec);

/**
 * @function
 *
 * Submits HEADERS frame and optionally one or more DATA frames.
 *
 * The |pri_spec| is priority specification of this request.  ``NULL``
 * means the default priority (see
 * `nghttp2_priority_spec_default_init()`).  To specify the priority,
 * use `nghttp2_priority_spec_init()`.  If |pri_spec| is not ``NULL``,
 * this function will copy its data members.
 *
 * The ``pri_spec->weight`` must be in [:enum:`NGHTTP2_MIN_WEIGHT`,
 * :enum:`NGHTTP2_MAX_WEIGHT`], inclusive.  If ``pri_spec->weight`` is
 * strictly less than :enum:`NGHTTP2_MIN_WEIGHT`, it becomes
 * :enum:`NGHTTP2_MIN_WEIGHT`.  If it is strictly greater than
 * :enum:`NGHTTP2_MAX_WEIGHT`, it becomes :enum:`NGHTTP2_MAX_WEIGHT`.
 *
 * The |nva| is an array of name/value pair :type:`nghttp2_nv` with
 * |nvlen| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |nva| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.  The order of elements in
 * |nva| is preserved.
 *
 * HTTP/2 specification has requirement about header fields in the
 * request HEADERS.  See the specification for more details.
 *
 * If |data_prd| is not ``NULL``, it provides data which will be sent
 * in subsequent DATA frames.  In this case, a method that allows
 * request message bodies
 * (https://tools.ietf.org/html/rfc7231#section-4) must be specified
 * with ``:method`` key in |nva| (e.g. ``POST``).  This function does
 * not take ownership of the |data_prd|.  The function copies the
 * members of the |data_prd|.  If |data_prd| is ``NULL``, HEADERS have
 * END_STREAM set.  The |stream_user_data| is data associated to the
 * stream opened by this request and can be an arbitrary pointer,
 * which can be retrieved later by
 * `nghttp2_session_get_stream_user_data()`.
 *
 * This function returns assigned stream ID if it succeeds, or one of
 * the following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE`
 *     No stream ID is available because maximum stream ID was
 *     reached.
 *
 * .. warning::
 *
 *   This function returns assigned stream ID if it succeeds.  But
 *   that stream is not opened yet.  The application must not submit
 *   frame to that stream ID before
 *   :type:`nghttp2_before_frame_send_callback` is called for this
 *   frame.
 *
 */
NGHTTP2_EXTERN int32_t
    nghttp2_submit_request(nghttp2_session *session,
                           const nghttp2_priority_spec *pri_spec,
                           const nghttp2_nv *nva, size_t nvlen,
                           const nghttp2_data_provider *data_prd,
                           void *stream_user_data);

/**
 * @function
 *
 * Submits response HEADERS frame and optionally one or more DATA
 * frames against the stream |stream_id|.
 *
 * The |nva| is an array of name/value pair :type:`nghttp2_nv` with
 * |nvlen| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |nva| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.  The order of elements in
 * |nva| is preserved.
 *
 * HTTP/2 specification has requirement about header fields in the
 * response HEADERS.  See the specification for more details.
 *
 * If |data_prd| is not ``NULL``, it provides data which will be sent
 * in subsequent DATA frames.  This function does not take ownership
 * of the |data_prd|.  The function copies the members of the
 * |data_prd|.  If |data_prd| is ``NULL``, HEADERS will have
 * END_STREAM flag set.
 *
 * This method can be used as normal HTTP response and push response.
 * When pushing a resource using this function, the |session| must be
 * configured using `nghttp2_session_server_new()` or its variants and
 * the target stream denoted by the |stream_id| must be reserved using
 * `nghttp2_submit_push_promise()`.
 *
 * To send non-final response headers (e.g., HTTP status 101), don't
 * use this function because this function half-closes the outbound
 * stream.  Instead, use `nghttp2_submit_headers()` for this purpose.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |stream_id| is 0.
 * :enum:`NGHTTP2_ERR_DATA_EXIST`
 *     DATA or HEADERS has been already submitted and not fully
 *     processed yet.  Normally, this does not happen, but when
 *     application wrongly calls `nghttp2_submit_response()` twice,
 *     this may happen.
 *
 * .. warning::
 *
 *   Calling this function twice for the same stream ID may lead to
 *   program crash.  It is generally considered to a programming error
 *   to commit response twice.
 */
NGHTTP2_EXTERN int
nghttp2_submit_response(nghttp2_session *session, int32_t stream_id,
                        const nghttp2_nv *nva, size_t nvlen,
                        const nghttp2_data_provider *data_prd);

/**
 * @function
 *
 * Submits trailer HEADERS against the stream |stream_id|.
 *
 * The |nva| is an array of name/value pair :type:`nghttp2_nv` with
 * |nvlen| elements.  The application is responsible not to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |nva|.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.  The order of elements in
 * |nva| is preserved.
 *
 * For server, trailer must be followed by response HEADERS or
 * response DATA.  The library does not check that response HEADERS
 * has already sent and if `nghttp2_submit_trailer()` is called before
 * any response HEADERS submission (usually by
 * `nghttp2_submit_response()`), the content of |nva| will be sent as
 * reponse headers, which will result in error.
 *
 * This function has the same effect with `nghttp2_submit_headers()`,
 * with flags = :enum:`NGHTTP2_FLAG_END_HEADERS` and both pri_spec and
 * stream_user_data to NULL.
 *
 * To submit trailer after `nghttp2_submit_response()` is called, the
 * application has to specify :type:`nghttp2_data_provider` to
 * `nghttp2_submit_response()`.  In side
 * :type:`nghttp2_data_source_read_callback`, when setting
 * :enum:`NGHTTP2_DATA_FLAG_EOF`, also set
 * :enum:`NGHTTP2_DATA_FLAG_NO_END_STREAM`.  After that, the
 * application can send trailer using `nghttp2_submit_trailer()`.
 * `nghttp2_submit_trailer()` can be used inside
 * :type:`nghttp2_data_source_read_callback`.
 *
 * This function returns 0 if it succeeds and |stream_id| is -1.
 * Otherwise, this function returns 0 if it succeeds, or one of the
 * following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |stream_id| is 0.
 */
NGHTTP2_EXTERN int nghttp2_submit_trailer(nghttp2_session *session,
                                          int32_t stream_id,
                                          const nghttp2_nv *nva, size_t nvlen);

/**
 * @function
 *
 * Submits HEADERS frame. The |flags| is bitwise OR of the
 * following values:
 *
 * * :enum:`NGHTTP2_FLAG_END_STREAM`
 *
 * If |flags| includes :enum:`NGHTTP2_FLAG_END_STREAM`, this frame has
 * END_STREAM flag set.
 *
 * The library handles the CONTINUATION frame internally and it
 * correctly sets END_HEADERS to the last sequence of the PUSH_PROMISE
 * or CONTINUATION frame.
 *
 * If the |stream_id| is -1, this frame is assumed as request (i.e.,
 * request HEADERS frame which opens new stream).  In this case, the
 * assigned stream ID will be returned.  Otherwise, specify stream ID
 * in |stream_id|.
 *
 * The |pri_spec| is priority specification of this request.  ``NULL``
 * means the default priority (see
 * `nghttp2_priority_spec_default_init()`).  To specify the priority,
 * use `nghttp2_priority_spec_init()`.  If |pri_spec| is not ``NULL``,
 * this function will copy its data members.
 *
 * The ``pri_spec->weight`` must be in [:enum:`NGHTTP2_MIN_WEIGHT`,
 * :enum:`NGHTTP2_MAX_WEIGHT`], inclusive.  If ``pri_spec->weight`` is
 * strictly less than :enum:`NGHTTP2_MIN_WEIGHT`, it becomes
 * :enum:`NGHTTP2_MIN_WEIGHT`.  If it is strictly greater than
 * :enum:`NGHTTP2_MAX_WEIGHT`, it becomes :enum:`NGHTTP2_MAX_WEIGHT`.
 *
 * The |nva| is an array of name/value pair :type:`nghttp2_nv` with
 * |nvlen| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |nva| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.  The order of elements in
 * |nva| is preserved.
 *
 * The |stream_user_data| is a pointer to an arbitrary data which is
 * associated to the stream this frame will open.  Therefore it is
 * only used if this frame opens streams, in other words, it changes
 * stream state from idle or reserved to open.
 *
 * This function is low-level in a sense that the application code can
 * specify flags directly.  For usual HTTP request,
 * `nghttp2_submit_request()` is useful.  Likewise, for HTTP response,
 * prefer `nghttp2_submit_response()`.
 *
 * This function returns newly assigned stream ID if it succeeds and
 * |stream_id| is -1.  Otherwise, this function returns 0 if it
 * succeeds, or one of the following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE`
 *     No stream ID is available because maximum stream ID was
 *     reached.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |stream_id| is 0.
 * :enum:`NGHTTP2_ERR_DATA_EXIST`
 *     DATA or HEADERS has been already submitted and not fully
 *     processed yet.  This happens if stream denoted by |stream_id|
 *     is in reserved state.
 *
 * .. warning::
 *
 *   This function returns assigned stream ID if it succeeds and
 *   |stream_id| is -1.  But that stream is not opened yet.  The
 *   application must not submit frame to that stream ID before
 *   :type:`nghttp2_before_frame_send_callback` is called for this
 *   frame.
 *
 */
NGHTTP2_EXTERN int32_t
    nghttp2_submit_headers(nghttp2_session *session, uint8_t flags,
                           int32_t stream_id,
                           const nghttp2_priority_spec *pri_spec,
                           const nghttp2_nv *nva, size_t nvlen,
                           void *stream_user_data);

/**
 * @function
 *
 * Submits one or more DATA frames to the stream |stream_id|.  The
 * data to be sent are provided by |data_prd|.  If |flags| contains
 * :enum:`NGHTTP2_FLAG_END_STREAM`, the last DATA frame has END_STREAM
 * flag set.
 *
 * This function does not take ownership of the |data_prd|.  The
 * function copies the members of the |data_prd|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_DATA_EXIST`
 *     DATA or HEADERS has been already submitted and not fully
 *     processed yet.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |stream_id| is 0.
 * :enum:`NGHTTP2_ERR_STREAM_CLOSED`
 *     The stream was alreay closed; or the |stream_id| is invalid.
 *
 * .. note::
 *
 *   Currently, only one DATA or HEADERS is allowed for a stream at a
 *   time.  Submitting these frames more than once before first DATA
 *   or HEADERS is finished results in :enum:`NGHTTP2_ERR_DATA_EXIST`
 *   error code.  The earliest callback which tells that previous
 *   frame is done is :type:`nghttp2_on_frame_send_callback`.  In side
 *   that callback, new data can be submitted using
 *   `nghttp2_submit_data()`.  Of course, all data except for last one
 *   must not have :enum:`NGHTTP2_FLAG_END_STREAM` flag set in
 *   |flags|.  This sounds a bit complicated, and we recommend to use
 *   `nghttp2_submit_request()` and `nghttp2_submit_response()` to
 *   avoid this cascading issue.  The experience shows that for HTTP
 *   use, these two functions are enough to implement both client and
 *   server.
 */
NGHTTP2_EXTERN int nghttp2_submit_data(nghttp2_session *session, uint8_t flags,
                                       int32_t stream_id,
                                       const nghttp2_data_provider *data_prd);

/**
 * @function
 *
 * Submits PRIORITY frame to change the priority of stream |stream_id|
 * to the priority specification |pri_spec|.
 *
 * The |flags| is currently ignored and should be
 * :enum:`NGHTTP2_FLAG_NONE`.
 *
 * The |pri_spec| is priority specification of this request.  ``NULL``
 * is not allowed for this function. To specify the priority, use
 * `nghttp2_priority_spec_init()`.  This function will copy its data
 * members.
 *
 * The ``pri_spec->weight`` must be in [:enum:`NGHTTP2_MIN_WEIGHT`,
 * :enum:`NGHTTP2_MAX_WEIGHT`], inclusive.  If ``pri_spec->weight`` is
 * strictly less than :enum:`NGHTTP2_MIN_WEIGHT`, it becomes
 * :enum:`NGHTTP2_MIN_WEIGHT`.  If it is strictly greater than
 * :enum:`NGHTTP2_MAX_WEIGHT`, it becomes :enum:`NGHTTP2_MAX_WEIGHT`.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |stream_id| is 0; or the |pri_spec| is NULL; or trying to
 *     depend on itself.
 */
NGHTTP2_EXTERN int
nghttp2_submit_priority(nghttp2_session *session, uint8_t flags,
                        int32_t stream_id,
                        const nghttp2_priority_spec *pri_spec);

/**
 * @function
 *
 * Submits RST_STREAM frame to cancel/reject the stream |stream_id|
 * with the error code |error_code|.
 *
 * The pre-defined error code is one of :enum:`nghttp2_error_code`.
 *
 * The |flags| is currently ignored and should be
 * :enum:`NGHTTP2_FLAG_NONE`.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |stream_id| is 0.
 */
NGHTTP2_EXTERN int nghttp2_submit_rst_stream(nghttp2_session *session,
                                             uint8_t flags, int32_t stream_id,
                                             uint32_t error_code);

/**
 * @function
 *
 * Stores local settings and submits SETTINGS frame.  The |iv| is the
 * pointer to the array of :type:`nghttp2_settings_entry`.  The |niv|
 * indicates the number of :type:`nghttp2_settings_entry`.
 *
 * The |flags| is currently ignored and should be
 * :enum:`NGHTTP2_FLAG_NONE`.
 *
 * This function does not take ownership of the |iv|.  This function
 * copies all the elements in the |iv|.
 *
 * While updating individual stream's local window size, if the window
 * size becomes strictly larger than NGHTTP2_MAX_WINDOW_SIZE,
 * RST_STREAM is issued against such a stream.
 *
 * SETTINGS with :enum:`NGHTTP2_FLAG_ACK` is automatically submitted
 * by the library and application could not send it at its will.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |iv| contains invalid value (e.g., initial window size
 *     strictly greater than (1 << 31) - 1.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_submit_settings(nghttp2_session *session,
                                           uint8_t flags,
                                           const nghttp2_settings_entry *iv,
                                           size_t niv);

/**
 * @function
 *
 * Submits PUSH_PROMISE frame.
 *
 * The |flags| is currently ignored.  The library handles the
 * CONTINUATION frame internally and it correctly sets END_HEADERS to
 * the last sequence of the PUSH_PROMISE or CONTINUATION frame.
 *
 * The |stream_id| must be client initiated stream ID.
 *
 * The |nva| is an array of name/value pair :type:`nghttp2_nv` with
 * |nvlen| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |nva| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.  The order of elements in
 * |nva| is preserved.
 *
 * The |promised_stream_user_data| is a pointer to an arbitrary data
 * which is associated to the promised stream this frame will open and
 * make it in reserved state.  It is available using
 * `nghttp2_session_get_stream_user_data()`.  The application can
 * access it in :type:`nghttp2_before_frame_send_callback` and
 * :type:`nghttp2_on_frame_send_callback` of this frame.
 *
 * The client side is not allowed to use this function.
 *
 * To submit response headers and data, use
 * `nghttp2_submit_response()`.
 *
 * This function returns assigned promised stream ID if it succeeds,
 * or one of the following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_PROTO`
 *     This function was invoked when |session| is initialized as
 *     client.
 * :enum:`NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE`
 *     No stream ID is available because maximum stream ID was
 *     reached.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |stream_id| is 0; The |stream_id| does not designate stream
 *     that peer initiated.
 *
 * .. warning::
 *
 *   This function returns assigned promised stream ID if it succeeds.
 *   But that stream is not opened yet.  The application must not
 *   submit frame to that stream ID before
 *   :type:`nghttp2_before_frame_send_callback` is called for this
 *   frame.
 *
 */
NGHTTP2_EXTERN int32_t
    nghttp2_submit_push_promise(nghttp2_session *session, uint8_t flags,
                                int32_t stream_id, const nghttp2_nv *nva,
                                size_t nvlen, void *promised_stream_user_data);

/**
 * @function
 *
 * Submits PING frame.  You don't have to send PING back when you
 * received PING frame.  The library automatically submits PING frame
 * in this case.
 *
 * The |flags| is currently ignored and should be
 * :enum:`NGHTTP2_FLAG_NONE`.
 *
 * If the |opaque_data| is non ``NULL``, then it should point to the 8
 * bytes array of memory to specify opaque data to send with PING
 * frame.  If the |opaque_data| is ``NULL``, zero-cleared 8 bytes will
 * be sent as opaque data.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_submit_ping(nghttp2_session *session, uint8_t flags,
                                       const uint8_t *opaque_data);

/**
 * @function
 *
 * Submits GOAWAY frame with the last stream ID |last_stream_id| and
 * the error code |error_code|.
 *
 * The pre-defined error code is one of :enum:`nghttp2_error_code`.
 *
 * The |flags| is currently ignored and should be
 * :enum:`NGHTTP2_FLAG_NONE`.
 *
 * The |last_stream_id| is peer's stream ID or 0.  So if |session| is
 * initialized as client, |last_stream_id| must be even or 0.  If
 * |session| is initialized as server, |last_stream_id| must be odd or
 * 0.
 *
 * The HTTP/2 specification says last_stream_id must not be increased
 * from the value previously sent.  So the actual value sent as
 * last_stream_id is the minimum value between the given
 * |last_stream_id| and the last_stream_id previously sent to the
 * peer.
 *
 * If the |opaque_data| is not ``NULL`` and |opaque_data_len| is not
 * zero, those data will be sent as additional debug data.  The
 * library makes a copy of the memory region pointed by |opaque_data|
 * with the length |opaque_data_len|, so the caller does not need to
 * keep this memory after the return of this function.  If the
 * |opaque_data_len| is 0, the |opaque_data| could be ``NULL``.
 *
 * After successful transmission of GOAWAY, following things happen.
 * All incoming streams having strictly more than |last_stream_id| are
 * closed.  All incoming HEADERS which starts new stream are simply
 * ignored.  After all active streams are handled, both
 * `nghttp2_session_want_read()` and `nghttp2_session_want_write()`
 * return 0 and the application can close session.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |opaque_data_len| is too large; the |last_stream_id| is
 *     invalid.
 */
NGHTTP2_EXTERN int nghttp2_submit_goaway(nghttp2_session *session,
                                         uint8_t flags, int32_t last_stream_id,
                                         uint32_t error_code,
                                         const uint8_t *opaque_data,
                                         size_t opaque_data_len);

/**
 * @function
 *
 * Returns the last stream ID of a stream for which
 * :type:`nghttp2_on_frame_recv_callback` was invoked most recently.
 * The returned value can be used as last_stream_id parameter for
 * `nghttp2_submit_goaway()` and
 * `nghttp2_session_terminate_session2()`.
 *
 * This function always succeeds.
 */
NGHTTP2_EXTERN int32_t
    nghttp2_session_get_last_proc_stream_id(nghttp2_session *session);

/**
 * @function
 *
 * Submits WINDOW_UPDATE frame.
 *
 * The |flags| is currently ignored and should be
 * :enum:`NGHTTP2_FLAG_NONE`.
 *
 * The |stream_id| is the stream ID to send this WINDOW_UPDATE.  To
 * send connection level WINDOW_UPDATE, specify 0 to |stream_id|.
 *
 * If the |window_size_increment| is positive, the WINDOW_UPDATE with
 * that value as window_size_increment is queued.  If the
 * |window_size_increment| is larger than the received bytes from the
 * remote endpoint, the local window size is increased by that
 * difference.
 *
 * If the |window_size_increment| is negative, the local window size
 * is decreased by -|window_size_increment|.  If automatic
 * WINDOW_UPDATE is enabled
 * (`nghttp2_option_set_no_auto_window_update()`), and the library
 * decided that the WINDOW_UPDATE should be submitted, then
 * WINDOW_UPDATE is queued with the current received bytes count.
 *
 * If the |window_size_increment| is 0, the function does nothing and
 * returns 0.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_FLOW_CONTROL`
 *     The local window size overflow or gets negative.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_submit_window_update(nghttp2_session *session,
                                                uint8_t flags,
                                                int32_t stream_id,
                                                int32_t window_size_increment);

/**
 * @function
 *
 * Compares ``lhs->name`` of length ``lhs->namelen`` bytes and
 * ``rhs->name`` of length ``rhs->namelen`` bytes.  Returns negative
 * integer if ``lhs->name`` is found to be less than ``rhs->name``; or
 * returns positive integer if ``lhs->name`` is found to be greater
 * than ``rhs->name``; or returns 0 otherwise.
 */
NGHTTP2_EXTERN int nghttp2_nv_compare_name(const nghttp2_nv *lhs,
                                           const nghttp2_nv *rhs);

/**
 * @function
 *
 * A helper function for dealing with NPN in client side or ALPN in
 * server side.  The |in| contains peer's protocol list in preferable
 * order.  The format of |in| is length-prefixed and not
 * null-terminated.  For example, ``h2`` and
 * ``http/1.1`` stored in |in| like this::
 *
 *     in[0] = 2
 *     in[1..2] = "h2"
 *     in[3] = 8
 *     in[4..11] = "http/1.1"
 *     inlen = 12
 *
 * The selection algorithm is as follows:
 *
 * 1. If peer's list contains HTTP/2 protocol the library supports,
 *    it is selected and returns 1. The following step is not taken.
 *
 * 2. If peer's list contains ``http/1.1``, this function selects
 *    ``http/1.1`` and returns 0.  The following step is not taken.
 *
 * 3. This function selects nothing and returns -1 (So called
 *    non-overlap case).  In this case, |out| and |outlen| are left
 *    untouched.
 *
 * Selecting ``h2`` means that ``h2`` is written into |*out| and its
 * length (which is 2) is assigned to |*outlen|.
 *
 * For ALPN, refer to https://tools.ietf.org/html/rfc7301
 *
 * See http://technotes.googlecode.com/git/nextprotoneg.html for more
 * details about NPN.
 *
 * For NPN, to use this method you should do something like::
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
 *         if (rv == -1) {
 *             return SSL_TLSEXT_ERR_NOACK;
 *         }
 *         if (rv == 1) {
 *             ((MyType*)arg)->http2_selected = 1;
 *         }
 *         return SSL_TLSEXT_ERR_OK;
 *     }
 *     ...
 *     SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, my_obj);
 *
 */
NGHTTP2_EXTERN int nghttp2_select_next_protocol(unsigned char **out,
                                                unsigned char *outlen,
                                                const unsigned char *in,
                                                unsigned int inlen);

/**
 * @function
 *
 * Returns a pointer to a nghttp2_info struct with version information
 * about the run-time library in use.  The |least_version| argument
 * can be set to a 24 bit numerical value for the least accepted
 * version number and if the condition is not met, this function will
 * return a ``NULL``.  Pass in 0 to skip the version checking.
 */
NGHTTP2_EXTERN nghttp2_info *nghttp2_version(int least_version);

/**
 * @function
 *
 * Returns nonzero if the :type:`nghttp2_error` library error code
 * |lib_error| is fatal.
 */
NGHTTP2_EXTERN int nghttp2_is_fatal(int lib_error_code);

/**
 * @function
 *
 * Returns nonzero if HTTP header field name |name| of length |len| is
 * valid according to http://tools.ietf.org/html/rfc7230#section-3.2
 *
 * Because this is a header field name in HTTP2, the upper cased alphabet
 * is treated as error.
 */
NGHTTP2_EXTERN int nghttp2_check_header_name(const uint8_t *name, size_t len);

/**
 * @function
 *
 * Returns nonzero if HTTP header field value |value| of length |len|
 * is valid according to
 * http://tools.ietf.org/html/rfc7230#section-3.2
 */
NGHTTP2_EXTERN int nghttp2_check_header_value(const uint8_t *value, size_t len);

/* HPACK API */

struct nghttp2_hd_deflater;

/**
 * @struct
 *
 * HPACK deflater object.
 */
typedef struct nghttp2_hd_deflater nghttp2_hd_deflater;

/**
 * @function
 *
 * Initializes |*deflater_ptr| for deflating name/values pairs.
 *
 * The |deflate_hd_table_bufsize_max| is the upper bound of header
 * table size the deflater will use.
 *
 * If this function fails, |*deflater_ptr| is left untouched.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_hd_deflate_new(nghttp2_hd_deflater **deflater_ptr,
                                          size_t deflate_hd_table_bufsize_max);

/**
 * @function
 *
 * Like `nghttp2_hd_deflate_new()`, but with additional custom memory
 * allocator specified in the |mem|.
 *
 * The |mem| can be ``NULL`` and the call is equivalent to
 * `nghttp2_hd_deflate_new()`.
 *
 * This function does not take ownership |mem|.  The application is
 * responsible for freeing |mem|.
 *
 * The library code does not refer to |mem| pointer after this
 * function returns, so the application can safely free it.
 */
NGHTTP2_EXTERN int nghttp2_hd_deflate_new2(nghttp2_hd_deflater **deflater_ptr,
                                           size_t deflate_hd_table_bufsize_max,
                                           nghttp2_mem *mem);

/**
 * @function
 *
 * Deallocates any resources allocated for |deflater|.
 */
NGHTTP2_EXTERN void nghttp2_hd_deflate_del(nghttp2_hd_deflater *deflater);

/**
 * @function
 *
 * Changes header table size of the |deflater| to
 * |settings_hd_table_bufsize_max| bytes.  This may trigger eviction
 * in the dynamic table.
 *
 * The |settings_hd_table_bufsize_max| should be the value received in
 * SETTINGS_HEADER_TABLE_SIZE.
 *
 * The deflater never uses more memory than
 * ``deflate_hd_table_bufsize_max`` bytes specified in
 * `nghttp2_hd_deflate_new()`.  Therefore, if
 * |settings_hd_table_bufsize_max| > ``deflate_hd_table_bufsize_max``,
 * resulting maximum table size becomes
 * ``deflate_hd_table_bufsize_max``.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int
nghttp2_hd_deflate_change_table_size(nghttp2_hd_deflater *deflater,
                                     size_t settings_hd_table_bufsize_max);

/**
 * @function
 *
 * Deflates the |nva|, which has the |nvlen| name/value pairs, into
 * the |buf| of length |buflen|.
 *
 * If |buf| is not large enough to store the deflated header block,
 * this function fails with :enum:`NGHTTP2_ERR_INSUFF_BUFSIZE`.  The
 * caller should use `nghttp2_hd_deflate_bound()` to know the upper
 * bound of buffer size required to deflate given header name/value
 * pairs.
 *
 * Once this function fails, subsequent call of this function always
 * returns :enum:`NGHTTP2_ERR_HEADER_COMP`.
 *
 * After this function returns, it is safe to delete the |nva|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_HEADER_COMP`
 *     Deflation process has failed.
 * :enum:`NGHTTP2_ERR_INSUFF_BUFSIZE`
 *     The provided |buflen| size is too small to hold the output.
 */
NGHTTP2_EXTERN ssize_t
    nghttp2_hd_deflate_hd(nghttp2_hd_deflater *deflater, uint8_t *buf,
                          size_t buflen, const nghttp2_nv *nva, size_t nvlen);

/**
 * @function
 *
 * Returns an upper bound on the compressed size after deflation of
 * |nva| of length |nvlen|.
 */
NGHTTP2_EXTERN size_t nghttp2_hd_deflate_bound(nghttp2_hd_deflater *deflater,
                                               const nghttp2_nv *nva,
                                               size_t nvlen);

struct nghttp2_hd_inflater;

/**
 * @struct
 *
 * HPACK inflater object.
 */
typedef struct nghttp2_hd_inflater nghttp2_hd_inflater;

/**
 * @function
 *
 * Initializes |*inflater_ptr| for inflating name/values pairs.
 *
 * If this function fails, |*inflater_ptr| is left untouched.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_hd_inflate_new(nghttp2_hd_inflater **inflater_ptr);

/**
 * @function
 *
 * Like `nghttp2_hd_inflate_new()`, but with additional custom memory
 * allocator specified in the |mem|.
 *
 * The |mem| can be ``NULL`` and the call is equivalent to
 * `nghttp2_hd_inflate_new()`.
 *
 * This function does not take ownership |mem|.  The application is
 * responsible for freeing |mem|.
 *
 * The library code does not refer to |mem| pointer after this
 * function returns, so the application can safely free it.
 */
NGHTTP2_EXTERN int nghttp2_hd_inflate_new2(nghttp2_hd_inflater **inflater_ptr,
                                           nghttp2_mem *mem);

/**
 * @function
 *
 * Deallocates any resources allocated for |inflater|.
 */
NGHTTP2_EXTERN void nghttp2_hd_inflate_del(nghttp2_hd_inflater *inflater);

/**
 * @function
 *
 * Changes header table size in the |inflater|.  This may trigger
 * eviction in the dynamic table.
 *
 * The |settings_hd_table_bufsize_max| should be the value transmitted
 * in SETTINGS_HEADER_TABLE_SIZE.
 *
 * This function must not be called while header block is being
 * inflated.  In other words, this function must be called after
 * initialization of |inflater|, but before calling
 * `nghttp2_hd_inflate_hd()`, or after
 * `nghttp2_hd_inflate_end_headers()`.  Otherwise,
 * `NGHTTP2_ERR_INVALID_STATE` was returned.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_STATE`
 *     The function is called while header block is being inflated.
 *     Probably, application missed to call
 *     `nghttp2_hd_inflate_end_headers()`.
 */
NGHTTP2_EXTERN int
nghttp2_hd_inflate_change_table_size(nghttp2_hd_inflater *inflater,
                                     size_t settings_hd_table_bufsize_max);

/**
 * @enum
 *
 * The flags for header inflation.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_HD_INFLATE_NONE = 0,
  /**
   * Indicates all headers were inflated.
   */
  NGHTTP2_HD_INFLATE_FINAL = 0x01,
  /**
   * Indicates a header was emitted.
   */
  NGHTTP2_HD_INFLATE_EMIT = 0x02
} nghttp2_hd_inflate_flag;

/**
 * @function
 *
 * Inflates name/value block stored in |in| with length |inlen|.  This
 * function performs decompression.  For each successful emission of
 * header name/value pair, :enum:`NGHTTP2_HD_INFLATE_EMIT` is set in
 * |*inflate_flags| and name/value pair is assigned to the |nv_out|
 * and the function returns.  The caller must not free the members of
 * |nv_out|.
 *
 * The |nv_out| may include pointers to the memory region in the |in|.
 * The caller must retain the |in| while the |nv_out| is used.
 *
 * The application should call this function repeatedly until the
 * ``(*inflate_flags) & NGHTTP2_HD_INFLATE_FINAL`` is nonzero and
 * return value is non-negative.  This means the all input values are
 * processed successfully.  Then the application must call
 * `nghttp2_hd_inflate_end_headers()` to prepare for the next header
 * block input.
 *
 * The caller can feed complete compressed header block.  It also can
 * feed it in several chunks.  The caller must set |in_final| to
 * nonzero if the given input is the last block of the compressed
 * header.
 *
 * This function returns the number of bytes processed if it succeeds,
 * or one of the following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_HEADER_COMP`
 *     Inflation process has failed.
 * :enum:`NGHTTP2_ERR_BUFFER_ERROR`
 *     The heder field name or value is too large.
 *
 * Example follows::
 *
 *     int inflate_header_block(nghttp2_hd_inflater *hd_inflater,
 *                              uint8_t *in, size_t inlen, int final)
 *     {
 *         ssize_t rv;
 *
 *         for(;;) {
 *             nghttp2_nv nv;
 *             int inflate_flags = 0;
 *
 *             rv = nghttp2_hd_inflate_hd(hd_inflater, &nv, &inflate_flags,
 *                                        in, inlen, final);
 *
 *             if(rv < 0) {
 *                 fprintf(stderr, "inflate failed with error code %zd", rv);
 *                 return -1;
 *             }
 *
 *             in += rv;
 *             inlen -= rv;
 *
 *             if(inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
 *                 fwrite(nv.name, nv.namelen, 1, stderr);
 *                 fprintf(stderr, ": ");
 *                 fwrite(nv.value, nv.valuelen, 1, stderr);
 *                 fprintf(stderr, "\n");
 *             }
 *             if(inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
 *                 nghttp2_hd_inflate_end_headers(hd_inflater);
 *                 break;
 *             }
 *             if((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 &&
 *                inlen == 0) {
 *                break;
 *             }
 *         }
 *
 *         return 0;
 *     }
 *
 */
NGHTTP2_EXTERN ssize_t nghttp2_hd_inflate_hd(nghttp2_hd_inflater *inflater,
                                             nghttp2_nv *nv_out,
                                             int *inflate_flags, uint8_t *in,
                                             size_t inlen, int in_final);

/**
 * @function
 *
 * Signals the end of decompression for one header block.
 *
 * This function returns 0 if it succeeds. Currently this function
 * always succeeds.
 */
NGHTTP2_EXTERN int
nghttp2_hd_inflate_end_headers(nghttp2_hd_inflater *inflater);

#ifdef __cplusplus
}
#endif

#endif /* NGHTTP2_H */
