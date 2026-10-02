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
#ifndef NGHTTP2_H
#define NGHTTP2_H

#ifdef __cplusplus
extern "C" {
#endif /* defined(__cplusplus) */

/* Define WIN32 when build target is Win32 API (borrowed from
   libcurl) */
#if (defined(_WIN32) || defined(__WIN32__)) && !defined(WIN32)
#  define WIN32
#endif /* (defined(_WIN32) || defined(__WIN32__)) && !defined(WIN32) */

#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable : 4324)
#endif /* defined(_MSC_VER) */

#include <stdlib.h>
#if defined(_MSC_VER) && (_MSC_VER < 1800)
/* MSVC < 2013 does not have inttypes.h because it is not C99
   compliant.  See compiler macros and version number in
   https://sourceforge.net/p/predef/wiki/Compilers/ */
#  include <stdint.h>
#else /* !(defined(_MSC_VER) && (_MSC_VER < 1800)) */
#  include <inttypes.h>
#endif /* !(defined(_MSC_VER) && (_MSC_VER < 1800)) */
#include <sys/types.h>
#include <stdarg.h>
#include <stddef.h>

#include <nghttp2v2/version.h>

#ifdef NGHTTP2_STATICLIB
#  define NGHTTP2_EXTERN
#elif defined(WIN32)
#  ifdef BUILDING_NGHTTP2
#    define NGHTTP2_EXTERN __declspec(dllexport)
#  else /* !defined(BUILDING_NGHTTP2) */
#    define NGHTTP2_EXTERN __declspec(dllimport)
#  endif /* !defined(BUILDING_NGHTTP2) */
#else    /* !(defined(NGHTTP2_STATICLIB) || defined(WIN32)) */
#  ifdef BUILDING_NGHTTP2
#    define NGHTTP2_EXTERN __attribute__((visibility("default")))
#  else /* !defined(BUILDING_NGHTTP2) */
#    define NGHTTP2_EXTERN
#  endif /* !defined(BUILDING_NGHTTP2) */
#endif   /* !(defined(NGHTTP2_STATICLIB) || defined(WIN32)) */

#ifdef _MSC_VER
#  define NGHTTP2_ALIGN(N) __declspec(align(N))
#else /* !defined(_MSC_VER) */
#  define NGHTTP2_ALIGN(N) __attribute__((aligned(N)))
#endif /* !defined(_MSC_VER) */

/**
 * @macrosection
 *
 * HTTP/2 specific macros
 */

/**
 * @macro
 *
 * :macro:`NGHTTP2_CLIENT_HTTP2_PREFACE` is the client HTTP/2 preface.
 */
#define NGHTTP2_CLIENT_HTTP2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

/**
 * @macro
 *
 * :macro:`NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY` is the default
 * maximum HPACK dynamic header table capacity.
 */
#define NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY ((size_t)(1U << 12))

/**
 * @macro
 *
 * :macro:`NGHTTP2_INITIAL_WINDOW_SIZE` is he default initial window
 * size for both connection and stream-level flow control.
 */
#define NGHTTP2_INITIAL_WINDOW_SIZE ((uint32_t)((1U << 16) - 1))

/**
 * @macrosection
 *
 * nghttp2 library error codes
 */

/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_INVALID_ARGUMENT` indicates that a passed argument
 * is invalid.
 */
#define NGHTTP2_ERR_INVALID_ARGUMENT -201
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_NOBUF` indicates that a provided buffer does not
 * have enough space to store data.
 */
#define NGHTTP2_ERR_NOBUF -202
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_PROTO` indicates a general protocol error.
 */
#define NGHTTP2_ERR_PROTO -203
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_INVALID_STATE` indicates that a requested
 * operation is not allowed at the current connection state.
 */
#define NGHTTP2_ERR_INVALID_STATE -204
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_HPACK_FATAL` indicates that HPACK encoder or
 * decoder encounters an error.
 */
#define NGHTTP2_ERR_HPACK_FATAL -205
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_STREAM_ID_BLOCKED` indicates that there is no
 * spare stream ID available.
 */
#define NGHTTP2_ERR_STREAM_ID_BLOCKED -206
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_REFUSED_STREAM` indicates that stream creation
 * is refused.
 */
#define NGHTTP2_ERR_REFUSED_STREAM -207
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_WOULDBLOCK` indicates that an operation might
 * block.
 */
#define NGHTTP2_ERR_WOULDBLOCK -208
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_FLOW_CONTROL` indicates flow control error.
 */
#define NGHTTP2_ERR_FLOW_CONTROL -209
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_FRAME_SIZE` indicates that the incoming frame
 * is too large.
 */
#define NGHTTP2_ERR_FRAME_SIZE -210
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_STREAM_LIMIT` indicates that a remote endpoint
 * opens more streams that is permitted.
 */
#define NGHTTP2_ERR_STREAM_LIMIT -211
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_MALFORMED_HTTP_HEADER` indicates that an HTTP
 * header field is malformed.
 */
#define NGHTTP2_ERR_MALFORMED_HTTP_HEADER -212
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_REMOVE_HTTP_HEADER` indicates that an HTTP
 * header field is discarded.
 */
#define NGHTTP2_ERR_REMOVE_HTTP_HEADER -213
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_MALFORMED_HTTP_MESSAGING` indicates that HTTP
 * messaging is malformed.
 */
#define NGHTTP2_ERR_MALFORMED_HTTP_MESSAGING -214
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_STREAM_DATA_OVERFLOW` indicates that stream
 * data is too large.
 */
#define NGHTTP2_ERR_STREAM_DATA_OVERFLOW -215
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_SETTINGS_TIMEOUT` indicates that SETTINGS ACK
 * has not been received within the configured period of time.
 */
#define NGHTTP2_ERR_SETTINGS_TIMEOUT -216
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_FRAME_ENCODING` indicates there is an error in
 * frame encoding.
 */
#define NGHTTP2_ERR_FRAME_ENCODING -217
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_STREAM_SHUT_WR` indicates no more data can be
 * sent to a stream.
 */
#define NGHTTP2_ERR_STREAM_SHUT_WR -219
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_STREAM_NOT_FOUND` indicates that a stream was not
 * found.
 */
#define NGHTTP2_ERR_STREAM_NOT_FOUND -220
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_STREAM_STATE` indicates that a requested operation
 * is not allowed at the current stream state.
 */
#define NGHTTP2_ERR_STREAM_STATE -221
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_CLOSING` indicates that connection is in closing
 * state.
 */
#define NGHTTP2_ERR_CLOSING -223
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_DRAINING` indicates that connection is in draining
 * state.
 */
#define NGHTTP2_ERR_DRAINING -224
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_INTERNAL` indicates an internal error.
 */
#define NGHTTP2_ERR_INTERNAL -228
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_FATAL` indicates that error codes less than this
 * value is fatal error.  When this error is returned, an endpoint
 * should close connection immediately.
 */
#define NGHTTP2_ERR_FATAL -500
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_NOMEM` indicates out of memory.
 */
#define NGHTTP2_ERR_NOMEM -501
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_CALLBACK_FAILURE` indicates that user defined
 * callback function failed.
 */
#define NGHTTP2_ERR_CALLBACK_FAILURE -502
/**
 * @macro
 *
 * :macro:`NGHTTP2_ERR_EXCESSIVE_LOAD` indicates that the remote
 * endpoint exhibits the behavior that causes the excessive load to
 * the local endpoint.
 */
#define NGHTTP2_ERR_EXCESSIVE_LOAD -503

/**
 * @macrosection
 *
 * HTTP/2 error codes
 */

/**
 * @macro
 *
 * :macro:`NGHTTP2_NO_ERROR` is HTTP/2 error code ``NO_ERROR``.
 */
#define NGHTTP2_NO_ERROR 0x0U

/**
 * @macro
 *
 * :macro:`NGHTTP2_PROTOCOL_ERROR` is HTTP/2 error code
 * ``PROTOCOL_ERROR``.
 */
#define NGHTTP2_PROTOCOL_ERROR 0x1U

/**
 * @macro
 *
 * :macro:`NGHTTP2_INTERNAL_ERROR` is HTTP/2 error code
 * ``INTERNAL_ERROR``.
 */
#define NGHTTP2_INTERNAL_ERROR 0x2U

/**
 * @macro
 *
 * :macro:`NGHTTP2_FLOW_CONTROL_ERROR` is HTTP/2 error code
 * ``FLOW_CONTROL_ERROR``.
 */
#define NGHTTP2_FLOW_CONTROL_ERROR 0x3U

/**
 * @macro
 *
 * :macro:`NGHTTP2_SETTINGS_TIMEOUT` is HTTP/2 error code
 * ``SETTINGS_TIMEOUT``.
 */
#define NGHTTP2_SETTINGS_TIMEOUT 0x4U

/**
 * @macro
 *
 * :macro:`NGHTTP2_STREAM_CLOSED` is HTTP/2 error code
 * ``STREAM_CLOSED``.
 */
#define NGHTTP2_STREAM_CLOSED 0x5U

/**
 * @macro
 *
 * :macro:`NGHTTP2_FRAME_SIZE_ERROR` is HTTP/2 error code
 * ``FRAME_SIZE_ERROR``.
 */
#define NGHTTP2_FRAME_SIZE_ERROR 0x6U

/**
 * @macro
 *
 * :macro:`NGHTTP2_REFUSED_STREAM` is HTTP/2 error code
 * ``REFUSED_STREAM``.
 */
#define NGHTTP2_REFUSED_STREAM 0x7U

/**
 * @macro
 *
 * :macro:`NGHTTP2_CANCEL` is HTTP/2 error code ``CANCEL``.
 */
#define NGHTTP2_CANCEL 0x8U

/**
 * @macro
 *
 * :macro:`NGHTTP2_COMPRESSION_ERROR` is HTTP/2 error code
 * ``COMPRESSION_ERROR``.
 */
#define NGHTTP2_COMPRESSION_ERROR 0x9U

/**
 * @macro
 *
 * :macro:`NGHTTP2_CONNECT_ERROR` is HTTP/2 error code
 * ``CONNECT_ERROR``.
 */
#define NGHTTP2_CONNECT_ERROR 0xAU

/**
 * @macro
 *
 * :macro:`NGHTTP2_ENHANCE_YOUR_CALM` is HTTP/2 error code
 * ``ENHANCE_YOUR_CALM``.
 */
#define NGHTTP2_ENHANCE_YOUR_CALM 0xBU

/**
 * @macro
 *
 * :macro:`NGHTTP2_INADEQUATE_SECURITY` is HTTP/2 error code
 * ``INADEQUATE_SECURITY``.
 */
#define NGHTTP2_INADEQUATE_SECURITY 0xCU

/**
 * @macro
 *
 * :macro:`NGHTTP2_HTTP_1_1_REQUIRED` is HTTP/2 error code
 * ``HTTP_1_1_REQUIRED``.
 */
#define NGHTTP2_HTTP_1_1_REQUIRED 0xDU

/**
 * @typedef
 *
 * :type:`nghttp2_ssize` is signed counterpart of size_t.
 */
typedef ptrdiff_t nghttp2_ssize;

/**
 * @functypedef
 *
 * :type:`nghttp2_malloc` is a custom memory allocator to replace
 * :manpage:`malloc(3)`.  The |user_data| is
 * :member:`nghttp2_mem.user_data`.
 */
typedef void *(*nghttp2_malloc)(size_t size, void *user_data);

/**
 * @functypedef
 *
 * :type:`nghttp2_free` is a custom memory allocator to replace
 * :manpage:`free(3)`.  The |user_data| is
 * :member:`nghttp2_mem.user_data`.
 */
typedef void (*nghttp2_free)(void *ptr, void *user_data);

/**
 * @functypedef
 *
 * :type:`nghttp2_calloc` is a custom memory allocator to replace
 * :manpage:`calloc(3)`.  The |user_data| is the
 * :member:`nghttp2_mem.user_data`.
 */
typedef void *(*nghttp2_calloc)(size_t nmemb, size_t size, void *user_data);

/**
 * @functypedef
 *
 * :type:`nghttp2_realloc` is a custom memory allocator to replace
 * :manpage:`realloc(3)`.  The |user_data| is the
 * :member:`nghttp2_mem.user_data`.
 */
typedef void *(*nghttp2_realloc)(void *ptr, size_t size, void *user_data);

/**
 * @struct
 *
 * :type:`nghttp2_mem` is a custom memory allocator.  The
 * :member:`user_data` field is passed to each allocator function.
 * This can be used, for example, to achieve per-connection memory
 * pool.
 *
 * In the following example code, ``my_malloc``, ``my_free``,
 * ``my_calloc`` and ``my_realloc`` are the replacement of the
 * standard allocators :manpage:`malloc(3)`, :manpage:`free(3)`,
 * :manpage:`calloc(3)` and :manpage:`realloc(3)` respectively::
 *
 *     void *my_malloc_cb(size_t size, void *user_data) {
 *       (void)user_data;
 *       return my_malloc(size);
 *     }
 *
 *     void my_free_cb(void *ptr, void *user_data) {
 *       (void)user_data;
 *       my_free(ptr);
 *     }
 *
 *     void *my_calloc_cb(size_t nmemb, size_t size, void *user_data) {
 *       (void)user_data;
 *       return my_calloc(nmemb, size);
 *     }
 *
 *     void *my_realloc_cb(void *ptr, size_t size, void *user_data) {
 *       (void)user_data;
 *       return my_realloc(ptr, size);
 *     }
 *
 *     void conn_new() {
 *       nghttp2_mem mem = {
 *         .malloc = my_malloc_cb,
 *         .free = my_free_cb,
 *         .calloc = my_calloc_cb,
 *         .realloc = my_realloc_cb,
 *       };
 *
 *       ...
 *     }
 */
typedef struct nghttp2_mem {
  /**
   * :member:`user_data` is an arbitrary user supplied data.  This
   * is passed to each allocator function.
   */
  void *user_data;
  /**
   * :member:`malloc` is a custom allocator function to replace
   * :manpage:`malloc(3)`.
   */
  nghttp2_malloc malloc;
  /**
   * :member:`free` is a custom allocator function to replace
   * :manpage:`free(3)`.
   */
  nghttp2_free free;
  /**
   * :member:`calloc` is a custom allocator function to replace
   * :manpage:`calloc(3)`.
   */
  nghttp2_calloc calloc;
  /**
   * :member:`realloc` is a custom allocator function to replace
   * :manpage:`realloc(3)`.
   */
  nghttp2_realloc realloc;
} nghttp2_mem;

/**
 * @function
 *
 * `nghttp2_mem_default` returns the default, system standard memory
 * allocator.
 */
NGHTTP2_EXTERN const nghttp2_mem *nghttp2_mem_default(void);

/**
 * @struct
 *
 * :type:`nghttp2_vec` is struct iovec compatible structure to reference
 * arbitrary array of bytes.
 */
typedef struct nghttp2_vec {
  /**
   * :member:`base` points to the data.
   */
  uint8_t *base;
  /**
   * :member:`len` is the number of bytes which the buffer pointed by
   * base contains.
   */
  size_t len;
} nghttp2_vec;

/**
 * @typedef
 *
 * :type:`nghttp2_tstamp` is a timestamp with nanosecond resolution.
 * ``UINT64_MAX`` is an invalid value, and it is often used to
 * indicate that no value is set.
 */
typedef uint64_t nghttp2_tstamp;

/**
 * @typedef
 *
 * :type:`nghttp2_duration` is a period of time in nanosecond resolution.
 * ``UINT64_MAX`` is an invalid value, and it is often used to
 * indicate that no value is set.
 */
typedef uint64_t nghttp2_duration;

/**
 * @macrosection
 *
 * Time related macros
 */

/**
 * @macro
 *
 * :macro:`NGHTTP2_NANOSECONDS` is a count of tick which corresponds to
 * 1 nanosecond.
 */
#define NGHTTP2_NANOSECONDS ((nghttp2_duration)1ULL)

/**
 * @macro
 *
 * :macro:`NGHTTP2_MICROSECONDS` is a count of tick which corresponds
 * to 1 microsecond.
 */
#define NGHTTP2_MICROSECONDS ((nghttp2_duration)(1000ULL * NGHTTP2_NANOSECONDS))

/**
 * @macro
 *
 * :macro:`NGHTTP2_MILLISECONDS` is a count of tick which corresponds
 * to 1 millisecond.
 */
#define NGHTTP2_MILLISECONDS                                                   \
  ((nghttp2_duration)(1000ULL * NGHTTP2_MICROSECONDS))

/**
 * @macro
 *
 * :macro:`NGHTTP2_SECONDS` is a count of tick which corresponds to 1
 * second.
 */
#define NGHTTP2_SECONDS ((nghttp2_duration)(1000ULL * NGHTTP2_MILLISECONDS))

/**
 * @macro
 *
 * :macro:`NGHTTP2_MINUTES` is a count of tick which corresponds to 1
 * minute.
 */
#define NGHTTP2_MINUTES ((nghttp2_duration)(60ULL * NGHTTP2_SECONDS))

/**
 * @struct
 *
 * :type:`nghttp2_rcbuf` is the object representing reference counted
 * buffer.  The details of this structure are intentionally hidden
 * from the public API.
 */
typedef struct nghttp2_rcbuf nghttp2_rcbuf;

/**
 * @function
 *
 * `nghttp2_rcbuf_incref` increments the reference count of |rcbuf| by
 * 1.
 */
NGHTTP2_EXTERN void nghttp2_rcbuf_incref(nghttp2_rcbuf *rcbuf);

/**
 * @function
 *
 * `nghttp2_rcbuf_decref` decrements the reference count of |rcbuf| by
 * 1.  If the reference count becomes zero, the object pointed by
 * |rcbuf| will be freed.  In this case, application must not use
 * |rcbuf| again.
 */
NGHTTP2_EXTERN void nghttp2_rcbuf_decref(nghttp2_rcbuf *rcbuf);

/**
 * @function
 *
 * `nghttp2_rcbuf_get_buf` returns the underlying buffer managed by
 * |rcbuf|.
 */
NGHTTP2_EXTERN nghttp2_vec nghttp2_rcbuf_get_buf(const nghttp2_rcbuf *rcbuf);

/**
 * @function
 *
 * `nghttp2_rcbuf_is_static` returns nonzero if the underlying buffer
 * is statically allocated, and 0 otherwise. This can be useful for
 * language bindings that wish to avoid creating duplicate strings for
 * these buffers.
 */
NGHTTP2_EXTERN int nghttp2_rcbuf_is_static(const nghttp2_rcbuf *rcbuf);

/**
 * @struct
 *
 * :type:`nghttp2_buf` is the variable size buffer.
 */
typedef struct nghttp2_buf {
  /**
   * :member:`begin` points to the beginning of the buffer.
   */
  uint8_t *begin;
  /**
   * :member:`end` points to the one beyond of the last byte of the
   * buffer
   */
  uint8_t *end;
  /**
   * :member:`pos` points to the start of data.  Typically, this
   * points to the address that next data should be read.  Initially,
   * it points to :member:`begin`.
   */
  uint8_t *pos;
  /**
   * :member:`last` points to the one beyond of the last data of the
   * buffer.  Typically, new data is written at this point.
   * Initially, it points to :member:`begin`.
   */
  uint8_t *last;
} nghttp2_buf;

/**
 * @function
 *
 * `nghttp2_buf_init` initializes empty |buf|.
 */
NGHTTP2_EXTERN void nghttp2_buf_init(nghttp2_buf *buf);

/**
 * @function
 *
 * `nghttp2_buf_free` frees resources allocated for |buf| using |mem|
 * as memory allocator.  :member:`buf->begin <nghttp2_buf.begin>` must
 * be a heap buffer allocated by |mem|.
 */
NGHTTP2_EXTERN void nghttp2_buf_free(nghttp2_buf *buf, const nghttp2_mem *mem);

/**
 * @function
 *
 * `nghttp2_buf_left` returns the number of additional bytes which can
 * be written to the underlying buffer.  In other words, it returns
 * :member:`buf->end <nghttp2_buf.end>` - :member:`buf->last
 * <nghttp2_buf.last>`.
 */
NGHTTP2_EXTERN size_t nghttp2_buf_left(const nghttp2_buf *buf);

/**
 * @function
 *
 * `nghttp2_buf_len` returns the number of bytes left to read.  In
 * other words, it returns :member:`buf->last <nghttp2_buf.last>` -
 * :member:`buf->pos <nghttp2_buf.pos>`.
 */
NGHTTP2_EXTERN size_t nghttp2_buf_len(const nghttp2_buf *buf);

/**
 * @function
 *
 * `nghttp2_buf_reset` sets :member:`buf->pos <nghttp2_buf.pos>` and
 * :member:`buf->last <nghttp2_buf.last>` to :member:`buf->begin
 * <nghttp2_buf.begin>`.
 */
NGHTTP2_EXTERN void nghttp2_buf_reset(nghttp2_buf *buf);

/**
 * @macrosection
 *
 * Flags for HTTP field name/value pair
 */

/**
 * @macro
 *
 * :macro:`NGHTTP2_NV_FLAG_NONE` indicates no flag set.
 */
#define NGHTTP2_NV_FLAG_NONE 0x00U

/**
 * @macro
 *
 * :macro:`NGHTTP2_NV_FLAG_NEVER_INDEX` indicates that this name/value
 * pair must not be indexed.  Other implementation calls this bit as
 * "sensitive".
 */
#define NGHTTP2_NV_FLAG_NEVER_INDEX 0x01U

/**
 * @macro
 *
 * :macro:`NGHTTP2_NV_FLAG_NO_COPY_NAME` is set solely by application.
 * If this flag is set, the library does not make a copy of field
 * name.  This could improve performance.
 */
#define NGHTTP2_NV_FLAG_NO_COPY_NAME 0x02U

/**
 * @macro
 *
 * :macro:`NGHTTP2_NV_FLAG_NO_COPY_VALUE` is set solely by
 * application.  If this flag is set, the library does not make a copy
 * of field value.  This could improve performance.
 */
#define NGHTTP2_NV_FLAG_NO_COPY_VALUE 0x04U

/**
 * @struct
 *
 * :type:`nghttp2_nv` is the name/value pair, which mainly used to
 * represent HTTP fields.
 */
typedef struct nghttp2_nv {
  /**
   * :member:`name` is the HTTP field name.
   */
  const uint8_t *name;
  /**
   * :member:`value` is the HTTP field value.
   */
  const uint8_t *value;
  /**
   * :member:`namelen` is the length of the |name|, excluding
   * terminating NULL.
   */
  size_t namelen;
  /**
   * :member:`valuelen` is the length of the |value|, excluding
   * terminating NULL.
   */
  size_t valuelen;
  /**
   * :member:`flags` is bitwise OR of one or more of
   * :macro:`NGHTTP2_NV_FLAG_* <NGHTTP2_NV_FLAG_NONE>`.
   */
  uint8_t flags;
} nghttp2_nv;

/* Generated by genlibtokenlookup.py */
/**
 * @enum
 *
 * :type:`nghttp2_hpack_token` defines HTTP field name tokens to
 * identify field name quickly.  It appears in
 * :member:`nghttp2_hpack_nv.token`.
 */
typedef enum nghttp2_hpack_token {
  NGHTTP2_HPACK_TOKEN__AUTHORITY = 0,
  NGHTTP2_HPACK_TOKEN__METHOD = 1,
  NGHTTP2_HPACK_TOKEN__PATH = 3,
  NGHTTP2_HPACK_TOKEN__SCHEME = 5,
  NGHTTP2_HPACK_TOKEN__STATUS = 7,
  NGHTTP2_HPACK_TOKEN_ACCEPT_CHARSET = 14,
  NGHTTP2_HPACK_TOKEN_ACCEPT_ENCODING = 15,
  NGHTTP2_HPACK_TOKEN_ACCEPT_LANGUAGE = 16,
  NGHTTP2_HPACK_TOKEN_ACCEPT_RANGES = 17,
  NGHTTP2_HPACK_TOKEN_ACCEPT = 18,
  NGHTTP2_HPACK_TOKEN_ACCESS_CONTROL_ALLOW_ORIGIN = 19,
  NGHTTP2_HPACK_TOKEN_AGE = 20,
  NGHTTP2_HPACK_TOKEN_ALLOW = 21,
  NGHTTP2_HPACK_TOKEN_AUTHORIZATION = 22,
  NGHTTP2_HPACK_TOKEN_CACHE_CONTROL = 23,
  NGHTTP2_HPACK_TOKEN_CONTENT_DISPOSITION = 24,
  NGHTTP2_HPACK_TOKEN_CONTENT_ENCODING = 25,
  NGHTTP2_HPACK_TOKEN_CONTENT_LANGUAGE = 26,
  NGHTTP2_HPACK_TOKEN_CONTENT_LENGTH = 27,
  NGHTTP2_HPACK_TOKEN_CONTENT_LOCATION = 28,
  NGHTTP2_HPACK_TOKEN_CONTENT_RANGE = 29,
  NGHTTP2_HPACK_TOKEN_CONTENT_TYPE = 30,
  NGHTTP2_HPACK_TOKEN_COOKIE = 31,
  NGHTTP2_HPACK_TOKEN_DATE = 32,
  NGHTTP2_HPACK_TOKEN_ETAG = 33,
  NGHTTP2_HPACK_TOKEN_EXPECT = 34,
  NGHTTP2_HPACK_TOKEN_EXPIRES = 35,
  NGHTTP2_HPACK_TOKEN_FROM = 36,
  NGHTTP2_HPACK_TOKEN_HOST = 37,
  NGHTTP2_HPACK_TOKEN_IF_MATCH = 38,
  NGHTTP2_HPACK_TOKEN_IF_MODIFIED_SINCE = 39,
  NGHTTP2_HPACK_TOKEN_IF_NONE_MATCH = 40,
  NGHTTP2_HPACK_TOKEN_IF_RANGE = 41,
  NGHTTP2_HPACK_TOKEN_IF_UNMODIFIED_SINCE = 42,
  NGHTTP2_HPACK_TOKEN_LAST_MODIFIED = 43,
  NGHTTP2_HPACK_TOKEN_LINK = 44,
  NGHTTP2_HPACK_TOKEN_LOCATION = 45,
  NGHTTP2_HPACK_TOKEN_MAX_FORWARDS = 46,
  NGHTTP2_HPACK_TOKEN_PROXY_AUTHENTICATE = 47,
  NGHTTP2_HPACK_TOKEN_PROXY_AUTHORIZATION = 48,
  NGHTTP2_HPACK_TOKEN_RANGE = 49,
  NGHTTP2_HPACK_TOKEN_REFERER = 50,
  NGHTTP2_HPACK_TOKEN_REFRESH = 51,
  NGHTTP2_HPACK_TOKEN_RETRY_AFTER = 52,
  NGHTTP2_HPACK_TOKEN_SERVER = 53,
  NGHTTP2_HPACK_TOKEN_SET_COOKIE = 54,
  NGHTTP2_HPACK_TOKEN_STRICT_TRANSPORT_SECURITY = 55,
  NGHTTP2_HPACK_TOKEN_TRANSFER_ENCODING = 56,
  NGHTTP2_HPACK_TOKEN_USER_AGENT = 57,
  NGHTTP2_HPACK_TOKEN_VARY = 58,
  NGHTTP2_HPACK_TOKEN_VIA = 59,
  NGHTTP2_HPACK_TOKEN_WWW_AUTHENTICATE = 60,
  NGHTTP2_HPACK_TOKEN_TE,
  NGHTTP2_HPACK_TOKEN_CONNECTION,
  NGHTTP2_HPACK_TOKEN_KEEP_ALIVE,
  NGHTTP2_HPACK_TOKEN_PROXY_CONNECTION,
  NGHTTP2_HPACK_TOKEN_UPGRADE,
  NGHTTP2_HPACK_TOKEN__PROTOCOL,
  NGHTTP2_HPACK_TOKEN_PRIORITY,
} nghttp2_hpack_token;

/**
 * @struct
 *
 * :type:`nghttp2_hpack_nv` represents HTTP field name/value pair just
 * like :type:`nghttp2_nv`.  It is an extended version of
 * :type:`nghttp2_nv`, and has reference counted buffers and tokens.
 */
typedef struct nghttp2_hpack_nv {
  /**
   * :member:`name` is the buffer containing HTTP field name.
   * NULL-termination is guaranteed.
   */
  nghttp2_rcbuf *name;
  /**
   * :member:`value` is the buffer containing HTTP field value.
   * NULL-termination is guaranteed.
   */
  nghttp2_rcbuf *value;
  /**
   * :member:`token` is :type:`nghttp2_hpack_token` value of
   * :member:`name`.  It could be -1 if we have no token for that HTTP
   * field name.
   */
  int32_t token;
  /**
   * :member:`flags` is a bitwise OR of one or more of
   * :macro:`NGHTTP2_NV_FLAG_* <NGHTTP2_NV_FLAG_NONE>`.
   */
  uint8_t flags;
} nghttp2_hpack_nv;

/**
 * @struct
 *
 * :type:`nghttp2_conn` represents a single QMux connection.
 */
typedef struct nghttp2_conn nghttp2_conn;

/**
 * @functypedef
 *
 * :type:`nghttp2_log_write` is a callback function for logging.
 * |user_data| is the same object passed to `nghttp2_conn_client_new` or
 * `nghttp2_conn_server_new`.  The caller guarantees that the memory
 * region [|msg|, |msg| + |len|], inclusive, are writable, and
 * |msg|[|len|] == '\0'.  If application needs to emit a single line
 * with a line terminator, one can do msg[len] = '\n', and write |len|
 * + 1 bytes from |msg|.
 */
typedef void (*nghttp2_log_write)(void *user_data, char *msg, size_t len);

/**
 * @struct
 *
 * :type:`nghttp2_settings` defines HTTP/2 connection settings.
 */
typedef struct nghttp2_settings {
  /**
   * :member:`conn_id` is the identifier of this connection.
   * Currently, it is used in a log header so that people can
   * distinguish the particular connection from the others.
   */
  uint64_t conn_id;
  /**
   * :member:`initial_ts` is an initial timestamp given to the
   * library.
   */
  nghttp2_tstamp initial_ts;
  /**
   * :member:`log_write` is the callback function when a single log
   * message is emitted.  If this field is NULL, logging is disabled.
   */
  nghttp2_log_write log_write;
  /**
   * :member:`settings_timeout` is the timeout before receiving
   * SETTINGS frame with ACK flag set.  Setting UINT64_MAX disables
   * timeout.
   */
  nghttp2_duration settings_timeout;
  /**
   * :member:`hpack_max_dtable_capacity` is the maximum size of HPACK
   * dynamic table.
   */
  size_t hpack_max_dtable_capacity;
  /**
   * :member:`hpack_encoder_max_dtable_capacity` is the upper bound of
   * HPACK dynamic table capacity that the HPACK encoder is willing to
   * use.  The effective maximum dynamic table capacity is the minimum
   * of this field and the value of the received
   * SETTINGS_HEADER_TABLE_SIZE.  If this field is set to 0, the
   * encoder does not use the dynamic table.
   */
  size_t hpack_encoder_max_dtable_capacity;
  /**
   * :member:`max_concurrent_streams_local` is the number of
   * concurrent streams that a local endpoint can open until the
   * actual limit is known.  When SETTINGS frame is received from the
   * remote endpoint, and if ``SETTINGS_MAX_CONCURRENT_STREAMS`` is
   * not included in the frame, the limit is unchanged because the
   * unlimited concurrent stream is insane.
   */
  uint32_t max_concurrent_streams_local;
  /**
   * :member:`max_concurrent_streams_remote` is the number of
   * concurrent streams that a remote endpoint can open.
   */
  uint32_t max_concurrent_streams_remote;
  /**
   * :member:`initial_max_stream_data` is the window size for
   * stream-level flow control.
   */
  uint32_t initial_max_stream_data;
  /**
   * :member:`initial_max_data` is the window size for
   * connection-level flow control.
   */
  uint32_t initial_max_data;
  /**
   * :member:`enable_connect_protocol`, if set to nonzero, enables
   * Extended CONNECT Method (see :rfc:`9220`).  Client ignores this
   * field.
   */
  uint8_t enable_connect_protocol;
  /**
   * :member:`glitch_ratelim_burst` is the maximum number of tokens
   * available to "glitch" rate limiter.  It is clamped to UINT64_MAX
   * / NGHTTP2_SECONDS.  "glitch" is a suspicious activity from a remote
   * endpoint.  If detected, certain amount of tokens are consumed.
   * If no tokens are available to consume, the connection is closed.
   * The rate of token generation is specified by
   * :member:`glitch_ratelim_rate`.
   */
  uint64_t glitch_ratelim_burst;
  /**
   * :member:`glitch_ratelim_rate` is the number of tokens generated
   * per second.  See :member:`glitch_ratelim_burst` for "glitch" rate
   * limiter.
   */
  uint64_t glitch_ratelim_rate;
} nghttp2_settings;

/**
 * @function
 *
 * `nghttp2_settings_default` initializes |settings| with the default
 * values.  First this function fills |settings| with 0, and sets the
 * default values to the following fields:
 *
 * - :member:`hpack_max_dtable_capacity
 *   <nghttp2_settings.hpack_max_dtable_capacity>` =
 *   :macro:`NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY`
 * - :member:`hpack_encoder_max_dtable_capacity
 *   <nghttp2_settings.hpack_encoder_max_dtable_capacity>` =
 *   :macro:`NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY`
 * - :member:`max_concurrent_streams_local
 *   <nghttp2_settings.max_concurrent_streams_local>` = 100
 * - :member:`initial_max_stream_data
 *   <nghttp2_settings.initial_max_stream_data>` =
 *   :macro:`NGHTTP2_INITIAL_WINDOW_SIZE`
 * - :member:`initial_max_data <nghttp2_settings.initial_max_data>` =
 *   :macro:`NGHTTP2_INITIAL_WINDOW_SIZE`.
 * - :member:`settings_timeout <nghttp2_settings.settings_timeout>` =
 *   10 * :macro:`NGHTTP2_SECONDS`
 * - :member:`glitch_ratelim_burst
 *   <nghttp2_settings.glitch_ratelim_burst>` = 10000
 * - :member:`glitch_ratelim_rate
 *   <nghttp2_settings.glitch_ratelim_rate>` = 330
 */
NGHTTP2_EXTERN void nghttp2_settings_default(nghttp2_settings *settings);

/**
 * @struct
 *
 * :type:`nghttp2_proto_settings` contains HTTP/2 settings that this
 * library can recognize.
 */
typedef struct nghttp2_proto_settings {
  /**
   * :member:`hpack_max_dtable_capacity` is the maximum size of HPACK
   * dynamic table.  It corresponds to ``SETTINGS_HEADER_TABLE_SIZE``.
   */
  size_t hpack_max_dtable_capacity;
  /**
   * :member:`max_concurrent_streams` is the maximum number of the
   * concurrent streams that the receiver can open.  It corresponds to
   * ``SETTINGS_MAX_CONCURRENT_STREAMS``.
   */
  uint32_t max_concurrent_streams;
  /**
   * :member:`initial_max_stream_data` is the initial window size of
   * stream-level flow control.  It corresponds to
   * ``SETTINGS_INITIAL_WINDOW_SIZE``.
   */
  uint32_t initial_max_stream_data;
  /**
   * :member:`max_field_section_size` specifies the maximum header
   * section (block) size.  It correspoinds to
   * ``SETTINGS_MAX_HEADER_LIST_SIZE``.
   */
  uint32_t max_field_section_size;
  /**
   * :member:`enable_connect_protocol`, if set to nonzero, enables
   * Extended CONNECT Method (see :rfc:`8441`).  Client ignores this
   * field.
   */
  uint8_t enable_connect_protocol;
} nghttp2_proto_settings;

/**
 * @type
 *
 * `nghttp2_ping_data` contains the data sent along with PING frame.
 */
typedef struct nghttp2_ping_data {
  /**
   * :member:`data` is the data sent along with PING frame.
   */
  uint8_t data[8];
} nghttp2_ping_data;

/**
 * @functypedef
 *
 * :type:`nghttp2_recv_settings` is a callback function which is
 * invoked when SETTINGS frame is received.  |settings| is a received
 * remote HTTP/2 settings.
 *
 * The implementation of this callback must return 0 if it succeeds.
 * Returning :macro:`NGHTTP2_ERR_CALLBACK_FAILURE` will return to the
 * caller immediately.  Any values other than 0 is treated as
 * :macro:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_recv_settings)(nghttp2_conn *conn,
                                     const nghttp2_proto_settings *settings,
                                     void *user_data);

/**
 * @functypedef
 *
 * :type:`nghttp2_stream_open` is a callback function which is called
 * when remote stream is opened by a remote endpoint.  This function
 * is not called if stream is opened by implicitly (we might
 * reconsider this behaviour later).
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :macro:`NGHTTP2_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*nghttp2_stream_open)(nghttp2_conn *conn, int64_t stream_id,
                                   void *user_data);

/**
 * @macrosection
 *
 * Stream close flags for :type:`nghttp2_stream_close` callback.
 */

/**
 * @macro
 *
 * :macro:`NGHTTP2_STREAM_CLOSE_FLAG_NONE` indicates no flag set.
 */
#define NGHTTP2_STREAM_CLOSE_FLAG_NONE 0x00U

/**
 * @macro
 *
 * :macro:`NGHTTP2_STREAM_CLOSE_FLAG_ERROR_CODE_SET` indicates that
 * error_code parameter is set.
 */
#define NGHTTP2_STREAM_CLOSE_FLAG_ERROR_CODE_SET 0x01U

/**
 * @functypedef
 *
 * :type:`nghttp2_stream_close` is invoked when a stream is closed.
 * This callback is not called when HTTP/2 connection is closed before
 * existing streams are closed.  |flags| is the bitwise-OR of zero or
 * more of :macro:`NGHTTP2_STREAM_CLOSE_FLAG_*
 * <NGHTTP2_STREAM_CLOSE_FLAG_NONE>`.  |error_code| indicates the
 * error code that shut down this stream if
 * :macro:`NGHTTP2_STREAM_CLOSE_FLAG_ERROR_CODE_SET` is set in
 * |flags|.  No error code means that a stream is closed cleanly.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :macro:`NGHTTP2_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*nghttp2_stream_close)(nghttp2_conn *conn, uint32_t flags,
                                    int64_t stream_id, uint32_t error_code,
                                    void *user_data, void *stream_user_data);

/**
 * @functypedef
 *
 * :type:`nghttp2_extend_max_stream_data` is a callback function which
 * is invoked when max stream data is extended.  |stream_id|
 * identifies the stream.  |max_data| is a cumulative number of bytes
 * an endpoint can send on this stream.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGHTTP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*nghttp2_extend_max_stream_data)(nghttp2_conn *conn,
                                              int64_t stream_id,
                                              uint64_t max_data,
                                              void *user_data,
                                              void *stream_user_data);

/**
 * @functypedef
 *
 * :type:`nghttp2_rand` is a callback function which is invoked when
 * unpredictable data of |destlen| bytes are needed.  The
 * implementation must write unpredictable data of |destlen| bytes
 * into the buffer pointed by |dest|.
 */
typedef void (*nghttp2_rand)(uint8_t *dest, size_t destlen);

/**
 * @functypedef
 *
 * :type:`nghttp2_write_stream_data_offset` is a callback function
 * which is invoked when the stream data is written to DATA frame.
 * |stream_id| identifies the stream.  |offset| is the starting offset
 * of the stream data.  |len| is the length of the stream data.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGHTTP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*nghttp2_write_stream_data_offset)(nghttp2_conn *conn,
                                                int64_t stream_id,
                                                uint64_t offset, size_t len,
                                                void *user_data,
                                                void *stream_user_data);

/**
 * @functypedef
 *
 * :type:`nghttp2_begin_fields` is a callback function which is
 * invoked when an incoming HTTP field section is started on a stream
 * denoted by |stream_id|.  Each HTTP field is passed to application
 * by :type:`nghttp2_recv_header` callback.  And then
 * :type:`nghttp2_end_headers` is called when a whole HTTP field
 * section is processed.
 *
 * The implementation of this callback must return 0 if it succeeds.
 * Returning :macro:`NGHTTP2_ERR_CALLBACK_FAILURE` will return to the
 * caller immediately.  Any values other than 0 is treated as
 * :macro:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_begin_fields)(nghttp2_conn *conn, int64_t stream_id,
                                    void *conn_user_data,
                                    void *stream_user_data);

/**
 * @functypedef
 *
 * :type:`nghttp2_recv_field` is a callback function which is invoked
 * when an HTTP field is received on a stream denoted by |stream_id|.
 * |name| contains a field name, and |value| contains a field value.
 * |token| is one of token defined in :type:`nghttp2_qpack_token` or
 * -1 if no token is defined for |name|.  |flags| is bitwise OR of
 * zero or more of :macro:`NGHTTP2_NV_FLAG_* <NGHTTP2_NV_FLAG_NONE>`.
 *
 * The buffers for |name| and |value| are reference counted. If
 * application needs to keep them, increment the reference count with
 * `nghttp2_rcbuf_incref`.  When they are no longer used, call
 * `nghttp2_rcbuf_decref`.
 *
 * The implementation of this callback must return 0 if it succeeds.
 * Returning :macro:`NGHTTP2_ERR_CALLBACK_FAILURE` will return to the
 * caller immediately.  Any values other than 0 is treated as
 * :macro:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_recv_field)(nghttp2_conn *conn, int64_t stream_id,
                                  int32_t token, nghttp2_rcbuf *name,
                                  nghttp2_rcbuf *value, uint8_t flags,
                                  void *conn_user_data, void *stream_user_data);

/**
 * @functypedef
 *
 * :type:`nghttp2_end_fields` is a callback function which is invoked
 * when an incoming HTTP field section has ended.
 *
 * If the stream ends with this HTTP field section, |fin| is set to
 * nonzero.
 *
 * The implementation of this callback must return 0 if it succeeds.
 * Returning :macro:`NGHTTP2_ERR_CALLBACK_FAILURE` will return to the
 * caller immediately.  Any values other than 0 is treated as
 * :macro:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_end_fields)(nghttp2_conn *conn, int64_t stream_id,
                                  int fin, void *conn_user_data,
                                  void *stream_user_data);

/**
 * @functypedef
 *
 * :type:`nghttp2_recv_data` is a callback function which is invoked
 * when a part of request or response body on stream identified by
 * |stream_id| is received.  |data| points to the received data, and
 * its length is |datalen|.
 *
 * The application is responsible for increasing flow control credit
 * (say, increasing by |datalen| bytes).
 *
 * The implementation of this callback must return 0 if it succeeds.
 * Returning :macro:`NGHTTP2_ERR_CALLBACK_FAILURE` will return to the
 * caller immediately.  Any values other than 0 is treated as
 * :macro:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_recv_data)(nghttp2_conn *conn, int64_t stream_id,
                                 const uint8_t *data, size_t datalen, int fin,
                                 void *conn_user_data, void *stream_user_data);

/**
 * @functypedef
 *
 * :type:`nghttp2_end_stream` is a callback function which is invoked
 * when the receiving side of stream is closed.  For server, this
 * callback function is invoked when HTTP request is received
 * completely.  For client, this callback function is invoked when
 * HTTP response is received completely.
 *
 * The implementation of this callback must return 0 if it succeeds.
 * Returning :macro:`NGHTTP2_ERR_CALLBACK_FAILURE` will return to the
 * caller immediately.  Any values other than 0 is treated as
 * :macro:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_end_stream)(nghttp2_conn *conn, int64_t stream_id,
                                  void *conn_user_data, void *stream_user_data);

/**
 * @functypedef
 *
 * :type:`nghttp2_recv_ping_ack` is a callback function which is
 * invoked when PING with ACK flag set is received.  |data| contains
 * the data received with PING frame.  This is the data that the local
 * endpoint sent to the remote endpoint.  The data is 8 bytes long.
 *
 * The implementation of this callback must return 0 if it succeeds.
 * Returning :macro:`NGHTTP2_ERR_CALLBACK_FAILURE` will return to the
 * caller immediately.  Any values other than 0 is treated as
 * :macro:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_recv_ping_ack)(nghttp2_conn *conn,
                                     const nghttp2_ping_data *data,
                                     void *conn_user_data);

/**
 * @functypedef
 *
 * :type:`nghttp2_shutdown` is a callback function which is invoked
 * when a shutdown is initiated by the remote endpoint.  For client,
 * |last_stream_id| contains a stream ID of a client initiated stream,
 * for server, it contains a stream ID of server push.  All client
 * streams with stream ID larger than |last_stream_id| are guaranteed
 * not to be processed by the remote endpoint.  Because libnghttp2
 * does not implement Server Push, the server should ignore
 * |last_stream_id|.
 *
 * It is possible that this callback is invoked multiple times on a
 * single connection, however the |last_stream_id| can only stay the
 * same or decrease, never increase.
 *
 * The implementation of this callback must return 0 if it succeeds.
 * Returning :macro:`NGHTTP2_ERR_CALLBACK_FAILURE` will return to the
 * caller immediately.  Any values other than 0 is treated as
 * :macro:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_shutdown)(nghttp2_conn *conn, int64_t last_stream_id,
                                uint32_t error_code, void *conn_user_data);

/**
 * @struct
 *
 * :type:`nghttp2_callbacks` holds a set of callback functions.
 */
typedef struct nghttp2_callbacks {
  /**
   * :member:`rand` is a callback function which is invoked when the
   * library needs random data.  This callback function must be
   * specified.
   */
  nghttp2_rand rand;
  /**
   * :member:`recv_settings` is a callback function which is invoked
   * when SETTINGS frame is received from the remote endpoint.
   */
  nghttp2_recv_settings recv_settings;
  /**
   * :member:`stream_open` is a callback function which is invoked
   * when new remote stream is opened by a remote endpoint.  This
   * callback function is optional.
   */
  nghttp2_stream_open stream_open;
  /**
   * :member:`stream_close` is a callback function which is invoked
   * when a stream is closed.  This callback function is optional.
   */
  nghttp2_stream_close stream_close;
  /**
   * :member:`extend_max_stream_data` is callback function which is
   * invoked when the maximum offset of stream data that a local
   * endpoint can send is increased.  This callback function is
   * optional.
   */
  nghttp2_extend_max_stream_data extend_max_stream_data;
  /**
   * :member:`write_stream_data_offset` is a callback function which
   * is invoked when the stream data is written.  This callback
   * function is optional.
   */
  nghttp2_write_stream_data_offset write_stream_data_offset;
  /**
   * :member:`begin_headers` is a callback function which is invoked
   * when an HTTP header field section has started on a particular
   * stream.
   */
  nghttp2_begin_fields begin_headers;
  /**
   * :member:`recv_header` is a callback function which is invoked
   * when a single HTTP header field is received on a particular
   * stream.
   */
  nghttp2_recv_field recv_header;
  /**
   * :member:`end_headers` is a callback function which is invoked
   * when an HTTP header field section has ended on a particular
   * stream.
   */
  nghttp2_end_fields end_headers;
  /**
   * :member:`begin_trailers` is a callback function which is invoked
   * when an HTTP trailer field section has started on a particular
   * stream.
   */
  nghttp2_begin_fields begin_trailers;
  /**
   * :member:`recv_trailer` is a callback function which is invoked
   * when a single HTTP trailer field is received on a particular
   * stream.
   */
  nghttp2_recv_field recv_trailer;
  /**
   * :member:`end_trailers` is a callback function which is invoked
   * when an HTTP trailer field section has ended on a particular
   * stream.
   */
  nghttp2_end_fields end_trailers;
  /**
   * :member:`recv_data` is a callback function which is invoked when
   * stream data is received.
   */
  nghttp2_recv_data recv_data;
  /**
   * :member:`end_stream` is a callback function which is invoked when
   * a receiving side of stream has been closed.
   */
  nghttp2_end_stream end_stream;
  /**
   * :member:`recv_ping_ack` is a callback function which is invoked
   * when PING frame with ACK flag set is received.
   */
  nghttp2_recv_ping_ack recv_ping_ack;
  /**
   * :member:`shutdown` is a callback function which is invoked when
   * GOAWAY frame is received.
   */
  nghttp2_shutdown shutdown;
} nghttp2_callbacks;

/**
 * @macrosection
 *
 * Data flags
 */

/**
 * @macro
 *
 * :macro:`NGHTTP2_READ_DATA_FLAG_NONE` indicates no flag set.
 */
#define NGHTTP2_READ_DATA_FLAG_NONE 0x00U

/**
 * @macro
 *
 * :macro:`NGHTTP2_READ_DATA_FLAG_EOF` indicates that all request or
 * response body has been provided to the library.  It also indicates
 * that sending side of stream is closed unless
 * :macro:`NGHTTP2_READ_DATA_FLAG_NO_END_STREAM` is given at the same
 * time.
 */
#define NGHTTP2_READ_DATA_FLAG_EOF 0x01U

/**
 * @macro
 *
 * :macro:`NGHTTP2_READ_DATA_FLAG_NO_END_STREAM` indicates that
 * sending side of stream is not closed even if
 * :macro:`NGHTTP2_READ_DATA_FLAG_EOF` is set.  Usually this flag is
 * used to send trailer fields with `nghttp2_conn_submit_trailers`.
 * If `nghttp2_conn_submit_trailers` has been called, regardless of
 * this flag, the submitted trailer fields are sent.
 */
#define NGHTTP2_READ_DATA_FLAG_NO_END_STREAM 0x02U

/**
 * @functypedef
 *
 * :type:`nghttp2_read_data` is a callback function invoked when the
 * library asks an application to provide stream data for a stream
 * denoted by |stream_id|.
 *
 * The library provides |vec| of length |veccnt| to the application.
 * The application should fill data and its length to |vec|.  It has
 * to return the number of the filled objects.  The application must
 * retain data until they are safe to free.  It is notified by
 * :type:`nghttp2_acked_stream_data` callback.
 *
 * If this is the last data to send (or there is no data to send
 * because all data have been sent already), set
 * :macro:`NGHTTP2_READ_DATA_FLAG_EOF` to |*pflags|.
 *
 * If the application is unable to provide data temporarily, return
 * :macro:`NGHTTP2_ERR_WOULDBLOCK`.  When it is ready to provide data,
 * call `nghttp2_conn_resume_stream`.
 *
 * If the callback returns 0 or the sum of length in |vec| is 0, and
 * |*pflags| does not have :macro:`NGHTTP2_READ_DATA_FLAG_EOF` not
 * set, it is treated as if :macro:`NGHTTP2_ERR_CALLBACK_FAILURE` is
 * returned.
 *
 * The callback should return the number of objects in |vec| that the
 * application filled if it succeeds, or
 * :macro:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef nghttp2_ssize (*nghttp2_read_data)(nghttp2_conn *conn,
                                           int64_t stream_id, nghttp2_vec *vec,
                                           size_t veccnt, uint32_t *pflags,
                                           void *conn_user_data,
                                           void *stream_user_data);

/**
 * @struct
 *
 * :type:`nghttp2_data_reader` specifies the way how to generate
 * request or response body.
 */
typedef struct nghttp2_data_reader {
  /**
   * :member:`read_data` is a callback function to generate body.
   */
  nghttp2_read_data read_data;
} nghttp2_data_reader;

/**
 * @function
 *
 * `nghttp2_conn_server_new` creates new :type:`nghttp2_conn` as a
 * server.  If it succeeds, it assigns the pointer to the object to
 * |*pconn|.  |callbacks| and |settings| must not be NULL, and the
 * function makes a copy of each of them.  |user_data| is the
 * arbitrary pointer which is passed to the user-defined callback
 * functions.  |mem| is a memory allocator.  If |mem| is NULL, the
 * memory allocator returned by `nghttp2_mem_default()` is used.
 *
 * Call `nghttp2_conn_del` to free memory allocated for |*pconn|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_conn_server_new(nghttp2_conn **pconn,
                                           const nghttp2_callbacks *callbacks,
                                           const nghttp2_settings *settings,
                                           const nghttp2_mem *mem,
                                           void *user_data);

/**
 * @function
 *
 * `nghttp2_conn_client_new` creates new :type:`nghttp2_conn` as a
 * client.  If it succeeds, it assigns the pointer to the object to
 * |*pconn|.  |callbacks| and |settings| must not be NULL, and the
 * function makes a copy of each of them.  |user_data| is the
 * arbitrary pointer which is passed to the user-defined callback
 * functions.  |mem| is a memory allocator.  If |mem| is NULL, the
 * memory allocator returned by `nghttp2_mem_default()` is used.
 *
 * Call `nghttp2_conn_del` to free memory allocated for |*pconn|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_conn_client_new(nghttp2_conn **pconn,
                                           const nghttp2_callbacks *callbacks,
                                           const nghttp2_settings *settings,
                                           const nghttp2_mem *mem,
                                           void *user_data);

/**
 * @function
 *
 * `nghttp2_conn_del` frees resources allocated for |conn|.  It also
 * frees memory pointed by |conn|.
 */
NGHTTP2_EXTERN void nghttp2_conn_del(nghttp2_conn *conn);

/**
 * @function
 *
 * `nghttp2_conn_read` processes the incoming data pointed by |data| of
 * length |datalen|.  |ts| is the timestamp of this call.  Normally,
 * this function processes all input data.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * TBD
 *
 * In general, when one of negative error codes is returned, the QMux
 * connection must be closed, and |conn| must be deleted by
 * `nghttp2_conn_del`.
 */
NGHTTP2_EXTERN int nghttp2_conn_read(nghttp2_conn *conn, const uint8_t *data,
                                     size_t datalen, nghttp2_tstamp ts);

/**
 * @function
 *
 * `nghttp2_conn_extend_max_stream_offset` extends the maximum stream
 * data that a remote endpoint can send by |datalen|.  |stream_id|
 * specifies the stream ID.  This function only extends stream-level
 * flow control window.
 *
 * This function returns 0 if a stream denoted by |stream_id| is not
 * found.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_conn_extend_max_stream_offset(nghttp2_conn *conn,
                                                         int64_t stream_id,
                                                         uint32_t datalen);

/**
 * @function
 *
 * `nghttp2_conn_extend_max_offset` extends max data offset by
 * |datalen|.  This function only extends connection-level flow
 * control window.
 */
NGHTTP2_EXTERN int nghttp2_conn_extend_max_offset(nghttp2_conn *conn,
                                                  uint32_t datalen);

/**
 * @function
 *
 * `nghttp2_conn_shutdown_stream` closes a stream denoted by
 * |stream_id| abruptly.  |error_code| is one of HTTP/2 error codes,
 * and indicates the reason of shutdown.  Successful call of this
 * function does not immediately erase the state of the stream.  The
 * actual deletion is done when the RST_STREAM frame is sent.
 *
 * |flags| is currently unused, and should be set to 0.
 */
NGHTTP2_EXTERN void nghttp2_conn_shutdown_stream(nghttp2_conn *conn,
                                                 uint32_t flags,
                                                 int64_t stream_id,
                                                 uint32_t error_code);

/**
 * @function
 *
 * `nghttp2_conn_resume_stream` resumes stream identified by
 * |stream_id| which was previously unable to provide data.  See
 * :type:`nghttp2_read_data`.
 *
 * If a stream denoted by |stream_id| is not found, this function
 * returns 0.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_conn_resume_stream(nghttp2_conn *conn,
                                              int64_t stream_id);

/**
 * @function
 *
 * `nghttp2_conn_get_streams_left` returns the number of streams which
 * the local endpoint can open without violating stream concurrency
 * limit.  Only client can call this function.
 */
NGHTTP2_EXTERN size_t nghttp2_conn_get_streams_left(const nghttp2_conn *conn);

/**
 * @function
 *
 * `nghttp2_conn_write` writes HTTP/2 frames into the buffer pointed
 * by |dest| of length |destlen|.  The caller should provide a buffer
 * of 16384 bytes long to just fit into a single TLS record.
 */
NGHTTP2_EXTERN nghttp2_ssize nghttp2_conn_write(nghttp2_conn *conn,
                                                uint8_t *dest, size_t destlen,
                                                nghttp2_tstamp ts);

/**
 * @function
 *
 * `nghttp2_conn_is_server` returns nonzero if |conn| is initialized as
 * server.
 */
NGHTTP2_EXTERN int nghttp2_conn_is_server(const nghttp2_conn *conn);

/**
 * @function
 *
 * `nghttp2_conn_get_timestamp` returns the latest timestamp that is
 * known to |conn|.
 */
NGHTTP2_EXTERN nghttp2_tstamp
nghttp2_conn_get_timestamp(const nghttp2_conn *conn);

/**
 * @function
 *
 * `nghttp2_conn_get_expiry` returns the next expiry time.  It returns
 * ``UINT64_MAX`` if there is no next expiry.
 *
 * Call `nghttp2_conn_handle_expiry` when the expiry time has passed.
 */
NGHTTP2_EXTERN nghttp2_tstamp nghttp2_conn_get_expiry(const nghttp2_conn *conn);

/**
 * @function
 *
 * `nghttp2_conn_handle_expiry` handles expired timer.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NGHTTP2_ERR_SETTINGS_TIMEOUT`
 *     The SETTINGS ACK timer has fired.
 */
NGHTTP2_EXTERN int nghttp2_conn_handle_expiry(nghttp2_conn *conn,
                                              nghttp2_tstamp ts);

/**
 * @function
 *
 * `nghttp2_strerror` returns the text representation of |liberr|.
 * |liberr| must be one of nghttp2 library error codes (which is defined
 * as :macro:`NGHTTP2_ERR_* <NGHTTP2_ERR_INVALID_ARGUMENT>` macros).
 */
NGHTTP2_EXTERN const char *nghttp2_strerror(int liberr);

/**
 * @function
 *
 * `nghttp2_err_is_fatal` returns nonzero if |liberr| is a fatal error.
 * |liberr| must be one of nghttp2 library error codes (which is defined
 * as :macro:`NGHTTP2_ERR_* <NGHTTP2_ERR_INVALID_ARGUMENT>` macros).
 */
NGHTTP2_EXTERN int nghttp2_err_is_fatal(int liberr);

/**
 * @function
 *
 * `nghttp2_err_infer_http2_error_code` returns an HTTP/2 error code
 * which corresponds to |liberr|.  |liberr| must be one of nghttp2
 * library error codes (which is defined as :macro:`NGHTTP2_ERR_*
 * <NGHTTP2_ERR_INVALID_ARGUMENT>` macros).
 */
NGHTTP2_EXTERN uint32_t nghttp2_err_infer_http2_error_code(int liberr);

/**
 * @function
 *
 * `nghttp2_conn_get_next_stream_id` returns the next stream ID.  If
 * it returns the invalid stream ID > INT32_MAX, all stream IDs have
 * been spent or GOAWAY has been received, and new stream cannot be
 * created for this connection.  Only client can call this function.
 */
NGHTTP2_EXTERN int64_t
nghttp2_conn_get_next_stream_id(const nghttp2_conn *conn);

/**
 * @function
 *
 * `nghttp2_conn_submit_request` creates new stream and submits HTTP
 * request header fields and the optional request body.  Only client
 * can submit HTTP request.  |nva| of length |nvlen| specifies HTTP
 * request header fields.  |dr| specifies a request body.  If there is
 * no request body, specify NULL.  If |dr| is NULL, it implies the end
 * of stream.
 *
 * This function returns the stream ID if it succeeds.  To know the
 * stream ID before calling this function, use
 * `nghttp2_conn_get_next_stream_id`.
 *
 * This function returns the stream ID that the new stream is
 * designated with if it succeeds, or one of the following negative
 * error codes:
 *
 * :macro:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :macro:`NGHTTP2_ERR_REFUSED_STREAM`
 *     Connection is shutting down, and no new stream is allowed.
 * :macro:`NGHTTP2_ERR_STREAM_ID_BLOCKED`
 *     The remote endpoint does not allow |stream_id| yet.
 */
NGHTTP2_EXTERN int64_t nghttp2_conn_submit_request(
  nghttp2_conn *conn, const nghttp2_nv *nva, size_t nvlen,
  const nghttp2_data_reader *dr, void *stream_user_data);

/**
 * @function
 *
 * `nghttp2_conn_submit_info` submits HTTP non-final response header
 * fields on the stream identified by |stream_id|.  |nva| of length
 * |nvlen| specifies HTTP response header fields.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NGHTTP2_ERR_STREAM_NOT_FOUND`
 *     Stream not found
 * :macro:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_conn_submit_info(nghttp2_conn *conn,
                                            int64_t stream_id,
                                            const nghttp2_nv *nva,
                                            size_t nvlen);

/**
 * @function
 *
 * `nghttp2_conn_submit_response` submits HTTP response header fields
 * and body on the stream identified by |stream_id|.  |nva| of length
 * |nvlen| specifies HTTP response header fields.  |dr| specifies a
 * response body.  If there is no response body, specify NULL.  If
 * |dr| is NULL, it implies the end of stream.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NGHTTP2_ERR_STREAM_NOT_FOUND`
 *     Stream not found
 * :macro:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_conn_submit_response(nghttp2_conn *conn,
                                                int64_t stream_id,
                                                const nghttp2_nv *nva,
                                                size_t nvlen,
                                                const nghttp2_data_reader *dr);

/**
 * @function
 *
 * `nghttp2_conn_submit_trailers` submits HTTP trailer fields on the
 * stream identified by |stream_id|.  |nva| of length |nvlen|
 * specifies HTTP trailer fields.  Calling this function implies the
 * end of stream.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NGHTTP2_ERR_STREAM_NOT_FOUND`
 *     Stream not found
 * :macro:`NGHTTP2_ERR_INVALID_STATE`
 *     Application has already submitted fin to stream.
 * :macro:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_conn_submit_trailers(nghttp2_conn *conn,
                                                int64_t stream_id,
                                                const nghttp2_nv *nva,
                                                size_t nvlen);

/**
 * @function
 *
 * `nghttp2_conn_submit_ping` submits PING frame with the given
 * |data|.  |data| must point to the buffer that contains at least 8
 * bytes of data.  At most 1 PING is allowed in flight.  When PING
 * frame with ACK flag is set is received from the remote endpoint,
 * :type:`nghttp2_recv_ping_ack` callback is called.
 *
 * :macro:`NGHTTP2_ERR_INVALID_STATE`
 *     Another PING is already in-flight.
 */
NGHTTP2_EXTERN int nghttp2_conn_submit_ping(nghttp2_conn *conn,
                                            const nghttp2_ping_data *data);

/**
 * @function
 *
 * `nghttp2_conn_submit_shutdown_notice` notifies the other endpoint
 * to stop creating new stream.  After a couple of RTTs later, call
 * `nghttp2_conn_shutdown` to start graceful shutdown.
 */
NGHTTP2_EXTERN void nghttp2_conn_submit_shutdown_notice(nghttp2_conn *conn);

/**
 * @function
 *
 * `nghttp2_conn_shutdown` starts graceful shutdown.  It should be
 * called after `nghttp2_conn_submit_shutdown_notice` and a couple of
 * RTTs.  After calling this function, the local endpoint starts
 * rejecting new incoming streams.
 */
NGHTTP2_EXTERN void nghttp2_conn_shutdown(nghttp2_conn *conn);

/**
 * @function
 *
 * `nghttp2_conn_terminate` shutdowns the connection abruptly with the
 * given |error_code|.  After calling this function,
 * `nghttp2_conn_read` discards all incoming data.  Close the
 * underlying connection after `nghttp2_conn_write` returns
 * :macro:`NGHTTP2_ERR_CLOSING`.
 */
NGHTTP2_EXTERN void nghttp2_conn_terminate(nghttp2_conn *conn,
                                           uint32_t error_code);

/**
 * @macrosection
 *
 * HTTP stream priority flags
 */

/**
 * @macro
 *
 * :macro:`NGHTTP2_DEFAULT_URGENCY` is the default urgency level.
 */
#define NGHTTP2_DEFAULT_URGENCY 3

/**
 * @macro
 *
 * :macro:`NGHTTP2_URGENCY_HIGH` is the highest urgency level.
 */
#define NGHTTP2_URGENCY_HIGH 0

/**
 * @macro
 *
 * :macro:`NGHTTP2_URGENCY_LOW` is the lowest urgency level.
 */
#define NGHTTP2_URGENCY_LOW 7

/**
 * @macro
 *
 * :macro:`NGHTTP2_URGENCY_LEVELS` is the number of urgency levels.
 */
#define NGHTTP2_URGENCY_LEVELS (NGHTTP2_URGENCY_LOW + 1)

/**
 * @struct
 *
 * :type:`nghttp2_pri` represents HTTP priority.
 */
typedef struct NGHTTP2_ALIGN(8) nghttp2_pri {
  /**
   * :member:`urgency` is the urgency of a stream, it must be in
   * [:macro:`NGHTTP2_URGENCY_HIGH`, :macro:`NGHTTP2_URGENCY_LOW`],
   * inclusive, and 0 is the highest urgency.
   */
  uint32_t urgency;
  /**
   * :member:`inc` indicates that a content can be processed
   * incrementally or not.  If it is 0, it cannot be processed
   * incrementally.  If it is 1, it can be processed incrementally.
   * Other value is not permitted.
   */
  uint8_t inc;
} nghttp2_pri;

/**
 * @function
 *
 * `nghttp2_pri_parse_priority` parses Priority header field value
 * pointed by |value| of length |len|, and stores the result in the
 * object pointed by |dest|.  Priority header field is defined in
 * :rfc:`9218`.
 *
 * This function does not initialize the object pointed by |dest|
 * before storing the result.  It only assigns the values that the
 * parser correctly extracted to fields.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     Failed to parse the header field value.
 */
NGHTTP2_EXTERN int nghttp2_pri_parse_priority(nghttp2_pri *dest,
                                              const uint8_t *value, size_t len);

/**
 * @function
 *
 * `nghttp2_conn_get_stream_priority` stores stream priority of a
 * stream denoted by |stream_id| into |*dest|.  Only server can use
 * this function.
 *
 * This function must not be called if |conn| is initialized as
 * client.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NGHTTP2_ERR_STREAM_NOT_FOUND`
 *     Stream not found.
 */
NGHTTP2_EXTERN int nghttp2_conn_get_stream_priority(const nghttp2_conn *conn,
                                                    nghttp2_pri *dest,
                                                    int64_t stream_id);

/**
 * @function
 *
 * `nghttp2_conn_set_client_stream_priority` updates priority of a
 * stream denoted by |stream_id| with the value pointed by |data| of
 * length |datalen|, which should be a serialized :rfc:`9218` priority
 * field value.
 *
 * This function must not be called if |conn| is initialized as
 * server.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_conn_set_client_stream_priority(nghttp2_conn *conn,
                                                           int64_t stream_id,
                                                           const uint8_t *data,
                                                           size_t datalen);

/**
 * @function
 *
 * `nghttp2_conn_set_server_stream_priority` updates priority of a
 * stream denoted by |stream_id| with the value pointed by |pri|.
 *
 * This function must not be called if |conn| is initialized as
 * client.
 *
 * This function completely overrides stream priority set by client,
 * and any attempts to update priority by client are ignored.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int
nghttp2_conn_set_server_stream_priority(nghttp2_conn *conn, int64_t stream_id,
                                        const nghttp2_pri *pri);

/**
 * @function
 *
 * `nghttp2_check_header_name` returns nonzero if HTTP field name
 * |name| of length |len| is valid according to
 * :rfc:`7230#section-3.2`.
 *
 * Because this is an HTTP field name in HTTP/2, the upper cased
 * alphabet is treated as error.
 */
NGHTTP2_EXTERN int nghttp2_check_header_name(const uint8_t *name, size_t len);

/**
 * @function
 *
 * `nghttp2_check_header_value` returns nonzero if HTTP field value
 * |value| of length |len| is valid according to
 * :rfc:`7230#section-3.2`.
 */
NGHTTP2_EXTERN int nghttp2_check_header_value(const uint8_t *value, size_t len);

/* TODO: Add HPACK public API here */

#ifdef _MSC_VER
#  pragma warning(pop)
#endif /* defined(_MSC_VER) */

#ifdef __cplusplus
}
#endif /* defined(__cplusplus) */

#endif /* !defined(NGHTTP2_H) */
