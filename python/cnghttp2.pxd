# nghttp2 - HTTP/2 C Library

# Copyright (c) 2013 Tatsuhiro Tsujikawa

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
from libc.stdint cimport uint8_t, uint16_t, uint32_t, int32_t

cdef extern from 'nghttp2/nghttp2.h':

    const char NGHTTP2_PROTO_VERSION_ID[]
    const char NGHTTP2_CLIENT_CONNECTION_PREFACE[]
    const size_t NGHTTP2_INITIAL_WINDOW_SIZE
    const size_t NGHTTP2_DEFAULT_HEADER_TABLE_SIZE

    ctypedef struct nghttp2_session:
        pass

    ctypedef enum nghttp2_error:
        NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE
        NGHTTP2_ERR_DEFERRED

    ctypedef enum nghttp2_flag:
        NGHTTP2_FLAG_NONE
        NGHTTP2_FLAG_END_STREAM
        NGHTTP2_FLAG_ACK

    ctypedef enum nghttp2_error_code:
        NGHTTP2_NO_ERROR
        NGHTTP2_PROTOCOL_ERROR
        NGHTTP2_INTERNAL_ERROR
        NGHTTP2_SETTINGS_TIMEOUT

    ctypedef enum nghttp2_frame_type:
        NGHTTP2_DATA
        NGHTTP2_HEADERS
        NGHTTP2_RST_STREAM
        NGHTTP2_SETTINGS
        NGHTTP2_PUSH_PROMISE
        NGHTTP2_GOAWAY

    ctypedef enum nghttp2_nv_flag:
        NGHTTP2_NV_FLAG_NONE
        NGHTTP2_NV_FLAG_NO_INDEX

    ctypedef struct nghttp2_nv:
        uint8_t *name
        uint8_t *value
        uint16_t namelen
        uint16_t valuelen
        uint8_t flags

    ctypedef enum nghttp2_settings_id:
        SETTINGS_HEADER_TABLE_SIZE
        NGHTTP2_SETTINGS_HEADER_TABLE_SIZE
        NGHTTP2_SETTINGS_ENABLE_PUSH
        NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS
        NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE

    ctypedef struct nghttp2_settings_entry:
        int32_t settings_id
        uint32_t value

    ctypedef struct nghttp2_frame_hd:
        size_t length
        int32_t stream_id
        uint8_t type
        uint8_t flags

    ctypedef struct nghttp2_data:
        nghttp2_frame_hd hd
        size_t padlen

    ctypedef enum nghttp2_headers_category:
        NGHTTP2_HCAT_REQUEST
        NGHTTP2_HCAT_RESPONSE
        NGHTTP2_HCAT_PUSH_RESPONSE
        NGHTTP2_HCAT_HEADERS

    ctypedef struct nghttp2_headers:
        nghttp2_frame_hd hd
        size_t padlen
        nghttp2_nv *nva
        size_t nvlen
        nghttp2_headers_category cat
        int32_t pri

    ctypedef struct nghttp2_rst_stream:
        nghttp2_frame_hd hd
        uint32_t error_code


    ctypedef struct nghttp2_push_promise:
        nghttp2_frame_hd hd
        nghttp2_nv *nva
        size_t nvlen
        int32_t promised_stream_id

    ctypedef struct nghttp2_goaway:
        nghttp2_frame_hd hd
        int32_t last_stream_id
        uint32_t error_code
        uint8_t *opaque_data
        size_t opaque_data_len

    ctypedef union nghttp2_frame:
        nghttp2_frame_hd hd
        nghttp2_data data
        nghttp2_headers headers
        nghttp2_rst_stream rst_stream
        nghttp2_push_promise push_promise
        nghttp2_goaway goaway

    ctypedef ssize_t (*nghttp2_send_callback)\
        (nghttp2_session *session, const uint8_t *data, size_t length,
         int flags, void *user_data)

    ctypedef int (*nghttp2_on_frame_recv_callback)\
        (nghttp2_session *session, const nghttp2_frame *frame, void *user_data)

    ctypedef int (*nghttp2_on_data_chunk_recv_callback)\
        (nghttp2_session *session, uint8_t flags, int32_t stream_id,
         const uint8_t *data, size_t length, void *user_data)

    ctypedef int (*nghttp2_before_frame_send_callback)\
        (nghttp2_session *session, const nghttp2_frame *frame, void *user_data)

    ctypedef int (*nghttp2_on_stream_close_callback)\
        (nghttp2_session *session, int32_t stream_id,
         uint32_t error_code, void *user_data)

    ctypedef int (*nghttp2_on_begin_headers_callback)\
        (nghttp2_session *session, const nghttp2_frame *frame, void *user_data)

    ctypedef int (*nghttp2_on_header_callback)\
        (nghttp2_session *session,
         const nghttp2_frame *frame,
         const uint8_t *name, size_t namelen,
         const uint8_t *value, size_t valuelen,
         uint8_t flags,
         void *user_data)

    ctypedef int (*nghttp2_on_frame_send_callback)\
        (nghttp2_session *session, const nghttp2_frame *frame, void *user_data)

    ctypedef int (*nghttp2_on_frame_not_send_callback)\
        (nghttp2_session *session, const nghttp2_frame *frame,
         int lib_error_code, void *user_data)

    ctypedef struct nghttp2_session_callbacks:
        pass

    int nghttp2_session_callbacks_new(
        nghttp2_session_callbacks **callbacks_ptr)

    void nghttp2_session_callbacks_del(nghttp2_session_callbacks *callbacks)

    void nghttp2_session_callbacks_set_send_callback(
        nghttp2_session_callbacks *cbs, nghttp2_send_callback send_callback)

    void nghttp2_session_callbacks_set_on_frame_recv_callback(
        nghttp2_session_callbacks *cbs,
        nghttp2_on_frame_recv_callback on_frame_recv_callback)

    void nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        nghttp2_session_callbacks *cbs,
        nghttp2_on_data_chunk_recv_callback on_data_chunk_recv_callback)

    void nghttp2_session_callbacks_set_before_frame_send_callback(
        nghttp2_session_callbacks *cbs,
        nghttp2_before_frame_send_callback before_frame_send_callback)

    void nghttp2_session_callbacks_set_on_frame_send_callback(
        nghttp2_session_callbacks *cbs,
        nghttp2_on_frame_send_callback on_frame_send_callback)

    void nghttp2_session_callbacks_set_on_frame_not_send_callback(
        nghttp2_session_callbacks *cbs,
        nghttp2_on_frame_not_send_callback on_frame_not_send_callback)

    void nghttp2_session_callbacks_set_on_stream_close_callback(
        nghttp2_session_callbacks *cbs,
        nghttp2_on_stream_close_callback on_stream_close_callback)

    void nghttp2_session_callbacks_set_on_begin_headers_callback(
        nghttp2_session_callbacks *cbs,
        nghttp2_on_begin_headers_callback on_begin_headers_callback)

    void nghttp2_session_callbacks_set_on_header_callback(
        nghttp2_session_callbacks *cbs,
        nghttp2_on_header_callback on_header_callback)

    int nghttp2_session_client_new(nghttp2_session **session_ptr,
                                   const nghttp2_session_callbacks *callbacks,
                                   void *user_data)

    int nghttp2_session_server_new(nghttp2_session **session_ptr,
                                   const nghttp2_session_callbacks *callbacks,
                                   void *user_data)

    void nghttp2_session_del(nghttp2_session *session)


    ssize_t nghttp2_session_mem_recv(nghttp2_session *session,
                                     const uint8_t *data, size_t datalen)

    ssize_t nghttp2_session_mem_send(nghttp2_session *session,
                                     const uint8_t **data_ptr)

    int nghttp2_session_send(nghttp2_session *session)

    int nghttp2_session_want_read(nghttp2_session *session)

    int nghttp2_session_want_write(nghttp2_session *session)

    ctypedef union nghttp2_data_source:
        int fd
        void *ptr

    ctypedef enum nghttp2_data_flag:
        NGHTTP2_DATA_FLAG_NONE
        NGHTTP2_DATA_FLAG_EOF

    ctypedef ssize_t (*nghttp2_data_source_read_callback)\
        (nghttp2_session *session, int32_t stream_id,
         uint8_t *buf, size_t length, uint32_t *data_flags,
         nghttp2_data_source *source, void *user_data)

    ctypedef struct nghttp2_data_provider:
        nghttp2_data_source source
        nghttp2_data_source_read_callback read_callback

    ctypedef struct nghttp2_priority_spec:
        int32_t stream_id
        int32_t weight
        uint8_t exclusive

    int nghttp2_submit_request(nghttp2_session *session, const nghttp2_priority_spec *pri_spec,
                               const nghttp2_nv *nva, size_t nvlen,
                               const nghttp2_data_provider *data_prd,
                               void *stream_user_data)

    int nghttp2_submit_response(nghttp2_session *session,
                                int32_t stream_id,
                                const nghttp2_nv *nva, size_t nvlen,
                                const nghttp2_data_provider *data_prd)

    int nghttp2_submit_push_promise(nghttp2_session *session, uint8_t flags,
                                    int32_t stream_id,
                                    const nghttp2_nv *nva, size_t nvlen,
                                    void *stream_user_data)

    int nghttp2_submit_settings(nghttp2_session *session, uint8_t flags,
                                const nghttp2_settings_entry *iv, size_t niv)

    int nghttp2_submit_rst_stream(nghttp2_session *session, uint8_t flags,
                                  int32_t stream_id,
                                  uint32_t error_code)

    void* nghttp2_session_get_stream_user_data(nghttp2_session *session,
                                               uint32_t stream_id)

    int nghttp2_session_set_stream_user_data(nghttp2_session *session,
                                             uint32_t stream_id,
                                             void *stream_user_data)

    int nghttp2_session_terminate_session(nghttp2_session *session,
                                          uint32_t error_code)

    int nghttp2_session_resume_data(nghttp2_session *session,
                                    int32_t stream_id)

    const char* nghttp2_strerror(int lib_error_code)

    int nghttp2_session_check_server_session(nghttp2_session *session)

    int nghttp2_session_get_stream_remote_close(nghttp2_session *session, int32_t stream_id)

    int nghttp2_hd_deflate_new(nghttp2_hd_deflater **deflater_ptr,
                               size_t deflate_hd_table_bufsize_max)

    void nghttp2_hd_deflate_del(nghttp2_hd_deflater *deflater)

    int nghttp2_hd_deflate_change_table_size(nghttp2_hd_deflater *deflater,
                                             size_t hd_table_bufsize_max)

    ssize_t nghttp2_hd_deflate_hd(nghttp2_hd_deflater *deflater,
                                  uint8_t *buf, size_t buflen,
                                  const nghttp2_nv *nva, size_t nvlen)

    size_t nghttp2_hd_deflate_bound(nghttp2_hd_deflater *deflater,
                                    const nghttp2_nv *nva, size_t nvlen)

    int nghttp2_hd_inflate_new(nghttp2_hd_inflater **inflater_ptr)

    void nghttp2_hd_inflate_del(nghttp2_hd_inflater *inflater)

    int nghttp2_hd_inflate_change_table_size(nghttp2_hd_inflater *inflater,
                                             size_t hd_table_bufsize_max)

    ssize_t nghttp2_hd_inflate_hd2(nghttp2_hd_inflater *inflater,
                                   nghttp2_nv *nv_out, int *inflate_flags,
                                   const uint8_t *input, size_t inlen,
                                   int in_final)

    int nghttp2_hd_inflate_end_headers(nghttp2_hd_inflater *inflater)

    ctypedef enum nghttp2_hd_inflate_flag:
        NGHTTP2_HD_INFLATE_EMIT
        NGHTTP2_HD_INFLATE_FINAL

    ctypedef struct nghttp2_hd_deflater:
        pass

    ctypedef struct nghttp2_hd_inflater:
        pass

    size_t nghttp2_hd_deflate_get_num_table_entries(nghttp2_hd_deflater *deflater)

    const nghttp2_nv * nghttp2_hd_deflate_get_table_entry(nghttp2_hd_deflater *deflater, size_t idx)

    size_t nghttp2_hd_inflate_get_num_table_entries(nghttp2_hd_inflater *inflater)

    const nghttp2_nv *nghttp2_hd_inflate_get_table_entry(nghttp2_hd_inflater *inflater, size_t idx)
