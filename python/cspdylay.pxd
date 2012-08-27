from libc.stdint cimport uint8_t, uint16_t, uint32_t, int32_t

cdef extern from 'spdylay/spdylay.h':

    ctypedef enum spdylay_proto_version:
        SPDYLAY_PROTO_SPDY2
        SPDYLAY_PROTO_SPDY3

    ctypedef enum spdylay_error:
        SPDYLAY_ERR_INVALID_ARGUMENT
        SPDYLAY_ERR_ZLIB
        SPDYLAY_ERR_UNSUPPORTED_VERSION
        SPDYLAY_ERR_WOULDBLOCK
        SPDYLAY_ERR_PROTO
        SPDYLAY_ERR_INVALID_FRAME
        SPDYLAY_ERR_EOF
        SPDYLAY_ERR_DEFERRED
        SPDYLAY_ERR_STREAM_ID_NOT_AVAILABLE
        SPDYLAY_ERR_STREAM_CLOSED
        SPDYLAY_ERR_STREAM_CLOSING
        SPDYLAY_ERR_STREAM_SHUT_WR
        SPDYLAY_ERR_INVALID_STREAM_ID
        SPDYLAY_ERR_INVALID_STREAM_STATE
        SPDYLAY_ERR_DEFERRED_DATA_EXIST
        SPDYLAY_ERR_SYN_STREAM_NOT_ALLOWED
        SPDYLAY_ERR_GOAWAY_ALREADY_SENT
        SPDYLAY_ERR_INVALID_HEADER_BLOCK
        SPDYLAY_ERR_INVALID_STATE
        SPDYLAY_ERR_GZIP
        SPDYLAY_ERR_TEMPORAL_CALLBACK_FAILURE
        SPDYLAY_ERR_FATAL
        SPDYLAY_ERR_NOMEM
        SPDYLAY_ERR_CALLBACK_FAILURE

    ctypedef enum spdylay_ctrl_flag:
        SPDYLAY_CTRL_FLAG_NONE
        SPDYLAY_CTRL_FLAG_FIN
        SPDYLAY_CTRL_FLAG_UNIDIRECTIONAL

    ctypedef enum spdylay_data_flag:
        SPDYLAY_DATA_FLAG_NONE
        SPDYLAY_DATA_FLAG_FIN

    ctypedef enum spdylay_frame_type:
        SPDYLAY_SYN_STREAM
        SPDYLAY_SYN_REPLY
        SPDYLAY_RST_STREAM
        SPDYLAY_SETTINGS
        SPDYLAY_NOOP
        SPDYLAY_PING
        SPDYLAY_GOAWAY
        SPDYLAY_HEADERS
        SPDYLAY_WINDOW_UPDATE
        SPDYLAY_CREDENTIAL

    ctypedef enum spdylay_status_code:
        SPDYLAY_OK
        SPDYLAY_PROTOCOL_ERROR
        SPDYLAY_INVALID_STREAM
        SPDYLAY_REFUSED_STREAM
        SPDYLAY_UNSUPPORTED_VERSION
        SPDYLAY_CANCEL
        SPDYLAY_INTERNAL_ERROR
        SPDYLAY_FLOW_CONTROL_ERROR
        # Following status codes were introduced in SPDY/3
        SPDYLAY_STREAM_IN_USE
        SPDYLAY_STREAM_ALREADY_CLOSED
        SPDYLAY_INVALID_CREDENTIALS
        SPDYLAY_FRAME_TOO_LARGE

    # The status codes for GOAWAY, introduced in SPDY/3.
    ctypedef enum spdylay_goaway_status_code:
        SPDYLAY_GOAWAY_OK
        SPDYLAY_GOAWAY_PROTOCOL_ERROR
        SPDYLAY_GOAWAY_INTERNAL_ERROR

    ctypedef enum spdylay_settings_flag:
        SPDYLAY_FLAG_SETTINGS_NONE
        SPDYLAY_FLAG_SETTINGS_CLEAR_SETTINGS

    ctypedef enum spdylay_settings_id_flag:
        SPDYLAY_ID_FLAG_SETTINGS_NONE
        SPDYLAY_ID_FLAG_SETTINGS_PERSIST_VALUE
        SPDYLAY_ID_FLAG_SETTINGS_PERSISTED

    ctypedef enum spdylay_settings_id:
        SPDYLAY_SETTINGS_UPLOAD_BANDWIDTH
        SPDYLAY_SETTINGS_DOWNLOAD_BANDWIDTH
        SPDYLAY_SETTINGS_ROUND_TRIP_TIME
        SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS
        SPDYLAY_SETTINGS_CURRENT_CWND
        SPDYLAY_SETTINGS_DOWNLOAD_RETRANS_RATE
        SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE
        SPDYLAY_SETTINGS_CLIENT_CERTIFICATE_VECTOR_SIZE
        SPDYLAY_SETTINGS_MAX

    ctypedef struct spdylay_ctrl_hd:
        uint16_t version
        uint16_t type
        uint8_t flags
        int32_t length

    ctypedef struct spdylay_syn_stream:
        spdylay_ctrl_hd hd
        int32_t stream_id
        int32_t assoc_stream_id
        uint8_t pri
        uint8_t slot
        char **nv

    ctypedef struct spdylay_syn_reply:
        spdylay_ctrl_hd hd
        int32_t stream_id
        char **nv

    ctypedef struct spdylay_headers:
        spdylay_ctrl_hd hd
        int32_t stream_id
        char **nv

    ctypedef struct spdylay_rst_stream:
        spdylay_ctrl_hd hd
        int32_t stream_id
        uint32_t status_code

    ctypedef struct spdylay_settings_entry:
        int32_t settings_id
        uint8_t flags
        uint32_t value

    ctypedef struct spdylay_settings:
        spdylay_ctrl_hd hd
        size_t niv
        spdylay_settings_entry *iv

    ctypedef struct spdylay_ping:
        spdylay_ctrl_hd hd
        uint32_t unique_id

    ctypedef struct spdylay_goaway:
        spdylay_ctrl_hd hd
        int32_t last_good_stream_id
        uint32_t status_code

    ctypedef struct spdylay_window_update:
        spdylay_ctrl_hd hd
        int32_t stream_id
        int32_t delta_window_size

    ctypedef union spdylay_frame:
        spdylay_syn_stream syn_stream
        spdylay_syn_reply syn_reply
        spdylay_rst_stream rst_stream
        spdylay_settings settings
        spdylay_ping ping
        spdylay_goaway goaway
        spdylay_headers headers
        spdylay_window_update window_update
        #spdylay_credential credential

    ctypedef union spdylay_data_source:
        int fd
        void *ptr

    ctypedef ssize_t (*spdylay_data_source_read_callback)\
        (spdylay_session *session, int32_t stream_id,
         uint8_t *buf, size_t length, int *eof,
         spdylay_data_source *source, void *user_data)

    ctypedef struct spdylay_data_provider:
        spdylay_data_source source
        spdylay_data_source_read_callback read_callback

    ctypedef struct spdylay_session:
        pass


    ctypedef ssize_t (*spdylay_send_callback)\
        (spdylay_session *session,
         uint8_t *data, size_t length, int flags, void *user_data)

    ctypedef ssize_t (*spdylay_recv_callback)\
        (spdylay_session *session,
         uint8_t *buf, size_t length, int flags, void *user_data)

    ctypedef void (*spdylay_on_ctrl_recv_callback)\
        (spdylay_session *session, spdylay_frame_type frame_type,
         spdylay_frame *frame, void *user_data)

    ctypedef void (*spdylay_on_invalid_ctrl_recv_callback)\
        (spdylay_session *session, spdylay_frame_type type,
         spdylay_frame *frame, uint32_t status_code, void *user_data)

    ctypedef void (*spdylay_on_data_chunk_recv_callback)\
        (spdylay_session *session, uint8_t flags, int32_t stream_id,
         uint8_t *data, size_t len, void *user_data)

    ctypedef void (*spdylay_on_data_recv_callback)\
        (spdylay_session *session, uint8_t flags, int32_t stream_id,
         int32_t length, void *user_data)

    ctypedef void (*spdylay_before_ctrl_send_callback)\
        (spdylay_session *session, spdylay_frame_type type,
         spdylay_frame *frame, void *user_data)

    ctypedef void (*spdylay_on_ctrl_send_callback)\
        (spdylay_session *session, spdylay_frame_type type,
         spdylay_frame *frame, void *user_data)

    ctypedef void (*spdylay_on_ctrl_not_send_callback)\
        (spdylay_session *session, spdylay_frame_type type,
         spdylay_frame *frame, int error_code, void *user_data)

    ctypedef void (*spdylay_on_data_send_callback)\
        (spdylay_session *session, uint8_t flags, int32_t stream_id,
         int32_t length, void *user_data)

    ctypedef void (*spdylay_on_stream_close_callback)\
        (spdylay_session *session, int32_t stream_id,
         spdylay_status_code status_code, void *user_data)

    ctypedef void (*spdylay_on_request_recv_callback)\
        (spdylay_session *session, int32_t stream_id, void *user_data)

    ctypedef void (*spdylay_on_ctrl_recv_parse_error_callback)\
        (spdylay_session *session, spdylay_frame_type type,
         uint8_t *head, size_t headlen, uint8_t *payload, size_t payloadlen,
         int error_code, void *user_data)

    ctypedef void (*spdylay_on_unknown_ctrl_recv_callback)\
        (spdylay_session *session, uint8_t *head, size_t headlen,
         uint8_t *payload, size_t payloadlen, void *user_data)

    ctypedef struct spdylay_session_callbacks:
        spdylay_send_callback send_callback
        spdylay_recv_callback recv_callback
        spdylay_on_ctrl_recv_callback on_ctrl_recv_callback
        spdylay_on_invalid_ctrl_recv_callback on_invalid_ctrl_recv_callback
        spdylay_on_data_chunk_recv_callback on_data_chunk_recv_callback
        spdylay_on_data_recv_callback on_data_recv_callback
        spdylay_before_ctrl_send_callback before_ctrl_send_callback
        spdylay_on_ctrl_send_callback on_ctrl_send_callback
        spdylay_on_ctrl_not_send_callback on_ctrl_not_send_callback
        spdylay_on_data_send_callback on_data_send_callback
        spdylay_on_stream_close_callback on_stream_close_callback
        spdylay_on_request_recv_callback on_request_recv_callback
        spdylay_on_ctrl_recv_parse_error_callback \
            on_ctrl_recv_parse_error_callback
        spdylay_on_unknown_ctrl_recv_callback on_unknown_ctrl_recv_callback

    int spdylay_session_client_new(spdylay_session **session_ptr,
                                   int version,
                                   spdylay_session_callbacks *callbacks,
                                   void *user_data)

    int spdylay_session_server_new(spdylay_session **session_ptr,
                                   int version,
                                   spdylay_session_callbacks *callbacks,
                                   void *user_data)

    void spdylay_session_del(spdylay_session *session)


    int spdylay_session_recv(spdylay_session *session)

    ssize_t spdylay_session_mem_recv(spdylay_session *session,
                                     uint8_t *data, size_t length)

    int spdylay_session_send(spdylay_session *session)

    int spdylay_session_resume_data(spdylay_session *session,
                                    int32_t stream_id)

    bint spdylay_session_want_read(spdylay_session *session)

    bint spdylay_session_want_write(spdylay_session *session)

    void* spdylay_session_get_stream_user_data(spdylay_session *session,
                                               int32_t stream_id)

    size_t spdylay_session_get_outbound_queue_size(spdylay_session *session)

    uint8_t spdylay_session_get_pri_lowest(spdylay_session *session)

    int spdylay_session_fail_session(spdylay_session *session,
                                     uint32_t status_code)

    char* spdylay_strerror(int error_code)

    int spdylay_submit_request(spdylay_session *session, uint8_t pri,
                               char **nv,
                               spdylay_data_provider *data_prd,
                               void *stream_user_data)

    int spdylay_submit_response(spdylay_session *session,
                                int32_t stream_id, char **nv,
                                spdylay_data_provider *data_prd)

    int spdylay_submit_syn_stream(spdylay_session *session, uint8_t flags,
                                  int32_t assoc_stream_id, uint8_t pri,
                                  char **nv, void *stream_user_data)

    int spdylay_submit_syn_reply(spdylay_session *session, uint8_t flags,
                                 int32_t stream_id, char **nv)

    int spdylay_submit_headers(spdylay_session *session, uint8_t flags,
                               int32_t stream_id, char **nv)

    int spdylay_submit_data(spdylay_session *session, int32_t stream_id,
                            uint8_t flags, spdylay_data_provider *data_prd)

    int spdylay_submit_rst_stream(spdylay_session *session,
                                  int32_t stream_id, uint32_t status_code)

    int spdylay_submit_ping(spdylay_session *session)

    int spdylay_submit_goaway(spdylay_session *session, uint32_t status_code)

    int spdylay_submit_settings(spdylay_session *session, uint8_t flags,
                                spdylay_settings_entry *iv, size_t niv)

    int spdylay_submit_window_update(spdylay_session *session,
                                     int32_t stream_id,
                                     int32_t delta_window_size)

    ctypedef struct spdylay_npn_proto:
        unsigned char *proto
        uint8_t len
        uint16_t version

    spdylay_npn_proto* spdylay_npn_get_proto_list(size_t *len_ptr)

    uint16_t spdylay_npn_get_version(unsigned char *proto,
                                     size_t protolen)
