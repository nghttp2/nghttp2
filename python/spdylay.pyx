cimport cspdylay

from libc.stdlib cimport malloc, free
from libc.string cimport memcpy, memset
from libc.stdint cimport uint8_t, uint16_t, uint32_t, int32_t

# Also update version in setup.py
__version__ = '0.1.2'

class EOFError(Exception):
    pass

class CallbackFailureError(Exception):
    pass

class TemporalCallbackFailureError(Exception):
    pass

class InvalidArgumentError(Exception):
    pass

class ZlibError(Exception):
    pass

class UnsupportedVersionError(Exception):
    pass

class StreamClosedError(Exception):
    pass

class DataProvider:
    def __init__(self, source, read_cb):
        self.source = source
        self.read_cb = read_cb

cdef class CtrlFrame:
    cdef uint16_t version
    cdef uint16_t frame_type
    cdef uint8_t flags
    cdef int32_t length

    cdef void fillhd(self, cspdylay.spdylay_ctrl_hd *hd):
        self.version = hd.version
        self.frame_type = hd.type
        self.flags = hd.flags
        self.length = hd.length

    property version:
        def __get__(self):
            return self.version

    property frame_type:
        def __get__(self):
            return self.frame_type

    property flags:
        def __get__(self):
            return self.flags

    property length:
        def __get__(self):
            return self.length

cdef class SynStreamFrame(CtrlFrame):
    cdef int32_t stream_id
    cdef int32_t assoc_stream_id
    cdef uint8_t pri
    cdef uint8_t slot
    cdef object nv

    cdef fill(self, cspdylay.spdylay_syn_stream *frame):
        self.fillhd(&frame.hd)

        self.stream_id = frame.stream_id
        self.assoc_stream_id = frame.assoc_stream_id
        self.pri = frame.pri
        self.slot = frame.slot
        self.nv = cnv2pynv(frame.nv)

    property stream_id:
        def __get__(self):
            return self.stream_id

    property assoc_stream_id:
        def __get__(self):
            return self.assoc_stream_id

    property pri:
        def __get__(self):
            return self.pri

    property nv:
        def __get__(self):
            return self.nv

cdef class SynReplyFrame(CtrlFrame):
    cdef int32_t stream_id
    cdef object nv

    cdef fill(self, cspdylay.spdylay_syn_reply *frame):
        self.fillhd(&frame.hd)

        self.stream_id = frame.stream_id
        self.nv = cnv2pynv(frame.nv)

    property stream_id:
        def __get__(self):
            return self.stream_id
    property nv:
        def __get__(self):
            return self.nv

cdef class HeadersFrame(CtrlFrame):
    cdef int32_t stream_id
    cdef object nv

    cdef fill(self, cspdylay.spdylay_headers *frame):
        self.fillhd(&frame.hd)

        self.stream_id = frame.stream_id
        self.nv = cnv2pynv(frame.nv)

    property stream_id:
        def __get__(self):
            return self.stream_id

    property nv:
        def __get__(self):
            return self.nv

cdef class RstStreamFrame(CtrlFrame):
    cdef int32_t stream_id
    cdef uint32_t status_code

    cdef fill(self, cspdylay.spdylay_rst_stream *frame):
        self.fillhd(&frame.hd)

        self.stream_id = frame.stream_id
        self.status_code = frame.status_code

    property stream_id:
        def __get__(self):
            return self.stream_id

    property status_code:
        def __get__(self):
            return self.status_code

cdef class SettingsFrame(CtrlFrame):
    cdef object iv

    cdef fill(self, cspdylay.spdylay_settings *frame):
        self.fillhd(&frame.hd)

        self.iv = csettings2pysettings(frame.niv, frame.iv)


    property iv:
        def __get__(self):
            return self.iv

cdef class PingFrame(CtrlFrame):
    cdef uint32_t unique_id

    cdef fill(self, cspdylay.spdylay_ping *frame):
        self.fillhd(&frame.hd)

        self.unique_id = frame.unique_id

    property unique_id:
        def __get__(self):
            return self.unique_id

cdef class GoawayFrame(CtrlFrame):
    cdef int32_t last_good_stream_id
    cdef uint32_t status_code

    cdef fill(self, cspdylay.spdylay_goaway *frame):
        self.fillhd(&frame.hd)

        self.last_good_stream_id = frame.last_good_stream_id
        self.status_code = frame.status_code

    property last_good_stream_id:
        def __get__(self):
            return self.last_good_stream_id

    property status_code:
        def __get__(self):
            return self.status_code

cdef class WindowUpdateFrame(CtrlFrame):
    cdef int32_t stream_id
    cdef int32_t delta_window_size

    cdef fill(self, cspdylay.spdylay_window_update *frame):
        self.fillhd(&frame.hd)

        self.stream_id = frame.stream_id
        self.delta_window_size = frame.delta_window_size

    property stream_id:
        def __get__(self):
            return self.stream_id

    property delta_window_size:
        def __get__(self):
            return self.delta_window_size

cdef cnv2pynv(char **nv):
    ''' Convert C-style name/value pairs ``nv`` to Python style
    pairs. We assume that strings in nv is UTF-8 encoded as per SPDY
    spec. In Python pairs, we use unicode string.'''
    cdef size_t i
    pynv = []
    i = 0
    while nv[i] != NULL:
        pynv.append((nv[i].decode('UTF-8'), nv[i+1].decode('UTF-8')))
        i += 2
    return pynv

cdef char** pynv2cnv(object nv) except *:
    ''' Convert Python style UTF-8 name/value pairs ``nv`` to C-style
    pairs. Python style name/value pairs are list of tuple (key,
    value).'''
    cdef char **cnv = <char**>malloc((len(nv)*2+1)*sizeof(char*))
    cdef size_t i
    if cnv == NULL:
        raise MemoryError()
    i = 0
    for n, v in nv:
        cnv[i] = n
        i += 1
        cnv[i] = v
        i += 1
    cnv[i] = NULL
    return cnv

cdef pynv_encode(nv):
    res = []
    for k, v in nv:
        res.append((k.encode('UTF-8'), v.encode('UTF-8')))
    return res

cdef object csettings2pysettings(size_t niv,
                                 cspdylay.spdylay_settings_entry *iv):
    cdef size_t i = 0
    cdef cspdylay.spdylay_settings_entry *ent
    res = []
    while i < niv:
        ent = &iv[i]
        res.append((ent.settings_id, ent.flags, ent.value))
        i += 1
    return res

cdef cspdylay.spdylay_settings_entry* pysettings2csettings(object iv) except *:
    cdef size_t i
    cdef cspdylay.spdylay_settings_entry *civ =\
        <cspdylay.spdylay_settings_entry*>malloc(\
        len(iv)*sizeof(cspdylay.spdylay_settings_entry))
    if civ == NULL:
        raise MemoryError()
    i = 0
    for settings_id, flags, value in iv:
        civ[i].settings_id = settings_id
        civ[i].flags = flags
        civ[i].value = value
        i += 1
    return civ

cdef cspdylay.spdylay_data_provider create_c_data_prd\
(cspdylay.spdylay_data_provider *cdata_prd, object pydata_prd):
    cdata_prd.source.ptr = <void*>pydata_prd
    cdata_prd.read_callback = read_callback


cdef object cframe2pyframe(cspdylay.spdylay_frame_type frame_type,
                           cspdylay.spdylay_frame *frame):
    cdef SynStreamFrame syn_stream
    cdef SynReplyFrame syn_reply
    cdef HeadersFrame headers
    cdef RstStreamFrame rst_stream
    cdef SettingsFrame settings
    cdef PingFrame ping
    cdef GoawayFrame goaway
    cdef WindowUpdateFrame window_update
    cdef object pyframe = None
    if frame_type == cspdylay.SPDYLAY_SYN_STREAM:
        syn_stream = SynStreamFrame()
        syn_stream.fill(&frame.syn_stream)
        pyframe = syn_stream
    elif frame_type == cspdylay.SPDYLAY_SYN_REPLY:
        syn_reply = SynReplyFrame()
        syn_reply.fill(&frame.syn_reply)
        pyframe = syn_reply
    elif frame_type == cspdylay.SPDYLAY_HEADERS:
        headers = HeadersFrame()
        headers.fill(&frame.headers)
        pyframe = headers
    elif frame_type == cspdylay.SPDYLAY_RST_STREAM:
        rst_stream = RstStreamFrame()
        rst_stream.fill(&frame.rst_stream)
        pyframe = rst_stream
    elif frame_type == cspdylay.SPDYLAY_SETTINGS:
        settings = SettingsFrame()
        settings.fill(&frame.settings)
        pyframe = settings
    elif frame_type == cspdylay.SPDYLAY_PING:
        ping = PingFrame()
        ping.fill(&frame.ping)
        pyframe = ping
    elif frame_type == cspdylay.SPDYLAY_GOAWAY:
        goaway = GoawayFrame()
        goaway.fill(&frame.goaway)
        pyframe = goaway
    elif frame_type == cspdylay.SPDYLAY_WINDOW_UPDATE:
        window_update = WindowUpdateFrame()
        window_update.fill(&frame.window_update)
        pyframe = window_update
    return pyframe

cdef void _call_frame_callback(Session pysession,
                               cspdylay.spdylay_frame_type frame_type,
                               cspdylay.spdylay_frame *frame,
                               object callback):
    if not callback:
        return
    try:
        pyframe = cframe2pyframe(frame_type, frame)
        if pyframe:
            callback(pysession, pyframe)
    except Exception as e:
        pysession.error = e
    except BaseException as e:
        pysession.base_error = e

cdef void on_ctrl_recv_callback(cspdylay.spdylay_session *session,
                                cspdylay.spdylay_frame_type frame_type,
                                cspdylay.spdylay_frame *frame,
                                void *user_data):
    cdef Session pysession = <Session>user_data
    _call_frame_callback(pysession, frame_type, frame,
                         pysession.on_ctrl_recv_cb)

cdef void on_invalid_ctrl_recv_callback(cspdylay.spdylay_session *session,
                                        cspdylay.spdylay_frame_type frame_type,
                                        cspdylay.spdylay_frame *frame,
                                        uint32_t status_code,
                                        void *user_data):
    cdef Session pysession = <Session>user_data

    if not pysession.on_invalid_ctrl_recv_cb:
        return
    try:
        pyframe = cframe2pyframe(frame_type, frame)
        if pyframe:
            pysession.on_invalid_ctrl_recv_cb(pysession, pyframe, status_code)
    except Exception as e:
        pysession.error = e
    except BaseException as e:
        pysession.base_error = e

cdef void before_ctrl_send_callback(cspdylay.spdylay_session *session,
                                    cspdylay.spdylay_frame_type frame_type,
                                    cspdylay.spdylay_frame *frame,
                                    void *user_data):
    cdef Session pysession = <Session>user_data
    _call_frame_callback(pysession, frame_type, frame,
                         pysession.before_ctrl_send_cb)

cdef void on_ctrl_send_callback(cspdylay.spdylay_session *session,
                                cspdylay.spdylay_frame_type frame_type,
                                cspdylay.spdylay_frame *frame,
                                void *user_data):
    cdef Session pysession = <Session>user_data
    _call_frame_callback(pysession, frame_type, frame,
                         pysession.on_ctrl_send_cb)

cdef void on_ctrl_not_send_callback(cspdylay.spdylay_session *session,
                                    cspdylay.spdylay_frame_type frame_type,
                                    cspdylay.spdylay_frame *frame,
                                    int error_code,
                                    void *user_data):
    cdef Session pysession = <Session>user_data

    if not pysession.on_ctrl_not_send_cb:
        return
    try:
        pyframe = cframe2pyframe(frame_type, frame)
        if pyframe:
            pysession.on_ctrl_not_send_cb(pysession, pyframe, error_code)
    except Exception as e:
        pysession.error = e
    except BaseException as e:
        pysession.base_error = e

cdef void on_ctrl_recv_parse_error_callback(\
    cspdylay.spdylay_session *session,
    cspdylay.spdylay_frame_type frame_type,
    uint8_t *head, size_t headlen,
    uint8_t *payload, size_t payloadlen,
    int error_code, void *user_data):
    cdef Session pysession = <Session>user_data

    if not pysession.on_ctrl_recv_parse_error_cb:
        return
    try:
        pysession.on_ctrl_recv_parse_error_cb(pysession, frame_type,
                                              (<char*>head)[:headlen],
                                              (<char*>payload)[:payloadlen],
                                              error_code)
    except Exception as e:
        pysession.error = e
    except BaseException as e:
        pysession.base_error = e

cdef void on_unknown_ctrl_recv_callback(cspdylay.spdylay_session *session,
                                        uint8_t *head, size_t headlen,
                                        uint8_t *payload, size_t payloadlen,
                                        void *user_data):
    cdef Session pysession = <Session>user_data

    if not pysession.on_unknown_ctrl_recv_cb:
        return
    try:
        pysession.on_unknown_ctrl_recv_cb(pysession,
                                          (<char*>head)[:headlen],
                                          (<char*>payload)[:payloadlen])
    except Exception as e:
        pysession.error = e
    except BaseException as e:
        pysession.base_error = e

cdef ssize_t recv_callback(cspdylay.spdylay_session *session,
                           uint8_t *buf, size_t length,
                           int flags, void *user_data):
    cdef Session pysession = <Session>user_data
    if pysession.recv_callback:
        try:
            data = pysession.recv_callback(pysession, length)
        except EOFError as e:
            pysession.error = e
            return cspdylay.SPDYLAY_ERR_EOF
        except CallbackFailureError as e:
            pysession.error = e
            return cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE
        except Exception as e:
            pysession.error = e
            return cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE
        except BaseException as e:
            pysession.base_error = e
            return cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE
        if data:
            if len(data) > length:
                return cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE
            memcpy(buf, <char*>data, len(data))
            return len(data)
        else:
            return cspdylay.SPDYLAY_ERR_WOULDBLOCK
    else:
        return cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE

cdef ssize_t send_callback(cspdylay.spdylay_session *session,
                           uint8_t *data, size_t length, int flags,
                           void *user_data):
    cdef Session pysession = <Session>user_data
    if pysession.send_callback:
        try:
            rv = pysession.send_callback(pysession, (<char*>data)[:length])
        except CallbackFailureError as e:
            pysession.error = e
            return cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE
        except Exception as e:
            pysession.error = e
            return cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE
        except BaseException as e:
            pysession.base_error = e
            return cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE

        if rv:
            return rv
        else:
            return cspdylay.SPDYLAY_ERR_WOULDBLOCK
    else:
        # If no send_callback is given, pretend all data were sent and
        # just return length
        return length

cdef void on_data_chunk_recv_callback(cspdylay.spdylay_session *session,
                                      uint8_t flags, int32_t stream_id,
                                      uint8_t *data, size_t length,
                                      void *user_data):
    cdef Session pysession = <Session>user_data
    if pysession.on_data_chunk_recv_cb:
        try:
            pysession.on_data_chunk_recv_cb(pysession, flags, stream_id,
                                            (<char*>data)[:length])
        except Exception as e:
            pysession.error = e
        except BaseException as e:
            pysession.base_error = e

cdef void on_data_recv_callback(cspdylay.spdylay_session *session,
                                uint8_t flags, int32_t stream_id,
                                int32_t length, void *user_data):
    cdef Session pysession = <Session>user_data
    if pysession.on_data_recv_cb:
        try:
            pysession.on_data_recv_cb(pysession, flags, stream_id, length)
        except Exception as e:
            pysession.error = e
        except BaseException as e:
            pysession.base_error = e

cdef void on_data_send_callback(cspdylay.spdylay_session *session,
                                uint8_t flags, int32_t stream_id,
                                int32_t length, void *user_data):
    cdef Session pysession = <Session>user_data
    if pysession.on_data_send_cb:
        try:
            pysession.on_data_send_cb(pysession, flags, stream_id, length)
        except Exception as e:
            pysession.error = e
        except BaseException as e:
            pysession.base_error = e

cdef void on_stream_close_callback(cspdylay.spdylay_session *session,
                                   int32_t stream_id,
                                   cspdylay.spdylay_status_code status_code,
                                   void *user_data):
    cdef Session pysession = <Session>user_data
    if pysession.on_stream_close_cb:
        try:
            pysession.on_stream_close_cb(pysession, stream_id, status_code)
        except Exception as e:
            pysession.error = e
        except BaseException as e:
            pysession.base_error = e

cdef void on_request_recv_callback(cspdylay.spdylay_session *session,
                                   int32_t stream_id,
                                   void *user_data):
    cdef Session pysession = <Session>user_data
    if pysession.on_request_recv_cb:
        try:
            pysession.on_request_recv_cb(pysession, stream_id)
        except Exception as e:
            pysession.error = e
        except BaseException as e:
            pysession.base_error = e

cdef class ReadCtrl:
    cdef int flags

    def __cinit__(self):
        self.flags = 0

    property flags:
        def __set__(self, value):
            self.flags = value

cdef ssize_t read_callback(cspdylay.spdylay_session *session,
                           int32_t stream_id, uint8_t *buf, size_t length,
                           int *eof, cspdylay.spdylay_data_source *source,
                           void *user_data):
    cdef Session pysession = <Session>user_data
    cdef ReadCtrl read_ctrl = ReadCtrl()
    data_prd = <object>source.ptr

    try:
        res = data_prd.read_cb(pysession, stream_id, length, read_ctrl,
                               data_prd.source)
    except TemporalCallbackFailureError as e:
        return cspdylay.SPDYLAY_ERR_TEMPORAL_CALLBACK_FAILURE
    except CallbackFailureError as e:
        pysession.error = e
        return cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE
    except Exception as e:
        pysession.error = e
        return cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE
    except BaseException as e:
        pysession.base_error = e
        return cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE

    if read_ctrl.flags & READ_EOF:
        eof[0] = 1
    if res == cspdylay.SPDYLAY_ERR_DEFERRED:
        return res
    elif res:
        if len(res) > length:
            return cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE
        memcpy(buf, <char*>res, len(res))
        return len(res)
    else:
        return 0

cdef class Session:
    cdef cspdylay.spdylay_session *_c_session
    cdef object recv_callback
    cdef object send_callback
    cdef object on_ctrl_recv_cb
    cdef object on_invalid_ctrl_recv_cb
    cdef object on_data_chunk_recv_cb
    cdef object on_data_recv_cb
    cdef object before_ctrl_send_cb
    cdef object on_ctrl_send_cb
    cdef object on_ctrl_not_send_cb
    cdef object on_data_send_cb
    cdef object on_stream_close_cb
    cdef object on_request_recv_cb
    cdef object on_ctrl_recv_parse_error_cb
    cdef object on_unknown_ctrl_recv_cb
    cdef object user_data

    cdef object error
    cdef object base_error

    property user_data:
        def __get__(self):
            return self.user_data

    def __cinit__(self, side, version, config=None,
                  send_cb=None, recv_cb=None,
                  on_ctrl_recv_cb=None,
                  on_invalid_ctrl_recv_cb=None,
                  on_data_chunk_recv_cb=None,
                  on_data_recv_cb=None,
                  before_ctrl_send_cb=None,
                  on_ctrl_send_cb=None,
                  on_ctrl_not_send_cb=None,
                  on_data_send_cb=None,
                  on_stream_close_cb=None,
                  on_request_recv_cb=None,
                  on_ctrl_recv_parse_error_cb=None,
                  on_unknown_ctrl_recv_cb=None,
                  user_data=None):
        cdef cspdylay.spdylay_session_callbacks c_session_callbacks
        cdef int rv
        self._c_session = NULL
        memset(&c_session_callbacks, 0, sizeof(c_session_callbacks))
        c_session_callbacks.recv_callback = \
            <cspdylay.spdylay_recv_callback>recv_callback
        c_session_callbacks.send_callback = \
            <cspdylay.spdylay_send_callback>send_callback
        c_session_callbacks.on_ctrl_recv_callback = \
            <cspdylay.spdylay_on_ctrl_recv_callback>on_ctrl_recv_callback
        c_session_callbacks.on_invalid_ctrl_recv_callback = \
            <cspdylay.spdylay_on_invalid_ctrl_recv_callback>\
            on_invalid_ctrl_recv_callback
        c_session_callbacks.on_data_chunk_recv_callback = \
            <cspdylay.spdylay_on_data_chunk_recv_callback>\
            on_data_chunk_recv_callback
        c_session_callbacks.on_data_recv_callback = \
            <cspdylay.spdylay_on_data_recv_callback>on_data_recv_callback
        c_session_callbacks.before_ctrl_send_callback = \
            <cspdylay.spdylay_before_ctrl_send_callback>\
            before_ctrl_send_callback
        c_session_callbacks.on_ctrl_send_callback = \
            <cspdylay.spdylay_on_ctrl_send_callback>on_ctrl_send_callback
        c_session_callbacks.on_ctrl_not_send_callback = \
            <cspdylay.spdylay_on_ctrl_not_send_callback>\
            on_ctrl_not_send_callback
        c_session_callbacks.on_data_send_callback = \
            <cspdylay.spdylay_on_data_send_callback>on_data_send_callback
        c_session_callbacks.on_stream_close_callback = \
            <cspdylay.spdylay_on_stream_close_callback>on_stream_close_callback
        c_session_callbacks.on_request_recv_callback = \
            <cspdylay.spdylay_on_request_recv_callback>on_request_recv_callback
        # c_session_callbacks.get_credential_proof = NULL
        # c_session_callbacks.get_credential_ncerts = NULL
        # c_session_callbacks.get_credential_cert = NULL
        c_session_callbacks.on_ctrl_recv_parse_error_callback = \
            <cspdylay.spdylay_on_ctrl_recv_parse_error_callback>\
            on_ctrl_recv_parse_error_callback
        c_session_callbacks.on_unknown_ctrl_recv_callback = \
            <cspdylay.spdylay_on_unknown_ctrl_recv_callback>\
            on_unknown_ctrl_recv_callback

        self.recv_callback = recv_cb
        self.send_callback = send_cb
        self.on_ctrl_recv_cb = on_ctrl_recv_cb
        self.on_invalid_ctrl_recv_cb = on_invalid_ctrl_recv_cb
        self.on_data_chunk_recv_cb = on_data_chunk_recv_cb
        self.on_data_recv_cb = on_data_recv_cb
        self.before_ctrl_send_cb = before_ctrl_send_cb
        self.on_ctrl_send_cb = on_ctrl_send_cb
        self.on_ctrl_not_send_cb = on_ctrl_not_send_cb
        self.on_data_send_cb = on_data_send_cb
        self.on_stream_close_cb = on_stream_close_cb
        self.on_request_recv_cb = on_request_recv_cb
        self.on_ctrl_recv_parse_error_cb = on_ctrl_recv_parse_error_cb
        self.on_unknown_ctrl_recv_cb = on_unknown_ctrl_recv_cb

        self.user_data = user_data

        if side == CLIENT:
            rv = cspdylay.spdylay_session_client_new(&self._c_session,
                                                      version,
                                                      &c_session_callbacks,
                                                      <void*>self)
        elif side == SERVER:
            rv = cspdylay.spdylay_session_server_new(&self._c_session,
                                                      version,
                                                      &c_session_callbacks,
                                                      <void*>self)
        else:
            raise InvalidArgumentError('side must be either CLIENT or SERVER')

        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()
        elif rv == cspdylay.SPDYLAY_ERR_ZLIB:
            raise ZlibError(_strerror(rv))
        elif rv == cspdylay.SPDYLAY_ERR_UNSUPPORTED_VERSION:
            raise UnsupportedVersionError(_strerror(rv))

    def __init__(self, side, version, config=None,
                 send_cb=None, recv_cb=None,
                 on_ctrl_recv_cb=None,
                 on_invalid_ctrl_recv_cb=None,
                 on_data_chunk_recv_cb=None,
                 on_data_recv_cb=None,
                 before_ctrl_send_cb=None,
                 on_ctrl_send_cb=None,
                 on_ctrl_not_send_cb=None,
                 on_data_send_cb=None,
                 on_stream_close_cb=None,
                 on_request_recv_cb=None,
                 on_ctrl_recv_parse_error_cb=None,
                 user_data=None):
        pass

    def __dealloc__(self):
        cspdylay.spdylay_session_del(self._c_session)

    cpdef recv(self, data=None):
        cdef int rv
        cdef char *c_data
        self.error = self.base_error = None
        if data is None:
            rv = cspdylay.spdylay_session_recv(self._c_session)
        else:
            c_data = data
            rv = cspdylay.spdylay_session_mem_recv(self._c_session,
                                                   <uint8_t*>c_data, len(data))
        if self.base_error:
            raise self.base_error
        if self.error:
            raise self.error

        if rv >= 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_EOF:
            raise EOFError()
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()
        elif rv == cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE:
            raise CallbackFailureError()

    cpdef send(self):
        cdef int rv
        self.error = self.base_error = None
        rv = cspdylay.spdylay_session_send(self._c_session)
        if self.base_error:
            raise self.base_error
        elif self.error:
            raise self.error

        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()
        elif rv == cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE:
            raise CallbackFailureError()

    cpdef resume_data(self, stream_id):
        cpdef int rv
        rv = cspdylay.spdylay_session_resume_data(self._c_session, stream_id)
        if rv == 0:
            return True
        elif rv == cspdylay.SPDYLAY_ERR_INVALID_ARGUMENT:
            return False
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef want_read(self):
        return cspdylay.spdylay_session_want_read(self._c_session)

    cpdef want_write(self):
        return cspdylay.spdylay_session_want_write(self._c_session)

    cpdef get_stream_user_data(self, stream_id):
        return <object>cspdylay.spdylay_session_get_stream_user_data(\
            self._c_session, stream_id)

    cpdef get_outbound_queue_size(self):
        return cspdylay.spdylay_session_get_outbound_queue_size(\
            self._c_session)

    cpdef get_pri_lowest(self):
        return cspdylay.spdylay_session_get_pri_lowest(self._c_session)


    cpdef fail_session(self, status_code):
        cdef int rv
        rv = cspdylay.spdylay_session_fail_session(self._c_session,
                                                   status_code)
        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_request(self, pri, nv, data_prd=None, stream_user_data=None):
        cdef cspdylay.spdylay_data_provider c_data_prd
        cdef cspdylay.spdylay_data_provider *c_data_prd_ptr
        cpdef int rv
        cdef char **cnv
        nv = pynv_encode(nv)
        cnv = pynv2cnv(nv)
        if data_prd:
            create_c_data_prd(&c_data_prd, data_prd)
            c_data_prd_ptr = &c_data_prd
        else:
            c_data_prd_ptr = NULL

        rv = cspdylay.spdylay_submit_request(self._c_session, pri, cnv,
                                             c_data_prd_ptr,
                                             <void*>stream_user_data)
        free(cnv)
        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_INVALID_ARGUMENT:
            raise InvalidArgumentError(_strerror(rv))
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_response(self, stream_id, nv, data_prd=None):
        cdef cspdylay.spdylay_data_provider c_data_prd
        cdef cspdylay.spdylay_data_provider *c_data_prd_ptr
        cpdef int rv
        cdef char **cnv
        nv = pynv_encode(nv)
        cnv = pynv2cnv(nv)
        if data_prd:
            create_c_data_prd(&c_data_prd, data_prd)
            c_data_prd_ptr = &c_data_prd
        else:
            c_data_prd_ptr = NULL

        rv = cspdylay.spdylay_submit_response(self._c_session, stream_id,
                                              cnv, c_data_prd_ptr)
        free(cnv)
        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_INVALID_ARGUMENT:
            raise InvalidArgumentError(_strerror(rv))
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_syn_stream(self, flags, pri, nv, assoc_stream_id=0,
                            stream_user_data=None):
        cdef int rv
        cdef char **cnv
        nv = pynv_encode(nv)
        cnv = pynv2cnv(nv)
        rv = cspdylay.spdylay_submit_syn_stream(self._c_session,
                                                flags,
                                                assoc_stream_id,
                                                pri,
                                                cnv,
                                                <void*>stream_user_data)
        free(cnv)
        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_INVALID_ARGUMENT:
            raise InvalidArgumentError(_strerror(rv))
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_syn_reply(self, flags, stream_id, nv):
        cdef int rv
        cdef char **cnv
        nv = pynv_encode(nv)
        cnv = pynv2cnv(nv)
        rv = cspdylay.spdylay_submit_syn_reply(self._c_session,
                                               flags, stream_id, cnv)
        free(cnv)
        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_INVALID_ARGUMENT:
            raise InvalidArgumentError(_strerror(rv))
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_headers(self, flags, stream_id, nv):
        cdef int rv
        cdef char **cnv
        nv = pynv_encode(nv)
        cnv = pynv2cnv(nv)
        rv = cspdylay.spdylay_submit_headers(self._c_session,
                                             flags, stream_id, cnv)
        free(cnv)
        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_INVALID_ARGUMENT:
            raise InvalidArgumentError(_strerror(rv))
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_data(self, stream_id, flags, data_prd):
        cdef cspdylay.spdylay_data_provider c_data_prd
        cdef cspdylay.spdylay_data_provider *c_data_prd_ptr
        cpdef int rv
        if data_prd:
            create_c_data_prd(&c_data_prd, data_prd)
            c_data_prd_ptr = &c_data_prd
        else:
            c_data_prd_ptr = NULL

        rv = cspdylay.spdylay_submit_data(self._c_session, stream_id,
                                          flags, c_data_prd_ptr)
        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_rst_stream(self, stream_id, status_code):
        cdef int rv
        rv = cspdylay.spdylay_submit_rst_stream(self._c_session, stream_id,
                                                status_code)
        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_ping(self):
        cdef int rv
        rv = cspdylay.spdylay_submit_ping(self._c_session)
        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_goaway(self, status_code):
        cdef int rv
        rv = cspdylay.spdylay_submit_goaway(self._c_session, status_code)
        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_window_update(self, stream_id, delta_window_size):
        cdef int rv
        rv = cspdylay.spdylay_submit_window_update(self._c_session, stream_id,
                                                   delta_window_size)
        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_INVALID_ARGUMENT:
            raise InvalidArgumentError()
        elif rv == cspdylay.SPDYLAY_ERR_STREAM_CLOSED:
            raise StreamClosedError()
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_settings(self, flags, iv):
        ''' Submit SETTINGS frame. iv is list of tuple (settings_id,
        flag, value)
        '''
        cdef int rv
        cdef cspdylay.spdylay_settings_entry *civ = pysettings2csettings(iv)
        rv = cspdylay.spdylay_submit_settings(self._c_session, flags,
                                              civ, len(iv))
        free(civ)
        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_INVALID_ARGUMENT:
            raise InvalidArgumentError(_strerror(rv))
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

cdef _strerror(int error_code):
    return cspdylay.spdylay_strerror(error_code).decode('UTF-8')

cpdef get_npn_protocols():
    cdef size_t proto_list_len
    cdef cspdylay.spdylay_npn_proto *proto_list
    proto_list = cspdylay.spdylay_npn_get_proto_list(&proto_list_len)
    res = []
    for i in range(proto_list_len):
        res.append((<char*>proto_list[i].proto)[:proto_list[i].len]\
                       .decode('UTF-8'))
    return res

cpdef int npn_get_version(proto):
    cdef char *cproto
    if proto == None:
        return 0
    proto = proto.encode('UTF-8')
    cproto = proto
    return cspdylay.spdylay_npn_get_version(<unsigned char*>cproto, len(proto))

# Side
CLIENT = 1
SERVER = 2

# SPDY protocol version
PROTO_SPDY2 = cspdylay.SPDYLAY_PROTO_SPDY2
PROTO_SPDY3 = cspdylay.SPDYLAY_PROTO_SPDY3

# Control frame flags
CTRL_FLAG_NONE = cspdylay.SPDYLAY_CTRL_FLAG_NONE
CTRL_FLAG_FIN = cspdylay.SPDYLAY_CTRL_FLAG_FIN
CTRL_FLAG_UNIDIRECTIONAL = cspdylay.SPDYLAY_CTRL_FLAG_UNIDIRECTIONAL

# Data frame flags
DATA_FLAG_NONE = cspdylay.SPDYLAY_DATA_FLAG_NONE
DATA_FLAG_FIN = cspdylay.SPDYLAY_DATA_FLAG_FIN

# Error codes
ERR_INVALID_ARGUMENT = cspdylay.SPDYLAY_ERR_INVALID_ARGUMENT
ERR_ZLIB = cspdylay.SPDYLAY_ERR_ZLIB
ERR_UNSUPPORTED_VERSION = cspdylay.SPDYLAY_ERR_UNSUPPORTED_VERSION
ERR_WOULDBLOCK = cspdylay.SPDYLAY_ERR_WOULDBLOCK
ERR_PROTO = cspdylay.SPDYLAY_ERR_PROTO
ERR_INVALID_FRAME = cspdylay.SPDYLAY_ERR_INVALID_FRAME
ERR_EOF = cspdylay.SPDYLAY_ERR_EOF
ERR_DEFERRED = cspdylay.SPDYLAY_ERR_DEFERRED
ERR_STREAM_ID_NOT_AVAILABLE = cspdylay.SPDYLAY_ERR_STREAM_ID_NOT_AVAILABLE
ERR_STREAM_CLOSED = cspdylay.SPDYLAY_ERR_STREAM_CLOSED
ERR_STREAM_CLOSING = cspdylay.SPDYLAY_ERR_STREAM_CLOSING
ERR_STREAM_SHUT_WR = cspdylay.SPDYLAY_ERR_STREAM_SHUT_WR
ERR_INVALID_STREAM_ID = cspdylay.SPDYLAY_ERR_INVALID_STREAM_ID
ERR_INVALID_STREAM_STATE = cspdylay.SPDYLAY_ERR_INVALID_STREAM_STATE
ERR_DEFERRED_DATA_EXIST = cspdylay.SPDYLAY_ERR_DEFERRED_DATA_EXIST
ERR_SYN_STREAM_NOT_ALLOWED = cspdylay.SPDYLAY_ERR_SYN_STREAM_NOT_ALLOWED
ERR_GOAWAY_ALREADY_SENT = cspdylay.SPDYLAY_ERR_GOAWAY_ALREADY_SENT
ERR_INVALID_HEADER_BLOCK = cspdylay.SPDYLAY_ERR_INVALID_HEADER_BLOCK
ERR_INVALID_STATE = cspdylay.SPDYLAY_ERR_INVALID_STATE
ERR_GZIP = cspdylay.SPDYLAY_ERR_GZIP
ERR_TEMPORAL_CALLBACK_FAILURE = cspdylay.SPDYLAY_ERR_TEMPORAL_CALLBACK_FAILURE
ERR_FATAL = cspdylay.SPDYLAY_ERR_FATAL
ERR_NOMEM = cspdylay.SPDYLAY_ERR_NOMEM
ERR_CALLBACK_FAILURE = cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE

# Read Callback Flags
READ_EOF = 1

# The status code for RST_STREAM
OK = cspdylay.SPDYLAY_OK
PROTOCOL_ERROR = cspdylay.SPDYLAY_PROTOCOL_ERROR
INVALID_STREAM = cspdylay.SPDYLAY_INVALID_STREAM
REFUSED_STREAM = cspdylay.SPDYLAY_REFUSED_STREAM
UNSUPPORTED_VERSION = cspdylay.SPDYLAY_UNSUPPORTED_VERSION
CANCEL = cspdylay.SPDYLAY_CANCEL
INTERNAL_ERROR = cspdylay.SPDYLAY_INTERNAL_ERROR
FLOW_CONTROL_ERROR = cspdylay.SPDYLAY_FLOW_CONTROL_ERROR
# Following status codes were introduced in SPDY/3
STREAM_IN_USE = cspdylay.SPDYLAY_STREAM_IN_USE
STREAM_ALREADY_CLOSED = cspdylay.SPDYLAY_STREAM_ALREADY_CLOSED
INVALID_CREDENTIALS = cspdylay.SPDYLAY_INVALID_CREDENTIALS
FRAME_TOO_LARGE = cspdylay.SPDYLAY_FRAME_TOO_LARGE

# The status codes for GOAWAY, introduced in SPDY/3.
GOAWAY_OK = cspdylay.SPDYLAY_GOAWAY_OK
GOAWAY_PROTOCOL_ERROR = cspdylay.SPDYLAY_GOAWAY_PROTOCOL_ERROR
GOAWAY_INTERNAL_ERROR = cspdylay.SPDYLAY_GOAWAY_INTERNAL_ERROR

# Frame types
SYN_STREAM = cspdylay.SPDYLAY_SYN_STREAM
SYN_REPLY = cspdylay.SPDYLAY_SYN_REPLY
RST_STREAM = cspdylay.SPDYLAY_RST_STREAM
SETTINGS = cspdylay.SPDYLAY_SETTINGS
NOOP = cspdylay.SPDYLAY_NOOP
PING = cspdylay.SPDYLAY_PING
GOAWAY = cspdylay.SPDYLAY_GOAWAY
HEADERS = cspdylay.SPDYLAY_HEADERS
WINDOW_UPDATE = cspdylay.SPDYLAY_WINDOW_UPDATE
CREDENTIAL = cspdylay.SPDYLAY_CREDENTIAL

# The flags for the SETTINGS control frame.
FLAG_SETTINGS_NONE = cspdylay.SPDYLAY_FLAG_SETTINGS_NONE
FLAG_SETTINGS_CLEAR_SETTINGS = cspdylay.SPDYLAY_FLAG_SETTINGS_CLEAR_SETTINGS

# The flags for SETTINGS ID/value pair.
ID_FLAG_SETTINGS_NONE = cspdylay.SPDYLAY_ID_FLAG_SETTINGS_NONE
ID_FLAG_SETTINGS_PERSIST_VALUE = cspdylay.SPDYLAY_ID_FLAG_SETTINGS_PERSIST_VALUE
ID_FLAG_SETTINGS_PERSISTED = cspdylay.SPDYLAY_ID_FLAG_SETTINGS_PERSISTED

# The SETTINGS ID.
SETTINGS_UPLOAD_BANDWIDTH = cspdylay.SPDYLAY_SETTINGS_UPLOAD_BANDWIDTH
SETTINGS_DOWNLOAD_BANDWIDTH = cspdylay.SPDYLAY_SETTINGS_DOWNLOAD_BANDWIDTH
SETTINGS_ROUND_TRIP_TIME = cspdylay.SPDYLAY_SETTINGS_ROUND_TRIP_TIME
SETTINGS_MAX_CONCURRENT_STREAMS = \
    cspdylay.SPDYLAY_SETTINGS_MAX_CONCURRENT_STREAMS
SETTINGS_CURRENT_CWND = cspdylay.SPDYLAY_SETTINGS_CURRENT_CWND
SETTINGS_DOWNLOAD_RETRANS_RATE = \
    cspdylay.SPDYLAY_SETTINGS_DOWNLOAD_RETRANS_RATE
SETTINGS_INITIAL_WINDOW_SIZE = cspdylay.SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE
SETTINGS_CLIENT_CERTIFICATE_VECTOR_SIZE = \
    cspdylay.SPDYLAY_SETTINGS_CLIENT_CERTIFICATE_VECTOR_SIZE
SETTINGS_MAX = cspdylay.SPDYLAY_SETTINGS_MAX

try:
    # Simple SPDY Server implementation. We mimics the methods and
    # attributes of http.server.BaseHTTPRequestHandler. Since this
    # implementation uses TLS NPN, Python 3.3.0 or later is required.

    import socket
    import threading
    import socketserver
    import ssl
    import io
    import select
    import sys
    import time
    from xml.sax.saxutils import escape

    class Stream:
        def __init__(self, stream_id):
            self.stream_id = stream_id
            self.data_prd = None

            self.method = None
            self.path = None
            self.version = None
            self.scheme = None
            self.host = None
            self.headers = []

            self.rfile = None
            self.wfile = None

        def process_headers(self, headers):
            for k, v in headers:
                if k == ':method':
                    self.method = v
                elif k == ':scheme':
                    self.scheme = v
                elif k == ':path':
                    self.path = v
                elif k == ':version':
                    self.version = v
                elif k == ':host':
                    self.host = v
                else:
                    self.headers.append((k, v))

    class SessionCtrl:
        def __init__(self):
            self.streams = {}

    class BaseSPDYRequestHandler(socketserver.BaseRequestHandler):

        server_version = 'Python-spdylay'

        error_content_type = 'text/html; charset=UTF-8'

        # Same HTML from Apache error page
        error_message_format = '''\
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>{code} {reason}</title>
</head><body>
<h1>{reason}</h1>
<p>{explain}</p>
<hr>
<address>{server} at {hostname} Port {port}</address>
</body></html>
'''

        def send_error(self, code, message=None):
            # Make sure that code is really int
            code = int(code)
            try:
                shortmsg, longmsg = self.responses[code]
            except KeyError:
                shortmsg, longmsg = '???', '???'
            if message is None:
                message = shortmsg
            explain = longmsg

            content = self.error_message_format.format(\
                code=code,
                reason = escape(message),
                explain=escape(explain),
                server=escape(self.server_version),
                hostname=escape(socket.getfqdn()),
                port=self.server.server_address[1]).encode('UTF-8')

            self.send_response(code, message)
            self.send_header('content-type', self.error_content_type)
            self.send_header('content-length', str(len(content)))

            self.wfile.write(content)

        def send_response(self, code, message=None):
            if message is None:
                try:
                    shortmsg, _ = self.responses[code]
                except KeyError:
                    shortmsg = '???'
                message = shortmsg

            self._response_headers.append((':status',
                                           '{} {}'.format(code, message)))

        def send_header(self, keyword, value):
            self._response_headers.append((keyword, value))

        def version_string(self):
            return self.server_version + ' ' + self.sys_version

        def handle_one_request(self, stream):
            self.stream = stream

            stream.wfile = io.BytesIO()

            self.command = stream.method
            self.path = stream.path
            self.request_version = stream.version
            self.headers = stream.headers
            self.rfile = stream.rfile
            self.wfile = stream.wfile
            self._response_headers = []

            if stream.method is None:
                self.send_error(400)
            else:
                mname = 'do_' + stream.method
                if hasattr(self, mname):
                    method = getattr(self, mname)

                    if self.rfile is not None:
                        self.rfile.seek(0)

                    method()
                else:
                    self.send_error(501, 'Unsupported method ({})'\
                                        .format(stream.method))

            self.wfile.seek(0)
            data_prd = DataProvider(self.wfile, self.read_cb)
            stream.data_prd = data_prd

            self.send_header(':version', 'HTTP/1.1')
            self.send_header('server', self.version_string())
            self.send_header('date', self.date_time_string())

            self.session.submit_response(stream.stream_id,
                                         self._response_headers, data_prd)


        def send_cb(self, session, data):
            return self.request.send(data)

        def read_cb(self, session, stream_id, length, read_ctrl, source):
            data = source.read(length)
            if not data:
                read_ctrl.flags = READ_EOF
            return data

        def on_ctrl_recv_cb(self, session, frame):
            if frame.frame_type == SYN_STREAM:
                stream = Stream(frame.stream_id)
                self.ssctrl.streams[frame.stream_id] = stream

                stream.process_headers(frame.nv)
            elif frame.frame_type == HEADERS:
                if frame.stream_id in self.ssctrl.streams:
                    stream = self.ssctrl.streams[frame.stream_id]
                    stream.process_headers(frame.nv)

        def on_data_chunk_recv_cb(self, session, flags, stream_id, data):
            if stream_id in self.ssctrl.streams:
                stream = self.ssctrl.streams[stream_id]
                if stream.method == 'POST':
                    if not stream.rfile:
                        stream.rfile = io.BytesIO()
                    stream.rfile.write(data)
                else:
                    # We don't allow request body if method is not POST
                    session.submit_rst_stream(stream_id, PROTOCOL_ERROR)

        def on_stream_close_cb(self, session, stream_id, status_code):
            if stream_id in self.ssctrl.streams:
                del self.ssctrl.streams[stream_id]

        def on_request_recv_cb(self, session, stream_id):
            if stream_id in self.ssctrl.streams:
                stream = self.ssctrl.streams[stream_id]
                self.handle_one_request(stream)

        def handle(self):
            self.request.setsockopt(socket.IPPROTO_TCP,
                                    socket.TCP_NODELAY, True)
            try:
                self.request.do_handshake()
                self.request.setblocking(False)

                version = npn_get_version(self.request.selected_npn_protocol())
                if version == 0:
                    return

                self.ssctrl = SessionCtrl()
                self.session = Session(\
                    SERVER, version,
                    send_cb=self.send_cb,
                    on_ctrl_recv_cb=self.on_ctrl_recv_cb,
                    on_data_chunk_recv_cb=self.on_data_chunk_recv_cb,
                    on_stream_close_cb=self.on_stream_close_cb,
                    on_request_recv_cb=self.on_request_recv_cb)

                self.session.submit_settings(\
                    FLAG_SETTINGS_NONE,
                    [(SETTINGS_MAX_CONCURRENT_STREAMS, ID_FLAG_SETTINGS_NONE,
                      100)]
                    )

                while self.session.want_read() or self.session.want_write():
                    want_read = want_write = False
                    try:
                        data = self.request.recv(4096)
                        if data:
                            self.session.recv(data)
                        else:
                            break
                    except ssl.SSLWantReadError:
                        want_read = True
                    except ssl.SSLWantWriteError:
                        want_write = True
                    try:
                        self.session.send()
                    except ssl.SSLWantReadError:
                        want_read = True
                    except ssl.SSLWantWriteError:
                        want_write = True

                    if want_read or want_write:
                        select.select([self.request] if want_read else [],
                                      [self.request] if want_write else [],
                                      [])
            finally:
                self.request.setblocking(True)

        # The following methods and attributes are copied from
        # Lib/http/server.py of cpython source code

        def date_time_string(self, timestamp=None):
            """Return the current date and time formatted for a
            message header."""
            if timestamp is None:
                timestamp = time.time()
            year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)
            s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
                    self.weekdayname[wd],
                    day, self.monthname[month], year,
                    hh, mm, ss)
            return s

        weekdayname = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

        monthname = [None,
                     'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                     'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

        # The Python system version, truncated to its first component.
        sys_version = "Python/" + sys.version.split()[0]

        # Table mapping response codes to messages; entries have the
        # form {code: (shortmessage, longmessage)}.
        # See RFC 2616 and 6585.
        responses = {
            100: ('Continue', 'Request received, please continue'),
            101: ('Switching Protocols',
                  'Switching to new protocol; obey Upgrade header'),

            200: ('OK', 'Request fulfilled, document follows'),
            201: ('Created', 'Document created, URL follows'),
            202: ('Accepted',
                  'Request accepted, processing continues off-line'),
            203: ('Non-Authoritative Information',
                  'Request fulfilled from cache'),
            204: ('No Content', 'Request fulfilled, nothing follows'),
            205: ('Reset Content', 'Clear input form for further input.'),
            206: ('Partial Content', 'Partial content follows.'),

            300: ('Multiple Choices',
                  'Object has several resources -- see URI list'),
            301: ('Moved Permanently',
                  'Object moved permanently -- see URI list'),
            302: ('Found', 'Object moved temporarily -- see URI list'),
            303: ('See Other', 'Object moved -- see Method and URL list'),
            304: ('Not Modified',
                  'Document has not changed since given time'),
            305: ('Use Proxy',
                  'You must use proxy specified in Location to access this '
                  'resource.'),
            307: ('Temporary Redirect',
                  'Object moved temporarily -- see URI list'),

            400: ('Bad Request',
                  'Bad request syntax or unsupported method'),
            401: ('Unauthorized',
                  'No permission -- see authorization schemes'),
            402: ('Payment Required',
                  'No payment -- see charging schemes'),
            403: ('Forbidden',
                  'Request forbidden -- authorization will not help'),
            404: ('Not Found', 'Nothing matches the given URI'),
            405: ('Method Not Allowed',
                  'Specified method is invalid for this resource.'),
            406: ('Not Acceptable', 'URI not available in preferred format.'),
            407: ('Proxy Authentication Required', 'You must authenticate with '
                  'this proxy before proceeding.'),
            408: ('Request Timeout', 'Request timed out; try again later.'),
            409: ('Conflict', 'Request conflict.'),
            410: ('Gone',
                  'URI no longer exists and has been permanently removed.'),
            411: ('Length Required', 'Client must specify Content-Length.'),
            412: ('Precondition Failed', 'Precondition in headers is false.'),
            413: ('Request Entity Too Large', 'Entity is too large.'),
            414: ('Request-URI Too Long', 'URI is too long.'),
            415: ('Unsupported Media Type',
                  'Entity body in unsupported format.'),
            416: ('Requested Range Not Satisfiable',
                  'Cannot satisfy request range.'),
            417: ('Expectation Failed',
                  'Expect condition could not be satisfied.'),
            428: ('Precondition Required',
                  'The origin server requires the request to be conditional.'),
            429: ('Too Many Requests', 'The user has sent too many requests '
                  'in a given amount of time ("rate limiting").'),
            431: ('Request Header Fields Too Large',
                  'The server is unwilling to process '
                  'the request because its header fields are too large.'),

            500: ('Internal Server Error', 'Server got itself in trouble'),
            501: ('Not Implemented',
                  'Server does not support this operation'),
            502: ('Bad Gateway',
                  'Invalid responses from another server/proxy.'),
            503: ('Service Unavailable',
                  'The server cannot process the request due to a high load'),
            504: ('Gateway Timeout',
                  'The gateway server did not receive a timely response'),
            505: ('HTTP Version Not Supported', 'Cannot fulfill request.'),
            511: ('Network Authentication Required',
                  'The client needs to authenticate to gain network access.'),
            }

    class ThreadedSPDYServer(socketserver.ThreadingMixIn,
                             socketserver.TCPServer):
        def __init__(self, server_address, RequestHandlerCalss,
                     cert_file, key_file):
            self.allow_reuse_address = True

            self.ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.ctx.options = ssl.OP_ALL | ssl.OP_NO_SSLv2 | \
                ssl.OP_NO_COMPRESSION
            self.ctx.load_cert_chain(cert_file, key_file)
            self.ctx.set_npn_protocols(get_npn_protocols())

            socketserver.TCPServer.__init__(self, server_address,
                                            RequestHandlerCalss)

        def start(self, daemon=False):
            server_thread = threading.Thread(target=self.serve_forever)
            server_thread.daemon = daemon
            server_thread.start()

        def process_request(self, request, client_address):
            # ThreadingMixIn.process_request() dispatches request and
            # client_address to separate thread. To cleanly shutdown
            # SSL/TLS wrapped socket, we wrap socket here.

            # SSL/TLS handshake is postponed to each thread.
            request = self.ctx.wrap_socket(\
                request, server_side=True, do_handshake_on_connect=False)

            socketserver.ThreadingMixIn.process_request(self,
                                                        request, client_address)


    # Simple SPDY client implementation. Since this implementation
    # uses TLS NPN, Python 3.3.0 or later is required.

    from urllib.parse import urlsplit

    class BaseSPDYStreamHandler:
        def __init__(self, url, fetcher):
            self.url = url
            self.fetcher = fetcher
            self.stream_id = None

        def on_header(self, nv):
            pass

        def on_data(self, data):
            pass

        def on_close(self, status_code):
            pass

    class UrlFetchError(Exception):
        pass

    class UrlFetcher:
        def __init__(self, server_address, urls, StreamHandlerClass):
            self.server_address = server_address
            self.handlers = [StreamHandlerClass(url, self) for url in urls]
            self.streams = {}
            self.finished = []

            self.ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.ctx.options = ssl.OP_ALL | ssl.OP_NO_SSLv2 | \
                ssl.OP_NO_COMPRESSION
            self.ctx.set_npn_protocols(get_npn_protocols())

        def send_cb(self, session, data):
            return self.sock.send(data)

        def before_ctrl_send_cb(self, session, frame):
            if frame.frame_type == SYN_STREAM:
                handler = session.get_stream_user_data(frame.stream_id)
                if handler:
                    handler.stream_id = frame.stream_id
                    self.streams[handler.stream_id] = handler

        def on_ctrl_recv_cb(self, session, frame):
            if frame.frame_type == SYN_REPLY or frame.frame_type == HEADERS:
                if frame.stream_id in self.streams:
                    handler = self.streams[frame.stream_id]
                    handler.on_header(frame.nv)

        def on_data_chunk_recv_cb(self, session, flags, stream_id, data):
            if stream_id in self.streams:
                handler = self.streams[stream_id]
                handler.on_data(data)

        def on_stream_close_cb(self, session, stream_id, status_code):
            if stream_id in self.streams:
                handler = self.streams[stream_id]
                handler.on_close(status_code)
                del self.streams[stream_id]
                self.finished.append(handler)

        def connect(self, server_address):
            self.sock = None
            for res in socket.getaddrinfo(server_address[0], server_address[1],
                                          socket.AF_UNSPEC,
                                          socket.SOCK_STREAM):
                af, socktype, proto, canonname, sa = res
                try:
                    self.sock = socket.socket(af, socktype, proto)
                except OSError as msg:
                    self.sock = None
                    continue
                try:
                    self.sock.connect(sa)
                except OSError as msg:
                    self.sock.close()
                    self.sock = None
                    continue
                break
            else:
                raise UrlFetchError('Could not connect to {}'\
                                        .format(server_address))

        def tls_handshake(self):
            self.sock = self.ctx.wrap_socket(self.sock, server_side=False,
                                             do_handshake_on_connect=False)
            self.sock.do_handshake()

            self.version = npn_get_version(self.sock.selected_npn_protocol())
            if self.version == 0:
                raise UrlFetchError('NPN failed')

        def loop(self):
            self.connect(self.server_address)
            try:
                self._loop()
            finally:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()

        def _loop(self):
            self.tls_handshake()
            self.sock.setblocking(False)

            session = Session(CLIENT,
                              self.version,
                              send_cb=self.send_cb,
                              on_ctrl_recv_cb=self.on_ctrl_recv_cb,
                              on_data_chunk_recv_cb=self.on_data_chunk_recv_cb,
                              before_ctrl_send_cb=self.before_ctrl_send_cb,
                              on_stream_close_cb=self.on_stream_close_cb)

            session.submit_settings(\
                FLAG_SETTINGS_NONE,
                [(SETTINGS_MAX_CONCURRENT_STREAMS, ID_FLAG_SETTINGS_NONE, 100)]
                )

            if self.server_address[1] == 443:
                hostport = self.server_address[0]
            else:
                hostport = '{}:{}'.format(self.server_address[0],
                                          self.server_address[1])

            for handler in self.handlers:
                res = urlsplit(handler.url)
                if res.path:
                    path = res.path
                else:
                    path = '/'
                if res.query:
                    path = '?'.join([path, res.query])

                session.submit_request(0,
                                       [(':method', 'GET'),
                                        (':scheme', 'https'),
                                        (':path', path),
                                        (':version', 'HTTP/1.1'),
                                        (':host', hostport),
                                        ('accept', '*/*'),
                                        ('user-agent', 'python-spdylay')],
                                       stream_user_data=handler)

            while (session.want_read() or session.want_write()) \
                    and not len(self.finished) == len(self.handlers):
                want_read = want_write = False
                try:
                    data = self.sock.recv(4096)
                    if data:
                        session.recv(data)
                    else:
                        break
                except ssl.SSLWantReadError:
                    want_read = True
                except ssl.SSLWantWriteError:
                    want_write = True
                try:
                    session.send()
                except ssl.SSLWantReadError:
                    want_read = True
                except ssl.SSLWantWriteError:
                    want_write = True

                if want_read or want_write:
                    select.select([self.sock] if want_read else [],
                                  [self.sock] if want_write else [],
                                  [])

    def _urlfetch_session_one(urls, StreamHandlerClass):
        res = urlsplit(urls[0])
        if res.scheme != 'https':
            raise UrlFetchError('Unsupported scheme {}'.format(res.scheme))
        hostname = res.hostname
        port = res.port if res.port else 443

        f = UrlFetcher((hostname, port), urls, StreamHandlerClass)
        f.loop()

    def urlfetch(url_or_urls, StreamHandlerClass):
        if isinstance(url_or_urls, str):
            _urlfetch_session_one([url_or_urls], StreamHandlerClass)
        else:
            urls = []
            prev_addr = (None, None)
            for url in url_or_urls:
                res = urlsplit(url)
                port = res.port if res.port else 443
                if prev_addr != (res.hostname, port):
                    if urls:
                        _urlfetch_session_one(urls, StreamHandlerClass)
                        urls = []
                prev_addr = (res.hostname, port)
                urls.append(url)
            if urls:
                _urlfetch_session_one(urls, StreamHandlerClass)

except ImportError:
    # No server for 2.x because they lack TLS NPN.
    pass
