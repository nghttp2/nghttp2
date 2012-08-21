cimport cspdylay

from libc.stdlib cimport malloc, free
from libc.string cimport memcpy, memset
from libc.stdint cimport uint8_t, uint16_t, uint32_t, int32_t

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

    cdef void fill(self, cspdylay.spdylay_syn_stream *frame):
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

    cdef void fill(self, cspdylay.spdylay_syn_reply *frame):
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

    cdef void fill(self, cspdylay.spdylay_headers *frame):
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

    cdef void fill(self, cspdylay.spdylay_rst_stream *frame):
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

    cdef void fill(self, cspdylay.spdylay_settings *frame):
        self.fillhd(&frame.hd)

        self.iv = csettings2pysettings(frame.niv, frame.iv)


    property iv:
        def __get__(self):
            return self.iv

cdef class PingFrame(CtrlFrame):
    cdef uint32_t unique_id

    cdef void fill(self, cspdylay.spdylay_ping *frame):
        self.fillhd(&frame.hd)

        self.unique_id = frame.unique_id

    property unique_id:
        def __get__(self):
            return self.unique_id

cdef class GoawayFrame(CtrlFrame):
    cdef int32_t last_good_stream_id
    cdef uint32_t status_code

    cdef void fill(self, cspdylay.spdylay_goaway *frame):
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

    cdef void fill(self, cspdylay.spdylay_window_update *frame):
        self.fillhd(&frame.hd)

        self.stream_id = frame.stream_id
        self.delta_window_size = frame.delta_window_size

    property stream_id:
        def __get__(self):
            return self.stream_id

    property delta_window_size:
        def __get__(self):
            return self.delta_window_size

cdef object cnv2pynv(char **nv):
    ''' Convert C-style name/value pairs ``nv`` to Python style
    pairs. '''
    cdef size_t i
    pynv = []
    i = 0
    while nv[i] != NULL:
        pynv.append((nv[i], nv[i+1]))
        i += 2
    return pynv

cdef char** pynv2cnv(object nv) except *:
    ''' Convert Python style name/value pairs ``nv`` to C-style
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

cdef void on_ctrl_recv_callback(cspdylay.spdylay_session *session,
                                cspdylay.spdylay_frame_type frame_type,
                                cspdylay.spdylay_frame *frame,
                                void *user_data):
    cdef SynStreamFrame syn_stream
    cdef SynReplyFrame syn_reply
    cdef HeadersFrame headers
    cdef RstStreamFrame rst_stream
    cdef SettingsFrame settings
    cdef PingFrame ping
    cdef GoawayFrame goaway
    cdef WindowUpdateFrame window_update

    cdef Session pysession = <Session>user_data

    if not pysession.on_ctrl_recv_cb:
        return

    pyframe = None
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

    if pyframe:
        try:
            pysession.on_ctrl_recv_cb(pysession, pyframe)
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

cdef ssize_t read_callback(cspdylay.spdylay_session *session,
                           int32_t stream_id, uint8_t *buf, size_t length,
                           int *eof, cspdylay.spdylay_data_source *source,
                           void *user_data):
    cdef Session pysession = <Session>user_data
    data_prd = <object>source.ptr

    try:
        res = data_prd.read_cb(pysession, stream_id, length,
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

    if res == cspdylay.SPDYLAY_ERR_DEFERRED:
        return res
    elif res:
        if len(res) > length:
            return cspdylay.SPDYLAY_ERR_CALLBACK_FAILURE
        memcpy(buf, <char*>res, len(res))
        return len(res)
    else:
        eof[0] = 1
        return 0

cdef class Session:
    cdef cspdylay.spdylay_session *_c_session
    cdef object recv_callback
    cdef object send_callback
    cdef object on_ctrl_recv_cb
    cdef object on_data_chunk_recv_cb
    cdef object on_stream_close_cb
    cdef object on_request_recv_cb
    cdef object user_data

    cdef object error
    cdef object base_error

    property user_data:
        def __get__(self):
            return self.user_data

    def __cinit__(self, side, version, config=None,
                  send_cb=None, recv_cb=None,
                  on_ctrl_recv_cb=None,
                  on_data_chunk_recv_cb=None,
                  on_stream_close_cb=None,
                  on_request_recv_cb=None,
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
        # c_session_callbacks.on_invalid_ctrl_recv_callback = NULL
        c_session_callbacks.on_data_chunk_recv_callback = \
            <cspdylay.spdylay_on_data_chunk_recv_callback>\
            on_data_chunk_recv_callback
        # c_session_callbacks.on_data_recv_callback = NULL
        # c_session_callbacks.before_ctrl_send_callback = NULL
        # c_session_callbacks.on_ctrl_send_callback = NULL
        # c_session_callbacks.on_ctrl_not_send_callback = NULL
        # c_session_callbacks.on_data_send_callback = NULL
        c_session_callbacks.on_stream_close_callback = \
            <cspdylay.spdylay_on_stream_close_callback>on_stream_close_callback
        c_session_callbacks.on_request_recv_callback = \
            <cspdylay.spdylay_on_request_recv_callback>on_request_recv_callback
        # c_session_callbacks.get_credential_proof = NULL
        # c_session_callbacks.get_credential_ncerts = NULL
        # c_session_callbacks.get_credential_cert = NULL
        # c_session_callbacks.on_ctrl_recv_parse_error_callback = NULL
        # c_session_callbacks.on_unknown_ctrl_recv_callback = NULL

        self.recv_callback = recv_cb
        self.send_callback = send_cb
        self.on_data_chunk_recv_cb = on_data_chunk_recv_cb
        self.on_ctrl_recv_cb = on_ctrl_recv_cb
        self.on_stream_close_cb = on_stream_close_cb
        self.on_request_recv_cb = on_request_recv_cb

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
            raise ZlibError(cspdylay.spdylay_strerror(rv))
        elif rv == cspdylay.SPDYLAY_ERR_UNSUPPORTED_VERSION:
            raise UnsupportedVersionError(cspdylay.spdylay_strerror(rv))

    def __init__(self, side, version, config=None,
                 send_cb=None, recv_cb=None,
                 on_ctrl_recv_cb=None,
                 on_data_chunk_recv_cb=None,
                 on_stream_close_cb=None,
                 on_request_recv_cb=None,
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
            return
        elif rv == cspdylay.SPDYLAY_ERR_INVALID_ARGUMENT:
            raise InvalidArgumentError(cspdylay.spdylay_strerror(rv))
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
        ''' Submits frame and optionally one or more DATA frames.  If
        data_prd is not None, it provides data which will be sent in
        subsequent DATA frames. It must have 2 attributes: source and
        read_cb. source is an opaque object and passed to read_cb
        callback.  read_cb must be None or a callable object. The
        library calls it when it needs data. 4 arguments are passed to
        read_cb: session, stream_id, length and source. And it returns
        at most length bytes of byte string. The session is self. The
        stream_id is the stream ID of the stream.  The length is the
        maximum length the library expects. read_cb must not return
        more that length bytes. The source is the object passed in
        data_prd.source.
        '''
        cdef cspdylay.spdylay_data_provider c_data_prd
        cdef cspdylay.spdylay_data_provider *c_data_prd_ptr
        cdef char **cnv = pynv2cnv(nv)
        cpdef int rv
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
            raise InvalidArgumentError(cspdylay.spdylay_strerror(rv))
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_response(self, stream_id, nv, data_prd=None):
        cdef cspdylay.spdylay_data_provider c_data_prd
        cdef cspdylay.spdylay_data_provider *c_data_prd_ptr
        cdef char **cnv = pynv2cnv(nv)
        cpdef int rv
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
            raise InvalidArgumentError(cspdylay.spdylay_strerror(rv))
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_syn_stream(self, flags, assoc_stream_id, pri, nv,
                            stream_user_data):
        cdef char **cnv = pynv2cnv(nv)
        cdef int rv
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
            raise InvalidArgumentError(cspdylay.spdylay_strerror(rv))
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_syn_reply(self, flags, stream_id, nv):
        cdef char **cnv = pynv2cnv(nv)
        cdef int rv
        rv = cspdylay.spdylay_submit_syn_reply(self._c_session,
                                               flags, stream_id, cnv)
        free(cnv)
        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_INVALID_ARGUMENT:
            raise InvalidArgumentError(cspdylay.spdylay_strerror(rv))
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

    cpdef submit_headers(self, flags, stream_id, nv):
        cdef char **cnv = pynv2cnv(nv)
        cdef int rv
        rv = cspdylay.spdylay_submit_headers(self._c_session,
                                             flags, stream_id, cnv)
        free(cnv)
        if rv == 0:
            return
        elif rv == cspdylay.SPDYLAY_ERR_INVALID_ARGUMENT:
            raise InvalidArgumentError(cspdylay.spdylay_strerror(rv))
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
            raise InvalidArgumentError(cspdylay.spdylay_strerror(rv))
        elif rv == cspdylay.SPDYLAY_ERR_NOMEM:
            raise MemoryError()

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

# Error codes used in callback
ERR_OK = 0 # Not defined in <spdylay/spdylay.h>
ERR_EOF = cspdylay.SPDYLAY_ERR_EOF
ERR_DEFERRED = cspdylay.SPDYLAY_ERR_DEFERRED

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
