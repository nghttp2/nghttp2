Python-spdylay - Spdylay Python Extension Module
================================================

.. py:module:: spdylay

Python-spdylay is the Python extension module of Spdylay SPDY C
library.

Build
-----

To generate C source code from ``spdylay.pyx``, run ``cython``::

    $ cython spdylay.pyx

To build extension, run ``setup.py``::

    $ python setup.py build_ext

Session Objects
---------------

.. py:class:: Session(side, version, config=None, send_cb=None, recv_cb=None, on_ctrl_recv_cb=None, on_invalid_ctrl_recv_cb=None, on_data_chunk_recv_cb=None, on_data_recv_cb=None, before_ctrl_send_cb=None, on_ctrl_send_cb=None, on_ctrl_not_send_cb=None, on_data_send_cb=None, on_stream_close_cb=None, on_request_recv_cb=None, on_ctrl_recv_parse_error_cb=None, on_unknown_ctrl_recv_cb=None, user_data=None)

    This is the class to hold the resources needed for a SPDY session.
    Sending and receiving SPDY frames are done using the methods of
    this class.

    The *side* specifies server or client. Use one of the following:

    .. py:data:: CLIENT

        Indicates client.

    .. py:data:: SERVER

        Indicates server.

    The *version* specifies SPDY protocol version. Use of the following:

    .. py:data:: PROTO_SPDY2

        Indicates SPDY/2.

    .. py:data:: PROTO_SPDY3

        Indicates SPDY/3.

    The *user_data* specifies opaque object tied to this object. It
    can be accessed through :py:attr:`user_data` attribute.

    The *recv_cb* specifies callback function (callable) invoked when
    the object wants to receive data from the remote peer. The
    signature of this callback is:

    .. py:function:: recv_cb(session, length)

        The *session* is the :py:class:`Session` object invoking the
        callback.  The implementation of this function must read at
        most *length* bytes of bytestring and return it. If it cannot
        read any single byte without blocking, it must return empty
        bytestring or ``None``. If it gets EOF before it reads any
        single byte, it must raise :py:class:`EOFError`. For other
        errors, it must raise :py:class:`CallbackFailureError`.

    The *send_cb* specifies callback function (callable) invoked when
    session wants to send data to the remote peer. The signature of
    this callback is:

    .. py:function:: send_cb(session, data)

        The *session* is the :py:class:`Session` object invoking the
        callback. The *data* is the bytestring to send. The
        implementation of this function will send all or part of
        *data*. It must return the number of bytes sent if it
        succeeds. If it cannot send any single byte without blocking,
        it must return 0 or ``None``. For other errors, it must return
        :py:class:`CallbackFailureError`.

    The *on_ctrl_recv_cb* specifies callback function (callable)
    invoked when a control frame is received.

    .. py:function:: on_ctrl_recv_cb(session, frame)

        The *session* is the :py:class:`Session` object invoking the
        callback. The *frame* is the received control
        frame. ``frame.frame_type`` tells the type of frame. See
        `Frame Types`_ for the details. Once the frame type is
        identified, access attribute of the *frame* to get
        information.

    The *on_invalid_ctrl_recv_cb* specifies callback function
    (callable) invoked when an invalid control frame is received.

    .. py:function:: on_invalid_ctrl_recv_cb(session, frame, status_code)

        The *session* is the :py:class:`Session` object invoking the
        callback. The *frame* is the received control
        frame. ``frame.frame_type`` tells the type of frame. See
        `Frame Types`_ for the details. Once the frame type is
        identified, access attribute of the *frame* to get
        information.  The *status_code* is one of the `Stream Status
        Codes`_ and indicates the error. When this callback function
        is invoked, either RST_STREAM or GOAWAY will be sent.

    The *on_data_chunk_recv_cb* specifies callback function (callable)
    invoked when a chunk of data in DATA frame is received.

    .. py:function:: on_data_chunk_recv_cb(session, flags, stream_id, data)

        The *session* is the :py:class:`Session` object invoking the
        callback. The *stream_id* is the stream ID this DATA frame
        belongs to. The *flags* is the flags of DATA frame which this
        data chunk is contained. ``(flags & DATA_FLAG_FIN) != 0`` does
        not necessarily mean this chunk of data is the last one in the
        stream. You should use :py:func:`on_data_recv_cb` to know all
        data frames are received. The *data* is the bytestring of
        received data.

    The *on_data_recv_cb* specifies callback function (callable)
    invoked when DATA frame is received.

    .. py:function:: on_data_recv_cb(session, flags, stream_id, length)

        The actual data it contains are received by
        :py:func:`on_data_chunk_recv_cb()`.

    The *before_ctrl_send_cb* specifies callback function (callable)
    invoked before the control frame is sent.

    .. py:function:: before_ctrl_send_cb(session, frame)

        The *session* is the :py:class:`Session` object invoking the
        callback. The *frame* is the control frame to be
        sent. ``frame.frame_type`` tells the type of frame. See `Frame
        Types`_ for the details. Once the frame type is identified,
        access attribute of the *frame* to get information.

    The *on_ctrl_send_cb* specifies callback function (callable)
    invoked after the control frame is sent.

    .. py:function:: on_ctrl_send_cb(session, frame)

        The *session* is the :py:class:`Session` object invoking the
        callback. The *frame* is the control frame to be
        sent. ``frame.frame_type`` tells the type of frame. See `Frame
        Types`_ for the details. Once the frame type is identified,
        access attribute of the *frame* to get information.

    The *on_ctrl_not_send_cb* specifies callback function (callable)
    after the control frame is not sent because of the error.

    .. py:function:: on_ctrl_not_send_cb(session, frame, error_code)

        The *session* is the :py:class:`Session` object invoking the
        callback. The *frame* is the received control
        frame. ``frame.frame_type`` tells the type of frame. See
        `Frame Types`_ for the details. Once the frame type is
        identified, access attribute of the *frame* to get
        information.  The *error_code* is one of the `Error Codes`_
        and indicates the error.

    The *on_data_send_cb* specifies callback function (callable)
    invoked after DATA frame is sent.

    .. py:function:: on_data_send_cb(session, flags, stream_id, length)

    The *on_stream_close_cb* specifies callback function (callable)
    invoked when the stream is closed.

    .. py:function:: on_stream_close_cb(session, stream_id, status_code)

        The *session* is the :py:class:`Session` object invoking the
        callback. The *stream_id* indicates the stream ID.  The reason
        of closure is indicated by the *status_code*. See `Stream
        Status Codes`_ for the details. The stream_user_data, which
        was specified in :py:meth:`submit_request()` or
        :py:meth:`submit_syn_stream()`, is still available in this
        function.

    The *on_request_recv_cb* specifies callback function (callable)
    invoked when the request from the remote peer is received. In
    other words, the frame with FIN flag set is received. In HTTP,
    this means HTTP request, including request body, is fully
    received.

    .. py:function:: on_request_recv_cb(session, stream_id)

        The *session* is the :py:class:`Session` object invoking the
        callback. The *stream_id* indicates the stream ID.

    The *on_ctrl_recv_parse_error_cb* specifies callback function
    (callable) invoked when the received control frame octets could
    not be parsed correctly.

    .. py:function:: on_ctrl_recv_parse_error_cb(session, type, head, payload, error_code)

        The *type* indicates the type of received control frame. The
        *head* is the bytestring of control frame header. The
        *payload* is the bytestring of data portion of the received
        frame. The *error_code* is one of the error code defined in
        `Error Codes`_ and indicates the error.

    The *on_unknown_ctrl_recv_cb* specifies callback function
    (callable) invoked when the received control frame type is
    unknown.

    .. py:function:: on_unknown_ctrl_recv_cb(session, head, payload)

        The *head* is the bytestring of control frame header. The
        *payload* is the bytestring of data portion of the received
        frame.

    The :py:class:`InvalidArgumentError` will be raised if the given
    argument is invalid.  The :py:class:`UnsupportedVersionError` will
    be raised if the *version* is not supported. The
    :py:class:`ZlibError` will be raised if initialization of zlib
    failed.

.. py:attribute:: Session.user_data

    The object passed in the constructor as *user_data* argument.
    This attribute is read-only.

.. py:method:: Session.send()

    Sends pending frames to the remote peer.  This method retrieves
    the highest prioritized frame from the outbound queue and sends it
    to the remote peer. It does this as many as possible until the
    user callback :py:func:`send_cb` returns 0 or ``None`` or the
    outbound queue becomes empty. This method calls several callback
    functions which are passed when initializing the session.  See
    :func:`spdylay_session_send` about the callback functions invoked
    from this method.

    The :py:class:`CallbackFailureError` will be raised if the
    callback function failed.

.. py:method:: Session.recv(data=None)

    Receives frames from the remote peer.  This method receives as
    many frames as possible until the user callback :py:func:`recv_cb`
    returns empty bytestring or ``None``. This function calls several
    callback functions which are passed when initializing the session.
    See :func:`spdylay_session_recv` about the callback functions
    invoked from this method. If data is ``None``, this method will
    invoke :py:func:`recv_cb` callback function to receive incoming
    data.  If data is not ``None``, it must be a bytestring and this
    method uses it as the incoming data and does not call
    :py:func:`recv_cb` callback function.

    The :py:class:`EOFError` will be raised if the remote peer did
    shutdown on the connection. The :py:class:`CallbackFailureError`
    will be raised if the callback function failed.

.. py:method:: Session.resume_data(stream_id)

    Puts back previously deferred DATA frame in the stream *stream_id*
    to the outbound queue.

    This method returns ``True`` if it succeeds, or ``False``.  This
    method will fail if the stream does not exist or no deferred data
    exist.

.. py:method:: Session.want_read()

    Returns ``True`` if session wants to receive data from the
    remote peer.

    If both :py:meth:`want_read()` and :py:meth:`want_write()` return
    ``False``, the application should drop the connection.

.. py:method:: Session.want_write()

    Returns ``True`` if session wants to send data to the remote peer.

    If both :py:meth:`want_read()` and :py:meth:`want_write()` return
    ``False``, the application should drop the connection.

.. py:method:: Session.get_stream_user_data(stream_id)

    Returns stream_user_data for the stream *stream_id*. The
    stream_user_data is provided by :py:meth:`submit_request()` or
    :py:meth:`submit_syn_stream()`. If the stream is initiated by the
    remote endpoint, stream_user_data is always ``None``. If the
    stream is initiated by the local endpoint and ``None`` is given in
    :py:meth:`submit_request()` or :py:meth:`submit_syn_stream()`,
    then this function returns ``None``. If the stream does not exist,
    this function returns ``None``.

.. py:method:: Session.get_outbound_queue_size()

    Returns the number of frames in the outbound queue. This does not
    include the deferred DATA frames.

.. py:method:: Session.get_pri_lowest()

    Returns lowest priority value for the session.

.. py:method:: Session.fail_session(status_code)

    Submits GOAWAY frame. The status code *status_code* is ignored if
    the protocol version is :py:const:`PROTO_SPDY2`.

    This method should be called when the connection should be
    terminated after sending GOAWAY. If the remaining streams should
    be processed after GOAWAY, use :py:meth:`submit_goaway()` instead.

.. py:method:: Session.submit_request(pri, nv, data_prd=None, stream_user_data=None)

    Submits SYN_STREAM frame and optionally one or more DATA frames.

    The *pri* is priority of this request. ``0`` is the highest
    priority value. Use :py:meth:`get_pri_lowest()` to know the lowest
    priority value for this session.

    The *nv* is a list containing the name/value pairs.  The each
    element is a pair of unicode strings: name and value (e.g.,
    ``(u'host', u'localhost')``).

    The *nv* must include following name/value pairs:

    ``:method``
        HTTP method (e.g., ``GET``, ``POST``, ``HEAD``, etc)
    ``:scheme``
        URI scheme (e.g., ``https``)
    ``:path``
        Absolute path and parameters of this request (e.g., ``/foo``,
        ``/foo;bar;haz?h=j&y=123``)
    ``:version``
        HTTP version (e.g., ``HTTP/1.1``)
    ``:host``
        The hostport portion of the URI for this request (e.g.,
        ``example.org:443``). This is the same as the HTTP “Host”
        header field.

    If the session is initialized with the version
    :py:const:`PROTO_SPDY2`, the above names are translated to
    ``method``, ``scheme``, ``url``, ``version`` and ``host``
    respectively.

    The names in *nv* will be lower-cased when they are sent.

    If *data_prd* is not ``None``, it provides data which will be sent
    in subsequent DATA frames. In this case, a method that allows
    request message bodies
    (http://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9) must
    be specified with ``:method`` key in nv (e.g. ``POST``).  The type
    of *data_prd* is expected to be :py:class:`DataProvider`. If
    *data_prd* is ``None``, SYN_STREAM have FLAG_FIN set.

    .. note::

         This method does not increase reference count of *data_prd*,
         so the application must hold the reference to it until the
         stream is closed.

    The *stream_user_data* is data associated to the stream opened by
    this request and can be an arbitrary object, which can be
    retrieved later by :py:meth:`get_stream_user_data()`.

    Since the library reorders the frames and tries to send the
    highest prioritized one first and the SPDY specification requires
    the stream ID must be strictly increasing, the stream ID of this
    request cannot be known until it is about to sent. To know the
    stream ID of the request, the application can use
    :py:func:`before_ctrl_send_cb`. This callback is called just
    before the frame is sent. For SYN_STREAM frame, the argument frame
    has the stream ID assigned. Also since the stream is already
    opened, :py:meth:`get_stream_user_data()` can be used to get
    stream_user_data to identify which SYN_STREAM we are processing.

    The :py:class:`InvalidArgumentError` will be raised if the *pri*
    is invalid; or the *nv* includes empty name or ``None`` value.

.. py:method:: Session.submit_response(stream_id, nv, data_prd=None)

    Submits SYN_REPLY frame and optionally one or more DATA frames
    against the stream *stream_id*.

    The *nv* is a list containing the name/value pairs.  The each
    element is a pair of unicode strings: name and value (e.g.,
    ``(u'host', u'localhost')``).

    The *nv* must include following name/value pairs:

    ``:status``
        HTTP status code (e.g., ``200`` or ``200 OK``)
    ``:version``
        HTTP response version (e.g., ``HTTP/1.1``)

    If the session is initialized with the version
    :py:const:`PROTO_SPDY2`, the above names are translated to
    ``status`` and ``version`` respectively.

    The names in *nv* will be lower-cased when they are sent.

    If *data_prd* is not ``None``, it provides data which will be sent
    in subsequent DATA frames. The type of *data_prd* is expected to
    be :py:class:`DataProvider`.  If *data_prd* is ``None``, SYN_REPLY
    have FLAG_FIN set.

    .. note::

         This method does not increase reference count of *data_prd*,
         so the application must hold the reference to it until the
         stream is closed.

    The :py:class:`InvalidArgumentError` will be raised if the *nv*
    includes empty name or ``None`` value.

.. py:method:: Session.submit_syn_stream(flags, pri, nv, assoc_stream_id=0, stream_user_data=None)

    Submits SYN_STREAM frame. The *flags* is bitwise OR of the
    following values:

    * :py:const:`CTRL_FLAG_FIN`
    * :py:const:`CTRL_FLAG_UNIDIRECTIONAL`

    If *flags* includes :py:const:`CTRL_FLAG_FIN`, this frame has
    FLAG_FIN flag set.

    The *assoc_stream_id* is used for server-push. Specify 0 if this
    stream is not server-push. If session is initialized for client
    use, *assoc_stream_id* is ignored.

    The *pri* is priority of this request. ``0`` is the highest
    priority value. Use :py:meth:`get_pri_lowest()` to know the lowest
    priority value for this session.

    The *nv* is a list containing the name/value pairs.  The each
    element is a pair of unicode strings: name and value (e.g.,
    ``(u'host', u'localhost')``).

    The names in *nv* will be lower-cased when they are sent.

    The *stream_user_data* is data associated to the stream opened by
    this request and can be an arbitrary object, which can be
    retrieved later by :py:meth:`get_stream_user_data()`.

    This function is low-level in a sense that the application code
    can specify flags and the Associated-To-Stream-ID directly. For
    usual HTTP request, :py:meth:`submit_request()` is useful.

    The :py:class:`InvalidArgumentError` will be raised if the *pri*
    is invalid; or the *assoc_stream_id* is invalid; or the *nv*
    includes empty name or ``None`` value.

.. py:method:: Session.submit_syn_reply(flags, stream_id, nv)

    Submits SYN_REPLY frame. The *flags* is bitwise OR of the
    following values:

    * :py:const:`CTRL_FLAG_FIN`

    If *flags* includes :py:const:`CTRL_FLAG_FIN`, this frame has
    FLAG_FIN flag set.

    The stream which this frame belongs to is given in the
    *stream_id*. The *nv* is the name/value pairs in this frame.

    The *nv* is a list containing the name/value pairs.  The each
    element is a pair of unicode strings: name and value (e.g.,
    ``(u'host', u'localhost')``).

    The names in *nv* will be lower-cased when they are sent.

    The :py:class:`InvalidArgumentError` will be raised if the *nv*
    includes empty name or ``None`` value.

.. py:method:: Session.submit_headers(flags, stream_id, nv)

    Submits HEADERS frame. The *flags* is bitwise OR of the following
    values:

    * :py:const:`CTRL_FLAG_FIN`

    If *flags* includes :py:const:`CTRL_FLAG_FIN`, this frame has
    FLAG_FIN flag set.

    The stream which this frame belongs to is given in the
    *stream_id*. The *nv* is the name/value pairs in this frame.

    The *nv* is a list containing the name/value pairs.  The each
    element is a pair of unicode strings: name and value (e.g.,
    ``(u'host', u'localhost')``).

    The names in *nv* will be lower-cased when they are sent.

    The :py:class:`InvalidArgumentError` will be raised if the *nv*
    includes empty name or ``None`` value.

.. py:method:: Session.submit_data(stream_id, flags, data_prd)

    Submits one or more DATA frames to the stream *stream_id*. The
    data to be sent are provided by *data_prd*.  The type of
    *data_prd* is expected to be :py:class:`DataProvider`. If *flags*
    contains :py:const:`DATA_FLAG_FIN`, the last DATA frame has
    FLAG_FIN set.

    .. note::

         This method does not increase reference count of *data_prd*,
         so the application must hold the reference to it until the
         stream is closed.

.. py:method:: Session.submit_rst_stream(stream_id, status_code)

    Submits RST_STREAM frame to cancel/reject the stream *stream_id*
    with the status code *status_code*. See `Stream Status Codes`_ for
    available status codes.

.. py:method:: Session.submit_ping()

    Submits PING frame.

.. py:method:: Session.submit_goaway(status_code)

    Submits GOAWAY frame. The status code *status_code* is ignored if
    the protocol version is :py:const:`PROTO_SPDY2`. See `GOAWAY
    Status Codes`_ for available status codes.

.. py:method:: Session.submit_settings(flags, iv)

    Stores local settings and submits SETTINGS frame. The *flags* is
    bitwise OR of the values described in `SETTINGS Frame Flags`_.

    The *iv* is a list of tuple ``(settings_id, flag, value)``.  For
    settings_id, see `SETTINGS IDs`_. For flag, see `SETTINGS ID
    Flags`_.

    The :py:class:`InvalidArgumentError` will be raised if the *iv*
    contains duplicate settings ID or invalid value.

.. py:method:: Session.submit_window_update(stream_id, delta_window_size)

    Submits WINDOW_UPDATE frame. The effective range of the
    *delta_window_size* is ``[1, (1 << 31)-1]``, inclusive. But the
    application must be responsible to keep the resulting window
    ``size <= (1 << 31)-1``.

    The :py:class:`InvalidArgumentError` will be raised if the
    *delta_window_size* is 0 or negative. The
    :py:class:`StreamClosedError` will be raised if the stream is
    already closed or does not exist.

Helper Functions
----------------

.. py:function:: get_npn_protocols()

    Returns SPDY version strings which can be directly passed to
    ``ssl.SSLContext.set_npn_protocols()``. Please note that the
    returned list only includes SPDY version strings this library
    supports. If the application intends to support other fallback
    protocols (e.g., ``http/1.1``), the application should add them to
    the returned list.

.. py:function:: npn_get_version(proto)

    Returns SPDY version which spdylay library supports from the given
    protocol name. The *proto* is the unicode string to the protocol
    name. Currently, ``spdy/2`` and ``spdy/3`` are supported.  The
    returned nonzero SPDY version can be passed as the version
    argument in :py:class:`Session` constructor.

    This function returns nonzero SPDY version if it succeeds, or 0.


Data Provider Objects
---------------------

.. py:class:: DataProvider(source, read_cb)

    This class represents the data source and the way to read a chunk
    of data from it. The *source* is expected to be the data source to
    read, but the application can freely pass any object including
    ``None``. The *read_cb* is the callback function invoked when the
    library needs to read data. The data read will be sent as DATA
    frame.

    .. py:function:: read_cb(session, stream_id, length, read_ctrl, source)

        The *session* is the :py:class:`Session` object. The
        *stream_id* is the stream to send data. The *source* is the
        object passed as a *source* in DataProvider constructor. The
        implementation of this callback must read at most *length*
        bytes of data and return it as bytestring. When all data is
        read, assign :py:const:`READ_EOF` to ``read_ctrl.flags``.  If
        the application wants to postpone DATA frames, (e.g.,
        asynchronous I/O, or reading data blocks for long time), it is
        achieved by returning :py:const:`ERR_DEFERRED` without reading
        any data in this invocation. The library removes DATA frame
        from the outgoing queue temporarily. To move back deferred
        DATA frame to outgoing queue, call
        :py:meth:`Session.resume_data()`. In case of error, there are
        2 choices. Raising :py:class:`TemporalCallbackFailureError`
        will close the stream by issuing RST_STREAM with
        :py:const:`INTERNAL_ERROR`. Raising
        :py:class:`CallbackFailureError` will signal the entire
        session failure.

.. py:attribute:: DataProvider.source

.. py:attribute:: DataProvider.read_cb

Control Frame Objects
---------------------

.. py:class:: CtrlFrame

    The base class of SPDY control frames.

    .. py:attribute:: version

        Version

    .. py:attribute:: frame_type

        Frame type. See `Frame Types`_.

    .. py:attribute:: flags

        Flags. See `Control Frame Flags`_.

    .. py:attribute:: length

        Frame payload length

The following frame classes inherit :py:class:`CtrlFrame` class.

.. py:class:: SynStreamFrame

    .. py:attribute:: stream_id

        Stream ID

    .. py:attribute:: assoc_stream_id

        Associated-To-Stream-ID

    .. py:attribute:: pri

        Priority

    .. py:attribute:: slot

        Credential slot

    .. py:attribute:: nv

        List of name/value pair.

.. py:class:: SynReplyFrame

    .. py:attribute:: stream_id

        Stream ID

    .. py:attribute:: nv

        List of name/value pair.

.. py:class:: HeadersFrame

    .. py:attribute:: stream_id

        Stream ID

    .. py:attribute:: nv

        List of name/value pair.

.. py:class:: RstStreamFrame


    .. py:attribute:: stream_id

        Stream ID

    .. py:attribute:: status_code

        Status code

.. py:class:: SettingsFrame

    .. py:attribute:: iv

        List of tuple ``(settings_id, flags, value)``

.. py:class:: PingFrame

    .. py:attribute:: unique_id

        Unique ID

.. py:class:: GoawayFrame

    .. py:attribute:: last_good_stream_id

        Last good stream ID

    .. py:attribute:: status_code

        Status code

.. py:class:: WindowUpdateFrame

    .. py:attribute:: stream_id

        Stream ID

    .. py:attribute:: delta_window_size

        Delta window size

Exceptions
----------

.. py:class:: EOFError

.. py:class:: CallbackFailureError

.. py:class:: TemporalCallbackFailureError

.. py:class:: InvalidArgumentError

.. py:class:: ZlibError

.. py:class:: UnsupportedVersionError

.. py:class:: StreamClosedError

Read Callback Flags
-------------------

.. py:data:: READ_EOF

Error Codes
-----------

.. py:data:: ERR_INVALID_ARGUMENT
.. py:data:: ERR_ZLIB
.. py:data:: ERR_UNSUPPORTED_VERSION
.. py:data:: ERR_WOULDBLOCK
.. py:data:: ERR_PROTO
.. py:data:: ERR_INVALID_FRAME
.. py:data:: ERR_EOF
.. py:data:: ERR_DEFERRED
.. py:data:: ERR_STREAM_ID_NOT_AVAILABLE
.. py:data:: ERR_STREAM_CLOSED
.. py:data:: ERR_STREAM_CLOSING
.. py:data:: ERR_STREAM_SHUT_WR
.. py:data:: ERR_INVALID_STREAM_ID
.. py:data:: ERR_INVALID_STREAM_STATE
.. py:data:: ERR_DEFERRED_DATA_EXIST
.. py:data:: ERR_SYN_STREAM_NOT_ALLOWED
.. py:data:: ERR_GOAWAY_ALREADY_SENT
.. py:data:: ERR_INVALID_HEADER_BLOCK
.. py:data:: ERR_INVALID_STATE
.. py:data:: ERR_GZIP
.. py:data:: ERR_TEMPORAL_CALLBACK_FAILURE

Following error codes indicate fatal error.

.. py:data:: ERR_FATAL
.. py:data:: ERR_NOMEM
.. py:data:: ERR_CALLBACK_FAILURE

Frame Types
-----------

.. py:data:: SYN_STREAM

.. py:data:: SYN_REPLY

.. py:data:: RST_STREAM

.. py:data:: SETTINGS

.. py:data:: NOOP

   Note that this was deprecated in SPDY/3.

.. py:data:: PING

.. py:data:: GOAWAY

.. py:data:: HEADERS

.. py:data:: WINDOW_UPDATE

   This first appeared in SPDY/3.

.. py:data:: CREDENTIAL

   This first appeared in SPDY/3.

Control Frame Flags
-------------------

.. py:data:: CTRL_FLAG_NONE

   Indicates no flags set.

.. py:data:: CTRL_FLAG_FIN

.. py:data:: CTRL_FLAG_UNIDIRECTIONAL

Stream Status Codes
-------------------

.. py:data:: OK

   This is not a valid status code for RST_STREAM. Don't use this in
   :py:meth:`Session.submit_rst_stream()`.

.. py:data:: PROTOCOL_ERROR

.. py:data:: INVALID_STREAM

.. py:data:: REFUSED_STREAM

.. py:data:: UNSUPPORTED_VERSION

.. py:data:: CANCEL

.. py:data:: INTERNAL_ERROR

.. py:data:: FLOW_CONTROL_ERROR

Following status codes were introduced in SPDY/3.

.. py:data:: STREAM_IN_USE

.. py:data:: STREAM_ALREADY_CLOSED

.. py:data:: INVALID_CREDENTIALS

.. py:data:: FRAME_TOO_LARGE

GOAWAY Status Codes
-------------------

.. py:data:: GOAWAY_OK

.. py:data:: GOAWAY_PROTOCOL_ERROR

.. py:data:: GOAWAY_INTERNAL_ERROR

SETTINGS Frame Flags
--------------------

.. py:data:: FLAG_SETTINGS_NONE

.. py:data:: FLAG_SETTINGS_CLEAR_SETTINGS

SETTINGS IDs
------------

.. py:data:: SETTINGS_UPLOAD_BANDWIDTH

.. py:data:: SETTINGS_DOWNLOAD_BANDWIDTH

.. py:data:: SETTINGS_ROUND_TRIP_TIME

.. py:data:: SETTINGS_MAX_CONCURRENT_STREAMS

.. py:data:: SETTINGS_CURRENT_CWND

.. py:data:: SETTINGS_DOWNLOAD_RETRANS_RATE

.. py:data:: SETTINGS_INITIAL_WINDOW_SIZE

.. py:data:: SETTINGS_CLIENT_CERTIFICATE_VECTOR_SIZE

.. py:data::  SETTINGS_MAX

SETTINGS ID Flags
-----------------

.. py:data:: ID_FLAG_SETTINGS_NONE

.. py:data:: ID_FLAG_SETTINGS_PERSIST_VALUE

.. py:data:: ID_FLAG_SETTINGS_PERSISTED

Simple SPDY Client
------------------

This module offers a simple SPDY client implementation.  The function
:py:func:`urlfetch()` fetches given URLs. For each URL,
*StreamHandlerClass* is instantiated and its methods are called when
certain event occurs. The *StreamHandlerClass* must be a subclass of
:py:class:`BaseSPDYStreamHandler`.

.. py:function:: urlfetch(url_or_urls, StreamHandlerClass)

    Opens URL and handles the response from the servers.

    The *url_or_urls* is either one URL string or list of URL string.
    For each URL, *StreamHandlerClass* is instantiated and it handles
    the request to and response from the server. If successive URLs in
    *url_or_urls* list have same origin, they are processed in one
    SPDY session.

.. py:class:: BaseSPDYStreamHandler(url, fetcher)

    This class handles one URL retrieval, which corresponds one SPDY
    stream. The *url* is the URL to fetch. The *fetcher* is a driver
    object to call methods of this object. For now it is opaque
    object. This class is intended to be subclassed by the application
    to add specific behavior.

    ``BaseSPDYStreamHandler`` has the following instance variables:

    .. py:attribute:: url

        The URL for this stream.

    .. py:attribute:: stream_id

        The stream ID for this stream.

    ``BaseSPDYStreamHandler`` has the following methods:

    .. py:method:: on_header(nv)

        Called when name/value pairs (headers) *nv* is received.  This
        method may be overridden by subclasses. The default
        implementation does nothing.

    .. py:method:: on_data(data)

        Called when *data* is received. This method may be overridden
        by subclass. The default implementation does nothing.

    .. py:method:: on_close(status_code)

        Called when this stream is closed. The *status_code* indicates
        the reason of the closure. See `Stream Status Codes`_.  This
        method may be overridden by subclass. The default
        implementation does nothing.

The example follows:

.. literalinclude:: ../python/spdyclient.py
    :language: python

Simple SPDY Server
------------------

This module offers a simple SPDY server implementation to ready for
use with little additional code.

The :py:class:`ThreadedSPDYServer` is a ``socketserver.TCPServer``
subclass.  As the name of the class suggests, it is multi threaded.
It only supports SPDY connection and does not fallback to HTTP/1.1.
Since it uses TLS NPN extension, Python 3.3.0 or later is required.

.. py:class:: ThreadedSPDYServer(server_address, RequestHandlerCalss, cert_file, key_file)

    This class builds on ``TCPServer`` class by passing
    *server_address* and *RequestHandlerCalss*. The request is handled
    by the instance of *RequestHandlerCalss*.

The :py:class:`ThreadedSPDYServer` requires a *RequestHandlerCalss* on
instantiation, which must be a subclass of
:py:class:`BaseSPDYRequestHandler`.

Most texts are copied (and modified) from ``http.server``
documentation.

.. py:class:: BaseSPDYRequestHandler(request, client_address, server)

    This class is used to handle the SPDY requests (streams) that
    arrive at the server. By itself, it cannot respond to any actual
    SPDY requests; it must be subclassed to handle each request method
    (e.g. ``GET`` or ``POST``). ``BaseSPDYRequestHandler`` provides a
    number of class and instance variables, and methods for use by
    subclasses.

    The handler will gather headers (name/value pairs in SPDY terms)
    and read POST data (if any), then call a method specific to the
    request type. The method name is constructed from the request. For
    example, for the request method ``SPAM``, the ``do_SPAM()`` method
    will be called with no arguments. All of the relevant information
    is stored in instance variables of the handler. Subclasses should
    not need to override or extend the ``__init__()`` method.

    .. note::

        Currently, this implementation accepts request body only if
        method is POST and the request body will be stored in memory.

    ``BaseSPDYRequestHandler`` has the following instance variables:

    .. py:attribute:: client_address

        Contains a tuple of the form ``(host, port)`` referring to the
        client's address.

    .. py:attribute:: server

        Contains the server instance.

    .. py:attribute:: command

        Contains the command (request type, method). For example,
        ``GET``.

    .. py:attribute:: path

        Contains the request path.

    .. py:attribute:: request_version

        Contains the version string from the request. For example,
        ``HTTP/1.1``.

    .. py:attribute:: headers

        Contains the request headers. Each name/value pair is a tuple
        of the form ``(name, value)``.

    .. py:attribute:: rfile

        Contains an input stream, positioned at the start of the
        optional input data. If there is no optional input data, it
        may be ``None``.

    .. py:attribute:: wfile

        Contains the output stream for writing a response back to the
        client.

    ``BaseSPDYRequestHandler`` has the following class variables:

    .. py:attribute:: server_version

        Specifies the server software version.

    .. py:attribute:: sys_version

        Contains the Python system version.

    A ``BaseSPDYRequestHandler`` instance has the following methods:

    .. py:method:: handle()

        Interacts client exchanging SPDY frames. When a request is
        completely received, it calls appropriate ``do_*()`` method.
        This method will handle multiple requests (streams) until SPDY
        session is over.

    .. py:method:: send_error(code, message=None)

        Send a complete error reply to the client The numeric *code*
        specifies the HTTP error code, with *message* as optional,
        more specific text. A complete set of headers is sent,
        followed by HTML text.

    .. py:method:: send_response(code, message=None)

        Adds a response code and, optionally, short message.
        This will be formatted as ':status' response header field.

    .. py:method:: send_header(keyword, value)

        Adds the HTTP header. The *keyword* and *value* must be
        unicode strings and not ``None``.

The example of ``BaseSPDYRequestHandler`` and ``ThreadedSPDYServer``
follows:

.. literalinclude:: ../python/spdyserv.py
    :language: python
