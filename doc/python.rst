Spdylay Python Extension
========================

.. py:module:: spdylay

This is the Python extension of Spdylay library.  The wrapping is made
using Cython.  The extension provides mostly same APIs as original C
API. The API is still callback-centric.  We use exceptions instead of
error code where they are appropriate.

Build
-----

To generate C source code from ``spdylay.pyx``, run ``cython``::

    $ cython spdylay.pyx

To build extension, run ``setup.py``::

    $ python setup.py build_ext

Session objects
---------------

.. py:class:: Session(side, version, send_cb=None, recv_cb=None, on_ctrl_recv_cb=None, on_data_chunk_recv_cb=None, on_stream_close_cb=None, on_request_recv_cb=None, user_data=None)

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

.. py:method:: Session.resume_data(stream_id)

    Puts back previously deferred DATA frame in the stream *stream_id*
    to the outbound queue.

    The :py:class:`InvalidArgumentError` will be raised if the stream
    does not exist or no deferred data exist.

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

    The *nv* contains the name/value pairs. For ``i >= 0``,
    ``nv[2 * i]`` contains a bytestring indicating name and
    ``nv[2 * i + 1]`` contains a bytestring indicating value.

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
    of *data_prd* is expected to be :py:class:`DataProvider`.  This
    method does not increase reference count of *data_prd*, so the
    application must hold the reference to it until the stream is
    closed.  If *data_prd* is ``None``, SYN_STREAM have FLAG_FIN set.

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
    is invalid.

.. py:method:: Session.submit_response(stream_id, nv, data_prd=None)

    Submits SYN_REPLY frame and optionally one or more DATA frames
    against the stream *stream_id*.

    The *nv* contains the name/value pairs. For ``i >= 0``,
    ``nv[2 * i]`` contains a bytestring indicating name and
    ``nv[2 * i + 1]`` contains a bytestring indicating value.

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
    be :py:class:`DataProvider`.  This method does not increase
    reference count of *data_prd*, so the application must hold the
    reference to it until the stream is closed.  If *data_prd* is
    ``None``, SYN_REPLY have FLAG_FIN set.

.. py:method:: Session.submit_request()

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

Stream Status Codes
-------------------

.. py:data:: OK

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
