API Reference
=============

Includes
--------

To use the public APIs, include ``nghttp2/nghttp2.h``::

    #include <nghttp2/nghttp2.h>

The header files are also available online: :doc:`nghttp2.h` and
:doc:`nghttp2ver.h`.

Remarks
-------

Do not call `nghttp2_session_send()`, `nghttp2_session_mem_send()`,
`nghttp2_session_recv()` or `nghttp2_session_mem_recv()` from the
nghttp2 callback functions directly or indirectly. It will lead to the
crash.  You can submit requests or frames in the callbacks then call
these functions outside the callbacks.

Currently, `nghttp2_session_send()` and `nghttp2_session_mem_send()`
do not send client connection preface
(:macro:`NGHTTP2_CLIENT_CONNECTION_PREFACE`).  The applications are
responsible to send it before sending any HTTP/2 frames using these
functions if :type:`nghttp2_session` is configured as client.
Similarly, `nghttp2_session_recv()` and `nghttp2_session_mem_recv()`
do not consume client connection preface.  The applications are
responsible to receive it before calling these functions if
:type:`nghttp2_session` is configured as server.
