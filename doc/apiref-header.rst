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

Do not call `nghttp2_session_send`, `nghttp2_session_recv` or
`nghttp2_session_mem_recv` from the nghttp2 callback functions
directly or indirectly. It will lead to the crash. You can submit
requests or frames in the callbacks then call `nghttp2_session_send`,
`nghttp2_session_recv` or `nghttp2_session_mem_recv` outside of the
callbacks.
