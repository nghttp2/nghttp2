API Reference
=============

Includes
--------

To use the public APIs, include ``spdylay/spdylay.h``::

    #include <spdylay/spdylay.h>

Remarks
-------

Do not call `spdylay_session_send`, `spdylay_session_recv` or
`spdylay_session_mem_recv` from the spdylay callback functions
directly or indirectly. It will lead to the crash. You can submit
requests or frames in the callbacks then call `spdylay_session_send`,
`spdylay_session_recv` or `spdylay_session_mem_recv` outside of the
callbacks.
