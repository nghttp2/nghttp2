Programmers' Guide
==================

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

`nghttp2_session_send()` and `nghttp2_session_mem_send()` send first
24 bytes of client magic string (MAGIC)
(:macro:`NGHTTP2_CLIENT_MAGIC`) on client configuration.  The
applications are responsible to send SETTINGS frame as part of
connection preface using `nghttp2_submit_settings()`.  Similarly,
`nghttp2_session_recv()` and `nghttp2_session_mem_recv()` consume
MAGIC on server configuration unless
`nghttp2_option_set_no_recv_client_magic()` is used with nonzero
option value.

.. _http-messaging:

HTTP Messaging
--------------

By default, nghttp2 library checks HTTP messaging rules described in
`HTTP/2 specification, section 8
<https://tools.ietf.org/html/draft-ietf-httpbis-http2-17#section-8>`_.
Everything described in that section is not validated however.  We
briefly describe what the library does in this area.  In the following
description, without loss of generality we omit CONTINUATION frame
since they must follow HEADERS frame and are processed atomically.  In
other words, they are just one big HEADERS frame.  To disable these
validations, use `nghttp2_option_set_no_http_messaging()`.

For HTTP request, including those carried by PUSH_PROMISE, HTTP
message starts with one HEADERS frame containing request headers.  It
is followed by zero or more DATA frames containing request body, which
is followed by zero or one HEADERS containing trailer headers.  The
request headers must include ":scheme", ":method" and ":path" pseudo
header fields unless ":method" is not "CONNECT".  ":authority" is
optional, but nghttp2 requires either ":authority" or "Host" header
field must be present.  If ":method" is "CONNECT", the request headers
must include ":method" and ":authority" and must omit ":scheme" and
":path".

For HTTP response, HTTP message starts with zero or more HEADERS
frames containing non-final response (status code 1xx).  They are
followed by one HEADERS frame containing final response headers
(non-1xx).  It is followed by zero or more DATA frames containing
response body, which is followed by zero or one HEADERS containing
trailer headers.  The non-final and final response headers must
contain ":status" pseudo header field containing 3 digits only.

All request and response headers must include exactly one valid value
for each pseudo header field.  Additionally nghttp2 requires all
request headers must not include more than one "Host" header field.

HTTP/2 prohibits connection-specific header fields.  The following
header fields must not appear: "Connection", "Keep-Alive",
"Proxy-Connection", "Transfer-Encoding" and "Upgrade".  Additionally,
"TE" header field must not include any value other than "trailers".

Each header field name and value must obey the field-name and
field-value production rules described in `RFC 7230, section
3.2. <https://tools.ietf.org/html/rfc7230#section-3.2>`_.
Additionally, all field name must be lower cased.  While the pseudo
header fields must satisfy these rules, we just ignore illegal regular
headers (this means that these header fields are not passed to
application callback).  This is because these illegal header fields
are floating around in existing internet and resetting stream just
because of this may break many web sites.  This is especially true if
we forward to or translate from HTTP/1 traffic.

For "http" or "https" URIs, ":path" pseudo header fields must start
with "/".  The only exception is OPTIONS request, in that case, "*" is
allowed in ":path" pseudo header field to represent system-wide
OPTIONS request.

With the above validations, nghttp2 library guarantees that header
field name passed to `nghttp2_on_header_callback()` is not empty.
Also required pseudo headers are all present and not empty.

nghttp2 enforces "Content-Length" validation as well.  All request or
response headers must not contain more than one "Content-Length"
header field.  If "Content-Length" header field is present, it must be
parsed as 64 bit signed integer.  The sum of data length in the
following DATA frames must match with the number in "Content-Length"
header field if it is present (this does not include padding bytes).

Any deviation results in stream error of type PROTOCOL_ERROR.  If
error is found in PUSH_PROMISE frame, stream error is raised against
promised stream.
