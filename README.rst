nghttp2 - HTTP/2.0 C Library
============================

This is an experimental implementation of Hypertext Transfer Protocol
version 2.0.

Development Status
------------------

We started to implement HTTP-defat-04/2.0
(http://tools.ietf.org/html/draft-ietf-httpbis-http2-04) based on
spdylay code base.

The following features are not implemented:

* Header continuation
* PUSH_PROMISE and server-push in general
* ALPN: ``nghttp`` client and ``nghttpd`` server use OpenSSL without ALPN
  support and still use NPN to negotiate ``HTTP-draft-04/2.0``.
* HTTP Upgrade dance

With those missing parts, the library is not still inter-operable
right now.

The ``nghttp`` client and ``nghttpd`` server are working now assuming
the above limitation.  Both programs start HTTP/2.0 with `prior
knowledge
<http://tools.ietf.org/html/draft-ietf-httpbis-http2-04#section-3.4>`_
or TLS NPN negotiation. No HTTP upgrade dance is supported yet.  You
can see the HTTP/2.0 frames back and forth and connection-level and
stream level flow controls.

Here is sample output from ``nghttp`` client::

    $ src/nghttp https://localhost:3000/COPYING http://localhost:3000/AUTHORS  -nv --no-tls
    [  0.000] Handshake complete
    [  0.000] recv SETTINGS frame <length=8, flags=0, stream_id=0>
              (niv=1)
              [4:100]
    [  0.000] send HEADERS frame <length=72, flags=5, stream_id=1>
              ; END_STREAM | END_HEADERS
              ; Open new stream
              :host: localhost:3000
              :method: GET
              :path: /COPYING
              :scheme: https
              accept: */*
              accept-encoding: gzip, deflate
              user-agent: nghttp2/0.1.0-DEV
    [  0.000] send HEADERS frame <length=14, flags=5, stream_id=3>
              ; END_STREAM | END_HEADERS
              ; Open new stream
              :host: localhost:3000
              :method: GET
              :path: /AUTHORS
              :scheme: http
              accept: */*
              accept-encoding: gzip, deflate
              user-agent: nghttp2/0.1.0-DEV
    [  0.001] recv HEADERS frame <length=121, flags=4, stream_id=1>
              ; END_HEADERS
              ; First response header
              :status: 200 OK
              cache-control: max-age=3600
              content-length: 1080
              date: Fri, 19 Jul 2013 17:02:21 GMT
              last-modified: Fri, 12 Jul 2013 14:55:22 GMT
              server: nghttpd nghttp2/0.1.0-DEV
    [  0.001] recv DATA frame (length=1080, flags=0, stream_id=1)
    [  0.001] recv DATA frame (length=0, flags=1, stream_id=1)
    [  0.001] recv HEADERS frame <length=6, flags=4, stream_id=3>
              ; END_HEADERS
              ; First response header
              :status: 200 OK
              cache-control: max-age=3600
              content-length: 66
              date: Fri, 19 Jul 2013 17:02:21 GMT
              last-modified: Fri, 12 Jul 2013 14:55:22 GMT
              server: nghttpd nghttp2/0.1.0-DEV
    [  0.001] recv DATA frame (length=66, flags=0, stream_id=3)
    [  0.001] recv DATA frame (length=0, flags=1, stream_id=3)
    [  0.001] send GOAWAY frame <length=8, flags=0, stream_id=0>
              (last_stream_id=0, error_code=NO_ERROR(0), opaque_data=)
