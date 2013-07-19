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
* PRIORITY frame handling
* PUSH_PROMISE and server-push in general
* Client connection header: spdycat and spdyd do not send/handle
  client connection header.
* ALPN: spdycat and spdyd use openssl without ALPN support and still
  uses NPN to negotiate HTTP-draft-04/2.0.

With those missing parts, the library is not still inter-operable
right now.

The spdycat and spdyd are (the names are now odd for HTTP/2.0) working
now assuming the above limitation. You can see the HTTP/2.0 frames
back and forth and connection-level and stream level flow controls.
