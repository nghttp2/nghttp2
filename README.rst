nghttp2 - HTTP/2.0 C Library
============================

This is an experimental implementation of Hypertext Transfer Protocol
version 2.0.

Development Status
------------------

We started work based on spdylay codebase and just replaced spdylay
keyword with nghttp2. So just now it is just a relabled SPDY
implementation and is not HTTP/2.0 implementation at all. To take
advantage of the existing code, we will perform the following steps to
implement HTTP/2.0 based on implementation draft
(http://tools.ietf.org/html/draft-ietf-httpbis-http2-04):

1. Implement HTTP/2.0 frames and semantics, except for header
   compression. Server push may be omitted because I am not so
   interested in it.
2. Modify spdycat and spdyd to work with new library code and perform
   internal testing. We use NPN for TLS for now.
3. Implement header compression, which may be based on draft-x (x >=
   1).
4. Add new client and server which can perform HTTP upgrade mechanism.
5. At this step, the library and demo client/server should be
   interoperable to the other implementation. Do some interoperable
   testing with the other ones (e.g., node-http2)
