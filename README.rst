Spdylay - SPDY C Library
========================

This is an experimental implementation of Google's SPDY protocol
version 2 in C.

The current status of development is in very early stage.  But there
is a demo program ``spdycat`` in *examples* directory, which can
connect to SPDY-capable server via SSL and select spdy/2 with NPN and
get a resource given in the command-line::

    $ ./spdycat -d https://www.google.com/
    NPN select next proto: server offers:
      * spdy/2
      * http/1.1
    send SYN_STREAM frame (stream_id=1, flags=1, length=83)
      method: GET
      scheme: https
      url: /
      user-agent: spdylay/0.0.0
      version: HTTP/1.1
    recv SYN_REPLY frame (stream_id=1, flags=0, length=579)
      cache-control: private, max-age=0
      content-type: text/html; charset=ISO-8859-1
      date: Sun, 29 Jan 2012 15:36:57 GMT
      expires: -1
      server: gws
      status: 200 OK
      version: HTTP/1.1
      x-frame-options: SAMEORIGIN
      x-xss-protection: 1; mode=block
    recv DATA frame (stream_id=1, flags=0, length=4096)
    recv DATA frame (stream_id=1, flags=0, length=2419)
    recv DATA frame (stream_id=1, flags=0, length=4096)
    recv DATA frame (stream_id=1, flags=1, length=3167)
    send GOAWAY frame (last_good_stream_id=0)
