Spdylay - SPDY C Library
========================

This is an experimental implementation of Google's SPDY protocol
version 2 in C.

The current status of development is in very early stage. But
``spdycl`` in *examples* directory can connect to SPDY-capable server
via SSL and select spdy/2 with NPN and get a resource given in
command-line::

    $ ./spdycl www.google.com 443 /
    NPN select next proto: server offers:
    * spdy/2
    * http/1.1
    send SYN_STREAM frame (stream_id=1, flags=1, length=65)
      method: GET
      scheme: https
      url: /
      version: HTTP/1.1
    recv SYN_REPLY frame (stream_id=1, flags=0, length=576)
      cache-control: private, max-age=0
      content-type: text/html; charset=ISO-8859-1
      date: Fri, 27 Jan 2012 18:53:12 GMT
      expires: -1
      server: gws
      set-cookie: (INTENTIONALLY HIDDEN)
      status: 200 OK
      version: HTTP/1.1
      x-frame-options: SAMEORIGIN
      x-xss-protection: 1; mode=block
    recv DATA frame (stream_id=1, flags=0, length=4096)
    recv DATA frame (stream_id=1, flags=0, length=3310)
    recv DATA frame (stream_id=1, flags=0, length=4096)
    recv DATA frame (stream_id=1, flags=0, length=4096)
    recv DATA frame (stream_id=1, flags=0, length=4096)
    recv DATA frame (stream_id=1, flags=0, length=4096)
    recv DATA frame (stream_id=1, flags=0, length=4096)
    recv DATA frame (stream_id=1, flags=0, length=1188)
    recv DATA frame (stream_id=1, flags=0, length=4096)
    recv DATA frame (stream_id=1, flags=1, length=1514)
