Spdylay - SPDY C Library
========================

This is an experimental implementation of Google's SPDY protocol
version 2 in C.

The current status of development is in very early stage.  But there
is a demo program ``spdycat`` in *examples* directory, which can
connect to SPDY-capable server via SSL and select spdy/2 with NPN and
get a resource given in the command-line::

    $ ./spdycat -vn https://www.google.com/
    [  0.023] NPN select next protocol: the remote server offers:
      * spdy/2
      * http/1.1
    [  0.034] send SYN_STREAM frame (stream_id=1, assoc_stream_id=0, flags=1, length=83, pri=3)
      method: GET
      scheme: https
      url: /
      user-agent: spdylay/0.0.0
      version: HTTP/1.1
    [  0.082] recv SYN_REPLY frame (stream_id=1, flags=0, length=580)
      cache-control: private, max-age=0
      content-type: text/html; charset=ISO-8859-1
      date: Sun, 29 Jan 2012 15:36:57 GMT
      expires: -1
      server: gws
      status: 200 OK
      version: HTTP/1.1
      x-frame-options: SAMEORIGIN
      x-xss-protection: 1; mode=block
    [  0.083] recv DATA frame (stream_id=1, flags=0, length=4096)
    [  0.083] recv DATA frame (stream_id=1, flags=0, length=2426)
    [  0.084] recv DATA frame (stream_id=1, flags=0, length=4096)
    [  0.091] recv DATA frame (stream_id=1, flags=1, length=3114)
    [  0.091] send GOAWAY frame (last_good_stream_id=0)

Please note that OpenSSL with
`NPN <http://technotes.googlecode.com/git/nextprotoneg.html>`_
support is required in order to build and run ``spdycat``.

==============
Build from git
==============

Building from git is easy, but please be sure that at least autoconf 2.68 is
used.

autoreconf -i
automake
autoconf
./configure
make
