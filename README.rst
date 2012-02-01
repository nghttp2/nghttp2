Spdylay - SPDY C Library
========================

This is an experimental implementation of Google's SPDY protocol
version 2 in C.

The current status of development is in very early stage.  But there
is a demo program ``spdycat`` in *examples* directory, which can
connect to SPDY-capable server via SSL and select spdy/2 with NPN and
get a resource given in the command-line::

    $ ./spdycat -vn https://www.google.com/
    [  0.029] NPN select next protocol: the remote server offers:
              * spdy/2
              * http/1.1
    [  0.040] recv SETTINGS frame <version=2, flags=0, length=12>
              (niv=1)
              [4(1):100]
    [  0.040] send SYN_STREAM frame <version=2, flags=1, length=107>
              (stream_id=1, assoc_stream_id=0, pri=3)
              host: www.google.com:443
              method: GET
              scheme: https
              url: /
              user-agent: spdylay/0.0.0
              version: HTTP/1.1
    [  0.087] recv SYN_REPLY frame <version=2, flags=0, length=580>
              (stream_id=1)
              cache-control: private, max-age=0
              content-type: text/html; charset=ISO-8859-1
              date: Wed, 01 Feb 2012 15:43:00 GMT
              expires: -1
              server: gws
              status: 200 OK
              version: HTTP/1.1
              x-frame-options: SAMEORIGIN
              x-xss-protection: 1; mode=block
    [  0.087] recv DATA frame (stream_id=1, flags=0, length=4096)
    [  0.088] recv DATA frame (stream_id=1, flags=0, length=2617)
    [  0.094] recv DATA frame (stream_id=1, flags=0, length=4096)
    [  0.094] recv DATA frame (stream_id=1, flags=1, length=828)
    [  0.094] send GOAWAY frame <version=2, flags=0, length=4>
              (last_good_stream_id=0)

Please note that OpenSSL with
`NPN <http://technotes.googlecode.com/git/nextprotoneg.html>`_
support is required in order to build and run ``spdycat``.

==============
Build from git
==============

Building from git is easy, but please be sure that at least autoconf 2.68 is
used.::

    $ autoreconf -i
    $ automake
    $ autoconf
    $ ./configure
    $ make
