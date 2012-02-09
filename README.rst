Spdylay - SPDY C Library
========================

This is an experimental implementation of Google's SPDY protocol
version 2 in C.

The current status of development is in a beta stage now. As described
below, we can create SPDY client and server with the current Spdylay
API.

Build from git
--------------

Building from git is easy, but please be sure that at least autoconf 2.68 is
used.::

    $ autoreconf -i
    $ automake
    $ autoconf
    $ ./configure
    $ make

Examples
--------

*examples* directory contains SPDY client and server implementation
using Spdylay. These programs are intended to make sure that Spdylay
API is acutally usable for real implementation and also for debugging
purposes. Please note that OpenSSL with `NPN
<http://technotes.googlecode.com/git/nextprotoneg.html>`_ support is
required in order to build and run these programs.  At the time of
this writing, the Beta 2 of OpenSSL 1.0.1 supports NPN.

SPDY client is called ``spdycat``. It is a dead simple downloader like
wget/curl. It connects to SPDY server and gets resources given in the
command-line::

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

SPDY server is called ``spdyd``. It is a non-blocking server and only
serves static contents. It only speaks ``spdy/2``::

    $ ./spdyd --htdocs=/your/htdocs/ -v 3000 server.key server.crt
    The negotiated next protocol: spdy/2
    [id=1] [  1.633] recv SYN_STREAM frame <version=2, flags=1, length=99>
              (stream_id=1, assoc_stream_id=0, pri=3)
              host: localhost:3000
              method: GET
              scheme: https
              url: /
              user-agent: spdylay/0.0.0
              version: HTTP/1.1
    [id=1] [  1.633] send SYN_REPLY frame <version=2, flags=0, length=126>
              (stream_id=1)
              cache-control: max-age=3600
              content-length: 8472
              date: Mon, 16 Jan 2012 12:46:27 GMT
              last-modified: Mon, 16 Jan 2012 12:46:27 GMT
              server: spdyd spdylay/0.1.0
              status: 200 OK
              version: HTTP/1.1
    [id=1] [  1.633] send DATA frame (stream_id=1, flags=0, length=4104)
    [id=1] [  1.633] send DATA frame (stream_id=1, flags=0, length=4104)
    [id=1] [  1.633] send DATA frame (stream_id=1, flags=0, length=288)
    [id=1] [  1.633] send DATA frame (stream_id=1, flags=1, length=8)
    [id=1] [  1.633] stream_id=1 closed
    [id=1] [  1.634] recv GOAWAY frame <version=2, flags=0, length=4>
              (last_good_stream_id=0)
    [id=1] [  1.634] closed

Currently, ``spdyd`` needs ``epoll`` or ``kqueue``.
