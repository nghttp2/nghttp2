Spdylay - SPDY C Library
========================

This is an experimental implementation of Google's SPDY protocol
version 2 and 3 in C.

This library provides SPDY framing layer implementation.  It does not
perform any I/O operations.  When the library needs them, it calls the
callback functions provided by the application. It also does not
include any event polling mechanism, so the application can freely
choose the way of handling events. This library code does not depend
on any particular SSL library (except for example programs which
depend on OpenSSL 1.0.1 or later).

STATUS
------

SPDY/2
    Most of the SPDY/2 functionality has been implemented.

SPDY/3
    CREDENTIALS frame has not been implemented yet.

In both versions, the direct support of server-push has not been
available yet.  The application can achieve server-push using
primitive APIs though.

As described below, we can create SPDY client and server with the
current Spdylay API.

Build from git
--------------

The following packages are needed to build the library:

* pkg-config >= 0.20

To build and run the example programs, the following packages are
needed:

* OpenSSL >= 1.0.1

Building from git is easy, but please be sure that at least autoconf 2.68 is
used.::

    $ autoreconf -i
    $ automake
    $ autoconf
    $ ./configure
    $ make

API
---

The public API reference is available on online. Visit
http://spdylay.sourceforge.net/.  All public APIs are in
*spdylay/spdylay.h*. All public API functions as well as the callback
function typedefs are documented.

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

``spdycat`` can speak SPDY/3. Note that SPDY/3 is still moving target
and thus considered highly experimental. ``-3`` option forces ``spdycat``
to use SPDY/3 only::

    $ ./spdycat -nv3 https://localhost:3000/
    [  0.000] NPN select next protocol: the remote server offers:
              * spdy/2
              * spdy/3
              NPN selected the protocol: spdy/3
    [  0.002] send SYN_STREAM frame <version=3, flags=1, length=95>
              (stream_id=1, assoc_stream_id=0, pri=3)
              :host: localhost:3000
              :method: GET
              :path: /
              :scheme: https
              :version: HTTP/1.1
              user-agent: spdylay/0.0.0
    [  0.003] recv SYN_REPLY frame <version=3, flags=0, length=95>
              (stream_id=1)
              :status: 404 Not Found
              :version: HTTP/1.1
              cache-control: max-age=3600
              content-length: 144
              date: Sun, 26 Feb 2012 09:16:51 GMT
              server: spdyd spdylay/0.1.0
    [  0.003] recv DATA frame (stream_id=1, flags=0, length=144)
    [  0.003] recv DATA frame (stream_id=1, flags=1, length=0)
    [  0.003] send GOAWAY frame <version=3, flags=0, length=8>
              (last_good_stream_id=0)

SPDY server is called ``spdyd``. It is a non-blocking server and only
serves static contents. It can speak SPDY/2 and SPDY/3::

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

There is another SPDY server called ``spdynative``, which is
`node.native <https://github.com/d5/node.native>`_ style simple SPDY
server::

    #include <iostream>

    #include "spdy.h"

    int main()
    {
      spdy server;
      if(!server.listen("localhost", 8080, "server.key", "server.crt",
                        [](request& req, response& res) {
                          res.set_status(200);
                          res.set_header("content-type", "text/plain");
                          res.end("C++ FTW\n");
                        }))
        return EXIT_FAILURE;

      std::cout << "Server running at http://localhost:8080/" << std::endl;
      return reactor::run(server);
    }

Don't expect much from ``spdynative``. It is just an example and does
not support asynchronous I/O at all.
