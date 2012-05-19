Spdylay - SPDY C Library
========================

This is an experimental implementation of Google's SPDY protocol in C.

This library provides SPDY version 2 and 3 framing layer
implementation.  It does not perform any I/O operations.  When the
library needs them, it calls the callback functions provided by the
application. It also does not include any event polling mechanism, so
the application can freely choose the way of handling events. This
library code does not depend on any particular SSL library (except for
example programs which depend on OpenSSL 1.0.1 or later).

Development Status
------------------

Most of the SPDY/2 and SPDY/3 functionality has been implemented.  In
both versions, the direct support of server-push has not been
available yet.  The application can achieve server-push using
primitive APIs though.

As described below, we can create SPDY client and server with the
current Spdylay API.

Requirements
------------

The following packages are needed to build the library:

* pkg-config >= 0.20
* zlib >= 1.2.3

To build and run the unit test programs, the following packages are
needed:

* cunit >= 2.1

To build and run the example programs, the following packages are
needed:

* OpenSSL >= 1.0.1

To enable ``-a`` option (getting linked assets from the downloaded
resouce) in spdycat (one of the example program), the following
packages are needed:

* libxml2 >= 2.7.7

Build from git
--------------

Building from git is easy, but please be sure that at least autoconf 2.68 is
used::

    $ autoreconf -i
    $ automake
    $ autoconf
    $ ./configure
    $ make

Building documentation
----------------------

To build documentation, run::

    $ make html

The documents will be generated under ``doc/manual/html/``.

The generated documents will not be installed with ``make install``.

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
this writing, the OpenSSL 1.0.1 supports NPN.

The SPDY client is called ``spdycat``. It is a dead simple downloader
like wget/curl. It connects to SPDY server and gets resources given in
the command-line::

    $ examples/spdycat -h
    Usage: spdycat [-Onv23] [-t <SECONDS>] [-w <WINDOW_BITS>] [--cert=<CERT>]
                   [--key=<KEY>] <URI>...

    OPTIONS:
        -v, --verbose      Print debug information such as reception/
                           transmission of frames and name/value pairs.
        -n, --null-out     Discard downloaded data.
        -O, --remote-name  Save download data in the current directory.
                           The filename is dereived from URI. If URI
                           ends with '/', 'index.html' is used as a
                           filename. Not implemented yet.
        -2, --spdy2        Only use SPDY/2.
        -3, --spdy3        Only use SPDY/3.
        -t, --timeout=<N>  Timeout each request after <N> seconds.
        -w, --window-bits=<N>
                           Sets the initial window size to 2**<N>.
        --cert=<CERT>      Use the specified client certificate file.
                           The file must be in PEM format.
        --key=<KEY>        Use the client private key file. The file
                           must be in PEM format.
    $ examples/spdycat -nv https://www.google.com/
    [  0.025] NPN select next protocol: the remote server offers:
              * spdy/3
              * spdy/2
              * http/1.1
              NPN selected the protocol: spdy/3
    [  0.035] recv SETTINGS frame <version=3, flags=0, length=20>
              (niv=2)
              [4(1):100]
              [7(0):12288]
    [  0.035] send SYN_STREAM frame <version=3, flags=1, length=106>
              (stream_id=1, assoc_stream_id=0, pri=3)
              :host: www.google.com
              :method: GET
              :path: /
              :scheme: https
              :version: HTTP/1.1
              accept: */*
              user-agent: spdylay/0.2.0
    [  0.077] recv SYN_REPLY frame <version=3, flags=0, length=558>
              (stream_id=1)
              :status: 302 Found
              :version: HTTP/1.1
              cache-control: private
              content-length: 222
              content-type: text/html; charset=UTF-8
              date: Sun, 13 May 2012 08:02:54 GMT
              location: https://www.google.co.jp/
              server: gws
              x-frame-options: SAMEORIGIN
              x-xss-protection: 1; mode=block
    [  0.077] recv DATA frame (stream_id=1, flags=1, length=222)
    [  0.077] send GOAWAY frame <version=3, flags=0, length=8>
              (last_good_stream_id=0)

SPDY server is called ``spdyd``. It is a non-blocking server and only
serves static contents. It can speak SPDY/2 and SPDY/3::

    $ examples/spdyd --htdocs=/your/htdocs/ -v 3000 server.key server.crt
    IPv4: listen on port 3000
    IPv6: listen on port 3000
    The negotiated next protocol: spdy/3
    [id=1] [ 17.456] send SETTINGS frame <version=3, flags=0, length=12>
              (niv=1)
              [4(0):100]
    [id=1] [ 17.457] recv SYN_STREAM frame <version=3, flags=1, length=108>
              (stream_id=1, assoc_stream_id=0, pri=3)
              :host: localhost:3000
              :method: GET
              :path: /README
              :scheme: https
              :version: HTTP/1.1
              accept: */*
              user-agent: spdylay/0.2.0
    [id=1] [ 17.457] send SYN_REPLY frame <version=3, flags=0, length=113>
              (stream_id=1)
              :status: 200 OK
              :version: HTTP/1.1
              cache-control: max-age=3600
              content-length: 15
              date: Sun, 13 May 2012 08:06:12 GMT
              last-modified: Tue, 17 Jan 2012 15:39:01 GMT
              server: spdyd spdylay/0.2.0
    [id=1] [ 17.467] send DATA frame (stream_id=1, flags=0, length=15)
    [id=1] [ 17.467] send DATA frame (stream_id=1, flags=1, length=0)
    [id=1] [ 17.468] stream_id=1 closed
    [id=1] [ 17.468] recv GOAWAY frame <version=3, flags=0, length=8>
              (last_good_stream_id=0)
    [id=1] [ 17.468] closed

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

If you are looking for the example program written in C, see
``spdycli`` which is the simple SPDY client.
