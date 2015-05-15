nghttp2 - HTTP/2 C Library
==========================

This is an implementation of the Hypertext Transfer Protocol version 2
in C.

The framing layer of HTTP/2 is implemented as a reusable C
library.  On top of that, we have implemented an HTTP/2 client, server
and proxy.  We have also developed load test and benchmarking tools for
HTTP/2 and SPDY.

An HPACK encoder and decoder are available as a public API.

An experimental high level C++ library is also available.

We have Python bindings of this library, but we do not have full
code coverage yet.

Development Status
------------------

We have implemented `RFC 7540 <https://tools.ietf.org/html/rfc7540>`_
HTTP/2 and `RFC 7541 <https://tools.ietf.org/html/rfc7541>`_ HPACK -
Header Compression for HTTP/2

The nghttp2 code base was forked from the spdylay
(https://github.com/tatsuhiro-t/spdylay) project.

Public Test Server
------------------

The following endpoints are available to try out our nghttp2
implementation.

* https://nghttp2.org/ (TLS + ALPN/NPN)

  This endpoint supports ``h2``, ``h2-16``, ``h2-14``, ``spdy/3.1``
  and ``http/1.1`` via ALPN/NPN and requires TLSv1.2 for HTTP/2
  connection.

* http://nghttp2.org/ (HTTP Upgrade and HTTP/2 Direct)

  ``h2c`` and ``http/1.1``.

Requirements
------------

The following package is required to build the libnghttp2 library:

* pkg-config >= 0.20

To build and run the unit test programs, the following package is
required:

* cunit >= 2.1

To build the documentation, you need to install:

* sphinx (http://sphinx-doc.org/)

To build and run the application programs (``nghttp``, ``nghttpd`` and
``nghttpx``) in the ``src`` directory, the following packages are
required:

* OpenSSL >= 1.0.1
* libev >= 4.15
* zlib >= 1.2.3

ALPN support requires OpenSSL >= 1.0.2 (released 22 January 2015).

To enable the SPDY protocol in the application program ``nghttpx`` and
``h2load``, the following package is required:

* spdylay >= 1.3.0

To enable ``-a`` option (getting linked assets from the downloaded
resource) in ``nghttp``, the following package is required:

* libxml2 >= 2.7.7

The HPACK tools require the following package:

* jansson >= 2.5

To build sources under the examples directory, libevent is required:

* libevent-openssl >= 2.0.8

To mitigate heap fragmentation in long running server programs
(``nghttpd`` and ``nghttpx``), jemalloc is recommended:

* jemalloc

libnghttp2_asio C++ library requires the following packages:

* libboost-dev >= 1.54.0
* libboost-thread-dev >= 1.54.0

The Python bindings require the following packages:

* cython >= 0.19
* python >= 2.7

If you are using Ubuntu 14.04 LTS (trusty), run the following to install the needed packages::

    sudo apt-get install make binutils autoconf  automake autotools-dev libtool pkg-config \
      zlib1g-dev libcunit1-dev libssl-dev libxml2-dev libev-dev libevent-dev libjansson-dev \
      libjemalloc-dev cython python3.4-dev

spdylay is not packaged in Ubuntu, so you need to build it yourself:
http://tatsuhiro-t.github.io/spdylay/

Building from git
-----------------

Building from git is easy, but please be sure that at least autoconf 2.68 is
used::

    $ autoreconf -i
    $ automake
    $ autoconf
    $ ./configure
    $ make

To compile the source code, gcc >= 4.8.3 or clang >= 3.4 is required.

.. note::

   Mac OS X users may need the ``--disable-threads`` configure option to
   disable multi-threading in nghttpd, nghttpx and h2load to prevent
   them from crashing. A patch is welcome to make multi threading work
   on Mac OS X platform.

Notes for building on Windows (Mingw/Cygwin)
--------------------------------------------

Under Mingw environment, you can only compile the library, it's
``libnghttp2-X.dll`` and ``libnghttp2.a``.

If you want to compile the applications(``h2load``, ``nghttp``,
``nghttpx``, ``nghttpd``), you need to use the Cygwin environment.

Under Cygwin environment, to compile the applications you need to
compile and install the libev first.

Secondly, you need to undefine the macro ``__STRICT_ANSI__``, if you
not, the functions ``fdopen``, ``fileno`` and ``strptime`` will not
available.

the sample command like this::

    $ export CFLAGS="-U__STRICT_ANSI__ -I$libev_PREFIX/include -L$libev_PREFIX/lib"
    $ export CXXFLAGS=$CFLAGS
    $ ./configure
    $ make

If you want to compile the applications under ``examples/``, you need
to remove or rename the ``event.h`` from libev's installation, because
it conflicts with libevent's installation.

Building the documentation
--------------------------

.. note::

   Documentation is still incomplete.

To build the documentation, run::

    $ make html

The documents will be generated under ``doc/manual/html/``.

The generated documents will not be installed with ``make install``.

The online documentation is available at
https://nghttp2.org/documentation/

Unit tests
----------

Unit tests are done by simply running ``make check``.

Integration tests
-----------------

We have the integration tests for the nghttpx proxy server.  The tests are
written in the `Go programming language <http://golang.org/>`_ and uses
its testing framework.  We depend on the following libraries:

* https://github.com/bradfitz/http2
* https://github.com/tatsuhiro-t/go-nghttp2
* https://golang.org/x/net/spdy

To download the above packages, after settings ``GOPATH``, run the
following command under ``integration-tests`` directory::

    $ make itprep

To run the tests, run the following command under
``integration-tests`` directory::

    $ make it

Inside the tests, we use port 3009 to run the test subject server.

Migration from v0.7.9 or earlier
--------------------------------

nghttp2 v1.0.0 introduced several backward incompatible changes.  In
this section, we describe these changes and how to migrate to v1.0.0.

ALPN protocol ID is now ``h2`` and ``h2c``
++++++++++++++++++++++++++++++++++++++++++

Previously we announced ``h2-14`` and ``h2c-14``.  v1.0.0 implements
final protocol version, and we changed ALPN ID to ``h2`` and ``h2c``.
The macros ``NGHTTP2_PROTO_VERSION_ID``,
``NGHTTP2_PROTO_VERSION_ID_LEN``,
``NGHTTP2_CLEARTEXT_PROTO_VERSION_ID``, and
``NGHTTP2_CLEARTEXT_PROTO_VERSION_ID_LEN`` have been updated to
reflect this change.

Basically, existing applications do not have to do anything, just
recompiling is enough for this change.

Use word "client magic" where we use "client connection preface"
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

We use "client connection preface" to mean first 24 bytes of client
connection preface.  This is technically not correct, since client
connection preface is composed of 24 bytes client magic byte string
followed by SETTINGS frame.  For clarification, we call "client magic"
for this 24 bytes byte string and updated API.

* ``NGHTTP2_CLIENT_CONNECTION_PREFACE`` was replaced with
  ``NGHTTP2_CLIENT_MAGIC``.
* ``NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN`` was replaced with
  ``NGHTTP2_CLIENT_MAGIC_LEN``.
* ``NGHTTP2_BAD_PREFACE`` was renamed as ``NGHTTP2_BAD_CLIENT_MAGIC``

The alreay deprecated ``NGHTTP2_CLIENT_CONNECTION_HEADER`` and
``NGHTTP2_CLIENT_CONNECTION_HEADER_LEN`` were removed.

If application uses these macros, just replace old ones with new ones.
Since v1.0.0, client magic is sent by library (see next subsection),
so client application may just remove these macro use.

Client magic is sent by library
+++++++++++++++++++++++++++++++

Previously nghttp2 library did not send client magic, which is first
24 bytes byte string of client connection preface, and client
applications have to send it by themselves.  Since v1.0.0, client
magic is sent by library via first call of ``nghttp2_session_send()``
or ``nghttp2_session_mem_send()``.

The client applications which send client magic must remove the
relevant code.

Remove HTTP Alternative Services (Alt-Svc) related code
+++++++++++++++++++++++++++++++++++++++++++++++++++++++

Alt-Svc specification is not finalized yet.  To make our API stable,
we have decided to remove all Alt-Svc related API from nghttp2.

* ``NGHTTP2_EXT_ALTSVC`` was removed.
* ``nghttp2_ext_altsvc`` was removed.

We have already removed the functionality of Alt-Svc in v0.7 series
and they have been essentially noop.  The application using these
macro and struct, remove those lines.

Use nghttp2_error in nghttp2_on_invalid_frame_recv_callback
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Previously ``nghttp2_on_invalid_frame_recv_cb_called`` took the
``error_code``, defined in ``nghttp2_error_code``, as parameter.  But
they are not detailed enough to debug.  Therefore, we decided to use
more detailed ``nghttp2_error`` values instead.

The application using this callback should update the callback
signature.  If it treats ``error_code`` as HTTP/2 error code, update
the code so that it is treated as ``nghttp2_error``.

Receive client magic by default
+++++++++++++++++++++++++++++++

Previously nghttp2 did not process client magic (24 bytes byte
string).  To make it deal with it, we had to use
``nghttp2_option_set_recv_client_preface()``.  Since v1.0.0, nghttp2
processes client magic by default and
``nghttp2_option_set_recv_client_preface()`` was removed.

Some application may want to disable this behaviour, so we added
``nghttp2_option_set_no_recv_client_magic()`` to achieve this.

The application using ``nghttp2_option_set_recv_client_preface()``
with nonzero value, just remove it.

The application using ``nghttp2_option_set_recv_client_preface()``
with zero value or not using it must use
``nghttp2_option_set_no_recv_client_magic()`` with nonzero value.

Client, Server and Proxy programs
---------------------------------

The ``src`` directory contains the HTTP/2 client, server and proxy programs.

nghttp - client
+++++++++++++++

``nghttp`` is a HTTP/2 client.  It can connect to the HTTP/2 server
with prior knowledge, HTTP Upgrade and NPN/ALPN TLS extension.

It has verbose output mode for framing information.  Here is sample
output from ``nghttp`` client::

    $ nghttp -nv https://nghttp2.org
    [  0.033][NPN] server offers:
              * h2
              * spdy/3.1
              * http/1.1
    The negotiated protocol: h2
    [  0.068] send SETTINGS frame <length=15, flags=0x00, stream_id=0>
              (niv=3)
              [SETTINGS_MAX_CONCURRENT_STREAMS(3):100]
              [SETTINGS_INITIAL_WINDOW_SIZE(4):65535]
              [SETTINGS_COMPRESS_DATA(5):1]
    [  0.068] send HEADERS frame <length=46, flags=0x05, stream_id=1>
              ; END_STREAM | END_HEADERS
              (padlen=0)
              ; Open new stream
              :authority: nghttp2.org
              :method: GET
              :path: /
              :scheme: https
              accept: */*
              accept-encoding: gzip, deflate
              user-agent: nghttp2/0.4.0-DEV
    [  0.068] recv SETTINGS frame <length=10, flags=0x00, stream_id=0>
              (niv=2)
              [SETTINGS_MAX_CONCURRENT_STREAMS(3):100]
              [SETTINGS_INITIAL_WINDOW_SIZE(4):65535]
    [  0.068] send SETTINGS frame <length=0, flags=0x01, stream_id=0>
              ; ACK
              (niv=0)
    [  0.079] recv SETTINGS frame <length=0, flags=0x01, stream_id=0>
              ; ACK
              (niv=0)
    [  0.080] (stream_id=1, noind=0) :status: 200
    [  0.080] (stream_id=1, noind=0) accept-ranges: bytes
    [  0.080] (stream_id=1, noind=0) age: 15
    [  0.080] (stream_id=1, noind=0) content-length: 40243
    [  0.080] (stream_id=1, noind=0) content-type: text/html
    [  0.080] (stream_id=1, noind=0) date: Wed, 14 May 2014 15:14:30 GMT
    [  0.080] (stream_id=1, noind=0) etag: "535d0eea-9d33"
    [  0.080] (stream_id=1, noind=0) last-modified: Sun, 27 Apr 2014 14:06:34 GMT
    [  0.080] (stream_id=1, noind=0) server: nginx/1.4.6 (Ubuntu)
    [  0.080] (stream_id=1, noind=0) x-varnish: 2114900538 2114900537
    [  0.080] (stream_id=1, noind=0) via: 1.1 varnish, 1.1 nghttpx
    [  0.080] (stream_id=1, noind=0) strict-transport-security: max-age=31536000
    [  0.080] recv HEADERS frame <length=162, flags=0x04, stream_id=1>
              ; END_HEADERS
              (padlen=0)
              ; First response header
    [  0.080] recv DATA frame <length=3786, flags=0x00, stream_id=1>
    [  0.080] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.081] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.093] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.093] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.094] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.094] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.094] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.096] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.096] send WINDOW_UPDATE frame <length=4, flags=0x00, stream_id=0>
              (window_size_increment=36554)
    [  0.096] send WINDOW_UPDATE frame <length=4, flags=0x00, stream_id=1>
              (window_size_increment=36554)
    [  0.108] recv DATA frame <length=3689, flags=0x00, stream_id=1>
    [  0.108] recv DATA frame <length=0, flags=0x01, stream_id=1>
              ; END_STREAM
    [  0.108] send GOAWAY frame <length=8, flags=0x00, stream_id=0>
              (last_stream_id=0, error_code=NO_ERROR(0), opaque_data(0)=[])

The HTTP Upgrade is performed like this::

    $ nghttp -nvu http://nghttp2.org
    [  0.013] HTTP Upgrade request
    GET / HTTP/1.1
    Host: nghttp2.org
    Connection: Upgrade, HTTP2-Settings
    Upgrade: h2c-14
    HTTP2-Settings: AwAAAGQEAAD__wUAAAAB
    Accept: */*
    User-Agent: nghttp2/0.4.0-DEV


    [  0.024] HTTP Upgrade response
    HTTP/1.1 101 Switching Protocols
    Connection: Upgrade
    Upgrade: h2c-14


    [  0.024] HTTP Upgrade success
    [  0.024] send SETTINGS frame <length=15, flags=0x00, stream_id=0>
              (niv=3)
              [SETTINGS_MAX_CONCURRENT_STREAMS(3):100]
              [SETTINGS_INITIAL_WINDOW_SIZE(4):65535]
              [SETTINGS_COMPRESS_DATA(5):1]
    [  0.024] recv SETTINGS frame <length=10, flags=0x00, stream_id=0>
              (niv=2)
              [SETTINGS_MAX_CONCURRENT_STREAMS(3):100]
              [SETTINGS_INITIAL_WINDOW_SIZE(4):65535]
    [  0.024] send SETTINGS frame <length=0, flags=0x01, stream_id=0>
              ; ACK
              (niv=0)
    [  0.024] (stream_id=1, noind=0) :status: 200
    [  0.024] (stream_id=1, noind=0) accept-ranges: bytes
    [  0.024] (stream_id=1, noind=0) age: 10
    [  0.024] (stream_id=1, noind=0) content-length: 40243
    [  0.024] (stream_id=1, noind=0) content-type: text/html
    [  0.024] (stream_id=1, noind=0) date: Wed, 14 May 2014 15:16:34 GMT
    [  0.024] (stream_id=1, noind=0) etag: "535d0eea-9d33"
    [  0.024] (stream_id=1, noind=0) last-modified: Sun, 27 Apr 2014 14:06:34 GMT
    [  0.024] (stream_id=1, noind=0) server: nginx/1.4.6 (Ubuntu)
    [  0.024] (stream_id=1, noind=0) x-varnish: 2114900541 2114900540
    [  0.024] (stream_id=1, noind=0) via: 1.1 varnish, 1.1 nghttpx
    [  0.024] recv HEADERS frame <length=148, flags=0x04, stream_id=1>
              ; END_HEADERS
              (padlen=0)
              ; First response header
    [  0.024] recv DATA frame <length=3786, flags=0x00, stream_id=1>
    [  0.025] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.031] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.031] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.032] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.032] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.033] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.033] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.033] send WINDOW_UPDATE frame <length=4, flags=0x00, stream_id=0>
              (window_size_increment=33164)
    [  0.033] send WINDOW_UPDATE frame <length=4, flags=0x00, stream_id=1>
              (window_size_increment=33164)
    [  0.038] recv DATA frame <length=4096, flags=0x00, stream_id=1>
    [  0.038] recv DATA frame <length=3689, flags=0x00, stream_id=1>
    [  0.038] recv DATA frame <length=0, flags=0x01, stream_id=1>
              ; END_STREAM
    [  0.038] recv SETTINGS frame <length=0, flags=0x01, stream_id=0>
              ; ACK
              (niv=0)
    [  0.038] send GOAWAY frame <length=8, flags=0x00, stream_id=0>
              (last_stream_id=0, error_code=NO_ERROR(0), opaque_data(0)=[])

Using the ``-s`` option, ``nghttp`` prints out some timing information for
requests, sorted by completion time::

    $ nghttp -nas https://nghttp2.org/
    ***** Statistics *****

    Request timing:
      complete: relative time from protocol handshake to stream close
       request: relative   time  from   protocol   handshake  to   request
                transmission.  If '*' is shown, this was pushed by server.
       process: time for request and response
          code: HTTP status code
          size: number  of   bytes  received  as  response   body  without
                inflation.
           URI: request URI

    sorted by 'complete'

    complete  request    process  code size request path
     +11.07ms     +120us  10.95ms  200   9K /
     +16.77ms *  +8.80ms   7.98ms  200   8K /stylesheets/screen.css
     +27.00ms   +11.16ms  15.84ms  200   3K /javascripts/octopress.js
     +27.40ms   +11.16ms  16.24ms  200   3K /javascripts/modernizr-2.0.js
     +76.14ms   +11.17ms  64.97ms  200 171K /images/posts/with-pri-blog.png
     +88.52ms   +11.17ms  77.36ms  200 174K /images/posts/without-pri-blog.png

Using the ``-r`` option, ``nghttp`` writes more detailed timing data to
the given file in HAR format.

nghttpd - server
++++++++++++++++

``nghttpd`` is a multi-threaded static web server.

By default, it uses SSL/TLS connection.  Use ``--no-tls`` option to
disable it.

``nghttpd`` only accepts HTTP/2 connections via NPN/ALPN or direct
HTTP/2 connections.  No HTTP Upgrade is supported.

The ``-p`` option allows users to configure server push.

Just like ``nghttp``, it has a verbose output mode for framing
information.  Here is sample output from ``nghttpd``::

    $ nghttpd --no-tls -v 8080
    IPv4: listen on port 8080
    IPv6: listen on port 8080
    [id=1] [ 15.921] send SETTINGS frame <length=10, flags=0x00, stream_id=0>
              (niv=2)
              [SETTINGS_MAX_CONCURRENT_STREAMS(3):100]
              [SETTINGS_COMPRESS_DATA(5):1]
    [id=1] [ 15.921] recv SETTINGS frame <length=15, flags=0x00, stream_id=0>
              (niv=3)
              [SETTINGS_MAX_CONCURRENT_STREAMS(3):100]
              [SETTINGS_INITIAL_WINDOW_SIZE(4):65535]
              [SETTINGS_COMPRESS_DATA(5):1]
    [id=1] [ 15.921] (stream_id=1, noind=0) :authority: localhost:8080
    [id=1] [ 15.921] (stream_id=1, noind=0) :method: GET
    [id=1] [ 15.921] (stream_id=1, noind=0) :path: /
    [id=1] [ 15.921] (stream_id=1, noind=0) :scheme: http
    [id=1] [ 15.921] (stream_id=1, noind=0) accept: */*
    [id=1] [ 15.921] (stream_id=1, noind=0) accept-encoding: gzip, deflate
    [id=1] [ 15.921] (stream_id=1, noind=0) user-agent: nghttp2/0.4.0-DEV
    [id=1] [ 15.921] recv HEADERS frame <length=48, flags=0x05, stream_id=1>
              ; END_STREAM | END_HEADERS
              (padlen=0)
              ; Open new stream
    [id=1] [ 15.921] recv SETTINGS frame <length=0, flags=0x01, stream_id=0>
              ; ACK
              (niv=0)
    [id=1] [ 15.921] send SETTINGS frame <length=0, flags=0x01, stream_id=0>
              ; ACK
              (niv=0)
    [id=1] [ 15.921] send HEADERS frame <length=82, flags=0x04, stream_id=1>
              ; END_HEADERS
              (padlen=0)
              ; First response header
              :status: 200
              cache-control: max-age=3600
              content-length: 612
              date: Wed, 14 May 2014 15:19:03 GMT
              last-modified: Sat, 08 Mar 2014 16:04:06 GMT
              server: nghttpd nghttp2/0.4.0-DEV
    [id=1] [ 15.922] send DATA frame <length=381, flags=0x20, stream_id=1>
              ; COMPRESSED
    [id=1] [ 15.922] send DATA frame <length=0, flags=0x01, stream_id=1>
              ; END_STREAM
    [id=1] [ 15.922] stream_id=1 closed
    [id=1] [ 15.922] recv GOAWAY frame <length=8, flags=0x00, stream_id=0>
              (last_stream_id=0, error_code=NO_ERROR(0), opaque_data(0)=[])
    [id=1] [ 15.922] closed

nghttpx - proxy
+++++++++++++++

``nghttpx`` is a multi-threaded reverse proxy for HTTP/2, SPDY and
HTTP/1.1, and powers http://nghttp2.org and supports HTTP/2 server
push.

``nghttpx`` implements `important performance-oriented features
<https://istlsfastyet.com/#server-performance>`_ in TLS, such as
session IDs, session tickets (with automatic key rotation), OCSP
stapling, dynamic record sizing, ALPN/NPN, forward secrecy and SPDY &
HTTP/2.

``nghttpx`` has several operational modes:

================== ============================ ============== =============
Mode option        Frontend                     Backend        Note
================== ============================ ============== =============
default mode       HTTP/2, SPDY, HTTP/1.1 (TLS) HTTP/1.1       Reverse proxy
``--http2-proxy``  HTTP/2, SPDY, HTTP/1.1 (TLS) HTTP/1.1       SPDY proxy
``--http2-bridge`` HTTP/2, SPDY, HTTP/1.1 (TLS) HTTP/2 (TLS)
``--client``       HTTP/2, HTTP/1.1             HTTP/2 (TLS)
``--client-proxy`` HTTP/2, HTTP/1.1             HTTP/2 (TLS)   Forward proxy
================== ============================ ============== =============

The interesting mode at the moment is the default mode.  It works like
a reverse proxy and listens for HTTP/2, SPDY and HTTP/1.1 and can be
deployed as a SSL/TLS terminator for existing web server.

The default mode, ``--http2-proxy`` and ``--http2-bridge`` modes use
SSL/TLS in the frontend connection by default.  To disable SSL/TLS,
use the ``--frontend-no-tls`` option.  If that option is used, SPDY is
disabled in the frontend and incoming HTTP/1.1 connections can be
upgraded to HTTP/2 through HTTP Upgrade.

The ``--http2-bridge``, ``--client`` and ``--client-proxy`` modes use
SSL/TLS in the backend connection by default.  To disable SSL/TLS, use
the ``--backend-no-tls`` option.

``nghttpx`` supports a configuration file.  See the ``--conf`` option and
sample configuration file ``nghttpx.conf.sample``.

In the default mode, (without any of ``--http2-proxy``,
``--http2-bridge``, ``--client-proxy`` and ``--client`` options),
``nghttpx`` works as reverse proxy to the backend server::

    Client <-- (HTTP/2, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/1.1) --> Web Server
                                          [reverse proxy]

With the ``--http2-proxy`` option, it works as a so called secure proxy (aka
SPDY proxy)::

    Client <-- (HTTP/2, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/1.1) --> Proxy
                                           [secure proxy]          (e.g., Squid, ATS)

The ``Client`` in the above example needs to be configured to use
``nghttpx`` as secure proxy.

At the time of this writing, Chrome is the only browser which supports
secure proxy.  One way to configure Chrome to use a secure proxy is
to create a proxy.pac script like this:

.. code-block:: javascript

    function FindProxyForURL(url, host) {
        return "HTTPS SERVERADDR:PORT";
    }

``SERVERADDR`` and ``PORT`` is the hostname/address and port of the
machine nghttpx is running on.  Please note that Chrome requires a valid
certificate for secure proxy.

Then run Chrome with the following arguments::

    $ google-chrome --proxy-pac-url=file:///path/to/proxy.pac --use-npn

With ``--http2-bridge``, it accepts HTTP/2, SPDY and HTTP/1.1
connections and communicates with the backend in HTTP/2::

    Client <-- (HTTP/2, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/2) --> Web or HTTP/2 Proxy etc
                                                                         (e.g., nghttpx -s)

With ``--client-proxy``, it works as a forward proxy and expects
that the backend is an HTTP/2 proxy::

    Client <-- (HTTP/2, HTTP/1.1) --> nghttpx <-- (HTTP/2) --> HTTP/2 Proxy
                                     [forward proxy]               (e.g., nghttpx -s)

The ``Client`` needs to be configured to use nghttpx as a forward
proxy.  The frontend HTTP/1.1 connection can be upgraded to HTTP/2
through HTTP Upgrade.  With the above configuration, one can use
HTTP/1.1 client to access and test their HTTP/2 servers.

With ``--client``, it works as a reverse proxy and expects that
the backend is an HTTP/2 Web server::

    Client <-- (HTTP/2, HTTP/1.1) --> nghttpx <-- (HTTP/2) --> Web Server
                                    [reverse proxy]

The frontend HTTP/1.1 connection can be upgraded to HTTP/2
through HTTP Upgrade.

For the operation modes which talk to the backend in HTTP/2 over
SSL/TLS, the backend connections can be tunneled through an HTTP proxy.
The proxy is specified using ``--backend-http-proxy-uri``.  The
following figure illustrates the example of the ``--http2-bridge`` and
``--backend-http-proxy-uri`` options to talk to the outside HTTP/2
proxy through an HTTP proxy::

    Client <-- (HTTP/2, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/2) --

            --===================---> HTTP/2 Proxy
              (HTTP proxy tunnel)     (e.g., nghttpx -s)

Benchmarking tool
-----------------

The ``h2load`` program is a benchmarking tool for HTTP/2 and SPDY.
The SPDY support is enabled if the program was built with the spdylay
library.  The UI of ``h2load`` is heavily inspired by ``weighttp``
(https://github.com/lighttpd/weighttp).  The typical usage is as
follows::

    $ h2load -n100000 -c100 -m100 https://localhost:8443/
    starting benchmark...
    spawning thread #0: 100 concurrent clients, 100000 total requests
    Protocol: TLSv1.2
    Cipher: ECDHE-RSA-AES128-GCM-SHA256
    progress: 10% done
    progress: 20% done
    progress: 30% done
    progress: 40% done
    progress: 50% done
    progress: 60% done
    progress: 70% done
    progress: 80% done
    progress: 90% done
    progress: 100% done

    finished in 7.10s, 14092 req/s, 55.67MB/s
    requests: 100000 total, 100000 started, 100000 done, 100000 succeeded, 0 failed, 0 errored
    status codes: 100000 2xx, 0 3xx, 0 4xx, 0 5xx
    traffic: 414200800 bytes total, 2723100 bytes headers, 409600000 bytes data
                         min         max         mean         sd        +/- sd
    time for request:   283.86ms       1.46s    659.70ms    150.87ms    84.68%

The above example issued total 100,000 requests, using 100 concurrent
clients (in other words, 100 HTTP/2 sessions), and a maximum of 100 streams
per client.  With the ``-t`` option, ``h2load`` will use multiple native
threads to avoid saturating a single core on client side.

.. warning::

   **Don't use this tool against publicly available servers.** That is
   considered a DOS attack.  Please only use it against your private
   servers.

HPACK tools
-----------

The ``src`` directory contains the HPACK tools.  The ``deflatehd`` program is a
command-line header compression tool.  The ``inflatehd`` program is a
command-line header decompression tool.  Both tools read input from
stdin and write output to stdout.  Errors are written to stderr.
They take JSON as input and output.  We  (mostly) use the same JSON data
format described at https://github.com/http2jp/hpack-test-case.

deflatehd - header compressor
+++++++++++++++++++++++++++++

The ``deflatehd`` program reads JSON data or HTTP/1-style header fields from
stdin and outputs compressed header block in JSON.

For the JSON input, the root JSON object must include a ``cases`` key.
Its value has to include the sequence of input header set.  They share
the same compression context and are processed in the order they
appear.  Each item in the sequence is a JSON object and it must
include a ``headers`` key.  Its value is an array of JSON objects,
which includes exactly one name/value pair.

Example:

.. code-block:: json

    {
      "cases":
      [
        {
          "headers": [
            { ":method": "GET" },
            { ":path": "/" }
          ]
        },
        {
          "headers": [
            { ":method": "POST" },
            { ":path": "/" }
          ]
        }
      ]
    }


With the ``-t`` option, the program can accept more familiar HTTP/1 style
header field blocks.  Each header set is delimited by an empty line:

Example::

    :method: GET
    :scheme: https
    :path: /

    :method: POST
    user-agent: nghttp2

The output is in JSON object.  It should include a ``cases`` key and its
value is an array of JSON objects, which has at least the following keys:

seq
    The index of header set in the input.

input_length
    The sum of the length of the name/value pairs in the input.

output_length
    The length of the compressed header block.

percentage_of_original_size
    ``input_length`` / ``output_length`` * 100

wire
    The compressed header block as a hex string.

headers
    The input header set.

header_table_size
    The header table size adjusted before deflating the header set.

Examples:

.. code-block:: json

    {
      "cases":
      [
        {
          "seq": 0,
          "input_length": 66,
          "output_length": 20,
          "percentage_of_original_size": 30.303030303030305,
          "wire": "01881f3468e5891afcbf83868a3d856659c62e3f",
          "headers": [
            {
              ":authority": "example.org"
            },
            {
              ":method": "GET"
            },
            {
              ":path": "/"
            },
            {
              ":scheme": "https"
            },
            {
              "user-agent": "nghttp2"
            }
          ],
          "header_table_size": 4096
        }
        ,
        {
          "seq": 1,
          "input_length": 74,
          "output_length": 10,
          "percentage_of_original_size": 13.513513513513514,
          "wire": "88448504252dd5918485",
          "headers": [
            {
              ":authority": "example.org"
            },
            {
              ":method": "POST"
            },
            {
              ":path": "/account"
            },
            {
              ":scheme": "https"
            },
            {
              "user-agent": "nghttp2"
            }
          ],
          "header_table_size": 4096
        }
      ]
    }


The output can be used as the input for ``inflatehd`` and
``deflatehd``.

With the ``-d`` option, the extra ``header_table`` key is added and its
associated value includes the state of dynamic header table after the
corresponding header set was processed.  The value includes at least
the following keys:

entries
    The entry in the header table.  If ``referenced`` is ``true``, it
    is in the reference set.  The ``size`` includes the overhead (32
    bytes).  The ``index`` corresponds to the index of header table.
    The ``name`` is the header field name and the ``value`` is the
    header field value.

size
    The sum of the spaces entries occupied, this includes the
    entry overhead.

max_size
    The maximum header table size.

deflate_size
    The sum of the spaces entries occupied within
    ``max_deflate_size``.

max_deflate_size
    The maximum header table size the encoder uses.  This can be smaller
    than ``max_size``.  In this case, the encoder only uses up to first
    ``max_deflate_size`` buffer.  Since the header table size is still
    ``max_size``, the encoder has to keep track of entries outside the
    ``max_deflate_size`` but inside the ``max_size`` and make sure
    that they are no longer referenced.

Example:

.. code-block:: json

    {
      "cases":
      [
        {
          "seq": 0,
          "input_length": 66,
          "output_length": 20,
          "percentage_of_original_size": 30.303030303030305,
          "wire": "01881f3468e5891afcbf83868a3d856659c62e3f",
          "headers": [
            {
              ":authority": "example.org"
            },
            {
              ":method": "GET"
            },
            {
              ":path": "/"
            },
            {
              ":scheme": "https"
            },
            {
              "user-agent": "nghttp2"
            }
          ],
          "header_table_size": 4096,
          "header_table": {
            "entries": [
              {
                "index": 1,
                "name": "user-agent",
                "value": "nghttp2",
                "referenced": true,
                "size": 49
              },
              {
                "index": 2,
                "name": ":scheme",
                "value": "https",
                "referenced": true,
                "size": 44
              },
              {
                "index": 3,
                "name": ":path",
                "value": "/",
                "referenced": true,
                "size": 38
              },
              {
                "index": 4,
                "name": ":method",
                "value": "GET",
                "referenced": true,
                "size": 42
              },
              {
                "index": 5,
                "name": ":authority",
                "value": "example.org",
                "referenced": true,
                "size": 53
              }
            ],
            "size": 226,
            "max_size": 4096,
            "deflate_size": 226,
            "max_deflate_size": 4096
          }
        }
        ,
        {
          "seq": 1,
          "input_length": 74,
          "output_length": 10,
          "percentage_of_original_size": 13.513513513513514,
          "wire": "88448504252dd5918485",
          "headers": [
            {
              ":authority": "example.org"
            },
            {
              ":method": "POST"
            },
            {
              ":path": "/account"
            },
            {
              ":scheme": "https"
            },
            {
              "user-agent": "nghttp2"
            }
          ],
          "header_table_size": 4096,
          "header_table": {
            "entries": [
              {
                "index": 1,
                "name": ":method",
                "value": "POST",
                "referenced": true,
                "size": 43
              },
              {
                "index": 2,
                "name": "user-agent",
                "value": "nghttp2",
                "referenced": true,
                "size": 49
              },
              {
                "index": 3,
                "name": ":scheme",
                "value": "https",
                "referenced": true,
                "size": 44
              },
              {
                "index": 4,
                "name": ":path",
                "value": "/",
                "referenced": false,
                "size": 38
              },
              {
                "index": 5,
                "name": ":method",
                "value": "GET",
                "referenced": false,
                "size": 42
              },
              {
                "index": 6,
                "name": ":authority",
                "value": "example.org",
                "referenced": true,
                "size": 53
              }
            ],
            "size": 269,
            "max_size": 4096,
            "deflate_size": 269,
            "max_deflate_size": 4096
          }
        }
      ]
    }

inflatehd - header decompressor
+++++++++++++++++++++++++++++++

The ``inflatehd`` program reads JSON data from stdin and outputs decompressed
name/value pairs in JSON.

The root JSON object must include the ``cases`` key.  Its value has to
include the sequence of compressed header blocks.  They share the same
compression context and are processed in the order they appear.  Each
item in the sequence is a JSON object and it must have at least a
``wire`` key.  Its value is a compressed header block as a hex string.

Example:

.. code-block:: json

    {
      "cases":
      [
        { "wire": "8285" },
        { "wire": "8583" }
      ]
    }

The output is a JSON object.  It should include a ``cases`` key and its
value is an array of JSON objects, which has at least following keys:

seq
    The index of the header set in the input.

headers
    A JSON array that includes decompressed name/value pairs.

wire
    The compressed header block as a hex string.

header_table_size
    The header table size adjusted before inflating compressed header
    block.

Example:

.. code-block:: json

    {
      "cases":
      [
        {
          "seq": 0,
          "wire": "01881f3468e5891afcbf83868a3d856659c62e3f",
          "headers": [
            {
              ":authority": "example.org"
            },
            {
              ":method": "GET"
            },
            {
              ":path": "/"
            },
            {
              ":scheme": "https"
            },
            {
              "user-agent": "nghttp2"
            }
          ],
          "header_table_size": 4096
        }
        ,
        {
          "seq": 1,
          "wire": "88448504252dd5918485",
          "headers": [
            {
              ":method": "POST"
            },
            {
              ":path": "/account"
            },
            {
              "user-agent": "nghttp2"
            },
            {
              ":scheme": "https"
            },
            {
              ":authority": "example.org"
            }
          ],
          "header_table_size": 4096
        }
      ]
    }

The output can be used as the input for ``deflatehd`` and
``inflatehd``.

With the ``-d`` option, the extra ``header_table`` key is added and its
associated value includes the state of the dynamic header table after the
corresponding header set was processed.  The format is the same as
``deflatehd``.

libnghttp2_asio: High level HTTP/2 C++ library
----------------------------------------------

libnghttp2_asio is C++ library built on top of libnghttp2 and provides
high level abstraction API to build HTTP/2 applications.  It depends
on the Boost::ASIO library and OpenSSL.  Currently libnghttp2_asio
provides both client and server APIs.

libnghttp2_asio is not built by default.  Use the ``--enable-asio-lib``
configure flag to build libnghttp2_asio.  The required Boost libraries
are:

* Boost::Asio
* Boost::System
* Boost::Thread

The server API is designed to build an HTTP/2 server very easily to utilize
C++11 anonymous functions and closures.  The bare minimum example of
an HTTP/2 server looks like this:

.. code-block:: cpp

    #include <nghttp2/asio_http2_server.h>

    using namespace nghttp2::asio_http2;
    using namespace nghttp2::asio_http2::server;

    int main(int argc, char *argv[]) {
      boost::system::error_code ec;
      http2 server;

      server.handle("/", [](const request &req, const response &res) {
        res.write_head(200);
        res.end("hello, world\n");
      });

      if (server.listen_and_serve(ec, "localhost", "3000")) {
        std::cerr << "error: " << ec.message() << std::endl;
      }
    }

Here is sample code to use the client API:

.. code-block:: cpp

    #include <iostream>

    #include <nghttp2/asio_http2_client.h>

    using boost::asio::ip::tcp;

    using namespace nghttp2::asio_http2;
    using namespace nghttp2::asio_http2::client;

    int main(int argc, char *argv[]) {
      boost::system::error_code ec;
      boost::asio::io_service io_service;

      // connect to localhost:3000
      session sess(io_service, "localhost", "3000");

      sess.on_connect([&sess](tcp::resolver::iterator endpoint_it) {
	boost::system::error_code ec;

	auto req = sess.submit(ec, "GET", "http://localhost:3000/");

	req->on_response([](const response &res) {
	  // print status code and response header fields.
	  std::cerr << "HTTP/2 " << res.status_code() << std::endl;
	  for (auto &kv : res.header()) {
	    std::cerr << kv.first << ": " << kv.second.value << "\n";
	  }
	  std::cerr << std::endl;

	  res.on_data([](const uint8_t *data, std::size_t len) {
	    std::cerr.write(reinterpret_cast<const char *>(data), len);
	    std::cerr << std::endl;
	  });
	});

	req->on_close([&sess](uint32_t error_code) {
	  // shutdown session after first request was done.
	  sess.shutdown();
	});
      });

      sess.on_error([](const boost::system::error_code &ec) {
	std::cerr << "error: " << ec.message() << std::endl;
      });

      io_service.run();
    }

For more details, see the documentation of libnghttp2_asio.

Python bindings
---------------

The ``python`` directory contains nghttp2 Python bindings.  The
bindings currently provide HPACK compressor and decompressor classes
and an HTTP/2 server.

The extension module is called ``nghttp2``.

``make`` will build the bindings and target Python version is
determined by the ``configure`` script.  If the detected Python version is not
what you expect, specify a path to Python executable in a ``PYTHON``
variable as an argument to configure script (e.g., ``./configure
PYTHON=/usr/bin/python3.4``).

The following example code illustrates basic usage of the HPACK compressor
and decompressor in Python:

.. code-block:: python

    import binascii
    import nghttp2

    deflater = nghttp2.HDDeflater()
    inflater = nghttp2.HDInflater()

    data = deflater.deflate([(b'foo', b'bar'),
                             (b'baz', b'buz')])
    print(binascii.b2a_hex(data))

    hdrs = inflater.inflate(data)
    print(hdrs)

The ``nghttp2.HTTP2Server`` class builds on top of the asyncio event
loop.  On construction, *RequestHandlerClass* must be given, which
must be a subclass of ``nghttp2.BaseRequestHandler`` class.

The ``BaseRequestHandler`` class is used to handle the HTTP/2 stream.
By default, it does nothing.  It must be subclassed to handle each
event callback method.

The first callback method invoked is ``on_headers()``.  It is called
when HEADERS frame, which includes the request header fields, has arrived.

If the request has a request body, ``on_data(data)`` is invoked for each
chunk of received data.

Once the entire request is received, ``on_request_done()`` is invoked.

When the stream is closed, ``on_close(error_code)`` is called.

The application can send a response using ``send_response()`` method.
It can be used in ``on_headers()``, ``on_data()`` or
``on_request_done()``.

The application can push resources using the ``push()`` method.  It must be
used before the ``send_response()`` call.

The following instance variables are available:

client_address
    Contains a tuple of the form (host, port) referring to the
    client's address.

stream_id
    Stream ID of this stream.

scheme
    Scheme of the request URI.  This is a value of :scheme header
    field.

method
    Method of this stream.  This is a value of :method header field.

host
    This is a value of :authority or host header field.

path
    This is a value of :path header field.

The following example illustrates the HTTP2Server and
BaseRequestHandler usage:

.. code-block:: python

    #!/usr/bin/env python

    import io, ssl
    import nghttp2

    class Handler(nghttp2.BaseRequestHandler):

        def on_headers(self):
            self.push(path='/css/bootstrap.css',
                      request_headers = [('content-length', '3')],
                      status=200,
                      body='foo')

            self.push(path='/js/bootstrap.js',
                      method='GET',
                      request_headers = [('content-length', '10')],
                      status=200,
                      body='foobarbuzz')

            self.send_response(status=200,
                               headers = [('content-type', 'text/plain')],
                               body=io.BytesIO(b'nghttp2-python FTW'))

    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ctx.options = ssl.OP_ALL | ssl.OP_NO_SSLv2
    ctx.load_cert_chain('server.crt', 'server.key')

    # give None to ssl to make the server non-SSL/TLS
    server = nghttp2.HTTP2Server(('127.0.0.1', 8443), Handler, ssl=ctx)
    server.serve_forever()

Contribution
------------

[This text was composed based on 1.2. License section of curl/libcurl
project.]

When contributing with code, you agree to put your changes and new
code under the same license nghttp2 is already using unless stated and
agreed otherwise.

When changing existing source code, do not alter the copyright of
the original file(s).  The copyright will still be owned by the
original creator(s) or those who have been assigned copyright by the
original author(s).

By submitting a patch to the nghttp2 project, you (or your employer, as
the case may be) agree to assign the copyright of your submission to us.
.. the above really needs to be reworded to pass legal muster.
We will credit you for your
changes as far as possible, to give credit but also to keep a trace
back to who made what changes.  Please always provide us with your
full real name when contributing!

See `Contribution Guidelines
<https://nghttp2.org/documentation/contribute.html>`_ for more
details.
