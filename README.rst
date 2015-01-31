nghttp2 - HTTP/2 C Library
==========================

This is an implementation of Hypertext Transfer Protocol version 2
in C.

The framing layer of HTTP/2 is implemented as a form of reusable C
library.  On top of that, we have implemented HTTP/2 client, server
and proxy.  We have also developed load test and benchmarking tool for
HTTP/2 and SPDY.

HPACK encoder and decoder are available as public API.

The experimental high level C++ library is also available.

We have Python binding of this libary, but we have not covered
everything yet.

Development Status
------------------

We started to implement h2-14
(http://tools.ietf.org/html/draft-ietf-httpbis-http2-14), the header
compression
(http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-09).

The nghttp2 code base was forked from spdylay project.

=========================== =======
HTTP/2 Features             Support
=========================== =======
Core frames handling        Yes
Dependency Tree             Yes
Large header (CONTINUATION) Yes
=========================== =======

Public Test Server
------------------

The following endpoints are available to try out nghttp2
implementation.

* https://nghttp2.org/ (TLS + ALPN/NPN)

  NPN offer ``h2-14``, ``spdy/3.1`` and ``http/1.1``.

  This endpoint requires TLSv1.2 for HTTP/2 connection.

* http://nghttp2.org/ (Upgrade / Direct)

  ``h2c-14`` and ``http/1.1``.

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
``nghttpx``) in ``src`` directory, the following packages are
required:

* OpenSSL >= 1.0.1
* libev >= 4.15
* zlib >= 1.2.3

ALPN support requires unreleased version OpenSSL >= 1.0.2.

To enable SPDY protocol in the application program ``nghttpx`` and
``h2load``, the following package is required:

* spdylay >= 1.3.0

To enable ``-a`` option (getting linked assets from the downloaded
resource) in ``nghttp``, the following package is required:

* libxml2 >= 2.7.7

The HPACK tools require the following package:

* jansson >= 2.5

To build sources under examples directory, libevent is required:

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

If you are using Ubuntu 14.04 LTS, you need the following packages
installed::

    apt-get install make binutils autoconf  automake autotools-dev libtool pkg-config zlib1g-dev libcunit1-dev libssl-dev libxml2-dev libev-dev libevent-dev libjansson-dev libjemalloc-dev cython python3.4-dev

spdylay is not packaged in Ubuntu, so you need to build it yourself:
http://tatsuhiro-t.github.io/spdylay/

Build from git
--------------

Building from git is easy, but please be sure that at least autoconf 2.68 is
used::

    $ autoreconf -i
    $ automake
    $ autoconf
    $ ./configure
    $ make

To compile source code, gcc >= 4.8.3 or clang >= 3.4 is required.

.. note::

   Mac OS X users may need ``--disable-threads`` configure option to
   disable multi threading in nghttpd, nghttpx and h2load to prevent
   them from crashing.  Patch is welcome to make multi threading work
   on Mac OS X platform.

Building documentation
----------------------

.. note::

   Documentation is still incomplete.

To build documentation, run::

    $ make html

The documents will be generated under ``doc/manual/html/``.

The generated documents will not be installed with ``make install``.

The online documentation is available at
https://nghttp2.org/documentation/

Unit tests
----------

Unit tests are done by simply running `make check`.

Integration tests
-----------------

We have the integration tests for nghttpx proxy server.  The tests are
written in `Go programming language <http://golang.org/>`_ and uses
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

Inside the tests, we use port 3009 to run test subject server.

Client, Server and Proxy programs
---------------------------------

The src directory contains HTTP/2 client, server and proxy programs.

nghttp - client
+++++++++++++++

``nghttp`` is a HTTP/2 client.  It can connect to the HTTP/2 server
with prior knowledge, HTTP Upgrade and NPN/ALPN TLS extension.

It has verbose output mode for framing information.  Here is sample
output from ``nghttp`` client::

    $ src/nghttp -nv https://nghttp2.org
    [  0.033][NPN] server offers:
              * h2-14
              * spdy/3.1
              * http/1.1
    The negotiated protocol: h2-14
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

    $ src/nghttp -nvu http://nghttp2.org
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

nghttpd - server
++++++++++++++++

``nghttpd`` is a multi-threaded static web server.

By default, it uses SSL/TLS connection.  Use ``--no-tls`` option to
disable it.

``nghttpd`` only accepts the HTTP/2 connection via NPN/ALPN or direct
HTTP/2 connection.  No HTTP Upgrade is supported.

``-p`` option allows users to configure server push.

Just like ``nghttp``, it has verbose output mode for framing
information.  Here is sample output from ``nghttpd`` server::

    $ src/nghttpd --no-tls -v 8080
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

``nghttpx`` is a multi-threaded reverse proxy for ``h2-14``, SPDY and
HTTP/1.1 and powers nghttp2.org site.  It has several operation modes:

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
a reverse proxy and listens for ``h2-14``, SPDY and HTTP/1.1 and can
be deployed SSL/TLS terminator for existing web server.

The default mode, ``--http2-proxy`` and ``--http2-bridge`` modes use
SSL/TLS in the frontend connection by default.  To disable SSL/TLS,
use ``--frontend-no-tls`` option.  If that option is used, SPDY is
disabled in the frontend and incoming HTTP/1.1 connection can be
upgraded to HTTP/2 through HTTP Upgrade.

The ``--http2-bridge``, ``--client`` and ``--client-proxy`` modes use
SSL/TLS in the backend connection by deafult.  To disable SSL/TLS, use
``--backend-no-tls`` option.

``nghttpx`` supports configuration file.  See ``--conf`` option and
sample configuration file ``nghttpx.conf.sample``.

``nghttpx`` does not support server push.

In the default mode, (without any of ``--http2-proxy``,
``--http2-bridge``, ``--client-proxy`` and ``--client`` options),
``nghttpx`` works as reverse proxy to the backend server::

    Client <-- (HTTP/2, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/1.1) --> Web Server
                                          [reverse proxy]

With ``--http2-proxy`` option, it works as so called secure proxy (aka
SPDY proxy)::

    Client <-- (HTTP/2, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/1.1) --> Proxy
                                           [secure proxy]          (e.g., Squid, ATS)

The ``Client`` in the above needs to be configured to use
``nghttpx`` as secure proxy.

At the time of this writing, Chrome is the only browser which supports
secure proxy.  The one way to configure Chrome to use secure proxy is
create proxy.pac script like this:

.. code-block:: javascript

    function FindProxyForURL(url, host) {
        return "HTTPS SERVERADDR:PORT";
    }

``SERVERADDR`` and ``PORT`` is the hostname/address and port of the
machine nghttpx is running.  Please note that Chrome requires valid
certificate for secure proxy.

Then run Chrome with the following arguments::

    $ google-chrome --proxy-pac-url=file:///path/to/proxy.pac --use-npn

With ``--http2-bridge``, it accepts HTTP/2, SPDY and HTTP/1.1
connections and communicates with backend in HTTP/2::

    Client <-- (HTTP/2, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/2) --> Web or HTTP/2 Proxy etc
                                                                         (e.g., nghttpx -s)

With ``--client-proxy`` option, it works as forward proxy and expects
that the backend is HTTP/2 proxy::

    Client <-- (HTTP/2, HTTP/1.1) --> nghttpx <-- (HTTP/2) --> HTTP/2 Proxy
                                     [forward proxy]               (e.g., nghttpx -s)

The ``Client`` needs to be configured to use nghttpx as forward
proxy.  The frontend HTTP/1.1 connection can be upgraded to HTTP/2
through HTTP Upgrade.  With the above configuration, one can use
HTTP/1.1 client to access and test their HTTP/2 servers.

With ``--client`` option, it works as reverse proxy and expects that
the backend is HTTP/2 Web server::

    Client <-- (HTTP/2, HTTP/1.1) --> nghttpx <-- (HTTP/2) --> Web Server
                                    [reverse proxy]

The frontend HTTP/1.1 connection can be upgraded to HTTP/2
through HTTP Upgrade.

For the operation modes which talk to the backend in HTTP/2 over
SSL/TLS, the backend connections can be tunneled through HTTP proxy.
The proxy is specified using ``--backend-http-proxy-uri`` option.  The
following figure illustrates the example of ``--http2-bridge`` and
``--backend-http-proxy-uri`` options to talk to the outside HTTP/2
proxy through HTTP proxy::

    Client <-- (HTTP/2, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/2) --

            --===================---> HTTP/2 Proxy
              (HTTP proxy tunnel)     (e.g., nghttpx -s)

Benchmarking tool
-----------------

The ``h2load`` program is a benchmarking tool for HTTP/2 and SPDY.
The SPDY support is enabled if the program was built with spdylay
library.  The UI of ``h2load`` is heavily inspired by ``weighttp``
(https://github.com/lighttpd/weighttp).  The typical usage is as
follows::

    $ src/h2load -n100000 -c100 -m100 https://localhost:8443/
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

The above example issued total 100000 requests, using 100 concurrent
clients (in other words, 100 HTTP/2 sessions), and maximum 100 streams
per client.  With ``-t`` option, ``h2load`` will use multiple native
threads to avoid saturating single core on client side.

.. warning::

   **Don't use this tool against publicly available servers.** That is
   considered a DOS attack.  Please only use against your private
   servers.

HPACK tools
-----------

The ``src`` directory contains HPACK tools.  The ``deflatehd`` is a
command-line header compression tool.  The ``inflatehd`` is
command-line header decompression tool.  Both tools read input from
stdin and write output to stdout.  The errors are written to stderr.
They take JSON as input and output.  We use (mostly) same JSON data
format described at https://github.com/http2jp/hpack-test-case

deflatehd - header compressor
+++++++++++++++++++++++++++++

The ``deflatehd`` reads JSON data or HTTP/1-style header fields from
stdin and outputs compressed header block in JSON.

For the JSON input, the root JSON object must include ``cases`` key.
Its value has to include the sequence of input header set.  They share
the same compression context and are processed in the order they
appear.  Each item in the sequence is a JSON object and it must
include ``headers`` key.  Its value is an array of a JSON object,
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


With ``-t`` option, the program can accept more familiar HTTP/1 style
header field block.  Each header set is delimited by empty line:

Example::

    :method: GET
    :scheme: https
    :path: /

    :method: POST
    user-agent: nghttp2

The output is JSON object.  It should include ``cases`` key and its
value is an array of JSON object, which has at least following keys:

seq
    The index of header set in the input.

input_length
    The sum of length of name/value pair in the input.

output_length
    The length of compressed header block.

percentage_of_original_size
    ``input_length`` / ``output_length`` * 100

wire
    The compressed header block in hex string.

headers
    The input header set.

header_table_size
    The header table size adjusted before deflating header set.

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

With ``-d`` option, the extra ``header_table`` key is added and its
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
    The maximum header table size encoder uses.  This can be smaller
    than ``max_size``.  In this case, encoder only uses up to first
    ``max_deflate_size`` buffer.  Since the header table size is still
    ``max_size``, the encoder has to keep track of entries ouside the
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

The ``inflatehd`` reads JSON data from stdin and outputs decompressed
name/value pairs in JSON.

The root JSON object must include ``cases`` key.  Its value has to
include the sequence of compressed header block.  They share the same
compression context and are processed in the order they appear.  Each
item in the sequence is a JSON object and it must have at least
``wire`` key.  Its value is a compressed header block in hex string.

Example:

.. code-block:: json

    {
      "cases":
      [
        { "wire": "8285" },
        { "wire": "8583" }
      ]
    }

The output is JSON object.  It should include ``cases`` key and its
value is an array of JSON object, which has at least following keys:

seq
    The index of header set in the input.

headers
    The JSON array includes decompressed name/value pairs.

wire
    The compressed header block in hex string.

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

With ``-d`` option, the extra ``header_table`` key is added and its
associated value includes the state of dynamic header table after the
corresponding header set was processed.  The format is the same as
``deflatehd``.

libnghttp2_asio: High level HTTP/2 C++ library
----------------------------------------------

libnghttp2_asio is C++ library built on top of libnghttp2 and provides
high level abstraction API to build HTTP/2 applications.  It depends
on Boost::ASIO library and OpenSSL.  Currently libnghttp2_asio
provides server side API.

libnghttp2_asio is not built by default.  Use ``--enable-asio-lib``
configure flag to build libnghttp2_asio.  The required Boost libraries
are:

* Boost::Asio
* Boost::System
* Boost::Thread

Server API is designed to build HTTP/2 server very easily to utilize
C++11 anonymous function and closure.  The bare minimum example of
HTTP/2 server looks like this:

.. code-block:: cpp

    #include <nghttp2/asio_http2.h>

    using namespace nghttp2::asio_http2;
    using namespace nghttp2::asio_http2::server;

    int main(int argc, char *argv[]) {
      http2 server;

      server.listen("*", 3000, [](const std::shared_ptr<request> &req,
                                  const std::shared_ptr<response> &res) {
        res->write_head(200);
        res->end("hello, world");
      });
    }

For more details, see the documentation of libnghttp2_asio.

Python bindings
---------------

This ``python`` directory contains nghttp2 Python bindings.  The
bindings currently provide HPACK compressor and decompressor classes
and HTTP/2 server.

The extension module is called ``nghttp2``.

``make`` will build the bindings and target Python version is
determined by configure script.  If the detected Python version is not
what you expect, specify a path to Python executable in ``PYTHON``
variable as an argument to configure script (e.g., ``./configure
PYTHON=/usr/bin/python3.4``).

The following example code illustrates basic usage of HPACK compressor
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
when HEADERS frame, which includes request header fields, has arrived.

If request has request body, ``on_data(data)`` is invoked for each
chunk of received data.

When whole request is received, ``on_request_done()`` is invoked.

When stream is closed, ``on_close(error_code)`` is called.

The application can send response using ``send_response()`` method.
It can be used in ``on_headers()``, ``on_data()`` or
``on_request_done()``.

The application can push resource using ``push()`` method.  It must be
used before ``send_response()`` call.

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

When changing existing source code, you do not alter the copyright of
the original file(s).  The copyright will still be owned by the
original creator(s) or those who have been assigned copyright by the
original author(s).

By submitting a patch to the nghttp2 project, you are assumed to have
the right to the code and to be allowed by your employer or whatever
to hand over that patch/code to us.  We will credit you for your
changes as far as possible, to give credit but also to keep a trace
back to who made what changes.  Please always provide us with your
full real name when contributing!

See `Contribution Guidelines
<https://nghttp2.org/documentation/contribute.html>`_ for more
details.
