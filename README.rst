nghttp2 - HTTP/2.0 C Library
============================

This is an experimental implementation of Hypertext Transfer Protocol
version 2.0.

Development Status
------------------

We started to implement HTTP-draft-06/2.0
(http://tools.ietf.org/html/draft-ietf-httpbis-http2-06) and the
header compression
(http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-03).

The nghttp2 code base was forked from spdylay project.

=================== =================
Features            HTTP-draft-06/2.0
=================== =================
Flow Control        Done
Header Compression  Done
Reprioritization    Done
Header Continuation
Server Push         Done
HTTP Upgrade        Done
ALPN
NPN                 Done
=================== =================

Public Test Server
------------------

The following endpoints are available to try out nghttp2
implementation.  These endpoints supports ``HTTP-draft-06/2.0`` and
the earlier draft versions are not supporeted.

* https://106.186.112.116 (TLS + NPN)

  NPN offers ``HTTP-draft-06/2.0``, ``spdy/3``, ``spdy/2`` and
  ``http/1.1``.

  Note: certificate is self-signed and a browser will show alert

* http://106.186.112.116 (Upgrade + Direct)

Requirements
------------

The following packages are needed to build the library:

* pkg-config >= 0.20
* zlib >= 1.2.3

To build and run the unit test programs, the following packages are
required:

* cunit >= 2.1

To build and run the application programs (``nghttp``, ``nghttpd`` and
``nghttpx``) in ``src`` directory, the following packages are
required:

* OpenSSL >= 1.0.1
* libevent-openssl >= 2.0.8

To enable SPDY protocol in the application program ``nghttpx``, the
following packages are required:

* spdylay >= 1.0.0

To enable ``-a`` option (getting linked assets from the downloaded
resouce) in ``nghttp``, the following
packages are needed:

* libxml2 >= 2.7.7

If you are using Ubuntu 12.04, you need the following packages
installed:

* autoconf
* automake
* autotools-dev
* libtool
* pkg-config
* zlib1g-dev
* libcunit1-dev
* libssl-dev
* libxml2-dev
* libevent-dev

spdylay is not packaged in Ubuntu, so you need to build it yourself:
http://spdylay.sourceforge.net/

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

.. note::

   Documentation is still incomplete.

To build documentation, run::

    $ make html

The documents will be generated under ``doc/manual/html/``.

The generated documents will not be installed with ``make install``.

The online documentation is available at
http://tatsuhiro-t.github.io/nghttp2/

Client, Server and Proxy programs
---------------------------------

The src directory contains HTTP/2.0 client, server and proxy programs.

nghttp - client
+++++++++++++++

``nghttp`` is a HTTP/2.0 client. It can connect to the HTTP/2.0 server
with prior knowledge, HTTP Upgrade and NPN TLS extension.

It has verbose output mode for framing information. Here is sample
output from ``nghttp`` client::

    $ src/nghttp -vn https://localhost:8443
    [  0.001] NPN select next protocol: the remote server offers:
              * HTTP-draft-06/2.0
              * spdy/3
              * spdy/2
              * http/1.1
              NPN selected the protocol: HTTP-draft-06/2.0
    [  0.006] send SETTINGS frame <length=16, flags=0x00, stream_id=0>
              (niv=2)
              [MAX_CONCURRENT_STREAMS(4):100]
              [INITIAL_WINDOW_SIZE(7):65535]
    [  0.006] send HEADERS frame <length=58, flags=0x05, stream_id=1>
              ; END_STREAM | END_HEADERS
              ; Open new stream
              :host: localhost:8443
              :method: GET
              :path: /
              :scheme: https
              accept: */*
              accept-encoding: gzip, deflate
              user-agent: nghttp2/0.1.0-DEV
    [  0.007] recv SETTINGS frame <length=16, flags=0x00, stream_id=0>
              (niv=2)
              [MAX_CONCURRENT_STREAMS(4):100]
              [INITIAL_WINDOW_SIZE(7):65535]
    [  0.008] recv WINDOW_UPDATE frame <length=4, flags=0x00, stream_id=0>
              (window_size_increment=1000000007)
    [  0.008] recv HEADERS frame <length=179, flags=0x04, stream_id=1>
              ; END_HEADERS
              ; First response header
              :status: 200 OK
              accept-ranges: bytes
              content-encoding: gzip
              content-length: 56
              content-type: text/html
              date: Thu, 22 Aug 2013 16:37:17 GMT
              etag: "cf405c-2d-45adabdf282c0"
              last-modified: Tue, 04 Nov 2008 10:44:03 GMT
              server: Apache/2.2.22 (Debian)
              vary: Accept-Encoding
              via: 1.1 nghttpx
    [  0.009] recv DATA frame <length=56, flags=0x00, stream_id=1>
    [  0.009] recv DATA frame <length=0, flags=0x01, stream_id=1>
              ; END_STREAM
    [  0.009] send GOAWAY frame <length=8, flags=0x00, stream_id=0>
              (last_stream_id=0, error_code=NO_ERROR(0), opaque_data(0)=[])

The HTTP Upgrade is performed like this::

    $ src/nghttp -vnu http://localhost:8080
    [  0.000] HTTP Upgrade request
    GET / HTTP/1.1
    Host: localhost:8080
    Connection: Upgrade, HTTP2-Settings
    Upgrade: HTTP-draft-06/2.0
    HTTP2-Settings: AAAABAAAAGQAAAAHAAD__w
    Accept: */*
    User-Agent: nghttp2/0.1.0-DEV


    [  0.000] HTTP Upgrade response
    HTTP/1.1 101 Switching Protocols
    Connection: Upgrade
    Upgrade: HTTP/2.0


    [  0.000] HTTP Upgrade success
    [  0.001] send SETTINGS frame <length=16, flags=0x00, stream_id=0>
              (niv=2)
              [MAX_CONCURRENT_STREAMS(4):100]
              [INITIAL_WINDOW_SIZE(7):65535]
    [  0.001] recv SETTINGS frame <length=16, flags=0x00, stream_id=0>
              (niv=2)
              [MAX_CONCURRENT_STREAMS(4):100]
              [INITIAL_WINDOW_SIZE(7):65535]
    [  0.001] recv WINDOW_UPDATE frame <length=4, flags=0x00, stream_id=0>
              (window_size_increment=1000000007)
    [  0.001] recv HEADERS frame <length=198, flags=0x04, stream_id=1>
              ; END_HEADERS
              ; First response header
              :status: 200 OK
              accept-ranges: bytes
              content-length: 45
              content-type: text/html
              date: Thu, 22 Aug 2013 16:39:04 GMT
              etag: "cf405c-2d-45adabdf282c0"
              last-modified: Tue, 04 Nov 2008 10:44:03 GMT
              server: Apache/2.2.22 (Debian)
              vary: Accept-Encoding
              via: 1.1 nghttpx
              x-pad: avoid browser bug
    [  0.001] recv DATA frame <length=45, flags=0x00, stream_id=1>
    [  0.001] recv DATA frame <length=0, flags=0x01, stream_id=1>
              ; END_STREAM
    [  0.001] send GOAWAY frame <length=8, flags=0x00, stream_id=0>
              (last_stream_id=0, error_code=NO_ERROR(0), opaque_data(0)=[])

nghttpd - server
++++++++++++++++

``nghttpd`` is static web server. It is single threaded and
multiplexes connections using non-blocking socket.

By default, it uses SSL/TLS connection. Use ``--no-tls`` option to
disable it.

``nghttpd`` only accept the HTTP/2.0 connection via NPN or direct
HTTP/2.0 connection. No HTTP Upgrade is supported.

Just like ``nghttp``, it has verbose output mode for framing
information. Here is sample output from ``nghttpd`` server::

    $ src/nghttpd --no-tls -v 8080
    IPv4: listen on port 8080
    IPv6: listen on port 8080
    [id=1] [ 14.716] send SETTINGS frame <length=8, flags=0x00, stream_id=0>
              (niv=1)
              [MAX_CONCURRENT_STREAMS(4):100]
    [id=1] [ 14.717] recv SETTINGS frame <length=16, flags=0x00, stream_id=0>
              (niv=2)
              [MAX_CONCURRENT_STREAMS(4):100]
              [INITIAL_WINDOW_SIZE(7):65535]
    [id=1] [ 14.717] recv HEADERS frame <length=58, flags=0x05, stream_id=1>
              ; END_STREAM | END_HEADERS
              ; Open new stream
              :host: localhost:8080
              :method: GET
              :path: /
              :scheme: http
              accept: */*
              accept-encoding: gzip, deflate
              user-agent: nghttp2/0.1.0-DEV
    [id=1] [ 14.717] send HEADERS frame <length=105, flags=0x04, stream_id=1>
              ; END_HEADERS
              ; First response header
              :status: 404 Not Found
              content-encoding: gzip
              content-type: text/html; charset=UTF-8
              date: Thu, 22 Aug 2013 16:41:05 GMT
              server: nghttpd nghttp2/0.1.0-DEV
    [id=1] [ 14.717] send DATA frame <length=128, flags=0x00, stream_id=1>
    [id=1] [ 14.717] send DATA frame <length=0, flags=0x01, stream_id=1>
              ; END_STREAM
    [id=1] [ 14.717] stream_id=1 closed
    [id=1] [ 14.717] recv GOAWAY frame <length=8, flags=0x00, stream_id=0>
              (last_stream_id=0, error_code=NO_ERROR(0), opaque_data(0)=[])
    [id=1] [ 14.717] closed

nghttpx - proxy
+++++++++++++++

The ``nghttpx`` is a multi-threaded reverse proxy for
HTTP-draft-06/2.0, SPDY and HTTP/1.1. It has several operation modes:

================== ============================== ============== =============
Mode option        Frontend                       Backend        Note
================== ============================== ============== =============
default mode       HTTP/2.0, SPDY, HTTP/1.1 (TLS) HTTP/1.1       Reverse proxy
``--spdy``         HTTP/2.0, SPDY, HTTP/1.1 (TLS) HTTP/1.1       SPDY proxy
``--spdy-bridge``  HTTP/2.0, SPDY, HTTP/1.1 (TLS) HTTP/2.0 (TLS)
``--client``       HTTP/2.0, HTTP/1.1             HTTP/2.0 (TLS)
``--client-proxy`` HTTP/2.0, HTTP/1.1             HTTP/2.0 (TLS) Forward proxy
================== ============================== ============== =============

The interesting mode at the moment is the default mode. It works like
a reverse proxy and listens HTTP-draft-06/2.0, SPDY and HTTP/1.1 and
can be deployed SSL/TLS terminator for existing web server.

The default mode, ``--spdy`` and ``--spdy-bridge`` modes use SSL/TLS
in the frontend connection by default. To disable SSL/TLS, use
``--frontend-no-tls`` option. If that option is used, SPDY is disabled
in the frontend and incoming HTTP/1.1 connection can be upgraded to
HTTP/2.0 through HTTP Upgrade.

The ``--spdy-bridge``, ``--client`` and ``--client-proxy`` modes use
SSL/TLS in the backend connection by deafult. To disable SSL/TLS, use
``--backend-no-tls`` option.

The ``nghttpx`` supports configuration file. See ``--conf`` option and
sample configuration file ``nghttpx.conf.sample``.

The ``nghttpx`` is ported from ``shrpx`` in spdylay project, and it
still has SPDY color in option names. They will be fixed as the
development goes.

In the default mode, (without any of ``--spdy``, ``--spdy-bridge``,
``--client-proxy`` and ``--client`` options), ``nghttpx`` works as
reverse proxy to the backend server::

    Client <-- (HTTP/2.0, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/1.1) --> Web Server
                                          [reverse proxy]

With ``--spdy`` option, it works as so called secure proxy (aka SPDY
proxy)::

    Client <-- (HTTP/2.0, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/1.1) --> Proxy
                                           [secure proxy]            (e.g., Squid)

The ``Client`` in the above is needs to be configured to use
``nghttpx`` as secure proxy.

At the time of this writing, Chrome is the only browser which supports
secure proxy. The one way to configure Chrome to use secure proxy is
create proxy.pac script like this::

    function FindProxyForURL(url, host) {
        return "HTTPS SERVERADDR:PORT";
    }

``SERVERADDR`` and ``PORT`` is the hostname/address and port of the
machine nghttpx is running.  Please note that Chrome requires valid
certificate for secure proxy.

Then run chrome with the following arguments::

    $ google-chrome --proxy-pac-url=file:///path/to/proxy.pac --use-npn

With ``--spdy-bridge``, it accepts HTTP/2.0, SPDY and HTTP/1.1
connections and communicates with backend in HTTP/2.0::

    Client <-- (HTTP/2.0, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/2.0) --> Web or HTTP/2.0 Proxy etc
                                                                         (e.g., nghttpx -s)

With ``--client-proxy`` option, it works as forward proxy and expects
that the backend is HTTP/2.0 proxy::

    Client <-- (HTTP/2.0, HTTP/1.1) --> nghttpx <-- (HTTP/2.0) --> HTTP/2.0 Proxy
                                     [forward proxy]               (e.g., nghttpx -s)

The ``Client`` is needs to be configured to use nghttpx as forward
proxy.  The frontend HTTP/1.1 connection can be upgraded to HTTP/2.0
through HTTP Upgrade.  With the above configuration, one can use
HTTP/1.1 client to access and test their HTTP/2.0 servers.

With ``--client`` option, it works as reverse proxy and expects that
the backend is HTTP/2.0 Web server::

    Client <-- (HTTP/2.0, HTTP/1.1) --> nghttpx <-- (HTTP/2.0) --> Web Server
                                    [reverse proxy]

The frontend HTTP/1.1 connection can be upgraded to HTTP/2.0
through HTTP Upgrade.

For the operation modes which talk to the backend in HTTP/2.0 over
SSL/TLS, the backend connections can be tunneled though HTTP
proxy. The proxy is specified using ``--backend-http-proxy-uri``
option. The following figure illustrates the example of
``--spdy-bridge`` and ``--backend-http-proxy-uri`` option to talk to
the outside HTTP/2.0 proxy through HTTP proxy::

    Client <-- (HTTP/2.0, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/2.0) --

            --===================---> HTTP/2.0 Proxy
              (HTTP proxy tunnel)     (e.g., nghttpx -s)
