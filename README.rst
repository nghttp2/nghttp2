nghttp2 - HTTP/2.0 C Library
============================

This is an experimental implementation of Hypertext Transfer Protocol
version 2.0.

Development Status
------------------

We started to implement HTTP-defat-04/2.0
(http://tools.ietf.org/html/draft-ietf-httpbis-http2-04) based on
spdylay code base.

The following features are not implemented:

* Header continuation
* ALPN: instead, NPN is used
* HTTP Upgrade dance

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

Client, Server and Proxy programs
---------------------------------

The src directory contains HTTP/2.0 client, server and proxy programs.

nghttp - client
+++++++++++++++

``nghttp`` is HTTP-default04/2.0 client. It can connect to the
HTTP/2.0 server with prior knowledge (without HTTP Upgrade) and NPN in
TLS extension.

By default, it uses SSL/TLS connection. Use ``--no-tls`` option to
disable it.

It has verbose output mode for framing information. Here is sample
output from ``nghttp`` client::

    $ src/nghttp -nv https://localhost:3000/
    [  0.000] NPN select next protocol: the remote server offers:
              * HTTP-draft-04/2.0
              * spdy/3
              * spdy/2
              * http/1.1
              NPN selected the protocol: HTTP-draft-04/2.0
    [  0.005] send SETTINGS frame <length=0, flags=0, stream_id=0>
              (niv=0)
    [  0.005] send HEADERS frame <length=58, flags=5, stream_id=1>
              ; END_STREAM | END_HEADERS
              ; Open new stream
              :host: localhost:3000
              :method: GET
              :path: /
              :scheme: https
              accept: */*
              accept-encoding: gzip, deflate
              user-agent: nghttp2/0.1.0-DEV
    [  0.005] recv SETTINGS frame <length=16, flags=0, stream_id=0>
              (niv=2)
              [4:100]
              [7:65536]
    [  0.005] recv WINDOW_UPDATE frame <length=4, flags=1, stream_id=0>
              ; END_FLOW_CONTROL
              (window_size_increment=0)
    [  0.006] recv HEADERS frame <length=179, flags=4, stream_id=1>
              ; END_HEADERS
              ; First response header
              :status: 200 OK
              accept-ranges: bytes
              content-encoding: gzip
              content-length: 56
              content-type: text/html
              date: Sat, 27 Jul 2013 12:08:56 GMT
              etag: "cf405c-2d-45adabdf282c0"
              last-modified: Tue, 04 Nov 2008 10:44:03 GMT
              server: Apache/2.2.22 (Debian)
              vary: Accept-Encoding
              via: 1.1 nghttpx
    [  0.006] recv DATA frame (length=56, flags=0, stream_id=1)
    [  0.006] recv DATA frame (length=0, flags=1, stream_id=1)
    [  0.006] send GOAWAY frame <length=8, flags=0, stream_id=0>
              (last_stream_id=0, error_code=NO_ERROR(0), opaque_data=)

nghttpd - server
++++++++++++++++

``nghttpd`` is static web server. It is single threaded and
multiplexes connections using non-blocking socket.

By default, it uses SSL/TLS connection. Use ``--no-tls`` option to
disable it.

Just like ``nghttp``, it has verbose output mode for framing
information. Here is sample output from ``nghttpd`` server::

    $ src/nghttpd 3000 --no-tls -v
    IPv4: listen on port 3000
    IPv6: listen on port 3000
    [id=1] [  1.020] send SETTINGS frame <length=8, flags=0, stream_id=0>
              (niv=1)
              [4:100]
    [id=1] [  1.020] closed
    [id=2] [  1.838] send SETTINGS frame <length=8, flags=0, stream_id=0>
              (niv=1)
              [4:100]
    [id=2] [  1.838] recv SETTINGS frame <length=0, flags=0, stream_id=0>
              (niv=0)
    [id=2] [  1.838] recv HEADERS frame <length=58, flags=5, stream_id=1>
              ; END_STREAM | END_HEADERS
              ; Open new stream
              :host: localhost:3000
              :method: GET
              :path: /
              :scheme: http
              accept: */*
              accept-encoding: gzip, deflate
              user-agent: nghttp2/0.1.0-DEV
    [id=2] [  1.838] send HEADERS frame <length=105, flags=4, stream_id=1>
              ; END_HEADERS
              ; First response header
              :status: 404 Not Found
              content-encoding: gzip
              content-type: text/html; charset=UTF-8
              date: Sat, 27 Jul 2013 12:32:10 GMT
              server: nghttpd nghttp2/0.1.0-DEV
    [id=2] [  1.838] send DATA frame (length=127, flags=0, stream_id=1)
    [id=2] [  1.838] send DATA frame (length=0, flags=1, stream_id=1)
    [id=2] [  1.838] stream_id=1 closed
    [id=2] [  1.839] closed

nghttpx - proxy
+++++++++++++++

The ``nghttpx`` is a multi-threaded reverse proxy for
HTTP-draft-04/2.0, SPDY/HTTPS. It has several operation modes:

================== ======================== ======== ======================
Mode option        Frontend                 Backend  Note
================== ======================== ======== ======================
default            HTTP/2.0, SPDY, HTTPS    HTTP/1.1 Reverse proxy
``--spdy``         HTTP/2.0, SPDY, HTTPS    HTTP/1.1 SPDY proxy
``--spdy-bridge``  HTTP/2.0, SPDY, HTTPS    HTTP/2.0 SPDY proxy
``--client``       HTTP/1.1                 HTTP/2.0 1.1 <-> 2.0 conversion
``--client-proxy`` HTTP/1.1                 HTTP/2.0 Forward proxy
================== ======================== ======== ======================

The interesting mode at the moment is the default mode. It works like
a reverse proxy and listens HTTP-draft-04/2.0 as well as SPDY and
HTTPS and can be deployed SSL/TLS terminator for existing web server.

By default, it uses SSL/TLS connection for HTTP/2.0 and SPDY. Use
``--frontend-spdy--no-tls`` to disable it in frontend
connection. Likewise, use ``--backend-spdy-no-tls`` option to disable
it in backend connection.

The ``nghttpx`` supports configuration file. See ``--conf`` option and
sample configuration file ``nghttpx.conf.sample``.

The ``nghttpx`` is ported from ``shrpx`` in spdylay project, and it
still has SPDY color in option names. They will be fixed as the
development goes.

Without any of ``-s``, ``--spdy-bridge``, ``-p`` and ``--client``
options, ``nghttpx`` works as reverse proxy to the backend server::

    Client <-- (HTTP/2.0, SPDY, HTTPS) --> nghttpx <-- (HTTP) --> Web Server
                                       [reverse proxy]

With ``-s`` option, it works as so called secure SPDY proxy::

    Client <-- (HTTP/2.0, SPDY, HTTPS) --> nghttpx <-- (HTTP) --> Proxy
                                       [SPDY proxy]            (e.g., Squid)

The ``Client`` in the above is needs to be configured to use nghttpx as
secure SPDY proxy.

At the time of this writing, Chrome is the only browser which supports
secure SPDY proxy. The one way to configure Chrome to use secure SPDY
proxy is create proxy.pac script like this::

    function FindProxyForURL(url, host) {
        return "HTTPS SERVERADDR:PORT";
    }

``SERVERADDR`` and ``PORT`` is the hostname/address and port of the
machine nghttpx is running.  Please note that Chrome requires valid
certificate for secure SPDY proxy.

Then run chrome with the following arguments::

    $ google-chrome --proxy-pac-url=file:///path/to/proxy.pac --use-npn

With ``--spdy-bridge``, it accepts HTTP/2.0, SPDY and HTTPS
connections and communicates with backend in HTTP/2.0::

    Client <-- (HTTP/2.0, SPDY, HTTPS) --> nghttpx <-- (HTTP/2.0) --> Web or HTTP/2.0 Proxy etc
                                        [SPDY bridge]              (e.g., nghttpx -s)

With ``-p`` option, it works as forward proxy and expects that the
backend is HTTP/2.0 proxy::

    Client <-- (HTTP) --> nghttpx <-- (HTTP/2.0) --> HTTP/2.0 Proxy
                     [forward proxy]                 (e.g., nghttpx -s)

The ``Client`` is needs to be configured to use nghttpx as forward proxy.

With the above configuration, one can use HTTP/1.1 client to access
and test their HTTP/2.0 servers.

With ``--client`` option, it works as reverse proxy and expects that
the backend is HTTP/2.0 Web server::

    Client <-- (HTTP) --> nghttpx <-- (HTTP/2.0) --> Web Server
                     [reverse proxy]

For the operation modes which talk to the backend in HTTP/2.0, the
backend connections can be tunneled though HTTP proxy. The proxy is
specified using ``--backend-http-proxy-uri`` option. The following
figure illustrates the example of ``--spdy-bridge`` and
``--backend-http-proxy-uri`` option to talk to the outside HTTP/2.0 proxy
through HTTP proxy::

    Client <-- (HTTP/2.0, SPDY, HTTPS) --> nghttpx <-- (HTTP/2.0) --
                                       [SPDY bridge]

            --===================---> HTTP/2.0 Proxy
              (HTTP proxy tunnel)     (e.g., nghttpx -s)
