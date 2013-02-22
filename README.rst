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

This project also develops SPDY client, server and proxy on top of
Spdylay library. See `SPDY Client and Server Programs`_ section.

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
resouce) in ``spdycat`` (one of the example program), the following
packages are needed:

* libxml2 >= 2.7.7

To build SPDY/HTTPS to HTTP reverse proxy ``shrpx`` (one of the
example program), the following packages are needed:

* libevent-openssl >= 2.0.8

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

SPDY Client and Server Programs
-------------------------------

The *src* directory contains SPDY client and server implementations
using Spdylay library. These programs are intended to make sure that
Spdylay API is acutally usable for real implementation and also for
debugging purposes. Please note that OpenSSL with `NPN
<http://technotes.googlecode.com/git/nextprotoneg.html>`_ support is
required in order to build and run these programs.  At the time of
this writing, the OpenSSL 1.0.1 supports NPN.

Spdycat - SPDY client
+++++++++++++++++++++

The SPDY client is called ``spdycat``. It is a dead simple downloader
like wget/curl. It connects to SPDY server and gets resources given in
the command-line::

    $ src/spdycat -h
    Usage: spdycat [-Oansv23] [-t <SECONDS>] [-w <WINDOW_BITS>] [--cert=<CERT>]
                   [--key=<KEY>] [--no-tls] [-d <FILE>] [-m <N>] <URI>...

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
        -a, --get-assets   Download assets such as stylesheets, images
                           and script files linked from the downloaded
                           resource. Only links whose origins are the
                           same with the linking resource will be
                           downloaded.
        -s, --stat         Print statistics.
        -H, --header       Add a header to the requests.
        --cert=<CERT>      Use the specified client certificate file.
                           The file must be in PEM format.
        --key=<KEY>        Use the client private key file. The file
                           must be in PEM format.
        --no-tls           Disable SSL/TLS. Use -2 or -3 to specify
                           SPDY protocol version to use.
        -d, --data=<FILE>  Post FILE to server. If - is given, data
                           will be read from stdin.
        -m, --multiply=<N> Request each URI <N> times. By default, same
                           URI is not requested twice. This option
                           disables it too.

    $ src/spdycat -nv https://www.google.com/
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

Spdyd - SPDY server
+++++++++++++++++++

SPDY server is called ``spdyd`` and serves static files. It is single
threaded and multiplexes connections using non-blocking socket. The
static files are read using blocking I/O system call, ``read(2)``. It
speaks SPDY/2 and SPDY/3::

    $ src/spdyd --htdocs=/your/htdocs/ -v 3000 server.key server.crt
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

Shrpx - A reverse proxy for SPDY/HTTPS
++++++++++++++++++++++++++++++++++++++

The ``shrpx`` is a multi-threaded reverse proxy for SPDY/HTTPS.  It
converts SPDY/HTTPS traffic to plain HTTP.  It is initially developed
as a reverse proxy, but now it has other operation modes such as a
frontend forward proxy.  For example, with ``--spdy-proxy`` (``-s`` in
shorthand) option, it can be used as secure SPDY proxy with a proxy
(e.g., Squid) in the backend.  With ``--cliet-proxy`` (``-p``) option,
it acts like an ordinaly forward proxy but expects secure SPDY proxy
in the backend. Thus it becomes an adapter to secure SPDY proxy for
clients which does not support secure SPDY proxy. The another notable
operation mode is ``--spdy-relay``, which just relays SPDY/HTTPS
traffic to the backend in SPDY. The following table summarizes the
operation modes.

================== ========== ======= =============
Mode option        Frontend   Backend Note
================== ========== ======= =============
default            SPDY/HTTPS HTTP    Reverse proxy
``--spdy``         SPDY/HTTPS HTTP    SPDY proxy
``--spdy-relay``   SPDY/HTTPS SPDY
``--client``       HTTP       SPDY
``--client-proxy`` HTTP       SPDY    Forward proxy
================== ========== ======= =============

The ``shrpx`` supports configuration file. See ``--conf`` option and
sample configuration file ``shrpx.conf.sample``.

We briefly describe the architecture of ``shrpx`` here.  It has a
dedicated thread which listens on server sockets.  When it accepted
the incoming connection, it passes the file descriptor of the incoming
connection to one of the worker thread.  Each worker thread has its
own event loop and can handle many connections using non-blocking I/O.
The number of worker thread can be specified using the command-line
option. The `libevent <http://libevent.org/>`_ is used to handle
low-level network I/O.

Here is the command-line options::

    $ src/shrpx -h
    Usage: shrpx [-Dh] [-s|--client|-p] [-b <HOST,PORT>]
                 [-f <HOST,PORT>] [-n <CORES>] [-c <NUM>] [-L <LEVEL>]
                 [OPTIONS...] [<PRIVATE_KEY> <CERT>]

    A reverse proxy for SPDY/HTTPS.

    Positional arguments:
        <PRIVATE_KEY>      Set path to server's private key. Required
                           unless either -p or --client is specified.
        <CERT>             Set path to server's certificate. Required
                           unless either -p or --client is specified.

    OPTIONS:

      Connections:
        -b, --backend=<HOST,PORT>
                           Set backend host and port.
                           Default: '127.0.0.1,80'
        -f, --frontend=<HOST,PORT>
                           Set frontend host and port.
                           Default: '0.0.0.0,3000'
        --backlog=<NUM>    Set listen backlog size.
                           Default: 256
        --backend-ipv4     Resolve backend hostname to IPv4 address
                           only.
        --backend-ipv6     Resolve backend hostname to IPv6 address
                           only.

      Performance:
        -n, --workers=<CORES>
                           Set the number of worker threads.
                           Default: 1

      Timeout:
        --frontend-spdy-read-timeout=<SEC>
                           Specify read timeout for SPDY frontend
                           connection. Default: 180
        --frontend-read-timeout=<SEC>
                           Specify read timeout for non-SPDY frontend
                           connection. Default: 180
        --frontend-write-timeout=<SEC>
                           Specify write timeout for both SPDY and
                           non-SPDY frontends.
                           connection. Default: 60
        --backend-read-timeout=<SEC>
                           Specify read timeout for backend connection.
                           Default: 900
        --backend-write-timeout=<SEC>
                           Specify write timeout for backend
                           connection. Default: 60
        --backend-keep-alive-timeout=<SEC>
                           Specify keep-alive timeout for backend
                           connection. Default: 60
        --backend-http-proxy-uri=<URI>
                           Specify proxy URI in the form
                           http://[<USER>:<PASS>@]<PROXY>:<PORT>. If
                           a proxy requires authentication, specify
                           <USER> and <PASS>. Note that they must be
                           properly percent-encoded. This proxy is used
                           when the backend connection is SPDY. First,
                           make a CONNECT request to the proxy and
                           it connects to the backend on behalf of
                           shrpx. This forms tunnel. After that, shrpx
                           performs SSL/TLS handshake with the
                           downstream through the tunnel. The timeouts
                           when connecting and making CONNECT request
                           can be specified by --backend-read-timeout
                           and --backend-write-timeout options.

      SSL/TLS:
        --ciphers=<SUITE>  Set allowed cipher list. The format of the
                           string is described in OpenSSL ciphers(1).
        -k, --insecure     When used with -p or --client, don't verify
                           backend server's certificate.
        --cacert=<PATH>    When used with -p or --client, set path to
                           trusted CA certificate file.
                           The file must be in PEM format. It can
                           contain multiple certificates. If the
                           linked OpenSSL is configured to load system
                           wide certificates, they are loaded
                           at startup regardless of this option.
        --private-key-passwd-file=<FILEPATH>
                           Path to file that contains password for the
                           server's private key. If none is given and
                           the private key is password protected it'll
                           be requested interactively.
        --subcert=<KEYPATH>:<CERTPATH>
                           Specify additional certificate and private
                           key file. Shrpx will choose certificates
                           based on the hostname indicated by client
                           using TLS SNI extension. This option can be
                           used multiple times.

      SPDY:
        -c, --spdy-max-concurrent-streams=<NUM>
                           Set the maximum number of the concurrent
                           streams in one SPDY session.
                           Default: 100
        --frontend-spdy-window-bits=<N>
                           Sets the initial window size of SPDY
                           frontend connection to 2**<N>.
                           Default: 16
        --backend-spdy-window-bits=<N>
                           Sets the initial window size of SPDY
                           backend connection to 2**<N>.
                           Default: 16
        --backend-spdy-no-tls
                           Disable SSL/TLS on backend SPDY connections.
                           SPDY protocol must be specified using
                           --backend-spdy-proto
        --backend-spdy-proto
                           Specify SPDY protocol used in backend
                           connection if --backend-spdy-no-tls is used.
                           Default: spdy/3

      Mode:
        -s, --spdy-proxy   Enable secure SPDY proxy mode.
        --spdy-bridge      Communicate with the backend in SPDY. Thus
                           the incoming SPDY/HTTPS connections are
                           converted to SPDY connection and relayed to
                           the backend. See --backend-http-proxy-uri
                           option if you are behind the proxy and want
                           to connect to the outside SPDY proxy.
        --client           Instead of accepting SPDY/HTTPS connection,
                           accept HTTP connection and communicate with
                           backend server in SPDY. To use shrpx as
                           a forward proxy, use -p option instead.
        -p, --client-proxy Like --client option, but it also requires
                           the request path from frontend must be
                           an absolute URI, suitable for use as a
                           forward proxy.

      Logging:
        -L, --log-level=<LEVEL>
                           Set the severity level of log output.
                           INFO, WARNING, ERROR and FATAL.
                           Default: WARNING
        --accesslog        Print simple accesslog to stderr.
        --syslog           Send log messages to syslog.
        --syslog-facility=<FACILITY>
                           Set syslog facility.
                           Default: daemon

      Misc:
        --add-x-forwarded-for
                           Append X-Forwarded-For header field to the
                           downstream request.
        --no-via           Don't append to Via header field. If Via
                           header field is received, it is left
                           unaltered.
        -D, --daemon       Run in a background. If -D is used, the
                           current working directory is changed to '/'.
        --pid-file=<PATH>  Set path to save PID of this program.
        --user=<USER>      Run this program as USER. This option is
                           intended to be used to drop root privileges.
        --conf=<PATH>      Load configuration from PATH.
                           Default: /etc/shrpx/shrpx.conf
        -v, --version      Print version and exit.
        -h, --help         Print this help and exit.

For those of you who are curious, ``shrpx`` is an abbreviation of
"Spdy/https to Http Reverse ProXy".

Without any of ``-s``, ``--spdy-bridge``, ``-p`` and ``--client``
options, ``shrpx`` works as reverse proxy to the backend server::

    Client <-- (SPDY, HTTPS) --> Shrpx <-- (HTTP) --> Web Server
                            [reverse proxy]

With ``-s`` option, it works as secure SPDY proxy::

    Client <-- (SPDY, HTTPS) --> Shrpx <-- (HTTP) --> Proxy
                              [SPDY proxy]            (e.g., Squid)

The ``Client`` in the above is needs to be configured to use shrpx as
secure SPDY proxy.

At the time of this writing, Chrome is the only browser which supports
secure SPDY proxy. The one way to configure Chrome to use secure SPDY
proxy is create proxy.pac script like this::

    function FindProxyForURL(url, host) {
        return "HTTPS SERVERADDR:PORT";
    }

``SERVERADDR`` and ``PORT`` is the hostname/address and port of the
machine shrpx is running.  Please note that Chrome requires valid
certificate for secure SPDY proxy.

Then run chrome with the following arguments::

    $ google-chrome --proxy-pac-url=file:///path/to/proxy.pac --use-npn

.. note::

   At the time of this writing, Chrome 24 limits the maximum
   concurrent connections to the proxy to 32. And due to the
   limitation of socket pool handling in Chrome, it is quickly filled
   up if SPDY proxy is used and many SPDY sessions are established. If
   it reaches the limit, the new connections are simply blocked until
   existing connections are timed out. (See `Chrome Issue 92244
   <https://code.google.com/p/chromium/issues/detail?id=92244>`_). The
   workaround is make the number of maximum connections high, say, 99,
   which is the highest. To do this, you need to change so called
   Policy setup.  See `Policy Templates
   <http://dev.chromium.org/administrators/policy-templates>`_ for
   details how to change Policy setup on the platform you use.  The
   Policy name we are looking for is `MaxConnectionsPerProxy
   <http://dev.chromium.org/administrators/policy-list-3#MaxConnectionsPerProxy>`_
   For example, if you are using Linux, follow the instruction
   described in `Linux Quick Start
   <http://dev.chromium.org/administrators/linux-quick-start>`_ and
   create ``/etc/opt/chrome/policies/managed/test_policy.json`` file
   with the following content and restart Chrome::

       {
           "MaxConnectionsPerProxy" :99
       }

With ``--spdy-bridge``, it accepts SPDY/HTTPS connections and
communicates with backend in SPDY::

    Client <-- (SPDY, HTTPS) --> Shrpx <-- (SPDY) --> Web or SPDY Proxy etc
                              [SPDY bridge]           (e.g., shrpx -s)

With ``-p`` option, it works as forward proxy and expects that the
backend is secure SPDY proxy::

    Client <-- (HTTP) --> Shrpx <-- (SPDY) --> Secure SPDY Proxy
                     [forward proxy]         (e.g., shrpx -s or node-spdyproxy)

The ``Client`` is needs to be configured to use shrpx as forward proxy.

In this configuration, clients which do not support secure SPDY proxy
can use secure SPDY proxy through ``shrpx``. Putting ``shrpx`` in the
same box or same network with the clients, this configuration can
bring the benefits of secure SPDY proxy to those clients. Since the
maximum number of connections per server still applies in proxy
connection, the performance gain is not obvious. For example, if the
maximum number of connections per server is 6, after sending 6
requests to the proxy, client blocks further requests, which kills
performance which might be gained in SPDY connection.  For clients
which can tweak these values (e.g.,
``network.http.max-connections-per-server`` in Firefox), increasing
them may improve the performance.

With ``--client`` option, it works as reverse proxy and expects that
the backend is SPDY-enabled Web server::

    Client <-- (HTTP) --> Shrpx <-- (SPDY) --> Web Server
                     [reverse proxy]

For the operation modes which talk to the backend in SPDY, the backend
connections can be tunneled though HTTP proxy. The proxy is specified
using ``--backend-http-proxy-uri`` option. The following figure
illustrates the example of ``--spdy-bridge`` and
``--backend-http-proxy-uri`` option to talk to the outside SPDY proxy
through HTTP proxy::

    Client <-- (SPDY, HTTPS) --> Shrpx <-- (SPDY) --
                             [SPDY bridge]

            --===================---> SPDY Proxy
              (HTTP proxy tunnel)     (e.g., shrpx -s)

Examples
--------

The *examples* directory contains a simple SPDY client implementation
in C.

Python-Spdylay - Python Wrapper
-------------------------------

The library comes with Python wrapper ``python-spdylay``. See
``python`` directory.
