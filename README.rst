nghttp2 - HTTP/2.0 C Library
============================

This is an experimental implementation of Hypertext Transfer Protocol
version 2.0.

Development Status
------------------

We started to implement h2-10
(http://tools.ietf.org/html/draft-ietf-httpbis-http2-10) and the
header compression
(http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-06).

The nghttp2 code base was forked from spdylay project.

========================== =====
Features                   h2-10
========================== =====
HPACK-draft-06             Done
Strict SETTINGS validation Done
Disallow client to push    Done
Padding                    Done
END_SEGMENT
========================== =====

Public Test Server
------------------

The following endpoints are available to try out nghttp2
implementation.  These endpoints supports ``HTTP-draft-09/2.0`` and
the earlier draft versions are not supporeted.

* https://106.186.112.116 (TLS + NPN / ALPN)

  ALPN and NPN offer ``HTTP-draft-09/2.0``, ``spdy/3.1``, ``spdy/3``,
  ``spdy/2`` and ``http/1.1``.

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

To build the documentation, you need to install:

* sphinx (http://sphinx-doc.org/)

To build and run the application programs (``nghttp``, ``nghttpd`` and
``nghttpx``) in ``src`` directory, the following packages are
required:

* OpenSSL >= 1.0.1
* libevent-openssl >= 2.0.8

ALPN support requires unreleased version OpenSSL >= 1.0.2.

To enable SPDY protocol in the application program ``nghttpx``, the
following packages are required:

* spdylay >= 1.2.3

To enable ``-a`` option (getting linked assets from the downloaded
resource) in ``nghttp``, the following packages are needed:

* libxml2 >= 2.7.7

The HPACK tools require the following package:

* jansson >= 2.5

The Python bindings require the following packages:

* cython >= 0.19
* python >= 2.7

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
* libjansson-dev

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
with prior knowledge, HTTP Upgrade and NPN/ALPN TLS extension.

It has verbose output mode for framing information. Here is sample
output from ``nghttp`` client::

    $ src/nghttp -nv https://localhost:8443
    [  0.004][NPN] server offers:
              * h2-10
              * spdy/3.1
              * spdy/3
              * spdy/2
              * http/1.1
    The negotiated protocol: h2-10
    [  0.006] send SETTINGS frame <length=10, flags=0x00, stream_id=0>
              (niv=2)
              [SETTINGS_MAX_CONCURRENT_STREAMS(3):100]
              [SETTINGS_INITIAL_WINDOW_SIZE(4):65535]
    [  0.007] send HEADERS frame <length=48, flags=0x05, stream_id=1>
              ; END_STREAM | END_HEADERS
              (padlen=0)
              ; Open new stream
              :authority: localhost:8443
              :method: GET
              :path: /
              :scheme: https
              accept: */*
              accept-encoding: gzip, deflate
              user-agent: nghttp2/0.4.0-DEV
    [  0.007] recv SETTINGS frame <length=15, flags=0x00, stream_id=0>
              (niv=3)
              [SETTINGS_MAX_CONCURRENT_STREAMS(3):100]
              [SETTINGS_INITIAL_WINDOW_SIZE(4):65535]
              [SETTINGS_ENABLE_PUSH(2):0]
    [  0.007] send SETTINGS frame <length=0, flags=0x01, stream_id=0>
              ; ACK
              (niv=0)
    [  0.007] recv SETTINGS frame <length=0, flags=0x01, stream_id=0>
              ; ACK
              (niv=0)
    [  0.008] (stream_id=1) :status: 200
    [  0.008] (stream_id=1) accept-ranges: bytes
    [  0.008] (stream_id=1) content-encoding: gzip
    [  0.008] (stream_id=1) content-length: 146
    [  0.008] (stream_id=1) content-type: text/html
    [  0.008] (stream_id=1) date: Sat, 15 Feb 2014 08:14:12 GMT
    [  0.008] (stream_id=1) etag: "b1-4e5535a027780-gzip"
    [  0.008] (stream_id=1) last-modified: Sun, 01 Sep 2013 14:34:22 GMT
    [  0.008] (stream_id=1) server: Apache/2.4.6 (Debian)
    [  0.008] (stream_id=1) vary: Accept-Encoding
    [  0.008] (stream_id=1) via: 1.1 nghttpx
    [  0.008] recv HEADERS frame <length=141, flags=0x04, stream_id=1>
              ; END_HEADERS
              (padlen=0)
              ; First response header
    [  0.008] recv DATA frame <length=146, flags=0x00, stream_id=1>
    [  0.008] recv DATA frame <length=0, flags=0x01, stream_id=1>
              ; END_STREAM
    [  0.008] send GOAWAY frame <length=8, flags=0x00, stream_id=0>
              (last_stream_id=0, error_code=NO_ERROR(0), opaque_data(0)=[])

The HTTP Upgrade is performed like this::

    $ src/nghttp -nvu http://localhost:8080
    [  0.000] HTTP Upgrade request
    GET / HTTP/1.1
    Host: localhost:8080
    Connection: Upgrade, HTTP2-Settings
    Upgrade: h2-10
    HTTP2-Settings: AwAAAGQEAAD__w
    Accept: */*
    User-Agent: nghttp2/0.4.0-DEV


    [  0.001] HTTP Upgrade response
    HTTP/1.1 101 Switching Protocols
    Connection: Upgrade
    Upgrade: h2-10


    [  0.001] HTTP Upgrade success
    [  0.001] send SETTINGS frame <length=10, flags=0x00, stream_id=0>
              (niv=2)
              [SETTINGS_MAX_CONCURRENT_STREAMS(3):100]
              [SETTINGS_INITIAL_WINDOW_SIZE(4):65535]
    [  0.001] recv SETTINGS frame <length=15, flags=0x00, stream_id=0>
              (niv=3)
              [SETTINGS_MAX_CONCURRENT_STREAMS(3):100]
              [SETTINGS_INITIAL_WINDOW_SIZE(4):65535]
              [SETTINGS_ENABLE_PUSH(2):0]
    [  0.001] (stream_id=1) :status: 200
    [  0.001] (stream_id=1) accept-ranges: bytes
    [  0.001] (stream_id=1) content-length: 177
    [  0.001] (stream_id=1) content-type: text/html
    [  0.001] (stream_id=1) date: Sat, 15 Feb 2014 08:16:23 GMT
    [  0.001] (stream_id=1) etag: "b1-4e5535a027780"
    [  0.001] (stream_id=1) last-modified: Sun, 01 Sep 2013 14:34:22 GMT
    [  0.001] (stream_id=1) server: Apache/2.4.6 (Debian)
    [  0.001] (stream_id=1) vary: Accept-Encoding
    [  0.001] (stream_id=1) via: 1.1 nghttpx
    [  0.001] recv HEADERS frame <length=132, flags=0x04, stream_id=1>
              ; END_HEADERS
              (padlen=0)
              ; First response header
    [  0.001] recv DATA frame <length=177, flags=0x00, stream_id=1>
    [  0.001] recv DATA frame <length=0, flags=0x01, stream_id=1>
              ; END_STREAM
    [  0.002] send SETTINGS frame <length=0, flags=0x01, stream_id=0>
              ; ACK
              (niv=0)
    [  0.002] send GOAWAY frame <length=8, flags=0x00, stream_id=0>
              (last_stream_id=0, error_code=NO_ERROR(0), opaque_data(0)=[])
    [  0.002] recv SETTINGS frame <length=0, flags=0x01, stream_id=0>
              ; ACK
              (niv=0)

nghttpd - server
++++++++++++++++

``nghttpd`` is static web server. It is single threaded and
multiplexes connections using non-blocking socket.

By default, it uses SSL/TLS connection. Use ``--no-tls`` option to
disable it.

``nghttpd`` only accept the HTTP/2.0 connection via NPN/ALPN or direct
HTTP/2.0 connection. No HTTP Upgrade is supported.

``-p`` option allows users to configure server push.

Just like ``nghttp``, it has verbose output mode for framing
information. Here is sample output from ``nghttpd`` server::

    $ src/nghttpd --no-tls -v 8080
    IPv4: listen on port 8080
    IPv6: listen on port 8080
    [id=1] [  1.027] send SETTINGS frame <length=10, flags=0x00, stream_id=0>
              (niv=2)
              [SETTINGS_MAX_CONCURRENT_STREAMS(3):100]
              [SETTINGS_ENABLE_PUSH(2):0]
    [id=1] [  1.027] recv SETTINGS frame <length=10, flags=0x00, stream_id=0>
              (niv=2)
              [SETTINGS_MAX_CONCURRENT_STREAMS(3):100]
              [SETTINGS_INITIAL_WINDOW_SIZE(4):65535]
    [id=1] [  1.027] (stream_id=1) :authority: localhost:8080
    [id=1] [  1.027] (stream_id=1) :method: GET
    [id=1] [  1.027] (stream_id=1) :path: /
    [id=1] [  1.027] (stream_id=1) :scheme: http
    [id=1] [  1.027] (stream_id=1) accept: */*
    [id=1] [  1.027] (stream_id=1) accept-encoding: gzip, deflate
    [id=1] [  1.027] (stream_id=1) user-agent: nghttp2/0.4.0-DEV
    [id=1] [  1.027] recv HEADERS frame <length=48, flags=0x05, stream_id=1>
              ; END_STREAM | END_HEADERS
              (padlen=0)
              ; Open new stream
    [id=1] [  1.027] send SETTINGS frame <length=0, flags=0x01, stream_id=0>
              ; ACK
              (niv=0)
    [id=1] [  1.027] send HEADERS frame <length=72, flags=0x04, stream_id=1>
              ; END_HEADERS
              (padlen=0)
              ; First response header
              :status: 404
              content-encoding: gzip
              content-type: text/html; charset=UTF-8
              date: Sat, 15 Feb 2014 08:18:53 GMT
              server: nghttpd nghttp2/0.4.0-DEV
    [id=1] [  1.028] send DATA frame <length=118, flags=0x00, stream_id=1>
    [id=1] [  1.028] send DATA frame <length=0, flags=0x01, stream_id=1>
              ; END_STREAM
    [id=1] [  1.028] stream_id=1 closed
    [id=1] [  1.028] recv SETTINGS frame <length=0, flags=0x01, stream_id=0>
              ; ACK
              (niv=0)
    [id=1] [  1.028] recv GOAWAY frame <length=8, flags=0x00, stream_id=0>
              (last_stream_id=0, error_code=NO_ERROR(0), opaque_data(0)=[])
    [id=1] [  1.028] closed

nghttpx - proxy
+++++++++++++++

The ``nghttpx`` is a multi-threaded reverse proxy for
h2-10, SPDY and HTTP/1.1. It has several operation modes:

================== ============================== ============== =============
Mode option        Frontend                       Backend        Note
================== ============================== ============== =============
default mode       HTTP/2.0, SPDY, HTTP/1.1 (TLS) HTTP/1.1       Reverse proxy
``--http2-proxy``  HTTP/2.0, SPDY, HTTP/1.1 (TLS) HTTP/1.1       SPDY proxy
``--http2-bridge`` HTTP/2.0, SPDY, HTTP/1.1 (TLS) HTTP/2.0 (TLS)
``--client``       HTTP/2.0, HTTP/1.1             HTTP/2.0 (TLS)
``--client-proxy`` HTTP/2.0, HTTP/1.1             HTTP/2.0 (TLS) Forward proxy
================== ============================== ============== =============

The interesting mode at the moment is the default mode. It works like
a reverse proxy and listens h2-10, SPDY and HTTP/1.1 and
can be deployed SSL/TLS terminator for existing web server.

The default mode, ``--http2-proxy`` and ``--http2-bridge`` modes use
SSL/TLS in the frontend connection by default. To disable SSL/TLS, use
``--frontend-no-tls`` option. If that option is used, SPDY is disabled
in the frontend and incoming HTTP/1.1 connection can be upgraded to
HTTP/2.0 through HTTP Upgrade.

The ``--http2-bridge``, ``--client`` and ``--client-proxy`` modes use
SSL/TLS in the backend connection by deafult. To disable SSL/TLS, use
``--backend-no-tls`` option.

The ``nghttpx`` supports configuration file. See ``--conf`` option and
sample configuration file ``nghttpx.conf.sample``.

The ``nghttpx`` does not support server push.

In the default mode, (without any of ``--http2-proxy``,
``--http2-bridge``, ``--client-proxy`` and ``--client`` options),
``nghttpx`` works as reverse proxy to the backend server::

    Client <-- (HTTP/2.0, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/1.1) --> Web Server
                                          [reverse proxy]

With ``--http2-proxy`` option, it works as so called secure proxy (aka
SPDY proxy)::

    Client <-- (HTTP/2.0, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/1.1) --> Proxy
                                           [secure proxy]            (e.g., Squid)

The ``Client`` in the above is needs to be configured to use
``nghttpx`` as secure proxy.

At the time of this writing, Chrome is the only browser which supports
secure proxy. The one way to configure Chrome to use secure proxy is
create proxy.pac script like this:

.. code-block:: javascript

    function FindProxyForURL(url, host) {
        return "HTTPS SERVERADDR:PORT";
    }

``SERVERADDR`` and ``PORT`` is the hostname/address and port of the
machine nghttpx is running.  Please note that Chrome requires valid
certificate for secure proxy.

Then run chrome with the following arguments::

    $ google-chrome --proxy-pac-url=file:///path/to/proxy.pac --use-npn

With ``--http2-bridge``, it accepts HTTP/2.0, SPDY and HTTP/1.1
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
``--http2-bridge`` and ``--backend-http-proxy-uri`` option to talk to
the outside HTTP/2.0 proxy through HTTP proxy::

    Client <-- (HTTP/2.0, SPDY, HTTP/1.1) --> nghttpx <-- (HTTP/2.0) --

            --===================---> HTTP/2.0 Proxy
              (HTTP proxy tunnel)     (e.g., nghttpx -s)

HPACK tools
-----------

The ``src`` directory contains HPACK tools. The ``deflatehd`` is
command-line header compression tool. The ``inflatehd`` is
command-line header decompression tool.  Both tools read input from
stdin and write output to stdout. The errors are written to
stderr. They take JSON as input and output. We use the same JSON data
format used in https://github.com/Jxck/hpack-test-case

deflatehd - header compressor
+++++++++++++++++++++++++++++

The ``deflatehd`` reads JSON data or HTTP/1-style header fields from
stdin and outputs compressed header block in JSON.

For the JSON input, the root JSON object must include ``cases``
key. Its value has to include the sequence of input header set. They
share the same compression context and are processed in the order they
appear.  Each item in the sequence is a JSON object and it must
include ``headers`` key. Its value is an array of a JSON object ,
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
header field block. Each header set is delimited by empty line:

Example::

    :method: GET
    :scheme: https
    :path: /

    :method: POST
    user-agent: nghttp2

The output is JSON object. It should include ``cases`` key and its
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
    The header table size adjsuted before deflating header set.

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
associated value includes the state of dyanmic header table after the
corresponding header set was processed. The value includes at least
following keys:

entries
    The entry in the header table. If ``referenced`` is ``true``, it
    is in the reference set. The ``size`` includes the overhead (32
    bytes). The ``index`` corresponds to the index of header table.
    The ``name`` is the header field name and the ``value`` is the
    header field value. They may be displayed as ``**DEALLOCATED**``,
    which means that the memory for that string is freed and not
    available. This will happen when the specifying smaller value in
    ``-S`` than ``-s``.

size
    The sum of the spaces entries occupied, this includes the
    entry overhead.

max_size
    The maximum header table size.

deflate_size
    The sum of the spaces entries occupied within
    ``max_deflate_size``.

max_deflate_size
    The maximum header table size encoder uses. This can be smaller
    than ``max_size``. In this case, encoder only uses up to first
    ``max_deflate_size`` buffer. Since the header table size is still
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

The root JSON object must include ``cases`` key. Its value has to
include the sequence of compressed header block. They share the same
compression context and are processed in the order they appear. Each
item in the sequence is a JSON object and it must have at least
``wire`` key. Its value is a compressed header block in hex string.

Example:

.. code-block:: json

    {
      "cases":
      [
        { "wire": "8285" },
        { "wire": "8583" }
      ]
    }

The output is JSON object. It should include ``cases`` key and its
value is an array of JSON object, which has at least following keys:

seq
    The index of header set in the input.

headers
    The JSON array includes decompressed name/value pairs.

wire
    The compressed header block in hex string.

header_table_size
    The header table size adjsuted before inflating compressed header
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
associated value includes the state of dyanmic header table after the
corresponding header set was processed. The format is the same as
``deflatehd``.

Python bindings
---------------

This ``python`` directory contains nghttp2 Python bindings. The
bindings currently only provide HPACK compressor and decompressor
classes.

The extension module is called ``nghttp2``.

``make`` will build the bindings and target Python version is
determined by configure script. If the detected Python version is not
what you expect, specify a path to Python executable in ``PYTHON``
variable as an argument to configure script (e.g., ``./configure
PYTHON=/usr/bin/python3.3``).

Example
+++++++

The following example code illustrates basic usage of HPACK compressor
and decompressor in Python:

.. code-block:: python

    import binascii
    import nghttp2

    deflater = nghttp2.HDDeflater(nghttp2.HD_SIDE_REQUEST)
    inflater = nghttp2.HDInflater(nghttp2.HD_SIDE_REQUEST)

    data = deflater.deflate([(b'foo', b'bar'),
                             (b'baz', b'buz')])
    print(binascii.b2a_hex(data))

    hdrs = inflater.inflate(data)
    print(hdrs)
