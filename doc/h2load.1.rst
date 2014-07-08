.. program:: h2load

h2load(1)
=========

NAME
----
h2load - HTTP/2 benchmarking tool

SYNOPSIS
--------
**h2load** [OPTIONS]... <URI>...

DESCRIPTION
-----------
benchmarking tool for HTTP/2 and SPDY server

.. option:: URI

    Specify  URI to  access.   Multiple  URIs can  be
    specified.  URIs are used  in this order for each
    client.   All URIs  are used,  then first  URI is
    used and  then 2nd URI,  and so on.   The scheme,
    host and port in the subsequent URIs, if present,
    are  ignored.  Those  in the  first URI  are used
    solely.

OPTIONS
-------

.. option:: -n, --requests=<N>

    Number of requests. Default: 1

.. option:: -c, --clients=<N>

    
    Number of concurrent clients. Default: 1

.. option:: -t, --threads=<N>

    
    Number of native threads. Default: 1

.. option:: -m, --max-concurrent-streams=(auto|<N>)

    
    Max concurrent streams to  issue per session.  If
    "auto"  is given,  the  number of  given URIs  is
    used.  Default: auto

.. option:: -w, --window-bits=<N>

    
    Sets  the stream  level  initial  window size  to
    (2\*\*<N>)-1.  For SPDY, 2\*\*<N> is used instead.

.. option:: -W, --connection-window-bits=<N>

    
    Sets the connection level  initial window size to
    (2\*\*<N>)-1.  For  SPDY, if  <N> is  strictly less
    than  16,  this  option  is  ignored.   Otherwise
    2\*\*<N> is used for SPDY.

.. option:: -p, --no-tls-proto=<PROTOID>

    
    Specify  ALPN identifier  of the  protocol to  be
    used  when accessing  http  URI without  SSL/TLS.
    Available protocols: spdy/2, spdy/3, spdy/3.1 and
    h2c-13
    Default: h2c-13

.. option:: -v, --verbose

    
    Output debug information.

.. option:: --version

    
    Display version information and exit.

.. option:: -h, --help

    
    Display this help and exit.

SEE ALSO
--------

nghttp(1), nghttpd(1), nghttpx(1)
