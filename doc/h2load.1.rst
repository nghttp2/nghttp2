
h2load(1)
=========

SYNOPSIS
--------

**h2load** [OPTIONS]... [URI]...

DESCRIPTION
-----------

benchmarking tool for HTTP/2 and SPDY server

.. describe:: <URI>

    Specify URI to access.   Multiple URIs can be specified.
    URIs are used  in this order for each  client.  All URIs
    are used, then  first URI is used and then  2nd URI, and
    so  on.  The  scheme, host  and port  in the  subsequent
    URIs, if present,  are ignored.  Those in  the first URI
    are used solely.

OPTIONS:
--------

.. option:: -n, --requests=<N>

    Number of requests.

    Default: ``1``

.. option:: -c, --clients=<N>

    Number of concurrent clients.

    Default: ``1``

.. option:: -t, --threads=<N>

    Number of native threads.

    Default: ``1``

.. option:: -i, --input-file=<FILE>

    Path of a file with multiple URIs are seperated by EOLs.
    This option will disable URIs getting from command-line.
    If '-' is given as <FILE>, URIs will be read from stdin.
    URIs are used  in this order for each  client.  All URIs
    are used, then  first URI is used and then  2nd URI, and
    so  on.  The  scheme, host  and port  in the  subsequent
    URIs, if present,  are ignored.  Those in  the first URI
    are used solely.

.. option:: -m, --max-concurrent-streams=(auto|<N>)

    Max concurrent streams to  issue per session.  If "auto"
    is given, the number of given URIs is used.

    Default: ``auto``

.. option:: -w, --window-bits=<N>

    Sets the stream level initial window size to (2\*\*<N>)-1.
    For SPDY, 2**<N> is used instead.

.. option:: -W, --connection-window-bits=<N>

    Sets  the  connection  level   initial  window  size  to
    (2**<N>)-1.  For SPDY, if <N>  is strictly less than 16,
    this option  is ignored.   Otherwise 2\*\*<N> is  used for
    SPDY.

.. option:: -H, --header=<HEADER>

    Add/Override a header to the requests.

.. option:: -p, --no-tls-proto=<PROTOID>

    Specify ALPN identifier of the  protocol to be used when
    accessing http URI without SSL/TLS.
    Available protocols: spdy/2, spdy/3, spdy/3.1 and h2c-14

    Default: ``h2c-14``

.. option:: -v, --verbose

    Output debug information.

.. option:: --version

    Display version information and exit.

.. option:: -h, --help

    Display this help and exit.

OUTPUT
------

requests
  total
    The number of requests h2load was instructed to make.
  started
    The number of requests h2load has started.
  done
    The number of requests completed.
  succeeded
    The number of requests completed successfully.  Only HTTP status
    code 2xx or3xx are considered as success.
  failed
    The number of requests failed, including HTTP level failures
    (non-successful HTTP status code).
  errored
    The number of requests failed, except for HTTP level failures.
    status code.  This is the subset of the number reported in
    ``failed`` and most likely the network level failures or stream
    was reset by RST_STREAM.

status codes
  The number of status code h2load received.

traffic
  total
    The number of bytes received from the server "on the wire".  If
    requests were made via TLS, this value is the number of decrpyted
    bytes.
  headers
    The number of response header bytes from the server without
    decompression.  For HTTP/2, this is the sum of the payload of
    HEADERS frame.  For SPDY, this is the sum of the payload of
    SYN_REPLY frame.
  data
    The number of response body bytes received from the server.

time for request
  min
    The minimum time taken for request and response.
  max
    The maximum time taken for request and response.
  mean
    The mean time taken for request and response.
  sd
    The standard deviation of the time for request and response.
  +/- sd
    The fraction of the number of requests within standard deviation
    range (mean +/- sd) against total number of successful requests.

SEE ALSO
--------

:manpage:`nghttp(1)`, :manpage:`nghttpd(1)`, :manpage:`nghttpx(1)`
