h2load - HTTP/2 benchmarking tool - HOW-TO
==========================================

h2load is benchmarking tool for HTTP/2.  If built with
spdylay (http://tatsuhiro-t.github.io/spdylay/) library, it also
supports SPDY protocol.  It supports SSL/TLS and clear text for both
HTTP/2 and SPDY.

Basic Usage
-----------

In order to set benchmark settings, specify following 3 options.

``-n``
    The number of total requests.  Default: 1

``-c``
    The number of concurrent clients.  Default: 1

``-m``
   The max concurrent streams to issue per client.
   If ``auto`` is given, the number of given URIs is used.
   Default: ``auto``

Here is a command-line to perform benchmark to URI \https://localhost
using total 100000 requests, 100 concurrent clients and 10 max
concurrent streams::

    $ h2load -n100000 -c100 -m10 https://localhost

The benchmarking result looks like this::

    finished in 0 sec, 385 millisec and 851 microsec, 2591 req/s, 1689 kbytes/s
    requests: 1000 total, 1000 started, 1000 done, 1000 succeeded, 0 failed, 0 errored
    status codes: 1000 2xx, 0 3xx, 0 4xx, 0 5xx
    traffic: 667500 bytes total, 28700 bytes headers, 612000 bytes data

The number of ``failed`` is the number of requests returned with non
2xx status.  The number of ``error`` is the number of ``failed`` plus
the number of requests which failed with connection error.

The number of ``total`` in ``traffic`` is the received application
data.  If SSL/TLS is used, this number is calculated after decryption.
The number of ``headers`` is the sum of payload size of response
HEADERS (or SYN_REPLY for SPDY).  This number comes before
decompressing header block.  The number of ``data`` is the sum of
response body.

Flow Control
------------

HTTP/2 and SPDY/3 or later employ flow control and it may affect
benchmarking results.  By default, h2load uses large enough flow
control window, which effectively disables flow control.  To adjust
receiver flow control window size, there are following options:

``-w``
   Sets  the stream  level  initial  window size  to
   (2**<N>)-1.  For SPDY, 2**<N> is used instead.

``-W``
   Sets the connection level  initial window size to
   (2**<N>)-1.  For  SPDY, if  <N> is  strictly less
   than  16,  this  option  is  ignored.   Otherwise
   2**<N> is used for SPDY.

Multi-Threading
---------------

Sometimes benchmarking client itself becomes a bottleneck.  To remedy
this situation, use ``-t`` option to specify the number of native
thread to use.

``-t``
    The number of native threads. Default: 1

Selecting protocol for clear text
---------------------------------

By default, if \http:// URI is given, HTTP/2 protocol is used.  To
change the protocol to use for clear text, use ``-p`` option.

Multiple URIs
-------------

If multiple URIs are specified, they are used in round robin manner.

.. note::

    Please note that h2load uses scheme, host and port in the first URI
    and ignores those parts in the rest of the URIs.
