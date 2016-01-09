h2load - HTTP/2 benchmarking tool - HOW-TO
==========================================

h2load is benchmarking tool for HTTP/2 and HTTP/1.1.  If built with
spdylay (http://tatsuhiro-t.github.io/spdylay/) library, it also
supports SPDY protocol.  It supports SSL/TLS and clear text for all
supported protocols.

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

For SSL/TLS connection, the protocol will be negotiated via ALPN/NPN.
You can set specific protocols in ``--npn-list`` option.  For
cleartext connection, the default protocol is HTTP/2.  To change the
protocol in cleartext connection, use ``--no-tls-proto`` option.  For
convenience, ``--h1`` option forces HTTP/1.1 for both cleartext and
SSL/TLS connections.

Here is a command-line to perform benchmark to URI \https://localhost
using total 100000 requests, 100 concurrent clients and 10 max
concurrent streams:

.. code-block:: text

    $ h2load -n100000 -c100 -m10 https://localhost

The benchmarking result looks like this:

.. code-block:: text

    finished in 7.08s, 141164.80 req/s, 555.33MB/s
    requests: 1000000 total, 1000000 started, 1000000 done, 1000000 succeeded, 0 failed, 0 errored, 0 timeout
    status codes: 1000000 2xx, 0 3xx, 0 4xx, 0 5xx
    traffic: 4125025824 bytes total, 11023424 bytes headers (space savings 93.07%), 4096000000 bytes data
                         min         max         mean         sd        +/- sd
    time for request:    15.31ms    146.85ms     69.78ms      9.26ms    92.43%
    time for connect:     1.08ms     25.04ms     10.71ms      9.80ms    64.00%
    time to 1st byte:    25.36ms    184.96ms     79.11ms     53.97ms    78.00%
    req/s (client)  :    1412.04     1447.84     1426.52       10.57    63.00%

See the h2load manual page :ref:`h2load-1-output` section for the
explanation of the above numbers.

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
