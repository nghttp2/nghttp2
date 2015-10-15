nghttpx - HTTP/2 proxy - HOW-TO
===============================

nghttpx is a proxy translating protocols between HTTP/2 and other
protocols (e.g., HTTP/1, SPDY).  It operates in several modes and each
mode may require additional programs to work with.  This article
describes each operation mode and explains the intended use-cases.  It
also covers some useful options later.

Default mode
------------

If nghttpx is invoked without any ``-s``, ``-p`` and ``--client``, it
operates in default mode.  In this mode, nghttpx frontend listens for
HTTP/2 requests and translates them to HTTP/1 requests.  Thus it works
as reverse proxy (gateway) for HTTP/2 clients to HTTP/1 web server.
HTTP/1 requests are also supported in frontend as a fallback.  If
nghttpx is linked with spdylay library and frontend connection is
SSL/TLS, the frontend also supports SPDY protocol.

By default, this mode's frontend connection is encrypted using
SSL/TLS.  So server's private key and certificate must be supplied to
the command line (or through configuration file).  In this case, the
frontend protocol selection will be done via ALPN or NPN.

With ``--frontend-no-tls`` option, user can turn off SSL/TLS in
frontend connection.  In this case, SPDY protocol is not available
even if spdylay library is liked to nghttpx.  HTTP/2 and HTTP/1 are
available on the frontend and a HTTP/1 connection can be upgraded to
HTTP/2 using HTTP Upgrade.  Starting HTTP/2 connection by sending
HTTP/2 connection preface is also supported.

The backend is supposed to be HTTP/1 Web server.  For example, to make
nghttpx listen to encrypted HTTP/2 requests at port 8443, and a
backend HTTP/1 web server is configured to listen to HTTP/1 request at
port 8080 in the same host, run nghttpx command-line like this::

    $ nghttpx -f0.0.0.0,8443 -b127.0.0.1,8080 /path/to/server.key /path/to/server.crt

Then HTTP/2 enabled client can access to the nghttpx in HTTP/2.  For
example, you can send GET request to the server using nghttp::

    $ nghttp -nv https://localhost:8443/

HTTP/2 proxy mode
-----------------

If nghttpx is invoked with ``-s`` option, it operates in HTTP/2 proxy
mode.  The supported protocols in frontend and backend connections are
the same in `default mode`_.  The difference is that this mode acts
like forward proxy and assumes the backend is HTTP/1 proxy server
(e.g., squid, traffic server).  So HTTP/1 request must include
absolute URI in request line.

By default, frontend connection is encrypted.  So this mode is also
called secure proxy.  If nghttpx is linked with spdylay, it supports
SPDY protocols and it works as so called SPDY proxy.

With ``--frontend-no-tls`` option, SSL/TLS is turned off in frontend
connection, so the connection gets insecure.

The backend must be HTTP/1 proxy server.  nghttpx supports multiple
backend server addresses.  It translates incoming requests to HTTP/1
request to backend server.  The backend server performs real proxy
work for each request, for example, dispatching requests to the origin
server and caching contents.

For example, to make nghttpx listen to encrypted HTTP/2 requests at
port 8443, and a backend HTTP/1 proxy server is configured to listen
to HTTP/1 request at port 8080 in the same host, run nghttpx
command-line like this::

    $ nghttpx -s -f'*,8443' -b127.0.0.1,8080 /path/to/server.key /path/to/server.crt

At the time of this writing, Firefox 41 and Chromium v46 can use
nghttpx as HTTP/2 proxy.

To make Firefox or Chromium use nghttpx as HTTP/2 or SPDY proxy, user
has to create proxy.pac script file like this:

.. code-block:: javascript

    function FindProxyForURL(url, host) {
        return "HTTPS SERVERADDR:PORT";
    }

``SERVERADDR`` and ``PORT`` is the hostname/address and port of the
machine nghttpx is running.  Please note that both Firefox and
Chromium require valid certificate for secure proxy.

For Firefox, open Preference window and select Advanced then click
Network tab.  Clicking Connection Settings button will show the
dialog.  Select "Automatic proxy configuration URL" and enter the path
to proxy.pac file, something like this::

    file:///path/to/proxy.pac

For Chromium, use following command-line::

    $ google-chrome --proxy-pac-url=file:///path/to/proxy.pac --use-npn

As HTTP/1 proxy server, Squid may work as out-of-box.  Traffic server
requires to be configured as forward proxy.  Here is the minimum
configuration items to edit::

    CONFIG proxy.config.reverse_proxy.enabled INT 0
    CONFIG proxy.config.url_remap.remap_required INT 0

Consult Traffic server `documentation
<https://docs.trafficserver.apache.org/en/latest/admin/forward-proxy.en.html>`_
to know how to configure traffic server as forward proxy and its
security implications.

Client mode
-----------

If nghttpx is invoked with ``--client`` option, it operates in client
mode.  In this mode, nghttpx listens for plain, unencrypted HTTP/2 and
HTTP/1 requests and translates them to encrypted HTTP/2 requests to
the backend.  User cannot enable SSL/TLS in frontend connection.

HTTP/1 frontend connection can be upgraded to HTTP/2 using HTTP
Upgrade.  To disable SSL/TLS in backend connection, use
``--backend-no-tls`` option.

By default, the number of backend HTTP/2 connections per worker
(thread) is determined by number of ``-b`` option.  To adjust this
value, use ``--backend-http2-connections-per-worker`` option.

The backend server is supporsed to be a HTTP/2 web server (e.g.,
nghttpd).  The one use-case of this mode is utilize existing HTTP/1
clients to test HTTP/2 deployment.  Suppose that HTTP/2 web server
listens to port 80 without encryption.  Then run nghttpx as client
mode to access to that web server::

    $ nghttpx --client -f127.0.0.1,8080 -b127.0.0.1,80 --backend-no-tls

.. note::

    You may need ``-k`` option if HTTP/2 server enables SSL/TLS and
    its certificate is self-signed. But please note that it is
    insecure.

Then you can use curl to access HTTP/2 server via nghttpx::

    $ curl http://localhost:8080/

Client proxy mode
-----------------

If nghttpx is invoked with ``-p`` option, it operates in client proxy
mode.  This mode behaves like `client mode`_, but it works like
forward proxy.  So HTTP/1 request must include absolute URI in request
line.

HTTP/1 frontend connection can be upgraded to HTTP/2 using HTTP
Upgrade.  To disable SSL/TLS in backend connection, use
``--backend-no-tls`` option.

By default, the number of backend HTTP/2 connections per worker
(thread) is determined by number of ``-b`` option.  To adjust this
value, use ``--backend-http2-connections-per-worker`` option.

The backend server must be a HTTP/2 proxy.  You can use nghttpx in
`HTTP/2 proxy mode`_ as backend server.  The one use-case of this mode
is utilize existing HTTP/1 clients to test HTTP/2 connections between
2 proxies. The another use-case is use this mode to aggregate local
HTTP/1 connections to one HTTP/2 backend encrypted connection.  This
makes HTTP/1 clients which does not support secure proxy can use
secure HTTP/2 proxy via nghttpx client mode.

Suppose that HTTP/2 proxy listens to port 8443, just like we saw in
`HTTP/2 proxy mode`_.  To run nghttpx in client proxy mode to access
that server, invoke nghttpx like this::

    $ nghttpx -p -f127.0.0.1,8080 -b127.0.0.1,8443

.. note::

    You may need ``-k`` option if HTTP/2 server's certificate is
    self-signed. But please note that it is insecure.

Then you can use curl to issue HTTP request via HTTP/2 proxy::

    $ curl --http-proxy=http://localhost:8080 http://www.google.com/

You can configure web browser to use localhost:8080 as forward
proxy.

HTTP/2 bridge mode
------------------

If nghttpx is invoked with ``--http2-bridge`` option, it operates in
HTTP/2 bridge mode.  The supported protocols in frontend connections
are the same in `default mode`_.  The protocol in backend is HTTP/2
only.

With ``--frontend-no-tls`` option, SSL/TLS is turned off in frontend
connection, so the connection gets insecure.  To disable SSL/TLS in
backend connection, use ``--backend-no-tls`` option.

By default, the number of backend HTTP/2 connections per worker
(thread) is determined by number of ``-b`` option.  To adjust this
value, use ``--backend-http2-connections-per-worker`` option.

The backend server is supporsed to be a HTTP/2 web server or HTTP/2
proxy.  If backend server is HTTP/2 proxy, use
``--no-location-rewrite`` and ``--no-host-rewrite`` options to disable
rewriting location, host and :authority header field.

The use-case of this mode is aggregate the incoming connections to one
HTTP/2 connection.  One backend HTTP/2 connection is created per
worker (thread).

Disable SSL/TLS
---------------

In `default mode`_, `HTTP/2 proxy mode`_ and `HTTP/2 bridge mode`_,
frontend connections are encrypted with SSL/TLS by default.  To turn
off SSL/TLS, use ``--frontend-no-tls`` option.  If this option is
used, the private key and certificate are not required to run nghttpx.

In `client mode`_, `client proxy mode`_ and `HTTP/2 bridge mode`_,
backend connections are encrypted with SSL/TLS by default.  To turn
off SSL/TLS, use ``--backend-no-tls`` option.

Specifying additional CA certificate
------------------------------------

By default, nghttpx tries to read CA certificate from system.  But
depending on the system you use, this may fail or is not supported.
To specify CA certificate manually, use ``--cacert`` option.  The
specified file must be PEM format and can contain multiple
certificates.

By default, nghttpx validates server's certificate.  If you want to
turn off this validation, knowing this is really insecure and what you
are doing, you can use ``-k`` option to disable certificate
validation.

Read/write rate limit
---------------------

nghttpx supports transfer rate limiting on frontend connections.  You
can do rate limit per frontend connection for reading and writing
individually.

To perform rate limit for reading, use ``--read-rate`` and
``--read-burst`` options.  For writing, use ``--write-rate`` and
``--write-burst``.

Please note that rate limit is performed on top of TCP and nothing to
do with HTTP/2 flow control.

Rewriting location header field
-------------------------------

nghttpx automatically rewrites location response header field if the
following all conditions satisfy:

* URI in location header field is not absolute URI or is not https URI.
* URI in location header field includes non empty host component.
* host (without port) in URI in location header field must match the
  host appearing in :authority or host header field.

When rewrite happens, URI scheme and port are replaced with the ones
used in frontend, and host is replaced with which appears in
:authority or host request header field.  :authority header field has
precedence.  If the above conditions are not met with the host value
in :authority header field, rewrite is retried with the value in host
header field.

Hot swapping
------------

nghttpx supports hot swapping using signals.  The hot swapping in
nghttpx is multi step process.  First send USR2 signal to nghttpx
process.  It will do fork and execute new executable, using same
command-line arguments and environment variables.  At this point, both
current and new processes can accept requests.  To gracefully shutdown
current process, send QUIT signal to current nghttpx process.  When
all existing frontend connections are done, the current process will
exit.  At this point, only new nghttpx process exists and serves
incoming requests.

Re-opening log files
--------------------

When rotating log files, it is desirable to re-open log files after
log rotation daemon renamed existing log files.  To tell nghttpx to
re-open log files, send USR1 signal to nghttpx process.  It will
re-open files specified by ``--accesslog-file`` and
``--errorlog-file`` options.

Multiple backend addresses
--------------------------

nghttpx supports multiple backend addresses.  To specify them, just
use ``-b`` option repeatedly.  For example, to use backend1:8080 and
backend2:8080, use command-line like this: ``-bbackend1,8080
-bbackend2,8080``.  For HTTP/2 backend, see also
``--backend-http2-connections-per-worker`` option.
