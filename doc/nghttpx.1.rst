
nghttpx(1)
==========

SYNOPSIS
--------

**nghttpx** [OPTIONS]... [<PRIVATE_KEY> <CERT>]

DESCRIPTION
-----------

A reverse proxy for HTTP/2, HTTP/1 and SPDY.

.. describe:: <PRIVATE_KEY>

    
    Set path  to server's private key.   Required unless :option:`-p`\,
    :option:`--client` or :option:`\--frontend-no-tls` are given.

.. describe:: <CERT>

    Set path  to server's certificate.  Required  unless :option:`-p`\,
    :option:`--client` or :option:`\--frontend-no-tls` are given.


OPTIONS:
--------

The options are categorized into several groups.

Connections:
~~~~~~~~~~~~

.. option:: -b, --backend=<HOST,PORT>

    Set backend host and port.  For HTTP/1 backend, multiple
    backend addresses are accepted by repeating this option.
    HTTP/2  backend   does  not  support   multiple  backend
    addresses  and the  first occurrence  of this  option is
    used.

    Default: ``127.0.0.1,80``

.. option:: -f, --frontend=<HOST,PORT>

    Set  frontend  host and  port.   If  <HOST> is  '\*',  it
    assumes all addresses including both IPv4 and IPv6.

    Default: ``*,3000``

.. option:: --backlog=<N>

    Set listen backlog size.

    Default: ``512``

.. option:: --backend-ipv4

    Resolve backend hostname to IPv4 address only.

.. option:: --backend-ipv6

    Resolve backend hostname to IPv6 address only.

.. option:: --backend-http-proxy-uri=<URI>

    Specify      proxy       URI      in       the      form
    http://[<USER>:<PASS>@]<PROXY>:<PORT>.    If   a   proxy
    requires  authentication,  specify  <USER>  and  <PASS>.
    Note that  they must be properly  percent-encoded.  This
    proxy  is used  when the  backend connection  is HTTP/2.
    First,  make  a CONNECT  request  to  the proxy  and  it
    connects  to the  backend  on behalf  of nghttpx.   This
    forms  tunnel.   After  that, nghttpx  performs  SSL/TLS
    handshake with  the downstream through the  tunnel.  The
    timeouts when connecting and  making CONNECT request can
    be     specified    by     :option:`--backend-read-timeout`    and
    :option:`--backend-write-timeout` options.


Performance:
~~~~~~~~~~~~

.. option:: -n, --workers=<N>

    Set the number of worker threads.

    Default: ``1``

.. option:: --read-rate=<SIZE>

    Set maximum  average read  rate on  frontend connection.
    Setting 0 to this option means read rate is unlimited.

    Default: ``0``

.. option:: --read-burst=<SIZE>

    Set  maximum read  burst  size  on frontend  connection.
    Setting  0  to this  option  means  read burst  size  is
    unlimited.

    Default: ``0``

.. option:: --write-rate=<SIZE>

    Set maximum  average write rate on  frontend connection.
    Setting 0 to this option means write rate is unlimited.

    Default: ``0``

.. option:: --write-burst=<SIZE>

    Set  maximum write  burst size  on frontend  connection.
    Setting  0 to  this  option means  write  burst size  is
    unlimited.

    Default: ``0``

.. option:: --worker-read-rate=<SIZE>

    Set maximum average read rate on frontend connection per
    worker.  Setting  0 to  this option  means read  rate is
    unlimited.  Not implemented yet.

    Default: ``0``

.. option:: --worker-read-burst=<SIZE>

    Set maximum  read burst size on  frontend connection per
    worker.  Setting 0 to this  option means read burst size
    is unlimited.  Not implemented yet.

    Default: ``0``

.. option:: --worker-write-rate=<SIZE>

    Set maximum  average write  rate on  frontend connection
    per worker.  Setting  0 to this option  means write rate
    is unlimited.  Not implemented yet.

    Default: ``0``

.. option:: --worker-write-burst=<SIZE>

    Set maximum write burst  size on frontend connection per
    worker.  Setting 0 to this option means write burst size
    is unlimited.  Not implemented yet.

    Default: ``0``

.. option:: --worker-frontend-connections=<N>

    Set maximum number  of simultaneous connections frontend
    accepts.  Setting 0 means unlimited.

    Default: ``0``

.. option:: --backend-http1-connections-per-host=<N>

    Set   maximum  number   of  backend   concurrent  HTTP/1
    connections per host.  This option is meaningful when :option:`-s`
    option is used.  To limit  the number of connections per
    frontend        for       default        mode,       use
    :option:`--backend-http1-connections-per-frontend`\.

    Default: ``8``

.. option:: --backend-http1-connections-per-frontend=<N>

    Set   maximum  number   of  backend   concurrent  HTTP/1
    connections per frontend.  This  option is only used for
    default mode.   0 means unlimited.  To  limit the number
    of connections  per host for  HTTP/2 or SPDY  proxy mode
    (-s option), use :option:`--backend-http1-connections-per-host`\.

    Default: ``0``

.. option:: --rlimit-nofile=<N>

    Set maximum number of open files (RLIMIT_NOFILE) to <N>.
    If 0 is given, nghttpx does not set the limit.

    Default: ``0``

.. option:: --backend-request-buffer=<SIZE>

    Set buffer size used to store backend request.

    Default: ``16K``

.. option:: --backend-response-buffer=<SIZE>

    Set buffer size used to store backend response.

    Default: ``16K``


Timeout:
~~~~~~~~

.. option:: --frontend-http2-read-timeout=<DURATION>

    Specify  read  timeout  for  HTTP/2  and  SPDY  frontend
    connection.

    Default: ``180s``

.. option:: --frontend-read-timeout=<DURATION>

    Specify read timeout for HTTP/1.1 frontend connection.

    Default: ``180s``

.. option:: --frontend-write-timeout=<DURATION>

    Specify write timeout for all frontend connections.

    Default: ``30s``

.. option:: --stream-read-timeout=<DURATION>

    Specify  read timeout  for HTTP/2  and SPDY  streams.  0
    means no timeout.

    Default: ``0``

.. option:: --stream-write-timeout=<DURATION>

    Specify write  timeout for  HTTP/2 and SPDY  streams.  0
    means no timeout.

    Default: ``0``

.. option:: --backend-read-timeout=<DURATION>

    Specify read timeout for backend connection.

    Default: ``180s``

.. option:: --backend-write-timeout=<DURATION>

    Specify write timeout for backend connection.

    Default: ``30s``

.. option:: --backend-keep-alive-timeout=<DURATION>

    Specify keep-alive timeout for backend connection.

    Default: ``2s``

.. option:: --listener-disable-timeout=<DURATION>

    After accepting  connection failed,  connection listener
    is disabled  for a given  amount of time.   Specifying 0
    disables this feature.

    Default: ``0``


SSL/TLS:
~~~~~~~~

.. option:: --ciphers=<SUITE>

    Set allowed  cipher list.  The  format of the  string is
    described in OpenSSL ciphers(1).

.. option:: -k, --insecure

    Don't  verify   backend  server's  certificate   if  :option:`-p`\,
    :option:`--client`    or    :option:`\--http2-bridge`     are    given    and
    :option:`--backend-no-tls` is not given.

.. option:: --cacert=<PATH>

    Set path to trusted CA  certificate file if :option:`-p`\, :option:`--client`
    or :option:`--http2-bridge` are given  and :option:`\--backend-no-tls` is not
    given.  The file must be  in PEM format.  It can contain
    multiple  certificates.    If  the  linked   OpenSSL  is
    configured to  load system  wide certificates,  they are
    loaded at startup regardless of this option.

.. option:: --private-key-passwd-file=<PATH>

    Path  to file  that contains  password for  the server's
    private key.   If none is  given and the private  key is
    password protected it'll be requested interactively.

.. option:: --subcert=<KEYPATH>:<CERTPATH>

    Specify  additional certificate  and  private key  file.
    nghttpx will  choose certificates based on  the hostname
    indicated  by  client  using TLS  SNI  extension.   This
    option can be used multiple times.

.. option:: --backend-tls-sni-field=<HOST>

    Explicitly  set the  content of  the TLS  SNI extension.
    This will default to the backend HOST name.

.. option:: --dh-param-file=<PATH>

    Path to file that contains  DH parameters in PEM format.
    Without  this   option,  DHE   cipher  suites   are  not
    available.

.. option:: --npn-list=<LIST>

    Comma delimited list of  ALPN protocol identifier sorted
    in the  order of preference.  That  means most desirable
    protocol comes  first.  This  is used  in both  ALPN and
    NPN.  The parameter must be  delimited by a single comma
    only  and any  white spaces  are  treated as  a part  of
    protocol string.

    Default: ``h2-16,h2-14,spdy/3.1,http/1.1``

.. option:: --verify-client

    Require and verify client certificate.

.. option:: --verify-client-cacert=<PATH>

    Path  to file  that contains  CA certificates  to verify
    client certificate.  The file must be in PEM format.  It
    can contain multiple certificates.

.. option:: --client-private-key-file=<PATH>

    Path to  file that contains  client private key  used in
    backend client authentication.

.. option:: --client-cert-file=<PATH>

    Path to  file that  contains client certificate  used in
    backend client authentication.

.. option:: --tls-proto-list=<LIST>

    Comma delimited list of  SSL/TLS protocol to be enabled.
    The following protocols  are available: TLSv1.2, TLSv1.1
    and   TLSv1.0.    The   name   matching   is   done   in
    case-insensitive   manner.    The  parameter   must   be
    delimited by  a single comma  only and any  white spaces
    are treated as a part of protocol string.

    Default: ``TLSv1.2,TLSv1.1``

.. option:: --tls-ticket-key-file=<PATH>

    Path  to file  that  contains 48  bytes  random data  to
    construct TLS  session ticket parameters.   This options
    can  be  used  repeatedly  to  specify  multiple  ticket
    parameters.  If several files  are given, only the first
    key is used to encrypt  TLS session tickets.  Other keys
    are accepted  but server  will issue new  session ticket
    with  first  key.   This allows  session  key  rotation.
    Please   note  that   key   rotation   does  not   occur
    automatically.   User should  rearrange files  or change
    options  values  and  restart  nghttpx  gracefully.   If
    opening or reading given file fails, all loaded keys are
    discarded and it is treated as if none of this option is
    given.  If this option is not given or an error occurred
    while  opening  or  reading  a file,  key  is  generated
    automatically and  renewed every 12hrs.  At  most 2 keys
    are stored in memory.

.. option:: --tls-ctx-per-worker

    Create OpenSSL's SSL_CTX per worker, so that no internal
    locking is required.  This  may improve scalability with
    multi  threaded   configuration.   If  this   option  is
    enabled, session ID is  no longer shared accross SSL_CTX
    objects, which means session  ID generated by one worker
    is not acceptable by another worker.  On the other hand,
    session ticket key is shared across all worker threads.


HTTP/2 and SPDY:
~~~~~~~~~~~~~~~~

.. option:: -c, --http2-max-concurrent-streams=<N>

    Set the maximum number of  the concurrent streams in one
    HTTP/2 and SPDY session.

    Default: ``100``

.. option:: --frontend-http2-window-bits=<N>

    Sets the  per-stream initial window size  of HTTP/2 SPDY
    frontend connection.  For HTTP/2,  the size is 2\*\*<N>-1.
    For SPDY, the size is 2\*\*<N>.

    Default: ``16``

.. option:: --frontend-http2-connection-window-bits=<N>

    Sets the  per-connection window size of  HTTP/2 and SPDY
    frontend   connection.    For   HTTP/2,  the   size   is
    2**<N>-1. For SPDY, the size is 2\*\*<N>.

    Default: ``16``

.. option:: --frontend-no-tls

    Disable SSL/TLS on frontend connections.

.. option:: --backend-http2-window-bits=<N>

    Sets  the   initial  window   size  of   HTTP/2  backend
    connection to 2\*\*<N>-1.

    Default: ``16``

.. option:: --backend-http2-connection-window-bits=<N>

    Sets the  per-connection window  size of  HTTP/2 backend
    connection to 2\*\*<N>-1.

    Default: ``16``

.. option:: --backend-no-tls

    Disable SSL/TLS on backend connections.

.. option:: --http2-no-cookie-crumbling

    Don't crumble cookie header field.

.. option:: --padding=<N>

    Add  at most  <N> bytes  to  a HTTP/2  frame payload  as
    padding.  Specify 0 to  disable padding.  This option is
    meant for debugging purpose  and not intended to enhance
    protocol security.


Mode:
~~~~~

.. describe:: (default mode)

    
    Accept  HTTP/2,  SPDY  and HTTP/1.1  over  SSL/TLS.   If
    :option:`--frontend-no-tls` is  used, accept HTTP/2  and HTTP/1.1.
    The  incoming HTTP/1.1  connection  can  be upgraded  to
    HTTP/2  through  HTTP  Upgrade.   The  protocol  to  the
    backend is HTTP/1.1.

.. option:: -s, --http2-proxy

    Like default mode, but enable secure proxy mode.

.. option:: --http2-bridge

    Like default  mode, but communicate with  the backend in
    HTTP/2 over SSL/TLS.  Thus  the incoming all connections
    are converted  to HTTP/2  connection and relayed  to the
    backend.  See :option:`--backend-http-proxy-uri` option if you are
    behind  the proxy  and want  to connect  to the  outside
    HTTP/2 proxy.

.. option:: --client

    Accept  HTTP/2   and  HTTP/1.1  without   SSL/TLS.   The
    incoming HTTP/1.1  connection can be upgraded  to HTTP/2
    connection through  HTTP Upgrade.   The protocol  to the
    backend is HTTP/2.   To use nghttpx as  a forward proxy,
    use :option:`-p` option instead.

.. option:: -p, --client-proxy

    Like :option:`--client`  option, but it also  requires the request
    path from frontend must be an absolute URI, suitable for
    use as a forward proxy.


Logging:
~~~~~~~~

.. option:: -L, --log-level=<LEVEL>

    Set the severity  level of log output.   <LEVEL> must be
    one of INFO, NOTICE, WARN, ERROR and FATAL.

    Default: ``NOTICE``

.. option:: --accesslog-file=<PATH>

    Set path to write access log.  To reopen file, send USR1
    signal to nghttpx.

.. option:: --accesslog-syslog

    Send  access log  to syslog.   If this  option is  used,
    :option:`--accesslog-file` option is ignored.

.. option:: --accesslog-format=<FORMAT>

    Specify  format  string  for access  log.   The  default
    format is combined format.   The following variables are
    available:

    * $remote_addr: client IP address.
    * $time_local: local time in Common Log format.
    * $time_iso8601: local time in ISO 8601 format.
    * $request: HTTP request line.
    * $status: HTTP response status code.
    * $body_bytes_sent: the  number of bytes sent  to client
      as response body.
    * $http_<VAR>: value of HTTP  request header <VAR> where
      '_' in <VAR> is replaced with '-'.
    * $remote_port: client  port.
    * $server_port: server port.
    * $request_time: request processing time in seconds with
      milliseconds resolution.
    * $pid: PID of the running process.
    * $alpn: ALPN identifier of the protocol which generates
      the response.   For HTTP/1,  ALPN is  always http/1.1,
      regardless of minor version.


    Default: ``$remote_addr - - [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"``

.. option:: --errorlog-file=<PATH>

    Set path to write error  log.  To reopen file, send USR1
    signal to nghttpx.

    Default: ``/dev/stderr``

.. option:: --errorlog-syslog

    Send  error log  to  syslog.  If  this  option is  used,
    :option:`--errorlog-file` option is ignored.

.. option:: --syslog-facility=<FACILITY>

    Set syslog facility to <FACILITY>.

    Default: ``daemon``


HTTP:
~~~~~

.. option:: --add-x-forwarded-for

    Append  X-Forwarded-For header  field to  the downstream
    request.

.. option:: --strip-incoming-x-forwarded-for

    Strip X-Forwarded-For  header field from  inbound client
    requests.

.. option:: --no-via

    Don't append to  Via header field.  If  Via header field
    is received, it is left unaltered.

.. option:: --no-location-rewrite

    Don't rewrite  location header field  on :option:`--http2-bridge`\,
    :option:`--client`  and  default   mode.   For  :option:`\--http2-proxy`  and
    :option:`--client-proxy` mode,  location header field will  not be
    altered regardless of this option.

.. option:: --altsvc=<PROTOID,PORT[,HOST,[ORIGIN]]>

    Specify   protocol  ID,   port,  host   and  origin   of
    alternative service.  <HOST>  and <ORIGIN> are optional.
    They are  advertised in  alt-svc header field  or HTTP/2
    ALTSVC frame.  This option can be used multiple times to
    specify   multiple   alternative   services.    Example:
    :option:`--altsvc`\=h2,443

.. option:: --add-response-header=<HEADER>

    Specify  additional  header  field to  add  to  response
    header set.   This option just appends  header field and
    won't replace anything already  set.  This option can be
    used several  times to  specify multiple  header fields.
    Example: :option:`--add-response-header`\="foo: bar"


Debug:
~~~~~~

.. option:: --frontend-http2-dump-request-header=<PATH>

    Dumps request headers received by HTTP/2 frontend to the
    file denoted  in <PATH>.  The  output is done  in HTTP/1
    header field format and each header block is followed by
    an empty line.  This option  is not thread safe and MUST
    NOT be used with option :option:`-n`\<N>, where <N> >= 2.

.. option:: --frontend-http2-dump-response-header=<PATH>

    Dumps response headers sent  from HTTP/2 frontend to the
    file denoted  in <PATH>.  The  output is done  in HTTP/1
    header field format and each header block is followed by
    an empty line.  This option  is not thread safe and MUST
    NOT be used with option :option:`-n`\<N>, where <N> >= 2.

.. option:: -o, --frontend-frame-debug

    Print HTTP/2 frames in  frontend to stderr.  This option
    is  not thread  safe and  MUST NOT  be used  with option
    :option:`-n`\=N, where N >= 2.


Process:
~~~~~~~~

.. option:: -D, --daemon

    Run in a background.  If :option:`-D` is used, the current working
    directory is changed to '*/*'.

.. option:: --pid-file=<PATH>

    Set path to save PID of this program.

.. option:: --user=<USER>

    Run this program as <USER>.   This option is intended to
    be used to drop root privileges.


Misc:
~~~~~

.. option:: --conf=<PATH>

    Load configuration from <PATH>.

    Default: ``/etc/nghttpx/nghttpx.conf``

.. option:: -v, --version

    Print version and exit.

.. option:: -h, --help

    Print this help and exit.


The <SIZE> argument is an integer and an optional unit (e.g., 10K is
10 * 1024).  Units are K, M and G (powers of 1024).

The <DURATION> argument is an integer and an optional unit (e.g., 1s
is 1 second and 500ms is 500  milliseconds).  Units are s or ms.  If
a unit is omitted, a second is used as unit.

FILES
-----

*/etc/nghttpx/nghttpx.conf*
  The default configuration file path nghttpx searches at startup.
  The configuration file path can be changed using :option:`--conf`
  option.

  Those lines which are staring ``#`` are treated as comment.

  The option name in the configuration file is the long command-line
  option name with leading ``--`` stripped (e.g., ``frontend``).  Put
  ``=`` between option name and value.  Don't put extra leading or
  trailing spaces.

  The options which do not take argument in the command-line *take*
  argument in the configuration file.  Specify ``yes`` as an argument
  (e.g., ``http2-proxy=yes``).  If other string is given, it is
  ignored.

  To specify private key and certificate file which are given as
  positional arguments in commnad-line, use ``private-key-file`` and
  ``certificate-file``.

  :option:`--conf` option cannot be used in the configuration file and
  will be ignored if specified.

SIGNALS
-------

SIGQUIT
  Shutdown gracefully.  First accept pending connections and stop
  accepting connection.  After all connections are handled, nghttpx
  exits.

SIGUSR1
  Reopen log files.

SIGUSR2
  Fork and execute nghttpx.  It will execute the binary in the same
  path with same command-line arguments and environment variables.
  After new process comes up, sending SIGQUIT to the original process
  to perform hot swapping.

SEE ALSO
--------

:manpage:`nghttp(1)`, :manpage:`nghttpd(1)`, :manpage:`h2load(1)`
