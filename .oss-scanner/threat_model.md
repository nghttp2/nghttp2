# Threat model

## What this project does and where untrusted input enters

This is RFC 7540 / RFC 9113 HTTP/2 implementation.  It also implements
RFC 7541 HPACK, the HTTP header compression.

It reads HTTP/2 traffic that is usually coming from public Internet
which is totally untrusted.

## Components that matter most / least

The primary object is nghttp2_session object that is created per
HTTP/2 connection.  Both read and write matter, but read should be
more important because it reads untrusted inputs.  nghttp2 itself does
not do any I/O (aka sans-I/O).  Instead, it reads and writes pure byte
string that are read or written into TLS or TCP byte stream.

- Reading byte stream from TLS/TCP: Parse HTTP/2 frame, process it and
  call the registered callbacks.
- Writing byte stream: The library encodes HTTP/2 frames.  The
  application is responsible to send them.
- Header compression/decompression: HEADERS frame carries the
  compressed header block.  When received, HPACK decoder decompresses
  it.  On transmission, the passed HTTP fields are compressed by HPACK
  encoder, and are sent as a payload of HEADERS.
- Flow control: HTTP/2 has its own flow control in 2 ways:
  stream-level and connection-level.  Both have the default
  value 65535.  SETTINGS frame can alter this setting for stream-level
  flow control window.  Upon receiving SETTINGS ACK, receiving side of
  flow control window of all streams is updated by the value of
  SETTINGS_INITIAL_WINDOW_SIZE sent by the local endpoint.  This
  update is quite complicated.  If the window size is reduced, the
  flow control credit may become negative.

## How to exercise it

The tests directory contains unit tests.  The src directory contains
the applications using libnghttp2:

- nghttp: HTTP/2 client
- nghttpd: HTTP/2 server
- nghttpx: HTTP/2 proxy
- h2load: HTTP/2 benchmark tool

lib/includes/nghttp2/nghttp2.h contains the public API with
documentation.

## How you rate severity

Any buffer overflow, use-after-free, or double free is high+ at a
minimum.  If the overflow is controlled and may lead to RCE then it
should be critical.  All DoS is high.

## Anything to leave alone

Do not report anything about test code that is under tests directory.
Do not report anything about the source code under third-party
directory.
