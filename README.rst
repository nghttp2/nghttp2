Spdylay - SPDY C Library
========================

This is an experimental implementation of Google's SPDY protocol
version 2 in C.

The current status of development is in very early stage. Not all
control frames have not been implemented yet.  But ``spdycl`` in
*examples* directory can connect to SPDY-capable server via SSL and
select spdy/2 with NPN and get a resource given in command-line.
