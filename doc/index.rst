.. Spdylay documentation master file, created by
   sphinx-quickstart on Sun Mar 11 22:57:49 2012.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Spdylay's documentation!
===================================

This is an experimental implementation of Google's SPDY protocol
version 2 and 3 in C.

This library provides SPDY framing layer implementation.  It does not
perform any I/O operations.  When the library needs them, it calls the
callback functions provided by the application. It also does not
include any event polling mechanism, so the application can freely
choose the way of handling events. This library code does not depend
on any particular SSL library (except for example programs which
depend on OpenSSL 1.0.1 or later).

Contents:

.. toctree::
   :maxdepth: 2

   apiref
