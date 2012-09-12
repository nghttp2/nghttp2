.. Spdylay documentation master file, created by
   sphinx-quickstart on Sun Mar 11 22:57:49 2012.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Spdylay - SPDY C Library
========================

This is an experimental implementation of Google's SPDY protocol in C.

.. hlist::
   :columns: 3

   * `Download <http://sourceforge.net/projects/spdylay/files/stable/>`_
   * `Sourceforge.net <http://sourceforge.net/projects/spdylay>`_
   * `Source <https://github.com/tatsuhiro-t/spdylay>`_

This library provides SPDY version 2 and 3 framing layer
implementation.  It does not perform any I/O operations.  When the
library needs them, it calls the callback functions provided by the
application. It also does not include any event polling mechanism, so
the application can freely choose the way of handling events. This
library code does not depend on any particular SSL library (except for
example programs which depend on OpenSSL 1.0.1 or later).

This project also develops SPDY client, server and proxy on top of
Spdylay library.

Contents:

.. toctree::
   :maxdepth: 2

   package_README
   apiref
   python

Resources
---------

* http://www.chromium.org/spdy
