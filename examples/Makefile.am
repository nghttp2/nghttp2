# nghttp2 - HTTP/2.0 C Library

# Copyright (c) 2012 Tatsuhiro Tsujikawa

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

if ENABLE_EXAMPLES

AM_CFLAGS = -Wall
AM_CPPFLAGS = \
	-Wall \
	-I$(srcdir)/../lib/includes \
	-I$(builddir)/../lib/includes \
	-I$(top_srcdir)/src \
	@LIBEVENT_OPENSSL_CFLAGS@ \
	@OPENSSL_CFLAGS@ \
	@DEFS@
AM_LDFLAGS = \
	@LIBEVENT_OPENSSL_LIBS@ \
	@OPENSSL_LIBS@
LDADD = $(top_builddir)/lib/libnghttp2.la

noinst_PROGRAMS = client libevent-client libevent-server
client_SOURCES = client.c

libevent_client_SOURCES = \
	libevent-client.c \
	$(top_srcdir)/src/http-parser/http_parser.c

libevent_server_SOURCES = libevent-server.c

endif # ENABLE_EXAMPLES

EXTRA_DIST = README.rst
