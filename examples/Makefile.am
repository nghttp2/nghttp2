# nghttp2 - HTTP/2 C Library

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

AM_CPPFLAGS = \
	-Wall \
	-I$(top_srcdir)/lib/includes \
	-I$(top_builddir)/lib/includes \
	-I$(top_srcdir)/src/includes \
	-I$(top_srcdir)/third-party \
	@LIBEVENT_OPENSSL_CFLAGS@ \
	@OPENSSL_CFLAGS@ \
	@DEFS@
AM_LDFLAGS = \
	@LIBEVENT_OPENSSL_LIBS@ \
	@OPENSSL_LIBS@
LDADD = \
	$(top_builddir)/lib/libnghttp2.la \
	$(top_builddir)/third-party/libhttp-parser.la

noinst_PROGRAMS = client libevent-client libevent-server deflate

client_SOURCES = client.c

libevent_client_SOURCES = libevent-client.c

libevent_server_SOURCES = libevent-server.c

deflate_SOURCES = deflate.c

noinst_PROGRAMS += tiny-nghttpd

tiny_nghttpd_SOURCES = tiny-nghttpd.c

if ENABLE_ASIO_LIB

noinst_PROGRAMS += asio-sv asio-sv2

ASIOCPPFLAGS = ${BOOST_CPPFLAGS} ${AM_CPPFLAGS}
ASIOLDFLAGS = @JEMALLOC_LIBS@
ASIOLDADD = $(top_builddir)/src/libnghttp2_asio.la

asio_sv_SOURCES = asio-sv.cc
asio_sv_CPPFLAGS = ${ASIOCPPFLAGS}
asio_sv_LDFLAGS = ${ASIOLDFLAGS}
asio_sv_LDADD = ${ASIOLDADD}

asio_sv2_SOURCES = asio-sv2.cc
asio_sv2_CPPFLAGS = ${ASIOCPPFLAGS}
asio_sv2_LDFLAGS = ${ASIOLDFLAGS}
asio_sv2_LDADD = ${ASIOLDADD}

endif # ENABLE_ASIO_LIB

endif # ENABLE_EXAMPLES
