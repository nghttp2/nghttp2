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
SUBDIRS = testdata

EXTRA_DIST = \
	CMakeLists.txt \
	test.example.com.pem \
	test.nghttp2.org.pem

bin_PROGRAMS =
check_PROGRAMS =
TESTS =

AM_CFLAGS = $(WARNCFLAGS)
AM_CXXFLAGS = $(WARNCXXFLAGS) $(CXX1XCXXFLAGS)
AM_CPPFLAGS = \
	-DPKGDATADIR='"$(pkgdatadir)"' \
	-DPKGLIBDIR='"$(pkglibdir)"' \
	-I$(top_srcdir)/lib/includes \
	-I$(top_builddir)/lib/includes \
	-I$(top_srcdir)/lib \
	-I$(top_srcdir)/third-party/urlparse \
	-I$(top_srcdir)/third-party/llhttp/include \
	@JEMALLOC_CFLAGS@ \
	@LIBXML2_CFLAGS@ \
	@LIBEV_CFLAGS@ \
	@LIBNGHTTP3_CFLAGS@ \
	@LIBNGTCP2_CRYPTO_WOLFSSL_CFLAGS@ \
	@LIBNGTCP2_CRYPTO_QUICTLS_CFLAGS@ \
	@LIBNGTCP2_CRYPTO_LIBRESSL_CFLAGS@ \
	@LIBNGTCP2_CRYPTO_BORINGSSL_CFLAGS@ \
	@LIBNGTCP2_CRYPTO_OSSL_CFLAGS@ \
	@LIBNGTCP2_CFLAGS@ \
	@WOLFSSL_CFLAGS@ \
	@OPENSSL_CFLAGS@ \
	@LIBCARES_CFLAGS@ \
	@JANSSON_CFLAGS@ \
	@LIBBPF_CFLAGS@ \
	@ZLIB_CFLAGS@ \
	@LIBBROTLIENC_CFLAGS@ \
	@LIBBROTLIDEC_CFLAGS@ \
	@EXTRA_DEFS@ \
	@DEFS@
AM_LDFLAGS = @LIBTOOL_LDFLAGS@

LDADD = $(top_builddir)/lib/libnghttp2v2.la \
	$(top_builddir)/third-party/liburlparse.la \
	$(top_builddir)/third-party/libllhttp.la \
	@JEMALLOC_LIBS@ \
	@LIBXML2_LIBS@ \
	@LIBEV_LIBS@ \
	@LIBNGHTTP3_LIBS@ \
	@LIBNGTCP2_CRYPTO_WOLFSSL_LIBS@ \
	@LIBNGTCP2_CRYPTO_QUICTLS_LIBS@ \
	@LIBNGTCP2_CRYPTO_LIBRESSL_LIBS@ \
	@LIBNGTCP2_CRYPTO_BORINGSSL_LIBS@ \
	@LIBNGTCP2_CRYPTO_OSSL_LIBS@ \
	@LIBNGTCP2_LIBS@ \
	@WOLFSSL_LIBS@ \
	@OPENSSL_LIBS@ \
	@LIBCARES_LIBS@ \
	@SYSTEMD_LIBS@ \
	@JANSSON_LIBS@ \
	@LIBBPF_LIBS@ \
	@ZLIB_LIBS@ \
	@LIBBROTLIENC_LIBS@ \
	@LIBBROTLIDEC_LIBS@ \
	@APPLDFLAGS@

if ENABLE_APP

bin_PROGRAMS += nghttpd

HELPER_OBJECTS = util.cc \
	http2.cc timegm.c app_helper.cc nghttp2_gzip.c network.cc
HELPER_HFILES = util.h \
	http2.h timegm.h app_helper.h nghttp2_config.h \
	nghttp2_gzip.h network.h errors.h template.h allocator.h memchunk.h \
	base64.h buffer.h

if HAVE_LIBXML2
endif # HAVE_LIBXML2

nghttpd_SOURCES = ${HELPER_OBJECTS} ${HELPER_HFILES} nghttpd.cc \
	tls.cc tls.h ssl_compat.h \
	HttpServer.cc HttpServer.h

if ENABLE_HTTP3
endif # ENABLE_HTTP3

if HAVE_MRUBY
endif # HAVE_MRUBY

if ENABLE_HTTP3
endif # ENABLE_HTTP3

if HAVE_MRUBY
endif # HAVE_MRUBY

if HAVE_NEVERBLEED
endif # HAVE_NEVERBLEED

if ENABLE_HTTP3
endif # ENABLE_HTTP3

if HAVE_MRUBY
endif # HAVE_MRUBY

if HAVE_NEVERBLEED
endif # HAVE_NEVERBLEED

endif # ENABLE_APP

if ENABLE_HPACK_TOOLS

endif # ENABLE_HPACK_TOOLS
