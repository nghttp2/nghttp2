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

bin_PROGRAMS =
check_PROGRAMS =
TESTS =

if ENABLE_SRC

AM_CPPFLAGS = -Wall -I$(srcdir)/../lib/includes -I$(builddir)/../lib/includes \
	@LIBSPDYLAY_CFLAGS@ \
	@XML_CPPFLAGS@	\
	@LIBEVENT_OPENSSL_CFLAGS@ \
	@OPENSSL_CFLAGS@ \
	@DEFS@
AM_LDFLAGS = \
	@LIBSPDYLAY_LIBS@ \
	@XML_LIBS@ \
	@LIBEVENT_OPENSSL_LIBS@ \
	@OPENSSL_LIBS@ \
	@SRC_LIBS@

LDADD = $(top_builddir)/lib/libnghttp2.la

bin_PROGRAMS += nghttp nghttpd nghttpx

HELPER_OBJECTS = util.cc timegm.c app_helper.cc
HELPER_HFILES = util.h timegm.h app_helper.h nghttp2_config.h

HTML_PARSER_OBJECTS =
HTML_PARSER_HFILES = HtmlParser.h

if HAVE_LIBXML2
HTML_PARSER_OBJECTS += HtmlParser.cc
endif # HAVE_LIBXML2

nghttp_SOURCES = ${HELPER_OBJECTS} ${HELPER_HFILES} nghttp.cc \
	${HTML_PARSER_OBJECTS} ${HTML_PARSER_HFILES} \
	http-parser/http_parser.c http-parser/http_parser.h

nghttpd_SOURCES = ${HELPER_OBJECTS} ${HELPER_HFILES} nghttpd.cc \
	HttpServer.cc HttpServer.h

NGHTTPX_SRCS = \
	util.cc util.h timegm.c timegm.h base64.h \
	shrpx_config.cc shrpx_config.h \
	shrpx_error.h \
	shrpx_listen_handler.cc shrpx_listen_handler.h \
	shrpx_client_handler.cc shrpx_client_handler.h \
	shrpx_upstream.h \
	shrpx_http2_upstream.cc shrpx_http2_upstream.h \
	shrpx_https_upstream.cc shrpx_https_upstream.h \
	shrpx_downstream_queue.cc shrpx_downstream_queue.h \
	shrpx_downstream.cc shrpx_downstream.h \
	shrpx_downstream_connection.cc shrpx_downstream_connection.h \
	shrpx_http_downstream_connection.cc shrpx_http_downstream_connection.h \
	shrpx_spdy_downstream_connection.cc shrpx_spdy_downstream_connection.h \
	shrpx_spdy_session.cc shrpx_spdy_session.h \
	shrpx_log.cc shrpx_log.h \
	shrpx_http.cc shrpx_http.h \
	shrpx_io_control.cc shrpx_io_control.h \
	shrpx_ssl.cc shrpx_ssl.h \
	shrpx_thread_event_receiver.cc shrpx_thread_event_receiver.h \
	shrpx_worker.cc shrpx_worker.h \
	shrpx_accesslog.cc shrpx_accesslog.h\
	http-parser/http_parser.c http-parser/http_parser.h

if HAVE_SPDYLAY
NGHTTPX_SRCS += shrpx_spdy_upstream.cc shrpx_spdy_upstream.h
endif # HAVE_SPDYLAY

nghttpx_SOURCES = ${NGHTTPX_SRCS} shrpx.cc shrpx.h

# if HAVE_CUNIT
# check_PROGRAMS += shrpx-unittest
# shrpx_unittest_SOURCES = shrpx-unittest.cc \
# 	shrpx_ssl_test.cc shrpx_ssl_test.h\
# 	${SHRPX_SRCS}
# shrpx_unittest_CPPFLAGS = ${AM_CPPFLAGS}\
# 	 -DNGHTTP2_TESTS_DIR=\"$(top_srcdir)/tests\"
# shrpx_unittest_LDFLAGS = -static @OPENSSL_LIBS@ @LIBEVENT_OPENSSL_LIBS@\
# 	@SRC_LIBS@ @CUNIT_LIBS@ @TESTS_LIBS@
# TESTS += shrpx-unittest
# endif # HAVE_CUNIT

endif # ENABLE_SRC
