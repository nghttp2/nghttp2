# Spdylay - SPDY Library

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

if ENABLE_SRC

AM_CFLAGS = -Wall
AM_CPPFLAGS = -Wall -I$(srcdir)/../lib/includes -I$(builddir)/../lib/includes \
	@OPENSSL_CFLAGS@ @XML_CPPFLAGS@ @LIBEVENT_OPENSSL_CFLAGS@ @DEFS@
AM_LDFLAGS = @OPENSSL_LIBS@ @XML_LIBS@ @LIBEVENT_OPENSSL_LIBS@ -pthread
LDADD = $(top_builddir)/lib/libspdylay.la

bin_PROGRAMS = spdycat spdyd

if HAVE_LIBEVENT_OPENSSL
bin_PROGRAMS += shrpx
endif # HAVE_LIBEVENT_OPENSSL

HELPER_OBJECTS = uri.cc util.cc spdylay_ssl.cc
HELPER_HFILES = uri.h util.h spdylay_ssl.h spdylay_config.h

EVENT_OBJECTS =
EVENT_HFILES = EventPoll.h EventPollEvent.h

if HAVE_EPOLL
EVENT_OBJECTS += EventPoll_epoll.cc
EVENT_HFILES += EventPoll_epoll.h
endif # HAVE_EPOLL

if HAVE_KQUEUE
EVENT_OBJECTS += EventPoll_kqueue.cc
EVENT_HFILES += EventPoll_kqueue.h
endif # HAVE_KQUEUE

HTML_PARSER_OBJECTS =
HTML_PARSER_HFILES = HtmlParser.h

if HAVE_LIBXML2
HTML_PARSER_OBJECTS += HtmlParser.cc
endif # HAVE_LIBXML2

SPDY_SERVER_OBJECTS = SpdyServer.cc
SPDY_SERVER_HFILES = SpdyServer.h

spdycat_SOURCES = ${HELPER_OBJECTS} ${HELPER_HFILES} spdycat.cc \
	${HTML_PARSER_OBJECTS} ${HTML_PARSER_HFILES}

spdyd_SOURCES = ${HELPER_OBJECTS} ${HELPER_HFILES} \
	${EVENT_OBJECTS} ${EVENT_HFILES} \
	${SPDY_SERVER_OBJECTS} ${SPDY_SERVER_HFILES} \
	spdyd.cc

if HAVE_LIBEVENT_OPENSSL
shrpx_SOURCES = ${HELPER_OBJECTS} ${HELPER_HFILES} \
	shrpx_config.cc shrpx_config.h \
	shrpx.cc shrpx.h \
	shrpx_error.h \
	shrpx_listen_handler.cc shrpx_listen_handler.h \
	shrpx_client_handler.cc shrpx_client_handler.h \
	shrpx_upstream.h \
	shrpx_spdy_upstream.cc shrpx_spdy_upstream.h \
	shrpx_https_upstream.cc shrpx_https_upstream.h \
	shrpx_downstream_queue.cc shrpx_downstream_queue.h \
	shrpx_downstream.cc shrpx_downstream.h \
	shrpx_downstream_connection.cc shrpx_downstream_connection.h \
	shrpx_log.cc shrpx_log.h \
	shrpx_http.cc shrpx_http.h \
	shrpx_io_control.cc shrpx_io_control.h \
	shrpx_ssl.cc shrpx_ssl.h \
	shrpx_thread_event_receiver.cc shrpx_thread_event_receiver.h \
	shrpx_worker.cc shrpx_worker.h \
	shrpx_accesslog.cc shrpx_accesslog.h\
	http-parser/http_parser.c http-parser/http_parser.h
endif # HAVE_LIBEVENT_OPENSSL

endif # ENABLE_SRC
