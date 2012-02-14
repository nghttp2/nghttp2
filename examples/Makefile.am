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

AM_CFLAGS = -Wall
AM_CPPFLAGS = -I$(srcdir)/../lib/includes -I$(builddir)/../lib/includes \
	@OPENSSL_CFLAGS@
AM_LDFLAGS = @OPENSSL_LIBS@
LDADD = $(top_builddir)/lib/libspdylay.la

bin_PROGRAMS = spdycat spdyd

HELPER_OBJECTS = uri.cc util.cc spdylay_ssl.cc
HELPER_HFILES = uri.h util.h spdylay_ssl.h

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

SPDY_SERVER_OBJECTS = SpdyServer.cc
SPDY_SERVER_HFILES = SpdyServer.h

spdycat_SOURCES = ${HELPER_OBJECTS} ${HELPER_HFILES} spdycat.cc

spdyd_SOURCES = ${HELPER_OBJECTS} ${HELPER_HFILES} \
	${EVENT_OBJECTS} ${EVENT_HFILES} \
	${SPDY_SERVER_OBJECTS} ${SPDY_SERVER_HFILES}\
	spdyd.cc
