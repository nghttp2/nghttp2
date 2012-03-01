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

if HAVE_CUNIT

check_PROGRAMS = main

OBJECTS = main.c spdylay_pq_test.c spdylay_map_test.c spdylay_queue_test.c \
	spdylay_buffer_test.c spdylay_zlib_test.c spdylay_session_test.c \
	spdylay_frame_test.c spdylay_stream_test.c spdylay_npn_test.c

HFILES = spdylay_pq_test.h spdylay_map_test.h spdylay_queue_test.h \
	spdylay_buffer_test.h spdylay_zlib_test.h spdylay_session_test.h \
	spdylay_frame_test.h spdylay_stream_test.h spdylay_npn_test.h

main_SOURCES = $(HFILES) $(OBJECTS)

main_LDADD = ${top_builddir}/lib/libspdylay.la
main_LDFLAGS = -static @CUNIT_LIBS@
AM_CFLAGS = -Wall -g -O2 -I${top_srcdir}/lib -I${top_srcdir}/lib/includes -I${top_builddir}/lib/includes \
	@CUNIT_CFLAGS@

TESTS = main end_to_end.py

endif # HAVE_CUNIT
