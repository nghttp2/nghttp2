# nghttp2

# Copyright (c) 2026 nghttp2 contributors

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
check_PROGRAMS = main

EXTRA_DIST = CMakeLists.txt munit/COPYING

SOURCES = \
	main.c \
	munit/munit.c munit/munit.h \
	nghttp2_conn_test.c nghttp2_conn_test.h \
	nghttp2_frame_test.c nghttp2_frame_test.h \
	nghttp2_hpack_test.c nghttp2_hpack_test.h \
	nghttp2_log_test.c nghttp2_log_test.h \
	nghttp2_test_helper.c nghttp2_test_helper.h

main_SOURCES = $(SOURCES)

# With static lib disabled and symbol hiding enabled, we have to link
# object files directly because the tests use symbols not included in
# public API.
if ENABLE_SHARED
main_LDADD = \
	${top_builddir}/lib/.libs/*.o \
	${top_builddir}/lib/sfparse/.libs/*.o
else
main_LDADD = ${top_builddir}/lib/.libs/libnghttp2v2.la
endif
main_LDFLAGS = -static

AM_CFLAGS = $(WARNCFLAGS) \
	-I${top_srcdir}/lib \
	-I${top_srcdir}/lib/includes \
	-I${top_srcdir}/tests/munit \
	-I${top_builddir}/lib/includes \
	-DBUILDING_NGHTTP2 \
	@DEFS@
AM_LDFLAGS = -no-install

TESTS = main
