# nghttp2 - HTTP/2 C Library

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
SUBDIRS = includes

EXTRA_DIST = CMakeLists.txt config.cmake.in

AM_CFLAGS = $(WARNCFLAGS) $(EXTRACFLAG)
AM_CPPFLAGS = -I$(srcdir)/includes -I$(builddir)/includes -DBUILDING_NGHTTP2 \
	@DEFS@
AM_LDFLAGS = @LIBTOOL_LDFLAGS@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnghttp2v2.pc
DISTCLEANFILES = $(pkgconfig_DATA)

lib_LTLIBRARIES = libnghttp2v2.la

SOURCES = \
	nghttp2_buf.c nghttp2_buf.h \
	nghttp2_conn.c nghttp2_conn.h \
	nghttp2_conv.c nghttp2_conv.h \
	nghttp2_err.c nghttp2_err.h \
	nghttp2_fmt.c nghttp2_fmt.h \
	nghttp2_frame.c nghttp2_frame.h \
	nghttp2_frame_reader.c nghttp2_frame_reader.h \
	nghttp2_hpack.c nghttp2_hpack.h \
	nghttp2_hpack_huffman.c nghttp2_hpack_huffman.h \
	nghttp2_hpack_huffman_data.c \
	nghttp2_http.c nghttp2_http.h \
	nghttp2_http_writer.c nghttp2_http_writer.h \
	nghttp2_log.c nghttp2_log.h \
	nghttp2_macro.h \
	nghttp2_map.c nghttp2_map.h \
	nghttp2_mem.c nghttp2_mem.h \
	nghttp2_net.h \
	nghttp2_pq.c nghttp2_pq.h \
	nghttp2_ratelim.c nghttp2_ratelim.h \
	nghttp2_rcbuf.c nghttp2_rcbuf.h \
	nghttp2_ringbuf.c nghttp2_ringbuf.h \
	nghttp2_settings.c nghttp2_settings.h \
	nghttp2_str.c nghttp2_str.h \
	nghttp2_stream.c nghttp2_stream.h \
	nghttp2_unreachable.c nghttp2_unreachable.h \
	nghttp2_vec.c nghttp2_vec.h \
	sfparse/sfparse.c sfparse/sfparse.h

libnghttp2v2_la_SOURCES = $(SOURCES)
libnghttp2v2_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
