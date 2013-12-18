# nghttp2 - HTTP/2.0 C Library

# Copyright (c) 2013 Tatsuhiro Tsujikawa

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

EXTRA_DIST = README.rst cnghttp2.pxd nghttp2.pyx setup.py

PYSETUP_INCLUDE_DIRS=$(top_srcdir)/lib/includes:$(top_srcdir)/lib
PYSETUP_LIBDIRS=$(top_builddir)/lib/.libs

.PHONY: help build_ext

help:
	@echo "Please use \`make <target>\` where <target> is one of"
	@echo "  build_ext  to build Python @PYTHON_VERSION@ nghttp2 extension"

nghttp2.c: nghttp2.pyx cnghttp2.pxd
	$(CYTHON) nghttp2.pyx

build_ext: nghttp2.c
	$(PYTHON) setup.py build_ext --include-dirs=$(PYSETUP_INCLUDE_DIRS) \
	    --library-dirs=$(PYSETUP_LIBDIRS)
