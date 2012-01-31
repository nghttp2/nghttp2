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
CC = gcc
CXX = g++
CFLAGS = -Wall -g -O2 -I../lib/includes
CXXFLAGS = $(CFLAGS)
LDFLAGS = -L../lib/.libs
LIBS = -lspdylay -lssl -lcrypto

PROGRAMS = spdycat
SPDYCAT_OBJS = spdycat.o spdylay_ssl.o util.o uri.o

.PHONY: all
all: $(PROGRAMS)

util.o: util.cc util.h
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c $<

uri.o: uri.cc uri.h
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c $<

spdylay_ssl.o: spdylay_ssl.cc spdylay_ssl.h
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c $<

spdycat.o: spdycat.cc
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c $<

spdycat: $(SPDYCAT_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(SPDYCAT_OBJS) -o $@ $(LIBS)

.PHONY: clean
clean:
	rm -f *.o $(PROGRAMS)
