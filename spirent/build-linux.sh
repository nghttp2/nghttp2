#!/bin/bash
#
# Builds nghttp2 64 bit.
# Prerequisites for build:
#   Install automake, autoconf and libtool based on latest requirements.
# Prerequisites:
# boost 1.64 ( same used by STC)
# openssl 1.0+ (same used by STC)

set -eo pipefail

# Build configure file
autoreconf -i
automake
autoconf

# Set the path to openssl builds.
readonly OPEN_SSL64=/table/table/bandrews/openssl/x64/openssl-1.0.1u

# Set the path to boost builds.
readonly BOOST_64=/table/table/bandrews/boost/x64/boost_1_64_0

readonly RELEASE_64=release64
readonly DEBUG_64=debug64

if [ ! -d "$OPEN_SSL64" ]; then
  echo "$OPEN_SSL64 does not exist" >&2
  exit 1
fi

if [ ! -d "$BOOST_64" ]; then
  echo "$BOOST_64 does not exist" >&2
  exit 1
fi

export OPENSSL_LIBS="$OPEN_SSL64"
# auto cofig script does not pick up include path similar to boost for openssl
export OPENSSL_CFLAGS="-I ${OPEN_SSL64}/include"
export BOOST_ROOT="$BOOST_64"


# --------------------------------- BUILDING Linux 64 Release ----------------------------------
# LDFLAGS is required as libtools does not work properly with multiple gcc installations. link fail beause libstdc++ 32 bit is used instead of 64 bit.
# Boost library path required in LD_LIBRARY_PATH.

PREFIXDIR="$PWD/$RELEASE_64"
if [ ! -d "$PREFIXDIR" ]; then
  mkdir $PREFIXDIR
fi

LDFLAGS=-L/usr/gcc_4_9/lib64 CXXFLAGS="-std=c++14" CXX=/usr/gcc_4_9/bin/g++ LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/gcc_7_2/lib64:$BOOST_ROOT/stage/lib \
./configure --enable-asio-lib --prefix=$PREFIXDIR &&\

CXXFLAGS="-std=c++14" CXX=/usr/gcc_4_9/bin/g++ LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/gcc_7_2/lib64 make -j 4 &&\
make install

# --------------------------------- BUILDING Linux 64 Debug  ----------------------------------

# PREFIXDIR="$PWD/$DEBUG_64"
# if [ ! -d "$PREFIXDIR" ]; then
#   mkdir $PREFIXDIR
# fi

# LDFLAGS=-L/usr/gcc_4_9/lib64 CXXFLAGS="-std=c++14" CXX=/usr/gcc_4_9/bin/g++ LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/gcc_7_2/lib64:$BOOST_ROOT/stage/lib \
# ./configure --enable-asio-lib --prefix=$PREFIXDIR --enable-debug &&\

# CXXFLAGS="-std=c++14" CXX=/usr/gcc_4_9/bin/g++ LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/gcc_7_2/lib64 make -j 4&&\
# make install
