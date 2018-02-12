#!/bin/bash

_startup_dir=`pwd`

export CI_BOOST_ROOT=${HOME}/boost

# Download Boost
mkdir -p ${HOME}/boost_source
CI_BOOST_VERSION_=`echo -n ${CI_BOOST_VERSION} | sed 's/\./_/g'`
CI_BOOST_URL="https://dl.bintray.com/boostorg/release/${CI_BOOST_VERSION}/source/boost_${CI_BOOST_VERSION_}.tar.gz"
travis_retry wget --no-check-certificate --quiet -O - ${CI_BOOST_URL} | tar --strip-components=1 -xz -C ${HOME}/boost_source

# Build Boost
mkdir -p ${HOME}/boost/include
cd ${HOME}/boost_source


if [[ $CXX == g++* ]]; then
    CI_B2_TOOLSET="gcc"
fi
if [[ "$CXX" = clang* ]]; then
    CI_B2_TOOLSET="clang"
fi

echo -n "using ${CI_B2_TOOLSET} : : ${CXX} ;" > tools/build/src/user-config.jam;

./bootstrap.sh --with-toolset=${CI_B2_TOOLSET}

CI_B2_OPTIONS="--with-system --with-thread --with-date_time --with-regex --with-serialization --build-type=minimal --stagedir=${CI_BOOST_ROOT}"
CI_B2_PROPERTIES="threading=multi link=static variant=${CI_BUILD_TYPE,,} cflags=-fPIC cxxflags=-fPIC" toolset=${CI_B2_TOOLSET}
./b2 -d2 -q ${CI_B2_OPTIONS} ${CI_B2_PROPERTIES} stage
mv ${HOME}/boost_source/boost ${CI_BOOST_ROOT}/include/

cd ${_startup_dir}
unset _startup_dir

