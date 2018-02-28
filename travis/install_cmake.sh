#!/usr/bin/bash

echo "Installing CMake ${CI_CMAKE_VERSION}"

if [[ "${TRAVIS_OS_NAME}" == "linux" ]]; then
    mkdir -p ${HOME}/cmake
    CI_CMAKE_VERSION_SHORT=`echo -n ${CI_CMAKE_VERSION} | awk -F. '{print $1 "." $2}'`
    CI_CMAKE_URL="https://cmake.org/files/v${CI_CMAKE_VERSION_SHORT}/cmake-${CI_CMAKE_VERSION}-Linux-x86_64.tar.gz"
    travis_retry wget --no-check-certificate --quiet -O - ${CI_CMAKE_URL} | tar --strip-components=1 -xz -C ${HOME}/cmake
    export PATH=${HOME}/cmake/bin:${PATH}
else
    brew upgrade cmake || brew install cmake
fi

- cmake --version

echo "Done installing CMake"
