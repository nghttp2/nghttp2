#!/bin/bash -eu

autoreconf -i
./configure --disable-dependency-tracking --enable-lib-only
make -j$(nproc)

"$(dirname "$(realpath "${BASH_SOURCE[0]}")")"/build_fuzzer.sh
