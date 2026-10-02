#!/bin/bash -eu

FUZZERS=(
    read_write
)

for fuzzer in "${FUZZERS[@]}"; do
    $CXX $CXXFLAGS -std=c++23 -Ilib/includes \
         fuzz/${fuzzer}.cc -o $OUT/${fuzzer} \
         $LIB_FUZZING_ENGINE lib/.libs/libnghttp2v2.a
done
