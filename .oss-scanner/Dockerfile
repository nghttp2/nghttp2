FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive \
    CC=clang-21 \
    CXX=clang++-21
RUN apt-get update && apt-get install -y --no-install-recommends \
      git clang-21 make autoconf automake libtool pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

RUN cd /src && \
    git submodule update --init --depth 1 && \
    autoreconf -i && \
    ./configure --disable-dependency-tracking --enable-lib-only \
      CPPFLAGS="-fno-omit-frame-pointer" && \
    make -j"$(nproc)" && \
    (make -j"$(nproc)" check || echo "WARNING: test failed!")
