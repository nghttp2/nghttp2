FROM debian:10 as build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git g++ make binutils autoconf automake autotools-dev libtool \
        pkg-config \
        zlib1g-dev libev-dev libjemalloc-dev ruby-dev libc-ares-dev bison && \
    git clone --depth 1 -b OpenSSL_1_1_1k+quic https://github.com/quictls/openssl && \
    cd openssl && ./config enable-tls1_3 --openssldir=/etc/ssl && make -j$(nproc) && make install_sw && cd .. && rm -rf openssl && \
    git clone --depth 1 https://github.com/ngtcp2/nghttp3 && \
    cd nghttp3 && autoreconf -i && \
    ./configure --enable-lib-only && \
    make -j$(nproc) && make install-strip && cd .. && rm -rf nghttp3 && \
    git clone --depth 1 https://github.com/ngtcp2/ngtcp2 && \
    cd ngtcp2 && autoreconf -i && \
    ./configure --enable-lib-only \
        LIBTOOL_LDFLAGS="-static-libtool-libs" \
        OPENSSL_LIBS="-l:libssl.a -l:libcrypto.a -ldl -lpthread" && \
    make -j$(nproc) && make install-strip && cd .. && rm -rf ngtcp2 && \
    git clone --depth 1 https://github.com/nghttp2/nghttp2.git && \
    cd nghttp2 && \
    git submodule update --init && autoreconf -i && \
    ./configure --disable-examples --disable-hpack-tools \
        --disable-python-bindings --with-mruby --with-neverbleed \
        --enable-http3 \
        LIBTOOL_LDFLAGS="-static-libtool-libs" \
        LIBS="-ldl -pthread" \
        OPENSSL_LIBS="-l:libssl.a -l:libcrypto.a" \
        LIBEV_LIBS="-l:libev.a" \
        JEMALLOC_LIBS="-l:libjemalloc.a" \
        LIBCARES_LIBS="-l:libcares.a" \
        ZLIB_LIBS="-l:libz.a" && \
    make -j$(nproc) install-strip

FROM gcr.io/distroless/cc-debian10

COPY --from=build /usr/local/bin/h2load /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/h2load"]
