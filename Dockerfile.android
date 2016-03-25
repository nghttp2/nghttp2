# vim: ft=dockerfile:
# Dockerfile to build nghttp2 android binary
#
# $ sudo docker build -t nghttp2-android - < Dockerfile.android
#
# After successful build, android binaries are located under
# /root/build/nghttp2.  You can copy the binary using docker cp.  For
# example, to copy nghttpx binary to host file system location
# /path/to/dest, do this:
#
# $ sudo docker run -v /path/to/dest:/out nghttp2-android cp /root/build/nghttp2/src/nghttpx /out

FROM ubuntu:vivid

MAINTAINER Tatsuhiro Tsujikawa

ENV ANDROID_HOME /root/android
ENV PREFIX $ANDROID_HOME/usr/local
ENV TOOLCHAIN $ANDROID_HOME/toolchain
ENV PATH $TOOLCHAIN/bin:$PATH

# It would be better to use nearest ubuntu archive mirror for faster
# downloads.
# RUN sed -ie 's/archive\.ubuntu/jp.archive.ubuntu/g' /etc/apt/sources.list

RUN apt-get update
# genisoimage, libc6-i386 and lib32stdc++6 are required to decompress ndk.
RUN apt-get install -y make binutils autoconf automake autotools-dev libtool \
    pkg-config git curl dpkg-dev libxml2-dev \
    genisoimage libc6-i386 lib32stdc++6

WORKDIR /root/build
RUN curl -L -O http://dl.google.com/android/ndk/android-ndk-r10d-linux-x86_64.bin && \
    chmod a+x android-ndk-r10d-linux-x86_64.bin && \
    ./android-ndk-r10d-linux-x86_64.bin && \
    rm android-ndk-r10d-linux-x86_64.bin

WORKDIR /root/build/android-ndk-r10d
RUN /bin/bash build/tools/make-standalone-toolchain.sh \
    --install-dir=$ANDROID_HOME/toolchain \
    --toolchain=arm-linux-androideabi-4.9 --llvm-version=3.5 \
    --system=linux-x86_64

WORKDIR /root/build
RUN git clone https://github.com/tatsuhiro-t/spdylay
WORKDIR /root/build/spdylay
RUN autoreconf -i && \
    ./configure \
    --disable-shared \
    --host=arm-linux-androideabi \
    --build=`dpkg-architecture -qDEB_BUILD_GNU_TYPE` \
    --prefix=$PREFIX \
    --without-libxml2 \
    --disable-src \
    --disable-examples \
    CPPFLAGS="-I$PREFIX/include" \
    PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig" \
    LDFLAGS="-L$PREFIX/lib" && \
    make install

WORKDIR /root/build
RUN curl -L -O https://www.openssl.org/source/openssl-1.0.2d.tar.gz && \
    tar xf openssl-1.0.2d.tar.gz && \
    rm openssl-1.0.2d.tar.gz

WORKDIR /root/build/openssl-1.0.2d
RUN export CROSS_COMPILE=$TOOLCHAIN/bin/arm-linux-androideabi- && \
    ./Configure --prefix=$PREFIX android && \
    make && make install_sw

WORKDIR /root/build
RUN curl -L -O http://dist.schmorp.de/libev/libev-4.19.tar.gz && \
    curl -L -O https://gist.github.com/tatsuhiro-t/48c45f08950f587180ed/raw/80a8f003b5d1091eae497c5995bbaa68096e739b/libev-4.19-android.patch && \
    tar xf libev-4.19.tar.gz && \
    rm libev-4.19.tar.gz

WORKDIR /root/build/libev-4.19
RUN patch -p1 < ../libev-4.19-android.patch && \
    ./configure \
    --host=arm-linux-androideabi \
    --build=`dpkg-architecture -qDEB_BUILD_GNU_TYPE` \
    --prefix=$PREFIX \
    --disable-shared \
    --enable-static \
    CPPFLAGS=-I$PREFIX/include \
    LDFLAGS=-L$PREFIX/lib && \
    make install

WORKDIR /root/build
RUN curl -L -O http://zlib.net/zlib-1.2.8.tar.gz && \
    tar xf zlib-1.2.8.tar.gz && \
    rm zlib-1.2.8.tar.gz

WORKDIR /root/build/zlib-1.2.8
RUN HOST=arm-linux-androideabi \
    CC=$HOST-gcc \
    AR=$HOST-ar \
    LD=$HOST-ld \
    RANLIB=$HOST-ranlib \
    STRIP=$HOST-strip \
    ./configure \
    --prefix=$PREFIX \
    --libdir=$PREFIX/lib \
    --includedir=$PREFIX/include \
    --static && \
    make install

WORKDIR /root/build
RUN git clone https://github.com/nghttp2/nghttp2
WORKDIR /root/build/nghttp2
RUN autoreconf -i && \
    ./configure \
    --disable-shared \
    --host=arm-linux-androideabi \
    --build=`dpkg-architecture -qDEB_BUILD_GNU_TYPE` \
    --with-xml-prefix="$PREFIX" \
    --without-libxml2 \
    --disable-python-bindings \
    --disable-examples \
    --disable-threads \
    LIBSPDYLAY_CFLAGS=-I$PREFIX/usr/local/include \
    LIBSPDYLAY_LIBS="-L$PREFIX/usr/local/lib -lspdylay" \
    CPPFLAGS="-fPIE -I$PREFIX/include" \
    CXXFLAGS="-fno-strict-aliasing" \
    PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig" \
    LDFLAGS="-fPIE -pie -L$PREFIX/lib" && \
    make && \
    arm-linux-androideabi-strip src/nghttpx src/nghttpd src/nghttp
