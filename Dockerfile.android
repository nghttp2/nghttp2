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


# Only use standalone-toolchain for reduce size
FROM ubuntu:xenial
MAINTAINER Tatsuhiro Tsujikawa
ENV ANDROID_HOME /root
ENV TOOLCHAIN $ANDROID_HOME/toolchain
ENV PATH $TOOLCHAIN/bin:$PATH

ENV NDK_VERSION r14b

WORKDIR /root
RUN apt-get update && \
    apt-get install -y unzip make binutils autoconf \
      automake autotools-dev libtool pkg-config git \
      curl dpkg-dev libxml2-dev genisoimage libc6-i386 \
      lib32stdc++6 python&& \
    rm -rf /var/cache/apk/*

# Install toolchain
RUN curl -L -O https://dl.google.com/android/repository/android-ndk-$NDK_VERSION-linux-x86_64.zip && \
   unzip -q android-ndk-$NDK_VERSION-linux-x86_64.zip && \
   rm android-ndk-$NDK_VERSION-linux-x86_64.zip && \
   mkdir -p $ANDROID_HOME/toolchain && \
   $ANDROID_HOME/android-ndk-$NDK_VERSION/build/tools/make-standalone-toolchain.sh \
       --install-dir=$ANDROID_HOME/toolchain \
       --toolchain=arm-linux-androideabi-4.9 \
       --force && \
   rm -r android-ndk-$NDK_VERSION

ENV PREFIX /root/usr/local

# Setup version of libraries
ENV OPENSSL_VERSION 1.0.2d
ENV SPDYLAY_VERSION v1.4.0
ENV LIBEV_VERSION 4.19
ENV ZLIB_VERSION 1.2.8
ENV CARES_VERSION 1.13.0
ENV NGHTTP2_VERSION v1.24.0

WORKDIR /root/build
RUN git clone https://github.com/tatsuhiro-t/spdylay -b $SPDYLAY_VERSION --depth 1
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
RUN curl -L -O https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz && \
    tar xf openssl-$OPENSSL_VERSION.tar.gz && \
    rm openssl-$OPENSSL_VERSION.tar.gz

WORKDIR /root/build/openssl-$OPENSSL_VERSION
RUN export CROSS_COMPILE=$TOOLCHAIN/bin/arm-linux-androideabi- && \
    ./Configure --prefix=$PREFIX android && \
    make && make install_sw

WORKDIR /root/build
RUN curl -L -O http://dist.schmorp.de/libev/Attic/libev-$LIBEV_VERSION.tar.gz && \
    curl -L -O https://gist.github.com/tatsuhiro-t/48c45f08950f587180ed/raw/80a8f003b5d1091eae497c5995bbaa68096e739b/libev-4.19-android.patch && \
    tar xf libev-$LIBEV_VERSION.tar.gz && \
    rm libev-$LIBEV_VERSION.tar.gz

WORKDIR /root/build/libev-$LIBEV_VERSION
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
RUN curl -L -O https://downloads.sourceforge.net/project/libpng/zlib/$ZLIB_VERSION/zlib-$ZLIB_VERSION.tar.gz && \
    tar xf zlib-$ZLIB_VERSION.tar.gz && \
    rm zlib-$ZLIB_VERSION.tar.gz

WORKDIR /root/build/zlib-$ZLIB_VERSION
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
RUN curl -L -O https://c-ares.haxx.se/download/c-ares-$CARES_VERSION.tar.gz && \
    tar xf c-ares-$CARES_VERSION.tar.gz && \
    rm c-ares-$CARES_VERSION.tar.gz

WORKDIR /root/build/c-ares-$CARES_VERSION
RUN ./configure \
      --host=arm-linux-androideabi \
      --build=`dpkg-architecture -qDEB_BUILD_GNU_TYPE` \
      --prefix=$PREFIX \
      --disable-shared && \
    make install

WORKDIR /root/build
RUN git clone https://github.com/nghttp2/nghttp2 -b $NGHTTP2_VERSION --depth 1
WORKDIR /root/build/nghttp2
RUN autoreconf -i && \
    ./configure \
    --enable-app \
    --disable-shared \
    --host=arm-linux-androideabi \
    --build=`dpkg-architecture -qDEB_BUILD_GNU_TYPE` \
    --with-xml-prefix="$PREFIX" \
    --without-libxml2 \
    --disable-python-bindings \
    --disable-examples \
    --disable-threads \
      CC="$TOOLCHAIN"/bin/arm-linux-androideabi-clang \
      CXX="$TOOLCHAIN"/bin/arm-linux-androideabi-clang++ \
      CPPFLAGS="-fPIE -I$PREFIX/include" \
      PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig" \
      LDFLAGS="-fPIE -pie -L$PREFIX/lib" && \
    make && \
    arm-linux-androideabi-strip src/nghttpx src/nghttpd src/nghttp
