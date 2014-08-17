Building Android binary
=======================

In this article, we briefly describe how to build Android binary using
`Android NDK <http://developer.android.com/tools/sdk/ndk/index.html>`_
cross-compiler on Debian Linux.

We offer ``android-config`` and ``android-make`` scripts to make the
build easier.  To make these script work, NDK toolchain must be
installed in the following way.  First, let us introduce
``ANDROID_HOME`` environment variable.  We need to install toolchain
under ``$ANDROID_HOME/toolchain``.  An user can freely choose the path
for ``ANDROID_HOME``.  For example, to install toolchain under
``$ANDROID_HOME/toolchain``, do this in the the directory where NDK is
unpacked::

    $ build/tools/make-standalone-toolchain.sh \
      --install-dir=$ANDROID_HOME/toolchain \
      --toolchain=arm-linux-androideabi-4.8 \
      --llvm-version=3.4

The additional flag ``--system=linux-x86_64`` may be required if you
are using x86_64 system.

The platform level is not important here because we don't use Android
specific C/C++ API.

The dependent libraries, such as OpenSSL and libevent should be built
with the toolchain and installed under ``$ANDROID_HOME/usr/local``.
We recommend to build these libraries as static library to make the
deployment easier.  libxml2 support is currently disabled.

We use zlib which comes with Android NDK, so we don't have to build it
by ourselves.

If SPDY support is required for nghttpx and h2load, build and install
spdylay as well.

Before running ``android-config`` and ``android-make``,
``ANDROID_HOME`` environment variable must be set to point to the
correct path.  Also add ``$ANDROID_HOME/toolchain/bin`` to ``PATH``::

    $ export PATH=$PATH:$ANDROID_HOME/toolchain/bin

To configure OpenSSL, use the following script::

    #!/bin/sh

    if [ -z "$ANDROID_HOME" ]; then
        echo 'No $ANDROID_HOME specified.'
        exit 1
    fi
    PREFIX=$ANDROID_HOME/usr/local
    TOOLCHAIN=$ANDROID_HOME/toolchain
    PATH=$TOOLCHAIN/bin:$PATH

    export CROSS_COMPILE=$TOOLCHAIN/bin/arm-linux-androideabi-
    ./Configure --prefix=$PREFIX android

And run ``make install`` to build and install.

To configure libevent, use the following script::

    #!/bin/sh

    if [ -z "$ANDROID_HOME" ]; then
        echo 'No $ANDROID_HOME specified.'
        exit 1
    fi
    PREFIX=$ANDROID_HOME/usr/local
    TOOLCHAIN=$ANDROID_HOME/toolchain
    PATH=$TOOLCHAIN/bin:$PATH

    ./configure \
        --host=arm-linux-androideabi \
        --build=`dpkg-architecture -qDEB_BUILD_GNU_TYPE` \
        --prefix=$PREFIX \
        --disable-shared \
        --enable-static \
        CPPFLAGS=-I$PREFIX/include \
        LDFLAGS=-L$PREFIX/lib

And run ``make install`` to build and install.

To configure spdylay, use the following script::

    if [ -z "$ANDROID_HOME" ]; then
	echo 'No $ANDROID_HOME specified.'
	exit 1
    fi
    PREFIX=$ANDROID_HOME/usr/local
    TOOLCHAIN=$ANDROID_HOME/toolchain
    PATH=$TOOLCHAIN/bin:$PATH

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
	LDFLAGS="-L$PREFIX/lib"

And run ``make install`` to build and install.  After spdylay
installation, edit $ANDROID_HOME/usr/local/lib/pkgconfig/libspdylay.pc
and remove the following line::

    Requires.private: zlib

After prerequisite libraries are prepared, run ``android-config`` and
then ``android-make`` to compile nghttp2 source files.

If all went well, application binaries, such as nghttpx, are created
under src directory.  Strip debugging information from the binary
using the following command::

    $ arm-linux-androideabi-strip src/nghttpx
