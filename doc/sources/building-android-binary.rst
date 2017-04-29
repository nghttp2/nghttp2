Building Android binary
=======================

In this article, we briefly describe how to build Android binary using
`Android NDK <https://developer.android.com/ndk/index.html>`_
cross-compiler on Debian Linux.

The easiest way to build android binary is use Dockerfile.android.
See Dockerfile.android for more details.  If you cannot use
Dockerfile.android for whatever reason, continue to read the rest of
this article.

We offer ``android-config`` and ``android-make`` scripts to make the
build easier.  To make these script work, NDK toolchain must be
installed in the following way.  First, let us introduce
``ANDROID_HOME`` environment variable.  We need to install toolchain
under ``$ANDROID_HOME/toolchain``.  An user can freely choose the path
for ``ANDROID_HOME``.  For example, to install toolchain under
``$ANDROID_HOME/toolchain``, do this in the the directory where NDK is
unpacked:

.. code-block:: text

    $ build/tools/make_standalone_toolchain.py \
      --arch arm --api 16 --stl gnustl \
      --install-dir $ANDROID_HOME/toolchain

The API level (``--api``) is not important here because we don't use
Android specific C/C++ API.

The dependent libraries, such as OpenSSL, libev, and c-ares should be
built with the toolchain and installed under
``$ANDROID_HOME/usr/local``.  We recommend to build these libraries as
static library to make the deployment easier.  libxml2 support is
currently disabled.

Although zlib comes with Android NDK, it seems not to be a part of
public API, so we have to built it for our own.  That also provides us
proper .pc file as a bonus.

Before running ``android-config`` and ``android-make``,
``ANDROID_HOME`` environment variable must be set to point to the
correct path.  Also add ``$ANDROID_HOME/toolchain/bin`` to ``PATH``:

.. code-block:: text

    $ export PATH=$PATH:$ANDROID_HOME/toolchain/bin

To configure OpenSSL, use the following script:

.. code-block:: sh

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

And run ``make install_sw`` to build and install without
documentation.

We cannot compile libev without modification.  Apply `this patch
<https://gist.github.com/tatsuhiro-t/48c45f08950f587180ed>`_ before
configuring libev.  This patch is for libev-4.19.  After applying the
patch, to configure libev, use the following script:

.. code-block:: sh

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

To configure c-ares, use the following script:

.. code-block:: sh

    #!/bin/sh -e

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
        --disable-shared

To configure zlib, use the following script:

.. code-block:: sh

    #!/bin/sh -e

    if [ -z "$ANDROID_HOME" ]; then
        echo 'No $ANDROID_HOME specified.'
        exit 1
    fi
    PREFIX=$ANDROID_HOME/usr/local
    TOOLCHAIN=$ANDROID_HOME/toolchain
    PATH=$TOOLCHAIN/bin:$PATH

    HOST=arm-linux-androideabi

    CC=$HOST-gcc \
    AR=$HOST-ar \
    LD=$HOST-ld \
    RANLIB=$HOST-ranlib \
    STRIP=$HOST-strip \
    ./configure \
        --prefix=$PREFIX \
        --libdir=$PREFIX/lib \
        --includedir=$PREFIX/include \
        --static

And run ``make install`` to build and install.

After prerequisite libraries are prepared, run ``android-config`` and
then ``android-make`` to compile nghttp2 source files.

If all went well, application binaries, such as nghttpx, are created
under src directory.  Strip debugging information from the binary
using the following command:

.. code-block:: text

    $ arm-linux-androideabi-strip src/nghttpx
