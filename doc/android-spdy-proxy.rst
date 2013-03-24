SPDY Proxy with Firefox for Android
===================================

This document describes how to use SPDY proxy from Android device
using Firefox for Android. No root privilege is required. It may be
possible to use other Web browser/software if they provide the ability
to specify HTTP proxy. Because we don't use the features only
available in latest Android devices, this method works on relatively
old but still used versions, e.g., Andriod 2.3 series.

Setting up SPDY Proxy
---------------------

If you have VPS, then you can setup SPDY proxy there.  You can use
``shrpx`` with ``-s`` option + Squid as SPDY proxy.  Alternatively,
`node-spdyproxy <https://github.com/igrigorik/node-spdyproxy/>`_ may
also work. If you don't have VPS, but your home internet connection
has global IP address which can be accessible from Android device, you
can use your home PC as SPDY proxy temporarily for the experiment.
The self-signed certificate is OK because we will run ``shrpx`` with
``-k`` option on Android in this example. Alternatively, you can store
your certificate in Android device and specify it using ``--cacert``
option. If you think these are insecure, obtain valid certificate.

Building spdylay library and shrpx
----------------------------------

First Android NDK must be installed on your system.  Refer
:doc:`package_README` to see how to install NDK. In the following document, We
use ``ANDROID_HOME`` environment variable.

To make it easier to run Android cross-compiler tools (and for the
sake of this document), include the path to those commands to
``PATH``::

    $ export PATH=$ANDROID_HOME/toolchain/bin:$PATH

We need to build dependent libraries: OpenSSL and libevent.

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

Then run ``make install`` to build and install library.

For libevent, use the following script to configure::

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

Then run ``make install`` to
build and install library.

To build spdylay, use ``android-config`` to configure and
``android-make`` to build as described in :doc:`package_README`.

If all went well, ``shrpx`` binary is created in src directory.  Strip
debugging information from the binary using the following command::

    $ arm-linux-androideabi-strip src/shrpx

Setup shrpx on Android device
-----------------------------

There may be several ways to run ``shrpx`` on Android. I describe the
way to use `Android Terminal Emulator
<https://github.com/jackpal/Android-Terminal-Emulator>`_.  It can be
installed from Google Play. Copy ``shrpx`` binary to the location
where the Android-Terminal-Emulator is installed (In case of my phone,
it is ``/data/data/jackpal.androidterm``) and give the executable
permission to ``shrpx`` using ``chmod``::

    $ chmod 755 shrpx

Then run ``shrpx`` in client-mode like this::

    $ ./shrpx -k -p -f localhost,8000 -b SPDY-PROXY-ADDR,SPDY-PROXY-PORT

Substitute ``SPDY-PROXY-ADDR`` and ``SPDY-PROXY-PORT`` with the SPDY
proxy address and port you have setup respectively. The ``-k`` option
tells ``shrpx`` not to complain the self-signed certificate for SPDY
proxy. The ``-p`` option makes ``shrpx`` run so called client mode.
In that mode, ``shrpx`` acts like ordinary HTTP forward proxy in
frontend connection, it forwards the requests from the client to
backend in encrypted SPDY connection. The ``-f`` option specify the
address and port ``shrpx`` listens to. In this setup, the web browser
should be setup to use HTTP proxy localhost:8000. The ``-b`` option
specify the SPDY proxy address and port ``shrpx`` forwards the
requests from the client. The configuration looks like this::


    +----Android------------------------+          +---SPDY-Proxy------+
    | [Firefox] <-- HTTP --> [shrpx] <--=-- SPDY --=-->[shrpx,squid]<--=-- SPDY --> ...
    +-----------------------------------+          +-------------------+   HTTP

With the above command-line option, ``shrpx`` only opens 1 connection
to SPDY proxy. Of course, Firefox will use multiple connections to
neighboring ``shrpx``. ``shrpx`` coalesces all the requests in 1
backend connection, that is the benefit SPDY proxy brings in.

Setup Firefox to use SPDY proxy
-------------------------------

If you have not installed, Firefox for Android, install it.  Enter
``about:config`` in URL bar in Firefox and locate proxy
settings. Setup those values like this::

    network.proxy.http = localhost
    network.proxy.http_port = 8000
    network.proxy.ssl = localhost
    network.proxy.ssl_port = 8000
    network.proxy.type = 1

You also need to tweak the following settings to increase in-flight
requests to circumvent latency::

    network.http.max-persistent-connections-per-proxy
    network.http.max-connections
    network.http.max-connections-per-server

Since ``shrpx`` handles maximum 100 concurrent streams, it is
reasonable to set
``network.http.max-persistent-connections-per-proxy`` to ``100``.

Now borwse the sites with Firefox. The all HTTP requests are now sent
via internal ``shrpx`` to SPDY proxy in 1 connection. SPDY proxy will
get resources on behalf of the client and sent back the response.
