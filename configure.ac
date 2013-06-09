dnl Spdylay - SPDY Library

dnl Copyright (c) 2012 Tatsuhiro Tsujikawa

dnl Permission is hereby granted, free of charge, to any person obtaining
dnl a copy of this software and associated documentation files (the
dnl "Software"), to deal in the Software without restriction, including
dnl without limitation the rights to use, copy, modify, merge, publish,
dnl distribute, sublicense, and/or sell copies of the Software, and to
dnl permit persons to whom the Software is furnished to do so, subject to
dnl the following conditions:

dnl The above copyright notice and this permission notice shall be
dnl included in all copies or substantial portions of the Software.

dnl THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
dnl EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
dnl MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
dnl NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
dnl LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
dnl OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
dnl WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
AC_PREREQ(2.61)
AC_INIT([spdylay], [1.0.0], [t-tujikawa@users.sourceforge.net])
LT_PREREQ([2.2.6])
LT_INIT()
dnl See versioning rule:
dnl  http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
AC_SUBST(LT_CURRENT, 5)
AC_SUBST(LT_REVISION, 0)
AC_SUBST(LT_AGE, 0)

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE()
AC_CONFIG_HEADERS([config.h])

dnl Checks for command-line options
AC_ARG_ENABLE([maintainer-mode],
    [AS_HELP_STRING([--enable-maintainer-mode],
                    [Turn on compile time warnings])],
    [maintainer_mode=$enableval], [maintainer_mode=no])

AC_ARG_ENABLE([src],
    [AS_HELP_STRING([--enable-src],
                    [Build installable SPDY client/server programs in src])],
    [request_src=$enableval], [request_src=yes])

AC_ARG_ENABLE([examples],
    [AS_HELP_STRING([--enable-examples],
                    [Build example programs])],
    [request_examples=$enableval], [request_examples=yes])

AC_ARG_WITH([libxml2],
    [AS_HELP_STRING([--without-libxml2],
                    [disable support for libxml2])],
    [], [with_libxml2=yes])

dnl Checks for programs
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG([0.20])

AC_COMPILE_STDCXX_11
AM_CONDITIONAL([HAVE_STDCXX_11],
               [ test "x$ac_cv_cxx_compile_cxx11_cxx" = "xyes" ])

# Checks for libraries.

# Additional libraries required for tests.
TESTS_LIBS=

# Additional libraries required for programs under src directory.
SRC_LIBS=

LIBS_OLD=$LIBS
# Search for dlsym function, which is used in tests. Linux needs -ldl,
# but netbsd does not need it.
AC_SEARCH_LIBS([dlsym], [dl])
TESTS_LIBS="$LIBS $TESTS_LIBS"
LIBS=$LIBS_OLD

LIBS_OLD=$LIBS
AC_SEARCH_LIBS([clock_gettime], [rt],
               [AC_DEFINE([HAVE_CLOCK_GETTIME], [1],
                          [Define to 1 if you have the `clock_gettime`.])])
SRC_LIBS="$LIBS $SRC_LIBS"
LIBS=$LIBS_OLD

case "$host" in
  *android*)
    android_build=yes
    # android does not need -pthread, but needs followng 2 libs for C++
    SRC_LIBS="$SRC_LIBS -lstdc++ -lsupc++"
    ;;
  *)
    SRC_LIBS="$SRC_LIBS -pthread"
    ;;
esac

# zlib
if test "x$android_build" = "xyes"; then
  # Use zlib provided by NDK
  LIBS="-lz $LIBS"
else
  PKG_CHECK_MODULES([ZLIB], [zlib >= 1.2.3])
  LIBS="$ZLIB_LIBS $LIBS"
  CFLAGS="$CFLAGS $ZLIB_CFLAGS"
fi

# cunit
PKG_CHECK_MODULES([CUNIT], [cunit >= 2.1], [have_cunit=yes], [have_cunit=no])
# If pkg-config does not find cunit, check it using AC_CHECK_LIB.  We
# do this because Debian (Ubuntu) lacks pkg-config file for cunit.
if test "x${have_cunit}" = "xno"; then
  AC_MSG_WARN([${CUNIT_PKG_ERRORS}])
  AC_CHECK_LIB([cunit], [CU_initialize_registry],
               [have_cunit=yes], [have_cunit=no])
  if test "x${have_cunit}" = "xyes"; then
    CUNIT_LIBS="-lcunit"
    CUNIT_CFLAGS=""
    AC_SUBST([CUNIT_LIBS])
    AC_SUBST([CUNIT_CFLAGS])
  fi
fi
if test "x${have_cunit}" = "xyes"; then
  # cunit in Mac OS X requires ncurses. Note that in Mac OS X, test
  # program can be built without -lncurses, but it emits runtime
  # error.
  case "${build}" in
    *-apple-darwin*)
      CUNIT_LIBS="$CUNIT_LIBS -lncurses"
      AC_SUBST([CUNIT_LIBS])
      ;;
  esac
fi

AM_CONDITIONAL([HAVE_CUNIT], [ test "x${have_cunit}" = "xyes" ])

# openssl (for examples)
PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.0.1],
                  [have_openssl=yes], [have_openssl=no])
if test "x${have_openssl}" = "xno"; then
  AC_MSG_NOTICE($OPENSSL_PKG_ERRORS)
  AC_MSG_NOTICE([The example programs will not be built.])
fi

# libevent_openssl
# 2.0.8 is required because we use evconnlistener_set_error_cb()
PKG_CHECK_MODULES([LIBEVENT_OPENSSL], [libevent_openssl >= 2.0.8],
                  [have_libevent_openssl=yes], [have_libevent_openssl=no])
if test "x${have_libevent_openssl}" = "xno"; then
  AC_MSG_NOTICE($LIBEVENT_OPENSSL_PKG_ERRORS)
  AC_MSG_NOTICE([Shrpx example program will not be built.])
fi
AM_CONDITIONAL([HAVE_LIBEVENT_OPENSSL],
               [ test "x${have_libevent_openssl}" = "xyes" ])

# libxml2 (for examples/spdycat)
have_libxml2=no
if test "x$with_libxml2" != "xno"; then
  AM_PATH_XML2(2.7.7, [have_libxml2=yes], [have_libxml2=no])
  if test "x${have_libxml2}" = "xyes"; then
    AC_DEFINE([HAVE_LIBXML2], [1], [Define to 1 if you have `libxml2` library.])
  fi
fi
AM_CONDITIONAL([HAVE_LIBXML2], [ test "x${have_libxml2}" = "xyes" ])

# The src programs depend on OpenSSL
enable_src=no
if test "x${request_src}" = "xyes" &&
   test "x${have_openssl}" = "xyes"; then
    enable_src=yes
fi

AM_CONDITIONAL([ENABLE_SRC], [ test "x${enable_src}" = "xyes" ])

# The example programs depend on OpenSSL
enable_examples=no
if test "x${request_examples}" = "xyes" &&
   test "x${have_openssl}" = "xyes"; then
    enable_examples=yes
fi

AM_CONDITIONAL([ENABLE_EXAMPLES], [ test "x${enable_examples}" = "xyes" ])

# Checks for header files.
AC_CHECK_HEADERS([ \
  arpa/inet.h \
  netinet/in.h \
  pwd.h \
  stddef.h \
  stdint.h \
  stdlib.h \
  string.h \
  time.h \
  unistd.h \
])

case "${host}" in
  *mingw*)
    # For ntohl, ntohs in Windows
    AC_CHECK_HEADERS([winsock2.h])
    ;;
esac

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_CHECK_TYPES([ptrdiff_t])
AC_C_BIGENDIAN
AC_SYS_LARGEFILE

# Checks for library functions.
if test "x$cross_compiling" != "xyes"; then
  AC_FUNC_MALLOC
fi
AC_CHECK_FUNCS([ \
  getpwnam \
  memmove \
  memset \
  timegm \
])

AX_HAVE_EPOLL([have_epoll=yes], [have_epoll=no])
if test "x${have_epoll}" = "xyes"; then
  AC_DEFINE([HAVE_EPOLL], [1], [Define to 1 if you have the `epoll`.])
fi
AM_CONDITIONAL([HAVE_EPOLL], [ test "x${have_epoll}" = "xyes" ])

AC_CHECK_FUNCS([kqueue], [have_kqueue=yes])
AM_CONDITIONAL([HAVE_KQUEUE], [ test "x${have_kqueue}" = "xyes" ])

AM_CONDITIONAL([ENABLE_SPDYD],
         [ test "x${have_epoll}" = "xyes" || test "x${have_kqueue}" = "xyes" ])

AC_LANG_PUSH(C++)
AC_MSG_CHECKING([whether struct kevent.udata is intptr_t])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
]],
[[
struct kevent event;
event.udata = (intptr_t)(&event);
]])],
[kevent_udata_intptr_t=yes], [kevent_udata_intptr_t=no])
AC_MSG_RESULT([$kevent_udata_intptr_t])
if test "x$kevent_udata_intptr_t" = "xyes"; then
  AC_DEFINE([KEVENT_UDATA_INTPTR_T], [1],
            [Define to 1 if struct kevent.udata is intptr_t])
fi
AC_LANG_POP()

dnl Windows library for winsock2
case "${host}" in
  *mingw*)
    LIBS="$LIBS -lws2_32"
    ;;
esac

if test "x$maintainer_mode" != "xno"; then
    CFLAGS="$CFLAGS -Wall -Wextra -Werror"
    CFLAGS="$CFLAGS -Wmissing-prototypes -Wstrict-prototypes"
    CFLAGS="$CFLAGS -Wmissing-declarations -Wpointer-arith"
    CFLAGS="$CFLAGS -Wdeclaration-after-statement"
    CFLAGS="$CFLAGS -Wformat-security"
    CFLAGS="$CFLAGS -Wwrite-strings -Wshadow -Winline -Wnested-externs"
    CFLAGS="$CFLAGS -Wfloat-equal -Wundef -Wendif-labels -Wempty-body"
    CFLAGS="$CFLAGS -Wcast-align -Wclobbered -Wvla"
    CFLAGS="$CFLAGS -Wno-unused-parameter"
fi

AC_SUBST([TESTS_LIBS])
AC_SUBST([SRC_LIBS])

AC_CONFIG_FILES([
  Makefile
  lib/Makefile
  lib/libspdylay.pc
  lib/includes/Makefile
  lib/includes/spdylay/spdylayver.h
  tests/Makefile
  tests/testdata/Makefile
  src/Makefile
  examples/Makefile
  doc/Makefile
  doc/conf.py
  python/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([summary of build options:

    Version:        ${VERSION} shared $LT_CURRENT:$LT_REVISION:$LT_AGE
    Host type:      ${host}
    Install prefix: ${prefix}
    C compiler:     ${CC}
    CFLAGS:         ${CFLAGS}
    LDFLAGS:        ${LDFLAGS}
    LIBS:           ${LIBS}
    CPPFLAGS:       ${CPPFLAGS}
    C preprocessor: ${CPP}
    C++ compiler:   ${CXX}
    CXXFLAGS:       ${CXXFLAGS}
    CXXCPP:         ${CXXCPP}
    Library types:  Shared=${enable_shared}, Static=${enable_static}
    CUnit:          ${have_cunit}
    OpenSSL:        ${have_openssl}
    Libxml2:        ${have_libxml2}
    Libevent(SSL):  ${have_libevent_openssl}
    Src:            ${enable_src}
    Examples:       ${enable_examples}
])
