# nghttp2 - HTTP/2 C Library
#
# Copyright (c) 2012, 2013, 2014, 2015 Tatsuhiro Tsujikawa
# Copyright (c) 2016 Peter Wu <peter@lekensteyn.nl>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

cmake_minimum_required(VERSION 3.0)
# XXX using 1.7.90 instead of 1.8.0-DEV
project(nghttp2 VERSION 1.7.90)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(Version)

set(PACKAGE_VERSION     "${PROJECT_VERSION}")
HexVersion(PACKAGE_VERSION_NUM ${PROJECT_VERSION_MAJOR} ${PROJECT_VERSION_MINOR} ${PROJECT_VERSION_PATCH})

option(ENABLE_WERROR    "Turn on compile time warnings")
option(ENABLE_DEBUG     "Turn on debug output")
option(ENABLE_THREADS   "Turn on threading in apps" ON)
option(ENABLE_APP       "Build applications (nghttp, nghttpd, nghttpx and h2load)"
        check)
option(ENABLE_HPACK_TOOLS "Build HPACK tools" check)
option(ENABLE_ASIO_LIB  "Build C++ libnghttp2_asio library")
option(ENABLE_EXAMPLES  "Build examples" check)
option(ENABLE_PYTHON_BINDINGS "Build Python bindings" check)
option(ENABLE_FAILMALLOC "Build failmalloc test program" ON)
option(ENABLE_LIB_ONLY  "Build libnghttp2 only.  This is a short hand for -DENABLE_APP=0 -DENABLE_EXAMPLES=0 -DENABLE_HPACK_TOOLS=0 -DENABLE_PYTHON_BINDINGS=0")

option(WITH_LIBXML2     "Use libxml2" check)
option(WITH_JEMALLOC    "Use jemalloc" check)
option(WITH_SPDYLAY     "Use spdylay" check)
option(WITH_MRUBY       "Use mruby")
option(WITH_NEVERBLEED  "Use neverbleed")
set(CYTHON_PATH "" CACHE PATH     "Use cython in given path")
set(CYTHON      "" CACHE FILEPATH "The Cython executable")

find_package(PkgConfig 0.20)
# XXX fail only when "ON" instead of "CHECK"?
if(ENABLE_PYTHON_BINDINGS)
  find_package(PythonInterp REQUIRED)
endif()
# AM_PATH_PYTHON([2.7],, [:])

if(ENABLE_LIB_ONLY)
  set(ENABLE_APP            OFF)
  set(ENABLE_HPACK_TOOLS    OFF)
  set(ENABLE_EXAMPLES       OFF)
  set(ENABLE_PYTHON_BINDINGS OFF)
endif()

if(ENABLE_PYTHON_BINDINGS)
  find_package(PythonLibs 2.7 REQUIRED)
  # XXX find cython
endif()
# if [test "x$request_python_bindings" != "xno"]; then
#   AX_PYTHON_DEVEL([>= '2.7'])
# fi
#
# if test "x${cython_path}" = "x"; then
#   AC_CHECK_PROGS([CYTHON], [cython.py cython])
# else
#   CYTHON=${cython_path}
#   AC_SUBST([CYTHON])
# fi

#
# If we're running GCC or clang define _U_ to be "__attribute__((unused))"
# so we can use _U_ to flag unused function parameters and not get warnings
# about them. Otherwise, define _U_ to be an empty string so that _U_ used
# to flag an unused function parameters will compile with other compilers.
#
# XXX - similar hints for other compilers?
#
if(CMAKE_C_COMPILER_ID MATCHES "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  add_definitions(
    "-D_U_=__attribute__((unused))"
    "-DNGHTTP2_NORETURN=__attribute__((noreturn))"
  )
else()
  add_definitions(-D_U_ -DNGHTTP2_NORETURN)
endif()

include(CheckCXXCompilerFlag)
foreach(_cxx1x_flag "-std=gnu++11" "-std=gnu++0x")
  CHECK_CXX_COMPILER_FLAG(${_cxx1x_flag} _cxx1x_flag_supported)
  if(_cxx1x_flag_supported)
    set(CXX1XCXXFLAGS ${_cxx1x_flag})
    break()
  endif()
endforeach()

include(CMakePushCheckState)
include(CheckCXXSourceCompiles)
cmake_push_check_state()
set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} ${CXX1XCXXFLAGS}")
# Check that std::future is available.
CHECK_CXX_SOURCE_COMPILES("
#include <vector>
#include <future>
int main() { std::vector<std::future<int>> v; }" HAVE_STD_FUTURE)
# Check that std::map::emplace is available for g++-4.7.
CHECK_CXX_SOURCE_COMPILES("
#include <map>
int main() { std::map<int, int>().emplace(1, 2); }" HAVE_STD_MAP_EMPLACE)
cmake_pop_check_state()


# Checks for libraries.
#
# # Additional libraries required for tests.
# TESTLDADD=
#
# # Additional libraries required for programs under src directory.
# APPLDFLAGS=
#
# case "$host" in
#   *android*)
#     android_build=yes
#     # android does not need -pthread, but needs followng 3 libs for C++
#     APPLDFLAGS="$APPLDFLAGS -lstdc++ -latomic -lsupc++"
#     ;;
#   *)
#     PTHREAD_LDFLAGS="-pthread"
#     APPLDFLAGS="$APPLDFLAGS $PTHREAD_LDFLAGS"
#     ;;
# esac

pkg_check_modules(ZLIB zlib>=1.2.3)

# # dl: openssl requires libdl when it is statically linked.
# case "${host_os}" in
#   *bsd*)
#     # dlopen is in libc on *BSD
#     ;;
#   *)
#     save_LIBS=$LIBS
#     AC_SEARCH_LIBS([dlopen], [dl], [APPLDFLAGS="-ldl $APPLDFLAGS"], [], [])
#     LIBS=$save_LIBS
#     ;;
# esac

# XXX put this in FindCUNIT.cmake
pkg_check_modules(CUNIT cunit>=2.1)
# # If pkg-config does not find cunit, check it using AC_CHECK_LIB.  We
# # do this because Debian (Ubuntu) lacks pkg-config file for cunit.
# if test "x${have_cunit}" = "xno"; then
#   AC_MSG_WARN([${CUNIT_PKG_ERRORS}])
#   AC_CHECK_LIB([cunit], [CU_initialize_registry],
#                [have_cunit=yes], [have_cunit=no])
#   if test "x${have_cunit}" = "xyes"; then
#     CUNIT_LIBS="-lcunit"
#     CUNIT_CFLAGS=""
#     AC_SUBST([CUNIT_LIBS])
#     AC_SUBST([CUNIT_CFLAGS])
#   fi
# fi
# if test "x${have_cunit}" = "xyes"; then
#   # cunit in Mac OS X requires ncurses. Note that in Mac OS X, test
#   # program can be built without -lncurses, but it emits runtime
#   # error.
#   case "${build}" in
#     *-apple-darwin*)
#       CUNIT_LIBS="$CUNIT_LIBS -lncurses"
#       AC_SUBST([CUNIT_LIBS])
#       ;;
#   esac
# fi
#
# AM_CONDITIONAL([HAVE_CUNIT], [ test "x${have_cunit}" = "xyes" ])

# # libev (for src)
# # libev does not have pkg-config file.  Check it in an old way.
# save_LIBS=$LIBS
# # android requires -lm for floor
# AC_CHECK_LIB([ev], [ev_time], [have_libev=yes], [have_libev=no], [-lm])
# if test "x${have_libev}" = "xyes"; then
#   AC_CHECK_HEADER([ev.h], [have_libev=yes], [have_libev=no])
#   if test "x${have_libev}" = "xyes"; then
#     LIBEV_LIBS=-lev
#     LIBEV_CFLAGS=
#     AC_SUBST([LIBEV_LIBS])
#     AC_SUBST([LIBEV_CFLAGS])
#   fi
# fi
# LIBS=$save_LIBS

# openssl (for src)
pkg_check_modules(OPENSSL openssl>=1.0.1)
# libevent_openssl (for examples)
# 2.0.8 is required because we use evconnlistener_set_error_cb()
pkg_check_modules(LIBEVENT_OPENSSL libevent_openssl>=2.0.8)

# jansson (for src/nghttp, src/deflatehd and src/inflatehd)
pkg_check_modules(JANSSON jansson>=2.5)
if(JANSSON_FOUND)
  set(HAVE_JANSSON 1)
endif()

# libxml2 (for src/nghttp)
if(WITH_LIBXML2)
  find_package(LibXml2 2.7.7 REQUIRED)
  set(HAVE_LIBXML2 1)
  # XXX fail if WITH_LIBXML2=ON
endif()

# jemalloc
if(WITH_JEMALLOC)
  # FIXME
# have_jemalloc=no
# if test "x${request_jemalloc}" != "xno"; then
#   save_LIBS=$LIBS
#   AC_SEARCH_LIBS([malloc_stats_print], [jemalloc], [have_jemalloc=yes], [],
#                  [$PTHREAD_LDFLAGS])
#
#   if test "x${have_jemalloc}" = "xyes"; then
#     jemalloc_libs=${ac_cv_search_malloc_stats_print}
#   else
#     # On Darwin, malloc_stats_print is je_malloc_stats_print
#     AC_SEARCH_LIBS([je_malloc_stats_print], [jemalloc], [have_jemalloc=yes], [],
#                    [$PTHREAD_LDFLAGS])
#
#     if test "x${have_jemalloc}" = "xyes"; then
#       jemalloc_libs=${ac_cv_search_je_malloc_stats_print}
#     fi
#   fi
#
#   LIBS=$save_LIBS
#
#   if test "x${have_jemalloc}" = "xyes" &&
#      test "x${jemalloc_libs}" != "xnone required"; then
#     JEMALLOC_LIBS=${jemalloc_libs}
#     AC_SUBST([JEMALLOC_LIBS])
#   fi
# fi
#
# if test "x${request_jemalloc}" = "xyes" &&
#    test "x${have_jemalloc}" != "xyes"; then
#   AC_MSG_ERROR([jemalloc was requested (--with-jemalloc) but not found])
# fi
endif()

# spdylay (for src/nghttpx and src/h2load)
if(WITH_SPDYLAY)
  pkg_check_modules(LIBSPDYLAY libspdylay>=1.3.2)
  if(LIBSPDYLAY_FOUND)
    set(HAVE_SPDYLAY 1)
  else()
    message(STATUS "The SPDY support in nghttpx and h2load will be disabled.")
  endif()
  # XXX fail if WITH_SPDYLAY=ON
endif()

# # Check Boost Asio library
# have_asio_lib=no
#
# if test "x${request_asio_lib}" = "xyes"; then
#   AX_BOOST_BASE([1.54.0], [have_boost_base=yes], [have_boost_base=no])
#
#   if test "x${have_boost_base}" = "xyes"; then
#     AX_BOOST_ASIO()
#     AX_BOOST_SYSTEM()
#     AX_BOOST_THREAD()
#
#     if test "x${ax_cv_boost_asio}" = "xyes" &&
#        test "x${ax_cv_boost_system}" = "xyes" &&
#        test "x${ax_cv_boost_thread}" = "xyes"; then
#       have_asio_lib=yes
#     fi
#   fi
# fi
#
# # The nghttp, nghttpd and nghttpx under src depend on zlib, OpenSSL
# # and libev
# enable_app=no
# if test "x${request_app}" != "xno" &&
#    test "x${have_zlib}" = "xyes" &&
#    test "x${have_openssl}" = "xyes" &&
#    test "x${have_libev}" = "xyes"; then
#   enable_app=yes
# fi
#
# if test "x${request_app}" = "xyes" &&
#    test "x${enable_app}" != "xyes"; then
#   AC_MSG_ERROR([applications were requested (--enable-app) but dependencies are not met.])
# fi
#
# AM_CONDITIONAL([ENABLE_APP], [ test "x${enable_app}" = "xyes" ])
#
# enable_hpack_tools=no
# # HPACK tools requires jansson
# if test "x${request_hpack_tools}" != "xno" &&
#    test "x${have_jansson}" = "xyes"; then
#   enable_hpack_tools=yes
# fi
#
# if test "x${request_hpack_tools}" = "xyes" &&
#    test "x${enable_hpack_tools}" != "xyes"; then
#   AC_MSG_ERROR([HPACK tools were requested (--enable-hpack-tools) but dependencies are not met.])
# fi
#
# AM_CONDITIONAL([ENABLE_HPACK_TOOLS], [ test "x${enable_hpack_tools}" = "xyes" ])
#
# # C++ library libnghttp2_asio
#
# enable_asio_lib=no
# if test "x${request_asio_lib}" != "xno" &&
#    test "x${have_asio_lib}" = "xyes"; then
#   enable_asio_lib=yes
# fi
#
# AM_CONDITIONAL([ENABLE_ASIO_LIB], [ test "x${enable_asio_lib}" = "xyes" ])
#
# # The example programs depend on OpenSSL and libevent_openssl
# enable_examples=no
# if test "x${request_examples}" != "xno" &&
#    test "x${have_openssl}" = "xyes" &&
#    test "x${have_libevent_openssl}" = "xyes"; then
#   enable_examples=yes
# fi
#
# if test "x${request_examples}" = "xyes" &&
#    test "x${enable_examples}" != "xyes"; then
#   AC_MSG_ERROR([examples were requested (--enable-examples) but dependencies are not met.])
# fi
#
# AM_CONDITIONAL([ENABLE_EXAMPLES], [ test "x${enable_examples}" = "xyes" ])
#
# # third-party only be built when needed
#
# enable_third_party=no
# have_mruby=no
# have_neverbleed=no
# if test "x${enable_examples}" = "xyes" ||
#    test "x${enable_app}" = "xyes" ||
#    test "x${enable_hpack_tools}" = "xyes" ||
#    test "x${enable_asio_lib}" = "xyes"; then
#   enable_third_party=yes
#
#   # mruby (for src/nghttpx)
#   if test "x${request_mruby}" = "xyes"; then
#     # We are going to build mruby
#     have_mruby=yes
#     AC_DEFINE([HAVE_MRUBY], [1], [Define to 1 if you have `mruby` library.])
#     LIBMRUBY_LIBS="-lmruby -lm"
#     LIBMRUBY_CFLAGS=
#     AC_SUBST([LIBMRUBY_LIBS])
#     AC_SUBST([LIBMRUBY_CFLAGS])
#   fi
#
#   # neverbleed (for src/nghttpx)
#   if test "x${request_neverbleed}" = "xyes"; then
#     have_neverbleed=yes
#     AC_DEFINE([HAVE_NEVERBLEED], [1], [Define to 1 if you have `neverbleed` library.])
#   fi
# fi
#
# AM_CONDITIONAL([ENABLE_THIRD_PARTY], [ test "x${enable_third_party}" = "xyes" ])
# AM_CONDITIONAL([HAVE_MRUBY], [test "x${have_mruby}" = "xyes"])
# AM_CONDITIONAL([HAVE_NEVERBLEED], [test "x${have_neverbleed}" = "xyes"])
#
# # Python bindings
# enable_python_bindings=no
# if test "x${request_python_bindings}" != "xno" &&
#    test "x${CYTHON}" != "x" &&
#    test "x${PYTHON}" != "x:" &&
#    test "x${have_python_dev}" = "xyes"; then
#   enable_python_bindings=yes
# fi
#
# if test "x${request_python_bindings}" = "xyes" &&
#    test "x${enable_python_bindings}" != "xyes"; then
#   AC_MSG_ERROR([python bindings were requested (--enable-python-bindings) but dependencies are not met.])
# fi
#
# AM_CONDITIONAL([ENABLE_PYTHON_BINDINGS],
#                [test "x${enable_python_bindings}" = "xyes"])
#
# # Produce cython conditional, so that we can distribute generated C
# # source
# AM_CONDITIONAL([HAVE_CYTHON], [test "x${CYTHON}" != "x"])
#
# # failmalloc tests
# enable_failmalloc=no
# if test "x${request_failmalloc}" = "xyes"; then
#   enable_failmalloc=yes
# fi
#
# AM_CONDITIONAL([ENABLE_FAILMALLOC], [ test "x${enable_failmalloc}" = "xyes" ])
#
# # Checks for header files.
# AC_HEADER_ASSERT
# AC_CHECK_HEADERS([ \
#   arpa/inet.h \
#   fcntl.h \
#   inttypes.h \
#   limits.h \
#   netdb.h \
#   netinet/in.h \
#   pwd.h \
#   stddef.h \
#   stdint.h \
#   stdlib.h \
#   string.h \
#   sys/socket.h \
#   sys/time.h \
#   syslog.h \
#   time.h \
#   unistd.h \
# ])
#
# # Checks for typedefs, structures, and compiler characteristics.
# AC_TYPE_SIZE_T
# AC_TYPE_SSIZE_T
# AC_TYPE_UINT8_T
# AC_TYPE_UINT16_T
# AC_TYPE_UINT32_T
# AC_TYPE_UINT64_T
# AC_TYPE_INT8_T
# AC_TYPE_INT16_T
# AC_TYPE_INT32_T
# AC_TYPE_INT64_T
# AC_TYPE_OFF_T
# AC_TYPE_PID_T
# AC_TYPE_UID_T
# AC_CHECK_TYPES([ptrdiff_t])
# AC_C_BIGENDIAN
# AC_C_INLINE
# AC_SYS_LARGEFILE
#
# AC_CHECK_MEMBER([struct tm.tm_gmtoff], [have_struct_tm_tm_gmtoff=yes],
#                 [have_struct_tm_tm_gmtoff=no], [[#include <time.h>]])
#
# if test "x$have_struct_tm_tm_gmtoff" = "xyes"; then
#   AC_DEFINE([HAVE_STRUCT_TM_TM_GMTOFF], [1],
#             [Define to 1 if you have `struct tm.tm_gmtoff` member.])
# fi
#
# # Check size of pointer to decide we need 8 bytes alignment
# # adjustment.
# AC_CHECK_SIZEOF([int *])
#
# AC_CHECK_SIZEOF([time_t])
#
# # Checks for library functions.
#
# # Don't check malloc, since it does not play nicely with C++ stdlib
# # AC_FUNC_MALLOC
#
# AC_FUNC_CHOWN
# AC_FUNC_ERROR_AT_LINE
# AC_FUNC_FORK
# # Don't check realloc, since LeakSanitizer detects memory leak during check
# # AC_FUNC_REALLOC
# AC_FUNC_STRERROR_R
# AC_FUNC_STRNLEN
#
# AC_CHECK_FUNCS([ \
#   _Exit \
#   accept4 \
#   dup2 \
#   getcwd \
#   getpwnam \
#   localtime_r \
#   memchr \
#   memmove \
#   memset \
#   socket \
#   sqrt \
#   strchr \
#   strdup \
#   strerror \
#   strndup \
#   strstr \
#   strtol \
#   strtoul \
#   timegm \
# ])
#
# # timerfd_create was added in linux kernel 2.6.25
#
# AC_CHECK_FUNC([timerfd_create],
#               [have_timerfd_create=yes], [have_timerfd_create=no])
#
# # For cygwin: we can link initgroups, so AC_CHECK_FUNCS succeeds, but
# # cygwin disables initgroups due to feature test macro magic with our
# # configuration.
# AC_CHECK_DECLS([initgroups], [], [], [[#include <grp.h>]])
#
# # Checks for epoll availability, primarily for examples/tiny-nghttpd
# AX_HAVE_EPOLL([have_epoll=yes], [have_epoll=no])
#
# AM_CONDITIONAL([ENABLE_TINY_NGHTTPD],
#                [ test "x${have_epoll}" = "xyes" &&
#                  test "x${have_timerfd_create}" = "xyes"])
#
# save_CFLAGS=$CFLAGS
# save_CXXFLAGS=$CXXFLAGS
#
# CFLAGS=
# CXXFLAGS=
#
# if test "x$werror" != "xno"; then
#     # For C compiler
#     AX_CHECK_COMPILE_FLAG([-Wall], [CFLAGS="$CFLAGS -Wall"])
#     AX_CHECK_COMPILE_FLAG([-Wextra], [CFLAGS="$CFLAGS -Wextra"])
#     AX_CHECK_COMPILE_FLAG([-Werror], [CFLAGS="$CFLAGS -Werror"])
#     AX_CHECK_COMPILE_FLAG([-Wmissing-prototypes], [CFLAGS="$CFLAGS -Wmissing-prototypes"])
#     AX_CHECK_COMPILE_FLAG([-Wstrict-prototypes], [CFLAGS="$CFLAGS -Wstrict-prototypes"])
#     AX_CHECK_COMPILE_FLAG([-Wmissing-declarations], [CFLAGS="$CFLAGS -Wmissing-declarations"])
#     AX_CHECK_COMPILE_FLAG([-Wpointer-arith], [CFLAGS="$CFLAGS -Wpointer-arith"])
#     AX_CHECK_COMPILE_FLAG([-Wdeclaration-after-statement], [CFLAGS="$CFLAGS -Wdeclaration-after-statement"])
#     AX_CHECK_COMPILE_FLAG([-Wformat-security], [CFLAGS="$CFLAGS -Wformat-security"])
#     AX_CHECK_COMPILE_FLAG([-Wwrite-strings], [CFLAGS="$CFLAGS -Wwrite-strings"])
#     AX_CHECK_COMPILE_FLAG([-Wshadow], [CFLAGS="$CFLAGS -Wshadow"])
#     AX_CHECK_COMPILE_FLAG([-Winline], [CFLAGS="$CFLAGS -Winline"])
#     AX_CHECK_COMPILE_FLAG([-Wnested-externs], [CFLAGS="$CFLAGS -Wnested-externs"])
#     AX_CHECK_COMPILE_FLAG([-Wfloat-equal], [CFLAGS="$CFLAGS -Wfloat-equal"])
#     AX_CHECK_COMPILE_FLAG([-Wundef], [CFLAGS="$CFLAGS -Wundef"])
#     AX_CHECK_COMPILE_FLAG([-Wendif-labels], [CFLAGS="$CFLAGS -Wendif-labels"])
#     AX_CHECK_COMPILE_FLAG([-Wempty-body], [CFLAGS="$CFLAGS -Wempty-body"])
#     AX_CHECK_COMPILE_FLAG([-Wcast-align], [CFLAGS="$CFLAGS -Wcast-align"])
#     AX_CHECK_COMPILE_FLAG([-Wclobbered], [CFLAGS="$CFLAGS -Wclobbered"])
#     AX_CHECK_COMPILE_FLAG([-Wvla], [CFLAGS="$CFLAGS -Wvla"])
#     AX_CHECK_COMPILE_FLAG([-Wpragmas], [CFLAGS="$CFLAGS -Wpragmas"])
#     AX_CHECK_COMPILE_FLAG([-Wunreachable-code], [CFLAGS="$CFLAGS -Wunreachable-code"])
#     AX_CHECK_COMPILE_FLAG([-Waddress], [CFLAGS="$CFLAGS -Waddress"])
#     AX_CHECK_COMPILE_FLAG([-Wattributes], [CFLAGS="$CFLAGS -Wattributes"])
#     AX_CHECK_COMPILE_FLAG([-Wdiv-by-zero], [CFLAGS="$CFLAGS -Wdiv-by-zero"])
#     AX_CHECK_COMPILE_FLAG([-Wshorten-64-to-32], [CFLAGS="$CFLAGS -Wshorten-64-to-32"])
#
#     AX_CHECK_COMPILE_FLAG([-Wconversion], [CFLAGS="$CFLAGS -Wconversion"])
#     AX_CHECK_COMPILE_FLAG([-Wextended-offsetof], [CFLAGS="$CFLAGS -Wextended-offsetof"])
#     AX_CHECK_COMPILE_FLAG([-Wformat-nonliteral], [CFLAGS="$CFLAGS -Wformat-nonliteral"])
#     AX_CHECK_COMPILE_FLAG([-Wlanguage-extension-token], [CFLAGS="$CFLAGS -Wlanguage-extension-token"])
#     AX_CHECK_COMPILE_FLAG([-Wmissing-field-initializers], [CFLAGS="$CFLAGS -Wmissing-field-initializers"])
#     AX_CHECK_COMPILE_FLAG([-Wmissing-noreturn], [CFLAGS="$CFLAGS -Wmissing-noreturn"])
#     AX_CHECK_COMPILE_FLAG([-Wmissing-variable-declarations], [CFLAGS="$CFLAGS -Wmissing-variable-declarations"])
#     # Not used because we cannot change public structs
#     # AX_CHECK_COMPILE_FLAG([-Wpadded], [CFLAGS="$CFLAGS -Wpadded"])
#     AX_CHECK_COMPILE_FLAG([-Wsign-conversion], [CFLAGS="$CFLAGS -Wsign-conversion"])
#     # Not used because this basically disallows default case
#     # AX_CHECK_COMPILE_FLAG([-Wswitch-enum], [CFLAGS="$CFLAGS -Wswitch-enum"])
#     AX_CHECK_COMPILE_FLAG([-Wunreachable-code-break], [CFLAGS="$CFLAGS -Wunreachable-code-break"])
#     AX_CHECK_COMPILE_FLAG([-Wunused-macros], [CFLAGS="$CFLAGS -Wunused-macros"])
#     AX_CHECK_COMPILE_FLAG([-Wunused-parameter], [CFLAGS="$CFLAGS -Wunused-parameter"])
#     AX_CHECK_COMPILE_FLAG([-Wredundant-decls], [CFLAGS="$CFLAGS -Wredundant-decls"])
#     # Only work with Clang for the moment
#     AX_CHECK_COMPILE_FLAG([-Wheader-guard], [CFLAGS="$CFLAGS -Wheader-guard"])
#
#     # For C++ compiler
#     AC_LANG_PUSH(C++)
#     AX_CHECK_COMPILE_FLAG([-Wall], [CXXFLAGS="$CXXFLAGS -Wall"])
#     AX_CHECK_COMPILE_FLAG([-Werror], [CXXFLAGS="$CXXFLAGS -Werror"])
#     AX_CHECK_COMPILE_FLAG([-Wformat-security], [CXXFLAGS="$CXXFLAGS -Wformat-security"])
#     AC_LANG_POP()
# fi
#
# WARNCFLAGS=$CFLAGS
# WARNCXXFLAGS=$CXXFLAGS
#
# CFLAGS=$save_CFLAGS
# CXXFLAGS=$save_CXXFLAGS
#
# AC_SUBST([WARNCFLAGS])
# AC_SUBST([WARNCXXFLAGS])
#
# EXTRACFLAG=
# AX_CHECK_COMPILE_FLAG([-fvisibility=hidden], [EXTRACFLAG="-fvisibility=hidden"])
#
# AC_SUBST([EXTRACFLAG])
#
# if test "x$debug" != "xno"; then
#     AC_DEFINE([DEBUGBUILD], [1], [Define to 1 to enable debug output.])
# fi
#
# enable_threads=yes
# # Some platform does not have working std::future.  We disable
# # threading for those platforms.
# if test "x$threads" != "xyes" ||
#    test "x$have_std_future" != "xyes"; then
#     enable_threads=no
#     AC_DEFINE([NOTHREADS], [1], [Define to 1 if you want to disable threads.])
# fi
#
# # propagate $enable_static to tests/Makefile.am
# AM_CONDITIONAL([ENABLE_STATIC], [test "x$enable_static" = "xyes"])
#
# AC_SUBST([TESTLDADD])
# AC_SUBST([APPLDFLAGS])
#
# AC_CONFIG_FILES([
#   Makefile
#   lib/Makefile
#   lib/libnghttp2.pc
#   lib/includes/Makefile
#   lib/includes/nghttp2/nghttp2ver.h
#   tests/Makefile
#   tests/testdata/Makefile
#   third-party/Makefile
#   src/Makefile
#   src/includes/Makefile
#   src/libnghttp2_asio.pc
#   examples/Makefile
#   python/Makefile
#   python/setup.py
#   integration-tests/Makefile
#   integration-tests/config.go
#   integration-tests/setenv
#   doc/Makefile
#   doc/conf.py
#   doc/index.rst
#   doc/package_README.rst
#   doc/tutorial-client.rst
#   doc/tutorial-server.rst
#   doc/tutorial-hpack.rst
#   doc/nghttpx-howto.rst
#   doc/h2load-howto.rst
#   doc/libnghttp2_asio.rst
#   doc/python-apiref.rst
#   doc/building-android-binary.rst
#   doc/nghttp2.h.rst
#   doc/nghttp2ver.h.rst
#   doc/asio_http2.h.rst
#   doc/asio_http2_server.h.rst
#   doc/asio_http2_client.h.rst
#   doc/contribute.rst
#   contrib/Makefile
#   script/Makefile
# ])
# AC_OUTPUT
#
# AC_MSG_NOTICE([summary of build options:
#
#     Package version: ${VERSION}
#     Library version: $LT_CURRENT:$LT_REVISION:$LT_AGE
#     Install prefix:  ${prefix}
#     System types:
#       Build:         ${build}
#       Host:          ${host}
#       Target:        ${target}
#     Compiler:
#       C compiler:     ${CC}
#       CFLAGS:         ${CFLAGS}
#       LDFLAGS:        ${LDFLAGS}
#       C++ compiler:   ${CXX}
#       CXXFLAGS:       ${CXXFLAGS}
#       CXXCPP:         ${CXXCPP}
#       C preprocessor: ${CPP}
#       CPPFLAGS:       ${CPPFLAGS}
#       WARNCFLAGS:     ${WARNCFLAGS}
#       CXX1XCXXFLAGS:  ${CXX1XCXXFLAGS}
#       EXTRACFLAG:     ${EXTRACFLAG}
#       LIBS:           ${LIBS}
#     Library:
#       Shared:         ${enable_shared}
#       Static:         ${enable_static}
#     Python:
#       Python:         ${PYTHON}
#       PYTHON_VERSION: ${PYTHON_VERSION}
#       pyexecdir:      ${pyexecdir}
#       Python-dev:     ${have_python_dev}
#       PYTHON_CPPFLAGS:${PYTHON_CPPFLAGS}
#       PYTHON_LDFLAGS: ${PYTHON_LDFLAGS}
#       Cython:         ${CYTHON}
#     Test:
#       CUnit:          ${have_cunit} (CFLAGS='${CUNIT_CFLAGS}' LIBS='${CUNIT_LIBS}')
#       Failmalloc:     ${enable_failmalloc}
#     Libs:
#       OpenSSL:        ${have_openssl} (CFLAGS='${OPENSSL_CFLAGS}' LIBS='${OPENSSL_LIBS}')
#       Libxml2:        ${have_libxml2} (CFLAGS='${XML_CPPFLAGS}' LIBS='${XML_LIBS}')
#       Libev:          ${have_libev} (CFLAGS='${LIBEV_CFLAGS}' LIBS='${LIBEV_LIBS}')
#       Libevent(SSL):  ${have_libevent_openssl} (CFLAGS='${LIBEVENT_OPENSSL_CFLAGS}' LIBS='${LIBEVENT_OPENSSL_LIBS}')
#       Spdylay:        ${have_spdylay} (CFLAGS='${LIBSPDYLAY_CFLAGS}' LIBS='${LIBSPDYLAY_LIBS}')
#       Jansson:        ${have_jansson} (CFLAGS='${JANSSON_CFLAGS}' LIBS='${JANSSON_LIBS}')
#       Jemalloc:       ${have_jemalloc} (LIBS='${JEMALLOC_LIBS}')
#       Zlib:           ${have_zlib} (CFLAGS='${ZLIB_CFLAGS}' LIBS='${ZLIB_LIBS}')
#       Boost CPPFLAGS: ${BOOST_CPPFLAGS}
#       Boost LDFLAGS:  ${BOOST_LDFLAGS}
#       Boost::ASIO:    ${BOOST_ASIO_LIB}
#       Boost::System:  ${BOOST_SYSTEM_LIB}
#       Boost::Thread:  ${BOOST_THREAD_LIB}
#     Third-party:
#       http-parser:    ${enable_third_party}
#       MRuby:          ${have_mruby} (CFLAGS='${LIBMRUBY_CFLAGS}' LIBS='${LIBMRUBY_LIBS}')
#       Neverbleed:     ${have_neverbleed}
#     Features:
#       Applications:   ${enable_app}
#       HPACK tools:    ${enable_hpack_tools}
#       Libnghttp2_asio:${enable_asio_lib}
#       Examples:       ${enable_examples}
#       Python bindings:${enable_python_bindings}
#       Threading:      ${enable_threads}
# ])
