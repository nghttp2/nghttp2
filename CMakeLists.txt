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

# See versioning rule:
#  http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
set(LT_CURRENT  18)
set(LT_REVISION 1)
set(LT_AGE      4)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(Version)

math(EXPR LT_SOVERSION "${LT_CURRENT} - ${LT_AGE}")
set(LT_VERSION "${LT_SOVERSION}.${LT_AGE}.${LT_REVISION}")
set(PACKAGE_VERSION     "${PROJECT_VERSION}")
HexVersion(PACKAGE_VERSION_NUM ${PROJECT_VERSION_MAJOR} ${PROJECT_VERSION_MINOR} ${PROJECT_VERSION_PATCH})

include(GNUInstallDirs)

# XXX "check" is treated as "OFF" now, consider detecting it first
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
# For Python bindings and documentation
find_package(PythonInterp)
# XXX fail only when "ON" instead of "CHECK"?
if(ENABLE_PYTHON_BINDINGS)
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

include(ExtractValidFlags)
foreach(_cxx1x_flag -std=gnu++11 -std=gnu++0x)
  extract_valid_cxx_flags(_cxx1x_flag_supported ${_cxx1x_flag})
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
check_cxx_source_compiles("
#include <vector>
#include <future>
int main() { std::vector<std::future<int>> v; }" HAVE_STD_FUTURE)
# Check that std::map::emplace is available for g++-4.7.
check_cxx_source_compiles("
#include <map>
int main() { std::map<int, int>().emplace(1, 2); }" HAVE_STD_MAP_EMPLACE)
cmake_pop_check_state()


# Checks for libraries.
# Additional libraries required for tests.
set(TEST_LIBRARIES)
# Additional libraries required for programs under src directory.
set(APP_LIBRARIES)

set(CMAKE_THREAD_PREFER_PTHREAD 1)
find_package(Threads)
if(CMAKE_USE_PTHREADS_INIT)
  list(APPEND APP_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})
endif()
# XXX android and C++, is this still needed in cmake?
# case "$host" in
#   *android*)
#     android_build=yes
#     # android does not need -pthread, but needs followng 3 libs for C++
#     APPLDFLAGS="$APPLDFLAGS -lstdc++ -latomic -lsupc++"

pkg_check_modules(ZLIB zlib>=1.2.3)
if(ZLIB_FOUND)
  set(HAVE_ZLIB 1)
else()
  set(HAVE_ZLIB 0)
endif()

# dl: openssl requires libdl when it is statically linked.
# XXX shouldn't ${CMAKE_DL_LIBS} be appended to OPENSSL_LIBRARIES instead of
# APP_LIBRARIES if it is really specific to OpenSSL?

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

# libev (for src)
find_package(Libev)
if(Libev_FOUND)
  set(HAVE_LIBEV 1)
else()
  set(HAVE_LIBEV 0)
endif()

# openssl (for src)
pkg_check_modules(OPENSSL openssl>=1.0.1)
# for find_package, replace OPENSSL_INCLUDE_DIRS by OPENSSL_INCLUDE_DIR
#find_package(OpenSSL 1.0.1)
if(OPENSSL_FOUND)
  set(HAVE_OPENSSL 1)
else()
  set(HAVE_OPENSSL 0)
endif()
# libevent_openssl (for examples)
# 2.0.8 is required because we use evconnlistener_set_error_cb()
pkg_check_modules(LIBEVENT_OPENSSL libevent_openssl>=2.0.8)
if(LIBEVENT_OPENSSL_FOUND)
  set(HAVE_LIBEVENT_OPENSSL 1)
else()
  set(HAVE_LIBEVENT_OPENSSL 0)
endif()

# jansson (for src/nghttp, src/deflatehd and src/inflatehd)
pkg_check_modules(JANSSON jansson>=2.5)
if(JANSSON_FOUND)
  set(HAVE_JANSSON 1)
else()
  set(HAVE_JANSSON 0)
endif()

# libxml2 (for src/nghttp)
if(WITH_LIBXML2)
  find_package(LibXml2 2.7.7 REQUIRED)
  set(HAVE_LIBXML2 1)
  # XXX fail if WITH_LIBXML2=ON
else()
  set(HAVE_LIBXML2 0)
endif()

# jemalloc
if(WITH_JEMALLOC)
  pkg_check_modules(JEMALLOC jemalloc)
  if(NOT JEMALLOC_FOUND)
    find_package(jemalloc REQUIRED)
  endif()
  if(JEMALLOC_FOUND)
    set(HAVE_JEMALLOC 1)
  else()
    set(HAVE_JEMALLOC 0)
  endif()
else()
  set(HAVE_JEMALLOC 0)
endif()

# spdylay (for src/nghttpx and src/h2load)
if(WITH_SPDYLAY)
  pkg_check_modules(LIBSPDYLAY libspdylay>=1.3.2)
  if(LIBSPDYLAY_FOUND)
    set(HAVE_SPDYLAY 1)
  else()
    set(HAVE_SPDYLAY 0)
    message(STATUS "The SPDY support in nghttpx and h2load will be disabled.")
  endif()
  # XXX fail if WITH_SPDYLAY=ON
else()
  set(HAVE_SPDYLAY 0)
endif()

if(ENABLE_ASIO_LIB)
  find_package(Boost 1.54.0 REQUIRED system thread)
endif()

# The nghttp, nghttpd and nghttpx under src depend on zlib, OpenSSL and libev
if(ENABLE_APP AND NOT (ZLIB_FOUND AND OPENSSL_FOUND AND LIBEV_FOUND))
  message(FATAL_ERROR "Applications were requested (ENABLE_APP=1) but dependencies are not met.")
endif()

# HPACK tools requires jansson
if(ENABLE_HPACK_TOOLS AND NOT HAVE_JANSSON)
  message(FATAL_ERROR "HPACK tools were requested (ENABLE_HPACK_TOOLS=1) but dependencies are not met.")
endif()

# C++ library libnghttp2_asio
if(ENABLE_EXAMPLES AND NOT (OPENSSL_FOUND AND LIBEVENT_OPENSSL_FOUND))
  message(FATAL_ERROR "examples were requested (--enable-examples) but dependencies are not met.")
endif()

# third-party http-parser only be built when needed
if(ENABLE_EXAMPLES OR ENABLE_APP OR ENABLE_HPACK_TOOLS OR ENABLE_ASIO_LIB)
  set(ENABLE_THIRD_PARTY 1)
  # mruby (for src/nghttpx)
  if(WITH_MRUBY)
    set(HAVE_MRUBY 1)
    # XXX add -lmruby and -lm libs
  else()
    set(HAVE_MRUBY 0)
  endif()
  if(WITH_NEVERBLEED)
    set(HAVE_NEVERBLEED 1)
  else()
    set(HAVE_NEVERBLEED 0)
  endif()
else()
  set(HAVE_MRUBY 0)
  set(HAVE_NEVERBLEED 0)
endif()

# Python bindings
if(ENABLE_PYTHON_BINDINGS AND NOT CYTHON AND NOT PYTHONLIBS_FOUND)
# XXX PythonInterp and PythonLibs are looked up before, unreachable check?
# if test "x${request_python_bindings}" != "xno" &&
#    test "x${CYTHON}" != "x" &&
#    test "x${PYTHON}" != "x:" &&
#    test "x${have_python_dev}" = "xyes"; then
  message(FATAL_ERROR "python bindings were requested (ENABLE_PYTHON_BINDINGS=1) but dependencies are not met.")
endif()

# Checks for header files.
# XXX AC_HEADER_ASSERT adds --disable-assert which sets -DNDEBUG
include(CheckIncludeFile)
check_include_file("arpa/inet.h"    HAVE_ARPA_INET_H)
check_include_file("fcntl.h"        HAVE_FCNTL_H)
check_include_file("inttypes.h"     HAVE_INTTYPES_H)
check_include_file("limits.h"       HAVE_LIMITS_H)
check_include_file("netdb.h"        HAVE_NETDB_H)
check_include_file("netinet/in.h"   HAVE_NETINET_IN_H)
check_include_file("pwd.h"          HAVE_PWD_H)
check_include_file("sys/socket.h"   HAVE_SYS_SOCKET_H)
check_include_file("sys/time.h"     HAVE_SYS_TIME_H)
check_include_file("syslog.h"       HAVE_SYSLOG_H)
check_include_file("time.h"         HAVE_TIME_H)
check_include_file("unistd.h"       HAVE_UNISTD_H)

# Checks for typedefs, structures, and compiler characteristics.
# XXX The AC_TYPE_* macros would define suitable types if standard headers do
# not define them. No equivalent in cmake...
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
# XXX To support inline for crappy compilers, see https://cmake.org/Wiki/CMakeTestInline
# AC_C_INLINE
# XXX is AC_SYS_LARGEFILE still needed for modern systems?
# add_definitions(-D_FILE_OFFSET_BITS=64)

include(CheckStructHasMember)
check_struct_has_member("struct tm" tm_gmtoff time.h HAVE_STRUCT_TM_TM_GMTOFF)

# Check size of pointer to decide we need 8 bytes alignment adjustment.
include(CheckTypeSize)
check_type_size("int *"   SIZEOF_INT_P)
check_type_size("time_t"  SIZEOF_TIME_T)

# Checks for library functions.
include(CheckFunctionExists)
check_function_exists(_Exit     HAVE__EXIT)
check_function_exists(accept4   HAVE_ACCEPT4)

# timerfd_create was added in linux kernel 2.6.25
include(CheckSymbolExists)
# XXX does this correctly detect initgroups (un)availability on cygwin?
check_symbol_exists(initgroups grp.h HAVE_DECL_INITGROUPS)

check_function_exists(timerfd_create HAVE_TIMERFD_CREATE)
# Checks for epoll availability, primarily for examples/tiny-nghttpd
check_symbol_exists(epoll_create sys/epoll.h HAVE_EPOLL)
if(HAVE_EPOLL AND HAVE_TIMERFD_CREATE)
  set(ENABLE_TINY_NGHTTPD 1)
endif()

if(ENABLE_WERROR)
  # For C compiler
  extract_valid_c_flags(WARNCFLAGS
    -Wall
    -Wextra
    -Werror
    -Wmissing-prototypes
    -Wstrict-prototypes
    -Wmissing-declarations
    -Wpointer-arith
    -Wdeclaration-after-statement
    -Wformat-security
    -Wwrite-strings
    -Wshadow
    -Winline
    -Wnested-externs
    -Wfloat-equal
    -Wundef
    -Wendif-labels
    -Wempty-body
    -Wcast-align
    -Wclobbered
    -Wvla
    -Wpragmas
    -Wunreachable-code
    -Waddress
    -Wattributes
    -Wdiv-by-zero
    -Wshorten-64-to-32

    -Wconversion
    -Wextended-offsetof
    -Wformat-nonliteral
    -Wlanguage-extension-token
    -Wmissing-field-initializers
    -Wmissing-noreturn
    -Wmissing-variable-declarations
    # Not used because we cannot change public structs
    # -Wpadded
    -Wsign-conversion
    # Not used because this basically disallows default case
    # -Wswitch-enum
    -Wunreachable-code-break
    -Wunused-macros
    -Wunused-parameter
    -Wredundant-decls
    # Only work with Clang for the moment
    -Wheader-guard
  )

  extract_valid_cxx_flags(WARNCXXFLAGS
    # For C++ compiler
    -Wall
    -Werror
    -Wformat-security
  )
endif()

extract_valid_c_flags(EXTRACFLAG
  -fvisibility=hidden
)

if(ENABLE_DEBUG)
  set(DEBUGBUILD 1)
endif()

# Some platform does not have working std::future.  We disable
# threading for those platforms.
if(NOT ENABLE_THREADS OR NOT HAVE_STD_FUTURE)
  set(NOTHREADS 1)
endif()

# # propagate $enable_static to tests/Makefile.am
# AM_CONDITIONAL([ENABLE_STATIC], [test "x$enable_static" = "xyes"])
#
# AC_SUBST([TESTLDADD])
# AC_SUBST([APPLDFLAGS])

add_definitions(-DHAVE_CONFIG_H)
configure_file(cmakeconfig.h.in config.h)
# autotools-compatible names
# Sphinx expects relative paths in the .rst files. Use the fact that the files
# below are all one directory level deep.
file(RELATIVE_PATH top_srcdir   "${CMAKE_BINARY_DIR}/dir" "${CMAKE_SOURCE_DIR}")
file(RELATIVE_PATH top_builddir "${CMAKE_BINARY_DIR}/dir" "${CMAKE_BINARY_DIR}")
set(abs_top_srcdir  "${CMAKE_SOURCE_DIR}")
set(abs_top_builddir "${CMAKE_BINARY_DIR}")
# libnghttp2.pc (pkg-config file)
set(prefix          "${CMAKE_INSTALL_PREFIX}")
set(exec_prefix     "${CMAKE_INSTALL_PREFIX}")
set(libdir          "${CMAKE_INSTALL_FULL_LIBDIR}")
set(includedir      "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
set(VERSION         "${PACKAGE_VERSION}")
# For init scripts and systemd service file
set(bindir          "${CMAKE_INSTALL_FULL_BINDIR}")
set(sbindir         "${CMAKE_INSTALL_FULL_SBINDIR}")
foreach(name
   lib/libnghttp2.pc
   lib/includes/nghttp2/nghttp2ver.h
   src/libnghttp2_asio.pc
   python/setup.py
   integration-tests/config.go
   integration-tests/setenv
   doc/conf.py
   doc/index.rst
   doc/package_README.rst
   doc/tutorial-client.rst
   doc/tutorial-server.rst
   doc/tutorial-hpack.rst
   doc/nghttpx-howto.rst
   doc/h2load-howto.rst
   doc/libnghttp2_asio.rst
   doc/python-apiref.rst
   doc/building-android-binary.rst
   doc/nghttp2.h.rst
   doc/nghttp2ver.h.rst
   doc/asio_http2.h.rst
   doc/asio_http2_server.h.rst
   doc/asio_http2_client.h.rst
   doc/contribute.rst
)
  configure_file("${name}.in" "${name}" @ONLY)
endforeach()

include_directories(
  "${CMAKE_BINARY_DIR}" # for config.h
)
# For use in src/CMakeLists.txt
set(PKGDATADIR "${CMAKE_INSTALL_FULL_DATADIR}/${CMAKE_PROJECT_NAME}")

add_subdirectory(lib)
#add_subdirectory(lib/includes)
add_subdirectory(third-party)
add_subdirectory(src)
#add_subdirectory(src/includes)
add_subdirectory(examples)
add_subdirectory(python)
if(0)
add_subdirectory(tests)
#add_subdirectory(tests/testdata)
add_subdirectory(integration-tests)
endif()
add_subdirectory(doc)
if(0)
add_subdirectory(contrib)
add_subdirectory(script)
endif()


# XXX - fix list of variables
message(STATUS "summary of build options:

    Package version: ${VERSION}
    Library version: ${LT_CURRENT}:${LT_REVISION}:${LT_AGE}
    Install prefix:  ${prefix}
    System types:
      Build:         ${build}
      Host:          ${host}
      Target:        ${target}
    Compiler:
    C compiler:       ${CMAKE_C_COMPILER}
      CFLAGS:         ${CMAKE_C_FLAGS}
      C++ compiler:   ${CMAKE_CXX_COMPILER}
      CXXFLAGS:       ${CMAKE_CXX_FLAGS}
      WARNCFLAGS:     ${WARNCFLAGS}
      CXX1XCXXFLAGS:  ${CXX1XCXXFLAGS}
      EXTRACFLAG:     ${EXTRACFLAG}
      LIBS:           ${LIBS}
    Library:
      Shared:         ${enable_shared}
      Static:         ${enable_static}
    Python:
      Python:         ${PYTHON}
      PYTHON_VERSION: ${PYTHON_VERSION}
      pyexecdir:      ${pyexecdir}
      Python-dev:     ${have_python_dev}
      PYTHON_CPPFLAGS:${PYTHON_CPPFLAGS}
      PYTHON_LDFLAGS: ${PYTHON_LDFLAGS}
      Cython:         ${CYTHON}
    Test:
      CUnit:          ${HAVE_CUNIT} (CFLAGS='${CUNIT_CFLAGS}' LIBS='${CUNIT_LIBS}')
      Failmalloc:     ${ENABLE_FAILMALLOC}
    Libs:
      OpenSSL:        ${HAVE_OPENSSL} (CFLAGS='${OPENSSL_CFLAGS}' LIBS='${OPENSSL_LIBS}')
      Libxml2:        ${HAVE_LIBXML2} (CFLAGS='${XML_CPPFLAGS}' LIBS='${XML_LIBS}')
      Libev:          ${HAVE_LIBEV} (CFLAGS='${LIBEV_CFLAGS}' LIBS='${LIBEV_LIBS}')
      Libevent(SSL):  ${HAVE_LIBEVENT_OPENSSL} (CFLAGS='${LIBEVENT_OPENSSL_CFLAGS}' LIBS='${LIBEVENT_OPENSSL_LIBS}')
      Spdylay:        ${HAVE_SPDYLAY} (CFLAGS='${LIBSPDYLAY_CFLAGS}' LIBS='${LIBSPDYLAY_LIBS}')
      Jansson:        ${HAVE_JANSSON} (CFLAGS='${JANSSON_CFLAGS}' LIBS='${JANSSON_LIBS}')
      Jemalloc:       ${HAVE_JEMALLOC} (LIBS='${JEMALLOC_LIBS}')
      Zlib:           ${HAVE_ZLIB} (CFLAGS='${ZLIB_CFLAGS}' LIBS='${ZLIB_LIBS}')
      Boost CPPFLAGS: ${BOOST_CPPFLAGS}
      Boost LDFLAGS:  ${BOOST_LDFLAGS}
      Boost::ASIO:    ${BOOST_ASIO_LIB}
      Boost::System:  ${BOOST_SYSTEM_LIB}
      Boost::Thread:  ${BOOST_THREAD_LIB}
    Third-party:
      http-parser:    ${ENABLE_THIRD_PARTY}
      MRuby:          ${HAVE_MRUBY} (CFLAGS='${LIBMRUBY_CFLAGS}' LIBS='${LIBMRUBY_LIBS}')
      Neverbleed:     ${HAVE_NEVERBLEED}
    Features:
      Applications:   ${ENABLE_APP}
      HPACK tools:    ${ENABLE_HPACK_TOOLS}
      Libnghttp2_asio:${ENABLE_ASIO_LIB}
      Examples:       ${ENABLE_EXAMPLES}
      Python bindings:${ENABLE_PYTHON_BINDINGS}
      Threading:      ${ENABLE_THREADS}
")
