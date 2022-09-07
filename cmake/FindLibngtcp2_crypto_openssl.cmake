# - Try to find libngtcp2_crypto_openssl
# Once done this will define
#  LIBNGTCP2_CRYPTO_OPENSSL_FOUND        - System has libngtcp2_crypto_openssl
#  LIBNGTCP2_CRYPTO_OPENSSL_INCLUDE_DIRS - The libngtcp2_crypto_openssl include directories
#  LIBNGTCP2_CRYPTO_OPENSSL_LIBRARIES    - The libraries needed to use libngtcp2_crypto_openssl

find_package(PkgConfig QUIET)
pkg_check_modules(PC_LIBNGTCP2_CRYPTO_OPENSSL QUIET libngtcp2_crypto_openssl)

find_path(LIBNGTCP2_CRYPTO_OPENSSL_INCLUDE_DIR
  NAMES ngtcp2/ngtcp2_crypto_openssl.h
  HINTS ${PC_LIBNGTCP2_CRYPTO_OPENSSL_INCLUDE_DIRS}
)
find_library(LIBNGTCP2_CRYPTO_OPENSSL_LIBRARY
  NAMES ngtcp2_crypto_openssl
  HINTS ${PC_LIBNGTCP2_CRYPTO_OPENSSL_LIBRARY_DIRS}
)

if(LIBNGTCP2_CRYPTO_OPENSSL_INCLUDE_DIR)
  set(_version_regex "^#define[ \t]+NGTCP2_VERSION[ \t]+\"([^\"]+)\".*")
  file(STRINGS "${LIBNGTCP2_CRYPTO_OPENSSL_INCLUDE_DIR}/ngtcp2/version.h"
    LIBNGTCP2_CRYPTO_OPENSSL_VERSION REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1"
    LIBNGTCP2_CRYPTO_OPENSSL_VERSION "${LIBNGTCP2_CRYPTO_OPENSSL_VERSION}")
  unset(_version_regex)
endif()

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set
# LIBNGTCP2_CRYPTO_OPENSSL_FOUND to TRUE if all listed variables are
# TRUE and the requested version matches.
find_package_handle_standard_args(Libngtcp2_crypto_openssl REQUIRED_VARS
                                  LIBNGTCP2_CRYPTO_OPENSSL_LIBRARY
                                  LIBNGTCP2_CRYPTO_OPENSSL_INCLUDE_DIR
                                  VERSION_VAR LIBNGTCP2_CRYPTO_OPENSSL_VERSION)

if(LIBNGTCP2_CRYPTO_OPENSSL_FOUND)
  set(LIBNGTCP2_CRYPTO_OPENSSL_LIBRARIES ${LIBNGTCP2_CRYPTO_OPENSSL_LIBRARY})
  set(LIBNGTCP2_CRYPTO_OPENSSL_INCLUDE_DIRS ${LIBNGTCP2_CRYPTO_OPENSSL_INCLUDE_DIR})
endif()

mark_as_advanced(LIBNGTCP2_CRYPTO_OPENSSL_INCLUDE_DIR
                 LIBNGTCP2_CRYPTO_OPENSSL_LIBRARY)
