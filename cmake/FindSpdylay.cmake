# - Try to find spdylay
# Once done this will define
#  SPDYLAY_FOUND        - System has spdylay
#  SPDYLAY_INCLUDE_DIRS - The spdylay include directories
#  SPDYLAY_LIBRARIES    - The libraries needed to use spdylay

find_package(PkgConfig QUIET)
pkg_check_modules(PC_SPDYLAY QUIET libspdylay)

find_path(SPDYLAY_INCLUDE_DIR
  NAMES spdylay/spdylay.h
  HINTS ${PC_SPDYLAY_INCLUDE_DIRS}
)
find_library(SPDYLAY_LIBRARY
  NAMES spdylay
  HINTS ${PC_SPDYLAY_LIBRARY_DIRS}
)

if(SPDYLAY_INCLUDE_DIR)
  set(_version_regex "^#define[ \t]+SPDYLAY_VERSION[ \t]+\"([^\"]+)\".*")
  file(STRINGS "${SPDYLAY_INCLUDE_DIR}/spdylay/spdylayver.h"
    SPDYLAY_VERSION REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1"
    SPDYLAY_VERSION "${SPDYLAY_VERSION}")
  unset(_version_regex)
endif()

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set SPDYLAY_FOUND to TRUE
# if all listed variables are TRUE and the requested version matches.
find_package_handle_standard_args(Spdylay REQUIRED_VARS
                                  SPDYLAY_LIBRARY SPDYLAY_INCLUDE_DIR
                                  VERSION_VAR SPDYLAY_VERSION)

if(SPDYLAY_FOUND)
  set(SPDYLAY_LIBRARIES     ${SPDYLAY_LIBRARY})
  set(SPDYLAY_INCLUDE_DIRS  ${SPDYLAY_INCLUDE_DIR})
endif()

mark_as_advanced(SPDYLAY_INCLUDE_DIR SPDYLAY_LIBRARY)
