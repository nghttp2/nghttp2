# - Try to find libevent
#.rst
# FindLibevent
# ------------
#
# Find Libevent include directories and libraries. Invoke as::
#
#   find_package(Libevent
#     [version] [EXACT]   # Minimum or exact version
#     [REQUIRED]          # Fail if Libevent is not found
#     [COMPONENT <C>...]) # Libraries to look for
#
# Valid components are one or more of:: libevent core extra pthreads openssl.
# Note that 'libevent' contains both core and extra. You must specify one of
# them for the other components.
#
# This module will define the following variables::
#
#  LIBEVENT_FOUND        - True if headers and requested libraries were found
#  LIBEVENT_INCLUDE_DIRS - Libevent include directories
#  LIBEVENT_LIBRARIES    - Libevent libraries to be linked
#  LIBEVENT_<C>_FOUND    - Component <C> was found (<C> is uppercase)
#  LIBEVENT_<C>_LIBRARY  - Library to be linked for Libevent omponent <C>.

find_package(PkgConfig QUIET)
pkg_check_modules(PC_LIBEVENT QUIET libevent)

# Look for the Libevent 2.0 or 1.4 headers
find_path(LIBEVENT_INCLUDE_DIR
  NAMES
    event2/event-config.h
    event-config.h
  HINTS
    ${PC_LIBEVENT_INCLUDE_DIRS}
)
set(_LIBEVENT_REQUIRED_VARS LIBEVENT_INCLUDE_DIR)

if(LIBEVENT_INCLUDE_DIR)
  set(_version_regex "^#define[ \t]+_EVENT_VERSION[ \t]+\"([^\"]+)\".*")
  if(EXISTS "${LIBEVENT_INCLUDE_DIR}/event2/event-config.h")
    # Libevent 2.0
    file(STRINGS "${LIBEVENT_INCLUDE_DIR}/event2/event-config.h"
      LIBEVENT_VERSION REGEX "${_version_regex}")
  else()
    # Libevent 1.4
    file(STRINGS "${LIBEVENT_INCLUDE_DIR}/event-config.h"
      LIBEVENT_VERSION REGEX "${_version_regex}")
  endif()
  string(REGEX REPLACE "${_version_regex}" "\\1"
    LIBEVENT_VERSION "${LIBEVENT_VERSION}")
  unset(_version_regex)
endif()

foreach(COMPONENT ${Libevent_FIND_COMPONENTS})
  set(_LIBEVENT_LIBNAME libevent)
  # Note: compare two variables to avoid a CMP0054 policy warning
  if(COMPONENT STREQUAL _LIBEVENT_LIBNAME)
    set(_LIBEVENT_LIBNAME event)
  else()
    set(_LIBEVENT_LIBNAME "event_${COMPONENT}")
  endif()
  string(TOUPPER "${COMPONENT}" COMPONENT)
  find_library(LIBEVENT_${COMPONENT}_LIBRARY
    NAMES ${_LIBEVENT_LIBNAME}
    HINTS ${PC_LIBEVENT_LIBRARY_DIRS}
  )
  if(LIBEVENT_${COMPONENT}_LIBRARY)
    set(LIBEVENT_${COMPONENT}_FOUND 1)
  endif()
  list(APPEND _LIBEVENT_REQUIRED_VARS LIBEVENT_${COMPONENT}_LIBRARY)
endforeach()
unset(_LIBEVENT_LIBNAME)

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBEVENT_FOUND to TRUE
# if all listed variables are TRUE and the requested version matches.
find_package_handle_standard_args(LIBEVENT REQUIRED_VARS
                                  ${_LIBEVENT_REQUIRED_VARS}
                                  VERSION_VAR LIBEVENT_VERSION
                                  HANDLE_COMPONENTS)

if(LIBEVENT_FOUND)
  set(LIBEVENT_INCLUDE_DIRS  ${LIBEVENT_INCLUDE_DIR})
  set(LIBEVENT_LIBRARIES)
  if(NOT Libevent_FIND_QUIETLY)
    message(STATUS "Found the following Libevent components:")
  endif()
  foreach(_COMPONENT ${Libevent_FIND_COMPONENTS})
    string(TOUPPER "${_COMPONENT}" COMPONENT)
    if(LIBEVENT_${COMPONENT}_FOUND)
      if(NOT Libevent_FIND_QUIETLY)
        message(STATUS "  ${_COMPONENT}")
      endif()
      list(APPEND LIBEVENT_LIBRARIES ${LIBEVENT_${COMPONENT}_LIBRARY})
    endif()
  endforeach()
endif()

mark_as_advanced(${_LIBEVENT_REQUIRED_VARS})
unset(_LIBEVENT_REQUIRED_VARS)
