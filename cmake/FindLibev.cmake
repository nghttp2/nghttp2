# - Try to find libev
# Once done this will define
#  LIBEV_FOUND        - System has libev
#  LIBEV_INCLUDE_DIRS - The libev include directories
#  LIBEV_LIBRARIES    - The libraries needed to use libev

find_path(LIBEV_INCLUDE_DIR ev.h)
find_library(LIBEV_LIBRARY NAMES ev)

# Assume that the discovered "ev" library contains ev_time
#include(CheckLibraryExists)
#CHECK_LIBRARY_EXISTS(ev ev_time "" HAVE_LIBEV)

set(LIBEV_LIBRARIES ${LIBEV_LIBRARY})
set(LIBEV_INCLUDE_DIRS ${LIBEV_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBEV_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(Libev DEFAULT_MSG
                                  LIBEV_LIBRARY LIBEV_INCLUDE_DIR)

mark_as_advanced(LIBEV_INCLUDE_DIR LIBEV_LIBRARY)
