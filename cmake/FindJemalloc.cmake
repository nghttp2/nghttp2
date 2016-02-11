# - Try to find jemalloc
# Once done this will define
#  JEMALLOC_FOUND        - System has jemalloc
#  JEMALLOC_INCLUDE_DIRS - The jemalloc include directories
#  JEMALLOC_LIBRARIES    - The libraries needed to use jemalloc

find_path(JEMALLOC_INCLUDE_DIR jemalloc/jemalloc.h)
find_library(JEMALLOC_LIBRARY NAMES jemalloc)

set(JEMALLOC_LIBRARIES ${JEMALLOC_LIBRARY})
set(JEMALLOC_INCLUDE_DIRS ${JEMALLOC_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set JEMALLOC_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(jemalloc DEFAULT_MSG
                                  JEMALLOC_LIBRARY JEMALLOC_INCLUDE_DIR)

mark_as_advanced(JEMALLOC_INCLUDE_DIR JEMALLOC_LIBRARY)
