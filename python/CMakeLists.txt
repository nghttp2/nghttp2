# EXTRA_DIST = cnghttp2.pxd nghttp2.pyx

if(ENABLE_PYTHON_BINDINGS)
  add_custom_target(python ALL
    COMMAND "${PYTHON_EXECUTABLE}" setup.py build
    VERBATIM
    DEPENDS nghttp2.c nghttp2
  )

  configure_file(install-python.cmake.in install-python.cmake ESCAPE_QUOTES @ONLY)
  install(SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/install-python.cmake")

  add_custom_command(OUTPUT nghttp2.c
    COMMAND "${CYTHON_EXECUTABLE}" -o nghttp2.c
      "${CMAKE_CURRENT_SOURCE_DIR}/nghttp2.pyx"
    VERBATIM
    DEPENDS nghttp2.pyx
  )

  # Instead of calling "setup.py clean --all", this should do...
  set_directory_properties(PROPERTIES
    ADDITIONAL_MAKE_CLEAN_FILES "build;python_nghttp2.egg-info"
  )

## This works also, except that the installation target is missing...
#  include(UseCython)
#  cython_add_module(python_nghttp2 nghttp2.pyx)
#  set_target_properties(python_nghttp2 PROPERTIES
#    OUTPUT_NAME nghttp2
#  )
#  target_include_directories(python_nghttp2 PRIVATE
#    "${CMAKE_SOURCE_DIR}/lib"
#    "${CMAKE_SOURCE_DIR}/lib/includes"
#    "${CMAKE_BINARY_DIR}/lib/includes"
#  )
#  target_link_libraries(python_nghttp2
#    nghttp2
#  )
endif()
