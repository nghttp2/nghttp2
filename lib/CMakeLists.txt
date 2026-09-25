add_subdirectory(includes)

include_directories(
  "${CMAKE_CURRENT_SOURCE_DIR}/includes"
  "${CMAKE_CURRENT_BINARY_DIR}/includes"
)

add_definitions(-DBUILDING_NGHTTP2)

set(NGHTTP2_SOURCES
  nghttp2_buf.c
  nghttp2_conn.c
  nghttp2_conv.c
  nghttp2_err.c
  nghttp2_fmt.c
  nghttp2_frame.c
  nghttp2_frame_reader.c
  nghttp2_hpack.c
  nghttp2_hpack_huffman.c
  nghttp2_hpack_huffman_data.c
  nghttp2_http.c
  nghttp2_http_writer.c
  nghttp2_log.c
  nghttp2_macro.h
  nghttp2_map.c
  nghttp2_mem.c
  nghttp2_net.h
  nghttp2_pq.c
  nghttp2_ratelim.c
  nghttp2_rcbuf.c
  nghttp2_ringbuf.c
  nghttp2_settings.c
  nghttp2_str.c
  nghttp2_stream.c
  nghttp2_unreachable.c
  nghttp2_vec.c
  sfparse/sfparse.c
)

set(NGHTTP2_RES "")
set(STATIC_LIB "nghttp2v2_static")
set(SHARED_LIB "nghttp2v2")

if(BUILD_SHARED_LIBS AND BUILD_STATIC_LIBS AND MSVC AND NOT STATIC_LIB_SUFFIX)
  set(STATIC_LIB_SUFFIX "_static")
endif()

set(NGHTTP2_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(NGHTTP2_VERSION_CONFIG "${NGHTTP2_GENERATED_DIR}/${PROJECT_NAME}ConfigVersion.cmake")
set(NGHTTP2_PROJECT_CONFIG "${NGHTTP2_GENERATED_DIR}/${PROJECT_NAME}Config.cmake")
set(NGHTTP2_TARGETS_EXPORT_NAME "${PROJECT_NAME}Targets")
set(NGHTTP2_CONFIG_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")
set(NGHTTP2_NAMESPACE "${PROJECT_NAME}::")
set(NGHTTP2_VERSION ${PROJECT_VERSION})

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  "${NGHTTP2_VERSION_CONFIG}" VERSION ${NGHTTP2_VERSION} COMPATIBILITY SameMajorVersion
)
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/config.cmake.in" "${NGHTTP2_PROJECT_CONFIG}" @ONLY)

# Install cmake config files
install(
  FILES "${NGHTTP2_PROJECT_CONFIG}" "${NGHTTP2_VERSION_CONFIG}"
  DESTINATION "${NGHTTP2_CONFIG_INSTALL_DIR}")

install(
  EXPORT "${NGHTTP2_TARGETS_EXPORT_NAME}"
  NAMESPACE "${NGHTTP2_NAMESPACE}"
  DESTINATION "${NGHTTP2_CONFIG_INSTALL_DIR}")

# Public shared library
if(BUILD_SHARED_LIBS)
  add_library(${SHARED_LIB} SHARED ${NGHTTP2_SOURCES} ${NGHTTP2_RES})

  set_target_properties(${SHARED_LIB} PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    VERSION ${LT_VERSION} SOVERSION ${LT_SOVERSION}
    C_VISIBILITY_PRESET hidden
  )

  target_include_directories(${SHARED_LIB} INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/includes>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/includes>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  install(TARGETS ${SHARED_LIB}
    EXPORT ${NGHTTP2_TARGETS_EXPORT_NAME}
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
  list(APPEND nghttp2_exports ${SHARED_LIB})
endif()

# Static library (for unittests because of symbol visibility)
if(BUILD_STATIC_LIBS)
  add_library(${STATIC_LIB} STATIC ${NGHTTP2_SOURCES})

  set_target_properties(${STATIC_LIB} PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    VERSION ${LT_VERSION} SOVERSION ${LT_SOVERSION}
    ARCHIVE_OUTPUT_NAME nghttp2${STATIC_LIB_SUFFIX}
  )

  target_include_directories(${STATIC_LIB} INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/includes>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/includes>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  target_compile_definitions(${STATIC_LIB} PUBLIC "-DNGHTTP2_STATICLIB")

  install(TARGETS ${STATIC_LIB}
    EXPORT ${NGHTTP2_TARGETS_EXPORT_NAME}
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
  list(APPEND nghttp2_exports ${STATIC_LIB})
endif()

if(BUILD_SHARED_LIBS)
  set(LIB_SELECTED ${SHARED_LIB})
else()
  set(LIB_SELECTED ${STATIC_LIB})
endif()

add_library(nghttp2 ALIAS ${LIB_SELECTED})

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libnghttp2v2.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
