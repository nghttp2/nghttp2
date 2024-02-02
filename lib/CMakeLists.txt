add_subdirectory(includes)

include_directories(
  "${CMAKE_CURRENT_SOURCE_DIR}/includes"
  "${CMAKE_CURRENT_BINARY_DIR}/includes"
)

add_definitions(-DBUILDING_NGHTTP2)

set(NGHTTP2_SOURCES
  nghttp2_pq.c nghttp2_map.c nghttp2_queue.c
  nghttp2_frame.c
  nghttp2_buf.c
  nghttp2_stream.c nghttp2_outbound_item.c
  nghttp2_session.c nghttp2_submit.c
  nghttp2_helper.c
  nghttp2_alpn.c
  nghttp2_hd.c nghttp2_hd_huffman.c nghttp2_hd_huffman_data.c
  nghttp2_version.c
  nghttp2_priority_spec.c
  nghttp2_option.c
  nghttp2_callbacks.c
  nghttp2_mem.c
  nghttp2_http.c
  nghttp2_rcbuf.c
  nghttp2_extpri.c
  nghttp2_ratelim.c
  nghttp2_time.c
  nghttp2_debug.c
  sfparse.c
)

set(NGHTTP2_RES "")

if(WIN32)
  configure_file(
    version.rc.in
    ${CMAKE_CURRENT_BINARY_DIR}/version.rc
    @ONLY)

  set(NGHTTP2_RES ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
endif()

set(EXPORT_SET "${PROJECT_NAME}-targets")

# Public shared library
if(BUILD_SHARED_LIBS)
  add_library(nghttp2 SHARED ${NGHTTP2_SOURCES} ${NGHTTP2_RES})

  set_target_properties(nghttp2 PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    VERSION ${LT_VERSION} SOVERSION ${LT_SOVERSION}
    C_VISIBILITY_PRESET hidden
  )

  target_include_directories(nghttp2 INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/includes>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/includes>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  install(TARGETS nghttp2 EXPORT ${EXPORT_SET})
endif()

if(HAVE_CUNIT OR BUILD_STATIC_LIBS)
  # Static library (for unittests because of symbol visibility)
  add_library(nghttp2_static STATIC ${NGHTTP2_SOURCES})

  set_target_properties(nghttp2_static PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    VERSION ${LT_VERSION} SOVERSION ${LT_SOVERSION}
    ARCHIVE_OUTPUT_NAME nghttp2${STATIC_LIB_SUFFIX}
  )

  target_include_directories(nghttp2 INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/includes>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/includes>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  target_compile_definitions(nghttp2_static PUBLIC "-DNGHTTP2_STATICLIB")

  if(BUILD_STATIC_LIBS)
    install(TARGETS nghttp2_static EXPORT ${EXPORT_SET})
  endif()
endif()

if(BUILD_SHARED_LIBS)
  set(LIB_SELECTED nghttp2)
else()
  set(LIB_SELECTED nghttp2_static)
endif()

add_library(nghttp2::nghttp2 ALIAS ${LIB_SELECTED})

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libnghttp2.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
