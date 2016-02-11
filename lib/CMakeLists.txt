include_directories(
  "${CMAKE_BINARY_DIR}" # for config.h
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
  nghttp2_npn.c
  nghttp2_hd.c nghttp2_hd_huffman.c nghttp2_hd_huffman_data.c
  nghttp2_version.c
  nghttp2_priority_spec.c
  nghttp2_option.c
  nghttp2_callbacks.c
  nghttp2_mem.c
  nghttp2_http.c
)

add_library(nghttp2 SHARED ${NGHTTP2_SOURCES})
#target_link_libraries(nghttp2 ...)
set_target_properties(nghttp2 PROPERTIES
  COMPILE_FLAGS "${WARNCFLAGS} ${EXTRACFLAG}"
  VERSION ${LT_CURRENT}.${LT_REVISION}.${LT_AGE}
  SOVERSION ${LT_CURRENT})

install(TARGETS nghttp2
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libnghttp2.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
