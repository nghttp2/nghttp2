# XXX testdata/: EXTRA_DIST = cacert.pem  index.html  privkey.pem
string(REPLACE " " ";" c_flags "${WARNCFLAGS}")
add_compile_options(${c_flags})

include_directories(
  "${CMAKE_SOURCE_DIR}/lib/includes"
  "${CMAKE_SOURCE_DIR}/lib"
  "${CMAKE_SOURCE_DIR}/tests/munit"
  "${CMAKE_BINARY_DIR}/lib/includes"
)

set(MAIN_SOURCES
  main.c
  munit/munit.c
  nghttp2_conn_test.c
  nghttp2_frame_test.c
  nghttp2_hpack_test.c
  nghttp2_log_test.c
  nghttp2_test_helper.c
)

add_executable(main EXCLUDE_FROM_ALL
  ${MAIN_SOURCES}
)
target_link_libraries(main
  nghttp2v2_static
)
add_test(main main)
add_dependencies(check main)
