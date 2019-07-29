add_subdirectory(includes)

file(GLOB c_sources *.c)
set_source_files_properties(${c_sources} PROPERTIES
  COMPILE_FLAGS "${WARNCFLAGS}")
file(GLOB cxx_sources *.cc)
set_source_files_properties(${cxx_sources} PROPERTIES
  COMPILE_FLAGS "${WARNCXXFLAGS} ${CXX1XCXXFLAGS}")

include_directories(
  "${CMAKE_CURRENT_SOURCE_DIR}/includes"
  "${CMAKE_CURRENT_SOURCE_DIR}/../third-party"
  "${CMAKE_CURRENT_SOURCE_DIR}/../third-party/llhttp/include"

  ${JEMALLOC_INCLUDE_DIRS}
  ${LIBXML2_INCLUDE_DIRS}
  ${LIBEV_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIRS}
  ${LIBCARES_INCLUDE_DIRS}
  ${JANSSON_INCLUDE_DIRS}
  ${ZLIB_INCLUDE_DIRS}
)

# XXX per-target?
link_libraries(
  nghttp2
  ${JEMALLOC_LIBRARIES}
  ${LIBXML2_LIBRARIES}
  ${LIBEV_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${LIBCARES_LIBRARIES}
  ${JANSSON_LIBRARIES}
  ${ZLIB_LIBRARIES}
  ${APP_LIBRARIES}
)

if(ENABLE_APP)
  set(HELPER_OBJECTS
    util.cc
    http2.cc timegm.c app_helper.cc nghttp2_gzip.c
  )

  # nghttp client
  set(NGHTTP_SOURCES
    ${HELPER_OBJECTS}
    nghttp.cc
    tls.cc
  )
  if(HAVE_LIBXML2)
    list(APPEND NGHTTP_SOURCES HtmlParser.cc)
  endif()

  # nghttpd
  set(NGHTTPD_SOURCES
    ${HELPER_OBJECTS}
    nghttpd.cc
    tls.cc
    HttpServer.cc
  )

  # h2load
  set(H2LOAD_SOURCES
    util.cc
    http2.cc h2load.cc
    timegm.c
    tls.cc
    h2load_http2_session.cc
    h2load_http1_session.cc
  )


  # Common libnhttpx sources (used for nghttpx and unit tests)
  set(NGHTTPX_SRCS
    util.cc http2.cc timegm.c
    app_helper.cc
    tls.cc
    shrpx_config.cc
    shrpx_accept_handler.cc
    shrpx_connection_handler.cc
    shrpx_client_handler.cc
    shrpx_http2_upstream.cc
    shrpx_https_upstream.cc
    shrpx_downstream.cc
    shrpx_downstream_connection.cc
    shrpx_http_downstream_connection.cc
    shrpx_http2_downstream_connection.cc
    shrpx_http2_session.cc
    shrpx_downstream_queue.cc
    shrpx_log.cc
    shrpx_http.cc
    shrpx_io_control.cc
    shrpx_tls.cc
    shrpx_worker.cc
    shrpx_log_config.cc
    shrpx_connect_blocker.cc
    shrpx_live_check.cc
    shrpx_downstream_connection_pool.cc
    shrpx_rate_limit.cc
    shrpx_connection.cc
    shrpx_memcached_dispatcher.cc
    shrpx_memcached_connection.cc
    shrpx_worker_process.cc
    shrpx_signal.cc
    shrpx_router.cc
    shrpx_api_downstream_connection.cc
    shrpx_health_monitor_downstream_connection.cc
    shrpx_exec.cc
    shrpx_dns_resolver.cc
    shrpx_dual_dns_resolver.cc
    shrpx_dns_tracker.cc
    xsi_strerror.c
  )
  if(HAVE_MRUBY)
    list(APPEND NGHTTPX_SRCS
      shrpx_mruby.cc
      shrpx_mruby_module.cc
      shrpx_mruby_module_env.cc
      shrpx_mruby_module_request.cc
      shrpx_mruby_module_response.cc
    )
  endif()
  add_library(nghttpx_static STATIC ${NGHTTPX_SRCS})
  set_target_properties(nghttpx_static PROPERTIES ARCHIVE_OUTPUT_NAME nghttpx)

  set(NGHTTPX-bin_SOURCES
    shrpx.cc
  )

  if(HAVE_SYSTEMD)
    target_link_libraries(nghttpx_static ${SYSTEMD_LIBRARIES})
    target_compile_definitions(nghttpx_static PUBLIC HAVE_LIBSYSTEMD)
    target_include_directories(nghttpx_static PUBLIC ${SYSTEMD_INCLUDE_DIRS})
  endif()

  if(HAVE_MRUBY)
    target_link_libraries(nghttpx_static mruby-lib)
  endif()

  if(HAVE_NEVERBLEED)
    target_link_libraries(nghttpx_static neverbleed)
  endif()


  if(HAVE_CUNIT)
    set(NGHTTPX_UNITTEST_SOURCES
      shrpx-unittest.cc
      shrpx_tls_test.cc
      shrpx_downstream_test.cc
      shrpx_config_test.cc
      shrpx_worker_test.cc
      shrpx_http_test.cc
      shrpx_router_test.cc
      http2_test.cc
      util_test.cc
      nghttp2_gzip_test.c
      nghttp2_gzip.c
      buffer_test.cc
      memchunk_test.cc
      template_test.cc
      base64_test.cc
    )
    add_executable(nghttpx-unittest EXCLUDE_FROM_ALL
      ${NGHTTPX_UNITTEST_SOURCES}
      $<TARGET_OBJECTS:llhttp>
      $<TARGET_OBJECTS:url-parser>
    )
    target_include_directories(nghttpx-unittest PRIVATE ${CUNIT_INCLUDE_DIRS})
    target_compile_definitions(nghttpx-unittest
      PRIVATE "-DNGHTTP2_SRC_DIR=\"${CMAKE_SOURCE_DIR}/src\""
    )
    target_link_libraries(nghttpx-unittest nghttpx_static ${CUNIT_LIBRARIES})
    if(HAVE_MRUBY)
      target_link_libraries(nghttpx-unittest mruby-lib)
    endif()
    if(HAVE_NEVERBLEED)
      target_link_libraries(nghttpx-unittest neverbleed)
    endif()

    add_test(nghttpx-unittest nghttpx-unittest)
    add_dependencies(check nghttpx-unittest)
  endif()

  add_executable(nghttp   ${NGHTTP_SOURCES}   $<TARGET_OBJECTS:llhttp>
    $<TARGET_OBJECTS:url-parser>
  )
  add_executable(nghttpd  ${NGHTTPD_SOURCES}  $<TARGET_OBJECTS:llhttp>
    $<TARGET_OBJECTS:url-parser>
  )
  add_executable(nghttpx  ${NGHTTPX-bin_SOURCES} $<TARGET_OBJECTS:llhttp>
    $<TARGET_OBJECTS:url-parser>
  )
  target_compile_definitions(nghttpx PRIVATE "-DPKGDATADIR=\"${PKGDATADIR}\"")
  target_link_libraries(nghttpx nghttpx_static)
  add_executable(h2load   ${H2LOAD_SOURCES}   $<TARGET_OBJECTS:llhttp>
    $<TARGET_OBJECTS:url-parser>
  )

  install(TARGETS nghttp nghttpd nghttpx h2load
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

if(ENABLE_HPACK_TOOLS)
  set(inflatehd_SOURCES
    inflatehd.cc
    comp_helper.c
  )
  set(deflatehd_SOURCES
    deflatehd.cc
    comp_helper.c
  )
  add_executable(inflatehd ${inflatehd_SOURCES})
  add_executable(deflatehd ${deflatehd_SOURCES})
  install(TARGETS inflatehd deflatehd
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

if(ENABLE_ASIO_LIB)
  set(NGHTTP2_ASIO_SOURCES
    util.cc http2.cc
    tls.cc
    timegm.c
    asio_common.cc
    asio_io_service_pool.cc
    asio_server_http2.cc
    asio_server_http2_impl.cc
    asio_server.cc
    asio_server_http2_handler.cc
    asio_server_request.cc
    asio_server_request_impl.cc
    asio_server_response.cc
    asio_server_response_impl.cc
    asio_server_stream.cc
    asio_server_serve_mux.cc
    asio_server_request_handler.cc
    asio_server_tls_context.cc
    asio_client_session.cc
    asio_client_session_impl.cc
    asio_client_session_tcp_impl.cc
    asio_client_session_tls_impl.cc
    asio_client_response.cc
    asio_client_response_impl.cc
    asio_client_request.cc
    asio_client_request_impl.cc
    asio_client_stream.cc
    asio_client_tls_context.cc
  )

  add_library(nghttp2_asio SHARED
     ${NGHTTP2_ASIO_SOURCES}
     $<TARGET_OBJECTS:llhttp>
     $<TARGET_OBJECTS:url-parser>
  )
  target_include_directories(nghttp2_asio PRIVATE
    ${OPENSSL_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
  )
  target_include_directories(nghttp2_asio INTERFACE
    "${CMAKE_CURRENT_BINARY_DIR}/../lib/includes"
    "${CMAKE_CURRENT_SOURCE_DIR}/../lib/includes"
    "${CMAKE_CURRENT_SOURCE_DIR}/includes"
  )
  target_link_libraries(nghttp2_asio
    nghttp2
    ${OPENSSL_LIBRARIES}
    ${Boost_LIBRARIES}
  )
  set_target_properties(nghttp2_asio PROPERTIES
    VERSION 1.0.0 SOVERSION 1)

  install(TARGETS nghttp2_asio
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libnghttp2_asio.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
endif()
