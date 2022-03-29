if(ENABLE_EXAMPLES)
  file(GLOB c_sources *.c)
  set_source_files_properties(${c_sources} PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}")
  file(GLOB cxx_sources *.cc)
  set_source_files_properties(${cxx_sources} PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} ${CXX1XCXXFLAGS}")

  include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/../third-party"
    "${CMAKE_CURRENT_SOURCE_DIR}/../third-party/llhttp/include"

    ${LIBEVENT_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
  )

  link_libraries(
    nghttp2
    ${LIBEVENT_OPENSSL_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${APP_LIBRARIES}
  )

  add_executable(client           client.c $<TARGET_OBJECTS:llhttp>
    $<TARGET_OBJECTS:url-parser>
  )
  add_executable(libevent-client  libevent-client.c $<TARGET_OBJECTS:llhttp>
    $<TARGET_OBJECTS:url-parser>
  )
  add_executable(libevent-server  libevent-server.c $<TARGET_OBJECTS:llhttp>
    $<TARGET_OBJECTS:url-parser>
  )
  add_executable(deflate          deflate.c $<TARGET_OBJECTS:llhttp>
    $<TARGET_OBJECTS:url-parser>
  )

  if(ENABLE_ASIO_LIB)
      set(cc_includes
          ${OPENSSL_INCLUDE_DIRS}
          ${Boost_INCLUDE_DIRS}
      )
      set(cc_libraries
          nghttp2
          nghttp2_asio
          ${JEMALLOC_LIBRARIES}
          ${OPENSSL_LIBRARIES}
          ${Boost_LIBRARIES}
          ${APP_LIBRARIES}
      )
    foreach(name asio-sv asio-sv2 asio-cl asio-cl2)
      add_executable(${name} ${name}.cc $<TARGET_OBJECTS:llhttp>
        $<TARGET_OBJECTS:url-parser>
      )
      target_include_directories(${name} PRIVATE ${cc_includes} )
      target_link_libraries(${name} ${cc_libraries} )
    endforeach()
  endif()

  if(ENABLE_ASIO_LIB AND ENABLE_GRPC)
      MESSAGE("GENERATING protobuggg!")
    protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS helloworld.proto)
    foreach(name grpc-sv)
      add_executable(${name} ${name}.cc
          $<TARGET_OBJECTS:llhttp>
          $<TARGET_OBJECTS:url-parser>
          ${PROTO_SRCS}
          ${PROTO_HDRS}
      )
      target_include_directories(${name} PRIVATE
          ${cc_includes}
          ${Protobuf_INCLUDE_DIRS}
          ${CMAKE_CURRENT_BINARY_DIR}
          )
      target_link_libraries(${name} ${cc_libraries} ${Protobuf_LIBRARIES})
    endforeach()
  else()
      MESSAGE("NOtdsdsda")
  endif()


endif()
