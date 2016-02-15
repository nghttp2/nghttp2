if(ENABLE_THIRD_PARTY)
  set(LIBHTTP_PARSER_SOURCES
    http-parser/http_parser.c
  )
  add_library(http-parser OBJECT ${LIBHTTP_PARSER_SOURCES})

  if(HAVE_NEVERBLEED)
    set(NEVERBLEED_SOURCES
      neverbleed/neverbleed.c
    )
    add_library(neverbleed ${NEVERBLEED_SOURCES})
    target_include_directories(neverbleed PRIVATE ${OPENSSL_INCLUDE_DIRS})
    target_include_directories(neverbleed INTERFACE
      "${CMAKE_SOURCE_DIR}/third-party/neverbleed"
    )
    target_link_libraries(neverbleed ${OPENSSL_LIBRARIES})
  endif()

  if(HAVE_MRUBY)
    ## EXTRA_DIST = build_config.rb mruby/*

    #.PHONY: all-local clean mruby

    #mruby:
    #  MRUBY_CONFIG="${srcdir}/build_config.rb" \
    #  BUILD_DIR="${abs_builddir}/mruby/build" \
    #  INSTALL_DIR="${abs_builddir}/mruby/build/install/bin" \
    #  CC="${CC}" CXX="${CXX}" LD="${LD}" \
    #  CFLAGS="${CPPFLAGS} ${CFLAGS}" CXXFLAGS="${CPPFLAGS} ${CXXFLAGS}" \
    #  LDFLAGS="${LDFLAGS}" \
    #  "${srcdir}/mruby/minirake" -f "${srcdir}/mruby/Rakefile"

    #all-local: mruby

    #clean-local:
    #  -rm -rf "${abs_builddir}/mruby/build"
  endif()
endif()
