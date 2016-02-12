# EXTRA_DIST = cnghttp2.pxd nghttp2.pyx

# XXX consider https://github.com/thewtex/cython-cmake-example

if(ENABLE_PYTHON_BINDINGS)
  # XXX add ALL? Will always be invoked as target is always out-of-date though.
  add_custom_target(python
    COMMAND ${PYTHON_EXECUTABLE} setup.py build
    DEPENDS nghttp2.c
  )

  add_custom_target(python-install
    COMMAND ${PYTHON_EXECUTABLE} setup.py install --prefix=${DESTDIR}${CMAKE_INSTALL_PREFIX}
  )

  # XXX cmake does not have an uninstall target, do not bother with this then.
  # XXX glob patterns like this will probably not work
  #add_custom_target(python-uninstall
  #  COMMAND ${CMAKE} -E remove -f ${DESTDIR}${CMAKE_INSTALL_FULL_LIBDIR}/python*/site-packages/nghttp2.so
  #  COMMAND ${CMAKE} -E remove -f ${DESTDIR}${CMAKE_INSTALL_FULL_LIBDIR}/python*/site-packages/python_nghttp2-*.egg
  #)

  # XXX cleaner way to advertise the build artifacts? (note nghttp2.c is cleaned automatically)
  add_custom_target(python-clean
    COMMAND ${PYTHON_EXECUTABLE} setup.py clean --all
  )

  # XXX CYTHON_EXECUTABLE is not set!
  add_custom_command(OUTPUT nghttp2.c
    COMMAND ${CYTHON_EXECUTABLE} -o nghttp2.c nghttp2.pyx
    DEPENDS nghttp2.pyx
  )
endif()
