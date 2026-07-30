# Transport layer source files

# Select corresponding implementation files based on transport type
set(TRANSPORT_SOURCES)

if(SDFX_TRANSPORT_TYPE STREQUAL "unix")
    list(APPEND TRANSPORT_SOURCES transport_unix.c)
elseif(SDFX_TRANSPORT_TYPE STREQUAL "tcp")
    if(WIN32)
        list(APPEND TRANSPORT_SOURCES transport_tcp_windows.c)
    else()
        list(APPEND TRANSPORT_SOURCES transport_tcp.c)
    endif()
elseif(SDFX_TRANSPORT_TYPE STREQUAL "shm")
    list(APPEND TRANSPORT_SOURCES transport_shm.c)
elseif(SDFX_TRANSPORT_TYPE STREQUAL "custom")
    list(APPEND TRANSPORT_SOURCES transport_custom.c)
else()
    # Default to Unix socket
    list(APPEND TRANSPORT_SOURCES transport_unix.c)
endif()

add_library(sdfx_transport STATIC
    ${TRANSPORT_SOURCES}
)

# Set position-independent code flag
set_property(TARGET sdfx_transport PROPERTY POSITION_INDEPENDENT_CODE ON)

if(WIN32)
    execute_process(COMMAND /usr/bin/cygpath.exe -w "${CMAKE_CURRENT_SOURCE_DIR}/../include" OUTPUT_VARIABLE SDFX_TRANSPORT_INCLUDE OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND /usr/bin/cygpath.exe -w "${CMAKE_CURRENT_SOURCE_DIR}/../../include" OUTPUT_VARIABLE SDFX_PUBLIC_INCLUDE OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND /usr/bin/cygpath.exe -w "${CMAKE_CURRENT_SOURCE_DIR}/../../common/include" OUTPUT_VARIABLE SDFX_COMMON_INCLUDE OUTPUT_STRIP_TRAILING_WHITESPACE)
    target_compile_options(sdfx_transport PRIVATE
        "-I${SDFX_TRANSPORT_INCLUDE}" "-I${SDFX_PUBLIC_INCLUDE}"
        "-I${SDFX_COMMON_INCLUDE}")
else()
    target_include_directories(sdfx_transport PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
    )
    target_include_directories(sdfx_transport PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../common/include
    )
endif()

target_link_libraries(sdfx_transport
    ${COMMON_LIBS}
)

# Install library files
install(TARGETS sdfx_transport
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Install header files
install(FILES ../include/transport_interface.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sdfx
)
