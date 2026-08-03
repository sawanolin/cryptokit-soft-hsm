# SDK module

add_library(sdfx_sdk SHARED
    src/sdfx_api.c
    src/sdf_device.c
    src/sdf_random.c
    src/sdf_hash.c
    src/sdf_symmetric.c
    src/sdf_asymmetric.c
    src/protocol_client.c
    src/sdf_key_file.c
    src/sdf_internal_key.c
    src/sdf_rsa.c
    src/handle_manager.c
    src/error_handler.c
    src/sdf_extended.c
    src/sdf_agreement.c
    src/sdf_vpn.c
    src/sdf_stubs_sm9_vpn.c
    ../common/src/config.c
)

if(WIN32)
    execute_process(COMMAND /usr/bin/cygpath.exe -w "${CMAKE_CURRENT_SOURCE_DIR}/../include" OUTPUT_VARIABLE SDFX_PUBLIC_INCLUDE OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND /usr/bin/cygpath.exe -w "${CMAKE_CURRENT_SOURCE_DIR}/include" OUTPUT_VARIABLE SDFX_SDK_INCLUDE OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND /usr/bin/cygpath.exe -w "${CMAKE_CURRENT_SOURCE_DIR}/../common/include" OUTPUT_VARIABLE SDFX_COMMON_INCLUDE OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND /usr/bin/cygpath.exe -w "${CMAKE_CURRENT_SOURCE_DIR}/../transport/include" OUTPUT_VARIABLE SDFX_TRANSPORT_INCLUDE OUTPUT_STRIP_TRAILING_WHITESPACE)
    target_compile_options(sdfx_sdk PRIVATE
        "-I${SDFX_PUBLIC_INCLUDE}" "-I${SDFX_SDK_INCLUDE}"
        "-I${SDFX_COMMON_INCLUDE}" "-I${SDFX_TRANSPORT_INCLUDE}")
else()
    target_include_directories(sdfx_sdk PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
endif()

target_compile_definitions(sdfx_sdk PRIVATE SDFAPI_EXPORTS)

target_link_libraries(sdfx_sdk
    sdfx_transport
    sdfx_protocol
    ${COMMON_LIBS}
)

# Set platform-specific public artifact names.
if(WIN32)
    set_target_properties(sdfx_sdk PROPERTIES
        OUTPUT_NAME sdfapi_x64
        PREFIX ""
        IMPORT_PREFIX ""
    )
else()
    set_target_properties(sdfx_sdk PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION 1
        OUTPUT_NAME sdfx
    )
endif()

# Install library files
install(TARGETS sdfx_sdk
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
