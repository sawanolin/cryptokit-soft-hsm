# Public header files directory

# Create protocol handling library
add_library(sdfx_protocol STATIC ../common/src/protocol.c)
if(WIN32)
    execute_process(COMMAND /usr/bin/cygpath.exe -w "${CMAKE_CURRENT_SOURCE_DIR}" OUTPUT_VARIABLE SDFX_PROTOCOL_INCLUDE OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND /usr/bin/cygpath.exe -w "${CMAKE_CURRENT_SOURCE_DIR}/../common/include" OUTPUT_VARIABLE SDFX_COMMON_INCLUDE OUTPUT_STRIP_TRAILING_WHITESPACE)
    target_compile_options(sdfx_protocol PRIVATE
        "-I${SDFX_PROTOCOL_INCLUDE}" "-I${SDFX_COMMON_INCLUDE}")
else()
    target_include_directories(sdfx_protocol PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/include
    )
endif()
target_link_libraries(sdfx_protocol ${COMMON_LIBS})

# Install public header files
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sdfx
    FILES_MATCHING PATTERN "*.h"
    PATTERN "CMakeLists.txt" EXCLUDE
)