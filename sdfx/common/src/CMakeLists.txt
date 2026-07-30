# Common source files directory

# Create configuration management library
add_library(sdfx_config STATIC config.c)
target_include_directories(sdfx_config PUBLIC ../include)
target_link_libraries(sdfx_config ${COMMON_LIBS})

# Create openHiTLS initialization library
add_library(sdfx_hitls_init STATIC hitls_init.c)
target_include_directories(sdfx_hitls_init PUBLIC 
    ../include
    ${OPENHITLS_ROOT}/include
    ${OPENHITLS_ROOT}/include/hitls/bsl
)
target_link_libraries(sdfx_hitls_init ${COMMON_LIBS})

# Protocol handling library is already defined in include/CMakeLists.txt
# protocol.c is managed by include directory's CMakeLists.txt