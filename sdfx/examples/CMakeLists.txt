# Example Programs

# Basic Usage Example
add_executable(basic_usage
    basic_usage.c
)

target_include_directories(basic_usage PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(basic_usage
    sdfx_sdk
    ${COMMON_LIBS}
)

# Hash Algorithm Demo
add_executable(hash_demo
    hash_demo.c
)

target_include_directories(hash_demo PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(hash_demo
    sdfx_sdk
    ${COMMON_LIBS}
)

# Cryptographic Algorithm Demo
add_executable(crypto_demo
    crypto_demo.c
)

target_include_directories(crypto_demo PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(crypto_demo
    sdfx_sdk
    ${COMMON_LIBS}
)

# Install Example Programs
install(TARGETS basic_usage hash_demo crypto_demo
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/examples
)