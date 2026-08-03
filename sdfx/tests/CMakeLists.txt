# Test programs

enable_testing()

# Basic tests
add_executable(test_basic
    test_basic.c
)

target_include_directories(test_basic PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(test_basic
    sdfx_sdk
    ${COMMON_LIBS}
)

add_test(NAME test_basic COMMAND test_basic)

# Random number tests
add_executable(test_random
    test_random.c
)

target_include_directories(test_random PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(test_random
    sdfx_sdk
    ${COMMON_LIBS}
)

add_test(NAME test_random COMMAND test_random)

# Hash tests
add_executable(test_hash
    test_hash.c
)

target_include_directories(test_hash PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(test_hash
    sdfx_sdk
    ${COMMON_LIBS}
)

add_test(NAME test_hash COMMAND test_hash)

# GM/T 0018-2023 streaming, HMAC, AEAD and Appendix C integration tests
add_executable(test_0018_extended
    test_0018_extended.c
)

target_include_directories(test_0018_extended PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(test_0018_extended
    sdfx_sdk
    ${COMMON_LIBS}
)

add_test(NAME test_0018_extended COMMAND test_0018_extended)

# Symmetric encryption tests
add_executable(test_symmetric
    test_symmetric.c
)

target_include_directories(test_symmetric PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(test_symmetric
    sdfx_sdk
    ${COMMON_LIBS}
)

# Legacy padding-oriented test is kept as a sample, but GM/T 0018 requires
# callers to provide block-aligned SM4 ECB/CBC input. test_key_file covers it.

# SM2 tests
add_executable(test_sm2
    test_sm2.c
)

target_include_directories(test_sm2 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(test_sm2
    sdfx_sdk
    ${COMMON_LIBS}
)

add_test(NAME test_sm2 COMMAND test_sm2)

# Session key, KEK, MAC and persistent user-file integration tests
add_executable(test_key_file
    test_key_file.c
)

target_include_directories(test_key_file PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(test_key_file
    sdfx_sdk
    ${COMMON_LIBS}
)

add_test(NAME test_key_file COMMAND test_key_file)

# Internal SM2 keys and session-scoped private-key permissions
add_executable(test_internal_key
    test_internal_key.c
)

target_include_directories(test_internal_key PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(test_internal_key
    sdfx_sdk
    ${COMMON_LIBS}
)

add_test(NAME test_internal_key COMMAND test_internal_key)
